//! Only Notes and Reminders run here. Reuse upstream passes and queue/crash semantics.
use quince_auth::{Client, Endpoints, Store};
use quince_core::Library;
use quince_sync::{library_lock::LibraryLock, pass, queue};
use serde_json::{json, Value};
use std::path::Path;
use tokio::sync::Mutex;

pub(crate) const MAX_PENDING: usize = 128;
/// Refused rows kept for the human before admission stops.
pub const MAX_REFUSED: usize = 1024;

pub(crate) fn pending_operations(
    library: &Library,
) -> Result<Vec<quince_core::outbox::Pending>, &'static str> {
    // Refused rows wait for the human (`skykeep-mcp quarantine`); they never count here.
    let all = library.outbox_count().map_err(|_| "library_unavailable")?;
    let refused = library
        .outbox_refused_count()
        .map_err(|_| "library_unavailable")?;
    if all.saturating_sub(refused) > MAX_PENDING {
        return Err("queue_too_large");
    }
    let mut pending = library
        .outbox_pending("notes")
        .map_err(|_| "library_unavailable")?;
    pending.extend(
        library
            .outbox_pending("reminders")
            .map_err(|_| "library_unavailable")?,
    );
    if pending.iter().any(|p| p.payload.len() > 262144) {
        return Err("payload_too_large");
    }
    Ok(pending)
}

fn pending_value(p: &quince_core::outbox::Pending) -> Value {
    // Tries changes on every retry. All operation-defining bytes must stay exact.
    json!({"id":p.id,"service":p.service,"record":p.record,"kind":p.kind,"payload":p.payload})
}

fn send_context(
    library: &Library,
    p: &quince_core::outbox::Pending,
) -> Result<Value, &'static str> {
    match (p.service.as_str(), p.kind.as_str()) {
        ("notes", "create") => {
            let template = library
                .state(quince_icloud::notes::TEMPLATE_KEY)
                .map_err(|_| "library_unavailable")?;
            if template.as_ref().is_some_and(|t| t.len() > 131072) {
                return Err("template_too_large");
            }
            Ok(json!({"template":template}))
        }
        ("reminders", "create") | (_, "delete") => Ok(Value::Null),
        // Only the cached rows the native sender reads for this operation. Lists, folders
        // and sibling items stay out, so unrelated refreshes and writes cannot stale it.
        ("notes", kind) => {
            let mut item = library
                .note(&p.record)
                .map_err(|_| "library_unavailable")?
                .ok_or("not_found")?;
            // `Note.runs` never serializes; the sender takes runs from the payload.
            if kind == "save" {
                item.body = library
                    .note_body(&p.record)
                    .map_err(|_| "library_unavailable")?;
            }
            bounded_context(json!({"item":crate::bounded_json(&item)?}))
        }
        ("reminders", kind) => {
            let item = library
                .reminder(&p.record)
                .map_err(|_| "library_unavailable")?
                .ok_or("not_found")?;
            // An edit that moves lists also moves the cached subtasks with it.
            let edit: Value = serde_json::from_str(&p.payload).unwrap_or(Value::Null);
            let moves = kind == "edit"
                && edit["list_guid"]
                    .as_str()
                    .is_some_and(|to| Some(to) != edit["from_list"].as_str());
            let children = if moves {
                crate::bounded_json(
                    &library
                        .subtasks_of(&p.record)
                        .map_err(|_| "library_unavailable")?,
                )?
            } else {
                Value::Null
            };
            bounded_context(json!({"item":crate::bounded_json(&item)?,"children":children}))
        }
        _ => Err("unknown_service"),
    }
}

fn bounded_context(context: Value) -> Result<Value, &'static str> {
    crate::bounded_value(&context, crate::MAX_ARGUMENT_BYTES)?;
    Ok(context)
}

/// Grant failures that belong to one queued write. Anything else (an unreadable library,
/// a changed policy, account or directory) still stops the whole pass.
const QUARANTINABLE: [&str; 11] = [
    "payload_too_large",
    "preview_too_large",
    "invalid_preview",
    "legacy_write_quarantined",
    "authorization_too_large",
    "invalid_authorization",
    "write_authorization_stale",
    "not_found",
    "operation_too_large",
    "template_too_large",
    "unknown_service",
];

/// Moves each pending write without a current grant out of the queue, alone, with its
/// reason. It is kept for the human and never sent or re-authorized.
fn quarantine_unauthorized(library: &mut Library, dir: &Path) -> Result<(), &'static str> {
    let pending = library
        .outbox_all_pending()
        .map_err(|_| "library_unavailable")?;
    for p in pending {
        match authorized(library, dir, &p) {
            Ok(()) => {}
            Err(reason) if QUARANTINABLE.contains(&reason) => library
                .atomically(|library| -> quince_core::Result<()> {
                    library.outbox_refuse(p.id, &format!("mcp_quarantine:{reason}"))?;
                    library.set_state(&format!("mcp.authorization.{}", p.id), "")?;
                    library.set_state(&reread_key(&p.service), "1")
                })
                .map_err(|_| "library_unavailable")?,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Set when a write is quarantined: the cache still shows it as if on its way. The next
/// pass that reaches the drain re-reads the service in full, which replays only waiting
/// writes, and clears this once that pass succeeds. Kept until then, across failures.
pub(crate) fn reread_key(service: &str) -> String {
    format!("mcp.full_reread.{service}")
}

/// Whether this write's sender answers done only when CloudKit took every write it makes: a
/// reminder create with no date or flag (one write, made once), or one with a repeat or
/// alerts, whose every step fails the change. A dated plain create logs and skips a failed
/// date or flag, and other senders can skip work, so they are not called accepted.
fn every_write_checked(p: &quince_core::outbox::Pending) -> bool {
    if p.service != "reminders" || p.kind != "create" {
        return false;
    }
    serde_json::from_str::<quince_sync::reminders::Create>(&p.payload).is_ok_and(|c| {
        c.repeat.is_some()
            || c.alarm.is_some()
            || c.early_alert.is_some()
            || (c.due_at.is_none() && c.flagged.is_none())
    })
}

/// Skykeep's own refusal codes are shown; engine and Apple reasons can hold HTTP text.
fn shown_reason(reason: &str) -> &str {
    if reason.starts_with("mcp_quarantine:")
        || reason == "mcp_policy_migration_quarantine"
        || reason == "superseded_by_approved_deletion"
    {
        reason
    } else {
        "refused_by_sync_engine"
    }
}

/// A refused write as MCP may show it: identifiers and a reason code, never the payload.
pub(crate) fn refused_view(r: &quince_core::outbox::RefusedBrief) -> Value {
    json!({"id":r.id,"service":r.service,"kind":r.kind,"record":r.record,"reason":shown_reason(&r.reason)})
}

fn refused_ids(dir: &Path) -> Result<Vec<i64>, &'static str> {
    let library = Library::open(dir).map_err(|_| "library_unavailable")?;
    Ok(library
        .outbox_refused_brief()
        .map_err(|_| "library_unavailable")?
        .into_iter()
        .map(|r| r.id)
        .collect())
}

pub(crate) fn record_authorization(
    library: &mut Library,
    p: &quince_core::outbox::Pending,
) -> Result<(), &'static str> {
    let policy = library
        .state("mcp.policy")
        .map_err(|_| "policy_unavailable")?
        .ok_or("policy_unavailable")?;
    let grant =
        json!({"policy":policy,"pending":pending_value(p),"context":send_context(library,p)?});
    library
        .set_state(&format!("mcp.authorization.{}", p.id), &grant.to_string())
        .map_err(|_| "library_unavailable")
}

/// Testable send boundary. No tool can create or change this authorization.
pub fn authorized(
    library: &Library,
    dir: &Path,
    p: &quince_core::outbox::Pending,
) -> Result<(), &'static str> {
    authorization_check(library, dir, p, true)
}

pub(crate) fn authorized_payload(
    library: &Library,
    dir: &Path,
    p: &quince_core::outbox::Pending,
) -> Result<(), &'static str> {
    authorization_check(library, dir, p, false)
}

fn authorization_check(
    library: &Library,
    dir: &Path,
    p: &quince_core::outbox::Pending,
    context: bool,
) -> Result<(), &'static str> {
    let Some((_, binding)) = crate::policy(library, dir)? else {
        return Err("configured_policy_required");
    };
    if p.payload.len() > 262144 {
        return Err("payload_too_large");
    }
    let raw = library
        .state(&format!("mcp.authorization.{}", p.id))
        .map_err(|_| "library_unavailable")?
        .ok_or("legacy_write_quarantined")?;
    if raw.len() > 1572864 {
        return Err("authorization_too_large");
    }
    let grant: Value = serde_json::from_str(&raw).map_err(|_| "invalid_authorization")?;
    if grant.as_object().is_none_or(|m| m.len() != 3)
        || grant["policy"] != binding.policy
        || grant["pending"] != pending_value(p)
        || (context && grant["context"] != send_context(library, p)?)
    {
        return Err("write_authorization_stale");
    }
    Ok(())
}

pub async fn run(dir: &Path) -> Result<Value, &'static str> {
    run_authorized(dir, false).await
}

fn refresh_gate(dir: &Path, approved: bool) -> Result<bool, &'static str> {
    let mut library = Library::open(dir).map_err(|_| "library_unavailable")?;
    let configured = crate::policy(&library, dir)?;
    if configured
        .as_ref()
        .is_some_and(|(p, _)| p.mode == "reads_and_writes")
        && !approved
    {
        return Err("read_approval_required");
    }
    if configured.is_some() {
        quarantine_unauthorized(&mut library, dir)?;
    }
    Ok(configured.is_some())
}

pub(crate) async fn run_authorized(dir: &Path, approved: bool) -> Result<Value, &'static str> {
    let before = refused_ids(dir)?;
    refresh_gate(dir, approved)?;
    let store = Store::isolated_keyring(dir).map_err(|_| "secure_storage_unavailable")?;
    let session = store
        .try_load()
        .map_err(|_| "login_required_unlock_secure_storage")?;
    if !session.is_resumable() {
        return Err("login_required");
    }
    let client = Client::with(dir, Endpoints::default(), store).map_err(|_| "login_required")?;
    with_client_inner(dir, client, approved, before).await
}

/// Test seam with synthetic endpoints. Production constructs its own Apple-only client.
/// Caller holds the private directory's exclusive operation lock.
pub async fn with_client(dir: &Path, client: Client) -> Result<Value, &'static str> {
    let before = refused_ids(dir)?;
    with_client_inner(dir, client, false, before).await
}

/// `before` holds the refused ids from before this sync's first gate, so the reply can
/// name every write this sync refused or quarantined.
async fn with_client_inner(
    dir: &Path,
    client: Client,
    approved: bool,
    before: Vec<i64>,
) -> Result<Value, &'static str> {
    let configured = refresh_gate(dir, approved)?;
    if configured {
        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            sync_pass(dir, client, true, &before),
        )
        .await
        .map_err(|_| "sync_timeout_delivery_uncertain")?
    } else {
        sync_pass(dir, client, false, &before).await
    }
}

async fn sync_pass(
    dir: &Path,
    mut client: Client,
    configured: bool,
    before_refused: &[i64],
) -> Result<Value, &'static str> {
    if !client
        .resume()
        .await
        .map_err(|_| "login_required_or_network_unavailable")?
    {
        return Err("login_required");
    }
    if client.waits_on_icloud_com() {
        return Err("login_required_complete_account_setup");
    }
    let dsid = client.session().dsid.as_deref().ok_or("login_required")?;
    let tag = queue::account_tag(dsid);
    let library = Library::open(dir).map_err(|_| "library_unavailable")?;
    if crate::account::binding(&library, dsid)? != crate::account::Binding::Same {
        return Err("account_mismatch_use_new_state_directory");
    }
    let data = LibraryLock::new(library, Some(dir.to_owned()));
    let ctx = pass::Ctx::new(
        client.http().clone(),
        client.service_params(),
        client.session().service_url("ckdatabasews"),
        client.data_access_missing(),
        &pass::NoHooks,
    );
    let root = ctx.cloudkit.as_deref().ok_or("service_unavailable")?;
    let mut services = Vec::new();
    // Each write waiting before the drain: the ones gone after it, not refused, left the
    // queue. Only some senders answer done only when CloudKit took every write; the rest can
    // finish with a part logged and skipped, or with nothing written (a tick another device
    // overtook), so leaving the queue is reported as accepted only for those. Neither is read
    // back.
    let mut waiting_before = Vec::new();
    for service in ["notes", "reminders"] {
        let lock = Mutex::new(());
        let before = pass::run(service, &ctx, &data, &lock).await;
        waiting_before.extend(
            data.lock()
                .await
                .outbox_pending(service)
                .map_err(|_| "library_unavailable")?,
        );
        // Never send when the authenticated read is gated or failed.
        let mut sent = false;
        if matches!(before.outcome, pass::Outcome::Ok) {
            let report = queue::drain_as(&data, service, &lock, &tag, |p| {
                let data = &data;
                let http = &ctx.http;
                let params = ctx.params.clone();
                async move {
                    if configured {
                        let mut library = data.lock().await;
                        if let Err(reason) = authorized(&library, dir, &p) {
                            let _ = library.set_state(&reread_key(service), "1");
                            return Err(quince_icloud::Error::Refused(format!(
                                "mcp_quarantine:{reason}"
                            )));
                        }
                    }
                    if service == "notes" {
                        quince_sync::notes::send(data, http, root, params, p).await
                    } else {
                        quince_sync::reminders::send(data, http, root, params, p).await
                    }
                }
            })
            .await;
            sent = report.sent;
        }
        let reread = configured
            && matches!(before.outcome, pass::Outcome::Ok)
            && data
                .lock()
                .await
                .state(&reread_key(service))
                .map_err(|_| "library_unavailable")?
                .as_deref()
                == Some("1");
        if reread {
            data.lock()
                .await
                .forget_full_sync(service)
                .map_err(|_| "library_unavailable")?;
        }
        let after = if sent || reread {
            pass::run(service, &ctx, &data, &lock).await
        } else {
            before
        };
        if reread && matches!(after.outcome, pass::Outcome::Ok) {
            data.lock()
                .await
                .set_state(&reread_key(service), "")
                .map_err(|_| "library_unavailable")?;
        }
        // Raw upstream error details can contain HTTP bodies. Expose only typed outcomes.
        services.push(json!({"service":service,"outcome":after.outcome,"sent":sent,"last_synced_at":after.last_synced_at}));
    }
    let library = data.lock().await;
    let refused = library
        .outbox_refused_brief()
        .map_err(|_| "library_unavailable")?;
    let waiting = library
        .outbox_count()
        .map_err(|_| "library_unavailable")?
        .saturating_sub(refused.len());
    let mut still = Vec::new();
    for service in ["notes", "reminders"] {
        still.extend(
            library
                .outbox_pending(service)
                .map_err(|_| "library_unavailable")?
                .into_iter()
                .map(|p| p.id),
        );
    }
    let left: Vec<Value> = waiting_before
        .iter()
        .filter(|p| !still.contains(&p.id) && !refused.iter().any(|r| r.id == p.id))
        .take(MAX_PENDING)
        .map(|p| {
            let outcome = if every_write_checked(p) {
                "cloudkit_accepted"
            } else {
                "finished_unconfirmed"
            };
            json!({"service":p.service,"kind":p.kind,"record":p.record,"outcome":outcome})
        })
        .collect();
    // Bounded: admission stops at MAX_PENDING waiting writes, and each is refused at most once.
    let refused_now: Vec<Value> = refused
        .iter()
        .filter(|r| !before_refused.contains(&r.id))
        .take(MAX_PENDING)
        .map(refused_view)
        .collect();
    Ok(
        json!({"services":services,"queued":waiting,"refused":refused.len(),"refused_this_sync":refused_now,"left_queue_this_sync":left,"remote_verified":false,"verification":"upstream sync and replay only; field-level read-back is not guaranteed"}),
    )
}

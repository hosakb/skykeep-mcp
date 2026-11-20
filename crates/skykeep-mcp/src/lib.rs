//! Local MCP adapter. The library and codecs remain owned by the upstream crates.
pub mod account;
pub mod calendar;
pub mod contacts;
pub mod drive;
pub mod login;
pub mod photos;
pub mod scheduler;
pub mod state;
pub mod sync;
pub mod terminal;
use quince_core::Library;
use quince_sync::queue::ACCOUNT_KEY;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;

pub const MAX_FRAME_BYTES: usize = 65536;
const MAX_ARGUMENT_BYTES: usize = 32768;
const MAX_PREVIEW_BYTES: usize = 131072;

// Count before serialization or cloning. Also cap the shape of already-parsed
// library callers, independently of the stdio parser's recursion limit.
fn bounded_value(value: &Value, limit: usize) -> Result<(), &'static str> {
    fn visit(
        v: &Value,
        left: &mut usize,
        nodes: &mut usize,
        depth: usize,
    ) -> Result<(), &'static str> {
        if depth > 32 || *nodes == 0 {
            return Err("operation_too_large");
        }
        *nodes -= 1;
        let size = match v {
            Value::String(s) => s.len(),
            Value::Object(m) => m
                .keys()
                .try_fold(0usize, |n, k| n.checked_add(k.len()))
                .ok_or("operation_too_large")?,
            _ => 8,
        };
        *left = left.checked_sub(size).ok_or("operation_too_large")?;
        match v {
            Value::Array(a) => {
                for v in a {
                    visit(v, left, nodes, depth + 1)?;
                }
            }
            Value::Object(m) => {
                for v in m.values() {
                    visit(v, left, nodes, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut remaining = limit;
    let mut nodes = 4096;
    visit(value, &mut remaining, &mut nodes, 0)
}

/// Cancellation-safe bounded framing: the caller retains partially received bytes
/// across timer ticks. Oversized frames close the connection without parsing.
pub async fn read_frame<R: tokio::io::AsyncBufRead + Unpin>(
    input: &mut R,
    frame: &mut Vec<u8>,
) -> Result<Option<String>, &'static str> {
    use tokio::io::AsyncBufReadExt;
    loop {
        let available = input.fill_buf().await.map_err(|_| "transport_failed")?;
        if available.is_empty() {
            if frame.is_empty() {
                return Ok(None);
            }
            return String::from_utf8(std::mem::take(frame))
                .map(Some)
                .map_err(|_| "invalid_utf8");
        }
        let end = available.iter().position(|b| *b == b'\n');
        let count = end.map_or(available.len(), |n| n + 1);
        if count > MAX_FRAME_BYTES.saturating_sub(frame.len()) {
            return Err("frame_too_large");
        }
        frame.extend_from_slice(&available[..count]);
        input.consume(count);
        if end.is_some() {
            return String::from_utf8(std::mem::take(frame))
                .map(Some)
                .map_err(|_| "invalid_utf8");
        }
    }
}

#[derive(Clone, PartialEq)]
struct ApprovalBinding {
    policy: String,
    account: Option<String>,
    identity: (u64, u64),
    snapshot: Option<Value>,
    preview_read: bool,
}

struct PendingConsent {
    id: String,
    request: Value,
    binding: ApprovalBinding,
    deadline: std::time::Instant,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    mode: String,
    revision: String,
    account: Option<String>,
    state_identity: (u64, u64),
}

fn policy(
    library: &Library,
    dir: &Path,
) -> Result<Option<(Policy, ApprovalBinding)>, &'static str> {
    let Some(raw) = library
        .state("mcp.policy")
        .map_err(|_| "policy_unavailable")?
    else {
        return Ok(None);
    };
    let parsed: Policy = serde_json::from_str(&raw).map_err(|_| "invalid_policy")?;
    if parsed.state_identity != directory_identity(dir)? {
        return Err("policy_state_changed");
    }
    if parsed.account
        != library
            .state(ACCOUNT_KEY)
            .map_err(|_| "policy_unavailable")?
    {
        return Err("policy_account_changed");
    }
    if !["reads_and_writes", "writes_only", "yolo"].contains(&parsed.mode.as_str())
        || parsed.revision.is_empty()
    {
        return Err("invalid_policy");
    }
    Ok(Some((
        parsed,
        ApprovalBinding {
            policy: raw,
            account: library
                .state(ACCOUNT_KEY)
                .map_err(|_| "policy_unavailable")?,
            identity: (0, 0),
            snapshot: None,
            preview_read: false,
        },
    )))
}

fn tool_reply(id: Value, result: Result<Value, &'static str>) -> Value {
    let failed = result.is_err();
    let value = result.unwrap_or_else(|error| json!({"error":error}));
    json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":value.to_string()}],"isError":failed}})
}

fn accepts_confirmation(response: &Value) -> bool {
    // This continuation only emits an empty confirmation form. An old checkbox
    // answer or omitted content is not an answer to that form. Result metadata
    // may describe the response but never supplies operation arguments or consent.
    let Some(envelope) = response.as_object() else {
        return false;
    };
    let Some(result) = response.get("result").and_then(Value::as_object) else {
        return false;
    };
    envelope
        .keys()
        .all(|key| ["jsonrpc", "id", "result"].contains(&key.as_str()))
        && response["jsonrpc"] == "2.0"
        && result
            .keys()
            .all(|key| ["action", "content", "_meta"].contains(&key.as_str()))
        && result
            .get("action")
            .is_some_and(|action| action == "accept")
        && result
            .get("content")
            .and_then(Value::as_object)
            .is_some_and(|content| content.is_empty())
        && result.get("_meta").is_none_or(Value::is_object)
}

fn directory_identity(dir: &Path) -> Result<(u64, u64), &'static str> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(dir).map_err(|_| "state_unavailable")?;
    Ok((meta.dev(), meta.ino()))
}

struct Limited(Vec<u8>);
impl std::io::Write for Limited {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_PREVIEW_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("preview_too_large"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bounded_json<T: serde::Serialize>(value: &T) -> Result<Value, &'static str> {
    let mut raw = Limited(Vec::new());
    serde_json::to_writer(&mut raw, value).map_err(|_| "preview_too_large")?;
    let value: Value = serde_json::from_slice(&raw.0).map_err(|_| "invalid_preview")?;
    bounded_value(&value, MAX_ARGUMENT_BYTES)?;
    Ok(value)
}

fn inert_preview(params: &Value) -> Result<String, &'static str> {
    bounded_value(params, MAX_ARGUMENT_BYTES)?;
    let mut raw = Limited(Vec::new());
    serde_json::to_writer_pretty(&mut raw, params).map_err(|_| "preview_too_large")?;
    let raw = String::from_utf8(raw.0).map_err(|_| "invalid_preview")?;
    let mut length = 0usize;
    for c in raw.chars() {
        let size = if !c.is_ascii() || "<>&`*_[]!#~|".contains(c) {
            c.len_utf16() * 6
        } else {
            1
        };
        if size > MAX_PREVIEW_BYTES.saturating_sub(length) {
            return Err("preview_too_large");
        }
        length += size;
    }
    let mut preview = String::with_capacity(length);
    for c in raw.chars() {
        let size = if !c.is_ascii() || "<>&`*_[]!#~|".contains(c) {
            c.len_utf16() * 6
        } else {
            1
        };
        if size > MAX_PREVIEW_BYTES.saturating_sub(preview.len()) {
            return Err("preview_too_large");
        }
        if !c.is_ascii() || "<>&`*_[]!#~|".contains(c) {
            for unit in c.encode_utf16(&mut [0; 2]) {
                preview.push_str(&format!("\\u{unit:04x}"));
            }
        } else {
            preview.push(c);
        }
    }
    Ok(preview)
}

fn needs_consent(mode: &str, name: &str) -> Result<bool, &'static str> {
    match name {
        "auth_status" | "sync_status" => Ok(false),
        "notes_write" | "reminders_write" => Ok(mode != "yolo"),
        "notes_get" | "notes_list" | "notes_search" | "notes_folders" | "reminders_get"
        | "reminders_list" | "reminders_search" | "reminders_lists" => {
            Ok(mode == "reads_and_writes")
        }
        "sync" => Ok(mode == "reads_and_writes"),
        // Contacts content and its refresh are reads: prompted only under reads_and_writes.
        "contacts_list" | "contacts_search" | "contacts_get" | "contacts_refresh" => {
            Ok(mode == "reads_and_writes")
        }
        // Calendar content and its refresh are reads too.
        "calendar_calendars" | "calendar_events" | "calendar_search" | "calendar_get"
        | "calendar_refresh" => Ok(mode == "reads_and_writes"),
        // Photos metadata and its refresh are reads too.
        "photos_albums" | "photos_list" | "photos_search" | "photos_get" | "photos_refresh" => {
            Ok(mode == "reads_and_writes")
        }
        // Drive metadata and its refresh are reads too.
        "drive_list" | "drive_get" | "drive_search" | "drive_refresh" => {
            Ok(mode == "reads_and_writes")
        }
        _ => Err("unknown_tool"),
    }
}

fn resolved_snapshot(library: &Library, name: &str, args: &Value) -> Result<Value, &'static str> {
    let guid = args["guid"].as_str().ok_or("guid_required")?;
    if name == "notes_write" {
        let _: NoteWrite = serde_json::from_value(args.clone()).map_err(|_| "invalid_arguments")?;
    } else if name == "reminders_write" {
        let _: ReminderWrite =
            serde_json::from_value(args.clone()).map_err(|_| "invalid_arguments")?;
    }
    let mut snapshot = resolved_state(library, name, guid)?;
    let queued: Vec<_> = sync::pending_operations(library)?
        .into_iter()
        .filter(|p| p.record == guid)
        .map(|p| json!({"id":p.id,"kind":p.kind,"payload":p.payload}))
        .collect();
    snapshot["queued_operations"] = json!(queued);
    bounded_value(&snapshot, MAX_ARGUMENT_BYTES)?;
    Ok(snapshot)
}

fn resolved_state(library: &Library, name: &str, guid: &str) -> Result<Value, &'static str> {
    let snapshot = if name == "notes_write" {
        let mut item = library
            .note(guid)
            .map_err(|_| "library_unavailable")?
            .ok_or("not_found")?;
        item.body = library.note_body(guid).map_err(|_| "library_unavailable")?;
        // Note.runs intentionally does not serialize. Bind its complete cached
        // representation explicitly, with the same budgets as the rest of the preview.
        let runs = bounded_json(&library.note_runs(guid).map_err(|_| "library_unavailable")?)?;
        let runs = match runs {
            Value::String(raw) => {
                serde_json::from_str::<Value>(&raw).map_err(|_| "invalid_cached_runs")?
            }
            _ => Value::Null,
        };
        bounded_value(&runs, MAX_ARGUMENT_BYTES)?;
        let item = bounded_json(&item)?;
        let containers = bounded_json(&library.note_folders().map_err(|_| "library_unavailable")?)?;
        json!({"item":item,"runs":runs,"containers":containers})
    } else if name == "reminders_write" {
        let item = bounded_json(
            &library
                .reminder(guid)
                .map_err(|_| "library_unavailable")?
                .ok_or("not_found")?,
        )?;
        let detail = bounded_json(
            &library
                .reminder_detail(guid)
                .map_err(|_| "library_unavailable")?,
        )?;
        let children = bounded_json(
            &library
                .subtasks_of(guid)
                .map_err(|_| "library_unavailable")?,
        )?;
        let containers = bounded_json(
            &library
                .reminder_lists()
                .map_err(|_| "library_unavailable")?,
        )?;
        json!({"item":item,"detail":detail,"children":children,"containers":containers})
    } else {
        return Err("unknown_tool");
    };
    bounded_value(&snapshot, MAX_ARGUMENT_BYTES)?;
    Ok(snapshot)
}

pub struct Server {
    /// `None` until the first operation that holds the private directory's lock.
    library: Option<Library>,
    dir: std::path::PathBuf,
    initialized: bool,
    forms: bool,
    pending: Option<PendingConsent>,
    grant: Option<ApprovalBinding>,
}

#[cfg(test)]
mod consent_tests {
    use super::*;
    #[tokio::test]
    async fn timeout_and_disconnect_drop_unconsumed_consent() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut server = Server::open(dir.path()).unwrap();
        let mut library = Library::open(dir.path()).unwrap();
        library.set_state(ACCOUNT_KEY, "synthetic").unwrap();
        server.set_policy("writes_only").unwrap();
        server.handle(json!({"id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"elicitation":{}}}})).await;
        let request = json!({"id":2,"method":"tools/call","params":{"name":"notes_write","arguments":{"action":"create","body":"exact"}}});
        let form = server.handle(request.clone()).await.unwrap();
        server.pending.as_mut().unwrap().deadline = std::time::Instant::now();
        assert_eq!(server.expire_consent().unwrap()["id"], 2);
        assert!(server
            .handle(
                json!({"jsonrpc":"2.0","id":form["id"],"result":{"action":"accept","content":{}}})
            )
            .await
            .is_none());
        server.handle(request).await;
        drop(server); // EOF drops the only pending record; nothing is persisted.
        assert_eq!(library.outbox_count().unwrap(), 0);
        let mut reopened = Server::open(dir.path()).unwrap();
        assert!(reopened
            .handle(
                json!({"jsonrpc":"2.0","id":form["id"],"result":{"action":"accept","content":{}}})
            )
            .await
            .is_none());
    }

    #[tokio::test]
    async fn a_timed_out_contacts_read_returns_nothing_and_its_late_answer_is_ignored() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut server = Server::open(dir.path()).unwrap();
        let mut library = Library::open(dir.path()).unwrap();
        library.set_state(ACCOUNT_KEY, "synthetic").unwrap();
        let mut card = quince_core::contacts::Contact {
            guid: "C-1".into(),
            first_name: Some("Synthetic".into()),
            middle_name: None,
            photo_url: None,
            photo_signature: None,
            photo_crop: None,
            last_name: Some("Person".into()),
            company: None,
            is_company: false,
            birthday: None,
            notes: None,
            etag: None,
            methods: Vec::new(),
        };
        card.notes = Some("SYNTHETIC-PRIVATE".into());
        library.put_contacts(&[card]).unwrap();
        server.set_policy("reads_and_writes").unwrap();
        server.handle(json!({"id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"elicitation":{}}}})).await;
        for (name, args) in [
            ("contacts_get", json!({"guid":"C-1"})),
            ("contacts_refresh", json!({})),
        ] {
            let form = server
                .handle(
                    json!({"id":2,"method":"tools/call","params":{"name":name,"arguments":args}}),
                )
                .await
                .unwrap();
            assert_eq!(form["method"], "elicitation/create");
            server.pending.as_mut().unwrap().deadline = std::time::Instant::now();
            let expired = server.expire_consent().unwrap();
            assert_eq!(expired["id"], 2);
            assert!(expired.to_string().contains("approval_timeout"));
            assert!(!expired.to_string().contains("SYNTHETIC-PRIVATE"));
            assert!(server
                .handle(json!({"jsonrpc":"2.0","id":form["id"],"result":{"action":"accept","content":{}}}))
                .await
                .is_none());
        }
        assert!(library
            .sync_health()
            .unwrap()
            .iter()
            .all(|h| h.service != "contacts" || h.last_error.is_none()));
    }
}

impl Server {
    fn prepare_consent(
        &mut self,
        params: &Value,
        read_grant: Option<&ApprovalBinding>,
    ) -> Result<Option<ApprovalBinding>, &'static str> {
        let held = state::PrivateState::open(&self.dir)?;
        let dir = held.path.clone();
        let library = self.ready(&held)?;
        let Some((p, mut binding)) = policy(library, &held.path)? else {
            return Ok(None);
        };
        let name = params["name"].as_str().ok_or("invalid_tool")?;
        // Malformed Contacts arguments are refused before anyone is asked to approve them.
        contacts::validate(name, &params["arguments"])?;
        calendar::validate(name, &params["arguments"])?;
        photos::validate(name, &params["arguments"])?;
        drive::validate(name, &params["arguments"])?;
        if !needs_consent(&p.mode, name)? {
            return Ok(None);
        }
        if name.ends_with("_write") && binding.account.is_none() {
            return Err("login_required");
        }
        binding.identity = directory_identity(&dir)?;
        if name.ends_with("_write") && params["arguments"]["action"] != "create" {
            if p.mode == "reads_and_writes" {
                if let Some(previous) = read_grant {
                    let mut expected = binding.clone();
                    expected.preview_read = true;
                    if previous != &expected {
                        return Err("approval_policy_changed");
                    }
                } else {
                    binding.preview_read = true;
                    return Ok(Some(binding));
                }
            }
            binding.snapshot = Some(resolved_snapshot(library, name, &params["arguments"])?);
        }
        Ok(Some(binding))
    }

    fn consent_form(&mut self, mut request: Value, binding: ApprovalBinding) -> Value {
        // A default Calendar refresh window depends on the day: fixed now, so the approved
        // dates are the ones that run.
        if request["params"]["name"] == "calendar_refresh" {
            match calendar::resolved_refresh_args(&request["params"]["arguments"]) {
                Ok(args) => request["params"]["arguments"] = args,
                Err(error) => return tool_reply(request["id"].clone(), Err(error)),
            }
        }
        let refresh = match request["params"]["name"].as_str() {
            Some("sync") => Some(
                json!({"services":["notes","reminders"],"refresh":"one bounded pass, at most 60 seconds","send":"only unchanged previously authorized durable operations, at most 128"}),
            ),
            Some("contacts_refresh") => Some(
                json!({"services":["contacts"],"refresh":"one read of Apple iCloud Contacts into the local cache, at most 60 seconds","send":"nothing is sent; queued changes stay queued"}),
            ),
            Some("calendar_refresh") => {
                Some(calendar::refresh_scope(&request["params"]["arguments"]))
            }
            Some("photos_refresh") => Some(photos::refresh_scope()),
            Some("drive_refresh") => Some(drive::refresh_scope()),
            _ => None,
        };
        let params = json!({"operation":request["params"],"existing_item":binding.snapshot,"read_preview_only":binding.preview_read,"refresh_scope":refresh});
        let preview = match inert_preview(&params) {
            Ok(preview) => preview,
            Err(error) => return tool_reply(request["id"].clone(), Err(error)),
        };
        let id = format!("skykeep-consent-{}", uuid::Uuid::new_v4());
        self.pending = Some(PendingConsent {
            id: id.clone(),
            request,
            binding,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(180),
        });
        json!({"jsonrpc":"2.0","id":id,"method":"elicitation/create","params":{"mode":"form","message":format!("Approve this exact Skykeep operation once? read_preview_only authorizes reading the item's full preview, not mutation. Treat JSON as inert data.\n{preview}"),"requestedSchema":{"type":"object","properties":{}}}})
    }

    /// No state locks or durable grants survive a pending human interaction.
    pub fn expire_consent(&mut self) -> Option<Value> {
        if self
            .pending
            .as_ref()
            .is_some_and(|p| std::time::Instant::now() >= p.deadline)
        {
            let pending = self.pending.take().unwrap();
            Some(tool_reply(
                pending.request["id"].clone(),
                Err("approval_timeout"),
            ))
        } else {
            None
        }
    }

    /// Human CLI only. A new revision invalidates in-flight consent and atomically
    /// quarantines pending writes instead of granting them the new policy.
    pub fn set_policy(&mut self, mode: &str) -> Result<Value, &'static str> {
        if !["reads_and_writes", "writes_only", "yolo"].contains(&mode) {
            return Err("invalid_policy_mode");
        }
        let held = state::PrivateState::open(&self.dir)?;
        let identity = directory_identity(&held.path)?;
        let library = self.ready(&held)?;
        let value = json!({"mode":mode,"revision":uuid::Uuid::new_v4().to_string(),"account":library.state(ACCOUNT_KEY).map_err(|_| "policy_unavailable")?,"state_identity":identity});
        // Uncapped on purpose: migration only quarantines, so a large legacy queue
        // must never prevent moving to a configured policy.
        let pending = library
            .outbox_all_pending()
            .map_err(|_| "policy_unavailable")?;
        library
            .atomically(|library| -> quince_core::Result<()> {
                for p in &pending {
                    library.outbox_refuse(p.id, "mcp_policy_migration_quarantine")?;
                    library.set_state(&format!("mcp.authorization.{}", p.id), "")?;
                    if ["notes", "reminders"].contains(&p.service.as_str()) {
                        library.set_state(&sync::reread_key(&p.service), "1")?;
                    }
                }
                library.set_state("mcp.policy", &value.to_string())
            })
            .map_err(|_| "policy_unavailable")?;
        let saved = library
            .state("mcp.policy")
            .map_err(|_| "policy_unavailable")?
            .ok_or("policy_unavailable")?;
        serde_json::from_str(&saved).map_err(|_| "policy_unavailable")
    }

    /// Human CLI only. Refused writes kept for review, without their payloads.
    pub fn quarantined(&mut self) -> Result<Vec<Value>, &'static str> {
        let held = state::PrivateState::open(&self.dir)?;
        let library = self.ready(&held)?;
        let refused = library
            .outbox_refused()
            .map_err(|_| "library_unavailable")?;
        // Upstream reasons can hold HTTP text; the terminal gets a bounded line with no
        // control or text-direction characters that could rearrange what is shown.
        let plain = |text: &str, limit: usize| -> String {
            text.chars()
                .filter(|c| {
                    !c.is_control()
                        && !matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
                })
                .take(limit)
                .collect()
        };
        Ok(refused
            .iter()
            .map(|r| {
                json!({"id":r.change.id,"service":plain(&r.change.service, 40),"kind":plain(&r.change.kind, 40),
                    "record":plain(&r.change.record, 200),"reason":plain(&r.reason, 160),"refused_at":r.refused_at})
            })
            .collect())
    }

    /// Human CLI only, after `quarantined` was shown. Discards exactly these ids while they
    /// are still refused; waiting writes and rows refused later are left alone. Retired
    /// writes are never sent.
    pub fn retire_quarantined(&mut self, ids: &[i64]) -> Result<usize, &'static str> {
        let held = state::PrivateState::open(&self.dir)?;
        let library = self.ready(&held)?;
        let refused = library
            .outbox_refused()
            .map_err(|_| "library_unavailable")?;
        let chosen: Vec<i64> = refused
            .iter()
            .map(|r| r.change.id)
            .filter(|id| ids.contains(id))
            .collect();
        library
            .atomically(|library| -> quince_core::Result<()> {
                for id in &chosen {
                    library.outbox_discard(*id)?;
                    library.set_state(&format!("mcp.authorization.{id}"), "")?;
                }
                Ok(())
            })
            .map_err(|_| "library_unavailable")?;
        Ok(chosen.len())
    }

    /// Starts even while another process holds the directory lock, for example during its
    /// sync. Setup is then deferred, and each call reports `state_busy_retry` until the lock
    /// is free.
    pub fn open(dir: &Path) -> Result<Self, &'static str> {
        match state::PrivateState::open(dir) {
            Ok(held) => Ok(Self {
                library: Some(setup(&held.path)?),
                dir: held.path.clone(),
                initialized: false,
                forms: false,
                pending: None,
                grant: None,
            }),
            Err("state_busy_retry") => Ok(Self {
                library: None,
                dir: std::path::absolute(dir).map_err(|_| "state_unavailable")?,
                initialized: false,
                forms: false,
                pending: None,
                grant: None,
            }),
            Err(error) => Err(error),
        }
    }

    /// Caller holds the directory lock through `held`.
    fn ready(&mut self, held: &state::PrivateState) -> Result<&mut Library, &'static str> {
        if self.library.is_none() {
            self.library = Some(setup(&held.path)?);
            self.dir = held.path.clone();
        }
        self.library.as_mut().ok_or("state_unavailable")
    }

    pub async fn refresh(&mut self) -> Result<Value, &'static str> {
        self.call("sync", json!({})).await
    }

    pub async fn handle(&mut self, request: Value) -> Option<Value> {
        if bounded_value(&request, MAX_FRAME_BYTES).is_err() {
            return Some(tool_reply(Value::Null, Err("operation_too_large")));
        }
        if request["method"] == "notifications/cancelled" {
            if self
                .pending
                .as_ref()
                .is_some_and(|p| p.request["id"] == request["params"]["requestId"])
            {
                let pending = self.pending.take().unwrap();
                return Some(tool_reply(
                    pending.request["id"].clone(),
                    Err("approval_cancelled"),
                ));
            }
            return None;
        }
        if request.get("method").is_none()
            && (request.get("result").is_some() || request.get("error").is_some())
        {
            if !self.pending.as_ref().is_some_and(|p| request["id"] == p.id) {
                return None;
            }
            let pending = self.pending.take().unwrap();
            let accepted =
                accepts_confirmation(&request) && std::time::Instant::now() < pending.deadline;
            if !accepted {
                return Some(tool_reply(
                    pending.request["id"].clone(),
                    Err("approval_denied"),
                ));
            }
            if pending.binding.preview_read {
                return Some(
                    match self.prepare_consent(&pending.request["params"], Some(&pending.binding)) {
                        Ok(Some(binding)) => self.consent_form(pending.request, binding),
                        _ => tool_reply(
                            pending.request["id"].clone(),
                            Err("approval_policy_changed"),
                        ),
                    },
                );
            }
            self.grant = Some(pending.binding);
            let params = &pending.request["params"];
            let result = self
                .call(
                    params["name"].as_str().unwrap_or(""),
                    params["arguments"].clone(),
                )
                .await;
            self.grant = None;
            return Some(tool_reply(pending.request["id"].clone(), result));
        }
        // Batches and other non-object messages are not supported; say so instead of dropping them.
        if !request.is_object() {
            return Some(
                json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request: batches are not supported"}}),
            );
        }
        // Responses belong to server-originated RPCs, never to the tool dispatcher.
        // Pure responses were handled above. Discard ambiguous envelopes carrying
        // both a method and a result/error instead of dispatching their method.
        if request.get("result").is_some() || request.get("error").is_some() {
            return None;
        }
        let id = request.get("id")?.clone();
        if !id.is_string() && !id.is_i64() && !id.is_u64() {
            return Some(
                json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid request ID"}}),
            );
        }
        let result = match request.get("method").and_then(Value::as_str) {
            Some("initialize") => {
                if self.initialized {
                    return Some(tool_reply(id, Err("already_initialized")));
                }
                self.initialized = true;
                let version = request["params"]["protocolVersion"]
                    .as_str()
                    .unwrap_or("2025-03-26");
                let elicitation = &request["params"]["capabilities"]["elicitation"];
                self.forms = version == "2025-11-25"
                    && elicitation.as_object().is_some_and(|c| {
                        c.is_empty() || c.get("form").is_some_and(Value::is_object)
                    });
                let version = if version == "2025-11-25" {
                    version
                } else {
                    "2025-03-26"
                };
                let mut server_info =
                    json!({"name":"skykeep-mcp","version":env!("CARGO_PKG_VERSION")});
                // Implementation.title exists only from protocol 2025-06-18 on.
                if version == "2025-11-25" {
                    server_info["title"] = json!(SERVER_TITLE);
                }
                Ok(
                    json!({"protocolVersion":version,"capabilities":{"tools":{"listChanged":false}},"serverInfo":server_info,"instructions":SERVER_INSTRUCTIONS}),
                )
            }
            Some("ping") => Ok(json!({})),
            Some("tools/list") if self.initialized => Ok(json!({"tools":tools()})),
            Some("tools/call") if self.initialized => {
                if bounded_value(&request["params"], MAX_ARGUMENT_BYTES).is_err() {
                    return Some(tool_reply(id, Err("operation_too_large")));
                }
                let params = request.get("params").cloned().unwrap_or(Value::Null);
                if self.pending.is_some()
                    && !["auth_status", "sync_status"]
                        .contains(&params["name"].as_str().unwrap_or(""))
                {
                    return Some(tool_reply(id, Err("approval_pending")));
                }
                match self.prepare_consent(&params, None) {
                    Ok(Some(binding)) => {
                        if !self.forms {
                            return Some(tool_reply(id, Err("approval_requires_form_client")));
                        }
                        return Some(self.consent_form(request, binding));
                    }
                    Err(error) => return Some(tool_reply(id, Err(error))),
                    Ok(None) => {}
                }
                let result = self
                    .call(
                        params["name"].as_str().unwrap_or(""),
                        params.get("arguments").cloned().unwrap_or(json!({})),
                    )
                    .await;
                let (value, failed) = match result {
                    Ok(value) => (value, false),
                    Err(error) => (json!({"error":error}), true),
                };
                Ok(json!({"content":[{"type":"text","text":value.to_string()}],"isError":failed}))
            }
            _ => Err((-32601, "Method not found")),
        };
        Some(match result {
            Ok(result) => json!({"jsonrpc":"2.0","id":id,"result":result}),
            Err((code, message)) => {
                json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
            }
        })
    }

    /// Trusted local CLI only. No MCP method calls this function.
    pub fn approval_details(&self, id: &str) -> Result<String, &'static str> {
        uuid::Uuid::parse_str(id).map_err(|_| "invalid_request_id")?;
        self.library
            .as_ref()
            .ok_or("state_busy_retry")?
            .state(&format!("mcp.approval.{id}"))
            .map_err(|_| "library_unavailable")?
            .filter(|s| !s.is_empty())
            .ok_or("approval_not_found")
    }

    pub fn approve(&mut self, id: &str) -> Result<Value, &'static str> {
        let held = state::PrivateState::open(&self.dir)?;
        if policy(self.ready(&held)?, &held.path)?.is_some() {
            return Err("legacy_approval_quarantined");
        }
        uuid::Uuid::parse_str(id).map_err(|_| "invalid_request_id")?;
        let key = format!("mcp.approval.{id}");
        self.ready(&held)?
            .atomically(|library| {
                let raw = library.state(&key)?.ok_or_else(|| {
                    quince_core::Error::Io(std::io::Error::other("approval_not_found"))
                })?;
                let value: Value = serde_json::from_str(&raw).map_err(|_| {
                    quince_core::Error::Io(std::io::Error::other("approval_not_found"))
                })?;
                if value["account"] != json!(library.state(ACCOUNT_KEY)?) {
                    return Err(quince_core::Error::Io(std::io::Error::other(
                        "account_mismatch",
                    )));
                }
                let result = match value["tool"].as_str() {
                    Some("notes_write") => serde_json::from_value(value["args"].clone())
                        .map_err(|_| "invalid_arguments")
                        .and_then(|args| enqueue_note(library, args)),
                    Some("reminders_write") => serde_json::from_value(value["args"].clone())
                        .map_err(|_| "invalid_arguments")
                        .and_then(|args| enqueue_reminder(library, args)),
                    _ => Err("invalid_tool"),
                }
                .map_err(|e| quince_core::Error::Io(std::io::Error::other(e)))?;
                library.set_state(&key, "")?;
                Ok(result)
            })
            .map_err(|_| "approval_refused")
    }

    async fn call(&mut self, name: &str, args: Value) -> Result<Value, &'static str> {
        let grant = self.grant.take();
        let held = state::PrivateState::open(&self.dir)?;
        let dir = held.path.clone();
        let library = self.ready(&held)?;
        let configured = policy(library, &dir)?;
        if let Some(ref grant) = grant {
            let mut current = configured
                .as_ref()
                .map(|(_, b)| b.clone())
                .ok_or("approval_policy_changed")?;
            current.identity = directory_identity(&dir)?;
            let mut expected = grant.clone();
            expected.snapshot = None;
            if current != expected {
                return Err("approval_policy_changed");
            }
            if grant.snapshot.is_some() {
                current.snapshot = Some(resolved_snapshot(library, name, &args)?);
            }
            if grant != &current {
                return Err("approval_policy_changed");
            }
        }
        if let Some((ref p, ref binding)) = configured {
            if needs_consent(&p.mode, name)? {
                let mut binding = binding.clone();
                binding.identity = directory_identity(&dir)?;
                if name.ends_with("_write") && args["action"] != "create" {
                    binding.snapshot = Some(resolved_snapshot(library, name, &args)?);
                }
                if grant.as_ref() != Some(&binding) {
                    return Err("approval_required_or_stale");
                }
            }
        } else if grant.is_some() {
            return Err("approval_policy_changed");
        }
        match name {
            "sync" => {
                let _: Empty = serde_json::from_value(args).map_err(|_| "invalid_arguments")?;
                if library
                    .state(ACCOUNT_KEY)
                    .map_err(|_| "library_unavailable")?
                    .is_none()
                {
                    return Err("login_required");
                }
                sync::run_authorized(&dir, grant.is_some()).await
            }
            "contacts_list" => contacts::list(library, args),
            "contacts_search" => contacts::search(library, args),
            "contacts_get" => contacts::get(library, args),
            "contacts_refresh" => {
                contacts::validate(name, &args)?;
                if library
                    .state(ACCOUNT_KEY)
                    .map_err(|_| "library_unavailable")?
                    .is_none()
                {
                    return Err("login_required");
                }
                contacts::refresh(&dir, grant.is_some()).await
            }
            "calendar_calendars" => calendar::calendars(library, args),
            "calendar_events" => calendar::events(library, args),
            "calendar_search" => calendar::search(library, args),
            "calendar_get" => calendar::get(library, args),
            "calendar_refresh" => {
                calendar::validate(name, &args)?;
                if library
                    .state(ACCOUNT_KEY)
                    .map_err(|_| "library_unavailable")?
                    .is_none()
                {
                    return Err("login_required");
                }
                calendar::refresh(&dir, grant.is_some(), args).await
            }
            "photos_albums" => photos::albums(library, args),
            "photos_list" => photos::list(library, args),
            "photos_search" => photos::search(library, args),
            "photos_get" => photos::get(library, args),
            "photos_refresh" => {
                photos::validate(name, &args)?;
                if library
                    .state(ACCOUNT_KEY)
                    .map_err(|_| "library_unavailable")?
                    .is_none()
                {
                    return Err("login_required");
                }
                photos::refresh(&dir, grant.is_some()).await
            }
            "drive_list" => drive::list(library, args),
            "drive_get" => drive::get(library, args),
            "drive_search" => drive::search(library, args),
            "drive_refresh" => {
                drive::validate(name, &args)?;
                if library
                    .state(ACCOUNT_KEY)
                    .map_err(|_| "library_unavailable")?
                    .is_none()
                {
                    return Err("login_required");
                }
                drive::refresh(&dir, grant.is_some(), args).await
            }
            "sync_status" => {
                let _: Empty = serde_json::from_value(args).map_err(|_| "invalid_arguments")?;
                let health = library.sync_health().map_err(|_| "library_unavailable")?;
                let refused = library
                    .outbox_refused_brief()
                    .map_err(|_| "library_unavailable")?;
                let mut services = Vec::new();
                for service in ["notes", "reminders"] {
                    let h = health.iter().find(|h| h.service == service);
                    let mine: Vec<_> = refused.iter().filter(|r| r.service == service).collect();
                    let pending = library
                        .outbox_pending(service)
                        .map_err(|_| "library_unavailable")?
                        .len();
                    // Upstream error text may hold HTTP bodies; report only that one exists.
                    services.push(
                        json!({"service":service,"last_synced_at":h.and_then(|h| h.last_synced_at),
                        "last_error":h.is_some_and(|h| h.last_error.is_some()),"pending":pending,
                        "refused":mine.len(),
                        // Identifiers and reason codes only, newest last, so the user can be
                        // told which approved write will not be sent and why.
                        "refused_recent":mine[mine.len().saturating_sub(20)..].iter().map(|r| sync::refused_view(r)).collect::<Vec<_>>()}),
                    );
                }
                Ok(json!({"source":"local_cache","services":services,"remote_verified":false}))
            }
            "auth_status" => {
                let _: Empty = serde_json::from_value(args).map_err(|_| "invalid_arguments")?;
                let bound = library
                    .state(ACCOUNT_KEY)
                    .map_err(|_| "library_unavailable")?
                    .is_some();
                Ok(
                    json!({"status":if bound {"session_unverified"} else {"login_required"},"instructions":"Run skykeep-mcp login --state-dir PRIVATE_DIRECTORY in your own trusted terminal, outside agent/tool capture. Never send passwords or codes to MCP or chat.","session_checked":false}),
                )
            }
            "reminders_get" => {
                let args: Get = serde_json::from_value(args).map_err(|_| "invalid_arguments")?;
                let item = library
                    .reminder(&args.guid)
                    .map_err(|_| "library_unavailable")?
                    .ok_or("not_found")?;
                let detail = library
                    .reminder_detail(&args.guid)
                    .map_err(|_| "library_unavailable")?;
                Ok(
                    json!({"source":"local_cache","item":item,"detail":detail,"complete_representation":false}),
                )
            }
            "reminders_lists" => {
                let args: Page = serde_json::from_value(args).map_err(|_| "invalid_arguments")?;
                page(
                    library
                        .reminder_lists()
                        .map_err(|_| "library_unavailable")?,
                    args.into(),
                )
            }
            "notes_folders" => {
                let args: Page = serde_json::from_value(args).map_err(|_| "invalid_arguments")?;
                page(
                    library.note_folders().map_err(|_| "library_unavailable")?,
                    args.into(),
                )
            }
            "notes_get" => {
                let args: Get = serde_json::from_value(args).map_err(|_| "invalid_arguments")?;
                let mut item = library
                    .note(&args.guid)
                    .map_err(|_| "library_unavailable")?
                    .ok_or("not_found")?;
                item.body = library
                    .note_body(&args.guid)
                    .map_err(|_| "library_unavailable")?;
                item.runs = library
                    .note_runs(&args.guid)
                    .map_err(|_| "library_unavailable")?;
                let runs: Option<Value> = item
                    .runs
                    .as_deref()
                    .map(serde_json::from_str)
                    .transpose()
                    .map_err(|_| "invalid_cached_runs")?;
                Ok(
                    json!({"source":"local_cache","item":item,"runs":runs,"complete_representation":false}),
                )
            }
            "reminders_search" => {
                let args: Search = serde_json::from_value(args).map_err(|_| "invalid_arguments")?;
                page(
                    library
                        .search_reminders(&args.query)
                        .map_err(|_| "search_unavailable")?,
                    List {
                        offset: args.offset,
                        limit: args.limit,
                        parent: None,
                    },
                )
            }
            "notes_search" => {
                let args: Search = serde_json::from_value(args).map_err(|_| "invalid_arguments")?;
                page(
                    library
                        .search_notes(&args.query)
                        .map_err(|_| "search_unavailable")?,
                    List {
                        offset: args.offset,
                        limit: args.limit,
                        parent: None,
                    },
                )
            }
            "notes_list" => {
                let args: List = serde_json::from_value(args).map_err(|_| "invalid_arguments")?;
                let items = library
                    .notes_in(args.parent.as_deref())
                    .map_err(|_| "library_unavailable")?;
                page(items, args)
            }
            "reminders_list" => {
                let args: List = serde_json::from_value(args).map_err(|_| "invalid_arguments")?;
                let parent = args.parent.as_deref().ok_or("parent_required")?;
                let items = library
                    .reminders_in(parent, true)
                    .map_err(|_| "library_unavailable")?;
                page(items, args)
            }
            "reminders_write" => {
                let args: ReminderWrite =
                    serde_json::from_value(args).map_err(|_| "invalid_arguments")?;
                if library
                    .state(ACCOUNT_KEY)
                    .map_err(|_| "library_unavailable")?
                    .is_none()
                {
                    return Err("login_required");
                }
                if configured.is_none()
                    && (matches!(args, ReminderWrite::Delete { .. })
                        || library
                            .state("mcp.require_write_approval")
                            .map_err(|_| "library_unavailable")?
                            .as_deref()
                            == Some("true"))
                {
                    let id = uuid::Uuid::new_v4().to_string();
                    let proposal = json!({"tool":name,"args":args,"account":library.state(ACCOUNT_KEY).map_err(|_| "library_unavailable")?});
                    library
                        .set_state(&format!("mcp.approval.{id}"), &proposal.to_string())
                        .map_err(|_| "library_unavailable")?;
                    return Ok(
                        json!({"status":"approval_required","request_id":id,"remote_verified":false}),
                    );
                }
                if configured.is_some() {
                    authorized_enqueue(library, &dir, |l| enqueue_reminder(l, args))
                } else {
                    enqueue_reminder(library, args)
                }
            }
            "notes_write" => {
                let args: NoteWrite =
                    serde_json::from_value(args).map_err(|_| "invalid_arguments")?;
                if library
                    .state(ACCOUNT_KEY)
                    .map_err(|_| "library_unavailable")?
                    .is_none()
                {
                    return Err("login_required");
                }
                if configured.is_none()
                    && (args.is_destructive()
                        || library
                            .state("mcp.require_write_approval")
                            .map_err(|_| "library_unavailable")?
                            .as_deref()
                            == Some("true"))
                {
                    let id = uuid::Uuid::new_v4().to_string();
                    let proposal = json!({"tool":name,"args":args,"account":library.state(ACCOUNT_KEY).map_err(|_| "library_unavailable")?});
                    library
                        .set_state(&format!("mcp.approval.{id}"), &proposal.to_string())
                        .map_err(|_| "library_unavailable")?;
                    return Ok(
                        json!({"status":"approval_required","request_id":id,"remote_verified":false}),
                    );
                }
                if configured.is_some() {
                    authorized_enqueue(library, &dir, |l| enqueue_note(l, args))
                } else {
                    enqueue_note(library, args)
                }
            }
            _ => Err("unknown_tool"),
        }
    }
}

fn authorized_enqueue(
    library: &mut Library,
    dir: &Path,
    enqueue: impl FnOnce(&mut Library) -> Result<Value, &'static str>,
) -> Result<Value, &'static str> {
    if library
        .outbox_refused_count()
        .map_err(|_| "library_unavailable")?
        >= sync::MAX_REFUSED
    {
        return Err("quarantine_full_retire_in_terminal");
    }
    let before = sync::pending_operations(library)?;
    for p in &before {
        sync::authorized_payload(library, dir, p)?;
    }
    let exists = |library: &Library, p: &quince_core::outbox::Pending| {
        if p.service == "notes" {
            library.note(&p.record).map(|n| n.is_some())
        } else {
            library.reminder(&p.record).map(|r| r.is_some())
        }
    };
    // Writes whose full grant, context included, is current right now. Only this approved
    // write can change their context before the transaction ends, so they may be re-bound.
    let mut current = Vec::new();
    let mut present = Vec::new();
    for p in &before {
        if sync::authorized(library, dir, p).is_ok() {
            current.push(p.id);
        }
        if exists(library, p).map_err(|_| "library_unavailable")? {
            present.push(p.id);
        }
    }
    library
        .atomically(|library| -> quince_core::Result<Value> {
            let convert = |error| quince_core::Error::Io(std::io::Error::other(error));
            let result = enqueue(library).map_err(convert)?;
            let after = sync::pending_operations(library).map_err(convert)?;
            for p in &after {
                let old = before.iter().find(|old| old.id == p.id);
                if old.is_some()
                    && p.kind != "delete"
                    && present.contains(&p.id)
                    && !exists(library, p)?
                {
                    // This approved deletion removed the item, or its parent took it along.
                    // Older writes to it are superseded, never sent with an invented context.
                    library.outbox_refuse(p.id, "superseded_by_approved_deletion")?;
                    library.set_state(&format!("mcp.authorization.{}", p.id), "")?;
                    continue;
                }
                // A new operation from this write, or any queued operation on the record
                // the human just reviewed (the preview lists them), takes a fresh grant. An
                // unchanged write elsewhere is re-bound only if its grant was current a
                // moment ago, so only this approved write moved its context. A changed
                // payload on another record is never re-authorized; sync quarantines it.
                if old.is_none()
                    || result["guid"] == p.record
                    || (old == Some(p) && current.contains(&p.id))
                {
                    sync::record_authorization(library, p).map_err(convert)?;
                }
            }
            for p in &before {
                if !after.iter().any(|new| new.id == p.id) {
                    library.set_state(&format!("mcp.authorization.{}", p.id), "")?;
                }
            }
            Ok(result)
        })
        .map_err(|_| "mutation_refused")
}

/// One-time setup under the directory lock: persistent document writer and private modes.
fn setup(path: &Path) -> Result<Library, &'static str> {
    let mut library = Library::open(path).map_err(|_| "library_unavailable")?;
    let id = library
        .state("documents.writer")
        .map_err(|_| "library_unavailable")?
        .and_then(|id| uuid::Uuid::parse_str(&id).ok())
        .unwrap_or_else(uuid::Uuid::new_v4);
    library
        .set_state("documents.writer", &id.to_string())
        .map_err(|_| "library_unavailable")?;
    quince_icloud::topotext::set_writer(*id.as_bytes());
    use std::os::unix::fs::PermissionsExt;
    for file in std::fs::read_dir(path).map_err(|_| "state_unavailable")? {
        let file = file.map_err(|_| "state_unavailable")?;
        if file.file_type().map_err(|_| "state_unavailable")?.is_file() {
            std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
                .map_err(|_| "state_unavailable")?;
        }
    }
    Ok(library)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Get {
    guid: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Search {
    query: String,
    #[serde(default)]
    offset: usize,
    limit: Option<usize>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct List {
    parent: Option<String>,
    #[serde(default)]
    offset: usize,
    limit: Option<usize>,
}

/// Arguments of list tools that have no parent.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    #[serde(default)]
    offset: usize,
    limit: Option<usize>,
}

impl From<Page> for List {
    fn from(p: Page) -> Self {
        List {
            parent: None,
            offset: p.offset,
            limit: p.limit,
        }
    }
}

fn page<T: serde::Serialize>(items: Vec<T>, args: List) -> Result<Value, &'static str> {
    let total = items.len();
    let limit = args.limit.unwrap_or(100).clamp(1, 1000);
    let items: Vec<_> = items.into_iter().skip(args.offset).take(limit).collect();
    let next = args.offset.saturating_add(items.len());
    Ok(
        json!({"source":"local_cache","items":items,"total":total,"next_offset":(next < total).then_some(next),"complete_representation":false}),
    )
}

#[derive(Deserialize, serde::Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum NoteWrite {
    Move {
        guid: String,
        folder_guid: Option<String>,
        base_etag: Option<String>,
    },
    Pin {
        guid: String,
        pinned: bool,
        base_etag: Option<String>,
    },
    Save {
        guid: String,
        body: String,
        base_etag: Option<String>,
        runs: Option<Vec<quince_icloud::ckdocument::Run>>,
    },
    Create {
        body: String,
        folder_guid: Option<String>,
    },
    Delete {
        guid: String,
        base_etag: Option<String>,
    },
}

impl NoteWrite {
    /// Legacy writes that remove content need terminal approval. Upstream deletes a note by moving
    /// it into the trash folder, so such a move is a deletion; so is erasing the whole body.
    fn is_destructive(&self) -> bool {
        match self {
            NoteWrite::Delete { .. } => true,
            NoteWrite::Save { body, .. } => body.trim().is_empty(),
            NoteWrite::Move { folder_guid, .. } => {
                folder_guid.as_deref() == Some(quince_core::notes::TRASH_FOLDER)
            }
            _ => false,
        }
    }
}

/// `None` files a note in the default folder; a named folder must be in the synced cache.
fn require_folder(library: &Library, folder: Option<&str>) -> Result<(), &'static str> {
    let Some(folder) = folder else { return Ok(()) };
    if library
        .note_folders()
        .map_err(|_| "library_unavailable")?
        .iter()
        .any(|f| f.guid == folder)
    {
        Ok(())
    } else {
        Err("folder_not_found")
    }
}

fn enqueue_note(library: &mut Library, args: NoteWrite) -> Result<Value, &'static str> {
    match args {
        NoteWrite::Move {
            guid,
            folder_guid,
            base_etag,
        } => {
            let note = library
                .note(&guid)
                .map_err(|_| "library_unavailable")?
                .ok_or("not_found")?;
            if note.etag != base_etag {
                return Err("conflict");
            }
            if note.locked || !note.editable {
                return Err("read_only_note");
            }
            require_folder(library, folder_guid.as_deref())?;
            quince_sync::notes::record_note_move(library, &guid, folder_guid)
                .map_err(|_| "write_refused")?;
            Ok(json!({"guid":guid,"status":"queued","remote_verified":false}))
        }
        NoteWrite::Pin {
            guid,
            pinned,
            base_etag,
        } => {
            let note = library
                .note(&guid)
                .map_err(|_| "library_unavailable")?
                .ok_or("not_found")?;
            if note.etag != base_etag {
                return Err("conflict");
            }
            if note.locked || !note.editable {
                return Err("read_only_note");
            }
            quince_sync::notes::record_note_pin(library, &guid, pinned)
                .map_err(|_| "write_refused")?;
            Ok(json!({"guid":guid,"status":"queued","remote_verified":false}))
        }
        NoteWrite::Save {
            guid,
            body,
            base_etag,
            runs,
        } => {
            let note = library
                .note(&guid)
                .map_err(|_| "library_unavailable")?
                .ok_or("not_found")?;
            if note.etag != base_etag {
                return Err("conflict");
            }
            if note.locked || !note.editable {
                return Err("read_only_note");
            }
            let base = library
                .note_body(&guid)
                .map_err(|_| "library_unavailable")?
                .ok_or("note_body_unavailable_sync_first")?;
            let base_runs = library
                .note_runs(&guid)
                .map_err(|_| "library_unavailable")?
                .map(|raw| serde_json::from_str(&raw).map_err(|_| "invalid_cached_runs"))
                .transpose()?;
            quince_sync::notes::record_note_save(
                library,
                &guid,
                &body,
                Some(base),
                runs,
                base_runs,
            )
            .map_err(|_| "write_refused")?;
            Ok(json!({"guid":guid,"status":"queued","remote_verified":false}))
        }
        NoteWrite::Delete { guid, base_etag } => {
            let note = library
                .note(&guid)
                .map_err(|_| "library_unavailable")?
                .ok_or("not_found")?;
            if note.etag != base_etag {
                return Err("conflict");
            }
            if note.locked || !note.editable {
                return Err("read_only_note");
            }
            quince_sync::notes::record_note_delete(library, &note).map_err(|_| "write_refused")?;
            Ok(json!({"guid":guid,"status":"queued","remote_verified":false}))
        }
        NoteWrite::Create { body, folder_guid } => {
            if folder_guid.as_deref() == Some(quince_core::notes::TRASH_FOLDER) {
                return Err("folder_not_writable");
            }
            require_folder(library, folder_guid.as_deref())?;
            let guid = quince_sync::notes::record_note_create(library, folder_guid, &body)
                .map_err(|_| "write_refused")?;
            Ok(json!({"guid":guid,"status":"queued","remote_verified":false}))
        }
    }
}

#[derive(Deserialize, serde::Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum ReminderWrite {
    Delete {
        guid: String,
    },
    Tick {
        guid: String,
        done: bool,
    },
    Edit {
        guid: String,
        patch: Value,
    },
    Create {
        list_guid: String,
        title: String,
        due_at: Option<i64>,
        all_day: Option<bool>,
        flagged: Option<bool>,
        // Left out of the approval record when unset, so a plain create reads as before.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        repeat: Option<RepeatArg>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        due_time_alert: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        early_alert: Option<EarlyAlertArg>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timezone: Option<String>,
    },
}

#[derive(Deserialize, serde::Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RepeatFrequency {
    Daily,
}

/// A new reminder's repeat: daily, until the end of `until` (`YYYY-MM-DD`) or for ever.
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RepeatArg {
    frequency: RepeatFrequency,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    until: Option<String>,
}

#[derive(Deserialize, serde::Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AlertUnit {
    Minutes,
    Hours,
    Days,
    Weeks,
    Months,
}

impl AlertUnit {
    /// Apple's `dueDateDeltaUnit`.
    fn apple(self) -> i64 {
        match self {
            AlertUnit::Minutes => 0,
            AlertUnit::Hours => 1,
            AlertUnit::Days => 2,
            AlertUnit::Weeks => 3,
            AlertUnit::Months => 4,
        }
    }
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct EarlyAlertArg {
    amount: i64,
    unit: AlertUnit,
}

/// The largest early-alert amount Apple's writer takes.
const MOST_EARLY_ALERT: i64 = 10_000;

/// A create's repeat and alerts, checked against its date and turned into what is queued, with
/// every record id chosen now. Refused with a code naming the first combination that does
/// not work; nothing is queued then.
struct CreateOptions {
    timezone: Option<String>,
    repeat: Option<quince_sync::reminders::CreateRepeat>,
    alarm: Option<quince_sync::reminders::CreateAlarm>,
    early_alert: Option<quince_sync::reminders::CreateEarlyAlert>,
}

fn part_id() -> String {
    uuid::Uuid::new_v4().to_string().to_uppercase()
}

#[allow(clippy::too_many_arguments)]
fn create_options(
    library: &Library,
    due_at: Option<i64>,
    all_day: Option<bool>,
    repeat: Option<RepeatArg>,
    due_time_alert: Option<bool>,
    early_alert: Option<EarlyAlertArg>,
    timezone: Option<String>,
) -> Result<CreateOptions, &'static str> {
    use quince_sync::reminders as r;
    let all_day = all_day.unwrap_or(false) && due_at.is_some();
    let timed = due_at.is_some() && !all_day;
    let timezone = match timezone {
        Some(name) => Some(r::iana_zone(&name).ok_or("unknown_timezone")?),
        None => None,
    };
    if timezone.is_some() && !timed {
        return Err("timezone_requires_timed_due_at");
    }
    // A timed create with options is kept in one zone from here on: chosen now, queued, and
    // used for its repeat's end and by every later send, whatever this computer's zone becomes.
    let any_option = repeat.is_some() || due_time_alert == Some(true) || early_alert.is_some();
    let timezone = match timezone {
        None if timed && any_option => Some(r::system_zone()),
        other => other,
    };
    let alarm = if due_time_alert == Some(true) {
        if due_at.is_none() {
            return Err("due_time_alert_requires_due_at");
        }
        if all_day {
            return Err("all_day_cannot_have_timed_alert");
        }
        Some(r::CreateAlarm {
            alarm_id: part_id(),
            trigger_id: part_id(),
        })
    } else {
        None
    };
    let early_alert = match early_alert {
        None => None,
        Some(alert) => {
            if !(1..=MOST_EARLY_ALERT).contains(&alert.amount) {
                return Err("invalid_early_alert");
            }
            if due_at.is_none() {
                return Err("early_alert_requires_due_at");
            }
            if all_day {
                return Err("all_day_cannot_have_timed_alert");
            }
            let account = library
                .early_alert_account()
                .map_err(|_| "library_unavailable")?
                .ok_or("early_alert_account_unavailable")?;
            Some(r::CreateEarlyAlert {
                count: alert.amount,
                unit: alert.unit.apple(),
                account,
                id: part_id(),
            })
        }
    };
    let repeat = match repeat {
        None => None,
        Some(repeat) => {
            let due = due_at.ok_or("repeat_requires_due_at")?;
            let RepeatFrequency::Daily = repeat.frequency;
            let end_at = match repeat.until {
                None => None,
                Some(until) => {
                    // An all-day date is that day's midnight in UTC, so its last day is read
                    // there; a timed one in the zone it rings in.
                    let zone = if all_day {
                        "UTC".to_string()
                    } else {
                        timezone.clone().unwrap_or_else(r::system_zone)
                    };
                    let end = r::end_of_day(&until, &zone).ok_or("invalid_repeat_end")?;
                    if end < due {
                        return Err("repeat_end_before_due");
                    }
                    Some(end)
                }
            };
            Some(r::CreateRepeat {
                frequency: 0,
                interval: 1,
                end_at,
                rule_id: part_id(),
            })
        }
    };
    Ok(CreateOptions {
        timezone,
        repeat,
        alarm,
        early_alert,
    })
}

/// The options a queued create carries, as the reply names them: no record ids or account id.
fn options_view(c: &quince_sync::reminders::Create) -> Value {
    let unit = |u: i64| match u {
        0 => "minutes",
        1 => "hours",
        2 => "days",
        3 => "weeks",
        _ => "months",
    };
    json!({
        "timezone": c.timezone,
        "repeat": c.repeat.as_ref().map(|r| json!({"frequency":"daily","ends_at":r.end_at})),
        "due_time_alert": c.alarm.is_some(),
        "early_alert": c.early_alert.as_ref().map(|e| json!({"amount":e.count,"unit":unit(e.unit)})),
    })
}

fn enqueue_reminder(library: &mut Library, args: ReminderWrite) -> Result<Value, &'static str> {
    match args {
        ReminderWrite::Delete { guid } => {
            let reminder = library
                .reminder(&guid)
                .map_err(|_| "library_unavailable")?
                .ok_or("not_found")?;
            quince_sync::reminders::record_reminder_delete(library, &reminder)
                .map_err(|_| "write_refused")?;
            Ok(json!({"guid":guid,"status":"queued","remote_verified":false}))
        }
        ReminderWrite::Tick { guid, done } => {
            let reminder = library
                .reminder(&guid)
                .map_err(|_| "library_unavailable")?
                .ok_or("not_found")?;
            quince_sync::reminders::record_reminder_tick(
                library,
                &reminder,
                done,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| "clock_unavailable")?
                    .as_secs() as i64,
            )
            .map_err(|_| "write_refused")?;
            Ok(json!({"guid":guid,"status":"queued","remote_verified":false}))
        }
        ReminderWrite::Edit { guid, patch } => {
            let reminder = library
                .reminder(&guid)
                .map_err(|_| "library_unavailable")?
                .ok_or("not_found")?;
            let mut fields = patch.as_object().cloned().ok_or("invalid_patch")?;
            if fields.is_empty()
                || fields.keys().any(|k| {
                    ![
                        "title",
                        "notes",
                        "due_at",
                        "all_day",
                        "flagged",
                        "completed",
                        "priority",
                        "list_guid",
                        "parent_guid",
                    ]
                    .contains(&k.as_str())
                })
            {
                return Err("invalid_patch");
            }
            fields.insert("from_list".into(), json!(reminder.list_guid));
            let e: quince_sync::reminders::Edit =
                serde_json::from_value(Value::Object(fields)).map_err(|_| "invalid_patch")?;
            let edit = quince_icloud::reminders::ReminderEdit {
                title: e.title,
                notes: e.notes,
                due_at: e.due_at,
                all_day: e.all_day,
                flagged: e.flagged,
                completed: e.completed,
                priority: e.priority,
                list_guid: e.list_guid,
                parent_guid: e.parent_guid,
                timezone: None,
            };
            quince_sync::reminders::record_reminder_edit(library, &reminder, &edit)
                .map_err(|_| "write_refused")?;
            Ok(json!({"guid":guid,"status":"queued","remote_verified":false}))
        }
        ReminderWrite::Create {
            list_guid,
            title,
            due_at,
            all_day,
            flagged,
            repeat,
            due_time_alert,
            early_alert,
            timezone,
        } => {
            if !library
                .reminder_lists()
                .map_err(|_| "library_unavailable")?
                .iter()
                .any(|l| l.guid == list_guid)
            {
                return Err("list_unavailable_or_read_only");
            }
            if title.trim().is_empty() {
                return Err("title_required");
            }
            let options = create_options(
                library,
                due_at,
                all_day,
                repeat,
                due_time_alert,
                early_alert,
                timezone,
            )?;
            let create = quince_sync::reminders::Create {
                list_guid,
                title,
                due_at,
                all_day,
                flagged,
                timezone: options.timezone,
                repeat: options.repeat,
                alarm: options.alarm,
                early_alert: options.early_alert,
            };
            let guid = quince_sync::reminders::record_reminder_create(library, &create)
                .map_err(|_| "write_refused")?;
            // Queued here only. `sync` says which queued writes CloudKit took; nothing reads
            // the repeat or alerts back from Apple, so remote_verified stays false.
            Ok(
                json!({"guid":guid,"status":"queued","queued":true,"cloudkit_accepted":false,"remote_verified":false,"options":options_view(&create)}),
            )
        }
    }
}

const SERVER_TITLE: &str =
    "Skykeep: Apple iCloud Notes, Reminders, Contacts, Calendar, Photos & iCloud Drive";
const SERVER_INSTRUCTIONS: &str = "Skykeep reads and changes the user's Apple iCloud Notes and Apple Reminders through a local synced cache, and reads the user's Apple iCloud Contacts, Apple iCloud Calendar and Apple iCloud Photos metadata (read-only), and Apple iCloud Drive folder listings and file details (read-only; no file contents). Reads return cached data. Contacts refresh only through contacts_refresh, Calendar only through calendar_refresh, Photos only through photos_refresh, and Drive one folder at a time through drive_refresh. Photos tools show the personal library's photo details, never the pictures, places or faces. Drive paths start with / and use the names Apple shows. Calendar dates are YYYY-MM-DD; pass the user's IANA time zone to calendar_events. Changes follow the configured approval mode and are queued until sync sends them. Sign-in happens only in the user's own terminal; never ask for Apple passwords or codes.";

fn tools() -> Vec<Value> {
    // (name, description, parent property, parent required)
    let lists = [
        (
            "notes_list",
            "List the user's Apple iCloud Notes from the local cache.",
            Some("Folder GUID; omit for all notes."),
            false,
        ),
        (
            "reminders_list",
            "List the user's Apple Reminders in one list from the local cache.",
            Some("Reminder list GUID."),
            true,
        ),
        (
            "notes_folders",
            "List Apple iCloud Notes folders from the local cache.",
            None,
            false,
        ),
        (
            "reminders_lists",
            "List Apple Reminders lists from the local cache.",
            None,
            false,
        ),
    ];
    let mut tools: Vec<_> = lists.iter().map(|(name, description, parent, required)| {
        let mut properties = json!({"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":1000}});
        if let Some(description) = parent {
            properties["parent"] = json!({"type":"string","description":description});
        }
        let mut schema = json!({"type":"object","properties":properties,"additionalProperties":false});
        if *required {
            schema["required"] = json!(["parent"]);
        }
        json!({
            "name":name,"description":format!("{description} Sync requires an authenticated session."),
            "inputSchema":schema,
            "annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}
        })
    }).collect();
    for (name, kind) in [
        ("notes_search", "Apple iCloud Notes"),
        ("reminders_search", "Apple Reminders"),
    ] {
        tools.push(json!({"name":name,"description":format!("Search the user's {kind} in the local cache index."),"inputSchema":{"type":"object","properties":{"query":{"type":"string"},"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":1000}},"required":["query"],"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}}));
    }
    tools.push(json!({"name":"notes_write","description":"Queue a change to the user's Apple iCloud Notes (create, save, move, pin, delete). Follows the approval mode. Queued is not remote-verified.","inputSchema":{"type":"object","properties":{"action":{"enum":["create","save","move","pin","delete"]},"body":{"type":"string"},"pinned":{"type":"boolean"},"runs":{"type":["array","null"],"items":{"type":"object"}},"folder_guid":{"type":["string","null"]},"guid":{"type":"string"},"base_etag":{"type":["string","null"]}},"required":["action"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":true,"openWorldHint":true}}));
    tools.push(json!({"name":"reminders_write","description":"Queue a change to the user's Apple Reminders (create, edit, tick, delete). A create can also repeat daily and alert at or before its due time. Deletions need local terminal approval. Queued is not CloudKit-accepted; sync reports accepted writes. No field-level remote verification.","inputSchema":{"type":"object","properties":{"action":{"enum":["create","edit","tick","delete"]},"guid":{"type":"string"},"list_guid":{"type":"string"},"title":{"type":"string"},"due_at":{"type":["integer","null"]},"all_day":{"type":"boolean"},"flagged":{"type":"boolean"},"done":{"type":"boolean"},"patch":{"type":"object","description":"Supported fields: title, notes, due_at, all_day, flagged, completed, priority, list_guid, parent_guid. Absent leaves unchanged; null clears notes/due_at/parent_guid."},"repeat":{"type":"object","description":"Create only. Repeats daily from due_at, until the end of the given day or for ever. Needs due_at.","properties":{"frequency":{"enum":["daily"]},"until":{"type":"string","pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}$","description":"YYYY-MM-DD, the last day it repeats, read in timezone."}},"required":["frequency"],"additionalProperties":false},"due_time_alert":{"type":"boolean","description":"Create only. Alert at due_at. Needs a timed (not all-day) due_at."},"early_alert":{"type":"object","description":"Create only. Alert this long before due_at. Needs a timed due_at and an early alert already set on one of the user's reminders from an Apple device.","properties":{"amount":{"type":"integer","minimum":1,"maximum":10000},"unit":{"enum":["minutes","hours","days","weeks","months"]}},"required":["amount","unit"],"additionalProperties":false},"timezone":{"type":"string","maxLength":64,"description":"Create only. IANA zone the timed due_at and its alerts are kept in, such as Europe/Berlin. Default: this computer's zone."}},"required":["action"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":true,"openWorldHint":true}}));
    tools.push(json!({"name":"reminders_get","description":"Read one cached Apple Reminders item and its supported details. Not a complete archive.","inputSchema":{"type":"object","properties":{"guid":{"type":"string"}},"required":["guid"],"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}}));
    tools.push(json!({"name":"notes_get","description":"Read one cached Apple iCloud Notes note. Not a complete preservation archive.","inputSchema":{"type":"object","properties":{"guid":{"type":"string"}},"required":["guid"],"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}}));
    tools.push(json!({"name":"sync","description":"Refresh Apple iCloud Notes and Apple Reminders and send approved queued changes. Queued/sent is not field-level remote verification. Never opens a login prompt.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":true,"openWorldHint":true}}));
    tools.push(json!({"name":"sync_status","description":"Local sync state for Apple iCloud Notes and Reminders: last refresh, whether the last pass failed, pending and refused queued changes. No network access.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}}));
    let page = json!({"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":contacts::MAX_LIMIT,"default":25}});
    let read = json!({"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false});
    tools.push(json!({"name":"contacts_list","description":"List the user's Apple iCloud Contacts from the local cache, in name order, as summaries with emails and phones. Read-only; refresh with contacts_refresh.","inputSchema":{"type":"object","properties":page,"additionalProperties":false},"annotations":read}));
    let mut search = page.clone();
    search["query"] = json!({"type":"string","minLength":1,"maxLength":contacts::MAX_QUERY_BYTES,"description":"Words matched against names, company, details, emails, phones and other cached fields, ignoring case and accents. At most 256 UTF-8 bytes."});
    tools.push(json!({"name":"contacts_search","description":"Search the user's cached Apple iCloud Contacts by name, email, phone or other kept fields. Read-only.","inputSchema":{"type":"object","properties":search,"required":["query"],"additionalProperties":false},"annotations":read}));
    tools.push(json!({"name":"contacts_get","description":"Read one cached Apple iCloud Contacts card with its kept fields and lists. Not a complete card: photos, the original vCard and fields the cache does not keep are not included.","inputSchema":{"type":"object","properties":{"guid":{"type":"string","minLength":1,"maxLength":512,"description":"Contact GUID from contacts_list or contacts_search. At most 512 UTF-8 bytes."}},"required":["guid"],"additionalProperties":false},"annotations":read}));
    tools.push(json!({"name":"contacts_refresh","description":"Read the user's Apple iCloud Contacts from Apple into the local cache, replacing the cached copy. Never changes contacts at Apple and sends no queued changes. Never opens a login prompt.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true}}));
    let page = json!({"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":calendar::MAX_LIMIT,"default":25}});
    let day = |what: &str| json!({"type":"string","pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}$","description":what});
    let guid = json!({"type":"string","minLength":1,"maxLength":calendar::MAX_GUID_BYTES});
    tools.push(json!({"name":"calendar_calendars","description":"List the user's Apple iCloud Calendar calendars from the local cache, with which is the default and which are read-only. Read-only; refresh with calendar_refresh.","inputSchema":{"type":"object","properties":page,"additionalProperties":false},"annotations":read}));
    let mut range = page.clone();
    range["from"] = day("First day, YYYY-MM-DD, in timezone.");
    range["to"] = day(&format!(
        "Day after the last, YYYY-MM-DD (exclusive). At most {} days after from.",
        calendar::MAX_RANGE_DAYS
    ));
    range["timezone"] = json!({"type":"string","minLength":1,"maxLength":calendar::MAX_ZONE_BYTES,"description":"IANA time zone the days are read in, such as Europe/Berlin."});
    range["calendar_guid"] = guid.clone();
    tools.push(json!({"name":"calendar_events","description":"List the user's Apple iCloud Calendar events from the local cache that overlap a date range. All-day events are dates and floating events are clock times; timed events give UTC and zone times. Says whether the last calendar_refresh covered the range. Read-only.","inputSchema":{"type":"object","properties":range,"required":["from","to","timezone"],"additionalProperties":false},"annotations":read}));
    let mut search = page.clone();
    search["query"] = json!({"type":"string","minLength":1,"maxLength":calendar::MAX_QUERY_BYTES,"description":"Words matched against title, location and notes, ignoring case and accents. At most 256 UTF-8 bytes."});
    tools.push(json!({"name":"calendar_search","description":"Search the user's cached Apple iCloud Calendar events by title, location or notes. At most 300 matches nearest today are kept. Read-only.","inputSchema":{"type":"object","properties":search,"required":["query"],"additionalProperties":false},"annotations":read}));
    tools.push(json!({"name":"calendar_get","description":"Read one cached Apple iCloud Calendar event with its notes and calendar. Not a complete event: attendees, alerts, the repeat rule and status are not included.","inputSchema":{"type":"object","properties":{"guid":guid},"required":["guid"],"additionalProperties":false},"annotations":read}));
    tools.push(json!({"name":"calendar_refresh","description":format!("Read the user's Apple iCloud Calendar from Apple into the local cache over a window (default: last month to three months ahead; at most {} days). Never changes events at Apple, never answers invitations and sends no queued changes. Never opens a login prompt.", calendar::MAX_REFRESH_DAYS),"inputSchema":{"type":"object","properties":{"from":day("First day, YYYY-MM-DD (UTC)."),"to":day("Day after the last, YYYY-MM-DD (exclusive).")},"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true}}));
    let page = json!({"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":photos::MAX_LIMIT,"default":25}});
    let id = json!({"type":"string","minLength":1,"maxLength":photos::MAX_ID_BYTES});
    tools.push(json!({"name":"photos_albums","description":"List the albums and folders the user made in Apple iCloud Photos, from the local cache, with how many photos each shows. Read-only; refresh with photos_refresh.","inputSchema":{"type":"object","properties":page,"additionalProperties":false},"annotations":read}));
    let mut list = page.clone();
    list["album_id"] = json!({"type":"string","minLength":1,"maxLength":photos::MAX_ID_BYTES,"description":"Album id from photos_albums; omit for the whole library."});
    tools.push(json!({"name":"photos_list","description":"List the user's Apple iCloud Photos (personal library) from the local cache, newest first or in an album's order: dates, kind (image, video, Live Photo), size, filename, title, caption and keywords. No pictures, places or faces. Read-only.","inputSchema":{"type":"object","properties":list,"additionalProperties":false},"annotations":read}));
    let mut search = page.clone();
    search["query"] = json!({"type":"string","minLength":1,"maxLength":photos::MAX_QUERY_BYTES,"description":"Words matched against title, filename, caption, keywords, and the year or month taken. At most 256 UTF-8 bytes."});
    tools.push(json!({"name":"photos_search","description":"Search the user's cached Apple iCloud Photos (personal library) by title, filename, caption, keyword or the year or month taken. Read-only.","inputSchema":{"type":"object","properties":search,"required":["query"],"additionalProperties":false},"annotations":read}));
    tools.push(json!({"name":"photos_get","description":"Read one cached Apple iCloud Photos item's details, with a longer caption. Not the picture itself: no image, video, thumbnail, place or faces.","inputSchema":{"type":"object","properties":{"id":id},"required":["id"],"additionalProperties":false},"annotations":read}));
    tools.push(json!({"name":"photos_refresh","description":"Read the user's Apple iCloud Photos metadata (personal library) from Apple into the local cache, a bounded batch at a time; a large library takes several calls. Never downloads pictures, never changes photos or albums at Apple and sends no queued changes. Never opens a login prompt.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true}}));
    let page = json!({"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":drive::MAX_LIMIT,"default":25}});
    let cloud_path = json!({"type":"string","minLength":1,"maxLength":drive::MAX_PATH_BYTES,"description":format!("Cloud path in Apple iCloud Drive, such as /Documents/Taxes. / is the top. Names are matched as Apple lists them; ., .., empty names and control characters are refused. At most {} names.", drive::MAX_DEPTH)});
    let id = json!({"type":"string","minLength":1,"maxLength":drive::MAX_ID_BYTES,"description":"Item id from drive_list, drive_get or drive_search. At most 512 UTF-8 bytes."});
    let mut folder = page.clone();
    folder["path"] = cloud_path.clone();
    folder["id"] = id.clone();
    tools.push(json!({"name":"drive_list","description":"List one Apple iCloud Drive folder from the local cache: names, kinds, sizes and dates, folders first. Give path or id; the top folder by default. Says whether drive_refresh has read the folder. No file contents. Read-only.","inputSchema":{"type":"object","properties":folder,"additionalProperties":false},"annotations":read}));
    tools.push(json!({"name":"drive_get","description":"Read one cached Apple iCloud Drive item's details by path or id: name, kind, size, dates, parent and cloud path. No file contents. Read-only.","inputSchema":{"type":"object","properties":{"path":cloud_path.clone(),"id":id.clone()},"additionalProperties":false},"annotations":read}));
    let mut search = page.clone();
    search["query"] = json!({"type":"string","minLength":1,"maxLength":drive::MAX_QUERY_BYTES,"description":"Words matched against item names, ignoring case and accents. At most 256 UTF-8 bytes."});
    tools.push(json!({"name":"drive_search","description":"Search the names of cached Apple iCloud Drive items in folders drive_refresh has read. At most 1000 matches, most recently changed first. Read-only.","inputSchema":{"type":"object","properties":search,"required":["query"],"additionalProperties":false},"annotations":read}));
    tools.push(json!({"name":"drive_refresh","description":"Read one Apple iCloud Drive folder's item list from Apple into the local cache, with each folder on its path. Give path or a cached folder id; the top folder by default. Reads names, kinds, sizes and dates only: never file contents, and never uploads, renames, moves or deletes. Sends no queued changes. Never opens a login prompt.","inputSchema":{"type":"object","properties":{"path":cloud_path,"id":id},"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true}}));
    tools.push(json!({"name":"auth_status","description":"Apple iCloud sign-in status and setup instructions. Never accepts secrets or opens a prompt.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}}));
    tools
}

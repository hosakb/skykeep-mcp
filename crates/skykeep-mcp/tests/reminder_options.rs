//! A reminder created with a daily repeat, an alert at its time, an early alert and a zone:
//! checked, queued with the ids its records will have, and reported as queued only. Every
//! fixture is synthetic and every remote a loopback mock.
use quince_auth::{session::Session, Client, Endpoints, Store};
use serde_json::{json, Value};
use skykeep_mcp::Server;
use std::os::unix::fs::PermissionsExt;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// 9:00 on 7 March 2026 in New York, the day before its clocks go forward.
const DUE: i64 = 1_772_892_000;

fn setup(account: bool) -> (tempfile::TempDir, Server, quince_core::Library) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let server = Server::open(dir.path()).unwrap();
    let mut library = quince_core::Library::open(dir.path()).unwrap();
    library.set_state("account", "synthetic-account").unwrap();
    library
        .put_reminder_lists(&[quince_core::reminders::ReminderList {
            guid: "list".into(),
            ..Default::default()
        }])
        .unwrap();
    if account {
        // An early alert a phone set on another reminder, with the account id Apple writes.
        library
            .put_reminder_local(&quince_core::reminders::Reminder {
                guid: "Reminder/OTHER".into(),
                list_guid: "list".into(),
                title: "Synthetic other".into(),
                ..Default::default()
            })
            .unwrap();
        library
            .put_reminder_details(&quince_core::reminders::ReminderDetailsPass {
                early_alerts: vec![(
                    "Reminder/OTHER".into(),
                    Some("SYNTHETIC-ALERT-ACCOUNT".into()),
                    vec![quince_core::reminders::EarlyAlert {
                        id: "E".into(),
                        count: 5,
                        unit: 0,
                    }],
                )],
                ..Default::default()
            })
            .unwrap();
    }
    (dir, server, library)
}

async fn call(server: &mut Server, args: Value) -> (bool, Value) {
    server.handle(json!({"id":1,"method":"initialize"})).await;
    let response = server
        .handle(json!({"id":2,"method":"tools/call","params":{"name":"reminders_write","arguments":args}}))
        .await
        .unwrap();
    (
        response["result"]["isError"] == true,
        serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap(),
    )
}

fn full() -> Value {
    json!({
        "action":"create","list_guid":"list","title":"Synthetic daily","due_at":DUE,
        "repeat":{"frequency":"daily","until":"2026-03-20"},
        "due_time_alert":true,
        "early_alert":{"amount":15,"unit":"minutes"},
        "timezone":"America/New_York"
    })
}

#[tokio::test]
async fn a_create_with_a_repeat_and_alerts_is_queued_and_reported_as_queued_only() {
    let (_dir, mut server, library) = setup(true);
    let (failed, result) = call(&mut server, full()).await;
    assert!(!failed, "{result}");
    assert_eq!(result["status"], "queued");
    assert_eq!(result["queued"], true);
    assert_eq!(result["cloudkit_accepted"], false);
    assert_eq!(result["remote_verified"], false);
    // The end of 20 March in New York (EDT, UTC-4): 03:59:59 UTC on 21 March.
    assert_eq!(
        result["options"],
        json!({
            "timezone":"America/New_York",
            "repeat":{"frequency":"daily","ends_at":1_774_065_599},
            "due_time_alert":true,
            "early_alert":{"amount":15,"unit":"minutes"}
        })
    );
    // The reply names no record ids and no account id.
    let text = result.to_string();
    assert!(!text.contains("SYNTHETIC-ALERT-ACCOUNT"), "{text}");
    assert!(
        !text.contains("rule_id") && !text.contains("alarm_id"),
        "{text}"
    );

    let queued = library.outbox_pending("reminders").unwrap();
    assert_eq!(queued.len(), 1);
    let payload: Value = serde_json::from_str(&queued[0].payload).unwrap();
    assert_eq!(payload["timezone"], "America/New_York");
    assert_eq!(payload["repeat"]["frequency"], 0);
    assert_eq!(payload["repeat"]["end_at"], 1_774_065_599);
    assert_eq!(payload["early_alert"]["account"], "SYNTHETIC-ALERT-ACCOUNT");
    assert_eq!(payload["early_alert"]["unit"], 0);
    for id in [
        &payload["repeat"]["rule_id"],
        &payload["alarm"]["alarm_id"],
        &payload["alarm"]["trigger_id"],
        &payload["early_alert"]["id"],
    ] {
        assert_eq!(id.as_str().map(str::len), Some(36), "{payload}");
    }
    let shown = library
        .reminder(result["guid"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(shown.recur_frequency, Some(0));
    assert_eq!(shown.timezone.as_deref(), Some("America/New_York"));
}

#[tokio::test]
async fn combinations_that_cannot_work_are_refused_and_queue_nothing() {
    let base = || json!({"action":"create","list_guid":"list","title":"Synthetic"});
    let with = |extra: Value| {
        let mut v = base();
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v
    };
    let cases = [
        (
            json!({"due_time_alert":true}),
            "due_time_alert_requires_due_at",
        ),
        (
            json!({"due_at":DUE,"all_day":true,"due_time_alert":true}),
            "all_day_cannot_have_timed_alert",
        ),
        (
            json!({"due_at":DUE,"all_day":true,"early_alert":{"amount":1,"unit":"days"}}),
            "all_day_cannot_have_timed_alert",
        ),
        (
            json!({"early_alert":{"amount":5,"unit":"minutes"}}),
            "early_alert_requires_due_at",
        ),
        (
            json!({"due_at":DUE,"early_alert":{"amount":0,"unit":"minutes"}}),
            "invalid_early_alert",
        ),
        (
            json!({"due_at":DUE,"early_alert":{"amount":10_001,"unit":"minutes"}}),
            "invalid_early_alert",
        ),
        (
            json!({"due_at":DUE,"timezone":"Mars/Olympus"}),
            "unknown_timezone",
        ),
        (
            json!({"due_at":DUE,"timezone":"+05:00"}),
            "unknown_timezone",
        ),
        (
            json!({"due_at":DUE,"timezone":"x".repeat(65)}),
            "unknown_timezone",
        ),
        (
            json!({"due_at":DUE,"all_day":true,"timezone":"Europe/Berlin"}),
            "timezone_requires_timed_due_at",
        ),
        (
            json!({"timezone":"Europe/Berlin"}),
            "timezone_requires_timed_due_at",
        ),
        (
            json!({"repeat":{"frequency":"daily"}}),
            "repeat_requires_due_at",
        ),
        (
            json!({"due_at":DUE,"timezone":"America/New_York","repeat":{"frequency":"daily","until":"2026-03-06"}}),
            "repeat_end_before_due",
        ),
        (
            json!({"due_at":DUE,"repeat":{"frequency":"daily","until":"2026-02-30"}}),
            "invalid_repeat_end",
        ),
        (
            json!({"due_at":DUE,"repeat":{"frequency":"daily","until":"next week"}}),
            "invalid_repeat_end",
        ),
        (
            json!({"due_at":DUE,"repeat":{"frequency":"weekly"}}),
            "invalid_arguments",
        ),
        (
            json!({"due_at":DUE,"repeat":{"frequency":"daily","interval":2}}),
            "invalid_arguments",
        ),
        (
            json!({"due_at":DUE,"early_alert":{"amount":5,"unit":"seconds"}}),
            "invalid_arguments",
        ),
        (
            json!({"due_at":DUE,"due_time_alert":"yes"}),
            "invalid_arguments",
        ),
    ];
    for (extra, code) in cases {
        let (_dir, mut server, library) = setup(true);
        let (failed, result) = call(&mut server, with(extra.clone())).await;
        assert!(failed, "{extra}: {result}");
        assert_eq!(result["error"], code, "{extra}");
        assert_eq!(library.outbox_count().unwrap(), 0, "{extra}");
    }
    // No early alert anywhere on the account: no account id to write inside one.
    let (_dir, mut server, library) = setup(false);
    let (failed, result) = call(
        &mut server,
        with(json!({"due_at":DUE,"early_alert":{"amount":5,"unit":"minutes"}})),
    )
    .await;
    assert!(failed);
    assert_eq!(result["error"], "early_alert_account_unavailable");
    assert_eq!(library.outbox_count().unwrap(), 0);
    // The options belong to a create; an edit carrying one is not understood.
    let (_dir, mut server, _library) = setup(true);
    let (failed, result) = call(
        &mut server,
        json!({"action":"edit","guid":"Reminder/X","patch":{"title":"t"},"due_time_alert":true}),
    )
    .await;
    assert!(failed);
    assert_eq!(result["error"], "invalid_arguments");
}

/// An all-day reminder can repeat daily; its last day is read in UTC, where an all-day date is
/// that day's midnight. A due-time alert of `false` asks for nothing.
#[tokio::test]
async fn an_all_day_reminder_repeats_until_its_last_day() {
    let (_dir, mut server, library) = setup(false);
    // Midnight UTC on 7 March 2026.
    let day = 1_772_841_600;
    let (failed, result) = call(
        &mut server,
        json!({"action":"create","list_guid":"list","title":"Synthetic","due_at":day,"all_day":true,
               "due_time_alert":false,"repeat":{"frequency":"daily","until":"2026-03-07"}}),
    )
    .await;
    assert!(!failed, "{result}");
    assert_eq!(result["options"]["repeat"]["ends_at"], day + 86_399);
    assert_eq!(result["options"]["due_time_alert"], false);
    let payload: Value =
        serde_json::from_str(&library.outbox_pending("reminders").unwrap()[0].payload).unwrap();
    assert!(payload.get("alarm").is_none() && payload.get("timezone").is_none());
}

/// With no zone given, a timed create with options is kept in this computer's zone as it was
/// when queued: the repeat's end and every later send use that one zone. A plain create
/// queues no zone, as before.
#[tokio::test]
async fn the_default_zone_is_chosen_once_and_queued() {
    let (_dir, mut server, library) = setup(false);
    let (failed, result) = call(
        &mut server,
        json!({"action":"create","list_guid":"list","title":"Synthetic","due_at":DUE,
               "repeat":{"frequency":"daily","until":"2026-03-20"}}),
    )
    .await;
    assert!(!failed, "{result}");
    let zone = result["options"]["timezone"]
        .as_str()
        .expect("a zone")
        .to_string();
    assert_eq!(
        quince_sync::reminders::iana_zone(&zone).as_deref(),
        Some(zone.as_str())
    );
    let payload: Value =
        serde_json::from_str(&library.outbox_pending("reminders").unwrap()[0].payload).unwrap();
    assert_eq!(payload["timezone"], zone.as_str());
    assert_eq!(
        payload["repeat"]["end_at"],
        quince_sync::reminders::end_of_day("2026-03-20", &zone).unwrap()
    );
    let (_, plain) = call(
        &mut server,
        json!({"action":"create","list_guid":"list","title":"Synthetic plain","due_at":DUE}),
    )
    .await;
    let queued = library.outbox_pending("reminders").unwrap();
    let plain_payload: Value = serde_json::from_str(
        &queued
            .iter()
            .find(|p| p.record == plain["guid"].as_str().unwrap())
            .unwrap()
            .payload,
    )
    .unwrap();
    assert!(plain_payload.get("timezone").is_none(), "{plain_payload}");
}

/// Under the approval policy the options wait with the rest of the create, and the human's
/// approval queues exactly them.
#[tokio::test]
async fn options_wait_for_approval_with_the_create() {
    let (_dir, mut server, mut library) = setup(true);
    library
        .set_state("mcp.require_write_approval", "true")
        .unwrap();
    let (_, result) = call(&mut server, full()).await;
    assert_eq!(result["status"], "approval_required", "{result}");
    assert_eq!(library.outbox_count().unwrap(), 0);
    let details = server
        .approval_details(result["request_id"].as_str().unwrap())
        .unwrap();
    assert!(details.contains("2026-03-20") && details.contains("America/New_York"));
    let approved = server
        .approve(result["request_id"].as_str().unwrap())
        .unwrap();
    assert_eq!(approved["status"], "queued");
    assert_eq!(approved["remote_verified"], false);
    assert_eq!(approved["options"]["early_alert"]["amount"], 15);
    let payload: Value =
        serde_json::from_str(&library.outbox_pending("reminders").unwrap()[0].payload).unwrap();
    assert_eq!(payload["repeat"]["frequency"], 0);
}

#[tokio::test]
async fn the_schema_describes_the_new_create_fields() {
    let (_dir, mut server, _library) = setup(false);
    server.handle(json!({"id":1,"method":"initialize"})).await;
    let list = server
        .handle(json!({"id":2,"method":"tools/list"}))
        .await
        .unwrap();
    let tool = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "reminders_write")
        .unwrap()
        .clone();
    let props = &tool["inputSchema"]["properties"];
    assert_eq!(
        props["repeat"]["properties"]["frequency"]["enum"],
        json!(["daily"])
    );
    assert_eq!(props["repeat"]["additionalProperties"], false);
    assert_eq!(props["due_time_alert"]["type"], "boolean");
    assert_eq!(
        props["early_alert"]["properties"]["amount"]["maximum"],
        10_000
    );
    assert_eq!(props["early_alert"]["additionalProperties"], false);
    assert_eq!(props["timezone"]["maxLength"], 64);
    assert_eq!(tool["inputSchema"]["additionalProperties"], false);
}

fn saved_client(dir: &std::path::Path, uri: &str) -> Client {
    let store = Store::file(dir).unwrap().without_passwords();
    store
        .save(&Session {
            dsid: Some("1234567890".into()),
            session_token: Some("SYNTHETIC-TOKEN".into()),
            webservices: Some(json!({"ckdatabasews":{"url":uri}})),
            ..Default::default()
        })
        .unwrap();
    Client::with(dir, Endpoints::at(uri), store).unwrap()
}

/// Sync names the writes CloudKit took, apart from read-back, which stays unverified. A
/// create whose repeat could not be written (this pretend Apple never has the reminder to
/// point at a rule) is not called taken: it waits, queued, to be sent again.
#[tokio::test]
async fn sync_names_only_writes_cloudkit_took_whole() {
    let remote = MockServer::start().await;
    Mock::given(method("POST")).and(path("/setup/ws/1/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"dsInfo":{"dsid":"1234567890"},"webservices":{"ckdatabasews":{"url":remote.uri()}}}))).mount(&remote).await;
    Mock::given(method("POST"))
        .and(path_regex(".*/changes/zone$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"zones":[{"records":[],"syncToken":"synthetic","moreComing":false}]}),
        ))
        .mount(&remote)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(".*/records/lookup$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"records":[]})))
        .mount(&remote)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(".*/records/modify$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"records":[{"recordName":"synthetic"}]})),
        )
        .mount(&remote)
        .await;
    let (dir, mut server, mut library) = setup(false);
    library
        .set_state("account", &quince_sync::queue::account_tag("1234567890"))
        .unwrap();
    server.set_policy("yolo").unwrap();
    let (_, plain) = call(
        &mut server,
        json!({"action":"create","list_guid":"list","title":"Synthetic plain"}),
    )
    .await;
    // Its date is written after the reminder, and a failure there is only logged: it leaves
    // the queue, but CloudKit's taking it is not confirmed.
    let (_, dated) = call(
        &mut server,
        json!({"action":"create","list_guid":"list","title":"Synthetic dated","due_at":DUE}),
    )
    .await;
    let (failed, repeating) = call(
        &mut server,
        json!({"action":"create","list_guid":"list","title":"Synthetic daily","due_at":DUE,"repeat":{"frequency":"daily"}}),
    )
    .await;
    assert!(!failed, "{repeating}");
    let result =
        skykeep_mcp::sync::with_client(dir.path(), saved_client(dir.path(), &remote.uri()))
            .await
            .unwrap();
    assert_eq!(result["remote_verified"], false);
    assert!(result.get("cloudkit_accepted_this_sync").is_none());
    let left = result["left_queue_this_sync"].as_array().unwrap();
    assert_eq!(left.len(), 2, "{result}");
    assert_eq!(left[0]["record"], plain["guid"]);
    assert_eq!(left[0]["kind"], "create");
    assert_eq!(left[0]["outcome"], "cloudkit_accepted");
    assert_eq!(left[1]["record"], dated["guid"]);
    assert_eq!(left[1]["outcome"], "finished_unconfirmed");
    let waiting = library.outbox_pending("reminders").unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].record, repeating["guid"].as_str().unwrap());
    assert_eq!(waiting[0].tries, 1);
    assert!(!result.to_string().contains("SYNTHETIC-TOKEN"));
}

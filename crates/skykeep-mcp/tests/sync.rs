use quince_auth::{session::Session, Client, Endpoints, Store};
use serde_json::json;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn read_approval_policy_gates_refresh_before_session_validation() {
    use std::os::unix::fs::PermissionsExt;
    let remote = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut server = skykeep_mcp::Server::open(dir.path()).unwrap();
    let mut library = quince_core::Library::open(dir.path()).unwrap();
    library
        .set_state("account", &quince_sync::queue::account_tag("1234567890"))
        .unwrap();
    server.set_policy("reads_and_writes").unwrap();
    let client = saved_client(dir.path(), &remote.uri());
    assert!(skykeep_mcp::sync::with_client(dir.path(), client)
        .await
        .is_err());
    assert!(
        remote.received_requests().await.unwrap().is_empty(),
        "no session or content request before read consent"
    );
}

#[tokio::test]
async fn configured_native_send_uses_exact_grant_and_tampering_never_reaches_network() {
    use std::os::unix::fs::PermissionsExt;
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
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut server = skykeep_mcp::Server::open(dir.path()).unwrap();
    let mut library = quince_core::Library::open(dir.path()).unwrap();
    library
        .set_state("account", &quince_sync::queue::account_tag("1234567890"))
        .unwrap();
    library
        .put_reminder_lists(&[quince_core::reminders::ReminderList {
            guid: "list".into(),
            ..Default::default()
        }])
        .unwrap();
    server.set_policy("yolo").unwrap();
    server.handle(json!({"id":1,"method":"initialize"})).await;
    let reply=server.handle(json!({"id":2,"method":"tools/call","params":{"name":"reminders_write","arguments":{"action":"create","list_guid":"list","title":"approved wire title"}}})).await.unwrap();
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    let pending = library.outbox_pending("reminders").unwrap().remove(0);
    let mut changed = pending.clone();
    changed.payload.push(' ');
    assert!(skykeep_mcp::sync::authorized(&library, dir.path(), &changed).is_err());
    let mut retried = pending.clone();
    retried.tries = 4;
    assert!(skykeep_mcp::sync::authorized(&library, dir.path(), &retried).is_ok());
    let data = quince_sync::library_lock::LibraryLock::new(
        quince_core::Library::open(dir.path()).unwrap(),
        Some(dir.path().to_owned()),
    );
    let pass = tokio::sync::Mutex::new(());
    let report = quince_sync::queue::drain_as(
        &data,
        "reminders",
        &pass,
        &quince_sync::queue::account_tag("1234567890"),
        |p| {
            assert!(skykeep_mcp::sync::authorized(&library, dir.path(), &p).is_ok());
            async { Err(quince_icloud::Error::Busy(None)) }
        },
    )
    .await;
    assert!(!report.sent);
    assert_eq!(library.outbox_pending("reminders").unwrap()[0].tries, 1);
    drop(data);
    let client = saved_client(dir.path(), &remote.uri());
    let result = skykeep_mcp::sync::with_client(dir.path(), client)
        .await
        .unwrap();
    assert!(
        result["services"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["service"] == "reminders" && s["sent"] == true),
        "{result}"
    );
    assert_eq!(library.outbox_count().unwrap(), 0);
    let requests = remote.received_requests().await.unwrap();
    let modify = requests
        .iter()
        .find(|r| r.url.path().ends_with("/records/modify"))
        .expect("native writer was exercised");
    let wire: serde_json::Value = serde_json::from_slice(&modify.body).unwrap();
    assert_eq!(
        wire["operations"][0]["record"]["fields"]["TitleDocument"]["value"],
        quince_icloud::ckdocument::text_to_base64("approved wire title")
    );
    remote.reset().await;
    let id = library
        .outbox_append("reminders", "unapproved", "create", "{}")
        .unwrap();
    let client = saved_client(dir.path(), &remote.uri());
    // The reset mock has no routes, so the pass itself fails after the local gate.
    assert!(skykeep_mcp::sync::with_client(dir.path(), client)
        .await
        .is_err());
    assert!(remote
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|r| !r.url.path().ends_with("/records/modify")));
    // The unapproved row is quarantined alone, kept for the human and never sent.
    assert!(library.outbox_pending("reminders").unwrap().is_empty());
    let refused = library.outbox_refused().unwrap();
    assert_eq!(refused[0].change.id, id);
    assert_eq!(refused[0].reason, "mcp_quarantine:legacy_write_quarantined");
}

#[tokio::test]
async fn authenticated_sync_refreshes_only_notes_and_reminders() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(path("/setup/ws/1/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"dsInfo":{"dsid":"1234567890"},"webservices":{"ckdatabasews":{"url":server.uri()}}}))).mount(&server).await;
    Mock::given(method("POST"))
        .and(path_regex(".*/changes/zone$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"zones":[{"records":[],"syncToken":"synthetic-cursor","moreComing":false}]}),
        ))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let store = Store::file(dir.path()).unwrap().without_passwords();
    store
        .save(&Session {
            dsid: Some("1234567890".into()),
            session_token: Some("SYNTHETIC-TOKEN".into()),
            webservices: Some(json!({"ckdatabasews":{"url":server.uri()}})),
            ..Default::default()
        })
        .unwrap();
    let client = Client::with(dir.path(), Endpoints::at(&server.uri()), store).unwrap();
    let mut library = quince_core::Library::open(dir.path()).unwrap();
    library
        .set_state("account", &quince_sync::queue::account_tag("1234567890"))
        .unwrap();
    let result = skykeep_mcp::sync::with_client(dir.path(), client)
        .await
        .unwrap();
    assert_eq!(result["services"].as_array().unwrap().len(), 2);
    assert_eq!(result["remote_verified"], false);
    let requests = server.received_requests().await.unwrap();
    assert!(requests
        .iter()
        .any(|r| r.url.path().contains("com.apple.notes")));
    assert!(requests
        .iter()
        .any(|r| r.url.path().contains("com.apple.reminders")));
    assert!(
        requests
            .iter()
            .all(|r| r.url.path() == "/setup/ws/1/validate"
                || r.url.path().contains("com.apple.notes")
                || r.url.path().contains("com.apple.reminders")),
        "unexpected service access"
    );
    let result = result.to_string();
    assert!(!result.contains("SYNTHETIC-TOKEN"));
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

#[tokio::test]
async fn expired_session_returns_login_required_without_service_access() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/setup/ws/1/validate"))
        .respond_with(
            ResponseTemplate::new(421).set_body_json(json!({"error":"SYNTHETIC-EXPIRED-BODY"})),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let client = saved_client(dir.path(), &server.uri());
    let mut library = quince_core::Library::open(dir.path()).unwrap();
    library
        .set_state("account", &quince_sync::queue::account_tag("1234567890"))
        .unwrap();
    let error = skykeep_mcp::sync::with_client(dir.path(), client)
        .await
        .unwrap_err();
    assert!(error.starts_with("login_required"), "{error}");
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests.iter().all(|r| !r.url.path().contains("com.apple")),
        "no data access after expiry"
    );
}

#[tokio::test]
async fn session_for_another_account_never_reads_or_sends() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(path("/setup/ws/1/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"dsInfo":{"dsid":"1234567890"},"webservices":{"ckdatabasews":{"url":server.uri()}}}))).mount(&server).await;
    let dir = tempfile::tempdir().unwrap();
    let client = saved_client(dir.path(), &server.uri());
    let mut library = quince_core::Library::open(dir.path()).unwrap();
    library
        .set_state("account", &quince_sync::queue::account_tag("9999999999"))
        .unwrap();
    assert_eq!(
        skykeep_mcp::sync::with_client(dir.path(), client)
            .await
            .unwrap_err(),
        "account_mismatch_use_new_state_directory"
    );
    assert!(server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|r| !r.url.path().contains("com.apple")));
}

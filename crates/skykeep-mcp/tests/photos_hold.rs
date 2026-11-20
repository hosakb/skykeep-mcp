//! A throttled CloudKit asking the Photos refresh to wait longer than a request can: the
//! container is held off and later refreshes fail at once, unsent. Its own test binary, since
//! the hold is process-wide and wiremock hands a pooled address to the next test.
//! Every fixture is synthetic and every remote is a loopback mock.
use quince_auth::{session::Session, Client, Endpoints, Store};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const DSID: &str = "1234567890";
const DB: &str = "/database/1/com.apple.photos.cloud/production/private";

fn bound() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    drop(skykeep_mcp::Server::open(dir.path()).unwrap());
    quince_core::Library::open(dir.path())
        .unwrap()
        .set_state("account", &quince_sync::queue::account_tag(DSID))
        .unwrap();
    dir
}

fn client(dir: &std::path::Path, uri: &str) -> Client {
    let store = Store::file(dir).unwrap().without_passwords();
    store
        .save(&Session {
            dsid: Some(DSID.into()),
            session_token: Some("SYNTHETIC-TOKEN".into()),
            webservices: Some(json!({"ckdatabasews":{"url":uri}})),
            ..Session::default()
        })
        .unwrap();
    Client::with(dir, Endpoints::at(uri), store).unwrap()
}

async fn remote(zones_list: ResponseTemplate) -> MockServer {
    let remote = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/setup/ws/1/validate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "dsInfo":{"dsid":DSID},
            "webservices":{"ckdatabasews":{"url":remote.uri()}}
        })))
        .mount(&remote)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{DB}/zones/list")))
        .respond_with(zones_list)
        .mount(&remote)
        .await;
    remote
}

async fn cloudkit_asks(remote: &MockServer) -> usize {
    remote
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().starts_with(DB))
        .count()
}

async fn refresh(dir: &std::path::Path, uri: &str) -> Result<serde_json::Value, &'static str> {
    skykeep_mcp::photos::refresh_with_client(dir, client(dir, uri)).await
}

#[tokio::test]
async fn a_long_retry_after_holds_photos_off_and_later_refreshes_fail_unsent() {
    // A 503 with Retry-After of 30 minutes: one request, then none until it has passed.
    let throttled = remote(
        ResponseTemplate::new(503)
            .insert_header("Retry-After", "1800")
            .set_body_string("SYNTHETIC-UPSTREAM-BODY"),
    )
    .await;
    let dir = bound();
    let started = std::time::Instant::now();
    for _ in 0..3 {
        assert_eq!(
            refresh(dir.path(), &throttled.uri()).await.unwrap_err(),
            "photos_refresh_failed_cache_kept"
        );
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert_eq!(cloudkit_asks(&throttled).await, 1);
    assert!(quince_icloud::cloudkit::container_held_off(
        &throttled.uri(),
        "com.apple.photos.cloud"
    )
    .is_some_and(|left| left.as_secs() > 1790));

    // The same ask said inside a 200 for the zone holds it off as well.
    let zone_throttled = remote(ResponseTemplate::new(200).set_body_json(json!({"zones":[
        {"zoneID":{"zoneName":"PrimarySync"}}
    ]})))
    .await;
    Mock::given(method("POST"))
        .and(path(format!("{DB}/records/query")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "serverErrorCode":"THROTTLED","retryAfter":1200
        })))
        .mount(&zone_throttled)
        .await;
    let dir = bound();
    for _ in 0..2 {
        assert_eq!(
            refresh(dir.path(), &zone_throttled.uri())
                .await
                .unwrap_err(),
            "photos_refresh_failed_cache_kept"
        );
    }
    assert_eq!(
        cloudkit_asks(&zone_throttled).await,
        2,
        "list and query, once"
    );

    // A 503 whose body is over the cap is not read, and its header's wait still holds.
    let oversized = remote(
        ResponseTemplate::new(503)
            .insert_header("Retry-After", "1800")
            .set_body_string("x".repeat(4096)),
    )
    .await;
    let dir = bound();
    let limits = || skykeep_mcp::photos::RefreshLimits {
        max_small_bytes: 1024,
        ..Default::default()
    };
    let first = skykeep_mcp::photos::refresh_with_client_limited(
        dir.path(),
        client(dir.path(), &oversized.uri()),
        limits(),
    )
    .await;
    assert_eq!(first.unwrap_err(), "photos_response_too_large_cache_kept");
    let again = skykeep_mcp::photos::refresh_with_client_limited(
        dir.path(),
        client(dir.path(), &oversized.uri()),
        limits(),
    )
    .await;
    assert_eq!(again.unwrap_err(), "photos_refresh_failed_cache_kept");
    assert_eq!(cloudkit_asks(&oversized).await, 1);
}

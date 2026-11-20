//! A reminder made here with a daily repeat, an alert at its time and an early alert, sent to
//! a pretend CloudKit that keeps its records: sent once, failed part way and sent again, and
//! read back from the queue after a restart. Every record and id is synthetic.

use super::*;
use crate::library_lock::LibraryLock;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const LIST: &str = "List/SYNTHETIC-LIST";

/// How the next matching write goes wrong: refused before it is applied, or applied with the
/// answer lost.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    Before,
    AnswerLost,
}

#[derive(Default)]
struct Store {
    records: BTreeMap<String, Value>,
    tag: u64,
    /// A write whose body holds this text fails once, as said.
    fault: Option<(String, Fault)>,
    /// Records made, by name, counting a second make of the same name.
    made: Vec<String>,
    /// Updates to `Reminder/` records.
    updates: usize,
}

#[derive(Clone, Default)]
struct Cloud(Arc<Mutex<Store>>);

impl Cloud {
    fn record(&self, name: &str) -> Option<Value> {
        self.0.lock().unwrap().records.get(name).cloned()
    }
    fn of_type(&self, kind: &str) -> Vec<Value> {
        self.0
            .lock()
            .unwrap()
            .records
            .values()
            .filter(|r| r["recordType"] == kind)
            .cloned()
            .collect()
    }
    fn fail_once(&self, text: &str, fault: Fault) {
        self.0.lock().unwrap().fault = Some((text.into(), fault));
    }
    fn made(&self) -> Vec<String> {
        self.0.lock().unwrap().made.clone()
    }
    /// A phone moves the reminder to another due date.
    fn phone_moves_due(&self, guid: &str, due: i64) {
        let mut s = self.0.lock().unwrap();
        s.tag += 1;
        let tag = s.tag.to_string();
        let r = s.records.get_mut(guid).unwrap();
        r["fields"]["DueDate"] = json!({ "type": "TIMESTAMP", "value": due * 1000 });
        r["recordChangeTag"] = json!(tag);
    }
    /// How many writes the reminder record itself has had.
    fn reminder_updates(&self) -> usize {
        self.0.lock().unwrap().updates
    }
    /// A phone adds an alarm of its own to the reminder.
    fn phone_adds_alarm(&self, guid: &str, id: &str) {
        let mut s = self.0.lock().unwrap();
        s.tag += 1;
        let tag = s.tag.to_string();
        let r = s.records.get_mut(guid).unwrap();
        let mut ids = r
            .pointer("/fields/AlarmIDs/value")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        ids.push(json!(id));
        r["fields"]["AlarmIDs"] = json!({ "type": "STRING_LIST", "value": ids });
        r["recordChangeTag"] = json!(tag);
    }
}

impl Respond for Cloud {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let mut s = self.0.lock().unwrap();
        if request.url.path().ends_with("/records/lookup") {
            let name = body["records"][0]["recordName"].as_str().unwrap();
            let found =
                s.records.get(name).cloned().unwrap_or_else(
                    || json!({ "recordName": name, "serverErrorCode": "NOT_FOUND" }),
                );
            return ResponseTemplate::new(200).set_body_json(json!({ "records": [found] }));
        }
        let text = String::from_utf8_lossy(&request.body).to_string();
        let fault = match &s.fault {
            Some((needle, fault)) if text.contains(needle.as_str()) => Some(*fault),
            _ => None,
        };
        if fault.is_some() {
            s.fault = None;
        }
        // 500, not 503: the client asks again by itself after a 503.
        if fault == Some(Fault::Before) {
            return ResponseTemplate::new(500);
        }
        let op = &body["operations"][0];
        let name = op["record"]["recordName"].as_str().unwrap().to_string();
        s.tag += 1;
        let tag = s.tag.to_string();
        if op["operationType"] == "update" && name.starts_with("Reminder/") {
            s.updates += 1;
        }
        let answer = match op["operationType"].as_str().unwrap() {
            "create" => {
                if s.records.contains_key(&name) {
                    json!({ "recordName": name, "serverErrorCode": "EXISTS", "reason": "record exists" })
                } else {
                    let mut record = op["record"].clone();
                    record["recordChangeTag"] = json!(tag);
                    s.made.push(name.clone());
                    s.records.insert(name.clone(), record.clone());
                    record
                }
            }
            "update" => match s.records.get_mut(&name) {
                None => {
                    json!({ "recordName": name, "serverErrorCode": "NOT_FOUND", "reason": "gone" })
                }
                Some(r) => {
                    let sent = op["record"]["recordChangeTag"].as_str();
                    if sent.is_some_and(|t| Some(t) != r["recordChangeTag"].as_str()) {
                        json!({ "recordName": name, "serverErrorCode": "CONFLICT", "reason": "oplock" })
                    } else {
                        for (k, v) in op["record"]["fields"].as_object().unwrap() {
                            r["fields"][k] = v.clone();
                        }
                        r["recordChangeTag"] = json!(tag);
                        r.clone()
                    }
                }
            },
            _ => {
                s.records.remove(&name);
                json!({ "recordName": name })
            }
        };
        if fault == Some(Fault::AnswerLost) {
            return ResponseTemplate::new(500);
        }
        ResponseTemplate::new(200).set_body_json(json!({ "records": [answer] }))
    }
}

async fn cloud() -> (MockServer, Cloud) {
    let server = MockServer::start().await;
    let cloud = Cloud::default();
    Mock::given(method("POST"))
        .and(path_regex(r".*/records/(lookup|modify)$"))
        .respond_with(cloud.clone())
        .mount(&server)
        .await;
    (server, cloud)
}

/// 9:00 on 7 March 2026 in New York (EST, UTC-5), the day before its clocks go forward.
const DUE: i64 = 1_772_892_000;

fn create() -> Create {
    Create {
        list_guid: LIST.into(),
        title: "Synthetic daily".into(),
        due_at: Some(DUE),
        all_day: None,
        flagged: Some(true),
        timezone: Some("America/New_York".into()),
        repeat: Some(CreateRepeat {
            frequency: 0,
            interval: 1,
            end_at: end_of_day("2026-03-20", "America/New_York"),
            rule_id: "RULE-1".into(),
        }),
        alarm: Some(CreateAlarm {
            alarm_id: "ALARM-1".into(),
            trigger_id: "TRIGGER-1".into(),
        }),
        early_alert: Some(CreateEarlyAlert {
            count: 15,
            unit: 0,
            account: "SYNTHETIC-ACCOUNT".into(),
            id: "EARLY-1".into(),
        }),
    }
}

fn library() -> Library {
    let mut l = Library::in_memory().unwrap();
    l.put_reminder_lists(&[quince_core::reminders::ReminderList {
        guid: LIST.into(),
        ..Default::default()
    }])
    .unwrap();
    l
}

async fn send_one(lock: &LibraryLock, uri: &str, p: &Pending) -> Result<(), Error> {
    send(lock, &reqwest::Client::new(), uri, vec![], p.clone()).await
}

fn ids(record: &Value, field: &str) -> Vec<String> {
    record
        .pointer(&format!("/fields/{field}/value"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Standard base64, decoded here: the crate has no base64 dependency of its own.
fn b64(text: &str) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in text.bytes().filter(|&c| c != b'=') {
        let v = alphabet.iter().position(|&a| a == c).unwrap() as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn early_alerts(record: &Value) -> Vec<Value> {
    let raw = record["fields"]["DueDateDeltaAlertsData"]["value"]
        .as_str()
        .unwrap();
    let blob: Value = serde_json::from_slice(&b64(raw)).unwrap();
    blob["dueDateDeltaAlerts"].as_array().unwrap().clone()
}

/// Every record the create made is the one it was queued with, made once, and pointed at:
/// one rule, one alarm with its trigger, one early alert. Nothing made that nothing lists.
fn assert_whole(cloud: &Cloud, guid: &str, other_alarms: &[&str]) {
    let reminder = cloud.record(guid).expect("the reminder is at Apple");
    assert_eq!(ids(&reminder, "RecurrenceRuleIDs"), ["RULE-1"]);
    let mut alarms = other_alarms
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    alarms.push("ALARM-1".into());
    let mut listed = ids(&reminder, "AlarmIDs");
    listed.sort();
    alarms.sort();
    assert_eq!(listed, alarms);
    assert_eq!(cloud.of_type("RecurrenceRule").len(), 1);
    assert_eq!(cloud.of_type("Alarm").len(), 1);
    assert_eq!(cloud.of_type("AlarmTrigger").len(), 1);
    assert_eq!(cloud.of_type("Reminder").len(), 1);
    let rule = cloud.record("RecurrenceRule/RULE-1").unwrap();
    assert_eq!(rule["fields"]["Frequency"]["value"], 0);
    assert_eq!(rule["fields"]["Reminder"]["value"]["recordName"], guid);
    let trigger = cloud.record("AlarmTrigger/TRIGGER-1").unwrap();
    assert_eq!(
        trigger["fields"]["Alarm"]["value"]["recordName"],
        "Alarm/ALARM-1"
    );
    let early = early_alerts(&reminder);
    assert_eq!(early.len(), 1);
    assert_eq!(early[0]["identifier"], "EARLY-1");
    assert_eq!(early[0]["dueDateDeltaCount"], -15);
    assert_eq!(reminder["fields"]["TimeZone"]["value"], "America/New_York");
    assert_eq!(
        reminder["fields"]["DueDate"]["value"],
        DUE * 1000,
        "the due date as given"
    );
    let mut made = cloud.made();
    let all = made.len();
    made.dedup();
    assert_eq!(made.len(), all, "no record made twice: {made:?}");
}

#[tokio::test]
async fn a_create_with_options_writes_each_record_once() {
    let (server, cloud) = cloud().await;
    let mut l = library();
    let guid = record_reminder_create(&mut l, &create()).unwrap();
    let p = l.outbox_pending(REMINDERS).unwrap().remove(0);
    let lock = LibraryLock::new(l, None);
    send_one(&lock, &server.uri(), &p).await.unwrap();
    assert_whole(&cloud, &guid, &[]);
    // The alarm rings at 9:00 New York time, written as that wall clock in that zone.
    let trigger = cloud.record("AlarmTrigger/TRIGGER-1").unwrap();
    let raw = trigger["fields"]["DateComponentsData"]["value"]
        .as_str()
        .unwrap();
    let parts: Value = serde_json::from_slice(&b64(raw)).unwrap();
    assert_eq!(
        (&parts["day"], &parts["hour"], &parts["minute"]),
        (&json!(7), &json!(9), &json!(0))
    );
    assert_eq!(parts["timeZone"]["identifier"], "America/New_York");
    // Sent again, as after an answer lost at the very end: nothing more is made.
    let before = cloud.made().len();
    send_one(&lock, &server.uri(), &p).await.unwrap();
    assert_eq!(cloud.made().len(), before);
    assert_whole(&cloud, &guid, &[]);
}

/// Each step failing in turn, refused or with its answer lost, and the change sent again: it
/// ends whole every time, never with a second rule or alert, or one nothing points at.
#[tokio::test]
async fn a_send_failing_part_way_is_finished_by_the_next_never_doubled() {
    for (needle, fault) in [
        ("\"RecurrenceRule\"", Fault::AnswerLost),
        ("\"RecurrenceRule\"", Fault::Before),
        ("RecurrenceRuleIDs", Fault::AnswerLost),
        ("\"Alarm\"", Fault::AnswerLost),
        ("\"AlarmTrigger\"", Fault::Before),
        ("\"AlarmTrigger\"", Fault::AnswerLost),
        ("AlarmIDs", Fault::AnswerLost),
        ("DueDateDeltaAlertsData", Fault::Before),
        ("DueDateDeltaAlertsData", Fault::AnswerLost),
    ] {
        let (server, cloud) = cloud().await;
        let mut l = library();
        let guid = record_reminder_create(&mut l, &create()).unwrap();
        let p = l.outbox_pending(REMINDERS).unwrap().remove(0);
        let lock = LibraryLock::new(l, None);
        cloud.fail_once(needle, fault);
        let first = send_one(&lock, &server.uri(), &p).await;
        assert!(
            first.is_err(),
            "{needle}: the failure is said, not swallowed"
        );
        send_one(&lock, &server.uri(), &p).await.unwrap();
        assert_whole(&cloud, &guid, &[]);
    }
}

/// The ids live in the queued change, so a send after a restart, read from the queue again,
/// finishes what the one before made. An alarm a phone added in between stays.
#[tokio::test]
async fn after_a_restart_the_queued_ids_finish_the_job_and_keep_a_phones_alarm() {
    let (server, cloud) = cloud().await;
    let dir = tempfile::tempdir().unwrap();
    let guid = {
        let mut l = Library::open(dir.path()).unwrap();
        l.put_reminder_lists(&[quince_core::reminders::ReminderList {
            guid: LIST.into(),
            ..Default::default()
        }])
        .unwrap();
        record_reminder_create(&mut l, &create()).unwrap()
    };
    let p = Library::open(dir.path())
        .unwrap()
        .outbox_pending(REMINDERS)
        .unwrap()
        .remove(0);
    for id in [
        "RULE-1",
        "ALARM-1",
        "TRIGGER-1",
        "EARLY-1",
        "America/New_York",
    ] {
        assert!(p.payload.contains(id), "{id} is kept in the queue");
    }
    {
        let lock = LibraryLock::new(Library::open(dir.path()).unwrap(), None);
        cloud.fail_once("\"AlarmTrigger\"", Fault::Before);
        assert!(send_one(&lock, &server.uri(), &p).await.is_err());
    }
    cloud.phone_adds_alarm(&guid, "PHONE-ALARM");
    // The process is gone; the queue is read again from disk.
    let again = Library::open(dir.path())
        .unwrap()
        .outbox_pending(REMINDERS)
        .unwrap()
        .remove(0);
    assert_eq!(again.payload, p.payload);
    let lock = LibraryLock::new(Library::open(dir.path()).unwrap(), None);
    send_one(&lock, &server.uri(), &again).await.unwrap();
    let reminder = cloud.record(&guid).unwrap();
    assert!(ids(&reminder, "AlarmIDs").contains(&"PHONE-ALARM".to_string()));
    assert_whole(&cloud, &guid, &["PHONE-ALARM"]);
}

/// An early alert already on the reminder stays beside the new one; the account id already
/// there is the one kept.
#[test]
fn an_added_early_alert_keeps_the_ones_there() {
    use quince_icloud::reminders::details::early_alert_added_json;
    let existing = json!({
        "accountIdentifier": "THEIRS",
        "dueDateDeltaAlerts": [{ "identifier": "OLD", "dueDateDeltaCount": -1, "dueDateDeltaUnit": 2 }],
        "other": 1
    });
    let added =
        early_alert_added_json(Some(&existing), "MINE", "Reminder/R", (15, 0), "NEW", 1.0).unwrap();
    let alerts = added["dueDateDeltaAlerts"].as_array().unwrap();
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0]["identifier"], "OLD");
    assert_eq!(alerts[1]["identifier"], "NEW");
    assert_eq!(added["accountIdentifier"], "THEIRS");
    assert_eq!(added["other"], 1);
    assert!(
        early_alert_added_json(Some(&added), "MINE", "Reminder/R", (15, 0), "NEW", 2.0).is_none()
    );
}

/// A plain create is queued as it always was: no new keys in its JSON, so changes queued
/// before this version read the same and their approvals still hold.
#[test]
fn a_plain_create_is_queued_as_before() {
    let plain = Create {
        list_guid: LIST.into(),
        title: "Plain".into(),
        due_at: None,
        all_day: None,
        flagged: None,
        timezone: None,
        repeat: None,
        alarm: None,
        early_alert: None,
    };
    let text = serde_json::to_string(&plain).unwrap();
    assert_eq!(
        text,
        r#"{"list_guid":"List/SYNTHETIC-LIST","title":"Plain","due_at":null,"all_day":null,"flagged":null}"#
    );
    let back: Create = serde_json::from_str(&text).unwrap();
    assert_eq!(back, plain);
}

/// Shown at once as repeating daily in its own zone: ticked before it is sent, it moves to
/// 9:00 the next day across the night New York's clocks go forward, not to 10:00.
#[test]
fn a_new_daily_reminder_is_shown_repeating_in_its_zone() {
    let mut l = library();
    let guid = record_reminder_create(&mut l, &create()).unwrap();
    let shown = l.reminder(&guid).unwrap().unwrap();
    assert_eq!(shown.recur_frequency, Some(0));
    assert_eq!(shown.timezone.as_deref(), Some("America/New_York"));
    // 9:00 EDT (UTC-4) on 8 March 2026: 23 hours after 9:00 EST the day before.
    assert_eq!(shown.next_occurrence_after(DUE), Some(DUE + 23 * 3600));
}

#[test]
fn zones_and_end_days_are_read_strictly_and_across_a_clock_change() {
    assert_eq!(iana_zone("Europe/Berlin").as_deref(), Some("Europe/Berlin"));
    assert_eq!(iana_zone("UTC").as_deref(), Some("UTC"));
    for bad in [
        "",
        "Not/AZone",
        " UTC",
        "+05:00",
        "EST5EDT,M3.2.0,M11.1.0",
        &"A".repeat(65),
    ] {
        assert_eq!(iana_zone(bad), None, "{bad:?}");
    }
    // The end of 8 March 2026 in New York, after its clocks went forward: 03:59:59 UTC on 9 March.
    assert_eq!(
        end_of_day("2026-03-08", "America/New_York"),
        Some(1_773_028_799)
    );
    // Before the change the same wall clock is an hour later in UTC.
    assert_eq!(
        end_of_day("2026-03-07", "America/New_York"),
        Some(1_772_945_999)
    );
    for bad in ["2026-02-30", "2026-3-8", "20260308", "2026-03-08T00:00"] {
        assert_eq!(end_of_day(bad, "UTC"), None, "{bad}");
    }
}

/// The early alert fails after the date and the alarm are at Apple, and the person moves the
/// reminder on a phone before the next send. That send finishes only the early alert: it does
/// not put the old date back over the phone's.
#[tokio::test]
async fn a_retry_finishes_only_what_is_left_and_keeps_a_phones_new_date() {
    let (server, cloud) = cloud().await;
    let mut l = library();
    let guid = record_reminder_create(&mut l, &create()).unwrap();
    let p = l.outbox_pending(REMINDERS).unwrap().remove(0);
    let lock = LibraryLock::new(l, None);
    cloud.fail_once("DueDateDeltaAlertsData", Fault::Before);
    assert!(send_one(&lock, &server.uri(), &p).await.is_err());
    let moved = DUE + 2 * 86_400;
    cloud.phone_moves_due(&guid, moved);
    let updates = cloud.reminder_updates();
    send_one(&lock, &server.uri(), &p).await.unwrap();
    let reminder = cloud.record(&guid).unwrap();
    assert_eq!(reminder["fields"]["DueDate"]["value"], moved * 1000);
    // One write to the reminder: its early alert. No date, flag or zone again.
    assert_eq!(cloud.reminder_updates(), updates + 1);
    assert_eq!(early_alerts(&reminder).len(), 1);
    assert_eq!(ids(&reminder, "AlarmIDs"), ["ALARM-1"]);
    assert_eq!(cloud.of_type("Alarm").len(), 1);
}

/// The alarm's trigger is not made yet when the phone moves the date: it rings at the date
/// Apple holds then, not the one queued.
#[tokio::test]
async fn an_alert_still_to_write_rings_at_the_date_apple_holds() {
    let (server, cloud) = cloud().await;
    let mut l = library();
    let guid = record_reminder_create(&mut l, &create()).unwrap();
    let p = l.outbox_pending(REMINDERS).unwrap().remove(0);
    let lock = LibraryLock::new(l, None);
    cloud.fail_once("\"AlarmTrigger\"", Fault::Before);
    assert!(send_one(&lock, &server.uri(), &p).await.is_err());
    // 10:30 on 9 March in New York (EDT).
    let moved = DUE + 2 * 86_400 - 3_600 + 5_400;
    cloud.phone_moves_due(&guid, moved);
    send_one(&lock, &server.uri(), &p).await.unwrap();
    let trigger = cloud.record("AlarmTrigger/TRIGGER-1").unwrap();
    let raw = trigger["fields"]["DateComponentsData"]["value"]
        .as_str()
        .unwrap();
    let parts: Value = serde_json::from_slice(&b64(raw)).unwrap();
    assert_eq!(
        (&parts["day"], &parts["hour"], &parts["minute"]),
        (&json!(9), &json!(10), &json!(30))
    );
    assert_eq!(
        cloud.record(&guid).unwrap()["fields"]["DueDate"]["value"],
        moved * 1000
    );
}

/// A repeat ending on its due day, ticked before it was ever sent: the series is done, as the
/// phone ends it, not moved on to the next day past its end.
#[test]
fn a_new_repeat_ending_today_ticked_offline_completes() {
    let mut l = library();
    let mut c = create();
    c.repeat.as_mut().unwrap().end_at = end_of_day("2026-03-07", "America/New_York");
    let guid = record_reminder_create(&mut l, &c).unwrap();
    let shown = l.reminder(&guid).unwrap().unwrap();
    record_reminder_tick(&mut l, &shown, true, DUE + 60).unwrap();
    let after = l.reminder(&guid).unwrap().unwrap();
    assert_eq!(after.completed_at, Some(DUE + 60));
    assert_eq!(after.due_at, Some(DUE));
    let kinds: Vec<String> = l
        .outbox_pending(REMINDERS)
        .unwrap()
        .into_iter()
        .map(|p| p.kind)
        .collect();
    assert_eq!(kinds, ["create", "done"]);
    // Laid again over a pass, it stays done.
    replay(&mut l).unwrap();
    assert_eq!(
        l.reminder(&guid).unwrap().unwrap().completed_at,
        Some(DUE + 60)
    );
}

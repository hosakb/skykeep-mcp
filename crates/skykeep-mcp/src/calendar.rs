//! Apple iCloud Calendar, read-only: cached calendars, events over a bounded date range,
//! search and one event, and an explicit refresh that reads a window of Apple's calendar into
//! the local cache. Nothing here writes to Apple, answers an invitation or sends a queued
//! change. The engine crates own the parsing and the cache; the refresh's requests are made
//! here so every response is read under a byte limit, and the engine's own readers
//! (`parse_snapshot`, `apply_calendar`) do the rest.
//!
//! Times. The cache keeps an all-day or floating (zoneless) event as its wall-clock time and
//! reads it back in this computer's zone. Reads here use the cache in UTC instead
//! (`Library::set_zone`), which gives back that wall-clock time unchanged, so an all-day
//! event is reported as the days Apple gave it and a floating one as the clock time it has,
//! whatever zone the computer or the caller is in. A timed event with a zone is an instant,
//! reported in UTC, in its own zone and in the zone the caller asked about.
use crate::account::{binding, Binding};
use crate::contacts::{cut, encoded_len, gate, owner, read_capped, record_timeout_of};
use quince_auth::{Client, Endpoints, Store};
use quince_core::calendar::{floats, instant_of, wall_clock, Calendar, Event};
use quince_core::Library;
use quince_icloud::calendar::{is_occurrence, parse_snapshot, series_of, Snapshot};
use quince_icloud::zones::{self, Zone};
use quince_sync::{library_lock::LibraryLock, pass};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};

const SERVICE: &str = "calendar";
const DEFAULT_LIMIT: usize = 25;
pub(crate) const MAX_LIMIT: usize = 100;
pub(crate) const MAX_QUERY_BYTES: usize = 256;
pub(crate) const MAX_GUID_BYTES: usize = 512;
pub(crate) const MAX_ZONE_BYTES: usize = 64;
/// The widest range `calendar_events` reads, in days.
pub(crate) const MAX_RANGE_DAYS: i64 = 93;
/// The widest window `calendar_refresh` reads, in days: seven of Apple's 28-day windows.
pub(crate) const MAX_REFRESH_DAYS: i64 = 186;
/// Apple refuses a calendar window wider than about a month (quince-icloud `sync.rs`).
const APPLE_WINDOW_DAYS: i64 = 28;
/// What `search_events_near` keeps when more match: the ones nearest today.
const SEARCH_KEEPS: usize = 300;
const DAY: i64 = 86_400;
/// Dates are read between these years: far enough for any calendar, near enough that day
/// arithmetic never comes close to overflowing.
const YEARS: std::ops::RangeInclusive<i64> = 1970..=2200;

/// Caps on a tool result's text as encoded in the JSON-RPC frame, as for Contacts.
const MAX_PAGE_BYTES: usize = 262_144;
const MAX_EVENT_BYTES: usize = 524_288;
const MAX_ITEM_BYTES: usize = 32_768;
/// Characters per text field, tried in turn until a summary fits. Zero leaves the times and
/// identifiers only; with identifiers at most `MAX_GUID_BYTES` the last level always fits.
const SUMMARY_LEVELS: [usize; 4] = [512, 128, 32, 0];
/// The same for one event: whole, then each text cut. Never below what a date takes.
const EVENT_LEVELS: [Option<usize>; 3] = [None, Some(4096), Some(256)];

/// What a cached event does not hold. The cache is a projection of Apple's event.
const NOT_INCLUDED: [&str; 6] = [
    "attendees and their answers; this server never reads or changes invitations",
    "alerts",
    "the repeat rule: a repeating event is listed as the occurrences Apple sent, each with its series id",
    "event status: a cancelled meeting that Apple still lists is shown like any other event, because the cache does not keep the status; an occurrence removed from a series is absent once a refresh covering its day has run",
    "attachments, travel time, availability and private comments",
    "calendars of other accounts (CalDAV, Nextcloud) and subscribed calendars",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    #[serde(default)]
    offset: usize,
    limit: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Range {
    from: String,
    to: String,
    timezone: String,
    calendar_guid: Option<String>,
    #[serde(default)]
    offset: usize,
    limit: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Search {
    query: String,
    #[serde(default)]
    offset: usize,
    limit: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Get {
    guid: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Refresh {
    from: Option<String>,
    to: Option<String>,
}

fn parse<T: serde::de::DeserializeOwned>(args: &Value) -> Result<T, &'static str> {
    serde_json::from_value(args.clone()).map_err(|_| "invalid_arguments")
}

fn page_limit(limit: Option<usize>) -> Result<usize, &'static str> {
    match limit {
        None => Ok(DEFAULT_LIMIT),
        Some(n) if (1..=MAX_LIMIT).contains(&n) => Ok(n),
        Some(_) => Err("invalid_arguments"),
    }
}

// --- Days, as whole days since 1970-01-01, without a date library.

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date `days` after 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (
        if m <= 2 {
            yoe + era * 400 + 1
        } else {
            yoe + era * 400
        },
        m,
        d,
    )
}

/// `YYYY-MM-DD`, exactly, as a day number.
fn parse_day(text: &str) -> Result<i64, &'static str> {
    let b = text.as_bytes();
    let digits = |r: std::ops::Range<usize>| -> Option<i64> {
        b.get(r.clone())?
            .iter()
            .all(u8::is_ascii_digit)
            .then(|| text[r].parse().ok())?
    };
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return Err("invalid_date");
    }
    let (Some(y), Some(m), Some(d)) = (digits(0..4), digits(5..7), digits(8..10)) else {
        return Err("invalid_date");
    };
    if !YEARS.contains(&y) || !(1..=12).contains(&m) || d < 1 {
        return Err("invalid_date");
    }
    let next = if m == 12 {
        days_from_civil(y + 1, 1, 1)
    } else {
        days_from_civil(y, m + 1, 1)
    };
    if d > next - days_from_civil(y, m, 1) {
        return Err("invalid_date");
    }
    Ok(days_from_civil(y, m, d))
}

fn day_text(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// A wall-clock time counted in seconds as if it were UTC, as `YYYY-MM-DDTHH:MM:SS`.
fn wall_text(wall: i64) -> String {
    let secs = wall.rem_euclid(DAY);
    format!(
        "{}T{:02}:{:02}:{:02}",
        day_text(wall.div_euclid(DAY)),
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// An instant as it reads in `zone`, with its offset: `2026-03-29T09:30:00+02:00`.
fn zoned_text(at: i64, zone: &Zone) -> String {
    let wall = wall_clock(at, &zone.tz);
    let offset = wall - at;
    let sign = if offset < 0 { '-' } else { '+' };
    let o = offset.abs();
    format!(
        "{}{sign}{:02}:{:02}",
        wall_text(wall),
        o / 3600,
        o % 3600 / 60
    )
}

pub(crate) fn utc_text(at: i64) -> String {
    format!("{}Z", wall_text(at))
}

/// The zone `name` names: an IANA name, a Windows name, or an id ending in an IANA name.
/// A name longer than any real zone's is not looked up: the lookup tries every tail of a
/// slash-separated id, and an event's zone name is whatever Apple sent.
fn zone(name: &str) -> Option<Zone> {
    if name.len() > MAX_ZONE_BYTES {
        return None;
    }
    zones::named(name)
}

/// A date range read in `zone`: its first and last-plus-one days as wall-clock seconds and as
/// instants in that zone.
struct Span {
    from_day: i64,
    to_day: i64,
    zone: Zone,
    zone_name: String,
}

impl Span {
    fn walls(&self) -> (i64, i64) {
        (self.from_day * DAY, self.to_day * DAY)
    }

    fn instants(&self) -> (i64, i64) {
        let (from, to) = self.walls();
        (
            instant_of(from, &self.zone.tz),
            instant_of(to, &self.zone.tz),
        )
    }

    /// Wide enough for both: what is read from the cache before each event is judged.
    fn widest(&self) -> (i64, i64) {
        let (wf, wt) = self.walls();
        let (i_from, i_to) = self.instants();
        (wf.min(i_from), wt.max(i_to))
    }
}

fn range_args(args: &Value) -> Result<(Range, Span), &'static str> {
    let range: Range = parse(args)?;
    page_limit(range.limit)?;
    if range.timezone.is_empty() || range.timezone.len() > MAX_ZONE_BYTES {
        return Err("invalid_arguments");
    }
    if range
        .calendar_guid
        .as_ref()
        .is_some_and(|g| g.is_empty() || g.len() > MAX_GUID_BYTES)
    {
        return Err("invalid_arguments");
    }
    let from_day = parse_day(&range.from)?;
    let to_day = parse_day(&range.to)?;
    if to_day <= from_day {
        return Err("invalid_range");
    }
    if to_day - from_day > MAX_RANGE_DAYS {
        return Err("range_too_wide");
    }
    let zone = zone(&range.timezone).ok_or("unknown_timezone")?;
    let zone_name = zone.name.clone().unwrap_or_else(|| range.timezone.clone());
    Ok((
        range,
        Span {
            from_day,
            to_day,
            zone,
            zone_name,
        },
    ))
}

fn search_args(args: &Value) -> Result<Search, &'static str> {
    let search: Search = parse(args)?;
    page_limit(search.limit)?;
    if search.query.len() > MAX_QUERY_BYTES {
        return Err("query_too_long");
    }
    if search.query.trim().is_empty() {
        return Err("query_required");
    }
    Ok(search)
}

fn get_args(args: &Value) -> Result<Get, &'static str> {
    let get: Get = parse(args)?;
    if get.guid.is_empty() || get.guid.len() > MAX_GUID_BYTES {
        return Err("invalid_arguments");
    }
    Ok(get)
}

/// The window a refresh reads, as day numbers `[from, to)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Window {
    from: i64,
    to: i64,
}

impl Window {
    fn view(self) -> Value {
        json!({"from":day_text(self.from),"to":day_text(self.to),"to_is_exclusive":true})
    }

    /// The days Apple is asked about, inclusive: one more on each side than the window, so
    /// a day of the window read in any zone (never a whole day from UTC) lies inside them.
    fn asked(self) -> (i64, i64) {
        (self.from - 1, self.to)
    }

    /// Exactly what Apple was asked about, in seconds `[from, to)`: what a refresh removes
    /// unlisted events from and what reads call covered. A timed event with a zone is judged
    /// by its instant; an all-day or floating one by its wall-clock start, which is how
    /// Apple, asked in UTC, places it (see [`prune`]).
    fn covers(self) -> (i64, i64) {
        let (first, last) = self.asked();
        (first * DAY, (last + 1) * DAY)
    }

    fn token(self) -> String {
        let (a, b) = self.covers();
        json!({"from":day_text(self.from),"to":day_text(self.to),"covers":[a,b]}).to_string()
    }
}

/// From the last refresh's stored position: the window it read.
fn stored_window(library: &Library) -> Option<Window> {
    let token: Value = serde_json::from_str(&library.sync_token(SERVICE).ok()??).ok()?;
    let from = parse_day(token["from"].as_str()?).ok()?;
    let to = parse_day(token["to"].as_str()?).ok()?;
    let window = Window { from, to };
    (token["covers"] == json!([window.covers().0, window.covers().1])).then_some(window)
}

fn today() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    secs.div_euclid(DAY)
}

/// The desktop app's window, by UTC's date: the month before this one through three after.
fn default_window() -> Window {
    let (y, m, _) = civil_from_days(today());
    let month = |offset: i64| {
        let n = y * 12 + (m - 1) + offset;
        days_from_civil(n.div_euclid(12), n.rem_euclid(12) + 1, 1)
    };
    Window {
        from: month(-1),
        to: month(4),
    }
}

/// The refresh's window from its arguments: both dates or neither.
pub(crate) fn refresh_window(args: &Value) -> Result<Window, &'static str> {
    let refresh: Refresh = parse(args)?;
    let window = match (refresh.from, refresh.to) {
        (None, None) => default_window(),
        (Some(from), Some(to)) => Window {
            from: parse_day(&from)?,
            to: parse_day(&to)?,
        },
        _ => return Err("invalid_arguments"),
    };
    if window.to <= window.from {
        return Err("invalid_range");
    }
    if window.to - window.from > MAX_REFRESH_DAYS {
        return Err("range_too_wide");
    }
    Ok(window)
}

/// Checks a Calendar tool's arguments before any approval prompt or cache access.
pub(crate) fn validate(name: &str, args: &Value) -> Result<(), &'static str> {
    match name {
        "calendar_calendars" => page_limit(parse::<Page>(args)?.limit).map(|_| ()),
        "calendar_events" => range_args(args).map(|_| ()),
        "calendar_search" => search_args(args).map(|_| ()),
        "calendar_get" => get_args(args).map(|_| ()),
        "calendar_refresh" => refresh_window(args).map(|_| ()),
        _ => Ok(()),
    }
}

/// A refresh's arguments with its window resolved to explicit dates, so what is approved is
/// what runs even if the day changes between the prompt and the answer.
pub(crate) fn resolved_refresh_args(args: &Value) -> Result<Value, &'static str> {
    let w = refresh_window(args)?;
    Ok(json!({"from":day_text(w.from),"to":day_text(w.to)}))
}

/// What the approval prompt says a refresh will read: the window, and the days Apple is asked.
pub(crate) fn refresh_scope(args: &Value) -> Value {
    let window = refresh_window(args).ok();
    let asked = window.map(|w| {
        let (first, last) = w.asked();
        json!({"first":day_text(first),"last":day_text(last),"in":"UTC"})
    });
    json!({"services":["calendar"],"window":window.map(Window::view),"asked_apple_days":asked,"refresh":"one read of Apple iCloud Calendar over these days into the local cache; events Apple no longer lists on them are removed from the cache; at most 60 seconds","send":"nothing is sent; queued changes stay queued"})
}

/// An Apple iCloud calendar: not another account's (CalDAV) and not a subscribed feed.
fn icloud(guid: &str) -> bool {
    !guid.starts_with(quince_core::dav::PREFIX)
        && !guid.starts_with(quince_icloud::calendar_feeds::PREFIX)
}

/// Reads the cache with all-day and floating events at their wall-clock times (see the
/// module's notes), then puts the library back as it was.
fn wall_view<T>(
    library: &mut Library,
    read: impl FnOnce(&Library) -> Result<T, &'static str>,
) -> Result<T, &'static str> {
    let utc = zone("UTC").ok_or("timezone_database_unavailable")?;
    library.set_zone(Some(utc.tz));
    let result = read(library);
    library.set_zone(None);
    result
}

/// How current the cache is. Apple error text stays in the library; only its presence shows.
fn cache_state(library: &Library) -> Result<Value, &'static str> {
    let health = library.sync_health().map_err(|_| "library_unavailable")?;
    let mine = health.iter().find(|h| h.service == SERVICE);
    let at = mine.and_then(|h| h.last_synced_at);
    Ok(json!({
        "refreshed": at.is_some(),
        "last_refreshed_at": at,
        "last_refresh_failed": mine.is_some_and(|h| h.last_error.is_some()),
        "refresh": "only by calendar_refresh; there is no background Calendar refresh",
    }))
}

fn coverage(library: &Library, span: Option<&Span>) -> Value {
    let window = stored_window(library);
    let within = match (window, span) {
        (Some(w), Some(span)) => {
            let (lo, hi) = span.widest();
            let (a, b) = w.covers();
            a <= lo && hi <= b
        }
        _ => false,
    };
    json!({
        "last_refresh_window": window.map(Window::view),
        "range_within_last_refresh": within,
        "meaning": "true only when the last successful refresh read this whole range; outside it the cache may hold events Apple has since changed or removed",
    })
}

/// An event's original start, from its occurrence id `<series>__20261102T090000Z` (an
/// instant) or `<series>__20261102` (a day).
enum Original {
    At(i64),
    Day(i64),
}

fn original_of(guid: &str) -> Option<Original> {
    let (_, tail) = guid.split_once("__")?;
    let b = tail.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = b.get(r.clone())?;
        part.iter()
            .all(u8::is_ascii_digit)
            .then(|| tail[r].parse().ok())?
    };
    let day = || -> Option<i64> {
        let text = format!(
            "{}-{}-{}",
            tail.get(0..4)?,
            tail.get(4..6)?,
            tail.get(6..8)?
        );
        parse_day(&text).ok()
    };
    match b.len() {
        8 => Some(Original::Day(day()?)),
        16 if b[8] == b'T' && b[15] == b'Z' => {
            let (h, m, s) = (num(9..11)?, num(11..13)?, num(13..15)?);
            (h < 24 && m < 60 && s < 60).then_some(())?;
            Some(Original::At(day()? * DAY + h * 3600 + m * 60 + s))
        }
        _ => None,
    }
}

fn occurrence(e: &Event) -> Value {
    if !is_occurrence(&e.guid) {
        return Value::Null;
    }
    let series = series_of(&e.guid);
    match original_of(&e.guid) {
        Some(Original::At(at)) => {
            let moved = (!floats(e)).then_some(e.starts_at != at);
            json!({"series_guid":series,"original_start_utc":utc_text(at),"moved":moved})
        }
        Some(Original::Day(day)) => {
            let moved = e.all_day.then_some(e.starts_at.div_euclid(DAY) != day);
            json!({"series_guid":series,"original_start_date":day_text(day),"moved":moved})
        }
        None => json!({"series_guid":series,"moved":null}),
    }
}

/// An all-day event's first day and the day after its last. Its times are midnights, but one
/// the clocks skipped in this computer's zone when it was read in is stored an hour off
/// (Sao Paulo's 2018-11-04), so each is taken to the nearest midnight. An end at or before
/// the start leaves the event one day long.
fn all_day_days(e: &Event) -> (i64, i64) {
    let nearest = |t: i64| t.saturating_add(DAY / 2).div_euclid(DAY);
    let first = nearest(e.starts_at);
    (first, nearest(e.ends_at).max(first + 1))
}

/// An event's start and end, as the module's notes say. Read through [`wall_view`].
fn times(e: &Event, requested: Option<&Zone>) -> (Value, Value, Value) {
    if e.all_day {
        let (first, last) = all_day_days(e);
        return (
            json!({"date":day_text(first)}),
            json!({"date":day_text(last)}),
            Value::Null,
        );
    }
    let Some(name) = e.timezone.as_deref() else {
        return (
            json!({"local":wall_text(e.starts_at)}),
            json!({"local":wall_text(e.ends_at)}),
            Value::Null,
        );
    };
    // Read as UTC by the engine when no zone database knows the name.
    let own = zone(name);
    let resolved = own.is_some();
    let own = own.or_else(|| zone("UTC"));
    let at = |t: i64| {
        let mut v = json!({"utc":utc_text(t)});
        if let Some(own) = &own {
            v["in_event_zone"] = json!(zoned_text(t, own));
        }
        if let Some(requested) = requested {
            v["in_requested_zone"] = json!(zoned_text(t, requested));
        }
        v
    };
    (at(e.starts_at), at(e.ends_at), json!(resolved))
}

fn summary(e: &Event, requested: Option<&Zone>, chars: usize) -> Value {
    let mut cut_any = false;
    let (start, end, resolved) = times(e, requested);
    json!({
        "guid": e.guid,
        "calendar_guid": e.calendar_guid,
        "title": cut(Some(&e.title), chars, &mut cut_any),
        "location": cut(e.location.as_deref(), chars, &mut cut_any),
        "all_day": e.all_day,
        "floating": floats(e),
        "timezone": cut(e.timezone.as_deref(), chars.max(64), &mut cut_any),
        "timezone_resolved": resolved,
        "start": start,
        "end": end,
        "occurrence": occurrence(e),
        "summary_truncated": cut_any,
    })
}

/// One page entry. An identifier too long to ask for with `calendar_get` is never cut into a
/// different, unusable one: the entry says so and holds its place.
fn item(e: &Event, requested: Option<&Zone>) -> Value {
    if e.guid.len() > MAX_GUID_BYTES || e.calendar_guid.len() > MAX_GUID_BYTES {
        return json!({"guid":null,"unsupported":"guid_too_long","guid_bytes":e.guid.len(),"summary_truncated":true});
    }
    let mut shown = Value::Null;
    for chars in SUMMARY_LEVELS {
        shown = summary(e, requested, chars);
        if encoded_len(&shown) <= MAX_ITEM_BYTES {
            break;
        }
    }
    shown
}

fn calendar_item(c: &Calendar) -> Value {
    if c.guid.len() > MAX_GUID_BYTES {
        return json!({"guid":null,"unsupported":"guid_too_long","guid_bytes":c.guid.len(),"summary_truncated":true});
    }
    let mut cut_any = false;
    json!({
        "guid": c.guid,
        "title": cut(Some(&c.title), 512, &mut cut_any),
        "colour": cut(c.colour.as_deref(), 32, &mut cut_any),
        "is_default": c.is_default,
        "read_only": !c.writable,
        "shown_on_icloud_web": c.enabled,
        "summary_truncated": cut_any,
    })
}

/// A page of `items` (made only for the page) under the byte cap, in `envelope`.
fn paged<T>(
    all: &[T],
    offset: usize,
    limit: usize,
    item: impl Fn(&T) -> Value,
    envelope: impl Fn(&[Value], bool) -> Value,
) -> Result<Value, &'static str> {
    let total = all.len();
    let page = |items: &[Value], shortened: bool| {
        let next = offset.saturating_add(items.len());
        let mut value = envelope(items, shortened);
        value["items"] = json!(items);
        value["total"] = json!(total);
        value["offset"] = json!(offset);
        value["limit"] = json!(limit);
        value["next_offset"] = json!((next < total).then_some(next));
        value["page_shortened_to_fit"] = json!(shortened);
        value["unsupported_items"] = json!(items.iter().filter(|i| i["guid"].is_null()).count());
        value["summaries_truncated"] = json!(items
            .iter()
            .filter(|i| i["summary_truncated"] == true)
            .count());
        value
    };
    let mut used = encoded_len(&page(&[], true)).saturating_add(64);
    let mut items = Vec::new();
    let mut shortened = false;
    for one in all.iter().skip(offset).take(limit) {
        let shown = item(one);
        let size = encoded_len(&shown).saturating_sub(1);
        if used.saturating_add(size) > MAX_PAGE_BYTES {
            shortened = true;
            break;
        }
        used = used.saturating_add(size);
        items.push(shown);
    }
    loop {
        let value = page(&items, shortened);
        if encoded_len(&value) <= MAX_PAGE_BYTES {
            return Ok(value);
        }
        if items.pop().is_none() {
            return Err("page_too_large");
        }
        shortened = true;
    }
}

fn icloud_calendars(library: &Library) -> Result<Vec<Calendar>, &'static str> {
    Ok(library
        .calendars()
        .map_err(|_| "library_unavailable")?
        .into_iter()
        .filter(|c| icloud(&c.guid))
        .collect())
}

pub(crate) fn calendars(library: &mut Library, args: Value) -> Result<Value, &'static str> {
    let args: Page = parse(&args)?;
    let limit = page_limit(args.limit)?;
    let all = icloud_calendars(library)?;
    let cache = cache_state(library)?;
    paged(
        &all,
        args.offset,
        limit,
        calendar_item,
        |_, _| json!({"source":"local_cache","cache":cache,"remote_verified":false}),
    )
}

/// Whether `e` overlaps `[from, to)`; a zero-length event counts where it starts.
fn overlaps(start: i64, end: i64, from: i64, to: i64) -> bool {
    start < to && (end > from || (end == start && start >= from))
}

pub(crate) fn events(library: &mut Library, args: Value) -> Result<Value, &'static str> {
    let (args, span) = range_args(&args)?;
    let limit = page_limit(args.limit)?;
    let calendars = icloud_calendars(library)?;
    if let Some(wanted) = &args.calendar_guid {
        if !calendars.iter().any(|c| &c.guid == wanted) {
            return Err("calendar_not_found");
        }
    }
    let (lo, hi) = span.widest();
    let found = wall_view(library, |library| {
        library
            .events_between(lo.saturating_sub(1), hi)
            .map_err(|_| "library_unavailable")
    })?;
    let (wall_from, wall_to) = span.walls();
    let (at_from, at_to) = span.instants();
    // Ordered by where each starts in the asked zone, then by id.
    let mut kept: Vec<(i64, Event)> = found
        .into_iter()
        .filter(|e| calendars.iter().any(|c| c.guid == e.calendar_guid))
        .filter(|e| {
            args.calendar_guid
                .as_ref()
                .is_none_or(|g| *g == e.calendar_guid)
        })
        .filter(|e| {
            if e.all_day {
                let (first, last) = all_day_days(e);
                overlaps(first * DAY, last * DAY, wall_from, wall_to)
            } else if floats(e) {
                overlaps(e.starts_at, e.ends_at, wall_from, wall_to)
            } else {
                overlaps(e.starts_at, e.ends_at, at_from, at_to)
            }
        })
        .map(|e| {
            let key = if e.all_day {
                instant_of(all_day_days(&e).0 * DAY, &span.zone.tz)
            } else if floats(&e) {
                instant_of(e.starts_at, &span.zone.tz)
            } else {
                e.starts_at
            };
            (key, e)
        })
        .collect();
    kept.sort_by(|(a, x), (b, y)| a.cmp(b).then_with(|| x.guid.cmp(&y.guid)));
    let all: Vec<Event> = kept.into_iter().map(|(_, e)| e).collect();
    let cache = cache_state(library)?;
    let coverage = coverage(library, Some(&span));
    let range = json!({"from":day_text(span.from_day),"to":day_text(span.to_day),"to_is_exclusive":true,"timezone":span.zone_name,"calendar_guid":args.calendar_guid});
    paged(
        &all,
        args.offset,
        limit,
        |e| item(e, Some(&span.zone)),
        |_, _| json!({"source":"local_cache","range":range,"coverage":coverage,"cache":cache,"complete_representation":false,"remote_verified":false}),
    )
}

/// Keeps the [`SEARCH_KEEPS`] matches nearest `now`, as `search_events_near` chooses them.
fn keep_nearest(found: &mut Vec<Event>, now: i64) {
    found.sort_by_cached_key(|e| {
        (
            e.ends_at
                .max(e.starts_at)
                .saturating_sub(now)
                .saturating_abs(),
            e.guid.clone(),
        )
    });
    found.truncate(SEARCH_KEEPS);
}

/// Events whose title, location or notes hold every word of the query, by the engine's own
/// folding, at most the [`SEARCH_KEEPS`] nearest today, iCloud calendars only.
///
/// When every cached calendar is iCloud's (the MCP server never adds any other), the engine's
/// `search_events_near` does it in one pass, keeping only matches. Otherwise its cut to the
/// nearest across every calendar could leave out every iCloud match, so the cache is read
/// once as identifiers and calendars, and only iCloud events are read whole, one at a time,
/// keeping only matches, never more than twice what is returned.
pub(crate) fn search(library: &mut Library, args: Value) -> Result<Value, &'static str> {
    use quince_core::fold;
    let args = search_args(&args)?;
    let limit = page_limit(args.limit)?;
    let calendars = icloud_calendars(library)?;
    let foreign = library
        .calendars()
        .map_err(|_| "library_unavailable")?
        .iter()
        .any(|c| !icloud(&c.guid));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    let words = fold::words(&args.query);
    let matches = |e: &Event| {
        let text = [
            Some(e.title.as_str()),
            e.location.as_deref(),
            e.notes.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
        fold::holds_all(&fold::fold(&text), &words)
    };
    let mut all: Vec<Event> = Vec::new();
    let mut matched = 0usize;
    if !foreign {
        all = wall_view(library, |library| {
            library
                .search_events_near(&args.query, now)
                .map_err(|_| "search_unavailable")
        })?;
        all.retain(|e| calendars.iter().any(|c| c.guid == e.calendar_guid));
        // The engine keeps the nearest when more match, and does not say how many did.
        matched = if all.len() >= SEARCH_KEEPS {
            SEARCH_KEEPS + 1
        } else {
            all.len()
        };
    } else if !words.is_empty() {
        wall_view(library, |library| {
            let rows = library
                .events_starting_between(i64::MIN / 4, i64::MAX / 4)
                .map_err(|_| "search_unavailable")?;
            for (guid, calendar) in rows {
                if !calendars.iter().any(|c| c.guid == calendar) {
                    continue;
                }
                let Some(e) = library.event(&guid).map_err(|_| "search_unavailable")? else {
                    continue;
                };
                if matches(&e) {
                    matched += 1;
                    all.push(e);
                    if all.len() >= 2 * SEARCH_KEEPS {
                        keep_nearest(&mut all, now);
                    }
                }
            }
            Ok(())
        })?;
    }
    let capped = matched > SEARCH_KEEPS;
    if capped {
        keep_nearest(&mut all, now);
    }
    all.sort_by(|a, b| {
        a.starts_at
            .cmp(&b.starts_at)
            .then_with(|| a.guid.cmp(&b.guid))
    });
    let cache = cache_state(library)?;
    paged(
        &all,
        args.offset,
        limit,
        |e| item(e, None),
        |_, _| {
            json!({"source":"local_cache","search_keeps_at_most":SEARCH_KEEPS,"may_be_incomplete":capped,
                "order":"by start; all-day and floating events by their wall-clock start",
                "cache":cache,"complete_representation":false,"remote_verified":false})
        },
    )
}

/// Every text cut to `chars` characters, identifiers excepted.
fn cut_event(value: &Value, chars: usize, cut_any: &mut bool) -> Value {
    match value {
        Value::String(text) => Value::String(cut(Some(text), chars, cut_any).unwrap_or_default()),
        Value::Array(list) => {
            Value::Array(list.iter().map(|v| cut_event(v, chars, cut_any)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let v = if ["guid", "calendar_guid", "series_guid"].contains(&k.as_str()) {
                        v.clone()
                    } else {
                        cut_event(v, chars, cut_any)
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

pub(crate) fn get(library: &mut Library, args: Value) -> Result<Value, &'static str> {
    let args = get_args(&args)?;
    let calendars = icloud_calendars(library)?;
    let event = wall_view(library, |library| {
        library.event(&args.guid).map_err(|_| "library_unavailable")
    })?
    .ok_or("not_found")?;
    if event.calendar_guid.len() > MAX_GUID_BYTES {
        return Err("calendar_guid_too_long");
    }
    let calendar = calendars
        .iter()
        .find(|c| c.guid == event.calendar_guid)
        .ok_or("not_found")?;
    let mut whole = summary(&event, None, usize::MAX);
    if let Some(map) = whole.as_object_mut() {
        map.remove("summary_truncated");
        map.insert("notes".into(), json!(event.notes));
        map.insert("url".into(), json!(event.url));
        map.insert("etag".into(), json!(event.etag));
        map.insert(
            "calendar".into(),
            json!({"guid":calendar.guid,"title":calendar.title,"read_only":!calendar.writable,"is_default":calendar.is_default}),
        );
    }
    let cache = cache_state(library)?;
    let coverage = coverage(library, None);
    for level in EVENT_LEVELS {
        let mut cut_any = false;
        let shown = match level {
            None => whole.clone(),
            Some(chars) => cut_event(&whole, chars, &mut cut_any),
        };
        let value = json!({
            "source": "local_cache",
            "event": shown,
            "event_truncated": cut_any,
            "truncation": level.filter(|_| cut_any).map(|chars| json!({"max_chars_per_text":chars})),
            "complete_representation": false,
            "not_included": NOT_INCLUDED,
            "cache": cache,
            "coverage": coverage,
            "remote_verified": false,
        });
        if encoded_len(&value) <= MAX_EVENT_BYTES {
            return Ok(value);
        }
    }
    Err("event_too_large")
}

// --- Refresh.

/// Resource limits of one refresh. Bytes are counted as decoded, as they arrive.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct RefreshLimits {
    /// One response.
    pub max_response_bytes: usize,
    /// Every response of the refresh together.
    pub max_total_bytes: usize,
    /// Distinct events read over the whole window.
    pub max_events: usize,
    /// The whole refresh; nothing is stored once it has passed.
    pub timeout: Duration,
    /// The time source the deadline is checked against; `Instant::now` outside tests.
    pub clock: fn() -> Instant,
}

impl Default for RefreshLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: 8 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_events: 50_000,
            timeout: Duration::from_secs(60),
            clock: Instant::now,
        }
    }
}

/// Why a refresh read stopped. Apple's own error bodies are never read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    Reauth,
    Busy,
    Failed,
    TooLarge,
    TooManyEvents,
}

impl Stop {
    fn code(self) -> &'static str {
        match self {
            Stop::Reauth => "login_required",
            Stop::Busy | Stop::Failed => "calendar_refresh_failed_cache_kept",
            Stop::TooLarge => "calendar_response_too_large_cache_kept",
            Stop::TooManyEvents => "calendar_too_many_events_cache_kept",
        }
    }

    /// What the library records for the failed pass: a fixed phrase, never Apple's text.
    fn error(self) -> quince_icloud::Error {
        match self {
            Stop::Reauth => quince_icloud::Error::ReauthRequired,
            Stop::Busy => quince_icloud::Error::Busy(None),
            other => quince_icloud::Error::Protocol(other.code().into()),
        }
    }
}

fn refused(status: u16) -> Option<Stop> {
    match status {
        200..=299 => None,
        450 => Some(Stop::Reauth),
        429 | 500..=599 => Some(Stop::Busy),
        _ => Some(Stop::Failed),
    }
}

/// One window read from `/ca/startup` or `/ca/events`, as the engine's `CalendarClient`
/// asks for it, its body read under the limits and parsed by the engine's reader.
async fn window_read(
    client: &Client,
    root: &str,
    path: &str,
    (from, to): (i64, i64),
    limits: &RefreshLimits,
    budget: &mut usize,
) -> Result<(Snapshot, Vec<String>), Stop> {
    let mut query = client.service_params();
    // Without the web client's version Apple answers 200 with no events at all.
    query.push(("clientVersion".into(), "5.1".into()));
    query.push(("requestID".into(), "4".into()));
    query.push(("startDate".into(), day_text(from)));
    query.push(("endDate".into(), day_text(to)));
    query.push(("lang".into(), "en-us".into()));
    query.push(("usertz".into(), "UTC".into()));
    let response = client
        .http()
        .get(format!("{}{path}", root.trim_end_matches('/')))
        .query(&query)
        .send()
        .await
        .map_err(|_| Stop::Failed)?;
    if let Some(stop) = refused(response.status().as_u16()) {
        return Err(stop);
    }
    let body = read_capped!(response, limits.max_response_bytes, budget)?;
    let body: Value = serde_json::from_slice(&body).map_err(|_| Stop::Failed)?;
    let listed = checked_rows(&body, limits)?;
    Ok((parse_snapshot(&body), listed))
}

/// Checks an answer before the engine reads it, and returns the id of every event row in it.
/// It must be a JSON object. Its rows are counted before they are parsed, and a zone name
/// longer than any zone's is refused: the engine's zone lookup tries every tail of a
/// slash-separated name, which on a long one would hold the server past its deadline. Every
/// row with an id counts as listed, read or not, so a row the engine cannot read is never
/// taken as removed. An answer without an `Event` list has no events, as the engine reads it.
fn checked_rows(body: &Value, limits: &RefreshLimits) -> Result<Vec<String>, Stop> {
    if !body.is_object() {
        return Err(Stop::Failed);
    }
    let Some(rows) = body.get("Event").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    if rows.len() > limits.max_events {
        return Err(Stop::TooManyEvents);
    }
    let mut listed = Vec::with_capacity(rows.len());
    for row in rows {
        if row
            .get("tz")
            .and_then(Value::as_str)
            .is_some_and(|tz| tz.len() > MAX_ZONE_BYTES)
        {
            return Err(Stop::Failed);
        }
        if let Some(guid) = row.get("guid").and_then(Value::as_str) {
            listed.push(guid.to_string());
        }
    }
    Ok(listed)
}

/// As the engine's `fetch_calendar`: every 28-day window asked both ways (`/ca/startup` does
/// not always carry the events), one after another, merged; refused whole if any read fails,
/// so a partial answer is never stored as the calendar.
async fn fetch(
    client: &Client,
    root: &str,
    window: Window,
    limits: &RefreshLimits,
) -> Result<(Snapshot, std::collections::HashSet<String>), Stop> {
    let mut budget = limits.max_total_bytes;
    let mut calendars = Vec::new();
    let mut events = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut listed = std::collections::HashSet::new();
    let (first, last) = window.asked();
    let mut start = first;
    while start <= last {
        let end = (start + APPLE_WINDOW_DAYS - 1).min(last);
        for path in ["/ca/startup", "/ca/events"] {
            let (read, rows) =
                window_read(client, root, path, (start, end), limits, &mut budget).await?;
            listed.extend(rows);
            if calendars.is_empty() {
                calendars = read.calendars;
            }
            for event in read.events {
                if seen.insert(event.guid.clone()) {
                    events.push(event);
                }
            }
            if events.len() > limits.max_events {
                return Err(Stop::TooManyEvents);
            }
        }
        start = end + 1;
    }
    // Every iCloud account has a calendar: an answer with none is a broken answer.
    if calendars.is_empty() {
        return Err(Stop::Failed);
    }
    // Removal is left to `prune`, over the window's wall-clock days.
    Ok((
        Snapshot {
            calendars,
            events,
            covers: None,
        },
        listed,
    ))
}

/// Removes the events of the calendars Apple listed that start in `covers` and that Apple did
/// not list (`returned`: every row Apple sent with an id, whether the engine could read it). As `apply_calendar` does for its own window, but an all-day or floating event
/// is judged by its wall-clock start (read through the UTC view, see [`wall_view`]) rather
/// than as an instant in this computer's zone, which put one on the window's first day
/// outside it east of UTC and left it cached after Apple removed it.
fn prune(
    library: &mut Library,
    covers: (i64, i64),
    known: &std::collections::HashSet<String>,
    returned: &std::collections::HashSet<String>,
) -> quince_icloud::Result<usize> {
    let utc = zone("UTC").ok_or_else(|| {
        quince_icloud::Error::Protocol("calendar_refresh_failed_cache_kept".into())
    })?;
    library.set_zone(Some(utc.tz));
    let found = library.events_starting_between(covers.0, covers.1);
    library.set_zone(None);
    let gone: Vec<String> = found?
        .into_iter()
        .filter(|(guid, calendar)| known.contains(calendar) && !returned.contains(guid))
        .map(|(guid, _)| guid)
        .collect();
    library.forget_events(&gone)?;
    Ok(gone.len())
}

/// Production refresh: the directory's own keyring session and Apple's endpoints only.
/// Caller holds the private directory's exclusive operation lock.
pub(crate) async fn refresh(
    dir: &Path,
    approved: bool,
    args: Value,
) -> Result<Value, &'static str> {
    let window = refresh_window(&args)?;
    gate(dir, approved)?;
    let store = Store::isolated_keyring(dir).map_err(|_| "secure_storage_unavailable")?;
    let session = store
        .try_load()
        .map_err(|_| "login_required_unlock_secure_storage")?;
    if !session.is_resumable() {
        return Err("login_required");
    }
    let client = Client::with(dir, Endpoints::default(), store).map_err(|_| "login_required")?;
    timed(dir, client, window, RefreshLimits::default()).await
}

/// Test seam with synthetic endpoints, never approved for `reads_and_writes`.
/// Caller holds the private directory's exclusive operation lock.
pub async fn refresh_with_client(
    dir: &Path,
    client: Client,
    args: Value,
) -> Result<Value, &'static str> {
    refresh_with_client_limited(dir, client, args, RefreshLimits::default()).await
}

/// [`refresh_with_client`] under other limits, so tests can reach them with small bodies.
#[doc(hidden)]
pub async fn refresh_with_client_limited(
    dir: &Path,
    client: Client,
    args: Value,
    limits: RefreshLimits,
) -> Result<Value, &'static str> {
    let window = refresh_window(&args)?;
    gate(dir, false)?;
    timed(dir, client, window, limits).await
}

const TIMED_OUT: &str = "calendar_refresh_timeout_cache_kept";

async fn timed(
    dir: &Path,
    client: Client,
    window: Window,
    limits: RefreshLimits,
) -> Result<Value, &'static str> {
    // As for Contacts: reads are cancelled at the deadline, and the deadline is checked again
    // inside the store's transaction, which rolls back when it has passed.
    let started_for = owner(dir)?;
    let deadline = (limits.clock)() + limits.timeout;
    match tokio::time::timeout(
        limits.timeout,
        read_window(dir, client, window, limits, deadline),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            record_timeout_of(dir, &started_for, SERVICE, TIMED_OUT);
            Err(TIMED_OUT)
        }
    }
}

async fn read_window(
    dir: &Path,
    mut client: Client,
    window: Window,
    limits: RefreshLimits,
    deadline: Instant,
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
    let library = Library::open(dir).map_err(|_| "library_unavailable")?;
    if binding(&library, dsid)? != Binding::Same {
        return Err("account_mismatch_use_new_state_directory");
    }
    let root = client
        .session()
        .service_url(SERVICE)
        .ok_or("calendar_service_unavailable")?;
    let data = LibraryLock::new(library, Some(dir.to_owned()));
    // The pass stores only for the account its parameters ask as, and only while the
    // library still names that account.
    let ctx = pass::Ctx::new(
        client.http().clone(),
        client.service_params(),
        None,
        Vec::new(),
        &pass::NoHooks,
    );
    let stopped = std::sync::Mutex::new(None::<&'static str>);
    let read = std::sync::Mutex::new((0usize, 0usize));
    let lock = tokio::sync::Mutex::new(());
    let report = pass::driven(SERVICE, &ctx, &data, &lock, async {
        let mut fetched = fetch(&client, &root, window, &limits)
            .await
            .map_err(|stop| {
                *stopped
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(stop.code());
                stop.error()
            });
        let expired = || {
            let late = (limits.clock)() >= deadline;
            if late {
                *stopped
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(TIMED_OUT);
            }
            late
        };
        if fetched.is_ok() && expired() {
            fetched = Err(quince_icloud::Error::Protocol(TIMED_OUT.into()));
        }
        // Queued Calendar changes are neither sent nor laid over what Apple returned.
        pass::store(
            SERVICE,
            &data,
            &ctx,
            fetched,
            |library, (mut snapshot, returned)| {
                // Checked again inside the transaction: another process may have changed the
                // account since `pass::store` looked, and nothing is written for the wrong one.
                if !pass::owned(library, ctx.account.as_deref()) {
                    *stopped
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some("account_changed_during_refresh_cache_kept");
                    return Err(quince_icloud::Error::Protocol(pass::NOT_YOURS_WORDS.into()));
                }
                let known: std::collections::HashSet<String> =
                    snapshot.calendars.iter().map(|c| c.guid.clone()).collect();
                // `apply_calendar` replaces the set of calendars and keeps only other accounts'
                // (CalDAV): subscribed calendars are carried over as they are, so neither they nor
                // their events go. They are not Apple's, so `prune` never judges them.
                snapshot.calendars.extend(
                    library
                        .calendars()?
                        .into_iter()
                        .filter(|c| c.guid.starts_with(quince_icloud::calendar_feeds::PREFIX)),
                );
                let summary = quince_icloud::sync::apply_calendar(library, snapshot)?;
                prune(library, window.covers(), &known, &returned)?;
                library.mark_synced(SERVICE, Some(&window.token()))?;
                *read
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    (summary.calendars, summary.events);
                // Last, before the transaction commits: past the deadline, it rolls back and the
                // pass is recorded as failed.
                if expired() {
                    return Err(quince_icloud::Error::Protocol(TIMED_OUT.into()));
                }
                Ok("read".to_string())
            },
        )
        .await
    })
    .await;
    match report.outcome {
        pass::Outcome::Ok => {}
        pass::Outcome::Paused => return Err("calendar_paused_approve_on_apple_device"),
        _ if report.detail.as_deref() == Some(pass::NOT_YOURS_WORDS) => {
            return Err("account_changed_during_refresh_cache_kept")
        }
        _ => {
            let stopped = *stopped
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            return Err(stopped.unwrap_or("calendar_refresh_failed_cache_kept"));
        }
    }
    let (calendars_read, events_read) = *read
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let library = data.lock().await;
    let cached = icloud_calendars(&library)?.len();
    let queued = library
        .outbox_pending(SERVICE)
        .map_err(|_| "library_unavailable")?
        .len();
    let mut shown = window.view();
    shown["asked_apple_in"] = json!("UTC");
    Ok(json!({
        "service": SERVICE,
        "outcome": "ok",
        "window": shown,
        "calendars_read": calendars_read,
        "events_read": events_read,
        "cached_calendars": cached,
        "last_refreshed_at": report.last_synced_at,
        "queued_calendar_changes": queued,
        "queued_changes_sent": 0,
        "remote_verified": false,
        "verification": "Apple's calendar over this window was read into the local cache; events in the window that Apple no longer lists were removed from the cache; nothing was sent to Apple",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn day_arithmetic_round_trips_and_rejects_impossible_dates() {
        for day in [-1, 0, 59, 60, 365, 10_957, 20_000, 84_000] {
            let (y, m, d) = civil_from_days(day);
            assert_eq!(days_from_civil(y, m, d), day);
        }
        assert_eq!(parse_day("1970-01-01"), Ok(0));
        assert_eq!(parse_day("2024-02-29").map(day_text).unwrap(), "2024-02-29");
        for bad in [
            "2026-02-29",
            "2026-13-01",
            "2026-00-10",
            "2026-1-01",
            "1969-12-31",
            "+026-01-01",
            "2026-01-32",
        ] {
            assert_eq!(parse_day(bad), Err("invalid_date"), "{bad}");
        }
        assert_eq!(wall_text(-1), "1969-12-31T23:59:59");
    }

    #[test]
    fn all_day_days_survive_a_shift_at_a_daylight_saving_midnight() {
        let day = 17_839; // 2018-11-04, when Sao Paulo's clocks skipped midnight.
        let e = Event {
            guid: "D".into(),
            all_day: true,
            // The day before, its end read an hour late; and a start read an hour late.
            starts_at: (day - 1) * DAY,
            ends_at: day * DAY + 3600,
            ..Default::default()
        };
        assert_eq!(all_day_days(&e), (day - 1, day));
        let e = Event {
            starts_at: day * DAY + 3600,
            ends_at: (day + 1) * DAY,
            ..e
        };
        assert_eq!(all_day_days(&e), (day, day + 1));
        assert_eq!(times(&e, None).0, json!({"date":"2018-11-04"}));
    }

    #[test]
    fn long_zone_names_are_not_looked_up() {
        assert!(zone("Europe/Berlin").is_some());
        assert!(zone(&"a/".repeat(20_000)).is_none());
        let e = Event {
            guid: "E".into(),
            timezone: Some(format!("{}Europe/Berlin", "x/".repeat(40))),
            ..Default::default()
        };
        assert_eq!(times(&e, None).2, json!(false));
    }

    #[test]
    fn occurrence_ids_give_their_original_start() {
        assert!(
            matches!(original_of("S__20261102T073300Z"), Some(Original::At(at)) if utc_text(at) == "2026-11-02T07:33:00Z")
        );
        assert!(
            matches!(original_of("S__20261102"), Some(Original::Day(d)) if day_text(d) == "2026-11-02")
        );
        assert!(original_of("S__2026110").is_none());
        assert!(original_of("S__20261102T253300Z").is_none());
        assert!(original_of("S").is_none());
    }

    #[test]
    fn the_default_window_is_whole_months_within_the_limit() {
        let w = default_window();
        assert_eq!(civil_from_days(w.from).2, 1);
        assert_eq!(civil_from_days(w.to).2, 1);
        assert!(w.to - w.from <= MAX_REFRESH_DAYS);
        assert!(w.from <= today() && today() < w.to);
    }
}

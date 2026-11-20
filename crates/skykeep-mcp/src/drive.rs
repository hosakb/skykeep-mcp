//! Apple iCloud Drive, read-only metadata: a cached folder listing, one item's details, a name
//! search, and an explicit refresh that reads one folder's item list (and that of each folder
//! on its path) into the local cache. Nothing here reads file contents, writes to Apple, sends
//! a queued change or touches a local file path. The engine crates own the parsing and the
//! cache; the refresh's requests are made here so every response is read under a byte limit,
//! and the engine's own reader (`parse_folder`) does the rest.
//!
//! Paths. A cloud path is `/` and then names joined by `/`, matched against the names Apple
//! lists after composing both to Unicode NFC, and otherwise exactly. Each name is data: an
//! empty name, `.`, `..` and control characters are refused, never interpreted. An item whose
//! name cannot be written that way (a `/` or a control character in it) is still listed and
//! read by its id.
//!
//! Which folders have been read is kept beside the cache (`LISTED_KEY`), so a folder never
//! read reads as not listed rather than as empty.
use crate::account::{binding, Binding};
use crate::calendar::utc_text;
use crate::contacts::{cut, encoded_len, gate, owner, read_capped, record_timeout_of};
use quince_auth::{Client, Endpoints, Store};
use quince_core::drive::{DriveItem, ROOT};
use quince_core::Library;
use quince_icloud::drive::TRASH;
use quince_sync::{library_lock::LibraryLock, pass};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};

const SERVICE: &str = "drive";
const DEFAULT_LIMIT: usize = 25;
pub(crate) const MAX_LIMIT: usize = 100;
pub(crate) const MAX_QUERY_BYTES: usize = 256;
pub(crate) const MAX_ID_BYTES: usize = 512;
pub(crate) const MAX_PATH_BYTES: usize = 1024;
pub(crate) const MAX_NAME_BYTES: usize = 255;
pub(crate) const MAX_DEPTH: usize = 32;
/// What `drive_search` keeps when more match: the most recently changed.
const SEARCH_KEEPS: usize = 1000;
/// Folders whose reading is remembered; past this the oldest are forgotten and read as not
/// listed again.
const MAX_LISTED: usize = 10_000;
/// Where the folders read by `drive_refresh` are kept: a JSON object, id to unix seconds.
const LISTED_KEY: &str = "mcp.drive.listed";

/// Caps on a tool result's text as encoded in the JSON-RPC frame, as for Contacts.
const MAX_PAGE_BYTES: usize = 262_144;
const MAX_GET_BYTES: usize = 65_536;
const MAX_ITEM_BYTES: usize = 32_768;
/// Characters per text field, tried in turn until a summary fits. Zero leaves the ids, kinds,
/// sizes and dates only; with ids at most `MAX_ID_BYTES` the last level always fits.
const SUMMARY_LEVELS: [usize; 4] = [512, 128, 32, 0];
/// The same for one item: whole, then each text cut.
const GET_LEVELS: [Option<usize>; 3] = [None, Some(4096), Some(256)];
/// Dates outside these unix seconds (1970 to 2200) are not written as dates.
const DATES: std::ops::RangeInclusive<i64> = 0..=7_258_118_400;

/// What a cached item does not hold.
const NOT_INCLUDED: [&str; 6] = [
    "file contents; this server never downloads, uploads, renames, moves or deletes Drive items",
    "items in Recently Deleted",
    "folders not yet read with drive_refresh",
    "sharing, collaboration and version history",
    "tags, colors and Finder comments",
    "local file paths; only cloud paths and ids",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Locate {
    path: Option<String>,
    id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    path: Option<String>,
    id: Option<String>,
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

/// Where an argument points: the root, a cloud path's names, or an id.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Target {
    Path(Vec<String>),
    Id(String),
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

/// The names of a cloud path. `/` is the root and has none.
fn path_names(path: &str) -> Result<Vec<String>, &'static str> {
    if path.len() > MAX_PATH_BYTES {
        return Err("path_too_long");
    }
    let Some(rest) = path.strip_prefix('/') else {
        return Err("invalid_path");
    };
    if rest.is_empty() {
        return Ok(Vec::new());
    }
    let names: Vec<&str> = rest.split('/').collect();
    if names.len() > MAX_DEPTH {
        return Err("path_too_deep");
    }
    if names.iter().any(|name| !addressable(name)) {
        return Err("invalid_path");
    }
    Ok(names.into_iter().map(ToString::to_string).collect())
}

/// Whether `name` can be one name of a cloud path.
fn addressable(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.chars().any(char::is_control)
}

fn checked_id(id: &str) -> Result<(), &'static str> {
    if id.is_empty() || id.len() > MAX_ID_BYTES || id.chars().any(char::is_control) {
        return Err("invalid_id");
    }
    Ok(())
}

/// A folder argument: the root when neither is given. Recently Deleted and file ids are
/// refused by their form, before the cache is read.
fn folder_target(path: Option<&str>, id: Option<&str>) -> Result<Target, &'static str> {
    match (path, id) {
        (Some(_), Some(_)) => Err("invalid_arguments"),
        (Some(path), None) => Ok(Target::Path(path_names(path)?)),
        (None, Some(id)) => {
            checked_id(id)?;
            if id == TRASH || id.contains(TRASH) {
                return Err("trash_not_supported");
            }
            if id != ROOT && !id.starts_with("FOLDER::") {
                return Err("not_a_folder");
            }
            Ok(Target::Id(id.to_string()))
        }
        (None, None) => Ok(Target::Path(Vec::new())),
    }
}

/// An item argument: exactly one of the two.
fn item_target(locate: &Locate) -> Result<Target, &'static str> {
    match (locate.path.as_deref(), locate.id.as_deref()) {
        (Some(path), None) => Ok(Target::Path(path_names(path)?)),
        (None, Some(id)) => {
            checked_id(id)?;
            if id.contains(TRASH) {
                return Err("trash_not_supported");
            }
            Ok(Target::Id(id.to_string()))
        }
        _ => Err("invalid_arguments"),
    }
}

fn list_args(args: &Value) -> Result<(Target, usize, usize), &'static str> {
    let list: List = parse(args)?;
    let limit = page_limit(list.limit)?;
    let target = folder_target(list.path.as_deref(), list.id.as_deref())?;
    Ok((target, list.offset, limit))
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

fn refresh_target(args: &Value) -> Result<Target, &'static str> {
    let locate: Locate = parse(args)?;
    folder_target(locate.path.as_deref(), locate.id.as_deref())
}

/// Checks a Drive tool's arguments before any approval prompt or cache access.
pub(crate) fn validate(name: &str, args: &Value) -> Result<(), &'static str> {
    match name {
        "drive_list" => list_args(args).map(|_| ()),
        "drive_get" => item_target(&parse(args)?).map(|_| ()),
        "drive_search" => search_args(args).map(|_| ()),
        "drive_refresh" => refresh_target(args).map(|_| ()),
        _ => Ok(()),
    }
}

/// What the approval prompt says a refresh does.
pub(crate) fn refresh_scope() -> Value {
    json!({
        "services": ["drive"],
        "refresh": "one read of an Apple iCloud Drive folder's item list, and of each folder on its path, into the local cache, at most 60 seconds",
        "download": "no file contents are read; names, kinds, sizes and dates only",
        "send": "nothing is sent; queued changes stay queued",
    })
}

// --- The cache.

fn is_trash(item: &DriveItem) -> bool {
    item.drivewsid.contains(TRASH) || item.parent_id.as_deref().is_some_and(|p| p.contains(TRASH))
}

/// What `drive_refresh` has read: folder id to unix seconds.
fn listed_map(library: &Library) -> serde_json::Map<String, Value> {
    library
        .state(LISTED_KEY)
        .ok()
        .flatten()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|value| match value {
            Value::Object(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default()
}

fn listed_at(library: &Library, id: &str) -> Option<i64> {
    listed_map(library).get(id).and_then(Value::as_i64)
}

fn children(library: &Library, id: &str) -> Result<Vec<DriveItem>, &'static str> {
    let mut items = library
        .drive_children(id)
        .map_err(|_| "library_unavailable")?;
    items.retain(|i| !is_trash(i));
    // The engine's order, with the id to keep equal names in one order.
    items.sort_by(|a, b| {
        (!a.is_container())
            .cmp(&!b.is_container())
            .then_with(|| quince_core::fold::natural(&a.name, &b.name))
            .then_with(|| a.drivewsid.cmp(&b.drivewsid))
    });
    Ok(items)
}

fn same_name(item: &DriveItem, name: &str) -> bool {
    quince_core::fold::composed(&item.display_name()) == quince_core::fold::composed(name)
}

/// The cached item a path names, `None` for the root. Each folder on the way must have been
/// listed, or the cache cannot say what is in it.
fn resolve_cached(library: &Library, names: &[String]) -> Result<Option<DriveItem>, &'static str> {
    let listed = listed_map(library);
    let mut at: Option<DriveItem> = None;
    for name in names {
        let folder = at.as_ref().map_or(ROOT, |i| i.drivewsid.as_str());
        if at.as_ref().is_some_and(|i| !i.is_container()) {
            return Err("not_a_folder");
        }
        if !listed.contains_key(folder) {
            return Err("path_not_in_cache_run_drive_refresh");
        }
        let mut found = children(library, folder)?
            .into_iter()
            .filter(|i| same_name(i, name));
        let first = found.next().ok_or("not_found")?;
        if found.next().is_some() {
            return Err("ambiguous_path_use_id");
        }
        at = Some(first);
    }
    Ok(at)
}

fn cached_item(library: &Library, id: &str) -> Result<Option<DriveItem>, &'static str> {
    Ok(library
        .drive_item(id)
        .map_err(|_| "library_unavailable")?
        .filter(|i| !is_trash(i)))
}

/// The cloud path of a cached item, by its parents up to the root. `None` when the chain is
/// not cached whole or a name cannot be written in a path.
fn cloud_path(library: &Library, item: &DriveItem) -> Option<String> {
    let mut names = vec![item.display_name()];
    let mut parent = item.parent_id.clone();
    loop {
        let id = parent?;
        if id == ROOT {
            break;
        }
        if names.len() >= MAX_DEPTH {
            return None;
        }
        let up = library.drive_item(&id).ok().flatten()?;
        names.push(up.display_name());
        parent = up.parent_id;
    }
    if !names.iter().all(|n| addressable(n)) {
        return None;
    }
    names.reverse();
    let path = format!("/{}", names.join("/"));
    (path.len() <= MAX_PATH_BYTES).then_some(path)
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
        "refresh": "only by drive_refresh, one folder at a time; there is no background Drive refresh",
    }))
}

fn date(at: Option<i64>) -> Value {
    at.filter(|at| DATES.contains(at))
        .map_or(Value::Null, |at| Value::String(utc_text(at)))
}

fn kind(item: &DriveItem) -> &'static str {
    match item.kind.as_str() {
        "FOLDER" => "folder",
        "APP_LIBRARY" => "app_library",
        "FILE" => "file",
        _ => "other",
    }
}

/// An item's fields, every text cut to `chars` (`None`: whole). Ids are never cut.
fn fields(item: &DriveItem, chars: Option<usize>, path: Option<&str>, cut_any: &mut bool) -> Value {
    let mut text = |t: Option<&str>| match chars {
        None => t.map(ToString::to_string),
        Some(chars) => cut(t, chars, cut_any),
    };
    let other = kind(item) == "other";
    json!({
        "id": item.drivewsid,
        "parent_id": item.parent_id,
        "name": text(Some(&item.name)),
        "extension": text(item.extension.as_deref()),
        "display_name": text(Some(&item.display_name())),
        "path": text(path),
        "kind": kind(item),
        "apple_type": if other { text(Some(&item.kind)) } else { None },
        "is_folder": item.is_container(),
        "size": item.size,
        "child_count": item.child_count,
        "created_at": date(item.created_at),
        "modified_at": date(item.modified_at),
    })
}

/// One page entry. An id too long to ask for again is never cut into a different, unusable
/// one: the entry says so, with its length, and holds its place.
fn summary(item: &DriveItem, path: Option<&str>) -> Value {
    let longest = item
        .drivewsid
        .len()
        .max(item.parent_id.as_deref().map_or(0, str::len));
    if longest > MAX_ID_BYTES {
        return json!({"id":null,"unsupported":"id_too_long","id_bytes":item.drivewsid.len(),"name_truncated":true});
    }
    let mut shown = Value::Null;
    for chars in SUMMARY_LEVELS {
        let mut cut_any = false;
        shown = fields(item, Some(chars), path, &mut cut_any);
        shown["name_truncated"] = json!(cut_any);
        if encoded_len(&shown) <= MAX_ITEM_BYTES {
            break;
        }
    }
    shown
}

/// A page of entries under the byte cap, stopping early with `next_offset` rather than grow
/// past it. `envelope` adds the fields of its tool.
/// `entries` are the page's own, from `offset` on; `total` counts every match.
fn paged(
    entries: &[Value],
    total: usize,
    offset: usize,
    limit: usize,
    envelope: impl Fn(&mut Value),
) -> Result<Value, &'static str> {
    let page = |items: &[Value], shortened: bool| {
        let next = offset.saturating_add(items.len());
        let mut value = json!({
            "source": "local_cache",
            "items": items,
            "total": total,
            "offset": offset,
            "limit": limit,
            "next_offset": (next < total).then_some(next),
            "page_shortened_to_fit": shortened,
            "unsupported_items": items.iter().filter(|i| i["id"].is_null()).count(),
            "names_truncated": items.iter().filter(|i| i["name_truncated"] == true && !i["id"].is_null()).count(),
            "remote_verified": false,
        });
        envelope(&mut value);
        value
    };
    let mut used = encoded_len(&page(&[], true)).saturating_add(64);
    let mut items = Vec::new();
    let mut shortened = false;
    for entry in entries.iter().take(limit) {
        let size = encoded_len(entry).saturating_sub(1);
        if used.saturating_add(size) > MAX_PAGE_BYTES {
            shortened = true;
            break;
        }
        used = used.saturating_add(size);
        items.push(entry.clone());
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

/// The folder a list or refresh argument names, from the cache: its id and cloud path.
fn cached_folder(
    library: &Library,
    target: &Target,
) -> Result<(String, Option<String>), &'static str> {
    match target {
        Target::Path(names) => match resolve_cached(library, names)? {
            None => Ok((ROOT.to_string(), Some("/".into()))),
            Some(item) if item.is_container() => {
                let path = cloud_path(library, &item);
                Ok((item.drivewsid, path))
            }
            Some(_) => Err("not_a_folder"),
        },
        Target::Id(id) if id == ROOT => Ok((ROOT.to_string(), Some("/".into()))),
        Target::Id(id) => match cached_item(library, id)? {
            Some(item) if item.is_container() => {
                let path = cloud_path(library, &item);
                Ok((item.drivewsid, path))
            }
            Some(_) => Err("not_a_folder"),
            None => Err("not_found"),
        },
    }
}

pub(crate) fn list(library: &Library, args: Value) -> Result<Value, &'static str> {
    let (target, offset, limit) = list_args(&args)?;
    let (id, path) = cached_folder(library, &target)?;
    let at = listed_at(library, &id);
    let items = if at.is_some() {
        children(library, &id)?
    } else {
        Vec::new()
    };
    // Only the requested page is summarized.
    let entries: Vec<Value> = items
        .iter()
        .skip(offset)
        .take(limit)
        .map(|i| summary(i, None))
        .collect();
    let cache = cache_state(library)?;
    let folder = json!({"id":id,"path":path,"listed":at.is_some(),"listed_at":at});
    paged(&entries, items.len(), offset, limit, |page| {
        page["folder"] = folder.clone();
        // Complete as of the folder's last read: every item Apple listed then, trash aside.
        page["complete"] = json!(at.is_some());
        page["cache"] = cache.clone();
        if at.is_none() {
            page["hint"] = json!("this folder has not been read yet; drive_refresh reads it");
        }
    })
}

/// A folder's cached children in no particular order: the rows and columns
/// `Library::drive_children` reads, without its name sort, which folds both names on every
/// comparison. For search, which orders its matches by date itself.
fn unsorted_children(library: &Library, parent: &str) -> Result<Vec<DriveItem>, ()> {
    let mut stmt = library
        .conn()
        .prepare_cached(
            "SELECT drivewsid, parent_id, name, extension, kind, size, child_count,
                    created_at, modified_at, etag
             FROM drive_items
             WHERE parent_id = ?1",
        )
        .map_err(|_| ())?;
    let rows = stmt
        .query_map([parent], |row| {
            Ok(DriveItem {
                drivewsid: row.get(0)?,
                parent_id: row.get(1)?,
                name: row.get(2)?,
                extension: row.get(3)?,
                kind: row.get(4)?,
                size: row.get(5)?,
                child_count: row.get(6)?,
                created_at: row.get(7)?,
                modified_at: row.get(8)?,
                etag: row.get(9)?,
            })
        })
        .map_err(|_| ())?;
    rows.collect::<Result<Vec<_>, _>>().map_err(|_| ())
}

/// Newest first: changed most recently, undated last, then by id so equal dates keep one
/// order. The engine's search orders the same way, without the id.
fn newest_first(a: &DriveItem, b: &DriveItem) -> std::cmp::Ordering {
    a.modified_at
        .is_none()
        .cmp(&b.modified_at.is_none())
        .then_with(|| b.modified_at.cmp(&a.modified_at))
        .then_with(|| a.drivewsid.cmp(&b.drivewsid))
}

/// Items whose name holds every word of `query` (case and accents aside, as the engine's
/// `search_drive` matches them), only in folders still marked as read: a folder whose mark
/// was let go (past `MAX_LISTED`) no longer says its items are current. Only eligible items
/// count toward `SEARCH_KEEPS`, so items in unmarked folders never crowd out the rest. At most
/// `SEARCH_KEEPS`, newest first, and whether more matched. One listed folder's children are
/// held at a time, and the matches kept never pass twice the cap.
fn eligible_matches(
    library: &Library,
    query: &str,
) -> Result<(Vec<DriveItem>, bool), &'static str> {
    let words = quince_core::fold::words(query);
    if words.is_empty() {
        return Ok((Vec::new(), false));
    }
    let mut folders: Vec<String> = listed_map(library).into_iter().map(|(id, _)| id).collect();
    folders.sort();
    let mut found: Vec<DriveItem> = Vec::new();
    for folder in folders {
        let held = unsorted_children(library, &folder).map_err(|_| "search_unavailable")?;
        for item in held.into_iter().filter(|i| !is_trash(i)) {
            let name = format!("{}.{}", item.name, item.extension.as_deref().unwrap_or(""));
            if quince_core::fold::holds_all(&quince_core::fold::fold(&name), &words) {
                found.push(item);
            }
        }
        if found.len() > 2 * SEARCH_KEEPS {
            found.sort_by(newest_first);
            found.truncate(SEARCH_KEEPS + 1);
        }
    }
    found.sort_by(newest_first);
    let more = found.len() > SEARCH_KEEPS;
    found.truncate(SEARCH_KEEPS);
    Ok((found, more))
}

pub(crate) fn search(library: &Library, args: Value) -> Result<Value, &'static str> {
    let args = search_args(&args)?;
    let limit = page_limit(args.limit)?;
    let (found, capped) = eligible_matches(library, &args.query)?;
    let entries: Vec<Value> = found
        .iter()
        .skip(args.offset)
        .take(limit)
        .map(|i| summary(i, cloud_path(library, i).as_deref()))
        .collect();
    let cache = cache_state(library)?;
    paged(&entries, found.len(), args.offset, limit, |page| {
        page["matches_capped"] = json!(capped);
        page["searched"] = json!("names of items in folders read by drive_refresh");
        page["cache"] = cache.clone();
    })
}

/// Every text cut to `chars` characters, ids excepted.
fn cut_value(value: &Value, chars: usize, cut_any: &mut bool) -> Value {
    match value {
        Value::String(text) => Value::String(cut(Some(text), chars, cut_any).unwrap_or_default()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let v = if k == "id" || k == "parent_id" {
                        v.clone()
                    } else {
                        cut_value(v, chars, cut_any)
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

pub(crate) fn get(library: &Library, args: Value) -> Result<Value, &'static str> {
    let target = item_target(&parse(&args)?)?;
    let item = match &target {
        Target::Path(names) => resolve_cached(library, names)?.ok_or("root_has_no_details")?,
        Target::Id(id) => cached_item(library, id)?.ok_or("not_found")?,
    };
    let path = cloud_path(library, &item);
    let at = item
        .is_container()
        .then(|| listed_at(library, &item.drivewsid))
        .flatten();
    let mut whole_cut = false;
    let whole = fields(&item, None, path.as_deref(), &mut whole_cut);
    let cache = cache_state(library)?;
    for level in GET_LEVELS {
        let mut cut_any = false;
        let shown = match level {
            None => whole.clone(),
            Some(chars) => cut_value(&whole, chars, &mut cut_any),
        };
        let value = json!({
            "source": "local_cache",
            "item": shown,
            "item_truncated": cut_any,
            "truncation": level.filter(|_| cut_any).map(|chars| json!({"max_chars_per_text":chars})),
            "path_addressable": path.is_some(),
            "listed": item.is_container().then_some(at.is_some()),
            "listed_at": at,
            "file_contents_included": false,
            "complete_representation": false,
            "not_included": NOT_INCLUDED,
            "cache": cache,
            "remote_verified": false,
        });
        if encoded_len(&value) <= MAX_GET_BYTES {
            return Ok(value);
        }
    }
    Err("item_too_large")
}

// --- Refresh.

/// Resource limits of one refresh. Bytes are counted as decoded, as they arrive.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct RefreshLimits {
    /// One folder's answer.
    pub max_response_bytes: usize,
    /// Every answer of the refresh together.
    pub max_total_bytes: usize,
    /// Items Apple lists in one folder.
    pub max_items: usize,
    /// One item as Apple sent it.
    pub max_item_bytes: usize,
    /// The whole refresh; nothing is stored once it has passed.
    pub timeout: Duration,
    /// The time source the deadline is checked against; `Instant::now` outside tests.
    pub clock: fn() -> Instant,
}

impl Default for RefreshLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: 32 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_items: 50_000,
            max_item_bytes: 64 * 1024,
            timeout: Duration::from_secs(60),
            clock: Instant::now,
        }
    }
}

/// What is read of a refusal, only to tell Advanced Data Protection's from any other. Never
/// stored or shown.
const MAX_REFUSAL_BYTES: usize = 4096;

/// Why a refresh read stopped. Apple's own error bodies are never stored or shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    Reauth,
    Busy,
    Failed,
    Paused,
    TooLarge,
    FolderTooLarge,
    ItemTooLarge,
    FolderGone,
    PathNotFound,
    Ambiguous,
    NotAFolder,
    InTrash,
}

impl Stop {
    fn code(self) -> &'static str {
        match self {
            Stop::Reauth => "login_required",
            Stop::Busy | Stop::Failed => "drive_refresh_failed_cache_kept",
            Stop::Paused => PAUSED,
            Stop::TooLarge => "drive_response_too_large_cache_kept",
            Stop::FolderTooLarge => "drive_folder_too_large_cache_kept",
            Stop::ItemTooLarge => "drive_item_too_large_cache_kept",
            Stop::FolderGone => "drive_folder_not_found_cache_kept",
            Stop::PathNotFound => "drive_path_not_found_cache_kept",
            Stop::Ambiguous => "drive_ambiguous_path_cache_kept",
            Stop::NotAFolder => "drive_not_a_folder_cache_kept",
            Stop::InTrash => "drive_folder_in_trash_cache_kept",
        }
    }

    /// What the library records for the failed pass: a fixed phrase, never Apple's text.
    fn error(self) -> quince_icloud::Error {
        match self {
            Stop::Reauth => quince_icloud::Error::ReauthRequired,
            Stop::Busy => quince_icloud::Error::Busy(None),
            Stop::Paused => quince_icloud::Error::NeedsDeviceApproval,
            other => quince_icloud::Error::Protocol(other.code().into()),
        }
    }
}

const PAUSED: &str = "drive_paused_approve_on_apple_device";

fn refused(status: u16) -> Option<Stop> {
    match status {
        200..=299 => None,
        450 => Some(Stop::Reauth),
        429 | 500..=599 => Some(Stop::Busy),
        _ => Some(Stop::Failed),
    }
}

/// One folder's item list from `retrieveItemDetailsInFolders`, as the engine's
/// `fetch_folder` asks for it, its body read under the limits, checked, and parsed by the
/// engine's reader. Recently Deleted items are left out.
async fn folder_read(
    client: &Client,
    root: &str,
    id: &str,
    limits: &RefreshLimits,
    budget: &mut usize,
) -> Result<Vec<DriveItem>, Stop> {
    let mut query = client.service_params();
    query.push(("clientVersion".into(), "2.1".into()));
    let ask = serde_json::to_vec(&json!([{ "drivewsid": id, "partialData": false }]))
        .map_err(|_| Stop::Failed)?;
    let response = client
        .http()
        .post(format!(
            "{}/retrieveItemDetailsInFolders",
            root.trim_end_matches('/')
        ))
        .query(&query)
        .header("Content-Type", "application/json")
        .body(ask)
        .send()
        .await
        .map_err(|_| Stop::Failed)?;
    let status = response.status().as_u16();
    if let Some(stop) = refused(status) {
        // Advanced Data Protection answers in words, never by its status alone.
        if matches!(status, 403 | 421 | 423) {
            let mut small = MAX_REFUSAL_BYTES.min(*budget);
            if let Ok(body) = read_capped!(response, MAX_REFUSAL_BYTES, &mut small) {
                if quince_icloud::locked_by_data_protection(&String::from_utf8_lossy(&body)) {
                    return Err(Stop::Paused);
                }
            }
        }
        return Err(stop);
    }
    let body = read_capped!(response, limits.max_response_bytes, budget)?;
    let body: Value = serde_json::from_slice(&body).map_err(|_| Stop::Failed)?;
    checked_listing(id, &body, limits)
}

/// Checks an answer before the engine reads it. It must name the folder's status as OK (a
/// folder Apple no longer has answers `ID_INVALID` with no items, which must never read as an
/// empty folder) and carry an item list, its items counted and measured before parsing.
fn checked_listing(id: &str, body: &Value, limits: &RefreshLimits) -> Result<Vec<DriveItem>, Stop> {
    let folder = body
        .as_array()
        .and_then(|folders| folders.first())
        .filter(|f| f.is_object())
        .ok_or(Stop::Failed)?;
    match folder.get("status").and_then(Value::as_str) {
        None | Some("OK") => {}
        Some("ID_INVALID") => return Err(Stop::FolderGone),
        Some(_) => return Err(Stop::Failed),
    }
    // A folder in Recently Deleted is not listed as live, nor are its items. Apple marks one
    // there as it marks a trashed item: filed under the trash, or carrying where Recover puts
    // it back.
    let filed_in_trash = ["parentId", "drivewsid"].iter().any(|key| {
        folder
            .get(*key)
            .and_then(Value::as_str)
            .is_some_and(|v| v.contains(TRASH))
    });
    if filed_in_trash
        || folder.get("restorePath").is_some()
        || folder.get("dateExpiration").is_some()
    {
        return Err(Stop::InTrash);
    }
    let rows = folder
        .get("items")
        .and_then(Value::as_array)
        .ok_or(Stop::Failed)?;
    if rows.len() > limits.max_items {
        return Err(Stop::FolderTooLarge);
    }
    if rows
        .iter()
        .any(|row| crate::contacts::card_bytes(row) > limits.max_item_bytes)
    {
        return Err(Stop::ItemTooLarge);
    }
    // Recently Deleted, as Apple marks it (`restorePath`, `dateExpiration`) or files it.
    let kept: Vec<&Value> = rows
        .iter()
        .filter(|row| row.get("restorePath").is_none() && row.get("dateExpiration").is_none())
        .collect();
    let mut items = quince_icloud::drive::parse_folder(&json!([{ "items": &kept }]));
    exact_names(&mut items, &kept);
    // Never a folder inside itself, nor the root inside anything.
    items.retain(|i| !is_trash(i) && i.drivewsid != id && i.drivewsid != ROOT);
    Ok(items)
}

/// The engine's reader trims a name and an extension, which can turn ` Reports ` into
/// `Reports` and drop a leading control character. Each item gets back the name and the
/// extension Apple sent, character for character, so a path names exactly what Apple has.
/// A name Apple sent empty keeps the engine's `Untitled`, and an empty extension stays none.
fn exact_names(items: &mut [DriveItem], rows: &[&Value]) {
    let mut sent: std::collections::HashMap<&str, &Value> = std::collections::HashMap::new();
    for row in rows {
        if let Some(id) = row.get("drivewsid").and_then(Value::as_str) {
            sent.entry(id.trim()).or_insert(row);
        }
    }
    for item in items {
        let Some(row) = sent.get(item.drivewsid.as_str()) else {
            continue;
        };
        if let Some(name) = row
            .get("name")
            .and_then(Value::as_str)
            .filter(|n| !n.is_empty())
        {
            item.name = name.to_string();
        }
        item.extension = row
            .get("extension")
            .and_then(Value::as_str)
            .filter(|e| !e.is_empty())
            .map(ToString::to_string);
    }
}

/// The folders cached in `before` that the folders read no longer hold anywhere. A folder
/// that moved into another folder read in the same refresh is not gone.
fn gone_folders(before: &[String], returned: &std::collections::HashSet<&str>) -> Vec<String> {
    before
        .iter()
        .filter(|id| !returned.contains(id.as_str()))
        .cloned()
        .collect()
}

/// What a refresh read: each folder's items, in the order read, the folder asked for last.
struct Read {
    folders: Vec<(String, Vec<DriveItem>)>,
    path: Option<String>,
}

/// The one item in `items` named `name`.
fn child_named<'a>(items: &'a [DriveItem], name: &str) -> Result<&'a DriveItem, Stop> {
    let mut found = items.iter().filter(|i| same_name(i, name));
    let first = found.next().ok_or(Stop::PathNotFound)?;
    if found.next().is_some() {
        return Err(Stop::Ambiguous);
    }
    if !first.is_container() {
        return Err(Stop::NotAFolder);
    }
    Ok(first)
}

/// Drops from a folder's items any folder already read above it in this refresh: stored, it
/// would make a folder its own ancestor.
fn not_above(items: &mut Vec<DriveItem>, above: &[(String, Vec<DriveItem>)]) {
    items.retain(|i| !above.iter().any(|(id, _)| *id == i.drivewsid));
}

/// Reads the folder `start` names: for a path, the root and each folder on it in turn; for an
/// id, that folder alone. Any read failing fails the whole refresh.
async fn fetch(
    client: &Client,
    root: &str,
    start: &Start,
    limits: &RefreshLimits,
) -> Result<Read, Stop> {
    let mut budget = limits.max_total_bytes;
    match start {
        Start::Folder(id, path) => {
            let items = folder_read(client, root, id, limits, &mut budget).await?;
            // `checked_listing` already drops the folder itself from its own items.
            Ok(Read {
                folders: vec![(id.clone(), items)],
                path: path.clone(),
            })
        }
        Start::Path(names) => {
            let mut folders: Vec<(String, Vec<DriveItem>)> = Vec::new();
            let mut id = ROOT.to_string();
            for name in names {
                let mut items = folder_read(client, root, &id, limits, &mut budget).await?;
                not_above(&mut items, &folders);
                let next = child_named(&items, name)?.drivewsid.clone();
                folders.push((id, items));
                id = next;
            }
            let mut items = folder_read(client, root, &id, limits, &mut budget).await?;
            not_above(&mut items, &folders);
            folders.push((id, items));
            Ok(Read {
                folders,
                path: Some(format!("/{}", names.join("/"))),
            })
        }
    }
}

/// Stores what a refresh read, inside the pass's transaction: each folder's items replace
/// the cached ones, a folder no longer listed is forgotten with everything cached beneath it,
/// and the folders read are marked as listed. Drive's cursor is kept as it was.
fn apply(library: &mut Library, read: &Read) -> quince_icloud::Result<()> {
    let stamp = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(i64::MAX);
    let mut listed = listed_map(library);
    // Every item any folder read holds, gathered once. A folder that left one folder read
    // and turned up in another moved: it keeps its cached contents. Only a folder found in
    // none of them is forgotten, after every folder is stored, so nothing is forgotten and
    // then stored again with its contents missing.
    let returned: std::collections::HashSet<&str> = read
        .folders
        .iter()
        .flat_map(|(_, items)| items.iter().map(|i| i.drivewsid.as_str()))
        .collect();
    let mut gone = Vec::new();
    for (id, items) in &read.folders {
        // Still a live cached folder: the root, one this refresh stored a moment ago, or the
        // one asked for by id. Something else may have changed the cache since it was read;
        // items stored under a folder it no longer holds would be rows no path reaches.
        let live = id == ROOT
            || library
                .drive_item(id)?
                .is_some_and(|f| f.is_container() && !is_trash(&f));
        if !live {
            return Err(quince_icloud::Error::Protocol(LEFT_CACHE.into()));
        }
        let before: Vec<String> = library
            .drive_children(id)?
            .into_iter()
            .filter(DriveItem::is_container)
            .map(|i| i.drivewsid)
            .collect();
        library.put_drive_children(id, items)?;
        gone.extend(gone_folders(&before, &returned));
        listed.insert(id.clone(), json!(stamp));
    }
    for id in &gone {
        library.forget_drive_folder(id)?;
    }
    // A folder forgotten above, or under one, is no longer listed.
    let mut kept: Vec<(String, i64)> = Vec::new();
    for (id, at) in listed {
        if id == ROOT || library.drive_item(&id)?.is_some() {
            kept.push((id, at.as_i64().unwrap_or(0)));
        }
    }
    kept.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    kept.truncate(MAX_LISTED);
    let map: serde_json::Map<String, Value> =
        kept.into_iter().map(|(id, at)| (id, json!(at))).collect();
    library.set_state(LISTED_KEY, &Value::Object(map).to_string())?;
    let cursor = library.sync_token(SERVICE)?;
    library.mark_synced(SERVICE, cursor.as_deref())?;
    Ok(())
}

/// A folder that was cached when the refresh started and is not any more.
const LEFT_CACHE: &str = "drive_folder_left_cache_cache_kept";

/// Where a refresh starts, settled from the cache before anything is asked.
#[derive(Clone, Debug)]
enum Start {
    /// A cached folder (or the root) by id, with its cached path.
    Folder(String, Option<String>),
    /// A cloud path, walked from the root.
    Path(Vec<String>),
}

fn start_of(dir: &Path, args: &Value) -> Result<Start, &'static str> {
    match refresh_target(args)? {
        Target::Path(names) => Ok(Start::Path(names)),
        Target::Id(id) if id == ROOT => Ok(Start::Folder(id, Some("/".into()))),
        Target::Id(id) => {
            let library = Library::open(dir).map_err(|_| "library_unavailable")?;
            match cached_item(&library, &id)? {
                Some(item) if item.is_container() => {
                    let path = cloud_path(&library, &item);
                    Ok(Start::Folder(id, path))
                }
                Some(_) => Err("not_a_folder"),
                None => Err("folder_not_in_cache_use_path"),
            }
        }
    }
}

/// Production refresh: the directory's own keyring session and Apple's endpoints only.
/// Caller holds the private directory's exclusive operation lock.
pub(crate) async fn refresh(
    dir: &Path,
    approved: bool,
    args: Value,
) -> Result<Value, &'static str> {
    refresh_target(&args)?;
    gate(dir, approved)?;
    let start = start_of(dir, &args)?;
    let store = Store::isolated_keyring(dir).map_err(|_| "secure_storage_unavailable")?;
    let session = store
        .try_load()
        .map_err(|_| "login_required_unlock_secure_storage")?;
    if !session.is_resumable() {
        return Err("login_required");
    }
    let client = Client::with(dir, Endpoints::default(), store).map_err(|_| "login_required")?;
    timed(dir, client, start, RefreshLimits::default()).await
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
    refresh_target(&args)?;
    gate(dir, false)?;
    let start = start_of(dir, &args)?;
    timed(dir, client, start, limits).await
}

const TIMED_OUT: &str = "drive_refresh_timeout_cache_kept";

async fn timed(
    dir: &Path,
    client: Client,
    start: Start,
    limits: RefreshLimits,
) -> Result<Value, &'static str> {
    // As for Contacts: reads are cancelled at the deadline, and the deadline is checked again
    // inside the store's transaction, which rolls back when it has passed.
    let started_for = owner(dir)?;
    let deadline = (limits.clock)() + limits.timeout;
    match tokio::time::timeout(
        limits.timeout,
        read_folder(dir, client, start, limits, deadline),
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

async fn read_folder(
    dir: &Path,
    mut client: Client,
    start: Start,
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
        .service_url("drivews")
        .ok_or("drive_service_unavailable")?;
    // Advanced Data Protection keeps Drive until the person approves on a device. Without its
    // key Apple would only refuse, so it is not asked, and no approval is requested from here.
    if client.data_access_missing().contains(&SERVICE) {
        return Err(PAUSED);
    }
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
    let summary = std::sync::Mutex::new((0usize, 0usize, String::new(), None::<String>));
    let lock = tokio::sync::Mutex::new(());
    let report = pass::driven(SERVICE, &ctx, &data, &lock, async {
        let mut fetched = fetch(&client, &root, &start, &limits)
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
        // Queued Drive changes are neither sent nor laid over what Apple returned.
        pass::store(SERVICE, &data, &ctx, fetched, |library, read| {
            // Checked again inside the transaction: another process may have changed the
            // account since `pass::store` looked, and nothing is written for the wrong one.
            if !pass::owned(library, ctx.account.as_deref()) {
                *stopped
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some("account_changed_during_refresh_cache_kept");
                return Err(quince_icloud::Error::Protocol(pass::NOT_YOURS_WORDS.into()));
            }
            if let Err(e) = apply(library, &read) {
                if matches!(&e, quince_icloud::Error::Protocol(m) if m == LEFT_CACHE) {
                    *stopped
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(LEFT_CACHE);
                }
                return Err(e);
            }
            if let Some((id, items)) = read.folders.last() {
                *summary
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = (
                    read.folders.len(),
                    items.len(),
                    id.clone(),
                    read.path.clone(),
                );
            }
            // Last, before the transaction commits: past the deadline, it rolls back and the
            // pass is recorded as failed.
            if expired() {
                return Err(quince_icloud::Error::Protocol(TIMED_OUT.into()));
            }
            Ok("read".to_string())
        })
        .await
    })
    .await;
    match report.outcome {
        pass::Outcome::Ok => {}
        pass::Outcome::Paused => return Err(PAUSED),
        _ if report.detail.as_deref() == Some(pass::NOT_YOURS_WORDS) => {
            return Err("account_changed_during_refresh_cache_kept")
        }
        _ => {
            let stopped = *stopped
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            return Err(stopped.unwrap_or("drive_refresh_failed_cache_kept"));
        }
    }
    let (folders_read, items_read, id, path) = summary
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let library = data.lock().await;
    let queued = library
        .outbox_pending(SERVICE)
        .map_err(|_| "library_unavailable")?
        .len();
    Ok(json!({
        "service": SERVICE,
        "outcome": "ok",
        "folder": {"id": id, "path": path},
        "folders_read": folders_read,
        "items_read": items_read,
        "last_refreshed_at": report.last_synced_at,
        "queued_drive_changes": queued,
        "queued_changes_sent": 0,
        "file_contents_read": false,
        "remote_verified": false,
        "verification": "the item lists of these Apple iCloud Drive folders were read into the local cache; folders Apple no longer lists in them were removed from the cache; no file contents were read and nothing was sent to Apple",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_names_are_data_and_bounded() {
        assert_eq!(path_names("/"), Ok(vec![]));
        assert_eq!(
            path_names("/a/Été 📁"),
            Ok(vec!["a".to_string(), "Été 📁".to_string()])
        );
        for bad in [
            "",
            "a",
            "//",
            "/a/",
            "/./a",
            "/a/..",
            "/a\u{0}",
            "/a\u{7f}",
            "/a\u{85}b",
        ] {
            assert_eq!(path_names(bad), Err("invalid_path"), "{bad:?}");
        }
        assert_eq!(path_names(&"/a".repeat(33)), Err("path_too_deep"));
        assert_eq!(
            path_names(&format!("/{}", "b".repeat(1100))),
            Err("path_too_long")
        );
    }

    #[test]
    fn decomposed_and_composed_names_are_the_same_name() {
        let item = DriveItem {
            drivewsid: "FILE::z::1".into(),
            parent_id: None,
            name: "Cafe\u{301}".into(),
            extension: Some("txt".into()),
            kind: "FILE".into(),
            size: None,
            child_count: None,
            created_at: None,
            modified_at: None,
            etag: None,
        };
        assert!(same_name(&item, "Caf\u{e9}.txt"));
        assert!(!same_name(&item, "cafe\u{301}.txt"));
    }

    /// One pass over a folder of 50,000 child folders against 50,000 returned ids. Compared
    /// pairwise, this took about 1.25 billion comparisons inside the write transaction.
    #[test]
    fn finding_gone_folders_is_one_pass_over_a_large_folder() {
        let before: Vec<String> = (0..50_000).map(|i| format!("FOLDER::z::{i}")).collect();
        let returned: std::collections::HashSet<&str> =
            before.iter().skip(1).map(String::as_str).collect();
        let started = Instant::now();
        let gone = gone_folders(&before, &returned);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(gone, ["FOLDER::z::0"]);
    }

    #[test]
    fn names_keep_the_spaces_and_characters_apple_sent() {
        let rows = [
            json!({"drivewsid":"FOLDER::z::r","name":" Reports ","type":"FOLDER"}),
            json!({"drivewsid":"FILE::z::c","name":"\u{7}bell","extension":" txt","type":"FILE"}),
            json!({"drivewsid":"FILE::z::e","name":"","extension":"","type":"FILE"}),
        ];
        let refs: Vec<&Value> = rows.iter().collect();
        let mut items = quince_icloud::drive::parse_folder(&json!([{ "items": &refs }]));
        assert_eq!(items[0].name, "Reports", "the engine trims");
        exact_names(&mut items, &refs);
        assert_eq!(items[0].name, " Reports ");
        assert_eq!(items[1].name, "\u{7}bell");
        assert_eq!(items[1].extension.as_deref(), Some(" txt"));
        assert_eq!(items[2].name, "Untitled");
        assert_eq!(items[2].extension, None);
    }

    /// The unsorted read holds exactly the rows `drive_children` holds, field for field.
    #[test]
    fn the_unsorted_child_read_matches_the_engine_read() {
        let mut library = Library::in_memory().unwrap();
        let item = |id: &str, name: &str, kind: &str, at: Option<i64>| DriveItem {
            drivewsid: id.into(),
            parent_id: None,
            name: name.into(),
            extension: (kind == "FILE").then(|| "txt".to_string()),
            kind: kind.into(),
            size: (kind == "FILE").then_some(3),
            child_count: (kind == "FOLDER").then_some(2),
            created_at: Some(1),
            modified_at: at,
            etag: Some("e".into()),
        };
        library
            .put_drive_children(
                ROOT,
                &[
                    item("FILE::z::b", "Scan 10", "FILE", Some(5)),
                    item("FOLDER::z::a", "Zoo", "FOLDER", None),
                    item("FILE::z::c", " Été ", "FILE", Some(9)),
                ],
            )
            .unwrap();
        library
            .put_drive_children("FOLDER::z::a", &[item("FILE::z::d", "in", "FILE", None)])
            .unwrap();
        let key = |mut v: Vec<DriveItem>| {
            v.sort_by(|a, b| a.drivewsid.cmp(&b.drivewsid));
            v
        };
        for parent in [ROOT, "FOLDER::z::a", "FOLDER::z::none"] {
            assert_eq!(
                key(unsorted_children(&library, parent).unwrap()),
                key(library.drive_children(parent).unwrap()),
                "{parent}"
            );
        }
    }

    #[test]
    fn folder_ids_are_checked_by_form() {
        assert_eq!(
            folder_target(None, Some("TRASH_ROOT")),
            Err("trash_not_supported")
        );
        assert_eq!(folder_target(None, Some("FILE::z::1")), Err("not_a_folder"));
        assert_eq!(folder_target(None, None), Ok(Target::Path(vec![])));
        assert_eq!(
            folder_target(Some("/"), Some(ROOT)),
            Err("invalid_arguments")
        );
    }
}

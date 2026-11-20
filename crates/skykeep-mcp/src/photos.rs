//! Apple iCloud Photos, read-only metadata of the personal library: cached albums, photos,
//! search and one photo, and an explicit refresh that reads Apple's change feed into the local
//! cache. No picture, video, thumbnail or download link is read or kept, and nothing is sent to
//! Apple. Places, faces and people are dropped from what Apple sends before anything is stored.
//!
//! The refresh makes its own requests, so every answer is read under a byte limit, and hands
//! the records to the engine's reader (`quince_icloud::photos::apply`). It reads only the
//! personal library's zone in the private database; the Shared Library and shared albums are
//! never asked for. It is not part of `sync`, and queued Photos changes are neither sent nor
//! laid over what Apple returned.
use crate::account::{binding, Binding};
use crate::contacts::{encoded_len, gate, owner, read_capped, record_timeout_of};
use quince_auth::{Client, Endpoints, Store};
use quince_core::photos::{Album, Kind, Photo, Source, View};
use quince_core::Library;
use quince_icloud::cloudkit;
use quince_icloud::photos::{self as apple, PhotosFetch, Readiness};
use quince_sync::{library_lock::LibraryLock, pass};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};

const SERVICE: &str = apple::SERVICE;
const DEFAULT_LIMIT: usize = 25;
pub(crate) const MAX_LIMIT: usize = 100;
pub(crate) const MAX_QUERY_BYTES: usize = 256;
pub(crate) const MAX_ID_BYTES: usize = 512;
/// Caps on a tool result's text as encoded in the JSON-RPC frame.
const MAX_PAGE_BYTES: usize = 262_144;
const MAX_ITEM_BYTES: usize = 8192;
const MAX_DETAIL_BYTES: usize = 65_536;
/// The most albums a listing reads; any after these are not listed.
const MAX_ALBUMS: usize = 10_000;

/// How far each kind of text is cut, tried in turn until an item fits its cap. The first level
/// is the documented one; the later ones only ever apply to text that is mostly characters
/// JSON has to escape. With identifiers at most `MAX_ID_BYTES` the last level always fits.
#[derive(Clone, Copy)]
struct Cuts {
    /// Titles, filenames and album names, in characters.
    text: usize,
    caption: usize,
    keywords: usize,
    keyword_chars: usize,
}

const LIST_LEVELS: [Cuts; 4] = [
    Cuts {
        text: 256,
        caption: 256,
        keywords: 50,
        keyword_chars: 64,
    },
    Cuts {
        text: 64,
        caption: 64,
        keywords: 10,
        keyword_chars: 32,
    },
    Cuts {
        text: 16,
        caption: 16,
        keywords: 3,
        keyword_chars: 16,
    },
    Cuts {
        text: 0,
        caption: 0,
        keywords: 0,
        keyword_chars: 0,
    },
];

const DETAIL_LEVELS: [Cuts; 4] = [
    Cuts {
        text: 256,
        caption: 2048,
        keywords: 50,
        keyword_chars: 64,
    },
    Cuts {
        text: 128,
        caption: 512,
        keywords: 20,
        keyword_chars: 32,
    },
    Cuts {
        text: 32,
        caption: 64,
        keywords: 5,
        keyword_chars: 16,
    },
    Cuts {
        text: 0,
        caption: 0,
        keywords: 0,
        keyword_chars: 0,
    },
];

/// What a reply never holds.
const NOT_INCLUDED: [&str; 6] = [
    "the pictures and videos themselves, thumbnails, previews and download links",
    "location: no coordinates or place is kept or shown",
    "faces and people",
    "hidden photos, Recently Deleted, the Shared Library and shared albums",
    "edits, adjustments and the original file's other metadata (camera, exposure)",
    "smart albums such as Favorites or Screenshots; only albums and folders the person made",
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
struct List {
    album_id: Option<String>,
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
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

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

fn id_ok(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_ID_BYTES
}

fn list_args(args: &Value) -> Result<List, &'static str> {
    let list: List = parse(args)?;
    page_limit(list.limit)?;
    if list.album_id.as_deref().is_some_and(|a| !id_ok(a)) {
        return Err("invalid_arguments");
    }
    Ok(list)
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
    if !id_ok(&get.id) {
        return Err("invalid_arguments");
    }
    Ok(get)
}

/// Checks a Photos tool's arguments before any approval prompt or cache access.
pub(crate) fn validate(name: &str, args: &Value) -> Result<(), &'static str> {
    match name {
        "photos_albums" => page_limit(parse::<Page>(args)?.limit).map(|_| ()),
        "photos_list" => list_args(args).map(|_| ()),
        "photos_search" => search_args(args).map(|_| ()),
        "photos_get" => get_args(args).map(|_| ()),
        "photos_refresh" => parse::<Empty>(args).map(|_| ()),
        _ => Ok(()),
    }
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
        "refresh": "only by photos_refresh; there is no background Photos refresh, and a large library takes several",
    }))
}

/// A photo any reply may show: the personal library's, neither hidden nor deleted.
fn shown(library: &Library, photo: &Photo) -> Result<bool, &'static str> {
    if photo.hidden || photo.deleted {
        return Ok(false);
    }
    Ok(library
        .photo_zone(&photo.id)
        .map_err(|_| "library_unavailable")?
        .is_none())
}

/// `text` cut to `chars` characters; a cut adds `name` to `shortened`.
fn cut(
    text: Option<&str>,
    chars: usize,
    name: &'static str,
    shortened: &mut Vec<&'static str>,
) -> Option<String> {
    let text = text?;
    if text.chars().count() <= chars {
        return Some(text.to_string());
    }
    if !shortened.contains(&name) {
        shortened.push(name);
    }
    Some(text.chars().take(chars).collect())
}

fn kind(kind: Kind) -> &'static str {
    match kind {
        Kind::Image => "image",
        Kind::Video => "video",
        Kind::Live => "live_photo",
    }
}

fn time(at: Option<i64>) -> Value {
    at.map_or(Value::Null, |at| json!(crate::calendar::utc_text(at)))
}

/// A photo's allowlisted fields, its texts cut as `cuts` says. Identifiers are never cut.
fn view(p: &Photo, cuts: Cuts) -> Value {
    let mut shortened = Vec::new();
    let filename = cut(p.filename.as_deref(), cuts.text, "filename", &mut shortened);
    let title = cut(p.title.as_deref(), cuts.text, "title", &mut shortened);
    let caption = cut(
        p.caption.as_deref(),
        cuts.caption,
        "caption",
        &mut shortened,
    );
    let file_type = cut(p.uti.as_deref(), cuts.text, "file_type", &mut shortened);
    let mut keyword_cut = p.keywords.len() > cuts.keywords;
    let keywords: Vec<String> = p
        .keywords
        .iter()
        .take(cuts.keywords)
        .map(|k| {
            if k.chars().count() > cuts.keyword_chars {
                keyword_cut = true;
            }
            k.chars().take(cuts.keyword_chars).collect()
        })
        .collect();
    if keyword_cut {
        shortened.push("keywords");
    }
    json!({
        "id": p.id,
        "kind": kind(p.kind),
        "taken_at": time(Some(p.taken_at)),
        "added_at": time(p.added_at),
        "width": p.width,
        "height": p.height,
        "duration_seconds": p.duration,
        "filename": filename,
        "title": title,
        "caption": caption,
        "keywords": keywords,
        "keywords_total": p.keywords.len(),
        "favorite": p.favorite,
        "rating": p.rating,
        "file_type": file_type,
        "size_bytes": p.size,
        "live_photo_video_bytes": p.live_size,
        "shortened": shortened,
    })
}

/// One page entry. An identifier too long to ask for with `photos_get` is never cut into a
/// different, unusable one: the entry says so, with its length, and holds its place.
fn item(p: &Photo) -> Value {
    if p.id.len() > MAX_ID_BYTES {
        return json!({"id":null,"unsupported":"id_too_long","id_bytes":p.id.len()});
    }
    for cuts in LIST_LEVELS {
        let shown = view(p, cuts);
        if encoded_len(&shown) <= MAX_ITEM_BYTES {
            return shown;
        }
    }
    // Every text is bounded, so this is not reached; it keeps a page from stalling if it were.
    json!({"id":p.id,"unsupported":"item_too_large","shortened":["all"]})
}

fn shortened(item: &Value) -> bool {
    item["shortened"].as_array().is_some_and(|s| !s.is_empty())
}

/// A page of `total` entries from `offset`, built by `entry` until `limit` or the page's cap.
/// `envelope` is everything else the page says.
fn paged(
    total: usize,
    offset: usize,
    limit: usize,
    mut entry: impl FnMut(usize) -> Result<Option<Value>, &'static str>,
    envelope: impl Fn(&[Value], usize, bool, usize) -> Value,
) -> Result<Value, &'static str> {
    let page = |items: &[Value], consumed: usize, cut: bool, excluded: usize| {
        let mut value = envelope(items, consumed, cut, excluded);
        let next = offset.saturating_add(consumed);
        value["total"] = json!(total);
        value["offset"] = json!(offset);
        value["limit"] = json!(limit);
        value["next_offset"] = json!((next < total).then_some(next));
        value["page_shortened_to_fit"] = json!(cut);
        value
    };
    // Each item adds its encoded text and a comma; the envelope is measured with room for its
    // counts to grow.
    let mut used = encoded_len(&page(&[], 0, true, 0)).saturating_add(64);
    // Each item with how many entries are settled once it is shown: itself and any left out
    // before it.
    let mut items: Vec<(Value, usize)> = Vec::new();
    let mut cut = false;
    let mut settled = 0;
    let mut excluded = 0;
    for at in offset..total.min(offset.saturating_add(limit)) {
        let Some(item) = entry(at)? else {
            settled += 1;
            excluded += 1;
            continue;
        };
        let size = encoded_len(&item).saturating_sub(1);
        if used.saturating_add(size) > MAX_PAGE_BYTES {
            cut = true;
            break;
        }
        used = used.saturating_add(size);
        settled += 1;
        items.push((item, settled));
    }
    // The page as it will be sent, measured: never over the cap.
    let mut popped = false;
    loop {
        let shown: Vec<Value> = items.iter().map(|(v, _)| v.clone()).collect();
        let upto = if popped {
            items.last().map_or(0, |(_, n)| *n)
        } else {
            settled
        };
        let value = page(&shown, upto, cut, excluded);
        if encoded_len(&value) <= MAX_PAGE_BYTES {
            return Ok(value);
        }
        if items.pop().is_none() {
            return Err("page_too_large");
        }
        popped = true;
        cut = true;
    }
}

fn photo_page(
    library: &Library,
    ids: &[String],
    offset: usize,
    limit: usize,
    extra: Value,
) -> Result<Value, &'static str> {
    let cache = cache_state(library)?;
    paged(
        ids.len(),
        offset,
        limit,
        |at| {
            let Some(p) = library.photo(&ids[at]).map_err(|_| "library_unavailable")? else {
                return Ok(None);
            };
            Ok(shown(library, &p)?.then(|| item(&p)))
        },
        |items, _, _, excluded| {
            let mut value = json!({
                "source": "local_cache",
                "library": "personal",
                "items": items,
                "unsupported_items": items.iter().filter(|i| i["id"].is_null()).count(),
                "items_shortened": items.iter().filter(|i| shortened(i)).count(),
                "excluded_items": excluded,
                "complete_representation": false,
                "not_included": NOT_INCLUDED,
                "cache": cache,
                "remote_verified": false,
            });
            if let (Some(map), Some(more)) = (value.as_object_mut(), extra.as_object()) {
                map.extend(more.clone());
            }
            value
        },
    )
}

/// Reads an album from a row of `id, name, position, folder, parent`. A closure, so the row's
/// type is inferred: this crate does not name the engine's SQLite crate.
macro_rules! album_row {
    () => {
        |r| {
            Ok(Album {
                id: r.get(0)?,
                name: r.get(1)?,
                position: r.get(2)?,
                change_tag: None,
                folder: r.get::<_, i64>(3)? != 0,
                parent: r.get(4)?,
            })
        }
    };
}

/// The albums as listed, at most `MAX_ALBUMS`, with whether there were more. The cap is in the
/// query, with one row more to tell whether more exist, so a larger table is never read whole.
/// Counts are left to [`album_count`], for the albums a page shows.
fn album_index(library: &Library) -> Result<(Vec<Album>, bool), &'static str> {
    let sql = format!(
        "SELECT id, name, position, folder, parent FROM photo_albums
         ORDER BY position, name LIMIT {}",
        MAX_ALBUMS + 1
    );
    let mut stmt = library
        .conn()
        .prepare(&sql)
        .map_err(|_| "library_unavailable")?;
    let mut all: Vec<Album> = stmt
        .query_map([], album_row!())
        .map_err(|_| "library_unavailable")?
        .collect::<Result<_, _>>()
        .map_err(|_| "library_unavailable")?;
    let capped = all.len() > MAX_ALBUMS;
    all.truncate(MAX_ALBUMS);
    Ok((all, capped))
}

/// One album, by id.
fn album_by_id(library: &Library, id: &str) -> Result<Option<Album>, &'static str> {
    let mut stmt = library
        .conn()
        .prepare("SELECT id, name, position, folder, parent FROM photo_albums WHERE id = ?1")
        .map_err(|_| "library_unavailable")?;
    let mut rows = stmt
        .query_map([id], album_row!())
        .map_err(|_| "library_unavailable")?;
    rows.next().transpose().map_err(|_| "library_unavailable")
}

/// How many photos an album shows in `photos_list`: the personal library's, neither hidden nor
/// deleted.
fn album_count(library: &Library, id: &str) -> Result<i64, &'static str> {
    library
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM photo_album_items i JOIN photos p ON p.id = i.asset
             WHERE i.album = ?1 AND p.deleted = 0 AND p.hidden = 0 AND p.zone IS NULL",
            [id],
            |r| r.get(0),
        )
        .map_err(|_| "library_unavailable")
}

fn album_item(album: &Album, count: i64) -> Value {
    if album.id.len() > MAX_ID_BYTES {
        return json!({"id":null,"unsupported":"id_too_long","id_bytes":album.id.len()});
    }
    let mut shortened = Vec::new();
    let mut shown = Value::Null;
    for cuts in LIST_LEVELS {
        shortened.clear();
        let name = cut(Some(&album.name), cuts.text, "name", &mut shortened);
        // A parent too long to ask for is left out rather than cut.
        let parent = album.parent.as_deref().filter(|p| p.len() <= MAX_ID_BYTES);
        shown = json!({
            "id": album.id,
            "name": name,
            "folder": album.folder,
            "parent_id": parent,
            "parent_unsupported": album.parent.as_deref().is_some_and(|p| p.len() > MAX_ID_BYTES),
            "photo_count": count,
            "shortened": shortened,
        });
        if encoded_len(&shown) <= MAX_ITEM_BYTES {
            break;
        }
    }
    shown
}

pub(crate) fn albums(library: &Library, args: Value) -> Result<Value, &'static str> {
    let args: Page = parse(&args)?;
    let limit = page_limit(args.limit)?;
    let (all, capped) = album_index(library)?;
    let cache = cache_state(library)?;
    paged(
        all.len(),
        args.offset,
        limit,
        |at| {
            let album = &all[at];
            let count = if album.id.len() > MAX_ID_BYTES {
                0
            } else {
                album_count(library, &album.id)?
            };
            Ok(Some(album_item(album, count)))
        },
        |items, _, _, _| {
            json!({
                "source": "local_cache",
                "library": "personal",
                "items": items,
                "album_index_capped": capped,
                "album_index_cap": MAX_ALBUMS,
                "unsupported_items": items.iter().filter(|i| i["id"].is_null()).count(),
                "items_shortened": items.iter().filter(|i| shortened(i)).count(),
                "photo_count": "photos photos_list shows for the album: the personal library's, without hidden or deleted ones",
                "complete_representation": false,
                "cache": cache,
                "remote_verified": false,
            })
        },
    )
}

pub(crate) fn list(library: &Library, args: Value) -> Result<Value, &'static str> {
    let args = list_args(&args)?;
    let limit = page_limit(args.limit)?;
    let (source, extra) = match args.album_id {
        None => (
            Source::View(View::Library),
            json!({"order":"newest taken first, then by id"}),
        ),
        Some(id) => {
            let album = album_by_id(library, &id)?.ok_or("album_not_found")?;
            if album.folder {
                return Err("album_is_folder");
            }
            let mut ignored = Vec::new();
            (
                Source::Album(id),
                json!({"order":"the album's own order",
                    "album":{"id":album.id,"name":cut(Some(&album.name), 256, "name", &mut ignored)}}),
            )
        }
    };
    let index = library
        .photo_index(&source, None)
        .map_err(|_| "library_unavailable")?;
    photo_page(library, &index.ids, args.offset, limit, extra)
}

pub(crate) fn search(library: &Library, args: Value) -> Result<Value, &'static str> {
    let args = search_args(&args)?;
    let limit = page_limit(args.limit)?;
    let index = library
        .photo_index(&Source::Query(args.query), None)
        .map_err(|_| "search_unavailable")?;
    photo_page(
        library,
        &index.ids,
        args.offset,
        limit,
        json!({"order":"newest taken first, then by id",
            "matched":"every word starts a word of the title, filename, caption or a keyword, or names the year or month taken"}),
    )
}

pub(crate) fn get(library: &Library, args: Value) -> Result<Value, &'static str> {
    let args = get_args(&args)?;
    let photo = library
        .photo(&args.id)
        .map_err(|_| "library_unavailable")?
        .filter(|p| p.id == args.id)
        .ok_or("not_found")?;
    if !shown(library, &photo)? {
        return Err("not_found");
    }
    let cache = cache_state(library)?;
    for cuts in DETAIL_LEVELS {
        let shown = view(&photo, cuts);
        let value = json!({
            "source": "local_cache",
            "library": "personal",
            "photo_shortened": shortened(&shown),
            "photo": shown,
            "complete_representation": false,
            "not_included": NOT_INCLUDED,
            "cache": cache,
            "remote_verified": false,
        });
        if encoded_len(&value) <= MAX_DETAIL_BYTES {
            return Ok(value);
        }
    }
    Err("photo_too_large")
}

/// What the approval prompt says a refresh will read.
pub(crate) fn refresh_scope() -> Value {
    json!({
        "services": ["photos"],
        "library": "the personal library only; not the Shared Library, shared albums, hidden or deleted photos",
        "refresh": "one bounded read of Apple iCloud Photos metadata into the local cache: at most 10 pages of 500 changes, at most 60 seconds; a large library takes several refreshes",
        "reads": "no pictures, videos, thumbnails or download links; places, faces and people are dropped before anything is stored",
        "send": "nothing is sent; queued changes stay queued",
    })
}

// --- Refresh.

/// Resource limits of one refresh. Bytes are counted as decoded, as they arrive.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct RefreshLimits {
    /// One page of the change feed.
    pub max_response_bytes: usize,
    /// The zone list and the readiness answer, each.
    pub max_small_bytes: usize,
    /// Every answer of the refresh together.
    pub max_total_bytes: usize,
    /// Pages of the change feed one refresh reads.
    pub max_pages: usize,
    /// The whole refresh; nothing is stored once it has passed.
    pub timeout: Duration,
    /// The time source the deadline is checked against; `Instant::now` outside tests.
    pub clock: fn() -> Instant,
}

impl Default for RefreshLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: 8 * 1024 * 1024,
            max_small_bytes: 1024 * 1024,
            max_total_bytes: 48 * 1024 * 1024,
            max_pages: 10,
            timeout: Duration::from_secs(60),
            clock: Instant::now,
        }
    }
}

/// Records asked for per page, and the most a page may hold.
const PAGE_RECORDS: usize = 500;

/// The record types kept. Everything else (faces, people, memories, smart albums' records) is
/// dropped before the engine sees it.
const KEPT_TYPES: [&str; 4] = ["CPLMaster", "CPLAsset", "CPLContainerRelation", "CPLAlbum"];

/// Why a refresh read stopped. Apple's own error bodies are never kept or shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    Reauth,
    Busy,
    Failed,
    TooLarge,
    /// Advanced Data Protection keeps the library from this session until it is approved.
    Locked,
    Preparing,
    Missing,
    /// "More coming" with no new position to carry on from.
    BadContinuation,
    /// Apple will not read the change token held: read again from the start.
    StaleToken,
}

impl Stop {
    fn code(self) -> &'static str {
        match self {
            Stop::Reauth => "login_required",
            Stop::Busy | Stop::Failed | Stop::StaleToken => "photos_refresh_failed_cache_kept",
            Stop::TooLarge => "photos_response_too_large_cache_kept",
            Stop::Locked => "photos_paused_approve_on_apple_device",
            Stop::Preparing => "photos_library_preparing_cache_kept",
            Stop::Missing => "photos_library_unavailable_cache_kept",
            Stop::BadContinuation => "photos_bad_continuation_cache_kept",
        }
    }

    /// What the library records for the failed pass: a fixed phrase, never Apple's text.
    fn error(self) -> quince_icloud::Error {
        match self {
            Stop::Reauth => quince_icloud::Error::ReauthRequired,
            Stop::Busy => quince_icloud::Error::Busy(None),
            Stop::Locked => quince_icloud::Error::NeedsDeviceApproval,
            other => quince_icloud::Error::Protocol(other.code().into()),
        }
    }
}

/// CloudKit's address of one operation on the Photos container's private database.
fn url(root: &str, operation: &str) -> String {
    format!(
        "{}/database/1/{}/production/private/{operation}",
        root.trim_end_matches('/'),
        apple::CONTAINER
    )
}

/// The query every CloudKit request carries, as the engine sends it.
fn query(client: &Client) -> Vec<(String, String)> {
    let mut q = client.service_params();
    q.push(("ckjsBuildVersion".into(), "17DProjectDev77".into()));
    q.push(("ckjsVersion".into(), "2.6.1".into()));
    q
}

/// One POST, its answer read under `cap` and the refresh's `budget` before it is parsed. A
/// refusal's body is read only to recognise Advanced Data Protection's words.
async fn post(
    client: &Client,
    root: &str,
    operation: &str,
    body: &Value,
    cap: usize,
    budget: &mut usize,
) -> Result<Value, Stop> {
    // Apple asked for the container to be left alone (`cloudkit::container_busy`): nothing
    // is sent until then, by this refresh or the engine's own clients.
    if cloudkit::container_held_off(root, apple::CONTAINER).is_some() {
        return Err(Stop::Busy);
    }
    let response = client
        .http()
        .post(url(root, operation))
        .query(&query(client))
        .json(body)
        .send()
        .await
        .map_err(|_| Stop::Failed)?;
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);
    let busy = matches!(status, 429 | 503);
    let bytes = match read_capped!(response, cap, budget) {
        Ok(bytes) => bytes,
        // A busy answer whose body is too large or cut off still holds for its header's wait.
        Err(stop) => {
            if busy {
                cloudkit::container_busy(root, apple::CONTAINER, "", retry_after.as_deref());
            }
            return Err(stop);
        }
    };
    if !(200..300).contains(&status) {
        let text = String::from_utf8_lossy(&bytes);
        if quince_icloud::locked_by_data_protection(&text) {
            return Err(Stop::Locked);
        }
        if busy {
            cloudkit::container_busy(root, apple::CONTAINER, &text, retry_after.as_deref());
        }
        return Err(match status {
            401 | 421 | 450 => Stop::Reauth,
            409 | 429 | 500..=599 => Stop::Busy,
            _ => Stop::Failed,
        });
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| Stop::Failed)?;
    if !value.is_object() {
        return Err(Stop::Failed);
    }
    Ok(value)
}

/// A zone-level refusal inside a 200 answer, as the engine reads one (`cloudkit::trouble_with`).
fn zone_trouble(root: &str, result: &Value) -> Option<Stop> {
    let code = result.get("serverErrorCode").and_then(Value::as_str);
    let reason = result.get("reason").and_then(Value::as_str);
    match code {
        None if reason.is_none() => None,
        Some("ZONE_NOT_FOUND") => Some(Stop::Missing),
        Some("ACCESS_DENIED") if quince_icloud::locked_by_data_protection(&result.to_string()) => {
            Some(Stop::Locked)
        }
        Some("CHANGE_TOKEN_EXPIRED") => Some(Stop::StaleToken),
        Some("BAD_REQUEST")
            if reason.is_some_and(|r| r.to_ascii_lowercase().contains("continuation")) =>
        {
            Some(Stop::StaleToken)
        }
        Some("THROTTLED" | "TRY_AGAIN_LATER" | "ZONE_BUSY") => {
            cloudkit::container_busy(root, apple::CONTAINER, &result.to_string(), None);
            Some(Stop::Busy)
        }
        Some("AUTHENTICATION_FAILED" | "AUTHENTICATION_REQUIRED") => Some(Stop::Reauth),
        _ => Some(Stop::Failed),
    }
}

/// The zone the personal library is in, from Apple's own list (`photos::pick_zone`), else the
/// default. Shared Library zones are never chosen.
async fn library_zone(
    client: &Client,
    root: &str,
    limits: &RefreshLimits,
    budget: &mut usize,
) -> Result<String, Stop> {
    let list = post(
        client,
        root,
        "zones/list",
        &json!({}),
        limits.max_small_bytes,
        budget,
    )
    .await?;
    let zones = list
        .get("zones")
        .and_then(Value::as_array)
        .ok_or(Stop::Failed)?;
    let mut names = Vec::new();
    for zone in zones {
        let Some(name) = zone.pointer("/zoneID/zoneName").and_then(Value::as_str) else {
            continue;
        };
        if zone.get("serverErrorCode").is_some() {
            if name.starts_with(apple::DEFAULT_ZONE)
                && zone_trouble(root, zone) == Some(Stop::Locked)
            {
                return Err(Stop::Locked);
            }
            continue;
        }
        names.push(name.to_string());
    }
    Ok(apple::pick_zone(&names)
        .unwrap_or(apple::DEFAULT_ZONE)
        .to_string())
}

fn zone_id(zone: &str) -> Value {
    json!({"zoneName": zone, "zoneType": "REGULAR_CUSTOM_ZONE"})
}

/// Whether Apple has the library ready to read: a whole read of one it is still preparing would
/// take what it has not yet made as gone.
async fn ready(
    client: &Client,
    root: &str,
    zone: &str,
    limits: &RefreshLimits,
    budget: &mut usize,
) -> Result<(), Stop> {
    let answer = post(
        client,
        root,
        "records/query",
        &json!({"query":{"recordType":"CheckIndexingState"},"zoneID":zone_id(zone)}),
        limits.max_small_bytes,
        budget,
    )
    .await?;
    if let Some(stop) = zone_trouble(root, &answer) {
        return Err(stop);
    }
    let records = answer
        .get("records")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    match apple::readiness_of(records) {
        Readiness::Ready => Ok(()),
        Readiness::Preparing { .. } => Err(Stop::Preparing),
    }
}

/// Removes every `downloadURL` anywhere in `value`.
fn without_links(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("downloadURL");
            for v in map.values_mut() {
                without_links(v);
            }
        }
        Value::Array(list) => list.iter_mut().for_each(without_links),
        _ => {}
    }
}

/// A record as it may be stored: a kept type, or a tombstone; its place fields and download
/// links removed. Anything else is dropped (`None`).
fn kept(record: Value) -> Option<Value> {
    let Value::Object(mut map) = record else {
        return None;
    };
    let name = map.get("recordName").and_then(Value::as_str)?.to_string();
    if map.get("deleted").and_then(Value::as_bool) == Some(true) {
        return Some(json!({"recordName": name, "deleted": true}));
    }
    let kind = map.get("recordType").and_then(Value::as_str)?;
    if !KEPT_TYPES.contains(&kind) {
        return None;
    }
    map.retain(|k, _| {
        ["recordName", "recordType", "recordChangeTag", "fields"].contains(&k.as_str())
    });
    if let Some(Value::Object(fields)) = map.get_mut("fields") {
        fields.retain(|k, _| !k.to_ascii_lowercase().contains("location"));
    }
    let mut record = Value::Object(map);
    without_links(&mut record);
    Some(record)
}

struct FeedPage {
    records: Vec<Value>,
    token: Option<String>,
    more: bool,
}

async fn feed_page(
    client: &Client,
    root: &str,
    zone: &str,
    token: Option<&str>,
    limits: &RefreshLimits,
    budget: &mut usize,
) -> Result<FeedPage, Stop> {
    let mut zone_body = json!({"zoneID": zone_id(zone), "maxChanges": PAGE_RECORDS});
    if let Some(token) = token {
        zone_body["syncToken"] = json!(token);
    }
    let mut answer = post(
        client,
        root,
        "changes/zone",
        &json!({"zones":[zone_body]}),
        limits.max_response_bytes,
        budget,
    )
    .await?;
    let result = answer
        .get_mut("zones")
        .and_then(Value::as_array_mut)
        .and_then(|zones| zones.first_mut())
        .ok_or(Stop::Failed)?;
    if let Some(stop) = zone_trouble(root, result) {
        return Err(stop);
    }
    let records = match result.get_mut("records").map(Value::take) {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(records)) => records,
        Some(_) => return Err(Stop::Failed),
    };
    if records.len() > PAGE_RECORDS {
        return Err(Stop::TooLarge);
    }
    Ok(FeedPage {
        records,
        token: result
            .get("syncToken")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .map(str::to_string),
        more: result
            .get("moreComing")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

/// What a fetch read, for the reply.
#[derive(Clone, Copy, Default)]
struct Read {
    pages: usize,
    records: usize,
    dropped: usize,
}

/// Pages of the change feed from `since` (or the start), until Apple has no more or the page
/// limit: the records kept, where to carry on from, and whether the feed was read to its end.
async fn walk(
    client: &Client,
    root: &str,
    zone: &str,
    since: Option<&str>,
    limits: &RefreshLimits,
    budget: &mut usize,
    read: &mut Read,
) -> Result<(Vec<Value>, Option<String>, bool), Stop> {
    let mut records = Vec::new();
    let mut token = since.map(str::to_string);
    loop {
        if read.pages >= limits.max_pages {
            return Ok((records, token, false));
        }
        let first = read.pages == 0;
        read.pages += 1;
        let page = feed_page(client, root, zone, token.as_deref(), limits, budget).await?;
        // A token answered with no position at all was not taken.
        if first && since.is_some() && page.token.is_none() {
            return Err(Stop::StaleToken);
        }
        for record in page.records {
            match kept(record) {
                Some(record) => {
                    read.records += 1;
                    records.push(record);
                }
                None => read.dropped += 1,
            }
        }
        let advanced = page.token.is_some() && page.token != token;
        if page.token.is_some() {
            token = page.token;
        }
        if !page.more {
            return Ok((records, token, true));
        }
        if !advanced {
            return Err(Stop::BadContinuation);
        }
    }
}

/// One bounded batch of the personal library's change feed, read whole before anything is
/// stored: from where the last refresh got to, or from the start (asking first whether Apple
/// has the library ready) when there is no such place or Apple will not read it.
async fn fetch(
    client: &Client,
    root: &str,
    since: Option<String>,
    limits: &RefreshLimits,
) -> Result<(PhotosFetch, Read), Stop> {
    let mut budget = limits.max_total_bytes;
    let mut read = Read::default();
    let zone = library_zone(client, root, limits, &mut budget).await?;
    if let Some(from) = since.filter(|t| !t.trim().is_empty()) {
        match walk(
            client,
            root,
            &zone,
            Some(&from),
            limits,
            &mut budget,
            &mut read,
        )
        .await
        {
            Ok((records, token, complete)) => {
                let fetched = PhotosFetch {
                    records,
                    token,
                    from: Some(from),
                    incremental: true,
                    complete,
                    zone: None,
                };
                return Ok((fetched, read));
            }
            Err(Stop::StaleToken) => {}
            Err(stop) => return Err(stop),
        }
    }
    ready(client, root, &zone, limits, &mut budget).await?;
    let (records, token, complete) =
        walk(client, root, &zone, None, limits, &mut budget, &mut read)
            .await
            .map_err(|stop| {
                if stop == Stop::StaleToken {
                    Stop::Failed
                } else {
                    stop
                }
            })?;
    let fetched = PhotosFetch {
        records,
        token,
        from: None,
        incremental: false,
        complete,
        zone: None,
    };
    Ok((fetched, read))
}

/// Production refresh: the directory's own keyring session and Apple's endpoints only.
/// Caller holds the private directory's exclusive operation lock.
pub(crate) async fn refresh(dir: &Path, approved: bool) -> Result<Value, &'static str> {
    gate(dir, approved)?;
    let store = Store::isolated_keyring(dir).map_err(|_| "secure_storage_unavailable")?;
    let session = store
        .try_load()
        .map_err(|_| "login_required_unlock_secure_storage")?;
    if !session.is_resumable() {
        return Err("login_required");
    }
    let client = Client::with(dir, Endpoints::default(), store).map_err(|_| "login_required")?;
    timed(dir, client, RefreshLimits::default()).await
}

/// Test seam with synthetic endpoints, never approved for `reads_and_writes`.
/// Caller holds the private directory's exclusive operation lock.
pub async fn refresh_with_client(dir: &Path, client: Client) -> Result<Value, &'static str> {
    refresh_with_client_limited(dir, client, RefreshLimits::default()).await
}

/// [`refresh_with_client`] under other limits, so tests can reach them with small bodies.
#[doc(hidden)]
pub async fn refresh_with_client_limited(
    dir: &Path,
    client: Client,
    limits: RefreshLimits,
) -> Result<Value, &'static str> {
    gate(dir, false)?;
    timed(dir, client, limits).await
}

const TIMED_OUT: &str = "photos_refresh_timeout_cache_kept";

async fn timed(dir: &Path, client: Client, limits: RefreshLimits) -> Result<Value, &'static str> {
    // As for Contacts: reads are cancelled at the deadline. Storing is synchronous and cannot be
    // cancelled, so the deadline is checked before it starts and again inside its transaction,
    // which rolls back when it has passed: a refresh leaves the old cache and cursor or the new
    // ones, and never new ones after its deadline. Each way, the failure is recorded.
    let started_for = owner(dir)?;
    let deadline = (limits.clock)() + limits.timeout;
    match tokio::time::timeout(limits.timeout, read_library(dir, client, limits, deadline)).await {
        Ok(result) => result,
        Err(_) => {
            record_timeout_of(dir, &started_for, SERVICE, TIMED_OUT);
            Err(TIMED_OUT)
        }
    }
}

async fn read_library(
    dir: &Path,
    mut client: Client,
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
        .service_url("ckdatabasews")
        .ok_or("photos_service_unavailable")?;
    // Advanced Data Protection with no Photos key held: Apple would only refuse.
    if client.data_access_missing().contains(&SERVICE) {
        return Err(Stop::Locked.code());
    }
    let data = LibraryLock::new(library, Some(dir.to_owned()));
    // The pass stores only for the account its parameters ask as, and only while the library
    // still names that account.
    let ctx = pass::Ctx::new(
        client.http().clone(),
        client.service_params(),
        Some(root.clone()),
        Vec::new(),
        &pass::NoHooks,
    );
    let since = pass::token(&data, SERVICE).await;
    let stopped = std::sync::Mutex::new(None::<&'static str>);
    let outcome = std::sync::Mutex::new((Read::default(), false, false));
    let lock = tokio::sync::Mutex::new(());
    let note = |code: &'static str| {
        *stopped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(code);
    };
    let report = pass::driven(SERVICE, &ctx, &data, &lock, async {
        let mut fetched = fetch(&client, &root, since, &limits).await.map_err(|stop| {
            note(stop.code());
            stop.error()
        });
        let expired = || {
            let late = (limits.clock)() >= deadline;
            if late {
                note(TIMED_OUT);
            }
            late
        };
        // Before the store begins: it cannot be stopped once it has.
        if fetched.is_ok() && expired() {
            fetched = Err(quince_icloud::Error::Protocol(TIMED_OUT.into()));
        }
        pass::store(SERVICE, &data, &ctx, fetched, |library, (batch, read)| {
            // Checked again inside the transaction: another process may have changed the
            // account since `pass::store` looked, and nothing is written for the wrong one.
            if !pass::owned(library, ctx.account.as_deref()) {
                note("account_changed_during_refresh_cache_kept");
                return Err(quince_icloud::Error::Protocol(pass::NOT_YOURS_WORDS.into()));
            }
            let (complete, incremental) = (batch.complete, batch.incremental);
            // The engine's reader, alone: queued Photos changes are not laid over it.
            apple::apply(library, batch)?;
            // Last, before the transaction commits: past the deadline, it rolls back.
            if expired() {
                return Err(quince_icloud::Error::Protocol(TIMED_OUT.into()));
            }
            *outcome
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = (read, complete, incremental);
            Ok(if incremental { "changes" } else { "full" }.to_string())
        })
        .await
    })
    .await;
    match report.outcome {
        pass::Outcome::Ok => {}
        pass::Outcome::Paused => return Err(Stop::Locked.code()),
        _ if report.detail.as_deref() == Some(pass::NOT_YOURS_WORDS) => {
            return Err("account_changed_during_refresh_cache_kept")
        }
        _ => {
            let stopped = *stopped
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            return Err(stopped.unwrap_or("photos_refresh_failed_cache_kept"));
        }
    }
    let (read, complete, incremental) = *outcome
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let library = data.lock().await;
    let photos = library
        .photo_index(&Source::View(View::Library), None)
        .map_err(|_| "library_unavailable")?
        .ids;
    let mut cached = 0usize;
    for id in &photos {
        if library
            .photo_zone(id)
            .map_err(|_| "library_unavailable")?
            .is_none()
        {
            cached += 1;
        }
    }
    let albums = library.albums().map_err(|_| "library_unavailable")?.len();
    let queued = library
        .outbox_pending(SERVICE)
        .map_err(|_| "library_unavailable")?
        .len();
    Ok(json!({
        "service": SERVICE,
        "library": "personal",
        "outcome": "ok",
        "read": if incremental { "changes" } else { "full" },
        "complete": complete,
        "more": !complete,
        "continue": (!complete).then_some("Apple has more: call photos_refresh again and it carries on from where this one stopped"),
        "pages_read": read.pages,
        "records_read": read.records,
        "records_dropped": read.dropped,
        "cached_photos": cached,
        "cached_albums": albums,
        "last_refreshed_at": report.last_synced_at,
        "queued_photo_changes": queued,
        "queued_changes_sent": 0,
        "remote_verified": false,
        "verification": "Apple's personal photo library metadata was read into the local cache, without places, faces or download links; nothing was sent to Apple",
    }))
}

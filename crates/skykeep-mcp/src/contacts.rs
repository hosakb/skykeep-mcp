//! Apple iCloud Contacts, read-only: cached list, search and get, and an explicit refresh
//! that reads Apple's address book into the local cache. Nothing here writes to Apple or
//! sends queued changes. The engine crates own the parsing and the cache; the refresh's
//! requests are made here so every response is read under a byte limit.
use crate::account::{binding, Binding};
use quince_auth::{Client, Endpoints, Store};
use quince_core::contacts::{Card, ContactMethod, PostalAddress};
use quince_core::Library;
use quince_icloud::contacts::{self as apple, Tokens};
use quince_sync::{library_lock::LibraryLock, pass, queue::ACCOUNT_KEY};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};

const SERVICE: &str = "contacts";
const DEFAULT_LIMIT: usize = 25;
pub(crate) const MAX_LIMIT: usize = 100;
pub(crate) const MAX_QUERY_BYTES: usize = 256;
const MAX_GUID_BYTES: usize = 512;
/// Caps on a tool result's text as encoded in the JSON-RPC frame. A page stops early, with
/// `next_offset`, rather than grow past its cap.
const MAX_PAGE_BYTES: usize = 262_144;
const MAX_CARD_BYTES: usize = 524_288;
/// One summary, encoded. With identifiers at most `MAX_GUID_BYTES` the last level always fits,
/// so the first item of a page always fits and every page makes progress.
const MAX_ITEM_BYTES: usize = 32_768;
/// (characters per text field, entries per email or phone list), tried in turn until a
/// summary fits. Zero characters leaves only the identifier and the counts.
const SUMMARY_LEVELS: [(usize, usize); 4] = [(512, 20), (128, 8), (32, 2), (0, 0)];
/// The same for one card: whole, then each text cut and each list shortened.
const CARD_LEVELS: [Option<(usize, usize)>; 3] = [None, Some((4096, 100)), Some((256, 20))];

/// What a cached card does not hold. The cache is a projection of Apple's card, not a copy.
const NOT_INCLUDED: [&str; 5] = [
    "photo image data and the photo's location; only whether a photo exists",
    "the original vCard; this is not a lossless vCard export",
    "custom fields and card properties the cache does not keep: anything beyond names, company, birthday, notes, name and work details, phones, emails, URLs, postal addresses, related names, dates, instant messaging and social profiles",
    "instant messaging and social profile entries keep one value and one label each",
    "labels are Apple's stored label strings, untranslated; custom labels are kept as typed",
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

/// Checks a Contacts tool's arguments before any approval prompt or cache access.
pub(crate) fn validate(name: &str, args: &Value) -> Result<(), &'static str> {
    match name {
        "contacts_list" => page_limit(parse::<Page>(args)?.limit).map(|_| ()),
        "contacts_search" => search_args(args).map(|_| ()),
        "contacts_get" => get_args(args).map(|_| ()),
        "contacts_refresh" => parse::<Empty>(args).map(|_| ()),
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
        "refresh": "only by contacts_refresh; there is no background Contacts refresh",
    }))
}

/// Display order: folded last name then first name (else what the card shows), with digit
/// runs compared as numbers, then GUID so equal names keep one order.
fn ordered(mut cards: Vec<Card>) -> Vec<Card> {
    let key = |card: &Card| {
        let c = &card.contact;
        let name = [c.last_name.as_deref(), c.first_name.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        if name.trim().is_empty() {
            c.display_name()
        } else {
            name
        }
    };
    let mut keyed: Vec<(String, Card)> = cards.drain(..).map(|c| (key(&c), c)).collect();
    keyed.sort_by(|(a, x), (b, y)| {
        quince_core::fold::natural(a, b).then_with(|| x.contact.guid.cmp(&y.contact.guid))
    });
    keyed.into_iter().map(|(_, c)| c).collect()
}

/// Bytes a value takes as tool-result text inside the JSON-RPC frame: serialized once as the
/// text, then again as a JSON string.
pub(crate) fn encoded_len(value: &Value) -> usize {
    serde_json::to_string(&Value::String(value.to_string())).map_or(usize::MAX, |s| s.len())
}

pub(crate) fn cut(text: Option<&str>, chars: usize, cut_any: &mut bool) -> Option<String> {
    let text = text?;
    if text.chars().count() <= chars {
        return Some(text.to_string());
    }
    *cut_any = true;
    (chars > 0).then(|| text.chars().take(chars).collect())
}

fn summary(card: &Card, chars: usize, entries: usize) -> Value {
    let c = &card.contact;
    let mut cut_any = false;
    let mut of_kind = |kind: &str| {
        let all: Vec<&ContactMethod> = c.methods.iter().filter(|m| m.kind == kind).collect();
        if all.len() > entries {
            cut_any = true;
        }
        let shown: Vec<Value> = all
            .iter()
            .take(entries)
            .map(|m| {
                json!({"label":cut(m.label.as_deref(), chars, &mut cut_any),"value":cut(Some(&m.value), chars, &mut cut_any)})
            })
            .collect();
        (shown, all.len())
    };
    let (emails, emails_total) = of_kind("email");
    let (phones, phones_total) = of_kind("phone");
    json!({
        "guid": c.guid,
        "display_name": cut(Some(&c.display_name()), chars, &mut cut_any),
        "first_name": cut(c.first_name.as_deref(), chars, &mut cut_any),
        "middle_name": cut(c.middle_name.as_deref(), chars, &mut cut_any),
        "last_name": cut(c.last_name.as_deref(), chars, &mut cut_any),
        "company": cut(c.company.as_deref(), chars, &mut cut_any),
        "is_company": c.is_company,
        "emails": emails,
        "emails_total": emails_total,
        "phones": phones,
        "phones_total": phones_total,
        "has_photo": c.photo_url.is_some(),
        "summary_truncated": cut_any,
    })
}

/// One page entry. An identifier too long to ask for with `contacts_get` is never cut into a
/// different, unusable one: the entry says so, with its length, and holds its place.
fn item(card: &Card) -> Value {
    let guid = &card.contact.guid;
    if guid.len() > MAX_GUID_BYTES {
        return json!({"guid":null,"unsupported":"guid_too_long","guid_bytes":guid.len(),"summary_truncated":true});
    }
    let mut shown = Value::Null;
    for (chars, entries) in SUMMARY_LEVELS {
        shown = summary(card, chars, entries);
        if encoded_len(&shown) <= MAX_ITEM_BYTES {
            break;
        }
    }
    shown
}

fn paged(
    library: &Library,
    cards: Vec<Card>,
    offset: usize,
    limit: usize,
) -> Result<Value, &'static str> {
    let total = cards.len();
    let cache = cache_state(library)?;
    let page = |items: &[Value], shortened: bool| {
        let next = offset.saturating_add(items.len());
        json!({
            "source": "local_cache",
            "items": items,
            "total": total,
            "offset": offset,
            "limit": limit,
            "next_offset": (next < total).then_some(next),
            "page_shortened_to_fit": shortened,
            "unsupported_items": items.iter().filter(|i| i["guid"].is_null()).count(),
            "summaries_truncated": items.iter().filter(|i| i["summary_truncated"] == true).count(),
            "complete_representation": false,
            "cache": cache,
            "remote_verified": false,
        })
    };
    // Each item adds its encoded text and a comma; the envelope is measured with room for
    // its counts to grow.
    let mut used = encoded_len(&page(&[], true)).saturating_add(64);
    let mut items = Vec::new();
    let mut shortened = false;
    for card in cards.iter().skip(offset).take(limit) {
        let item = item(card);
        let size = encoded_len(&item).saturating_sub(1);
        if used.saturating_add(size) > MAX_PAGE_BYTES {
            shortened = true;
            break;
        }
        used = used.saturating_add(size);
        items.push(item);
    }
    // The page as it will be sent, measured: never over the cap.
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

pub(crate) fn list(library: &Library, args: Value) -> Result<Value, &'static str> {
    let args: Page = parse(&args)?;
    let limit = page_limit(args.limit)?;
    let cards = ordered(library.cards(None).map_err(|_| "library_unavailable")?);
    paged(library, cards, args.offset, limit)
}

pub(crate) fn search(library: &Library, args: Value) -> Result<Value, &'static str> {
    let args = search_args(&args)?;
    let limit = page_limit(args.limit)?;
    let cards = ordered(
        library
            .cards(Some(&args.query))
            .map_err(|_| "search_unavailable")?,
    );
    paged(library, cards, args.offset, limit)
}

fn method_view(m: &ContactMethod) -> Value {
    json!({"label":m.label,"value":m.value})
}

fn address_view(a: &PostalAddress) -> Value {
    json!({
        "label": a.label,
        "street": a.street,
        "sub_locality": a.sub_locality,
        "city": a.city,
        "sub_administrative_area": a.sub_administrative_area,
        "state": a.state,
        "postal_code": a.postal_code,
        "country": a.country,
        "country_code": a.country_code,
    })
}

/// Every text cut to `chars` characters and every list to `entries`, identifiers excepted.
fn cut_card(value: &Value, chars: usize, entries: usize, cut_any: &mut bool) -> Value {
    match value {
        Value::String(text) => Value::String(cut(Some(text), chars, cut_any).unwrap_or_default()),
        Value::Array(list) => {
            if list.len() > entries {
                *cut_any = true;
            }
            Value::Array(
                list.iter()
                    .take(entries)
                    .map(|v| cut_card(v, chars, entries, cut_any))
                    .collect(),
            )
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let v = if k == "guid" {
                        v.clone()
                    } else {
                        cut_card(v, chars, entries, cut_any)
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

pub(crate) fn get(library: &Library, args: Value) -> Result<Value, &'static str> {
    let args = get_args(&args)?;
    let card = library
        .cards_by_guid(std::slice::from_ref(&args.guid))
        .map_err(|_| "library_unavailable")?
        .into_iter()
        .find(|c| c.contact.guid == args.guid)
        .ok_or("not_found")?;
    let c = &card.contact;
    let d = &card.details;
    let addresses = library
        .contact_addresses(&c.guid)
        .map_err(|_| "library_unavailable")?;
    let lists: Vec<Value> = apple::stored_lists(library)
        .into_iter()
        .filter(|l| l.members.contains(&c.guid))
        .map(|l| json!({"guid":l.guid,"name":l.name}))
        .collect();
    let kind = |k: &str| -> Vec<Value> {
        c.methods
            .iter()
            .filter(|m| m.kind == k)
            .map(method_view)
            .collect()
    };
    let others: Vec<Value> = c
        .methods
        .iter()
        .filter(|m| !["email", "phone", "address"].contains(&m.kind.as_str()))
        .map(|m| json!({"kind":m.kind,"label":m.label,"value":m.value}))
        .collect();
    let (emails, phones) = (kind("email"), kind("phone"));
    let totals = json!({
        "emails": emails.len(),
        "phones": phones.len(),
        "postal_addresses": addresses.len(),
        "other_methods": others.len(),
        "lists": lists.len(),
    });
    let whole = json!({
        "guid": c.guid,
        "display_name": c.display_name(),
        "first_name": c.first_name,
        "middle_name": c.middle_name,
        "last_name": c.last_name,
        "company": c.company,
        "is_company": c.is_company,
        "birthday": c.birthday,
        "notes": c.notes,
        "etag": c.etag,
        "details": {
            "prefix": d.prefix,
            "suffix": d.suffix,
            "nickname": d.nickname,
            "phonetic_first_name": d.phonetic_first_name,
            "phonetic_last_name": d.phonetic_last_name,
            "phonetic_company": d.phonetic_company,
            "job_title": d.job_title,
            "department": d.department,
        },
        "emails": emails,
        "phones": phones,
        "postal_addresses": addresses.iter().map(address_view).collect::<Vec<_>>(),
        "other_methods": others,
        "lists": lists,
        "photo": {"present": c.photo_url.is_some(), "image_included": false},
    });
    let cache = cache_state(library)?;
    for level in CARD_LEVELS {
        let mut cut_any = false;
        let contact = match level {
            None => whole.clone(),
            Some((chars, entries)) => cut_card(&whole, chars, entries, &mut cut_any),
        };
        let value = json!({
            "source": "local_cache",
            "contact": contact,
            "card_truncated": cut_any,
            "truncation": level.filter(|_| cut_any).map(|(chars, entries)| json!({"max_chars_per_text":chars,"max_entries_per_list":entries})),
            "entry_totals": totals,
            "complete_representation": false,
            "not_included": NOT_INCLUDED,
            "cache": cache,
            "remote_verified": false,
        });
        if encoded_len(&value) <= MAX_CARD_BYTES {
            return Ok(value);
        }
    }
    Err("contact_too_large")
}

/// Refuses before any keyring, session or network use: an unapproved read under
/// `reads_and_writes`, or a directory not yet bound to an account. Touches no queued write.
pub(crate) fn gate(dir: &Path, approved: bool) -> Result<(), &'static str> {
    let library = Library::open(dir).map_err(|_| "library_unavailable")?;
    if crate::policy(&library, dir)?.is_some_and(|(p, _)| p.mode == "reads_and_writes") && !approved
    {
        return Err("read_approval_required");
    }
    if library
        .state(ACCOUNT_KEY)
        .map_err(|_| "library_unavailable")?
        .is_none()
    {
        return Err("login_required");
    }
    Ok(())
}

/// Resource limits of one refresh. Bytes are counted as decoded, as they arrive.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct RefreshLimits {
    /// One response.
    pub max_response_bytes: usize,
    /// Every response of the refresh together.
    pub max_total_bytes: usize,
    /// Cards in the book.
    pub max_contacts: usize,
    /// One card as Apple sent it.
    pub max_card_bytes: usize,
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
            max_contacts: 25_000,
            max_card_bytes: 256 * 1024,
            timeout: Duration::from_secs(60),
            clock: Instant::now,
        }
    }
}

/// `/co/changeset` answers with tokens and, at most, a few changed records.
const MAX_CHANGESET_BYTES: usize = 1024 * 1024;
/// Cards per page when the book is read in pages, as icloud.com reads it.
const PAGE_CARDS: usize = 500;

/// Why a refresh read stopped. Apple's own error bodies are never read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    Reauth,
    Busy,
    Failed,
    TooLarge,
    BookTooLarge,
    CardTooLarge,
}

impl Stop {
    fn code(self) -> &'static str {
        match self {
            Stop::Reauth => "login_required",
            Stop::Busy | Stop::Failed => "contacts_refresh_failed_cache_kept",
            Stop::TooLarge => "contacts_response_too_large_cache_kept",
            Stop::BookTooLarge => "contacts_book_too_large_cache_kept",
            Stop::CardTooLarge => "contacts_card_too_large_cache_kept",
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

/// Reads a response body chunk by chunk, as decoded, and stops at whichever of `cap` and the
/// refresh's remaining `budget` comes first. No length Apple announces is trusted or used to
/// reserve memory.
macro_rules! read_capped {
    ($response:expr, $cap:expr, $budget:expr) => {{
        let mut response = $response;
        let cap: usize = $cap;
        let budget: &mut usize = $budget;
        let mut body: Vec<u8> = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if chunk.len() > cap.saturating_sub(body.len()) || chunk.len() > *budget {
                        break Err(Stop::TooLarge);
                    }
                    *budget -= chunk.len();
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break Ok(body),
                Err(_) => break Err(Stop::Failed),
            }
        }
    }};
}
/// Shared with the Calendar refresh, which names its own `Stop` with the same two variants.
pub(crate) use read_capped;

/// The query every Contacts request carries, as the engine sends it.
fn base_query(client: &Client) -> Vec<(String, String)> {
    let mut query = client.service_params();
    query.push(("clientVersion".into(), "2.1".into()));
    query.push(("locale".into(), "en_US".into()));
    query.push(("order".into(), "last,first".into()));
    query
}

/// Whether the book moved since `tokens`, by Apple's `/co/changeset`; its tokens are taken.
async fn changed(
    client: &Client,
    root: &str,
    tokens: &mut Tokens,
    budget: &mut usize,
) -> Result<bool, Stop> {
    let mut query = base_query(client);
    query.push(("prefToken".into(), tokens.pref.clone()));
    query.push(("syncToken".into(), tokens.sync.clone()));
    let response = client
        .http()
        .post(format!("{}/co/changeset", root.trim_end_matches('/')))
        .query(&query)
        .send()
        .await
        .map_err(|_| Stop::Failed)?;
    let status = response.status().as_u16();
    if status == 420 {
        return Ok(true);
    }
    if let Some(stop) = refused(status) {
        return Err(stop);
    }
    let body = read_capped!(response, MAX_CHANGESET_BYTES, budget)?;
    let body: Value = serde_json::from_slice(&body).map_err(|_| Stop::Failed)?;
    let carries = |key: &str| {
        body.get(key)
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
    };
    let gone = body
        .get("deletes")
        .and_then(Value::as_object)
        .is_some_and(|d| {
            d.values()
                .any(|v| v.as_array().is_some_and(|a| !a.is_empty()))
        });
    let mut moved = carries("contacts") || carries("groups") || gone;
    if let Some(sync) = body.get("syncToken").and_then(Value::as_str) {
        moved |= sync != tokens.sync;
        tokens.sync = sync.to_string();
    }
    if let Some(pref) = body.get("prefToken").and_then(Value::as_str) {
        tokens.pref = pref.to_string();
    }
    Ok(moved)
}

/// Bytes one card takes as JSON, counted without building the text.
pub(crate) fn card_bytes(card: &Value) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, card).map_or(usize::MAX, |()| count.0)
}

/// The whole book by `/co/startup` and, for a large one, its pages, each read under the limits.
/// Parsed by the engine's own readers.
async fn whole_book(
    client: &Client,
    root: &str,
    limits: &RefreshLimits,
    budget: &mut usize,
) -> Result<(apple::AddressBook, Tokens), Stop> {
    let root = root.trim_end_matches('/');
    let query = base_query(client);
    let response = client
        .http()
        .get(format!("{root}/co/startup"))
        .query(&query)
        .send()
        .await
        .map_err(|_| Stop::Failed)?;
    if let Some(stop) = refused(response.status().as_u16()) {
        return Err(stop);
    }
    let bytes = read_capped!(response, limits.max_response_bytes, budget)?;
    let mut body: Value = serde_json::from_slice(&bytes).map_err(|_| Stop::Failed)?;
    drop(bytes);
    let token = |key: &str| {
        body.get(key)
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .ok_or(Stop::Failed)
    };
    let tokens = Tokens {
        sync: token("syncToken")?,
        pref: token("prefToken")?,
    };
    let wanted = body
        .get("contactsOrder")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let cards = body
        .as_object_mut()
        .ok_or(Stop::Failed)?
        .entry("contacts")
        .or_insert_with(|| Value::Array(Vec::new()));
    let Value::Array(cards) = cards else {
        return Err(Stop::Failed);
    };
    if wanted > limits.max_contacts || cards.len() > limits.max_contacts {
        return Err(Stop::BookTooLarge);
    }
    // A large book comes in pages; each page adds at least one card or the read stops.
    while cards.len() < wanted {
        let mut page_query = query.clone();
        page_query.push(("syncToken".into(), tokens.sync.clone()));
        page_query.push(("prefToken".into(), tokens.pref.clone()));
        page_query.push(("offset".into(), cards.len().to_string()));
        page_query.push(("limit".into(), PAGE_CARDS.to_string()));
        let response = client
            .http()
            .get(format!("{root}/co/contacts/card/"))
            .query(&page_query)
            .send()
            .await
            .map_err(|_| Stop::Failed)?;
        let status = response.status().as_u16();
        if let Some(stop) = refused(status) {
            return Err(if stop == Stop::Reauth {
                stop
            } else {
                Stop::Failed
            });
        }
        let bytes = read_capped!(response, limits.max_response_bytes, budget)?;
        let mut page: Value = serde_json::from_slice(&bytes).map_err(|_| Stop::Failed)?;
        drop(bytes);
        let more = match page.get_mut("contacts").map(Value::take) {
            Some(Value::Array(more)) if !more.is_empty() => more,
            // Stored short, the cards it missed would read as deleted.
            _ => return Err(Stop::Failed),
        };
        if more.len() > limits.max_contacts.saturating_sub(cards.len()) {
            return Err(Stop::BookTooLarge);
        }
        cards.extend(more);
    }
    if cards
        .iter()
        .any(|card| card_bytes(card) > limits.max_card_bytes)
    {
        return Err(Stop::CardTooLarge);
    }
    let book = apple::AddressBook {
        contacts: apple::parse(&body),
        lists: apple::parse_lists(&body),
        me: apple::me_card(&body),
        addresses: apple::parse_addresses(&body),
        details: apple::parse_details(&body),
    };
    Ok((book, tokens))
}

/// As the engine's Contacts pass: a cheap changeset check when tokens are kept, and the whole
/// book only when it moved (or the check could not say). Every read is bounded.
async fn fetch(
    client: &Client,
    root: &str,
    since: Option<Tokens>,
    limits: &RefreshLimits,
) -> Result<apple::Pass, Stop> {
    let mut budget = limits.max_total_bytes;
    if let Some(mut tokens) = since {
        match changed(client, root, &mut tokens, &mut budget).await {
            Ok(false) => return Ok(apple::Pass::Unchanged(tokens)),
            Ok(true) => {}
            Err(stop @ (Stop::Reauth | Stop::TooLarge)) => return Err(stop),
            Err(_) => {}
        }
    }
    let (book, tokens) = whole_book(client, root, limits, &mut budget).await?;
    Ok(apple::Pass::Read(book, tokens))
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

const TIMED_OUT: &str = "contacts_refresh_timeout_cache_kept";

/// Who the directory belongs to: its account tag and its identity on disk.
pub(crate) fn owner(dir: &Path) -> Result<(Option<String>, (u64, u64)), &'static str> {
    let library = Library::open(dir).map_err(|_| "library_unavailable")?;
    let account = library
        .state(ACCOUNT_KEY)
        .map_err(|_| "library_unavailable")?;
    Ok((account, crate::directory_identity(dir)?))
}

/// A refresh cut off by its deadline is a failed refresh, recorded as one only while the
/// directory is the same one and still names the account the refresh started for.
fn record_timeout(dir: &Path, started_for: &(Option<String>, (u64, u64))) {
    record_timeout_of(dir, started_for, SERVICE, TIMED_OUT);
}

/// [`record_timeout`] for any service: `words` recorded as its failure.
pub(crate) fn record_timeout_of(
    dir: &Path,
    started_for: &(Option<String>, (u64, u64)),
    service: &str,
    words: &str,
) {
    if started_for.0.is_none() || crate::directory_identity(dir).ok() != Some(started_for.1) {
        return;
    }
    let Ok(mut library) = Library::open(dir) else {
        return;
    };
    let _ = library.atomically(|library| -> quince_core::Result<()> {
        if library.state(ACCOUNT_KEY)? == started_for.0 {
            library.mark_sync_failed(service, words)?;
        }
        Ok(())
    });
}

async fn timed(dir: &Path, client: Client, limits: RefreshLimits) -> Result<Value, &'static str> {
    // Network reads are cancelled at the deadline. Parsing and storing are bounded by the
    // byte and card limits. The deadline is checked again inside the store's transaction,
    // which rolls back when it has passed, so a refresh leaves either the old cache or the
    // new one, and never a new one after its deadline.
    let started_for = owner(dir)?;
    let deadline = (limits.clock)() + limits.timeout;
    match tokio::time::timeout(limits.timeout, read_book(dir, client, limits, deadline)).await {
        Ok(result) => result,
        Err(_) => {
            record_timeout(dir, &started_for);
            Err(TIMED_OUT)
        }
    }
}

async fn read_book(
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
        .service_url("contacts")
        .ok_or("contacts_service_unavailable")?;
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
    let since = pass::token(&data, SERVICE)
        .await
        .as_deref()
        .and_then(Tokens::from_stored);
    let stopped = std::sync::Mutex::new(None::<&'static str>);
    let lock = tokio::sync::Mutex::new(());
    let report = pass::driven(SERVICE, &ctx, &data, &lock, async {
        let mut fetched = fetch(&client, &root, since, &limits).await.map_err(|stop| {
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
        // Queued Contacts changes are neither sent nor laid over what Apple returned.
        pass::store(SERVICE, &data, &ctx, fetched, |library, found| {
            let read = match found {
                apple::Pass::Read(book, tokens) => {
                    apple::apply(library, book)?;
                    library.mark_synced(SERVICE, Some(&tokens.stored()))?;
                    library.mark_full_sync(SERVICE)?;
                    "full"
                }
                apple::Pass::Unchanged(tokens) => {
                    library.mark_synced(SERVICE, Some(&tokens.stored()))?;
                    "unchanged"
                }
            };
            // Last, before the transaction commits: past the deadline, it rolls back
            // and the pass is recorded as failed.
            if expired() {
                return Err(quince_icloud::Error::Protocol(TIMED_OUT.into()));
            }
            Ok(read.to_string())
        })
        .await
    })
    .await;
    match report.outcome {
        pass::Outcome::Ok => {}
        pass::Outcome::Paused => return Err("contacts_paused_approve_on_apple_device"),
        _ if report.detail.as_deref() == Some(pass::NOT_YOURS_WORDS) => {
            return Err("account_changed_during_refresh_cache_kept")
        }
        _ => {
            let stopped = *stopped
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            return Err(stopped.unwrap_or("contacts_refresh_failed_cache_kept"));
        }
    }
    let library = data.lock().await;
    let cached = library.contact_count().map_err(|_| "library_unavailable")?;
    let queued = library
        .outbox_pending(SERVICE)
        .map_err(|_| "library_unavailable")?
        .len();
    Ok(json!({
        "service": SERVICE,
        "outcome": "ok",
        "read": report.detail.as_deref().unwrap_or("full"),
        "cached_contacts": cached,
        "last_refreshed_at": report.last_synced_at,
        "queued_contact_changes": queued,
        "queued_changes_sent": 0,
        "remote_verified": false,
        "verification": "Apple's address book was read into the local cache; nothing was sent to Apple",
    }))
}

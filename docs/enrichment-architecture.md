# Enrichment architecture: browser extensions and shadow IT

## What this document is

This document describes how Fleet Hound enriches browser extensions and shadow IT software. It names each step, each external API, each configuration knob and each known limitation, with the file and line that implements it. It follows ASD-STE100 Simplified Technical English so that a newcomer can read it without prior knowledge of the repository.

NOTE: Line numbers refer to the repository state on 2026-10-27 at commit `521c0ac`. When you edit a file, the line numbers in this document can move.

NOTE: This document does not contain optimization proposals. It describes the system as it is.

## Terms used in this document

| Term | Meaning in this document |
|---|---|
| extension | One browser extension as reported by Fleet (osquery source `chrome_extensions`, `firefox_addons`, `safari_extensions` or `ie_extensions`). |
| store | The vendor catalog that lists an extension: Chrome Web Store, Edge Add-ons, Firefox AMO. `safari`, `brave`, `opera`, `vivaldi` and `chromium` are also store names in the code. |
| worker | A daemon thread inside the `webviz` container that runs on a timer. There are two workers: the extension worker and the enricher worker. |
| cache | A JSON file on disk under `config/extension_cache` that holds a store response, or an in-process dictionary. |
| risk score | An integer from 0 to 100 that `analyze_extension` computes for one extension. |
| signal | One named reason, with a weight, that contributes to a risk score. The code stores signals in `risk_signals_json`. |
| shadow IT | Software that a user installed without approval. Fleet Hound detects it by rarity, category or version sprawl. |

## Overview

### Browser extension flow

```
 Fleet REST API                       (src/extractor.py:176)
   GET /api/v1/fleet/hosts?populate_software=true
        |
        v
 Ingestion                            (src/ingestion.py:522, :958, :1130)
   derive_extension_identity()        (src/extension_intel.py:119)
   MERGE (:Software {name = extension_key})
   MERGE (:Software)-[:INSTALLED_ON]->(:Host)
        |
        v
 Memgraph                             (:Software nodes, INSTALLED_ON edges)
        |
        v
 Extension worker                     (webviz/extension_worker.py:848)
   at leader start: prune_cache() drops retired cache key versions
   every 21600 s, on POST /api/extensions/refresh,
   or on the OODA Orient trigger after an ingest
   1. load threat feeds + Mozilla blocklist
      (cache 6 h, then conditional GET with If-None-Match)
   2. read all extension groups
   3. fingerprint; select groups that are due
   4. store adapters  ---------> Chrome Web Store RPC
         |                       Chrome update2 + CRX
         |                       Edge Add-ons
         |                       Firefox AMO + XPI
         |                       (cache on disk, 7 to 28 d)
   5. analyze_extension()        (src/extension_intel.py:882)
         risk score 0-100, band low/medium/high/critical
   6. write ~40 properties back to :Software
        |
        v
 API route                            (webviz/routes/workers.py:250)
   GET /api/extensions, /detail, /status; POST /refresh
        |
        v
 UI: Extensions tab                   (webviz/static/app.js:4697)
```

### Shadow IT flow

```
 Memgraph :Software nodes
        |
        +--> ETL run_categorization()     (categorize_software.py:388)
        |      rare per platform, not a system package
        |      1. local catalog           (src/software_catalog.py:185)
        |      2. Wikipedia REST summary  (categorize_software.py:225)
        |      write s.category, s.wikidata_description
        |
        +--> Enricher worker              (webviz/enrich_worker.py:244)
        |      every 300 s, 25 items, same two lookups
        |
        v
 GET /api/shadow-it                       (webviz/routes/shadow_it.py:57)
   detector 1: outlier (rare) software
               (extension risk_band sets the level)
   detector 2: high-risk category or name
   detector 3: version sprawl
        |
        v
 UI: Shadow IT tab
```

## Part 1: Browser extension enrichment

### 1.1 Identity

The ingestion step calls `derive_extension_identity(software)` for every software row (`src/extension_intel.py:119`). The function returns `None` unless `software.source` is one of the four browser sources (`:44-46`, `:128-130`). It then builds one stable key for the extension.

Procedure that the function performs:

1. Clean `name`, `display_name`, `browser`, `extension_for` and `installed_paths` (`:132-139`).
2. Infer the store with `_infer_store` (`:71-99`). `firefox_addons` becomes `firefox`. `safari_extensions` becomes `safari`. `ie_extensions` becomes `edge`. `chrome_extensions` becomes `edge`, `brave`, `opera`, `vivaldi` or `chromium` when `browser` or `extension_for` contains that word (`:84-86`). An install path can also select `edge`, `brave`, `opera` or `vivaldi` (`:89-98`). Otherwise it becomes `chrome`.
3. Take the extension ID from `software.extension_id` when present (`:142`). Otherwise call `_infer_extension_id` (`:102-116`). Chrome and Edge use the first match of `\b[a-p]{32}\b`. Firefox uses a full match of `{uuid}` or `local@domain`. Safari uses a token with two or more dots and no spaces.
4. Build `extension_key = "ext:<store>:<id>"` in lowercase (`:148`).
5. When no ID exists, build `extension_key = "ext:<store>:name:<sha1(name)[:16]>"` (`:152-153`).
6. Set `is_builtin` with `is_browser_builtin` (`:188-210`).

The output dictionary (`:155-170`) holds `kind`, `store`, `extension_id`, `extension_key`, `browser`, `extension_for`, `display_name`, `installed_paths` (first 10), `installed_path` and `is_builtin`.

NOTE: Ingestion writes `extension_key` into `Software.name` (`src/ingestion.py:554`). The human title lives in `display_name`. The `UNIQUE(Software.name)` constraint therefore also enforces one node per extension.

Built-in detection (`src/extension_intel.py:188`) returns `True` in four cases. Case 1: a Firefox ID ends with `@mozilla.org` or `@mozilla.com` (`:61`, `:192-193`). Case 2: on a Chromium-family store, the ID is one of the 8 component IDs in `CHROMIUM_BUILTIN_IDS` (`:51-60`, `:194-196`). Case 3: an install path matches the anchored install-root regex for the store in `_BUILTIN_PATH_RES` (`:177-185`, `:204-206`). Case 4: a Safari install path starts with `/Applications/Safari.app/` or `/System/` (`:209-210`).

The function lowercases each path and changes `/` to `\` before the match (`:201`). `_WIN_ROOT` (`:176`) anchors a Windows path at `<drive>:\Program Files\`, `<drive>:\Program Files (x86)\` or `<drive>:\Users\<user>\AppData\Local\`. `_BUILTIN_PATH_RES` has these entries:

| Store | Built-in install root |
|---|---|
| chrome | `_WIN_ROOT` + `Google\Chrome\Application\` |
| edge | `_WIN_ROOT` + `Microsoft\Edge\Application\` |
| brave | `_WIN_ROOT` + `BraveSoftware\Brave-Browser\Application\` |
| vivaldi | `_WIN_ROOT` + `Vivaldi\Application\` |
| firefox | `_WIN_ROOT` + `Mozilla Firefox\`, `/Applications/Firefox.app/Contents/Resources/`, or `/usr/lib[64]/firefox[-esr]/`, each followed by `browser/features/` |

NOTE: Opera and Chromium have no path entry. On macOS and Linux, a Chromium-family extension is built-in only by its ID. An App Store Safari extension in `<App>.app/Contents/PlugIns` is not built-in.

A built-in extension gets risk score 0, trust 100 and `store_status = "builtin"` (`:913-944`). This short-circuit applies only when no blocklist entry and no threat feed hit exist (`:913`). With a hit, the extension gets a full score and keeps `is_builtin = True` (`:1088`).

`analyze_extension` recomputes `is_builtin` from the store, ID and paths (`:903-907`). It does not read the stored node flag. The extension worker also recomputes the flag in `_record_for` (`webviz/extension_worker.py:337-338`). Thus a change to the built-in rules takes effect at the next score, without a new ingest.

### 1.2 Worker selection and cadence

The extension worker lives in `webviz/extension_worker.py`. It starts when the first HTTP request reaches `/api/health` or any `/api/extensions*` route (`webviz/app.py:645`, `webviz/app.py:815-844`, `webviz/routes/workers.py:257`).

Procedure that `start_worker` performs (`webviz/extension_worker.py:848`):

1. Read the previous status file `config/extension_status.json` (`:165`).
2. Return when `EXTENSION_WORKER_ENABLED` is false.
3. Take a non-blocking `flock` on `/tmp/fleet-hound-extensions.lock` (`:863`, `webviz/worker_util.py:62-82`).
4. Return when another Gunicorn worker holds the lock.
5. Write the PID into the lock file.
6. Run `prune_cache` on the cache directory (`webviz/extension_worker.py:869`). See 1.2.1.
7. Start the daemon thread `fleet-hound-extensions` that runs `_loop` (`:872-886`).

Procedure that `_loop` performs (`:821`):

1. Run `_run_cycle` (`:832`).
2. Store any exception in `last_error`.
3. Call `sleep_until` for the rest of `interval_sec` (default 21600 s) (`:841-843`, `webviz/worker_util.py:92-101`).
4. `sleep_until` reads the trigger file mtime once per second.
5. Start the next cycle when the mtime advances or the interval ends.

Procedure that `_run_cycle` performs (`webviz/extension_worker.py:724`):

1. Count all hosts with `MATCH (h:Host) RETURN count(h)` (`:209`).
2. Load the threat feeds (`:654`) and the Mozilla blocklist (`:707`).
3. Read every extension group from Memgraph (`:286`).
4. Build a fingerprint per group and select the groups that are due (`:387`).
5. Split the due groups into chunks of `batch_size` (default 50).
6. For each chunk, prefetch Chrome listings in one batched RPC (`:517`).
7. Score each item of the chunk in a thread pool of `parallelism` threads (default 4) (`:534`).
8. Write the rows of the chunk to Memgraph (`:642`).
9. Update the status file after each chunk (`:785`).
10. Run the coverage query and store the result in the status file (`:681`).

A manual refresh is `POST /api/extensions/refresh` (`webviz/routes/workers.py:348-365`). It touches `/tmp/fleet-hound-extensions.trigger` with a 30 s cooldown (`webviz/extension_worker.py:911-913`, `webviz/worker_util.py:104-123`). The OODA Orient phase also touches this trigger file after each ingest (see 1.2.2).

The fingerprint (`webviz/extension_worker.py:342-354`) is a hash of the scoring inputs. The inputs are `SCORER_VERSION`, the store, the ID, the versions, the installs, the host count and the rare-in-fleet verdict. The inputs also include the threat digest, the digest of `config/known_publishers.json`, and the name, vendor, built-in and CVSS fields. A store call is due in four cases (`:367-384`). Case 1: the cache has no listing. Case 2: a new blocklist or feed hit exists. Case 3: the TTL has expired. Case 4: a host reports a version newer than the cached listing.

| Store | Listing cache TTL | Where |
|---|---|---|
| chrome, brave, vivaldi, chromium | 7 d | `webviz/extension_worker.py:89` |
| edge, firefox, opera, safari | 21 d plus a per-ID jitter of up to 7 d | `webviz/extension_worker.py:90-91`, `:263-268` |
| manifest (per store, ID and version) | never expires | `webviz/extension_worker.py:499` |
| threat feeds, Mozilla blocklist | 6 h, then a conditional GET (see 1.9) | `webviz/extension_worker.py:92` |

#### 1.2.1 Cache keys and pruning

`_cache_path` (`webviz/extension_worker.py:105-108`) maps a cache key to the file `<safe key, 60 chars>-<sha1[:20]>.json`. The key characters other than letters, digits, `-`, `_` and `.` become `_`. Thus the key `v12:listing:...` becomes a file name that starts with `v12_listing_`.

| Constant | Value | Cache key | Where |
|---|---|---|---|
| `LISTING_KEY_VERSION` | `v12` | `v12:listing:<store>:<id>` | `webviz/extension_worker.py:225`, `:229-230` |
| `MANIFEST_KEY_VERSION` | `v11` | `v11:manifest:<store>:<id>:<version>` | `webviz/extension_worker.py:226`, `:233-234` |

A change to the shape of a cached document must bump its key version. `v12` adds the integer `privacy_codes` to each listing (`:223-224`).

`prune_cache(cache_dir)` (`:240-260`) runs once when a worker wins the leader lock (`:869`). It deletes each file whose name matches `v<N>_` and does not start with `v12_listing_` or `v11_manifest_`. It does not touch feed copies, the blocklist copy, `:meta` files or unknown files. A failed delete logs a warning and does not stop the worker.

#### 1.2.2 Wake-up after an ingest

The OODA Orient phase touches the enricher trigger file and the extension trigger file (`webviz/ooda_worker.py:463-487`). `webviz/app.py` passes `EXTENSION_WORKER_TRIGGER_PATH` only when `EXTENSION_WORKER_ENABLED` is true (`webviz/app.py:784`). Thus, with OODA on, the extension worker scores new extensions within one OODA interval. A failed touch adds `<label> trigger failed` to the Orient phase error and does not stop the cycle.

#### 1.2.3 Shared worker helpers

`webviz/worker_util.py` holds the cross-process helpers of the enricher, extension and OODA workers.

| Helper | What it does | Where |
|---|---|---|
| `atomic_write_json` | Writes JSON with `mkstemp`, `fsync`, `chmod 0600` and `os.replace`. Raises on failure. | `webviz/worker_util.py:26-50` |
| `read_json` | Returns the parsed JSON, or `default` when the file is missing or malformed. | `webviz/worker_util.py:53-59` |
| `try_acquire_lock` | Takes a non-blocking exclusive `flock` and writes the PID. Returns the fd, or `None`. | `webviz/worker_util.py:62-82` |
| `trigger_mtime` | Returns the trigger file mtime, or 0.0. | `webviz/worker_util.py:85-89` |
| `sleep_until` | Sleeps until a deadline, a stop request or a newer trigger mtime. Polls every `TRIGGER_POLL_SEC` (1.0 s). | `webviz/worker_util.py:92-101` |
| `fire_trigger` | Touches the trigger file unless the last touch is inside the cooldown. Returns `(fired, retry_after_sec)`. | `webviz/worker_util.py:104-123` |

The extension worker status flush catches `OSError` and logs a warning (`webviz/extension_worker.py:188-192`). Thus a read-only config directory does not stop the loop.

### 1.3 HTTP client

All store adapters use `HttpClient` (`src/extension_intel.py:1148`). The client checks the host of the URL against an allowlist. It rejects redirects to hosts outside the allowlist (`:1142-1143`). It reads at most `max_bytes + 1` bytes. It does not retry. `get` accepts extra request headers, for example `If-None-Match` for a conditional GET (`:1154-1157`). The client always sets `User-Agent` and `Accept` itself (`:1169`).

| Property | Value | Where |
|---|---|---|
| User-Agent | `fleet-hound-extension-intel/1.0 (+https://github.com/)` | `src/extension_intel.py:1121` |
| Default timeout | 12.0 s | `src/extension_intel.py:1151` |
| Default byte cap | 8 MiB | `src/extension_intel.py:1122` |
| Chrome hosts | clients2.google.com, storage.googleapis.com, clients2.googleusercontent.com, redirector.gvt1.com, edgedl.me.gvt1.com, chromewebstore.google.com | `src/extension_intel.py:1123-1130` |
| Edge hosts | microsoftedge.microsoft.com | `src/extension_intel.py:1131` |
| AMO hosts | addons.mozilla.org | `src/extension_intel.py:1132` |
| Mozilla hosts | firefox.settings.services.mozilla.com | `src/extension_intel.py:1133` |
| Opera hosts | addons.opera.com | `_OPERA_HOSTS` |
| Apple hosts | itunes.apple.com | `_APPLE_HOSTS` |
| Rate-limit mark | HTTP 429, or HTTP 503 with a `Retry-After` header, sets `meta["rate_limited"] = True` | `src/extension_intel.py:1211-1221` |

CAUTION: An HTTP 4xx or 5xx response returns `error = None` (`:1187`). Every caller must test the status code itself.

### 1.4 Store adapter: Chrome Web Store listing RPC

`fetch_chrome_listings` (`src/extension_intel.py:1468`) fetches listing data for up to 40 IDs in one POST. The worker calls it once per chunk (`webviz/extension_worker.py:517`).

| Field | Value |
|---|---|
| URL | `https://chromewebstore.google.com/_/ChromeWebStoreConsumerFeUi/data/batchexecute?rpcids=xY2Ddd&hl=en&rt=c` (`src/extension_intel.py:1332`) |
| Method | POST, `application/x-www-form-urlencoded` |
| Request | Form field `f.req` = JSON `[[["xY2Ddd", "[\"<id>\"]", null, "<n>"], ...]]`, up to 40 IDs (`:1492-1495`) |
| Response fields used | Envelope `["wrb.fr", "xY2Ddd", payload, _, _, [code], tag]`. Payload indices: `[0][0]` id, `[0][2]` name, `[0][3]` rating, `[0][4]` rating_count, `[0][7]` developer website, `[0][8]` and `[0][15]` established_publisher, `[0][9]` featured, `[0][11][0]` category slug, `[0][14]` users, `[0][18]` manifest JSON, `[7]` privacy codes (stored as integer `privacy_codes` and as `privacy_disclosure` text, `src/extension_intel.py:1443-1449`), `[10][0]` developer email, `[10][3]` trader, `[10][5]`/`[10][7]` publisher name, `[10][10]` publisher_id, `[13]` version, `[14][0]` updated epoch, `[33]` privacy policy URL |
| Auth | none |
| Timeout | 12 s |
| Byte cap | 8 MiB |
| Cache TTL | 7 d (listing), written by the worker (`webviz/extension_worker.py:495`) |
| Failure behaviour | gRPC code 5: status `unlisted` plus `listing_missing`. Code 7: status `removed`. Code 8: `rate_limited`. Other code or missing envelope: `error`. A non-200 or unparseable chunk sets the same error on every ID in the chunk (`src/extension_intel.py:1508-1509`). After a 429 or 503, the function marks later chunks `rate_limited` without a request (`:1486-1491`). |
| Limitation | The RPC is an undocumented Google endpoint. The index map matches rendered detail pages from a manual check on 2026-10-27 (`src/extension_intel.py:1329`). A changed shape raises "listing RPC schema drift" per ID (`:1516`). Category labels cover 7 slugs (`:1338-1346`). |

### 1.5 Store adapter: Chrome update2 and CRX

`fetch_chrome_metadata` (`src/extension_intel.py:1529`) runs only when the listing RPC reported `listing_missing` (`:1540-1541`).

| Field | Value |
|---|---|
| URL | `https://clients2.google.com/service/update2/crx?response=updatecheck&prodversion=999.0&acceptformat=crx2,crx3&x=id%3D<id>%26uc` (`:1546-1553`), then GET `updatecheck@codebase` for the CRX package |
| Method | GET |
| Request | Query string only |
| Response fields used | `updatecheck@status`, `updatecheck@version`, `updatecheck@codebase`, `updatecheck@hash_sha256`; `manifest.json` inside the CRX |
| Auth | none |
| Timeout | 12 s |
| Byte cap | update2 XML 1,000,000 B (`:1554`); CRX 50 MiB (`:1597`); `manifest.json` 1 MiB (`:1276`) |
| Cache TTL | 7 d (listing); manifest never expires, keyed by version (`webviz/extension_worker.py:499`) |
| Failure behaviour | No `updatecheck` or status that starts with `error`: status `not_found`. `noupdate` without `codebase`: `manifest_unavailable` (`src/extension_intel.py:1592-1595`). CRX over 50 MiB: `manifest_unavailable` (`:1599-1602`). SHA-256 mismatch: `manifest_error`, but the manifest is still parsed and merged (`:1611-1620`). |
| Limitation | Listed Chrome extensions get the manifest from the RPC string, never from the package. `crx_hash_verified` exists only for unlisted Chrome and AMO items. `_parse_crx` skips the CRX3 signature block and does not verify it (`src/extension_intel.py:1289-1290`). |

`_parse_crx` (`src/extension_intel.py:1279`) accepts CRX3, CRX2 or a plain ZIP. It rejects archives with more than 5000 entries (`:1305`). It reads only `manifest.json`.

### 1.6 Store adapter: Edge Add-ons

`fetch_edge_metadata` (`src/extension_intel.py:1627`).

| Field | Value |
|---|---|
| URL | `https://microsoftedge.microsoft.com/addons/getproductdetailsbycrxid/{extension_id}` (`:1632`) |
| Method | GET |
| Request | Path parameter only |
| Response fields used | `name`/`extensionName`, `version`/`latestVersion`, `activeInstallCount`/`users`/`userCount`/`installCount`, `rating`/`averageRating`, `ratingCount`/`ratingsCount`/`rating_count`, `developer`/`developerName`/`publisher`/`publisherName`, `developerVerified`/`isDeveloperVerified`/`verified`, `lastUpdateDate`/`lastUpdated`/`updateDate`, `isBadgedAsFeatured`, `category`/`categories`, `privacyUrl`/`privacyPolicyUrl`/`privacyPolicy`, `publisherWebsiteUri`, `manifest`/`manifest_json`/`manifestJson` |
| Auth | none |
| Timeout | 12 s |
| Byte cap | 2,000,000 B (`:1633`) |
| Cache TTL | 21 to 28 d |
| Failure behaviour | HTTP 404 or empty object: status `not_found`. Non-200 or non-JSON: `error`. When Edge says `not_found` and the ID matches `[a-p]{32}`, the dispatcher calls the Chrome adapter and tags the result `resolved_from = "edge"` (`:1830-1832`). |
| Limitation | No package download and no hash check. Manifest fields exist only when the API embeds a manifest (`:1649`). The ID is not validated against `[a-p]{32}` before interpolation (`:1632`). The many alternative key names show that the response shape is not pinned (`:1650-1672`). |

### 1.7 Store adapter: Firefox AMO and XPI

`fetch_amo_metadata` (`src/extension_intel.py:1680`).

| Field | Value |
|---|---|
| URL | `https://addons.mozilla.org/api/v5/addons/addon/{guid}/` (`:1686`), then GET `current_version.file.url` (host must be addons.mozilla.org) |
| Method | GET |
| Request | Path parameter (URL-quoted GUID) |
| Response fields used | `name`, `status`, `is_disabled`, `authors[].id`, `authors[].name`, `authors[].username`, `ratings.average`, `ratings.count`, `average_daily_users`, `weekly_downloads`, `promoted[].category`, `support_email`, `homepage.url`, `category`/`categories`, `created`, `last_updated`, `has_privacy_policy`, `current_version.version`, `current_version.created`, `current_version.manifest_version`, `current_version.content_script_matches`, `current_version.file.{permissions, host_permissions, optional_permissions, url, size, hash}` |
| Auth | none |
| Timeout | 12 s |
| Byte cap | detail 2,000,000 B (`:1687`); XPI 50 MiB with a `file.size` pre-check (`:1786-1789`) |
| Cache TTL | 21 to 28 d; manifest never expires |
| Failure behaviour | HTTP 401: status `unlisted`. HTTP 404: status `not_found`. XPI `sha256:` hash mismatch: `manifest_error` and no parse. Unknown AMO status strings default to `public` (`:1720-1721`). |
| Limitation | A 401 returns no fields except the status (`:1690-1693`), so unlisted Firefox add-ons have no permissions or publisher. `users` mixes `average_daily_users` and `weekly_downloads` (`:1749`). |

### 1.7a Store adapter: Opera add-ons

`fetch_opera_metadata` (`src/extension_intel.py`). addons.opera.com has no public API, so the adapter reads the listing page.

| Field | Value |
|---|---|
| URL | `https://addons.opera.com/en/extensions/details/app_id/{extension_id}/` (302 to the slug page, 404 when unlisted), then GET `https://addons.opera.com/extensions/download/{slug}/` for the CRX |
| Method | GET |
| Request | Path parameter (32-char Chromium ID, validated) |
| Response fields used | `<meta property="aoc:app_id">` (must equal the requested ID, else the page is rejected), `aoc:slug`, `og:title`, the `h-byline` developer link, `#rating-value`, `#rating-count`, and the About table: Downloads, Category, Version, Last update, Support page. The CRX manifest supplies permissions, host permissions, content scripts and manifest version. |
| Auth | none |
| Byte cap | page 2,000,000 B; CRX 50 MiB |
| Cache TTL | 21 to 28 d; manifest never expires |
| Failure behaviour | Any non-public, non-rate-limited Opera answer (404, transport error, page drift) asks the Chrome Web Store (Opera installs CWS items too); a CWS answer other than `not_found`/`unknown` is returned with `resolved_from: "opera"`, else Opera's own answer stands. HTTP 404: `not_found`. Page drift: `error`, not cached. CRX transport error or 5xx: status `unknown`, not cached. Other CRX failure: `manifest_error`. A cached CWS-only answer from before this adapter is refetched once. |
| Limitation | `users` is total downloads, not active users. Opera shows only a developer username, so Opera gets no publisher trust. The CRX has no published hash to verify. |

### 1.7b Store adapter: Mac App Store (Safari)

`fetch_safari_metadata` (`src/extension_intel.py`). Fleet reports Safari extensions with an empty `extension_id`; osquery only finds them inside a top-level `/Applications/<App>.app/Contents/PlugIns/*.appex`. Ingestion maps that path to the containing app and reads the same host's Fleet `apps` row at that app path (`with_safari_app`, `src/ingestion.py`). When found, the identity becomes `ext:safari:<app bundle ID>/<appex name>@<team ID or unsigned>`, so extensions of different apps, or differently signed copies, never share a node (`@` is reserved: an ID inferred from a host-reported name or path never contains it, and trust needs the key to end in `@<app_team_id>`), and the node gets `app_bundle_id` and `app_team_id` (the app's code-signing team from `signature_information`). Without an `apps` row the old name/path key stays and no lookup runs. The worker asks the App Store about that bundle ID (`_lookup_id`, `webviz/extension_worker.py`).

| Field | Value |
|---|---|
| URL | `https://itunes.apple.com/lookup?entity=macSoftware&bundleId={app_bundle_id}` |
| Method | GET |
| Request | Query parameter (bundle ID, validated as dotted `[A-Za-z0-9-]` segments, at most 255 chars) |
| Response fields used | `results[].bundleId` (must equal the request), `trackName`, `version`, `sellerName`/`artistName`, `averageUserRating` and `userRatingCount` (only when the count is above 0), `primaryGenreName`, `currentVersionReleaseDate`, `releaseDate`, `trackViewUrl`, `sellerUrl` |
| Auth | none |
| Byte cap | 1,000,000 B |
| Cache TTL | 21 to 28 d (one listing per containing app) |
| Failure behaviour | No matching result: status `off_store` (Developer ID or sideloaded app): no threat points, an informational `not-in-app-store` signal. Non-200: `error`, not cached. Every listed result sets `manifest_unavailable` because the App Store serves no package. |
| Trust | The containing app's Apple code-signing team ID against `apple_team_ids` in `config/known_publishers.json` (seller names are not trusted), and only when every install path is an `.appex` inside a top-level `/Applications` app. |
| Limitation | The bundle ID is host-reported (the app's `Info.plist`): an app that claims a listed app's bundle ID inherits that listing's store signals (but not publisher trust, which needs the signing team). The lookup uses the US storefront, so an app sold only elsewhere reads as `not_found`. An extension whose app has no Fleet `apps` row gets no lookup. |

### 1.8 Store dispatch

`fetch_store_metadata` (`src/extension_intel.py:1813`) routes by store name.

| Store | Adapter |
|---|---|
| chrome, brave, vivaldi, chromium | `fetch_chrome_metadata` |
| opera | `fetch_opera_metadata`, then Chrome on `not_found` |
| edge | `fetch_edge_metadata`, then Chrome on `not_found` |
| firefox | `fetch_amo_metadata` |
| safari | `fetch_safari_metadata`, called with the containing app's bundle ID |
| any other value | No adapter. Result `{"status": "unknown", "error": "no anonymous metadata adapter for store '<store>'"}` |

### 1.9 Mozilla blocklist

`fetch_mozilla_blocklist` (`src/extension_intel.py:1859`) and `match_blocklist` (`:1964`).

| Field | Value |
|---|---|
| URL | `https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/addons/records`, then `Next-Page` header or `next` field (`:1869-1871`, `:1907`) |
| Method | GET |
| Request | At most 20 pages (`:1876`). The first page carries `If-None-Match: <etag>` when a cached copy and its ETag exist (`:1882`, `:1854-1856`). |
| Response fields used | `data[].guid`, `data[].versionRange[].minVersion`, `data[].versionRange[].maxVersion`, `Next-Page`, `next`, `ETag` of page 1 (`:1894-1895`) |
| Auth | none |
| Timeout | 12 s |
| Byte cap | 8 MiB per page (`:1881`) |
| Cache TTL | 6 h in `config/extension_cache/mozilla_blocklist-<sha1>.json` (`webviz/extension_worker.py:708`). After 6 h, the worker sends a conditional GET (`:711-712`). HTTP 304 returns `NOT_MODIFIED` (`src/extension_intel.py:1884-1885`). The worker then restarts the TTL of the cached copy with `_cache_touch` (`webviz/extension_worker.py:123-128`, `:141-143`). |
| Failure behaviour | The function returns `{}` unless it reads all pages. A non-200, empty or non-JSON page logs a warning and returns `{}` (`src/extension_intel.py:1886-1893`). More than 20 pages also returns `{}` (`:1908-1910`). The function writes the new ETag only after a full read (`:1911-1912`). The worker uses the stale cached copy on failure (`webviz/extension_worker.py:717`). With no cached copy, the worker raises and skips the whole cycle (`:719`). |
| Limitation | The regex pass scans the whole blocklist per extension (`src/extension_intel.py:1977-1981`). A GUID with no `versionRange`, or an extension with no known version, counts as blocked (`:1949-1953`). This fails closed. |

### 1.10 Open threat feeds

`load_threat_feeds` (`src/extension_intel.py:2021`), `fetch_threat_feed` (`:2075`), `match_threat_feeds` (`:2125`). The feed list is the data file `config/extension_threat_feeds.json`. One feed ships: `malext-sentry`, platform `chromium`, licence CC BY 4.0.

| Field | Value |
|---|---|
| URL | `https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/malicious_extensions_detailed.csv` (from the config file) |
| Method | GET |
| Request | `If-None-Match: <etag>` when a cached copy and its ETag exist (`:2085`). Allowlist is the feed host only. |
| Response fields used | CSV columns `extension_id`, `reason`, `source`, `insert_date_fmt`; the `ETag` header (`:2111-2112`) |
| Auth | none |
| Timeout | 30 s (`:2082`) |
| Byte cap | 32 MiB (`:2084`); 200,000 rows (`:2002`) |
| Cache TTL | 6 h in `config/extension_cache/feed_<name>-<sha1>.json` (`webviz/extension_worker.py:662-663`). After 6 h, the worker sends a conditional GET (`:666-667`). HTTP 304 returns `NOT_MODIFIED` (`src/extension_intel.py:2086-2087`) and restarts the TTL of the cached copy. |
| Failure behaviour | Non-200, parse error or missing ID column returns `None` (`src/extension_intel.py:2088-2096`). The worker uses the stale copy and reports `fetch failed; using stale copy` in feed health (`webviz/extension_worker.py:670-672`). |
| Limitation | Only one feed, chromium only. No Firefox feed exists. A feed over 32 MiB returns `None`. The config comment (`config/extension_threat_feeds.json:10-11`) gives the risk floors 85/70/60. The threat values 100/70/45 are in `src/extension_intel.py:2005-2011` and `:2116-2122`. |

`classify_feed_reason` (`:2116`) uses `_FEED_SEVERITY` (`:2005-2011`). It maps the reason text to a severity by substring. `malicious` (threat 100): malware, spyware, phish, steal, credential, backdoor, trojan, ransom, keylog, exfiltrat, cryptojack, miner, malicious, "rat ". `unwanted` (threat 70): adware, hijack, bundl, suspicious, fraud, scam, affiliate, injection, tracking. Everything else: `listed` (threat 45).

#### Conditional refresh of the feeds and the blocklist

`_conditional_fetch(cache_dir, key, fetch)` (`webviz/extension_worker.py:131-149`) refreshes one expired document. The worker calls it for each threat feed (`:666-667`) and for the Mozilla blocklist (`:711-712`).

Procedure that `_conditional_fetch` performs:

1. Read the cached copy with no TTL limit (`:137`).
2. When a copy exists, read the ETag from the cache key `<key>:meta` (`:138-139`).
3. Call the fetch function with the validators `{"etag": ...}` (`:140`).
4. On `NOT_MODIFIED`, touch the cached copy and return it (`:141-143`).
5. On a non-empty result, write the copy and the new `<key>:meta` file (`:144-148`).
6. Otherwise, return `None` (`:149`). The caller then uses the stale copy.

`NOT_MODIFIED` is a sentinel object in `src/extension_intel.py:1851`. The `:meta` files have no `v<N>_` prefix, so `prune_cache` keeps them.

### 1.11 Scoring

`analyze_extension(record, blocklist_entry, feed_hits, fleet_host_count)` (`src/extension_intel.py:882`) is a pure function. It does no I/O. `SCORER_VERSION = 9` (`:879`). A bump of this constant re-scores every group in the next cycle.

The function first recomputes the built-in flag (`:903-907`). A built-in with no blocklist entry and no feed hit returns risk 0 (`:913-944`). See 1.1.

#### Capability score (`:613-682`)

The function sums `_PERMISSION_WEIGHTS` (`:554-576`) over the required permissions.

| Permission | Weight |
|---|---|
| debugger | 25 |
| nativeMessaging, proxy | 20 |
| userScripts, cookies, webRequest, declarativeNetRequest, management | 15 |
| scripting, clipboardRead | 12 |
| tabCapture | 10 |
| history, identity | 8 |
| downloads, offscreen | 6 |
| activeTab | 2 |
| storage, contextMenus, alarms, notifications, sidePanel | 1 |

Optional permissions count half, capped at the required total (`:627-639`). `<all_urls>` or `*://*/*` adds 20 (`:640-646`). Other host patterns add `min(10, 2 * n)` (`:647-654`). Content scripts on all URLs add 10, other content scripts add 5 (`:655-678`). Declared data collection adds the sum of `_PRIVACY_WEIGHTS` over the listing `privacy_codes`, capped at 8 (`:669-678`). The signal is `declared-data-collection`. With no hosts and no content scripts, the function multiplies the score by 0.6 (`:680-681`). Cap 100.

| Privacy code (`_CWS_PRIVACY_LABELS`, `:1347-1351`) | Weight (`_PRIVACY_WEIGHTS`, `:581`) |
|---|---|
| 4 authentication information | 4 |
| 3 financial and payment information | 3 |
| 5 personal communications | 3 |
| 1 personally identifiable information | 2 |
| 7 web history | 2 |
| 6, 8, 9 (location, user activity, website content) | 0 |

`_PRIVACY_CAP = 8` (`:582`). Only the Chrome Web Store listing RPC supplies `privacy_codes` (`:947-948`).

#### Trust score (`:730-799`)

| Signal | Points |
|---|---|
| store status public / unlisted / unknown / not_found or removed | 25 / 5 / 8 / 0 |
| reputable publisher | 20 |
| developer_verified, or established_publisher | 10 |
| featured | 5 |
| manifest_version 3 | 8 |
| updated within 365 d / 730 d | 10 / 4 |
| users | `min(12, int(4 * log10(users + 1)))` |
| rating >= 4.0 with rating_count >= 100 | 5 |
| crx_hash_verified | 5 |

Each trust signal carries a negative weight equal to the trust points that it adds (`:735-797`). For example, `store-listed` has weight -25 and `store-unlisted` has weight -5 (`:737`, `:741`). The `store-updated` signal has weight -10, -4 or 0. The `not-store-install` signal keeps weight 0 (`:967`). The sum of the trust signal weights is therefore the negative trust score.

Publisher reputation (`:951-961`) keys on `meta.store`. Chrome uses `chrome_publisher_is_reputable(meta.publisher_id)`. Firefox uses `amo_author_is_reputable(meta.author_ids)`. Edge uses `edge_extension_is_reputable(extension_id, status)` and requires status `public`. Every other store uses `publisher_is_reputable(developer, publisher)` by normalised name. The trusted IDs and names come from `config/known_publishers.json`, loaded by `known_publishers()` (`:411`) with a `(path, mtime)` cache (`:420`).

On chrome, firefox and edge, a reputable publisher must also pass `store_install_verified` (`:481`, applied at `:963-970`). Every install path must match a profile root in `_CHROMIUM_ROOTS` or `_FIREFOX_ROOTS` (`:449-478`). One failed host removes the reputable flag and adds the signal `not-store-install`.

#### Threat score (`:802-867`)

The threat score is the maximum of the signals, not the sum.

| Signal | Threat |
|---|---|
| Mozilla blocklist entry | 100 |
| status removed or disabled | 45 |
| status not_found or sideloaded | 20 |
| status unlisted | 10 |
| rating < 2.5 with rating_count >= 50 | 15 |
| manifest_unavailable | 15 |
| manifest_error | 30 |
| max CVSS >= 9 / >= 7 / > 0 | 35 / 25 / 10 |
| threat feed hit | `hit.threat` (100 / 70 / 45), appended as `threat-feed:<feed>` (`:975-983`) |

#### Exposure score (`:870-874`)

`exposure = min(60, round(15 * log10(host_count + 1)))`, plus 10 when the extension has more than 2 versions in the fleet. Cap 100.

#### Name anomaly penalty (`:287-342`)

| Signal | Penalty |
|---|---|
| missing name | 12 |
| path as name | 12 |
| mixed-script name (Cyrillic or Greek) | 20 |
| control characters | 15 |
| oversized name (> 80 chars) | 6 |
| dotted identifier name (>= 4 dots, no space) | 4 |
| typosquat brand (one edit from one of 43 brands at `:220-228`) | 18 |
| brand affix (brand + x/pro/plus/app/ex/official) | 8 |
| brand look-alike, vouched (`brand-lookalike-vouched`) | 0 |

The function caps the penalty at 35 (`:342`).

A brand hit is either `typosquat-brand` or `brand-affix` (`:324-334`). When `vouched` is true, the function adds `brand-lookalike-vouched` with weight 0 instead (`:335-340`). `analyze_extension` sets `vouched` in two cases (`:995-998`):

1. The publisher is reputable. A reputable flag on chrome, firefox or edge already requires `store_install_verified`.
2. The store marks the developer as verified or established, the listing has at least 100,000 users, and `store_install_verified` passes.

A badge on a listing with fewer than 100,000 users does not vouch for the name. Such a publisher keeps the typosquat penalty.

#### Rarity penalty (`:1008-1034`)

| Condition | Penalty |
|---|---|
| users < 100 | 8 |
| users < 1000 | 4 |
| users < 1000 and reputable publisher | 0 (signal only) |
| host_count <= 1 | 4 |
| fleet_host_count >= 10 and host_count / fleet_host_count < 0.03 | 3 |

#### Composite risk score (`:1036-1074`)

```
risk = round(0.35 * capability
           + 0.25 * (100 - trust)
           + 0.25 * threat
           + 0.15 * exposure
           + name_penalty
           + rarity_penalty)
```

Floors (`:1046-1072`): a blocklist entry or a `malicious` feed hit sets `known_bad`. `known_bad` floors risk at 85. With users >= 10,000 the floor is 92. With users >= 100,000 the floor is 96. Any other feed hit floors at 70 (`unwanted`) or 60. Status `removed` floors at 60. Status `not_found` with name penalty >= 18 floors at 55. The function clamps the result to 0-100 (`:1074`).

Bands (`:689`): >= 75 critical, >= 50 high, >= 25 medium, else low.

The result dictionary (`:1078-1114`) carries these keys: `risk_score`, `risk_band`, the four sub-scores, `risk_signals` sorted by absolute weight (`:1076`), `store_status`, `is_builtin` (`:1088`), `publisher_reputable`, `known_bad`, `install_users`, `manifest_version`, permissions, `latest_version`, `store_name`, `store_url`, `publisher`, `category`, `rating`, `rating_count`, `updated_at`, `featured`, `established_publisher`, `developer_verified`, `developer_email`, `developer_website`, `trader`, `privacy_disclosure`, `privacy_policy_url`, `intel_error`.

### 1.12 Write-back

`_write_rows` (`webviz/extension_worker.py:642`) runs two `UNWIND` statements. `_WRITE_BY_KEY` matches `Software {extension_key: row.key}`. `_WRITE_BY_NAME` matches legacy `name:`-keyed groups. The `SET` clause (`:567-608`) writes these properties:

`kind`, `extension_key`, `risk_score`, `risk_band`, `capability_score`, `trust_score`, `threat_score`, `exposure_score`, `risk_signals_json`, `store_status`, `store_url`, `publisher`, `publisher_reputable`, `known_bad`, `install_users`, `latest_version`, `display_name` (only when the current value starts with `__MSG_`), `rating`, `rating_count`, `store_category`, `manifest_version`, `permissions`, `host_permissions`, `content_script_matches`, `store_updated_at`, `store_featured`, `established_publisher`, `developer_verified`, `developer_email`, `developer_website`, `trader`, `privacy_disclosure`, `privacy_policy_url`, `is_builtin`, `intel_error`, `intel_fingerprint`, `intel_refreshed_ts`, `intel_refreshed_at`.

The worker writes `is_builtin` from the scorer result (`webviz/extension_worker.py:603`). Thus the node flag follows the current built-in rules after each score. The worker makes no store call for a built-in record (`:373`, `:460`, `:513`).

The status file `config/extension_status.json` (`:194-206`) holds `enabled`, `running`, `last_tick_iso`, `items_scored_total`, `last_error`, `last_cycle`, `queue_remaining`, `sources`, `threat_feeds[]` and `coverage[]`. The worker rewrites it atomically with `atomic_write_json` (`webviz/worker_util.py:26-50`). A failed write logs a warning and does not stop the loop (`webviz/extension_worker.py:188-192`).

### 1.13 API and UI

| Route | What it does | Where |
|---|---|---|
| `GET /api/extensions` | Runs three Cypher queries: list with `LIMIT` (default 1000, max 5000), band counts, affected host count. Groups rows per `extension_key` in Python. Embeds the worker status. | `webviz/routes/workers.py:250-294` |
| `GET /api/extensions/status` | Returns the status file plus `enabled` and `interval_sec`. | `webviz/routes/workers.py:343-346`, snapshot at `:326-334` |
| `POST /api/extensions/refresh` | Touches the trigger file. Returns 204, or 429 inside the 30 s cooldown. | `webviz/routes/workers.py:348-365` |
| `GET /api/extensions/detail?key=` | Returns merged node properties, parsed `risk_signals_json` and `vulnerabilities_json`, and the host list. | `webviz/routes/workers.py:367-437` |

Every `/api/*` call must send `Authorization: Bearer <WEBVIZ_API_TOKEN>` or `X-Api-Token: <token>`.

The Extensions tab (`webviz/static/app.js:4697-5022`) calls `GET /api/extensions` on load, `GET /api/extensions/detail?key=` on a row click, and `POST /api/extensions/refresh` on the Refresh button. The overview page calls `GET /api/extensions?limit=1` for counters (`webviz/static/app.js:5453`).

Without `include_builtin=true`, the list hides built-in nodes with `risk_score = 0` (`webviz/routes/workers.py:151-154`). A built-in with a blocklist or feed hit has a risk score above 0, so the list shows it. The coverage query in the status file counts the same set (`webviz/extension_worker.py:686-687`).

The table row shows four signals. Signals with a positive weight come first, then trust signals (`webviz/static/app.js:4862-4867`). Each badge shows the signed weight, for example `+20` or `-25`. `_extSignalClass` gives a negative weight the class `good` (`webviz/static/app.js:4682-4690`).

## Part 2: Shadow IT enrichment

### 2.1 Source gate

`src/shadow_it_filter.py` defines which osquery sources count as shadow IT.

| Set | Sources | Where |
|---|---|---|
| `USER_APP_SOURCES` | apps, programs, homebrew_packages, chocolatey_packages | `src/shadow_it_filter.py:210` |
| `EXTENSION_SOURCES` | chrome_extensions, firefox_addons, safari_extensions, ie_extensions, vscode_extensions, atom_packages, jetbrains_plugins | `src/shadow_it_filter.py:193` |
| `SHADOW_IT_SOURCES` | union of the two sets above | `src/shadow_it_filter.py:220` |
| `DEV_LANGUAGE_SOURCES` | npm_packages, python_packages, gem_packages, cargo_packages, pkg_packages, portage_packages, go_binaries (noise) | `src/shadow_it_filter.py:176-182` |
| `LINUX_PACKAGE_SOURCES` | deb_packages, rpm_packages (noise unless `SHADOW_IT_INCLUDE_LINUX_PACKAGES` is true) | `src/shadow_it_filter.py:188` |

`is_system_package(name, db_categories, sources)` (`:366-412`) suppresses a row in five cases. Case 1: all sources are dev-language (`:387`). Case 2: all sources are deb/rpm and the opt-in is off (`:393`). Case 3: the name has no alphanumeric character (`:399`). Case 4: the name matches `SYSTEM_PACKAGE_RE` (`:35-136`) or `NON_USER_FACING_RE` (`:148-164`). Case 5: a category contains a `SYSTEM_CATEGORY_TOKENS` string (`:168-173`).

### 2.2 Outlier threshold

`compute_per_platform_thresholds(session, pct)` (`src/shadow_it_filter.py:340-363`) counts hosts per platform and returns `{platform: max(2, int(total * pct))}`. `pct` comes from `SHADOW_IT_OUTLIER_PCT` (default 0.03) via `get_outlier_pct` (`:287-310`).

### 2.3 ETL enrichment path

`run_categorization(limit, target_names)` (`categorize_software.py:388-639`) runs after ingest (`src/etl.py:665-671`) with `limit = 250`, or `None` with `--complete-enrichment`.

Procedure:

1. Compute the per-platform thresholds (`:425`).
2. For each platform, select `Software` nodes with `category IS NULL`, a shadow IT source, `kind <> 'browser_extension'`, no attempt within the cooldown, and `host_count <= threshold` (`:456-476`).
3. Merge candidates by name and keep the lowest host count (`:477-489`).
4. Drop names that `is_system_package` suppresses (`:500-503`).
5. Keep at most `limit` names.
6. For each name, call `software_catalog.lookup(name)` (`src/software_catalog.py:185`).
7. On a catalog hit, write the category and description with `categorization_source = 'catalog'` (`categorize_software.py:542-558`).
8. On a catalog miss, call `get_software_info(name, http)` (`:225`).
9. On a Wikipedia hit, write the fields with `categorization_source = 'wikipedia'` (`:577-590`).
10. On a miss, write only `last_categorization_attempt_iso` and `categorization_attempts` (`:598-606`).
11. On a transient error, write nothing.
12. Sleep 0.2 s after each network lookup. Sleep 5 s after 5 consecutive transient errors (`:624-629`).

NOTE: The query excludes browser extensions (`kind = 'browser_extension'`) from this path (`:461`). The extension worker in Part 1 owns their enrichment.

### 2.4 Local catalog

`src/software_catalog.py` holds `_CATALOG` (`:25-159`), a dictionary of 104 lowercase names to (categories, description). `lookup(name)` (`:185-193`) normalises the name with `_normalize` (`:174-182`) and does an exact dictionary match. The catalog is a Python literal; a change needs a redeploy.

### 2.5 Wikipedia REST summary

`get_software_info(name, http)` (`categorize_software.py:225-296`).

| Field | Value |
|---|---|
| URL | `https://en.wikipedia.org/api/rest_v1/page/summary/{title}` (`:89`), `title = quote(name.strip(), safe='')` (`:239`) |
| Method | GET |
| Request | Path parameter only. Headers `User-Agent: FleetHoundSoftwareCategorizer/1.0 (https://github.com/fleethound)`, `Accept: application/json` (`:241-244`) |
| Response fields used | `type`, `description`, `extract` |
| Auth | none |
| Timeout | 10 s (`:246`) |
| Byte cap | none |
| Cache TTL | No HTTP cache. The graph field `last_categorization_attempt_iso` blocks a retry for `ENRICH_FAILURE_COOLDOWN_DAYS` (default 7) after a miss (`:129`, `:449-452`). |
| Failure behaviour | Timeout, connection error or any exception: TRANSIENT (`:247-254`). HTTP 404: MISS. HTTP 429: sleep `min(Retry-After, 120)` s, else 30 s, then TRANSIENT (`:259-265`). HTTP >= 500: TRANSIENT. `type == "disambiguation"`: MISS (`:277-281`). Text that does not match `_SOFTWARE_HINT_RE` (`:92-106`): MISS (`:291-292`). |
| Limitation | English Wikipedia only. The page title is the raw software name. The hint regex is the only relevance check. The 429 sleep blocks the thread and ignores `stop_event` (`:261`). |

Categories come from `infer_categories_from_description` (`:206-222`), which matches `_KEYWORD_TO_CATEGORY` words (`:150-194`) and defaults to `['Application']`. The stored description is the first sentence of `extract`, capped at 300 characters (`:308-319`).

NOTE: No LLM and no Wikidata SPARQL call exists in this path. The graph field has the name `wikidata_description`, but the source is the Wikipedia REST summary.

### 2.6 Enricher worker

`webviz/enrich_worker.py` runs the same two lookups on a timer. `start_worker` (`:303-352`) takes a `flock` on `/tmp/fleet-hound-enricher.lock` (`:327`, `webviz/worker_util.py:62-82`) and starts a daemon thread that runs `_loop` (`webviz/enrich_worker.py:244-300`).

Procedure per tick:

1. On the first tick only, call `purge_non_software_descriptions` (`categorize_software.py:322-353`).
2. Call `_pick_uncategorized(driver, batch_size)` (`webviz/enrich_worker.py:66-96`). It selects `Software` nodes with `category IS NULL`, a shadow IT source, `kind <> 'browser_extension'`, and no attempt within the cooldown, ordered by host count, `LIMIT batch_size` (default 25).
3. Call `_fetch_batch` (`:199-241`). It runs `get_software_info` in a thread pool of `ENRICHER_PARALLELISM` threads (default 4) with one `requests.Session` per thread and a 0.2 s sleep per lookup.
4. On the loop thread, call `_mark_miss` (`:99-111`) or `_write_categories` (`:114-135`).
5. Write the status file `/app/config/enricher_status.json` with `atomic_write_json` (`:169-180`, `:284`).
6. Call `sleep_until`. It returns when `ENRICHER_INTERVAL_SEC` (default 300) elapses or the trigger file mtime advances (`:293-297`).

CAUTION: The enricher worker applies neither the per-platform threshold nor `is_system_package` (`:69-82`). It also does not write `categorization_source` or `categorization_attempts` (`:117-124`).

| Route | What it does | Where |
|---|---|---|
| `GET /api/enricher/status` | Returns the status file plus `queue_remaining` = count of all `Software` with `category IS NULL`. | `webviz/routes/workers.py:17-36`, `webviz/enrich_worker.py:138-146` |
| `POST /api/enricher/trigger` | Touches `/tmp/fleet-hound-enricher.trigger` with a 30 s cooldown. | `webviz/routes/workers.py:38-56`, `webviz/enrich_worker.py:367-371`, `webviz/worker_util.py:104-123` |

### 2.7 Runtime detection: `GET /api/shadow-it`

`get_shadow_it` (`webviz/routes/shadow_it.py:57-74`) caches the response per Gunicorn worker for 30 s. The cache key is the request arguments plus the whitelist file mtime. The cache holds at most 64 entries (`:47-48`, `:52-53`). `_get_shadow_it_uncached` (`:77-644`) reads the filters `team`, `platform`, `risk`, `detection_type`, `host_count`, `user_count` and `software_type`. It excludes names in `/app/config/whitelist.json` (`webviz/app.py:570-580`).

| Detector | Rule | Risk | Where |
|---|---|---|---|
| 1. Outlier | `host_count <= OUTLIER_THRESHOLD`, not a system package. `OUTLIER_THRESHOLD` is the maximum of the matching platform thresholds. | high when host_count == 1, else medium. A node with an extension `risk_band` uses the band level instead (see below). | `webviz/routes/shadow_it.py:276-379` |
| 2. High-risk category | A `db_category` or the name matches `HIGH_RISK_PATTERNS` (Remote Access Tools, File Sharing, Communication Apps, Cryptocurrency Mining, Tor/Privacy Tools) by word boundary. | high | `webviz/routes/shadow_it.py:382-516`, patterns at `:165-199` |
| 3. Version sprawl | More than 2 distinct versions on `INSTALLED_ON` edges, `LIMIT 20` in Cypher. | high > 5 versions, medium > 3, else low | `webviz/routes/shadow_it.py:530-614` |

The response (`:617-644`) is `{summary, detections, risk_distribution, filters}` with no pagination.

Detector 1 also reads `risk_band`, `risk_score` and `is_builtin` from each node (`:285-286`). `_EXT_BAND_TO_LEVEL` (`:50`) maps the extension band to a Shadow IT level: `critical` and `high` become `high`, `medium` stays `medium`, `low` stays `low`. The Shadow IT UI has no `critical` level.

Procedure that detector 1 performs for the risk level (`:326-336`):

1. Set the host-count level: `high` for 1 host, else `medium`.
2. When the node has no known band, keep the host-count level.
3. When the node is not built-in, use the band level. The band level can be lower than the host-count level.
4. When the node is built-in, use the higher of the two levels by `_LEVEL_RANK` (`:51`).
5. When the band level is used, `risk_reason` names the extension risk score and band (`:334-336`).

A built-in has risk 0 because of a host-reported ID or path. Thus a built-in band never lowers the level of a rare install. A built-in with a blocklist or feed hit can raise the level.

NOTE: The enrichment taxonomy emits `Remote Access`, `Cloud Storage`, `Communication`, `Crypto` and `Privacy Tool`. Detector 2 looks for `Remote Access Tools`, `File Sharing`, `Communication Apps`, `Cryptocurrency Mining` and `Tor/Privacy Tools`. The category match therefore rarely fires. The name match does the work.

## Configuration

| Knob | Default | Where |
|---|---|---|
| `EXTENSION_WORKER_ENABLED` | true | `webviz/app.py:162` |
| `EXTENSION_WORKER_INTERVAL_SEC` | 21600 | `webviz/app.py:164` |
| `EXTENSION_WORKER_BATCH_SIZE` | 50 | `webviz/app.py:168` |
| `EXTENSION_WORKER_PARALLELISM` | 4 | `webviz/app.py:172` |
| `EXTENSION_WORKER_LOCK_PATH` | /tmp/fleet-hound-extensions.lock | `webviz/app.py:175` |
| `EXTENSION_WORKER_TRIGGER_PATH` | /tmp/fleet-hound-extensions.trigger | `webviz/app.py:178` |
| `EXTENSION_WORKER_STATUS_PATH` | /app/config/extension_status.json | `webviz/app.py:181` |
| `EXTENSION_CACHE_DIR` | /app/config/extension_cache | `webviz/app.py:184` |
| `EXTENSION_MANUAL_TRIGGER_COOLDOWN` | 30.0 s (constant, not env) | `webviz/app.py:187` |
| `EXTENSION_THREAT_FEEDS_FILE` | /app/config/extension_threat_feeds.json, else `<repo>/config/extension_threat_feeds.json` | `src/extension_intel.py:2015` |
| `KNOWN_PUBLISHERS_FILE` | /app/config/known_publishers.json, else `<repo>/config/known_publishers.json` | `src/extension_intel.py:367` |
| `LISTING_TTL_CHROME_SEC` | 604800 (7 d) | `webviz/extension_worker.py:89` |
| `LISTING_TTL_MIN_SEC` | 1814400 (21 d) | `webviz/extension_worker.py:90` |
| `LISTING_TTL_JITTER_SEC` | 604800 (7 d) | `webviz/extension_worker.py:91` |
| `BLOCKLIST_TTL_SEC` | 21600 (6 h, also feeds) | `webviz/extension_worker.py:92` |
| `REFRESH_INTERVAL_SEC` | 21600 | `webviz/extension_worker.py:93` |
| `LISTING_KEY_VERSION` / `MANIFEST_KEY_VERSION` | `v12` / `v11` | `webviz/extension_worker.py:225-226` |
| `TRIGGER_POLL_SEC` (all workers) | 1.0 | `webviz/worker_util.py:23` |
| `SCORER_VERSION` | 9 | `src/extension_intel.py:879` |
| `CHROMIUM_BUILTIN_IDS` | 8 IDs | `src/extension_intel.py:51` |
| `FIREFOX_BUILTIN_SUFFIXES` | `@mozilla.org`, `@mozilla.com` | `src/extension_intel.py:61` |
| `_WIN_ROOT` | `<drive>:\Program Files[ (x86)]\` or `<drive>:\Users\<user>\AppData\Local\` | `src/extension_intel.py:176` |
| `_BUILTIN_PATH_RES` | anchored install roots for chrome, edge, brave, vivaldi, firefox | `src/extension_intel.py:177-185` |
| Safari built-in prefixes | `/Applications/Safari.app/`, `/System/` | `src/extension_intel.py:209` |
| `_BRANDS` | 43 brand strings | `src/extension_intel.py:220` |
| `_PUBLISHER_SUFFIXES` | inc, llc, ltd, ..., team | `src/extension_intel.py:247` |
| name anomaly cap | 35 | `src/extension_intel.py:342` |
| typosquat vouch gate | reputable publisher, or verified/established badge with users >= 100,000 and `store_install_verified` | `src/extension_intel.py:995-998` |
| `_HOME`, `_CHROMIUM_ROOTS`, `_FIREFOX_ROOTS` | profile-root regexes for macOS, Linux, Windows | `src/extension_intel.py:449-469` |
| `_PERMISSION_WEIGHTS` | 21 entries, debugger 25 to sidePanel 1 | `src/extension_intel.py:554` |
| `_PRIVACY_WEIGHTS` / `_PRIVACY_CAP` | codes 4: 4, 3: 3, 5: 3, 1: 2, 7: 2 / cap 8 | `src/extension_intel.py:581-582` |
| `_ALL_URLS` | `<all_urls>`, `*://*/*`, `http://*/*`, `https://*/*` | `src/extension_intel.py:584` |
| optional-permission factor | 0.5 | `src/extension_intel.py:631` |
| no-host capability discount | 0.6 | `src/extension_intel.py:681` |
| `_BANDS` | 75 critical, 50 high, 25 medium, 0 low | `src/extension_intel.py:689` |
| trust status points | public 25, unlisted 5, unknown 8, not_found/removed 0; each trust signal weight is the negative of its points | `src/extension_intel.py:735-746` |
| trust recency windows | 365 d 10, 730 d 4 | `src/extension_intel.py:775` |
| trust popularity | `min(12, int(4 * log10(users + 1)))` | `src/extension_intel.py:782` |
| trust rating gate | rating >= 4.0 and rating_count >= 100 | `src/extension_intel.py:789` |
| threat weights | see 1.11 | `src/extension_intel.py:807` |
| poor-reputation gate | rating < 2.5 and rating_count >= 50 | `src/extension_intel.py:828` |
| exposure formula | `min(60, round(15 * log10(hosts + 1))) + 10 if versions > 2` | `src/extension_intel.py:871` |
| rarity thresholds | users < 1000 (4), users < 100 (8), host_count <= 1 (4), fleet ratio < 0.03 with fleet >= 10 (3) | `src/extension_intel.py:1009` |
| composite weights | 0.35, 0.25, 0.25, 0.15 | `src/extension_intel.py:1037` |
| known_bad floors | 85; 92 at >= 10,000 users; 96 at >= 100,000 users | `src/extension_intel.py:1050` |
| feed / removed / not_found floors | 70, 60, 60, 55 | `src/extension_intel.py:1068` |
| `_USER_AGENT` | `fleet-hound-extension-intel/1.0 (+https://github.com/)` | `src/extension_intel.py:1121` |
| `_MAX_HTTP_BYTES` | 8 MiB | `src/extension_intel.py:1122` |
| `_CHROME_HOSTS`, `_EDGE_HOSTS`, `_AMO_HOSTS`, `_MOZILLA_HOSTS` | 6 / 1 / 1 / 1 hosts | `src/extension_intel.py:1123-1133` |
| `HttpClient` timeout | 12.0 s (feeds 30.0 s) | `src/extension_intel.py:1151` |
| `_MAX_MANIFEST_BYTES` | 1 MiB | `src/extension_intel.py:1276` |
| `_parse_crx` max ZIP entries | 5000 | `src/extension_intel.py:1305` |
| `_CWS_RPC_ID`, `_CWS_RPC_URL` | `xY2Ddd`, see 1.4 | `src/extension_intel.py:1331-1332` |
| `_CWS_RPC_BATCH` | 40 | `src/extension_intel.py:1335` |
| `_CWS_CATEGORY_LABELS` | 7 slugs | `src/extension_intel.py:1338` |
| `_CWS_PRIVACY_LABELS` | codes 1, 3, 4, 5, 6, 7, 8, 9 | `src/extension_intel.py:1347` |
| update2 prodversion / byte cap | 999.0 / 1,000,000 B | `src/extension_intel.py:1552-1554` |
| CRX download cap | 50 MiB | `src/extension_intel.py:1597` |
| Edge detail byte cap | 2,000,000 B | `src/extension_intel.py:1633` |
| AMO detail byte cap | 2,000,000 B | `src/extension_intel.py:1687` |
| XPI download cap | 50 MiB | `src/extension_intel.py:1786` |
| blocklist page cap / page count | 8 MiB / 20 | `src/extension_intel.py:1876-1881` |
| `_guid_regex` lru_cache | 4096 | `src/extension_intel.py:1916` |
| `_FEED_MAX_ROWS` | 200,000 | `src/extension_intel.py:2002` |
| `_FEED_SEVERITY` tiers | malicious 100, unwanted 70, listed 45 | `src/extension_intel.py:2005` |
| threat feed byte cap | 32 MiB | `src/extension_intel.py:2084` |
| configured feeds | 1 (malext-sentry) | `config/extension_threat_feeds.json:15` |
| `known_publishers.json` | schema_version 1; 51 entries; 16 with chrome IDs, 5 with AMO IDs, 1 with Edge IDs | `config/known_publishers.json:17` |
| `summarize_vulnerabilities` caps | 50 entries, 20,000 chars | `src/extension_intel.py:2147` |
| `OODA_ENABLED` | false | `webviz/app.py:190` |
| `OODA_INTERVAL_SEC` | 1800 | `webviz/app.py:192` |
| `INGEST_SW_PARALLELISM` | 4 | `src/ingestion.py:819` |
| `_SOFTWARE_NODE_CHUNK` | 5000 | `src/ingestion.py:821` |
| `SOFTWARE_REL_CHUNK_ROWS` | 5000 | `src/ingestion.py:1163` |
| software flush threshold | 200 hosts | `src/ingestion.py:589` |
| Fleet `/hosts` per_page | 500 | `src/extractor.py:207` |
| Fleet `/hosts` timeout | 120 s | `src/extractor.py:235` |
| Fleet `_get` retries | 5 | `src/extractor.py:96` |
| `ETLConfig.enrich_limit` | 250 | `src/etl.py:111` |
| `ETLConfig.software_reap_age_seconds` | 604800 (7 d) | `src/etl.py:132` |
| `/api/extensions` limit | 1000, max 5000 | `webviz/routes/workers.py:261` |
| `SHADOW_IT_OUTLIER_PCT` | 0.03 | `src/shadow_it_filter.py:287` |
| `MIN_OUTLIER_HOSTS` | 2 (constant) | `src/shadow_it_filter.py:284` |
| `SHADOW_IT_INCLUDE_LINUX_PACKAGES` | false | `src/shadow_it_filter.py:316` |
| `ENRICH_FAILURE_COOLDOWN_DAYS` | 7 | `categorize_software.py:129` |
| `ADAPTIVE_BACKOFF_TRIGGER` / `ADAPTIVE_BACKOFF_SECONDS` | 5 / 5.0 s | `categorize_software.py:134-135` |
| Wikipedia timeout | 10 s | `categorize_software.py:246` |
| `WIKIPEDIA_REST_URL` | `https://en.wikipedia.org/api/rest_v1/page/summary/{title}` | `categorize_software.py:89` |
| `--limit` (CLI) / `enrich_limit` (ETL) | 500 / 250 / None with `--complete-enrichment` | `main.py:198` |
| `ENRICHER_ENABLED` | true in webviz; `main.py` reads default false | `webviz/app.py:135`, `main.py:202` |
| `ENRICHER_INTERVAL_SEC` | 300 | `webviz/app.py:137` |
| `ENRICHER_BATCH_SIZE` | 25 | `webviz/app.py:141` |
| `ENRICHER_PARALLELISM` | 4 | `webviz/app.py:145` |
| `ENRICHER_LOCK_PATH` | /tmp/fleet-hound-enricher.lock | `webviz/app.py:148` |
| `ENRICHER_TRIGGER_PATH` | /tmp/fleet-hound-enricher.trigger | `webviz/app.py:149` |
| `ENRICHER_STATUS_PATH` | /app/config/enricher_status.json | `webviz/app.py:153` |
| `ENRICHER_MANUAL_TRIGGER_COOLDOWN` | 30.0 s (constant) | `webviz/app.py:156` |
| `SHADOW_CACHE_TTL_SEC` / `_SHADOW_CACHE_MAX` | 30 s / 64 | `webviz/routes/shadow_it.py:47-48` |
| `_EXT_BAND_TO_LEVEL` | critical and high to high, medium to medium, low to low | `webviz/routes/shadow_it.py:50` |
| `_LEVEL_RANK` | low 0, medium 1, high 2 | `webviz/routes/shadow_it.py:51` |
| `WHITELIST_FILE` | /app/config/whitelist.json | `webviz/app.py:130` |
| `MEMGRAPH_URI` | bolt://localhost:7687 | `categorize_software.py:83` |

## Limitations

| # | Limitation | Where | Effect |
|---|---|---|---|
| L1 | The name-digest fallback key uses `sha1(name)` only. | `src/extension_intel.py:152-153` | Two different unpacked extensions with the same name on the same store become one node. No store lookup runs for them. |
| L2 | `_infer_store` has no branch for Arc, Comet or Dia, although `_CHROMIUM_ROOTS` lists them. | `src/extension_intel.py:84-98`, `:454` | Their extensions get `store = chrome`. |
| L3 | Store path matching is a bare substring on `opera`, `brave`, `vivaldi`. | `src/extension_intel.py:93-96` | A username that contains `opera` flips the store. |
| L4 | The Chrome ID regex is a search, not a full match. | `src/extension_intel.py:109` | A 32-letter token anywhere in a path or display name becomes the identity. |
| L5 | The Safari ID heuristic accepts any dotted token. | `src/extension_intel.py:114` | A version string such as `1.2.3` can become the ID. |
| L7 | Typosquat detection penalises any unvouched 5+ character name within one edit of a brand. | `src/extension_intel.py:261-264`, `:324-340`, `:995-998` | `Money` (brand `honey`) and `Rocket` (brand `pocket`) get penalty 18, unless the store vouches for the publisher. |
| L8 | 33 of 51 known publishers carry no store ID. Name trust applies only on Safari. | `config/known_publishers.json`, `src/extension_intel.py:517-521` | Those vendors add no trust on Chrome, Firefox or Edge. Edge trust is one extension ID in total. |
| L9 | `store_install_verified` fails closed per fleet. | `src/extension_intel.py:508-509` | One host with a missing path removes publisher trust for the whole extension. Opera GX installs never verify (`:463`). |
| L10 | The reputation branch keys on `meta.store`, not the record store. | `src/extension_intel.py:954-960` | With empty store metadata, every store falls to `publisher_is_reputable(None, None)`, which is `False`. A store outage removes 20 trust points. |
| L11 | Permissions outside the 21-entry weight table score 0. | `src/extension_intel.py:554-576`, `:619-620` | `webNavigation`, `bookmarks`, `browsingData`, `desktopCapture`, `geolocation`, `privacy`, `sessions`, `topSites` add no capability. |
| L12 | Status `unknown` scores trust 8, status `unlisted` scores 5. | `src/extension_intel.py:739-746` | A failed store fetch yields more trust than a confirmed unlisted extension. |
| L14 | Threat is `max`, not a sum. | `src/extension_intel.py:807-865` | `removed` (45) plus `critical-cve` (35) plus `manifest-unparseable` (30) equals 45. |
| L15 | The scorer accepts feed hit values with only a 100 cap. | `src/extension_intel.py:976`, `:984`, `:1068` | Any feed row with a severity other than `malicious` or `unwanted` still floors risk at 60. |
| L16 | Exposure saturates at 60 near 10,000 hosts. | `src/extension_intel.py:871` | Exposure contributes at most 10.5 risk points and cannot move a band alone. |
| L17 | The scorer treats a missing host count as `single-host`. | `src/extension_intel.py:987`, `:1025` | A record with no host count gets penalty 4. |
| L18 | An unenriched extension lands in `medium`. | `src/extension_intel.py:743-746`, `:1025-1028`, `:1036-1043` | No metadata, no permissions, one host: risk 28. |
| L19 | Status `disabled` has no floor. | `src/extension_intel.py:811`, `:1069` | Only `removed` floors at 60. |
| L20 | The HTTP client has no retry, no backoff and no `Retry-After` honouring. | `src/extension_intel.py:1173-1189`, `:1211-1221` | One transient failure costs the extension a full cycle. The worker keeps the failed refresh in the cache until the TTL expires or the fingerprint changes. |
| L21 | The redirect guard checks the hostname only. | `src/extension_intel.py:1142-1143` | An https to http redirect to an allowlisted host passes. |
| L22 | The Chrome listing RPC is undocumented. | `src/extension_intel.py:1326-1330`, `:1516` | Google can change the payload shape without notice. A changed shape raises "listing RPC schema drift" per ID. |
| L23 | One failed listing chunk errors all 40 IDs in it. | `src/extension_intel.py:1508-1509` | A single bad POST blocks 40 extensions for the cycle. |
| L24 | `_parse_crx` skips the CRX3 signature. Edge downloads no package. | `src/extension_intel.py:1289-1290`, `:1627-1677` | Package authenticity rests on the SHA-256 from the same store endpoint. |
| L25 | Edge interpolates the ID into the URL without the `[a-p]{32}` check. | `src/extension_intel.py:1632` | An invalid ID reaches the Edge API. |
| L26 | Edge falls back to Chrome only on `not_found`. | `src/extension_intel.py:1830` | An Edge error or rate limit does not fall back. |
| L27 | AMO 401 returns status only. | `src/extension_intel.py:1690-1693` | Unlisted Firefox add-ons have no permissions, publisher or package. |
| L28 | Brave and Vivaldi route to the Chrome Web Store only. Safari is looked up by the containing app's host-reported bundle ID. | `fetch_store_metadata`, `fetch_safari_metadata` | A spoofed bundle ID inherits another app's App Store store signals. Publisher trust needs the signing team ID (`apple_team_ids`), which only 2 publishers carry. |
| L30 | A missing blocklist with no cached copy aborts the whole cycle. | `webviz/extension_worker.py:719` | Chrome and Edge scoring also stop, although the blocklist covers Firefox GUIDs. |
| L31 | Only one threat feed exists, chromium only. | `config/extension_threat_feeds.json:14-27` | Firefox has no feed coverage. |
| L33 | The code cuts JSON scalars at 20,000 characters after `json.dumps`. | `src/extension_intel.py:2166`, `:2171` | A long payload can become invalid JSON in the graph. `vulnerability_count` counts all entries while the JSON holds at most 50. |
| L34 | The leader lock and trigger live on a per-container `/tmp` path. | `webviz/extension_worker.py:82-83`, `webviz/app.py:175-179` | Two containers on one Memgraph both run cycles. |
| L35 | The worker starts only on the first `/api/health` or `/api/extensions*` request. | `webviz/app.py:645`, `:815-818`, `webviz/routes/workers.py:257` | A container with no HTTP traffic never scores anything. |
| L36 | `last_tick_iso` is never set. `sources.store_metadata` is hard-coded `True`. | `webviz/extension_worker.py:169`, `:198`, `:814` | The status file shows `null` and `true` regardless of outcome. |
| L37 | A manual trigger during a running cycle is not seen until the cycle ends. The trigger has no payload. | `webviz/extension_worker.py:841-843`, `webviz/worker_util.py:92-101` | A refresh cannot target one extension or force a full refetch. |
| L38 | The rare-in-fleet verdict, `SCORER_VERSION` and the publishers file digest are global fingerprint inputs. | `webviz/extension_worker.py:347`, `tests/test_extension_worker.py:108-134` | Crossing the 0.03 ratio or editing `known_publishers.json` re-scores every group in one cycle. |
| L39 | `_all_groups` returns `properties(n)` for every member node. `_coverage` runs a second full scan every cycle. | `webviz/extension_worker.py:286`, `:681` | Two full `:Software` scans per cycle, even when nothing is due. |
| L40 | The worker opens and parses the listing cache file 2 times per group on an idle cycle and 4 times per due group. | `webviz/extension_worker.py:362`, `:376`, `:469`, `:558` | The file opens scale with the group count, even when nothing is due. |
| L41 | The chunk pipeline is serial on the loop thread. Edge and AMO are one blocking call per extension. | `webviz/extension_worker.py:744-785`, `src/extension_intel.py:1627-1812` | The pool idles during prefetch and writes. A slow feed blocks the cycle before scoring. |
| L43 | A failed chunk write discards the scored results. | `webviz/extension_worker.py:782-784` | Every row in the chunk counts as an error. |
| L44 | `GET /api/extensions` applies `LIMIT` to nodes before Python grouping. | `webviz/routes/workers.py:267-277`, `:309` | `summary.total` can disagree with `len(extensions)`. |
| L45 | `GET /api/extensions/detail` keys hosts by hostname. | `webviz/routes/workers.py:415` | Two Fleet hosts with one hostname collapse into one row. |
| L46 | Ingestion writes `extension_key` into `Software.name`. | `src/ingestion.py:550-556` | Consumers that join on `name` see `ext:chrome:<id>`. |
| L47 | Ingestion keeps vulnerabilities, signature, CPE and vendor only for the four browser sources. | `src/ingestion.py:548-572` | Native app rows lose their Fleet vulnerabilities at ingest. |
| L48 | `ON MATCH` guards write only non-null values. | `src/ingestion.py:1073-1087`, `:1148-1151` | A property never returns to null from ingest. |
| L49 | The per-host short-circuit keys on `software_updated_at` only. | `src/ingestion.py:487-491` | New Fleet vulnerabilities for an unchanged inventory are not re-fetched. |
| L50 | `is_builtin` is node-level. The scorer recomputes it from the stored `installed_paths` (first 10). One matching path is enough. | `src/extension_intel.py:197-210`, `webviz/extension_worker.py:337-338` | One anchored vendor path marks the extension built-in for all hosts. With `include_builtin` off, the list hides it while its risk score is 0. |
| L51 | Only the OODA Orient phase wakes the extension worker after an ingest. A manual ETL run does not touch the trigger. | `webviz/ooda_worker.py:463-487`, `webviz/app.py:784` | With OODA off, new extensions can wait up to 6 h for a score. |
| L52 | Fleet `_get` never re-authenticates on 401. No response byte cap. | `src/extractor.py:96-154`, `:112-118` | A token that expires mid-cycle fails the cycle. A large page can time out behind Cloudflare. |
| L53 | Linux deb/rpm are invisible to shadow IT without the opt-in. | `src/shadow_it_filter.py:316-337`, `:393` | A deliberate `apt install teamviewer` is not detected by default. |
| L54 | `SYSTEM_PACKAGE_RE` contains empty alternations inside the `microsoft\.(...)` groups. | `src/shadow_it_filter.py:86-89`, `:105-108` | The regex suppresses any name that starts with `microsoft.`. `make.*` (`:53`) suppresses `MakeMKV`. |
| L55 | The outlier floor is 2 hosts. `int()` truncates. | `src/shadow_it_filter.py:284`, `:340-363` | On platforms with fewer than 100 hosts, `pct` has no effect. 99 hosts * 0.03 = 2. |
| L56 | Both shadow IT enrichment paths exclude browser extensions. | `categorize_software.py:461`, `webviz/enrich_worker.py:74` | Their category comes only from the extension worker. |
| L57 | The ETL limit cut happens after `ORDER BY host_count ASC`. | `categorize_software.py:456-506` | With more than 250 candidates, the most common rare software is never enriched by ETL. |
| L58 | The catalog is an exact match after suffix stripping, as a Python literal. | `src/software_catalog.py:174-193` | `Slack.app` misses the catalog. A new entry needs a redeploy. |
| L59 | Wikipedia lookup has no byte cap and sleeps up to 120 s on 429. | `categorize_software.py:246`, `:259-265` | The client reads a large extract whole. A 429 blocks the thread and ignores `stop_event`. |
| L60 | ETL write-back matches `Software {name}` with no platform scope. | `categorize_software.py:545`, `:580` | Two nodes with one name on two platforms get one verdict. |
| L61 | The enricher worker applies no threshold and no system-package filter, and writes no provenance. | `webviz/enrich_worker.py:69-82`, `:117-124` | It spends Wikipedia calls on common software. Its nodes carry no `categorization_source`. |
| L62 | `queue_remaining` counts every `Software` with `category IS NULL`. | `webviz/enrich_worker.py:142` | The count includes dev-language packages and nodes in cooldown. |
| L63 | `ENRICHER_ENABLED` defaults differ between processes. | `webviz/app.py:135`, `main.py:202` | A bare ETL run does inline enrichment while the daemon also runs. |
| L64 | `OUTLIER_THRESHOLD` with `platform=all` is the maximum over platforms. | `webviz/routes/shadow_it.py:220-241` | A row on 3 Linux hosts is an outlier when the Windows threshold is 30. |
| L65 | Detectors 1 and 3 collect hostnames in Cypher for every in-scope node, then filter in Python. Detector 2 classifies from a light aggregate and collects hosts only for matches (`:396-399`, `:446-456`). | `webviz/routes/shadow_it.py:277-316`, `:531-564` | Detectors 1 and 3 materialise hostname lists for packages that the Python filter then discards. |
| L66 | The enrichment taxonomy and `HIGH_RISK_PATTERNS` use different category names. | `categorize_software.py:150-194`, `webviz/routes/shadow_it.py:165-199` | The category match in detector 2 rarely fires. |
| L67 | Version sprawl applies `LIMIT 20` before the system-package filter. | `webviz/routes/shadow_it.py:548`, `:559` | The detector can return zero user-app rows while sprawled user apps exist below rank 20. |
| L68 | `/api/shadow-it` has no pagination. Detection IDs are per-request counters. | `webviz/routes/shadow_it.py:361`, `:500`, `:598`, `:617-644` | The response carries every hostname and username on each request. IDs are not stable. |
| L69 | The shadow IT cache is per Gunicorn worker. | `webviz/routes/shadow_it.py:47-53` | Four workers hold four caches. A request can see data up to 30 s stale. |
| L70 | The enricher lock lives on a per-container `/tmp` path. | `webviz/app.py:148` | Two replicas both run the loop. |
| L71 | Chrome, Edge, Brave and Vivaldi have only Windows install-root patterns. | `src/extension_intel.py:176-181` | On macOS and Linux, these extensions are built-in only through `CHROMIUM_BUILTIN_IDS`. A component extension outside the 8 IDs gets a normal score. |
| L72 | Opera and Chromium have no entry in `_BUILTIN_PATH_RES`. | `src/extension_intel.py:177-185` | An Opera or Chromium extension is never built-in by path. Only the ID list applies. |
| L73 | A store badge vouches for a brand look-alike name only at 100,000 users or more. | `src/extension_intel.py:995-998` | A small verified publisher with a name such as `Motion` keeps the typosquat penalty 18. |
| L74 | Only the Chrome Web Store listing supplies `privacy_codes`. | `src/extension_intel.py:1443-1449`, `:947-948` | Edge and Firefox extensions never get the `declared-data-collection` signal. |
| L75 | The blocklist conditional GET validates page 1 only. | `src/extension_intel.py:1882-1885` | A 304 on page 1 reuses the whole cached list. |
| L76 | `prune_cache` runs only when a worker wins the leader lock. | `webviz/extension_worker.py:868-871` | Retired key files stay on disk until the next container restart. |
| L77 | Detector 1 uses the extension band for a non-built-in node, also when the band is lower. | `webviz/routes/shadow_it.py:329-336` | A 1-host extension with band `low` shows as `low`, not `high`. |
| L78 | A code comment still calls the built-in path rules substring matches. | `src/extension_intel.py:911-912` | The comment contradicts the anchored regexes in `_BUILTIN_PATH_RES`. A reader of the code can be misled. |

## How to run a self-check

Run these commands from the repository root on the host. The `webviz` container must be running.

1. Run the pure scoring self-check inside the container:

   ```
   docker compose exec -T webviz python src/extension_intel.py
   ```

   The command exits with code 0 when every assertion passes.

2. Print the extension worker status file:

   ```
   docker compose exec -T webviz python webviz/extension_worker.py
   ```

   Check `running`, `last_error`, `last_cycle.due`, `last_cycle.scored`, `threat_feeds[].error` and `coverage[]`.

3. Read the extension worker status over HTTP. Replace `<token>` with `WEBVIZ_API_TOKEN` from `.env`:

   ```
   curl -s -H "Authorization: Bearer <token>" http://127.0.0.1:8080/api/extensions/status
   ```

4. Start one extension worker cycle now:

   ```
   curl -s -X POST -H "Authorization: Bearer <token>" http://127.0.0.1:8080/api/extensions/refresh
   ```

   The response is HTTP 204. HTTP 429 means that the 30 s cooldown is active.

5. Read the enricher worker status:

   ```
   curl -s -H "Authorization: Bearer <token>" http://127.0.0.1:8080/api/enricher/status
   ```

6. Read the shadow IT detections:

   ```
   curl -s -H "Authorization: Bearer <token>" "http://127.0.0.1:8080/api/shadow-it?platform=all"
   ```

7. Run the unit tests for the worker on the host:

   ```
   python3 -m pytest tests/test_extension_worker.py
   ```

CAUTION: `docker compose exec -T webviz python categorize_software.py --limit 0` enriches every candidate. It makes one Wikipedia request per candidate at 0.2 s pacing. Run it only when you accept the runtime.

CAUTION: Step 1 and step 2 call the worker status without a Fleet connection. Steps 3 to 6 need the running dashboard and the API token.

## Glossary

| Term | Meaning |
|---|---|
| AMO | addons.mozilla.org, the Firefox add-on store and its public API v5. |
| batchexecute | The internal Google RPC transport that the Chrome Web Store front end uses. Fleet Hound calls the RPC `xY2Ddd` on it. |
| blocklist | A list of extension GUIDs that Mozilla blocks in Firefox. Fleet Hound reads it from Mozilla Remote Settings (Kinto). |
| CRX | The Chrome extension package format. CRX2 and CRX3 are versions of the header. The body is a ZIP archive. |
| conditional GET | An HTTP GET with `If-None-Match: <etag>`. The server answers 304 when the document is unchanged. |
| CVSS | Common Vulnerability Scoring System. A 0 to 10 severity score for a CVE. Fleet reports it per software row. |
| EPSS | Exploit Prediction Scoring System. The probability that attackers exploit a CVE in the wild. Fleet reports it per vulnerability. |
| ETag | An HTTP response header that identifies one version of a document. The worker stores it in a `<key>:meta` cache file. |
| fingerprint | A hash of every scoring input for one extension group. A changed fingerprint makes the group due for a new score. |
| flock | A Linux file lock. The worker uses it to elect one leader among several Gunicorn workers. |
| GUID | The Firefox add-on identifier, in the form `{uuid}` or `name@domain`. |
| Gunicorn | The Python HTTP server that runs the `webviz` application in several worker processes. |
| Kinto | The Mozilla Remote Settings service that serves the blocklist as paged JSON. |
| leader election | The procedure by which one process wins the lock and runs the worker loop. The other processes do nothing. |
| listing | The store catalog page data for one extension: name, users, rating, publisher, manifest. |
| manifest | The `manifest.json` file inside an extension package. It declares permissions, host permissions and content scripts. |
| Memgraph | The graph database that stores `:Host` and `:Software` nodes and `INSTALLED_ON` edges. Queries use Cypher. |
| MV2, MV3 | Manifest version 2 and 3 of the Chrome extension platform. MV3 adds 8 trust points. |
| OODA | The supervisor thread in `webviz` that runs the ETL on a timer. |
| osquery source | The osquery table that reported a software row, for example `chrome_extensions` or `apps`. |
| outlier | Software on fewer hosts than the per-platform threshold. |
| publisher ID | The Chrome Web Store developer identifier, in the form `u` plus 32 hex characters. |
| Retry-After | An HTTP header that tells a client how long to wait after a 429 or 503 response. |
| risk band | The label for a risk score range: low, medium, high, critical. |
| sideloaded | An extension installed outside the store, for example an unpacked directory. |
| status file | The JSON file that a worker rewrites after each cycle: `config/extension_status.json` or `config/enricher_status.json`. |
| trigger file | A file whose mtime a worker polls. A touch starts the next cycle early. |
| TTL | Time to live. The age after which a cache entry is due for a refresh. |
| typosquat | A name within one edit of a known brand name, used to deceive users. |
| vouched | The store vouches for the publisher of a verified store install. A vouched brand look-alike name gets no typosquat penalty. |
| update2 | The Chrome extension update service at `clients2.google.com`. It returns the current version and the CRX download URL. |
| XPI | The Firefox extension package format. It is a signed ZIP archive. |

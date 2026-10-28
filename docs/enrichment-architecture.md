# Enrichment architecture: browser extensions and shadow IT

## What this document is

This document describes how Fleet Hound enriches browser extensions and shadow IT software. It names each step, each external API, each configuration knob and each known limitation, with the file and line that implements it. It follows ASD-STE100 Simplified Technical English so that a newcomer can read it without prior knowledge of the repository.

NOTE: Line numbers refer to the Go code (`cmd/fleethound`, `internal/`) on 2026-10-28 at commit `7952c6c`. When you edit a file, the line numbers in this document can move.

NOTE: This document does not contain optimization proposals. It describes the system as it is.

## Terms used in this document

| Term | Meaning in this document |
|---|---|
| extension | One browser extension as reported by Fleet (osquery source `chrome_extensions`, `firefox_addons`, `safari_extensions` or `ie_extensions`). |
| store | The vendor catalog that lists an extension: Chrome Web Store, Edge Add-ons, Firefox AMO. `safari`, `brave`, `opera`, `vivaldi` and `chromium` are also store names in the code. |
| worker | A goroutine inside the `fleethound serve` process in the `webviz` container that runs on a timer. There are two workers: the extension worker and the enricher worker. |
| cache | A JSON file on disk under `config/extension_cache` that holds a store response, or an in-process map. |
| risk score | An integer from 0 to 100 that `AnalyzeExtension` computes for one extension. |
| signal | One named reason, with a weight, that contributes to a risk score. The code stores signals in `risk_signals_json`. |
| shadow IT | Software that a user installed without approval. Fleet Hound detects it by rarity, category or version sprawl. |

## Overview

### Browser extension flow

```
 Fleet REST API                       (internal/fleet/fleet.go:397)
   GET /api/v1/fleet/hosts?populate_software=true
        |
        v
 Ingestion                            (internal/ingest/ingest.go:953-990, :1160-1219, :1229-1244)
   DeriveExtensionIdentity()          (internal/extintel/identity.go:222)
   MERGE (:Software {name = extension_key})
   MERGE (:Software)-[:INSTALLED_ON]->(:Host)
        |
        v
 Memgraph                             (:Software nodes, INSTALLED_ON edges)
        |
        v
 Extension worker                     (internal/extworker/extworker.go:1325)
   at leader start: pruneCache() drops retired cache key versions
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
   5. AnalyzeExtension()         (internal/extintel/score.go:386)
         risk score 0-100, band low/medium/high/critical
   6. write ~40 properties back to :Software
        |
        v
 API route                            (internal/api/workersapi/routes.go:408)
   GET /api/extensions, /detail, /status; POST /refresh
        |
        v
 UI: Extensions tab                   (webviz/static/app.js:4697)
```

### Shadow IT flow

```
 Memgraph :Software nodes
        |
        +--> ETL RunCategorization()      (internal/enrich/categorize.go:229)
        |      rare per platform, not a system package
        |      1. local catalog           (internal/catalog/software_catalog.go:150)
        |      2. Wikipedia REST summary  (internal/enrich/wikipedia.go:242)
        |      write s.category, s.wikidata_description
        |
        +--> Enricher worker              (internal/enrich/enrich.go:281)
        |      every 300 s, 25 items, same two lookups
        |
        v
 GET /api/shadow-it                       (internal/api/shadowit/routes.go:139)
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

The ingestion step calls `extintel.DeriveExtensionIdentity(software)` for every software row (`internal/extintel/identity.go:222`, called from `internal/ingest/ingest.go:757`). The function returns `nil` unless `software.source` is one of the four browser sources (`:11`, `:226-229`). It then builds one stable key for the extension.

Procedure that the function performs:

1. Clean `name`, `display_name`, `browser`, `extension_for` and `installed_paths` (`:230-246`).
2. Infer the store with `inferStore` (`:79-113`). `firefox_addons` becomes `firefox`. `safari_extensions` becomes `safari`. `ie_extensions` becomes `edge`. `chrome_extensions` becomes `edge`, `brave`, `opera`, `vivaldi` or `chromium` when `browser` or `extension_for` contains that word (`:91-96`). An install path can also select `edge`, `brave`, `opera` or `vivaldi` (`:99-111`). Otherwise it becomes `chrome`.
3. Take the extension ID from `software.extension_id` when present (`:249`). Otherwise call `inferExtensionID` (`:115-138`). Chrome and Edge use the first match of `\b[a-p]{32}\b`. Firefox uses a full match of `{uuid}` or `local@domain`. Safari uses a token with two or more dots, no spaces and no `@`.
4. Build `extension_key = "ext:<store>:<id>"` in lowercase (`:257`).
5. When no ID exists, build `extension_key = "ext:<store>:name:<sha1(name)[:16]>"` (`:261-266`).
6. Set `is_builtin` with `isBuiltin` (`:314-350`).

The output map (`:279-290`) holds `kind`, `store`, `extension_id`, `extension_key`, `browser`, `extension_for`, `display_name`, `installed_paths` (first 10), `installed_path` and `is_builtin`.

NOTE: Ingestion writes `extension_key` into `Software.name` (`internal/ingest/ingest.go:786`). The human title lives in `display_name`. The `UNIQUE(Software.name)` constraint therefore also enforces one node per extension.

Built-in detection (`internal/extintel/identity.go:314`) returns `true` in four cases. Case 1: a Firefox ID ends with `@mozilla.org` or `@mozilla.com` (`:27`, `:317-323`). Case 2: on a Chromium-family store, the ID is one of the 8 component IDs in `chromiumBuiltinIDs` (`:16-25`, `:324-326`). Case 3: an install path matches the anchored install-root regex for the store in `builtinPathRes` (`:298-306`, `:335-342`). Case 4: a Safari install path starts with `/Applications/Safari.app/` or `/System/` (`:345-347`).

The function lowercases each path and changes `/` to `\` before the match (`:337`). `winRoot` (`:296`) anchors a Windows path at `<drive>:\Program Files\`, `<drive>:\Program Files (x86)\` or `<drive>:\Users\<user>\AppData\Local\`. `builtinPathRes` has these entries:

| Store | Built-in install root |
|---|---|
| chrome | `winRoot` + `Google\Chrome\Application\` |
| edge | `winRoot` + `Microsoft\Edge\Application\` |
| brave | `winRoot` + `BraveSoftware\Brave-Browser\Application\` |
| vivaldi | `winRoot` + `Vivaldi\Application\` |
| firefox | `winRoot` + `Mozilla Firefox\`, `/Applications/Firefox.app/Contents/Resources/`, or `/usr/lib[64]/firefox[-esr]/`, each followed by `browser/features/` |

NOTE: Opera and Chromium have no path entry. On macOS and Linux, a Chromium-family extension is built-in only by its ID. An App Store Safari extension in `<App>.app/Contents/PlugIns` is not built-in.

A built-in extension gets risk score 0, trust 100 and `store_status = "builtin"` (`internal/extintel/score.go:347-377`, `:412-414`). This short-circuit applies only when no blocklist entry and no threat feed hit exist (`:412`). With a hit, the extension gets a full score and keeps `is_builtin = true` (`:613`).

`AnalyzeExtension` recomputes `is_builtin` from the store, ID and paths (`:407-409`). It does not read the stored node flag. The extension worker also recomputes the flag in `recordFor` (`internal/extworker/extworker.go:452-453`). Thus a change to the built-in rules takes effect at the next score, without a new ingest.

### 1.2 Worker selection and cadence

The extension worker lives in `internal/extworker/extworker.go`. It starts when the first healthy HTTP request reaches `/api/health` or any `/api/extensions*` route (`internal/server/handlers.go:64-66`, `internal/server/server.go:355-368`, `internal/api/workersapi/routes.go:409`).

Procedure that `Start` performs (`internal/extworker/extworker.go:1325-1344`):

1. Read the previous status file `config/extension_status.json` (`:1326`, `:275-288`).
2. Return when `EXTENSION_WORKER_ENABLED` is false.
3. Take a non-blocking `flock` on `<CONFIG_DIR>/.extensions.lock` (`/app/config/.extensions.lock` in Docker) (`:1331`, `internal/workerutil/workerutil.go:109-126`).
4. Return when another process (for example a second `fleethound` process) holds the lock.
5. Write the PID into the lock file.
6. Run `pruneCache` on the cache directory (`internal/extworker/extworker.go:1337-1339`). See 1.2.1.
7. Start the goroutine that runs `loop` (`:1340`, `internal/workerutil/workerutil.go:219`).

Procedure that `loop` performs (`internal/extworker/extworker.go:1281-1294`):

1. Run `runCycle` through `tick` (`:1286`, `:1296-1317`).
2. Store any error in `last_error` (`:1311-1313`).
3. Call `SleepUntil` for the rest of `IntervalSec` (default 21600 s) (`:1288-1290`, `internal/workerutil/workerutil.go:142-153`).
4. `SleepUntil` reads the trigger file mtime once per second.
5. Start the next cycle when the mtime advances or the interval ends.

Procedure that `runCycle` performs (`internal/extworker/extworker.go:1160`):

1. Count all hosts with `MATCH (h:Host) RETURN count(h)` (`:343-351`).
2. Load the threat feeds (`:1032`) and the Mozilla blocklist (`:1062`).
3. Read every extension group from Memgraph (`:369`).
4. Build a fingerprint per group and select the groups that are due (`:582`).
5. Split the due groups into chunks of `BatchSize` (default 50) (`:1183-1187`).
6. For each chunk, prefetch Chrome listings in one batched RPC (`:820`).
7. Score each item of the chunk in goroutines, at most `Parallelism` at a time (default 4) (`:1181`, `:1191-1204`).
8. Write the rows of the chunk to Memgraph (`:1003`).
9. Update the status file after each chunk (`:1244-1245`).
10. Run the coverage query and store the result in the status file (`:1116`).

A manual refresh is `POST /api/extensions/refresh` (`internal/api/workersapi/routes.go:515-521`). It touches `<CONFIG_DIR>/.extensions.trigger` with a 30 s cooldown (`internal/extworker/extworker.go:1364-1366`, `internal/workerutil/workerutil.go:160-172`). The OODA Orient phase also touches this trigger file after each ingest (see 1.2.2).

The fingerprint (`internal/extworker/extworker.go:483-504`) is a hash of the scoring inputs. The inputs are `ScorerVersion`, the store, the ID, the versions, the installs, the host count and the rare-in-fleet verdict. The inputs also include the threat digest, the digest of `config/known_publishers.json`, and the name, vendor, built-in, installed paths, CVSS, vulnerabilities and Safari app bundle and team ID fields. A store call is due in five cases (`:546-578`). Case 1: the cache has no listing. Case 2: a new blocklist or feed hit exists. Case 3: the TTL has expired. Case 4: a host reports a version newer than the cached listing. Case 5: an Opera listing was cached before the Opera adapter existed.

| Store | Listing cache TTL | Where |
|---|---|---|
| chrome, brave, vivaldi, chromium | 7 d | `internal/extworker/extworker.go:57` |
| edge, firefox, opera, safari | 21 d plus a per-ID jitter of up to 7 d | `internal/extworker/extworker.go:58-59`, `:534-542` |
| manifest (per store, ID and version) | never expires | `internal/extworker/extworker.go:736-738` |
| threat feeds, Mozilla blocklist | 6 h, then a conditional GET (see 1.9) | `internal/extworker/extworker.go:60` |

#### 1.2.1 Cache keys and pruning

`cachePath` (`internal/extworker/extworker.go:111-126`) maps a cache key to the file `<safe key, 60 chars>-<sha1[:20]>.json`. The key characters other than letters, digits, `-`, `_` and `.` become `_`. Thus the key `v14:listing:...` becomes a file name that starts with `v14_listing_`.

| Constant | Value | Cache key | Where |
|---|---|---|---|
| `listingKeyVersion` | `v14` | `v14:listing:<store>:<id>` | `internal/extworker/extworker.go:66`, `:515` |
| `manifestKeyVersion` | `v13` | `v13:manifest:<store>:<id>:<version>` | `internal/extworker/extworker.go:67`, `:516-518` |

A change to the shape of a cached document must bump its key version. Since `v12`, each listing holds the integer `privacy_codes`.

`pruneCache(cacheDir)` (`:222-242`) runs once when a worker wins the leader lock (`:1337`). It deletes each file whose name matches `v<N>_` and does not start with `v14_listing_` or `v13_manifest_`. It does not touch feed copies, the blocklist copy, `:meta` files or unknown files. A failed delete logs a warning and does not stop the worker.

#### 1.2.2 Wake-up after an ingest

The OODA Orient phase touches the enricher trigger file and the extension trigger file (`internal/ooda/ooda.go:580-606`). The server passes the extension trigger path only when `EXTENSION_WORKER_ENABLED` is true (`internal/config/webviz.go:145-150`, `internal/server/server.go:345`). Thus, with OODA on, the extension worker scores new extensions within one OODA interval. A failed touch adds `<label> trigger failed` to the Orient phase error and does not stop the cycle.

#### 1.2.3 Shared worker helpers

`internal/workerutil/workerutil.go` holds the cross-process helpers of the enricher, extension and OODA workers.

| Helper | What it does | Where |
|---|---|---|
| `AtomicWriteJSON` | Writes JSON with `os.CreateTemp`, `fsync`, `chmod 0600` and `os.Rename`. Returns the error. | `internal/workerutil/workerutil.go:34-81` |
| `ReadJSON` | Decodes the file and reports success. Returns false when the file is missing or malformed; the caller applies its default. | `internal/workerutil/workerutil.go:86-102` |
| `TryAcquireLock` | Takes a non-blocking exclusive `flock` and writes the PID. Returns the open file, or `nil`. | `internal/workerutil/workerutil.go:109-126` |
| `TriggerMtime` | Returns the trigger file mtime, or 0. | `internal/workerutil/workerutil.go:130-136` |
| `SleepUntil` | Sleeps until a deadline, context cancellation or a newer trigger mtime. Polls every `TriggerPoll` (1 s). | `internal/workerutil/workerutil.go:142-153` |
| `FireTrigger` | Touches the trigger file unless the last touch is inside the cooldown. Returns `(fired, retryAfterSec)`. | `internal/workerutil/workerutil.go:160-172` |

The extension worker status flush catches the write error and logs a warning (`internal/extworker/extworker.go:306-308`). Thus a read-only config directory does not stop the loop.

### 1.3 HTTP client

All store adapters use `HTTPClient` (`internal/extintel/extintel.go:41`, `internal/extintel/httpclient.go:99-184`). The client checks the host of the URL against an allowlist (`:100-103`). It rejects redirects to hosts outside the allowlist (`:147-156`, `:163-165`). It reads at most `maxBytes + 1` bytes (`:166`). It does not retry. `Get` accepts extra request headers, for example `If-None-Match` for a conditional GET (`:53`, `:135-137`). The client always sets `User-Agent` and `Accept` itself (`:138-139`).

| Property | Value | Where |
|---|---|---|
| User-Agent | `fleet-hound-extension-intel/1.0 (+https://github.com/)` | `internal/extintel/httpclient.go:18` |
| Default timeout | 12.0 s | `internal/extintel/httpclient.go:43-48` |
| Default byte cap | 8 MiB | `internal/extintel/httpclient.go:19` |
| Chrome hosts | clients2.google.com, storage.googleapis.com, clients2.googleusercontent.com, redirector.gvt1.com, edgedl.me.gvt1.com, chromewebstore.google.com | `internal/extintel/stores.go:24-31` |
| Edge hosts | microsoftedge.microsoft.com | `internal/extintel/stores.go:32` |
| AMO hosts | addons.mozilla.org | `internal/extintel/stores.go:33` |
| Mozilla hosts | firefox.settings.services.mozilla.com | `internal/extintel/stores.go:34` |
| Opera hosts | addons.opera.com | `operaHosts` |
| Apple hosts | itunes.apple.com | `appleHosts` |
| Rate-limit mark | HTTP 429, or HTTP 503 with a `Retry-After` header, sets `meta["rate_limited"] = true` | `internal/extintel/stores.go:56-63` |

CAUTION: An HTTP 4xx or 5xx response returns an empty `Err` (`internal/extintel/httpclient.go:176-179`). Every caller must test the status code itself.

### 1.4 Store adapter: Chrome Web Store listing RPC

`FetchChromeListings` (`internal/extintel/stores.go:470`) fetches listing data for up to 40 IDs in one POST. The worker calls it once per chunk (`internal/extworker/extworker.go:830`).

| Field | Value |
|---|---|
| URL | `https://chromewebstore.google.com/_/ChromeWebStoreConsumerFeUi/data/batchexecute?rpcids=xY2Ddd&hl=en&rt=c` (`internal/extintel/stores.go:240-241`) |
| Method | POST, `application/x-www-form-urlencoded` |
| Request | Form field `f.req` = JSON `[[["xY2Ddd", "[\"<id>\"]", null, "<n>"], ...]]`, up to 40 IDs (`:493-497`) |
| Response fields used | Envelope `["wrb.fr", "xY2Ddd", payload, _, _, [code], tag]`. Payload indices: `[0][0]` id, `[0][2]` name, `[0][3]` rating, `[0][4]` rating_count, `[0][7]` developer website, `[0][8]` and `[0][15]` established_publisher, `[0][9]` featured, `[0][11][0]` category slug, `[0][14]` users, `[0][18]` manifest JSON, `[7]` privacy codes (stored as integer `privacy_codes` and as `privacy_disclosure` text, `internal/extintel/stores.go:411-434`), `[10][0]` developer email, `[10][3]` trader, `[10][5]`/`[10][7]` publisher name, `[10][10]` publisher_id, `[13]` version, `[14][0]` updated epoch, `[33]` privacy policy URL |
| Auth | none |
| Timeout | 12 s |
| Byte cap | 8 MiB |
| Cache TTL | 7 d (listing), written by the worker (`internal/extworker/extworker.go:778`) |
| Failure behaviour | gRPC code 5: status `unlisted` plus `listing_missing`. Code 7: status `removed`. Code 8: `rate_limited`. Other code or missing envelope: `error`. A non-200 or unparseable chunk sets the same error on every ID in the chunk (`internal/extintel/stores.go:503-517`, `:523-524`). After a 429 or 503, the function marks later chunks `rate_limited` without a request (`:484-491`). |
| Limitation | The RPC is an undocumented Google endpoint. The index map matches rendered detail pages from a manual check on 2026-10-27 (`internal/extintel/stores.go:234-237`). A changed shape raises "listing RPC schema drift" per ID (`:530`). Category labels cover 7 slugs (`:248-256`). |

### 1.5 Store adapter: Chrome update2 and CRX

`FetchChromeMetadata` (`internal/extintel/stores.go:586`) runs only when the listing RPC reported `listing_missing` (`:597-601`).

| Field | Value |
|---|---|
| URL | `https://clients2.google.com/service/update2/crx?response=updatecheck&prodversion=999.0&acceptformat=crx2,crx3&x=id%3D<id>%26uc` (`:606-610`), then GET `updatecheck@codebase` for the CRX package |
| Method | GET |
| Request | Query string only |
| Response fields used | `updatecheck@status`, `updatecheck@version`, `updatecheck@codebase`, `updatecheck@hash_sha256`; `manifest.json` inside the CRX |
| Auth | none |
| Timeout | 12 s |
| Byte cap | update2 XML 1,000,000 B (`:611`); CRX 50 MiB (`:41`, `:669`); `manifest.json` 1 MiB (`:40`) |
| Cache TTL | 7 d (listing); manifest never expires, keyed by version (`internal/extworker/extworker.go:736-738`) |
| Failure behaviour | No `updatecheck` or status that starts with `error`: status `not_found` (`internal/extintel/stores.go:633-643`). No `codebase` (for example `noupdate`): `manifest_unavailable` (`:659-668`). CRX over 50 MiB: `manifest_unavailable` (`:670-675`). SHA-256 mismatch: `manifest_error`, but the manifest is still parsed and merged (`:684-697`). |
| Limitation | Listed Chrome extensions get the manifest from the RPC string, never from the package. `crx_hash_verified` exists only for unlisted Chrome and AMO items. `parseCRX` skips the CRX3 signature block and does not verify it (`internal/extintel/stores.go:175-177`). |

`parseCRX` (`internal/extintel/stores.go:160-228`) accepts CRX3, CRX2 or a plain ZIP. It rejects archives with more than 5000 entries (`:191`). It reads only `manifest.json`.

### 1.6 Store adapter: Edge Add-ons

`fetchEdgeMetadata` (`internal/extintel/stores.go:705`).

| Field | Value |
|---|---|
| URL | `https://microsoftedge.microsoft.com/addons/getproductdetailsbycrxid/{extension_id}` (`:713`) |
| Method | GET |
| Request | Path parameter only |
| Response fields used | `name`/`extensionName`, `version`/`latestVersion`, `activeInstallCount`/`users`/`userCount`/`installCount`, `rating`/`averageRating`, `ratingCount`/`ratingsCount`/`rating_count`, `developer`/`developerName`/`publisher`/`publisherName`, `developerVerified`/`isDeveloperVerified`/`verified`, `lastUpdateDate`/`lastUpdated`/`updateDate`, `isBadgedAsFeatured`, `category`/`categories`, `privacyUrl`/`privacyPolicyUrl`/`privacyPolicy`, `publisherWebsiteUri`, `manifest`/`manifest_json`/`manifestJson` |
| Auth | none |
| Timeout | 12 s |
| Byte cap | 2,000,000 B (`:714`) |
| Cache TTL | 21 to 28 d |
| Failure behaviour | HTTP 404 or empty object: status `not_found`. Non-200 or non-JSON: `error`. When Edge says `not_found` and the ID matches `[a-p]{32}`, the dispatcher calls the Chrome adapter and tags the result `resolved_from = "edge"` (`:1284-1297`). |
| Limitation | No package download and no hash check. Manifest fields exist only when the API embeds a manifest (`:745`). The ID is validated against `[a-p]{32}` before interpolation; an invalid ID returns `invalid edge extension id` without a request (`:708-710`). The many alternative key names show that the response shape is not pinned (`:746-788`). |

### 1.7 Store adapter: Firefox AMO and XPI

`fetchAMOMetadata` (`internal/extintel/stores.go:805`).

| Field | Value |
|---|---|
| URL | `https://addons.mozilla.org/api/v5/addons/addon/{guid}/` (`:810`), then GET `current_version.file.url` (host must be addons.mozilla.org) |
| Method | GET |
| Request | Path parameter (URL-quoted GUID) |
| Response fields used | `name`, `status`, `is_disabled`, `authors[].id`, `authors[].name`, `authors[].username`, `ratings.average`, `ratings.count`, `average_daily_users`, `weekly_downloads`, `promoted[].category`, `support_email`, `homepage.url`, `category`/`categories`, `created`, `last_updated`, `has_privacy_policy`, `current_version.version`, `current_version.created`, `current_version.manifest_version`, `current_version.content_script_matches`, `current_version.file.{permissions, host_permissions, optional_permissions, url, size, hash}` |
| Auth | none |
| Timeout | 12 s |
| Byte cap | detail 2,000,000 B (`:810`); XPI 50 MiB with a `file.size` pre-check (`:958-966`) |
| Cache TTL | 21 to 28 d; manifest never expires |
| Failure behaviour | HTTP 401: status `unlisted`. HTTP 404: status `not_found`. XPI `sha256:` hash mismatch: `manifest_error` and no parse. Unknown AMO status strings default to `public` (`:866-872`). |
| Limitation | A 401 returns no fields except the status (`:815-818`), so unlisted Firefox add-ons have no permissions or publisher. `users` mixes `average_daily_users` and `weekly_downloads` (`:910`). |

### 1.7a Store adapter: Opera add-ons

`fetchOperaMetadata` (`internal/extintel/stores.go:1106`). addons.opera.com has no public API, so the adapter reads the listing page.

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

`fetchSafariMetadata` (`internal/extintel/stores.go:1183`). Fleet reports Safari extensions with an empty `extension_id`; osquery only finds them inside a top-level `/Applications/<App>.app/Contents/PlugIns/*.appex`. Ingestion maps that path to the containing app and reads the same host's Fleet `apps` row at that app path (`WithSafariApp`, `internal/extintel/identity.go:181`, called from `internal/ingest/ingest.go:759`). When found, the identity becomes `ext:safari:<app bundle ID>/<appex name>@<team ID or unsigned>`, so extensions of different apps, or differently signed copies, never share a node (`@` is reserved: an ID inferred from a host-reported name or path never contains it, and trust needs the key to end in `@<app_team_id>`), and the node gets `app_bundle_id` and `app_team_id` (the app's code-signing team from `signature_information`). Without an `apps` row the old name/path key stays and no lookup runs. The worker asks the App Store about that bundle ID (`lookupID`, `internal/extworker/extworker.go:508`).

| Field | Value |
|---|---|
| URL | `https://itunes.apple.com/lookup?entity=macSoftware&bundleId={app_bundle_id}` |
| Method | GET |
| Request | Query parameter (bundle ID, validated as dotted `[A-Za-z0-9-]` segments, at most 255 chars) |
| Response fields used | `results[].bundleId` (must equal the request), `trackName`, `version`, `sellerName`/`artistName`, `averageUserRating` and `userRatingCount` (only when the count is above 0), `primaryGenreName`, `currentVersionReleaseDate`, `releaseDate`, `trackViewUrl`, `sellerUrl` |
| Auth | none |
| Byte cap | 1,000,000 B |
| Cache TTL | 21 to 28 d (one listing per containing app) |
| Failure behaviour | No matching result: status `off_store` (Developer ID or sideloaded app): no threat points, an informational `not-in-app-store` signal. Non-200: `error`, not cached. No package exists anywhere (Apple publishes none), so the result carries a neutral `manifest-not-published` signal (weight 0) instead of the `manifest-uninspected` penalty. |
| Trust | The containing app's Apple code-signing team ID against `apple_team_ids` in `config/known_publishers.json` (seller names are not trusted), and only when every install path is an `.appex` inside a top-level `/Applications` app. |
| Limitation | The bundle ID is host-reported (the app's `Info.plist`): an app that claims a listed app's bundle ID inherits that listing's store signals (but not publisher trust, which needs the signing team). The lookup uses the US storefront, so an app sold only elsewhere reads as `not_found`. An extension whose app has no Fleet `apps` row gets no lookup. |

### 1.7c Manifest checks (all stores)

One checker (`capability`, `internal/extintel/score.go:100`) scores every manifest the pipeline obtains, MV2 or MV3: permission weights (including `declarativeNetRequestWithHostAccess`), broad host access, content scripts, declared data collection, and a `weak-csp` signal (+15) when `content_security_policy` (MV2 string or MV3 `extension_pages`/`sandbox`) allows `'unsafe-eval'` or remote script sources (`script-src`, else `default-src`; MV3 `extension_pages` only, since sandboxed pages may eval). `'wasm-unsafe-eval'` is not counted. Safari name checks use the extension name without the `App ›` prefix. Not checked: declarativeNetRequest rule files (header rewriting), because the Chrome listing RPC returns only the manifest, not the package; the `declarativeNetRequest*` permissions are weighted instead. MV2 is not penalised (Firefox and Safari still support it); MV3 adds trust.

### 1.8 Store dispatch

`FetchStoreMetadata` (`internal/extintel/stores.go:1255`) routes by store name.

| Store | Adapter |
|---|---|
| chrome, brave, vivaldi, chromium | `FetchChromeMetadata` |
| opera | `fetchOperaMetadata`, then Chrome on `not_found` |
| edge | `fetchEdgeMetadata`, then Chrome on `not_found` |
| firefox | `fetchAMOMetadata` |
| safari | `fetchSafariMetadata`, called with the containing app's bundle ID |
| any other value | No adapter. Result `{"status": "unknown", "error": "no anonymous metadata adapter for store '<store>'"}` |

### 1.9 Mozilla blocklist

`FetchMozillaBlocklist` (`internal/extintel/feeds.go:35`) and `MatchBlocklist` (`:245`).

| Field | Value |
|---|---|
| URL | `https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/addons/records`, then `Next-Page` header or `next` field (`:37`, `:88-92`) |
| Method | GET |
| Request | At most 20 pages (`:42`). The first page carries `If-None-Match: <etag>` when a cached copy and its ETag exist (`:48-50`, `:22-27`). |
| Response fields used | `data[].guid`, `data[].versionRange[].minVersion`, `data[].versionRange[].maxVersion`, `Next-Page`, `next`, `ETag` of page 1 (`:68-70`) |
| Auth | none |
| Timeout | 12 s |
| Byte cap | 8 MiB per page (`:51`) |
| Cache TTL | 6 h in `config/extension_cache/mozilla_blocklist-<sha1>.json` (`internal/extworker/extworker.go:1063-1066`). After 6 h, the worker sends a conditional GET (`:1067-1069`). HTTP 304 returns `FetchNotModified` (`internal/extintel/feeds.go:52-54`). The worker then restarts the TTL of the cached copy with `cacheTouch` (`internal/extworker/extworker.go:152-157`, `:196-198`). |
| Failure behaviour | The function returns an empty map and `FetchFailed` unless it reads all pages. A non-200, empty or non-JSON page logs a warning and fails (`internal/extintel/feeds.go:55-67`). More than 20 pages also fails (`:94-97`). The function writes the new ETag only after a full read (`:98-100`). The worker uses the stale cached copy on failure (`internal/extworker/extworker.go:1075-1080`). With no cached copy, the worker returns an error and skips the whole cycle (`:1076-1078`). |
| Limitation | The regex pass scans the whole blocklist per extension (`internal/extintel/feeds.go:253-261`). A GUID with no `versionRange`, or an extension with no known version, counts as blocked (`:220-222`). This fails closed. |

### 1.10 Open threat feeds

`LoadThreatFeeds` (`internal/extintel/feeds.go:292`), `FetchThreatFeed` (`:381`), `MatchThreatFeeds` (`:480`). The feed list is the data file `config/extension_threat_feeds.json`. One feed ships: `malext-sentry`, platform `chromium`, licence CC BY 4.0.

| Field | Value |
|---|---|
| URL | `https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/malicious_extensions_detailed.csv` (from the config file) |
| Method | GET |
| Request | `If-None-Match: <etag>` when a cached copy and its ETag exist (`:386`). Allowlist is the feed host only. |
| Response fields used | CSV columns `extension_id`, `reason`, `source`, `insert_date_fmt`; the `ETag` header (`:454-458`) |
| Auth | none |
| Timeout | 30 s (`:382`) |
| Byte cap | 32 MiB (`:386`); 200,000 rows (`:275`) |
| Cache TTL | 6 h in `config/extension_cache/feed_<name>-<sha1>.json` (`internal/extworker/extworker.go:1037-1038`). After 6 h, the worker sends a conditional GET (`:1041-1043`). HTTP 304 returns `FetchNotModified` (`internal/extintel/feeds.go:387-389`) and restarts the TTL of the cached copy. |
| Failure behaviour | Non-200, parse error or missing ID column returns `FetchFailed` (`internal/extintel/feeds.go:390-420`). The worker uses the stale copy and reports `fetch failed; using stale copy` in feed health (`internal/extworker/extworker.go:1044-1048`). |
| Limitation | Only one feed, chromium only. No Firefox feed exists. A feed over 32 MiB fails. The config comment (`config/extension_threat_feeds.json:10-11`) gives the risk floors 85/70/60. The threat values 100/70/45 are in `internal/extintel/feeds.go:279-288` and `:464-474`. |

`classifyFeedReason` (`:464`) uses `feedSeverity` (`:279-288`). It maps the reason text to a severity by substring. `malicious` (threat 100): malware, spyware, phish, steal, credential, backdoor, trojan, ransom, keylog, exfiltrat, cryptojack, miner, malicious, "rat ". `unwanted` (threat 70): adware, hijack, bundl, suspicious, fraud, scam, affiliate, injection, tracking. Everything else: `listed` (threat 45).

#### Conditional refresh of the feeds and the blocklist

`conditionalFetch(cacheDir, key, fetch)` (`internal/extworker/extworker.go:185-209`) refreshes one expired document. The worker calls it for each threat feed (`:1041-1043`) and for the Mozilla blocklist (`:1067-1069`).

Procedure that `conditionalFetch` performs:

1. Read the cached copy with no TTL limit (`:186`).
2. When a copy exists, read the ETag from the cache key `<key>:meta` (`:188-194`).
3. Call the fetch function with the validators `{"etag": ...}` (`:195`).
4. On `FetchNotModified`, touch the cached copy and return it (`:196-199`).
5. On a non-empty result, write the copy and the new `<key>:meta` file (`:200-207`).
6. Otherwise, return `nil` (`:208`). The caller then uses the stale copy.

`FetchNotModified` is a `FetchResult` value in `internal/extintel/extintel.go:27-36`. The `:meta` files have no `v<N>_` prefix, so `pruneCache` keeps them.

### 1.11 Scoring

`AnalyzeExtension(record, AnalyzeOptions{BlocklistEntry, FeedHits, FleetHostCount})` (`internal/extintel/score.go:386`) is a pure function. It does no network I/O. `ScorerVersion = 14` (`internal/extintel/extintel.go:18`). A bump of this constant re-scores every group in the next cycle.

The function first recomputes the built-in flag (`internal/extintel/score.go:407-409`). A built-in with no blocklist entry and no feed hit returns risk 0 (`:412-414`). See 1.1.

#### Capability score (`:100-173`)

The function sums `permissionWeights` (`:16-39`) over the required permissions.

| Permission | Weight |
|---|---|
| debugger | 25 |
| nativeMessaging, proxy | 20 |
| userScripts, cookies, webRequest, declarativeNetRequest, declarativeNetRequestWithHostAccess, management | 15 |
| scripting, clipboardRead | 12 |
| tabCapture | 10 |
| history, identity | 8 |
| downloads, offscreen | 6 |
| activeTab | 2 |
| storage, contextMenus, alarms, notifications, sidePanel | 1 |

Optional permissions count half, capped at the required total (`:109-120`). `<all_urls>` or `*://*/*` adds 20 (`:121-124`). Other host patterns add `min(10, 2 * n)` (`:125-129`). Content scripts on all URLs add 10, other content scripts add 5 (`:130-136`). Declared data collection adds the sum of `privacyWeights` over the listing `privacy_codes`, capped at 8 (`:137-162`). The signal is `declared-data-collection`. With no hosts and no content scripts, the function multiplies the score by 0.6 (`:163-166`). A weak content security policy then adds 15 (`:167-171`). Cap 100.

| Privacy code (`cwsPrivacyLabels`, `:48-52`) | Weight (`privacyWeights`, `:44`) |
|---|---|
| 4 authentication information | 4 |
| 3 financial and payment information | 3 |
| 5 personal communications | 3 |
| 1 personally identifiable information | 2 |
| 7 web history | 2 |
| 6, 8, 9 (location, user activity, website content) | 0 |

`privacyCap = 8` (`:46`). Only the Chrome Web Store listing RPC supplies `privacy_codes` (`:417-418`, `internal/extintel/stores.go:411-434`).

#### Trust score (`internal/extintel/score.go:207-264`)

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

Each trust signal carries a negative weight equal to the trust points that it adds (`:211-214`). For example, `store-listed` has weight -25 and `store-unlisted` has weight -5 (`:218`, `:220`). The `store-updated` signal has weight -10, -4 or 0. The `not-store-install` signal keeps weight 0 (`:451-453`). The sum of the trust signal weights is therefore the negative trust score.

Publisher reputation (`:427-445`) keys on `meta.store`. Chrome uses `chromePublisherIsReputable(meta.publisher_id)`. Firefox uses `amoAuthorIsReputable(meta.author_ids)`. Edge uses `edgeExtensionIsReputable(extension_id, status)` and requires status `public`. Safari uses `appleTeamIsReputable(app_team_id)` and requires the key to end in `@<app_team_id>`. Every other store gets no publisher trust; the name match `publisherIsReputable` exists but the scorer does not call it. The trusted IDs come from `config/known_publishers.json`, loaded by `knownPublishers()` (`internal/extintel/publishers.go:375`) with a `(path, mtime)` cache (`:377-387`).

A reputable publisher must also pass `storeInstallVerified` (`:538-571`, applied at `internal/extintel/score.go:446-455`). Every install path must match a profile root in `chromiumRoots` or `firefoxRoots` (`internal/extintel/publishers.go:478-495`), or, on Safari, an `.appex` path inside a top-level `/Applications` app. One failed host removes the reputable flag and adds the signal `not-store-install`.

#### Threat score (`internal/extintel/score.go:266-337`)

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
| threat feed hit | `hit.threat` (100 / 70 / 45), appended as `threat-feed:<feed>` (`:461-473`) |

#### Exposure score (`:339-345`)

`exposure = min(60, round(15 * log10(host_count + 1)))`, plus 10 when the extension has more than 2 versions in the fleet. Cap 100.

#### Name anomaly penalty (`internal/extintel/publishers.go:148-213`)

| Signal | Penalty |
|---|---|
| missing name | 12 |
| path as name | 12 |
| mixed-script name (Cyrillic or Greek) | 20 |
| control characters | 15 |
| oversized name (> 80 chars) | 6 |
| dotted identifier name (>= 4 dots, no space) | 4 |
| typosquat brand (one edit from one of 43 brands at `:23-31`) | 18 |
| brand affix (brand + x/pro/plus/app/ex/official) | 8 |
| brand look-alike, vouched (`brand-lookalike-vouched`) | 0 |

The function caps the penalty at 35 (`:163`, `:212`).

A brand hit is either `typosquat-brand` or `brand-affix` (`:184-204`). When `vouched` is true, the function adds `brand-lookalike-vouched` with weight 0 instead (`:205-211`). `AnalyzeExtension` sets `vouched` in two cases (`internal/extintel/score.go:483-489`):

1. The publisher is reputable. A reputable flag already requires `storeInstallVerified`.
2. The store marks the developer as verified or established, the listing has at least 100,000 users, and `storeInstallVerified` passes.

A badge on a listing with fewer than 100,000 users does not vouch for the name. Such a publisher keeps the typosquat penalty.

#### Rarity penalty (`internal/extintel/score.go:505-534`)

| Condition | Penalty |
|---|---|
| users < 100 | 8 |
| users < 1000 | 4 |
| users < 1000 and reputable publisher | 0 (signal only) |
| host_count <= 1 | 4 |
| fleet_host_count >= 10 and host_count / fleet_host_count < 0.03 | 3 |

#### Composite risk score (`:536-580`)

```
risk = round(0.35 * capability
           + 0.25 * (100 - trust)
           + 0.25 * threat
           + 0.15 * exposure
           + name_penalty
           + rarity_penalty)
```

Floors (`:545-579`): a blocklist entry or a `malicious` feed hit sets `known_bad`. `known_bad` floors risk at 85. With users >= 10,000 the floor is 92. With users >= 100,000 the floor is 96. Any other feed hit floors at 70 (`unwanted`) or 60. Status `removed` floors at 60. Status `not_found` with name penalty >= 18 floors at 55. The function clamps the result to 0-100 (`:580`).

Bands (`riskBand`, `:179-189`): >= 75 critical, >= 50 high, >= 25 medium, else low.

The result map (`:603-638`) carries these keys: `risk_score`, `risk_band`, the four sub-scores, `risk_signals` sorted by absolute weight (`:582-589`), `store_status`, `is_builtin` (`:613`), `publisher_reputable`, `known_bad`, `install_users`, `manifest_version`, permissions, `latest_version`, `store_name`, `store_url`, `publisher`, `category`, `rating`, `rating_count`, `updated_at`, `featured`, `established_publisher`, `developer_verified`, `developer_email`, `developer_website`, `trader`, `privacy_disclosure`, `privacy_policy_url`, `intel_error`.

### 1.12 Write-back

`writeRows` (`internal/extworker/extworker.go:1003`) runs two `UNWIND` statements. `writeByKey` matches `Software {extension_key: row.key}`. `writeByName` matches legacy `name:`-keyed groups (`:932-936`). The `SET` clause (`:888-929`) writes these properties:

`kind`, `extension_key`, `risk_score`, `risk_band`, `capability_score`, `trust_score`, `threat_score`, `exposure_score`, `risk_signals_json`, `store_status`, `store_url`, `publisher`, `publisher_reputable`, `known_bad`, `install_users`, `latest_version`, `display_name` (only when the current value starts with `__MSG_`), `rating`, `rating_count`, `store_category`, `manifest_version`, `permissions`, `host_permissions`, `content_script_matches`, `store_updated_at`, `store_featured`, `established_publisher`, `developer_verified`, `developer_email`, `developer_website`, `trader`, `privacy_disclosure`, `privacy_policy_url`, `is_builtin`, `intel_error`, `intel_fingerprint`, `intel_refreshed_ts`, `intel_refreshed_at`.

The worker writes `is_builtin` from the scorer result (`internal/extworker/extworker.go:924`). Thus the node flag follows the current built-in rules after each score. The worker makes no store call for a built-in record (`:549`, `:709`, `:814`).

The status file `config/extension_status.json` (`:290-309`) holds `enabled`, `running`, `last_tick_iso`, `items_scored_total`, `last_error`, `last_cycle`, `queue_remaining`, `sources`, `threat_feeds[]` and `coverage[]`. The worker rewrites it atomically with `AtomicWriteJSON` (`internal/workerutil/workerutil.go:34-81`). A failed write logs a warning and does not stop the loop (`internal/extworker/extworker.go:306-308`).

### 1.13 API and UI

| Route | What it does | Where |
|---|---|---|
| `GET /api/extensions` | Runs three Cypher queries: list with `LIMIT` (default 1000, max 5000), band counts, affected host count. Groups rows per `extension_key` in Go (`groupRows`). Embeds the worker status. | `internal/api/workersapi/routes.go:408-495` |
| `GET /api/extensions/status` | Returns the status file plus `enabled` and `interval_sec`. | `internal/api/workersapi/routes.go:510-513`, snapshot at `:497-508` |
| `POST /api/extensions/refresh` | Touches the trigger file. Returns 204, or 429 inside the 30 s cooldown. | `internal/api/workersapi/routes.go:515-521` |
| `GET /api/extensions/detail?key=` | Returns merged node properties, parsed `risk_signals_json` and `vulnerabilities_json`, and the host list. | `internal/api/workersapi/routes.go:535-648` |

Every `/api/*` call must send `Authorization: Bearer <WEBVIZ_API_TOKEN>` or `X-Api-Token: <token>`.

The Extensions tab (`webviz/static/app.js:4697-5022`) calls `GET /api/extensions` on load, `GET /api/extensions/detail?key=` on a row click, and `POST /api/extensions/refresh` on the Refresh button. The overview page calls `GET /api/extensions?limit=1` for counters (`webviz/static/app.js:5453`).

Without `include_builtin=true`, the list hides built-in nodes with `risk_score = 0` (`internal/api/workersapi/routes.go:176-180`). A built-in with a blocklist or feed hit has a risk score above 0, so the list shows it. The coverage query in the status file counts the same set (`internal/extworker/extworker.go:1097`).

The table row shows four signals. Signals with a positive weight come first, then trust signals (`webviz/static/app.js:4862-4867`). Each badge shows the signed weight, for example `+20` or `-25`. `_extSignalClass` gives a negative weight the class `good` (`webviz/static/app.js:4682-4690`).

## Part 2: Shadow IT enrichment

### 2.1 Source gate

`internal/catalog/shadow_it_filter.go` defines which osquery sources count as shadow IT.

| Set | Sources | Where |
|---|---|---|
| `UserAppSources` | apps, programs, homebrew_packages, chocolatey_packages | `internal/catalog/shadow_it_filter.go:34` |
| `ExtensionSources` | chrome_extensions, firefox_addons, safari_extensions, ie_extensions, vscode_extensions, atom_packages, jetbrains_plugins | `internal/catalog/shadow_it_filter.go:31` |
| `ShadowITSources` | union of the two sets above | `internal/catalog/shadow_it_filter.go:36-45` |
| `DevLanguageSources` | npm_packages, python_packages, gem_packages, cargo_packages, pkg_packages, portage_packages, go_binaries (noise) | `internal/catalog/shadow_it_filter.go:29` |
| `LinuxPackageSources` | deb_packages, rpm_packages (noise unless `SHADOW_IT_INCLUDE_LINUX_PACKAGES` is true) | `internal/catalog/shadow_it_filter.go:30` |

`IsSystemPackage(name, dbCategories, sources)` (`:361-392`) suppresses a row in five cases. Case 1: all sources are dev-language (`:365-367`). Case 2: all sources are deb/rpm and the opt-in is off (`:368-370`). Case 3: the name has no alphanumeric character (`:371-375`). Case 4: the name matches `systemPackageRE` (`:215-313`) or `nonUserFacingRE` (`:320-333`). Case 5: a category contains a `SystemCategoryTokens` string (`:342-347`, `:379-390`).

### 2.2 Outlier threshold

`ComputePerPlatformThresholds(ctx, db, pct)` (`internal/catalog/shadow_it_filter.go:177-194`) counts hosts per platform and returns `{platform: max(2, int(total * pct))}`. `pct` comes from `SHADOW_IT_OUTLIER_PCT` (default 0.03) via `GetOutlierPct` (`:65-83`).

### 2.3 ETL enrichment path

`RunCategorization(ctx, memgraphURI, limit, targetNames)` (`internal/enrich/categorize.go:229-263`, candidates in `selectCandidates` `:151-223`, lookups in `enrichNames` `:266-337`) runs after ingest (`internal/etl/etl.go:599-605`) with `limit = 250`, or 0 (no limit) with `--complete-enrichment`.

Procedure:

1. Compute the per-platform thresholds (`internal/enrich/categorize.go:152-153`).
2. For each platform, select `Software` nodes with `category IS NULL`, a shadow IT source, `kind <> 'browser_extension'`, no attempt within the cooldown, and `host_count <= threshold` (`:27-41`, `:181-185`).
3. Merge candidates by name and keep the lowest host count (`:189-205`).
4. Drop names that `IsSystemPackage` suppresses (`:211-214`).
5. Keep at most `limit` names (`:216-218`).
6. For each name, call `catalog.Lookup(name)` (`internal/catalog/software_catalog.go:150`).
7. On a catalog hit, write the category and description with `categorization_source = 'catalog'` (`internal/enrich/categorize.go:42-51`, `:278-281`).
8. On a catalog miss, call `getSoftwareInfo(ctx, name, client)` (`internal/enrich/wikipedia.go:242`).
9. On a Wikipedia hit, write the fields with `categorization_source = 'wikipedia'` (`internal/enrich/categorize.go:52-61`, `:301-304`).
10. On a miss, write only `last_categorization_attempt_iso` and `categorization_attempts` (`:62-66`, `:312-318`).
11. On a transient error, write nothing (`:319-321`).
12. Sleep 0.2 s after each network lookup. Sleep 5 s after 5 consecutive transient errors (`:328-332`).

NOTE: The query excludes browser extensions (`kind = 'browser_extension'`) from this path (`:31`). The extension worker in Part 1 owns their enrichment.

### 2.4 Local catalog

`internal/catalog/software_catalog.go` holds `softwareCatalog` (`:16-121`), a map of 104 lowercase names to (categories, description). `Lookup(name)` (`:150-159`) normalises the name with `normalize` (`:136-145`) and does an exact map match. The catalog is a Go map literal; a change needs a rebuild and redeploy.

### 2.5 Wikipedia REST summary

`getSoftwareInfo(ctx, name, client)` (`internal/enrich/wikipedia.go:242-304`).

| Field | Value |
|---|---|
| URL | `https://en.wikipedia.org/api/rest_v1/page/summary/{title}` (`:26`), `title = quoteTitle(strip(name))` (`:248`, `:215-227`) |
| Method | GET |
| Request | Path parameter only. Headers `User-Agent: FleetHoundSoftwareCategorizer/1.0 (https://github.com/fleethound)`, `Accept: application/json` (`:23`, `:254-255`) |
| Response fields used | `type`, `description`, `extract` |
| Auth | none |
| Timeout | 10 s for the whole request (`:235`) |
| Byte cap | none |
| Cache TTL | No HTTP cache. The graph field `last_categorization_attempt_iso` blocks a retry for `ENRICH_FAILURE_COOLDOWN_DAYS` (default 7) after a miss (`:394`, `internal/enrich/categorize.go:32-33`). |
| Failure behaviour | Timeout, connection error or bad JSON: TRANSIENT (`internal/enrich/wikipedia.go:256-260`, `:278-282`). HTTP 404: MISS. HTTP 429: sleep `min(Retry-After, 120)` s, else 30 s, then TRANSIENT (`:266-271`, `:307-316`). HTTP >= 500: TRANSIENT. `type == "disambiguation"`: MISS (`:283-285`). Text that does not match `softwareHintRE` (`:37-48`): MISS (`:292-294`). |
| Limitation | English Wikipedia only. The page title is the raw software name. The hint regex is the only relevance check. The 429 sleep blocks the goroutine; only context cancellation (shutdown) ends it early (`:269-270`). |

Categories come from `InferCategoriesFromDescription` (`:137-165`), which matches `keywordToCategory` words (`:60-107`) and defaults to `['Application']`. The stored description is the first sentence of `extract`, capped at 300 characters (`:186-211`, `:296-302`).

NOTE: No LLM and no Wikidata SPARQL call exists in this path. The graph field has the name `wikidata_description`, but the source is the Wikipedia REST summary.

### 2.6 Enricher worker

`internal/enrich/enrich.go` runs the same two lookups on a timer. `Start` (`:312-330`) takes a `flock` on `<CONFIG_DIR>/.enricher.lock` (`/app/config/.enricher.lock` in Docker) (`:319`, `internal/workerutil/workerutil.go:109-126`) and starts a goroutine that runs `loop` (`internal/enrich/enrich.go:281-305`).

Procedure per tick:

1. Once per leader start, before the first tick, call `PurgeNonSoftwareDescriptions` (`:288-296`, `internal/enrich/categorize.go:73-95`).
2. Call `pickUncategorized(ctx, db, batchSize)` (`internal/enrich/enrich.go:102-125`). It selects `Software` nodes with `category IS NULL`, a shadow IT source, `kind <> 'browser_extension'`, and no attempt within the cooldown, ordered by host count, `LIMIT batchSize` (default 25) (`:52-64`).
3. Call `fetchBatch` (`:211-247`). It runs `getSoftwareInfo` in at most `ENRICHER_PARALLELISM` goroutines (default 4) with one shared `http.Client` and a 0.2 s sleep per lookup.
4. On the loop goroutine, call `markMiss` (`:127-131`) or `writeCategories` (`:133-146`) (`:265-276`).
5. Write the status file `<CONFIG_DIR>/enricher_status.json` with `AtomicWriteJSON` (`:177-181`, `:277-278`).
6. Call `SleepUntil`. It returns when `ENRICHER_INTERVAL_SEC` (default 300) elapses or the trigger file mtime advances (`:300-303`).

CAUTION: The enricher worker applies neither the per-platform threshold nor `IsSystemPackage` (`:52-64`). Its category write also does not write `categorization_source` or `categorization_attempts` (`:70-76`).

| Route | What it does | Where |
|---|---|---|
| `GET /api/enricher/status` | Returns the status file plus `queue_remaining` = count of all `Software` with `category IS NULL`. | `internal/api/workersapi/routes.go:62-81`, `internal/enrich/enrich.go:385-395` |
| `POST /api/enricher/trigger` | Touches `<CONFIG_DIR>/.enricher.trigger` with a 30 s cooldown. | `internal/api/workersapi/routes.go:104-109`, `internal/enrich/enrich.go:379-381`, `internal/workerutil/workerutil.go:160-172` |

### 2.7 Runtime detection: `GET /api/shadow-it`

`serve` (`internal/api/shadowit/routes.go:139-174`) caches the response in the server process for 30 s. The cache key is the request arguments plus the whitelist file mtime (`:117-137`). The cache holds at most 64 entries (`:30-33`, `:162-164`). `uncached` (`:391-842`) reads the filters `team`, `platform`, `risk`, `detection_type`, `host_count`, `user_count` and `software_type`. It excludes names in `<CONFIG_DIR>/whitelist.json` (`internal/app/app.go:116-137`).

| Detector | Rule | Risk | Where |
|---|---|---|---|
| 1. Outlier | `host_count <= outlierThreshold`, not a system package. `outlierThreshold` is the maximum of the matching platform thresholds. | high when host_count == 1, else medium. A node with an extension `risk_band` uses the band level instead (see below). | `internal/api/shadowit/routes.go:477-567` |
| 2. High-risk category | A `db_category` or the name matches `highRiskPatterns` (Remote Access Tools, File Sharing, Communication Apps, Cryptocurrency Mining, Tor/Privacy Tools) by word boundary. | high | `internal/api/shadowit/routes.go:569-702`, patterns at `:52-80` |
| 3. Version sprawl | More than 2 distinct versions on `INSTALLED_ON` edges, `LIMIT 20` in Cypher. | high > 5 versions, medium > 3, else low | `internal/api/shadowit/routes.go:704-794` |

The response (`:821-841`) is `{summary, detections, risk_distribution, filters}` with no pagination.

Detector 1 also reads `risk_band`, `risk_score` and `is_builtin` from each node (`:487-488`). `extBandToLevel` (`:37`) maps the extension band to a Shadow IT level: `critical` and `high` become `high`, `medium` stays `medium`, `low` stays `low`. The Shadow IT UI has no `critical` level.

Procedure that detector 1 performs for the risk level (`:519-533`):

1. Set the host-count level: `high` for 1 host, else `medium`.
2. When the node has no known band, keep the host-count level.
3. When the node is not built-in, use the band level. The band level can be lower than the host-count level.
4. When the node is built-in, use the higher of the two levels by `levelRank` (`:39`).
5. When the band level is used, `risk_reason` names the extension risk score and band (`:530-531`).

A built-in has risk 0 because of a host-reported ID or path. Thus a built-in band never lowers the level of a rare install. A built-in with a blocklist or feed hit can raise the level.

NOTE: The enrichment taxonomy emits `Remote Access`, `Cloud Storage`, `Communication`, `Crypto` and `Privacy Tool`. Detector 2 looks for `Remote Access Tools`, `File Sharing`, `Communication Apps`, `Cryptocurrency Mining` and `Tor/Privacy Tools`. The category match therefore rarely fires. The name match does the work.

## Configuration

| Knob | Default | Where |
|---|---|---|
| `EXTENSION_WORKER_ENABLED` | true | `internal/config/webviz.go:110` |
| `EXTENSION_WORKER_INTERVAL_SEC` | 21600 | `internal/config/webviz.go:111` |
| `EXTENSION_WORKER_BATCH_SIZE` | 50 | `internal/config/webviz.go:112` |
| `EXTENSION_WORKER_PARALLELISM` | 4 | `internal/config/webviz.go:113` |
| `EXTENSION_WORKER_LOCK_PATH` | `<CONFIG_DIR>/.extensions.lock` (/app/config in Docker) | `internal/config/webviz.go:114` |
| `EXTENSION_WORKER_TRIGGER_PATH` | `<CONFIG_DIR>/.extensions.trigger` | `internal/config/webviz.go:115` |
| `EXTENSION_WORKER_STATUS_PATH` | `<CONFIG_DIR>/extension_status.json` | `internal/config/webviz.go:116` |
| `EXTENSION_CACHE_DIR` | `<CONFIG_DIR>/extension_cache` | `internal/config/webviz.go:117` |
| `ExtensionManualTriggerCooldown` | 30.0 s (constant, not env) | `internal/config/webviz.go:11` |
| `EXTENSION_THREAT_FEEDS_FILE` | `<CONFIG_DIR>/extension_threat_feeds.json` when it exists | `internal/extintel/extintel.go:76-84` |
| `KNOWN_PUBLISHERS_FILE` | `<CONFIG_DIR>/known_publishers.json` when it exists | `internal/extintel/extintel.go:63-71` |
| `listingTTLChromeSec` | 604800 (7 d) | `internal/extworker/extworker.go:57` |
| `listingTTLMinSec` | 1814400 (21 d) | `internal/extworker/extworker.go:58` |
| `listingTTLJitterSec` | 604800 (7 d) | `internal/extworker/extworker.go:59` |
| `blocklistTTLSec` | 21600 (6 h, also feeds) | `internal/extworker/extworker.go:60` |
| `RefreshIntervalSec` | 21600 | `internal/extworker/extworker.go:39` |
| `listingKeyVersion` / `manifestKeyVersion` | `v14` / `v13` | `internal/extworker/extworker.go:66-67` |
| `TriggerPoll` (all workers) | 1 s | `internal/workerutil/workerutil.go:26` |
| `ScorerVersion` | 14 | `internal/extintel/extintel.go:18` |
| `chromiumBuiltinIDs` | 8 IDs | `internal/extintel/identity.go:16` |
| `firefoxBuiltinSuffixes` | `@mozilla.org`, `@mozilla.com` | `internal/extintel/identity.go:27` |
| `winRoot` | `<drive>:\Program Files[ (x86)]\` or `<drive>:\Users\<user>\AppData\Local\` | `internal/extintel/identity.go:296` |
| `builtinPathRes` | anchored install roots for chrome, edge, brave, vivaldi, firefox | `internal/extintel/identity.go:298-306` |
| Safari built-in prefixes | `/Applications/Safari.app/`, `/System/` | `internal/extintel/identity.go:345` |
| `brands` | 43 brand strings | `internal/extintel/publishers.go:23` |
| `publisherSuffixes` | inc, llc, ltd, ..., team | `internal/extintel/publishers.go:86` |
| name anomaly cap | 35 | `internal/extintel/publishers.go:212` |
| typosquat vouch gate | reputable publisher, or verified/established badge with users >= 100,000 and `storeInstallVerified` | `internal/extintel/score.go:483-489` |
| `homeRe`, `chromiumRoots`, `firefoxRoots` | profile-root regexes for macOS, Linux, Windows | `internal/extintel/publishers.go:478-495` |
| `permissionWeights` | 22 entries, debugger 25 to sidePanel 1 | `internal/extintel/score.go:16` |
| `privacyWeights` / `privacyCap` | codes 4: 4, 3: 3, 5: 3, 1: 2, 7: 2 / cap 8 | `internal/extintel/score.go:44-46` |
| `allURLs` | `<all_urls>`, `*://*/*`, `http://*/*`, `https://*/*` | `internal/extintel/score.go:55` |
| optional-permission factor | 0.5 | `internal/extintel/score.go:113` |
| no-host capability discount | 0.6 | `internal/extintel/score.go:165` |
| `riskBand` | 75 critical, 50 high, 25 medium, 0 low | `internal/extintel/score.go:179` |
| trust status points | public 25, unlisted 5, unknown 8, not_found/removed 0; each trust signal weight is the negative of its points | `internal/extintel/score.go:211-223` |
| trust recency windows | 365 d 10, 730 d 4 | `internal/extintel/score.go:243-247` |
| trust popularity | `min(12, int(4 * log10(users + 1)))` | `internal/extintel/score.go:252` |
| trust rating gate | rating >= 4.0 and rating_count >= 100 | `internal/extintel/score.go:257` |
| threat weights | see 1.11 | `internal/extintel/score.go:275` |
| poor-reputation gate | rating < 2.5 and rating_count >= 50 | `internal/extintel/score.go:297` |
| exposure formula | `min(60, round(15 * log10(hosts + 1))) + 10 if versions > 2` | `internal/extintel/score.go:340` |
| rarity thresholds | users < 1000 (4), users < 100 (8), host_count <= 1 (4), fleet ratio < 0.03 with fleet >= 10 (3) | `internal/extintel/score.go:511` |
| composite weights | 0.35, 0.25, 0.25, 0.15 | `internal/extintel/score.go:538` |
| known_bad floors | 85; 92 at >= 10,000 users; 96 at >= 100,000 users | `internal/extintel/score.go:557` |
| feed / removed / not_found floors | 70, 60, 60, 55 | `internal/extintel/score.go:567` |
| `userAgent` | `fleet-hound-extension-intel/1.0 (+https://github.com/)` | `internal/extintel/httpclient.go:18` |
| `maxHTTPBytes` | 8 MiB | `internal/extintel/httpclient.go:19` |
| `chromeHosts`, `edgeHosts`, `amoHosts`, `mozillaHosts` | 6 / 1 / 1 / 1 hosts | `internal/extintel/stores.go:24-34` |
| `HTTPClient` timeout | 12.0 s (feeds 30.0 s) | `internal/extintel/httpclient.go:45` |
| `maxManifestBytes` | 1 MiB | `internal/extintel/stores.go:40` |
| `parseCRX` max ZIP entries | 5000 | `internal/extintel/stores.go:191` |
| `cwsRPCID`, `cwsRPCURL` | `xY2Ddd`, see 1.4 | `internal/extintel/stores.go:239-241` |
| `cwsRPCBatch` | 40 | `internal/extintel/stores.go:243` |
| `cwsCategoryLabels` | 7 slugs | `internal/extintel/stores.go:248` |
| `cwsPrivacyLabels` | codes 1, 3, 4, 5, 6, 7, 8, 9 | `internal/extintel/score.go:48` |
| update2 prodversion / byte cap | 999.0 / 1,000,000 B | `internal/extintel/stores.go:609-611` |
| CRX download cap | 50 MiB | `internal/extintel/stores.go:41` |
| Edge detail byte cap | 2,000,000 B | `internal/extintel/stores.go:714` |
| AMO detail byte cap | 2,000,000 B | `internal/extintel/stores.go:810` |
| XPI download cap | 50 MiB | `internal/extintel/stores.go:958` |
| blocklist page cap / page count | 8 MiB / 20 | `internal/extintel/feeds.go:42-51` |
| `guidRegex` cache | 4096 | `internal/extintel/feeds.go:124` |
| `feedMaxRows` | 200,000 | `internal/extintel/feeds.go:275` |
| `feedSeverity` tiers | malicious 100, unwanted 70, listed 45 | `internal/extintel/feeds.go:279` |
| threat feed byte cap | 32 MiB | `internal/extintel/feeds.go:386` |
| configured feeds | 1 (malext-sentry) | `config/extension_threat_feeds.json:15` |
| `known_publishers.json` | schema_version 1; 51 entries; 16 with chrome IDs, 5 with AMO IDs, 1 with Edge IDs | `config/known_publishers.json:17` |
| `SummarizeVulnerabilities` caps | 50 entries, 20,000 chars | `internal/extintel/feeds.go:530`, `:548` |
| `OODA_ENABLED` | false | `internal/config/webviz.go:119` |
| `OODA_INTERVAL_SEC` | 1800 | `internal/config/webviz.go:120` |
| `INGEST_SW_PARALLELISM` | 4 | `internal/ingest/ingest.go:213` |
| `softwareNodeChunk` | 5000 | `internal/ingest/ingest.go:47` |
| `softwareRelChunkRows` | 5000 | `internal/ingest/ingest.go:48` |
| software flush threshold | 200 hosts | `internal/ingest/ingest.go:46` |
| Fleet `/hosts` per_page | 500 | `internal/fleet/fleet.go:417` |
| Fleet `/hosts` timeout | 120 s | `internal/fleet/fleet.go:435` |
| Fleet `get` retries | 5 | `internal/fleet/fleet.go:221` |
| `etl.Config.EnrichLimit` | 250 | `internal/etl/etl.go:84` |
| Unattached reap | every ETL cycle: Software, Label, User and Host nodes with no host edge are deleted; lists and the extension worker read only nodes installed on a host | `Ingestion.ReapUnattached` |
| `/api/extensions` limit | 1000, max 5000 | `internal/api/workersapi/routes.go:415` |
| `SHADOW_IT_OUTLIER_PCT` | 0.03 | `internal/catalog/shadow_it_filter.go:61` |
| `MinOutlierHosts` | 2 (constant) | `internal/catalog/shadow_it_filter.go:62` |
| `SHADOW_IT_INCLUDE_LINUX_PACKAGES` | false | `internal/catalog/shadow_it_filter.go:88` |
| `ENRICH_FAILURE_COOLDOWN_DAYS` | 7 | `internal/enrich/wikipedia.go:394` |
| `adaptiveBackoffTrigger` / `adaptiveBackoffSleep` | 5 / 5 s | `internal/enrich/wikipedia.go:29-32` |
| Wikipedia timeout | 10 s | `internal/enrich/wikipedia.go:235` |
| `WikipediaRESTURL` | `https://en.wikipedia.org/api/rest_v1/page/summary/{title}` | `internal/enrich/wikipedia.go:26` |
| `--limit` (`fleethound categorize`) / `EnrichLimit` (ETL) | 500 / 250 / 0 (no limit) with `--complete-enrichment` | `internal/enrich/categorize.go:344`, `internal/etl/cli.go:347-349` |
| `ENRICHER_ENABLED` | true in `fleethound serve`; `fleethound etl` reads default false | `internal/config/webviz.go:102`, `internal/etl/cli.go:353` |
| `ENRICHER_INTERVAL_SEC` | 300 | `internal/config/webviz.go:103` |
| `ENRICHER_BATCH_SIZE` | 25 | `internal/config/webviz.go:104` |
| `ENRICHER_PARALLELISM` | 4 | `internal/config/webviz.go:105` |
| `ENRICHER_LOCK_PATH` | `<CONFIG_DIR>/.enricher.lock` | `internal/config/webviz.go:106` |
| `ENRICHER_TRIGGER_PATH` | `<CONFIG_DIR>/.enricher.trigger` | `internal/config/webviz.go:107` |
| `ENRICHER_STATUS_PATH` | `<CONFIG_DIR>/enricher_status.json` | `internal/config/webviz.go:108` |
| `EnricherManualTriggerCooldown` | 30.0 s (constant) | `internal/config/webviz.go:10` |
| `cacheTTL` / `cacheMax` (shadow IT) | 30 s / 64 | `internal/api/shadowit/routes.go:30-33` |
| `extBandToLevel` | critical and high to high, medium to medium, low to low | `internal/api/shadowit/routes.go:37` |
| `levelRank` | low 0, medium 1, high 2 | `internal/api/shadowit/routes.go:39` |
| `WhitelistFile` | `<CONFIG_DIR>/whitelist.json` | `internal/config/webviz.go:98` |
| `MEMGRAPH_URI` (`fleethound categorize`) | bolt://localhost:7687 | `internal/enrich/wikipedia.go:397-402` |

## Limitations

| # | Limitation | Where | Effect |
|---|---|---|---|
| L1 | The name-digest fallback key uses `sha1(name)` only. | `internal/extintel/identity.go:258-266` | Two different unpacked extensions with the same name on the same store become one node. No store lookup runs for them. |
| L2 | `inferStore` has no branch for Arc, Comet or Dia, although `chromiumRoots` lists them. | `internal/extintel/identity.go:91-111`, `internal/extintel/publishers.go:482` | Their extensions get `store = chrome`. |
| L3 | Store path matching is a bare substring on `opera`, `brave`, `vivaldi`. | `internal/extintel/identity.go:104-109` | A username that contains `opera` flips the store. |
| L4 | The Chrome ID regex is a search, not a full match. | `internal/extintel/identity.go:36-55` | A 32-letter token anywhere in a path or display name becomes the identity. |
| L5 | The Safari ID heuristic accepts any dotted token without spaces or `@`. | `internal/extintel/identity.go:132-135` | A version string such as `1.2.3` can become the ID. |
| L7 | Typosquat detection penalises any unvouched 5+ character name within one edit of a brand. | `internal/extintel/publishers.go:184-211`, `internal/extintel/score.go:483-489` | `Money` (brand `honey`) and `Rocket` (brand `pocket`) get penalty 18, unless the store vouches for the publisher. |
| L8 | 33 of 51 known publishers carry no store ID. The scorer applies no name trust. | `config/known_publishers.json`, `internal/extintel/score.go:427-445` | Those vendors add no trust on any store. Edge trust is one extension ID in total. |
| L9 | `storeInstallVerified` fails closed per fleet. | `internal/extintel/publishers.go:559-567` | One host with a missing path removes publisher trust for the whole extension. Opera GX installs never verify (`:480-491`). |
| L10 | The reputation branch keys on `meta.store`, not the record store. | `internal/extintel/score.go:429-445` | With empty store metadata, every store falls to the default branch, which sets the reputable flag to false. A store outage removes 20 trust points. |
| L11 | Permissions outside the 22-entry weight table score 0. | `internal/extintel/score.go:16-39`, `:103-108` | `webNavigation`, `bookmarks`, `browsingData`, `desktopCapture`, `geolocation`, `privacy`, `sessions`, `topSites` add no capability. |
| L12 | Status `unknown` scores trust 8, status `unlisted` scores 5. | `internal/extintel/score.go:216-223` | A failed store fetch yields more trust than a confirmed unlisted extension. |
| L14 | Threat is `max`, not a sum. | `internal/extintel/score.go:266-337` | `removed` (45) plus `critical-cve` (35) plus `manifest-unparseable` (30) equals 45. |
| L15 | The scorer accepts feed hit values with only a 100 cap. | `internal/extintel/score.go:461-473`, `:567-574` | Any feed row with a severity other than `malicious` or `unwanted` still floors risk at 60. |
| L16 | Exposure saturates at 60 near 10,000 hosts. | `internal/extintel/score.go:340` | Exposure contributes at most 10.5 risk points and cannot move a band alone. |
| L17 | The scorer treats a missing host count as `single-host`. | `internal/extintel/score.go:476`, `:524-526` | A record with no host count gets penalty 4. |
| L18 | An unenriched extension lands in `medium`. | `internal/extintel/score.go:221-222`, `:524-526`, `:538-543` | No metadata, no permissions, one host: risk 28. |
| L19 | Status `disabled` has no floor. | `internal/extintel/score.go:282`, `:575` | Only `removed` floors at 60. |
| L20 | The HTTP client has no retry, no backoff and no `Retry-After` honouring. | `internal/extintel/httpclient.go:99-184`, `internal/extintel/stores.go:56-63` | One transient failure costs the extension a full cycle. The worker keeps the failed refresh in the cache until the TTL expires or the fingerprint changes. |
| L21 | The redirect guard checks the hostname only. | `internal/extintel/httpclient.go:147-156` | An https to http redirect to an allowlisted host passes. |
| L22 | The Chrome listing RPC is undocumented. | `internal/extintel/stores.go:234-237`, `:530` | Google can change the payload shape without notice. A changed shape raises "listing RPC schema drift" per ID. |
| L23 | One failed listing chunk errors all 40 IDs in it. | `internal/extintel/stores.go:503-524` | A single bad POST blocks 40 extensions for the cycle. |
| L24 | `parseCRX` skips the CRX3 signature. Edge downloads no package. | `internal/extintel/stores.go:175-177`, `:705-792` | Package authenticity rests on the SHA-256 from the same store endpoint. |
| L25 | Edge validates the ID against `[a-p]{32}` before interpolation. | `internal/extintel/stores.go:708-710` | An invalid ID returns status `unknown` with `invalid edge extension id`. No request reaches the Edge API. |
| L26 | Edge falls back to Chrome only on `not_found`. | `internal/extintel/stores.go:1288` | An Edge error or rate limit does not fall back. |
| L27 | AMO 401 returns status only. | `internal/extintel/stores.go:815-818` | Unlisted Firefox add-ons have no permissions, publisher or package. |
| L28 | Brave and Vivaldi route to the Chrome Web Store only. Safari is looked up by the containing app's host-reported bundle ID. | `FetchStoreMetadata`, `fetchSafariMetadata` | A spoofed bundle ID inherits another app's App Store store signals. Publisher trust needs the signing team ID (`apple_team_ids`), which only 2 publishers carry. |
| L30 | A missing blocklist with no cached copy aborts the whole cycle. | `internal/extworker/extworker.go:1076-1078` | Chrome and Edge scoring also stop, although the blocklist covers Firefox GUIDs. |
| L31 | Only one threat feed exists, chromium only. | `config/extension_threat_feeds.json:14-27` | Firefox has no feed coverage. |
| L33 | The code cuts JSON scalars at 20,000 characters after JSON encoding. | `internal/extintel/feeds.go:548`, `:557` | A long payload can become invalid JSON in the graph. `vulnerability_count` counts all entries while the JSON holds at most 50. |
| L34 | The leader lock and trigger live under `<CONFIG_DIR>` (`/app/config` in Docker). | `internal/config/webviz.go:114-115` | Two containers with separate config directories on one Memgraph both run cycles. |
| L35 | The worker starts only on the first healthy `/api/health` or `/api/extensions*` request. | `internal/server/handlers.go:64-66`, `internal/server/server.go:355-368`, `internal/api/workersapi/routes.go:409` | A container with no HTTP traffic never scores anything. |
| L36 | `last_tick_iso` is never set. `sources.store_metadata` is hard-coded `true`. | `internal/extworker/extworker.go:279`, `:297`, `:1275` | The status file shows `null` and `true` regardless of outcome. |
| L37 | A manual trigger during a running cycle is not seen until the cycle ends. The trigger has no payload. | `internal/extworker/extworker.go:1284-1290`, `internal/workerutil/workerutil.go:142-153` | A refresh cannot target one extension or force a full refetch. |
| L38 | The rare-in-fleet verdict, `ScorerVersion` and the publishers file digest are global fingerprint inputs. | `internal/extworker/extworker.go:487`, `:496-498`, `internal/extworker/extworker_test.go:130` | Crossing the 0.03 ratio or editing `known_publishers.json` re-scores every group in one cycle. |
| L39 | `allGroups` returns `properties(n)` for every member node. `coverage` runs a second full scan every cycle. | `internal/extworker/extworker.go:353-364`, `:1094-1112` | Two full `:Software` scans per cycle, even when nothing is due. |
| L40 | The worker opens and parses the listing cache file 2 times per group on an idle cycle and 4 times per due group. | `internal/extworker/extworker.go:527`, `:553`, `:725`, `:875` | The file opens scale with the group count, even when nothing is due. |
| L41 | The chunk pipeline is serial on the loop goroutine. Edge and AMO are one blocking call per extension. | `internal/extworker/extworker.go:1183-1246`, `internal/extintel/stores.go:705-1250` | The scoring goroutines idle during prefetch and writes. A slow feed blocks the cycle before scoring. |
| L43 | A failed chunk write discards the scored results. | `internal/extworker/extworker.go:1234-1239` | Every row in the chunk counts as an error. |
| L44 | `GET /api/extensions` applies `LIMIT` to nodes before Go grouping. | `internal/api/workersapi/routes.go:418-428`, `:470` | `summary.total` can disagree with `len(extensions)`. |
| L45 | `GET /api/extensions/detail` keys hosts by hostname. | `internal/api/workersapi/routes.go:590` | Two Fleet hosts with one hostname collapse into one row. |
| L46 | Ingestion writes `extension_key` into `Software.name`. | `internal/ingest/ingest.go:784-786` | Consumers that join on `name` see `ext:chrome:<id>`. |
| L47 | Ingestion keeps vulnerabilities, signature, CPE and vendor only for the four browser sources. | `internal/ingest/ingest.go:780-809` | Native app rows lose their Fleet vulnerabilities at ingest. |
| L48 | `ON MATCH` guards write only non-null values. | `internal/ingest/ingest.go:1188-1218`, `:1240-1243` | A property never returns to null from ingest. |
| L49 | The per-host short-circuit keys on `software_updated_at` only. | `internal/ingest/ingest.go:953-970` | New Fleet vulnerabilities for an unchanged inventory are not re-fetched. |
| L50 | `is_builtin` is node-level. The scorer recomputes it from the stored `installed_paths` (first 10). One matching path is enough. | `internal/extintel/identity.go:327-348`, `internal/extworker/extworker.go:452-453` | One anchored vendor path marks the extension built-in for all hosts. With `include_builtin` off, the list hides it while its risk score is 0. |
| L51 | Only the OODA Orient phase wakes the extension worker after an ingest. A manual ETL run does not touch the trigger. | `internal/ooda/ooda.go:580-606`, `internal/config/webviz.go:145-150` | With OODA off, new extensions can wait up to 6 h for a score. |
| L52 | Fleet `get` never re-authenticates on 401. The response cap is 1 GiB. | `internal/fleet/fleet.go:220-295`, `:40` | A token that expires mid-cycle fails the cycle. A large page can time out behind Cloudflare. |
| L53 | Linux deb/rpm are invisible to shadow IT without the opt-in. | `internal/catalog/shadow_it_filter.go:88-98`, `:368-370` | A deliberate `apt install teamviewer` is not detected by default. |
| L54 | `systemPackageRE` contains empty alternations inside the `microsoft\.(...)` groups. | `internal/catalog/shadow_it_filter.go:265-268`, `:284-287` | The regex suppresses any name that starts with `microsoft.`. `make.*` (`:232`) suppresses `MakeMKV`. |
| L55 | The outlier floor is 2 hosts. `int()` truncates. | `internal/catalog/shadow_it_filter.go:62`, `:177-194` | On platforms with fewer than 100 hosts, `pct` has no effect. 99 hosts * 0.03 = 2. |
| L56 | Both shadow IT enrichment paths exclude browser extensions. | `internal/enrich/categorize.go:31`, `internal/enrich/enrich.go:56` | Their category comes only from the extension worker. |
| L57 | The ETL limit cut happens after `ORDER BY host_count ASC`. | `internal/enrich/categorize.go:27-41`, `:207-218` | With more than 250 candidates, the most common rare software is never enriched by ETL. |
| L58 | The catalog is an exact match after suffix stripping, as a Go map literal. | `internal/catalog/software_catalog.go:136-159` | `Slack.app` misses the catalog. A new entry needs a rebuild and redeploy. |
| L59 | Wikipedia lookup has no byte cap and sleeps up to 120 s on 429. | `internal/enrich/wikipedia.go:235`, `:266-271` | The client decodes a large extract whole. A 429 blocks the goroutine; only shutdown ends the sleep early. |
| L60 | ETL write-back matches `Software {name}` with no platform scope. | `internal/enrich/categorize.go:43`, `:53` | Two nodes with one name on two platforms get one verdict. |
| L61 | The enricher worker applies no threshold and no system-package filter, and writes no provenance. | `internal/enrich/enrich.go:52-64`, `:70-76` | It spends Wikipedia calls on common software. Its nodes carry no `categorization_source`. |
| L62 | `queue_remaining` counts every `Software` with `category IS NULL`. | `internal/enrich/enrich.go:77` | The count includes dev-language packages and nodes in cooldown. |
| L63 | `ENRICHER_ENABLED` defaults differ between commands. | `internal/config/webviz.go:102`, `internal/etl/cli.go:353` | A bare `fleethound etl` run does inline enrichment while the server worker also runs. |
| L64 | `outlierThreshold` with `platform=all` is the maximum over platforms. | `internal/api/shadowit/routes.go:419-436` | A row on 3 Linux hosts is an outlier when the Windows threshold is 30. |
| L65 | Detectors 1 and 3 collect hostnames in Cypher for every in-scope node, then filter in Go. Detector 2 classifies from a light aggregate and collects hosts only for matches (`:571-582`, `:637-643`). | `internal/api/shadowit/routes.go:479-496`, `:708-726` | Detectors 1 and 3 materialise hostname lists for packages that the Go filter then discards. |
| L66 | The enrichment taxonomy and `highRiskPatterns` use different category names. | `internal/enrich/wikipedia.go:60-107`, `internal/api/shadowit/routes.go:52-80` | The category match in detector 2 rarely fires. |
| L67 | Version sprawl applies `LIMIT 20` before the system-package filter. | `internal/api/shadowit/routes.go:725`, `:742` | The detector can return zero user-app rows while sprawled user apps exist below rank 20. |
| L68 | `/api/shadow-it` has no pagination. Detection IDs are per-request counters. | `internal/api/shadowit/routes.go:546`, `:682`, `:775`, `:821-841` | The response carries every hostname and username on each request. IDs are not stable. |
| L69 | The shadow IT cache is in-process memory with a 30 s TTL. | `internal/api/shadowit/routes.go:30-33`, `:139-174` | A second server process holds its own cache. A request can see data up to 30 s stale. |
| L70 | The enricher lock lives under `<CONFIG_DIR>` (`/app/config` in Docker). | `internal/config/webviz.go:106` | Two replicas with separate config directories both run the loop. |
| L71 | Chrome, Edge, Brave and Vivaldi have only Windows install-root patterns. | `internal/extintel/identity.go:296-302` | On macOS and Linux, these extensions are built-in only through `chromiumBuiltinIDs`. A component extension outside the 8 IDs gets a normal score. |
| L72 | Opera and Chromium have no entry in `builtinPathRes`. | `internal/extintel/identity.go:298-306` | An Opera or Chromium extension is never built-in by path. Only the ID list applies. |
| L73 | A store badge vouches for a brand look-alike name only at 100,000 users or more. | `internal/extintel/score.go:483-489` | A small verified publisher with a name such as `Motion` keeps the typosquat penalty 18. |
| L74 | Only the Chrome Web Store listing supplies `privacy_codes`. | `internal/extintel/stores.go:411-434`, `internal/extintel/score.go:417-418` | Edge and Firefox extensions never get the `declared-data-collection` signal. |
| L75 | The blocklist conditional GET validates page 1 only. | `internal/extintel/feeds.go:48-54` | A 304 on page 1 reuses the whole cached list. |
| L76 | `pruneCache` runs only when a worker wins the leader lock. | `internal/extworker/extworker.go:1337-1339` | Retired key files stay on disk until the next container restart. |
| L77 | Detector 1 uses the extension band for a non-built-in node, also when the band is lower. | `internal/api/shadowit/routes.go:527-533` | A 1-host extension with band `low` shows as `low`, not `high`. |
| L78 | The comment at the built-in short-circuit describes the host-reported ID and path correctly. | `internal/extintel/score.go:407-414` | No effect. No comment calls the anchored `builtinPathRes` rules substring matches. |

## How to run a self-check

Run these commands from the repository root on the host. The `webviz` container must be running.

1. Run the pure scoring self-check inside the container:

   ```
   docker compose exec -T webviz fleethound selfcheck
   ```

   The command exits with code 0 and prints `extension_intel self-check: OK` when every assertion passes.

2. Print the extension worker status file. The image has no shell, so read the bind-mounted copy on the host:

   ```
   cat config/extension_status.json
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
   go test ./internal/extworker/...
   ```

CAUTION: `docker compose exec -T webviz fleethound categorize --limit 0` enriches every candidate. It makes one Wikipedia request per candidate at 0.2 s pacing. Run it only when you accept the runtime.

CAUTION: Step 1 and step 2 read the self-check and the worker status without a Fleet connection. Steps 3 to 6 need the running dashboard and the API token.

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
| flock | A Linux file lock. The worker uses it to elect one leader among several processes, for example a second `fleethound` process on the same config directory. |
| GUID | The Firefox add-on identifier, in the form `{uuid}` or `name@domain`. |
| net/http server | The Go HTTP server in `fleethound serve`. It runs the `webviz` application and its workers in one process. |
| Kinto | The Mozilla Remote Settings service that serves the blocklist as paged JSON. |
| leader election | The procedure by which one process wins the lock and runs the worker loop. The other processes do nothing. |
| listing | The store catalog page data for one extension: name, users, rating, publisher, manifest. |
| manifest | The `manifest.json` file inside an extension package. It declares permissions, host permissions and content scripts. |
| Memgraph | The graph database that stores `:Host` and `:Software` nodes and `INSTALLED_ON` edges. Queries use Cypher. |
| MV2, MV3 | Manifest version 2 and 3 of the Chrome extension platform. MV3 adds 8 trust points. |
| OODA | The supervisor goroutine in `fleethound serve` that runs the ETL on a timer. |
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

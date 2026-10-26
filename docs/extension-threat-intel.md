# Browser Extension Threat Intelligence — Research & Integration Plan

**Status:** Phase 0 implemented (2026-10-23). Sources below are live-verified and anonymous.
**Scope:** Chrome, Edge, Firefox, Safari extensions. IDE extensions are adjacent only.
**Constraint:** non-paid sources only.

### What shipped (2026-10-23)

| Action | Where |
|---|---|
| 1. Preserve extension identity/fields at ingestion | `src/ingestion.py` (additive `extension_key`, `kind`, `store`, `extension_id`, `browser`, per-host edge props `version/source/browser/installed_path/first_seen/last_seen`, vuln + signature summaries). MERGE key stays `name`. |
| 2. Free/no-auth store-metadata adapters | `src/extension_intel.py` (Chrome update2 + CRX manifest, Edge product-details, AMO, Mozilla blocklist; host allowlist, size caps, offline degrades to local score) |
| 3. Risk-scoring engine | `src/extension_intel.py::analyze_extension` (capability / trust / threat / exposure + name-anomaly + rarity + download rules; built-ins score 0; blocklist + ≥100k installs ⇒ ≥95) |
| 4. Worker + API + UI | `webviz/extension_worker.py` (leader-elected, cached, status/trigger files), `/api/extensions[...]` in `webviz/app.py`, "Extensions" tab in `webviz/static/index.html` |

Runnable self-check (inside the container, so it uses the shipped code and env):
`docker compose exec -T webviz python src/extension_intel.py`. Phase-1+ items below (policy
export, threat feeds with keys, static analysis) are intentionally NOT built yet.

---

## 1. Bottom line

- Fleet already returns everything needed to identify an extension: `extension_id`, `browser`, `extension_for`, `vendor`, `generated_cpe`, `vulnerabilities`, `signature_information`, `installed_paths`, `display_name`. Ingestion keeps only `name`, `version`, `source` (`src/ingestion.py:468`). **The highest-value change is to stop dropping those fields.**
- The missing primary key is the extension ID. Names are unreliable (some are filesystem paths), and the same 32-char ID can exist in both Chrome and Edge. Use `ext:<store>:<id>` as the canonical key; keep the human name for display.
- Enrich in a separate worker, not inline in ETL. Store metadata is rate-limited and failure-prone; ETL is already the long pole.
- Free sources cover identity, permissions, store status, blocklists, vulnerabilities, and reputation. No paid API is required. CRXcavator is dead; ExtensionTotal is now paid (Koidex/Koi); Chrome-Stats blocks automated access.
- Protection is possible because browsers expose enterprise policy (`ExtensionSettings`). The platform should export policy, not just alert. Allow by ID + publisher + permission ceiling; block known-bad; restrict high-capability extensions from sensitive domains.

---

## 2. What we have vs. what we drop

Fleet host payload (verified against the live API):

```json
{
  "name": "...",
  "version": "1.7.1",
  "source": "chrome_extensions",
  "extension_id": "cnjifjpddelmedmihgijeibhnjfabmlf",
  "browser": "chrome",
  "extension_for": "chrome",
  "vendor": "...",
  "generated_cpe": "...",
  "display_name": "...",
  "installed_paths": ["..."],
  "signature_information": {},
  "vulnerabilities": []
}
```

Ingestion (`src/ingestion.py:468`):

```python
cleaned_software.append({
    "name": name_lc,
    "version": s.get("version") or "unknown",
    "source": (s.get("source") or "").strip(),
})
```

Consequences:

- No way to query "which hosts have extension X" by ID.
- The same extension under two names becomes two `:Software` nodes.
- No permissions, publisher, store status, or vulnerability context.
- `INSTALLED_ON` has no version/path, so per-host version spread is invisible.
- Fleet's `vulnerabilities` are discarded for **every** software type, not just extensions. Example: Fleet returned CVE-2024-49050 for `ms-python.python` (CVSS 8.8, EPSS 0.01308, fixed in 2024.18.2); the graph never sees it.

Live fleet snapshot (2026-10-23): **32 hosts, 72 extension identities**:

| Channel | Identities | Notes |
|---|---:|---|
| Chrome/Edge (`chrome_extensions`) | 13 | 5 built-ins (Google Docs Offline, Chrome Web Store, Edge components) |
| Firefox (`firefox_addons`) | 12 | 10 built-ins (`@mozilla.org` / `@mozilla.com`) |
| VS Code (`vscode_extensions`) | 47 | out of scope; Fleet `extension_id` is a local UUID, use `name` |
| Safari | 0 | no data yet |

That is roughly **10 third-party browser extensions** today. Small, but the model must scale to 100k hosts.

---

## 3. Identity model

### 3.1 Canonical key

```text
software_key =
  "ext:chrome:<32-char-id>"      # Chrome
  "ext:edge:<32-char-id>"        # Edge (same ID namespace as Chrome)
  "ext:firefox:<guid>"           # Firefox ({uuid} or name@domain)
  "ext:safari:<bundle-id>"       # Safari (fallback: path hash)
  "ext:vscode:<publisher.name>"  # adjacent
  "name:<lowercased-name>"       # native software
```

Why the store is in the key:

- Chrome and Edge share the 32-char ID namespace. The same ID can be a different extension in each store.
- Store status, permissions, and policy are per-store.

Why not use `name` as the key:

- Fleet's `name` for Chromium extensions is sometimes the install path (`C:\...\Extensions\<id>\1.108.1_0`).
- Display names collide across stores ("AdBlock" exists in Chrome and Edge).
- Renames would split identity.

### 3.2 Schema changes

Keep one `:Software` label. Do **not** add an `:Extension` label — it duplicates nodes and breaks every existing query.

New/changed `:Software` properties:

| Property | Type | Source |
|---|---|---|
| `software_key` | string, unique | derived |
| `name` | string | display (lowercased native, store name for extensions) |
| `display_name` | string | Fleet `display_name` or store name |
| `kind` | enum | `browser_extension`, `ide_extension`, `native` |
| `store` | enum | `chrome`, `edge`, `firefox`, `safari`, `vscode` |
| `extension_id` | string | Fleet |
| `browser` | string | Fleet |
| `vendor` | string | Fleet |
| `publisher` | string | store |
| `store_status` | enum | `public`, `unlisted`, `removed`, `not_found`, `error` |
| `store_url` | string | derived |
| `latest_version` | string | store |
| `manifest_version` | int | manifest |
| `permissions` | list | manifest |
| `optional_permissions` | list | manifest |
| `host_permissions` | list | manifest |
| `content_script_matches` | list | manifest |
| `capability_score` | int 0-100 | analyzer |
| `trust_score` | int 0-100 | analyzer |
| `threat_score` | int 0-100 | feeds |
| `exposure_score` | int 0-100 | graph |
| `risk_score` | int 0-100 | composite |
| `risk_band` | enum | `good`, `watch`, `review`, `block` |
| `risk_signals` | list of maps | explainability |
| `install_users` | int | store |
| `rating` / `rating_count` | float / int | store |
| `category` | string | store |
| `privacy_policy_url` | string | store |
| `first_seen` / `last_seen` | datetime | ingest |
| `intel_refreshed_at` | datetime | worker |
| `decision` | enum | `allow`, `review`, `block` |
| `decision_by` / `decision_at` / `decision_note` | | analyst |

`INSTALLED_ON` edge properties:

| Property | Source |
|---|---|
| `version` | Fleet |
| `source` | Fleet |
| `browser` | Fleet |
| `extension_for` | Fleet |
| `installed_path` | Fleet `installed_paths[0]` |
| `signature_information` | Fleet |
| `first_seen` / `last_seen` | ingest |

Constraints:

```cypher
// one-shot migration order
MATCH (s:Software) WHERE s.software_key IS NULL
SET s.software_key = 'name:' + s.name;

// re-key nodes that already carry extension fields (Phase 0 data)
MATCH (s:Software)
WHERE s.extension_id IS NOT NULL AND s.store IS NOT NULL
SET s.software_key = 'ext:' + s.store + ':' + s.extension_id;

// dedupe by software_key in Python (see 3.3), then:
DROP CONSTRAINT ON (s:Software) ASSERT s.name IS UNIQUE;
CREATE CONSTRAINT ON (s:Software) ASSERT s.software_key IS UNIQUE;
```

### 3.3 Migration steps

1. Backfill `software_key` for all nodes (`name:<name>`).
2. Deploy Phase 0 ingestion (fields preserved) for one cycle.
3. Re-key extension nodes to `ext:<store>:<id>`.
4. Deduplicate: group by `software_key`; pick canonical (most edges, then oldest `first_seen`); redirect `INSTALLED_ON`; union `versions` / `sources`; copy best `display_name`; `DETACH DELETE` duplicates.
5. Drop `UNIQUE(name)`; create `UNIQUE(software_key)`.
6. Change MERGE in `_batch_create_software_grouped` to `software_key`.
7. Change stale-rel delete from `NOT s.name IN ...` to `NOT s.software_key IN ...`.
8. Gate `_dedupe_case_variant_software` to `software_key STARTS WITH 'name:'` — otherwise it will merge Chrome/Edge extensions that share a display name.
9. Update snapshot identity from `s.name` to `s.software_key` (snapshot format v2).
10. Update the whitelist to store `software_key`; migrate existing entries to `name:<lower>`.

Rollback: keep `name` and `extension_id` on every node. Take a snapshot before migration (`config/snapshots`). Dropping the `software_key` constraint and re-MERGing on `name` is possible, but merged duplicates stay merged.

---

## 4. Free source catalogue

### 4.1 Identity + store truth (Tier 1)

| Source | Gives | Endpoint | Auth | Verified | Notes |
|---|---|---|---|---|---|
| Chrome update2 | exists/removed, latest version, SHA-256, size, CRX URL | `https://clients2.google.com/service/update2/crx?response=updatecheck&prodversion=131.0&acceptformat=crx2,crx3&x=id%3D{ID}%26uc` | none | ✅ | `status="ok"` or `error-unknownApplication`; parse XML |
| Chrome CRX | `manifest.json` (permissions, hosts, MV, update_url), file list | `codebase` URL from update2 | none | ✅ | Follow redirects only to `clients2.google.com` / `storage.googleapis.com`; SHA-256 matches update2 `hash_sha256` |
| Edge product details | name, version, users, rating, developer, category, privacyData, manifest JSON, isMV2 | `https://microsoftedge.microsoft.com/addons/getproductdetailsbycrxid/{ID}` | none | ✅ | Can return a JSON body with HTTP 404 — only HTTP 200 is `public`; 404 or `null`/empty is `not_found` |
| Edge CRX | — | — | — | ❌ | Download endpoint returns HTTP 500; use detail JSON manifest |
| AMO addon API | name, version, permissions, host_permissions, optional_permissions, hash, size, users, ratings, status | `https://addons.mozilla.org/api/v5/addons/addon/{GUID}/` | none | ✅ | URL-encode GUID; 404 = built-in, 401 = unlisted/self-distributed |
| Mozilla blocklist | 1,014 records: guid, why, versionRange, severity | `https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/addons/records` | none | ✅ | Cache 6-12h. Paginate via the `Next-Page` header. `guid` may be a `/regex/` (matched against the extension ID); `versionRange` (`minVersion`/`maxVersion`, `*` = unbounded) is checked against installed versions, and an unknown installed version counts as blocked |
| Safari / App Store | containing app metadata | `https://itunes.apple.com/lookup?bundleId={BUNDLE}` | none | ⚠️ | Extensions are app-embedded; map via `installed_paths` / bundle ID; detection-only |
| VS Code Marketplace | metadata, versions, stats | `POST https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery` | none | ✅ | Unofficial; adjacent scope |
| Open VSX | metadata, versions | `https://open-vsx.org/api/{publisher}/{name}` | none | ✅ | Adjacent scope |

### 4.2 Threat intel (Tier 2)

| Source | Gives | Auth | Free quota | Use |
|---|---|---|---|---|
| VirusTotal v3 | file/URL/domain reputation | API key | 4 req/min, 500/day | CRX hash, manifest domains |
| Google Safe Browsing v4 | URL reputation | API key | daily quota | manifest URLs/domains |
| URLhaus | malware URLs | Auth-Key | free Auth-Key | network endpoints |
| ThreatFox | IOCs | Auth-Key | free | domains/IPs |
| MalwareBazaar | malware hashes | Auth-Key | free | CRX hash |
| PhishTank / OpenPhish | phishing URLs | none | free | manifest URLs |
| AlienVault OTX | pulses by domain/hash | API key | free | reputation |
| URLScan.io | scan/search by domain/hash | API key | 100 scans/day | endpoints |
| Pulsedive | threat intel | API key | free tier | domains |
| crt.sh | certificate transparency | none | polite | publisher domain age/history |
| Tranco | top 1M domains | none | free download | domain popularity |
| RDAP | domain registration | none | rate-limited | domain age (`.md` unsupported by rdap.org) |
| EasyList / EasyPrivacy / Disconnect | tracker lists | none | free | classify endpoints |
| NVD | CVEs | optional key | 5 req/30s | bundled libs |
| OSV | CVEs for packages | none | free | bundled JS libs |
| GitHub Advisory | CVEs | none | free | bundled libs |
| FIRST EPSS | exploit probability | none | free | prioritize |
| CISA KEV | known exploited | none | free | prioritize |
| OpenSSF Scorecard | repo health | none | free | publisher trust |
| deps.dev | dependency graph | none | free | bundled libs |
| retire.js | vulnerable JS libs | none | free | static scan |

**Terms check:** VirusTotal's free API is rate-limited and intended for non-commercial use. If Fleet Hound is commercial, stay within terms or rely on the other sources. The design must not depend on VT.

### 4.3 Static analysis (Tier 3, local)

| Tool | Use |
|---|---|
| `addons-linter` (npm) | MV2/MV3 validation, dangerous patterns |
| `tarnish` | Chrome extension static analysis |
| `ExtAnalysis` | permission/code review |
| `webcrack` | unpack bundled JS |
| Semgrep | custom exfil/obfuscation rules |
| YARA | malware family rules |
| gitleaks | secrets in bundles |
| `crx3` / `crx` | unpack CRX |

Run in a sandbox: no network, CPU/memory/time limits, zip-bomb caps, no code execution.

### 4.4 Dead / paid / unreliable

| Source | Status | Why |
|---|---|---|
| CRXcavator | dead | no API |
| ExtensionTotal | now Koidex/Koi, paid | not usable |
| Chrome-Stats | Cloudflare 403 | paid |
| Chrome Web Store HTML | unreliable | embedded manifests include recommended extensions; positional parsing is wrong |
| Install count as trust | unreliable | popular extensions get sold/compromised |

---

## 5. Architecture

```text
Fleet API ──> extractor ──> ingestion ──> Memgraph
                              │              │
                              │              ├── /api/extensions (read)
                              │              └── extension_worker (write intel)
                              │                        │
                              │        ┌───────────────┼───────────────┐
                              │        │               │               │
                              │   store adapters   threat feeds   static scan
                              │   (Chrome/Edge/    (VT/SB/abuse/   (linter/
                              │    AMO/Safari)      OTX/OSV)        Semgrep/YARA)
                              │        │               │               │
                              └────────┴───────┬───────┴───────────────┘
                                               │
                                     config/extension_policy.json
                                               │
                                     MDM / Fleet profiles
```

### 5.1 Modules

| File | Responsibility |
|---|---|
| `src/extension_intel.py` | Pure logic: store adapters, manifest analyzer, scoring, policy export. No Flask, no DB. Testable. |
| `webviz/extension_worker.py` | Leader-elected background worker: pick stale nodes, call adapters, write graph, cache/status. |
| `webviz/app.py` | APIs: list/detail/decision/status/policy. |
| `webviz/static/index.html` | "Extensions" tab. |
| `config/extension_policy.json` | Generated policy + decisions. |
| `config/extension_cache/` | Raw manifests + metadata (versioned). |
| `config/extension_status.json` | Worker status for UI. |

Why not inline in ingestion:

- External HTTP with quotas on the ETL critical path.
- ETL already takes 30 minutes at 100k hosts.
- Enrichment failures must not fail inventory.
- TTL/caching is natural in a worker.

### 5.2 Worker loop

1. Acquire `fcntl` lock (same pattern as `enrich_worker.py`).
2. Select `:Software` where `kind = 'browser_extension'` and (`intel_refreshed_at` is null or older than TTL), ordered by host count desc, limit 50.
3. For each:
   - Store adapter by `store`.
   - If version changed or no manifest: download CRX (Chrome), parse detail JSON (Edge), call AMO.
   - Analyze manifest → permissions, hosts, MV, content scripts.
   - Compute capability/trust.
   - Threat feeds (only for new/changed versions; cache by hash).
   - Compute exposure from graph.
   - Composite risk + signals.
   - Write properties.
4. Refresh the global Mozilla blocklist once per cycle.
5. Write status (last run, counts, errors, source health).
6. Sleep; respect `EXTENSION_WORKER_INTERVAL_SEC` (default 6h).

TTLs:

| Data | TTL |
|---|---|
| Store metadata | 24h |
| Blocklist | 6h |
| Manifest | until version change |
| VT/URL reputation | 24h per hash/domain |
| Static scan | until version change |
| Exposure score | every cycle (graph query is cheap) |

### 5.3 Failure handling

- Per-source circuit breaker: 3 consecutive failures → skip source for 1h; status shows degraded.
- Backoff with jitter on 429/5xx.
- Implemented today: a per-store, per-cycle breaker. A 429 (or 503 with `Retry-After`) from a store trips it; that store's remaining items are skipped, not cached and not stamped (`intel_refreshed_ts` unchanged), so they retry next cycle. `last_cycle` reports `deferred` and `rate_limited_stores`.
- One extension failure does not abort the batch.
- Manifest parse failure → `risk_signals += "manifest-unparseable"`, risk ≥ 60.
- Never follow arbitrary redirects (SSRF); allowlist store domains.
- Cap CRX download at 50 MB, extracted files at 10k / 200 MB.

---

## 6. Risk model

### 6.1 Scores

**Capability (0-100):** permission weights + host breadth.

| Signal | Weight |
|---|---|
| `debugger` | +25 |
| `nativeMessaging` | +20 |
| `proxy` | +20 |
| `userScripts` | +15 |
| `cookies` | +15 |
| `webRequest` / `declarativeNetRequest` | +15 |
| `management` | +15 |
| `scripting` | +12 |
| `clipboardRead` | +12 |
| `tabCapture` | +10 |
| `history` | +8 |
| `identity` | +8 |
| `downloads` | +6 |
| `offscreen` | +6 |
| `activeTab` | +2 |
| `storage`, `contextMenus`, `alarms`, `notifications`, `sidePanel` | +1 each |
| Host `<all_urls>` / `*://*/*` | +20 |
| Content script on `<all_urls>` | +10 |
| Optional permission | ×0.5 of its weight; optional total capped at the required-permission total |
| No host permissions and no content-script matches | ×0.6 |

**Trust (0-100, higher = better):**

| Signal | Weight |
|---|---|
| Public store listing | +25 |
| Unlisted | +5 |
| Removed / not found | 0 |
| Sideloaded | 0 |
| Known publisher (Google, Microsoft, Mozilla, Adobe, etc.) — store developer/publisher field only (never Fleet `vendor`), normalized exact match after dropping suffixes like Inc/LLC/Ltd/GmbH. The list is data, not code: `config/known_publishers.json` (one entry per publisher with `added_at`; reloaded on change, no rebuild). Chrome-family trust is by Chrome Web Store publisher ID only (`chrome_publisher_ids`, from the listing's `data-publisher-id` link; a page with more than one distinct ID trusts nothing). Firefox trust is by AMO author user ID only (`amo_author_ids`). Edge exposes no publisher ID, so Edge trust is per extension (`edge_extension_ids`) and only while the store lists the ID as public. Names are display-only on all three stores because anyone can register a lookalike; only Safari still matches `match_names`. Only trader-declared developers have a publisher link, so non-trader extensions stay unverified | +15 |
| MV3 | +10 |
| Updated < 12 months | +15 |
| Updated 12-24 months | +5 |
| Users (log scale) | up to +15 |
| Rating ≥ 4 with ≥ 100 ratings | +10 |
| CRX hash matches update2 | +10 |
| Open-source repo / Scorecard ≥ 7 | +5 |

**Threat (0-100):**

| Signal | Weight |
|---|---|
| Mozilla blocklist hit | 100 |
| VT malicious ≥ 3 | 90 |
| VT malicious 1-2 | 60 |
| Safe Browsing hit | 80 |
| URLhaus/ThreatFox IOC | 80 |
| Obfuscated code / `eval` / remote script load | +25 |
| Vulnerable bundled JS (retire.js) | +20 |
| CVE CVSS ≥ 7 in Fleet `vulnerabilities` | +25 |
| CISA KEV | +30 |
| Publisher domain < 90 days | +30 |
| Domain not in Tranco top 1M | +10 |

**Exposure (0-100):**

| Signal | Weight |
|---|---|
| Hosts (log scale) | 5-60 |
| Users (log scale) | up to 20 |
| Privileged teams (IT/finance/eng) | +20 |
| Version spread > 2 | +10 |
| Installed on servers | +20 |

**Composite:**

```python
risk = round(0.35 * cap + 0.25 * (100 - trust) + 0.25 * threat + 0.15 * exposure)
if threat >= 80:
    risk = max(risk, 85)
```

Bands:

| Band | Score | Default decision |
|---|---|---|
| Good | 0-24 | Allow |
| Watch | 25-49 | Allow + monitor |
| Review | 50-74 | Review / restrict |
| Block | 75-100 | Block |

**Never auto-block:** browser built-ins/component extensions, vendor-signed browser components. Maintain an ID allowlist + path heuristic (`.../Application/<Browser>.app/.../Extensions/`, `.../Microsoft/Edge/Application/...`).

### 6.2 Explainability

Store signals as:

```json
[
  {"code": "broad-host-access", "weight": 20, "detail": "host_permissions includes <all_urls>"},
  {"code": "sideloaded", "weight": 25, "detail": "not present in Chrome Web Store"},
  {"code": "store-removed", "weight": 40, "detail": "update2 returned error-unknownApplication"}
]
```

The UI must answer: "Why is this risky?" and "What breaks if I block it?"

### 6.3 Verified examples

| Extension | Store | Users | Capability | Risk | Decision |
|---|---|---:|---|---|---|
| Obsidian Web Clipper | Chrome | 1M | MV3, `scripting` + DNR + `<all_urls>` | Medium | Allow, monitor |
| Cookie-Editor | Chrome | 2M | `cookies` + `<all_urls>` | High | Review / restrict hosts |
| AdGuard AdBlocker | Edge | 11.5M | `webRequest` + `userScripts` + `<all_urls>` | Medium (expected) | Allow |
| Clear Browsing Data | AMO | 41K | `browsingData`, `storage` | Low | Allow |
| Google Docs Offline | Chrome | built-in | none | Built-in | Allow (never block) |
| browser-agent-bridge | AMO | 1 host | unknown (unlisted) | High | Review |

Note: unlisted ≠ malicious. Sideloaded ≠ malicious. The score explains; the analyst decides.

---

## 7. Protection

### 7.1 Decision model

| Decision | Meaning | Policy |
|---|---|---|
| `allow` | Approved baseline | `installation_mode: allowed` |
| `review` | Visible, not blocked; alert on new installs | not in policy (or `allowed` + alert) |
| `block` | Prevent install / disable existing (Firefox: prevents new installs; pair with the Mozilla blocklist for existing) | `installation_mode: blocked` |
| `force_install` | Required security extension | `installation_mode: force_installed` |

Approval is by **ID + publisher + permission ceiling**, not by name. If an approved extension adds a permission, it drops to `review` until re-approved.

### 7.2 Policy export

Chrome/Edge:

```json
{
  "ExtensionSettings": {
    "*": {"installation_mode": "allowed"},
    "cnjifjpddelmedmihgijeibhnjfabmlf": {
      "installation_mode": "allowed",
      "runtime_blocked_hosts": ["*://*.bank.example/*", "*://*.health.example/*"]
    },
    "maliciousid": {
      "installation_mode": "blocked",
      "blocked_install_message": "Blocked by Fleet Hound: known malicious."
    }
  }
}
```

Firefox:

```json
{
  "policies": {
    "ExtensionSettings": {
      "*": {"installation_mode": "allowed"},
      "badguid": {
        "installation_mode": "blocked",
        "blocked_install_message": "Blocked by Fleet Hound."
      }
    }
  }
}
```

### 7.3 Deployment

| Browser | Windows | macOS | Linux |
|---|---|---|---|
| Chrome | `HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionSettings` | `com.google.Chrome` profile key | `/etc/opt/chrome/policies/managed/extensions.json` |
| Edge | `HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionSettings` | `com.microsoft.Edge` profile key | `/etc/opt/edge/policies/managed/extensions.json` |
| Firefox | `C:\Program Files\Mozilla Firefox\distribution\policies.json` | `/Applications/Firefox.app/Contents/Resources/distribution/policies.json` | `/etc/firefox/policies/policies.json` |
| Safari | MDM app allowlist / block containing app | same | n/a |

Push via the MDM channel already used for hosts (Fleet MDM profiles, Intune, Jamf) or a startup script. Phase 1 exports the JSON; Phase 3 automates distribution.

### 7.4 Protect good-but-risky

- Allow adblockers/password managers, but `runtime_blocked_hosts` on banking/health/SSO.
- Force MV3; flag MV2 as watch.
- Alert on permission expansion, publisher change, store removal, version lag.
- Pre-block impact preview: hosts, users, teams, critical workflows.

---

## 8. API + UI

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/extensions` | GET | List with filters: `store`, `risk_band`, `decision`, `browser`, `team`, `host`, `q`, `page` |
| `/api/extensions/<store>/<id>` | GET | Detail: metadata, permissions, hosts, versions, signals, timeline |
| `/api/extensions/<store>/<id>/decision` | POST | `{decision, note}` → graph + `extension_policy.json` + audit log |
| `/api/extensions/policy` | GET | Export Chrome/Edge/Firefox JSON |
| `/api/extensions/status` | GET | Worker status, source health, last run |
| `/api/extensions/refresh` | POST | Trigger a cycle (rate-limited) |

UI: fifth tab "Extensions" (next to Shadow IT). Table columns: name, store, publisher, hosts, users, version lag, permissions badge, risk band, decision.

Detail drawer:

- Header: icon, name, publisher, store link, status.
- Risk: score, band, signal list with weights.
- Permissions: plain-English explanations, host access.
- Exposure: hosts, users, teams, version spread.
- Decision: allow/review/block + note + audit trail.
- Impact: "blocking affects N hosts / M users".

Reuse the existing Shadow IT table/filter patterns in `webviz/static/index.html`. Decisions use the same atomic temp+replace write pattern as `save_whitelist`. Decision endpoints inherit the existing LAN trust model; add authentication before exposing them beyond the LAN.

---

## 9. Roadmap

### Phase 0 — Stop dropping data (1-2 days)

- Preserve Fleet extension fields in `cleaned_software` (`src/ingestion.py:468`).
- Add `INSTALLED_ON` edge props (`version`, `source`, `browser`, `installed_path`, `first_seen`, `last_seen`).
- Add `first_seen` on `:Software`.
- Fix the whitelist lowercase bug (`webviz/app.py:2491`).
- Delete dead `_batch_create_software` (`src/ingestion.py:671`).
- Snapshot: include `versions`.
- Acceptance: `MATCH (s:Software) WHERE s.extension_id IS NOT NULL RETURN count(s)` > 0; edge props populated; no ETL slowdown.

### Phase 1 — Identity + store metadata (3-5 days)

- `src/extension_intel.py` adapters: Chrome update2 + CRX, Edge detail JSON, AMO, Mozilla blocklist.
- Manifest analyzer + capability/trust scoring.
- `webviz/extension_worker.py` with fcntl lock, cache, status.
- Schema migration to `software_key`; dedupe; constraint swap.
- Acceptance: every browser extension has `store`, `extension_id`, `latest_version`, `permissions`, `risk_score`; worker runs < 2 min for 100 extensions; failures degrade gracefully.

### Phase 2 — UI + decisions (3-4 days)

- `/api/extensions*` endpoints.
- Extensions tab + detail drawer.
- Decisions + audit log + `config/extension_policy.json`.
- Policy export (Chrome/Edge/Firefox).
- Acceptance: analyst can filter, inspect, decide, export; decision survives restart; audit log records actor/time/note.

### Phase 3 — Threat feeds + static analysis (4-6 days)

- VT/Safe Browsing/URLhaus/OTX adapters with quotas and caching.
- Domain intel: Tranco, crt.sh, RDAP, EasyList.
- Static scan: addons-linter, Tarnish, Semgrep/YARA, retire.js.
- Alerts: new extension, version change, permission expansion, store removal, blocklist hit.
- MDM push automation.
- Acceptance: blocklist hit auto-blocks; permission expansion alerts; no source exceeds quota.

### Phase 4 — Adjacent surfaces (3-5 days)

- VS Code Marketplace / Open VSX / JetBrains.
- Safari mapping via bundle ID / App Store.
- Fleet-wide dashboard: extension risk by team, top risky, coverage.
- Acceptance: IDE extensions visible with publisher/version; Safari detection-only.

Total: ~3-4 weeks for one engineer. Phase 0 is independent and safe.

---

## 10. Operational guardrails

- **SSRF:** allowlist store domains; no arbitrary redirects; timeout 15s; max 50 MB.
- **Zip bombs:** cap file count (10k) and uncompressed size (200 MB).
- **No code execution:** static analysis only; sandbox with no network.
- **Privacy:** send only public artifacts (extension ID, hash, manifest domains) to third parties; never hostnames/users.
- **Secrets:** API keys in env (`VT_API_KEY`, `SAFE_BROWSING_KEY`, `ABUSECH_AUTH_KEY`), not in `config/`.
- **Audit:** every decision logged to `config/audit.log` with actor, time, note.
- **Retention:** raw manifests 90 days; scores/decisions indefinite; cache pruned by age.
- **Rate limits:** per-source token bucket; jitter; circuit breaker.
- **Idempotency:** manifest cache keyed by `(store, id, version, sha256)`.

---

## 11. Existing bugs worth fixing on the way

| Bug | Location | Fix |
|---|---|---|
| Whitelist stores raw case, graph names are lowercased → `NOT s.name IN $whitelist` misses `Obsidian Web Clipper` | `webviz/app.py:2491` | Lowercase on save and load; migrate existing entries |
| OODA "shadow IT" proxy counts all software with ≤3 hosts, no source filter | `webviz/ooda_worker.py:245` | Add `s.sources` intersection with `SHADOW_IT_SOURCES` |
| Enricher categorizes extensions via Wikipedia | `webviz/enrich_worker.py` `_pick_uncategorized` | Fixed: `coalesce(s.kind, '') <> 'browser_extension'` |
| Snapshot omits `versions` and edge props | `src/snapshot.py:154` | Add `s.versions`; edge props in `INSTALLED_ON` lines |
| Dead `_batch_create_software` duplicates grouped logic | `src/ingestion.py:671` | Delete |
| Case-variant dedupe would merge same-named Chrome/Edge extensions | `src/ingestion.py:1418` | Gate to `software_key STARTS WITH 'name:'` |
| Shadow IT risk level is only host count (`high` if 1 host) | `webviz/app.py` outlier block | Use `risk_score` once available |

---

## 12. Open questions

1. Is Fleet Hound commercial? VirusTotal's free tier terms may not fit.
2. Which MDM channel is authoritative for policy push (Fleet profiles vs Intune/Jamf)?
3. Do we manage browser policies today? If not, Phase 3 needs an owner.
4. Should `block` auto-disable existing installs or only prevent new ones? (`blocked` vs `removed` in Chrome.)
5. Is Safari detection-only acceptable?

---

## 13. Immediate next step

Phase 0, one file: `src/ingestion.py`. Preserve the fields, add edge props, fix the whitelist lowercase bug. No schema migration, no worker, no UI. Ship it, verify on the live fleet, then start Phase 1.

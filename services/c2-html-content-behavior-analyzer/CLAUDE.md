# CLAUDE.md – C2 HTML Content & Behavior Analyzer

## Scope
- This is component **C2** of the 4-member monorepo J26-SE-316. Work **only** inside `services/c2-html-content-behavior-analyzer/`. Do not modify other services, `backend/` or `frontend/`.
- Never read or overwrite `.env` (holds secrets). Document new settings in `.env.example` and `src/c2_analyzer/config.py`.

## What C2 does
Takes raw HTML → analyzes DOM structure, multilingual text (en/si/ta, XLM-R) and static JS behavior (AST only, never execute JS) → unified JSON (`verdict`, `risk_score`, per-modality results, `findings`).
Threat classes: `benign`, `phishing`, `fake_ecommerce`, `crypto_scam`, `malware_delivery` (ids in `configs/labels.yaml`, never renumber).

## The 9 parts → code
1. Dataset preparation → `dataset/`, `scripts/build_metadata.py`, `deduplicate.py`, `dataset_stats.py`
2. HTML preprocessing → `preprocessing/` (output: `schemas.parsed_page.ParsedPage`, JSON in `data/processed/parsed_html/`)
3. DOM structural analysis → `dom/` (output: `schemas.dom.DomFeatures`)
4. DOM baseline classifiers → `classifiers/dom_baseline/`
5. Multilingual content analyzer → `content/` (language ID, intent taxonomy, corpus)
6. XLM-R classification → `nlp/` (training designed for Colab: `notebooks/04_xlmr_finetune_colab.ipynb`)
7. Static JS analyzer → `js_analyzer/` (esprima; unparsable JS must fail gracefully)
8. Behavioral intent mapping → `behavior/` (rules in `configs/sources_sinks.yaml`)
9. Fusion + API → `fusion/`, `api/`

Implement one part (or batch) at a time, when asked. See **Progress** below.

## Progress
- [x] Skeleton — all packages/stubs, `GET /health`.
- [x] **Part 1 – Batch A: dataset metadata foundation** (Tasks 1, 2, 10)
  - `data/metadata/dataset_schema.json` (JSON Schema 2020-12) ↔ `schemas/dataset.py::SampleMetadata` (pydantic twin). `tests/test_dataset_metadata.py` fails if the schema, model and configs drift apart.
  - Allowed values come only from `configs/labels.yaml`, `configs/languages.yaml` (`languages` + `special_values: mixed, unknown`) and `configs/sources.yaml`, via `config.get_labels/get_languages/get_sources`.
  - `dataset/metadata.py::MetadataStore` — the only code that touches `metadata.csv` (load/add/get/update/filter/next_sample_id/validate_all/save; atomic writes). Exact duplicates (same sha256) are rejected; a repeated `source_url` is only a warning.
  - `dataset/collector.py::register_file` + `scripts/build_metadata.py` (`register`, `validate`, `show`).
  - `file_path` is always `<label>/<file>` relative to `data/raw/`; sample ids are `c2_<label>_<6 digits>` and never reused.
- [x] **Part 1 – Batch B: sample collection tools** (Tasks 3–9)
  - Two stages: feeds/manual CSV → `data/metadata/candidates.csv` (`dataset/candidates.py::CandidateStore`, statuses pending/fetched/failed/skipped/duplicate, dedupe by `utils/url.py::normalize_url`) → fetch → `register_file` (all Batch A checks apply).
  - `dataset/feeds.py`: openphish, phishtank, urlhaus (online only, binary links filtered), tranco (top N, seeded sample, .zip ok), manual (`data/metadata/manual_urls_template.csv`). Importers read local files only; `download_feed` is the separate network helper.
  - `dataset/fetcher.py`: `StaticFetcher` (httpx; 15 s, 5 redirects, 5 MB streamed, HTML only, charset header→meta→utf-8, rate limit + per-host delay, blocks localhost/private IPs incl. redirects) and optional `RenderedFetcher` (Playwright, Docker only: `docker/fetcher.Dockerfile`, `requirements-fetcher.txt`).
  - Only 2xx pages are saved; non-benign pages redirected to another domain get a "check the label" note.
  - `utils/script_detect.py`: Unicode-range language hint (si/ta/en/mixed/unknown, thresholds in `configs/languages.yaml`) — replaced by real language ID in Part 5.
  - `dataset/collection.py` + `scripts/collect.py` (`download`, `import`, `fetch`, `retry-failed`, `progress`); targets in `configs/collection_targets.yaml`; settings in `configs/config.yaml → collection`.
  - Metadata gained optional `fetch_mode` (static/rendered/manual), `final_url`, `http_status`, `content_type`; old CSV headers are upgraded on load. `urlhaus` added to `configs/sources.yaml`. `constants.py` no longer duplicates config lists.
  - Tests use `httpx.MockTransport` only (no real network). The fetcher Docker image is not yet build-tested.
  - Windows robustness (after the first real run): pages are written to `data/tmp/` (never system Temp, so a Defender exclusion for `data/` covers them); `collection.process_candidate` never raises for one page (antivirus removal → `failed` + `blocked_by_antivirus: ...`, other errors → `failed` + `<Type>: <msg>`; Ctrl+C still stops); `utils/io.atomic_write_csv` retries `os.replace` on PermissionError (~3 s) then raises `FileSaveError`; `register_file` removes a half-copied file.
  - `collect.py failures` (reason codes from `collection.reason_code`, also printed after each fetch) and `collect.py repair [--dry-run]` (`dataset/repair.py`; never deletes raw files or edits metadata.csv).
  - URLhaus import filters (botnet tags, binary/CPU-arch extensions, bare-IP file links) live in `configs/url_filters.yaml`; `collect.py prune [--label]` re-applies them to pending candidates (→ `skipped`, `pruned_by_filter: ...`). `CandidateStore` caches its normalized-URL index.
- [x] **Part 1 – Batch C: cleaning & verification** (Tasks 11, 12)
  - Git: `data/metadata/{candidates.csv,metadata.csv,review/}` and `data/feeds/` are ignored (live scam URLs); only `dataset_schema.json` + templates are tracked.
  - Metadata gained `cluster_id` (`cl_<6 digits>`), `quality_flag` (enum in `configs/quality_rules.yaml`, read via `config.get_quality_flags`), `excluded` + `exclusion_reason` (both or neither), `label_original`. Old CSV headers are upgraded with each field's default.
  - **Relabel rule:** a sample keeps its `sample_id` forever; after a relabel the id's label part must equal `label_original` (the file moves to the new label folder). Chosen over new ids because nothing referencing the sample has to change.
  - `dataset/page_view.py`: one text-only parse per page (title, visible text, tag sequence, forms, external domains) shared by quality/dedup/review; `terminal_safe` strips control/bidi chars before printing page text.
  - `dataset/quality.py`: keyword/pattern rules from `configs/quality_rules.yaml`, first match wins, each rule limited to short pages; only sets `quality_flag`. Pages with inputs are never `empty`; captcha widgets and Cloudflare's injected `/cdn-cgi/challenge-platform` script are deliberately NOT challenge markers (real phishing pages carry them).
  - `dataset/deduplicator.py`: text word 5-grams + tag 4-grams, MinHash-LSH (threshold 0.6) for candidates, exact Jaccard + rule `text ≥ 0.90 or (dom ≥ 0.95 and text ≥ 0.70)` (config `dedup`), union-find clusters, representative = verified > longest text > oldest; mixed-label clusters = conflicts (not marked). Only usable pages (not excluded, flag ok/redirected_offsite) are compared; dedup recomputes and owns `is_duplicate_of`. Reports in `reports/dataset_stats/dedup_report.{json,csv}`. **Splits in Part 4/6 must group by `cluster_id`.**
  - `dataset/verifier.py` + `scripts/review_labels.py` (`review`, `export-peer`, `import-peer`): text-only review, saves after every decision; peer sheet hides labels/URLs (UTF-8 BOM for Excel); agreement % + Cohen's kappa (sklearn) → `peer_agreement.json`.
  - `dataset/safe_preview.py` + `scripts/safe_preview.py`: sanitized `_safe.html` in `data/metadata/review/` (drops script/iframe/meta/base/link, unwraps object/embed/noscript, strips on* and all URL attributes, CSS url()/@import, strict CSP, red banner).
  - `scripts/deduplicate.py` (`quality`, `dedup`, `all`, each `--dry-run`).
- [x] **Part 1 – Batch D: statistics & dataset versions** (Task 13) → **Part 1 done**
  - Views (`dataset/views.py::select_view`, shared by stats and manifests): **all** = every row; **usable** = not excluded and `quality_flag` in (ok, redirected_offsite); **clean** = usable and `is_duplicate_of` empty (one row per cluster) = what models train on.
  - `dataset/statistics.py`: per view counts (label, language, label×language, source, fetch_mode), verification %, quality flags, exclusions, clusters (top 10 with 2+ pages), relabel matrix, imbalance (ratio None if a class is empty), page stats via `page_view` (size/text median+p90, forms, % password, % script; each page parsed once), timeline; readiness of the CLEAN view vs `collection_targets.yaml`; `peer_agreement.json` summary.
  - `dataset/stats_report.py`: `reports/dataset_stats/dataset_stats.{json,md}` + 6 PNGs in `figures/` (matplotlib `Figure` API → Agg, 150 dpi, never opens a window).
  - `dataset/manifest.py`: `freeze` writes `data/metadata/manifests/dataset_<version>.{csv,json}` (clean view; sample_id, label, language, cluster_id, sha256, file_path; JSON has counts, git commit (+`-dirty`), notes, fingerprint). Never overwrites; refuses missing/changed files. `verify` re-hashes every file. Manifests have no URLs and are tracked in git. Stats report `dataset_version` = the frozen version whose fingerprint matches the clean view, else `unfrozen`.
  - `scripts/dataset_stats.py` (`stats [--view]`, `freeze --version [--notes]`, `verify --version`).
  - **Later parts must read a frozen manifest (not metadata.csv) and record its version.** Train/val/test splits are built in Part 4 from the manifest, grouped by `cluster_id` (the old `split_dataset` stub was removed from statistics.py).
- [x] **Part 2 – HTML preprocessing pipeline** (Tasks 1–12)
  - Principle: Part 2 EXTRACTS and ORGANIZES, never judges (no "suspicious" flags); never runs JS, never fetches anything. Same `pipeline.preprocess` for a manifest sample (`loader.from_sample`) and an HTML string + optional URL (`pipeline.preprocess_html`, for the Part 9 API).
  - `schemas/parsed_page.py::ParsedPage` (schema_version "1.0"): meta (sample_id, page_url, base_url = `<base href>` > final_url > source_url, dataset_version, parser_used, processing_ms + step_ms, html_size_bytes, source_sha256, domain_method, truncated + reasons, errors), title/meta tags (refresh `redirect_url` resolved), headings, paragraphs, visible_text, hidden_text, links, forms (+inputs/labels/buttons), inputs_outside_forms, css summary, comments summary, scripts_inline, structured_data (JSON-LD/JSON), templates, event_handlers, javascript_urls, scripts_external, embedded, dom (counts, depth, tag_counts, skeleton ≤3000 nodes/depth 40). JSON aliases: `async`, `class`; skeleton omits empty fields.
  - Modules in `preprocessing/`: `settings` (config `preprocessing`), `loader` (5 MB cap → truncated), `parser` (lxml → html.parser → empty; NUL → U+FFFD), `cleaner` (comments removed+counted; CSS summarised, `style=""` kept for Part 3), `text_utils` (NFC, keep ZWJ/ZWNJ, drop U+200B/FEFF/2060/180E + C0/C1 except 
	, block newlines), `visibility` (hidden attr, aria-hidden, inline display/visibility/opacity/font-size; CSS rules NOT evaluated), `text_extractor` (stack walk, no recursion), `form_extractor` (empty/`#` action = page URL, `javascript:` → None, labels via for/wrapping/aria-label, `form="id"` inputs), `script_extractor`, `dom_extractor`, `pipeline` (each step isolated + timed; a failing step → `meta.errors`, partial result), `batch` (manifest run), `report` (summary + `describe_page`).
  - `utils/url.py`: `registrable_domain` via tldextract OFFLINE (`suffix_list_urls=()`, private suffixes like pages.dev included), built-in fallback rule if not installed; `is_external` (unknown page URL → absolute links external). `utils/pii.py`: `mask_pii` ([EMAIL], [NIC] old/new, [CARD] Luhn-checked, [PHONE] incl. +94/07X) and `mask_url` (query values + fragment only) – applied to prefilled input values (passwords → `[REDACTED]`) and stored URLs, never to page text. `utils/io.atomic_write_text/write_json`.
  - Outputs: `data/processed/parsed_html/<version|adhoc>/<sample_id>.json` (+ `.txt` visible text); skip if same source_sha256 + schema_version + domain_method (`--force` redoes). Reports: `reports/preprocessing/<version>_summary.{json,md}`.
  - `scripts/preprocess_html.py`: `run --version [--label --limit --workers --force]` (refuses if manifest verify fails; ProcessPoolExecutor with spawn), `one --sample-id | --file [--url] [--save]`.
  - Fixed on the way (Part 1): `MetadataStore.add` copies the frame after the first row (pandas 3 made it read-only, so `update` failed).
  - Fixed after Part 2 (7 tests were failing with tldextract 5.4): `domain_of_host` uses the built-in rule for a well-formed host whose suffix is not on the PSL (`.example`, `.test`, `.local`); a host that IS a suffix (`s3.ap-southeast-1.amazonaws.com`) or is malformed stays whole. `visibility.is_hidden_in_tree(cache=...)` + precomputed form/label membership in `form_extractor` remove quadratic ancestor walks (1 MB nested page 3.5 s → 1.5 s). All 278 stored v0.1 JSONs are byte-identical with the new code (timing aside), so no re-run was needed.
- [x] **Developer inspector + Part 2 API** (after Part 2, before Part 3)
  - Public (stays for Part 9): `POST /api/v1/preprocess` `{html, url?}` → ParsedPage JSON (same bytes/aliases as stored files; `url` never fetched). `api/security.py`: `BodySizeLimitMiddleware` (config `api.max_body_bytes` 5 MB → 413, checks Content-Length AND streamed bytes) and `SecurityHeadersMiddleware` (nosniff + no-referrer on every response).
  - `api/main.py::create_app(app_env)`; dev routes (`api/dev_routes.py`) are registered ONLY when APP_ENV=development (otherwise 404, not in OpenAPI). Dockerfile sets `APP_ENV=production`. Tests build apps with `create_app("development"/"production")` and override `dependencies.get_dev_dataset`.
  - `GET /api/v1/dev/versions | samples?version&label&language&q&has_password&external_form_action | samples/{id}/parsed?version | samples/{id}/safe-preview?version` backed by `api/dev_data.py::DevDataset` (READ ONLY; manifest + stored JSON, per-file summary cache keyed by mtime/size; missing JSON → processed on the fly, not saved, header `X-Parsed-Source`; ids validated against pattern AND manifest; raw paths must stay in data/raw). Response models in `schemas/inspector.py`. Safe preview = Part 1 `sanitize_html` with CSP `default-src 'none'; style-src 'unsafe-inline'` + nosniff.
  - `GET /inspector` → `api/static/inspector.html` + `inspector.js` (vanilla, offline, CSP `script-src 'self'`). **XSS rule:** API values only via `el()`/textContent; no HTML-parsing sinks (grep test in `tests/test_inspector.py`); `el()` refuses href/src/on* attrs; page URLs are plain text; Safe Preview is an `<iframe sandbox="">`.
  - `scripts/run_api.py`: binds 127.0.0.1 (`--host` to change, warns if dev + non-loopback), port from API_PORT (8002), chdirs to the service folder so `.env` is found, prints the URLs.
  - **Inspector: add a tab per future part.** In `inspector.js` call `registerTab({id, title, render(ctx, box)})` (replace the disabled placeholder: "Content / NLP (Part 5–6)", "JS Behavior (Part 7–8)", "Unified Result (Part 9)"); add a dev endpoint for the part's output (e.g. `samples/{id}/dom-features`) in `dev_routes.py` + `DevDataset`; render with the text-only helpers; extend `tests/test_inspector.py`.
- [x] **Part 3 – DOM structural analysis** (Tasks 1–14)
  - Principle: ParsedPage → FIXED-ORDER numeric vector + evidence. Raw HTML is re-parsed (Part 2's `parse_html`) only for tree metrics Part 2 doesn't store (avg depth, leaf ratio, hidden elements); Part 2 visibility helpers reused. No ML (Part 4), no JS semantics (Part 7, scripts only counted). One entry point: `dom/pipeline.py::extract_dom_features(page, html=None)` (`dom_features_for_html` for the API).
  - **`configs/dom_features.yaml` is the single source of truth** (`feature_set_version: dom_v1`, 52 features in 11 groups): order = CSV/vector order; each feature has type (int/float/binary), description (viva), source, `needs_page_url`, optional evidence template `{message, severity high|medium|info, min_value}`. Also `field_rules` (classes password > card > otp_pin > email > username; types/autocomplete/patterns/exclude, en+si+ta + a few zh/ko/ru kit words), `known_form_services`, `hidden_elements` (offscreen_px, never_visible_tags), `report` thresholds. Rename/reorder/add → bump feature_set_version. `dom/dictionary.py` loads + validates; `dictionary_hash()` decides skip/redo.
  - Rules: unknown page URL → every `needs_page_url` feature 0 and `base_url_known=0`; zero denominators → 0.0; never NaN (`vectorizer.build_vector` raises on unknown/missing/non-finite/non-0-1 binary). Feature groups are isolated (a failing group → its features 0 + `errors`). hidden_element_count = elements hiding THEMSELVES (descendants not recounted; input type=hidden excluded). null link = empty/#…/javascript:; external_link_ratio = external / (internal + external web links). sensitive = password + otp_pin + card. Field classes never look at values (PII stays masked).
  - Modules: `tree` (DomTree; agrees with Part 2 counts on all 278 v0.1 pages), `form_features`, `element_features`, `link_features`, `vectorizer`, `evidence`, `pipeline`, `exporter`, `batch`, `report`. Output schema `schemas/dom.py::DomResult` (+ `EvidenceItem`); old fixed-field `DomFeatures` removed.
  - Outputs: `data/processed/dom_features/<version>/{dom_features.csv (sample_id, label, language, cluster_id + features), <sample_id>.json, feature_dictionary.json}`; CSV is always rebuilt from ALL valid stored results (a `--label` run never shrinks it). Missing/stale Part 2 JSON is produced and SAVED by the Part 3 run. `reports/dom_features/<version>_summary.{json,md}` + `figures/` (box plots of the top 12 by mutual information, correlation heatmap); constant / near-constant (≥95 %) / |r|>0.95 warnings. Descriptive only.
  - CLI `scripts/extract_dom_features.py run --version [--force --workers --label --limit --parsed-dir]`, `one --sample-id | --file [--url]`, `describe [--markdown]`. Part 2 `batch.run_tasks` gained a `worker=` parameter (shared runner).
  - API: public `POST /api/v1/dom-features {html, url?}` → DomResult; dev `GET /api/v1/dev/samples/{id}/dom-features` (stored or on-the-fly, `X-Features-Source`) and `GET /api/v1/dev/dom-dictionary?version` (dictionary + per-label medians from the report, only if its dictionary hash matches). Inspector tab "DOM Features (Part 3)": evidence first, non-zero features per group with label medians, "Show all features" table; a tab's render() may be async.
  - v0.1 (278 pages): 0 failures, ~19 ms/page, 3.5 s wall. Strongest descriptive separators: internal_link_count, node_count, link_count, element_count, avg_depth. Constant on v0.1: base_url_known, meta_refresh_external. Part 4: decide drops on the TRAIN split only; the credential/form-action features are near-constant in v0.1 (few positives).
- [ ] Parts 4–9

## Conventions
- Python ≥ 3.11, src layout, package `c2_analyzer`. Absolute imports (`from c2_analyzer.x import y`).
- Each module docstring states its purpose and Part number; keep that when implementing.
- Data contracts between stages are pydantic models in `schemas/` — change them there, not ad hoc dicts.
- Tunables live in `configs/*.yaml`; env-specific settings in `config.Settings`.
- `scripts/` are thin argparse wrappers; all logic goes in `src/`.
- A failing modality must not fail the request: the aggregator reports it in `missing_modalities`.
- Tests in `tests/`, fixtures in `tests/fixtures/sample_pages/`. Remove the `pytestmark = skip` from a part's test file when implementing it.
- Formatting: black + ruff, line length 100.

## How to run
```bash
python -m venv .venv && .venv\Scripts\activate      # Windows
pip install -r requirements.txt -r requirements-dev.txt && pip install --no-deps -e .
pytest
python scripts/run_api.py          # 127.0.0.1:8002 -> /inspector (APP_ENV=development), /docs
```
Port **8002** (C3 uses 8003, C4 uses 8000). The inspector is a developer tool only; the team dashboard (`frontend/scamtrace-dashboard`) is separate and not touched by C2.

## Integration note
`backend/api-gateway/src/server.js` calls `POST ${C2_URL}/analyze-html` with `{ url }`, while C2's main contract is `POST /api/v1/analyze` with `{ html, url? }`. `/analyze-html` is a 501 stub kept for compatibility; reconcile the contract with the team in Part 9.

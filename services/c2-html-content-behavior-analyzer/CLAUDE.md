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
7. Static JS analyzer → `js_analyzer/` (tree-sitter AST + lexical fallback; unparsable JS must fail gracefully)
8. Behavioral intent mapping → `behavior/` (sources / sinks in `configs/sources_sinks.yaml`, patterns in `behavior_patterns.yaml`, vector in `behavior_features.yaml`)
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
  - `utils/script_detect.py`: Unicode-range language hint (si/ta/en/mixed/unknown, thresholds in `configs/languages.yaml`) — still used by collection; the authoritative language is Part 5's `content/language.py`.
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
  - **Inspector: add a tab per future part.** In `inspector.js` call `registerTab({id, title, render(ctx, box)})` (replace the disabled placeholder: "XLM-R / NLP (Part 6)", "Unified Result (Part 9)"); add a dev endpoint for the part's output (e.g. `samples/{id}/dom-features`) in `dev_routes.py` + `DevDataset`; render with the text-only helpers; extend `tests/test_inspector.py`.
- [x] **Part 3 – DOM structural analysis** (Tasks 1–14)
  - Principle: ParsedPage → FIXED-ORDER numeric vector + evidence. Raw HTML is re-parsed (Part 2's `parse_html`) only for tree metrics Part 2 doesn't store (avg depth, leaf ratio, hidden elements); Part 2 visibility helpers reused. No ML (Part 4), no JS semantics (Part 7, scripts only counted). One entry point: `dom/pipeline.py::extract_dom_features(page, html=None)` (`dom_features_for_html` for the API).
  - **`configs/dom_features.yaml` is the single source of truth** (`feature_set_version: dom_v1`, 52 features in 11 groups): order = CSV/vector order; each feature has type (int/float/binary), description (viva), source, `needs_page_url`, optional evidence template `{message, severity high|medium|info, min_value}`. Also `field_rules` (classes password > card > otp_pin > email > username; types/autocomplete/patterns/exclude, en+si+ta + a few zh/ko/ru kit words), `known_form_services`, `hidden_elements` (offscreen_px, never_visible_tags), `report` thresholds. Rename/reorder/add → bump feature_set_version. `dom/dictionary.py` loads + validates; `dictionary_hash()` decides skip/redo.
  - Rules: unknown page URL → every `needs_page_url` feature 0 and `base_url_known=0`; zero denominators → 0.0; never NaN (`vectorizer.build_vector` raises on unknown/missing/non-finite/non-0-1 binary). Feature groups are isolated (a failing group → its features 0 + `errors`). hidden_element_count = elements hiding THEMSELVES (descendants not recounted; input type=hidden excluded). null link = empty/#…/javascript:; external_link_ratio = external / (internal + external web links). sensitive = password + otp_pin + card. Field classes never look at values (PII stays masked).
  - Modules: `tree` (DomTree; agrees with Part 2 counts on all 278 v0.1 pages), `form_features`, `element_features`, `link_features`, `vectorizer`, `evidence`, `pipeline`, `exporter`, `batch`, `report`. Output schema `schemas/dom.py::DomResult` (+ `EvidenceItem`); old fixed-field `DomFeatures` removed.
  - Outputs: `data/processed/dom_features/<version>/{dom_features.csv (sample_id, label, language, cluster_id + features), <sample_id>.json, feature_dictionary.json}`; CSV is always rebuilt from ALL valid stored results (a `--label` run never shrinks it). Missing/stale Part 2 JSON is produced and SAVED by the Part 3 run. `reports/dom_features/<version>_summary.{json,md}` + `figures/` (box plots of the top 12 by mutual information, correlation heatmap); constant / near-constant (≥95 %) / |r|>0.95 warnings. Descriptive only.
  - CLI `scripts/extract_dom_features.py run --version [--force --workers --label --limit --parsed-dir]`, `one --sample-id | --file [--url]`, `describe [--markdown]`. Part 2 `batch.run_tasks` gained a `worker=` parameter (shared runner).
  - API: public `POST /api/v1/dom-features {html, url?}` → DomResult; dev `GET /api/v1/dev/samples/{id}/dom-features` (stored or on-the-fly, `X-Features-Source`) and `GET /api/v1/dev/dom-dictionary?version` (dictionary + per-label medians from the report, only if its dictionary hash matches). Inspector tab "DOM Features (Part 3)": evidence first, non-zero features per group with label medians, "Show all features" table; a tab's render() may be async.
  - v0.1 (278 pages): 0 failures, ~19 ms/page, 3.5 s wall. Strongest descriptive separators: internal_link_count, node_count, link_count, element_count, avg_depth. Constant on v0.1: base_url_known, meta_refresh_external. Part 4: decide drops on the TRAIN split only; the credential/form-action features are near-constant in v0.1 (few positives).
- [x] **Part 4 – DOM baseline classifier** (Tasks 1–9) - PILOT on v0.1 ("Baseline 1" of the ablation study)
  - **Shared split `dataset/splits.py` (used by EVERY later part):** `data/splits/<version>/{split.csv, split.json, cv_folds.csv}` (tracked: ids/labels only). By sample_id from the frozen manifest, never by modality. StratifiedGroupKFold makes 20 cluster-pure pieces stratified by label × language; a seeded search (2000 tries) picks which pieces are val/test (ratios + label mix + si/ta spread). No cluster in two splits. Classes < `split.min_samples_per_class` (15) → split="excluded", listed in split.json (`pilot: true`). Refuses to overwrite without `--force`, refuses a manifest that no longer verifies; `check_current` refuses a split made from another manifest fingerprint. `cv_folds.csv` = grouped stratified 5-fold over train+val (test never in a fold). Config `split:` in config.yaml (seed = project.random_seed).
  - `classifiers/dom_baseline/`: `common` (BaselineConfig from `configs/dom_baseline.yaml` + config.yaml `dom_baseline:` paths/n_jobs; bundles = plain dicts in joblib; `readable_name` = first sentence of the dictionary description + [name]), `data` (feature CSV must equal feature_dictionary.json AND the current dictionary hash; labels in labels.yaml order restricted to included classes, contiguous 0..k-1; cleaning on TRAIN only: constant + |r| > 0.98 → drop the later one), `train` (grid per model, selected by mean macro-F1 over cv_folds, refit on train+val; LR = StandardScaler + lbfgs multinomial balanced; RF balanced_subsample, `n_jobs: 1` (threads slower on ~200 pages); XGB multi:softprob hist + balanced sample weights), `evaluate` (metrics, benign FPR, per-language with small-n flag, confusion PNG/text, misclassified rows), `importance` (LR std. coefficients, RF impurity + permutation on test, XGB gain + SHAP global/beeswarm; per-page `contributions`: LR coef×z, trees TreeExplainer), `predict` (`predict_features` → `schemas/dom_baseline.py::DomPrediction`; best model = highest CV macro-F1), `report` (`run_report`: checks bundles vs current split/features/classes/dictionary (StaleModelError), evaluates test ONCE, writes reports + model card).
  - Outputs: `models/dom_baseline/<v>/{logreg,random_forest,xgboost}.joblib` (git-ignored) + `model_card.json`, `label_mapping.json`, `features.json` (tracked; `.gitignore` ignores `models/**` except these); `reports/dom_baseline/<v>/{results.json, results.md, misclassified.csv, dropped_features.csv, figures/}`.
  - **Reuse:** the protocol is modality-independent; a `FeatureSource` (common.py) says which feature table to load and how to name / fingerprint it (DOM = `sources.DOM_SOURCE`, default). Part 8's behavior-only baseline passes its own.
  - CLI `scripts/train_dom_baseline.py split|train|evaluate|all|predict` (`all` = split if missing → train → evaluate+importance+report; `predict --sample-id | --file [--url] [--json]` uses XGBoost SHAP for the explanation).
  - API/inspector: dev `GET /api/v1/dev/samples/{id}/dom-prediction` (404 no models, 409 stale), `samples?misclassified=true` (best model's test mistakes; `SampleSummary.misclassified`). DOM Features tab has a "DOM baseline prediction (Part 4)" card (PILOT badge, probability bars, top 5 pushes towards/away); sidebar checkbox "misclassified (test)".
  - v0.1 pilot (3 classes; fake_ecommerce/crypto_scam excluded, 0 pages): split 194/42/42, si 6/2/1, ta 1/1/1. 52 → 47 features (dropped base_url_known, meta_refresh_external constant; element_count, has_external_form_action, form_action_to_known_form_service correlated). CV macro-F1 LR 0.747±0.030, RF 0.797±0.011 (best), XGB 0.788±0.024; test macro-F1 0.716 / 0.755 / 0.753; benign FPR 25 % / 10 % / 10 % (target ≤ 2 % NOT met). Run takes ~40 s.
- [x] **Part 7 – Static JavaScript intent analyzer** (Tasks 1–15). Order note: Parts 7/8 are done before Parts 5/6 while the multilingual corpus is being collected (approved by the supervisor).
  - **Principles (module docstrings):**
    - NEVER execute JS and NEVER fetch external scripts (the proposal's "lightweight, no sandbox" claim).
    - Part 7 DETECTS API usage + evidence and does not decide intent (that is Part 8, which builds on detections' locations / args / assigned_to / enclosing_function).
    - One entry point, `js_analyzer/pipeline.py::analyze_js(page)` (`js_analysis_for_html` for the API).
  - **Inputs (`extractor`):** reuses Part 2's ParsedPage.
    - `scripts_inline` (JSON-LD / templates already separated), `event_handlers` (source="event_handler") and `javascript_urls` (percent-decoded, source="javascript_url").
    - External scripts are reference-level only: domain, same site, async / defer, integrity, `known_cdn`, a library guess from the file name, and flags raw_ip / free_hosting / data_url (= `suspicious_host`) plus insecure_http.
  - **Parser (`ast_parser`):** tree-sitter 0.25 + tree-sitter-javascript 0.25 (requirements.txt; esprima removed).
    - Size: 500 KB cap per script (`truncated`). A truncated script with errors is retried at the last line / `;` / `}` before the first ERROR.
    - **Timeout:** `timeout_micros` per parse, Windows-safe. The new `progress_callback` API segfaulted on Windows, and the deprecation warning is silenced.
    - `has_error`, `error_ratio` (bytes in the outermost ERROR / MISSING nodes); more than 0.5 means unusable.
    - **Lexical fallback** (`lexical_scanner`): runs on unusable trees, timeouts, or a missing tree-sitter. Its regexes are in js_rules.yaml (`apis.<id>.lexical`, CASE-SENSITIVE), comments are blanked first, and results have confidence="low".
    - `visitor.AstWalker`: an iterative TreeCursor walk with `max_ast_depth` and an inside-ERROR flag.
  - **Detectors (`detectors`, helpers in `syntax`):**
    - `callee_path` normalizes `window` / `self` / `top` / `parent` / `globalThis` prefixes, `a["b"]`, `(0, eval)` and `document.location`.
    - Per-script aliases, in source order without scopes: `var e = eval`, the storage / document objects, `new XMLHttpRequest`, `new Image`, `createElement(img / a / meta)`, and element lookups (`var p = getElementById("password")` → `<el #password>`).
    - `x.value` is only recorded on a known element: a selector, an element alias, `target` / `elements` / `forms`, `this` in handlers, or a credential-like name. In minified bundles `e.value` is usually not an input.
    - `x.constructor()` only counts with a string argument (or a `.constructor.constructor` chain).
    - Image beacons need an image receiver plus query or concatenated data.
    - `pushState` is only recorded with an EXTERNAL URL.
    - Escape-heavy strings only count escapes that hide ASCII letters / digits / spaces; JSON-escaped Arabic text or `\u002F` is not counted.
    - API catalogue: `configs/js_rules.yaml` (categories, apis + descriptions, lists, library signatures, limits, obfuscation thresholds). `rules_hash()` = both YAMLs + `ANALYZER_VERSION` + parser version, and decides skip / redo.
  - **Libraries (`libraries`):** recognised by a `banner` in the first 3 KB, or a `marker` in a SHORT script (`max_chars`, so a kit padded behind a GTM snippet is not hidden), or by `src` patterns. Their detections are kept with `in_library=true` and excluded from page-own counts / features / flags.
  - **`obfuscation`:** descriptive statistics.
    - Measures: entropy, lines, whitespace, non-alphanumeric share, ASCII-hiding `escape_ratio`, identifier statistics, `_0x` ratio, string array size.
    - `minified` is a separate flag from `signatures` (packer, jjencode, aaencode, eval_of_decoded, base64_blob, jsfuck, hex_identifiers, string_array, escape_heavy).
    - String scanning is LINEAR (`string_lengths`; a regex was quadratic on unclosed quotes, 72 s for one page).
  - **Schema:** `schemas/js.py::JsAnalysisResult` (js_v1): meta, scripts[], external_scripts[], detections[] (capped at 3000 per page, counts complete), counts (page_own / library), summary flags, features, limitations. The old `JsFinding` / `JsFindings` were removed and the Part 8 stubs now take `JsAnalysisResult`.
  - **Features:** `configs/js_features.yaml` (js_v1, 51 features in 12 groups).
    - Each is `count: {apis, categories, access, external, credential}` over page-own detections, or `compute:` (`features.py`).
    - Outputs: `data/processed/js/<v>/{<id>.json, js_features.csv, js_feature_dictionary.json}`; batch rules as in Part 3 (verify, Part 2 produced + saved if missing, skip by sha + rules_hash + mtime, CSV always complete).
    - Report: `reports/js_analysis/<v>_summary.{json,md}`, with per-page times taken from the stored results.
  - **CLI:** `scripts/analyze_js.py run|one|describe`. API: public `POST /api/v1/js-analysis` (Swagger examples) and dev `GET /api/v1/dev/samples/{id}/js-analysis` (`X-Js-Source`, `DevDataset.js_root`). Inspector tab "JS Analysis (Part 7)" with snippets via textContent only.
  - **v0.2 run (306 pages):**
    - 0 failures; parse success 99.6 % (23 of 6,039 lexical; the 4 truncated 500 KB data scripts end inside strings, 19 are broken handlers).
    - Library scripts: 5.9 %. Time: avg 47 ms, median 8 ms per page; 5.4 s wall with 4 workers.
    - Phishing vs benign (page-own): credential read 19.5 % vs 2.6 %, external request 16.1 vs 4.5, external redirect 11.5 vs 0.6, key listener 26.4 vs 9.7.
    - malware_delivery has 42–44 % for `location.replace` / beacons / XHR / decoding (one kit family).
- [x] **Part 8 – Behavioral intent mapping** (Tasks 1–12) + behavior-only baseline, on v0.3 (5 classes)
  - **Principles (module docstrings):**
    - Part 7 says WHAT APIs are used; Part 8 says what the code is TRYING TO DO by linking SOURCE (sensitive data) → FLOW → SINK. A single API is never a pattern (fetch alone is normal; reading #password.value is what validation does).
    - Static only, no network. Re-parses with Part 7's `parse_js` (same limits → same tree → Part 7 byte ranges map to nodes, `code_index.find_node`); sources / sinks come from Part 7's detections (Part 8 only matches what Part 7 does not record: event.key in key listeners, navigator / screen fingerprint props, location.href reads, jQuery serialize, ws.send).
    - Lightweight, explainable intra-page taint analysis, NOT an interpreter; the limitations are listed in every result.
    - One entry point, `behavior/pipeline.py::map_behavior(page, js_result)` (`behavior_for_html` for the API). It refuses a Part 7 result of another page (sha / script list).
  - **Modules (`behavior/`):**
    - `rules` (3 YAMLs validated, every Part 7 api id checked; `rules_hash` = YAMLs + Part 3 field_rules + `ANALYZER_VERSION` "8.2").
    - `code_index` (scopes per function, block scopes NOT modelled; functions + params; string constants; preventDefault / debugger / click / href / history / devtools facts).
    - `triggers` (auto / user / unknown).
    - `sources_sinks` (`PageFields` looks JS selectors up in Part 2 forms with Part 3's `classify_field`; sink destinations from the literal URL or a string constant; known endpoints).
    - `dataflow` (`TaintEngine`); `patterns` (`PatternMatcher`); `intent_vector`; `batch`, `report`, `baseline`.
  - **Configs:**
    - `configs/sources_sinks.yaml`: 11 sources with sensitivity; 16 sinks with destination.
    - **`exfil_endpoints`** with kind: `collector` (Telegram, Discord / Slack webhooks, ngrok, webhook.site, pipedream …) vs `form_service` (Formspree, Getform, Web3Forms, EmailJS, Google Apps Script …).
    - `propagation` (encoders, pass-through calls, mutators, callbacks, non-propagating methods).
    - `events` (user vs auto; message / error / focus stay unknown).
    - `limits` (6 passes, 12 steps, 6 labels per value, 2000 vars per script, 4000 nodes per expression, 2 s per script, 5 s per page).
    - `configs/behavior_patterns.yaml`: patterns with variants (severity + message template), factors, risk weights, crypto / ClickFix regexes, risky extensions, active-content regex. `configs/behavior_features.yaml`: beh_v1, 39 features.
  - **Taint:**
    - **Labels:** a label per (scope, variable) = source + evidence steps (source / assign / concat / call / encode / sink) + encodings + via_function / via_object.
    - **What propagates:**
      - declarations and destructuring, `=` and `+=`;
      - concatenation, template literals, object and array literals;
      - `obj.p = v` taints obj; `push` / `append` / `set` / `Object.assign`;
      - pass-through calls; encoders, which mark the flow "encoded";
      - user functions by NAME (parameters + return), `.then` / `forEach` callbacks;
      - HTML handlers see inline-script globals.
    - **What does not:** comparisons, `.length`, `includes()` and the like are not data.
    - **Passes:** flow-insensitive but ordered fixed-point passes. Each nested helper call needs one more pass, so the cap is 6.
    - **Steps:** de-duplicated only when identical (line AND column; minified one-line code keeps its chain).
    - **Lexical scripts:** a sensitive source + a sink in the same script = co-occurrence flow, confidence low.
    - **Decoded strings:** recorded only into code_execution / html_injection / download sinks.
    - **Confidence:** high = direct, ≤ 4 steps; medium = function / object; low = regex-only or inside an ERROR region.
  - **Credential rules (from the v0.3 false-positive review):**
    - **Forms:** a form is a credential form only with a "secret" class (password / card / otp_pin). Email-only forms are newsletters, so `form_data_generic`; an unresolved FormData is also generic.
    - **Identity-only flows:** flows with only email / username are one level lower, two for a `form_service`; a `collector` stays critical.
    - **Keystrokes:** only per-key properties count (event.key / keyCode / which / code / charCode / data). A typed value read in an input listener is `user_input` (search-as-you-type is not a keylogger).
    - **Decode → HTML:** high only when the statically decoded literal contains active content (`<script`, `<iframe`, `on*=`, javascript:, eval). A dynamic decode is medium; decoded CSS / markup is no finding. Decode → eval through more than 6 steps is medium.
  - **Severities:**
    - credential_exfiltration is critical (external / collector / redirect URL / external form action), high for an unknown destination, medium for form data without credentials. Factors: known endpoint, encoded, submit handler with preventDefault().
    - keylogging: critical to the network, medium to storage.
    - forced_redirect: high (automatic, after credentials, history hijack, meta refresh); cloaking medium.
    - clipboard: ClickFix critical; wallet in a copy listener / auto critical, on a click high; copy_rewrite / clipboard → network high.
    - suspicious_download: risky + auto high (+1 if the content is decoded), risky + click medium.
    - obfuscated_execution: decode → exec / active HTML high; packed / entropy ≥ 5.5 + eval medium; minified never counts.
    - anti_analysis: low, several medium.
    - `behavior_risk_score` = capped sum of each pattern's highest-severity weight (50 / 25 / 10 / 3). It is descriptive.
  - **Schema** `schemas/behavior.py` (behavior_v1): `BehaviorResult` = meta (+ js_rules_hash, rules_hash, truncated, warnings), summary, sources_found, sinks_found (with trigger), flows (path of `FlowStep`), findings (sorted by severity, evidence = numbered chain), intent_vector, behavior_risk_score, top_findings (≤ 5 lines for Part 9), errors, limitations. The old stubs were replaced.
  - **Outputs:** `data/processed/behavior/<v>/{<id>.json, behavior_features.csv, behavior_feature_dictionary.json}`. Batch rules as in Part 7; it also runs and saves Part 2 / Part 7 for missing samples and rebuilds Part 7's CSV then. Skip uses sha + Part 8 hash + Part 7 hash + mtimes. Report `reports/behavior/<v>_summary.{json,md}` (per-label pattern / severity tables, flows, top 10 critical, benign false-positive list, timing).
  - **Behavior-only baseline:** Part 4 was generalized with `classifiers/dom_baseline/common.py::FeatureSource` (DOM = `sources.DOM_SOURCE`, the default; `BaselineConfig.load(source)` reads that source's config.yaml section). `behavior/baseline.py::BEHAVIOR_SOURCE` = js_features + behavior_features joined on sample_id, both checked against their rule hashes. The protocol is the same (shared split, grids, CV selection, one test evaluation, report, model card), plus `comparison.{json,md}`. Re-running the DOM v0.3 baseline after the refactor gave results.json / model_card.json identical to the committed ones (timestamps aside).
  - **CLI:** `scripts/map_behavior.py run|one|describe|train-baseline`. API: public `POST /api/v1/behavior` (Swagger examples), dev `GET /api/v1/dev/samples/{id}/behavior` (`X-Behavior-Source`, `DevDataset.behavior_root`), `samples?has_critical_behavior=`. Inspector tab "Behavior (Part 8)": risk gauge, severity-coloured finding cards with numbered evidence chains (text only), flows table, intent vector, sinks with triggers; sidebar checkbox "has critical behavior finding".
  - **v0.3 run (459 pages):**
    - 0 failures, 26 s wall with 4 workers; median 15 ms, p95 2.2 s, max 3.5 s per page.
    - 39 pages truncated: 34 are large minified bundles where taint still grows after 6 passes, 5 hit the path cap.
    - **0 of 227 benign pages have a critical / high finding.**
    - Phishing: credential exfiltration on 13.8 % (most go to a Telegram bot / form-service endpoint), forced redirect 8.0 %, critical / high on 14.9 %. No keylogging / clipboard / download pattern occurs in v0.3.
  - **Baseline v0.3 (test 68 pages):** behavior-only best RF test macro-F1 0.682 (CV 0.620 ± 0.078, benign FPR 20.6 %) vs DOM-only RF 0.786 (benign FPR 17.6 %); 90 → 70 features after train-only cleaning. crypto_scam is the weakest class (F1 0.29).
- [x] **Part 5 – Batch A: content extraction + language ID** (Tasks 1–9), on v0.3
  - **Principles (module docstrings):** Part 5 prepares TEXT for Part 6 and does not classify. It reuses Part 2's ParsedPage and `text_utils` (NFC, ZWJ / ZWNJ kept). Raw HTML is re-parsed (Part 2 `parse_html` + visibility helpers) ONLY for CTA / alert facts Part 2 doesn't store (`content/cta.py`: class btn/button/cta, role=button, role=alert / aria-live=assertive). One entry point `content/extractor.py::extract_content(page, html=None)` (no html → CTAs from Part 2 buttons + links, `meta.cta_source="parsed_page"`); `content_for_html` for the API.
  - **Schema** `schemas/content.py::PageText` (`text_v1`): meta (sample_id, dataset_version, rules_hash, source_sha256, cta_source, dropped counts, truncation, errors / warnings; NO URLs), `language: PageLanguage` (language, confidence, method, backend, shares, script_ratios, lang_attr as a hint), `segments: TextSegment[]` (segment_id s0001…, field, level, text, order, chars, count, language, lang_confidence, lang_method, script_mix), counts per field, chars, has_cta, has_form_labels, empty, page_text (+ chars / truncated). `ContentResult` (Part 6 stub) unchanged.
  - **Extraction** (`configs/content.yaml`): fields title, meta_description, heading, cta, form_label (Part 2 label_text, which already includes aria-label), placeholder, alert_banner (role=alert or ≤ 220 chars with an urgency marker en/si/ta), paragraph, visible_other (visible_text lines), hidden. Filled in `field_priority` order: text taken by an earlier field is dropped later (`covered_by_other_field`); a visible line made only of taken texts (a form row) is dropped too; repeats inside a field → one segment with `count` (menus/footers). Junk regexes (numbers / dates / prices / bare URL / bare email / © year / ≥ 40-char encoded blob) and < 2 letters → dropped. `mask_pii` applied to every segment (emails / phones / NIC / cards only). Caps per field, 500 chars per segment, 30 000 per page. CTA link rule: ≤ 6 words + an imperative verb (English whole words / phrases via regex; si / ta substrings because the verb is inflected and Sinhala puts it last). `order` = position of the text in Part 2's visible_text (title −2, description −1, hidden last).
  - **page_text:** markers `[TITLE] [CTA] [LABEL] [HEADING] [ALERT] [DESC] [TEXT]` in priority order (form_label + placeholder share [LABEL]; paragraph + visible_other share [TEXT]); segments joined with ` | `, groups with newlines; first segment that doesn't fit is cut at a word boundary (≥ 20 chars left) and nothing follows; max 3000; hidden never included.
  - **Language** (`content/language.py`, `configs/languages.yaml → language_id`; labels en, si, ta, si_latn, ta_latn, mixed, other, unknown — NOT metadata values, the metadata enum is unchanged): (1) script letter counts si/ta/latin/other (ZWJ not a letter), second script > 25 % → mixed; si / ta / other scripts decided by script alone; (2) Latin: Singlish / Tanglish lexicon (≥ 2 hits and ≥ 15 % of words; lexicons have no English words / no overlap) → si_latn / ta_latn, method lexicon; (3) Latin < 20 chars → inherits the page language (method inherited); else backend: **fastText lid.176.ftz via `fasttext-predict`** (one string at a time — the list API crashes) → langdetect (seed 0) → NoBackend ("en", 0.5, script_only). Non-en top ≥ 0.60 → other; weaker → en only if en prob ≥ 0.5 × top (close second), else other. (4) Page = chars of visible segments per language (mixed segments split by script), second > 25 % → mixed (method weighted), else top with confidence = mean conf × share and the method behind most chars. No votes at all → short texts judged together. `reset_caches()` in language / extractor for tests.
  - **rules_hash** = content.yaml + languages.yaml + `EXTRACTOR_VERSION` ("5a.1") + backend name (adding / removing the fastText model redoes everything). Model file `models/langid/lid.176.ftz` is git-ignored (`models/**`); download command in README.
  - **Batch** `content/batch.py` (rules as Part 3: verify, Part 2 stored or produced + saved, raw HTML read for CTAs, skip by sha + rules_hash + Part 2 mtime, one failing page never stops the run). Outputs `data/processed/text/<v>/{<id>.json, text_index.csv}` (sample_id, label, cluster_id, page_language, lang_confidence, n_segments, chars, has_cta, has_form_labels, si_ratio, ta_ratio; rebuilt from ALL valid stored results). `content/report.py`: `reports/content/<v>_summary.{json,md}` (language per label, metadata-vs-detected confusion, mean segments per field, text size, top 20 CTAs per label by pages, empty pages, timing) + `<v>_language_mismatch.csv` (REVIEW list; metadata.csv is never changed; si_latn / ta_latn / other always listed).
  - **CLI** `scripts/build_text_corpus.py extract --version [--force --workers --label --limit]`, `one --sample-id | --file [--url] [--json] [--save]`. The old `--input-dir/--corpus-dir` stub and `content/corpus_builder.py` (per-language corpus) are left for Batch B; `taxonomy.py` untouched.
  - **API / inspector:** public `POST /api/v1/content {html, url?}` → PageText (Swagger examples incl. Sinhala); dev `GET /api/v1/dev/samples/{id}/content` (`X-Content-Source`, `DevDataset.content_root`). Inspector tab "Content (Part 5)": page language + confidence + method, script-ratio bar, language shares, highlighted CTA list, segments grouped by field with a language chip each, page_text in `<pre>` — text only. Placeholder now "XLM-R / NLP (Part 6)".
  - **v0.3 run (459 pages):** 0 failures, 7 s wall (4 workers), median 21 ms / page; backend fasttext. Page language: en 330, si 7, ta 3, mixed 18, other 97 (all checked: real German / Lithuanian / Chinese / Russian / Spanish / Indonesian … pages), unknown 4; no si_latn / ta_latn in v0.3. Metadata vs detected: 123 mismatches (metadata en → other 90, → mixed 15; metadata unknown → en 6). Page method: fasttext 403, script 38, weighted 18. 4 pages have no visible text. page_text is cut on 73 % of benign pages (median 4.4 k visible chars) vs 23 % of phishing (median 0.8 k).
  - **For Part 6:** decide what to do with `other` pages (≈ 21 % of v0.3) — XLM-R covers most of them, but per-language metrics only report en / si / ta; si / ta are still tiny (10 pages), so the multilingual corpus collection matters more than the model.
- [ ] Part 5 Batch B (intent taxonomy / corpus), Parts 6, 9

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

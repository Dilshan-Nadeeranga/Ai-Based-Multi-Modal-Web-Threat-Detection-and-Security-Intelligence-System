# C2 – HTML Content & Behavior Analyzer

Part of **J26-SE-316 – AI-Based Multi-Modal Web Threat Detection System** (ScamTrace).

C2 is a Python (FastAPI) microservice that takes a webpage's raw HTML and analyzes it in three modalities:

1. **DOM structure** – forms, password/hidden fields, external form actions, iframes, scripts, link ratios.
2. **Multilingual text content** (English, Sinhala, Tamil) – social-engineering intent classified with fine-tuned XLM-RoBERTa.
3. **Static JavaScript behavior** – AST parsing (never executes code), dangerous API detection, source → sink behavioral intent mapping.

It returns one unified JSON result: `verdict`, `risk_score`, per-modality results and human-readable `findings`.

**Threat classes:** `benign`, `phishing`, `fake_ecommerce`, `crypto_scam`, `malware_delivery`.

> **Status:** Part 1 (dataset preparation), Part 2 (HTML preprocessing) and Part 3 (DOM features) are done. `GET /health`, `POST /api/v1/preprocess`, `POST /api/v1/dom-features` and the [developer inspector](#developer-inspector) work. Parts 4–9 are still stubs (`NotImplementedError`), implemented part by part.

## Implementation parts

| Part | Topic | Package (`src/c2_analyzer/`) | Script(s) |
|---|---|---|---|
| 1 | Multilingual dataset preparation | `dataset/` | `build_metadata.py`, `deduplicate.py`, `dataset_stats.py` |
| 2 | HTML preprocessing pipeline | `preprocessing/` | `preprocess_html.py` |
| 3 | DOM structural analysis | `dom/` | `extract_dom_features.py` |
| 4 | DOM baseline classifier (LogReg / RF / XGBoost) | `classifiers/dom_baseline/` | `train_dom_baseline.py` |
| 5 | Multilingual scam content analyzer | `content/` | `build_text_corpus.py` |
| 6 | XLM-R content classification | `nlp/` | `train_xlmr.py`, `evaluate_xlmr.py` |
| 7 | Static JavaScript intent analyzer | `js_analyzer/` | `analyze_js.py` |
| 8 | Behavioral intent mapping (sources → sinks) | `behavior/` | `map_behavior.py` |
| 9 | Preliminary tri-modal output + API | `fusion/`, `api/` | `run_api.py` |

## Setup

Requires Python 3.11+ (Docker image uses 3.11).

```bash
cd services/c2-html-content-behavior-analyzer
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pip install --no-deps -e .
cp .env.example .env    # then edit values
```

`torch` / `transformers` are only needed from Part 6 on; skip them for a faster install while working on Parts 1–5.

## Run

```bash
python scripts/run_api.py                          # 127.0.0.1:8002 (or: make run-api)
uvicorn c2_analyzer.api.main:app --reload --port 8002
pytest                                             # or: make test
make lint
```

Docker:

```bash
docker build -t c2-analyzer .
docker run -p 8002:8002 c2-analyzer
```

## How to collect samples

Collection has two stages, both run with `scripts/collect.py`:

1. **Candidates** – import URL lists into `data/metadata/candidates.csv` (no network).
2. **Fetch** – download each pending URL, save it to `data/raw/<label>/<sample_id>.html` and register it in `metadata.csv`.

```bash
python scripts/collect.py download --feed openphish             # optional helper: openphish | urlhaus | tranco
python scripts/collect.py import --feed openphish --file data/feeds/openphish.txt
python scripts/collect.py import --feed tranco --file data/feeds/tranco_top1m.csv.zip --top 1000 --sample 60
python scripts/collect.py import --feed manual --file data/feeds/manual_urls.csv   # template: data/metadata/manual_urls_template.csv
python scripts/collect.py fetch --label phishing --limit 60     # static mode (default)
python scripts/collect.py retry-failed                          # failed URLs, max 3 attempts
python scripts/collect.py progress                              # samples per label x language vs configs/collection_targets.yaml
python scripts/collect.py failures --label malware_delivery     # why candidates failed / were skipped
python scripts/collect.py repair --dry-run                      # after a crash: check the CSVs agree (drop --dry-run to fix)
python scripts/collect.py prune --label malware_delivery        # re-apply import filters (configs/url_filters.yaml) to pending URLs
python scripts/build_metadata.py validate                       # dataset health check
```

Fetch outcomes: **saved**, **skipped** (not HTML, > 5 MB, local-network address), **failed** (timeout, network error, non-2xx status – retryable), **duplicate** (same content as an existing sample). A scam URL that redirects to another domain is still saved, but its `notes` says `redirected to <host> - check the label`. At the end of a run the skip/fail reasons are counted (e.g. `non_html_content: 31`, `http_404: 12`, `blocked_by_antivirus: 3`).

One bad page never stops a run: any error while saving a page marks that candidate `failed` (retryable) with the reason. If a run was stopped by a crash or a locked file, run `collect.py repair`: it resets candidates whose sample was never saved, links saved samples to their candidates, removes leftover temp files, and lists files in `data/raw/` without a metadata row (it never deletes them).

If a CSV is open in Excel, saving is retried for about 3 seconds, then the command stops with "Could not save ... Close it in Excel". Close the file and run the command again.

**Rendered mode** (runs page JavaScript in headless Chromium) – Docker only:

```bash
docker build -f docker/fetcher.Dockerfile -t c2-fetcher .
docker run --rm --init --shm-size=1g --cap-drop=ALL --security-opt=no-new-privileges \
  -v "${PWD}/data:/app/data" c2-fetcher fetch --mode rendered --limit 20
```

The container only sees `data/`, runs as a non-root user and blocks downloads, media, fonts, websockets and browser permissions. Static mode works in the same image (`... c2-fetcher fetch --label phishing`).

### Safety rules

- **Never open fetched HTML in a normal browser** (no double-clicking files in `data/raw/`). Inspect them as text in VS Code.
- **Rendered mode only inside Docker.** It executes the pages' JavaScript.
- **Never commit `data/raw/` or the URL lists.** `data/raw/`, `data/feeds/`, `data/metadata/candidates.csv`, `data/metadata/metadata.csv` and `data/metadata/review/` are git-ignored because they contain live scam pages and URLs. Only `dataset_schema.json`, the templates and `manifests/` (no URLs) are tracked.
- Windows Defender quarantines many phishing pages. The collector writes pages only inside this project's `data/` folder (`data/tmp/` while saving, then `data/raw/`), never the system Temp folder, so a Defender exclusion for this project's `data\` folder is enough. Never exclude the whole project, your user folder or Temp. Pages Defender still removes are marked `blocked_by_antivirus`; files quarantined later show up as "file not found" in `build_metadata.py validate`.
- The fetcher never submits forms, never downloads linked resources, and refuses `localhost`/private-network addresses.

## Cleaning & verifying the dataset

Three steps after collecting. None of them deletes a file; they only set fields in `metadata.csv`.

**1. Quality check** sets `quality_flag`. It flags pages that are not the page we wanted:
- `empty`: a JavaScript app shell with no inputs;
- `parked_domain`, `error_page` (404, default server pages, directory listings), `bot_challenge` (Cloudflare "Just a moment..."), `suspended_hosting`;
- `login_wall`: benign samples only;
- `redirected_offsite`: from the collector's note.

Rules and phrases live in `configs/quality_rules.yaml`. Pages flagged with anything except `ok` or `redirected_offsite` are proposed for exclusion in the review.

**2. Near-duplicate clustering** sets `cluster_id` and `is_duplicate_of`. The same phishing kit on many domains is grouped into one cluster:
- How pages are compared:
  - text word 5-grams plus HTML-tag 4-grams;
  - MinHash/LSH finds candidate pairs, then exact Jaccard decides;
  - thresholds are in `configs/config.yaml → dedup`.
- In each cluster, one representative is kept and the others point to it.
- A cluster with **different labels** is reported as a *label conflict* and not marked; one of the labels is wrong.
- Train/test splits (Parts 4/6) are grouped by `cluster_id`, so near-copies never leak from training into testing.
- Only usable pages are compared (not excluded, flag `ok` or `redirected_offsite`); the others become single-page clusters.
- Reports: `reports/dataset_stats/dedup_report.json` and `.csv`.

```bash
python scripts/deduplicate.py all --dry-run   # quality + dedup, show results, save nothing
python scripts/deduplicate.py all             # save flags, clusters and reports
python scripts/deduplicate.py quality         # or run one step: quality | dedup
```

**3. Manual review** shows one sample at a time as **text only**: metadata, quality flag, cluster, title, the first 600 characters of visible text, forms with their action and input types, script/iframe counts, and the top external domains.

```bash
python scripts/review_labels.py review --reviewer <your name> --only-flagged       # decide exclusions first
python scripts/review_labels.py review --reviewer <your name> --cluster-representatives-only --label phishing
python scripts/safe_preview.py c2_phishing_000042    # sanitized copy, only when text is not enough
```

Keys: `[c]` confirm, `[r]` relabel, `[l]` fix language, `[x]` exclude, `[s]` skip, `[b]` back, `[q]` quit.
- Every decision is saved immediately, so you can quit and resume at any time.
- Other filters: `--label`, `--language`, `--include-verified`, `--random --seed N`, `--limit N`.
- **Relabelling keeps the sample_id.** The file moves to the new label folder and the old label is stored in `label_original`. Keeping the id means nothing that refers to the sample (duplicates, candidates.csv, reports) has to change.

`safe_preview.py` writes `data/metadata/review/<id>_safe.html`, a copy with every script, frame, link target, form action, event handler and outside resource removed. It also gets a strict Content-Security-Policy and a red banner. Open **only** the `_safe.html` file, never the original in `data/raw/`.

**Peer verification (for the report).** A second person labels a random 10% of your verified samples without seeing your labels:

```bash
python scripts/review_labels.py export-peer --fraction 0.1 --seed 42   # -> reports/dataset_stats/peer_review_sheet.csv
python scripts/review_labels.py import-peer --file <their filled sheet.csv>   # agreement % + Cohen's kappa
```

The sheet has no labels, sources or URLs. It is saved as UTF-8 with BOM, so Excel shows Sinhala and Tamil correctly. `import-peer` writes `peer_agreement.json` with the agreement %, Cohen's kappa (with its Landis & Koch interpretation) and the list of disagreements to re-check.

## Dataset statistics & versions

**Three views** are used everywhere (statistics, manifests, later the splits):

| view | rows |
|---|---|
| all | every row in `metadata.csv` |
| usable | not excluded and `quality_flag` is `ok` or `redirected_offsite` |
| clean | usable and not a near-duplicate (`is_duplicate_of` empty), one row per cluster. **The models train on this view.** |

```bash
python scripts/dataset_stats.py stats            # all three views (or --view clean)
```

`stats` prints the clean label × language table and a readiness line per label (`ready` or e.g. `12 more needed, 5 more si needed`, compared with `configs/collection_targets.yaml`). It writes to `reports/dataset_stats/`:
- `dataset_stats.json`: everything, machine-readable;
- `dataset_stats.md`: Markdown tables to paste into the progress report;
- `figures/`: `label_distribution`, `label_language_heatmap`, `quality_flags`, `text_length_by_label`, `collection_timeline` and `verification_progress` (PNG, 150 dpi).

These contain counts, sample ids and cluster ids, but no URLs.

**Freezing a dataset version.** When a review round is finished, freeze the clean view so every later experiment can name the exact data it used:

```bash
python scripts/dataset_stats.py freeze --version v0.1 --notes "after first full review"
python scripts/dataset_stats.py verify --version v0.1     # every file present, sha256 unchanged
```

- `freeze` writes `data/metadata/manifests/dataset_v0.1.csv` (sample_id, label, language, cluster_id, sha256, file_path) and `dataset_v0.1.json` (created_at, counts per label/language, git commit, notes, fingerprint).
- A version is never overwritten; a changed dataset gets a new number (v0.2, ...).
- Freezing refuses if any file is missing or changed (run `build_metadata.py validate` first).
- Manifests contain no URLs, so **commit them**. Parts 2–6 read a manifest, not `metadata.csv`, and report its version with their results.
- `dataset_stats.json` shows `dataset_version: v0.1` while the clean view still matches that manifest exactly, and `unfrozen` once anything changed.

## HTML preprocessing

Part 2 turns each HTML page into one structured JSON file (`ParsedPage`, `src/c2_analyzer/schemas/parsed_page.py`). It **extracts and organizes** facts; it does not decide whether anything is suspicious (Parts 3, 5 and 7/8 do that). It never runs JavaScript, never makes a network request and never downloads external scripts or CSS.

```bash
python scripts/preprocess_html.py run --version v0.1                 # every sample of a frozen version
python scripts/preprocess_html.py run --version v0.1 --label phishing --limit 20 --workers 2
python scripts/preprocess_html.py run --version v0.1 --force         # redo pages that are already done
python scripts/preprocess_html.py one --sample-id c2_phishing_000081 # what is extracted, as text
python scripts/preprocess_html.py one --file page.html --url https://example.com/login
```

What `ParsedPage` contains:
- **meta**: sample id, page URL, base URL, dataset version, parser used, timing per step, input size and sha256, truncation and errors.
- **text**: title, meta tags (a meta refresh gets its resolved `redirect_url`), headings with levels, paragraphs, `visible_text` (one line per block) and `hidden_text` (hidden attribute, `aria-hidden`, inline `display:none`/`visibility:hidden`/`opacity:0`/`font-size:0`, `<noscript>`).
- **forms**: resolved action, its domain, external or not, method; every input with type, label, `hidden`, `required` and a masked prefilled value; buttons. Inputs outside any form are listed too.
- **links and embedded frames**: absolute URL, registrable domain, external or not, size, and whether the frame is hidden.
- **JavaScript as text**: inline scripts (≤ 500 KB each), external script references, `on*=` event handlers and `javascript:` URLs. JSON-LD and templates are kept separately as data.
- **summaries**: CSS (`style=""` attributes stay in the DOM for Part 3) and comments (removed from the text, counted).
- **dom**: node, element and tag counts, depth, and a skeleton capped at 3000 nodes / depth 40.

Rules worth knowing:
- **Sinhala and Tamil are kept intact**: NFC normalization, but the zero-width joiner/non-joiner (needed for ශ්‍රී) are never removed. Zero-width spaces, BOMs and control characters are.
- **PII masking (FR10 / PDPA)**: prefilled input values and URL query/fragment values are masked as `[EMAIL]`, `[PHONE]` (including +94 / 07X numbers), `[CARD]` (Luhn-checked) and `[NIC]` (old and new). Prefilled passwords are stored as `[REDACTED]`. Visible page text is not masked, because the NLP models need it.
- **Domains**: "external" compares registrable domains (`bank.com.lk`, `x.pages.dev`) using tldextract **offline** (its bundled suffix list, no download). Without tldextract, a simpler built-in rule is used.
- **Robustness**: a page larger than 5 MB is cut and marked `truncated`. If lxml fails, `html.parser` is used. If one extractor fails, the error goes to `meta.errors` and the rest of the page is still saved.

Outputs (git-ignored):
- `data/processed/parsed_html/<version>/<sample_id>.json`, plus `.txt` with the visible text only, for Part 5;
- `one --save` writes to `data/processed/parsed_html/adhoc/`.

A run skips pages whose JSON already matches the source sha256, schema version and domain method. The run refuses to start if `dataset_stats.py verify` fails for that version. It writes `reports/preprocessing/<version>_summary.{json,md}` with these numbers:
- counts, failures, parser fallbacks, truncated pages and timing;
- a descriptive per-label table: median text length and % of pages with forms, password inputs, inline/external scripts, iframes and meta refresh.

## DOM features

Part 3 turns each `ParsedPage` into a **fixed-order numeric feature vector** (the Part 4 model input) plus **evidence**, short sentences such as "Password form submits to external domain submit-form.com". It counts and measures. It does not classify (Part 4) and does not interpret JavaScript (Part 7).

```bash
python scripts/extract_dom_features.py run --version v0.1           # whole version -> CSV + report
python scripts/extract_dom_features.py run --version v0.1 --force   # redo everything
python scripts/extract_dom_features.py one --sample-id c2_phishing_000081
python scripts/extract_dom_features.py one --file page.html --url https://example.com/login
python scripts/extract_dom_features.py describe [--markdown]        # the feature table for the report
```

- **The feature dictionary is `configs/dom_features.yaml`.** It holds the 52 features in 11 groups (context, structure, forms, credentials, hidden inputs, form actions, iframes, scripts, hidden elements, links, meta & resources). For each feature it gives the type, a plain-English reason, the ParsedPage source and an evidence template. Its order is the CSV column order. Changing the list means bumping `feature_set_version` (now `dom_v1`).
- **Credential fields** (password, e-mail, username, OTP/PIN, payment card) are detected from the type, autocomplete tokens, and name/id/placeholder/label patterns in English, Sinhala and Tamil, e.g. ඊමේල්, මුරපදය, පරිශීලක, மின்னஞ்சல், கடவுச்சொல். Exclusions handle cases like a Sri Lankan NIC, which is not a payment card, or a CAPTCHA, which is not an OTP.
- **Strong structural signals** include a password form posting to another domain, a form posting to a form-collection service (submit-form.com, formspree, …), a form posting to an IP address, hidden iframes, and the share of links that go nowhere.
- **Safe numbers:**
  - when the page URL is unknown, `base_url_known = 0` and every internal/external feature is 0;
  - a ratio with a zero denominator is 0.0, and no value is ever NaN;
  - if one feature group fails, only that group is set to 0 and the error is recorded.
- **Outputs (git-ignored)** go to `data/processed/dom_features/<version>/`:
  - `dom_features.csv`: `sample_id, label, language, cluster_id`, then the features in dictionary order;
  - one `<sample_id>.json` per sample, with the features and evidence;
  - `feature_dictionary.json`.
- **Report:** `reports/dom_features/<version>_summary.{json,md}` and `figures/` contain, per label, the mean, median and % non-zero of each feature. It warns about constant, near-constant and highly correlated (|r| > 0.95) features, and ranks the most separating features by mutual information with box plots. This ranking is descriptive only; Part 4 selects features on the training split.

## API

| Method | Path | Status |
|---|---|---|
| GET | `/health` | ✅ returns `{"status": "ok", "service": "c2"}` |
| POST | `/api/v1/dom-features` | ✅ Part 3: same body → `DomResult` (52-feature vector in dictionary order + evidence). No `url` → `base_url_known = 0` and external features 0 |
| POST | `/api/v1/preprocess` | ✅ Part 2: body `{"html": "...", "url": "..." or null}` → `ParsedPage` JSON (same as the stored files). `url` is never fetched. Body > 5 MB → `413` |
| POST | `/api/v1/analyze` | stub (501) – body `{"html": "...", "url": "..."}` |
| POST | `/analyze-html` | stub (501) – compatibility route for `backend/api-gateway`, which currently sends `{"url": ...}` |
| GET | `/api/v1/dev/...`, `/inspector` | developer only – see below (404 unless `APP_ENV=development`) |

The gateway reaches C2 through its `C2_URL` env var (e.g. `http://localhost:8002`). Swagger UI with example requests: `/docs`. Every response carries `X-Content-Type-Options: nosniff`.

## Developer inspector

A small web page that shows **how the C2 engine sees a page**, for debugging, supervisor demos and progress presentations. It is a developer tool, not the product UI: the team dashboard (`frontend/scamtrace-dashboard`) is separate.

```bash
python scripts/run_api.py        # APP_ENV=development (default in .env.example)
```

Then open **http://127.0.0.1:8002/inspector** (Swagger: http://127.0.0.1:8002/docs).

- **Left:** pick a frozen dataset version, filter by label, language, "has password input" or "external form action", search by id or title, and click a sample. Up/Down arrows move through the list.
- **Top:** paste HTML (and optionally its URL) or choose a local `.html` file, then press **Analyze**. This calls `POST /api/v1/preprocess`. The file is read as text and never rendered.
- **Tabs:** DOM Features (Part 3: evidence, non-zero features per group next to the label medians, and a full table) · Overview (sizes, timings, errors, count cards) · Text (headings, paragraphs, visible and hidden text; Sinhala/Tamil fonts) · Forms (action, EXTERNAL badge, inputs, buttons) · Scripts (inline JS as text, external scripts, handlers, `javascript:` URLs) · Links & Resources (internal/external ratio, stylesheets, iframes, meta refresh) · DOM (tag-count chart, lazy skeleton tree) · Raw JSON (copy button) · Safe Preview (dataset samples only). Greyed-out tabs are placeholders for Parts 5–6, 7–8 and 9.
- **Deep links:** the URL hash remembers the version, sample and tab (e.g. `/inspector#v=v0.1&sample=c2_phishing_000081&tab=forms`). This is handy for presentations.

Dev endpoints (only when `APP_ENV=development`; any other value gives `404`):

| Path | Returns |
|---|---|
| `GET /api/v1/dev/versions` | frozen versions (newest first) with counts and how many samples Part 2 processed |
| `GET /api/v1/dev/samples?version=v0.1&label=&language=&q=&has_password=&external_form_action=` | sample list from the manifest + stored Part 2 JSON (HTML is not re-parsed) |
| `GET /api/v1/dev/samples/{id}/parsed?version=v0.1` | the stored `ParsedPage`. A missing one is processed on the fly but not saved (header `X-Parsed-Source`) |
| `GET /api/v1/dev/samples/{id}/dom-features?version=v0.1` | the stored Part 3 `DomResult`, or one computed on the fly (header `X-Features-Source`) |
| `GET /api/v1/dev/dom-dictionary?version=v0.1` | the feature dictionary plus per-label medians from the Part 3 report |
| `GET /api/v1/dev/samples/{id}/safe-preview` | Part 1's sanitized copy, with `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'` and `nosniff` |

**Safety.** Dataset pages are hostile, so the inspector only ever shows them as text:
- every value goes through `textContent`. `innerHTML`, `eval` and similar HTML-parsing calls are banned, and a test greps for them;
- page URLs are never clickable;
- the page sends a strict CSP and loads no CDN, so it works offline;
- the only rendered HTML is the sanitized preview, inside an `<iframe sandbox="">`.

The dev endpoints are read-only and never fetch a URL. `run_api.py` binds to `127.0.0.1` (use `--host` to change it), and the Docker image sets `APP_ENV=production`.

**Adding a tab in a later part:** in `src/c2_analyzer/api/static/inspector.js`, replace the placeholder with `registerTab({ id, title, render(ctx, box) { ... } })`. If the tab needs new data, add a matching dev endpoint in `api/dev_routes.py`.

## Structure

```
configs/            YAML config: paths/splits/model params, labels, languages, intent taxonomy, JS rules, sources/sinks
data/
  raw/<label>/      collected HTML (git-ignored)
  metadata/         dataset_schema.json, manual_urls_template.csv, manifests/ (tracked); metadata.csv, candidates.csv, review/ (git-ignored)
  feeds/            downloaded feed files (git-ignored)
  tmp/              pages being saved by the collector (git-ignored, emptied automatically)
  interim/          after dedup (git-ignored)
  processed/        parsed_html/<version>/ (Part 2 JSON + TXT), dom_features, text, js, behavior (git-ignored)
  corpus/{en,si,ta} multilingual text corpus
  splits/           train/val/test
models/             dom_baseline/, xlmr/ (weights git-ignored)
reports/            dataset_stats/, metrics/, figures/
notebooks/          EDA, baselines, Colab fine-tuning
scripts/            thin argparse CLIs that call src/
src/c2_analyzer/    the package (see table above)
tests/              pytest suite + fixtures/sample_pages/
```

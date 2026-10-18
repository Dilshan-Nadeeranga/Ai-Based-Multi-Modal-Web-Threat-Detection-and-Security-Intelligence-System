# C2 – HTML Content & Behavior Analyzer

Part of **J26-SE-316 – AI-Based Multi-Modal Web Threat Detection System** (ScamTrace).

C2 is a Python (FastAPI) microservice that takes a webpage's raw HTML and analyzes it in three modalities:

1. **DOM structure** – forms, password/hidden fields, external form actions, iframes, scripts, link ratios.
2. **Multilingual text content** (English, Sinhala, Tamil) – social-engineering intent classified with fine-tuned XLM-RoBERTa.
3. **Static JavaScript behavior** – AST parsing (never executes code), dangerous API detection, source → sink behavioral intent mapping.

It returns one unified JSON result: `verdict`, `risk_score`, per-modality results and human-readable `findings`.

**Threat classes:** `benign`, `phishing`, `fake_ecommerce`, `crypto_scam`, `malware_delivery`.

> **Status:** Part 1 (dataset preparation), Part 2 (HTML preprocessing), Part 3 (DOM features), Part 4 (DOM baseline), Part 7 (static JavaScript analysis) and Part 8 (behavioral intent mapping + behavior-only baseline) are done. `GET /health`, `POST /api/v1/preprocess`, `POST /api/v1/dom-features`, `POST /api/v1/js-analysis`, `POST /api/v1/behavior` and the [developer inspector](#developer-inspector) work. Parts 5, 6 and 9 are still stubs (`NotImplementedError`), implemented part by part.

## Implementation parts

| Part | Topic | Package (`src/c2_analyzer/`) | Script(s) |
|---|---|---|---|
| 1 | Multilingual dataset preparation | `dataset/` | `build_metadata.py`, `deduplicate.py`, `dataset_stats.py` |
| 2 | HTML preprocessing pipeline | `preprocessing/` | `preprocess_html.py` |
| 3 | DOM structural analysis | `dom/` | `extract_dom_features.py` |
| 4 | DOM baseline classifier (LogReg / RF / XGBoost) | `classifiers/dom_baseline/` | `train_dom_baseline.py` |
| 5 | Multilingual scam content analyzer | `content/` | `build_text_corpus.py`, `review_corpus.py` |
| 6 | XLM-R content classification (6A: page level) | `nlp/` | `train_xlmr.py`, `evaluate_xlmr.py` |
| 7 | Static JavaScript intent analyzer | `js_analyzer/` | `analyze_js.py` |
| 8 | Behavioral intent mapping (sources → sinks) | `behavior/` | `map_behavior.py` |
| 9 | Tri-modal fusion + ablation (9A) · URL analysis engine + `/api/v1/analyze` (9B-1) · ThreatRadar ingestion, results store, dashboard APIs (9B-2) | `fusion/`, `api/`, `ingest/`, `store/` | `run_ablation.py`, `calibrate_verdict.py`, `evaluate_verdict.py`, `export_openapi.py`, `run_api.py`, `pull_threatradar.py`, `review_live.py`, `demo_ingest.py` |

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

`torch` / `transformers` are only needed from Part 6 on; skip them for a faster install while working on Parts 1–5. On Windows install the CPU build first (no CUDA, ~200 MB): `pip install torch --index-url https://download.pytorch.org/whl/cpu`, then `pip install -r requirements.txt`.

Optional for Part 5: the fastText language-ID model (`models/langid/lid.176.ftz`, see [Content extraction & language ID](#content-extraction--language-id)). Without it, langdetect is used.

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
python scripts/collect.py import --feed threatradar --dir ../../ingestion/threat-radar/backend/data   # see "Importing from ThreatRadar"
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

### Importing from ThreatRadar

ThreatRadar (`ingestion/threat-radar`, a teammate's service) scrapes Telegram channels, subreddits and newly registered domains. The `threatradar` feed reads its output folder directly, so you don't have to edit any CSVs by hand. ThreatRadar's files are only read, never changed:

| ThreatRadar file (under `backend/data/`) | rows | C2 `source` |
|---|---|---|
| `scraped/urls_only.csv` (Telegram) | `domain,url,channel,date,message_id,...` | `social_media_report` |
| `scraped/reddit_urls_only.csv` (Reddit) | `domain,url,subreddit,date,post_id,score,title` | `social_media_report` |
| `filtered/filtered_domains_*.json` (domain filter) | `domains[]` with `reasons`, `matchedKeywords`, `mimicBrand` | `other` |

ThreatRadar does not label anything, so each URL gets a **weak suggested label** from `configs/threatradar_rules.yaml`. The first rule that matches wins:
1. brand mimicry (ThreatRadar's `brand_mimicry:` reason, or a brand from the config inside a host that is not allow-listed, e.g. `paypal-verify.xyz`) → `phishing`;
2. crypto/investment/airdrop/USDT/profit keywords → `crypto_scam`;
3. shop/sale/discount/store keywords → `fake_ecommerce`;
4. download/apk/crack/update keywords → `malware_delivery`.

A row that matches no rule is **skipped**: the importer never guesses `benign`.
- Keywords are substrings (a domain has no word breaks) and are only searched in the fields that config lists for each source. For Telegram that is the URL and the channel name; for Reddit, the URL and the post title, not the subreddit (otherwise r/CryptoScams would label every link); for the domain filter, the domain and ThreatRadar's matched keywords.
- Each note reads `ThreatRadar <source>: <reason> — check label; <channel @x message_id=… | r/sub post_id=… | file + reasons>; seen <date>`. The note travels to `metadata.csv` with the page.
- `language_hint` is `si` or `ta` if the channel name, post title or matched keyword contains Sinhala or Tamil script. Otherwise it is `unknown`; the fetch step then detects the language from the page itself.
- Bare domains become `https://<domain>/`. URLs are normalized and compared with `candidates.csv`, with `metadata.csv` (`source_url` and `final_url`) and with each other.
- Well-known legitimate domains and their subdomains are skipped. That allow-list is in the same config file; free hosts such as `*.github.io` are not covered by it.
- A missing file is reported and skipped; it does not stop the import.

End to end, run from this folder. ThreatRadar is at `../../ingestion/threat-radar`:

```bash
# 1. queue the URLs (add --since YYYY-MM-DD for new rows only, --sources telegram,reddit,domain_filter, --limit N)
python scripts/collect.py import --feed threatradar --dir ../../ingestion/threat-radar/backend/data --since 2026-10-01
#    prints: rows read per source, imported per suggested label, skipped (duplicate / allow-listed / no rule matched)

# 2. fetch per label (static mode; 2xx HTML pages only)
python scripts/collect.py fetch --label phishing --limit 60
python scripts/collect.py fetch --label crypto_scam --limit 60
python scripts/collect.py fetch --label fake_ecommerce --limit 60
python scripts/collect.py fetch --label malware_delivery --limit 60
python scripts/collect.py failures                     # why some were skipped / failed

# 3. quality flags + near-duplicate clusters
python scripts/deduplicate.py all

# 4. review: the suggested labels are WEAK, so confirm or relabel every ThreatRadar page
python scripts/review_labels.py review --reviewer <your name> --only-flagged
python scripts/review_labels.py review --reviewer <your name> --label crypto_scam   # repeat per label

# 5. statistics, then freeze the new version (never overwrites an existing one)
python scripts/dataset_stats.py stats
python scripts/dataset_stats.py freeze --version v0.4 --notes "v0.3 + ThreatRadar imports (reviewed)"
python scripts/dataset_stats.py verify --version v0.4
```

Later parts keep reading the version they name (for example v0.3) until you rerun them with `--version v0.4`.

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

## DOM baseline

Part 4 is **Baseline 1** of the ablation study: DOM-only structural classification with Logistic Regression, Random Forest and XGBoost on the Part 3 feature vector. Later parts compare NLP-only (Part 6), behavior-only (Part 8) and the fused model against it **on the same split**.

```bash
python scripts/train_dom_baseline.py all --version v0.1        # split (if missing) -> train -> evaluate -> report
python scripts/train_dom_baseline.py split --version v0.1 [--force]
python scripts/train_dom_baseline.py train --version v0.1 --models logreg,rf,xgb
python scripts/train_dom_baseline.py evaluate --version v0.1
python scripts/train_dom_baseline.py predict --sample-id c2_phishing_000081
python scripts/train_dom_baseline.py predict --file page.html --url https://example.com/login [--json]
```

- **One shared split per dataset version** (`data/splits/<version>/split.csv`, `split.json`, `cv_folds.csv`; tracked in git, ids and labels only). It is made from the frozen manifest, 70/15/15 with seed 42, stratified by label × language and **grouped by near-duplicate cluster**, so copies of one phishing kit never end up in both train and test. Sinhala and Tamil pages are spread over the three splits. Classes with fewer than 15 pages are excluded and listed, and the run is then marked **PILOT** (v0.1: fake_ecommerce and crypto_scam have 0 pages). An existing split is never replaced without `--force`.
- **Model selection never sees the test split.** Each model has a small grid (`configs/dom_baseline.yaml`). The best grid point is chosen by mean macro-F1 over grouped 5-fold CV on train+val, refit on train+val, and only then evaluated **once** on test. Class imbalance is handled by `class_weight` (LR, RF) or balanced sample weights (XGBoost).
- **Feature cleaning on train only:** constant features and one of each pair with |r| > 0.98 are dropped (`dropped_features.csv` says why).
- **Metrics:**
  - per-class precision, recall and F1;
  - **macro-F1** (primary);
  - weighted-F1, accuracy, balanced accuracy and one-vs-rest ROC-AUC;
  - **benign false-positive rate** (target ≤ 2 %), with the flagged sample ids;
  - per-language results (small-n warning);
  - confusion matrices.
- **Importance:** LR standardized coefficients, RF impurity and permutation importance, XGBoost gain and SHAP (global bar plot and a beeswarm per class), all labelled with the feature descriptions. On the pilot set they are indicative only.
- **Outputs:**
  - `models/dom_baseline/<version>/*.joblib` (git-ignored), plus the tracked `model_card.json`. It records the dataset, split fingerprint, feature set, features, label mapping, best params, metrics, library versions and git commit;
  - `reports/dom_baseline/<version>/results.md` (the Baseline 1 table), `results.json`, `misclassified.csv`, `dropped_features.csv` and `figures/`.

v0.1 pilot (42 test pages), from `reports/dom_baseline/v0.1/results.md`:

| Model | CV macro-F1 | Test macro-F1 | Test accuracy | Benign FPR |
|---|---|---|---|---|
| Logistic Regression | 0.747 ± 0.030 | 0.716 | 0.738 | 25.0 % |
| **Random Forest** (best by CV) | 0.797 ± 0.011 | 0.755 | 0.786 | 10.0 % |
| XGBoost | 0.788 ± 0.024 | 0.753 | 0.786 | 10.0 % |

## Content extraction & language ID

Part 5 (Batch A) turns a page into **the text the NLP model (Part 6) will read**. It does not classify anything. It reuses Part 2's `ParsedPage` (title, headings, paragraphs, visible / hidden text, form labels and placeholders) and Part 2's normalization (NFC, ZWJ / ZWNJ kept, so ශ්‍රී stays intact). The raw HTML is re-parsed only for facts Part 2 does not store: link classes, `role=button` and `role=alert`. The same `content/extractor.py::extract_content(page, html)` serves dataset samples, the CLI and `POST /api/v1/content`.

```bash
python scripts/build_text_corpus.py extract --version v0.3 [--force] [--workers 4]   # runs Part 2 for missing samples
python scripts/build_text_corpus.py one --sample-id c2_benign_000118                  # segments by field + languages + page_text
python scripts/build_text_corpus.py one --file page.html [--url https://example.com/] [--json]
```

- **Segments** (`schemas/content.py::PageText`, `text_v1`). Each segment has `segment_id`, `field`, `text`, `order`, `count`, `language`, confidence, method and `script_mix`. The fields are:
  - `title` and `meta_description`;
  - `heading`, with its level;
  - `cta`: buttons, `input[type=submit|button]`, `a.btn` / `.cta` / `role=button`, and short (≤ 6 words) links with an imperative verb in English, Sinhala or Tamil, such as "verify", "තහවුරු", "சரிபார்";
  - `form_label`: the label, or the aria-label;
  - `placeholder`;
  - `alert_banner`: `role=alert`, or short text with an urgency marker;
  - `paragraph`;
  - `visible_other`: other visible lines, e.g. text in `<div>`s;
  - `hidden`: kept for reference, never sent to the model.
  The rules live in `configs/content.yaml`.
- **Cleaning:**
  - Fields are filled in priority order, so text taken by an earlier field is not repeated: "Sign in" stays a CTA.
  - Repeated menus and footers are merged into one segment with `count`.
  - Segments that are only a number, date, price, URL, email or encoded blob are dropped.
  - Emails, phone numbers, NIC numbers and card numbers are masked (`[EMAIL]`, `[PHONE]` …) with Part 2's `mask_pii`. The rest of the wording is kept.
  - Caps apply per field, per segment and per page.
- **`page_text`** is the model input, e.g. `[TITLE] … [CTA] … [LABEL] … [HEADING] … [ALERT] … [DESC] … [TEXT] …`. It is assembled in field priority order and cut to 3000 characters at a word boundary, so title, CTAs, labels, headings and alerts survive truncation.
- **Language ID** (`content/language.py`, `configs/languages.yaml → language_id`), per segment and per page. Labels: `en`, `si`, `ta`, `si_latn`, `ta_latn`, `mixed`, `other`, `unknown`.
  1. Unicode script ratios (Sinhala U+0D80–0DFF, Tamil U+0B80–0BFF, Latin, other). A Sinhala or Tamil segment is certain even if it is one word. If the second script has more than 25 % of the letters, the segment is `mixed`.
  2. Latin text first goes through the **Singlish / Tanglish lexicon** (frequent romanized words such as "oya", "karanna", "ungalukku") → `si_latn` / `ta_latn`. *Known gap:* XLM-R handles romanized Sinhala / Tamil poorly, so these pages are flagged, not hidden.
  3. Then English vs other Latin-script languages, with an offline model: **fastText lid.176** if present, else **langdetect** (seed 0), else "en" with low confidence. Latin segments under 20 characters ("OK", "Login") inherit the page language.
  4. The page language is weighted by characters over the visible segments. It is `mixed` if the second language has more than 25 %. Every result has a confidence and the method used.
  This replaces Part 1's `utils/script_detect.py` hint, which still serves collection.
- **fastText model** (optional, ~1 MB, not in git; the code works without it). `pip install fasttext-predict` is already in `requirements.txt`, then:
  ```bash
  curl -L -o models/langid/lid.176.ftz https://dl.fbaipublicfiles.com/fasttext/supervised-models/lid.176.ftz
  ```
  The backend name is part of the rules hash, so adding or removing the model redoes every stored result.
- **Outputs:**
  - `data/processed/text/<v>/<id>.json` and `text_index.csv` (sample_id, label, cluster_id, page_language, lang_confidence, n_segments, chars, has_cta, has_form_labels, si_ratio, ta_ratio);
  - `reports/content/<v>_summary.{json,md}`: language per label, metadata-vs-detected confusion table, segments per field, text size, top 20 CTAs per label, empty pages;
  - `reports/content/<v>_language_mismatch.csv`: a **review list only**. `metadata.csv` is never changed automatically.

v0.3 (459 pages), from `reports/content/v0.3_summary.md`:
- **Run:** 0 failures, 7 s wall time with 4 workers, median 21 ms per page, 4 pages with no visible text.
- **Languages:** 7 benign pages `si`, 3 `ta`; 97 pages `other`, which are real foreign-language pages: German, Lithuanian, Chinese, Russian, Spanish, Portuguese, Indonesian …. No Singlish / Tanglish pages yet.
- **Metadata vs detected:** 123 of 459 disagree. 90 metadata-`en` pages are really another Latin or other-script language, 15 are `mixed`, and 6 `unknown` pages are English.

| page language | en | si | ta | mixed | other | unknown |
|---|---|---|---|---|---|---|
| benign (227) | 165 | 7 | 3 | 7 | 44 | 1 |
| phishing (87) | 60 | 0 | 0 | 7 | 19 | 1 |
| fake_ecommerce (57) | 38 | 0 | 0 | 1 | 18 | 0 |
| crypto_scam (29) | 22 | 0 | 0 | 1 | 4 | 2 |
| malware_delivery (59) | 45 | 0 | 0 | 2 | 12 | 0 |

## Scam-text corpus

Part 5 Batch B builds `corpus_v1`: short texts in English, Sinhala and Tamil, each labelled
with a **social-engineering intent**. Part 6 trains on it.

**Research integrity.** The corpus mixes four sources with different trust levels. Every row
records `source_type` and `is_synthetic`. **Synthetic templates and machine translations are
train-only augmentation. Validation and test contain only real text.** Otherwise the scores
would be inflated: a model tested on its own template sentences looks better than it is. The
stats report shows the synthetic share of every split and fails if val / test is not 0 %.

- **Intents** (`configs/intent_taxonomy.yaml`, `intent_v1`): `credential_request`,
  `payment_request`, `investment_lure`, `fake_security_warning`, `fake_reward`,
  `urgency_threat`, `impersonation`, `benign`. Each has a definition, inclusion / exclusion
  rules, 2 English examples and cue words in en / si / ta. A text may have several intents;
  `primary_intent` = the first in the priority order (the most specific ask wins). The human
  version for me and the peer reviewer is [`docs/annotation_guide.md`](docs/annotation_guide.md).
  The si / ta cue words are a seed list that still needs a native-speaker check.
- **Sources** (`content/corpus_builder.py`, rules in `configs/corpus.yaml`):

  | source_type | from | label | split | group_id |
  |---|---|---|---|---|
  | `page_segment` | title / CTA / form label / alert / heading / short paragraph of the v0.3 pages (Part 5A) | weak, from cue words. On a benign page it stays `benign` unless ≥ 2 cue phrases match (then `needs_review`) | the page's split in the **shared** split (never re-split) | page cluster |
  | `real_message` | `data/corpus/real_texts.csv` (`text,language,intent,source,notes`; my SMS / WhatsApp / CERT / news texts; may be missing) | given | grouped stratified 70/15/15 by language × intent, seed 42 | normalized-text hash |
  | `synthetic_template` | `data/corpus/raw_texts_clean.csv` | given | **always train** | template_group |
  | `machine_translation` | `data/corpus/mt/*.csv` (`text,language,intent,source_text_id`) | source's | **always train**; dropped if the source row is not train | source row's group |

  - **PII:** real messages go through Part 2's `mask_pii` + `mask_url`. `[NAME]` placeholders are kept.
  - **Language:** detected with Part 5A `language.py`. The source's value is kept in
    `language_given`, and a mismatch gets `needs_review`.
  - **Near-duplicates:** `corpus.dedup_key` = NFC, case-folded, numbers → 0, URLs → `url`, no
    punctuation. They are merged within a group (`dup_count`).
  - **Cross-split duplicates:** a text found in train AND val / test is kept only in the
    held-out split.
  - **Small cells:** a real-message cell with fewer than 3 groups cannot be split. It goes
    to train and is reported.
- **Commands:**
  ```bash
  python scripts/build_text_corpus.py build --version v0.3     # corpus + stats (reviews re-applied)
  python scripts/build_text_corpus.py stats                    # reports/content/corpus_v1_stats.{json,md}
  python scripts/build_text_corpus.py export-mt-input          # data/corpus/mt/mt_input_en.csv
  python scripts/build_text_corpus.py freeze --name corpus_v1  # data/corpus/manifests/ (never overwritten)
  python scripts/review_corpus.py review --reviewer <name> [--language si] [--split test] [--source-type ...] [--intent ...] [--needs-review] [--random --seed 1 --limit 50]
  python scripts/review_corpus.py export-peer --fraction 0.1 --seed 42
  python scripts/review_corpus.py import-peer --file <peer sheet>   # agreement % + Cohen's kappa per language
  ```
- **Review tool keys:** `c` confirm, `i` change intents (numbers, first = primary), `l`
  language, `x` exclude with a reason, `s` skip, `b` back, `q` quit.
  - Every decision is saved at once to `data/corpus/review/corpus_reviews.csv`.
  - `text_id` is a hash of the source and the normalized text, so a rebuild keeps all
    decisions.
  - Confirming pins the shown intents and language.
- **Machine translation (optional):** `notebooks/05_corpus_mt_colab.ipynb` (Colab GPU, NLLB-200
  distilled 600M, `eng_Latn` → `sin_Sinh` / `tam_Taml`, placeholders protected). Upload
  `mt_input_en.csv`, then download `mt_si.csv` / `mt_ta.csv` into `data/corpus/mt/` and rebuild.
- **Outputs:**
  - `data/corpus/corpus_v1.{csv,jsonl}` (all rows, including excluded ones with their reason);
  - `data/corpus/{en,si,ta}/corpus_v1_<lang>.csv` (active rows);
  - `data/corpus/corpus_v1_build.json` (what was read, dropped and moved);
  - `reports/content/corpus_v1_stats.{json,md}` (counts only, no text).
- **Git:** corpus files can hold personal data even after masking, so `data/corpus/**` is
  ignored. The exceptions are `raw_texts_clean.csv` and `manifests/`; the stats report and the
  annotation guide are tracked. **Part 6 must use rows with `excluded = false`.**

First build on v0.3 (no real messages or translations yet), from `reports/content/corpus_v1_stats.md`:

- **Size:** 7,330 rows: 7,210 page segments and 120 synthetic rows (168 templates; 48 merged
  because they differ only in an amount).
- **Splits:** train 4,832 / val 1,215 / test 1,283. Synthetic share 2.5 % / 0 % / 0 %.
  Integrity checks passed.
- **Cross-split duplicates:** 1,623 train page segments were dropped because the same text is
  on a val / test page (mostly short CTAs such as "Sign in").
- **Weak labels:** only 32 page segments get a scam intent. Most text on any page is neutral,
  even on scam pages: menus and product names. So the page segments are mainly real benign /
  hard-negative text in en / si / ta / other.
- **Real Sinhala / Tamil text:** none with a scam intent in val + test yet. The gap to the
  target is 210 rows for si (30 per intent) and 105 for ta (15 per intent). Collecting real
  Sinhala / Tamil scam messages into `real_texts.csv` is the next step.

## XLM-R text model

Part 6A: **page-level threat classification from page text** - the *NLP-only* arm of the ablation study. Input = Part 5A `page_text` (`[TITLE] … [CTA] … [LABEL] …`), labels = the 5 threat classes (Part 4's label mapping), split = the **shared** `data/splits/v0.3` (never re-split: the same 68 test pages as DOM-only and Behavior-only; its fingerprint travels with every bundle and model). Part 6B (intent level, on the scam-text corpus) is postponed until the corpus has enough real scam texts.

Why XLM-R: one multilingual encoder (100 languages incl. Sinhala and Tamil) reads English, si, ta and the ~21 % "other" pages without a per-language pipeline. Why a **TF-IDF baseline**: character 2–5-grams work for any script and cost nothing - XLM-R is only worth it if it beats them on the same pages. Why **3 seeds**: with ~322 training pages one fine-tuning run is partly luck, so XLM-R is reported as mean ± std. Why **test once**: seeds, epochs and C are chosen on val / CV only.

```bash
# laptop
python scripts/train_xlmr.py token-stats  --version v0.3            # truncation at 512 per language
python scripts/train_xlmr.py baseline     --version v0.3            # TF-IDF char_wb 2-5 + LogReg
python scripts/train_xlmr.py train        --version v0.3 --smoke    # CPU pipeline check (tiny model, 1 step)
python scripts/train_xlmr.py export-bundle --version v0.3           # -> data/tmp/xlmr_bundle_v0.3.zip
# Colab: notebooks/04_xlmr_finetune_colab.ipynb (T4 GPU, 3 seeds) -> download xlmr_v0.3.zip
python scripts/train_xlmr.py import-model --zip xlmr_v0.3.zip --version v0.3
python scripts/evaluate_xlmr.py --version v0.3                      # reports/xlmr/v0.3 + ablation table
```

- **Training** (`nlp/train.py`, Hugging Face Trainer): class-weighted cross-entropy (n / (k · n_c)), lr 2e-5, ≤ 10 epochs, batch 16, warmup 0.1, weight decay 0.01, fp16 on GPU, early stopping on **val macro-F1** (patience 3, best epoch restored); seeds 42 / 43 / 44 → `models/xlmr/<v>/seed_<n>/` (safetensors, tokenizer, config, training_args, label_mapping, metrics, val + test predictions); final = seed with the best val macro-F1 → `final/` + `model_card.json`. All settings: `configs/xlmr.yaml`; base model: `.env XLMR_MODEL_NAME`.
- **Colab bundle** (~0.4 MB): examples jsonl (masked page_text only - no HTML, no URLs), label mapping, split fingerprint, the config and a self-contained copy of the training code (`tokenizer.py`, `model.py`, `train.py` never import the repo; a test checks it), `requirements-colab.txt` pinned to the laptop's transformers versions. By default only `final/` weights are downloaded (~1.1 GB); the other seeds come back as metrics + predictions.
- **import-model** refuses a zip whose split fingerprint, dataset version or label mapping differs from the laptop's, and any zip path outside the target.
- **Evaluation** (`nlp/evaluate.py`): final model re-run on the local CPU and compared with its Colab predictions (PASS = every predicted label identical and max |Δp| < 0.01; GPU vs CPU fp32 differences of ~1e-3 are expected - v0.3: labels 100 % identical, max |Δp| 0.0016); final + each seed on val and test: per-class P/R/F1, **macro P/R/F1** (primary: macro-F1), weighted-F1, accuracy, benign FPR, ROC-AUC OvR, **per language** (en / si / ta / mixed / other from Part 5A, n + small-n warning), confusion matrices (counts + normalized PNG), `misclassified.csv`, mean ± std over seeds; test metrics are added to the model card.
- **TF-IDF baseline** (`nlp/text_baseline.py`): Part 4's protocol - C ∈ {0.1, 1, 10, 100} by mean macro-F1 over the shared grouped CV folds (train+val, vectorizer fit inside each fold), refit on train+val, test once → `models/text_baseline/v0.3/`, `reports/text_baseline/v0.3/` (same format + strongest n-grams per class).
- **Serving** (`nlp/inference.py`): models load lazily on the first request (the API starts without importing torch); CPU, `no_grad`, batched; a missing model → `available: false`, "model not available".
- **Git:** weights, tokenizers, predictions and joblib files are ignored; `model_card.json`, `label_mapping.json`, `metrics.json`, `selection.json` are tracked.

v0.3 single arms (test = 68 pages, same split for every arm; the fused results are in **Fusion & ablation**):

| arm | model | CV / seed mean ± std | test macro-F1 | benign FPR |
|---|---|---|---|---|
| DOM-only (Part 4) | Random Forest | CV 0.701 ± 0.077 | 0.786 | 17.6 % |
| Behavior-only (Part 8) | Random Forest | CV 0.620 ± 0.078 | 0.682 | 20.6 % |
| Text TF-IDF (Part 6A) | char_wb 2–5 + LogReg (C = 10) | CV 0.706 ± 0.065 | 0.718 | **5.9 %** |
| Text XLM-R (Part 6A) | xlm-roberta-base, final seed 43 | 3-seed test 0.610 ± 0.062 | 0.657 | 23.5 % |

Token lengths (xlm-roberta-base tokenizer): median 740 tokens, **65 % of pages are longer than 512** (si / ta: all of them). Part 5A orders page_text by priority, so truncation cuts the trailing `[TEXT]` paragraphs and keeps title, CTAs, form labels and headings.

If the Hugging Face download fails with `CERTIFICATE_VERIFY_FAILED` on Windows (antivirus HTTPS scanning: `requests` trusts certifi, not the Windows store), download the four tokenizer files of `FacebookAI/xlm-roberta-base` by hand and pass the folder: `token-stats --tokenizer models/xlmr/base_tokenizer/xlm-roberta-base`. Colab is not affected.

## Fusion & ablation

Part 9A: the **tri-modal fusion** of the three single-modality arms (DOM, behavior, text) and the **ablation study** that compares every arm, every pair and the fusion on the same shared split. (Part 9 B-1 - the public `/api/v1/analyze` - is described under **Analyze API**; the gateway integration is B-2.)

```bash
python scripts/run_ablation.py --version v0.3                  # OOF per arm + fusion + ablation (~1 min)
python scripts/run_ablation.py --version v0.3 --reuse-oof      # keep the stored OOF tables
# optional XLM-R arm (needs a Colab GPU, ~25-30 min on a T4):
python scripts/train_xlmr.py export-bundle --version v0.3 --cv # -> data/tmp/xlmr_cv_bundle_v0.3.zip
# Colab: notebooks/06_xlmr_oof_colab.ipynb -> download xlmr_oof_v0.3.zip (a few KB)
python scripts/train_xlmr.py import-oof --zip xlmr_oof_v0.3.zip --version v0.3
python scripts/run_ablation.py --version v0.3 --reuse-oof
```

- **Out-of-fold (OOF) predictions** (`fusion/oof.py`) - why: a fusion model learns how much to trust each arm from the arms' probabilities; a probability from a model that was trained on the same page is over-confident, and the fusion would learn to over-trust that arm. So every train+val page gets its probabilities from an arm model trained on the **other** folds of the shared grouped 5-fold CV (`cv_folds.csv`, cluster-pure, checked), and every test page from the arm's **final** model (train+val). Each arm reuses its own Part's code and CV-chosen hyperparameters: DOM = Part 4 best model, Behavior = Part 8 best model (their recomputed OOF equals the OOF stored in the Part 4 / 8 bundles, max diff 5e-7), Text TF-IDF = Part 6A with the saved C, Text XLM-R = Part 6A on Colab (5 fold models, early stopping on a cluster-pure inner-validation slice of the training folds, predictions only). Output: `data/processed/fusion/<v>/oof_<arm>.{csv,json}` (tracked: ids + probabilities only).
- **Fusion strategies** (`fusion/strategies.py`), all fit on CV training folds and scored on the held-out fold: (a) **mean** of the arm probabilities; (b) **weighted** mean, weights on a 0.1 simplex grid (+ equal weights) chosen by CV macro-F1; (c) **stacking** - multinomial LogReg (balanced) on the concatenated OOF probabilities; (d) **hybrid** - XGBoost on raw DOM + behavior features + text OOF probabilities (constant / correlated features dropped on the training folds, Part 4's XGBoost settings). The **final model** = the tri-modal strategy with the best CV macro-F1 → `models/fusion/<v>/{fusion.joblib, model_card.json}`.
- **Benign-FPR operating point** (`fusion/operating_point.py`): benign if P(benign) ≥ t, else the most probable threat; t = the largest threshold with OOF benign FPR ≤ 2 % (the proposal target), chosen on train+val, applied once to test. Both argmax and threshold results are reported, with the recall cost.
- **Statistics:** paired bootstrap (1,000 resamples of the 68 test pages, seed 42) → 95 % CI of each row's test macro-F1 and of the difference "final − best single arm" (the report says when the CI includes 0). **Complementarity:** which modality got each test page right ("only DOM right", "all wrong", … + 5 example ids). **Explainability:** weights, LR coefficients, SHAP (hybrid) per arm and feature.
- **Outputs:** `reports/ablation/<v>/{ablation.md, ablation.json, test_predictions.csv, figures/}` (macro-F1 with CIs, benign FPR argmax vs threshold, confusion matrix of the final model, explanation plots).

v0.3 without XLM-R (test = 68 pages; CV = grouped 5-fold on train+val):

| row | CV macro-F1 | test macro-F1 [95 % CI] | accuracy | benign FPR argmax → at t |
|---|---|---|---|---|
| DOM-only | 0.701 ± 0.077 | 0.786 [0.652, 0.891] | 0.824 | 17.6 % → 0.0 % |
| Behavior-only | 0.620 ± 0.078 | 0.682 [0.551, 0.805] | 0.735 | 20.6 % → 0.0 % |
| Text TF-IDF | 0.706 ± 0.065 | 0.718 [0.569, 0.841] | 0.809 | 5.9 % → 0.0 % |
| DOM+Behavior (weighted) | 0.701 ± 0.077 | 0.786 [0.652, 0.891] | 0.824 | 17.6 % → 0.0 % |
| DOM+Text (mean) | 0.730 ± 0.048 | 0.824 [0.695, 0.923] | 0.853 | 8.8 % → 0.0 % |
| Behavior+Text (mean) | 0.732 ± 0.067 | 0.750 [0.592, 0.870] | 0.824 | 5.9 % → 2.9 % |
| **DOM+Behavior+Text (mean) - final** | 0.726 ± 0.081 | **0.833** [0.701, 0.928] | 0.868 | 5.9 % → **0.0 %** |
| DOM+Behavior+Text (stacking) | 0.718 ± 0.065 | 0.769 [0.638, 0.877] | 0.824 | 11.8 % → 0.0 % |
| DOM+Behavior+Text (hybrid) | 0.711 ± 0.057 | 0.807 [0.647, 0.914] | 0.853 | 8.8 % → 2.9 % |

Final model at the FPR threshold (t = 0.190): benign FPR 5.9 % → 0.0 %, threat recall 88.2 % → 67.6 %, macro-F1 0.833 → 0.741. Final − best single arm by CV (TF-IDF): +0.115 [+0.018, +0.237]; final − best single arm on test (DOM): +0.047 [−0.075, +0.174] - **the CI includes 0**, so on 68 pages the fusion cannot be shown to beat DOM-only.

## JavaScript analysis

Part 7 analyses every piece of JavaScript Part 2 found: inline scripts, `on*=` handlers and `javascript:` URLs. It works **statically**. Code is parsed into a syntax tree with [tree-sitter](https://tree-sitter.github.io/) and never executed, and external `<script src>` files are never downloaded; only their address is analysed. Part 7 **reports** API usage. Deciding intent (for example, "credential read + external fetch = exfiltration") is Part 8's job.

```bash
python scripts/analyze_js.py run --version v0.2 [--force] [--workers 4]
python scripts/analyze_js.py one --sample-id c2_phishing_000081      # grouped detections, line numbers, snippets
python scripts/analyze_js.py one --file page.html --url https://example.com/login [--json]
python scripts/analyze_js.py describe [--markdown]                    # the js_v1 feature table
```

- **Detected (tasks 5–15), including aliases:**
  - **eval:** `window["eval"]`, `(0, eval)()`, `var e = eval`, and `setTimeout` with a string;
  - **Function:** `new Function`, `x.constructor("code")`;
  - **HTML writes:** `document.write`, `innerHTML` / `outerHTML` / `insertAdjacentHTML` / `srcdoc`;
  - **Network:** `fetch`, `sendBeacon`, WebSocket / EventSource, image beacons, XMLHttpRequest (`open` method and URL, `send` body), jQuery ajax;
  - **Forms:** `form.submit()` / `requestSubmit` / `action =` / submit events;
  - **Redirects:** `location` assignments, `assign` / `replace` (also via `top` / `parent` / `document`), `window.open`, external `pushState`, meta refresh created by code;
  - **Cookies and storage:** `document.cookie` read vs write, local / session storage read vs write;
  - **Clipboard:** the clipboard API, `execCommand` copy / paste, clipboard listeners.
- **Extras for Part 8:** credential value reads (with the selector, e.g. `#password`), key / submit / beforeunload / contextmenu listeners, decoders and download triggers.
- **Facts recorded per detection:** where it is (script, line:column, byte range), how it is accessed (call / read / write / assign / construct / listener), the literal argument and URL (PII-masked), whether that URL leaves the page's site (resolved against `<base href>`), the HTTP method, the identifiers used, the enclosing function and the variable it is assigned to.
- **Error-tolerant parsing:** tree-sitter still gives a tree for broken code.
  - If more than half of a script is unparsable, the parse hits the time limit (3 s), or tree-sitter is missing, a **regex fallback** runs. Its results are marked `confidence: low`.
  - Scripts larger than 500 KB are analysed up to the limit and marked truncated.
  - The walk is iterative, so deep nesting cannot crash it.
- **Library awareness:** jQuery, Bootstrap, React, Vue, GTM / gtag, Facebook pixel, reCAPTCHA, Cloudflare, Webpack and others are recognised by license banners or short snippets. Their detections are kept but tagged `in_library` and **left out of the page-own counts**. Otherwise every benign site using jQuery would "use innerHTML and XHR".
- **Obfuscation statistics (descriptive):** entropy, line lengths, whitespace, escapes, identifier statistics, and signatures (packer, JSFuck, aaencode / jjencode, string arrays, `_0x` names, `eval(atob(...))`, base64 blobs). *Minified* (normal compression) is reported separately from *obfuscation signatures*.
- **Outputs:**
  - `data/processed/js/<version>/<sample_id>.json` (`JsAnalysisResult`, schema `js_v1`);
  - `js_features.csv` (sample_id, label, language, cluster_id + **51 features** from `configs/js_features.yaml`, page-own only);
  - `reports/js_analysis/<version>_summary.{json,md}`.

v0.2, from `reports/js_analysis/v0.2_summary.md`:
- **Parse success:** 99.6 % of 6,039 scripts parsed (23 used the lexical fallback).
- **Library code:** 5.9 % of inline scripts.
- **Speed:** 47 ms per page on average (median 8 ms); 5.4 s for all 306 pages with 4 workers.

| % of pages (page-own code) | benign | phishing | malware_delivery |
|---|---|---|---|
| reads a credential-like field | 2.6 | 19.5 | 1.7 |
| external request (literal URL) | 4.5 | 16.1 | 3.4 |
| external redirect | 0.6 | 11.5 | 0 |
| key / input listener | 9.7 | 26.4 | 1.7 |
| `location.replace` | 1.3 | 8.0 | 42.4 |

## Behavioral intent mapping

Part 7 says **which APIs** a page uses; Part 8 says **what the code is trying to do** by linking them: a sensitive **source** → the **flow** through variables, objects and calls → a dangerous **sink**. A single API is never a pattern on its own: `fetch` is on every modern site, and every login form's validation reads `#password.value`. Only the connection (this password reaches that external request) counts as evidence. Static only: nothing is executed and nothing is downloaded. Part 8 re-parses with Part 7's parser and builds on Part 7's detections; it does not detect APIs a second time.

```bash
python scripts/map_behavior.py run --version v0.3 [--force] [--workers 4]   # runs Part 2 / Part 7 for missing samples
python scripts/map_behavior.py one --sample-id c2_phishing_000081           # findings with numbered evidence chains
python scripts/map_behavior.py one --file page.html --url https://example.com/login [--json]
python scripts/map_behavior.py describe [--markdown]                         # the beh_v1 vector + pattern catalogue
python scripts/map_behavior.py train-baseline --version v0.3                 # behavior-only baseline + DOM comparison
```

- **Sources and sinks** (`configs/sources_sinks.yaml`):
  - **Sources:** credential fields, classified with Part 3's field rules by looking the selector up in the page's forms; per-key capture (`event.key` in key listeners); cookies, storage and clipboard reads; whole forms (`FormData`, `serialize`); page URL, referrer and browser fingerprint.
  - **Sinks:** requests external / internal / unknown, external form actions, redirects, clipboard writes, code execution, HTML injection, downloads and storage writes.
  - **Known collection endpoints:** collectors (Telegram bot API, Discord webhooks, ngrok, webhook.site …) and legitimate form services (Formspree, Getform, Web3Forms, Google Apps Script …). These raise the severity.
- **Data flow** (`behavior/dataflow.py`): a lightweight, explainable taint analysis over the AST, not a JavaScript interpreter.
  - **What carries taint:** `var` / `let` / `=` (with destructuring), `+=`, concatenation and template literals, object and array literals, `obj.p = v`, `push` / `append` / `Object.assign`, `JSON.stringify` and other pass-through calls, and encoders (`btoa` / `encodeURIComponent`, which mark the flow "encoded").
  - **Across functions:** function parameters and return values (matched by name), and `.then` / `forEach` callbacks.
  - **Across scripts:** HTML handlers see the inline scripts' global names.
  - **Order:** it is flow-insensitive but ordered, repeating passes until nothing changes (at most 6).
  - **Confidence:** each flow keeps the evidence chain and a confidence: high = direct and short; medium = through a function or object; low = a regex-only script.
  - **Caps:** chain length, labels per variable, nodes per expression, and time per script and page. Hitting one marks the result `truncated`; it never hangs.
- **Who triggers a sink** (`behavior/triggers.py`):
  - **auto:** top-level code, load / ready / timer callbacks, and named functions called from those.
  - **user:** click, submit and key handlers, including HTML `onclick="f()"`.
  - **unknown:** anything else.
  This separates a forced redirect or drive-by download from one the user asked for.
- **Patterns** (`configs/behavior_patterns.yaml`), each with a plain-English message, the evidence chain and its severity; library code never counts:

  | pattern | what triggers it | severity |
  |---|---|---|
  | credential_access | a credential field read in page code | low |
  | external_data_transmission | data from the page reaching another site | medium or low |
  | credential_exfiltration | credentials reaching another site, a collector or a redirect URL, or a form action changed to another site | **critical** |
  | | an address built at run time | high |
  | | only email / username | one level lower |
  | | a contact form to a form service | medium |
  | | boosted by: known endpoint, encoded data, `preventDefault()` in a submit handler | |
  | keylogging | keystrokes reaching the network | critical |
  | | keystrokes reaching storage | medium |
  | forced_redirect | an external redirect with no user action, right after reading credentials, with history manipulation, or by meta refresh | high |
  | | only after browser checks (cloaking) | medium |
  | clipboard_manipulation | a ClickFix command, or a wallet address written without a click / in a copy listener | critical |
  | | a wallet address on a click, a rewritten copy, or the clipboard sent away | high |
  | suspicious_download | a risky extension downloaded automatically | high |
  | | the same, with content decoded in the page | one level up |
  | | a risky extension on a click | medium |
  | obfuscated_execution | decode → eval / Function | high |
  | | decode → HTML containing `<script` / `<iframe` / handlers | high |
  | | a packed script that calls eval | medium |
  | anti_analysis | right-click / F12 / debugger traps / DevTools checks | low, or medium for several |
- **Intent vector and outputs:**
  - **Vector:** `configs/behavior_features.yaml` (`beh_v1`, 39 features): present / count / max severity per pattern, flow statistics, signals, and `behavior_risk_score`.
  - **Risk score:** 0–100, the capped sum of each pattern's highest-severity weight. It is descriptive; the verdict is Part 9's.
  - **Files:** `data/processed/behavior/<v>/<id>.json` (`BehaviorResult`), `behavior_features.csv`, and `reports/behavior/<v>_summary.{json,md}`.
  - **Report contents:** per-label pattern table, severities, flows, the top 10 findings, and the **false-positive check** (every benign page with a critical / high finding).
- **Behavior-only baseline** (ablation): Part 4's training and evaluation code, unchanged in protocol, on `js_features` + `behavior_features`. It uses the same split and the same CV / test protocol, and writes the same report format plus `comparison.md` (DOM-only vs behavior-only), to `reports/behavior_baseline/<v>/` and `models/behavior_baseline/<v>/`.

v0.3 (459 pages, 5 classes), from `reports/behavior/v0.3_summary.md`:
- **Run:** 0 failures; 26 s wall time with 4 workers; median 15 ms per page.
- **False positives:** **0 of 227 benign pages have a critical / high finding.**

| % of pages | benign | phishing | fake_ecommerce | crypto_scam | malware_delivery |
|---|---|---|---|---|---|
| credential exfiltration | 0 | 13.8 | 0 | 0 | 1.7 |
| forced redirect | 0 | 8.0 | 0 | 0 | 0 |
| anti-analysis | 3.5 | 8.0 | 0 | 0 | 1.7 |
| credential access (low) | 4.4 | 23.0 | 7.0 | 6.9 | 1.7 |
| highest severity critical / high | 0 | 14.9 | 0 | 0 | 0 |

| v0.3 test (68 pages) | best model | test macro-F1 | benign FPR |
|---|---|---|---|
| DOM-only (Part 4) | Random Forest | 0.786 | 17.6 % |
| Behavior-only (Part 7+8) | Random Forest | 0.682 | 20.6 % |

## Analyze API

Part 9 Batch B-1: **one call from a URL (or HTML) to a verdict.** A user (team frontend) or ThreatRadar submits a URL; C2 fetches the page itself, runs the whole tri-modal pipeline and answers with a verdict (Legitimate / Suspicious / Malicious), the threat class, a 0–100 risk score and plain-English findings. Contract + 3 example responses for teammates: [`docs/api_contract.md`](docs/api_contract.md) (OpenAPI: `docs/openapi.json`, regenerate with `python scripts/export_openapi.py`).

```bash
python scripts/calibrate_verdict.py --version v0.3   # tier thresholds -> configs/verdict.yaml (after every run_ablation.py)
python scripts/evaluate_verdict.py --version v0.3    # OOF + 68 test pages, latency -> reports/verdict/v0.3_operating_points.md
python scripts/run_api.py                            # loads every model once at start-up (GET /ready)

curl -s -X POST http://127.0.0.1:8002/api/v1/analyze -H "Content-Type: application/json" \
     -d '{"url": "https://example.com/", "source": "user"}'
curl -s -X POST http://127.0.0.1:8002/api/v1/analyze -H "Content-Type: application/json" \
     -d '{"html": "<form action=\"https://x.example/p\"><input type=password></form>", "url": "https://bank.example/"}'
```

- **Safe live fetch** (`fusion/live_fetch.py`, reusing Part 1's `StaticFetcher` - not a second fetcher). Why C2 fetches safely: the URL is attacker-controlled. One static GET, no JavaScript, no forms, no images / scripts / CSS; http / https only; 10 s timeout + 15 s whole-download cap, 5 redirects, 5 MB streamed, HTML only. **SSRF guard**: localhost, private, link-local and reserved addresses are refused for the submitted URL, every redirect hop and every address a hostname **resolves** to (`resolve_dns`; residual risk = DNS rebinding between the check and the connect, documented). A URL path / final URL ending in an executable / archive / installer extension (the `url_filters.yaml` lists), or a response with such a content type / `Content-Disposition: attachment`, is **never downloaded** → finding "URL serves a .exe file instead of a webpage" + evidence floor (malware_delivery, at least Suspicious). Other non-HTML → `inconclusive`; DNS / timeout / refused / TLS / 4xx / 5xx → `unreachable` (no verdict). Part 1's quality rules mark bot challenges, parking, suspended-hosting, error and empty pages `inconclusive` (evidence still returned) - unless the page asks for a password (placeholders never do; phishing lures say "account suspended" all the time).
- **Orchestrator** (`fusion/orchestrator.py`): Part 2 → 3 → 5A → 6A (TF-IDF + XLM-R) → 7 → 8 → the saved 9A fusion model, each through its public function, on ONE parsed page; every step timed (`timings_ms`) and checked against the 30 s budget (504 with the partial result). **Graceful degradation**: a part that raises or a model that is missing is reported as `failed` / `skipped` with the reason; the late-fusion weights are renormalized over the arms that answered, the thresholds calibrated for exactly that arm subset are used, and `degraded: true`. Models are loaded once (background thread at start-up; `XLMR_ENABLED=false` → 3 arms, no torch).
- **Verdict** (`fusion/verdict.py`, `configs/verdict.yaml`): risk_score = round(100 × (1 − P(benign))). **Malicious** below the 9A threshold (≤ 2 % OOF benign FPR), **Suspicious** below the cut-off where ≥ 95 % of OOF threat pages are caught, else **Legitimate**; threat_class = the most probable non-benign class. Thresholds are fitted on the 9A out-of-fold fused probabilities for **every subset of arms** (`fusion/calibration.py`; the full set reproduces 9A's threshold exactly). **Evidence floor**: password form → external domain / form-collection service, credential exfiltration, keylogging to the network, clipboard crypto swap, ClickFix, automatic risky download, executable URL → at least Suspicious, the rule is named; the floor never lowers a verdict.
- **Response** (`schemas/analysis.py`, `c2.analysis.v1`): status, verdict, threat_class, risk_score, class probabilities, page language, ≤ 10 findings ranked by severity (PII-masked evidence, never raw HTML), per-modality status / summary / arms, explanation (arm contributions, top features, rules), degraded, warnings (e.g. Sinhala / Tamil text-model caveat), model versions, timings.
- **API guards** (`api/guards.py`): in-memory cache per normalized URL (10 min, `cached: true`; unreachable results are not cached), per-client rate limit (30 / min → 429 + Retry-After), JSON only (415), url ≤ 2,048 chars and http(s) (422), html ≤ 5 MB (413), CORS only for `CORS_ORIGINS`. `GET /health` = liveness, `GET /ready` = models loaded + versions (503 while loading / broken).
- **Inspector**: tab "Unified Result (Part 9)" = the AnalysisResponse of the selected sample (html mode) or pasted HTML, plus a **Check a URL** box (url mode, fetched by the server): verdict badge, risk gauge, threat class, findings with severity colours, modality chips, warnings - text only.

v0.3 operating points (`reports/verdict/v0.3_operating_points.md`; flagged = Suspicious or Malicious):

| | benign FPR flagged | benign → Malicious | threat recall flagged | threat recall Malicious |
|---|---|---|---|---|
| OOF 391, 4 arms (design targets) | 25.4 % | 1.6 % | 95.5 % | 62.6 % |
| **test 68, 4 arms (live engine)** | **23.5 %** | **0.0 %** | **94.1 %** | **76.5 %** |
| test 68, 3 arms (no XLM-R) | 35.3 % | 2.9 % | 94.1 % | 58.8 % |

The evidence floor fired on 0 benign and 14 threat OOF pages and raised no verdict on v0.3 (the models already flag those pages) - it is a backstop for pages the models miss. Live engine = stored 9A test probabilities (max |Δp| ≤ 1e-6). Latency on this laptop (CPU, warm, html mode, 68 test pages): with XLM-R p50 586 ms / p95 1.3 s (model load 7.8 s), without XLM-R p50 202 ms / p95 1.0 s. A url-mode request adds the fetch time.

## ThreatRadar ingestion & dashboard APIs

Part 9 Batch B-2: **ThreatRadar pushes newly found URLs, C2 analyses them in the background and keeps the results for the team dashboard.** Teammate guide (exact request, retry rule, env vars, Node.js snippet): [`docs/threatradar_integration.md`](docs/threatradar_integration.md).

```bash
# .env: INGEST_API_KEY=<long random secret, shared with ThreatRadar>, INGEST_WORKER_ENABLED=true
python scripts/run_api.py                                       # API + background worker
curl -s -X POST http://127.0.0.1:8002/api/v1/ingest -H "Content-Type: application/json" \
     -H "X-C2-Ingest-Key: <secret>" \
     -d '{"source": "threatradar_push", "urls": [{"url": "https://x.example/", "source_ref": {"channel": "c", "message_id": 1}}]}'
curl -s "http://127.0.0.1:8002/api/v1/scans?verdict=Malicious&limit=20"
curl -s "http://127.0.0.1:8002/api/v1/stats/overview?window=24h"

python scripts/pull_threatradar.py --dir ..\..\ingestion\threat-radar\backend\data   # daily backup pull
python scripts/review_live.py review --reviewer <name>          # confirm / relabel / reject high-risk results
python scripts/review_live.py export                            # -> data/feeds/live_review_urls.csv (manual-feed format)
python scripts/demo_ingest.py [--count 20 --no-xlmr | --clear]  # demo history from the v0.3 test pages
```

- **Push → queue → worker.** `POST /api/v1/ingest` (≤ 500 URLs, `X-C2-Ingest-Key` checked in constant time; no key configured → 503) validates each URL (http/https, ≤ 2,048 chars; allow-listed sites from `threatradar_rules.yaml` skipped), queues it and answers **202** at once. A bad URL is listed in `rejected` and does not fail the batch. The **worker** is an asyncio task inside the API process (it shares the loaded models: XLM-R is not loaded twice) and analyses the queue with the 9B-1 engine: 2 at a time, 1 job start/s, 45 s per job. Transient fetch errors (timeout, connection, 5xx, 429) are retried with exponential backoff (3 attempts), while 404 / SSRF refusals are final. Jobs left `running` by a crash are re-queued on start (the queue lives in SQLite, not in memory).
- **Dedupe.** The same normalized URL analysed in the last 24 h (with a page verdict) or still queued → a `skipped_duplicate` job that reuses that result. The daily **pull** queues only URLs C2 has *never* seen (same Part 1 parsers as `collect.py import --feed threatradar`, no keyword rule needed).
- **Results store** (`store/`, SQLite `data/c2_results.db`, git-ignored, WAL, schema migrations via `PRAGMA user_version`): `scan_jobs`, `scan_results` (full AnalysisResponse JSON, never HTML), `review_queue`. Users' `/api/v1/analyze` checks are stored too (source = the request's `source`); a storage error never fails `/analyze`.
- **Never auto-trained on.** Malicious results, and Suspicious ones with risk ≥ 70 (`configs/ingest.yaml`), go to the review queue. Only labels a person **confirms** are exported, as `url,label,language_hint,source,notes` rows (Telegram / Reddit → `social_media_report`, otherwise `other`; notes carry the analysis id). They enter the dataset through the normal Part 1 pipeline. Feeding the model's own verdicts back as labels would turn its mistakes into "truth".
- **Read APIs** (CORS from `CORS_ORIGINS`): `GET /api/v1/scans` (filters `source, verdict (none = no verdict), threat_class, since, q`, cursor pagination), `GET /api/v1/scans/{id}` (stored AnalysisResponse), `GET /api/v1/stats/overview?window=24h|7d|30d` (by verdict / status / class / source / language, top flagged domains + imitated brands, per-hour series (per day for 30d), queue, review queue, worker), `GET /api/v1/feed/stream` (Server-Sent Events, `event: scan` per finished scan), `GET /api/v1/research/summary` (dataset, ablation rows with bootstrap CIs, operating points, model versions, read from existing reports only). **Every URL / domain is defanged** (`hxxps://example[.]com`) and no page HTML ever leaves C2.

Demo on this laptop (`demo_ingest.py`, 68 v0.3 test pages, 4 arms, 53 s): 28 Legitimate / 14 Suspicious / 26 Malicious, 32 items in the review queue.

## API

| Method | Path | Status |
|---|---|---|
| GET | `/health` | ✅ returns `{"status": "ok", "service": "c2"}` (liveness) |
| GET | `/ready` | ✅ Part 9 B-1: 200 + arms / model versions once every model is loaded, 503 while loading or broken |
| POST | `/api/v1/dom-features` | ✅ Part 3: same body → `DomResult` (52-feature vector in dictionary order + evidence). No `url` → `base_url_known = 0` and external features 0 |
| POST | `/api/v1/preprocess` | ✅ Part 2: body `{"html": "...", "url": "..." or null}` → `ParsedPage` JSON (same as the stored files). `url` is never fetched. Body > 5 MB → `413` |
| POST | `/api/v1/js-analysis` | ✅ Part 7: same body → `JsAnalysisResult` (detections with line numbers / arguments / masked snippets, scripts with obfuscation stats, external scripts, js_v1 features). Nothing is executed or downloaded |
| POST | `/api/v1/content` | ✅ Part 5: same body → `PageText` (segments per field with language, page language + confidence + method, model-ready `page_text`). Text is prepared, nothing is classified |
| POST | `/api/v1/text-prediction` | ✅ Part 6A: same body → `TextPrediction` (Part 2 → 5A page_text → fine-tuned XLM-R + TF-IDF baseline: predicted class + probability per class, XLM-R token count / truncation). A model not trained yet answers `available: false` + "model not available" (still 200) |
| POST | `/api/v1/behavior` | ✅ Part 8: same body → `BehaviorResult` (sources, sinks, flows with evidence chains, findings with severity and message, beh_v1 intent vector, risk score). Runs Part 2 + 7 + 8; nothing is executed or downloaded |
| POST | `/api/v1/analyze` | ✅ Part 9 B-1: `{"url": ...}` (C2 fetches safely) or `{"html": ..., "url"?: ...}` → `AnalysisResponse` (`c2.analysis.v1`: verdict, threat class, risk score, findings, modalities, explanation). See **Analyze API** above |
| POST | `/api/v1/ingest` | ✅ Part 9 B-2: ThreatRadar push (`X-C2-Ingest-Key`), ≤ 500 URLs → 202 `{accepted, duplicates, rejected[], job_ids}`. See **ThreatRadar ingestion** above |
| GET | `/api/v1/scans`, `/api/v1/scans/{id}` | ✅ Part 9 B-2: scan history (filters, cursor pagination) / one stored analysis, URLs defanged |
| GET | `/api/v1/stats/overview` | ✅ Part 9 B-2: dashboard numbers for `window=24h\|7d\|30d` |
| GET | `/api/v1/feed/stream` | ✅ Part 9 B-2: live feed (Server-Sent Events) |
| GET | `/api/v1/research/summary` | ✅ Part 9 B-2: research-page numbers read from the existing reports |
| POST | `/analyze-html` | stub (501) – compatibility route for `backend/api-gateway`, which currently sends `{"url": ...}`; the gateway should switch to `/api/v1/analyze` (Batch B-2) |
| GET | `/api/v1/dev/...`, `/inspector` | developer only – see below (404 unless `APP_ENV=development`) |

The gateway reaches C2 through its `C2_URL` env var (e.g. `http://localhost:8002`). Swagger UI with example requests: `/docs`. Every response carries `X-Content-Type-Options: nosniff`.

## Developer inspector

A small web page that shows **how the C2 engine sees a page**, for debugging, supervisor demos and progress presentations. It is a developer tool, not the product UI: the team dashboard (`frontend/scamtrace-dashboard`) is separate.

```bash
python scripts/run_api.py        # APP_ENV=development (default in .env.example)
```

Then open **http://127.0.0.1:8002/inspector** (Swagger: http://127.0.0.1:8002/docs).

- **Left:** pick a frozen dataset version, filter by label, language, "has password input", "external form action", "misclassified (test)" (test pages the best Part 4 model got wrong) or "has critical behavior finding" (stored Part 8 results), search by id or title, and click a sample. Up/Down arrows move through the list.
- **Top:** paste HTML (and optionally its URL) or choose a local `.html` file, then press **Analyze**. This calls `POST /api/v1/preprocess`. The file is read as text and never rendered.
- **Tabs:** DOM Features (Part 3, plus the Part 4 "DOM baseline prediction" card with the predicted class, probability bars, the top 5 features pushing towards or away from it, and a PILOT badge; then evidence, non-zero features per group next to the label medians, and a full table) · Overview (sizes, timings, errors, count cards) · Text (headings, paragraphs, visible and hidden text; Sinhala/Tamil fonts) · Forms (action, EXTERNAL badge, inputs, buttons) · Scripts (inline JS as text, external scripts, handlers, `javascript:` URLs) · Links & Resources (internal/external ratio, stylesheets, iframes, meta refresh) · DOM (tag-count chart, lazy skeleton tree) · Raw JSON (copy button) · Safe Preview (dataset samples only) · JS Analysis (Part 7: summary chips per API category, the detections table with snippets shown as monospace text only, external-URL / library / confidence badges, per-script obfuscation cards and the external scripts table) · Behavior (Part 8: risk-score gauge, finding cards coloured by severity with the message, factors and the **evidence chain as numbered steps** (line + code, monospace, text only), the flows table with expandable chains, the intent vector and the sinks with their triggers) · Content (Part 5: page language with confidence, method and a script-ratio bar, language shares, the highlighted CTA list, segments grouped by field with a language chip each, and `page_text` in monospace; text only; plus the Part 6A **"Text model (Part 6)"** card: XLM-R and TF-IDF predicted class with probability bars, token count / truncated badge, "model not available" when a model is missing). · Fusion (Part 9: per-arm probability bars side by side, the fused probabilities, the argmax verdict and the verdict at the ≤ 2 % benign-FPR threshold, which arm drove it and the top inputs - weights × probabilities, LR coefficients or SHAP). The greyed-out tab is the placeholder for the unified result (Part 9B).
- **Deep links:** the URL hash remembers the version, sample and tab (e.g. `/inspector#v=v0.1&sample=c2_phishing_000081&tab=forms`). This is handy for presentations.

Dev endpoints (only when `APP_ENV=development`; any other value gives `404`):

| Path | Returns |
|---|---|
| `GET /api/v1/dev/versions` | frozen versions (newest first) with counts and how many samples Part 2 processed |
| `GET /api/v1/dev/samples?version=v0.1&label=&language=&q=&has_password=&external_form_action=&misclassified=&has_critical_behavior=` | sample list from the manifest + stored Part 2 JSON (HTML is not re-parsed) |
| `GET /api/v1/dev/samples/{id}/parsed?version=v0.1` | the stored `ParsedPage`. A missing one is processed on the fly but not saved (header `X-Parsed-Source`) |
| `GET /api/v1/dev/samples/{id}/dom-features?version=v0.1` | the stored Part 3 `DomResult`, or one computed on the fly (header `X-Features-Source`) |
| `GET /api/v1/dev/samples/{id}/dom-prediction?version=v0.1` | Part 4: probabilities from every trained baseline, the best model's top 5 contributions, the split and whether it is misclassified on test (`404` if no model has been trained) |
| `GET /api/v1/dev/samples/{id}/js-analysis?version=v0.2` | the stored Part 7 `JsAnalysisResult`, or one computed on the fly (header `X-Js-Source`) |
| `GET /api/v1/dev/samples/{id}/content?version=v0.3` | the stored Part 5 `PageText`, or one computed on the fly (header `X-Content-Source`) |
| `GET /api/v1/dev/samples/{id}/text-prediction?version=v0.3` | Part 6A `TextPrediction` of the models trained on that version (+ true label and split) |
| `GET /api/v1/dev/samples/{id}/fusion?version=v0.3` | Part 9A: the saved fusion model on the STORED arm probabilities (OOF for train / val pages, final arm models for test pages): per-arm probabilities, fused probabilities, argmax verdict, verdict at the benign FPR threshold, which arm / feature drove it (`404` no model, `409` stale) |
| `GET /api/v1/dev/samples/{id}/behavior?version=v0.3` | the stored Part 8 `BehaviorResult`, or one computed on the fly (header `X-Behavior-Source`) |
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
  c2_results.db     Part 9 B-2 scan history + queue + review queue (SQLite, git-ignored)
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

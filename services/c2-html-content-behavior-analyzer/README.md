# C2 – HTML Content & Behavior Analyzer

Part of **J26-SE-316 – AI-Based Multi-Modal Web Threat Detection System** (ScamTrace).

C2 is a Python (FastAPI) microservice that takes a webpage's raw HTML and analyzes it in three modalities:

1. **DOM structure** – forms, password/hidden fields, external form actions, iframes, scripts, link ratios.
2. **Multilingual text content** (English, Sinhala, Tamil) – social-engineering intent classified with fine-tuned XLM-RoBERTa.
3. **Static JavaScript behavior** – AST parsing (never executes code), dangerous API detection, source → sink behavioral intent mapping.

It returns one unified JSON result: `verdict`, `risk_score`, per-modality results and human-readable `findings`.

**Threat classes:** `benign`, `phishing`, `fake_ecommerce`, `crypto_scam`, `malware_delivery`.

> **Status:** skeleton only. `GET /health` works; every other module is a stub (`NotImplementedError`) to be implemented part by part.

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
python scripts/run_api.py                          # or: make run-api
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
- **Never commit `data/raw/`** (already git-ignored, together with `data/feeds/`).
- Windows Defender quarantines many phishing pages. The collector writes pages only inside this project's `data/` folder (`data/tmp/` while saving, then `data/raw/`), never the system Temp folder, so a Defender exclusion for this project's `data\` folder is enough. Never exclude the whole project, your user folder or Temp. Pages Defender still removes are marked `blocked_by_antivirus`; files quarantined later show up as "file not found" in `build_metadata.py validate`.
- The fetcher never submits forms, never downloads linked resources, and refuses `localhost`/private-network addresses.

## API

| Method | Path | Status |
|---|---|---|
| GET | `/health` | ✅ returns `{"status": "ok", "service": "c2"}` |
| POST | `/api/v1/analyze` | stub (501) – body `{"html": "...", "url": "..."}` |
| POST | `/analyze-html` | stub (501) – compatibility route for `backend/api-gateway`, which currently sends `{"url": ...}` |

The gateway reaches C2 through its `C2_URL` env var (e.g. `http://localhost:8002`).

## Structure

```
configs/            YAML config: paths/splits/model params, labels, languages, intent taxonomy, JS rules, sources/sinks
data/
  raw/<label>/      collected HTML (git-ignored)
  metadata/         dataset_schema.json, metadata.csv, candidates.csv, manual_urls_template.csv
  feeds/            downloaded feed files (git-ignored)
  tmp/              pages being saved by the collector (git-ignored, emptied automatically)
  interim/          after dedup (git-ignored)
  processed/        parsed_html, dom_features, text, js, behavior (git-ignored)
  corpus/{en,si,ta} multilingual text corpus
  splits/           train/val/test
models/             dom_baseline/, xlmr/ (weights git-ignored)
reports/            dataset_stats/, metrics/, figures/
notebooks/          EDA, baselines, Colab fine-tuning
scripts/            thin argparse CLIs that call src/
src/c2_analyzer/    the package (see table above)
tests/              pytest suite + fixtures/sample_pages/
```

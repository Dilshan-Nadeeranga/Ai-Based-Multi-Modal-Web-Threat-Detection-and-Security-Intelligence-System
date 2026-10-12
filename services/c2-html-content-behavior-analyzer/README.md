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
  metadata/         dataset_schema.json + metadata.csv
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

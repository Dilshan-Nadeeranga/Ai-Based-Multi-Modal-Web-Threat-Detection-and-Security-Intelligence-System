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
- [ ] Part 1 – remaining batches (near-duplicate detection, verification, statistics, splits)
- [ ] Parts 2–9

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
uvicorn c2_analyzer.api.main:app --reload --port 8002
```
Port **8002** (C3 uses 8003, C4 uses 8000).

## Integration note
`backend/api-gateway/src/server.js` calls `POST ${C2_URL}/analyze-html` with `{ url }`, while C2's main contract is `POST /api/v1/analyze` with `{ html, url? }`. `/analyze-html` is a 501 stub kept for compatibility; reconcile the contract with the team in Part 9.

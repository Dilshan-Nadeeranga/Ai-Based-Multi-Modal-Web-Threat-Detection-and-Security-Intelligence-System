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

Status: skeleton only — `GET /health` is the only implemented logic. Implement one part at a time, when asked.

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

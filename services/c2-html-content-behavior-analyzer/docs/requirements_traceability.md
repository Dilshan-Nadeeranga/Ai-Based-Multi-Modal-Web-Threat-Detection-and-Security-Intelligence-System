# Requirements traceability - C2 HTML Content & Behavior Analyzer

Status on dataset **v0.3** (459 pages, 5 classes; shared split 322 train / 69 val / 68 test,
5 grouped CV folds over train+val). Every number below is copied from a report in
`reports/` (path given); nothing is estimated here. Status: **met** / **partially met** /
**not met** / **pending 6B** / **preliminary**.

> **Requirement texts.** The proposal document with the FR / NFR / RAI / TE wording is not in
> the repository and could not be read here. Rows whose meaning is stated in the
> requirements brief for this batch are filled in (NFR1 ≤ 5 s, NFR5 50 URLs/s, FR5
> embeddings, RAI2 fairness, RAI6 / TE8 analyst override, TE3 explanation faithfulness,
> behavioral detection ≥ 90 % TPR). For every other id the "requirement" cell says
> **TEXT NEEDED**: paste the proposal's wording and pick the implementation / evidence from
> the inventory at the end (already mapped to files, endpoints, tests and reports).

## Functional requirements

| id | requirement | where implemented | how verified | measured result | status |
|---|---|---|---|---|---|
| FR1 | TEXT NEEDED | - | - | - | to map |
| FR2 | TEXT NEEDED | - | - | - | to map |
| FR3 | TEXT NEEDED | - | - | - | to map |
| FR4 | TEXT NEEDED | - | - | - | to map |
| FR5 | Multilingual text embeddings (XLM-R) as a model input | `nlp/` (6A fine-tuned page classifier = the Text XLM-R arm); fusion `fusion/` | `tests/test_xlmr.py`, `reports/ablation/v0.3/ablation.md` | XLM-R arm test macro-F1 0.657 (CV 0.680 ± 0.041); in the final tri-modal fusion. The frozen-base **embedding + PCA hybrid variant is NOT built** (item 6 skipped this batch) | partially met - fine-tuned XLM-R used as a probability arm, embedding variant not built |
| FR6 | TEXT NEEDED | - | - | - | to map |
| FR7 | TEXT NEEDED | - | - | - | to map |
| FR8 | TEXT NEEDED | - | - | - | to map |
| FR9 | TEXT NEEDED | - | - | - | to map |
| FR10 | TEXT NEEDED | - | - | - | to map |

## Non-functional requirements

| id | requirement | where implemented | how verified | measured result | status |
|---|---|---|---|---|---|
| NFR1 | ≤ 5 s per URL analysis | `fusion/orchestrator.py`, `fusion/live_fetch.py`, `POST /api/v1/analyze` | `scripts/bench_api.py` → `reports/performance/v0.3_performance.md` (a) | 19 of 20 benign URLs fetched (1 unreachable); fetch p50 669 ms / p95 2,261 ms; end-to-end (fetch + analysis) with XLM-R p50 1,561 ms / p95 3,996 ms / max 5,154 ms (18/19 ≤ 5 s), without XLM-R p50 1,142 ms / p95 3,537 ms (19/19 ≤ 5 s) | met at p95 (one URL of 19 took 5.15 s with XLM-R; network time dominates the tail) |
| NFR2 | TEXT NEEDED | - | - | - | to map |
| NFR3 | TEXT NEEDED | - | - | - | to map |
| NFR4 | TEXT NEEDED | - | - | - | to map |
| NFR5 | 50 URLs/s throughput (scalability) | one uvicorn process; in-process worker `ingest/worker.py` | `scripts/bench_api.py` → `reports/performance/v0.3_performance.md` (b) | one process, html mode: with XLM-R 1.42-1.49 req/s at 1-20 clients (p95 1.6 s at 1 client, 31.1 s at 20); without XLM-R peak 3.34 req/s at 1 client (2.31 at 20); ≈ 34 / 15 such processes needed for 50 URLs/s; peak RSS 1.8 GB / 0.6 GB; at 20 clients 6 / 1 of 80 requests exceeded the 30 s budget (504) | not met - one laptop process; 50 URLs/s is a server-scale target needing horizontal scaling (report lists what) |
| NFR6 | TEXT NEEDED | - | - | - | to map |
| NFR7 | TEXT NEEDED | - | - | - | to map |

## Responsible-AI requirements

| id | requirement | where implemented | how verified | measured result | status |
|---|---|---|---|---|---|
| RAI1 | TEXT NEEDED | - | - | - | to map |
| RAI2 | Fairness: Sri Lankan SME / local sites and si / ta pages must not be flagged more | `fusion/fairness.py`, `scripts/evaluate_fairness.py` | `reports/fairness/v0.3_fairness.md`, `tests/test_evaluation_reports.py` | Benign Suspicious-or-worse FPR (OOF + test, 227 pages): LK SME 0/9 = 0.0 % [0.0, 29.9], LK other 6/42 = 14.3 % [6.7, 27.8], non-LK 51/176 = 29.0 % [22.8, 36.1]; Malicious 0 / 0 / 1.7 %. si 2/10 = 20.0 %, ta 1/4 = 25.0 % vs en 49/208 = 23.6 % (Fisher p = 1.0). Disparity found instead for detected language "other" 17/44 = 38.6 % vs en 21.8 % (p = 0.031) | partially met - LK SMEs not flagged more (small n, wide CIs); foreign-language ("other") pages are |
| RAI3 | TEXT NEEDED | - | - | - | to map |
| RAI4 | TEXT NEEDED | - | - | - | to map |
| RAI5 | TEXT NEEDED | - | - | - | to map |
| RAI6 | Analyst override / human in the loop | `ingest/review.py`, `scripts/review_live.py` (terminal review queue → manual feed); live results never auto-added to training | `tests/test_ingest.py` (review rules, export, rejected never exported) | 9B-2 demo: 32 pending reviews from 68 pages. Dashboard Confirm / Reject / Override / allow-list API (item 5) **not built** this batch | partially met - terminal review exists, dashboard override + allow-list pending |

## Technical evaluation requirements

| id | requirement | where implemented | how verified | measured result | status |
|---|---|---|---|---|---|
| TE1 | TEXT NEEDED | - | - | - | to map |
| TE2 | TEXT NEEDED | - | - | - | to map |
| TE3 | Explanation faithfulness (every finding's evidence exists in the analysed page) | findings built from Part 3 / 8 evidence (`fusion/aggregator.py`); the validator that drops unlocatable findings (item 4) **not built** | - | - | not met - validator pending (item 4 skipped this batch) |
| TE4 | TEXT NEEDED | - | - | - | to map |
| TE5 | TEXT NEEDED | - | - | - | to map |
| TE6 | TEXT NEEDED | - | - | - | to map |
| TE7 | TEXT NEEDED | - | - | - | to map |
| TE8 | Analyst override (as RAI6) | see RAI6 | see RAI6 | see RAI6 | partially met (as RAI6) |

## Evaluation metrics

The proposal's six metric names are not available here; the measured metrics are:

| metric | target | where measured | result (v0.3) | status |
|---|---|---|---|---|
| Behavioral intent detection rate | ≥ 90 % TPR | `scripts/eval_behavior.py` → `reports/behavior/benchmark_v1.md` | 14/18 = 77.8 % [54.8, 91.0] TPR, 0/15 = 0.0 % [0.0, 20.4] FPR on 33 hand-labelled REAL page cases (31 pages, all unconfirmed); credential exfiltration 8/10, anti-analysis 5/5; keylogging and download have 0 real positives (not measurable) | **preliminary (real pages only, small n)** |
| Macro-F1 (final tri-modal fusion, test 68) | - | `reports/ablation/v0.3/ablation.md` | 0.795 [0.654, 0.906] (CV 0.768 ± 0.073); best single arm DOM 0.786; final − TF-IDF +0.077 [−0.019, +0.201] (CI includes 0) | reported |
| Benign FPR | ≤ 2 % | `reports/ablation/v0.3/ablation.md`, `reports/verdict/v0.3_operating_points.md` | final at the threshold: OOF 1.6 %, test 0.0 % (threat recall 76.5 %); live verdict tiers (4 arms): Malicious 0.0 % / Suspicious-or-worse 23.5 % on test | met at the Malicious tier; the Suspicious "check first" band costs ~24 % |
| Threat recall (flagged) | 95 % OOF (Suspicious tier design target) | `reports/verdict/v0.3_operating_points.md` | OOF 95.5 %; test 94.1 % Suspicious-or-worse, 76.5 % Malicious | met (design) |
| End-to-end latency | ≤ 5 s | `reports/performance/v0.3_performance.md` | 19 of 20 benign URLs fetched (1 unreachable); fetch p50 669 ms / p95 2,261 ms; end-to-end (fetch + analysis) with XLM-R p50 1,561 ms / p95 3,996 ms / max 5,154 ms (18/19 ≤ 5 s), without XLM-R p50 1,142 ms / p95 3,537 ms (19/19 ≤ 5 s) | met at p95 (one URL of 19 took 5.15 s with XLM-R; network time dominates the tail) |
| Throughput | 50 URLs/s | `reports/performance/v0.3_performance.md` | one process, html mode: with XLM-R 1.42-1.49 req/s at 1-20 clients (p95 1.6 s at 1 client, 31.1 s at 20); without XLM-R peak 3.34 req/s at 1 client (2.31 at 20); ≈ 34 / 15 such processes needed for 50 URLs/s; peak RSS 1.8 GB / 0.6 GB; at 20 clients 6 / 1 of 80 requests exceeded the 30 s budget (504) | not met on one laptop process |

## Evidence inventory (for mapping the remaining ids)

| capability | implementation | API / CLI | verified by | result |
|---|---|---|---|---|
| Dataset collection, metadata, dedup, frozen versions | `dataset/` | `collect.py`, `build_metadata.py`, `deduplicate.py`, `dataset_stats.py` | `test_dataset_*.py`, `test_collection*.py` | v0.3 manifest 459 pages, 5 classes |
| Safe HTML preprocessing (no JS, no fetch) | `preprocessing/` | `POST /api/v1/preprocess` | `test_preprocessing.py` | 0 failures on v0.3 |
| DOM structural features (52) + DOM classifier | `dom/`, `classifiers/dom_baseline/` | `POST /api/v1/dom-features` | `test_dom.py`, `test_dom_baseline.py` | DOM-only test macro-F1 0.786 |
| Multilingual content + language ID (en / si / ta) | `content/` | `POST /api/v1/content` | `test_content.py` | v0.3: en 330, si 7, ta 3, mixed 18, other 97 |
| XLM-R page classification (6A) | `nlp/` | `POST /api/v1/text-prediction` | `test_xlmr.py` | test macro-F1 0.657; TF-IDF 0.718 |
| Intent-level text model (6B) | - | - | - | **pending 6B** (no real si / ta scam texts) |
| Static JS analysis (AST, never executed) | `js_analyzer/` | `POST /api/v1/js-analysis` | `test_js_analyzer.py` | parse success 99.6 % (v0.2) |
| Behavioral intent mapping (source → sink) | `behavior/` | `POST /api/v1/behavior` | `test_behavior.py`, benchmark above | 0 of 227 benign pages with critical / high finding |
| Tri-modal fusion + ablation | `fusion/` | `run_ablation.py` | `test_fusion.py` | see metrics |
| Verdict tiers + evidence floor | `fusion/verdict.py` | `POST /api/v1/analyze` | `test_analyze.py` | see metrics |
| Safe live fetch (SSRF / DNS guard) | `dataset/fetcher.py`, `fusion/live_fetch.py` | `POST /api/v1/analyze {url}` | `test_analyze.py` (8 private / metadata URLs refused) | - |
| ThreatRadar ingestion, results store, read APIs, SSE | `ingest/`, `store/` | `POST /api/v1/ingest`, `GET /api/v1/scans`, `/stats/overview`, `/feed/stream`, `/research/summary` | `test_ingest.py` | demo 68 pages: 28 / 14 / 26 |
| PII masking + defanged URLs | `utils/pii.py`, `utils/defang.py` | all read APIs | `test_ingest.py`, `test_preprocessing.py` | no raw HTML / live URL in any read API (test) |
| Dashboard UI | `frontend/scamtrace-dashboard/src/features/c2/` | `/c2` routes | lint + build | - |

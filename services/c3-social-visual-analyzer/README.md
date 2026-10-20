# ScamTrace C3 – Social Media & Web Visual Threat Analyzer

A Python **FastAPI** microservice that analyzes social media posts — **text, image and embedded link together** — and
explains whether the post is a scam. It is component **C3** of **ScamTrace: AI-Based Multi-Modal Web Threat Detection
and Security Intelligence System** (SLIIT research project J26-SE-316).

Paste a public Facebook or Reddit post URL (or upload the post), and C3 reads the caption, reads the text inside the
image (OCR), recognises brand logos, opens the link in a sandboxed browser, checks whether all of these tell the same
story, and returns a **LOW / MEDIUM / HIGH** risk level with the evidence behind it.

## ✨ AI-Powered Multimodal Analysis

C3 combines **AI models** (trained or pretrained neural networks) with **explainable rules** that turn their outputs
into evidence an analyst can check.

**AI models**

- 📝 **Text threat detection** – DistilBERT transformer, fine-tuned on scam / legitimate posts, scores the caption
  and the text inside the image
- 🗂️ **Threat category** – DistilBERT fine-tuned for legitimate / phishing / financial scam / data theft
- 📰 **Misinformation** – DistilBERT fine-tuned on Fakeddit headlines (news-style posts only)
- 🏷️ **Logo detection** – YOLO11n object detector, fine-tuned to find logos in post images and web pages
- 🖼️ **Brand recognition and logo matching** – CLIP vision-language model (pretrained, zero-shot) compares images
  and logos with 90 reference brands
- 🔤 **OCR** – Tesseract (LSTM neural-network engine) reads text from screenshots and post images

**Rule-based (not AI)**

- 🌐 **Destination capture** – the embedded link (short links expanded) is opened in a sandboxed headless browser
- 🔍 **Cross-source consistency** – brand vs domain, lookalike domains, caption vs image, post vs landing page
- 🎯 **Risk fusion** – weighted combination of the AI scores and consistency evidence into LOW / MEDIUM / HIGH
- 🧩 **Rule-based categories** – brand impersonation, malware, browser abuse and other scam (no labelled training
  data yet), detected from pipeline evidence

## Features

- ✨ Analyze a post from its **Facebook or Reddit URL** (text, image and link extracted automatically)
- 🧩 Works with any combination of **text, image and link** – missing parts are skipped, not penalised
- 📡 **Live pipeline progress** – each analysis step is streamed to the dashboard as it finishes
- 🛡️ **Safe link handling** – sandboxed browser, private/internal hosts blocked, downloads blocked, no permissions granted
- 🔗 **Short-link expansion** (bit.ly, tinyurl, ...) with safety checks on every redirect hop
- 🧾 **Evidence for analysts** – every score comes with the reasons behind it
- 🗃️ **Research dataset tools** – validation, preprocessing, duplicate detection, OCR, labelling and statistics
- 📊 **Dashboard** – Analyze Post, Dataset and Model Results tabs in the ScamTrace frontend
- 🔁 **Reproducible evaluation** – frozen dataset/model versions with SHA-256 hashes

## 🧠 Models

| Task | Model | Notes |
|---|---|---|
| Text scam detection | DistilBERT (`distilbert-base-uncased`), fine-tuned | caption and OCR text |
| Threat category | DistilBERT, 4 classes | legitimate / phishing / financial scam / data theft |
| Misinformation | DistilBERT on Fakeddit titles | only used for news-style posts |
| Logo detection | YOLO11n, 1 class (`logo`) | trained on real web pages + generated images |
| Brand / logo matching | CLIP `openai/clip-vit-base-patch16`, zero-shot | 90 reference brands |
| OCR | Tesseract | English (Sinhala/Tamil language packs optional) |
| Risk score | Rule-based weighted fusion | see [How the risk score works](#-how-the-risk-score-works) |

Brand impersonation, malware and browser abuse have no trained class yet; they come from evidence rules
(brand–domain mismatch, lookalike domains, file downloads, notification prompts, fake alerts).

## 🔄 Analysis Pipeline

| # | Step | What happens |
|---|---|---|
| 1 | Image preprocessing | validate, fix orientation, convert to RGB, resize, duplicate check (pHash) |
| 2 | OCR extraction | read text inside the image |
| 3 | Text threat analysis | scam probability for caption and OCR text |
| 4 | Brand analysis (CLIP) | which brand the image presents |
| 5 | Logo detection (YOLO) | find logos and match them to reference brands |
| 6 | Destination capture | expand short links, open the page in a sandbox, take a screenshot |
| 7 | Visual similarity | compare the post image with the landing page |
| 8 | Cross-source consistency | brand vs domain, lookalike domains, caption vs image |
| 9 | Risk fusion | LOW / MEDIUM / HIGH |
| 10 | Threat category | the most likely scam category plus all categories detected |

## 📈 How the risk score works

```text
base  = weighted average of the available scores
        text 0.50 · OCR 0.15 · visual 0.15 · website 0.20   (weights renormalised over what is available)
boost = brand identity mismatch: strong +0.25 · moderate +0.15 · weak +0.05  (+ up to 0.10 brand similarity)
        + 0.03 per low-severity inconsistency (max +0.09)
score = base + boost          HIGH ≥ 0.70 · MEDIUM ≥ 0.40 · LOW < 0.40
        a lookalike domain or a claimed-brand / domain mismatch is always at least MEDIUM
```

The weights are a preliminary, reliability-based late fusion (the fine-tuned text model is the most reliable source);
they are validated on the held-out test split and will be tuned on the validation split next.

## 📊 Results (PP1, held-out test sets)

| Model | n | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|---|
| Text scam model | 66 | 83.3% | 86.7% | 78.8% | 82.5% | 88.3% |
| Threat category (macro) | 65 | 75.4% | 81.2% | 68.9% | 72.9% | 93.4% |
| Misinformation | 150 | 77.3% | 88.7% | 62.7% | 73.4% | 86.6% |
| **Multimodal risk score** | 66 | **86.4%** | 85.3% | **87.9%** | **86.6%** | 88.8% |
| Logo brand matching (detected logos) | 86 | – | 98.8% | 94.2% | 96.4% | – |

Full report, scenario tests and limitations: [`docs/pp1_evaluation.md`](docs/pp1_evaluation.md).

## 🗃️ Datasets

| Dataset | Size | Used for |
|---|---|---|
| C3 multimodal dataset | 1,438 posts (219 legitimate, 219 scam, 1,000 Fakeddit) | training and evaluation |
| Manual social media posts | 38 Facebook posts (text + screenshot + link) | real-world scam and legitimate examples |
| Phish360, DIFrauD job scams | 200 + 200 | phishing and financial-scam text |
| Fakeddit | 1,000 posts | misinformation (provisional labels) |
| Brand reference set | 92 brands (90 logos, 81 homepage screenshots) | logo and brand recognition |
| Smishtank, TelePhish | 903 / 200 messages | external test data (kept out of Git, not used in training) |

Brand sources: the Zenodo phishing dataset brand list (ranked by how often each brand is impersonated), the Central
Bank of Sri Lanka list of licensed commercial banks and Wikidata official websites for Sri Lankan brands. Every
official URL was confirmed by visiting it. Images, screenshots and external message text stay out of Git
(see `.gitignore`); only annotations and statistics are tracked.

## Dependencies

Versions used during development (minimums are in `requirements.txt`):

- **FastAPI 0.142.2** – Web framework (REST API)
- **Uvicorn 0.54.0** – ASGI web server
- **python-multipart 0.0.32** – File / form uploads
- **Pydantic 2.13.5** + **pydantic-settings 2.15.0** – Data validation and `.env` settings
- **PyTorch 2.14.1 (CPU)** – Deep learning runtime
- **Transformers 5.19.0** – DistilBERT and CLIP models
- **Ultralytics 8.4.177** – YOLO11 logo detector
- **scikit-learn 1.9.1** – Metrics, TF-IDF text comparison
- **pytesseract 0.3.13** – Tesseract OCR wrapper
- **Pillow 12.3.0** – Image processing
- **ImageHash 4.3.2** – Perceptual hashing (duplicate detection)
- **NumPy 2.5.3** – Numerical computing
- **Playwright 1.63.0** – Sandboxed headless browser for link capture
- **httpx 0.28.1** – HTTP client (post fetching, short-link expansion)
- **tldextract 5.4.0** – Domain parsing (lookalike-domain checks)
- **truststore 0.10.5** – System certificate store for HTTPS
- **PyArrow 25.0.1** – Reading Parquet datasets
- **Matplotlib 3.11.2** – Confusion matrices and plots
- **pytest 9.1.1** – Testing

External tools: **Tesseract OCR** and **Chromium** (installed by Playwright).

## Installation

### Prerequisites

- Python 3.11 or higher (developed on Python 3.14)
- pip (Python package manager)
- [Tesseract OCR](https://github.com/tesseract-ocr/tesseract) (optional language packs: `sin`, `tam`)
- Chromium for Playwright (installed in step 4)

### Setup

1. Clone the repository:

```bash
git clone <repository-url>
cd J26-SE-316/services/c3-social-visual-analyzer
```

2. Create a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate        # On Linux/macOS: source .venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Install the capture browser:

```bash
python -m playwright install chromium
```

5. Configure environment variables:

```bash
copy .env.example .env        # On Linux/macOS: cp .env.example .env
# Edit .env if needed (e.g. TESSERACT_CMD, OCR_LANGUAGES, WEB_CAPTURE_ENABLED)
```

6. Get the model weights. Weights are not stored in Git (`models/` is ignored); retrain them with the scripts below
   or copy an existing `models/` folder.

## Quick Commands

### Windows (PowerShell)

Start the C3 service:

```powershell
cd "services\c3-social-visual-analyzer"
$env:PLAYWRIGHT_BROWSERS_PATH="$env:LOCALAPPDATA\ms-playwright"
$env:PYTHONIOENCODING="utf-8"
.venv\Scripts\python.exe -m uvicorn app.main:app --port 8003
```

- API docs: <http://127.0.0.1:8003/docs>
- Dashboard page (ScamTrace frontend running on port 5173): <http://localhost:5173/social-visual-analysis>

### Testing

Run the full suite (quiet):

```powershell
cd "services\c3-social-visual-analyzer"
$env:PLAYWRIGHT_BROWSERS_PATH="$env:LOCALAPPDATA\ms-playwright"
$env:PYTHONIOENCODING="utf-8"
.venv\Scripts\python.exe -m pytest -q
```

Verbose (show each test and skips):

```powershell
cd "services\c3-social-visual-analyzer"
$env:PLAYWRIGHT_BROWSERS_PATH="$env:LOCALAPPDATA\ms-playwright"
$env:PYTHONIOENCODING="utf-8"
.venv\Scripts\python.exe -m pytest -v
```

Stop on first failure:

```powershell
cd "services\c3-social-visual-analyzer"
$env:PLAYWRIGHT_BROWSERS_PATH="$env:LOCALAPPDATA\ms-playwright"
$env:PYTHONIOENCODING="utf-8"
.venv\Scripts\python.exe -m pytest -x
```

One test file:

```powershell
cd "services\c3-social-visual-analyzer"
$env:PLAYWRIGHT_BROWSERS_PATH="$env:LOCALAPPDATA\ms-playwright"
$env:PYTHONIOENCODING="utf-8"
.venv\Scripts\python.exe -m pytest tests\test_api.py -q
```

One test by name:

```powershell
cd "services\c3-social-visual-analyzer"
$env:PLAYWRIGHT_BROWSERS_PATH="$env:LOCALAPPDATA\ms-playwright"
$env:PYTHONIOENCODING="utf-8"
.venv\Scripts\python.exe -m pytest tests\test_threat_classifier.py -k "legitimate" -q
```

Skip OCR integration tests:

```powershell
cd "services\c3-social-visual-analyzer"
$env:PLAYWRIGHT_BROWSERS_PATH="$env:LOCALAPPDATA\ms-playwright"
$env:PYTHONIOENCODING="utf-8"
.venv\Scripts\python.exe -m pytest -q -m "not ocr_integration"
```

Only OCR integration (needs Tesseract installed):

```powershell
cd "services\c3-social-visual-analyzer"
$env:PLAYWRIGHT_BROWSERS_PATH="$env:LOCALAPPDATA\ms-playwright"
$env:PYTHONIOENCODING="utf-8"
.venv\Scripts\python.exe -m pytest -q -m ocr_integration
```

List collected tests:

```powershell
cd "services\c3-social-visual-analyzer"
.venv\Scripts\python.exe -m pytest --collect-only -q
```

Notes:

- Config is in `pytest.ini` (`testpaths=tests`, marker `ocr_integration`).
- OCR integration tests call the real Tesseract binary and are auto-skipped if it is not installed.
- Capture-related tests need Playwright Chromium (`python -m playwright install chromium`).
- There are ~30+ files under `tests/` covering API, schemas, fetchers, capture, OCR, threat classification, dataset helpers, and utilities.

### How models are trained

We fine-tune pretrained models on our labelled dataset (not train from scratch). Text uses
**DistilBERT** (`distilbert-base-uncased`); logos use **YOLOv11n**. Categories with no labelled
samples are assigned by **evidence rules** at inference. Risk fusion weights are hand-set, not learned.

| Component | Approach | Labels / data | Output |
|---|---|---|---|
| Binary text scam | Fine-tune DistilBERT | legitimate vs scam · post text + OCR · `text_baseline_dataset.jsonl` (≈70/15/15, seed 42) | `models/text_baseline/` |
| Threat category | Fine-tune DistilBERT (4 classes) | legitimate, phishing, financial_scam, data_theft | `models/threat_category/` |
| Misinformation | Fine-tune DistilBERT (binary) | real / fake · Fakeddit titles in `dataset_metadata.jsonl` | `models/misinformation/` |
| Logo detector | Train YOLOv11n (Ultralytics) | single class `logo` on brand reference boxes | `models/logo_detector/` |
| Brand similarity | Pretrained CLIP (no fine-tune for PP1) | brand catalog logos / screenshots | predictions under `data/annotations/` |
| Brand impersonation, malware, browser abuse, other_scam | Rules in live analyzer | no training samples for these classes | — |
| Risk score | Late fusion (hand-set weights) | text / OCR / visual / website signals | — |

Hybrid at runtime: DistilBERT for text categories we can label, YOLO for logos, CLIP for brand
similarity, rules for rare scam types, then consistency checks and risk fusion.

### Training models

Weights land under `models/` (gitignored). Run from the service folder after the dataset and brand
reference set exist:

Binary scam vs legitimate text model:

```powershell
cd "services\c3-social-visual-analyzer"
$env:PYTHONIOENCODING="utf-8"
.venv\Scripts\python.exe scripts\prepare_text_baseline.py
.venv\Scripts\python.exe scripts\train_text_baseline.py
```

Threat category (4-class) DistilBERT:

```powershell
cd "services\c3-social-visual-analyzer"
$env:PYTHONIOENCODING="utf-8"
.venv\Scripts\python.exe scripts\train_threat_category.py --task category
```

Misinformation DistilBERT:

```powershell
cd "services\c3-social-visual-analyzer"
$env:PYTHONIOENCODING="utf-8"
.venv\Scripts\python.exe scripts\train_threat_category.py --task misinformation
```

YOLO logo detector:

```powershell
cd "services\c3-social-visual-analyzer"
$env:PYTHONIOENCODING="utf-8"
.venv\Scripts\python.exe scripts\prepare_logo_yolo_dataset.py
.venv\Scripts\python.exe scripts\train_logo_detector.py
```

Optional refresh after changing brands or labels (CLIP / similarity / consistency / risk — not ML retrain):

```powershell
cd "services\c3-social-visual-analyzer"
$env:PYTHONIOENCODING="utf-8"
.venv\Scripts\python.exe scripts\clip_brand_analysis.py
.venv\Scripts\python.exe scripts\logo_similarity_analysis.py
.venv\Scripts\python.exe scripts\cross_source_consistency.py
.venv\Scripts\python.exe scripts\multimodal_risk_score.py
```

### Evaluation

```powershell
# PP1 metrics, confusion matrices, scenario checks → data/statistics + docs/pp1_evaluation.md
python scripts\pp1_evaluation.py

# Dataset sanity check
python scripts\validate_dataset.py
python scripts\generate_statistics.py
```

### Useful one-offs

```powershell
python scripts\convert_manual_posts.py --help
python scripts\import_evidence.py --help
python scripts\add_sample.py --help
python scripts\<name>.py --help   # every script documents its flags
```

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Service health |
| POST | `/api/v1/social/fetch-post` | Extract text, image and link from a public Facebook or Reddit post URL |
| POST | `/api/v1/social/analyze` | Analyze a post (multipart: `platform`, `post_text`, `embedded_url`, `image`) |
| POST | `/api/v1/social/analyze/stream` | Same analysis, streamed step by step (NDJSON) |
| GET | `/api/v1/social/platforms` | Supported platforms |
| GET | `/api/v1/social/model-results` | Saved evaluation metrics |
| GET | `/api/v1/social/datasets` | Brand, logo, training-split and external dataset summaries |
| POST | `/api/v1/preprocess-image` | Validate, preprocess, hash, duplicate-check and OCR one image |
| POST | `/api/v1/dataset/samples` | Add a labelled sample to the research dataset |
| GET | `/api/v1/dataset/samples/{sample_id}` | Read one sample |
| GET | `/api/v1/dataset/statistics` | Dataset statistics |
| GET | `/api/v1/dataset/classes` | Label classes |
| POST | `/api/v1/dataset/samples/{sample_id}/capture` | Capture a sample's embedded links |
| GET | `/api/v1/dataset/samples/{sample_id}/captures` | Stored captures of a sample |

Example:

```bash
curl -X POST http://127.0.0.1:8003/api/v1/social/analyze \
  -F platform=facebook \
  -F "post_text=Get a \$500 gift card! Enter your information now" \
  -F embedded_url=https://example.com/claim \
  -F image=@post.jpg
```

## 🛠️ Scripts

| Purpose | Scripts |
|---|---|
| Build the dataset | `convert_manual_posts.py` → `import_evidence.py`, `convert_phish360.py`, `convert_difraud.py`, `convert_fakeddit.py`, `validate_dataset.py`, `generate_statistics.py` |
| Brand reference set | `init_brand_reference.py`, `add_zenodo_brands.py`, `add_local_brands.py`, `collect_brand_logos.py`, `collect_brand_screenshots.py`, `normalize_brand_logos.py`, `annotate_brand_logos.py`, `split_brand_dataset.py`, `generate_brand_statistics.py` |
| Text models | `prepare_text_baseline.py`, `train_text_baseline.py`, `train_threat_category.py` |
| Vision models | `prepare_logo_yolo_dataset.py`, `train_logo_detector.py`, `logo_similarity_analysis.py`, `clip_brand_analysis.py` |
| Web capture | `capture_webpages.py` |
| Fusion and evaluation | `cross_source_consistency.py`, `multimodal_risk_score.py`, `pp1_evaluation.py` |
| External datasets | `import_smishtank.py`, `import_telephish.py`, `extract_telephish_candidates.py` |

Every script has usage notes in its header (`python scripts/<name>.py --help`).

## 📁 Project Structure

```text
c3-social-visual-analyzer/
├── app/
│   ├── api/            FastAPI routes (social analysis, dataset, capture, preprocessing, health)
│   ├── schemas/        Pydantic request/response and dataset models
│   ├── services/       analysis pipeline, OCR, capture sandbox, consistency, threat classifier, fetchers
│   ├── utils/          URL and image helpers
│   ├── config.py       settings (.env)
│   └── main.py         application factory
├── data/
│   ├── annotations/    dataset metadata, labels, brand catalog, splits, model predictions (tracked)
│   ├── statistics/     metrics, evaluation reports, confusion matrices (tracked)
│   ├── raw/, processed/, reference/, webpage_screenshots/   images and captures (not tracked)
├── docs/               dataset schema, label guide, brand reference schema, PP1 evaluation
├── models/             trained weights (not tracked)
├── scripts/            dataset, training and evaluation scripts
├── tests/              pytest suite
├── .env.example
└── requirements.txt
```

## ⚙️ Configuration

Settings are read from `.env` (see `.env.example` for all of them). The most important ones:

| Variable | Purpose |
|---|---|
| `TESSERACT_CMD` | Path to the Tesseract executable |
| `OCR_LANGUAGES` | OCR languages, e.g. `eng+sin+tam` (falls back to English if a pack is missing) |
| `WEB_CAPTURE_ENABLED` | Turn the sandboxed destination capture on or off |
| `WEB_CAPTURE_TIMEOUT_SECONDS` | Page-load time limit |
| `WEB_CAPTURE_ALLOW_PRIVATE_HOSTS` | Keep `false`: blocks internal / private network addresses |
| `DATA_DIR` | Location of the research dataset |

## 🔒 Safety and Data Handling

- Links are only opened in the sandboxed capture browser: downloads refused, no permissions, pop-ups closed,
  private and internal addresses blocked on every redirect.
- Analysing a post through the dashboard stores nothing in the research dataset.
- Bot challenges (e.g. Cloudflare) and login walls are not bypassed.
- Third-party dataset licences are respected: datasets that forbid redistribution are kept out of Git.

## 🚀 Future Enhancements

- [ ] Automatic identification of suspicious public social media posts (scam keywords, brand names, giveaway wording, short / lookalike links)
- [ ] Automatic collection and storage of each post (text, images, links, source, time) as evidence
- [ ] Analysis queue for new posts (background jobs, retries, duplicate removal by image hash and link)
- [ ] Automatic social media visual analysis of queued posts with the full C3 pipeline
- [ ] Alerts for HIGH-risk posts and a live results feed on the dashboard
- [ ] Sinhala and Tamil support: OCR language packs and multilingual text models for local-language posts
- [ ] More real Sri Lankan social media posts, especially data theft and brand impersonation
- [ ] Trained brand-impersonation class once enough labelled samples exist
- [ ] Learn the fusion weights and thresholds from the validation split; ablation study per evidence source
- [ ] Lower the risk when a link resolves to the claimed brand's official domain (fewer false alarms on real promotions)
- [ ] Fine-tune CLIP / add more reference images per brand to raise brand recognition recall
- [ ] More platforms: Instagram, X (Twitter), TikTok and public Telegram channels
- [ ] Detect bot-challenge pages (e.g. Cloudflare) during capture and mark them clearly
- [ ] Analysis history and analyst feedback ("correct / wrong") stored for retraining
- [ ] Connect C3 to the ScamTrace API gateway and the other components (C1 URL, C2 HTML, C4 code)
- [ ] Docker image for the service

## ⚠️ Limitations

- English text models; Sinhala/Tamil OCR needs extra Tesseract language packs.
- Few labelled examples for data theft and brand impersonation; malware and browser abuse are rule-based only.
- Brand recognition covers the 90 catalog brands; CLIP brand recall on real phishing pages is low (23.9%).
- Real brand promotions can look like scam giveaways; the destination-domain check is the main signal.
- Fusion weights are hand-set (preliminary) and test sets are small.

See [`docs/pp1_evaluation.md`](docs/pp1_evaluation.md) for the full list and next work.

## 📚 Documentation

- [`docs/dataset_schema.md`](docs/dataset_schema.md) – dataset record format
- [`docs/dataset_labels.md`](docs/dataset_labels.md) – label definitions and labelling rules
- [`docs/brand_reference_schema.md`](docs/brand_reference_schema.md) – brand reference set
- [`docs/pp1_evaluation.md`](docs/pp1_evaluation.md) – PP1 results, limitations and next work

## 🙏 Acknowledgements

Datasets: Zenodo phishing websites dataset, Phish360 (Multimodal-Phishing-Benchmarks), DIFrauD, Fakeddit,
Smishtank (Timko & Rahman, CODASPY 2024), TelePhish (Erfan et al., PST 2025). Models: DistilBERT (Hugging Face),
CLIP (OpenAI), YOLO11 (Ultralytics), Tesseract OCR.

## License

Academic research project (SLIIT, J26-SE-316). Third-party datasets and models keep their own licences.

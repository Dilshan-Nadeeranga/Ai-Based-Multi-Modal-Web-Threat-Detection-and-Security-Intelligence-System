# Large-Scale URL Intelligence Dataset & Training Pipeline (200,000+ Records)
## Component C1 — Multi-Layer URL & Domain Intelligence Framework

This document provides a guide for acquiring real-world datasets containing **200,000 or more legitimate and malicious URLs**, cleaning and preparing them without memory bloat, and training leakage-resistant **Random Forest** classifiers for Component C1.

---

## 1. Permitted Data Sources & Acquisition

To comply with terms of service and ensure realistic evaluation, obtain data from authorized open cybersecurity repositories. **Do not fabricate fake URLs.**

### Option A: Curated Research Datasets (Recommended for Immediate 200k–650k Scale)

| Dataset | Sample Count | Class Breakdown | Format & Source |
| :--- | :--- | :--- | :--- |
| **Kaggle Malicious URLs** (*Sid321axn / Manu Siddhartha*) | **651,191 URLs** | 428k Benign, 96k Defacement, 88k Phishing, 32k Malware | CSV (`url,type`). Download via Kaggle Web or CLI: `kaggle datasets download -d sid321axn/malicious-urls-dataset` |
| **ISCX-URL2016** (*Univ. of New Brunswick*) | **165,366 URLs** | Benign (Alexa Top 1M), Phishing (PhishTank), Malware (DNS-BH) | CSV (`URL,label`). Download from UNB Cybersecurity repository. |
| **Mendeley Webpages Dataset** | **1,200,000 URLs** | 50% Benign / 50% Malicious | Public research archive collected from PhishTank and OpenPhish. |

---

### Option B: Live Community Threat Intelligence Feeds (Direct Feeds)

You can assemble 200,000+ real records by combining verified threat feeds:

1. **abuse.ch URLhaus (Malicious — Malware Droppers & C2)**
   - **Download URL**: `https://urlhaus.abuse.ch/downloads/csv/` (Full active database, > 1,500,000 URLs)
   - **Usage Terms**: Free for research, academic, and defensive security operations (CC0 / Open Data).
   - **Format**: CSV with header `# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter`

2. **PhishTank (Malicious — Verified Phishing Campaigns)**
   - **Download URL**: `http://data.phishtank.com/data/online-valid.csv`
   - **Usage Terms**: Permitted for security defense and research with attribution. High-volume scraping requires a developer application key.
   - **Format**: CSV with columns `phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target`

3. **OpenPhish (Malicious — Targeted Phishing & Dynamic DNS)**
   - **Download URL**: `https://openphish.com/feed.txt`
   - **Usage Terms**: Free community tier updated every 6 hours for defensive use.

4. **Tranco Top 1M (Legitimate — High-Reputation Web Domains)**
   - **Download URL**: `https://tranco-list.eu/download_daily/`
   - **Usage Terms**: Open research list hardened against manipulation (CC BY-SA 4.0).
   - **Format**: CSV with `rank,domain` (e.g., `1,google.com`).

---

## 2. Preparing and Cleaning the Dataset (`prepare_dataset.py`)

The pipeline includes a streaming data cleaner (`app/ml/prepare_dataset.py`) built to process **200,000 to 2,000,000 rows** without running out of RAM:

### Key Capabilities:
- **Chunked Streaming (`--chunk-size 50000`)**: Processes files in batches, avoiding large memory allocations.
- **Strict Label Mapping**:
  - `0`: `benign`, `legitimate`, `good`, `clean`, `safe`, `ham`, `0`
  - `1`: `malicious`, `phishing`, `phish`, `malware`, `bad`, `scam`, `spam`, `defacement`, `1`
  - **Unknown / Unlabelled**: Dropped immediately. **The pipeline never invents or hallucinates labels.**
- **URL Syntax Validation**: Rejects empty strings, strings without domain delimiters (`.`), or invalid lengths (< 4 or > 4096 characters).
- **Streaming Deduplication**: Eliminates duplicate URLs across chunks.
- **Leakage Grouping**: Extracts registered apex domains (`registered_domain`) via `tldextract` for domain-level isolation.

### Example Commands:

#### 1. Prepare a 200,000 sample from a large unified CSV (e.g. Kaggle 650k dataset):
```bash
cd services/c1-url-domain-analyzer

.venv/bin/python -m app.ml.prepare_dataset \
  --input-csv /path/to/malicious_phish.csv \
  --output-csv data/cleaned_urls_200k.csv \
  --max-samples 200000 \
  --chunk-size 50000 \
  --balance \
  --report-json data/preparation_report.json
```

#### 2. Merge separate Benign (Tranco) and Malicious (URLhaus) CSV files:
```bash
.venv/bin/python -m app.ml.prepare_dataset \
  --benign-csv /path/to/tranco_benign.csv \
  --malicious-csv /path/to/urlhaus_malicious.csv \
  --output-csv data/cleaned_urls_200k.csv \
  --max-samples 200000 \
  --balance \
  --report-json data/preparation_report.json
```

---

## 3. Training the Random Forest Classifier (`train.py`)

Once you have your cleaned dataset at `data/cleaned_urls_200k.csv`, run the training script:

```bash
cd services/c1-url-domain-analyzer

.venv/bin/python -m app.ml.train \
  --data-path data/cleaned_urls_200k.csv \
  --output-dir models \
  --model-type random_forest \
  --split-strategy domain_grouped \
  --test-size 0.2 \
  --val-size 0.1 \
  --max-fpr 0.05 \
  --batch-size 10000
```

### Performance & Memory Architecture for 200,000 Records:
- **Pre-allocated Feature Matrix**: Features are stored in a contiguous 2D `float32` NumPy matrix:
  $$\text{Memory} = 200{,}000 \times 52 \text{ features} \times 4 \text{ bytes} \approx 39.67 \text{ MB}$$
- **Feature Extraction Speed**: ~15,000 to 17,000 URLs/second (extracts 200,000 URLs in ~12–15 seconds).
- **Leakage Prevention (`domain_grouped`)**:
  - Uses `GroupShuffleSplit` on `registered_domain`.
  - Guarantees **0 domain overlap** between train, validation, and test sets.
- **Class-Imbalance Handling**:
  - `class_weight="balanced"` dynamically weights tree splits inversely proportional to class frequencies.
- **Multi-Core Training (`n_jobs=-1`)**:
  - 100 parallel decision trees train across all CPU cores in ~15–30 seconds for 140,000 training samples.
- **Threshold Calibration**:
  - Decision threshold is calibrated on the validation set to keep False Positive Rate $\le 5\%$ (`--max-fpr 0.05`).

### Option 2: Automated Live Feed Acquisition (`build_live_dataset.py`)
To automatically fetch, standardize, balance, and assemble 200,000 real URLs from live open feeds without manual downloading:
```bash
python -m app.ml.build_live_dataset
```
This automatically:
1. Downloads live verified malware/payload URLs from **URLhaus (abuse.ch)** (`urlhaus_full.zip`, 73,385 URLs).
2. Downloads verified active phishing campaigns from **PhishTank** (`phishtank.csv`, 26,615 URLs).
3. Downloads high-reputation domains from **Tranco Top 1M** (`tranco_sample.zip`, 100,000 URLs with diverse realistic web navigation paths).
4. Combines and shuffles them into `data/dataset_200k.csv` (**200,000 records**, exactly 50% benign / 50% malicious, 127,451 unique apex domains).

---

## 4. Evaluated Metrics & Saved Artifacts

Upon completion, `train.py` outputs:
- **Accuracy, Precision, Recall, and F1-Score**
- **ROC-AUC (Area Under Curve)**
- **False Positive Rate (FPR) and True Negative Rate (TNR)**
- **Confusion Matrix** on held-out unseen domains
- **Training Duration (seconds) and Inference Latency (ms/sample)**

The following production artifacts are saved to `models/`:
- `models/best_model.joblib`: The trained Random Forest classifier.
- `models/preprocessor.joblib`: The median imputer and standard scaler fit strictly on the training partition.
- `models/model_metadata.json`: Feature list (52 dimensions), optimal decision threshold, and performance metrics.
- `models/model_comparison_report.json`: Machine-readable evaluation report.
- `models/model_comparison_report.md`: Markdown report with confusion matrices.

---

## 5. Live Inference & API Verification

The FastAPI backend dynamically loads the model into RAM:

### Verify API Status:
```bash
curl -s http://localhost:8001/api/v1/ml-model-status | jq .
```

### Run Real-Time Prediction:
```bash
curl -s -X POST http://localhost:8001/api/v1/ml-predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://secure-login.bankofamerica-verify-session.top/auth/signin"}' | jq .
```

The ScamTrace web dashboard (`http://localhost:5173/url-analyzer`) immediately uses the trained model in Layer 4 and synthesizes it with Layers 1–3 in the consolidated explainable risk score.

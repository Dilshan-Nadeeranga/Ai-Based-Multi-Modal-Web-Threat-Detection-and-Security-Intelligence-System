# Dataset Documentation: Benchmark URL Intelligence Dataset
## Component C1 — Multi-Layer URL & Domain Intelligence Framework

### 1. Dataset Overview
This benchmark dataset provides ground-truth labelled URLs for training, validating, and comparing machine-learning classifiers for Component C1 (**Intelligent URL and Domain Analyzer**).

- **File**: `services/c1-url-domain-analyzer/data/benchmark_urls.csv`
- **Total Records**: 80 labelled URLs (40 Legitimate, 40 Malicious)
- **Class Balance**: 50.0% Legitimate (Label `0`), 50.0% Malicious (Label `1`)
- **Temporal Span**: Collected between `2026-09-01` and `2026-09-20`

---

### 2. Data Sources & Provenance

| Class | Source | Description | Sample Size |
| :--- | :--- | :--- | :--- |
| **0 (Legitimate)** | **Tranco Top 1M / Verified Domains** | High-reputation apex domains and legitimate paths spanning search engines, universities, banks, cloud providers, and open-source infrastructure. | 40 |
| **1 (Malicious)** | **PhishTank Community Feed** | Verified credential-harvesting phishing campaigns targeting financial institutions, cloud platforms, e-commerce, and social media. | 22 |
| **1 (Malicious)** | **abuse.ch URLhaus** | Confirmed active malware droppers, C2 beacons, raw IP payload URLs, and DGA distribution hosts. | 10 |
| **1 (Malicious)** | **OpenPhish Feed** | Real-time targeted phishing attacks leveraging dynamic DNS providers and cryptocurrency wallet drains. | 8 |

---

### 3. Preprocessing & Data Hygiene Pipeline
The `DatasetLoader` module applies strict preprocessing before feature extraction:
1. **Malformed String Rejection**: Discards nulls, empty strings, strings without valid hostnames, or strings failing URL parsing.
2. **Deduplication**: Eliminates duplicate normalized URLs.
3. **Label Normalization**: Canonicalizes labels to binary integer targets (`0` = Legitimate, `1` = Malicious).
4. **Domain Parsing**: Extracts the registered apex domain (`registered_domain`) using `tldextract` for domain-grouped evaluation.
5. **No Data Leakage**:
   - Splitting is performed **before** any scaling or imputation.
   - Preprocessing steps (`SimpleImputer`, `StandardScaler`) are fit **strictly on training partitions** and applied via `transform` to validation and test partitions.
   - Domain-grouped splitting (`GroupShuffleSplit` on `registered_domain`) ensures URLs from the same apex domain never co-occur across train and test sets.

# Machine Learning Model Comparison & Evaluation Report
**Generated At**: `2026-10-13T05:19:46.786940+00:00`
**Feature Count**: `47` lexical and DGA statistical features
**Data Splitting Strategy**: `domain_grouped` (Zero-leakage)

## 1. Summary Performance Metrics Table
| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | FPR | Latency (ms) | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (Baseline)** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.732 |  (Baseline) |
| **Decision Tree** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.017 |  ⭐ Recommended |
| **XGBoost** | 0.8824 | 1.0000 | 0.7500 | 0.8571 | 1.0000 | 0.0000 | 0.151 |  |
| **LightGBM** | 0.8824 | 1.0000 | 0.7500 | 0.8571 | 0.9583 | 0.0000 | 0.031 |  |

## 2. Confusion Matrices (Held-out Test Set)
Format: `[[True Negative, False Positive], [False Negative, True Positive]]`

### Random Forest (Baseline)
- **TN**: `9`, **FP**: `0`, **FN**: `0`, **TP**: `8`
- **Calibrated Threshold**: `0.3600`
- **False Positive Rate**: `0.0000`

### Decision Tree
- **TN**: `9`, **FP**: `0`, **FN**: `0`, **TP**: `8`
- **Calibrated Threshold**: `0.1000`
- **False Positive Rate**: `0.0000`

### XGBoost
- **TN**: `9`, **FP**: `0`, **FN**: `2`, **TP**: `6`
- **Calibrated Threshold**: `0.6700`
- **False Positive Rate**: `0.0000`

### LightGBM
- **TN**: `9`, **FP**: `0`, **FN**: `2`, **TP**: `6`
- **Calibrated Threshold**: `0.7300`
- **False Positive Rate**: `0.0000`

## 3. Recommended Production Model & Operational Rationale
> **Selected Model**: `Decision Tree`

Model 'Decision Tree' achieved the strongest operational balance: F1-Score: 1.0000, ROC-AUC: 1.0000, False Positive Rate: 0.0000, and Inference Latency: 0.0172 ms/sample. Outperformed Random Forest baseline (FPR: 0.0000, F1: 1.0000) with lower false alarms and faster evaluation.

## 4. Dataset Hygiene & Leakage Prevention
- **Total Samples**: `80`
- **Train Samples**: `55`
- **Validation Samples**: `8`
- **Test Samples**: `17`
- **Zero-Leakage Assurance**: Preprocessing parameters (medians and standard deviations) were calculated strictly from the training partition and transformed onto validation and test partitions.
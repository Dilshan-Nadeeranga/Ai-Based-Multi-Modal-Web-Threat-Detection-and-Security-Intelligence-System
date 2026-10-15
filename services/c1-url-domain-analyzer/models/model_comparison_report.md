# Machine Learning Model Comparison & Evaluation Report
**Generated At**: `2026-10-15T12:53:32.857207+00:00`
**Feature Count**: `57` lexical, structural, and DGA features
**Data Splitting Strategy**: `domain_grouped` (Zero-leakage)

## 1. Summary Performance Metrics Table
| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | FPR | FNR | Latency (ms) | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (Baseline)** | 0.9805 | 0.9769 | 0.9737 | 0.9753 | 0.9972 | 0.0151 | 0.0263 | 0.001 |  (Baseline) |
| **Random Forest (Tuned & Improved)** | 0.9848 | 0.9890 | 0.9724 | 0.9807 | 0.9983 | 0.0071 | 0.0276 | 0.001 |  ⭐ Recommended |

## 2. Confusion Matrices (Held-out Test Set)
Format: `[[True Negative, False Positive], [False Negative, True Positive]]`

### Random Forest (Baseline)
- **True Negatives (TN)**: `19644`
- **False Positives (FP)**: `301`
- **False Negatives (FN)**: `344`
- **True Positives (TP)**: `12741`
- **Calibrated Decision Threshold**: `0.3400`
- **False Positive Rate [FP / (FP + TN)]**: `0.0151`
- **False Negative Rate [FN / (FN + TP)]**: `0.0263`

### Random Forest (Tuned & Improved)
- **True Negatives (TN)**: `19804`
- **False Positives (FP)**: `141`
- **False Negatives (FN)**: `361`
- **True Positives (TP)**: `12724`
- **Calibrated Decision Threshold**: `0.4400`
- **False Positive Rate [FP / (FP + TN)]**: `0.0071`
- **False Negative Rate [FN / (FN + TP)]**: `0.0276`

## 3. Baseline vs. Improved Model Comparison (FP & FN Reduction)
| Evaluation Metric | Baseline (RF Default) | Improved (RF Tuned + Enhanced Features) | Delta / Improvement |
| :--- | :---: | :---: | :---: |
| **False Positives (FP)** | `301` | `141` | **-160** |
| **False Negatives (FN)** | `344` | `361` | **+17** |
| **False Positive Rate (FPR)** | `1.5100%` | `0.7100%` | `-0.8000%` |
| **False Negative Rate (FNR)** | `2.6300%` | `2.7600%` | `+0.1300%` |
| **Accuracy** | `98.0500%` | `98.4800%` | `+0.4300%` |
| **Precision** | `97.6900%` | `98.9000%` | `+1.2100%` |
| **Recall** | `97.3700%` | `97.2400%` | `-0.1300%` |
| **F1-Score** | `0.9753` | `0.9807` | `+0.0054` |
| **ROC-AUC** | `0.9972` | `0.9983` | `+0.0011` |

## 4. Recommended Production Model & Operational Rationale
> **Selected Model**: `Random Forest (Tuned & Improved)`

Model 'Random Forest (Tuned & Improved)' achieved the strongest operational balance: F1-Score: 0.9807, ROC-AUC: 0.9983, False Positive Rate: 0.0071, False Negative Rate: 0.0276, and Inference Latency: 0.0012 ms/sample (Training Time: 2.24s). Compared to Baseline (FPR: 0.0151, FNR: 0.0263), reduced False Positives by +160 and False Negatives by -17.

## 5. Dataset Hygiene & Leakage Prevention
- **Total Samples**: `200000`
- **Train Samples**: `145899`
- **Validation Samples**: `21071`
- **Test Samples**: `33030`
- **Zero-Leakage Assurance**: Preprocessing parameters (medians and standard deviations) were calculated strictly from the training partition and transformed onto validation and test partitions.
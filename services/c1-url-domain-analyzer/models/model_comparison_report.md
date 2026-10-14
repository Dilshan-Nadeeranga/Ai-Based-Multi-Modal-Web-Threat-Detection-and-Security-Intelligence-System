# Machine Learning Model Comparison & Evaluation Report
**Generated At**: `2026-10-13T14:41:17.304055+00:00`
**Feature Count**: `52` lexical and DGA statistical features
**Data Splitting Strategy**: `domain_grouped` (Zero-leakage)

## 1. Summary Performance Metrics Table
| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | FPR | Latency (ms) | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (Baseline)** | 0.9754 | 0.9889 | 0.9587 | 0.9735 | 0.9967 | 0.0097 | 0.001 |  ⭐ Recommended |

## 2. Confusion Matrices (Held-out Test Set)
Format: `[[True Negative, False Positive], [False Negative, True Positive]]`

### Random Forest (Baseline)
- **TN**: `19749`, **FP**: `193`, **FN**: `739`, **TP**: `17151`
- **Calibrated Threshold**: `0.3100`
- **False Positive Rate**: `0.0097`

## 3. Recommended Production Model & Operational Rationale
> **Selected Model**: `Random Forest (Baseline)`

Model 'Random Forest (Baseline)' achieved the strongest operational balance: F1-Score: 0.9735, ROC-AUC: 0.9967, False Positive Rate: 0.0097, and Inference Latency: 0.0007 ms/sample (Training Time: 1.28s). Maintained the most reliable generalization boundary across all tested metrics.

## 4. Dataset Hygiene & Leakage Prevention
- **Total Samples**: `200000`
- **Train Samples**: `143303`
- **Validation Samples**: `18865`
- **Test Samples**: `37832`
- **Zero-Leakage Assurance**: Preprocessing parameters (medians and standard deviations) were calculated strictly from the training partition and transformed onto validation and test partitions.
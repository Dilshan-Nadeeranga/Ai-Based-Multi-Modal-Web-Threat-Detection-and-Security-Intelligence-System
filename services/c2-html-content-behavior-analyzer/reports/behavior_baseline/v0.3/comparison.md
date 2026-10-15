# DOM-only vs Behavior-only - v0.3

Same shared split, same protocol (grouped-CV model selection on train+val, ONE test evaluation on 68 pages). Best model of each arm by CV macro-F1.

| arm | best model | features used | CV macro-F1 | test macro-F1 | weighted-F1 | accuracy | balanced acc. | ROC-AUC | benign FPR |
|---|---|---|---|---|---|---|---|---|---|
| DOM-only (Part 4) | Random Forest | 48 | 0.701 +/- 0.077 | 0.786 | 0.827 | 0.824 | 0.810 | 0.968 | 17.6 % |
| Behavior-only (Part 7+8) | Random Forest | 70 | 0.620 +/- 0.078 | 0.682 | 0.755 | 0.735 | 0.683 | 0.861 | 20.6 % |

Per-class test F1 (best model of each arm):

| class | DOM-only (Part 4) | Behavior-only (Part 7+8) |
|---|---|---|
| benign | 0.889 | 0.806 |
| phishing | 0.750 | 0.720 |
| fake_ecommerce | 1.000 | 0.933 |
| crypto_scam | 0.667 | 0.286 |
| malware_delivery | 0.625 | 0.667 |

All models (test macro-F1):

- DOM-only (Part 4): Logistic Regression 0.658, Random Forest 0.786, XGBoost 0.765
- Behavior-only (Part 7+8): Logistic Regression 0.414, Random Forest 0.682, XGBoost 0.686

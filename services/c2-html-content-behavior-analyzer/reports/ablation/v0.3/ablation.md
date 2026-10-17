# Ablation study - v0.3 (C2 Part 9A: tri-modal fusion)

- created: 2026-10-16T23:19:15+05:30
- split fingerprint: `7d9ae69bbae3f5c699c022eb4ef74334ac49c4e95d68f30f9d480c9e55324f4f`; pages: train+val 391 (grouped 5-fold CV), test 68 (used once)
- arms: DOM-only, Behavior-only, Text TF-IDF, Text XLM-R
- every choice (weights, stacker, final strategy, benign threshold) is made on grouped CV over train+val; the test pages are predicted once per row and only reported. CV = mean ± std over the 5 folds of the selected configuration.

## Main table (test, argmax unless stated)

| row | CV macro-F1 | test macro-F1 [95 % CI] | weighted-F1 | accuracy | ROC-AUC | benign FPR (argmax) | benign FPR (≤ 2 % thr.) |
|---|---|---|---|---|---|---|---|
| DOM-only | 0.701 ± 0.077 | **0.786** [0.652, 0.891] | 0.827 | 0.824 | 0.968 | 17.6 % | 0.0 % |
| Behavior-only | 0.620 ± 0.078 | **0.682** [0.551, 0.805] | 0.755 | 0.735 | 0.861 | 20.6 % | 0.0 % |
| Text TF-IDF | 0.706 ± 0.065 | **0.718** [0.569, 0.841] | 0.787 | 0.809 | 0.962 | 5.9 % | 0.0 % |
| Text XLM-R | 0.680 ± 0.041 | **0.657** [0.514, 0.776] | 0.698 | 0.706 | 0.922 | 23.5 % | 5.9 % |
| DOM+Behavior · Late fusion - weighted | 0.701 ± 0.077 | **0.786** [0.652, 0.891] | 0.827 | 0.824 | 0.967 | 17.6 % | 0.0 % |
| DOM+Text (TF-IDF + XLM-R) · Late fusion - mean | 0.761 ± 0.054 | **0.836** [0.704, 0.933] | 0.859 | 0.868 | 0.975 | 5.9 % | 0.0 % |
| Behavior+Text (TF-IDF + XLM-R) · Late fusion - weighted | 0.757 ± 0.050 | **0.795** [0.654, 0.906] | 0.831 | 0.838 | 0.949 | 8.8 % | 0.0 % |
| DOM+Behavior+Text (TF-IDF + XLM-R) · Late fusion - mean | 0.756 ± 0.075 | **0.836** [0.704, 0.933] | 0.859 | 0.868 | 0.972 | 5.9 % | 0.0 % |
| **DOM+Behavior+Text (TF-IDF + XLM-R) · Late fusion - weighted** ★ | 0.768 ± 0.073 | **0.795** [0.654, 0.906] | 0.831 | 0.838 | 0.962 | 8.8 % | 0.0 % |
| DOM+Behavior+Text (TF-IDF + XLM-R) · Stacking - LogReg | 0.748 ± 0.084 | **0.783** [0.654, 0.884] | 0.823 | 0.824 | 0.948 | 11.8 % | 0.0 % |
| DOM+Behavior+Text (TF-IDF + XLM-R) · Hybrid - XGBoost | 0.749 ± 0.040 | **0.811** [0.680, 0.909] | 0.831 | 0.838 | 0.969 | 14.7 % | 2.9 % |

★ final fusion model: **DOM+Behavior+Text (TF-IDF + XLM-R) · Late fusion - weighted** (best tri-modal CV macro-F1 0.768).

## Per-class F1 (test)

| row | benign | phishing | fake_ecommerce | crypto_scam | malware_delivery |
|---|---|---|---|---|---|
| DOM-only | 0.889 | 0.750 | 1.000 | 0.667 | 0.625 |
| Behavior-only | 0.806 | 0.720 | 0.933 | 0.286 | 0.667 |
| Text TF-IDF | 0.877 | 0.815 | 0.933 | 0.600 | 0.364 |
| Text XLM-R | 0.788 | 0.640 | 0.700 | 0.727 | 0.429 |
| DOM+Behavior · Late fusion - weighted | 0.889 | 0.750 | 1.000 | 0.667 | 0.625 |
| DOM+Text (TF-IDF + XLM-R) · Late fusion - mean | 0.914 | 0.828 | 0.933 | 0.889 | 0.615 |
| Behavior+Text (TF-IDF + XLM-R) · Late fusion - weighted | 0.899 | 0.786 | 0.875 | 0.800 | 0.615 |
| DOM+Behavior+Text (TF-IDF + XLM-R) · Late fusion - mean | 0.914 | 0.828 | 0.933 | 0.889 | 0.615 |
| **DOM+Behavior+Text (TF-IDF + XLM-R) · Late fusion - weighted** ★ | 0.899 | 0.786 | 0.875 | 0.800 | 0.615 |
| DOM+Behavior+Text (TF-IDF + XLM-R) · Stacking - LogReg | 0.896 | 0.815 | 0.933 | 0.800 | 0.471 |
| DOM+Behavior+Text (TF-IDF + XLM-R) · Hybrid - XGBoost | 0.879 | 0.839 | 0.875 | 0.889 | 0.571 |

## Per-language accuracy (test; Part 5A detected language, n pages)

| row | en (n=51) | si (n=1) | ta (n=1) | mixed (n=1) | other (n=14) |
|---|---|---|---|---|---|
| DOM-only | 0.824 | 1.000 ⚠ | 1.000 ⚠ | 1.000 ⚠ | 0.786 |
| Behavior-only | 0.706 | 1.000 ⚠ | 1.000 ⚠ | 1.000 ⚠ | 0.786 |
| Text TF-IDF | 0.863 | 1.000 ⚠ | 1.000 ⚠ | 0.000 ⚠ | 0.643 |
| Text XLM-R | 0.706 | 1.000 ⚠ | 1.000 ⚠ | 0.000 ⚠ | 0.714 |
| DOM+Behavior · Late fusion - weighted | 0.824 | 1.000 ⚠ | 1.000 ⚠ | 1.000 ⚠ | 0.786 |
| DOM+Text (TF-IDF + XLM-R) · Late fusion - mean | 0.863 | 1.000 ⚠ | 1.000 ⚠ | 1.000 ⚠ | 0.857 |
| Behavior+Text (TF-IDF + XLM-R) · Late fusion - weighted | 0.843 | 1.000 ⚠ | 1.000 ⚠ | 1.000 ⚠ | 0.786 |
| DOM+Behavior+Text (TF-IDF + XLM-R) · Late fusion - mean | 0.863 | 1.000 ⚠ | 1.000 ⚠ | 1.000 ⚠ | 0.857 |
| **DOM+Behavior+Text (TF-IDF + XLM-R) · Late fusion - weighted** ★ | 0.843 | 1.000 ⚠ | 1.000 ⚠ | 1.000 ⚠ | 0.786 |
| DOM+Behavior+Text (TF-IDF + XLM-R) · Stacking - LogReg | 0.824 | 1.000 ⚠ | 1.000 ⚠ | 1.000 ⚠ | 0.786 |
| DOM+Behavior+Text (TF-IDF + XLM-R) · Hybrid - XGBoost | 0.863 | 1.000 ⚠ | 1.000 ⚠ | 1.000 ⚠ | 0.714 |

⚠ = fewer than 10 test pages: an anecdote, not an estimate.

## Benign-FPR operating point (target ≤ 2 %)

Rule: benign if P(benign) ≥ t, else the most probable threat class; t = the largest threshold whose OUT-OF-FOLD benign FPR on train+val is ≤ the target (chosen without test). Threat recall = threat pages flagged as any threat.

| row | t | OOF benign FPR | test benign FPR argmax → thr. | test threat recall argmax → thr. | test macro-F1 argmax → thr. |
|---|---|---|---|---|---|
| DOM-only | 0.095 | 1.6 % | 17.6 % → 0.0 % | 97.1 % → 50.0 % | 0.786 → 0.617 |
| Behavior-only | 0.102 | 1.6 % | 20.6 % → 0.0 % | 82.4 % → 29.4 % | 0.682 → 0.436 |
| Text TF-IDF | 0.167 | 1.6 % | 5.9 % → 0.0 % | 79.4 % → 52.9 % | 0.718 → 0.655 |
| Text XLM-R | 0.120 | 1.6 % | 23.5 % → 5.9 % | 82.4 % → 70.6 % | 0.657 → 0.637 |
| DOM+Behavior · Late fusion - weighted | 0.108 | 1.6 % | 17.6 % → 0.0 % | 97.1 % → 50.0 % | 0.786 → 0.550 |
| DOM+Text (TF-IDF + XLM-R) · Late fusion - mean | 0.161 | 1.6 % | 5.9 % → 0.0 % | 88.2 % → 76.5 % | 0.836 → 0.758 |
| Behavior+Text (TF-IDF + XLM-R) · Late fusion - weighted | 0.182 | 1.6 % | 8.8 % → 0.0 % | 88.2 % → 70.6 % | 0.795 → 0.720 |
| DOM+Behavior+Text (TF-IDF + XLM-R) · Late fusion - mean | 0.188 | 1.6 % | 5.9 % → 0.0 % | 88.2 % → 73.5 % | 0.836 → 0.720 |
| **DOM+Behavior+Text (TF-IDF + XLM-R) · Late fusion - weighted** ★ | 0.182 | 1.6 % | 8.8 % → 0.0 % | 88.2 % → 76.5 % | 0.795 → 0.726 |
| DOM+Behavior+Text (TF-IDF + XLM-R) · Stacking - LogReg | 0.066 | 1.6 % | 11.8 % → 0.0 % | 91.2 % → 82.4 % | 0.783 → 0.789 |
| DOM+Behavior+Text (TF-IDF + XLM-R) · Hybrid - XGBoost | 0.102 | 1.6 % | 14.7 % → 2.9 % | 91.2 % → 85.3 % | 0.811 → 0.819 |

Final model at the threshold: confusion matrix (test, rows = true):

```
true \ predicted                  benign          phishing    fake_ecommerce       crypto_scam  malware_delivery
benign                                34                 0                 0                 0                 0
phishing                               2                10                 0                 1                 0
fake_ecommerce                         0                 0                 7                 1                 0
crypto_scam                            2                 0                 0                 2                 0
malware_delivery                       4                 2                 0                 0                 3
```

## Tri-modal vs best single arm (paired bootstrap)

1000 resamples of the 68 test pages (seed 42), the same resamples for every row; 95 % percentile CI of the macro-F1 DIFFERENCE.

- final − best single arm by CV (`text_tfidf`): **+0.077** [-0.019, +0.201]; final better in 94.1 % of resamples → **the CI includes 0 - the test set cannot distinguish them** (small test set).
- final − best single arm on test (conservative) (`dom`): **+0.009** [-0.136, +0.141]; final better in 57.9 % of resamples → **the CI includes 0 - the test set cannot distinguish them** (small test set).

## Complementarity (test, argmax; text = `text_tfidf`)

Oracle (any modality right): 92.6 % of 68 pages vs final fusion accuracy 83.8 %.

| bucket | pages | final fusion right | examples |
|---|---|---|---|
| all right | 41 | 40 | `c2_benign_000001`, `c2_benign_000008`, `c2_benign_000025`, `c2_benign_000029`, `c2_benign_000048` |
| only dom right | 2 | 0 | `c2_fake_ecommerce_000032`, `c2_malware_delivery_000023` |
| only behavior right | 1 | 0 | `c2_malware_delivery_000050` |
| only text right | 3 | 2 | `c2_benign_000011`, `c2_benign_000040`, `c2_crypto_scam_000011` |
| only dom wrong | 3 | 2 | `c2_benign_000002`, `c2_benign_000062`, `c2_benign_000122` |
| only behavior wrong | 8 | 8 | `c2_benign_000024`, `c2_benign_000077`, `c2_benign_000083`, `c2_benign_000087`, `c2_crypto_scam_000039` |
| only text wrong | 5 | 4 | `c2_benign_000003`, `c2_crypto_scam_000010`, `c2_malware_delivery_000045`, `c2_malware_delivery_000052`, `c2_phishing_000071` |
| all wrong | 5 | 1 | `c2_benign_000076`, `c2_malware_delivery_000018`, `c2_malware_delivery_000036`, `c2_malware_delivery_000042`, `c2_phishing_000106` |

## Explainability (test pages)

- **weighted** (weights): Text XLM-R 40 %, Behavior-only 30 %, Text TF-IDF 20 %, DOM-only 10 %
- **stacking** (LR coefficients (mean |coef| over classes, summed per arm)): Text XLM-R 28 %, DOM-only 26 %, Text TF-IDF 26 %, Behavior-only 20 %
- **hybrid** (SHAP (TreeExplainer, mean |SHAP| over the test pages, summed over classes)): DOM-only 40 %, Text TF-IDF 28 %, Text XLM-R 23 %, Behavior-only 9 %
  - `text_xlmr.p_crypto_scam` mean |SHAP| 2.002
  - `text_xlmr.p_malware_delivery` mean |SHAP| 1.501
  - `text_tfidf.p_malware_delivery` mean |SHAP| 1.493
  - `text_tfidf.p_benign` mean |SHAP| 1.483
  - `text_tfidf.p_crypto_scam` mean |SHAP| 1.366
  - `text_tfidf.p_phishing` mean |SHAP| 1.352
  - `text_tfidf.p_fake_ecommerce` mean |SHAP| 1.232
  - `dom.external_link_ratio` mean |SHAP| 1.183
  - `text_xlmr.p_phishing` mean |SHAP| 0.900
  - `dom.avg_depth` mean |SHAP| 0.804

## Pairs: every strategy (✓ = chosen by CV)

| pair | strategy | CV macro-F1 | test macro-F1 | benign FPR |
|---|---|---|---|---|
| DOM+Behavior | Late fusion - mean | 0.685 ± 0.064 | 0.739 | 14.7 % |
| DOM+Behavior | Late fusion - weighted ✓ | 0.701 ± 0.077 | 0.786 | 17.6 % |
| DOM+Behavior | Stacking - LogReg | 0.668 ± 0.073 | 0.745 | 26.5 % |
| DOM+Behavior | Hybrid - XGBoost | 0.664 ± 0.117 | 0.771 | 8.8 % |
| DOM+Text (TF-IDF + XLM-R) | Late fusion - mean ✓ | 0.761 ± 0.054 | 0.836 | 5.9 % |
| DOM+Text (TF-IDF + XLM-R) | Late fusion - weighted | 0.750 ± 0.068 | 0.836 | 5.9 % |
| DOM+Text (TF-IDF + XLM-R) | Stacking - LogReg | 0.733 ± 0.083 | 0.785 | 14.7 % |
| DOM+Text (TF-IDF + XLM-R) | Hybrid - XGBoost | 0.754 ± 0.042 | 0.800 | 14.7 % |
| Behavior+Text (TF-IDF + XLM-R) | Late fusion - mean | 0.752 ± 0.061 | 0.804 | 5.9 % |
| Behavior+Text (TF-IDF + XLM-R) | Late fusion - weighted ✓ | 0.757 ± 0.050 | 0.795 | 8.8 % |
| Behavior+Text (TF-IDF + XLM-R) | Stacking - LogReg | 0.743 ± 0.063 | 0.755 | 14.7 % |
| Behavior+Text (TF-IDF + XLM-R) | Hybrid - XGBoost | 0.740 ± 0.048 | 0.782 | 20.6 % |

## Arm models (OOF = other folds; test = final model on train+val)

- **DOM-only**: Part 4 Random Forest {'n_estimators': 300, 'class_weight': 'balanced_subsample', 'max_depth': 8, 'max_features': 0.5, 'min_samples_leaf': 3} - reproduces the Part's CV: True
- **Behavior-only**: Part 8 Random Forest {'n_estimators': 300, 'class_weight': 'balanced_subsample', 'max_depth': 8, 'max_features': 'sqrt', 'min_samples_leaf': 1} - reproduces the Part's CV: True
- **Text TF-IDF**: Part 6A TF-IDF char 2-5 + LogReg {'C': 10.0, 'analyzer': 'char_wb', 'ngram_range': [2, 5], 'min_df': 2, 'max_features': 200000, 'sublinear_tf': True, 'max_iter': 5000} - reproduces the Part's CV: True
- **Text XLM-R**: Part 6A XLM-R (fine-tuned) {'max_length': 512, 'learning_rate': 2e-05, 'epochs': 10, 'batch_size': 16, 'eval_batch_size': 32, 'gradient_accumulation': 1, 'warmup_ratio': 0.1, 'weight_decay': 0.01, 'max_grad_norm': 1.0, 'fp16': True, 'patience': 3, 'class_weights': 'balanced'}

## Notes

- Stacking / weighted / hybrid are fit inside each CV fold on the other folds' pages; the arm OOF probabilities they read for those pages came from arm models that saw the held-out fold (standard stacking, not fully nested).
- The CV score of a selected configuration is slightly optimistic (it won a comparison on the same folds); the test score is the unbiased one, but on 68 pages.

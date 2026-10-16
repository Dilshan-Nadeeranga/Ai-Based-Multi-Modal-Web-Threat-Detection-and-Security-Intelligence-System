# Ablation study - v0.3 (C2 Part 9A: tri-modal fusion)

- created: 2026-10-16T22:38:39+05:30
- split fingerprint: `7d9ae69bbae3f5c699c022eb4ef74334ac49c4e95d68f30f9d480c9e55324f4f`; pages: train+val 391 (grouped 5-fold CV), test 68 (used once)
- arms: DOM-only, Behavior-only, Text TF-IDF
- **not included: text_xlmr** - no OOF predictions yet (text_xlmr needs the Colab CV run: `train_xlmr.py export-bundle --cv` → notebook → `import-oof`). Every row and the fusion below run without it.
- every choice (weights, stacker, final strategy, benign threshold) is made on grouped CV over train+val; the test pages are predicted once per row and only reported. CV = mean ± std over the 5 folds of the selected configuration.

## Main table (test, argmax unless stated)

| row | CV macro-F1 | test macro-F1 [95 % CI] | weighted-F1 | accuracy | ROC-AUC | benign FPR (argmax) | benign FPR (≤ 2 % thr.) |
|---|---|---|---|---|---|---|---|
| DOM-only | 0.701 ± 0.077 | **0.786** [0.652, 0.891] | 0.827 | 0.824 | 0.968 | 17.6 % | 0.0 % |
| Behavior-only | 0.620 ± 0.078 | **0.682** [0.551, 0.805] | 0.755 | 0.735 | 0.861 | 20.6 % | 0.0 % |
| Text TF-IDF | 0.706 ± 0.065 | **0.718** [0.569, 0.841] | 0.787 | 0.809 | 0.962 | 5.9 % | 0.0 % |
| DOM+Behavior · Late fusion - weighted | 0.701 ± 0.077 | **0.786** [0.652, 0.891] | 0.827 | 0.824 | 0.967 | 17.6 % | 0.0 % |
| DOM+Text (TF-IDF) · Late fusion - mean | 0.730 ± 0.048 | **0.824** [0.695, 0.923] | 0.845 | 0.853 | 0.981 | 8.8 % | 0.0 % |
| Behavior+Text (TF-IDF) · Late fusion - mean | 0.732 ± 0.067 | **0.750** [0.592, 0.870] | 0.811 | 0.824 | 0.958 | 5.9 % | 2.9 % |
| **DOM+Behavior+Text (TF-IDF) · Late fusion - mean** ★ | 0.726 ± 0.081 | **0.833** [0.701, 0.928] | 0.859 | 0.868 | 0.974 | 5.9 % | 0.0 % |
| DOM+Behavior+Text (TF-IDF) · Late fusion - weighted | 0.707 ± 0.060 | **0.833** [0.701, 0.928] | 0.859 | 0.868 | 0.974 | 5.9 % | 2.9 % |
| DOM+Behavior+Text (TF-IDF) · Stacking - LogReg | 0.718 ± 0.065 | **0.769** [0.638, 0.877] | 0.823 | 0.824 | 0.973 | 11.8 % | 0.0 % |
| DOM+Behavior+Text (TF-IDF) · Hybrid - XGBoost | 0.711 ± 0.057 | **0.807** [0.647, 0.914] | 0.849 | 0.853 | 0.971 | 8.8 % | 2.9 % |

★ final fusion model: **DOM+Behavior+Text (TF-IDF) · Late fusion - mean** (best tri-modal CV macro-F1 0.726).

## Per-class F1 (test)

| row | benign | phishing | fake_ecommerce | crypto_scam | malware_delivery |
|---|---|---|---|---|---|
| DOM-only | 0.889 | 0.750 | 1.000 | 0.667 | 0.625 |
| Behavior-only | 0.806 | 0.720 | 0.933 | 0.286 | 0.667 |
| Text TF-IDF | 0.877 | 0.815 | 0.933 | 0.600 | 0.364 |
| DOM+Behavior · Late fusion - weighted | 0.889 | 0.750 | 1.000 | 0.667 | 0.625 |
| DOM+Text (TF-IDF) · Late fusion - mean | 0.899 | 0.828 | 0.933 | 0.889 | 0.571 |
| Behavior+Text (TF-IDF) · Late fusion - mean | 0.901 | 0.786 | 0.933 | 0.667 | 0.462 |
| **DOM+Behavior+Text (TF-IDF) · Late fusion - mean** ★ | 0.914 | 0.857 | 0.933 | 0.889 | 0.571 |
| DOM+Behavior+Text (TF-IDF) · Late fusion - weighted | 0.914 | 0.857 | 0.933 | 0.889 | 0.571 |
| DOM+Behavior+Text (TF-IDF) · Stacking - LogReg | 0.896 | 0.815 | 0.933 | 0.667 | 0.533 |
| DOM+Behavior+Text (TF-IDF) · Hybrid - XGBoost | 0.899 | 0.889 | 0.875 | 0.750 | 0.625 |

## Per-language accuracy (test; Part 5A detected language, n pages)

| row | en (n=51) | si (n=1) | ta (n=1) | mixed (n=1) | other (n=14) |
|---|---|---|---|---|---|
| DOM-only | 0.824 | 1.000 ⚠ | 1.000 ⚠ | 1.000 ⚠ | 0.786 |
| Behavior-only | 0.706 | 1.000 ⚠ | 1.000 ⚠ | 1.000 ⚠ | 0.786 |
| Text TF-IDF | 0.863 | 1.000 ⚠ | 1.000 ⚠ | 0.000 ⚠ | 0.643 |
| DOM+Behavior · Late fusion - weighted | 0.824 | 1.000 ⚠ | 1.000 ⚠ | 1.000 ⚠ | 0.786 |
| DOM+Text (TF-IDF) · Late fusion - mean | 0.863 | 1.000 ⚠ | 1.000 ⚠ | 1.000 ⚠ | 0.786 |
| Behavior+Text (TF-IDF) · Late fusion - mean | 0.843 | 1.000 ⚠ | 1.000 ⚠ | 0.000 ⚠ | 0.786 |
| **DOM+Behavior+Text (TF-IDF) · Late fusion - mean** ★ | 0.882 | 1.000 ⚠ | 1.000 ⚠ | 1.000 ⚠ | 0.786 |
| DOM+Behavior+Text (TF-IDF) · Late fusion - weighted | 0.882 | 1.000 ⚠ | 1.000 ⚠ | 1.000 ⚠ | 0.786 |
| DOM+Behavior+Text (TF-IDF) · Stacking - LogReg | 0.824 | 1.000 ⚠ | 1.000 ⚠ | 1.000 ⚠ | 0.786 |
| DOM+Behavior+Text (TF-IDF) · Hybrid - XGBoost | 0.843 | 1.000 ⚠ | 1.000 ⚠ | 1.000 ⚠ | 0.857 |

⚠ = fewer than 10 test pages: an anecdote, not an estimate.

## Benign-FPR operating point (target ≤ 2 %)

Rule: benign if P(benign) ≥ t, else the most probable threat class; t = the largest threshold whose OUT-OF-FOLD benign FPR on train+val is ≤ the target (chosen without test). Threat recall = threat pages flagged as any threat.

| row | t | OOF benign FPR | test benign FPR argmax → thr. | test threat recall argmax → thr. | test macro-F1 argmax → thr. |
|---|---|---|---|---|---|
| DOM-only | 0.095 | 1.6 % | 17.6 % → 0.0 % | 97.1 % → 50.0 % | 0.786 → 0.617 |
| Behavior-only | 0.102 | 1.6 % | 20.6 % → 0.0 % | 82.4 % → 29.4 % | 0.682 → 0.436 |
| Text TF-IDF | 0.167 | 1.6 % | 5.9 % → 0.0 % | 79.4 % → 52.9 % | 0.718 → 0.655 |
| DOM+Behavior · Late fusion - weighted | 0.108 | 1.6 % | 17.6 % → 0.0 % | 97.1 % → 50.0 % | 0.786 → 0.550 |
| DOM+Text (TF-IDF) · Late fusion - mean | 0.147 | 1.6 % | 8.8 % → 0.0 % | 88.2 % → 61.8 % | 0.824 → 0.712 |
| Behavior+Text (TF-IDF) · Late fusion - mean | 0.214 | 1.6 % | 5.9 % → 2.9 % | 85.3 % → 70.6 % | 0.750 → 0.732 |
| **DOM+Behavior+Text (TF-IDF) · Late fusion - mean** ★ | 0.190 | 1.6 % | 5.9 % → 0.0 % | 88.2 % → 67.6 % | 0.833 → 0.741 |
| DOM+Behavior+Text (TF-IDF) · Late fusion - weighted | 0.217 | 1.6 % | 5.9 % → 2.9 % | 88.2 % → 73.5 % | 0.833 → 0.710 |
| DOM+Behavior+Text (TF-IDF) · Stacking - LogReg | 0.056 | 1.6 % | 11.8 % → 0.0 % | 91.2 % → 76.5 % | 0.769 → 0.748 |
| DOM+Behavior+Text (TF-IDF) · Hybrid - XGBoost | 0.040 | 1.6 % | 8.8 % → 2.9 % | 88.2 % → 73.5 % | 0.807 → 0.759 |

Final model at the threshold: confusion matrix (test, rows = true):

```
true \ predicted                  benign          phishing    fake_ecommerce       crypto_scam  malware_delivery
benign                                34                 0                 0                 0                 0
phishing                               2                11                 0                 0                 0
fake_ecommerce                         1                 0                 7                 0                 0
crypto_scam                            2                 0                 0                 2                 0
malware_delivery                       6                 1                 0                 0                 2
```

## Tri-modal vs best single arm (paired bootstrap)

1000 resamples of the 68 test pages (seed 42), the same resamples for every row; 95 % percentile CI of the macro-F1 DIFFERENCE.

- final − best single arm by CV (`text_tfidf`): **+0.115** [+0.018, +0.237]; final better in 99.2 % of resamples → the CI excludes 0.
- final − best single arm on test (conservative) (`dom`): **+0.047** [-0.075, +0.174]; final better in 78.5 % of resamples → **the CI includes 0 - the test set cannot distinguish them** (small test set).

## Complementarity (test, argmax; text = `text_tfidf`)

Oracle (any modality right): 92.6 % of 68 pages vs final fusion accuracy 86.8 %.

| bucket | pages | final fusion right | examples |
|---|---|---|---|
| all right | 41 | 41 | `c2_benign_000001`, `c2_benign_000008`, `c2_benign_000025`, `c2_benign_000029`, `c2_benign_000048` |
| only dom right | 2 | 0 | `c2_fake_ecommerce_000032`, `c2_malware_delivery_000023` |
| only behavior right | 1 | 0 | `c2_malware_delivery_000050` |
| only text right | 3 | 2 | `c2_benign_000011`, `c2_benign_000040`, `c2_crypto_scam_000011` |
| only dom wrong | 3 | 3 | `c2_benign_000002`, `c2_benign_000062`, `c2_benign_000122` |
| only behavior wrong | 8 | 8 | `c2_benign_000024`, `c2_benign_000077`, `c2_benign_000083`, `c2_benign_000087`, `c2_crypto_scam_000039` |
| only text wrong | 5 | 5 | `c2_benign_000003`, `c2_crypto_scam_000010`, `c2_malware_delivery_000045`, `c2_malware_delivery_000052`, `c2_phishing_000071` |
| all wrong | 5 | 0 | `c2_benign_000076`, `c2_malware_delivery_000018`, `c2_malware_delivery_000036`, `c2_malware_delivery_000042`, `c2_phishing_000106` |

## Explainability (test pages)

- **weighted** (weights): Text TF-IDF 50 %, Behavior-only 30 %, DOM-only 20 %
- **stacking** (LR coefficients (mean |coef| over classes, summed per arm)): Text TF-IDF 43 %, DOM-only 32 %, Behavior-only 24 %
- **hybrid** (SHAP (TreeExplainer, mean |SHAP| over the test pages, summed over classes)): DOM-only 48 %, Text TF-IDF 42 %, Behavior-only 11 %
  - `text_tfidf.p_crypto_scam` mean |SHAP| 2.559
  - `text_tfidf.p_phishing` mean |SHAP| 2.208
  - `text_tfidf.p_malware_delivery` mean |SHAP| 1.898
  - `text_tfidf.p_fake_ecommerce` mean |SHAP| 1.585
  - `text_tfidf.p_benign` mean |SHAP| 1.574
  - `dom.external_link_ratio` mean |SHAP| 1.126
  - `dom.internal_link_count` mean |SHAP| 1.002
  - `dom.null_link_ratio` mean |SHAP| 0.699
  - `dom.distinct_tag_count` mean |SHAP| 0.695
  - `dom.avg_depth` mean |SHAP| 0.649
- **mean** (weights): DOM-only 33 %, Behavior-only 33 %, Text TF-IDF 33 %

## Pairs: every strategy (✓ = chosen by CV)

| pair | strategy | CV macro-F1 | test macro-F1 | benign FPR |
|---|---|---|---|---|
| DOM+Behavior | Late fusion - mean | 0.685 ± 0.064 | 0.739 | 14.7 % |
| DOM+Behavior | Late fusion - weighted ✓ | 0.701 ± 0.077 | 0.786 | 17.6 % |
| DOM+Behavior | Stacking - LogReg | 0.668 ± 0.073 | 0.745 | 26.5 % |
| DOM+Behavior | Hybrid - XGBoost | 0.664 ± 0.117 | 0.771 | 8.8 % |
| DOM+Text (TF-IDF) | Late fusion - mean ✓ | 0.730 ± 0.048 | 0.824 | 8.8 % |
| DOM+Text (TF-IDF) | Late fusion - weighted | 0.706 ± 0.069 | 0.824 | 8.8 % |
| DOM+Text (TF-IDF) | Stacking - LogReg | 0.696 ± 0.059 | 0.772 | 11.8 % |
| DOM+Text (TF-IDF) | Hybrid - XGBoost | 0.729 ± 0.041 | 0.793 | 11.8 % |
| Behavior+Text (TF-IDF) | Late fusion - mean ✓ | 0.732 ± 0.067 | 0.750 | 5.9 % |
| Behavior+Text (TF-IDF) | Late fusion - weighted | 0.715 ± 0.065 | 0.761 | 8.8 % |
| Behavior+Text (TF-IDF) | Stacking - LogReg | 0.716 ± 0.045 | 0.816 | 11.8 % |
| Behavior+Text (TF-IDF) | Hybrid - XGBoost | 0.724 ± 0.071 | 0.736 | 20.6 % |

## Arm models (OOF = other folds; test = final model on train+val)

- **DOM-only**: Part 4 Random Forest {'n_estimators': 300, 'class_weight': 'balanced_subsample', 'max_depth': 8, 'max_features': 0.5, 'min_samples_leaf': 3} - reproduces the Part's CV: True
- **Behavior-only**: Part 8 Random Forest {'n_estimators': 300, 'class_weight': 'balanced_subsample', 'max_depth': 8, 'max_features': 'sqrt', 'min_samples_leaf': 1} - reproduces the Part's CV: True
- **Text TF-IDF**: Part 6A TF-IDF char 2-5 + LogReg {'C': 10.0, 'analyzer': 'char_wb', 'ngram_range': [2, 5], 'min_df': 2, 'max_features': 200000, 'sublinear_tf': True, 'max_iter': 5000} - reproduces the Part's CV: True

## Notes

- Stacking / weighted / hybrid are fit inside each CV fold on the other folds' pages; the arm OOF probabilities they read for those pages came from arm models that saw the held-out fold (standard stacking, not fully nested).
- The CV score of a selected configuration is slightly optimistic (it won a comparison on the same folds); the test score is the unbiased one, but on 68 pages.

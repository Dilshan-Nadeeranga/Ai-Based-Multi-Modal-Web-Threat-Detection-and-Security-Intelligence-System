# Behavior-only baseline (JS + behavioral intent) - v0.3

Created 2026-10-15T06:55:34+05:30 · feature set `js_v1+beh_v1` · model selection: mean macro-F1 over grouped stratified CV folds on train+val (test never used).

## Behavior-only classification (Part 7 JS features + Part 8 intent vector)

| Model | CV macro-F1 (mean ± std) | Test macro-F1 | Test weighted-F1 | Test accuracy | Test balanced acc. | Test ROC-AUC (OvR macro) | Benign FPR (test) |
|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.500 ± 0.054 | 0.414 | 0.510 | 0.456 | 0.449 | 0.758 | 50.0 % |
| **Random Forest** | 0.620 ± 0.078 | 0.682 | 0.755 | 0.735 | 0.683 | 0.861 | 20.6 % |
| XGBoost | 0.582 ± 0.064 | 0.686 | 0.753 | 0.750 | 0.708 | 0.866 | 23.5 % |

Best model (by CV macro-F1, chosen before looking at test): **Random Forest**. Test split: 68 pages, evaluated once. Benign FPR target: ≤ 2 % (benign test pages predicted as any threat).

CV details (mean ± std over folds):

| Model | weighted-F1 | accuracy | balanced acc. | ROC-AUC | F1 benign | F1 phishing | F1 fake_ecommerce | F1 crypto_scam | F1 malware_delivery |
|---|---|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.573 ± 0.047 | 0.522 ± 0.040 | 0.558 ± 0.048 | 0.816 ± 0.032 | 0.663 ± 0.028 | 0.427 ± 0.178 | 0.593 ± 0.088 | 0.237 ± 0.023 | 0.583 ± 0.101 |
| Random Forest | 0.707 ± 0.045 | 0.701 ± 0.044 | 0.615 ± 0.087 | 0.861 ± 0.036 | 0.805 ± 0.029 | 0.586 ± 0.047 | 0.744 ± 0.145 | 0.286 ± 0.166 | 0.677 ± 0.064 |
| XGBoost | 0.687 ± 0.030 | 0.685 ± 0.038 | 0.583 ± 0.071 | 0.868 ± 0.030 | 0.823 ± 0.023 | 0.530 ± 0.064 | 0.672 ± 0.131 | 0.269 ± 0.226 | 0.616 ± 0.039 |

## Split

| split | pages | share | benign | phishing | fake_ecommerce | crypto_scam | malware_delivery |
|---|---|---|---|---|---|---|---|
| train | 322 | 70.2 % | 159 | 61 | 40 | 21 | 41 |
| val | 69 | 15.0 % | 34 | 13 | 9 | 4 | 9 |
| test | 68 | 14.8 % | 34 | 13 | 8 | 4 | 9 |

Target 70/15/15, largest deviation 0.19 %. Stratified by label × language, grouped by near-duplicate cluster (0 clusters in two splits). Seed 42, 5 grouped CV folds over train+val. Sinhala/Tamil placement: si: train 7 / val 2 / test 1, ta: train 2 / val 1 / test 1.

Split fingerprint `7d9ae69bbae3f5c6…` (shared by every later part).

## Features

90 dictionary features → **70 used**. Dropped (decided on the TRAIN split only):

| feature | reason | detail |
|---|---|---|
| `clipboard_read_count` | constant | always 0 |
| `keylogging_present` | constant | always 0 |
| `keylogging_count` | constant | always 0 |
| `keylogging_max_severity` | constant | always 0 |
| `clipboard_manipulation_present` | constant | always 0 |
| `clipboard_manipulation_count` | constant | always 0 |
| `clipboard_manipulation_max_severity` | constant | always 0 |
| `suspicious_download_present` | constant | always 0 |
| `suspicious_download_count` | constant | always 0 |
| `suspicious_download_max_severity` | constant | always 0 |
| `clipboard_crypto_address` | constant | always 0 |
| `clickfix_command` | constant | always 0 |
| `risky_auto_download` | constant | always 0 |
| `third_party_script_no_integrity_count` | correlated | |r| = 0.9979 with third_party_script_count (kept, earlier in dictionary) |
| `credential_access_max_severity` | correlated | |r| = 1.0000 with credential_access_present (kept, earlier in dictionary) |
| `external_data_transmission_count` | correlated | |r| = 0.9897 with external_data_transmission_present (kept, earlier in dictionary) |
| `credential_exfiltration_max_severity` | correlated | |r| = 0.9849 with credential_exfiltration_present (kept, earlier in dictionary) |
| `forced_redirect_max_severity` | correlated | |r| = 1.0000 with forced_redirect_present (kept, earlier in dictionary) |
| `obfuscated_execution_max_severity` | correlated | |r| = 1.0000 with obfuscated_execution_present (kept, earlier in dictionary) |
| `anti_analysis_max_severity` | correlated | |r| = 1.0000 with anti_analysis_count (kept, earlier in dictionary) |

## Per-class test results

**Logistic Regression**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.810 | 0.500 | 0.618 | 34 |
| phishing | 0.625 | 0.385 | 0.476 | 13 |
| fake_ecommerce | 0.600 | 0.750 | 0.667 | 8 |
| crypto_scam | 0.074 | 0.500 | 0.129 | 4 |
| malware_delivery | 0.500 | 0.111 | 0.182 | 9 |

**Random Forest**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.818 | 0.794 | 0.806 | 34 |
| phishing | 0.750 | 0.692 | 0.720 | 13 |
| fake_ecommerce | 1.000 | 0.875 | 0.933 | 8 |
| crypto_scam | 0.200 | 0.500 | 0.286 | 4 |
| malware_delivery | 0.833 | 0.556 | 0.667 | 9 |

**XGBoost**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.839 | 0.765 | 0.800 | 34 |
| phishing | 0.733 | 0.846 | 0.786 | 13 |
| fake_ecommerce | 0.700 | 0.875 | 0.778 | 8 |
| crypto_scam | 0.333 | 0.500 | 0.400 | 4 |
| malware_delivery | 0.833 | 0.556 | 0.667 | 9 |

## Confusion matrix - Random Forest (test)

```
true \ predicted                  benign          phishing    fake_ecommerce       crypto_scam  malware_delivery
benign                                27                 2                 0                 4                 1
phishing                               1                 9                 0                 3                 0
fake_ecommerce                         0                 0                 7                 1                 0
crypto_scam                            2                 0                 0                 2                 0
malware_delivery                       3                 1                 0                 0                 5
```

Figures: `figures/confusion_logreg.png`, `figures/confusion_random_forest.png`, `figures/confusion_xgboost.png`

## Benign false positives (test)

- Logistic Regression: 50.0 % - c2_benign_000002, c2_benign_000003, c2_benign_000008, c2_benign_000011, c2_benign_000024, c2_benign_000025, c2_benign_000029, c2_benign_000040, c2_benign_000048, c2_benign_000062, c2_benign_000069, c2_benign_000076, c2_benign_000077, c2_benign_000083, c2_benign_000087, c2_benign_000109, c2_benign_000136
- Random Forest: 20.6 % - c2_benign_000011, c2_benign_000024, c2_benign_000040, c2_benign_000076, c2_benign_000077, c2_benign_000083, c2_benign_000087
- XGBoost: 23.5 % - c2_benign_000024, c2_benign_000040, c2_benign_000062, c2_benign_000069, c2_benign_000076, c2_benign_000077, c2_benign_000091, c2_benign_000122

## Per language - Random Forest (test)

| language | pages | accuracy | macro-F1 (classes present) | benign FPR | classes | note |
|---|---|---|---|---|---|---|
| en | 63 | 0.730 | 0.654 | 19.4 % | benign 31, phishing 13, fake_ecommerce 8, crypto_scam 3, malware_delivery 8 |  |
| si | 1 | 1.000 | 1.000 | 0.0 % | benign 1 | small n - anecdotal |
| ta | 1 | 1.000 | 1.000 | 0.0 % | benign 1 | small n - anecdotal |
| unknown | 3 | 0.667 | 0.667 | 100.0 % | benign 1, crypto_scam 1, malware_delivery 1 | small n - anecdotal |

## Feature importance

> Permutation importance and SHAP are computed on a small pilot test split; the rankings are indicative only (a few pages can reorder them).

**XGBoost - global SHAP (mean |SHAP| on test, all classes)**

| # | feature | mean |SHAP| | benign | phishing | fake_ecommerce | crypto_scam | malware_delivery |
|---|---|---|---|---|---|---|---|
| 1 | <script src> references (their content is NOT... [external_script_count] | 2.845 | 0.256 | 0.245 | 0.555 | 0.738 | 1.051 |
| 2 | Characters of page-own JavaScript analysed (i... [page_own_js_chars] | 1.932 | 0.315 | 0.335 | 0.430 | 0.309 | 0.541 |
| 3 | Longest string literal in page-own code (pack... [max_string_literal_length] | 1.578 | 0.183 | 0.260 | 0.582 | 0.181 | 0.372 |
| 4 | Inline scripts recognised as a well-known lib... [library_script_count] | 1.331 | 0.499 | 0.153 | 0.133 | 0.417 | 0.129 |
| 5 | External scripts from another site than the page [third_party_script_count] | 1.255 | 0.334 | 0.360 | 0.268 | 0.111 | 0.182 |
| 6 | Highest Shannon entropy (bits per character)... [max_script_entropy] | 1.209 | 0.114 | 0.192 | 0.366 | 0.281 | 0.257 |
| 7 | Inline <script> blocks that are code (JSON-LD... [inline_script_count] | 1.169 | 0.093 | 0.591 | 0.127 | 0.157 | 0.202 |
| 8 | Page-own scripts that look minified (long lin... [minified_script_count] | 0.915 | 0.157 | 0.081 | 0.281 | 0.331 | 0.064 |
| 9 | External scripts from a well-known CDN / serv... [known_cdn_script_count] | 0.811 | 0.230 | 0.031 | 0.401 | 0.115 | 0.034 |
| 10 | on*= event-handler attributes analysed as sma... [event_handler_count] | 0.745 | 0.194 | 0.215 | 0.112 | 0.141 | 0.083 |
| 11 | Number of distinct API categories used by pag... [api_category_count] | 0.491 | 0.214 | 0.094 | 0.071 | 0.060 | 0.052 |
| 12 | Navigations from code (location =, location.h... [redirect_count] | 0.483 | 0.078 | 0.014 | 0.177 | 0.080 | 0.134 |
| 13 | 0-100: sum of each pattern's highest-severity... [behavior_risk_score] | 0.328 | 0.004 | 0.242 | 0.002 | 0.029 | 0.050 |
| 14 | document.cookie reads (and cookieStore.get) [cookie_read_count] | 0.281 | 0.244 | 0.028 | 0.002 | 0.000 | 0.007 |
| 15 | External scripts from a raw IP, a free hostin... [external_script_suspicious_host_count] | 0.254 | 0.056 | 0.099 | 0.000 | 0.022 | 0.078 |

**XGBoost - gain**

| # | feature | value |
|---|---|---|
| 1 | Decoder calls (atob, unescape, decodeURI(Comp... [decode_call_count] | 6.932 |
| 2 | document.cookie reads (and cookieStore.get) [cookie_read_count] | 3.325 |
| 3 | 0-100: sum of each pattern's highest-severity... [behavior_risk_score] | 2.905 |
| 4 | location.replace calls (navigation that remov... [location_replace_count] | 2.477 |
| 5 | Distinct anti-analysis techniques (right-clic... [anti_analysis_count] | 2.411 |
| 6 | contextmenu listeners (usually block right-cl... [contextmenu_block_count] | 2.203 |
| 7 | Form destinations changed from code (form.act... [form_action_assign_count] | 2.082 |
| 8 | Longest string literal in page-own code (pack... [max_string_literal_length] | 1.969 |
| 9 | 1 if the page has a credential_access finding... [credential_access_present] | 1.876 |
| 10 | 1 if credential / form data reaches another s... [credential_flow_to_external] | 1.786 |
| 11 | HTML strings put into elements (innerHTML / o... [innerhtml_assign_count] | 1.775 |
| 12 | document.cookie writes (and cookieStore.set /... [cookie_write_count] | 1.757 |
| 13 | Inline scripts recognised as a well-known lib... [library_script_count] | 1.728 |
| 14 | <script src> references (their content is NOT... [external_script_count] | 1.588 |
| 15 | Flows whose data is encoded on the way (btoa,... [encoded_flow_count] | 1.471 |

**Random Forest - permutation importance on test (macro-F1 drop)**

| # | feature | drop | std |
|---|---|---|---|
| 1 | <script src> references (their content is NOT... [external_script_count] | 0.144 | 0.030 |
| 2 | Number of distinct API categories used by pag... [api_category_count] | 0.056 | 0.033 |
| 3 | Highest Shannon entropy (bits per character)... [max_script_entropy] | 0.050 | 0.029 |
| 4 | External scripts from another site than the page [third_party_script_count] | 0.046 | 0.021 |
| 5 | Inline <script> blocks that are code (JSON-LD... [inline_script_count] | 0.045 | 0.026 |
| 6 | Characters of page-own JavaScript analysed (i... [page_own_js_chars] | 0.043 | 0.031 |
| 7 | Longest string literal in page-own code (pack... [max_string_literal_length] | 0.025 | 0.026 |
| 8 | on*= event-handler attributes analysed as sma... [event_handler_count] | 0.022 | 0.016 |
| 9 | Inline scripts recognised as a well-known lib... [library_script_count] | 0.019 | 0.013 |
| 10 | Page-own scripts that look minified (long lin... [minified_script_count] | 0.017 | 0.027 |
| 11 | Decoder calls (atob, unescape, decodeURI(Comp... [decode_call_count] | 0.011 | 0.014 |
| 12 | Best flow confidence: 0 no flow, 1 low (regex... [max_flow_confidence] | 0.011 | 0.014 |
| 13 | Navigations from code (location =, location.h... [redirect_count] | 0.007 | 0.017 |
| 14 | 0-100: sum of each pattern's highest-severity... [behavior_risk_score] | 0.006 | 0.018 |
| 15 | Source-to-sink flows found (page-own code, de... [tainted_flow_count] | 0.006 | 0.016 |

**Random Forest - impurity importance**

| # | feature | value |
|---|---|---|
| 1 | Longest string literal in page-own code (pack... [max_string_literal_length] | 0.106 |
| 2 | <script src> references (their content is NOT... [external_script_count] | 0.106 |
| 3 | Characters of page-own JavaScript analysed (i... [page_own_js_chars] | 0.089 |
| 4 | Page-own scripts that look minified (long lin... [minified_script_count] | 0.079 |
| 5 | Inline <script> blocks that are code (JSON-LD... [inline_script_count] | 0.066 |
| 6 | Highest Shannon entropy (bits per character)... [max_script_entropy] | 0.061 |
| 7 | External scripts from another site than the page [third_party_script_count] | 0.048 |
| 8 | Decoder calls (atob, unescape, decodeURI(Comp... [decode_call_count] | 0.037 |
| 9 | Number of distinct API categories used by pag... [api_category_count] | 0.033 |
| 10 | Inline scripts recognised as a well-known lib... [library_script_count] | 0.030 |
| 11 | navigator.sendBeacon calls and image beacons... [beacon_count] | 0.023 |
| 12 | on*= event-handler attributes analysed as sma... [event_handler_count] | 0.023 |
| 13 | location.replace calls (navigation that remov... [location_replace_count] | 0.022 |
| 14 | External scripts from a well-known CDN / serv... [known_cdn_script_count] | 0.021 |
| 15 | Source-to-sink flows found (page-own code, de... [tainted_flow_count] | 0.018 |

**Logistic Regression - standardized coefficients (top 5 per class)**

| class | feature | coefficient |
|---|---|---|
| benign | Inline scripts recognised as a well-known lib... [library_script_count] | +0.241 |
| benign | document.cookie reads (and cookieStore.get) [cookie_read_count] | +0.133 |
| benign | document.cookie writes (and cookieStore.set /... [cookie_write_count] | +0.108 |
| benign | Inline <script> blocks that are code (JSON-LD... [inline_script_count] | +0.089 |
| benign | External scripts from a raw IP, a free hostin... [external_script_suspicious_host_count] | -0.088 |
| phishing | External scripts from another site than the page [third_party_script_count] | +0.159 |
| phishing | External scripts from a raw IP, a free hostin... [external_script_suspicious_host_count] | +0.110 |
| phishing | 0-100: sum of each pattern's highest-severity... [behavior_risk_score] | +0.107 |
| phishing | Decoder calls (atob, unescape, decodeURI(Comp... [decode_call_count] | -0.099 |
| phishing | Distinct anti-analysis techniques (right-clic... [anti_analysis_count] | +0.092 |
| fake_ecommerce | Longest string literal in page-own code (pack... [max_string_literal_length] | +0.239 |
| fake_ecommerce | Page-own scripts that look minified (long lin... [minified_script_count] | +0.206 |
| fake_ecommerce | Characters of page-own JavaScript analysed (i... [page_own_js_chars] | +0.164 |
| fake_ecommerce | Highest Shannon entropy (bits per character)... [max_script_entropy] | +0.125 |
| fake_ecommerce | <script src> references (their content is NOT... [external_script_count] | +0.090 |
| crypto_scam | Characters of page-own JavaScript analysed (i... [page_own_js_chars] | -0.120 |
| crypto_scam | Inline scripts recognised as a well-known lib... [library_script_count] | -0.117 |
| crypto_scam | Decoder calls (atob, unescape, decodeURI(Comp... [decode_call_count] | -0.097 |
| crypto_scam | Longest string literal in page-own code (pack... [max_string_literal_length] | -0.096 |
| crypto_scam | location.replace calls (navigation that remov... [location_replace_count] | -0.094 |
| malware_delivery | Decoder calls (atob, unescape, decodeURI(Comp... [decode_call_count] | +0.340 |
| malware_delivery | location.replace calls (navigation that remov... [location_replace_count] | +0.174 |
| malware_delivery | navigator.sendBeacon calls and image beacons... [beacon_count] | +0.138 |
| malware_delivery | <script src> references (their content is NOT... [external_script_count] | -0.127 |
| malware_delivery | Highest Shannon entropy (bits per character)... [max_script_entropy] | -0.093 |

Figures: `figures/importance_*.png`, `figures/shap_global_xgboost.png`, `figures/shap_beeswarm_<class>.png`.

## Misclassified test pages

- Logistic Regression: 37 of 68
- Random Forest: 18 of 68
- XGBoost: 17 of 68

`misclassified.csv` lists them (sample_id, true, predicted, probabilities). In the inspector tick **misclassified (test)** to browse them.

## Chosen hyperparameters

- Logistic Regression: max_iter=5000, class_weight=balanced, C=0.01 (4 grid points)
- Random Forest: n_estimators=300, class_weight=balanced_subsample, max_depth=8, max_features=sqrt, min_samples_leaf=1 (8 grid points)
- XGBoost: n_estimators=300, tree_method=hist, objective=multi:softprob, eval_metric=mlogloss, learning_rate=0.05, max_depth=3, subsample=0.8 (8 grid points)

## Reproduce

```bash
python scripts/map_behavior.py train-baseline --version v0.3
```

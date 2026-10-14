# DOM baseline (Baseline 1) - v0.3

Created 2026-10-14T22:49:44+05:30 · feature set `dom_v1` · model selection: mean macro-F1 over grouped stratified CV folds on train+val (test never used).

## Baseline 1 - DOM-only structural classification

| Model | CV macro-F1 (mean ± std) | Test macro-F1 | Test weighted-F1 | Test accuracy | Test balanced acc. | Test ROC-AUC (OvR macro) | Benign FPR (test) |
|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.599 ± 0.079 | 0.658 | 0.744 | 0.735 | 0.711 | 0.900 | 20.6 % |
| **Random Forest** | 0.701 ± 0.077 | 0.786 | 0.827 | 0.824 | 0.810 | 0.968 | 17.6 % |
| XGBoost | 0.684 ± 0.091 | 0.765 | 0.817 | 0.824 | 0.775 | 0.964 | 11.8 % |

Best model (by CV macro-F1, chosen before looking at test): **Random Forest**. Test split: 68 pages, evaluated once. Benign FPR target: ≤ 2 % (benign test pages predicted as any threat).

CV details (mean ± std over folds):

| Model | weighted-F1 | accuracy | balanced acc. | ROC-AUC | F1 benign | F1 phishing | F1 fake_ecommerce | F1 crypto_scam | F1 malware_delivery |
|---|---|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.698 ± 0.062 | 0.672 ± 0.072 | 0.618 ± 0.074 | 0.863 ± 0.037 | 0.799 ± 0.024 | 0.636 ± 0.143 | 0.680 ± 0.159 | 0.245 ± 0.061 | 0.634 ± 0.160 |
| Random Forest | 0.777 ± 0.057 | 0.772 ± 0.063 | 0.709 ± 0.079 | 0.902 ± 0.031 | 0.865 ± 0.041 | 0.725 ± 0.086 | 0.790 ± 0.120 | 0.475 ± 0.226 | 0.648 ± 0.087 |
| XGBoost | 0.769 ± 0.061 | 0.772 ± 0.067 | 0.673 ± 0.088 | 0.907 ± 0.024 | 0.866 ± 0.046 | 0.725 ± 0.090 | 0.720 ± 0.129 | 0.449 ± 0.257 | 0.662 ± 0.065 |

## Split

| split | pages | share | benign | phishing | fake_ecommerce | crypto_scam | malware_delivery |
|---|---|---|---|---|---|---|---|
| train | 322 | 70.2 % | 159 | 61 | 40 | 21 | 41 |
| val | 69 | 15.0 % | 34 | 13 | 9 | 4 | 9 |
| test | 68 | 14.8 % | 34 | 13 | 8 | 4 | 9 |

Target 70/15/15, largest deviation 0.19 %. Stratified by label × language, grouped by near-duplicate cluster (0 clusters in two splits). Seed 42, 5 grouped CV folds over train+val. Sinhala/Tamil placement: si: train 7 / val 2 / test 1, ta: train 2 / val 1 / test 1.

Split fingerprint `7d9ae69bbae3f5c6…` (shared by every later part).

## Features

52 dictionary features → **48 used**. Dropped (decided on the TRAIN split only):

| feature | reason | detail |
|---|---|---|
| `base_url_known` | constant | always 1 |
| `meta_refresh_external` | constant | always 0 |
| `element_count` | correlated | |r| = 0.9964 with node_count (kept, earlier in dictionary) |
| `form_action_to_known_form_service` | correlated | |r| = 1.0000 with password_form_external_action (kept, earlier in dictionary) |

## Per-class test results

**Logistic Regression**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.964 | 0.794 | 0.871 | 34 |
| phishing | 0.643 | 0.692 | 0.667 | 13 |
| fake_ecommerce | 0.636 | 0.875 | 0.737 | 8 |
| crypto_scam | 0.429 | 0.750 | 0.545 | 4 |
| malware_delivery | 0.500 | 0.444 | 0.471 | 9 |

**Random Forest**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.966 | 0.824 | 0.889 | 34 |
| phishing | 0.632 | 0.923 | 0.750 | 13 |
| fake_ecommerce | 1.000 | 1.000 | 1.000 | 8 |
| crypto_scam | 0.600 | 0.750 | 0.667 | 4 |
| malware_delivery | 0.714 | 0.556 | 0.625 | 9 |

**XGBoost**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.882 | 0.882 | 0.882 | 34 |
| phishing | 0.750 | 0.923 | 0.828 | 13 |
| fake_ecommerce | 0.875 | 0.875 | 0.875 | 8 |
| crypto_scam | 0.600 | 0.750 | 0.667 | 4 |
| malware_delivery | 0.800 | 0.444 | 0.571 | 9 |

## Confusion matrix - Random Forest (test)

```
true \ predicted                  benign          phishing    fake_ecommerce       crypto_scam  malware_delivery
benign                                28                 3                 0                 1                 2
phishing                               0                12                 0                 1                 0
fake_ecommerce                         0                 0                 8                 0                 0
crypto_scam                            0                 1                 0                 3                 0
malware_delivery                       1                 3                 0                 0                 5
```

Figures: `figures/confusion_logreg.png`, `figures/confusion_random_forest.png`, `figures/confusion_xgboost.png`

## Benign false positives (test)

- Logistic Regression: 20.6 % - c2_benign_000024, c2_benign_000029, c2_benign_000040, c2_benign_000062, c2_benign_000076, c2_benign_000091, c2_benign_000187
- Random Forest: 17.6 % - c2_benign_000002, c2_benign_000011, c2_benign_000040, c2_benign_000062, c2_benign_000076, c2_benign_000122
- XGBoost: 11.8 % - c2_benign_000011, c2_benign_000040, c2_benign_000062, c2_benign_000122

## Per language - Random Forest (test)

| language | pages | accuracy | macro-F1 (classes present) | benign FPR | classes | note |
|---|---|---|---|---|---|---|
| en | 63 | 0.841 | 0.791 | 16.1 % | benign 31, phishing 13, fake_ecommerce 8, crypto_scam 3, malware_delivery 8 |  |
| si | 1 | 1.000 | 1.000 | 0.0 % | benign 1 | small n - anecdotal |
| ta | 1 | 1.000 | 1.000 | 0.0 % | benign 1 | small n - anecdotal |
| unknown | 3 | 0.333 | 0.333 | 100.0 % | benign 1, crypto_scam 1, malware_delivery 1 | small n - anecdotal |

## Feature importance

> Permutation importance and SHAP are computed on a small pilot test split; the rankings are indicative only (a few pages can reorder them).

**XGBoost - global SHAP (mean |SHAP| on test, all classes)**

| # | feature | mean |SHAP| | benign | phishing | fake_ecommerce | crypto_scam | malware_delivery |
|---|---|---|---|---|---|---|---|
| 1 | Web links to the page's own registrable domai... [internal_link_count] | 2.436 | 0.802 | 0.871 | 0.342 | 0.336 | 0.086 |
| 2 | External web links divided by all web links (... [external_link_ratio] | 1.639 | 0.316 | 0.427 | 0.347 | 0.517 | 0.031 |
| 3 | Total characters of inline JavaScript [inline_script_chars_total] | 1.586 | 0.395 | 0.164 | 0.383 | 0.440 | 0.203 |
| 4 | Number of <script src> references [external_script_count] | 1.498 | 0.090 | 0.061 | 0.284 | 0.296 | 0.767 |
| 5 | Elements plus non-empty text nodes [node_count] | 1.385 | 0.049 | 0.145 | 0.116 | 0.594 | 0.481 |
| 6 | Visible characters divided by HTML bytes [text_to_html_ratio] | 1.224 | 0.136 | 0.084 | 0.315 | 0.404 | 0.286 |
| 7 | Number of different tag names [distinct_tag_count] | 1.050 | 0.200 | 0.344 | 0.328 | 0.163 | 0.015 |
| 8 | Share of elements with no child elements [leaf_ratio] | 0.980 | 0.241 | 0.223 | 0.071 | 0.298 | 0.148 |
| 9 | Average nesting level of all elements - how "... [avg_depth] | 0.866 | 0.231 | 0.029 | 0.147 | 0.274 | 0.185 |
| 10 | Characters in the title [title_length] | 0.863 | 0.156 | 0.057 | 0.061 | 0.285 | 0.304 |
| 11 | Null links divided by all links [null_link_ratio] | 0.785 | 0.115 | 0.269 | 0.068 | 0.259 | 0.074 |
| 12 | Web links to other domains [external_link_count] | 0.699 | 0.346 | 0.026 | 0.231 | 0.054 | 0.043 |
| 13 | Number of <a href> links [link_count] | 0.646 | 0.288 | 0.025 | 0.035 | 0.149 | 0.149 |
| 14 | Stylesheets loaded from other domains divided... [external_stylesheet_ratio] | 0.589 | 0.039 | 0.038 | 0.214 | 0.057 | 0.242 |
| 15 | Deepest nesting level (html = 1) [max_depth] | 0.553 | 0.049 | 0.073 | 0.272 | 0.064 | 0.097 |

**XGBoost - gain**

| # | feature | value |
|---|---|---|
| 1 | A form submits to a bare IP address instead o... [form_action_to_ip] | 4.265 |
| 2 | Web links to the page's own registrable domai... [internal_link_count] | 2.996 |
| 3 | Number of <script src> references [external_script_count] | 2.917 |
| 4 | All input/select/textarea fields, inside or o... [inputs_total] | 2.909 |
| 5 | A form with a password field uses method GET,... [form_method_get_with_password] | 2.905 |
| 6 | Fields asking for a card number, CVV or expir... [card_field_count] | 2.506 |
| 7 | Fields for secrets that a scammer can use dir... [sensitive_field_count] | 2.317 |
| 8 | Number of <a href> links [link_count] | 2.243 |
| 9 | Total characters of inline JavaScript [inline_script_chars_total] | 2.083 |
| 10 | External web links divided by all web links (... [external_link_ratio] | 1.808 |
| 11 | Distinct other domains that scripts are loade... [external_script_domain_count] | 1.762 |
| 12 | Password fields (type=password or a password... [password_field_count] | 1.720 |
| 13 | Fields not inside any form - typical of kits... [inputs_outside_forms_count] | 1.716 |
| 14 | Null links divided by all links [null_link_ratio] | 1.670 |
| 15 | Forms that submit to another registrable doma... [external_form_action_count] | 1.626 |

**Random Forest - permutation importance on test (macro-F1 drop)**

| # | feature | drop | std |
|---|---|---|---|
| 1 | Web links to the page's own registrable domai... [internal_link_count] | 0.214 | 0.053 |
| 2 | Number of <script src> references [external_script_count] | 0.095 | 0.033 |
| 3 | Elements plus non-empty text nodes [node_count] | 0.040 | 0.025 |
| 4 | External web links divided by all web links (... [external_link_ratio] | 0.034 | 0.033 |
| 5 | All input/select/textarea fields, inside or o... [inputs_total] | 0.033 | 0.036 |
| 6 | Hidden text divided by all text (hidden + vis... [hidden_text_ratio] | 0.018 | 0.024 |
| 7 | Fields for secrets that a scammer can use dir... [sensitive_field_count] | 0.008 | 0.017 |
| 8 | Password fields (type=password or a password... [password_field_count] | 0.007 | 0.015 |
| 9 | Number of <a href> links [link_count] | 0.006 | 0.017 |
| 10 | The page asks for a password [has_password_field] | 0.006 | 0.016 |
| 11 | Deepest nesting level (html = 1) [max_depth] | 0.000 | 0.000 |
| 12 | Average nesting level of all elements - how "... [avg_depth] | 0.000 | 0.000 |
| 13 | Visible characters divided by HTML bytes [text_to_html_ratio] | 0.000 | 0.000 |
| 14 | Number of <form> elements [form_count] | 0.000 | 0.000 |
| 15 | The page has at least one form [has_form] | 0.000 | 0.000 |

**Random Forest - impurity importance**

| # | feature | value |
|---|---|---|
| 1 | Web links to the page's own registrable domai... [internal_link_count] | 0.126 |
| 2 | Total characters of inline JavaScript [inline_script_chars_total] | 0.100 |
| 3 | Number of <script src> references [external_script_count] | 0.099 |
| 4 | External web links divided by all web links (... [external_link_ratio] | 0.076 |
| 5 | Visible characters divided by HTML bytes [text_to_html_ratio] | 0.050 |
| 6 | Web links to other domains [external_link_count] | 0.050 |
| 7 | Number of <a href> links [link_count] | 0.050 |
| 8 | Elements plus non-empty text nodes [node_count] | 0.047 |
| 9 | Share of elements with no child elements [leaf_ratio] | 0.042 |
| 10 | Average nesting level of all elements - how "... [avg_depth] | 0.037 |
| 11 | Number of inline <script> blocks with code (J... [inline_script_count] | 0.034 |
| 12 | Number of different domains that links point to [distinct_external_domains] | 0.033 |
| 13 | All input/select/textarea fields, inside or o... [inputs_total] | 0.029 |
| 14 | Characters in the title [title_length] | 0.026 |
| 15 | Number of different tag names [distinct_tag_count] | 0.023 |

**Logistic Regression - standardized coefficients (top 5 per class)**

| class | feature | coefficient |
|---|---|---|
| benign | Number of different domains that links point to [distinct_external_domains] | +0.509 |
| benign | Null links divided by all links [null_link_ratio] | -0.441 |
| benign | Frames that are invisible (zero size or hidde... [hidden_iframe_count] | +0.363 |
| benign | Distinct other domains that scripts are loade... [external_script_domain_count] | +0.339 |
| benign | Number of inline <script> blocks with code (J... [inline_script_count] | +0.294 |
| phishing | Null links divided by all links [null_link_ratio] | +0.623 |
| phishing | External web links divided by all web links (... [external_link_ratio] | +0.436 |
| phishing | The page asks for a password [has_password_field] | +0.391 |
| phishing | Number of different tag names [distinct_tag_count] | -0.381 |
| phishing | Hidden text divided by all text (hidden + vis... [hidden_text_ratio] | +0.375 |
| fake_ecommerce | Stylesheets loaded from other domains divided... [external_stylesheet_ratio] | +0.417 |
| fake_ecommerce | Number of <script src> references [external_script_count] | +0.381 |
| fake_ecommerce | Web links to the page's own registrable domai... [internal_link_count] | +0.346 |
| fake_ecommerce | Deepest nesting level (html = 1) [max_depth] | -0.342 |
| fake_ecommerce | Distinct other domains that scripts are loade... [external_script_domain_count] | -0.330 |
| crypto_scam | Number of different tag names [distinct_tag_count] | +0.430 |
| crypto_scam | Distinct other domains that scripts are loade... [external_script_domain_count] | +0.430 |
| crypto_scam | Total characters of inline JavaScript [inline_script_chars_total] | -0.418 |
| crypto_scam | Share of elements with no child elements [leaf_ratio] | +0.365 |
| crypto_scam | Hidden inputs divided by all inputs [hidden_input_ratio] | -0.349 |
| malware_delivery | Number of <script src> references [external_script_count] | -0.581 |
| malware_delivery | A form submits to a bare IP address instead o... [form_action_to_ip] | +0.427 |
| malware_delivery | Share of elements with no child elements [leaf_ratio] | -0.396 |
| malware_delivery | Null links divided by all links [null_link_ratio] | -0.368 |
| malware_delivery | Characters in the title [title_length] | -0.368 |

Figures: `figures/importance_*.png`, `figures/shap_global_xgboost.png`, `figures/shap_beeswarm_<class>.png`.

## Misclassified test pages

- Logistic Regression: 18 of 68
- Random Forest: 12 of 68
- XGBoost: 12 of 68

`misclassified.csv` lists them (sample_id, true, predicted, probabilities). In the inspector tick **misclassified (test)** to browse them.

## Chosen hyperparameters

- Logistic Regression: max_iter=5000, class_weight=balanced, C=0.1 (4 grid points)
- Random Forest: n_estimators=300, class_weight=balanced_subsample, max_depth=8, max_features=0.5, min_samples_leaf=3 (8 grid points)
- XGBoost: n_estimators=300, tree_method=hist, objective=multi:softprob, eval_metric=mlogloss, learning_rate=0.05, max_depth=3, subsample=0.8 (8 grid points)

## Reproduce

```bash
python scripts/train_dom_baseline.py all --version v0.3
```

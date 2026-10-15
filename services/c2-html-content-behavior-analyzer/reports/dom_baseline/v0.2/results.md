# DOM baseline (Baseline 1) - v0.2

> **PILOT run.** 3 classes (benign, phishing, malware_delivery); excluded because they have too few pages: fake_ecommerce (3), crypto_scam (2). Labels of v0.2 are mostly unverified. Re-run unchanged on the next dataset version with `python scripts/train_dom_baseline.py all --version <version>`.

Created 2026-10-14T16:32:09+05:30 · feature set `dom_v1` · model selection: mean macro-F1 over grouped stratified CV folds on train+val (test never used).

## Baseline 1 - DOM-only structural classification

| Model | CV macro-F1 (mean ± std) | Test macro-F1 | Test weighted-F1 | Test accuracy | Test balanced acc. | Test ROC-AUC (OvR macro) | Benign FPR (test) |
|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.715 ± 0.044 | 0.842 | 0.846 | 0.844 | 0.865 | 0.938 | 21.7 % |
| Random Forest | 0.779 ± 0.033 | 0.713 | 0.748 | 0.756 | 0.694 | 0.899 | 13.0 % |
| **XGBoost** | 0.795 ± 0.046 | 0.673 | 0.718 | 0.733 | 0.669 | 0.886 | 17.4 % |

Best model (by CV macro-F1, chosen before looking at test): **XGBoost**. Test split: 45 pages, evaluated once. Benign FPR target: ≤ 2 % (benign test pages predicted as any threat).

CV details (mean ± std over folds):

| Model | weighted-F1 | accuracy | balanced acc. | ROC-AUC | F1 benign | F1 phishing | F1 malware_delivery |
|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.750 ± 0.033 | 0.742 ± 0.034 | 0.738 ± 0.057 | 0.891 ± 0.029 | 0.814 ± 0.035 | 0.750 ± 0.024 | 0.581 ± 0.121 |
| Random Forest | 0.805 ± 0.029 | 0.809 ± 0.028 | 0.770 ± 0.034 | 0.911 ± 0.030 | 0.855 ± 0.037 | 0.806 ± 0.056 | 0.675 ± 0.117 |
| XGBoost | 0.819 ± 0.033 | 0.821 ± 0.032 | 0.792 ± 0.048 | 0.921 ± 0.025 | 0.868 ± 0.033 | 0.797 ± 0.015 | 0.722 ± 0.132 |

## Split

| split | pages | share | benign | phishing | malware_delivery |
|---|---|---|---|---|---|
| train | 211 | 70.1 % | 109 | 61 | 41 |
| val | 45 | 14.9 % | 23 | 13 | 9 |
| test | 45 | 14.9 % | 23 | 13 | 9 |

Target 70/15/15, largest deviation 0.10 %. Stratified by label × language, grouped by near-duplicate cluster (0 clusters in two splits). Seed 42, 5 grouped CV folds over train+val. Sinhala/Tamil placement: si: train 7 / val 1 / test 2, ta: train 2 / val 1 / test 1.

Split fingerprint `32bb56422aeb7097…` (shared by every later part).

## Features

52 dictionary features → **47 used**. Dropped (decided on the TRAIN split only):

| feature | reason | detail |
|---|---|---|
| `base_url_known` | constant | always 1 |
| `meta_refresh_external` | constant | always 0 |
| `element_count` | correlated | |r| = 0.9940 with node_count (kept, earlier in dictionary) |
| `has_external_form_action` | correlated | |r| = 1.0000 with external_form_action_count (kept, earlier in dictionary) |
| `form_action_to_known_form_service` | correlated | |r| = 1.0000 with password_form_external_action (kept, earlier in dictionary) |

## Per-class test results

**Logistic Regression**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.947 | 0.783 | 0.857 | 23 |
| phishing | 0.750 | 0.923 | 0.828 | 13 |
| malware_delivery | 0.800 | 0.889 | 0.842 | 9 |

**Random Forest**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.800 | 0.870 | 0.833 | 23 |
| phishing | 0.625 | 0.769 | 0.690 | 13 |
| malware_delivery | 1.000 | 0.444 | 0.615 | 9 |

**XGBoost**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.792 | 0.826 | 0.809 | 23 |
| phishing | 0.611 | 0.846 | 0.710 | 13 |
| malware_delivery | 1.000 | 0.333 | 0.500 | 9 |

## Confusion matrix - XGBoost (test)

```
true \ predicted                  benign          phishing  malware_delivery
benign                                19                 4                 0
phishing                               2                11                 0
malware_delivery                       3                 3                 3
```

Figures: `figures/confusion_logreg.png`, `figures/confusion_random_forest.png`, `figures/confusion_xgboost.png`

## Benign false positives (test)

- Logistic Regression: 21.7 % - c2_benign_000059, c2_benign_000062, c2_benign_000070, c2_benign_000104, c2_benign_000142
- Random Forest: 13.0 % - c2_benign_000002, c2_benign_000062, c2_benign_000104
- XGBoost: 17.4 % - c2_benign_000059, c2_benign_000062, c2_benign_000104, c2_benign_000122

## Per language - XGBoost (test)

| language | pages | accuracy | macro-F1 (classes present) | benign FPR | classes | note |
|---|---|---|---|---|---|---|
| en | 41 | 0.756 | 0.696 | 15.0 % | benign 20, phishing 12, malware_delivery 9 |  |
| si | 2 | 0.500 | 0.667 | 50.0 % | benign 2 | small n - anecdotal |
| ta | 1 | 1.000 | 1.000 | 0.0 % | benign 1 | small n - anecdotal |
| unknown | 1 | 0.000 | 0.000 | — | phishing 1 | small n - anecdotal |

## Feature importance

> Permutation importance and SHAP are computed on a small pilot test split; the rankings are indicative only (a few pages can reorder them).

**XGBoost - global SHAP (mean |SHAP| on test, all classes)**

| # | feature | mean |SHAP| | benign | phishing | malware_delivery |
|---|---|---|---|---|---|
| 1 | Web links to the page's own registrable domai... [internal_link_count] | 1.922 | 1.674 | 0.104 | 0.144 |
| 2 | Share of elements with no child elements [leaf_ratio] | 1.690 | 0.070 | 1.016 | 0.604 |
| 3 | Number of <a href> links [link_count] | 1.562 | 0.324 | 0.974 | 0.264 |
| 4 | Elements plus non-empty text nodes [node_count] | 1.550 | 0.117 | 0.624 | 0.808 |
| 5 | Characters in the title [title_length] | 1.003 | 0.392 | 0.056 | 0.555 |
| 6 | Null links divided by all links [null_link_ratio] | 0.974 | 0.297 | 0.485 | 0.192 |
| 7 | Hidden text divided by all text (hidden + vis... [hidden_text_ratio] | 0.952 | 0.010 | 0.245 | 0.697 |
| 8 | Number of different tag names [distinct_tag_count] | 0.909 | 0.617 | 0.248 | 0.044 |
| 9 | Web links to other domains [external_link_count] | 0.754 | 0.618 | 0.119 | 0.018 |
| 10 | Total characters of inline JavaScript [inline_script_chars_total] | 0.572 | 0.199 | 0.266 | 0.107 |
| 11 | Elements hidden by their own markup (hidden a... [hidden_element_count] | 0.543 | 0.016 | 0.015 | 0.511 |
| 12 | Number of inline <script> blocks with code (J... [inline_script_count] | 0.522 | 0.265 | 0.142 | 0.114 |
| 13 | Deepest nesting level (html = 1) [max_depth] | 0.494 | 0.088 | 0.092 | 0.314 |
| 14 | All input/select/textarea fields, inside or o... [inputs_total] | 0.473 | 0.167 | 0.218 | 0.088 |
| 15 | Average nesting level of all elements - how "... [avg_depth] | 0.372 | 0.157 | 0.059 | 0.156 |

**XGBoost - gain**

| # | feature | value |
|---|---|---|
| 1 | Fields asking for an e-mail address (type, au... [email_field_count] | 3.656 |
| 2 | A form submits to a bare IP address instead o... [form_action_to_ip] | 3.575 |
| 3 | Number of <script src> references [external_script_count] | 3.430 |
| 4 | A form with a password field uses method GET,... [form_method_get_with_password] | 2.801 |
| 5 | Web links to the page's own registrable domai... [internal_link_count] | 2.745 |
| 6 | Password fields (type=password or a password... [password_field_count] | 2.419 |
| 7 | Inputs of type=hidden or hidden by attribute/... [hidden_input_count] | 1.520 |
| 8 | Share of elements with no child elements [leaf_ratio] | 1.270 |
| 9 | Hidden text divided by all text (hidden + vis... [hidden_text_ratio] | 1.160 |
| 10 | All input/select/textarea fields, inside or o... [inputs_total] | 1.151 |
| 11 | Null links divided by all links [null_link_ratio] | 1.142 |
| 12 | Fields not inside any form - typical of kits... [inputs_outside_forms_count] | 0.935 |
| 13 | Fields for secrets that a scammer can use dir... [sensitive_field_count] | 0.873 |
| 14 | Elements plus non-empty text nodes [node_count] | 0.857 |
| 15 | Elements hidden by their own markup (hidden a... [hidden_element_count] | 0.763 |

**Random Forest - permutation importance on test (macro-F1 drop)**

| # | feature | drop | std |
|---|---|---|---|
| 1 | Number of <script src> references [external_script_count] | 0.048 | 0.015 |
| 2 | Web links to the page's own registrable domai... [internal_link_count] | 0.042 | 0.038 |
| 3 | Elements hidden by their own markup (hidden a... [hidden_element_count] | 0.031 | 0.020 |
| 4 | Stylesheets loaded from other domains divided... [external_stylesheet_ratio] | 0.029 | 0.021 |
| 5 | Web links to other domains [external_link_count] | 0.029 | 0.021 |
| 6 | Visible characters divided by HTML bytes [text_to_html_ratio] | 0.029 | 0.021 |
| 7 | Elements plus non-empty text nodes [node_count] | 0.012 | 0.029 |
| 8 | Share of elements with no child elements [leaf_ratio] | 0.011 | 0.022 |
| 9 | Average nesting level of all elements - how "... [avg_depth] | 0.010 | 0.008 |
| 10 | Characters in the title [title_length] | 0.007 | 0.016 |
| 11 | Deepest nesting level (html = 1) [max_depth] | 0.005 | 0.008 |
| 12 | Number of different tag names [distinct_tag_count] | 0.003 | 0.015 |
| 13 | All input/select/textarea fields, inside or o... [inputs_total] | 0.002 | 0.013 |
| 14 | Number of <a href> links [link_count] | 0.002 | 0.024 |
| 15 | The page asks for a password [has_password_field] | 0.001 | 0.003 |

**Random Forest - impurity importance**

| # | feature | value |
|---|---|---|
| 1 | Web links to the page's own registrable domai... [internal_link_count] | 0.192 |
| 2 | Number of <a href> links [link_count] | 0.098 |
| 3 | Elements plus non-empty text nodes [node_count] | 0.083 |
| 4 | Share of elements with no child elements [leaf_ratio] | 0.075 |
| 5 | All input/select/textarea fields, inside or o... [inputs_total] | 0.056 |
| 6 | Number of <script src> references [external_script_count] | 0.048 |
| 7 | Number of different tag names [distinct_tag_count] | 0.042 |
| 8 | Null links divided by all links [null_link_ratio] | 0.033 |
| 9 | Total characters of inline JavaScript [inline_script_chars_total] | 0.031 |
| 10 | Visible characters divided by HTML bytes [text_to_html_ratio] | 0.030 |
| 11 | Average nesting level of all elements - how "... [avg_depth] | 0.029 |
| 12 | Characters in the title [title_length] | 0.029 |
| 13 | Elements hidden by their own markup (hidden a... [hidden_element_count] | 0.025 |
| 14 | Web links to other domains [external_link_count] | 0.024 |
| 15 | Fields asking for an e-mail address (type, au... [email_field_count] | 0.019 |

**Logistic Regression - standardized coefficients (top 5 per class)**

| class | feature | coefficient |
|---|---|---|
| benign | Web links to the page's own registrable domai... [internal_link_count] | +0.524 |
| benign | Number of different domains that links point to [distinct_external_domains] | +0.362 |
| benign | Null links divided by all links [null_link_ratio] | -0.338 |
| benign | Distinct other domains that scripts are loade... [external_script_domain_count] | +0.297 |
| benign | Number of <a href> links [link_count] | +0.279 |
| phishing | Null links divided by all links [null_link_ratio] | +0.599 |
| phishing | Fields not inside any form - typical of kits... [inputs_outside_forms_count] | +0.370 |
| phishing | Share of elements with no child elements [leaf_ratio] | +0.341 |
| phishing | Web links to the page's own registrable domai... [internal_link_count] | -0.333 |
| phishing | The page asks for a password [has_password_field] | +0.330 |
| malware_delivery | Hidden text divided by all text (hidden + vis... [hidden_text_ratio] | -0.393 |
| malware_delivery | A form submits to a bare IP address instead o... [form_action_to_ip] | +0.374 |
| malware_delivery | Share of elements with no child elements [leaf_ratio] | -0.331 |
| malware_delivery | Elements plus non-empty text nodes [node_count] | -0.287 |
| malware_delivery | The page has at least one form [has_form] | +0.263 |

Figures: `figures/importance_*.png`, `figures/shap_global_xgboost.png`, `figures/shap_beeswarm_<class>.png`.

## Misclassified test pages

- Logistic Regression: 7 of 45
- Random Forest: 11 of 45
- XGBoost: 12 of 45

`misclassified.csv` lists them (sample_id, true, predicted, probabilities). In the inspector tick **misclassified (test)** to browse them.

## Chosen hyperparameters

- Logistic Regression: max_iter=5000, class_weight=balanced, C=0.1 (4 grid points)
- Random Forest: n_estimators=300, class_weight=balanced_subsample, max_depth=8, max_features=0.5, min_samples_leaf=1 (8 grid points)
- XGBoost: n_estimators=300, tree_method=hist, objective=multi:softprob, eval_metric=mlogloss, learning_rate=0.1, max_depth=3, subsample=1.0 (8 grid points)

## Reproduce

```bash
python scripts/train_dom_baseline.py all --version v0.2
```

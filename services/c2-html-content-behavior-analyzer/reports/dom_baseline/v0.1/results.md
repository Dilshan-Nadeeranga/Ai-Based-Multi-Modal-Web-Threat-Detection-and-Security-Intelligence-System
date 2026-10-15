# DOM baseline (Baseline 1) - v0.1

> **PILOT run.** 3 classes (benign, phishing, malware_delivery); excluded because they have too few pages: fake_ecommerce (0), crypto_scam (0). Labels of v0.1 are mostly unverified. Re-run unchanged on the next dataset version with `python scripts/train_dom_baseline.py all --version <version>`.

Created 2026-10-14T15:26:55+05:30 · feature set `dom_v1` · model selection: mean macro-F1 over grouped stratified CV folds on train+val (test never used).

## Baseline 1 - DOM-only structural classification

| Model | CV macro-F1 (mean ± std) | Test macro-F1 | Test weighted-F1 | Test accuracy | Test balanced acc. | Test ROC-AUC (OvR macro) | Benign FPR (test) |
|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.747 ± 0.030 | 0.716 | 0.749 | 0.738 | 0.738 | 0.909 | 25.0 % |
| **Random Forest** | 0.797 ± 0.011 | 0.755 | 0.782 | 0.786 | 0.746 | 0.909 | 10.0 % |
| XGBoost | 0.788 ± 0.024 | 0.753 | 0.783 | 0.786 | 0.746 | 0.913 | 10.0 % |

Best model (by CV macro-F1, chosen before looking at test): **Random Forest**. Test split: 42 pages, evaluated once. Benign FPR target: ≤ 2 % (benign test pages predicted as any threat).

CV details (mean ± std over folds):

| Model | weighted-F1 | accuracy | balanced acc. | ROC-AUC | F1 benign | F1 phishing | F1 malware_delivery |
|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.768 ± 0.030 | 0.763 ± 0.031 | 0.765 ± 0.029 | 0.901 ± 0.032 | 0.817 ± 0.050 | 0.782 ± 0.044 | 0.643 ± 0.045 |
| Random Forest | 0.813 ± 0.019 | 0.818 ± 0.021 | 0.791 ± 0.008 | 0.934 ± 0.012 | 0.846 ± 0.045 | 0.836 ± 0.049 | 0.709 ± 0.055 |
| XGBoost | 0.804 ± 0.025 | 0.805 ± 0.027 | 0.790 ± 0.023 | 0.931 ± 0.021 | 0.838 ± 0.028 | 0.821 ± 0.036 | 0.704 ± 0.043 |

## Split

| split | pages | share | benign | phishing | malware_delivery |
|---|---|---|---|---|---|
| train | 194 | 69.8 % | 92 | 60 | 42 |
| val | 42 | 15.1 % | 20 | 13 | 9 |
| test | 42 | 15.1 % | 20 | 14 | 8 |

Target 70/15/15, largest deviation 0.22 %. Stratified by label × language, grouped by near-duplicate cluster (0 clusters in two splits). Seed 42, 5 grouped CV folds over train+val. Sinhala/Tamil placement: si: train 6 / val 2 / test 1, ta: train 1 / val 1 / test 1.

Split fingerprint `65b6b526faac46ba…` (shared by every later part).

## Features

52 dictionary features → **47 used**. Dropped (decided on the TRAIN split only):

| feature | reason | detail |
|---|---|---|
| `base_url_known` | constant | always 1 |
| `meta_refresh_external` | constant | always 0 |
| `element_count` | correlated | |r| = 0.9934 with node_count (kept, earlier in dictionary) |
| `has_external_form_action` | correlated | |r| = 1.0000 with external_form_action_count (kept, earlier in dictionary) |
| `form_action_to_known_form_service` | correlated | |r| = 1.0000 with password_form_external_action (kept, earlier in dictionary) |

## Per-class test results

**Logistic Regression**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.938 | 0.750 | 0.833 | 20 |
| phishing | 0.714 | 0.714 | 0.714 | 14 |
| malware_delivery | 0.500 | 0.750 | 0.600 | 8 |

**Random Forest**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.818 | 0.900 | 0.857 | 20 |
| phishing | 0.769 | 0.714 | 0.741 | 14 |
| malware_delivery | 0.714 | 0.625 | 0.667 | 8 |

**XGBoost**

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.857 | 0.900 | 0.878 | 20 |
| phishing | 0.714 | 0.714 | 0.714 | 14 |
| malware_delivery | 0.714 | 0.625 | 0.667 | 8 |

## Confusion matrix - Random Forest (test)

```
true \ predicted                  benign          phishing  malware_delivery
benign                                18                 1                 1
phishing                               3                10                 1
malware_delivery                       1                 2                 5
```

Figures: `figures/confusion_logreg.png`, `figures/confusion_random_forest.png`, `figures/confusion_xgboost.png`

## Benign false positives (test)

- Logistic Regression: 25.0 % - c2_benign_000016, c2_benign_000040, c2_benign_000059, c2_benign_000061, c2_benign_000062
- Random Forest: 10.0 % - c2_benign_000040, c2_benign_000062
- XGBoost: 10.0 % - c2_benign_000040, c2_benign_000062

## Per language - Random Forest (test)

| language | pages | accuracy | macro-F1 (classes present) | benign FPR | classes | note |
|---|---|---|---|---|---|---|
| en | 39 | 0.795 | 0.767 | 11.1 % | benign 18, phishing 13, malware_delivery 8 |  |
| si | 1 | 1.000 | 1.000 | 0.0 % | benign 1 | small n - anecdotal |
| ta | 1 | 1.000 | 1.000 | 0.0 % | benign 1 | small n - anecdotal |
| unknown | 1 | 0.000 | 0.000 | — | phishing 1 | small n - anecdotal |

## Feature importance

> Permutation importance and SHAP are computed on a small pilot test split; the rankings are indicative only (a few pages can reorder them).

**XGBoost - global SHAP (mean |SHAP| on test, all classes)**

| # | feature | mean |SHAP| | benign | phishing | malware_delivery |
|---|---|---|---|---|---|
| 1 | Web links to the page's own registrable domai... [internal_link_count] | 2.283 | 1.927 | 0.230 | 0.126 |
| 2 | Share of elements with no child elements [leaf_ratio] | 1.337 | 0.163 | 0.641 | 0.533 |
| 3 | Null links divided by all links [null_link_ratio] | 1.273 | 0.134 | 1.023 | 0.115 |
| 4 | Elements plus non-empty text nodes [node_count] | 1.016 | 0.103 | 0.298 | 0.616 |
| 5 | Number of <a href> links [link_count] | 0.800 | 0.139 | 0.504 | 0.156 |
| 6 | External web links divided by all web links (... [external_link_ratio] | 0.707 | 0.143 | 0.553 | 0.012 |
| 7 | All input/select/textarea fields, inside or o... [inputs_total] | 0.703 | 0.194 | 0.454 | 0.055 |
| 8 | Average nesting level of all elements - how "... [avg_depth] | 0.586 | 0.401 | 0.135 | 0.050 |
| 9 | Total characters of inline JavaScript [inline_script_chars_total] | 0.584 | 0.338 | 0.093 | 0.153 |
| 10 | Characters in the title [title_length] | 0.566 | 0.319 | 0.021 | 0.225 |
| 11 | Number of inline <script> blocks with code (J... [inline_script_count] | 0.565 | 0.095 | 0.289 | 0.181 |
| 12 | Web links to other domains [external_link_count] | 0.551 | 0.366 | 0.110 | 0.075 |
| 13 | Visible characters divided by HTML bytes [text_to_html_ratio] | 0.541 | 0.062 | 0.158 | 0.321 |
| 14 | Number of <script src> references [external_script_count] | 0.471 | 0.066 | 0.006 | 0.399 |
| 15 | Number of different tag names [distinct_tag_count] | 0.376 | 0.157 | 0.101 | 0.119 |

**XGBoost - gain**

| # | feature | value |
|---|---|---|
| 1 | Fields asking for an e-mail address (type, au... [email_field_count] | 2.790 |
| 2 | Number of <script src> references [external_script_count] | 2.548 |
| 3 | A form submits to a bare IP address instead o... [form_action_to_ip] | 2.496 |
| 4 | Web links to the page's own registrable domai... [internal_link_count] | 1.952 |
| 5 | Null links divided by all links [null_link_ratio] | 1.301 |
| 6 | Number of <form> elements [form_count] | 0.981 |
| 7 | Fields for secrets that a scammer can use dir... [sensitive_field_count] | 0.848 |
| 8 | Fields not inside any form - typical of kits... [inputs_outside_forms_count] | 0.811 |
| 9 | Password fields (type=password or a password... [password_field_count] | 0.754 |
| 10 | Number of <a href> links [link_count] | 0.669 |
| 11 | Share of elements with no child elements [leaf_ratio] | 0.660 |
| 12 | Elements plus non-empty text nodes [node_count] | 0.629 |
| 13 | Number of different tag names [distinct_tag_count] | 0.625 |
| 14 | Inputs of type=hidden or hidden by attribute/... [hidden_input_count] | 0.622 |
| 15 | Number of different domains that links point to [distinct_external_domains] | 0.453 |

**Random Forest - permutation importance on test (macro-F1 drop)**

| # | feature | drop | std |
|---|---|---|---|
| 1 | Web links to the page's own registrable domai... [internal_link_count] | 0.150 | 0.049 |
| 2 | Number of <script src> references [external_script_count] | 0.046 | 0.041 |
| 3 | Elements hidden by their own markup (hidden a... [hidden_element_count] | 0.044 | 0.032 |
| 4 | Elements plus non-empty text nodes [node_count] | 0.042 | 0.033 |
| 5 | Characters in the title [title_length] | 0.039 | 0.001 |
| 6 | Number of different tag names [distinct_tag_count] | 0.039 | 0.009 |
| 7 | Web links to other domains [external_link_count] | 0.035 | 0.012 |
| 8 | Characters of text inside hidden elements [hidden_text_chars] | 0.033 | 0.032 |
| 9 | Number of <a href> links [link_count] | 0.033 | 0.009 |
| 10 | Number of different domains that links point to [distinct_external_domains] | 0.033 | 0.014 |
| 11 | Deepest nesting level (html = 1) [max_depth] | 0.032 | 0.016 |
| 12 | All input/select/textarea fields, inside or o... [inputs_total] | 0.031 | 0.035 |
| 13 | Number of inline <script> blocks with code (J... [inline_script_count] | 0.029 | 0.017 |
| 14 | Hidden text divided by all text (hidden + vis... [hidden_text_ratio] | 0.022 | 0.020 |
| 15 | Distinct other domains that scripts are loade... [external_script_domain_count] | 0.020 | 0.020 |

**Random Forest - impurity importance**

| # | feature | value |
|---|---|---|
| 1 | Web links to the page's own registrable domai... [internal_link_count] | 0.192 |
| 2 | Number of <a href> links [link_count] | 0.095 |
| 3 | Elements plus non-empty text nodes [node_count] | 0.072 |
| 4 | Share of elements with no child elements [leaf_ratio] | 0.061 |
| 5 | Number of <script src> references [external_script_count] | 0.053 |
| 6 | Null links divided by all links [null_link_ratio] | 0.049 |
| 7 | Total characters of inline JavaScript [inline_script_chars_total] | 0.042 |
| 8 | Number of different tag names [distinct_tag_count] | 0.042 |
| 9 | All input/select/textarea fields, inside or o... [inputs_total] | 0.037 |
| 10 | Average nesting level of all elements - how "... [avg_depth] | 0.030 |
| 11 | Visible characters divided by HTML bytes [text_to_html_ratio] | 0.029 |
| 12 | Characters in the title [title_length] | 0.028 |
| 13 | Elements hidden by their own markup (hidden a... [hidden_element_count] | 0.026 |
| 14 | Number of different domains that links point to [distinct_external_domains] | 0.023 |
| 15 | Number of inline <script> blocks with code (J... [inline_script_count] | 0.019 |

**Logistic Regression - standardized coefficients (top 5 per class)**

| class | feature | coefficient |
|---|---|---|
| benign | Web links to the page's own registrable domai... [internal_link_count] | +0.524 |
| benign | Number of different domains that links point to [distinct_external_domains] | +0.348 |
| benign | Null links divided by all links [null_link_ratio] | -0.343 |
| benign | A form submits to a bare IP address instead o... [form_action_to_ip] | -0.288 |
| benign | Frames that are invisible (zero size or hidde... [hidden_iframe_count] | +0.285 |
| phishing | Null links divided by all links [null_link_ratio] | +0.606 |
| phishing | Web links to the page's own registrable domai... [internal_link_count] | -0.362 |
| phishing | Fields not inside any form - typical of kits... [inputs_outside_forms_count] | +0.315 |
| phishing | Total characters of inline JavaScript [inline_script_chars_total] | -0.314 |
| phishing | The page asks for a password [has_password_field] | +0.299 |
| malware_delivery | A form submits to a bare IP address instead o... [form_action_to_ip] | +0.399 |
| malware_delivery | Hidden text divided by all text (hidden + vis... [hidden_text_ratio] | -0.394 |
| malware_delivery | Share of elements with no child elements [leaf_ratio] | -0.325 |
| malware_delivery | Elements plus non-empty text nodes [node_count] | -0.288 |
| malware_delivery | Frames that are invisible (zero size or hidde... [hidden_iframe_count] | -0.265 |

Figures: `figures/importance_*.png`, `figures/shap_global_xgboost.png`, `figures/shap_beeswarm_<class>.png`.

## Misclassified test pages

- Logistic Regression: 11 of 42
- Random Forest: 9 of 42
- XGBoost: 9 of 42

`misclassified.csv` lists them (sample_id, true, predicted, probabilities). In the inspector tick **misclassified (test)** to browse them.

## Chosen hyperparameters

- Logistic Regression: max_iter=5000, class_weight=balanced, C=0.1 (4 grid points)
- Random Forest: n_estimators=300, class_weight=balanced_subsample, max_depth=None, max_features=0.5, min_samples_leaf=1 (8 grid points)
- XGBoost: n_estimators=300, tree_method=hist, objective=multi:softprob, eval_metric=mlogloss, learning_rate=0.1, max_depth=6, subsample=1.0 (8 grid points)

## Reproduce

```bash
python scripts/train_dom_baseline.py all --version v0.1
```

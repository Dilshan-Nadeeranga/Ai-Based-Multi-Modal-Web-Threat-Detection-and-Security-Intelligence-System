# Ablation so far - v0.3 (same test pages, macro-F1 primary)

| arm | model | CV / seed mean ± std | test macro-F1 | benign FPR | n test | F1 benign | F1 phishing | F1 fake_ecommerce | F1 crypto_scam | F1 malware_delivery |
|---|---|---|---|---|---|---|---|---|---|---|
| DOM-only | Random Forest | CV 0.701 ± 0.077 | **0.786** | 17.6 % | 68 | 0.889 | 0.750 | 1.000 | 0.667 | 0.625 |
| Behavior-only | Random Forest | CV 0.620 ± 0.078 | **0.682** | 20.6 % | 68 | 0.806 | 0.720 | 0.933 | 0.286 | 0.667 |
| Text TF-IDF | TF-IDF char 2-5 + LogReg | CV 0.706 ± 0.065 | **0.718** | 5.9 % | 68 | 0.877 | 0.815 | 0.933 | 0.600 | 0.364 |
| Text XLM-R | XLM-R (fine-tuned) - final (seed 43) | 3-seed test 0.610 ± 0.062 | **0.657** | 23.5 % | 68 | 0.788 | 0.640 | 0.700 | 0.727 | 0.429 |

CV = grouped 5-fold over train+val (DOM, Behavior, TF-IDF; best model by CV). XLM-R = mean ± std of the test macro-F1 over its seeds; its 'test macro-F1' is the final model (seed chosen on val).

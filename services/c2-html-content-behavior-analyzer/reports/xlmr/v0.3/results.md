# text (XLM-R) - v0.3

- created: 2026-10-16T21:23:01+05:30
- split fingerprint: `7d9ae69bbae3f5c699c022eb4ef74334ac49c4e95d68f30f9d480c9e55324f4f` (train/val/test = {'train': 322, 'val': 69, 'test': 68})
- input: Part 5A page_text (text_v1, rules `2df7c7ad4a84`)
- selection: seed with the highest VAL macro-F1 (ties: lower seed); test never used

## Test results (evaluated once)

| model | selection score | macro-P | macro-R | macro-F1 | weighted-F1 | accuracy | benign FPR | ROC-AUC OvR |
|---|---|---|---|---|---|---|---|---|
| XLM-R (fine-tuned) - final (seed 43) | val 0.736 | 0.647 | 0.718 | **0.657** | 0.698 | 0.706 | 23.5 % | 0.922 |
| XLM-R (fine-tuned) - seed 42 | val 0.674 | 0.513 | 0.617 | **0.523** | 0.551 | 0.559 | 52.9 % | 0.885 |
| XLM-R (fine-tuned) - seed 43 | val 0.736 | 0.647 | 0.718 | **0.657** | 0.698 | 0.706 | 23.5 % | 0.922 |
| XLM-R (fine-tuned) - seed 44 | val 0.731 | 0.648 | 0.677 | **0.651** | 0.738 | 0.735 | 20.6 % | 0.934 |
| mean ± std over 3 seeds (val) |  | 0.741 ± 0.036 | 0.732 ± 0.014 | **0.714 ± 0.028** | 0.729 ± 0.041 | 0.725 ± 0.041 | 29.4 ± 10.5 % | 0.928 ± 0.016 |
| mean ± std over 3 seeds (test) |  | 0.603 ± 0.063 | 0.671 ± 0.041 | **0.610 ± 0.062** | 0.662 ± 0.080 | 0.667 ± 0.077 | 32.4 ± 14.6 % | 0.914 ± 0.021 |

## Per class - XLM-R (fine-tuned) - final (seed 43) (test)

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.812 | 0.765 | 0.788 | 34 |
| phishing | 0.667 | 0.615 | 0.640 | 13 |
| fake_ecommerce | 0.583 | 0.875 | 0.700 | 8 |
| crypto_scam | 0.571 | 1.000 | 0.727 | 4 |
| malware_delivery | 0.600 | 0.333 | 0.429 | 9 |

## Per language (test; Part 5A detected language)

| language | n | macro-P | macro-R | macro-F1 | accuracy | benign FPR | labels |
|---|---|---|---|---|---|---|---|
| en | 51 | 0.634 | 0.709 | 0.653 | 0.706 | 24.0 % | benign 25, phishing 12, fake_ecommerce 5, crypto_scam 4, malware_delivery 5 |
| si ⚠ small n | 1 | 1.000 | 1.000 | 1.000 | 1.000 | 0.0 % | benign 1 |
| ta ⚠ small n | 1 | 1.000 | 1.000 | 1.000 | 1.000 | 0.0 % | benign 1 |
| mixed ⚠ small n | 1 | 0.000 | 0.000 | 0.000 | 0.000 | — | malware_delivery 1 |
| other | 14 | 0.733 | 0.762 | 0.671 | 0.714 | 28.6 % | benign 7, phishing 1, fake_ecommerce 3, malware_delivery 3 |

Per-language macro scores average over the classes present in that language; with fewer test pages than the small-n limit they are anecdotes, not estimates.

## Confusion matrix (test, rows = true)

```
true \ predicted                  benign          phishing    fake_ecommerce       crypto_scam  malware_delivery
benign                                26                 2                 5                 0                 1
phishing                               2                 8                 0                 2                 1
fake_ecommerce                         0                 0                 7                 1                 0
crypto_scam                            0                 0                 0                 4                 0
malware_delivery                       4                 2                 0                 0                 3
```

Benign test pages flagged as a threat: 8 (c2_benign_000024, c2_benign_000025, c2_benign_000040, c2_benign_000062, c2_benign_000187, c2_benign_000198, c2_benign_000208, c2_benign_000233)

## Colab vs local CPU (final model)

- max |Δ probability| = 0.001632, argmax agreement 100.0 % over 137 pages (tolerance 0.001) → CHECK

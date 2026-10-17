# text (TF-IDF) - v0.3

- created: 2026-10-16T20:04:02+05:30
- split fingerprint: `7d9ae69bbae3f5c699c022eb4ef74334ac49c4e95d68f30f9d480c9e55324f4f` (train/val/test = {'train': 322, 'val': 69, 'test': 68})
- input: Part 5A page_text (text_v1, rules `2df7c7ad4a84`)
- selection: C by mean macro-F1 over the shared grouped CV folds (train+val); test never used

## Test results (evaluated once)

| model | selection score | macro-P | macro-R | macro-F1 | weighted-F1 | accuracy | benign FPR | ROC-AUC OvR |
|---|---|---|---|---|---|---|---|---|
| TF-IDF char 2-5 + LogReg | CV 0.706 ± 0.065 | 0.821 | 0.727 | **0.718** | 0.787 | 0.809 | 5.9 % | 0.962 |

## Per class - TF-IDF char 2-5 + LogReg (test)

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.821 | 0.941 | 0.877 | 34 |
| phishing | 0.786 | 0.846 | 0.815 | 13 |
| fake_ecommerce | 1.000 | 0.875 | 0.933 | 8 |
| crypto_scam | 0.500 | 0.750 | 0.600 | 4 |
| malware_delivery | 1.000 | 0.222 | 0.364 | 9 |

## Per language (test; Part 5A detected language)

| language | n | macro-P | macro-R | macro-F1 | accuracy | benign FPR | labels |
|---|---|---|---|---|---|---|---|
| en | 51 | 0.874 | 0.757 | 0.784 | 0.863 | 0.0 % | benign 25, phishing 12, fake_ecommerce 5, crypto_scam 4, malware_delivery 5 |
| si ⚠ small n | 1 | 1.000 | 1.000 | 1.000 | 1.000 | 0.0 % | benign 1 |
| ta ⚠ small n | 1 | 1.000 | 1.000 | 1.000 | 1.000 | 0.0 % | benign 1 |
| mixed ⚠ small n | 1 | 0.000 | 0.000 | 0.000 | 0.000 | — | malware_delivery 1 |
| other | 14 | 0.512 | 0.679 | 0.554 | 0.643 | 28.6 % | benign 7, phishing 1, fake_ecommerce 3, malware_delivery 3 |

Per-language macro scores average over the classes present in that language; with fewer test pages than the small-n limit they are anecdotes, not estimates.

## Confusion matrix (test, rows = true)

```
true \ predicted                  benign          phishing    fake_ecommerce       crypto_scam  malware_delivery
benign                                32                 2                 0                 0                 0
phishing                               1                11                 0                 1                 0
fake_ecommerce                         0                 0                 7                 1                 0
crypto_scam                            1                 0                 0                 3                 0
malware_delivery                       5                 1                 0                 1                 2
```

Benign test pages flagged as a threat: 2 (c2_benign_000003, c2_benign_000076)

## Strongest character n-grams per class (LR coefficients)

| class | n-grams |
|---|---|
| benign | `nka` · `anka` · `lank` · `lanka` · ` lank` · `sri` · `sr` · `sri ` · ` sri` · ` sri ` |
| phishing | ` ws` · `swor` · `swo` · `passw` · `asswo` · `sswo` · `sswor` · `assw` · `sword` · ` pass` |
| fake_ecommerce | `” ` · ` “` · ` “ ` · ` ”` · ` ” ` · `“ ` · `.”` · `.” ` · `shop` · `hop` |
| crypto_scam | `trad` · `ypto` · `rypto` · ` cryp` · `radin` · `coin` · `coi` · `coin ` · ` web3` · `web3` |
| malware_delivery | `soon ` · `herd` · `yh` · `yhe` · ` soon` · ` soo` · `soon` · `soo` · `oon ` · `rey` |

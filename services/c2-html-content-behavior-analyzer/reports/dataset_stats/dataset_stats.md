# C2 dataset statistics

- Generated: 2026-10-14T22:46:17+05:30
- Dataset version: **unfrozen** (latest frozen: v0.2)
- **all** view: every row in metadata.csv
- **usable** view: not excluded AND quality_flag in (ok, redirected_offsite)
- **clean** view: usable AND is_duplicate_of is empty (one row per cluster) - used for training

## Samples per label and view

| view | total | benign | phishing | fake_ecommerce | crypto_scam | malware_delivery |
|---|---|---|---|---|---|---|
| all | 567 | 235 | 132 | 60 | 39 | 101 |
| usable | 496 | 228 | 115 | 57 | 29 | 67 |
| clean | 459 | 227 | 87 | 57 | 29 | 59 |

## Readiness (clean view vs configs/collection_targets.yaml)

| label | clean / target | si / target | ta / target | status |
|---|---|---|---|---|
| benign | 227/50 | 10/20 | 4/0 | 10 more si needed |
| phishing | 87/50 | 0/20 | 0/0 | 20 more si needed |
| fake_ecommerce | 57/50 | 0/20 | 0/0 | 20 more si needed |
| crypto_scam | 29/50 | 0/20 | 0/0 | 21 more needed, 20 more si needed |
| malware_delivery | 59/50 | 0/0 | 0/0 | ready |

Local-language coverage (clean): Sinhala 10 (2.2%), Tamil 4 (0.9%); mixed-language pages: 0.

## Label x language (clean view)

| label | en | si | ta | mixed | unknown | total |
|---|---|---|---|---|---|---|
| benign | 208 | 10 | 4 | 0 | 5 | 227 |
| phishing | 83 | 0 | 0 | 0 | 4 | 87 |
| fake_ecommerce | 57 | 0 | 0 | 0 | 0 | 57 |
| crypto_scam | 22 | 0 | 0 | 0 | 7 | 29 |
| malware_delivery | 57 | 0 | 0 | 0 | 2 | 59 |
| **total** | 427 | 10 | 4 | 0 | 18 | 459 |

## Class balance (clean view)

| label | samples | % of total |
|---|---|---|
| benign | 227 | 49.5 |
| phishing | 87 | 19.0 |
| fake_ecommerce | 57 | 12.4 |
| crypto_scam | 29 | 6.3 |
| malware_delivery | 59 | 12.9 |

Majority/minority ratio: **7.83** (majority benign, minority crypto_scam).

## Verification (clean view)

| label | verified | unverified | % verified |
|---|---|---|---|
| benign | 155 | 72 | 68.3 |
| phishing | 87 | 0 | 100.0 |
| fake_ecommerce | 57 | 0 | 100.0 |
| crypto_scam | 29 | 0 | 100.0 |
| malware_delivery | 59 | 0 | 100.0 |

## Page statistics (clean view)

| label | pages | size median | size p90 | text chars median | text chars p90 | forms (mean) | % password field | % script |
|---|---|---|---|---|---|---|---|---|
| benign | 227 | 236.6 KB | 948.0 KB | 5,956 | 16,877 | 2.77 | 5.3 | 97.4 |
| phishing | 87 | 33.3 KB | 260.4 KB | 776 | 6,544 | 0.74 | 32.2 | 92.0 |
| fake_ecommerce | 57 | 270.0 KB | 406.4 KB | 2,093 | 10,082 | 2.23 | 7.0 | 100.0 |
| crypto_scam | 29 | 40.0 KB | 129.1 KB | 3,358 | 9,285 | 0.45 | 3.4 | 100.0 |
| malware_delivery | 59 | 122.1 KB | 180.9 KB | 189 | 5,943 | 0.69 | 5.1 | 79.7 |

## Quality flags and exclusions (all view)

| quality_flag | samples | usable? |
|---|---|---|
| ok | 467 | yes |
| empty | 46 | no |
| parked_domain | 4 | no |
| error_page | 14 | no |
| bot_challenge | 5 | no |
| login_wall | 1 | no |
| suspended_hosting | 1 | no |
| redirected_offsite | 29 | yes |

No samples excluded yet.

## Sources and fetch modes

| source | all | usable | clean |
|---|---|---|---|
| openphish | 132 | 115 | 87 |
| urlhaus | 101 | 67 | 59 |
| tranco | 99 | 96 | 96 |
| manual | 62 | 60 | 59 |
| other | 173 | 158 | 158 |

| fetch_mode | all | usable | clean |
|---|---|---|---|
| static | 567 | 496 | 459 |
| rendered | 0 | 0 | 0 |
| manual | 0 | 0 | 0 |

## Near-duplicate clusters

| view | clusters | with 2+ pages | rows without cluster |
|---|---|---|---|
| all | 529 | 21 | 0 |
| usable | 458 | 21 | 0 |
| clean | 458 | 1 | 0 |

Duplicates per label (all view): benign 1, phishing 28, fake_ecommerce 0, crypto_scam 0, malware_delivery 8

Largest clusters (all view):

| cluster_id | label | size |
|---|---|---|
| cl_000429 | phishing | 11 |
| cl_000443 | phishing | 5 |
| cl_000376 | malware_delivery | 4 |
| cl_000333 | malware_delivery | 3 |
| cl_000347 | malware_delivery | 3 |
| cl_000471 | phishing | 3 |
| cl_000125 | benign | 2 |
| cl_000181 | benign+fake_ecommerce | 2 |
| cl_000351 | malware_delivery | 2 |
| cl_000426 | phishing | 2 |

## Relabels during review (all view)

No samples relabelled yet.

## Collection timeline (all view)

| collection_date | benign | phishing | fake_ecommerce | crypto_scam | malware_delivery | total |
|---|---|---|---|---|---|---|
| 2026-10-12 | 138 | 132 | 0 | 2 | 101 | 373 |
| 2026-10-14 | 97 | 0 | 60 | 37 | 0 | 194 |

## Peer agreement

Not done yet (review_labels.py export-peer / import-peer).

## Figures

![label_distribution](figures/label_distribution.png)
![label_language_heatmap](figures/label_language_heatmap.png)
![quality_flags](figures/quality_flags.png)
![text_length_by_label](figures/text_length_by_label.png)
![collection_timeline](figures/collection_timeline.png)
![verification_progress](figures/verification_progress.png)

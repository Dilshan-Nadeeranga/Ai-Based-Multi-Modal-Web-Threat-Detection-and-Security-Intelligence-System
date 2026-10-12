# C2 dataset statistics

- Generated: 2026-10-12T21:25:14+05:30
- Dataset version: **unfrozen** (latest frozen: none)
- **all** view: every row in metadata.csv
- **usable** view: not excluded AND quality_flag in (ok, redirected_offsite)
- **clean** view: usable AND is_duplicate_of is empty (one row per cluster) - used for training

## Samples per label and view

| view | total | benign | phishing | fake_ecommerce | crypto_scam | malware_delivery |
|---|---|---|---|---|---|---|
| all | 373 | 138 | 132 | 0 | 2 | 101 |
| usable | 315 | 133 | 115 | 0 | 0 | 67 |
| clean | 278 | 132 | 87 | 0 | 0 | 59 |

## Readiness (clean view vs configs/collection_targets.yaml)

| label | clean / target | si / target | ta / target | status |
|---|---|---|---|---|
| benign | 132/50 | 9/20 | 3/0 | 11 more si needed |
| phishing | 87/50 | 0/20 | 0/0 | 20 more si needed |
| fake_ecommerce | 0/50 | 0/20 | 0/0 | 50 more needed, 20 more si needed |
| crypto_scam | 0/50 | 0/20 | 0/0 | 50 more needed, 20 more si needed |
| malware_delivery | 59/50 | 0/0 | 0/0 | ready |

Local-language coverage (clean): Sinhala 9 (3.2%), Tamil 3 (1.1%); mixed-language pages: 0.

## Label x language (clean view)

| label | en | si | ta | mixed | unknown | total |
|---|---|---|---|---|---|---|
| benign | 115 | 9 | 3 | 0 | 5 | 132 |
| phishing | 83 | 0 | 0 | 0 | 4 | 87 |
| fake_ecommerce | 0 | 0 | 0 | 0 | 0 | 0 |
| crypto_scam | 0 | 0 | 0 | 0 | 0 | 0 |
| malware_delivery | 57 | 0 | 0 | 0 | 2 | 59 |
| **total** | 255 | 9 | 3 | 0 | 11 | 278 |

## Class balance (clean view)

| label | samples | % of total |
|---|---|---|
| benign | 132 | 47.5 |
| phishing | 87 | 31.3 |
| fake_ecommerce | 0 | 0.0 |
| crypto_scam | 0 | 0.0 |
| malware_delivery | 59 | 21.2 |

Majority/minority ratio: **undefined (a class has no samples)** (majority benign, minority fake_ecommerce).

## Verification (clean view)

| label | verified | unverified | % verified |
|---|---|---|---|
| benign | 132 | 0 | 100.0 |
| phishing | 87 | 0 | 100.0 |
| fake_ecommerce | 0 | 0 | 0.0 |
| crypto_scam | 0 | 0 | 0.0 |
| malware_delivery | 59 | 0 | 100.0 |

## Page statistics (clean view)

| label | pages | size median | size p90 | text chars median | text chars p90 | forms (mean) | % password field | % script |
|---|---|---|---|---|---|---|---|---|
| benign | 132 | 215.9 KB | 904.6 KB | 5,414 | 18,236 | 1.39 | 3.0 | 97.0 |
| phishing | 87 | 33.3 KB | 260.4 KB | 776 | 6,544 | 0.74 | 32.2 | 92.0 |
| fake_ecommerce | 0 | - | - | - | - | - | 0.0 | 0.0 |
| crypto_scam | 0 | - | - | - | - | - | 0.0 | 0.0 |
| malware_delivery | 59 | 122.1 KB | 180.9 KB | 189 | 5,943 | 0.69 | 5.1 | 79.7 |

## Quality flags and exclusions (all view)

| quality_flag | samples | usable? |
|---|---|---|
| ok | 289 | yes |
| empty | 38 | no |
| parked_domain | 3 | no |
| error_page | 12 | no |
| bot_challenge | 4 | no |
| suspended_hosting | 1 | no |
| redirected_offsite | 26 | yes |

No samples excluded yet.

## Sources and fetch modes

| source | all | usable | clean |
|---|---|---|---|
| openphish | 132 | 115 | 87 |
| urlhaus | 101 | 67 | 59 |
| tranco | 99 | 96 | 96 |
| manual | 39 | 37 | 36 |
| other | 2 | 0 | 0 |

| fetch_mode | all | usable | clean |
|---|---|---|---|
| static | 373 | 315 | 278 |
| rendered | 0 | 0 | 0 |
| manual | 0 | 0 | 0 |

## Near-duplicate clusters

| view | clusters | with 2+ pages | rows without cluster |
|---|---|---|---|
| all | 336 | 20 | 0 |
| usable | 278 | 20 | 0 |
| clean | 278 | 0 | 0 |

Duplicates per label (all view): benign 1, phishing 28, fake_ecommerce 0, crypto_scam 0, malware_delivery 8

Largest clusters (all view):

| cluster_id | label | size |
|---|---|---|
| cl_000236 | phishing | 11 |
| cl_000250 | phishing | 5 |
| cl_000183 | malware_delivery | 4 |
| cl_000140 | malware_delivery | 3 |
| cl_000154 | malware_delivery | 3 |
| cl_000278 | phishing | 3 |
| cl_000125 | benign | 2 |
| cl_000158 | malware_delivery | 2 |
| cl_000233 | phishing | 2 |
| cl_000245 | phishing | 2 |

## Relabels during review (all view)

No samples relabelled yet.

## Collection timeline (all view)

| collection_date | benign | phishing | fake_ecommerce | crypto_scam | malware_delivery | total |
|---|---|---|---|---|---|---|
| 2026-10-12 | 138 | 132 | 0 | 2 | 101 | 373 |

## Peer agreement

Not done yet (review_labels.py export-peer / import-peer).

## Figures

![label_distribution](figures/label_distribution.png)
![label_language_heatmap](figures/label_language_heatmap.png)
![quality_flags](figures/quality_flags.png)
![text_length_by_label](figures/text_length_by_label.png)
![collection_timeline](figures/collection_timeline.png)
![verification_progress](figures/verification_progress.png)

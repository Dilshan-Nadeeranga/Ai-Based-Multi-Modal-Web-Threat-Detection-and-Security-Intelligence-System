# Scam-text corpus statistics (corpus_v1)

Dataset version: v0.3 | taxonomy: intent_v1 | built: 2026-10-15T23:01:52+05:30 | language backend: fasttext

Rows: 7330 (active 7330, excluded by review 0). Counts below are ACTIVE rows; intent = primary_intent.

**Research integrity:** synthetic templates and machine translations are train-only augmentation; validation / test contain only real text.

## Integrity checks: PASSED

- synthetic / MT rows in val or test: 0 (must be 0)
- near-identical texts in more than one split: 0 (must be 0)
- groups in more than one split: 0 (must be 0)

## Synthetic share per split

| split | rows | synthetic | share |
|---|---|---|---|
| train | 4832 | 120 | 2.48 % |
| val | 1215 | 0 | 0.0 % |
| test | 1283 | 0 | 0.0 % |

## Language x intent (all sources)

| language | credential_request | payment_request | investment_lure | fake_security_warning | fake_reward | urgency_threat | impersonation | benign | total |
|---|---|---|---|---|---|---|---|---|---|
| en | 19 | 0 | 10 | 7 | 16 | 20 | 0 | 5141 | 5213 |
| si | 12 | 0 | 4 | 4 | 12 | 8 | 0 | 176 | 216 |
| ta | 12 | 0 | 4 | 4 | 12 | 8 | 0 | 69 | 109 |
| mixed | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 97 | 97 |
| other | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1695 | 1695 |
| **total** | 43 | 0 | 18 | 15 | 40 | 36 | 0 | 7178 | 7330 |

## Source x split

| source | train | val | test | total |
|---|---|---|---|---|
| page_segment | 4712 | 1215 | 1283 | 7210 |
| real_message | 0 | 0 | 0 | 0 |
| synthetic_template | 120 | 0 | 0 | 120 |
| machine_translation | 0 | 0 | 0 | 0 |
| **total** | 4832 | 1215 | 1283 | 7330 |

## Language x split

| language | train | val | test | total |
|---|---|---|---|---|
| en | 3458 | 780 | 975 | 5213 |
| si | 133 | 54 | 29 | 216 |
| ta | 60 | 29 | 20 | 109 |
| mixed | 79 | 13 | 5 | 97 |
| other | 1102 | 339 | 254 | 1695 |
| **total** | 4832 | 1215 | 1283 | 7330 |

## Intent x split

| intent | train | val | test | total |
|---|---|---|---|---|
| credential_request | 38 | 0 | 5 | 43 |
| payment_request | 0 | 0 | 0 | 0 |
| investment_lure | 16 | 2 | 0 | 18 |
| fake_security_warning | 13 | 0 | 2 | 15 |
| fake_reward | 38 | 2 | 0 | 40 |
| urgency_threat | 35 | 1 | 0 | 36 |
| impersonation | 0 | 0 | 0 | 0 |
| benign | 4692 | 1210 | 1276 | 7178 |
| **total** | 4832 | 1215 | 1283 | 7330 |

## Language x intent: page_segment (7210 rows)

| language | credential_request | payment_request | investment_lure | fake_security_warning | fake_reward | urgency_threat | impersonation | benign | total |
|---|---|---|---|---|---|---|---|---|---|
| en | 7 | 0 | 6 | 3 | 4 | 12 | 0 | 5141 | 5173 |
| si | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 176 | 176 |
| ta | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 69 | 69 |
| mixed | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 97 | 97 |
| other | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1695 | 1695 |
| **total** | 7 | 0 | 6 | 3 | 4 | 12 | 0 | 7178 | 7210 |

## Language x intent: synthetic_template (120 rows)

| language | credential_request | payment_request | investment_lure | fake_security_warning | fake_reward | urgency_threat | impersonation | benign | total |
|---|---|---|---|---|---|---|---|---|---|
| en | 12 | 0 | 4 | 4 | 12 | 8 | 0 | 0 | 40 |
| si | 12 | 0 | 4 | 4 | 12 | 8 | 0 | 0 | 40 |
| ta | 12 | 0 | 4 | 4 | 12 | 8 | 0 | 0 | 40 |
| mixed | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| other | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **total** | 36 | 0 | 12 | 12 | 36 | 24 | 0 | 0 | 120 |

## Real Sinhala / Tamil text in val + test vs target

**si** (target 30 per intent): 0 of 7 scam intents met, total gap 210 rows.

| intent | page segments | real messages | total | target | gap |
|---|---|---|---|---|---|
| credential_request | 0 | 0 | 0 | 30 | 30 |
| payment_request | 0 | 0 | 0 | 30 | 30 |
| investment_lure | 0 | 0 | 0 | 30 | 30 |
| fake_security_warning | 0 | 0 | 0 | 30 | 30 |
| fake_reward | 0 | 0 | 0 | 30 | 30 |
| urgency_threat | 0 | 0 | 0 | 30 | 30 |
| impersonation | 0 | 0 | 0 | 30 | 30 |
| benign | 83 | 0 | 83 | 30 | 0 |

**ta** (target 15 per intent): 0 of 7 scam intents met, total gap 105 rows.

| intent | page segments | real messages | total | target | gap |
|---|---|---|---|---|---|
| credential_request | 0 | 0 | 0 | 15 | 15 |
| payment_request | 0 | 0 | 0 | 15 | 15 |
| investment_lure | 0 | 0 | 0 | 15 | 15 |
| fake_security_warning | 0 | 0 | 0 | 15 | 15 |
| fake_reward | 0 | 0 | 0 | 15 | 15 |
| urgency_threat | 0 | 0 | 0 | 15 | 15 |
| impersonation | 0 | 0 | 0 | 15 | 15 |
| benign | 49 | 0 | 49 | 15 | 0 |

## Verification

Verified: 0 rows (0.0 %); needs review: 1; review decisions whose text is no longer in the corpus: 0.

| source | verified % |
|---|---|
| page_segment | 0.0 % |
| real_message | 0.0 % |
| synthetic_template | 0.0 % |
| machine_translation | 0.0 % |

| language | verified % |
|---|---|
| en | 0.0 % |
| si | 0.0 % |
| ta | 0.0 % |
| mixed | 0.0 % |
| other | 0.0 % |

## Duplicates removed / rows dropped

- page_segment: duplicates_merged_in_group 126, dropped_duplicate_of_test 1465, dropped_duplicate_of_val 158
- synthetic_template: duplicates_merged 48

## Real-message split cells (language x intent, grouped)

No real messages yet (data/corpus/real_texts.csv missing or empty).

## Build counts

- page_segment: pages 459, segments_seen 18765, rejected_length 3884, capped_per_page 5907, duplicates_merged_in_group 126, rejected_few_letters 15, benign_page_strong_cue 1, rows 8833, dropped_duplicate_of_test 1465, dropped_duplicate_of_val 158
- real_message: file_missing 1
- synthetic_template: rows_read 168, duplicates_merged 48, rows 120
- machine_translation: rows 0

# C3 PP1 Evaluation

Component: **C3 – Social Media & Web Visual Threat Analyzer** (ScamTrace, SLIIT J26-SE-316).
Generated with `python scripts/pp1_evaluation.py` on 2026-10-19. Raw numbers: `data/statistics/pp1_evaluation.json`;
confusion matrices: `data/statistics/pp1_confusion_matrices.png`.

## 1. Frozen versions

Exact SHA-256 hashes of every file are in `data/statistics/pp1_freeze_manifest.json`.

| Item | Version |
|---|---|
| Multimodal dataset | 1,438 samples (219 legitimate, 219 scam with verified labels, 1,000 Fakeddit misinformation posts) · `dataset_metadata.jsonl` sha256 `e3e33d25e96e…` |
| Text dataset / splits | 438 rows, train 306 / val 66 / test 66, seed 42 · `text_baseline_dataset.jsonl` sha256 `32656480ad6a…` |
| Text scam model | DistilBERT (distilbert-base-uncased), fine-tuned · sha256 `b1b6fc7b7b3f…` |
| Threat category model | DistilBERT, 4 classes · sha256 `27331201125…` |
| Misinformation model | DistilBERT, Fakeddit titles · sha256 `4a99a3af82de…` |
| Logo detector | YOLO11n, 1 class "logo" · sha256 `909a12f782a7…` |
| Brand recognition | CLIP `openai/clip-vit-base-patch16`, zero-shot, 90 reference brands, threshold 0.55 |
| Risk score | Rule-based fusion: text 0.50, OCR 0.15, visual 0.15, website 0.20 + consistency boosts; HIGH ≥ 0.70, MEDIUM ≥ 0.40 |

## 2. Test-set results

Positive class = scam (fake for misinformation). FPR = false positive rate = legitimate items flagged as scam.

| Model | Test set | n | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR |
|---|---|---|---|---|---|---|---|---|
| Text scam model | text test split | 66 | 83.3% | 86.7% | 78.8% | 82.5% | 88.3% | 12.1% |
| Threat category model (macro) | text test split, 4 classes | 65 | 75.4% | 81.2% | 68.9% | 72.9% | 93.4% (one-vs-rest) | 21.2% |
| Misinformation model | Fakeddit test split | 150 | 77.3% | 88.7% | 62.7% | 73.4% | 86.6% | 8.0% |
| **Risk score** (MEDIUM/HIGH = scam) | text test split | 66 | **86.4%** | **85.3%** | **87.9%** | **86.6%** | **88.8%** | 15.2% |
| Risk score (HIGH only = scam) | text test split | 66 | 83.3% | 86.7% | 78.8% | 82.5% | 88.8% | 12.1% |
| CLIP brand recognition | Zenodo phishing pages | 250 | top-1 30.8% | 87.5% | 23.9% | 37.6% | – | 12.5% (unknown brand accepted) |
| Logo detector (detection) | logo test split | – | – | 85.0% | 73.2% | mAP@50 79.9% | – | – |
| Logo brand matching | detected crops / real pages | 86 / 55 | – | 98.8% / 73.8% | 94.2% / 58.5% | 96.4% / 65.3% | – | – |

Threat category per class: legitimate F1 77.6%, phishing 82.8%, financial scam 64.5%, data theft 66.7% (2 test samples).
Text scam model accuracy by source: Phish360 emails 90.0%, DIFrauD job ads 73.3%, manual Facebook posts 100% (6).
Risk levels on the test split: legitimate 28 LOW / 1 MEDIUM / 4 HIGH; scam 4 LOW / 3 MEDIUM / 26 HIGH.

**Reading the results:** the fused risk score has the best recall and F1 of all, which supports the multimodal design:
it catches 87.9% of scams at a 15.2% false-alarm rate. Brand recognition is precise (87.5%) but misses most brands
(recall 23.9%); logo matching is far stronger on clean logo crops (F1 96.4%) than on whole real pages (65.3%).

## 3. Scenario tests (full analyzer, manual Facebook test posts)

The six manual Facebook posts in the test split (never used for training) were run through the complete live
pipeline: preprocessing, OCR, text model, CLIP, logo detection, sandboxed capture of the link, consistency, risk
fusion and threat-category classification.

| Post | Scenario | Risk | Score | Primary category | Verdict correct? | Category correct? |
|---|---|---|---|---|---|---|
| SVT_000001 | Legitimate (bank iPhone promotion) | LOW | 0.26 | Misinformation | ✓ | ✗ |
| SVT_000007 | Legitimate (energy-drink ad contest) | LOW | 0.39 | Other scam | ✓ | ✗ |
| SVT_001428 | Legitimate (Bloomberg news) | LOW | 0.14 | Misinformation | ✓ | ✗ |
| SVT_000018 | Scam (PlayStation "enter your information") | HIGH | 0.73 | Other scam (true: data theft) | ✓ | ✗ |
| SVT_001431 | Scam ($100 gas card) | HIGH | 0.79 | Other scam (true: data theft) | ✓ | ✗ |
| SVT_001436 | Scam (fake Kroger gift card) | HIGH | 0.80 | Phishing (true: brand impersonation) | ✓ | ✗ |

**Legitimate scenario:** 3/3 rated LOW risk, 0/3 labelled LEGITIMATE. **Scam scenario:** 3/3 rated HIGH, 0/3 with
the exact category. The risk verdict is reliable; the category label is not yet.

## 4. Limitations

1. **Misinformation model does not transfer.** It is trained on short Fakeddit headlines and flags all six manual
   posts (promotions, news and scams) as misinformation, which turns legitimate posts into a "Misinformation" label.
2. **Category labels inconsistent with the risk level.** The OTHER_SCAM rule fires when the text scam score is ≥ 50%
   even if the fused risk is LOW (SVT_000007).
3. **Rare categories.** Data theft has 9 training samples, so data-theft posts fall back to OTHER_SCAM. Brand
   impersonation, malware and browser abuse have no trained class and rely on rules; brand impersonation only works
   for the 90 catalog brands (Kroger is not one, so the Kroger scam became PHISHING).
4. **Small test sets.** 66 text test samples and 6 scenario posts: one post changes accuracy by ~1.5 points.
5. **Source bias.** Phishing comes mostly from Phish360 emails and financial scams from DIFrauD job ads; accuracy on
   job ads (73.3%) is much lower than on emails (90%). External Telegram data (TelePhish) lowered accuracy when added.
6. **Brand recognition recall.** CLIP finds only 23.9% of impersonated brands on real phishing pages; logos on full
   pages are matched far worse than clean crops.
7. **Legitimate promotions look like scams.** Real giveaways (bank, retailer, exchange) score MEDIUM in several
   cases; the destination-domain check is the main signal separating them, and it needs a working capture.
8. **English only.** Sinhala and Tamil OCR language packs are not installed and the text models are English.
9. **Preliminary fusion.** Weights and thresholds were set by hand, not tuned on the validation split.
10. **Provisional labels.** Fakeddit (subreddit-derived), TelePhish (VirusTotal) and Smishtank category mappings are
    provisional; Smishtank and TelePhish are kept as external, unused datasets.

## 5. Next work (towards 80%)

1. Gate the misinformation model to news-like posts and require the scam rules to agree with the risk level
   (fixes limitations 1–2 without retraining).
2. Collect and label more real Sri Lankan social-media posts, especially data theft and brand impersonation;
   evaluate brand impersonation on the 563 Smishtank brand-impersonation messages.
3. Add a brand-impersonation class once enough samples exist; extend the brand catalog with commonly abused brands.
4. Tune fusion weights and thresholds on the validation split; run an ablation (text → +OCR → +visual → +website →
   +consistency) to measure each source's contribution; check score calibration.
5. Lower risk when the link resolves to the claimed brand's official domain (reduces false alarms on real promotions).
6. Install Sinhala/Tamil OCR and evaluate on local-language posts.
7. Fine-tune CLIP or add more reference images per brand to raise brand recall.
8. Re-run this evaluation as a new frozen version (PP2) and compare against these PP1 numbers.

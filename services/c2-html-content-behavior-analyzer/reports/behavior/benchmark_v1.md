# Behavioral intent detection - benchmark v1 (real pages)

> **PRELIMINARY, UNCONFIRMED, SMALL n.** 33 labelled cases on 31 real v0.3 pages; 33 of them are not yet confirmed by a reviewer. Labels come from reading each page's code, not from the detector. 95 % Wilson CIs. A rate is called measurable only with ≥ 3 pages behind it. The detector was NOT tuned on these pages (first run).

Rule: *detected* = Part 8 returns any finding of that pattern; *≥ high* = only high / critical findings (what the Part 9 evidence floor uses). FPR is over the pattern's real look-alike negatives.

| pattern | pos | neg | TPR (any) | FPR (any) | precision (any) | TPR (≥ high) |
|---|---|---|---|---|---|---|
| credential_exfiltration | 10 | 0 | 8/10 = 80.0 % [49.0, 94.3] | not measurable (n = 0) | 8/8 = 100.0 % [67.6, 100.0] | 8/10 = 80.0 % [49.0, 94.3] |
| keylogging | 0 | 4 | not measurable (n = 0) | 0/4 = 0.0 % [0.0, 49.0] | not measurable (n = 0) | not measurable (n = 0) |
| forced_redirect | 1 | 5 | not measurable (0/1 = 0.0 % [0.0, 79.3]) | 0/5 = 0.0 % [0.0, 43.4] | not measurable (n = 0) | not measurable (0/1 = 0.0 % [0.0, 79.3]) |
| clipboard_manipulation | 1 | 2 | not measurable (0/1 = 0.0 % [0.0, 79.3]) | not measurable (0/2 = 0.0 % [0.0, 65.8]) | not measurable (n = 0) | not measurable (0/1 = 0.0 % [0.0, 79.3]) |
| suspicious_download | 0 | 3 | not measurable (n = 0) | 0/3 = 0.0 % [0.0, 56.1] | not measurable (n = 0) | not measurable (n = 0) |
| obfuscated_execution | 1 | 0 | not measurable (1/1 = 100.0 % [20.7, 100.0]) | not measurable (n = 0) | not measurable (1/1 = 100.0 % [20.7, 100.0]) | not measurable (0/1 = 0.0 % [0.0, 79.3]) |
| anti_analysis | 5 | 1 | 5/5 = 100.0 % [56.6, 100.0] | not measurable (0/1 = 0.0 % [0.0, 79.3]) | 5/5 = 100.0 % [56.6, 100.0] | 0/5 = 0.0 % [0.0, 43.4] |
| **overall** | 18 | 15 | 14/18 = 77.8 % [54.8, 91.0] | 0/15 = 0.0 % [0.0, 20.4] | 14/14 = 100.0 % [78.5, 100.0] | 8/18 = 44.4 % [24.6, 66.3] |

## Coverage gaps

- **keylogging**: 0 real positive page(s) - TPR cannot be measured on real data yet.
- **forced_redirect**: 1 real positive page(s) - TPR cannot be measured on real data yet.
- **clipboard_manipulation**: 1 real positive page(s) - TPR cannot be measured on real data yet.
- **suspicious_download**: 0 real positive page(s) - TPR cannot be measured on real data yet.
- **obfuscated_execution**: 1 real positive page(s) - TPR cannot be measured on real data yet.

## Misses (positives not detected)

- `c2_phishing_000009` (credential_exfiltration): obfuscated string array builds a POST of email + password to a Telegram bot. Other patterns found: none. Expected static-analysis limitation: the endpoint and field names sit in an _0x string array resolved at run time, so no literal flow exists to follow.
- `c2_phishing_000043` (credential_exfiltration): password -> buildReport -> sendToTelegram (Image beacon to a Telegram bot). Other patterns found: credential_access, forced_redirect. The flow runs password -> buildReport() -> sendToTelegram() -> new Image().src with a URL built from constants; not investigated in this batch (detector unchanged).
- `c2_malware_delivery_000023` (clipboard_manipulation): ClickFix: fake reCAPTCHA copies a hidden PowerShell download-and-run command via execCommand('copy'). Other patterns found: none. **Possible detector miss** (ClickFix): the PowerShell command is built by string concatenation, passed through two helper functions into a temporary textarea's value and copied with execCommand('copy') - the clipboard pattern expects a literal command reaching a clipboard write. Not changed in this batch.
- `c2_benign_000009` (forced_redirect): meta refresh 0 s to another site (docs.github.com). Other patterns found: none. **Likely a LABEL error, not a miss:** the page is pages.github.com and the refresh goes to docs.github.com - the same registrable domain, which the pattern ("to another site") correctly treats as internal. Suggest relabelling to negative when confirming; the first-run number above keeps the original label.

## False alarms (negatives detected)

- none

## All cases

| sample_id | pattern | expected | detected | severities | confirmed |
|---|---|---|---|---|---|
| `c2_phishing_000009` | credential_exfiltration | positive | no | - | no |
| `c2_phishing_000013` | credential_exfiltration | positive | yes | critical | no |
| `c2_phishing_000014` | credential_exfiltration | positive | yes | critical | no |
| `c2_phishing_000017` | credential_exfiltration | positive | yes | critical | no |
| `c2_phishing_000043` | credential_exfiltration | positive | no | - | no |
| `c2_phishing_000052` | credential_exfiltration | positive | yes | critical | no |
| `c2_phishing_000058` | credential_exfiltration | positive | yes | critical | no |
| `c2_phishing_000063` | credential_exfiltration | positive | yes | critical | no |
| `c2_phishing_000089` | credential_exfiltration | positive | yes | critical | no |
| `c2_phishing_000094` | credential_exfiltration | positive | yes | critical | no |
| `c2_malware_delivery_000023` | clipboard_manipulation | positive | no | - | no |
| `c2_benign_000031` | clipboard_manipulation | negative | no | - | no |
| `c2_benign_000166` | clipboard_manipulation | negative | no | - | no |
| `c2_benign_000092` | obfuscated_execution | positive | yes | medium | no |
| `c2_phishing_000006` | anti_analysis | positive | yes | medium | no |
| `c2_phishing_000041` | anti_analysis | positive | yes | low | no |
| `c2_phishing_000060` | anti_analysis | positive | yes | medium | no |
| `c2_phishing_000117` | anti_analysis | positive | yes | medium | no |
| `c2_benign_000109` | anti_analysis | positive | yes | medium | no |
| `c2_benign_000163` | anti_analysis | negative | no | - | no |
| `c2_benign_000009` | forced_redirect | positive | no | - | no |
| `c2_benign_000052` | forced_redirect | negative | no | - | no |
| `c2_phishing_000125` | forced_redirect | negative | no | - | no |
| `c2_phishing_000005` | forced_redirect | negative | no | - | no |
| `c2_phishing_000015` | forced_redirect | negative | no | - | no |
| `c2_phishing_000027` | forced_redirect | negative | no | - | no |
| `c2_phishing_000060` | keylogging | negative | no | - | no |
| `c2_phishing_000091` | keylogging | negative | no | - | no |
| `c2_crypto_scam_000005` | keylogging | negative | no | - | no |
| `c2_phishing_000015` | keylogging | negative | no | - | no |
| `c2_malware_delivery_000005` | suspicious_download | negative | no | - | no |
| `c2_malware_delivery_000018` | suspicious_download | negative | no | - | no |
| `c2_malware_delivery_000036` | suspicious_download | negative | no | - | no |

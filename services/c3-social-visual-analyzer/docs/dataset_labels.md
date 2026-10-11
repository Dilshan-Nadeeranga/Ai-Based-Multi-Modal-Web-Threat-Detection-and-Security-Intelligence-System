# ScamTrace C3 – Dataset Classes and Labelling Guide (v0.1)

This guide defines the classes used in the multimodal dataset and how
annotators should apply them. The classes are enforced in code by
`app/schemas/dataset_classes.py`; `GET /api/v1/dataset/classes` returns the same
lists.

## 1. Label fields

Every sample has three label fields:

| Field | Values | Purpose |
| --- | --- | --- |
| `is_scam` | `0` = legitimate, `1` = scam, `null` = not decided yet | Binary target for later models. |
| `scam_type` | see §2 | Finer category. |
| `label_status` | `verified`, `provisional`, `needs_review` | How confident the label is. |

## 2. `scam_type` classes

| Value | `is_scam` | Use when the post… |
| --- | --- | --- |
| `legitimate` | 0 | is genuine content from the real organisation/person, or harmless content with no deceptive intent. |
| `phishing` | 1 | tries to obtain credentials, OTPs or card details through a fake login/verification page or form. |
| `brand_impersonation` | 1 | pretends to be a known brand, bank, government body or public figure (fake page, logo misuse, look-alike name) as the main deception. |
| `financial_scam` | 1 | promises money or asks for payment: fake giveaways, investment/crypto schemes, advance-fee, fake jobs or loans, fake shops. |
| `data_theft` | 1 | collects personal data (ID numbers, addresses, phone numbers, surveys for "prizes") without stealing a login. |
| `malware` | 1 | pushes a download or app install (APK, "update", "codec", cracked software) that is or delivers malicious software. |
| `browser_abuse` | 1 | leads to push-notification spam, fake virus alerts, forced redirects, malicious extensions or other browser-level tricks. |
| `other_scam` | 1 | is clearly a scam but fits none of the above. Explain in `notes`. |
| `unknown` | `null` | has not been categorised yet. Only allowed while `label_status` is not `verified`. |

The seven values from `phishing` to `other_scam` are the **scam categories**.

### Choosing one category when several apply

Pick the **primary harm** – what the attacker ultimately wants from the victim:

1. Wants a password / OTP / card → `phishing` (even if a brand is impersonated).
2. Wants a payment or "fee" → `financial_scam`.
3. Wants a file installed → `malware`.
4. Wants personal details only → `data_theft`.
5. Impersonation without one of the above clear goals (e.g. a fake brand page
   building followers, fake customer support) → `brand_impersonation`.

Record the brand being imitated in `claimed_brand` regardless of the category.

## 3. `label_status`

| Value | Meaning |
| --- | --- |
| `verified` | The label is confirmed by clear evidence (official warning, takedown, brand's own statement, obviously fraudulent destination) or by a second annotator. |
| `provisional` | Best judgement by one annotator; reasonable but not independently confirmed. |
| `needs_review` | The annotator is unsure. The sample must be reviewed before training/evaluation. |

## 4. Consistency rules (enforced)

| `is_scam` | Allowed `scam_type` | Allowed `label_status` |
| --- | --- | --- |
| `0` | `legitimate` only | any |
| `1` | a scam category (not `legitimate`); `unknown` only if not `verified` | any (but `unknown` ⇒ not `verified`) |
| `null` | `unknown` only | `needs_review` only |

Additionally `scam_type=unknown` can never be `verified`. Records that break a
rule are rejected by the API/CLI and reported by the validator
(`LABEL_INCONSISTENT`).

## 5. Inclusion rules

Include a sample only if **all** of these hold:

* It is a public post/page, an item from a published research dataset, or a
  research archive entry the team is allowed to use.
* It has post text and/or at least one image (screenshots of the post are fine).
* Images are readable JPEG, PNG or WEBP files.
* It contains no private messages and no personal data about uninvolved people.
  Crop or omit names, profile photos, phone numbers, emails and comments that
  are not part of the scam evidence.

Do **not** include:

* Content scraped automatically from Facebook, Instagram, X or similar platforms
  (out of scope for this card and against platform terms).
* Synthetic/test samples in the research dataset. `collection_method=synthetic_test`
  is refused unless `DATASET_ALLOW_SYNTHETIC=true`, and the CLI refuses
  `--allow-synthetic` with the default data folder. Use a separate `--data-dir`.
* Duplicates of a sample already in the dataset.

URLs are stored as text evidence only. Annotators should not open suspected
malicious links on a normal machine; nothing in this card visits URLs.

## 6. Ambiguous examples

| Situation | Suggested label |
| --- | --- |
| Real brand ad, but the link domain looks odd and cannot be checked | `is_scam=null`, `unknown`, `needs_review` |
| "Free iPhone giveaway – share and comment" from an unverified page, no link | `1`, `financial_scam`, `provisional` |
| Look-alike bank page asking to "verify your account" with a login link | `1`, `phishing`, `verified` if the destination is a known phishing report, else `provisional` |
| Post from the brand's verified official account warning about scams | `0`, `legitimate`, `verified` |
| Fake "customer support" page replying to complaints, no link yet | `1`, `brand_impersonation`, `provisional` |
| "Your device is infected – install this cleaner" with an APK link | `1`, `malware`, `provisional` |
| Satire/meme that mentions a scam but is not one | `0`, `legitimate`, `provisional` |
| Clearly fraudulent but cannot decide the category | `1`, `unknown`, `needs_review` (fix the category later) |

## 7. When to use `needs_review`

Use it whenever any of these apply; it is better to defer than to guess:

* You cannot tell whether the post is genuine (`is_scam=null`).
* You know it is a scam but not which category (`scam_type=unknown`).
* Text and image disagree (e.g. genuine logo, suspicious offer).
* The post is in a language you cannot read reliably.
* Evidence depends on the destination page, which has not been captured yet.

Samples marked `needs_review` are counted under `label_status` and, when
`is_scam=null`, under `binary_labels.undecided` in the statistics, so the
backlog stays visible. Statistics never guess a class for them.

## 8. Misinformation (fake-news) labels

Fake-news detection is a **separate task** from scam detection. Each sample
has a second label block, `labels.misinformation`:

| Field | Values |
| --- | --- |
| `is_fake` | `0` = real, `1` = fake, `null` = not decided / not annotated |
| `misinfo_type` | `real`, `satire_parody`, `misleading_content`, `imposter_content`, `false_connection`, `manipulated_content`, `unknown` |
| `label_status` | `verified`, `provisional`, `needs_review`, `not_annotated` |
| `source_label` | Original label in the source dataset, e.g. `fakeddit_2way=0;3way=2;6way=4` |

The categories follow the Fakeddit taxonomy:

| `misinfo_type` | Meaning |
| --- | --- |
| `real` | Genuine content, accurately presented. |
| `satire_parody` | Deliberately false for humour (The Onion, fake album covers). Not meant to deceive, but false. |
| `misleading_content` | Information framed to mislead (propaganda posters, clickbait headlines). |
| `imposter_content` | Content falsely attributed or bot-generated as if written by a real source. |
| `false_connection` | Image and text do not match (misleading thumbnails, "fake history" captions). |
| `manipulated_content` | Edited or photoshopped images. |

Rules are the same shape as for scams: `0` ⇒ `real`; `1` ⇒ a fake category
(or `unknown` while not verified); `null` ⇒ `unknown` with `needs_review` or
`not_annotated`.

### `not_annotated` and the two tasks

`label_status: not_annotated` means the sample was **never labelled for that
task**. It is not a pending review and is reported separately in the
statistics (`binary_labels.not_annotated`, `misinformation_labels.not_annotated`).

* Scam posts you collect: scam labels filled in, misinformation `not_annotated`
  (the default) unless you also judge whether the post is fake news.
* Fakeddit rows: misinformation labels from Fakeddit, scam `not_annotated`
  (`is_scam: null`, `scam_type: unknown`). Fakeddit was never checked for scams,
  so they are **not** counted as legitimate.
* Every sample must be annotated for at least one task.

Fakeddit labels are assigned per subreddit (distant supervision), not per post,
so imported Fakeddit rows use `label_status: provisional`.

A post can be both: a fake "giveaway" with a manipulated image can be
`is_scam: 1, scam_type: financial_scam` **and**
`is_fake: 1, misinfo_type: manipulated_content`.

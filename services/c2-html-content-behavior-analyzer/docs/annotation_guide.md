# Annotation guide: social-engineering intents (intent_v1)

For the scam-text corpus (`corpus_v1`, Part 5 Batch B). It is written for me and for the
peer reviewer. The machine-readable source is `configs/intent_taxonomy.yaml`. When the
two disagree, the YAML wins, so fix this guide.

## What you label

Label **what the text tries to make the reader do or believe**. Judge the text alone,
not the website it came from. The same "Sign in" button is on a bank's site and on its
phishing copy. The page's threat class is stored separately (`page_label`).

- **Multi-label is allowed.** Give every intent that clearly applies.
- **The first intent is the primary intent.** When a text fits several, order them by
  the priority list below. Only the primary intent is used for the peer-agreement
  kappa.
- `benign` is used only on its own. It means no other intent applies.
- When in doubt between an intent and `benign`, ask: would a careful reader feel
  pressured, baited or asked for something they should not give? If not, use `benign`.
- Exclude a text (`x` in the review tool) if it is not a message at all: a name, a
  number, garbled text, a cookie banner, or personal data that the masking missed.

## Priority (primary intent)

1. `credential_request`
2. `payment_request`
3. `investment_lure`
4. `fake_security_warning`
5. `fake_reward`
6. `urgency_threat`
7. `impersonation`
8. `benign`

Why this order: the most specific ask decides the primary intent, meaning what the
victim is asked to hand over (credentials, then money, then an investment). Framing
tactics such as a fake alarm, a reward, pressure or pretending to be someone come
with almost every scam, so they rank lower.

*Example:* "Your account will be suspended in 24 h. Verify your password now." gets
`credential_request; urgency_threat`, with `credential_request` as the primary.

## The intents

### `credential_request`
Asks the reader to type, confirm or send a secret: a password, PIN, OTP / one-time code,
card number / CVV / expiry, or an online-banking login. An NIC number counts when it
comes with a pretext.
- **Include:** "verify / update / confirm your password / card / account", OTP requests,
  and card / CVV / PIN fields outside a genuine checkout.
- **Exclude:** a plain login label with no pretext ("Email", "Password", "Sign in") is
  `benign`, because the DOM and behavior analyzers judge forms. "Never share your OTP"
  is `benign`. Asking for money is `payment_request`.
- *Examples:* "Your account has been limited. Verify your password and card details to
  restore access." / "Enter the 6-digit OTP sent to your phone to confirm your identity."

### `payment_request`
Asks the reader to pay an amount, usually a small one, to receive something. This covers
advance fees, delivery or redelivery fees, customs or clearance fees, processing or tax
fees, and the release fee for a prize or loan.
- **Exclude:** ordinary shop prices and checkout text on a real shop are `benign`.
  Investing for a promised return is `investment_lure`.
- *Examples:* "Your parcel is held at customs. Pay the clearance fee of Rs. 450 to
  release it." / "Delivery failed. A redelivery fee of $1.99 is required before 23:59
  today."

### `investment_lure`
Promises unrealistic or guaranteed returns to make the reader invest or deposit: crypto
doubling, daily-profit plans, trading bots, referral or pyramid income.
- **Exclude:** neutral information about investing or exchange rates is `benign`.
  Winning without investing is `fake_reward`.
- *Examples:* "Invest $100 today and earn 5% guaranteed profit every single day." /
  "Send any amount of BTC and we will double it instantly."

### `fake_security_warning`
A false alarm about the reader's device or account security, meant to scare them into
calling, clicking or installing something: virus or infection pop-ups, "unusual
activity", fake tech support, forced "security updates".
- **Exclude:** a real site's ordinary security advice is `benign`. "Your account will
  be suspended" with no security alarm is `urgency_threat`.
- *Examples:* "WARNING! Your computer is infected with 3 viruses. Call Microsoft
  Support now." / "Security alert: your phone has been hacked. Install the update to
  remove the threat."

### `fake_reward`
Claims the reader has won, or is entitled to, something valuable for free: a prize,
lottery, gift, cash-back, free data, or an unrealistic discount used as bait.
- **Exclude:** a real shop's ordinary sale ("20% off this weekend") is `benign`.
  Rewards that require an investment first are `investment_lure`.
- *Examples:* "Congratulations! You have won Rs. 1,000,000 in the national lucky
  draw." / "Claim your free 50GB data gift now."

### `urgency_threat`
Puts pressure on the reader through a deadline, a loss or a threat: account suspension
or blocking, "within 24 hours", legal action, fines, arrest.
- **Exclude:** "offer ends Sunday" in a real shop is `benign`, unless a loss or threat
  comes with it. A device or virus alarm is `fake_security_warning`.
- *Examples:* "Your account will be suspended within 24 hours unless you act now." /
  "Final notice: legal action will be taken if this is not resolved today."

### `impersonation`
Claims to come from a trusted organisation (a bank, government office, courier,
telecom or well-known brand) to borrow its authority.
- **Exclude:** the organisation's own genuine pages are `benign` unless another intent
  applies. A brand merely mentioned in a product name is `benign`.
- *Examples:* "Sri Lanka Post: your parcel could not be delivered. Confirm your
  address." / "Dear valued customer, this is the security team of your bank."

### `benign`
No social-engineering intent: navigation, product text, news, ordinary login or
checkout text, genuine safety advice.
- *Examples:* "Sign in to your account" / "Free delivery on orders over Rs. 5,000.
  Returns accepted within 14 days."

## Sinhala, Tamil and romanized text

- Apply the same rules in every language. Label the meaning, not the words. A
  translation keeps the intent of its source.
- Sinhala or Tamil written in Latin letters ("Singlish" / "Tanglish") gets the language
  `si_latn` / `ta_latn`. Fix the language with `l` if detection got it wrong.
- **Cue words are only hints.** The Sinhala and Tamil cue lists in the YAML are a seed
  list that still needs a native-speaker check. Never accept a suggested intent just
  because a cue word matched.

## Where the suggestions come from

| source | label shown | trust |
|---|---|---|
| `page_segment` | weak label from cue words. On a benign page it stays `benign` unless 2+ cue phrases match (then *needs review*) | low: always check |
| `real_message` | my label from `real_texts.csv` | medium: confirm |
| `synthetic_template` | template label | train only, review optional |
| `machine_translation` | label of the English source | train only, spot-check |

Synthetic and machine-translated rows are never in validation or test.

## How to review

```bash
python scripts/review_corpus.py review --reviewer <name> --split test --language si
python scripts/review_corpus.py review --reviewer <name> --needs-review
```

Keys: `c` confirm (pins the shown intents and language), `i` change intents (type
numbers, first = primary, e.g. `6 1`), `l` language, `x` exclude (with a reason), `s`
skip, `b` back, `q` quit. Every key press is saved, so you can stop at any time.

Review **val and test first**, then train: unverified text in val / test makes the
evaluation unreliable.

## Peer check

1. `python scripts/review_corpus.py export-peer --fraction 0.1 --seed 42` writes
   `data/corpus/review/corpus_peer_sheet.csv`. It holds a random 10 % of my verified
   texts per language, with no labels. It contains corpus text, so share it privately.
2. The peer fills `peer_primary_intent` (and optionally `peer_intents`) using only this
   guide.
3. `python scripts/review_corpus.py import-peer --file <their file>` reports agreement %
   and Cohen's kappa, overall and per language, in
   `reports/content/corpus_peer_agreement.json`. Interpretation (Landis & Koch): 0.41-0.60
   moderate, 0.61-0.80 substantial, above 0.80 almost perfect. Discuss every
   disagreement, and update this guide if a rule was unclear.

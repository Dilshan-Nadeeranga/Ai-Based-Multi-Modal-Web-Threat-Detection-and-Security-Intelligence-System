"""PII masking for values that may belong to a real victim (FR10 / Sri Lanka PDPA).

Shared (used across Parts 1-9; first used by Part 2).

Why: phishing pages are often saved with a victim's data already in them - a
prefilled email in a login form, or ``?email=victim@mail.com`` in a link or
form action. Our outputs must not keep that personal data. Matches are
replaced by tokens ([EMAIL], [PHONE], [CARD], [NIC]), so the FACT that a
value was there is kept for the models, but not the value itself.

Scope (on purpose): only prefilled input values and URL query/fragment
values are masked. Visible page text is NOT masked - the scam text itself is
what Part 5 has to read (and it is the scammer's text, not a victim's).

Patterns:
- email:  name@domain.tld
- NIC:    old Sri Lankan NIC = 9 digits + V/X; new NIC = 12 digits starting
          with the birth year (19xx/20xx)
- card:   13-19 digits (spaces/dashes allowed) that pass the Luhn check -
          the check keeps timestamps and ids from being masked as cards
- phone:  Sri Lankan numbers (+94 / 0094 / 0 followed by 9 digits, e.g.
          077 123 4567, 011-2345678) and international +<country> numbers
"""

from __future__ import annotations

import re
from urllib.parse import unquote, unquote_plus, urlsplit, urlunsplit

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
NIC = re.compile(r"(?<![0-9A-Za-z])(?:\d{9}[VvXx]|(?:19|20)\d{10})(?![0-9A-Za-z])")
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
PHONE = re.compile(
    r"(?<![\d+])(?:"
    r"(?:\+94|0094|0)[ -]?\d{2}[ -]?\d{3}[ -]?\d{4}"  # Sri Lanka: 0 + 9 digits
    r"|\+\d{1,3}[ -]?\d{2,4}[ -]?\d{3,4}[ -]?\d{3,4}"  # other countries
    r")(?!\d)"
)
TOKENS = ("[EMAIL]", "[NIC]", "[CARD]", "[PHONE]")


def luhn_valid(digits: str) -> bool:
    """The checksum every payment card number satisfies."""
    total = 0
    for position, char in enumerate(reversed(digits)):
        value = int(char)
        if position % 2 == 1:
            value = value * 2 - 9 if value > 4 else value * 2
        total += value
    return total % 10 == 0


def _mask_card(match: re.Match) -> str:
    digits = re.sub(r"\D", "", match.group())
    return "[CARD]" if luhn_valid(digits) else match.group()


def mask_pii(text: str) -> str:
    """Replace emails, NIC numbers, card numbers and phone numbers with tokens.

    Order matters: a 12-digit NIC would otherwise look like a phone or card.
    """
    text = EMAIL.sub("[EMAIL]", text)
    text = NIC.sub("[NIC]", text)
    text = CARD.sub(_mask_card, text)
    return PHONE.sub("[PHONE]", text)


def _mask_part(raw: str, decode) -> str:
    """Mask one query value / fragment; return it unchanged if it holds no PII."""
    masked = mask_pii(decode(raw))
    return raw if masked == decode(raw) else masked


def mask_url(url: str | None) -> str | None:
    """Mask PII inside a URL's query values and fragment; the rest stays exactly as written.

    ``https://x.test/a?email=v%40mail.com&lang=si`` -> ``https://x.test/a?email=[EMAIL]&lang=si``.
    ``mailto:`` / ``tel:`` links are masked completely (the address IS the value).
    """
    if not url:
        return url
    lowered = url.lower()
    if lowered.startswith(("mailto:", "tel:", "sms:")):
        scheme, _, rest = url.partition(":")
        return f"{scheme}:{mask_pii(unquote(rest))}"
    try:
        parts = urlsplit(url)
    except ValueError:
        return mask_pii(url)
    if not parts.query and not parts.fragment:
        return url

    query = []
    for segment in parts.query.split("&") if parts.query else []:
        key, equals, value = segment.partition("=")
        if equals:
            query.append(f"{key}={_mask_part(value, unquote_plus)}")
        else:  # "?victim@mail.com" - a bare value
            query.append(_mask_part(segment, unquote_plus))
    fragment = _mask_part(parts.fragment, unquote) if parts.fragment else ""
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(query), fragment))

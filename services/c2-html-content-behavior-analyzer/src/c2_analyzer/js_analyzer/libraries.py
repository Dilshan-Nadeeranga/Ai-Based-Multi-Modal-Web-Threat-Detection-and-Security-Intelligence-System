"""Recognise well-known library code (inline scripts and <script src> references).

Part 7: Static JavaScript intent analyzer.

Why library awareness: benign sites are full of library code that uses the
very APIs we look for - jQuery assigns innerHTML and builds XHRs, Google Tag
Manager injects scripts, the Facebook pixel sends image beacons, Cloudflare's
snippet uses innerHTML inside an iframe. Counting those as the page's own
behaviour would make every popular benign site look like a phishing kit
(false positives), and the counts would mostly measure "uses jQuery".

So a script that matches a library signature keeps all its detections (they
are still facts, and still in the JSON), but they are tagged
``in_library=true`` and left out of the page-own counts and the feature
vector. Signatures (configs/js_rules.yaml ``libraries``):
- ``banner``: a license header / version banner in the first few KB
  ("jQuery v3.6.0 | (c) OpenJS Foundation") - how minified libraries start;
- ``marker``: a characteristic string of a SHORT snippet (the GTM loader,
  ``fbq('init'``); a script much longer than ``max_chars`` is not hidden as a
  library just because it contains the snippet - a kit could paste its own
  code next to it;
- ``src``: file / host names of external references (jquery.min.js, gtm.js).
Limitation: code appended after a real library banner in the same <script>
is treated as library code. The detections are still recorded.
"""

from __future__ import annotations

from c2_analyzer.js_analyzer.rules import Rules


def identify_inline(text: str, rules: Rules) -> str | None:
    """Library name of an inline script, or None if it looks like page-own code."""
    head = text[: rules.banner_chars]
    for library in rules.libraries:
        if any(pattern.search(head) for pattern in library.banner):
            return library.name
        if library.marker and len(text) <= library.max_chars:
            if any(pattern.search(text) for pattern in library.marker):
                return library.name
    return None


def identify_src(src: str | None, rules: Rules) -> str | None:
    """Library name of an external script reference (by file / host name), or None."""
    if not src:
        return None
    for library in rules.libraries:
        if any(pattern.search(src) for pattern in library.src):
            return library.name
    return None

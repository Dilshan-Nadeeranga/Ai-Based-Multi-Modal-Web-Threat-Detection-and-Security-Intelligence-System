"""Modular URL Feature Extraction & Lexical Analysis Engine.

Extracts comprehensive structural, lexical, entropy, homoglyph, obfuscation,
and IP-address features from URLs without executing or rendering destination webpages.
"""

from __future__ import annotations

import ipaddress
import math
import re
import unicodedata
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlsplit

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:  # pragma: no cover
    _HAS_TLDEXTRACT = False

from app.config import get_settings
from app.schemas.url_schema import Layer1LexicalAnalysisResult, UrlLexicalFeatures

# Confusable character mapping for basic homoglyph detection (Cyrillic, Greek, etc. lookalikes)
CONFUSABLE_MAP: Dict[str, str] = {
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o',
    '\u0440': 'p', '\u0445': 'x', '\u0443': 'y', '\u0456': 'i',
    '\u0501': 'd', '\u0455': 's', '\u04bb': 'h', '\u043d': 'n',
    '\u03bf': 'o', '\u03c5': 'y', '\u03b1': 'a', '\u03c1': 'p',
}

ENCODED_PATTERN = re.compile(r'%[0-9a-fA-F]{2}')
DOUBLE_ENCODED_PATTERN = re.compile(r'%25[0-9a-fA-F]{2}')
HEX_IP_PATTERN = re.compile(r'^(0x[0-9a-fA-F]+(\.0x[0-9a-fA-F]+){3}|0x[0-9a-fA-F]{8})$', re.IGNORECASE)
OCTAL_IP_PATTERN = re.compile(r'^0[0-7]+(\.0[0-7]+){3}$')
DECIMAL_INT_IP_PATTERN = re.compile(r'^\d{8,11}$')


def calculate_shannon_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a string (in bits per character).

    Formula: H(S) = - sum(p(x) * log2(p(x)))
    Higher values indicate greater randomness or information density.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


def parse_ip_address(hostname: str) -> Tuple[bool, str, bool]:
    """Check if the hostname is an IP address (IPv4, IPv6, Hex, Octal, Decimal Int).

    Returns:
        (is_ip, ip_type, is_private)
    """
    clean_host = hostname.strip('[]').strip()

    # 1. Standard IPv4 / IPv6
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        ip_type = "ipv6" if isinstance(ip_obj, ipaddress.IPv6Address) else "ipv4"
        is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
        return True, ip_type, is_private
    except ValueError:
        pass

    # 2. Hexadecimal IP (e.g. 0xC0A80101 or 0xc0.0xa8.0x01.0x01)
    if HEX_IP_PATTERN.match(clean_host):
        return True, "hex_ip", False

    # 3. Octal IP (e.g. 0300.0250.0001.0001)
    if OCTAL_IP_PATTERN.match(clean_host):
        return True, "octal_ip", False

    # 4. Decimal Integer IP (e.g. 3232235777)
    if DECIMAL_INT_IP_PATTERN.match(clean_host):
        try:
            int_val = int(clean_host)
            ip_obj = ipaddress.IPv4Address(int_val)
            return True, "decimal_ip", ip_obj.is_private
        except ValueError:
            pass

    return False, "none", False


def detect_homoglyphs_and_unicode(hostname: str) -> Tuple[bool, bool, bool, List[str]]:
    """Detect Punycode, IDN, and mixed-script lookalike/homoglyph characters in hostnames.

    Returns:
        (is_punycode, is_idn, has_homoglyphs, details_list)
    """
    details: List[str] = []
    is_punycode = False
    is_idn = False
    has_homoglyphs = False

    lowered_host = hostname.lower()

    if "xn--" in lowered_host:
        is_punycode = True
        details.append("Punycode domain prefix (xn--) detected.")

    # Check for non-ASCII characters
    non_ascii_chars = [ch for ch in hostname if ord(ch) > 127]
    if non_ascii_chars:
        is_idn = True
        details.append(f"Internationalized Domain Name (IDN) with {len(non_ascii_chars)} non-ASCII character(s).")

    # Script mixing analysis & lookalike confusable detection
    scripts_found: set[str] = set()
    confusables_found: List[str] = []

    for char in hostname:
        if ord(char) > 127:
            char_name = unicodedata.name(char, "")
            script = char_name.split()[0] if char_name else "UNKNOWN"
            scripts_found.add(script)

            if char in CONFUSABLE_MAP:
                confusables_found.append(f"'{char}' (U+{ord(char):04X} confusable with '{CONFUSABLE_MAP[char]}')")

    if confusables_found:
        has_homoglyphs = True
        details.append(f"Homoglyph confusables detected: {', '.join(confusables_found[:5])}")

    if len(scripts_found) > 1 and "LATIN" in scripts_found:
        has_homoglyphs = True
        details.append(f"Mixed-script hostname detected involving LATIN and {', '.join(scripts_found - {'LATIN'})}.")

    return is_punycode, is_idn, has_homoglyphs, details


def extract_tld_structure(hostname: str) -> Tuple[str, str, str, int]:
    """Extract registered_domain, subdomain, tld, and domain_depth cleanly.

    Returns:
        (registered_domain, subdomain, tld, domain_depth)
    """
    if _HAS_TLDEXTRACT:
        extracted = tldextract.extract(hostname)
        subdomain = extracted.subdomain
        top_domain = getattr(extracted, "top_domain_under_public_suffix", "")
        if top_domain:
            registered_domain = top_domain
        elif extracted.suffix:
            registered_domain = f"{extracted.domain}.{extracted.suffix}"
        else:
            registered_domain = extracted.domain
        tld = extracted.suffix
    else:
        # Fallback naive parsing if tldextract is not installed
        parts = hostname.split('.')
        if len(parts) >= 2:
            tld = parts[-1]
            registered_domain = '.'.join(parts[-2:])
            subdomain = '.'.join(parts[:-2])
        else:
            tld = ""
            registered_domain = hostname
            subdomain = ""

    labels = [p for p in hostname.split('.') if p]
    domain_depth = len(labels)

    return registered_domain, subdomain, tld, domain_depth


class UrlLexicalAnalyzer:
    """Engine for extracting lexical, structural, and mathematical features from URLs."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def extract_features(self, raw_url: str) -> UrlLexicalFeatures:
        """Parse raw_url and extract all required numeric, boolean, and textual ML features.

        Inputs are validated and safely normalized without altering the original raw URL evidence.
        """
        if not raw_url or not isinstance(raw_url, str):
            raw_url = ""

        original_url = raw_url.strip()
        if not original_url:
            # Handle empty/null input safely
            return self._empty_features()

        # Safe URL normalization for parsing
        normalized_url = original_url
        if not (normalized_url.startswith("http://") or normalized_url.startswith("https://") or normalized_url.startswith("ftp://")):
            normalized_url = "http://" + normalized_url

        try:
            parsed = urlsplit(normalized_url)
        except Exception:
            # Handle malformed URL parsing gracefully
            parsed = urlsplit("http://malformed.local")

        scheme = parsed.scheme.lower() if parsed.scheme else "http"
        netloc = parsed.netloc
        path = parsed.path
        query = parsed.query
        fragment = parsed.fragment

        # Handle username/password in netloc (e.g. user:pass@hostname)
        has_at_symbol = "@" in netloc
        if "@" in netloc:
            netloc_parts = netloc.rsplit("@", 1)
            hostname_with_port = netloc_parts[1]
        else:
            hostname_with_port = netloc

        # Separate port from hostname
        if ":" in hostname_with_port and not hostname_with_port.endswith("]"):
            host_parts = hostname_with_port.rsplit(":", 1)
            hostname = host_parts[0]
            try:
                port = int(host_parts[1])
            except ValueError:
                port = None
        else:
            hostname = hostname_with_port
            port = None

        hostname = hostname.strip("[]").lower()

        # Extract TLD structure
        registered_domain, subdomain, tld, domain_depth = extract_tld_structure(hostname)

        # IP address evaluation
        is_ip_address, ip_type, is_private_ip = parse_ip_address(hostname)

        # Homoglyphs, IDN, Punycode
        is_punycode, is_idn, has_homoglyphs, homoglyph_details = detect_homoglyphs_and_unicode(hostname)

        # Length metrics
        url_length = len(normalized_url)
        hostname_length = len(hostname)
        path_length = len(path)
        query_length = len(query)
        tld_length = len(tld)
        subdomain_length = len(subdomain)

        # Character counts
        num_dots = normalized_url.count('.')
        num_dots_hostname = hostname.count('.')
        num_hyphens = normalized_url.count('-')
        num_hyphens_hostname = hostname.count('-')

        num_digits = sum(c.isdigit() for c in normalized_url)
        num_digits_hostname = sum(c.isdigit() for c in hostname)
        num_letters = sum(c.isalpha() for c in normalized_url)

        # Special characters
        special_chars = set("@?=%_/:&+-.#")
        num_special_chars = sum(c in special_chars for c in normalized_url)

        # Subdomains count
        subdomain_labels = [s for s in subdomain.split('.') if s]
        num_subdomains = len(subdomain_labels)

        # Path depth & query parameters
        path_segments = [p for p in path.split('/') if p]
        path_depth = len(path_segments)
        num_query_params = len(query.split('&')) if query else 0

        # Keyword matching
        lower_url = normalized_url.lower()
        found_keywords = [kw for kw in self.settings.suspicious_keywords if kw in lower_url]
        suspicious_keyword_count = len(found_keywords)
        has_suspicious_keyword = suspicious_keyword_count > 0

        # Repetition & Consecutive Digits
        digit_runs = re.findall(r'\d+', hostname or normalized_url)
        max_consecutive_digits = max((len(run) for run in digit_runs), default=0)
        digit_ratio = round(num_digits / url_length, 4) if url_length > 0 else 0.0

        # Max consecutive character repetition
        char_runs = [len(m.group(0)) for m in re.finditer(r'(.)\1+', normalized_url)]
        max_character_repetition = max(char_runs, default=1)
        has_excessive_repetition = max_character_repetition >= 4

        # Shannon Entropy
        url_entropy = calculate_shannon_entropy(normalized_url)
        hostname_entropy = calculate_shannon_entropy(hostname)
        path_entropy = calculate_shannon_entropy(path)
        query_entropy = calculate_shannon_entropy(query)

        # Obfuscation & Encoding
        encoded_matches = ENCODED_PATTERN.findall(original_url)
        encoded_char_count = len(encoded_matches)
        is_encoded = encoded_char_count > 0
        is_double_encoded = bool(DOUBLE_ENCODED_PATTERN.search(original_url))

        has_hex_obfuscation = bool(HEX_IP_PATTERN.match(hostname)) or ("0x" in hostname.lower())
        has_misleading_delimiter = "//" in path or ".." in hostname or "--" in hostname

        is_suspicious_tld = tld.lower() in self.settings.suspicious_tlds

        return UrlLexicalFeatures(
            original_url=original_url,
            normalized_url=normalized_url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            registered_domain=registered_domain,
            subdomain=subdomain,
            tld=tld,
            domain_depth=domain_depth,
            is_suspicious_tld=is_suspicious_tld,
            url_length=url_length,
            hostname_length=hostname_length,
            path_length=path_length,
            query_length=query_length,
            tld_length=tld_length,
            subdomain_length=subdomain_length,
            num_dots=num_dots,
            num_dots_hostname=num_dots_hostname,
            num_hyphens=num_hyphens,
            num_hyphens_hostname=num_hyphens_hostname,
            num_digits=num_digits,
            num_digits_hostname=num_digits_hostname,
            num_letters=num_letters,
            num_special_chars=num_special_chars,
            num_subdomains=num_subdomains,
            path_depth=path_depth,
            num_query_params=num_query_params,
            suspicious_keyword_count=suspicious_keyword_count,
            suspicious_keywords_found=found_keywords,
            has_suspicious_keyword=has_suspicious_keyword,
            is_ip_address=is_ip_address,
            ip_type=ip_type,
            is_private_ip=is_private_ip,
            max_consecutive_digits=max_consecutive_digits,
            digit_ratio=digit_ratio,
            max_character_repetition=max_character_repetition,
            has_excessive_repetition=has_excessive_repetition,
            url_entropy=url_entropy,
            hostname_entropy=hostname_entropy,
            path_entropy=path_entropy,
            query_entropy=query_entropy,
            is_punycode=is_punycode,
            is_idn=is_idn,
            has_homoglyphs=has_homoglyphs,
            homoglyph_details=homoglyph_details,
            is_encoded=is_encoded,
            is_double_encoded=is_double_encoded,
            encoded_char_count=encoded_char_count,
            has_at_symbol=has_at_symbol,
            has_hex_obfuscation=has_hex_obfuscation,
            has_misleading_delimiter=has_misleading_delimiter,
        )

    def analyze(self, raw_url: str) -> Layer1LexicalAnalysisResult:
        """Perform Layer 1 feature extraction and compute a multi-factor lexical risk score.

        Avoids automatically labelling a URL malicious based on a single factor (e.g. keywords or high entropy alone).
        Calculates a balanced weighted score with transparent risk indicators and explanations.
        """
        features = self.extract_features(raw_url)

        if not features.original_url:
            return Layer1LexicalAnalysisResult(
                component="C1_URL_DOMAIN",
                layer="Layer_1_Lexical_Feature_Extractor",
                status="invalid_input",
                url=features.original_url or str(raw_url or ""),
                score=0.0,
                risk_level="Low Risk",
                features=features,
                risk_indicators=["Empty or invalid URL provided."],
                explanation="Input URL was empty or contained only whitespace."
            )

        indicators: List[str] = []
        raw_score = 0.0

        # 1. IP address as host
        if features.is_ip_address:
            raw_score += 25.0
            indicators.append(f"Host is a raw IP address ({features.ip_type}).")
            if features.is_private_ip:
                raw_score += 15.0
                indicators.append("Host resolves to a private/internal IP space.")

        # 2. Homoglyph / Punycode / IDN
        if features.has_homoglyphs:
            raw_score += 30.0
            indicators.append("Homoglyph / lookalike confusable character detected in hostname.")
        elif features.is_punycode:
            raw_score += 15.0
            indicators.append("Punycode domain prefix (xn--) detected.")

        # 3. Obfuscation & Encoded delimiters
        if features.has_at_symbol:
            raw_score += 25.0
            indicators.append("Host contains suspicious '@' user-info authority delimiter.")
        if features.is_double_encoded:
            raw_score += 20.0
            indicators.append("Double URL percent-encoding (%25XX) detected.")
        if features.has_hex_obfuscation:
            raw_score += 20.0
            indicators.append("Hexadecimal IP or hex obfuscation detected in hostname.")

        # 4. TLD Risk
        if features.is_suspicious_tld:
            raw_score += 15.0
            indicators.append(f"High-risk top-level domain '.{features.tld}' detected.")

        # 5. Keywords (Weighted & capped to prevent single-factor false positives)
        if features.has_suspicious_keyword:
            kw_points = min(features.suspicious_keyword_count * 8.0, 24.0)
            raw_score += kw_points
            indicators.append(f"Suspicious security keyword(s) found: {', '.join(features.suspicious_keywords_found)}.")

        # 6. Subdomain & Path Depth
        if features.num_subdomains >= 3:
            raw_score += 15.0
            indicators.append(f"Excessive subdomain nesting ({features.num_subdomains} subdomains).")

        # 7. URL Length & Repetition
        if features.url_length > 120:
            raw_score += 15.0
            indicators.append(f"Excessively long URL ({features.url_length} characters).")
        elif features.url_length > 75:
            raw_score += 8.0
            indicators.append(f"Unusually long URL ({features.url_length} characters).")

        if features.has_excessive_repetition:
            raw_score += 10.0
            indicators.append(f"Excessive character repetition ({features.max_character_repetition} continuous identical chars).")

        # 8. High Hostname Entropy
        if features.hostname_entropy > 4.2 and not features.is_ip_address:
            raw_score += 12.0
            indicators.append(f"High hostname Shannon entropy ({features.hostname_entropy:.2f} bits/char).")

        # Cap score to [0.0, 100.0]
        final_score = round(min(max(raw_score, 0.0), 100.0), 1)

        # Determine risk label
        if final_score >= 75.0:
            risk_level = "High Risk Scam"
        elif final_score >= 50.0:
            risk_level = "Medium Risk"
        elif final_score >= 25.0:
            risk_level = "Suspicious"
        else:
            risk_level = "Low Risk"

        if not indicators:
            explanation = "URL exhibits standard structural characteristics with no suspicious lexical indicators."
        else:
            explanation = f"Extracted {len(indicators)} lexical risk indicator(s). Overall lexical sub-score: {final_score}/100."

        return Layer1LexicalAnalysisResult(
            component="C1_URL_DOMAIN",
            layer="Layer_1_Lexical_Feature_Extractor",
            status="success",
            url=features.original_url,
            score=final_score,
            risk_level=risk_level,
            features=features,
            risk_indicators=indicators,
            explanation=explanation,
        )

    def _empty_features(self) -> UrlLexicalFeatures:
        """Return zeroed features model for empty or invalid input handling."""
        return UrlLexicalFeatures(
            original_url="",
            normalized_url="",
            scheme="",
            hostname="",
            port=None,
            path="",
            query="",
            fragment="",
            registered_domain="",
            subdomain="",
            tld="",
            domain_depth=0,
            is_suspicious_tld=False,
            url_length=0,
            hostname_length=0,
            path_length=0,
            query_length=0,
            tld_length=0,
            subdomain_length=0,
            num_dots=0,
            num_dots_hostname=0,
            num_hyphens=0,
            num_hyphens_hostname=0,
            num_digits=0,
            num_digits_hostname=0,
            num_letters=0,
            num_special_chars=0,
            num_subdomains=0,
            path_depth=0,
            num_query_params=0,
            suspicious_keyword_count=0,
            suspicious_keywords_found=[],
            has_suspicious_keyword=False,
            is_ip_address=False,
            ip_type="none",
            is_private_ip=False,
            max_consecutive_digits=0,
            digit_ratio=0.0,
            max_character_repetition=0,
            has_excessive_repetition=False,
            url_entropy=0.0,
            hostname_entropy=0.0,
            path_entropy=0.0,
            query_entropy=0.0,
            is_punycode=False,
            is_idn=False,
            has_homoglyphs=False,
            homoglyph_details=[],
            is_encoded=False,
            is_double_encoded=False,
            encoded_char_count=0,
            has_at_symbol=False,
            has_hex_obfuscation=False,
            has_misleading_delimiter=False,
        )

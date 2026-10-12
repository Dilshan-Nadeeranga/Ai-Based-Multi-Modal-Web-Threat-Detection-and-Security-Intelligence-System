"""Controlled HTTP Redirect-Resolution & URL Shortener Intelligence Analyzer.

Resolves shortened URLs and inspects HTTP redirect chains (301, 302, 303, 307, 308)
using strict passive header inspection with zero JavaScript execution or HTML rendering.

Enforces SSRF prevention, DNS-rebinding checks, hop limits, loop detection, and connection timeouts.
Network resolution is cleanly decoupled from feature extraction to enable independent testing.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit

import httpx
import tldextract

from app.config import get_settings
from app.schemas.url_schema import RedirectChainFeatures, RedirectHop
from app.utils.ssrf_validator import SsrfValidator

logger = logging.getLogger(__name__)

REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}


class ShortenerDetector:
    """Detector for identifying known and heuristic URL shortener services."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def detect(self, url: str) -> Tuple[bool, Optional[str]]:
        """Determine whether a URL belongs to a recognized URL shortener.

        Returns:
            (is_shortened, shortener_provider)
        """
        try:
            parsed = urlsplit(url)
            hostname = (parsed.hostname or "").lower()
        except Exception:
            return False, None

        if not hostname:
            return False, None

        extracted = tldextract.extract(hostname)
        registered_domain = getattr(extracted, "top_domain_under_public_suffix", "") or extracted.registered_domain
        registered_domain = registered_domain.lower()

        # 1. Exact match against known shortener registry
        for shortener in self.settings.known_shorteners:
            if hostname == shortener or registered_domain == shortener:
                provider_name = shortener.split(".")[0].capitalize()
                return True, provider_name

        # 2. Heuristic shortener pattern: very short domain with short hash path
        path = parsed.path.strip("/")
        if len(registered_domain) <= 8 and 2 <= len(path) <= 12 and not parsed.query:
            return True, "GenericShortener"

        return False, None


class RedirectFeatureExtractor:
    """Pure, offline feature extractor for analyzing recorded redirect hops.

    Separated completely from network resolution to allow deterministic unit testing.
    """

    def __init__(self) -> None:
        self.settings = get_settings()

    def extract_features(
        self,
        original_url: str,
        chain_hops: List[RedirectHop],
        is_shortened: bool,
        shortener_provider: Optional[str],
        has_redirect_loop: bool = False,
        ssrf_blocked: bool = False,
        error_message: Optional[str] = None,
    ) -> RedirectChainFeatures:
        """Derive structured metrics and indicators from an ordered list of redirect hops."""
        total_hops = max(0, len(chain_hops) - 1)
        is_redirected = total_hops > 0
        final_url = chain_hops[-1].url if chain_hops else original_url

        orig_host = urlsplit(original_url).hostname or ""
        final_host = urlsplit(final_url).hostname or ""

        orig_ext = tldextract.extract(orig_host)
        final_ext = tldextract.extract(final_host)

        orig_domain = (getattr(orig_ext, "top_domain_under_public_suffix", "") or orig_ext.registered_domain).lower()
        final_domain = (getattr(final_ext, "top_domain_under_public_suffix", "") or final_ext.registered_domain).lower()

        destination_domain_changed = bool(orig_domain and final_domain and orig_domain != final_domain)
        has_cross_domain_redirect = any(hop.is_cross_domain for hop in chain_hops)
        has_excessive_redirects = total_hops >= 5

        indicators: List[str] = []

        if is_shortened:
            indicators.append(
                f"URL shortener detected ({shortener_provider or 'Shortener'})."
            )

        if total_hops > 0:
            indicators.append(f"Redirect chain observed with {total_hops} hop(s).")

        if destination_domain_changed:
            indicators.append(
                f"Cross-domain redirect destination: transitioned from '{orig_domain}' to '{final_domain}'."
            )

        if orig_ext.suffix and final_ext.suffix and orig_ext.suffix != final_ext.suffix:
            indicators.append(
                f"Top-Level Domain changed during redirection: (.{orig_ext.suffix} -> .{final_ext.suffix})."
            )

        if has_excessive_redirects:
            indicators.append(
                f"Excessive redirect chain length ({total_hops} hops exceeds standard navigation norm)."
            )

        if has_redirect_loop:
            indicators.append("Cyclic redirect loop detected and safely terminated.")

        if ssrf_blocked:
            indicators.append(f"SSRF Security Violation: Redirection aborted ({error_message}).")

        # Check if final destination is raw IP address
        if final_host.replace(".", "").isdigit():
            indicators.append(f"Terminal destination URL resolves directly to an IP address ({final_host}).")

        return RedirectChainFeatures(
            original_url=original_url,
            final_url=final_url,
            is_shortened=is_shortened,
            shortener_provider=shortener_provider,
            total_hops=total_hops,
            is_redirected=is_redirected,
            has_redirect_loop=has_redirect_loop,
            has_cross_domain_redirect=has_cross_domain_redirect,
            has_excessive_redirects=has_excessive_redirects,
            destination_domain_changed=destination_domain_changed,
            ssrf_blocked=ssrf_blocked,
            error_message=error_message,
            chain_hops=chain_hops,
            redirect_indicators=indicators,
        )


class ControlledRedirectResolver:
    """Safe HTTP redirect resolver enforcing SSRF prevention and connection bounds.

    Inspects only HTTP status codes and Location headers; never downloads full bodies or executes scripts.
    """

    def __init__(self) -> None:
        self.settings = get_settings()
        self.ssrf_validator = SsrfValidator()
        self.shortener_detector = ShortenerDetector()
        self.feature_extractor = RedirectFeatureExtractor()

    async def resolve(self, initial_url: str) -> RedirectChainFeatures:
        """Safely trace HTTP redirect hops for the given URL.

        Returns structured RedirectChainFeatures with verified hops and security indicators.
        """
        clean_url = initial_url.strip()
        is_shortened, provider = self.shortener_detector.detect(clean_url)

        # 1. Validate origin URL against SSRF policy
        is_safe, reason, initial_ips = self.ssrf_validator.validate_url(clean_url)
        if not is_safe:
            return self.feature_extractor.extract_features(
                original_url=clean_url,
                chain_hops=[],
                is_shortened=is_shortened,
                shortener_provider=provider,
                ssrf_blocked=True,
                error_message=reason,
            )

        visited_urls: Set[str] = set()
        hops: List[RedirectHop] = []
        current_url = clean_url
        current_ip = initial_ips[0] if initial_ips else None
        prev_domain = urlsplit(current_url).hostname or ""
        has_loop = False
        ssrf_blocked = False
        error_msg: Optional[str] = None

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        async with httpx.AsyncClient(
            timeout=self.settings.redirect_timeout_seconds,
            follow_redirects=False,
            verify=True,
        ) as client:
            for hop_idx in range(self.settings.max_redirect_hops):
                if current_url in visited_urls:
                    has_loop = True
                    break
                visited_urls.add(current_url)

                curr_domain = urlsplit(current_url).hostname or ""
                is_cross = bool(prev_domain and curr_domain and prev_domain != curr_domain)

                # Attempt passive HTTP HEAD request first (zero body download)
                response = None
                try:
                    res = await client.head(current_url, headers=headers)
                    # Some servers return 405 Method Not Allowed for HEAD; fallback to streamed GET
                    if res.status_code == 405:
                        async with client.stream("GET", current_url, headers=headers) as stream_res:
                            status_code = stream_res.status_code
                            location = stream_res.headers.get("location")
                    else:
                        status_code = res.status_code
                        location = res.headers.get("location")
                except httpx.TimeoutException:
                    error_msg = f"Connection timed out at hop {hop_idx}"
                    break
                except httpx.RequestError as exc:
                    error_msg = f"Network request error at hop {hop_idx}: {exc}"
                    break
                except Exception as exc:
                    error_msg = f"Unexpected error at hop {hop_idx}: {exc}"
                    break

                hops.append(
                    RedirectHop(
                        hop_number=hop_idx,
                        url=current_url,
                        domain=curr_domain,
                        status_code=status_code,
                        resolved_ip=current_ip,
                        is_cross_domain=is_cross,
                        location_header=location,
                    )
                )

                # Check if this status code represents a redirect
                if status_code in REDIRECT_STATUS_CODES and location:
                    next_url = urljoin(current_url, location.strip())

                    # Validate next hop against SSRF & DNS rebinding
                    is_safe_next, next_reason, next_ips = self.ssrf_validator.validate_url(next_url)
                    if not is_safe_next:
                        ssrf_blocked = True
                        error_msg = f"Hop {hop_idx + 1} blocked by SSRF policy: {next_reason}"
                        break

                    prev_domain = curr_domain
                    current_url = next_url
                    current_ip = next_ips[0] if next_ips else None
                else:
                    # Terminal destination reached (200, 404, etc.)
                    break

        return self.feature_extractor.extract_features(
            original_url=clean_url,
            chain_hops=hops,
            is_shortened=is_shortened,
            shortener_provider=provider,
            has_redirect_loop=has_loop,
            ssrf_blocked=ssrf_blocked,
            error_message=error_msg,
        )

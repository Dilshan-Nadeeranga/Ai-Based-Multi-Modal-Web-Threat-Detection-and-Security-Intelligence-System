"""SSRF & DNS-Rebinding Prevention Security Validator.

Validates destination schemes, hostnames, and resolved IP addresses to ensure no HTTP request
targets loopback, RFC-1918 private subnets, link-local, cloud metadata services, or reserved spaces.
Evaluated independently before and after every redirect step to block DNS-rebinding attacks.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import List, Tuple
from urllib.parse import urlsplit

from app.config import get_settings

logger = logging.getLogger(__name__)

# Cloud metadata IP addresses & hostnames
CLOUD_METADATA_IPS = {
    "169.254.169.254",   # AWS, GCP, Azure, OpenStack
    "100.100.100.200",   # Alibaba Cloud
    "192.0.0.170",       # Oracle Cloud
    "192.0.0.171",
}
CLOUD_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}

# Blocked schemes
ALLOWED_SCHEMES = {"http", "https"}


def is_ip_blocked(ip_str: str, allow_private_for_test: bool = False) -> Tuple[bool, str]:
    """Check if an IPv4 or IPv6 string falls into a prohibited/unsafe subnet."""
    clean_ip = ip_str.strip("[]").strip()
    if clean_ip in CLOUD_METADATA_IPS:
        return True, f"Prohibited cloud metadata address: {clean_ip}"

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return True, f"Invalid IP address format: {clean_ip}"

    # Handle IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    if allow_private_for_test:
        return False, "Allowed by test configuration"

    if ip_obj.is_loopback:
        return True, f"Prohibited loopback address: {clean_ip}"
    if ip_obj.is_private:
        return True, f"Prohibited RFC-1918 private address: {clean_ip}"
    if ip_obj.is_link_local:
        return True, f"Prohibited link-local address: {clean_ip}"
    if ip_obj.is_multicast:
        return True, f"Prohibited multicast address: {clean_ip}"
    if ip_obj.is_reserved:
        return True, f"Prohibited reserved address: {clean_ip}"
    if ip_obj.is_unspecified:
        return True, f"Prohibited unspecified address (0.0.0.0 / ::): {clean_ip}"

    return False, "Public IP validated"


class SsrfValidator:
    """Security validator for inspecting URLs and resolving target IPs safely."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def validate_url(self, target_url: str) -> Tuple[bool, str, List[str]]:
        """Validate URL scheme, hostname, and resolve DNS to ensure all IPs are safe.

        Returns:
            (is_safe, reason, resolved_ips)
        """
        if not target_url or not isinstance(target_url, str):
            return False, "Empty or invalid URL", []

        try:
            parsed = urlsplit(target_url.strip())
        except Exception as exc:
            return False, f"Malformed URL: {exc}", []

        # 1. Scheme check
        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            return False, f"Disallowed scheme '{scheme}'. Only HTTP and HTTPS are permitted.", []

        # 2. Hostname check
        hostname = (parsed.hostname or "").strip().lower()
        if not hostname:
            return False, "URL lacks a valid hostname", []

        if hostname in CLOUD_METADATA_HOSTS:
            return False, f"Prohibited cloud metadata hostname: {hostname}", []

        # Check if hostname itself is directly a numeric/hex/literal IP
        try:
            ip_obj = ipaddress.ip_address(hostname.strip("[]"))
            blocked, reason = is_ip_blocked(str(ip_obj), self.settings.allow_private_ips_for_test)
            if blocked:
                return False, reason, [str(ip_obj)]
            return True, "Literal IP validated", [str(ip_obj)]
        except ValueError:
            pass

        # 3. DNS resolution check (resolve hostname to ensure it doesn't resolve to internal IP)
        resolved_ips: List[str] = []
        try:
            addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
            for item in addr_info:
                sockaddr = item[4]
                ip_candidate = sockaddr[0]
                if ip_candidate not in resolved_ips:
                    resolved_ips.append(ip_candidate)
        except socket.gaierror as exc:
            return False, f"DNS resolution failed: {exc}", []
        except Exception as exc:
            return False, f"Unexpected error during DNS resolution: {exc}", []

        if not resolved_ips:
            return False, "Hostname did not resolve to any IP address", []

        # Validate EVERY resolved IP address
        for ip_addr in resolved_ips:
            blocked, reason = is_ip_blocked(ip_addr, self.settings.allow_private_ips_for_test)
            if blocked:
                logger.warning("SSRF blocked destination %s -> %s (%s)", hostname, ip_addr, reason)
                return False, f"Destination resolves to prohibited address: {reason}", resolved_ips

        return True, "Destination safely validated", resolved_ips

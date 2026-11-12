"""Tailscale address ranges the Agent never uses to reach the Main (Issue #150).

Capture enrollment and ingest are private-LAN only and need no Tailscale on
either host (Owner decision 2026-10-07). The Agent therefore refuses a Main
endpoint in a Tailscale range, whether it comes from the trust bundle, the
``pair --endpoint`` override, or a DNS name that resolved into one of them.

These are the same two documented ranges the Main uses
(``server/app/cameras/remote_agent/addresses.py``); the Agent is a separate,
stdlib-only package and cannot import the server, so the values are repeated
here and ``tests/unit/test_tailscale_ranges_match.py`` keeps both copies equal:

* IPv4 shared address space ``100.64.0.0/10`` (RFC 6598 CGNAT);
* IPv6 ULA prefix ``fd7a:115c:a1e0::/48`` (being "private" does not exempt it).

Classification is by address only: another private network that reuses one of
these ranges is refused too.
"""
from __future__ import annotations

import ipaddress
import re

_DNS_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
TAILSCALE_NETWORKS = (
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv6Network("fd7a:115c:a1e0::/48"),
)


def is_tailscale_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True when ``address`` (or its IPv4-mapped form) is in a Tailscale range."""
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    return any(address in network for network in TAILSCALE_NETWORKS
               if network.version == address.version)


def is_tailscale_host(host: object) -> bool:
    """True when ``host`` is an IP literal in a Tailscale range.

    A DNS name is not resolved here and returns False; the connected peer
    address is checked separately after the TCP connect.
    """
    if not isinstance(host, str):
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return is_tailscale_address(address)


def valid_server_name(value: object) -> bool:
    """A lowercase DNS name with at least two labels (the bundle's server name)."""
    if not isinstance(value, str) or not value.isascii() or not 0 < len(value) <= 253:
        return False
    if value != value.lower() or value.endswith("."):
        return False
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    labels = value.split(".")
    return len(labels) >= 2 and all(_DNS_LABEL.fullmatch(label) for label in labels)


def valid_endpoint_host(value: object) -> bool:
    """A usable Main endpoint: a DNS name, or an IP literal that is not unspecified/multicast."""
    if not isinstance(value, str) or not value.isascii():
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return valid_server_name(value)
    return not (address.is_unspecified or address.is_multicast)

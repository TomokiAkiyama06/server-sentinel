"""Address classification shared by the capture listeners (Issue #150).

Capture enrollment and ingest are private-LAN only and need no Tailscale on
either host, so neither listener may bind a Tailscale address. Tailscale
assigns node addresses from two documented ranges: the IPv4 shared address
space ``100.64.0.0/10`` (RFC 6598 CGNAT) and the IPv6 ULA prefix
``fd7a:115c:a1e0::/48``. The IPv6 prefix is a ULA, so ``is_private`` alone
does not exclude it; it is matched explicitly here. MagicDNS
(``100.100.100.100``, ``fd7a:115c:a1e0::53``) and 4via6 subnet-router
addresses (``fd7a:115c:a1e0:b1a::/64``) fall inside these ranges.

The ranges are classified by address only: this module does not ask the
Tailscale daemon or inspect interfaces, so it also refuses an address from
those ranges that some other CGNAT/ULA deployment happens to use.
"""
from __future__ import annotations

import ipaddress

TAILSCALE_NETWORKS = (
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv6Network("fd7a:115c:a1e0::/48"),
)


def socket_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address):
    """The IPv4 form of an IPv4-mapped IPv6 address, else the address itself.

    Linux treats ``::ffff:a.b.c.d`` and ``a.b.c.d`` as the same socket, so
    both spellings must be classified and compared the same way.
    """
    mapped = getattr(address, "ipv4_mapped", None)
    return address if mapped is None else mapped


def is_tailscale_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True when ``address`` (or its IPv4-mapped form) is in a Tailscale range."""
    address = socket_address(address)
    return any(address in network for network in TAILSCALE_NETWORKS
               if network.version == address.version)

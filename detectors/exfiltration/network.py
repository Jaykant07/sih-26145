"""
Network classification utilities for Exfiltration Detection (PS-26145 — Track B).

Provides IP address classification to distinguish internal network assets
from external destinations. Avoids hardcoding public IP ranges by supporting
configurable CIDR networks (defaulting to RFC 1918 private ranges, loopback,
link-local, multicast, and explicit lab subnets).
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Iterable, Optional

logger = logging.getLogger("exfiltration.network")

# Default internal networks: RFC 1918, loopback, link-local, and lab subnets
DEFAULT_INTERNAL_NETWORKS: list[str] = [
    "10.0.0.0/8",         # RFC 1918 Class A
    "172.16.0.0/12",       # RFC 1918 Class B (includes 172.16.0.0/16 lab hosts)
    "192.168.0.0/16",      # RFC 1918 Class C (includes 192.168.56.0/24 lab hosts)
    "127.0.0.0/8",         # Loopback
    "169.254.0.0/16",      # Link-local
]

# Non-routable / special destination networks that are never valid external exfil targets
SPECIAL_NON_EXTERNAL_NETWORKS: list[str] = [
    "224.0.0.0/4",         # Multicast (e.g. 224.0.0.252 LLMNR)
    "239.0.0.0/8",         # Administratively scoped multicast
    "255.255.255.255/32",  # Limited broadcast
    "0.0.0.0/8",           # Current network
]


class NetworkClassifier:
    """
    Classifies IP addresses as internal or external based on CIDR subnet definitions.
    """

    def __init__(
        self,
        internal_subnets: Optional[Iterable[str]] = None,
        exclude_special: bool = True,
    ) -> None:
        subnets_to_use = internal_subnets if internal_subnets is not None else DEFAULT_INTERNAL_NETWORKS
        self.internal_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

        for cidr in subnets_to_use:
            try:
                self.internal_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as err:
                logger.warning("Invalid internal CIDR subnet '%s': %s", cidr, err)

        self.special_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        if exclude_special:
            for cidr in SPECIAL_NON_EXTERNAL_NETWORKS:
                try:
                    self.special_networks.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass

    def is_internal(self, ip_str: str) -> bool:
        """Return True if the given IP address falls within internal networks."""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False

        return any(ip_obj in net for net in self.internal_networks)

    def is_external(self, ip_str: str) -> bool:
        """
        Return True if the given IP address is considered an external destination.
        Returns False for internal IPs and non-routable special addresses.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False

        # Internal IPs are not external
        if any(ip_obj in net for net in self.internal_networks):
            return False

        # Special non-external addresses (multicast, broadcast) are not external targets
        if any(ip_obj in net for net in self.special_networks):
            return False

        return True

    def is_internal_to_external(self, src_ip: str, dst_ip: str) -> bool:
        """
        Return True only if source is internal and destination is external.
        Excludes internal-to-internal traffic and external-to-internal downloads.
        """
        return self.is_internal(src_ip) and self.is_external(dst_ip)

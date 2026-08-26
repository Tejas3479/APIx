import asyncio
import ipaddress
import os
import socket
from urllib.parse import urlparse

from .log_filter import logger

# RESTRICTED IP NETWORKS & HOSTNAMES FOR ENHANCED SSRF PROTECTION
RESTRICTED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # AWS/Azure IMDS & Link-Local
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT & Cloud Internal
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba IMDS
    ipaddress.ip_network("10.96.0.0/12"),  # Kubernetes Service CIDR
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10"),  # IPv6 Link-Local
]

RESTRICTED_HOSTNAME_SUFFIXES = (
    ".internal",
    ".local",
    ".localhost",
    ".cluster.local",
    ".localdomain",
)

RESTRICTED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.gcp.internal",
}


NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")


def _is_ip_restricted(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # NAT64 well-known prefix (64:ff9b::/96) embeds a public IPv4 in its last
    # 32 bits. Extract it and re-check so private/loopback IPv4s cannot sneak
    # through NAT64 encoding.
    if ip.version == 6 and ip in NAT64_PREFIX:
        embedded_v4 = ipaddress.ip_address(int(ip) & 0xFFFFFFFF)
        return _is_ip_restricted(embedded_v4)

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    return any(ip in net for net in RESTRICTED_NETWORKS)


async def is_ssrf_safe(url: str) -> bool:
    """Enhanced async-safe SSRF check validating URL schemes, cloud metadata IPs, and restricted network ranges."""
    if os.getenv("DISABLE_SSRF_CHECK") == "true":
        return True
    try:
        parsed = urlparse(url)
        # 1. Scheme Validation
        if not parsed.scheme or parsed.scheme.lower() not in ("http", "https"):
            return False

        host = parsed.hostname
        if not host:
            return False

        host_lower = host.lower().strip()

        # 2. Hostname / Domain Blocklist
        if host_lower in RESTRICTED_HOSTNAMES or host_lower.endswith(
            RESTRICTED_HOSTNAME_SUFFIXES
        ):
            return False

        # 3. Direct IP Address Check
        try:
            ip = ipaddress.ip_address(host_lower)
            return not _is_ip_restricted(ip)
        except ValueError:
            pass

        # 4. Async DNS Resolution Check
        loop = asyncio.get_running_loop()
        addr_info = await loop.run_in_executor(
            None, socket.getaddrinfo, host_lower, None
        )
        for _family, _type, _proto, _canonname, sockaddr in addr_info:
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            if _is_ip_restricted(ip):
                return False
        return True
    except Exception as e:
        logger.error(f"SSRF safety check failed for {url}: {e}")
        return False

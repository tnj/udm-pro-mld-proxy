#!/usr/bin/env python3
"""
Simple MLD Proxy for Solicited-Node Multicast Addresses

Monitors NDP (NS/NA) on the downstream interface (br0) to discover
LAN hosts' IPv6 addresses, and joins the corresponding Solicited-Node
multicast groups on the upstream interface (eth9).

The kernel automatically sends MLD Reports when joining groups,
which allows NDP to work through a router when the upstream gateway
performs MLD Snooping.

Usage: sudo python3 mld_proxy.py <upstream_if> <downstream_if>
Example: sudo python3 mld_proxy.py eth9 br0
"""

import logging
import socket
import struct
import sys
import select
import time

logger = logging.getLogger("mld-proxy")

# ICMPv6 types
ICMPV6_NS = 135
ICMPV6_NA = 136

# Solicited-Node prefix
SOLICITED_NODE_PREFIX = b'\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff'

# ICMP6_FILTER socket option (not exposed in Python's socket module)
ICMP6_FILTER = 1

# Address expiry timeout (seconds)
# Addresses not seen in NDP traffic for this duration are considered stale.
ADDR_TIMEOUT = 1800

# Expiry check interval (seconds)
EXPIRY_CHECK_INTERVAL = 30

# select() timeout for the main loop (seconds)
SELECT_TIMEOUT = 1.0


def solicited_node_addr_from_bytes(addr_bytes):
    """Compute Solicited-Node multicast address from 16-byte IPv6 address"""
    return SOLICITED_NODE_PREFIX + addr_bytes[13:16]


def format_ipv6(addr_bytes):
    """Format 16-byte address as IPv6 string"""
    return socket.inet_ntop(socket.AF_INET6, addr_bytes)


def is_link_local(addr_bytes):
    """Check if address is link-local (fe80::/10)"""
    return addr_bytes[0] == 0xfe and (addr_bytes[1] & 0xc0) == 0x80


class MLDProxy:
    def __init__(self, upstream_if, downstream_if):
        self.upstream_if = upstream_if
        self.downstream_if = downstream_if
        self.upstream_idx = socket.if_nametoindex(upstream_if)

        # Track joined Solicited-Node addresses:
        #   sn_addr_bytes -> (dict of {target_addr_bytes: last_seen_time}, join_socket)
        self.joined_groups = {}

        # Create raw socket to receive NDP on downstream
        self.ndp_sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        self.ndp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                                  downstream_if.encode() + b'\x00')

        # Set ICMPv6 filter to only receive NS and NA
        icmp6_filter = bytearray(32)
        for t in (ICMPV6_NS, ICMPV6_NA):
            icmp6_filter[t // 8] |= (1 << (t % 8))
        icmp6_filter = bytes(b ^ 0xff for b in icmp6_filter)
        self.ndp_sock.setsockopt(socket.IPPROTO_ICMPV6, ICMP6_FILTER, icmp6_filter)

        logger.info("MLD Proxy: %s -> %s", downstream_if, upstream_if)

    def kernel_join(self, sn_addr):
        """Join multicast group at kernel level.

        The kernel automatically sends MLD Report when joining and
        responds to MLD Queries, so no manual MLD handling is needed.
        """
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            mreq = sn_addr + struct.pack("I", self.upstream_idx)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
            logger.info("Joined: %s on %s", format_ipv6(sn_addr), self.upstream_if)
            return sock
        except OSError as e:
            logger.error("Failed to join %s: %s", format_ipv6(sn_addr), e)
            return None

    def add_address(self, target_addr):
        """Add a target address and join its Solicited-Node group if new"""
        if is_link_local(target_addr):
            return

        now = time.time()
        sn = solicited_node_addr_from_bytes(target_addr)

        if sn in self.joined_groups:
            addrs, join_sock = self.joined_groups[sn]
            addrs[target_addr] = now
            return

        # New Solicited-Node group
        join_sock = self.kernel_join(sn)
        if join_sock is None:
            return
        self.joined_groups[sn] = ({target_addr: now}, join_sock)

    def expire_stale(self):
        """Remove addresses not seen recently and leave empty groups"""
        now = time.time()

        for sn in list(self.joined_groups.keys()):
            addrs, join_sock = self.joined_groups[sn]

            # Remove expired addresses
            expired = [addr for addr, ts in addrs.items() if now - ts >= ADDR_TIMEOUT]
            for addr in expired:
                logger.info("Expired: %s", format_ipv6(addr))
                del addrs[addr]

            # If no addresses remain, leave the group
            if not addrs:
                self._leave_group(sn, join_sock)
                del self.joined_groups[sn]

    def _leave_group(self, sn_addr, join_sock):
        """Leave a multicast group by closing its socket.

        Kernel sends MLD Leave automatically when the socket is closed.
        """
        logger.info("Left: %s on %s", format_ipv6(sn_addr), self.upstream_if)
        join_sock.close()

    def close(self):
        """Clean up all sockets"""
        for sn, (_, join_sock) in self.joined_groups.items():
            self._leave_group(sn, join_sock)
        self.joined_groups.clear()
        self.ndp_sock.close()

    def handle_ndp(self, data):
        """Handle received NDP message (NS or NA)"""
        if len(data) < 24:
            return

        icmp_type = data[0]

        if icmp_type in (ICMPV6_NS, ICMPV6_NA):
            # Target address at offset 8 (after type, code, checksum, reserved/flags)
            target = data[8:24]
            self.add_address(target)

    def run(self):
        """Main loop"""
        logger.info("Listening for NDP on downstream...")

        last_expiry_check = time.time()

        try:
            while True:
                readable, _, _ = select.select([self.ndp_sock], [], [], SELECT_TIMEOUT)
                if self.ndp_sock in readable:
                    data, _ = self.ndp_sock.recvfrom(4096)
                    self.handle_ndp(data)

                now = time.time()

                if now - last_expiry_check >= EXPIRY_CHECK_INTERVAL:
                    self.expire_stale()
                    last_expiry_check = now

        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.close()


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <upstream_if> <downstream_if>")
        print(f"Example: {sys.argv[0]} eth9 br0")
        sys.exit(1)

    upstream_if = sys.argv[1]
    downstream_if = sys.argv[2]

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    proxy = MLDProxy(upstream_if, downstream_if)
    proxy.run()


if __name__ == "__main__":
    main()

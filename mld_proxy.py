#!/usr/bin/env python3
"""
Simple MLD Proxy for Solicited-Node Multicast Addresses

Monitors NDP (NS/NA) on the downstream interface (br0) to discover
LAN hosts' IPv6 addresses, and joins the corresponding Solicited-Node
multicast groups on the upstream interface (eth9).

Additionally, periodically scans the kernel's neighbor table via Netlink
to maintain multicast group membership for hosts that remain in the
neighbor cache (even in STALE state), preventing premature group leaves.

The kernel automatically sends MLD Reports when joining groups,
which allows NDP to work through a router when the upstream gateway
performs MLD Snooping.

Usage: sudo python3 mld_proxy.py <upstream_if> <downstream_if> [--fix-ndppd-ttl]
Example: sudo python3 mld_proxy.py eth9 br0
         sudo python3 mld_proxy.py eth9 br0 --fix-ndppd-ttl
"""

import argparse
import logging
import os
import re
import socket
import struct
import subprocess
import sys
import select
import time

logger = logging.getLogger("mld-proxy")

# Netlink constants
NETLINK_ROUTE = 0
RTM_GETNEIGH = 30
RTM_NEWNEIGH = 28
NLM_F_REQUEST = 0x01
NLM_F_DUMP = 0x300
NLMSG_DONE = 3
NLMSG_ERROR = 2

# Neighbor Discovery Attribute types
NDA_DST = 1

# Neighbor states (valid states for our purposes)
NUD_REACHABLE = 0x02
NUD_STALE = 0x04
NUD_DELAY = 0x08
NUD_PROBE = 0x10
NUD_PERMANENT = 0x80
NUD_VALID_STATES = (NUD_REACHABLE, NUD_STALE, NUD_DELAY, NUD_PROBE, NUD_PERMANENT)

# ICMPv6 types
ICMPV6_NS = 135
ICMPV6_NA = 136

# Solicited-Node prefix
SOLICITED_NODE_PREFIX = b'\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff'

# ICMP6_FILTER socket option (not exposed in Python's socket module)
ICMP6_FILTER = 1

# Address expiry timeout (seconds)
# Addresses not seen in NDP traffic or neighbor table for this duration are
# considered stale.
ADDR_TIMEOUT = 1800

# Expiry check interval (seconds)
EXPIRY_CHECK_INTERVAL = 30

# Neighbor table scan interval (seconds)
NEIGHBOR_SCAN_INTERVAL = 60

# select() timeout for the main loop (seconds)
SELECT_TIMEOUT = 1.0

# Route metric adjustment: new metric will be original / ROUTE_METRIC_DIVISOR
ROUTE_METRIC_DIVISOR = 2

# Route priority check interval (seconds)
# RA may re-add routes with the original metric, so we check periodically
ROUTE_CHECK_INTERVAL = 300

# ndppd TTL configuration
NDPPD_TTL_DEFAULT = 30000
NDPPD_TTL_EXTENDED = 3600000


def get_ipv6_neighbors(ifindex):
    """Get IPv6 neighbor addresses for a specific interface using Netlink.

    Returns a list of 16-byte IPv6 addresses that are in valid states
    (REACHABLE, STALE, DELAY, PROBE, or PERMANENT).
    """
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_ROUTE)
    sock.bind((0, 0))

    try:
        # Build RTM_GETNEIGH request
        # struct ndmsg: family(1) + pad(3) + ifindex(4) + state(2) + flags(1) + type(1)
        ndmsg = struct.pack("BxxxiHBB", socket.AF_INET6, ifindex, 0, 0, 0)

        # struct nlmsghdr: len(4) + type(2) + flags(2) + seq(4) + pid(4)
        nlmsg_len = 16 + len(ndmsg)
        nlmsghdr = struct.pack(
            "IHHII", nlmsg_len, RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP, 1, 0
        )

        sock.send(nlmsghdr + ndmsg)

        neighbors = []

        while True:
            data = sock.recv(65536)
            offset = 0

            while offset < len(data):
                # Parse nlmsghdr
                if offset + 16 > len(data):
                    break

                nlmsg_len, nlmsg_type, _, _, _ = struct.unpack_from(
                    "IHHII", data, offset
                )

                if nlmsg_type == NLMSG_DONE:
                    return neighbors

                if nlmsg_type == NLMSG_ERROR:
                    return neighbors

                if nlmsg_type == RTM_NEWNEIGH:
                    # Parse ndmsg (12 bytes after nlmsghdr)
                    ndmsg_offset = offset + 16
                    if ndmsg_offset + 12 <= len(data):
                        family, nd_ifindex, state, _, _ = struct.unpack_from(
                            "BxxxiHBB", data, ndmsg_offset
                        )

                        if family == socket.AF_INET6 and nd_ifindex == ifindex:
                            # Parse attributes to find NDA_DST
                            attr_offset = ndmsg_offset + 12

                            while attr_offset + 4 <= offset + nlmsg_len:
                                rta_len, rta_type = struct.unpack_from(
                                    "HH", data, attr_offset
                                )
                                if rta_len < 4:
                                    break

                                if rta_type == NDA_DST and rta_len >= 4 + 16:
                                    dst_addr = data[attr_offset + 4 : attr_offset + 4 + 16]
                                    if state in NUD_VALID_STATES:
                                        neighbors.append(dst_addr)
                                    break

                                # Align to 4 bytes
                                attr_offset += (rta_len + 3) & ~3

                # Move to next message (aligned to 4 bytes)
                offset += (nlmsg_len + 3) & ~3

        return neighbors
    finally:
        sock.close()


def solicited_node_addr_from_bytes(addr_bytes):
    """Compute Solicited-Node multicast address from 16-byte IPv6 address"""
    return SOLICITED_NODE_PREFIX + addr_bytes[13:16]


def format_ipv6(addr_bytes):
    """Format 16-byte address as IPv6 string"""
    return socket.inet_ntop(socket.AF_INET6, addr_bytes)


def is_link_local(addr_bytes):
    """Check if address is link-local (fe80::/10)"""
    return addr_bytes[0] == 0xfe and (addr_bytes[1] & 0xc0) == 0x80


def get_ipv6_routes():
    """Get IPv6 routes from the kernel routing table.

    Returns a list of dicts with keys: prefix, dev, metric, proto
    """
    try:
        result = subprocess.run(
            ["ip", "-6", "route", "show"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.warning("Failed to get IPv6 routes: %s", e)
        return []

    routes = []

    for line in result.stdout.splitlines():
        # Skip default routes and link-local
        if line.startswith("default") or line.startswith("fe80:"):
            continue

        # Parse prefix and dev (required)
        prefix_match = re.match(r"^(\S+)\s+dev\s+(\S+)", line)
        if not prefix_match:
            continue

        prefix, dev = prefix_match.groups()

        # Extract metric (optional, search anywhere in line)
        metric_match = re.search(r"metric\s+(\d+)", line)
        metric = int(metric_match.group(1)) if metric_match else 0

        # Extract proto (optional)
        proto_match = re.search(r"proto\s+(\S+)", line)
        proto = proto_match.group(1) if proto_match else ""

        routes.append({
            "prefix": prefix,
            "dev": dev,
            "metric": metric,
            "proto": proto,
        })

    return routes


def fix_route_priority(upstream_if, downstream_if):
    """Fix route priority when upstream and downstream have the same prefix/metric.

    If both interfaces have routes to the same prefix with the same metric,
    add a higher-priority route (lower metric) for the downstream interface.
    """
    routes = get_ipv6_routes()

    # Group routes by prefix
    routes_by_prefix = {}
    for route in routes:
        prefix = route["prefix"]
        if prefix not in routes_by_prefix:
            routes_by_prefix[prefix] = []
        routes_by_prefix[prefix].append(route)

    for prefix, prefix_routes in routes_by_prefix.items():
        upstream_route = None
        downstream_route = None

        for route in prefix_routes:
            if route["dev"] == upstream_if:
                upstream_route = route
            elif route["dev"] == downstream_if:
                downstream_route = route

        if upstream_route and downstream_route:
            if upstream_route["metric"] == downstream_route["metric"]:
                original_metric = downstream_route["metric"]
                new_metric = max(1, original_metric // ROUTE_METRIC_DIVISOR)

                # Check if a better route already exists
                has_better_route = any(
                    r["dev"] == downstream_if and r["metric"] < original_metric
                    for r in prefix_routes
                )
                if has_better_route:
                    logger.debug(
                        "Route %s dev %s already has better metric, skipping",
                        prefix,
                        downstream_if,
                    )
                    continue

                logger.info(
                    "Fixing route priority: %s dev %s metric %d -> %d",
                    prefix,
                    downstream_if,
                    original_metric,
                    new_metric,
                )

                try:
                    subprocess.run(
                        [
                            "ip", "-6", "route", "add",
                            prefix, "dev", downstream_if, "metric", str(new_metric),
                        ],
                        capture_output=True,
                        check=True,
                    )
                except subprocess.CalledProcessError as e:
                    # Route may already exist
                    if b"File exists" not in e.stderr:
                        logger.warning(
                            "Failed to add route %s dev %s: %s",
                            prefix,
                            downstream_if,
                            e.stderr.decode().strip(),
                        )


def fix_ndppd_ttl(downstream_if, upstream_if):
    """Fix ndppd TTL configuration to extend session timeout.

    Modifies /run/ndppd_{downstream}_{upstream}.conf to change
    'ttl 30000' to 'ttl 3600000' to work around Ubiquiti U7 series
    multicast issues that cause Android devices to miss NS packets.

    Returns True if the config was modified and ndppd needs restart.
    """
    config_path = f"/run/ndppd_{downstream_if}_{upstream_if}.conf"

    if not os.path.exists(config_path):
        logger.warning("ndppd config not found: %s", config_path)
        return False

    try:
        with open(config_path, "r") as f:
            content = f.read()
    except OSError as e:
        logger.error("Failed to read ndppd config: %s", e)
        return False

    # Check if TTL is already extended
    if f"ttl {NDPPD_TTL_EXTENDED}" in content:
        logger.info("ndppd TTL already extended in %s", config_path)
        return False

    # Replace TTL value
    new_content, count = re.subn(
        rf"\bttl\s+{NDPPD_TTL_DEFAULT}\b",
        f"ttl {NDPPD_TTL_EXTENDED}",
        content,
    )

    if count == 0:
        logger.warning(
            "TTL pattern 'ttl %d' not found in %s",
            NDPPD_TTL_DEFAULT,
            config_path,
        )
        return False

    try:
        with open(config_path, "w") as f:
            f.write(new_content)
        logger.info(
            "Updated ndppd TTL: %d -> %d in %s",
            NDPPD_TTL_DEFAULT,
            NDPPD_TTL_EXTENDED,
            config_path,
        )
        return True
    except OSError as e:
        logger.error("Failed to write ndppd config: %s", e)
        return False


def restart_ndppd():
    """Restart ndppd to apply configuration changes.

    Sends SIGTERM to ndppd. On UDM Pro, ubios-udapi-server will
    automatically restart ndppd after it exits.
    """
    try:
        subprocess.run(["pkill", "-x", "ndppd"], capture_output=True)
        logger.info("Sent SIGTERM to ndppd (ubios-udapi-server will restart it)")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.warning("Failed to send SIGTERM to ndppd: %s", e)
        return False


class MLDProxy:
    def __init__(self, upstream_if, downstream_if):
        self.upstream_if = upstream_if
        self.downstream_if = downstream_if
        self.upstream_idx = socket.if_nametoindex(upstream_if)
        self.downstream_idx = socket.if_nametoindex(downstream_if)

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

        # Fix route priority if upstream and downstream have same prefix/metric
        fix_route_priority(upstream_if, downstream_if)

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

    def scan_neighbor_table(self):
        """Scan kernel neighbor table and refresh timestamps for known addresses.

        This prevents premature group leaves for hosts that remain in the
        neighbor cache even if they're not actively sending NDP messages.
        """
        neighbors = get_ipv6_neighbors(self.downstream_idx)
        logger.debug("Found %d neighbors in table", len(neighbors))

        refreshed = 0
        added = 0
        for addr in neighbors:
            if is_link_local(addr):
                continue

            sn = solicited_node_addr_from_bytes(addr)
            if sn in self.joined_groups:
                addrs, _ = self.joined_groups[sn]
                if addr in addrs:
                    addrs[addr] = time.time()
                    refreshed += 1
                else:
                    # Same SN group but different address - add it
                    self.add_address(addr)
                    added += 1
            else:
                # New address not yet tracked - add it
                self.add_address(addr)
                added += 1

        if refreshed > 0 or added > 0:
            logger.debug("Neighbor scan: refreshed=%d, added=%d", refreshed, added)

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
        last_neighbor_scan = time.time()
        last_route_check = time.time()

        # Initial neighbor table scan to pick up existing hosts
        self.scan_neighbor_table()

        try:
            while True:
                readable, _, _ = select.select([self.ndp_sock], [], [], SELECT_TIMEOUT)
                if self.ndp_sock in readable:
                    data, _ = self.ndp_sock.recvfrom(4096)
                    self.handle_ndp(data)

                now = time.time()

                if now - last_neighbor_scan >= NEIGHBOR_SCAN_INTERVAL:
                    self.scan_neighbor_table()
                    last_neighbor_scan = now

                if now - last_expiry_check >= EXPIRY_CHECK_INTERVAL:
                    self.expire_stale()
                    last_expiry_check = now

                if now - last_route_check >= ROUTE_CHECK_INTERVAL:
                    fix_route_priority(self.upstream_if, self.downstream_if)
                    last_route_check = now

        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.close()


def main():
    parser = argparse.ArgumentParser(
        description="MLD Proxy for Solicited-Node Multicast Addresses",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  sudo python3 mld_proxy.py eth9 br0
  sudo python3 mld_proxy.py eth9 br0 --fix-ndppd-ttl
""",
    )
    parser.add_argument(
        "upstream_if",
        help="Upstream interface (e.g., eth9)",
    )
    parser.add_argument(
        "downstream_if",
        help="Downstream interface (e.g., br0)",
    )
    parser.add_argument(
        "--fix-ndppd-ttl",
        action="store_true",
        help=(
            f"Extend ndppd TTL from {NDPPD_TTL_DEFAULT}ms to {NDPPD_TTL_EXTENDED}ms "
            "to work around Ubiquiti U7 multicast issues. "
            "Restarts ndppd if config is modified."
        ),
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.fix_ndppd_ttl:
        modified = fix_ndppd_ttl(args.downstream_if, args.upstream_if)
        if modified:
            restart_ndppd()

    proxy = MLDProxy(args.upstream_if, args.downstream_if)
    proxy.run()


if __name__ == "__main__":
    main()

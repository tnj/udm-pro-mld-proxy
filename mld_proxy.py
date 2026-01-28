#!/usr/bin/env python3
"""
Simple MLD Proxy for Solicited-Node Multicast Addresses

Monitors NDP (NS/NA) on the downstream interface (br0) to discover
LAN hosts' IPv6 addresses, and sends MLD Reports for corresponding
Solicited-Node multicast addresses on the upstream interface (eth9).

This allows NDP (Neighbor Solicitation) to work through a router
when the upstream gateway performs MLD Snooping.

Usage: sudo python3 mld_proxy.py <upstream_if> <downstream_if>
Example: sudo python3 mld_proxy.py eth9 br0
"""

import socket
import struct
import sys
import select
import time

# ICMPv6 types
ICMPV6_NS = 135
ICMPV6_NA = 136

# MLDv2 Report destination
MLDV2_ALL_ROUTERS = "ff02::16"

# Solicited-Node prefix
SOLICITED_NODE_PREFIX = b'\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff'

# Address expiry timeout (seconds)
# Addresses not seen in NDP traffic for this duration are considered stale.
ADDR_TIMEOUT = 300

# MLD Report refresh interval (seconds)
REFRESH_INTERVAL = 60

# Expiry check interval (seconds)
EXPIRY_CHECK_INTERVAL = 30


def solicited_node_addr_from_bytes(addr_bytes):
    """Compute Solicited-Node multicast address from 16-byte IPv6 address"""
    return SOLICITED_NODE_PREFIX + addr_bytes[13:16]


def format_ipv6(addr_bytes):
    """Format 16-byte address as IPv6 string"""
    return socket.inet_ntop(socket.AF_INET6, addr_bytes)


def is_link_local(addr_bytes):
    """Check if address is link-local (fe80::/10)"""
    return addr_bytes[0] == 0xfe and (addr_bytes[1] & 0xc0) == 0x80


def build_mldv2_report(mcast_addrs, record_type=2):
    """Build MLDv2 Report message"""
    num_records = len(mcast_addrs)

    header = struct.pack("!BBH HH",
        143, 0, 0,     # ICMPv6: type, code, checksum (kernel computes)
        0, num_records  # Reserved, Num Records
    )

    records = b''
    for addr in mcast_addrs:
        records += struct.pack("!BBH", record_type, 0, 0) + addr

    return header + records


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
        self.ndp_sock.setsockopt(socket.IPPROTO_ICMPV6, 1, icmp6_filter)

        # Create raw socket to send MLD on upstream
        self.send_sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        self.send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                                   upstream_if.encode() + b'\x00')
        self.send_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)

        print(f"MLD Proxy: {downstream_if} -> {upstream_if}")

    def send_mld_report(self, mcast_addrs, record_type=2):
        """Send MLDv2 Report on upstream interface"""
        if not mcast_addrs:
            return

        report = build_mldv2_report(mcast_addrs, record_type)
        dest = (MLDV2_ALL_ROUTERS, 0, 0, self.upstream_idx)

        action_map = {2: "Report", 3: "Leave", 4: "Join"}
        action = action_map.get(record_type, f"type={record_type}")

        try:
            self.send_sock.sendto(report, dest)
            for addr in mcast_addrs:
                print(f"Sent MLD {action}: {format_ipv6(addr)} on {self.upstream_if}")
        except OSError as e:
            print(f"Failed to send MLD Report: {e}")

    def kernel_join(self, sn_addr):
        """Join multicast group at kernel level so we receive packets"""
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            mreq = sn_addr + struct.pack("I", self.upstream_idx)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
            return sock
        except OSError as e:
            print(f"Failed kernel join {format_ipv6(sn_addr)}: {e}")
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
        self.joined_groups[sn] = ({target_addr: now}, join_sock)
        self.send_mld_report([sn], record_type=4)  # CHANGE_TO_EXCLUDE (join)

    def expire_stale(self):
        """Remove addresses not seen recently and leave empty groups"""
        now = time.time()
        to_leave = []

        for sn in list(self.joined_groups.keys()):
            addrs, join_sock = self.joined_groups[sn]

            # Remove expired addresses
            expired = [addr for addr, ts in addrs.items() if now - ts >= ADDR_TIMEOUT]
            for addr in expired:
                print(f"Expired: {format_ipv6(addr)}")
                del addrs[addr]

            # If no addresses remain, leave the group
            if not addrs:
                to_leave.append(sn)
                if join_sock:
                    join_sock.close()
                del self.joined_groups[sn]

        if to_leave:
            self.send_mld_report(to_leave, record_type=3)  # CHANGE_TO_INCLUDE (leave)

    def handle_ndp(self, data):
        """Handle received NDP message (NS or NA)"""
        if len(data) < 24:
            return

        icmp_type = data[0]

        if icmp_type in (ICMPV6_NS, ICMPV6_NA):
            # Target address at offset 8 (after type, code, checksum, reserved/flags)
            target = data[8:24]
            self.add_address(target)

    def refresh_all(self):
        """Resend MLD Reports for all joined groups"""
        if self.joined_groups:
            addrs = list(self.joined_groups.keys())
            self.send_mld_report(addrs, record_type=2)  # MODE_IS_EXCLUDE

    def run(self):
        """Main loop"""
        print("Listening for NDP on downstream...")

        last_refresh = time.time()
        last_expiry_check = time.time()

        try:
            while True:
                readable, _, _ = select.select([self.ndp_sock], [], [], 1.0)
                if self.ndp_sock in readable:
                    data, _ = self.ndp_sock.recvfrom(4096)
                    self.handle_ndp(data)

                now = time.time()

                if now - last_expiry_check >= EXPIRY_CHECK_INTERVAL:
                    self.expire_stale()
                    last_expiry_check = now

                if now - last_refresh >= REFRESH_INTERVAL:
                    self.refresh_all()
                    last_refresh = now

        except KeyboardInterrupt:
            print("\nShutting down...")
            if self.joined_groups:
                self.send_mld_report(list(self.joined_groups.keys()), record_type=3)
                for _, join_sock in self.joined_groups.values():
                    if join_sock:
                        join_sock.close()


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <upstream_if> <downstream_if>")
        print(f"Example: {sys.argv[0]} eth9 br0")
        sys.exit(1)

    upstream_if = sys.argv[1]
    downstream_if = sys.argv[2]

    proxy = MLDProxy(upstream_if, downstream_if)
    proxy.run()


if __name__ == "__main__":
    main()

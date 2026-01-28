# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Single-file Python script (`mld_proxy.py`) that acts as a lightweight MLD (Multicast Listener Discovery) proxy for Solicited-Node multicast addresses. It solves a specific problem: when using ndppd for NDP proxy on a Linux router, upstream gateways with MLD Snooping enabled will stop forwarding Neighbor Solicitations because they don't see MLD Reports for the LAN hosts' Solicited-Node multicast groups.

## Running

```
sudo python3 mld_proxy.py <upstream_if> <downstream_if>
# Example: sudo python3 mld_proxy.py eth9 br0
```

Requires root privileges and Python 3.6+. No external dependencies — uses only stdlib (`socket`, `struct`, `select`).

## Architecture

The `MLDProxy` class does three things:

1. **NDP monitoring** — Listens on the downstream interface (e.g., `br0`) via a raw ICMPv6 socket filtered to NS/NA packets. Extracts target IPv6 addresses from NDP messages.
2. **Multicast group management** — For each discovered address, computes the Solicited-Node multicast address (`ff02::1:ffXX:XXXX`) and joins the group on the upstream interface via `IPV6_JOIN_GROUP`. Tracks address freshness and expires stale entries after `ADDR_TIMEOUT` (300s).
3. **MLD Report sending** — Sends MLDv2 Reports on the upstream interface to notify the gateway. Periodically refreshes all group memberships every `REFRESH_INTERVAL` (60s). Sends leave messages (CHANGE_TO_INCLUDE) when groups expire or on shutdown.

Key constants are defined at module level: `ADDR_TIMEOUT`, `REFRESH_INTERVAL`, `EXPIRY_CHECK_INTERVAL`.

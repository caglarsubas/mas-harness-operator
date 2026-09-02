#!/usr/bin/env python3
"""Prove that the enclosing OS sandbox denies IPv4 and IPv6 networking."""

from __future__ import annotations

import errno
import socket


def denied(family: socket.AddressFamily, address: tuple[object, ...]) -> bool:
    try:
        candidate = socket.socket(family, socket.SOCK_STREAM)
        try:
            candidate.settimeout(0.1)
            candidate.connect(address)
        finally:
            candidate.close()
    except OSError as exc:
        return exc.errno in {errno.EPERM, errno.EACCES}
    return False


if not denied(socket.AF_INET, ("203.0.113.1", 9)):
    raise SystemExit("offline network canary: IPv4 was not denied by the OS")
if not denied(socket.AF_INET6, ("2001:db8::1", 9, 0, 0)):
    raise SystemExit("offline network canary: IPv6 was not denied by the OS")
print("offline network canary: OS denied IPv4 and IPv6 outbound egress")

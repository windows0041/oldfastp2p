#!/usr/bin/env python3
"""Minimal STUN server that honours RFC 3489 CHANGE-REQUEST.

Why this exists: public STUN servers mostly ignore CHANGE-REQUEST, so a NAT's
inbound filter cannot be measured through them (a filtered reply and an ignored
attribute look identical). Running this on a host with two public addresses makes
the "answer from a different address" case real, which is what separates a
full-cone NAT (NAT1) from an address-restricted one (NAT2) and a port-restricted
one (NAT3).

Behaviour:
  plain                 -> reply from the same socket
  CHANGE-REQUEST port   -> reply from <same ip>:<port + 1>
  CHANGE-REQUEST ip     -> reply from <other ip>:<same port>
  CHANGE-REQUEST ip+port-> reply from <other ip>:<port + 1>
With a single local address the ip variants simply do not answer, which tells the
client "not measurable" instead of inventing a verdict.

Usage: stun-responder.py [--port 3478] [--address 1.2.3.4 ...]

Note for operators: any UDP reflection service can be abused for amplification, so
this answers only requests that look like BINDING and never echoes arbitrary
payloads."""
import argparse
import json
import selectors
import subprocess
import socket
import struct
import sys

MAGIC = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ATTR_MAPPED = 0x0001
ATTR_CHANGE_REQUEST = 0x0003
ATTR_XOR_MAPPED = 0x0020


def local_addresses():
    """Every global IPv4 the host holds, via iproute2 (always present on the
    distributions this runs on). Falls back to the kernel's source selection."""
    addresses = []
    try:
        # JSON output keeps the broadcast address out of the list; the text form
        # also carries "brd <addr>", which is not a usable source.
        output = subprocess.run(['ip', '-j', '-4', 'addr', 'show', 'scope', 'global'],
                                capture_output=True, text=True, timeout=5).stdout
        for interface in json.loads(output or '[]'):
            for info in interface.get('addr_info', []):
                candidate = info.get('local')
                if info.get('family') == 'inet' and candidate and candidate not in addresses:
                    addresses.append(candidate)
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    if not addresses:
        # One address is still enough for the change-port case.
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(('1.1.1.1', 53))
            candidate = probe.getsockname()[0]
            if candidate.count('.') == 3 and candidate != '0.0.0.0':
                addresses.append(candidate)
        except OSError:
            pass
        finally:
            probe.close()
    return addresses


def build_response(transaction, address, port):
    """XOR-MAPPED-ADDRESS per RFC 5389 鎼?5.2 (IPv4)."""
    xport = port ^ (MAGIC >> 16)
    cookie = struct.pack('!I', MAGIC)
    packed = bytes(a ^ b for a, b in zip(socket.inet_aton(address), cookie))
    value = bytes([0, 1]) + struct.pack('!H', xport) + packed
    attr = struct.pack('!HH', ATTR_XOR_MAPPED, len(value)) + value
    return struct.pack('!HHI', BINDING_SUCCESS, len(attr), MAGIC) + transaction + attr


def parse_change_request(data):
    offset = 20
    while offset + 4 <= len(data):
        atype, alen = struct.unpack('!HH', data[offset:offset + 4])
        if atype == ATTR_CHANGE_REQUEST and alen == 4 and offset + 8 <= len(data):
            flags = struct.unpack('!I', data[offset + 4:offset + 8])[0]
            return bool(flags & 0x04), bool(flags & 0x02)
        offset += 4 + ((alen + 3) & ~3)
    return False, False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=3478)
    parser.add_argument('--address', action='append', default=[])
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()

    addresses = args.address or local_addresses()
    if not addresses:
        print('no local IPv4 address found', file=sys.stderr)
        return 1
    print('serving on %s, udp/%d and udp/%d' % (', '.join(addresses), args.port, args.port + 1))

    selector = selectors.DefaultSelector()
    # One socket per (address, port) so a reply can pick its source at will.
    for address in addresses:
        for port in (args.port, args.port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((address, port))
            selector.register(sock, selectors.EVENT_READ, (address, port))

    sockets = {(key.data[0], key.data[1]): key.fileobj for key in selector.get_map().values()}
    while True:
        for key, _ in selector.select(timeout=60):
            sock, (address, port) = key.fileobj, key.data
            try:
                data, peer = sock.recvfrom(2048)
            except OSError:
                continue
            # Only BINDING requests are answered: no echo, no amplification.
            if len(data) < 20 or struct.unpack('!H', data[:2])[0] != BINDING_REQUEST:
                continue
            if struct.unpack('!I', data[4:8])[0] != MAGIC:
                continue
            transaction = data[8:20]
            change_ip, change_port = parse_change_request(data)
            target_ip = address
            if change_ip:
                others = [a for a in addresses if a != address]
                if not others:
                    if args.verbose:
                        print('change-ip requested but only one address is bound; not answering')
                    continue
                target_ip = others[0]
            target_port = port + 1 if change_port else port
            out = sockets.get((target_ip, target_port))
            if out is None:
                continue
            try:
                out.sendto(build_response(transaction, peer[0], peer[1]), peer)
            except OSError:
                continue
            if args.verbose:
                print('%s:%d -> %s:%d (change ip=%s port=%s)' % (
                    address, port, target_ip, target_port, change_ip, change_port))


if __name__ == '__main__':
    sys.exit(main())



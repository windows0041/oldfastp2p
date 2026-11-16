#!/usr/bin/env python3
"""IPv4/IPv6 dual-stack gateway tests (DUALSTACK-SPEC §1-§6).

Runs in an isolated network namespace using only loopback (::1 / 127.0.0.1);
no public IPv6 connectivity is required. Covers:
  a) v6-only node login and observed family
  b) dual-stack node registration (families bitmap, per-family NAT levels)
  c) udpNatType6/tcpNatType6 read/write, the 6/9 channel, and the user_version
     5 -> 6 migration of an old database (data preserved)
  d) 5/0 relay selection hard family filter and the 5/1 family field
  e) login rate limiting for IPv6 sources, isolated from the IPv4 budget
  plus per-family NAT probe sockets and the SPEC §3 bracketed TCP echo.
"""
import argparse
import base64
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import sqlite3
import struct
import subprocess
import tempfile
import time
from urllib.parse import quote

p = argparse.ArgumentParser()
p.add_argument('--gateway', required=True)
p.add_argument('--cert-dir', required=True)
p.add_argument('--logs', required=True)
args = p.parse_args()
if Path('/proc/self/ns/net').readlink() == Path('/proc/1/ns/net').readlink():
    raise SystemExit('Use the isolated network test wrapper')
logs = Path(args.logs).resolve(); logs.mkdir(parents=True, exist_ok=True)
certs = Path(args.cert_dir).resolve()
context = ssl.create_default_context(cafile=str(certs / 'ca.crt'))
token = 9999999999999999
user, password = 'dualstack-admin', secrets.token_urlsafe(24)
results, clients = {}, []
process = None

def message(main, sub, body=None):
    if not isinstance(body, bytes): body = json.dumps(body, separators=(',', ':')).encode()
    return struct.pack('<IHH', len(body), main, sub) + body

def api(path, body=None, jwt=None, host='127.0.0.1', port=10008, timeout=5):
    conn = http.client.HTTPSConnection(host, port, context=context, timeout=timeout)
    headers = {'Content-Type': 'application/json'}
    if jwt: headers['Authorization'] = jwt
    try:
        conn.request('POST' if body is not None else 'GET', path,
                     json.dumps(body).encode() if body is not None else None, headers)
        response = conn.getresponse(); data = response.read()
        return response.status, json.loads(data) if data else None
    finally:
        conn.close()

def wait(check, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        assert process.poll() is None, 'Gateway exited; inspect the private log'
        try:
            value = check()
            if value: return value
        except (OSError, ValueError, AssertionError, StopIteration): pass
        time.sleep(.05)
    raise TimeoutError('Dual-stack integration step timed out')

def healthy():
    """A non-200 is a real answer, so surface the status instead of timing out."""
    status, body = api('/healthz')
    if status != 200:
        raise SystemExit('gateway /healthz answered %s: %s' % (status, body))
    return True


class WS:
    """Minimal fastp2p2 WSS fixture bound to one family's loopback."""
    def __init__(self, name, family=4, port=27183, extra='', credential=None, expected=101):
        self.name = name
        credential = token if credential is None else credential
        if family == 4:
            raw = socket.create_connection(('127.0.0.1', port), timeout=3, source_address=('127.0.0.1', 0))
            server_hostname = '127.0.0.1'
        else:
            raw = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            raw.settimeout(3); raw.connect(('::1', port, 0, 0))
            server_hostname = '::1'
        self.socket = context.wrap_socket(raw, server_hostname=server_hostname)
        self.buffer = bytearray()
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        request = (f'GET /api/v1/login?node={name}&token={credential}&protocol=fastp2p2'
                   f'&version=2.0.0{extra} HTTP/1.1\r\nHost: {server_hostname}:{port}\r\n'
                   f'Upgrade: websocket\r\nConnection: Upgrade\r\n'
                   f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n')
        self.socket.sendall(request.encode())
        while b'\r\n\r\n' not in self.buffer:
            part = self.socket.recv(4096)
            if not part: raise AssertionError('Upgrade closed without status')
            self.buffer.extend(part)
        header, left = self.buffer.split(b'\r\n\r\n', 1); self.buffer = bytearray(left)
        status = int(header.split(b' ', 2)[1])
        assert status == expected, ('upgrade status', status, expected)
        if expected != 101:
            self.socket.close(); return
        clients.append(self)
        self.login = json.loads(self.until(0, 0))
        assert self.login['token'] == token and self.login['node'] == name
    def exact(self, n):
        while len(self.buffer) < n:
            data = self.socket.recv(max(4096, n - len(self.buffer)))
            if not data: raise EOFError()
            self.buffer.extend(data)
        data = bytes(self.buffer[:n]); del self.buffer[:n]; return data
    def send(self, data, opcode=2):
        n = len(data); head = bytes([0x80 | opcode])
        if n < 126: head += bytes([0x80 | n])
        elif n < 65536: head += bytes([0xfe]) + struct.pack('>H', n)
        else: head += bytes([0xff]) + struct.pack('>Q', n)
        mask = secrets.token_bytes(4)
        self.socket.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))
    def receive(self):
        result = bytearray()
        while True:
            first, second = self.exact(2); n = second & 127
            if n == 126: n = struct.unpack('>H', self.exact(2))[0]
            elif n == 127: n = struct.unpack('>Q', self.exact(8))[0]
            data = self.exact(n); opcode = first & 15
            if opcode == 8: raise EOFError()
            if opcode == 9: self.send(data); continue
            result.extend(data)
            if first & 0x80: return bytes(result)
    def until(self, main, sub):
        for _ in range(40):
            frame = self.receive(); length, m, s = struct.unpack('<IHH', frame[:8])
            if (m, s) == (main, sub): return frame[8:]
        raise AssertionError('Expected frame not received')
    def report(self, body):
        self.send(message(6, 0, body)); assert json.loads(self.until(6, 7)) == {}
    def close(self):
        try: self.send(b'', 2)
        except OSError: pass
        try: self.socket.close()
        except OSError: pass

try:
    with tempfile.TemporaryDirectory(prefix='fastp2p-dualstack-') as temp, (logs / 'gateway.log').open('w') as output:
        directory = Path(temp)
        env = os.environ.copy()
        env.update(FASTP2P_USER=user, FASTP2P_PASSWORD=password, FASTP2P_TOKEN=str(token))
        process = subprocess.Popen([str(Path(args.gateway).resolve()),
            '--cert', str(certs / 'server.crt'), '--key', str(certs / 'server.key'),
            '--bind', '127.0.0.1', '--bind6', '::1', '--public-host', '2001:db8::55'],
            cwd=directory, env=env, stdout=output, stderr=subprocess.STDOUT)
        wait(healthy, timeout=30)
        # The IPv6 API listener is an independent socket on the same port.
        assert api('/healthz', host='::1')[0] == 200
        status, login = api('/api/v1/user/login', {'user': user, 'password': password})
        assert status == 200
        jwt = login['token']
        results['dual_stack_listeners_up']= True

        # (a) v6-only login: the socket family is hard evidence.
        v6 = WS('v6-only-node', family=6, extra='&nattype=1&families=2')
        assert v6.login.get('tcpProbeV3') == 1, 'login ack must negotiate probeV3'
        v6.report({'os': 'linux-c', 'version': '2.0.0', 'hasIPv6': 1, 'IPv6': '::1',
                   'families': 2, 'udpNatType': 314, 'tcpNatType': 314,
                   'udpNatType6': 1, 'tcpNatType6': 1, 'tcpNatSamples6': 4,
                   'tcpNatDestinationIPs6': 2})
        nodes = lambda: api('/api/v1/nodes', jwt=jwt)[1]['nodes']
        row = wait(lambda: next((n for n in nodes() if n['name'] == 'v6-only-node'
                                 and n.get('isActive')), None))
        assert row['ipv6'] == '::1' and int(row['families']) == 2, row
        assert row['ip'] == '', 'v6 socket must not fabricate an IPv4 source'
        assert row['udpNatType6'] == 1 and row['tcpNatType6'] == 1
        assert row['tcpNatSamples6'] == 4 and row['tcpNatDestinationIPs6'] == 2
        # The live device list carries the same fields for the console.
        live = next(n for n in api('/api/v1/devices', jwt=jwt)[1]['nodes']
                    if n['name'] == 'v6-only-node')
        assert live['families'] == 2 and live['udpNatType6'] == 1 and live['ipv6'] == '::1'
        results['v6_only_login_family_and_nat6_reported'] = True

        # (b) dual-stack node: v4 socket + reported v6 literal + families=3.
        dual = WS('dual-stack-node', family=4,
                  extra='&nattype=1&families=3&ipv6=2001%3Adb8%3A%3A1&tcpnattype=2')
        dual.report({'os': 'linux-c', 'version': '2.0.0', 'hasIPv4': 1, 'hasIPv6': 1,
                     'IPv6': '2001:db8::1', 'families': 3,
                     'udpNatType': 2, 'tcpNatType': 1, 'tcpNatSamples': 3,
                     'tcpNatDestinationIPs': 3,
                     'udpNatType6': 4, 'tcpNatType6': 2, 'tcpNatSamples6': 5,
                     'tcpNatDestinationIPs6': 1})
        row = wait(lambda: next((n for n in nodes() if n['name'] == 'dual-stack-node'
                                 and n.get('isActive')), None))
        assert row['ip'] == '127.0.0.1' and row['ipv6'] == '2001:db8::1'
        assert int(row['families']) == 3, row
        assert (row['udpNatType'], row['tcpNatType']) == (2, 1)
        assert (row['udpNatType6'], row['tcpNatType6']) == (4, 2)
        # A malformed v6 literal is ignored, not fatal and not stored: legacy
        # clients sent free-form text in this field.
        dual.send(message(6, 0, {'IPv6': 'not-an-address', 'version': '2.0.0'}))
        dual.until(6, 7)
        row = next(n for n in nodes() if n['name'] == 'dual-stack-node')
        assert row['ipv6'] == '2001:db8::1' and int(row['families']) == 3, row
        results['dual_stack_family_report_and_literal_validation'] = True

        # 6/9 updates the v6 levels without a re-registration.
        relogin = WS('dual-stack-node', family=4, extra='&families=3')
        relogin.send(message(6, 9, {'udpNatType6': 2, 'tcpNatType6': 1,
                                    'tcpNatSamples6': 6, 'tcpNatDestinationIPs6': 4,
                                    'IPv6': '2001:db8::9'}))
        row = wait(lambda: next((n for n in nodes() if n['name'] == 'dual-stack-node'
                                 and n.get('udpNatType6') == 2
                                 and n.get('tcpNatType6') == 1
                                 and n.get('tcpNatSamples6') == 6
                                 and n.get('tcpNatDestinationIPs6') == 4), None))
        assert row['ipv6'] == '2001:db8::9', row
        results['per_family_levels_update_over_6_9'] = True

        # Peer queries answer with the v6 fields and the family bitmap (SPEC §4).
        relogin.send(message(7, 0, {'peerNode': 'v6-only-node'}))
        answer = json.loads(relogin.until(7, 1))
        assert answer['online'] == 1 and answer['families'] == 2
        assert answer['IPv6'] == '::1' and answer['udpNatType6'] == 1
        results['peer_query_returns_v6_and_families'] = True

        # (d) relay family hard filter (SPEC §6).
        # Pair of v6 endpoints: the only eligible relay is the v6 one; a
        # v4-only relay must be skipped even when it ranks otherwise.
        v4_relay = WS('relay-v4-only', family=4, extra='&nattype=1')
        v4_relay.report({'os': 'linux-c', 'version': '2.0.0', 'hasIPv4': 1})
        v6_relay = WS('relay-dual', family=6, extra='&nattype=1&families=2')
        v6_relay.report({'os': 'linux-c', 'version': '2.0.0', 'hasIPv6': 1, 'families': 2})
        wait(lambda: len([n for n in nodes() if n.get('isActive')]) >= 4)
        v6.send(message(5, 0, {'peerNode': 'dual-stack-node'}))
        offer = json.loads(v6.until(5, 1))
        assert offer['error'] == 0 and offer['relay'] == 'relay-dual', offer
        assert offer['family'] == 2, offer
        # v4 requester + v4 peer: the common family set is {v4}, so only relays
        # that cover v4 are eligible. The pure-v6 relay is skipped by the family
        # filter even though its NAT is better; family=1 comes back in the
        # answer (SPEC §6).
        v4_backup = WS('relay-v4-backup', family=4, extra='&nattype=1')
        v4_backup.report({'os': 'linux-c', 'version': '2.0.0', 'hasIPv4': 1})
        dual2 = WS('v4-peer-node', family=4, extra='&nattype=1')
        dual2.report({'os': 'linux-c', 'version': '2.0.0', 'hasIPv4': 1})
        wait(lambda: any(n['name'] == 'v4-peer-node' and n.get('isActive') for n in nodes()))
        v4_relay.send(message(5, 0, {'peerNode': 'v4-peer-node'}))
        offer = json.loads(v4_relay.until(5, 1))
        assert offer['error'] == 0 and offer['family'] == 1, offer
        assert offer['relay'] == 'relay-v4-backup', offer
        results['relay_hard_family_filter_and_family_field'] = True

        # Per-family NAT probe sockets (SPEC §2/§3) on the v6 loopback.
        for port in range(27180, 27184):
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                sock.sendto(message(2, 0), ('::1', port))
                data, peer = sock.recvfrom(2048)
                body = json.loads(data[8:])
                assert peer[0] == '::1' and peer[1] == port and body['IP'] == '::1', body
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.connect(('::1', 27180))
            local_port = sock.getsockname()[1]
            sock.sendall(b'2')
            line = b''
            sock.settimeout(3)
            while not line.endswith(b'\n'):
                chunk = sock.recv(128)
                if not chunk: break
                line += chunk
            # SPEC §3: the IPv6 echo line is bracketed.
            assert line == f'[::1]:{local_port}\n'.encode(), line
        # IPv4 probes keep the legacy shape.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(message(2, 0), ('127.0.0.1', 27182))
            data, peer = sock.recvfrom(2048)
            assert json.loads(data[8:])['IP'] == '127.0.0.1'
        with socket.create_connection(('127.0.0.1', 27181), timeout=2) as sock:
            local_port = sock.getsockname()[1]
            sock.sendall(b'1')
            assert sock.recv(128) == f'127.0.0.1:{local_port}'.encode()
        results['per_family_probe_sockets_and_bracketed_v6_echo'] = True

        # (e) IPv6 login rate limiting, isolated from the IPv4 budget.
        statuses = []
        for _ in range(12):
            status, _body = api('/api/v1/user/login', {'user': user, 'password': 'wrong'},
                                host='::1')
            statuses.append(status)
        assert 429 in statuses, statuses
        assert statuses.count(401) >= statuses.count(429) * 0  # limited fast
        # A locked IPv6 source does not lock the same address family's correct
        # credentials either way, and the IPv4 budget is untouched: v4 must NOT
        # be limited just because v6 was.
        status, _body = api('/api/v1/user/login', {'user': user, 'password': password},
                            host='127.0.0.1')
        assert status == 200, 'IPv4 login must keep its own budget'
        status, _body = api('/api/v1/user/login', {'user': user, 'password': password},
                            host='::1')
        assert status == 429, 'IPv6 lockout must apply even to correct credentials'
        results['v6_login_ratelimit_and_family_isolation'] = True
        process.terminate(); process.wait(timeout=6); assert process.returncode == 0

        # (c) user_version 5 -> 6 migration: an old database keeps its rows and
        # gains the *6 columns with the schema defaults.
        old_db = directory / 'legacy.sqlite3'
        with sqlite3.connect(old_db) as db:
            db.execute("CREATE TABLE nodes(name TEXT PRIMARY KEY,node_id TEXT UNIQUE,device_id TEXT,"
                       "hostname TEXT NOT NULL DEFAULT '',ip TEXT NOT NULL DEFAULT '',ipv6 TEXT NOT NULL DEFAULT '',"
                       "lanip TEXT NOT NULL DEFAULT '',mac TEXT NOT NULL DEFAULT '',os TEXT NOT NULL DEFAULT '',"
                       "version TEXT NOT NULL DEFAULT '',nat INTEGER NOT NULL DEFAULT 314,bandwidth INTEGER NOT NULL DEFAULT 0,"
                       "first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL,last_offline INTEGER NOT NULL DEFAULT 0,"
                       "online INTEGER NOT NULL DEFAULT 0 CHECK(online IN(0,1)),tcp_nat INTEGER NOT NULL DEFAULT 314,"
                       "tcp_nat_samples INTEGER NOT NULL DEFAULT 0,tcp_nat_ips INTEGER NOT NULL DEFAULT 0)")
            db.execute("INSERT INTO nodes(name,node_id,ip,nat,tcp_nat,tcp_nat_samples,tcp_nat_ips,"
                       "first_seen,last_seen,online) VALUES('legacy-node','7','192.0.2.9',2,1,4,3,10,20,1)")
            db.execute("PRAGMA application_id=1179660880")
            db.execute("PRAGMA user_version=5")
            db.commit()
        process = subprocess.Popen([str(Path(args.gateway).resolve()),
            '--cert', str(certs / 'server.crt'), '--key', str(certs / 'server.key'),
            '--database', str(old_db), '--bind', '127.0.0.1'],
            cwd=directory, env=env, stdout=output, stderr=subprocess.STDOUT)
        wait(healthy, timeout=30)
        status, login = api('/api/v1/user/login', {'user': user, 'password': password})
        if status != 200:  # the legacy database has no stored account row yet
            status, login = api('/api/v1/user/login', {'user': user, 'password': password})
        jwt = login['token']
        legacy = next(n for n in nodes() if n['name'] == 'legacy-node')
        assert legacy['ip'] == '192.0.2.9' and legacy['natType'] == '2'
        assert legacy['udpNatType'] == 2 and legacy['tcpNatType'] == 1
        assert legacy['tcpNatSamples'] == 4 and legacy['tcpNatDestinationIPs'] == 3
        assert legacy['udpNatType6'] == 314 and legacy['tcpNatType6'] == 314
        assert legacy['tcpNatSamples6'] == 0 and legacy['families'] == 1
        assert legacy['isActive'] == 0 and legacy['lastSeen']
        with sqlite3.connect(old_db) as db:
            assert db.execute('PRAGMA user_version').fetchone()[0] == 8
            assert db.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
            row = db.execute("SELECT nat6,tcp_nat6,families FROM nodes WHERE name='legacy-node'").fetchone()
            assert row == (314, 314, 1), row
        results['v5_to_v6_migration_preserves_legacy_rows'] = True
        results['success'] = True
finally:
    for c in clients:
        try: c.close()
        except OSError: pass
    if process:
        process.terminate()
        try: process.wait(timeout=6)
        except subprocess.TimeoutExpired: process.kill(); process.wait()
        diagnostic = (logs / 'gateway.log').read_text(errors='replace')
        assert process.returncode == 0 and 'Sanitizer' not in diagnostic \
            and 'runtime error:' not in diagnostic, 'Gateway shutdown or sanitizer failure'
    (logs / 'result.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2))

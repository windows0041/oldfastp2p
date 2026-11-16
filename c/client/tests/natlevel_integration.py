#!/usr/bin/env python3
"""NAT level detection: mapping test plus the two inbound-filtering probes.

The interesting part cannot be faked by looking at JSON: one client must report
NAT1 because a *foreign* address reached its mapped port. So this test puts two
clients behind different addresses (separate namespaces, like two sites behind
two routers) and checks that the gateway arranges the foreign-source datagram and
that the tested client classifies itself as full cone.

With no NAT in the path every probe succeeds, which is exactly the full-cone
answer; the point here is that the mechanism runs and the level is published,
not that a simulator reproduces every NAT flavour.

Requires root + `unshare --net`.
"""
import argparse, json, os, secrets, socket, ssl, subprocess, sys, tempfile, threading, time
from pathlib import Path
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--gateway', required=True)
parser.add_argument('--c-client', required=True)
parser.add_argument('--cert-dir', required=True)
parser.add_argument('--logs', required=True)
args = parser.parse_args()
if Path('/proc/self/ns/net').readlink() == Path('/proc/1/ns/net').readlink():
    raise SystemExit('Run in a separate network namespace')

logs = Path(args.logs).resolve()
logs.mkdir(parents=True, exist_ok=True)
certs = Path(args.cert_dir).resolve()
context = ssl.create_default_context(cafile=str(certs / 'ca.crt'))
processes, handles, results = [], [], {}
password = secrets.token_urlsafe(24)
token = secrets.randbelow(9 * 10**15) + 10**15
credentials = {'FASTP2P_USER': 'natlevel-user', 'FASTP2P_PASSWORD': password,
               'FASTP2P_TOKEN': str(token)}
jwt = None
GATEWAY_IP = '10.203.0.1'


def api(path, data=None, auth=True):
    req = urllib.request.Request('https://127.0.0.1:10008' + path,
                                 data=json.dumps(data).encode() if data is not None else None,
                                 headers={'Content-Type': 'application/json'})
    if auth and jwt:
        req.add_header('Authorization', jwt)
    with urllib.request.urlopen(req, context=context, timeout=3) as response:
        payload = response.read()
        return json.loads(payload) if payload else None


def start(command, name, directory, env=None):
    out = (logs / (name + '.log')).open('w')
    handles.append(out)
    child_env = os.environ.copy()
    child_env.update(env or {})
    child = subprocess.Popen([str(x) for x in command], cwd=directory, env=child_env,
                             stdout=out, stderr=subprocess.STDOUT)
    processes.append(child)
    return child


def wait(check, timeout=90, what='condition'):
    deadline = time.monotonic() + timeout
    error = None
    while time.monotonic() < deadline:
        if any(p.poll() is not None for p in processes):
            raise RuntimeError('a process exited while waiting for ' + what)
        try:
            value = check()
            if value:
                return value
        except (OSError, urllib.error.URLError, ValueError, KeyError) as exc:
            error = type(exc).__name__
        time.sleep(.2)
    raise TimeoutError('timed out waiting for %s (%s)' % (what, error))


def node(name):
    for entry in api('/api/v1/nodes?limit=100').get('nodes', []):
        if entry.get('name') == name:
            return entry
    return None


def client_in_netns(name, address, anchor_ip, index):
    """One client behind its own veth pair, so the gateway sees a distinct IP."""
    directory = logs / name
    directory.mkdir(exist_ok=True)
    anchor = start(['unshare', '--net', '--', 'sleep', '300'], name + '-netns', directory)
    deadline = time.monotonic() + 5
    while Path('/proc/%d/ns/net' % anchor.pid).readlink() == Path('/proc/self/ns/net').readlink():
        if time.monotonic() > deadline:
            raise TimeoutError('could not create a network namespace')
        time.sleep(.02)
    outer, inner = 'nl%d' % index, 'ni%d' % index
    subprocess.run(['ip', 'link', 'add', outer, 'type', 'veth', 'peer', 'name', inner], check=True)
    subprocess.run(['ip', 'link', 'set', inner, 'netns', str(anchor.pid)], check=True)
    subprocess.run(['ip', 'addr', 'add', anchor_ip + '/30', 'dev', outer], check=True)
    subprocess.run(['ip', 'link', 'set', outer, 'up'], check=True)
    prefix = ['nsenter', '-t', str(anchor.pid), '-n', '--']
    for command in (['ip', 'link', 'set', 'lo', 'up'],
                    ['ip', 'addr', 'add', address + '/30', 'dev', inner],
                    ['ip', 'link', 'set', inner, 'up'],
                    ['ip', 'route', 'add', 'default', 'via', anchor_ip]):
        subprocess.run(prefix + command, check=True)
    cfg = directory / 'config.json'
    cfg.write_text(json.dumps({'network': {'Node': name, 'Token': token,
                                           'ServerHost': GATEWAY_IP, 'ServerPort': 27183},
                               'CACertFile': str(certs / 'ca.crt'), 'apps': []}))
    cfg.chmod(0o600)
    start(prefix + [Path(args.c_client).resolve(), '--config', cfg], name, directory)


try:
    with tempfile.TemporaryDirectory(prefix='fastp2p-natlevel-') as runtime:
        runtime = Path(runtime)
        runtime.chmod(0o700)
        subprocess.run(['ip', 'link', 'add', 'nl-gw', 'type', 'dummy'], check=True)
        subprocess.run(['ip', 'addr', 'add', GATEWAY_IP + '/32', 'dev', 'nl-gw'], check=True)
        subprocess.run(['ip', 'link', 'set', 'nl-gw', 'up'], check=True)
        gateway = start([Path(args.gateway).resolve(), '-bind', '0.0.0.0', '-apibind', '127.0.0.1',
                         '-cert', certs / 'server.crt', '-key', certs / 'server.key'],
                        'gateway', runtime, credentials)
        wait(lambda: api('/healthz', auth=False), what='the gateway')
        jwt = api('/api/v1/user/login',
                  {'user': credentials['FASTP2P_USER'], 'password': password}, False)['token']

        # Two sites, two distinct addresses: the second is the only thing that can
        # prove the first accepts an unsolicited foreign source.
        client_in_netns('natlevel-a', '10.203.1.2', '10.203.1.1', 1)
        client_in_netns('natlevel-b', '10.203.2.2', '10.203.2.1', 2)
        wait(lambda: (node('natlevel-a') or {}).get('isActive') and
                     (node('natlevel-b') or {}).get('isActive'),
             what='both clients to register')
        results['two_clients_on_distinct_addresses'] = True

        # The refinement runs after login, so give it its two probe windows and
        # wait for a *decided* level rather than the login-time placeholder.
        wait(lambda: (node('natlevel-a') or {}).get('natLevel') in (1, 2, 3, 4),
             timeout=90, what='natlevel-a to finish its NAT level')
        level_a = int(node('natlevel-a')['natLevel'])
        level_b = int(node('natlevel-b')['natLevel'])
        print('levels: a=%d b=%d' % (level_a, level_b), flush=True)
        assert level_a in (1, 2, 3, 4, 5), level_a
        assert level_b in (1, 2, 3, 4, 5), level_b
        results['nat_level_published'] = True

        # No NAT is in the path here, so every filtering probe has to get through:
        # that is the full-cone answer, and 5 would mean the foreign source never
        # arrived (the mechanism, not the NAT, would then be broken).
        assert level_a == 1, 'expected NAT1 without a NAT in the path, got %d' % level_a
        results['foreign_source_probe_reaches_full_cone_client'] = True

        # The console reads natLevel straight off the node list, so the API has to
        # carry it for both clients - not just the one that finished first.
        listing = api('/api/v1/nodes?limit=100')
        for name in ('natlevel-a', 'natlevel-b'):
            entry = next(n for n in listing['nodes'] if n['name'] == name)
            assert 'natLevel' in entry, entry
        results['api_reports_level'] = True

        results['success'] = True
finally:
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()
    for process in processes:
        try:
            process.wait(timeout=6)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    for handle in handles:
        handle.close()
    (logs / 'result.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2))

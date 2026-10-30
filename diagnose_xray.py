"""Temporary, privacy-preserving diagnostics for Xray validation on CI."""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import collector

XRAY = sys.argv[1]
MODE = sys.argv[2]
CONFIG = Path(sys.argv[3])
WORDS = frozenset({
    'address', 'allowinsecure', 'balancer', 'certificate', 'client', 'config',
    'configuration', 'convert', 'decode', 'dns', 'domain', 'empty', 'encryption',
    'error', 'failed', 'field', 'fingerprint', 'flow', 'format', 'geoip', 'geosite',
    'grpc', 'handler', 'host', 'http', 'inbound', 'invalid', 'json', 'legacy',
    'mask', 'mkcp', 'network', 'none', 'not', 'observable', 'observatory',
    'outbound', 'password', 'port', 'protocol', 'read', 'reality', 'removed',
    'router', 'routing', 'security', 'server', 'settings', 'shortid', 'spiderx',
    'stats', 'stream', 'tcp', 'tls', 'transport', 'type', 'udp', 'unknown',
    'unsupported', 'vless', 'websocket', 'xhttp', 'xtls',
})


def check(path):
    try:
        result = subprocess.run(
            [XRAY, 'run', '-test', '-format', 'json', '-c', str(path)],
            env=os.environ, capture_output=True, timeout=30, check=False,
        )
        return result.returncode == 0, (result.stdout + result.stderr).decode(errors='replace')
    except (OSError, subprocess.TimeoutExpired):
        return False, ''


def report(label, ok, output):
    state = 'valid' if ok else 'rejected'
    if 'unsupported config file extension' in output.lower():
        state = 'rejected_unsupported_file_extension'
    # Never print the raw output; Xray can include subscription credentials.
    relevant = ' '.join(line for line in output.splitlines() if 'failed to start' in line.lower())
    words = sorted({word for word in re.findall(r'[a-z]+', relevant.lower()) if word in WORDS})
    print(f'::notice title={label}::{state}; safe_error_words={",".join(words) or "none"}', flush=True)


ok, output = check(CONFIG)
report(MODE, ok, output)
if ok or MODE != 'generated':
    sys.exit(0)

with tempfile.TemporaryDirectory(prefix='xray-diagnostic-') as tmp:
    config_path = Path(tmp) / 'test.json'

    def test_nodes(nodes):
        payload = collector.generate_full_json_config(nodes)
        config_path.write_text(json.dumps(payload, ensure_ascii=False), encoding='utf-8')
        return check(config_path)

    fake = collector.parse_vless_to_outbound(
        'vless://8c376d80-c7a9-47e2-9d85-305b3e91df01@127.0.0.1:12345?type=tcp&security=none&encryption=none',
        'proxy-1',
    )
    base_ok, base_output = test_nodes([fake])
    report('synthetic_base', base_ok, base_output)
    if not base_ok:
        sys.exit(0)
    data = json.loads(CONFIG.read_text(encoding='utf-8'))
    nodes = [item for item in data['outbounds'] if item.get('protocol') == 'vless' and item.get('tag', '').startswith('proxy-')]
    print(f'::notice title=Candidate count::{len(nodes)}', flush=True)
    while len(nodes) > 1:
        mid = len(nodes) // 2
        left, right = nodes[:mid], nodes[mid:]
        left_ok, left_output = test_nodes(left)
        if not left_ok:
            nodes, output = left, left_output
            continue
        right_ok, right_output = test_nodes(right)
        if not right_ok:
            nodes, output = right, right_output
            continue
        print('::notice title=Isolation::failure_requires_multiple_outbounds', flush=True)
        sys.exit(0)
    if len(nodes) == 1:
        node = nodes[0]
        stream = node.get('streamSettings') or {}
        network = stream.get('network') if stream.get('network') in {'tcp','xhttp','grpc','ws','kcp','httpupgrade'} else 'other'
        security = stream.get('security') if stream.get('security') in {'none','tls','reality'} else 'other'
        print(f'::notice title=Offending outbound::network={network};security={security}', flush=True)
        report('isolated_outbound', False, output)

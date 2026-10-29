"""Collect VLESS subscriptions and produce an Xray configuration.

The only required input is the SUB_URLS environment variable, containing one
HTTP(S) subscription URL per line. Subscription URLs and VLESS credentials are
never written to the log.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import http.client
import io
import ipaddress
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import zlib
from pathlib import Path
from urllib.parse import SplitResult, parse_qs, unquote, urlsplit

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger(__name__)

FETCH_TIMEOUT = 20
FETCH_ATTEMPTS = 3
MAX_SUBSCRIPTION_BYTES = 25 * 1024 * 1024
CHUNK_SIZE = 1000
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(network) for network in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7',
))
PRIVATE_DOMAIN_SUFFIXES = (
    'lan', 'localdomain', 'example', 'invalid', 'localhost',
    'test', 'local', 'home.arpa', 'internal',
)

# Xray rejects a whole JSON configuration if one outbound has an unknown
# fingerprint. Keep unsupported nodes in the raw subscription instead.
XRAY_FINGERPRINTS = frozenset({
    '360', 'android', 'chrome', 'edge', 'firefox', 'hello360_11_0', 'hello360_7_5',
    'hello360_auto', 'helloandroid_11_okhttp', 'hellochrome_100', 'hellochrome_100_psk',
    'hellochrome_102', 'hellochrome_106_shuffle', 'hellochrome_112_psk_shuf',
    'hellochrome_114_padding_psk_shuf', 'hellochrome_115_pq', 'hellochrome_115_pq_psk',
    'hellochrome_120', 'hellochrome_120_pq', 'hellochrome_131', 'hellochrome_133',
    'hellochrome_58', 'hellochrome_62', 'hellochrome_70', 'hellochrome_72', 'hellochrome_83',
    'hellochrome_87', 'hellochrome_96', 'hellochrome_auto', 'helloedge_106', 'helloedge_85',
    'helloedge_auto', 'hellofirefox_102', 'hellofirefox_105', 'hellofirefox_120',
    'hellofirefox_148', 'hellofirefox_55', 'hellofirefox_56', 'hellofirefox_63',
    'hellofirefox_65', 'hellofirefox_99', 'hellofirefox_auto', 'hellogolang', 'helloios_11_1',
    'helloios_12_1', 'helloios_13', 'helloios_14', 'helloios_auto', 'helloqq_11_1',
    'helloqq_auto', 'hellorandomized', 'hellorandomizedalpn', 'hellorandomizednoalpn',
    'hellosafari_16_0', 'hellosafari_26_3', 'hellosafari_auto', 'ios', 'qq', 'random',
    'randomized', 'randomizednoalpn', 'safari', 'unsafe',
})


class SubscriptionError(Exception):
    """A source or its contents could not be processed safely."""


class ConfigError(ValueError):
    """A VLESS link cannot be converted to a supported Xray outbound."""


def subscription_urls(raw_urls: str) -> list[str]:
    """Read one HTTP(S) source URL per line, ignoring blanks and comments."""
    urls: list[str] = []
    seen: set[str] = set()
    for line in raw_urls.splitlines():
        url = line.strip().lstrip('\ufeff')
        if not url or url.startswith('#'):
            continue
        try:
            parsed = urlsplit(url)
            if (
                parsed.scheme.lower() not in {'http', 'https'}
                or not parsed.hostname
                or any(character.isspace() or ord(character) < 32 for character in url)
                or parsed.port == 0
            ):
                raise ValueError
        except ValueError:
            raise SubscriptionError(
                'SUB_URLS must contain one valid HTTP(S) URL per line.'
            ) from None
        if url not in seen:
            seen.add(url)
            urls.append(url)
    if not urls:
        raise SubscriptionError('SUB_URLS is empty; add one subscription URL per line.')
    return urls


def _vless_parts(url: str) -> tuple[SplitResult, str, str, int]:
    """Validate the VLESS authority and return parsed, UUID, host and port."""
    try:
        # Unescaped spaces in display names after # are harmless, but spaces
        # or control characters in the actual URI are not.
        uri = url.partition('#')[0]
        if not uri or any(c.isspace() or ord(c) < 32 for c in uri):
            raise ValueError
        parsed = urlsplit(url)
        if (
            parsed.scheme.lower() != 'vless'
            or not parsed.username
            or parsed.password is not None
            or not parsed.hostname
            or parsed.port is None
            or not 1 <= parsed.port <= 65535
        ):
            raise ValueError
        identifier = unquote(parsed.username, errors='strict')
        try:
            user_id = str(uuid.UUID(identifier))
        except ValueError:
            # Xray also accepts custom IDs of at most 30 UTF-8 bytes and maps
            # them to UUIDv5 using the nil UUID as namespace.
            if not 0 < len(identifier.encode('utf-8')) <= 30:
                raise ValueError from None
            user_id = str(uuid.uuid5(uuid.UUID(int=0), identifier))
        address = parsed.hostname
        if any(c.isspace() or c in '/?#@[]%' for c in address):
            raise ValueError
        if ':' not in address:
            address = address.encode('idna').decode('ascii')
            if not re.fullmatch(r'[a-zA-Z0-9._-]+', address) or '..' in address:
                raise ValueError
        return parsed, user_id, address, parsed.port
    except (ValueError, UnicodeError):
        raise ConfigError('invalid VLESS address, UUID, or port') from None


def is_valid_vless_url(url: str) -> bool:
    """Check the VLESS authority without excluding unsupported Xray features."""
    try:
        _vless_parts(url)
    except (ConfigError, AttributeError, TypeError):
        return False
    return True


def _decode_subscription(text: str) -> list[str]:
    """Accept plaintext and whole-payload standard or URL-safe base64."""
    lines = text.splitlines()
    if any(line.strip().lower().startswith('vless://') for line in lines):
        return lines

    compact = ''.join(text.split())
    try:
        decoded = base64.b64decode(
            compact + '=' * (-len(compact) % 4), altchars=b'-_', validate=True
        ).decode('utf-8-sig')
    except (binascii.Error, UnicodeError, ValueError):
        return lines
    decoded_lines = decoded.splitlines()
    if any(line.strip().lower().startswith('vless://') for line in decoded_lines):
        return decoded_lines
    return lines


def fetch_and_decode(url: str) -> list[str]:
    """Fetch a subscription, retry transient errors, and decode its contents.

    Error messages deliberately exclude the URL: it may contain access tokens.
    """
    request = urllib.request.Request(
        url,
        headers={
            'User-Agent': 'Mozilla/5.0 (compatible; sub-collector/1.0)',
            'Accept-Encoding': 'identity',
        },
    )
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:
                encoding = response.headers.get('Content-Encoding', '').strip().lower()
                length = response.headers.get('Content-Length')
                expected_length = None
                if length is not None:
                    try:
                        expected_length = int(length)
                    except ValueError:
                        raise SubscriptionError('invalid response length') from None
                    if expected_length < 0:
                        raise SubscriptionError('invalid response length')
                    if expected_length > MAX_SUBSCRIPTION_BYTES:
                        raise SubscriptionError('subscription response is too large')
                content = response.read(MAX_SUBSCRIPTION_BYTES + 1)
                if expected_length is not None and len(content) != expected_length:
                    raise http.client.IncompleteRead(content)
            break
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            retryable = status in {408, 425, 429, 500, 502, 503, 504}
            if not retryable or attempt == FETCH_ATTEMPTS:
                raise SubscriptionError(f'HTTP error {status}') from None
            logger.warning('Temporary HTTP error %d; retrying the subscription.', status)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, http.client.HTTPException):
            if attempt == FETCH_ATTEMPTS:
                raise SubscriptionError('network error or timeout') from None
            logger.warning('Temporary network error; retrying the subscription.')
        time.sleep(attempt)

    if len(content) > MAX_SUBSCRIPTION_BYTES:
        raise SubscriptionError('subscription response is too large')
    if encoding == 'gzip':
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(content)) as compressed:
                content = compressed.read(MAX_SUBSCRIPTION_BYTES + 1)
        except (OSError, EOFError, zlib.error):
            raise SubscriptionError('invalid gzip response') from None
        if len(content) > MAX_SUBSCRIPTION_BYTES:
            raise SubscriptionError('decompressed subscription is too large')
    elif encoding not in {'', 'identity'}:
        raise SubscriptionError('unsupported content encoding')

    try:
        text = content.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise SubscriptionError('subscription is not UTF-8 text') from None
    if not text.strip():
        raise SubscriptionError('subscription response is empty')
    return _decode_subscription(text)


def _base64_key(value: str, expected_bytes: int) -> str:
    """Normalize a base64 key to the unpadded URL-safe format Xray expects."""
    value = value.replace(' ', '+').replace('+', '-').replace('/', '_').rstrip('=')
    try:
        decoded = base64.b64decode(
            value + '=' * (-len(value) % 4), altchars=b'-_', validate=True
        )
    except (binascii.Error, ValueError):
        raise ConfigError('invalid Reality key') from None
    if len(decoded) != expected_bytes:
        raise ConfigError('invalid Reality key')
    return base64.urlsafe_b64encode(decoded).decode('ascii').rstrip('=')


def _supported_encryption(encryption: str) -> bool:
    if encryption == 'none':
        return True
    # Modern Xray also supports VLESS post-quantum encryption. Preserve it
    # rather than silently changing it to "none".
    parts = encryption.split('.')
    if (
        len(parts) < 4
        or parts[0] != 'mlkem768x25519plus'
        or parts[1] not in {'native', 'xorpub', 'random'}
        or parts[2] not in {'0rtt', '1rtt'}
    ):
        return False
    has_key = False
    for part in parts[3:]:
        if len(part) < 20:
            if has_key or not re.fullmatch(r'\d+-\d+-\d+', part):
                return False
            continue  # Optional padding specifications precede the key.
        try:
            decoded = base64.b64decode(
                part + '=' * (-len(part) % 4), altchars=b'-_', validate=True
            )
        except (binascii.Error, ValueError):
            return False
        if len(decoded) not in {32, 1184} or '=' in part or '+' in part or '/' in part:
            return False
        has_key = True
    return has_key


def _is_private_xray_address(address: str) -> bool:
    """Match the private addresses for which modern Xray permits plaintext."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        name = address.lower().rstrip('.')
        return (
            any(name == suffix or name.endswith('.' + suffix) for suffix in PRIVATE_DOMAIN_SUFFIXES)
            or bool(re.fullmatch(r'[a-z]([a-z0-9-]{0,61}[a-z0-9])?', name))
        )
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_link_local or any(ip in network for network in PRIVATE_NETWORKS)


def parse_vless_to_outbound(vless_url: str, tag_name: str) -> dict | None:
    """Convert supported VLESS links to Xray outbounds without logging secrets."""
    try:
        return _parse_vless_to_outbound(vless_url, tag_name)
    except ConfigError as error:
        logger.warning('Skipping VLESS configuration: %s.', error)
        return None


def _parse_vless_to_outbound(vless_url: str, tag_name: str) -> dict:
    parsed, user_id, address, port = _vless_parts(vless_url)
    try:
        params = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=1000)
    except ValueError:
        raise ConfigError('invalid query parameters') from None

    def param(name: str, default: str = '') -> str:
        return params.get(name, [default])[0]

    network = (param('type', 'tcp') or 'tcp').lower()
    network = {'raw': 'tcp', 'websocket': 'ws', 'splithttp': 'xhttp', 'mkcp': 'kcp'}.get(network, network)
    if network not in {'tcp', 'ws', 'grpc', 'xhttp', 'httpupgrade', 'kcp'}:
        raise ConfigError('unsupported transport')
    security = (param('security', 'none') or 'none').lower()
    if security not in {'none', 'tls', 'reality'}:
        raise ConfigError('unsupported security')
    if security == 'reality' and network not in {'tcp', 'xhttp', 'grpc'}:
        raise ConfigError('Reality is incompatible with this transport')

    encryption = param('encryption', 'none') or 'none'
    if not _supported_encryption(encryption):
        raise ConfigError('unsupported VLESS encryption')
    if security == 'none' and encryption == 'none' and not _is_private_xray_address(address):
        raise ConfigError('unencrypted VLESS to a public address is rejected by current Xray')
    flow = param('flow')
    if flow == 'none':
        flow = ''
    if flow not in {'', 'xtls-rprx-vision', 'xtls-rprx-vision-udp443'}:
        raise ConfigError('unsupported VLESS flow')
    if flow and encryption == 'none' and (network != 'tcp' or security == 'none'):
        raise ConfigError('Vision flow requires direct TLS or Reality')

    user = {'encryption': encryption, 'id': user_id, 'level': 8}
    if flow:
        user['flow'] = flow
    stream: dict = {'network': network}
    outbound = {
        'mux': {'concurrency': -1, 'enabled': False},
        'protocol': 'vless',
        'settings': {'vnext': [{'address': address, 'port': port, 'users': [user]}]},
        'streamSettings': stream,
        'tag': tag_name,
    }

    host = param('host')
    path = param('path', '/') or '/'
    if network == 'ws':
        ws: dict = {'path': path}
        if host:
            ws['host'] = host
        stream['wsSettings'] = ws
    elif network == 'httpupgrade':
        upgrade: dict = {'path': path}
        if host:
            upgrade['host'] = host
        stream['httpupgradeSettings'] = upgrade
    elif network == 'xhttp':
        xhttp: dict = {'path': path}
        if host:
            xhttp['host'] = host
        mode = param('mode')
        if mode:
            if mode not in {'auto', 'packet-up', 'stream-up', 'stream-one'}:
                raise ConfigError('unsupported XHTTP mode')
            xhttp['mode'] = mode
        extra = param('extra')
        if extra:
            try:
                extra_settings = json.loads(extra)
                # Reject NaN/Infinity and unpaired surrogates, which Python's
                # permissive JSON parser otherwise accepts but Xray does not.
                json.dumps(extra_settings, allow_nan=False, ensure_ascii=False).encode('utf-8')
            except (ValueError, UnicodeError, RecursionError):
                raise ConfigError('invalid XHTTP extra settings') from None
            if not isinstance(extra_settings, dict):
                raise ConfigError('invalid XHTTP extra settings')
            xhttp['extra'] = extra_settings
        stream['xhttpSettings'] = xhttp
    elif network == 'grpc':
        grpc: dict = {}
        if param('serviceName'):
            grpc['serviceName'] = param('serviceName')
        if param('authority'):
            grpc['authority'] = param('authority')
        mode = param('mode')
        if mode not in {'', 'gun', 'multi'}:
            raise ConfigError('unsupported gRPC mode')
        if mode == 'multi':
            grpc['multiMode'] = True
        if grpc:
            stream['grpcSettings'] = grpc
    elif network == 'tcp':
        header_type = (param('headerType', 'none') or 'none').lower()
        if header_type not in {'none', 'http'}:
            raise ConfigError('unsupported TCP header')
        if header_type == 'http':
            request: dict = {'path': [part.strip() for part in path.split(',') if part.strip()]}
            if host:
                request['headers'] = {'Host': [part.strip() for part in host.split(',') if part.strip()]}
            stream['tcpSettings'] = {'header': {'type': 'http', 'request': request}}
    elif network == 'kcp':
        header_type = (param('headerType', 'none') or 'none').lower()
        header_map = {
            'dns': 'dns', 'srtp': 'srtp', 'utp': 'utp',
            'wechat-video': 'wechat', 'dtls': 'dtls', 'wireguard': 'wireguard',
        }
        if header_type != 'none' and header_type not in header_map:
            raise ConfigError('unsupported mKCP header')
        seed = param('seed')
        # Current Xray uses finalmask for legacy mKCP. Emitting the removed
        # kcpSettings.seed/header fields makes some Xray releases reject the
        # entire configuration rather than using the supplied finalmask.
        masks = [{'type': 'mkcp-legacy', 'settings': {'value': seed}}] if seed else [{'type': 'mkcp-legacy'}]
        if header_type != 'none':
            masks.append({'type': 'mkcp-legacy', 'settings': {'header': header_map[header_type]}})
        stream['finalmask'] = {'udp': masks}

    if security in {'tls', 'reality'}:
        fingerprint = (param('fp', 'chrome') or 'chrome').lower()
        if fingerprint not in XRAY_FINGERPRINTS:
            raise ConfigError('unsupported TLS fingerprint')
        server_name = param('sni') or address
        stream['security'] = security
        if security == 'tls':
            # Current Xray rejects allowInsecure=true. Do not silently weaken
            # certificate verification or emit an unusable full configuration.
            for key in ('allowInsecure', 'insecure'):
                flag = param(key).lower()
                if flag not in {'', '0', 'false'}:
                    raise ConfigError('insecure TLS is unsupported')
            tls: dict = {
                'allowInsecure': False,
                'serverName': server_name,
                'fingerprint': fingerprint,
            }
            alpn = [item.strip() for item in param('alpn').split(',') if item.strip()]
            if len(alpn) > 1 and any(item.lower() == 'frommitm' for item in alpn):
                raise ConfigError('invalid TLS ALPN combination')
            if alpn:
                tls['alpn'] = alpn
            if param('pcs'):
                pins = [item.strip() for item in param('pcs').split(',') if item.strip()]
                if not pins or any(not re.fullmatch(r'(?:[0-9a-fA-F]{2}:?){32}', pin) for pin in pins):
                    raise ConfigError('invalid TLS certificate pin')
                tls['pinnedPeerCertSha256'] = ','.join(pins)
            if param('vcn'):
                tls['verifyPeerCertByName'] = param('vcn')
            stream['tlsSettings'] = tls
        else:
            if fingerprint in {'unsafe', 'hellogolang'}:
                raise ConfigError('unsupported Reality fingerprint')
            public_key = _base64_key(param('pbk'), 32)
            short_id = param('sid')
            if len(short_id) > 16 or len(short_id) % 2 or not re.fullmatch(r'[0-9a-fA-F]*', short_id):
                raise ConfigError('invalid Reality short ID')
            spider_x = param('spx', '/') or '/'
            if not spider_x.startswith('/'):
                raise ConfigError('invalid Reality spider path')
            reality: dict = {
                'show': False,
                'publicKey': public_key,
                'shortId': short_id,
                'serverName': server_name,
                'fingerprint': fingerprint,
                'spiderX': spider_x,
            }
            if param('pqv'):
                reality['mldsa65Verify'] = _base64_key(param('pqv'), 1952)
            stream['realitySettings'] = reality
    return outbound


def generate_full_json_config(outbound_proxies: list[dict]) -> dict:
    """تولید ساختار کامل JSON نهایی"""
    base_config: dict = {
        'dns': {
            'hosts': {
                'domain:googleapis.cn': 'googleapis.com',
                'dns.alidns.com': [
                    '223.5.5.5',
                    '223.6.6.6',
                    '2400:3200::1',
                    '2400:3200:baba::1',
                ],
                'one.one.one.one': [
                    '1.1.1.1',
                    '1.0.0.1',
                    '2606:4700:4700::1111',
                    '2606:4700:4700::1001',
                ],
                'dns.cloudflare.com': [
                    '104.16.132.229',
                    '104.16.133.229',
                    '2606:4700::6810:84e5',
                    '2606:4700::6810:85e5',
                ],
                'dns.google': [
                    '8.8.8.8',
                    '8.8.4.4',
                    '2001:4860:4860::8888',
                    '2001:4860:4860::8844',
                ],
            },
            'servers': [
                '1.1.1.1',
                {'address': '1.1.1.1', 'domains': ['geosite:google']},
                {
                    'address': '223.5.5.5',
                    'domains': [
                        'domain:alidns.com',
                        'domain:doh.pub',
                        'domain:dot.pub',
                        'geosite:cn',
                    ],
                    'expectIPs': ['geoip:cn'],
                    'skipFallback': True,
                    'tag': 'domestic-dns',
                },
            ],
            'tag': 'dns-module',
        },
        'inbounds': [
            {
                'listen': '127.0.0.1',
                'port': 10808,
                'protocol': 'socks',
                'settings': {'auth': 'noauth', 'udp': True, 'userLevel': 8},
                'sniffing': {
                    'destOverride': ['http', 'tls'],
                    'enabled': True,
                    'routeOnly': False,
                },
                'tag': 'socks',
            }
        ],
        'log': {'loglevel': 'warning'},
        'observatory': {
            'enableConcurrency': True,
            'probeInterval': '3m',
            'probeUrl': 'https://www.gstatic.com/generate_204',
            'subjectSelector': ['proxy-'],
        },
        'outbounds': [],
        'policy': {
            'levels': {
                '8': {
                    'connIdle': 300,
                    'downlinkOnly': 1,
                    'handshake': 4,
                    'uplinkOnly': 1,
                }
            },
            'system': {
                'statsOutboundDownlink': True,
                'statsOutboundUplink': True,
            },
        },
        'remarks': 'javidsub Intelligent Selection',
        'routing': {
            'balancers': [
                {
                    'selector': ['proxy-'],
                    'strategy': {'type': 'leastPing'},
                    'tag': 'proxy-round',
                }
            ],
            'domainStrategy': 'AsIs',
            'rules': [
                {
                    'network': 'udp',
                    'outboundTag': 'block',
                    'port': '443',
                    'type': 'field',
                },
                {
                    'balancerTag': 'proxy-round',
                    'domain': ['geosite:google'],
                    'type': 'field',
                },
                {
                    'ip': ['geoip:private'],
                    'outboundTag': 'direct',
                    'type': 'field',
                },
                {
                    'domain': ['geosite:private'],
                    'outboundTag': 'direct',
                    'type': 'field',
                },
                {
                    'ip': ['geoip:cn'],
                    'outboundTag': 'direct',
                    'type': 'field',
                },
                {
                    'domain': ['geosite:cn'],
                    'outboundTag': 'direct',
                    'type': 'field',
                },
                {
                    'inboundTag': ['domestic-dns'],
                    'outboundTag': 'direct',
                    'type': 'field',
                },
                {
                    'balancerTag': 'proxy-round',
                    'inboundTag': ['dns-module'],
                    'type': 'field',
                },
                {
                    'balancerTag': 'proxy-round',
                    'network': 'tcp,udp',
                    'type': 'field',
                },
            ],
        },
        'stats': {},
    }

    # افزودن تمام پروکسی‌ها به خروجی‌ها
    base_config['outbounds'].extend(outbound_proxies)

    # افزودن Direct و Block در انتهای لیست Outbounds
    base_config['outbounds'].append(
        {
            'protocol': 'freedom',
            'settings': {'domainStrategy': 'UseIP'},
            'tag': 'direct',
        }
    )
    base_config['outbounds'].append(
        {
            'protocol': 'blackhole',
            'settings': {'response': {'type': 'http'}},
            'tag': 'block',
        }
    )

    return base_config



def write_outputs(
    raw_configs: list[str],
    outbounds: list[dict],
    output_dir: Path | str = '.',
) -> None:
    """Stage outputs and replace them together, restoring old files on errors."""
    if not raw_configs or not outbounds:
        raise ValueError('Refusing to write an empty subscription or Xray config')

    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    chunk_count = (len(raw_configs) + CHUNK_SIZE - 1) // CHUNK_SIZE
    relative_files = [Path('javidsub'), Path('final_sub.txt')]
    relative_files.extend(
        Path('json_configs') / f'configs_{index}.json'
        for index in range(1, chunk_count + 1)
    )

    with tempfile.TemporaryDirectory(prefix='.sub-collector-', dir=root) as temporary:
        staging = Path(temporary) / 'new'
        backup = Path(temporary) / 'backup'
        (staging / 'json_configs').mkdir(parents=True)
        (staging / 'javidsub').write_text('\n'.join(raw_configs) + '\n', encoding='utf-8')
        with (staging / 'final_sub.txt').open('w', encoding='utf-8') as file:
            json.dump(generate_full_json_config(outbounds), file, ensure_ascii=False, indent=2, allow_nan=False)
            file.write('\n')
        for index in range(chunk_count):
            chunk = raw_configs[index * CHUNK_SIZE : (index + 1) * CHUNK_SIZE]
            chunk_data = {'chunk_index': index + 1, 'total_configs': len(chunk), 'configs': chunk}
            with (staging / relative_files[index + 2]).open('w', encoding='utf-8') as file:
                json.dump(chunk_data, file, ensure_ascii=False, indent=2)
                file.write('\n')

        chunk_dir = root / 'json_configs'
        chunk_dir.mkdir(exist_ok=True)
        stale_files = sorted(
            path.relative_to(root)
            for path in chunk_dir.glob('configs_*.json')
            if re.fullmatch(r'configs_\d+\.json', path.name)
            and (path.is_file() or path.is_symlink())
            and path.relative_to(root) not in relative_files
        )

        # Nothing is replaced until all new files and backups have been written.
        for relative in [*relative_files, *stale_files]:
            destination = root / relative
            if destination.exists() or destination.is_symlink():
                if destination.is_dir() and not destination.is_symlink():
                    raise OSError('An output path is a directory')
                backup_file = backup / relative
                backup_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(destination, backup_file, follow_symlinks=False)

        changed: list[Path] = []
        try:
            for relative in relative_files:
                os.replace(staging / relative, root / relative)
                changed.append(relative)
            for relative in stale_files:
                (root / relative).unlink()
                changed.append(relative)
        except OSError:
            # Restore both replaced and deleted outputs if any operation fails.
            for relative in reversed(changed):
                saved = backup / relative
                if saved.exists() or saved.is_symlink():
                    os.replace(saved, root / relative)
                else:
                    (root / relative).unlink(missing_ok=True)
            raise


def main() -> int:
    """Fetch all sources and publish only a complete, usable result."""
    try:
        urls = subscription_urls(os.environ.get('SUB_URLS', ''))
        raw_configs: list[str] = []
        seen: set[str] = set()
        for index, url in enumerate(urls, start=1):
            logger.info('Fetching subscription %d/%d.', index, len(urls))
            try:
                lines = fetch_and_decode(url)
            except SubscriptionError as error:
                raise SubscriptionError(f'subscription #{index}: {error}') from None

            valid_in_source = 0
            invalid_in_source = 0
            for line in lines:
                link = line.strip()
                if is_valid_vless_url(link):
                    valid_in_source += 1
                    # The fragment is only a display name, not connection data.
                    identity = link.partition('#')[0]
                    if identity not in seen:
                        seen.add(identity)
                        raw_configs.append(link)
                elif link.lower().startswith('vless://'):
                    invalid_in_source += 1
            if invalid_in_source:
                logger.warning(
                    'Subscription #%d contains %d malformed VLESS link(s).',
                    index, invalid_in_source,
                )
            if not valid_in_source:
                raise SubscriptionError(
                    f'subscription #{index} contains no valid VLESS links'
                )

        logger.info('Collected %d unique VLESS links.', len(raw_configs))
        outbounds: list[dict] = []
        for link in raw_configs:
            outbound = parse_vless_to_outbound(link, tag_name=f'proxy-{len(outbounds) + 1}')
            if outbound is not None:
                outbounds.append(outbound)
        if not outbounds:
            raise SubscriptionError('no VLESS links can be converted to an Xray outbound')
        logger.info('Converted %d/%d links to Xray outbounds.', len(outbounds), len(raw_configs))
        write_outputs(raw_configs, outbounds)
    except SubscriptionError as error:
        logger.error('Update aborted: %s. Existing output files were not changed.', error)
        return 1
    except OSError:
        logger.error('Could not write the output files; the update was aborted.')
        return 1

    logger.info('Subscription and Xray configuration updated successfully.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

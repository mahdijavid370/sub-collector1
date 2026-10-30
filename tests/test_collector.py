import base64
import gzip
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import quote, urlencode, urlsplit

import collector

SCRIPT = Path(collector.__file__).resolve()
UUID1 = 'd31ef4e4-3cb4-4cc2-b673-52d14c8ed977'
UUID2 = 'cc23637c-a67c-4976-8335-1f73a6253814'
UUID3 = '527a594f-f331-4649-b8c6-5869c1a1ab84'
PUBLIC_KEY = base64.urlsafe_b64encode(b'k' * 32).decode().rstrip('=')


def make_link(user=UUID1, host='server.test', port=443, query='', fragment='Test node'):
    return f'vless://{user}@{host}:{port}' + (f'?{query}' if query else '') + f'#{fragment}'


def get_stream(link):
    outbound = collector.parse_vless_to_outbound(link, 'proxy-1')
    if outbound is None:
        raise AssertionError('Expected a convertible outbound')
    return outbound['streamSettings']


class URLTests(unittest.TestCase):
    def test_source_urls_are_validated_deduplicated_and_keep_order(self):
        urls = collector.subscription_urls(
            '\ufeffhttps://one.example/sub?token=abc\n\n# comment\n'
            'http://two.example/sub\nhttps://one.example/sub?token=abc\n'
        )
        self.assertEqual(urls, [
            'https://one.example/sub?token=abc', 'http://two.example/sub',
        ])

    def test_missing_invalid_or_non_http_sources_are_rejected_without_secrets(self):
        for raw in ('', '# comment only', 'file:///tmp/private-secret',
                    'https://example.com:bad/sub?private-secret=abc',
                    'https://example.com/one https://example.com/two?private-secret=abc',
                    'https://example.com:0/'):
            with self.subTest(raw=raw):
                with self.assertRaises(collector.SubscriptionError) as result:
                    collector.subscription_urls(raw)
                self.assertNotIn('private-secret', str(result.exception))

    def test_vless_validation_accepts_uppercase_uuid_ipv6_and_display_names(self):
        link = make_link(UUID1.upper(), '[2001:db8::1]', 8443,
                         query='security=tls', fragment='🇫🇷 Paris node')
        self.assertTrue(collector.is_valid_vless_url(link))
        self.assertTrue(collector.is_valid_vless_url(link.replace('vless://', 'VLESS://')))
        outbound = collector.parse_vless_to_outbound(link, 'proxy-1')
        self.assertIsNotNone(outbound)
        vnext = outbound['settings']['vnext'][0]
        self.assertEqual(vnext['address'], '2001:db8::1')
        self.assertEqual(vnext['port'], 8443)
        self.assertEqual(vnext['users'][0]['id'], UUID1)

    def test_short_custom_xray_ids_are_mapped_to_uuidv5(self):
        for identifier, expected in [
            ('custom-user', '73641eb6-f94b-5b94-b083-8bd4ddcd0ba6'),
            ('我爱🍉老师1314', '5783a3e7-e373-51cd-8642-c83782b807c5'),
        ]:
            with self.subTest(identifier=identifier):
                link = make_link(user=quote(identifier, safe=''))
                self.assertTrue(collector.is_valid_vless_url(link))
                outbound = collector.parse_vless_to_outbound(link, 'proxy-1')
                self.assertEqual(outbound['settings']['vnext'][0]['users'][0]['id'], expected)

    def test_vless_validation_rejects_bad_authority_and_ports(self):
        invalid = [
            '', 'https://example.com',
            'vless://' + ('x' * 31) + '@server.test:443',
            'vless://' + ('-' * 36) + '@server.test:443',
            make_link(port=0), make_link(port=65536),
            f'vless://{UUID1}@server.test', f'vless://{UUID1}@:443',
            f'vless://{UUID1}:password@server.test:443',
            f'vless://{UUID1}@bad host:443',
            f'vless://{UUID1}@[not-ipv6]:443',
            f'vless://{UUID1}@server.test:abc',
            make_link(query='path=unescaped space'),
        ]
        for link in invalid:
            with self.subTest(link=link):
                self.assertFalse(collector.is_valid_vless_url(link))

    def test_private_addresses_match_current_xray_rules(self):
        private = ['10.1.2.3', '172.16.0.1', '192.168.1.1', '127.0.0.1',
                   '169.254.1.1', '::1', 'fd00::1', 'fe80::1',
                   'localhost', 'server', 'server.test', 'box.home.arpa']
        public = ['8.8.8.8', '100.64.0.1', '203.0.113.1', '2001:db8::1',
                  'example.com', 'test.example.com', '1a']
        for address in private:
            with self.subTest(address=address):
                self.assertTrue(collector._is_private_xray_address(address))
        for address in public:
            with self.subTest(address=address):
                self.assertFalse(collector._is_private_xray_address(address))


class OutboundTests(unittest.TestCase):
    def test_tcp_reality_preserves_flow_and_reality_parameters(self):
        query = urlencode({
            'type': 'tcp', 'security': 'reality', 'encryption': 'none',
            'flow': 'xtls-rprx-vision', 'pbk': PUBLIC_KEY, 'sid': 'a1b2',
            'sni': 'sni.example', 'fp': 'firefox', 'spx': '/test?x=1',
        })
        outbound = collector.parse_vless_to_outbound(make_link(query=query), 'proxy-7')
        self.assertEqual(outbound['tag'], 'proxy-7')
        self.assertEqual(outbound['settings']['vnext'][0]['users'][0]['flow'], 'xtls-rprx-vision')
        self.assertEqual(outbound['streamSettings']['realitySettings'], {
            'show': False, 'publicKey': PUBLIC_KEY, 'shortId': 'a1b2',
            'serverName': 'sni.example', 'fingerprint': 'firefox', 'spiderX': '/test?x=1',
        })

    def test_xhttp_reality_preserves_mode_extra_and_single_url_decoding(self):
        extra = quote(json.dumps({'xPaddingBytes': '100-1000'}), safe='')
        query = (
            f'type=xhttp&security=reality&pbk={PUBLIC_KEY}&sid=aa'
            f'&host=cdn.example&path=%2Fa%252Fb%3Fx%3D1%2By&mode=stream-up&extra={extra}'
            '&spx=%2Fhello%252Fworld'
        )
        stream = get_stream(make_link(query=query))
        self.assertEqual(stream['network'], 'xhttp')
        self.assertEqual(stream['xhttpSettings'], {
            'path': '/a%2Fb?x=1+y', 'host': 'cdn.example',
            'mode': 'stream-up', 'extra': {'xPaddingBytes': '100-1000'},
        })
        self.assertEqual(stream['realitySettings']['spiderX'], '/hello%2Fworld')

    def test_websocket_tls_preserves_host_path_and_alpn(self):
        query = ('type=ws&security=tls&host=cdn.example&path=%2Fchat%252Fv2'
                 '&sni=front.example&fp=firefox&alpn=h2%2Chttp%2F1.1')
        stream = get_stream(make_link(host='example.com', query=query))
        self.assertEqual(stream['wsSettings'], {
            'path': '/chat%2Fv2', 'host': 'cdn.example',
        })
        self.assertEqual(stream['tlsSettings']['serverName'], 'front.example')
        self.assertEqual(stream['tlsSettings']['fingerprint'], 'firefox')
        self.assertEqual(stream['tlsSettings']['alpn'], ['h2', 'http/1.1'])
        self.assertFalse(stream['tlsSettings']['allowInsecure'])

    def test_grpc_and_httpupgrade_settings(self):
        grpc = get_stream(make_link(query='type=grpc&security=tls&serviceName=api%2Fv1&authority=cdn.example&mode=multi'))
        self.assertEqual(grpc['grpcSettings'], {
            'serviceName': 'api/v1', 'authority': 'cdn.example', 'multiMode': True,
        })
        upgrade = get_stream(make_link(query='type=httpupgrade&security=tls&host=cdn.example&path=%2Fup'))
        self.assertEqual(upgrade['httpupgradeSettings'], {'path': '/up', 'host': 'cdn.example'})

    def test_tcp_http_header_preserves_path_and_hosts(self):
        stream = get_stream(make_link(query='type=raw&headerType=http&host=a.test%2Cb.test&path=%2Fa%2C%2Fb'))
        self.assertEqual(stream['network'], 'tcp')
        self.assertEqual(stream['tcpSettings']['header'], {
            'type': 'http', 'request': {'path': ['/a', '/b'], 'headers': {'Host': ['a.test', 'b.test']}},
        })

    def test_kcp_maps_legacy_fields_to_new_xray_finalmask(self):
        stream = get_stream(make_link(query='type=kcp&headerType=wechat-video&seed=secret-seed'))
        self.assertNotIn('kcpSettings', stream)
        self.assertEqual(stream['finalmask']['udp'], [
            {'type': 'mkcp-legacy', 'settings': {'value': 'secret-seed'}},
            {'type': 'mkcp-legacy', 'settings': {'header': 'wechat'}},
        ])
        default = get_stream(make_link(query='type=kcp'))
        self.assertEqual(default['finalmask']['udp'], [{'type': 'mkcp-legacy'}])

    def test_public_plaintext_is_skipped_but_private_and_encrypted_are_supported(self):
        with mock.patch.object(collector.logger, 'warning'):
            self.assertIsNone(collector.parse_vless_to_outbound(make_link(host='example.com'), 'proxy-1'))
        self.assertIsNotNone(collector.parse_vless_to_outbound(make_link(host='box.local'), 'proxy-1'))
        encryption = f'mlkem768x25519plus.native.0rtt.100-111-1111.{PUBLIC_KEY}'
        link = make_link(host='example.com', query=urlencode({'encryption': encryption}))
        outbound = collector.parse_vless_to_outbound(link, 'proxy-1')
        self.assertEqual(outbound['settings']['vnext'][0]['users'][0]['encryption'], encryption)

    def test_unsupported_or_invalid_settings_do_not_poison_full_config(self):
        bad_queries = [
            'type=quic', 'security=xtls', 'security=tls&allowInsecure=1',
            'security=tls&alpn=fromMitm%2Ch2', 'security=tls&fp=nonexistent', 'type=ws&security=reality&pbk=' + PUBLIC_KEY,
            'security=reality&pbk=bad', 'security=reality&pbk=' + PUBLIC_KEY + '&sid=zz',
            'security=reality&pbk=' + PUBLIC_KEY + '&sid=abc',
            'security=reality&pbk=' + PUBLIC_KEY + '&spx=no-slash',
            'security=reality&pbk=' + PUBLIC_KEY + '&fp=unsafe',
            'type=xhttp&mode=invalid', 'type=xhttp&extra=not-json',
            'type=xhttp&extra=%5B%5D', 'type=xhttp&extra=%7B%22a%22%3ANaN%7D',
            'type=xhttp&extra=%7B%22a%22%3A1e999%7D',
            'type=xhttp&extra=%7B%22a%22%3A%22%5Cud800%22%7D', 'type=grpc&mode=invalid',
            'type=tcp&headerType=unsupported', 'type=kcp&headerType=unsupported',
            'encryption=unknown', 'encryption=mlkem768x25519plus.native.0rtt.padding',
            'flow=unknown', 'flow=xtls-rprx-vision',
        ]
        for query in bad_queries:
            with self.subTest(query=query), mock.patch.object(collector.logger, 'warning'):
                self.assertIsNone(collector.parse_vless_to_outbound(make_link(query=query), 'proxy-1'))

    def test_base_configuration_contains_balancer_and_unique_tags(self):
        outbounds = [collector.parse_vless_to_outbound(make_link(user=user), f'proxy-{i}')
                     for i, user in enumerate([UUID1, UUID2], 1)]
        config = collector.generate_full_json_config(outbounds)
        self.assertEqual([item['tag'] for item in config['outbounds']],
                         ['proxy-1', 'proxy-2', 'direct', 'block'])
        balancer = config['routing']['balancers'][0]
        self.assertEqual(balancer['selector'], ['proxy-'])
        self.assertEqual(balancer['strategy']['type'], 'leastPing')
        self.assertEqual(balancer['fallbackTag'], 'proxy-1')
        self.assertNotIn('observatory', config)
        observer = config['burstObservatory']
        self.assertEqual(observer['subjectSelector'], ['proxy-'])
        self.assertEqual(observer['pingConfig']['interval'], '45s')
        self.assertEqual(observer['pingConfig']['sampling'], 1)
        self.assertEqual(observer['pingConfig']['timeout'], '5s')
        self.assertEqual(observer['pingConfig']['httpMethod'], 'HEAD')
        self.assertEqual(config['policy']['levels']['8']['downlinkOnly'], 30)
        self.assertEqual(config['policy']['levels']['8']['uplinkOnly'], 30)
        self.assertEqual(config['policy']['levels']['8']['handshake'], 8)

    def test_fallback_must_be_a_proxy_tag(self):
        with self.assertRaises(ValueError):
            collector.generate_full_json_config([{'tag': 'direct', 'protocol': 'freedom'}])
        with self.assertRaises(ValueError):
            collector.generate_full_json_config([{}])
        with self.assertRaises(ValueError):
            collector.generate_full_json_config([{'tag': 'proxy-1', 'protocol': 'freedom'}])

    def test_large_subscriptions_limit_steady_state_probe_rate(self):
        for count, interval in [(90, 45), (91, 46), (1001, 501)]:
            with self.subTest(count=count):
                nodes = [{'tag': f'proxy-{i}', 'protocol': 'vless'} for i in range(1, count + 1)]
                config = collector.generate_full_json_config(nodes)
                self.assertEqual(config['burstObservatory']['pingConfig']['interval'], f'{interval}s')
                self.assertLessEqual(count / interval, 2)
                self.assertEqual(config['routing']['balancers'][0]['fallbackTag'], 'proxy-1')


class TestHTTPServer:
    """A local-only HTTP server; route responses may be sequences for retry tests."""

    def __enter__(self):
        owner = self
        self.routes = {}
        self.calls = Counter()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                path = urlsplit(self.path).path
                owner.calls[path] += 1
                response = owner.routes.get(path, (404, {}, b'not found'))
                if isinstance(response, list):
                    response = response[min(owner.calls[path] - 1, len(response) - 1)]
                status, headers, body = response
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f'http://127.0.0.1:{self.server.server_port}'
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class FetchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.http = TestHTTPServer().__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.http.__exit__(None, None, None)

    def setUp(self):
        self.http.routes.clear()
        self.http.calls.clear()

    def test_plain_bom_and_unpadded_wrapped_urlsafe_base64(self):
        link = make_link(fragment='🇫🇷 test')
        plain = '\ufeff' + link + '\n' + make_link(user=UUID2)
        self.http.routes['/plain'] = (200, {}, plain.encode())
        encoded = base64.urlsafe_b64encode(plain.encode()).decode().rstrip('=')
        wrapped = '\n'.join(encoded[index:index + 35] for index in range(0, len(encoded), 35))
        self.http.routes['/encoded'] = (200, {}, wrapped.encode())
        self.assertEqual(collector.fetch_and_decode(self.http.base_url + '/plain'), plain.lstrip('\ufeff').splitlines())
        self.assertEqual(collector.fetch_and_decode(self.http.base_url + '/encoded'), plain.lstrip('\ufeff').splitlines())

    def test_gzip_content_is_decoded(self):
        link = make_link()
        self.http.routes['/gzip'] = (200, {'Content-Encoding': 'gzip'}, gzip.compress(link.encode()))
        self.assertEqual(collector.fetch_and_decode(self.http.base_url + '/gzip'), [link])

    def test_temporary_http_failures_are_retried(self):
        link = make_link()
        self.http.routes['/retry'] = [
            (503, {}, b'temporary'), (429, {}, b'busy'), (200, {}, link.encode()),
        ]
        with mock.patch.object(collector.time, 'sleep') as sleep:
            self.assertEqual(collector.fetch_and_decode(self.http.base_url + '/retry'), [link])
        self.assertEqual(self.http.calls['/retry'], 3)
        self.assertEqual(sleep.call_count, 2)

    def test_truncated_response_retries_and_fails_instead_of_using_partial_data(self):
        body = make_link().encode()
        self.http.routes['/truncated'] = (200, {'Content-Length': str(len(body) + 20)}, body)
        with (mock.patch.object(collector.time, 'sleep'),
              mock.patch.object(collector.logger, 'warning'),
              self.assertRaises(collector.SubscriptionError)):
            collector.fetch_and_decode(self.http.base_url + '/truncated')
        self.assertEqual(self.http.calls['/truncated'], collector.FETCH_ATTEMPTS)

    def test_http_error_never_includes_the_url_or_token(self):
        url = self.http.base_url + '/missing?token=very-private-token'
        with self.assertRaises(collector.SubscriptionError) as result:
            collector.fetch_and_decode(url)
        self.assertIn('404', str(result.exception))
        self.assertNotIn(url, str(result.exception))
        self.assertNotIn('very-private-token', str(result.exception))
        self.assertEqual(self.http.calls['/missing'], 1)

    def test_invalid_empty_non_utf8_and_oversized_responses_fail(self):
        corrupt_gzip = bytearray(gzip.compress(b'a' * 32))
        corrupt_gzip[10] = 0xff
        self.http.routes.update({
            '/empty': (200, {}, b' '),
            '/invalid': (200, {}, b'\xff\xfe\x00'),
            '/br': (200, {'Content-Encoding': 'br'}, b'something'),
            '/big': (200, {}, b'a' * 65),
            '/gzip-big': (200, {'Content-Encoding': 'gzip'}, gzip.compress(b'a' * 1000)),
            '/gzip-bad': (200, {'Content-Encoding': 'gzip'}, b'not gzip'),
            '/gzip-deflate-bad': (200, {'Content-Encoding': 'gzip'}, bytes(corrupt_gzip)),
        })
        for route in ['/empty', '/invalid', '/br', '/big', '/gzip-big', '/gzip-bad', '/gzip-deflate-bad']:
            with (self.subTest(route=route),
                  mock.patch.object(collector, 'MAX_SUBSCRIPTION_BYTES', 64),
                  self.assertRaises(collector.SubscriptionError)):
                collector.fetch_and_decode(self.http.base_url + route)


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.outbounds = [{'tag': 'proxy-1', 'protocol': 'vless'}]

    def test_chunk_boundaries_and_stale_chunk_cleanup(self):
        configs = [f'config-{i}' for i in range(1001)]
        collector.write_outputs(configs, self.outbounds, self.root)
        chunk1 = json.loads((self.root / 'json_configs/configs_1.json').read_text())
        chunk2 = json.loads((self.root / 'json_configs/configs_2.json').read_text())
        self.assertEqual((chunk1['total_configs'], chunk2['total_configs']), (1000, 1))
        self.assertEqual(chunk2['configs'], ['config-1000'])
        other = self.root / 'json_configs/notes.json'
        other.write_text('keep me')
        (self.root / 'json_configs/configs_0.json').write_text('old')
        collector.write_outputs(configs[:1], self.outbounds, self.root)
        self.assertFalse((self.root / 'json_configs/configs_2.json').exists())
        self.assertFalse((self.root / 'json_configs/configs_0.json').exists())
        self.assertEqual(other.read_text(), 'keep me')
        self.assertEqual((self.root / 'javidsub').read_text(), 'config-0\n')
        self.assertEqual(json.loads((self.root / 'json_configs/configs_1.json').read_text())['total_configs'], 1)

    def test_write_failure_restores_existing_files(self):
        collector.write_outputs(['old'], self.outbounds, self.root)
        stale = self.root / 'json_configs/configs_2.json'
        stale.write_text('old stale chunk')
        files = [self.root / 'javidsub', self.root / 'final_sub.txt',
                 self.root / 'json_configs/configs_1.json', stale]
        before = {path: path.read_bytes() for path in files}
        real_replace = os.replace

        def fail_second_write(source, destination):
            if Path(source).name == 'final_sub.txt' and Path(source).parent.name == 'new':
                raise OSError('simulated failure')
            return real_replace(source, destination)

        with (mock.patch.object(collector.os, 'replace', side_effect=fail_second_write),
              self.assertRaises(OSError)):
            collector.write_outputs(['new'], self.outbounds, self.root)
        self.assertEqual({path: path.read_bytes() for path in files}, before)

    def test_empty_outputs_are_refused(self):
        for links, outbounds in [([], self.outbounds), (['link'], [])]:
            with self.assertRaises(ValueError):
                collector.write_outputs(links, outbounds, self.root)
        self.assertEqual(list(self.root.iterdir()), [])


class CommandLineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.http = TestHTTPServer().__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.http.__exit__(None, None, None)

    def setUp(self):
        self.http.routes.clear()
        self.http.calls.clear()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        (self.root / 'json_configs').mkdir()
        self.existing = {
            'javidsub': 'previous raw\n',
            'final_sub.txt': 'previous JSON\n',
            'json_configs/configs_1.json': 'previous chunk 1\n',
            'json_configs/configs_2.json': 'previous chunk 2\n',
        }
        for name, content in self.existing.items():
            (self.root / name).write_text(content)

    def run_collector(self, secret=None):
        env = os.environ.copy()
        env.pop('SUB_URLS', None)
        if secret is not None:
            env['SUB_URLS'] = secret
        return subprocess.run([sys.executable, str(SCRIPT)], cwd=self.root, env=env,
                              text=True, capture_output=True, timeout=15, check=False)

    def assert_previous_files_unchanged(self):
        for name, content in self.existing.items():
            self.assertEqual((self.root / name).read_text(), content)

    def test_missing_secret_fails_and_preserves_files(self):
        result = self.run_collector()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SUB_URLS', result.stderr)
        self.assert_previous_files_unchanged()

    def test_partial_http_failure_does_not_publish_partial_results_or_log_secrets(self):
        link = make_link()
        self.http.routes['/ok'] = (200, {}, link.encode())
        secret = self.http.base_url + '/ok?token=secret-A\n' + self.http.base_url + '/missing?token=secret-B'
        result = self.run_collector(secret)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('HTTP error 404', result.stderr)
        self.assertNotIn('secret-A', result.stderr)
        self.assertNotIn('secret-B', result.stderr)
        self.assertNotIn(UUID1, result.stderr)
        self.assert_previous_files_unchanged()

    def test_empty_or_invalid_source_fails_even_when_another_source_succeeds(self):
        self.http.routes['/ok'] = (200, {}, make_link().encode())
        self.http.routes['/empty'] = (200, {}, b'no usable links here')
        result = self.run_collector(self.http.base_url + '/ok\n' + self.http.base_url + '/empty')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('no valid VLESS links', result.stderr)
        self.assert_previous_files_unchanged()

    def test_no_convertible_outbounds_fails_and_preserves_files(self):
        self.http.routes['/unsupported'] = (200, {}, make_link(query='type=quic').encode())
        result = self.run_collector(self.http.base_url + '/unsupported')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('no VLESS links can be converted', result.stderr)
        self.assert_previous_files_unchanged()

    def test_end_to_end_plain_and_base64_deduplicate_and_clean_stale(self):
        first = make_link(user=UUID1, query='type=tcp&security=tls')
        second = make_link(user=UUID2, query='type=ws&security=tls&path=%2Fws')
        third = make_link(user=UUID3, query=f'type=xhttp&security=reality&pbk={PUBLIC_KEY}&path=%2Fx&mode=stream-up')
        unsupported = make_link(user=str(uuid.UUID(int=4)), query='type=quic')
        self.http.routes['/plain'] = (200, {}, f'{first}\n{second}\n'.encode())
        same_node_other_label = second.partition('#')[0] + '#A different label'
        encoded = base64.urlsafe_b64encode(
            f'{same_node_other_label}\n{third}\n{unsupported}\n'.encode()
        ).rstrip(b'=')
        self.http.routes['/b64'] = (200, {}, encoded)
        secret = self.http.base_url + '/plain?token=secret-A\n' + self.http.base_url + '/b64?token=secret-B'
        result = self.run_collector(secret)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('secret-A', result.stderr)
        self.assertNotIn('secret-B', result.stderr)
        self.assertNotIn(UUID1, result.stderr)
        self.assertEqual((self.root / 'javidsub').read_text().splitlines(), [first, second, third, unsupported])
        chunk = json.loads((self.root / 'json_configs/configs_1.json').read_text())
        self.assertEqual(chunk['total_configs'], 4)
        self.assertEqual(chunk['configs'], [first, second, third, unsupported])
        self.assertFalse((self.root / 'json_configs/configs_2.json').exists())
        final = json.loads((self.root / 'final_sub.txt').read_text())
        self.assertEqual([item['tag'] for item in final['outbounds']],
                         ['proxy-1', 'proxy-2', 'proxy-3', 'direct', 'block'])
        self.assertEqual(final['outbounds'][2]['streamSettings']['xhttpSettings']['mode'], 'stream-up')
        before = {path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        again = self.run_collector(secret)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual({path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()}, before)


class WorkflowTests(unittest.TestCase):
    def test_schedule_secret_validation_and_push_are_configured(self):
        workflow = (SCRIPT.parent / '.github/workflows/update.yml').read_text(encoding='utf-8')
        self.assertIn("cron: '17 */4 * * *'", workflow)
        self.assertIn('SUB_URLS: ${{ secrets.SUB_URLS }}', workflow)
        self.assertIn('python -m unittest discover -s tests -v', workflow)
        self.assertIn('run -test -format json -c final_sub.txt', workflow)
        self.assertIn("-p 'test_xray_runtime.py'", workflow)
        self.assertIn('XRAY_BINARY: ${{ runner.temp }}/xray/xray', workflow)
        self.assertIn('sha256sum --check --status', workflow)
        self.assertIn('git add -A -- javidsub final_sub.txt json_configs/', workflow)
        self.assertIn('git push origin "HEAD:$GITHUB_REF"', workflow)
        self.assertIn('cancel-in-progress: false', workflow)


if __name__ == '__main__':
    unittest.main()

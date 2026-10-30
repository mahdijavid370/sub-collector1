import contextlib
import copy
import io
import json
import select
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

import collector
import speedtest


class FakeProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.paths.append(self.path)
        path = urlsplit(self.path).path
        if path == '/denied':
            self.send_response(403)
            self.end_headers()
            return
        body = b'x' * (1024 if path == '/short' else 16384)
        self.send_response(200)
        content_type = {'/block-page': 'text/html', '/text-file': 'text/plain'}.get(path, 'application/octet-stream')
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if path == '/trickle':
            try:
                for _ in range(10):
                    self.wfile.write(b'x')
                    self.wfile.flush()
                    time.sleep(0.1)
            except OSError:
                pass
        else:
            self.wfile.write(body)

    def log_message(self, *_args):
        pass


class MeasurementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proxy = ThreadingHTTPServer(('127.0.0.1', 0), FakeProxyHandler)
        cls.proxy.daemon_threads = True
        cls.proxy.paths = []
        cls.thread = threading.Thread(target=cls.proxy.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.proxy.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.proxy.shutdown()
        cls.proxy.server_close()
        cls.thread.join()

    def measure(self, path, timeout=2):
        target = speedtest.parse_test_url('http://not-a-real-host.invalid' + path)
        return speedtest.measure_sample(self.port, target, 16384, timeout)

    def test_download_uses_proxy_and_measures_all_bytes(self):
        result = self.measure('/ok')
        self.assertIsNotNone(result)
        self.assertGreater(result.bytes_per_second, 0)
        self.assertGreater(result.latency_seconds, 0)
        self.assertIn('http://not-a-real-host.invalid/ok', self.proxy.paths)
        # A full-length plain-text payload can also be a valid test file.
        self.assertIsNotNone(self.measure('/text-file'))

    def test_errors_short_bodies_and_block_pages_are_not_successes(self):
        for path in ('/denied', '/short', '/block-page'):
            with self.subTest(path=path):
                self.assertIsNone(self.measure(path))

    def test_trickle_has_an_overall_deadline(self):
        started = time.monotonic()
        self.assertIsNone(self.measure('/trickle', timeout=0.25))
        self.assertLess(time.monotonic() - started, 1.0)

    def test_scores_penalize_failed_attempts(self):
        with mock.patch.object(speedtest, 'measure_sample', side_effect=[speedtest.Sample(100.0, 0.25), None]):
            result = speedtest.measure_node('proxy-1', self.port, speedtest.parse_test_url('http://example.test/x'), 16384, 1, 2)
        self.assertEqual(result.samples_ok, 1)
        self.assertEqual(result.samples_total, 2)
        self.assertEqual(result.score, 50.0)

    def test_invalid_test_url_is_rejected_without_echoing_credentials(self):
        for url in ('file:///private', 'https://user:secret@example.test/', 'http://example.test:bad/',
                    'http://example.test:0/', 'http://example.test/with space'):
            with self.subTest(url=url), self.assertRaises(speedtest.SpeedTestError) as result:
                speedtest.parse_test_url(url)
            self.assertNotIn('secret', str(result.exception))


class TunnelProxyHandler(BaseHTTPRequestHandler):
    """Forward CONNECT to a local TLS server regardless of the test hostname."""

    def do_CONNECT(self):
        try:
            target = socket.create_connection(('127.0.0.1', self.server.target_port), timeout=2)
        except OSError:
            return
        try:
            self.send_response(200)
            self.end_headers()
            while True:
                readable, _, _ = select.select([self.connection, target], [], [], 3)
                if not readable:
                    return
                for source in readable:
                    chunk = source.recv(65536)
                    if not chunk:
                        return
                    (target if source is self.connection else self.connection).sendall(chunk)
        except OSError:
            pass
        finally:
            target.close()

    def log_message(self, *_args):
        pass


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is needed to generate a temporary TLS test certificate')
class TLSMeasurementTests(unittest.TestCase):
    def test_https_connect_verifies_certificate_and_downloads_through_the_proxy(self):
        with tempfile.TemporaryDirectory() as temporary:
            cert, key = Path(temporary) / 'cert.pem', Path(temporary) / 'key.pem'
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=test.invalid',
                '-addext', 'subjectAltName=DNS:test.invalid',
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            tls_server = ThreadingHTTPServer(('127.0.0.1', 0), FakeProxyHandler)
            tls_server.daemon_threads = True
            tls_server.paths = []
            tls_server.socket = context.wrap_socket(tls_server.socket, server_side=True)
            proxy = ThreadingHTTPServer(('127.0.0.1', 0), TunnelProxyHandler)
            proxy.daemon_threads = True
            proxy.target_port = tls_server.server_address[1]
            threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (tls_server, proxy)]
            for thread in threads:
                thread.start()
            try:
                target = speedtest.parse_test_url('https://test.invalid/ok')
                port = proxy.server_address[1]
                # A self-signed certificate is rejected without explicit trust.
                self.assertIsNone(speedtest.measure_sample(port, target, 16384, 3))
                trusted = ssl.create_default_context(cafile=str(cert))
                with mock.patch.object(speedtest.ssl, 'create_default_context', return_value=trusted):
                    result = speedtest.measure_sample(port, target, 16384, 3)
                self.assertIsNotNone(result)
                self.assertEqual(tls_server.paths, ['/ok'])
            finally:
                for server in (proxy, tls_server):
                    server.shutdown()
                    server.server_close()
                for thread in threads:
                    thread.join()


class OptimizationTests(unittest.TestCase):
    def setUp(self):
        self.nodes = [{'tag': f'proxy-{index}', 'protocol': 'vless'} for index in range(1, 4)]
        self.config = collector.generate_full_json_config(self.nodes)

    def test_selects_by_effective_speed_and_reliability_without_mutating_input(self):
        before = copy.deepcopy(self.config)
        results = [
            speedtest.Result('proxy-1', 2, 2, 100, 0.01),
            speedtest.Result('proxy-2', 1, 2, 300, 0.02),
            speedtest.Result('proxy-3', 2, 2, 130, 0.03),
        ]
        optimized, ranked = speedtest.optimized_config(self.config, results, 2)
        self.assertEqual([result.tag for result in ranked], ['proxy-2', 'proxy-3'])
        self.assertEqual([item['tag'] for item in optimized['outbounds']], ['proxy-2', 'proxy-3', 'direct', 'block'])
        self.assertEqual(optimized['routing']['balancers'][0]['fallbackTag'], 'proxy-2')
        self.assertEqual(self.config, before)

    def test_similarly_fast_results_prefer_different_server_endpoints(self):
        config = copy.deepcopy(self.config)
        for node, address in zip(config['outbounds'], ['a.invalid', 'a.invalid', 'b.invalid']):
            node['settings'] = {'vnext': [{'address': address, 'port': 443}]}
        results = [
            speedtest.Result('proxy-1', 2, 2, 100, 0.01),
            speedtest.Result('proxy-2', 2, 2, 99, 0.01),
            speedtest.Result('proxy-3', 2, 2, 90, 0.01),
        ]
        optimized, ranked = speedtest.optimized_config(config, results, 2)
        self.assertEqual([result.tag for result in ranked], ['proxy-1', 'proxy-3'])
        self.assertEqual(optimized['routing']['balancers'][0]['fallbackTag'], 'proxy-1')
        results[-1] = speedtest.Result('proxy-3', 2, 2, 60, 0.01)
        _, ranked = speedtest.optimized_config(config, results, 2)
        self.assertEqual([result.tag for result in ranked], ['proxy-1', 'proxy-2'])

    def test_recalculates_default_probe_interval_but_preserves_custom_interval(self):
        nodes = [{'tag': f'proxy-{index}', 'protocol': 'vless'} for index in range(1, 1002)]
        config = collector.generate_full_json_config(nodes)
        result = [speedtest.Result('proxy-1', 2, 2, 100, 0.01)]
        optimized, _ = speedtest.optimized_config(config, result, 1)
        expected = collector.generate_full_json_config(nodes[:1])['burstObservatory']['pingConfig']['interval']
        self.assertEqual(optimized['burstObservatory']['pingConfig']['interval'], expected)
        config['burstObservatory']['pingConfig']['interval'] = '7m'
        optimized, _ = speedtest.optimized_config(config, result, 1)
        self.assertEqual(optimized['burstObservatory']['pingConfig']['interval'], '7m')

    def test_failing_or_missing_results_do_not_make_an_output(self):
        with self.assertRaises(speedtest.SpeedTestError):
            speedtest.optimized_config(self.config, [], 3)
        with self.assertRaises(speedtest.SpeedTestError):
            speedtest.optimized_config(self.config, [speedtest.Result('unknown', 2, 2, 100, 0.1)], 3)

    def test_duplicate_tags_and_non_vless_profiles_are_rejected(self):
        duplicate = copy.deepcopy(self.config)
        duplicate['outbounds'][1]['tag'] = 'proxy-1'
        with self.assertRaises(speedtest.SpeedTestError):
            speedtest.candidate_outbounds(duplicate)
        with self.assertRaises(speedtest.SpeedTestError):
            speedtest.candidate_outbounds({'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}]})
        credential_in_tag = copy.deepcopy(self.config)
        credential_in_tag['outbounds'][0]['tag'] = 'proxy-private-token'
        with self.assertRaises(speedtest.SpeedTestError) as error:
            speedtest.candidate_outbounds(credential_in_tag)
        self.assertNotIn('private-token', str(error.exception))

    def test_rejects_invalid_balancer_before_starting_network_tests(self):
        invalid = copy.deepcopy(self.config)
        invalid['routing']['balancers'][0]['selector'] = ['direct']
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / 'original.json'
            original.write_text(json.dumps(invalid), encoding='utf-8')
            with mock.patch.object(speedtest.shutil, 'which', return_value='/fake/xray'), \
                    mock.patch.object(speedtest, 'benchmark_nodes') as benchmark, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(speedtest.main(['--input', str(original)]), 1)
                benchmark.assert_not_called()

    def test_benchmark_routing_forces_each_listener_through_its_node(self):
        config = speedtest._benchmark_config(self.nodes[:2], [11001, 11002])
        self.assertEqual([node['listen'] for node in config['inbounds']], ['127.0.0.1', '127.0.0.1'])
        self.assertEqual(config['routing']['rules'], [
            {'type': 'field', 'inboundTag': ['bench-1'], 'outboundTag': 'proxy-1'},
            {'type': 'field', 'inboundTag': ['bench-2'], 'outboundTag': 'proxy-2'},
        ])
        self.assertNotIn('direct', [outbound['tag'] for outbound in config['outbounds']])

    def test_failed_atomic_replace_preserves_previous_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'fast.txt'
            output.write_text('previous', encoding='utf-8')
            with mock.patch.object(speedtest.os, 'replace', side_effect=OSError), self.assertRaises(OSError):
                speedtest.write_config(self.config, output)
            self.assertEqual(output.read_text(), 'previous')
            self.assertEqual([path.name for path in Path(temporary).iterdir()], ['fast.txt'])

    def test_cli_will_not_overwrite_original_or_previous_output_on_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / 'original.txt'
            output = Path(temporary) / 'fast.txt'
            original.write_text(json.dumps(self.config), encoding='utf-8')
            output.write_text('previous', encoding='utf-8')
            with mock.patch.object(speedtest.shutil, 'which', return_value='/fake/xray'), \
                    mock.patch.object(speedtest, 'benchmark_nodes', return_value=[]), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(speedtest.main(['--input', str(original), '--output', str(output)]), 1)
                self.assertEqual(speedtest.main(['--input', str(original), '--output', str(original)]), 1)
            self.assertEqual(output.read_text(), 'previous')
            self.assertEqual(json.loads(original.read_text()), self.config)

    def test_cli_bounds_nodes_and_writes_a_separate_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / 'original.json'
            output = Path(temporary) / 'optimized.json'
            original.write_text(json.dumps(self.config), encoding='utf-8')
            results = [speedtest.Result('proxy-1', 2, 2, 100, 0.1)]
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(speedtest.shutil, 'which', return_value='/fake/xray'), \
                    mock.patch.object(speedtest, 'benchmark_nodes', return_value=results) as benchmark, \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(speedtest.main([
                    '--input', str(original), '--output', str(output), '--max-nodes', '2', '--top', '1',
                ]), 0)
            self.assertEqual(len(benchmark.call_args.args[0]), 2)
            self.assertIn('first 2 of 3', stderr.getvalue())
            self.assertIn('1.0 MiB', stderr.getvalue())
            optimized = json.loads(output.read_text(encoding='utf-8'))
            self.assertEqual([item['tag'] for item in optimized['outbounds']], ['proxy-1', 'direct', 'block'])
            self.assertEqual(json.loads(original.read_text()), self.config)

    def test_startup_failure_releases_reserved_ports(self):
        with self.assertRaises(speedtest.SpeedTestError), \
                speedtest.running_xray('/not-an-xray-executable', self.nodes[:1]):
            self.fail('Should not start a nonexistent executable')
        # Reserving new ephemeral ports still works after the startup error.
        ports, reservations = speedtest._reserve_ports(2)
        try:
            self.assertEqual(len(set(ports)), 2)
            for port in ports:
                self.assertTrue(0 < port < 65536)
        finally:
            for reservation in reservations:
                reservation.close()


if __name__ == '__main__':
    unittest.main()

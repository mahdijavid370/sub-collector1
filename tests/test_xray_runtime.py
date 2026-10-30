"""Optional real-Xray integration tests; all test traffic stays on loopback."""

import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import collector
import speedtest

XRAY_ENV = os.environ.get('XRAY_BINARY')
TEST_ID = '8c376d80-c7a9-47e2-9d85-305b3e91df01'


def loopback_redirect_settings(port):
    # Xray 26.10.29 blocks private destinations from VLESS inbounds by default.
    # Permit only the local HTTP server used by this test, not arbitrary targets.
    return {
        'redirect': f'127.0.0.1:{port}',
        'finalRules': [{'action': 'allow', 'network': 'tcp', 'ip': ['127.0.0.1/32'], 'port': str(port)}],
    }


class TargetHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.server.probe_count += 1
        if not self.server.probe_ok:
            # A network failure, not an HTTP error page: Xray's observer treats
            # any HTTP response status as a successful measurement.
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            return
        time.sleep(self.server.delay)
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        is_download = self.path == '/download'
        # The two download paths have identical initial latency but different
        # transfer rates; this checks throughput rather than only ping.
        delay = 2.0 if self.path == '/halfclose' else (0.02 if is_download else self.server.delay)
        time.sleep(delay)
        body = b'x' * 16384 if is_download else self.server.label.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            if is_download and self.server.label == 'slow':
                for offset in range(0, len(body), 1024):
                    self.wfile.write(body[offset:offset + 1024])
                    self.wfile.flush()
                    time.sleep(0.02)
            else:
                self.wfile.write(body)
        except OSError:
            pass

    def log_message(self, *_args):
        pass


def wait_listener(process, port):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError('The local test Xray instance exited during startup')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError('The local test Xray listener did not start')


def stop_process(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


@unittest.skipUnless(XRAY_ENV, 'Set XRAY_BINARY to run the real-Xray loopback integration tests')
class XrayRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = shutil.which(XRAY_ENV)
        if not cls.binary:
            raise AssertionError('XRAY_BINARY must identify an executable Xray binary')
        cls.tmp = tempfile.TemporaryDirectory(prefix='test-xray-')
        cls.targets = []
        cls.target_threads = []
        cls.server = None
        try:
            for label, delay in [('slow', 0.3), ('fast', 0.02)]:
                target = ThreadingHTTPServer(('127.0.0.1', 0), TargetHandler)
                target.daemon_threads = True
                target.label = label
                target.delay = delay
                target.probe_ok = True
                target.probe_count = 0
                thread = threading.Thread(target=target.serve_forever, daemon=True)
                thread.start()
                cls.targets.append(target)
                cls.target_threads.append(thread)
            ports, reservations = speedtest._reserve_ports(2)
            for reservation in reservations:
                reservation.close()
            inbounds, outbounds, rules = [], [], []
            for index, (port, target) in enumerate(zip(ports, cls.targets)):
                in_tag, out_tag = f'test-server-{index}', f'test-target-{index}'
                inbounds.append({
                    'tag': in_tag, 'listen': '127.0.0.1', 'port': port, 'protocol': 'vless',
                    'settings': {'clients': [{'id': TEST_ID, 'level': 8}], 'decryption': 'none'},
                })
                outbounds.append({
                    'tag': out_tag, 'protocol': 'freedom',
                    'settings': loopback_redirect_settings(target.server_address[1]),
                })
                rules.append({'type': 'field', 'inboundTag': [in_tag], 'outboundTag': out_tag})
            server_config = {
                'log': {'loglevel': 'error'}, 'inbounds': inbounds,
                'outbounds': outbounds, 'routing': {'rules': rules},
                'policy': {'levels': {'8': {'downlinkOnly': 30, 'uplinkOnly': 30}}},
            }
            server_file = Path(cls.tmp.name) / 'server.json'
            server_file.write_text(json.dumps(server_config), encoding='utf-8')
            cls.server = subprocess.Popen(
                [cls.binary, 'run', '-format', 'json', '-c', str(server_file)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            for port in ports:
                wait_listener(cls.server, port)
            cls.nodes = []
            for index, port in enumerate(ports, start=1):
                link = f'vless://{TEST_ID}@127.0.0.1:{port}?type=tcp&security=none&encryption=none'
                node = collector.parse_vless_to_outbound(link, f'proxy-{index}')
                if node is None:
                    raise AssertionError('Could not build a loopback test outbound')
                cls.nodes.append(node)
        except Exception:
            cls._cleanup()
            raise

    @classmethod
    def _cleanup(cls):
        stop_process(cls.server)
        for target in cls.targets:
            target.shutdown()
            target.server_close()
        for thread in cls.target_threads:
            thread.join()
        cls.tmp.cleanup()

    @classmethod
    def tearDownClass(cls):
        cls._cleanup()

    def test_subscription_txt_validates_via_stdin_and_invalid_json_is_rejected(self):
        config = collector.generate_full_json_config(self.nodes)
        with tempfile.TemporaryDirectory(prefix='test-xray-stdin-') as temporary:
            subscription = Path(temporary) / 'final_sub.txt'
            subscription.write_text(json.dumps(config), encoding='utf-8')
            command = [self.binary, 'run', '-test', '-format', 'json', '-c', 'stdin:']
            with subscription.open('rb') as file:
                valid = subprocess.run(
                    command, stdin=file, check=False,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20,
                )
            self.assertEqual(valid.returncode, 0, 'Xray rejected valid JSON from stdin')
            invalid = subprocess.run(
                command, input=b'{"outbounds": [', check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20,
            )
            self.assertNotEqual(invalid.returncode, 0, 'Xray accepted invalid JSON from stdin')

    def test_local_speed_test_selects_faster_tunnel_and_outputs_valid_xray_profile(self):
        config = collector.generate_full_json_config(self.nodes)
        with tempfile.TemporaryDirectory(prefix='test-speedtest-') as temporary:
            original, output = Path(temporary) / 'original.json', Path(temporary) / 'fast.json'
            original.write_text(json.dumps(config), encoding='utf-8')
            result = subprocess.run([
                sys.executable, str(Path(speedtest.__file__).resolve()), '--xray', self.binary,
                '--input', str(original), '--output', str(output), '--test-url', 'http://test.invalid/download',
                '--sample-kib', '16', '--samples', '2', '--timeout', '5', '--workers', '2', '--top', '1',
            ], check=False, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(TEST_ID, result.stdout + result.stderr)
            fast_config = json.loads(output.read_text(encoding='utf-8'))
            self.assertEqual([node['tag'] for node in fast_config['outbounds']], ['proxy-2', 'direct', 'block'])
            self.assertEqual(fast_config['routing']['balancers'][0]['fallbackTag'], 'proxy-2')
            validation = subprocess.run(
                [self.binary, 'run', '-test', '-format', 'json', '-c', str(output)],
                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20,
            )
            self.assertEqual(validation.returncode, 0, 'Xray rejected the optimized profile')

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is needed for the temporary TLS certificate')
    def test_https_speed_test_through_real_vless_tunnel_verifies_tls(self):
        with tempfile.TemporaryDirectory(prefix='test-xray-tls-') as temporary:
            root = Path(temporary)
            cert, key = root / 'cert.pem', root / 'key.pem'
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=test.invalid',
                '-addext', 'subjectAltName=DNS:test.invalid',
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.load_cert_chain(cert, key)
            target = ThreadingHTTPServer(('127.0.0.1', 0), TargetHandler)
            target.daemon_threads = True
            target.label, target.delay, target.probe_ok, target.probe_count = 'fast', 0.02, True, 0
            target.socket = tls_context.wrap_socket(target.socket, server_side=True)
            thread = threading.Thread(target=target.serve_forever, daemon=True)
            thread.start()
            server = None
            try:
                ports, reservations = speedtest._reserve_ports(1)
                port = ports[0]
                for reservation in reservations:
                    reservation.close()
                server_file = root / 'server.json'
                server_file.write_text(json.dumps({
                    'log': {'loglevel': 'error'},
                    'inbounds': [{
                        'listen': '127.0.0.1', 'port': port, 'protocol': 'vless',
                        'settings': {'clients': [{'id': TEST_ID}], 'decryption': 'none'},
                    }],
                    'outbounds': [{
                        'protocol': 'freedom',
                        'settings': loopback_redirect_settings(target.server_address[1]),
                    }],
                }), encoding='utf-8')
                server = subprocess.Popen(
                    [self.binary, 'run', '-format', 'json', '-c', str(server_file)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                wait_listener(server, port)
                link = f'vless://{TEST_ID}@127.0.0.1:{port}?type=tcp&security=none&encryption=none'
                node = collector.parse_vless_to_outbound(link, 'proxy-1')
                self.assertIsNotNone(node)
                original, output = root / 'input.json', root / 'fast.json'
                original.write_text(json.dumps(collector.generate_full_json_config([node])), encoding='utf-8')
                command = [
                    sys.executable, str(Path(speedtest.__file__).resolve()), '--xray', self.binary,
                    '--input', str(original), '--output', str(output),
                    '--test-url', 'https://test.invalid/download', '--sample-kib', '16', '--samples', '1',
                    '--timeout', '5', '--top', '1',
                ]
                env = os.environ.copy()
                env.pop('SSL_CERT_FILE', None)
                untrusted = subprocess.run(command, env=env, check=False, capture_output=True, text=True, timeout=20)
                self.assertNotEqual(untrusted.returncode, 0)
                self.assertFalse(output.exists())
                env['SSL_CERT_FILE'] = str(cert)
                trusted = subprocess.run(command, env=env, check=False, capture_output=True, text=True, timeout=20)
                self.assertEqual(trusted.returncode, 0, trusted.stderr)
                self.assertNotIn(TEST_ID, trusted.stdout + trusted.stderr)
                fast_config = json.loads(output.read_text(encoding='utf-8'))
                self.assertEqual(fast_config['routing']['balancers'][0]['fallbackTag'], 'proxy-1')
            finally:
                stop_process(server)
                target.shutdown()
                target.server_close()
                thread.join()

    def test_delayed_response_survives_client_half_close(self):
        for target in self.targets:
            target.probe_ok = False

        def exchange(downlink_timeout):
            ports, reservations = speedtest._reserve_ports(1)
            port = ports[0]
            for reservation in reservations:
                reservation.close()
            config = collector.generate_full_json_config(self.nodes)
            config['inbounds'][0]['port'] = port
            config.pop('dns', None)
            config['log'] = {'loglevel': 'error'}
            config['routing']['rules'] = [{'type': 'field', 'inboundTag': ['socks'], 'balancerTag': 'proxy-round'}]
            config['burstObservatory']['pingConfig']['destination'] = 'http://test.invalid/probe'
            config['policy']['levels']['8']['downlinkOnly'] = downlink_timeout
            client_file = Path(self.tmp.name) / f'halfclose-{downlink_timeout}.json'
            client_file.write_text(json.dumps(config), encoding='utf-8')
            client = subprocess.Popen(
                [self.binary, 'run', '-format', 'json', '-c', str(client_file)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            try:
                wait_listener(client, port)
                with socket.create_connection(('127.0.0.1', port), timeout=8) as sock:
                    def receive_exact(size):
                        data = bytearray()
                        while len(data) < size:
                            chunk = sock.recv(size - len(data))
                            self.assertTrue(chunk, 'SOCKS handshake closed early')
                            data.extend(chunk)
                        return bytes(data)

                    sock.sendall(b'\x05\x01\x00')
                    self.assertEqual(receive_exact(2), b'\x05\x00')
                    domain = b'test.invalid'
                    sock.sendall(b'\x05\x01\x00\x03' + bytes([len(domain)]) + domain + b'\x00\x50')
                    reply = receive_exact(4)
                    self.assertEqual(reply[:2], b'\x05\x00')
                    if reply[3] == 1:
                        remaining = 6
                    elif reply[3] == 4:
                        remaining = 18
                    else:
                        remaining = receive_exact(1)[0] + 2
                    receive_exact(remaining)
                    sock.sendall(b'GET /halfclose HTTP/1.1\r\nHost: test.invalid\r\nConnection: close\r\n\r\n')
                    sock.shutdown(socket.SHUT_WR)
                    received = bytearray()
                    while True:
                        try:
                            chunk = sock.recv(65536)
                        except ConnectionResetError:
                            break
                        if not chunk:
                            break
                        received.extend(chunk)
                    return bytes(received)
            finally:
                stop_process(client)

        try:
            self.assertIn(b'200 OK', exchange(30))
        finally:
            for target in self.targets:
                target.probe_ok = True

    def test_runtime_balancer_startup_latency_failover_and_recovery(self):
        # This tests actual Xray behavior. Ten seconds is its minimum observer
        # interval; random probe timing can take up to two cycles after a change.
        for target in self.targets:
            target.probe_ok = False
            target.probe_count = 0
        ports, reservations = speedtest._reserve_ports(1)
        port = ports[0]
        for reservation in reservations:
            reservation.close()
        config = collector.generate_full_json_config(self.nodes)
        config['log'] = {'loglevel': 'error'}
        config['inbounds'] = [{'tag': 'app', 'listen': '127.0.0.1', 'port': port, 'protocol': 'http', 'settings': {}}]
        config.pop('dns', None)
        config['routing']['rules'] = [{'type': 'field', 'inboundTag': ['app'], 'balancerTag': 'proxy-round'}]
        config['burstObservatory']['pingConfig'].update({
            'destination': 'http://test.invalid/probe', 'interval': '10s', 'timeout': '1s',
        })
        client_file = Path(self.tmp.name) / 'client.json'
        client_file.write_text(json.dumps(config), encoding='utf-8')
        client = subprocess.Popen(
            [self.binary, 'run', '-format', 'json', '-c', str(client_file)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        def request():
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
            try:
                connection.request('GET', 'http://test.invalid/who')
                response = connection.getresponse()
                return response.read().decode() if response.status == 200 else None
            except (OSError, http.client.HTTPException):
                return None
            finally:
                connection.close()

        def wait_for_label(label):
            deadline = time.monotonic() + 23
            while time.monotonic() < deadline:
                if request() == label:
                    return
                time.sleep(0.2)
            self.fail(f'Xray did not switch to the {label} loopback node')

        try:
            wait_listener(client, port)
            # With no healthy observations, the first *proxy* is the fallback;
            # a direct connection to the nonexistent test.invalid would fail.
            self.assertEqual(request(), 'slow')
            deadline = time.monotonic() + 5
            while any(target.probe_count == 0 for target in self.targets) and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(all(target.probe_count > 0 for target in self.targets))
            self.assertEqual(request(), 'slow')
            for target in self.targets:
                target.probe_ok = True
            wait_for_label('fast')
            self.targets[1].probe_ok = False
            wait_for_label('slow')
            self.targets[1].probe_ok = True
            wait_for_label('fast')
        finally:
            stop_process(client)
            for target in self.targets:
                target.probe_ok = True


if __name__ == '__main__':
    unittest.main()

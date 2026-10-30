"""Measure VLESS nodes from the user's network and make a faster Xray profile.

This is an opt-in, bounded download test. It runs a temporary Xray HTTP proxy
for each candidate, so it tests the actual VLESS tunnel rather than just the
TCP port. Subscription URLs and node credentials are not printed.
"""

from __future__ import annotations

import argparse
import copy
import http.client
import json
import os
import shutil
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import SplitResult, urlsplit, urlunsplit

DEFAULT_SAMPLE_KIB = 256
DEFAULT_SAMPLES = 2
DEFAULT_MAX_NODES = 50
DEFAULT_TOP = 3
DEFAULT_TIMEOUT = 10.0
DEFAULT_WORKERS = 2
BATCH_SIZE = 20
DIVERSITY_SCORE_FRACTION = 0.8


class SpeedTestError(Exception):
    """The benchmark could not safely produce an optimized config."""


@dataclass(frozen=True)
class Sample:
    bytes_per_second: float
    latency_seconds: float


@dataclass(frozen=True)
class Result:
    tag: str
    samples_ok: int
    samples_total: int
    bytes_per_second: float
    latency_seconds: float

    @property
    def score(self) -> float:
        # Prefer reliable nodes when a node fails some of the attempts.
        return self.bytes_per_second * self.samples_ok / self.samples_total


def parse_test_url(url: str) -> SplitResult:
    """Accept an explicit HTTP(S) download target, without URL credentials."""
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme.lower() not in {'http', 'https'}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or any(c.isspace() or ord(c) < 32 for c in url)
            or parsed.port == 0
        ):
            raise ValueError
    except ValueError:
        raise SpeedTestError('The test URL must be a valid HTTP(S) URL without credentials.') from None
    return parsed


def measure_sample(proxy_port: int, target: SplitResult, sample_bytes: int, timeout: float) -> Sample | None:
    """Download exactly sample_bytes through an Xray HTTP proxy, or fail closed."""
    if target.scheme == 'https':
        connection = http.client.HTTPSConnection(
            '127.0.0.1', proxy_port, timeout=timeout, context=ssl.create_default_context()
        )
        connection.set_tunnel(target.hostname, target.port or 443)
        request_target = urlunsplit(('', '', target.path or '/', target.query, ''))
    else:
        connection = http.client.HTTPConnection('127.0.0.1', proxy_port, timeout=timeout)
        request_target = urlunsplit((target.scheme, target.netloc, target.path or '/', target.query, ''))

    response = None
    opened_socket: list[socket.socket] = []

    def stop_overdue_request() -> None:
        active = connection.sock or (opened_socket[0] if opened_socket else None)
        if active is not None:
            try:
                active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    started = time.monotonic()
    deadline = started + timeout
    # A trickle of bytes must not extend the test indefinitely. Socket timeout
    # alone is per read, so also interrupt a request at its wall-clock deadline.
    timer = threading.Timer(timeout, stop_overdue_request)
    timer.daemon = True
    timer.start()
    try:
        connection.request('GET', request_target, headers={
            'Accept': '*/*',
            'Accept-Encoding': 'identity',
            'Cache-Control': 'no-cache',
            'Connection': 'close',
        })
        if connection.sock is not None:
            opened_socket.append(connection.sock)
        response = connection.getresponse()
        latency = time.monotonic() - started
        content_type = response.getheader('Content-Type', '').lower()
        # A block page or captive portal must not look like a fast connection.
        if response.status != 200 or content_type.startswith('text/html'):
            return None
        read_bytes = 0
        while read_bytes < sample_bytes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            active = connection.sock or (opened_socket[0] if opened_socket else None)
            if active is not None:
                active.settimeout(remaining)
            chunk = response.read1(min(65536, sample_bytes - read_bytes))
            if not chunk:
                return None
            read_bytes += len(chunk)
        elapsed = time.monotonic() - started
        if elapsed <= 0 or time.monotonic() > deadline:
            return None
        return Sample(bytes_per_second=read_bytes / elapsed, latency_seconds=latency)
    except (OSError, TimeoutError, http.client.HTTPException, ValueError):
        return None
    finally:
        timer.cancel()
        if response is not None:
            response.close()
        connection.close()


def measure_node(
    tag: str, proxy_port: int, target: SplitResult, sample_bytes: int, timeout: float, samples: int,
) -> Result | None:
    attempts = [measure_sample(proxy_port, target, sample_bytes, timeout) for _ in range(samples)]
    successes = [sample for sample in attempts if sample is not None]
    if not successes:
        return None
    return Result(
        tag=tag,
        samples_ok=len(successes),
        samples_total=samples,
        bytes_per_second=statistics.median(sample.bytes_per_second for sample in successes),
        latency_seconds=statistics.median(sample.latency_seconds for sample in successes),
    )


def candidate_outbounds(config: dict) -> list[dict]:
    """Find the collector's VLESS outbounds without exposing their contents."""
    outbounds = config.get('outbounds')
    if not isinstance(outbounds, list):
        raise SpeedTestError('The input does not contain an Xray outbounds list.')
    candidates = [
        outbound for outbound in outbounds
        if isinstance(outbound, dict)
        and outbound.get('protocol') == 'vless'
        and isinstance(outbound.get('tag'), str)
        and outbound['tag'].startswith('proxy-')
    ]
    if not candidates:
        raise SpeedTestError('The input has no VLESS proxy outbounds to test.')
    tags = [outbound['tag'] for outbound in candidates]
    if any(not tag[6:].isascii() or not tag[6:].isdecimal() for tag in tags):
        raise SpeedTestError('The input contains an unexpected proxy tag format.')
    if len(tags) != len(set(tags)):
        raise SpeedTestError('The input contains duplicate proxy tags.')
    return candidates


def proxy_balancer(config: dict) -> dict:
    routing = config.get('routing')
    balancers = routing.get('balancers') if isinstance(routing, dict) else None
    if not isinstance(balancers, list):
        raise SpeedTestError('The input does not contain the collector\'s proxy balancer.')
    matches = [item for item in balancers if isinstance(item, dict) and item.get('tag') == 'proxy-round']
    if len(matches) != 1:
        raise SpeedTestError('The input does not contain the collector\'s proxy balancer.')
    selector = matches[0].get('selector')
    strategy = matches[0].get('strategy')
    if selector != ['proxy-'] or not isinstance(strategy, dict) or strategy.get('type') != 'leastPing':
        raise SpeedTestError('The input does not contain the collector\'s proxy balancer.')
    return matches[0]


def _reserve_ports(count: int) -> tuple[list[int], list[socket.socket]]:
    reservations = []
    try:
        for _ in range(count):
            reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            reservations.append(reservation)
            reservation.bind(('127.0.0.1', 0))
        return [reservation.getsockname()[1] for reservation in reservations], reservations
    except OSError:
        for reservation in reservations:
            reservation.close()
        raise SpeedTestError('Could not reserve local ports for the speed test.') from None


def _benchmark_config(nodes: list[dict], ports: list[int]) -> dict:
    inbounds = []
    rules = []
    for index, (node, port) in enumerate(zip(nodes, ports), start=1):
        inbound_tag = f'bench-{index}'
        inbounds.append({
            'listen': '127.0.0.1', 'port': port, 'protocol': 'http',
            'settings': {}, 'tag': inbound_tag,
        })
        rules.append({'type': 'field', 'inboundTag': [inbound_tag], 'outboundTag': node['tag']})
    return {
        'log': {'loglevel': 'error'},
        'inbounds': inbounds,
        'outbounds': nodes,
        'routing': {'rules': rules},
    }


@contextmanager
def running_xray(binary: str, nodes: list[dict]):
    """Start one temporary Xray instance for a bounded batch of candidates."""
    ports, reservations = _reserve_ports(len(nodes))
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='sub-speedtest-') as temporary:
            config_file = Path(temporary) / 'benchmark.json'
            config_file.write_text(json.dumps(_benchmark_config(nodes, ports)), encoding='utf-8')
            # Keep the reserved ports until immediately before Xray binds them.
            for reservation in reservations:
                reservation.close()
            try:
                process = subprocess.Popen(
                    [binary, 'run', '-format', 'json', '-c', str(config_file)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            except OSError:
                raise SpeedTestError('Could not start Xray for the speed test.') from None
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    raise SpeedTestError('Xray could not start the benchmark configuration.')
                if time.monotonic() >= deadline:
                    raise SpeedTestError('Xray did not start its local benchmark listener in time.')
                try:
                    with socket.create_connection(('127.0.0.1', ports[-1]), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.05)
            yield dict(zip((node['tag'] for node in nodes), ports))
            if process.poll() is not None:
                raise SpeedTestError('Xray stopped unexpectedly during the speed test.')
    finally:
        for reservation in reservations:
            reservation.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def benchmark_nodes(
    nodes: list[dict], binary: str, target: SplitResult, sample_bytes: int,
    timeout: float, samples: int, workers: int,
) -> list[Result]:
    results = []
    for start in range(0, len(nodes), BATCH_SIZE):
        batch = nodes[start:start + BATCH_SIZE]
        with running_xray(binary, batch) as ports, ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(measure_node, node['tag'], ports[node['tag']], target, sample_bytes, timeout, samples)
                for node in batch
            ]
            for future in futures:
                result = future.result()
                if result is not None:
                    results.append(result)
    return results


def _endpoint_key(node: dict) -> tuple:
    """Identify a server endpoint without treating different credentials as duplicates."""
    try:
        vnext = node['settings']['vnext'][0]
        address, port = vnext['address'], vnext['port']
        if isinstance(address, str) and isinstance(port, int):
            return ('endpoint', address.lower().rstrip('.'), port)
    except (KeyError, IndexError, TypeError):
        pass
    # Unknown endpoint structure must not accidentally collapse distinct nodes.
    return ('tag', node['tag'])


def optimized_config(config: dict, results: list[Result], top: int) -> tuple[dict, list[Result]]:
    """Build a separate profile containing the best locally measured nodes."""
    candidates = candidate_outbounds(config)
    by_tag = {node['tag']: node for node in candidates}
    rank = {node['tag']: index for index, node in enumerate(candidates)}
    sorted_results = sorted(
        (result for result in results if result.tag in by_tag and result.samples_ok > 0),
        key=lambda result: (-result.score, result.latency_seconds, rank[result.tag]),
    )
    seen = set()
    ordered = []
    for result in sorted_results:
        if result.tag not in seen:
            seen.add(result.tag)
            ordered.append(result)
    if not ordered:
        raise SpeedTestError('No node completed the download test; check the target or try --test-url. No output was written.')

    # Retain the fastest node, but prefer another endpoint when its score is
    # close. This avoids a profile with several accounts on one failed server.
    selected = {ordered[0].tag}
    endpoints = {_endpoint_key(by_tag[ordered[0].tag])}
    threshold = ordered[0].score * DIVERSITY_SCORE_FRACTION
    for result in ordered[1:]:
        if len(selected) >= top or result.score < threshold:
            break
        endpoint = _endpoint_key(by_tag[result.tag])
        if endpoint not in endpoints:
            endpoints.add(endpoint)
            selected.add(result.tag)
    for result in ordered:
        if len(selected) >= top:
            break
        selected.add(result.tag)
    ranked = [result for result in ordered if result.tag in selected]

    optimized = copy.deepcopy(config)
    balancer = proxy_balancer(optimized)
    other_outbounds = [
        node for node in optimized['outbounds']
        if not (isinstance(node, dict) and isinstance(node.get('tag'), str) and node['tag'].startswith('proxy-'))
    ]
    optimized['outbounds'] = [copy.deepcopy(by_tag[result.tag]) for result in ranked] + other_outbounds
    balancer['fallbackTag'] = ranked[0].tag
    observer = optimized.get('burstObservatory')
    ping = observer.get('pingConfig') if isinstance(observer, dict) else None
    # Recalculate the collector's default interval for the smaller profile, but
    # preserve an interval that the user explicitly customized.
    original_interval = f'{max(45, (len(candidates) + 1) // 2)}s'
    if isinstance(ping, dict) and ping.get('interval') == original_interval:
        ping['interval'] = f'{max(45, (len(ranked) + 1) // 2)}s'
    optimized['remarks'] = str(optimized.get('remarks', 'javidsub')) + ' | local speed test'
    return optimized, ranked


def write_config(config: dict, output: Path) -> None:
    """Replace the optimized output atomically after a successful test."""
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=output.parent, delete=False) as file:
            temporary = Path(file.name)
            json.dump(config, file, ensure_ascii=False, indent=2, allow_nan=False)
            file.write('\n')
        os.replace(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=Path('final_sub.txt'), help='Existing Xray JSON profile')
    parser.add_argument('--output', type=Path, default=Path('final_sub.fast.txt'), help='Separate optimized profile')
    parser.add_argument('--xray', default='xray', help='Xray executable or path')
    parser.add_argument('--top', type=int, default=DEFAULT_TOP, help='Maximum number of successful nodes to keep')
    parser.add_argument('--max-nodes', type=int, default=DEFAULT_MAX_NODES, help='Test at most N nodes; 0 means all')
    parser.add_argument('--sample-kib', type=int, default=DEFAULT_SAMPLE_KIB, help='Download size per attempt in KiB')
    parser.add_argument('--samples', type=int, default=DEFAULT_SAMPLES, help='Number of attempts per node')
    parser.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, help='Seconds allowed per attempt')
    parser.add_argument('--workers', type=int, default=DEFAULT_WORKERS, help='Maximum simultaneous node tests')
    parser.add_argument('--test-url', help='HTTP(S) download URL; must return at least the sample size')
    args = parser.parse_args(argv)

    try:
        if not 1 <= args.top <= 100 or args.max_nodes < 0:
            raise SpeedTestError('--top must be 1–100 and --max-nodes must be non-negative.')
        if not 16 <= args.sample_kib <= 4096 or not 1 <= args.samples <= 5:
            raise SpeedTestError('--sample-kib must be 16–4096 and --samples must be 1–5.')
        if not 2 <= args.timeout <= 60 or not 1 <= args.workers <= 16:
            raise SpeedTestError('--timeout must be 2–60 seconds and --workers must be 1–16.')
        if args.input.resolve() == args.output.resolve():
            raise SpeedTestError('The output must be a separate file from the original profile.')
        binary = shutil.which(args.xray)
        if not binary:
            raise SpeedTestError('Xray was not found; install it or supply --xray /path/to/xray.')
        try:
            with args.input.open(encoding='utf-8') as file:
                config = json.load(file)
        except (OSError, ValueError):
            raise SpeedTestError('Could not read the input Xray JSON profile.') from None
        if not isinstance(config, dict):
            raise SpeedTestError('The input Xray configuration must be a JSON object.')
        proxy_balancer(config)  # Fail before downloading if this is not a collector profile.
        nodes = candidate_outbounds(config)
        if args.max_nodes and len(nodes) > args.max_nodes:
            print(
                f'Testing the first {args.max_nodes} of {len(nodes)} nodes; use --max-nodes 0 to test all.',
                file=sys.stderr,
            )
            nodes = nodes[:args.max_nodes]
        sample_bytes = args.sample_kib * 1024
        url = args.test_url or f'https://speed.cloudflare.com/__down?bytes={sample_bytes}'
        target = parse_test_url(url)
        max_mib = len(nodes) * args.samples * sample_bytes / (1024 * 1024)
        print(
            f'Testing {len(nodes)} nodes from this network; up to {max_mib:.1f} MiB of samples, plus overhead.',
            file=sys.stderr,
        )
        results = benchmark_nodes(nodes, binary, target, sample_bytes, args.timeout, args.samples, args.workers)
        optimized, ranked = optimized_config(config, results, args.top)
        write_config(optimized, args.output)
    except (SpeedTestError, OSError) as error:
        # Error messages are generic and never include source URLs or credentials.
        print(f'Speed test failed: {error if isinstance(error, SpeedTestError) else "file or network error"}', file=sys.stderr)
        return 1

    print(f'Selected {len(ranked)} of {len(nodes)} tested nodes:')
    for result in ranked:
        mbps = result.bytes_per_second * 8 / 1_000_000
        print(f'  {result.tag}: {mbps:.2f} Mb/s, {result.latency_seconds * 1000:.0f} ms, {result.samples_ok}/{result.samples_total} successful')
    print(f'Optimized Xray profile saved to {args.output}.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

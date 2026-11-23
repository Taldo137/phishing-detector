"""Send traffic through the load balancer and summarise the results.

    python scripts/load_test.py --url http://<alb-dns> --duration 120 --workers 5

Workers upload the sample emails (repeats are cache hits), some with a random header
(new content, cache misses), and a few bad requests (4xx). Prints status codes,
latency, cache results and how many responses each instance served.
"""

import argparse
import random
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

SAMPLES = sorted((Path(__file__).parent.parent / "samples").iterdir())


def run_worker(url: str, deadline: float) -> list[tuple[int, float, str, str]]:
    results = []
    with httpx.Client(timeout=10) as client:
        while time.monotonic() < deadline:
            sample = random.choice(SAMPLES)
            content = sample.read_bytes()
            if random.random() < 0.2:
                content = f"X-Load-Test: {uuid.uuid4()}\n".encode() + content  # new content: cache miss
            files = {"file": (sample.name, content)}
            if random.random() < 0.05:
                files = {"file": ("invoice.exe", b"MZ")}  # rejected with 415
            started = time.perf_counter()
            try:
                response = client.post(f"{url}/api/scan", files=files)
                cache = response.json().get("cache", "-") if response.status_code == 200 else "-"
                results.append((response.status_code, time.perf_counter() - started,
                                response.headers.get("x-served-by", "?"), cache))
            except httpx.HTTPError as exc:
                results.append((0, 0.0, type(exc).__name__, "-"))
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--duration", type=int, default=120)
    parser.add_argument("--workers", type=int, default=5)
    args = parser.parse_args()

    url, deadline = args.url.rstrip("/"), time.monotonic() + args.duration
    print(f"Sending traffic to {url} for {args.duration} s with {args.workers} workers...")
    with ThreadPoolExecutor(args.workers) as pool:
        results = [r for rs in pool.map(run_worker, [url] * args.workers, [deadline] * args.workers) for r in rs]

    latencies = sorted(r[1] for r in results if r[0])
    print(f"Requests: {len(results)} ({len(results) / args.duration:.1f}/s)")
    print("Status:   ", dict(Counter(r[0] for r in results)))
    if latencies:
        print(f"Latency:   p50 {latencies[len(latencies) // 2] * 1000:.0f} ms, "
              f"p95 {latencies[int(len(latencies) * 0.95)] * 1000:.0f} ms")
    print("Cache:    ", dict(Counter(r[3] for r in results if r[3] != "-")))
    print("Served by:", dict(Counter(r[2] for r in results)))


if __name__ == "__main__":
    main()

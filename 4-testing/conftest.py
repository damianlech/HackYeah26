"""Shared fixtures: start the poc/ gateway stack (mock LLM, guard service, gateway) as real processes
on free ports, with a temporary copy of the policy, so tests never touch the files in poc/."""
import copy
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
POC = ROOT / "poc"
FEED = ROOT / "examples" / "feed" / "signatures.yaml"
PROFILES = ROOT / "1-solution" / "profiles"
PY = sys.executable


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise RuntimeError(f"nothing listening on port {port} after {timeout}s")


class PocStack:
    """The poc/ gateway with its two helper services, isolated in a temp directory."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.ports = {"mock": free_port(), "guard": free_port(), "gateway": free_port()}
        self.policy_path = tmp / "policy.yaml"
        self.audit_path = tmp / "audit.jsonl"
        self.url = f"http://127.0.0.1:{self.ports['gateway']}"
        self.procs = []
        self.http = httpx.Client(base_url=self.url, timeout=10)
        self._mtime = time.time_ns()

    def localize(self, policy: dict) -> dict:
        """Point a policy at this stack: every model prefix goes to the mock, the guard to our guard,
        and the feed path becomes absolute (it is relative to the policy file otherwise)."""
        p = copy.deepcopy(policy)
        mock = f"http://127.0.0.1:{self.ports['mock']}/v1"
        p["upstreams"] = {prefix: mock for prefix in p["upstreams"]}
        p["controls"]["guard"]["url"] = f"http://127.0.0.1:{self.ports['guard']}/score"
        p["controls"]["signatures"]["feed"] = str(FEED)
        return p

    def load(self, path: Path) -> dict:
        return self.localize(yaml.safe_load(path.read_text()))

    def write_policy(self, policy):
        text = policy if isinstance(policy, str) else yaml.safe_dump(policy, sort_keys=False, allow_unicode=True)
        self.policy_path.write_text(text)
        self._mtime += 1_000_000  # a new mtime on every write, even two writes in the same clock tick
        os.utime(self.policy_path, ns=(self._mtime, self._mtime))

    def start(self):
        self.write_policy(self.load(POC / "policy.yaml"))
        env = {**os.environ, "MANDATE_POLICY": str(self.policy_path), "MANDATE_AUDIT": str(self.audit_path)}
        for app, port in (("mock_llm:app", "mock"), ("guard_svc:app", "guard"), ("gateway:app", "gateway")):
            log = open(self.tmp / f"{port}.log", "w")
            self.procs.append(subprocess.Popen(
                [PY, "-m", "uvicorn", app, "--port", str(self.ports[port]), "--log-level", "warning"],
                cwd=POC, env=env, stdout=log, stderr=subprocess.STDOUT))
        for port in self.ports.values():
            wait_port(port)

    def stop(self):
        self.http.close()
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()

    def reset(self, profile: Path = POC / "policy.yaml"):
        self.write_policy(self.load(profile))
        self.http.post("/control/budget/reset").raise_for_status()

    # ---- calls an agent would make
    def chat(self, text, key="sk-alice", model="mock/echo", max_tokens=4000):
        r = self.http.post("/v1/chat/completions", headers={"Authorization": f"Bearer {key}"} if key else {},
                           json={"model": model, "max_tokens": max_tokens,
                                 "messages": [{"role": "user", "content": text}]})
        return Reply(r)

    # ---- control plane
    def patch(self, control, cfg):
        r = self.http.patch(f"/control/controls/{control}", json=cfg)
        r.raise_for_status()
        return r.json()

    def status(self):
        return self.http.get("/control/status").json()


class Reply:
    """One gateway response, with the bits tests look at."""

    def __init__(self, r: httpx.Response):
        self.status = r.status_code
        self.json = r.json()
        self.headers = r.headers
        body = self.json.get("mandate") or self.json.get("error") or {}
        self.findings = body.get("findings", [])
        self.decision = r.headers.get("x-mandate-decision")

    @property
    def answer(self):
        return self.json["choices"][0]["message"]["content"]

    @property
    def forwarded(self):
        """The request exactly as the gateway sent it to the model."""
        return self.json["mandate"]["forwarded_request"]

    @property
    def error(self):
        return self.json.get("error", {}).get("message", "")

    def actions(self, control):
        return [f["action"] for f in self.findings if f["control"] == control]


@pytest.fixture(scope="session")
def poc_stack(tmp_path_factory):
    stack = PocStack(tmp_path_factory.mktemp("poc"))
    stack.start()
    yield stack
    stack.stop()


@pytest.fixture
def gw(poc_stack):
    """The running gateway, reset to the balanced policy with empty budgets before each test."""
    poc_stack.reset()
    return poc_stack

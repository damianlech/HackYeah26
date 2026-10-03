"""LAYER 1 - TLS interception (:8443).

The agent is configured with ANTHROPIC_BASE_URL=https://localhost:8443 and trusts our interception CA.
L1 terminates TLS (decrypts), records what it saw, and hands the PLAINTEXT request to L2 over the
internal network. The response travels back the same way and is re-encrypted to the agent here.
"""
import ssl
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

from certs import INTERCEPT_CERT, INTERCEPT_KEY, ensure_certs
from common import HOP_HEADERS, L1_PORT, L2_URL, trace

upstream = httpx.Client(timeout=180)


class Intercept(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mandate-l1"

    def relay(self):
        trace_id = "t-" + uuid.uuid4().hex[:8]
        body = self.rfile.read(int(self.headers.get("content-length") or 0))
        tls_version, cipher = self.connection.version(), self.connection.cipher()[0]
        trace(trace_id, "L1", "decrypt", tls=tls_version, cipher=cipher, client=self.client_address[0],
              method=self.command, path=self.path, bytes=len(body))

        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_HEADERS}
        headers.update({"x-trace-id": trace_id, "x-l1-tls": f"{tls_version} {cipher}"})
        try:
            r = upstream.request(self.command, L2_URL + self.path, headers=headers, content=body)
            status, out, resp_headers = r.status_code, r.content, r.headers
        except httpx.HTTPError as e:
            status, resp_headers = 502, {"content-type": "application/json"}
            out = (b'{"type":"error","error":{"type":"api_error","message":"L1: audit layer unreachable (%s)"}}'
                   % type(e).__name__.encode())

        trace(trace_id, "L1", "encrypt_response", status=status, bytes=len(out))
        self.send_response(status)
        for k, v in resp_headers.items():
            if k.lower() not in HOP_HEADERS and k.lower() not in ("date", "server"):
                self.send_header(k, v)
        self.send_header("x-proxy-trace", trace_id)
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = relay

    def log_message(self, *args):
        pass


def main():
    ensure_certs()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(INTERCEPT_CERT, INTERCEPT_KEY)
    server = ThreadingHTTPServer(("127.0.0.1", L1_PORT), Intercept)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(f"L1 intercept listening on https://localhost:{L1_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()

"""带外回连(OOB)采集服务。

- 任意请求打到 /<token>... 都会被记为一次回连命中,按路径首段作为 token。
- 查询某 token 是否命中: GET /__hits?token=<token>  → JSON。
- 列出全部命中:        GET /__hits              → JSON。
命中同时追加写入 /data/hits.jsonl,便于留证与复现。
监听 0.0.0.0:9100。只用标准库。
"""
import json
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(os.environ.get("OOB_PORT", "9100"))
LOG = os.environ.get("OOB_LOG", "/data/hits.jsonl")

_lock = threading.Lock()
_hits = {}  # token -> [record, ...]


def record(token, detail):
    with _lock:
        _hits.setdefault(token, []).append(detail)
        try:
            os.makedirs(os.path.dirname(LOG), exist_ok=True)
            with open(LOG, "a") as f:
                f.write(json.dumps({"token": token, **detail}, ensure_ascii=False) + "\n")
        except OSError:
            pass  # 落盘失败不影响内存记录


class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_any(self, method):
        parsed = urlparse(self.path)
        # 查询接口
        if parsed.path == "/__hits":
            q = parse_qs(parsed.query)
            if "token" in q:
                tok = q["token"][0]
                with _lock:
                    recs = _hits.get(tok, [])
                return self._json({"token": tok, "hit": len(recs) > 0, "count": len(recs), "records": recs})
            with _lock:
                return self._json({"tokens": {k: len(v) for k, v in _hits.items()}})
        # 其余一律记为回连命中
        token = parsed.path.strip("/").split("/", 1)[0] or "(root)"
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        record(token, {
            "time": datetime.now(timezone.utc).isoformat(),
            "method": method, "path": self.path,
            "remote": self.client_address[0],
            "ua": self.headers.get("User-Agent", ""),
            "body": body[:2000],
        })
        self._json({"ok": True})

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")

    def do_PUT(self):
        self.handle_any("PUT")

    def log_message(self, *a):
        pass  # 静默,命中已写 JSONL


if __name__ == "__main__":
    print(f"OOB collector listening on 0.0.0.0:{PORT}, log -> {LOG}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

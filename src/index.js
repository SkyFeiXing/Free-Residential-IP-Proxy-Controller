// ======  Proxy Controller (Active-Standby Multi-Tunnel) ======

// #15 模块级标志：同一 isolate 内只初始化一次表结构
let dbInitialized = false;

// ====== 安全辅助函数（纯函数，模块级定义，避免每请求重建）======

// H1: 生成安全的 Python 字符串字面量。
// JSON 字符串转义规则与 Python 字符串字面量兼容（\" \\ \n \uXXXX 等），
// 彻底杜绝环境变量中的特殊字符（引号 / 反斜杠 / 换行）破坏生成的 Python 源码或引发代码注入。
const pyStr = (s) => JSON.stringify(String(s));
// H1: 生成安全的 Python 字节串字面量（b"..."）。
const pyBytes = (s) => "b" + JSON.stringify(String(s));
// H1: 生成安全的 bash 单引号字面量，用于 agent.sh 中拼接 URL。
const bashQuote = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";

// H2/L1: 校验合法 IPv4/IPv6，防止 VPS 上报的非法 ip 污染代理导出 URL（代理劫持）与 SSRF。
const isValidIp = (ip) => {
  const s = String(ip == null ? "" : ip).trim();
  if (!s || /[\s@\/#?]/.test(s)) return false; // 拒绝会破坏 URL 结构的字符
  // IPv4：四段，每段 0-255 纯数字
  const v4 = s.split(".");
  if (v4.length === 4 && v4.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255)) return true;
  // IPv6：严格格式（:: 至多一次、段数 3-8、每段 1-4 位十六进制、长度上限），拒绝 :::/1::2::3 等非法形态
  if (s.includes(":") && /^[0-9a-fA-F:]+$/.test(s) && s.length <= 45) {
    const dbl = s.indexOf("::");
    if (dbl !== -1 && dbl !== s.lastIndexOf("::")) return false; // :: 至多出现一次
    const segs = s.split(":");
    if (segs.length < 3 || segs.length > 8) return false;
    if (segs.some((x) => x.length > 4)) return false;
    return true;
  }
  return false;
};

// M7: 合法 TCP 端口校验（1-65535）
const isValidPort = (p) => {
  const n = Number(p);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
};

// L7: 规范化国家代码（2 字母 A-Z），非法返回 null
const sanitizeCountry = (c) => {
  const s = String(c == null ? "" : c).trim().toUpperCase();
  return /^[A-Z]{2}$/.test(s) ? s : null;
};

// L7: /api/countries 预设列表、兜底列表与内存缓存（降低对 vpngate 的请求频率）
const PREDEFINED_COUNTRIES = ["US", "JP", "KR", "SG", "HK", "TW", "GB", "DE", "FR", "NL", "CA", "AU", "IN", "VN", "BR", "AE", "MY", "TH", "PH", "ID", "TR", "ZA", "IT", "ES", "RU", "CH", "SE", "PL", "NO", "DK", "FI", "IE", "AT", "NZ", "BE", "PT", "CZ", "GR", "HU", "RO", "BG", "HR", "SK", "SI", "LT", "LV", "EE", "UA", "RS", "BA", "CY", "MT", "IS", "LU"];
const COUNTRY_FALLBACK = ["US", "JP", "KR", "SG", "HK", "TW"];
const COUNTRY_CACHE_TTL = 300000; // 5 分钟
let countryCache = null;          // { data: string, at: number }

// H3: 默认弱凭证检测——部署者未修改默认口令时返回提示类型，供入口统一拒绝服务。
const detectWeakCredentials = (wu, wp, pu, pp) => {
  if (wu === "admin" && wp === "admin888") return "WEB";
  if (pu === "proxy" && pp === "888888") return "PROXY";
  return null;
};

// H3: isolate 级按源 IP 暴力破解防护（滑动窗口计数）。
// 局限：isolate 间不共享；跨边缘节点的分布式爆破需配合 Cloudflare WAF / Rate Limiting 规则。
const IP_FAIL_LIMIT = 10;     // 窗口内最大失败次数
const IP_FAIL_WINDOW = 60000; // 60 秒窗口
const ipFailMap = new Map();

const recordAuthFailure = (ip) => {
  const now = Date.now();
  const arr = (ipFailMap.get(ip) || []).filter((t) => now - t < IP_FAIL_WINDOW);
  arr.push(now);
  ipFailMap.set(ip, arr);
  if (ipFailMap.size > 2000) { // 防内存泄漏：超容量时清理已过期条目
    for (const [k, v] of ipFailMap) {
      if (v.every((t) => now - t >= IP_FAIL_WINDOW)) ipFailMap.delete(k);
    }
  }
};

const isRateLimited = (ip) => {
  const arr = ipFailMap.get(ip);
  if (!arr) return false;
  return arr.filter((t) => Date.now() - t < IP_FAIL_WINDOW).length >= IP_FAIL_LIMIT;
};

// H3: 默认弱凭证安全警告页（部署者访问根路径时看到，引导修改环境变量）
const SECURITY_WARNING_HTML = (type) => `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>安全配置未完成</title>
<style>body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:1rem}
.box{max-width:580px;background:#1e293b;border:1px solid #334155;border-radius:16px;padding:2.5rem;box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}
h1{color:#f87171;margin-top:0;font-size:1.4rem}.code{background:#0f172a;padding:.5rem .8rem;border-radius:6px;font-family:ui-monospace,monospace;color:#fbbf24;display:inline-block;margin:.15rem 0}
.tag{display:inline-block;padding:.2rem .6rem;border-radius:6px;background:#f87171;color:#fff;font-weight:700;font-size:.8rem}
p{line-height:1.7}</style></head>
<body><div class="box">
<h1>⚠️ 检测到默认弱凭证，服务已锁定</h1>
<p>系统检测到 <span class="tag">${type}</span> 仍使用默认口令，为防止被扫描器爆破，所有功能已暂停。</p>
<p>请前往 Cloudflare Workers 控制台 <b>Settings → Variables</b>，修改以下环境变量：</p>
<p><span class="code">WEB_USER</span> / <span class="code">WEB_PASS</span>（面板登录）<br>
<span class="code">PROXY_USER</span> / <span class="code">PROXY_PASS</span>（代理服务认证）</p>
<p style="color:#94a3b8;font-size:.9rem">保存后 Worker 自动生效，无需重新部署代码。修改任意一个口令即视为已加固。</p>
</div></body></html>`;

// /scripts 凭证保护：通过一次性纳管 token（SCRT）授权拉取脚本，避免 WEB/PROXY 凭证明文暴露在无认证端点。
// token 首次访问根路径时由 Worker 写入 D1；agent.sh 携带 Authorization: Bearer 拉取脚本。
const SCRIPT_TOKEN_KEY = "script_token";
const SCRT_TTL_MS = 7 * 24 * 60 * 60 * 1000; // SCRT 令牌 7 天过期

const regenerateScriptToken = () => {
  const a = new Uint8Array(32);
  crypto.getRandomValues(a);
  const token = Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");
  return { token, created_at: Date.now() };
};

// 获取或创建 SCRT：过期自动轮换，旧格式（纯字符串）自动迁移为带时间戳的新格式
const getOrCreateScrt = async (env) => {
  const save = async (data) => {
    await env.DB.prepare(`INSERT INTO global_config (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).bind(SCRIPT_TOKEN_KEY, JSON.stringify(data)).run();
  };
  const { results } = await env.DB.prepare(`SELECT value FROM global_config WHERE key = ?1`).bind(SCRIPT_TOKEN_KEY).all();
  if (results && results.length > 0) {
    const stored = JSON.parse(results[0].value);
    if (typeof stored === "string") {
      const migrated = { token: stored, created_at: Date.now() };
      await save(migrated);
      return migrated.token;
    }
    if (Date.now() - (stored.created_at || 0) > SCRT_TTL_MS) {
      const fresh = regenerateScriptToken();
      await save(fresh);
      return fresh.token;
    }
    return stored.token;
  }
  const fresh = regenerateScriptToken();
  await save(fresh);
  return fresh.token;
};

// 校验脚本拉取授权（query ?t= 或 Authorization: Bearer），常量时间比较防时序侧信道
const isScriptsAuthorized = async (request, env, url) => {
  const fromHeader = (() => {
    const h = request.headers.get("Authorization") || "";
    return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
  })();
  const provided = (url.searchParams.get("t") || fromHeader || "").trim();
  if (!provided) return false;
  try {
    const { results } = await env.DB.prepare(`SELECT value FROM global_config WHERE key = ?1`).bind(SCRIPT_TOKEN_KEY).all();
    if (!results || results.length === 0) return false;
    const stored = JSON.parse(results[0].value);
    // 兼容旧格式（纯字符串）和新格式（{token, created_at}）
    const expected = typeof stored === "string" ? stored : stored.token;
    const createdAt = typeof stored === "string" ? 0 : (stored.created_at || 0);
    // SCRT 过期检查（7天）；旧格式令牌（createdAt=0）不强制过期
    if (createdAt > 0 && Date.now() - createdAt > SCRT_TTL_MS) return false;
    const ea = new TextEncoder().encode(provided);
    const eb = new TextEncoder().encode(expected);
    if (ea.length !== eb.length) return false;
    let diff = 0;
    for (let i = 0; i < ea.length; i++) diff |= ea[i] ^ eb[i];
    return diff === 0;
  } catch (e) {
    return false;
  }
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const domain = url.origin;

    // --- 提取并处理云端安全隔离变量 ---
    const WEB_USER = env.WEB_USER || "admin";        
    const WEB_PASS = env.WEB_PASS || "admin888";     
    const PROXY_USER = env.PROXY_USER || "proxy";    
    const PROXY_PASS = env.PROXY_PASS || "888888";   

    // H3: 默认弱凭证统一拒绝服务（WEB 面板口令 / PROXY 代理口令），强制部署者修改环境变量
    const weakType = detectWeakCredentials(WEB_USER, WEB_PASS, PROXY_USER, PROXY_PASS);
    if (weakType) {
      if (url.pathname === "/") {
        return new Response(SECURITY_WARNING_HTML(weakType), { headers: { "Content-Type": "text/html;charset=UTF-8" } });
      }
      return new Response("Security setup incomplete: default credentials in use. Update CF env vars (WEB_PASS / PROXY_PASS).", {
        status: 403,
        headers: { "Content-Type": "text/plain;charset=UTF-8" }
      });
    }

    // H3: 客户端真实 IP（用于按 IP 暴力破解防护）
    const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";

    // #5 常量时间字符串比较，防止时序侧信道逐字符爆破
    const timingSafeEqual = (a, b) => {
      const ea = new TextEncoder().encode(String(a));
      const eb = new TextEncoder().encode(String(b));
      if (ea.length !== eb.length) return false;
      let diff = 0;
      for (let i = 0; i < ea.length; i++) diff |= ea[i] ^ eb[i];
      return diff === 0;
    };

    const authenticate = (request) => {
      // #4 默认弱口令已由入口 weakType 统一拦截（H3），此处仅做凭据常量时间比对
      const authHeader = request.headers.get("Authorization");
      if (!authHeader) return false;
      const [scheme, encoded] = authHeader.split(" ");
      if (scheme !== "Basic") return false;
      try {
        const decoded = atob(encoded);
        const idx = decoded.indexOf(":");
        if (idx < 0) return false;
        const username = decoded.slice(0, idx);
        const password = decoded.slice(idx + 1);
        return timingSafeEqual(username, WEB_USER) && timingSafeEqual(password, WEB_PASS);
      } catch (e) {
        return false;
      }
    };

    const unauthorizedResponse = () => {
      return new Response("Unauthorized Access. Scanner Blocked.", {
        status: 401,
        headers: {
          "WWW-Authenticate": 'Basic realm="Proxy System Security Control"',
          "Content-Type": "text/plain;charset=UTF-8"
        }
      });
    };

    // H3: 认证闸门——集成按 IP 滑动窗口暴力破解防护。返回 null 放行，否则返回拒绝 Response。
    const authGate = () => {
      if (isRateLimited(clientIp)) {
        return new Response("Too many failed login attempts. Retry later.", {
          status: 429,
          headers: { "Content-Type": "text/plain;charset=UTF-8", "Retry-After": "60" }
        });
      }
      if (!authenticate(request)) {
        recordAuthFailure(clientIp);
        return unauthorizedResponse();
      }
      return null;
    };

    // #15 表初始化（isolate 级 dbInitialized 避免重复写入）。提前到路由分发之前，确保 /scripts 拉取授权可读 global_config。
    if (!dbInitialized) {
      await env.DB.prepare(`CREATE TABLE IF NOT EXISTS servers (ip TEXT PRIMARY KEY, details TEXT, last_seen INTEGER)`).run();
      await env.DB.prepare(`CREATE TABLE IF NOT EXISTS server_logs (ip TEXT PRIMARY KEY, logs TEXT, updated_at INTEGER)`).run();
      await env.DB.prepare(`CREATE TABLE IF NOT EXISTS global_config (key TEXT PRIMARY KEY, value TEXT)`).run();
      dbInitialized = true;
    }

    if (url.pathname === "/scripts/proxy_server.py") {
      // /scripts 凭证保护：必须携带一次性纳管令牌（SCRT）才返回内容，杜绝凭证明文外泄
      if (!(await isScriptsAuthorized(request, env, url))) {
        return new Response("Forbidden: token required or expired.", { status: 403, headers: { "Content-Type": "text/plain;charset=UTF-8" } });
      }
      const PROXY_CODE = `#!/usr/bin/env python3
from __future__ import annotations
import select, socket, threading, urllib.parse, time, base64, hmac, struct
from typing import Any

PROXY_USER = ${pyBytes(PROXY_USER)}
PROXY_PASS = ${pyBytes(PROXY_PASS)}

# 全局软开关：由 lite_manager 动态更新，实现秒切
ACTIVE_BIND = "tun_main"

def parse_int(value: Any) -> int:
    try: return int(value)
    except Exception: return 0

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk: raise ConnectionError("Unexpected disconnect.")
        data += chunk
    return data

def create_connection(address: tuple[str, int], timeout: float = 20) -> socket.socket:
    global ACTIVE_BIND
    bind_interface = ACTIVE_BIND
    host, port = address
    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(timeout)
            if bind_interface:
                sock.setsockopt(socket.SOL_SOCKET, 25, bind_interface.encode('utf-8'))
            sock.connect(sa)
            return sock
        except OSError as e:
            err = e
            if sock: sock.close()
    raise err or OSError("getaddrinfo empty")

def relay(left: socket.socket, right: socket.socket) -> None:
    # #13 设置写超时，防止慢消费端让 sendall 无限阻塞撑爆内存
    for _s in (left, right):
        try: _s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, struct.pack('ll', 60, 0))
        except Exception: pass
    peers = {left: right, right: left}
    socks = [left, right]
    while socks:
        readable, _, errored = select.select(socks, [], socks, 120)
        if errored: return
        for source in readable:
            target = peers.get(source)
            if target is None: continue
            try: data = source.recv(65536)
            except Exception: data = b""
            if not data:
                # #13 半关闭：一方 EOF 仅关闭对端写端，继续转发另一方向的剩余数据
                try: target.shutdown(socket.SHUT_WR)
                except Exception: pass
                socks = [s for s in socks if s is not source]
                peers.pop(source, None)
                continue
            try: target.sendall(data)
            except Exception: return

def socks5_client(client: socket.socket, first_byte: bytes) -> None:
    upstream = None
    try:
        methods_count = recv_exact(client, 1)[0]
        methods = recv_exact(client, methods_count)
        
        if b"\\x02" not in methods:
            client.sendall(b"\\x05\\xFF") 
            return
        client.sendall(b"\\x05\\x02")
        
        auth_req = recv_exact(client, 2)
        if auth_req[0] != 1: return
        ulen = auth_req[1]
        uname = recv_exact(client, ulen)
        plen = recv_exact(client, 1)[0]
        upass = recv_exact(client, plen)
        
        if not (hmac.compare_digest(uname, PROXY_USER) and hmac.compare_digest(upass, PROXY_PASS)):
            client.sendall(b"\\x01\\x01") 
            return
        client.sendall(b"\\x01\\x00") 

        version, command, _, address_type = recv_exact(client, 4)
        if version != 5 or command != 1: return
        if address_type == 1: host = socket.inet_ntoa(recv_exact(client, 4))
        elif address_type == 3: host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
        elif address_type == 4: host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else: return
        port = int.from_bytes(recv_exact(client, 2), "big")
        
        upstream = create_connection((host, port), timeout=20)
        client.sendall(b"\\x05\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00")
        relay(client, upstream)
    except Exception as e: print(f"[!] SOCKS5 relay error: {type(e).__name__}: {e}", flush=True)
    finally:
        client.close()
        if upstream: upstream.close()

def http_client(client: socket.socket, first_byte: bytes) -> None:
    upstream = None
    try:
        data = first_byte
        while b"\\r\\n\\r\\n" not in data and len(data) < 65536:
            chunk = client.recv(4096)
            if not chunk: break
            data += chunk
        head, rest = data.split(b"\\r\\n\\r\\n", 1)
        lines = head.decode("iso-8859-1", errors="replace").split("\\r\\n")
        
        expected_auth = "Basic " + base64.b64encode(PROXY_USER + b":" + PROXY_PASS).decode("ascii")
        auth_passed = False
        for line in lines[1:]:
            if line.lower().startswith("proxy-authorization:"):
                if hmac.compare_digest(line.split(":", 1)[1].strip(), expected_auth):
                    auth_passed = True
                    break
                    
        if not auth_passed:
            client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\\r\\nProxy-Authenticate: Basic realm=\\"Proxy\\"\\r\\n\\r\\n")
            return

        method, target, version = lines[0].split(" ", 2)
        if method.upper() == "CONNECT":
            host, _, port_text = target.partition(":")
            upstream = create_connection((host, parse_int(port_text) or 443), timeout=20)
            client.sendall(b"HTTP/1.1 200 Connection Established\\r\\n\\r\\n")
            if rest: upstream.sendall(rest)
            relay(client, upstream)
            return
        parsed = urllib.parse.urlsplit(target)
        if not parsed.hostname: return
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = [line for line in lines[1:] if not line.lower().startswith(("proxy-connection:", "connection:", "proxy-authorization:"))]
        request = f"{method} {path} {version}\\r\\n" + "\\r\\n".join(headers) + "\\r\\nConnection: close\\r\\n\\r\\n"
        upstream = create_connection((parsed.hostname, port), timeout=20)
        upstream.sendall(request.encode("iso-8859-1") + rest)
        relay(client, upstream)
    except Exception as e: print(f"[!] HTTP relay error: {type(e).__name__}: {e}", flush=True)
    finally:
        client.close()
        if upstream: upstream.close()

def proxy_client(client: socket.socket, address: tuple[str, int]) -> None:
    try:
        client.settimeout(30)
        first = recv_exact(client, 1)
        if first == b"\\x05": socks5_client(client, first)
        else: http_client(client, first)
    except Exception:
        try: client.close()
        except Exception: pass

# M3: 全局并发上限，防止慢速/海量连接耗尽 VPS 线程资源（DoS）
MAX_CONN = 512
_conn_sem = threading.BoundedSemaphore(MAX_CONN)

def _handle_conn(client: socket.socket, address: tuple[str, int]) -> None:
    try:
        proxy_client(client, address)
    finally:
        try: _conn_sem.release()
        except Exception: pass

def start_proxy_server(host: str, port: int) -> None:
    try:
        # 支持双栈：判断地址中是否包含冒号以启用 AF_INET6
        af = socket.AF_INET6 if ":" in host else socket.AF_INET
        server = socket.socket(af, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 强制解除 V6ONLY，允许一个 IPv6 Socket 同时接收 IPv4 和 IPv6 连接
        if af == socket.AF_INET6:
            try:
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except Exception:
                pass
        server.bind((host, port))
        server.listen(256)
    except Exception as e:
        # M5: 绑定失败打印原因，便于排查端口占用
        print(f"[!] 代理服务监听 {host}:{port} 失败: {type(e).__name__}: {e}", flush=True)
        return
    while True:
        try:
            client, address = server.accept()
            # M3: 达并发上限立即拒绝新连接，避免无界创建线程
            if not _conn_sem.acquire(blocking=False):
                try: client.close()
                except Exception: pass
                continue
            threading.Thread(target=_handle_conn, args=(client, address), daemon=True).start()
        except Exception as e:
            # M5: accept 异常记录
            print(f"[!] accept 异常: {type(e).__name__}: {e}", flush=True)
            time.sleep(0.5)
`;
      return new Response(PROXY_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname === "/scripts/lite_manager.py") {
      if (!(await isScriptsAuthorized(request, env, url))) {
        return new Response("Forbidden: token required or expired.", { status: 403, headers: { "Content-Type": "text/plain;charset=UTF-8" } });
      }
      const MANAGER_CODE = `#!/usr/bin/env python3
import base64, csv, os, re, subprocess, threading, time, urllib.request, json
from pathlib import Path
import proxy_server

API_URL = "https://www.vpngate.net/api/iphone/"
C2_URL = ${pyStr(domain)}

WORKSPACE = Path("/opt/proxy_lite")
CONFIG_DIR = WORKSPACE / "configs"
AUTH_FILE = WORKSPACE / "auth.txt"

WEB_USER = ${pyStr(WEB_USER)}
WEB_PASS = ${pyStr(WEB_PASS)}

PROXY_PORT = 7920
target_country = "JP"
last_switch_trigger = 0
first_boot = True  # L1: 冷启动标志，首轮吸收持久化的 switch_trigger，避免每次重启误触发一次"强制更换"

state_lock = threading.Lock()
dead_ips = {}  # country -> set(ip)：按国家分桶黑名单（#2 熔断仅清当前国家，避免核弹级副作用）
last_blacklist_clear = time.time()
public_ip = ""

# #1 彻底淘汰机制：节点被熔断释放次数累计达阈值后，从蓄水池永久移除，打破死循环
node_release_count = {}
FATAL_RELEASE_THRESHOLD = 3

# #5 熔断日志节流：同一国家冷却期内仅打印一次，避免日志噪音淹没真实故障信号
last_breaker_log = {}
BREAKER_LOG_COOLDOWN = 60

global_node_reservoir = {} 
reservoir_lock = threading.Lock()

class Tunnel:
    def __init__(self, name: str, table_id: int):
        self.name = name
        self.table_id = table_id
        self.process = None
        self.node = None
        self.entry_ip = ""
        self.egress_ip = ""
        self.country = ""
        self.ready = False
        self.connected_at = 0
        self.is_connecting = False
        self.generation = 0  # #3 代际标记：隧道身份对调时递增，使进行中的 connect_node 写入失效

tun_main = Tunnel("tun_main", 101)
tun_backup = Tunnel("tun_backup", 102)

def penalize_node(ip: str, penalty: int):
    """
    节点信誉动态降级机制：
    给不可用或低质的节点加上高额的虚拟 ping 值惩罚，
    确保下一次调度排序时，该节点被永久压入蓄水池底部，从而避免"死循环假性枯竭"。
    """
    with reservoir_lock:
        if ip in global_node_reservoir:
            global_node_reservoir[ip]["ping"] += penalty

def blacklist_node(ip: str, country: str = ""):
    """
    将节点加入其所属国家的分桶黑名单（#2）。
    优先使用传入的 country；未提供时回退从蓄水池查询节点归属国家。
    """
    c = (country or "").upper()
    # #2 统一用 reservoir_lock 保护 dead_ips，消除跨线程读写竞态
    with reservoir_lock:
        if not c:
            node = global_node_reservoir.get(ip)
            if node: c = (node.get("country") or "").upper()
        if c:
            dead_ips.setdefault(c, set()).add(ip)

def get_public_ip():
    global public_ip
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=5) as res:
            ip = res.read().decode("utf-8").strip()
    except Exception as e:
        # M5: 记录失败而非完全静默；L2: 写入加 state_lock 规范化跨线程可见性
        print(f"[!] 获取公网IP失败: {type(e).__name__}: {e}", flush=True)
        ip = "Unknown_IP"
    with state_lock:
        public_ip = ip

def get_c2_headers():
    auth_ptr = base64.b64encode(f"{WEB_USER}:{WEB_PASS}".encode()).decode()
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Authorization": f"Basic {auth_ptr}"
    }

def get_recent_logs():
    try:
        res = subprocess.run(["journalctl", "-u", "proxy-lite.service", "-n", "30", "--no-pager", "--output=cat"], capture_output=True, text=True, errors="replace")
        return res.stdout
    except Exception: return "Waiting for logs..."

def update_config_loop():
    global target_country, last_switch_trigger, first_boot, PROXY_PORT, tun_main, tun_backup
    while True:
        try:
            req = urllib.request.Request(f"{C2_URL}/api/config", headers=get_c2_headers())
            with urllib.request.urlopen(req, timeout=10) as res:
                data = json.loads(res.read().decode("utf-8"))
                desired_country = str(data.get("0", "JP")).upper()
                switch_trigger = int(data.get("switch_trigger", 0))
                new_port = int(data.get("port", 7920))
                
                if new_port != PROXY_PORT:
                    print(f"[*] 收到端口变更指令 ({PROXY_PORT} -> {new_port})，主动清理隧道后重启守护进程...", flush=True)
                    # #14 os._exit 前主动终止 openvpn 子进程避免孤儿（daemon 线程中 sys.exit 无法终止整个进程，故保留 os._exit 并补齐清理）
                    with state_lock:
                        for _tun in (tun_main, tun_backup):
                            if _tun.process:
                                try: _tun.process.terminate()
                                except Exception: pass
                    time.sleep(1)
                    os._exit(0)
                
                with state_lock:
                    # L1: 冷启动首轮只吸收持久化的 switch_trigger，绝不触发强制清退（Bug 1 修复）。
                    if first_boot:
                        last_switch_trigger = switch_trigger
                        first_boot = False
                        if target_country != desired_country:
                            target_country = desired_country
                            print(f"[*] 冷启动策略初始化: 目标 {desired_country}", flush=True)
                        force_switch = False
                    else:
                        force_switch = (switch_trigger > last_switch_trigger)
                    if target_country != desired_country or force_switch:
                        target_country = desired_country
                        if force_switch: print(f"[*] 收到强制更换指令，正在清退通道并拉黑当前 IP...", flush=True)
                        else: print(f"[*] 策略热切换: 目标重定向到 {desired_country}...", flush=True)
                        
                        if tun_main.entry_ip: blacklist_node(tun_main.entry_ip, tun_main.country)
                        if tun_backup.entry_ip: blacklist_node(tun_backup.entry_ip, tun_backup.country)
                        if tun_main.process:
                            try: tun_main.process.terminate(); tun_main.process.wait(2)
                            except Exception:
                                try: tun_main.process.kill()
                                except Exception: pass
                        tun_main.ready = False; tun_main.is_connecting = False; tun_main.process = None; tun_main.node = None; tun_main.entry_ip = ""; tun_main.egress_ip = ""; tun_main.generation += 1
                        
                        if tun_backup.process:
                            try: tun_backup.process.terminate(); tun_backup.process.wait(2)
                            except Exception:
                                try: tun_backup.process.kill()
                                except Exception: pass
                        tun_backup.ready = False; tun_backup.is_connecting = False; tun_backup.process = None; tun_backup.node = None; tun_backup.entry_ip = ""; tun_backup.egress_ip = ""; tun_backup.generation += 1
                        
                        last_switch_trigger = switch_trigger
        except Exception as e:
            # M5: 记录配置拉取异常，避免故障静默
            body = ""
            if hasattr(e, 'read'):
                try: body = e.read().decode("utf-8", errors="replace")[:200]
                except Exception: pass
            print(f"[!] update_config_loop 异常: {type(e).__name__}: {e} | {body}", flush=True)
        time.sleep(15)

def c2_heartbeat_loop():
    global public_ip, PROXY_PORT, tun_main, tun_backup
    while True:
        if not public_ip or public_ip == "Unknown_IP": get_public_ip()
        details = []
        with state_lock:
            for tun in [tun_main, tun_backup]:
                if tun.ready and tun.process and tun.process.poll() is None:
                    uptime = time.time() - tun.connected_at
                    details.append({
                        "tunnel": tun.name,
                        "active": proxy_server.ACTIVE_BIND == tun.name,
                        "country": tun.country, 
                        "port": PROXY_PORT, 
                        "connected_time": int(uptime), 
                        "node_ip": tun.egress_ip if tun.egress_ip else tun.entry_ip
                    })
        
        payload = json.dumps({"ip": public_ip, "details": details, "logs": get_recent_logs()}).encode('utf-8')
        try:
            req = urllib.request.Request(f"{C2_URL}/api/report", data=payload, headers=get_c2_headers(), method='POST')
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            # M5: 心跳上报失败记录，便于发现 C2 连通性问题
            body = ""
            if hasattr(e, 'read'):
                try: body = e.read().decode("utf-8", errors="replace")[:200]
                except Exception: pass
            print(f"[!] c2_heartbeat_loop 上报异常: {type(e).__name__}: {e} | {body}", flush=True)
        time.sleep(8)

def setup_env():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text("vpn\\nvpn\\n", encoding="utf-8")
        AUTH_FILE.chmod(0o600)
    # 强制系统解除反向路径过滤，防止策略路由双拨时数据包被内核丢弃
    subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=2"], capture_output=True)
    subprocess.run(["sysctl", "-w", "net.ipv4.conf.default.rp_filter=2"], capture_output=True)

def harvest_snapshot_nodes() -> list:
    try:
        req = urllib.request.Request(API_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as res: text = res.read().decode("utf-8", errors="replace")
        lines = [line for line in text.splitlines() if line and not line.startswith("*")]
        if lines and lines[0].startswith("#"): lines[0] = lines[0][1:]
        nodes = []
        for row in csv.DictReader(lines):
            try:
                ip = row.get("IP")
                if not ip or not row.get("OpenVPN_ConfigData_Base64"): continue
                raw_ping = row.get("Ping", "")
                nodes.append({
                    "ip": ip, 
                    "ping": int(raw_ping) if raw_ping.isdigit() else 9999, 
                    "country": row.get("CountryShort", "").upper(), 
                    "config": base64.b64decode(row["OpenVPN_ConfigData_Base64"]).decode("utf-8", errors="replace"),
                    "harvested_at": time.time()
                })
            except Exception:
                continue  # #23 单行解析失败跳过，不影响整批快照（原实现一个坏 base64 会丢全部节点）
        return nodes
    except Exception as e:
        # M5: 抓取失败打印原因，避免节点库静默枯竭
        print(f"[!] harvest_snapshot_nodes 异常: {type(e).__name__}: {e}", flush=True)
        return []

def vpngate_fetch_loop():
    global global_node_reservoir, dead_ips
    while True:
        snapshot = harvest_snapshot_nodes()
        if snapshot:
            with reservoir_lock:
                for n in snapshot:
                    # #1 已被彻底淘汰的节点不再回收（即使快照中再次出现）
                    if node_release_count.get(n["ip"], 0) >= FATAL_RELEASE_THRESHOLD:
                        continue
                    # 保留原有的惩罚性 ping 值，防止坏节点被新抓取的快照刷新后又跑到前列去
                    if n["ip"] in global_node_reservoir:
                        n["ping"] = max(n["ping"], global_node_reservoir[n["ip"]]["ping"])
                    global_node_reservoir[n["ip"]] = n
            print(f"[*] ⚡ 节点库更新，当前囤积有效节点 -> {len(global_node_reservoir)} 个", flush=True)
        else:
            # FIX 3: VPNGate 接口被限流/不通，延长现有节点生命周期，防止库干涸
            with reservoir_lock:
                now = time.time()
                for n in global_node_reservoir.values():
                    n["harvested_at"] = now
        time.sleep(300)

def setup_routing(tun_name: str, table_id: int):
    subprocess.run(["ip", "rule", "del", "pref", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "del", "pref", str(table_id + 1000)], capture_output=True)
    subprocess.run(["ip", "route", "flush", "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "route", "add", "default", "dev", tun_name, "table", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "add", "oif", tun_name, "lookup", str(table_id), "pref", str(table_id)], capture_output=True)
    subprocess.run(["ip", "rule", "add", "iif", tun_name, "lookup", str(table_id), "pref", str(table_id + 1000)], capture_output=True)

def connect_node(tun: Tunnel, node: dict):
    global dead_ips
    my_gen = tun.generation  # #3 记录当前代际，隧道对调后用于使本次写入失效
    try:
        cfg_path = CONFIG_DIR / f"{tun.name}.ovpn"
        log_file = WORKSPACE / f"{tun.name}_err.log"
        # #26 清洗会劫持宿主默认路由的静态指令（--route-nopull 只挡服务端 push，挡不住 config body 里的静态 redirect-gateway，会导致 VPS SSH 断连）
        clean_cfg = re.sub(r'(?m)^[ \t]*redirect-gateway\b.*$', '', node["config"])
        cfg_path.write_text(clean_cfg, encoding="utf-8")
        
        ovpn_version = subprocess.run(["openvpn", "--version"], capture_output=True, text=True).stdout
        cipher_args = ["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"] if "2.4" in ovpn_version else ["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "--data-ciphers-fallback", "AES-128-CBC"]
        
        # 强制添加 --nobind 解除端口冲突，--route-nopull 剥夺路由修改权
        # M4: --verb 2 替代 3，大幅减少长期运行时的日志写入量，缓解 _err.log 无限增长
        cmd = ["openvpn", "--config", str(cfg_path), "--dev", tun.name, "--dev-type", "tun",
               "--nobind", "--route-nopull",
               "--pull-filter", "ignore", "route-ipv6", "--pull-filter", "ignore", "ifconfig-ipv6",
               "--auth-user-pass", str(AUTH_FILE), "--auth-nocache",
               "--connect-timeout", "5", "--connect-retry-max", "1", "--verb", "2"] + cipher_args
               
        with open(log_file, "w") as f: process = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)
        
        success = False
        for _ in range(15):
            time.sleep(1)
            if process.poll() is not None: break
            try:
                if "Initialization Sequence Completed" in log_file.read_text():
                    success = True; break
            except Exception: pass
                
        if success and process.poll() is None:
            setup_routing(tun.name, tun.table_id)
            time.sleep(1) 
            
            # --- 穿透获取通道真实出口 IP ---
            true_ip = ""
            try:
                true_ip_res = subprocess.run(["curl", "-s", "-m", "5", "--interface", tun.name, "https://api.ipify.org"], capture_output=True, text=True)
                candidate_ip = true_ip_res.stdout.strip()
                if candidate_ip and candidate_ip.count('.') == 3:
                    true_ip = candidate_ip
            except Exception: pass
            
            egress_ip = true_ip if true_ip else node['ip']
            
            if true_ip and true_ip != node['ip']:
                print(f"[*] {tun.name} 探测到真实出口 IP 与入口不一致: 入口 {node['ip']} -> 出口 {true_ip}", flush=True)

            # #24 质检并行化：TestISP 与 YouTube 同时执行，缩短隧道槽位占用（原串行 ~15s → 并行 ~8s）
            qc = {"residential": True, "yt_ok": True}

            def _check_isp():
                try:
                    req_url = f"https://testisp.info/api/check?ip={egress_ip}"
                    check_req = urllib.request.Request(req_url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}, method="GET")
                    with urllib.request.urlopen(check_req, timeout=8) as check_res:
                        data = json.loads(check_res.read().decode("utf-8"))
                        if str(data.get("isp", {}).get("flag", "")).lower() == "hosting":
                            qc["residential"] = False
                except Exception: pass

            def _check_yt():
                try:
                    res = subprocess.run(["curl", "-I", "-s", "-A", "Mozilla/5.0", "-m", "5", "--interface", tun.name, "https://www.youtube.com"], capture_output=True, timeout=8)
                    if res.returncode != 0: qc["yt_ok"] = False
                except Exception: qc["yt_ok"] = False

            print(f"[*] {tun.name} 并行深度质检 (TestISP + YouTube)...", flush=True)
            t_isp = threading.Thread(target=_check_isp); t_yt = threading.Thread(target=_check_yt)
            t_isp.start(); t_yt.start()
            t_isp.join(10); t_yt.join(7)

            def _abort_node(reason: str, penalty: int):
                """质检失败统一清理：惩罚 + 拉黑 + 终止 openvpn（#18 防 kill 二次异常）"""
                print(f"[-] {tun.name} {reason}: {node['ip']}", flush=True)
                penalize_node(node["ip"], penalty)
                blacklist_node(node["ip"], node["country"])
                try: process.terminate(); process.wait(2)
                except Exception:
                    try: process.kill()
                    except Exception: pass

            if not qc["residential"]:
                _abort_node(f"节点出口 ({egress_ip}) 检测为机房 IP，残忍抛弃", 50000)
                return

            if not qc["yt_ok"]:
                _abort_node("节点出口无法连通 YouTube，拉黑更换", 10000)
                return

            # #3 代际校验：隧道对调后身份变更则放弃写入，避免幽灵隧道
            with state_lock:
                if tun.generation != my_gen:
                    stale = True
                else:
                    stale = False
                    tun.process = process
                    tun.node = node
                    tun.entry_ip = node["ip"]
                    tun.egress_ip = egress_ip
                    tun.country = node["country"]
                    tun.connected_at = time.time()
                    tun.ready = True
            if stale:
                print(f"[!] {tun.name} 连接完成但代际已变更（隧道身份对调），丢弃结果避免幽灵隧道", flush=True)
                try: process.terminate(); process.wait(2)
                except Exception:
                    try: process.kill()
                    except Exception: pass
            else:
                role = "主网卡" if proxy_server.ACTIVE_BIND == tun.name else "备用网卡"
                print(f"[+] {tun.name} ({role}) 完全就绪: 入口 {node['ip']} -> 出口 {egress_ip}", flush=True)
                # M4: 连接成功后清空 _err.log，避免长期运行时日志文件持续膨胀
                try: log_file.write_text("Connection established.\\n", encoding="utf-8")
                except Exception: pass
        else:
            penalize_node(node["ip"], 5000)  # 建连超时中度惩罚
            try: process.terminate(); process.wait(2)
            except Exception:
                try: process.kill()
                except Exception: pass
            blacklist_node(node["ip"], node["country"])
    finally:
        # L2: 仅当本代连接(generation 未变)才释放单飞锁（Bug 4 修复）。
        with state_lock:
            if tun.generation == my_gen:
                tun.is_connecting = False

def health_check_loop():
    # H6: 主备双隧道独立容错——原先仅检测 tun_main，tun_backup 进程死亡后 ready 永真沦为僵尸隧道永不重连（根因 1-A）
    fail = {"tun_main": 0, "tun_backup": 0}
    last_ip = {"tun_main": "", "tun_backup": ""}

    def _probe(tun):
        # 冷启动 20 秒内不检测；未就绪/进程已退出的隧道重置计数后跳过
        with state_lock:
            if not (tun.ready and tun.process and tun.process.poll() is None):
                fail[tun.name] = 0
                return None
            if time.time() - tun.connected_at <= 20:
                return None
            return (tun.name, tun.entry_ip, tun.country, tun.process)

    def _check(tun):
        snap = _probe(tun)
        if snap is None: return
        tname, tip, tcountry, proc = snap
        # #6 隧道身份变化（对调或重连）时重置容错窗口，避免新隧道被过早踢线
        if tip != last_ip[tname]:
            fail[tname] = 0
            last_ip[tname] = tip
        # 1. 应用层：多维 HTTP 探针（原生 socket 建连 + 超时）
        endpoints = [
            ("www.gstatic.com", 80), ("cp.cloudflare.com", 80),
            ("1.1.1.1", 80), ("8.8.8.8", 80)
        ]
        is_alive = False
        for probe_host, probe_port in endpoints:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.setsockopt(socket.SOL_SOCKET, 25, tname.encode('utf-8'))
                s.connect((probe_host, probe_port))
                s.close()
                is_alive = True
                break
            except Exception:
                try: s.close()
                except Exception: pass
        # 2. 网络层：应用层全挂则尝试底层 ICMP 作为容错底线（住宅 IP 到国际端点可能偶尔抖动）
        if not is_alive:
            ping_res = subprocess.run(["ping", "-c", "2", "-W", "3", "-I", tname, "8.8.8.8"], capture_output=True)
            if ping_res.returncode == 0:
                is_alive = True
        # 3. 容错评估与处决
        if not is_alive:
            fail[tname] += 1
            if fail[tname] >= 3:
                print(f"[!] {tname} 连续 {fail[tname]} 次多维探针(HTTP/ICMP)均无响应，确认为真死断流，执行踢线: {tip}", flush=True)
                penalize_node(tip, 3000)
                blacklist_node(tip, tcountry)
                try: proc.terminate(); proc.wait(timeout=2)
                except Exception:
                    try: proc.kill()
                    except Exception: pass
                with state_lock:
                    if tun.process is proc: tun.ready = False
                fail[tname] = 0
            else:
                print(f"[*] {tname} 探针无响应，启动快频深度复核容错机制 ({fail[tname]}/3)...", flush=True)
        else:
            # 成功时衰减而非归零：对抗偶发假阳性（如隧道半死状态下 TCP 握手偶通），累积趋势仍能触发踢线
            fail[tname] = max(0, fail[tname] - 1)

    while True:
        # 任一隧道处于容错态时加快复核频率（保留原 5 秒快频语义）
        time.sleep(5 if (fail["tun_main"] or fail["tun_backup"]) else 15)
        _check(tun_main)
        _check(tun_backup)

def get_best_candidate():
    global global_node_reservoir, dead_ips, target_country, tun_main, tun_backup
    global node_release_count, last_breaker_log
    # L6: 锁内只做最小必要的快照与写操作，排序移到锁外，避免长持锁阻塞 harvest/blacklist
    with reservoir_lock:
        pool_snapshot = list(global_node_reservoir.values())
        dead_snap = dict(dead_ips)
        active_ips = []
        for _t in (tun_main, tun_backup):
            if _t.entry_ip: active_ips.append(_t.entry_ip)
            elif _t.node and isinstance(_t.node, dict) and _t.node.get("ip"): active_ips.append(_t.node["ip"])
        candidates = [n for n in pool_snapshot if n["country"] == target_country and n["ip"] not in dead_snap.get(target_country, set())]
        candidates = [n for n in candidates if n["ip"] not in active_ips]

    # 锁外排序 + 快速回锁校验存在性
    if candidates:
        candidates.sort(key=lambda x: x["ping"])
        chosen = candidates[0]
        with reservoir_lock:
            if chosen["ip"] in global_node_reservoir:
                return chosen
        return None

    # 候选枯竭：回锁内执行淘汰写操作
    with reservoir_lock:
        has_blacklisted = any(n["country"] == target_country for n in pool_snapshot)
        if has_blacklisted:
            released = dead_ips.pop(target_country, set())
            for ip in released:
                node_release_count[ip] = node_release_count.get(ip, 0) + 1
            fatal_ips = [ip for ip, cnt in node_release_count.items() if cnt >= FATAL_RELEASE_THRESHOLD]
            for ip in fatal_ips:
                global_node_reservoir.pop(ip, None)
                node_release_count.pop(ip, None)
            if fatal_ips:
                print(f"[!] 💀 [{target_country}] 彻底淘汰 {len(fatal_ips)} 个反复失效节点（累计熔断≥{FATAL_RELEASE_THRESHOLD}次），已从蓄水池永久移除", flush=True)
            now = time.time()
            if now - last_breaker_log.get(target_country, 0) > BREAKER_LOG_COOLDOWN:
                print(f"[!] ⚡ 紧急熔断：[{target_country}] 节点黑名单释放救场（由于动态信誉系统存在，历史坏节点将被沉底）", flush=True)
                last_breaker_log[target_country] = now
            candidates = [n for n in global_node_reservoir.values() if n["country"] == target_country and n["ip"] not in active_ips]

    # 锁外排序
    if candidates:
        candidates.sort(key=lambda x: x["ping"])
        return candidates[0]

    # H7: 跨国家回退——目标国家彻底无可用节点时，按优先级回退到节点丰富的国家，避免代理服务完全不可用（根因 2-B）
    FALLBACK_COUNTRIES = ["JP", "US", "SG", "HK", "KR", "TW", "GB", "DE", "FR", "NL", "CA"]
    with reservoir_lock:
        active_ips = []
        for _t in (tun_main, tun_backup):
            if _t.entry_ip: active_ips.append(_t.entry_ip)
            elif _t.node and isinstance(_t.node, dict) and _t.node.get("ip"): active_ips.append(_t.node["ip"])
        fb_match = None
        for fb in FALLBACK_COUNTRIES:
            if fb == target_country: continue
            fb_candidates = [n for n in global_node_reservoir.values()
                             if n["country"] == fb
                             and n["ip"] not in dead_ips.get(fb, set())
                             and n["ip"] not in active_ips]
            if fb_candidates:
                fb_match = (fb, fb_candidates)
                break
    # 锁外排序并返回
    if fb_match:
        fb, fb_candidates = fb_match
        fb_candidates.sort(key=lambda x: x["ping"])
        print(f"[!] ⚠️ [{target_country}] 已无任何可用节点，跨国家回退到 [{fb}]（出口 IP 将与目标地区不符）: {fb_candidates[0]['ip']}", flush=True)
        return fb_candidates[0]
    return None

def maintain_pool():
    global dead_ips, last_blacklist_clear, tun_main, tun_backup
    last_release_decay = time.time()  # H8: node_release_count 老化计时器
    while True:
        try:
            # H8: 每 30 分钟将 node_release_count 衰减 1，给偶发失败的节点复活机会（根因 2-C 缓解）
            if time.time() - last_release_decay > 1800:
                with reservoir_lock:
                    for ip in list(node_release_count.keys()):
                        node_release_count[ip] -= 1
                        if node_release_count[ip] <= 0:
                            del node_release_count[ip]
                print(f"[*] node_release_count 已衰减（当前追踪 {len(node_release_count)} 个节点）", flush=True)
                last_release_decay = time.time()
            if time.time() - last_blacklist_clear > 600:
                # L8: 不再定时全局清空 dead_ips（会让机房/坏节点被反复重试）。
                # 改为仅移除"已无对应蓄水池节点"的国家分桶，保留仍有节点的国家黑名单。
                with reservoir_lock:
                    alive_countries = {n["country"] for n in global_node_reservoir.values() if n.get("country")}
                    stale = [c for c in list(dead_ips.keys()) if c not in alive_countries]
                    for c in stale:
                        dead_ips.pop(c, None)
                last_blacklist_clear = time.time()

            with reservoir_lock:
                now = time.time()
                stale_ips = [ip for ip, node in global_node_reservoir.items() if now - node["harvested_at"] > 10800]
                for ip in stale_ips: global_node_reservoir.pop(ip, None)

            with state_lock:
                # FIX 2: 连接中的通道不判死，防止尚未就绪导致的错误判死和秒切混乱
                main_dead = False
                if not tun_main.is_connecting:
                    if tun_main.process is None or tun_main.process.poll() is not None or not tun_main.ready:
                        main_dead = True

                if main_dead:
                    if tun_backup.ready and tun_backup.process and tun_backup.process.poll() is None and not tun_backup.is_connecting:
                        print(f"[*] ⚡ 主通道暴毙，软开关秒切！无缝接管业务至备用通道: 出口 {tun_backup.egress_ip or tun_backup.entry_ip}", flush=True)
                        # 状态互换 (身份对调)
                        tun_main, tun_backup = tun_backup, tun_main
                        proxy_server.ACTIVE_BIND = tun_main.name

                        # 异步清理死掉的旧主卡 (现在的 tun_backup)
                        if tun_backup.process:
                            try: tun_backup.process.terminate(); tun_backup.process.wait(2)
                            except Exception:
                                try: tun_backup.process.kill()
                                except Exception: pass
                        tun_backup.process = None; tun_backup.node = None; tun_backup.entry_ip = ""; tun_backup.egress_ip = ""
                        tun_backup.ready = False; tun_backup.is_connecting = False
                        tun_backup.generation += 1  # #3 递增代际，使进行中的 connect_node 放弃写入
                    else:
                        if tun_main.process:
                            try: tun_main.process.terminate(); tun_main.process.wait(2)
                            except Exception:
                                try: tun_main.process.kill()
                                except Exception: pass
                        tun_main.process = None; tun_main.ready = False; tun_main.is_connecting = False
                        tun_main.entry_ip = ""; tun_main.egress_ip = ""

            with state_lock:
                needs_main = not tun_main.ready and not tun_main.is_connecting
                needs_backup = not tun_backup.ready and not tun_backup.is_connecting

            if needs_main:
                node = get_best_candidate()
                if node:
                    with state_lock:
                        tun_main.is_connecting = True
                        tun_main.node = node
                        tun_main.entry_ip = node["ip"]  # FIX 1: 提前占住坑位，防双通道抢同 IP
                    threading.Thread(target=connect_node, args=(tun_main, node,), daemon=True).start()
                    time.sleep(1)
                else:
                    print(f"[!] ⚠️ 调度枯竭：无法为 tun_main 获取候选（目标 {target_country}，蓄水池 {len(global_node_reservoir)} 个）", flush=True)
            if needs_backup:
                node = get_best_candidate()
                if node:
                    with state_lock:
                        tun_backup.is_connecting = True
                        tun_backup.node = node
                        tun_backup.entry_ip = node["ip"]  # FIX 1: 提前占住坑位
                    threading.Thread(target=connect_node, args=(tun_backup, node,), daemon=True).start()
                else:
                    print(f"[!] ⚠️ 调度枯竭：无法为 tun_backup 获取候选（目标 {target_country}，蓄水池 {len(global_node_reservoir)} 个）", flush=True)
        except Exception as e:
            # #1 兜底保护：任何异常都不让核心调度线程死亡（否则系统进入无告警的僵尸态）
            print(f"[!] maintain_pool 异常（已捕获，继续运行）: {type(e).__name__}: {e}", flush=True)
        time.sleep(2)

def main():
    global PROXY_PORT, tun_main
    if os.geteuid() != 0: return
    get_public_ip()
    setup_env()
    subprocess.run(["pkill", "-f", r"openvpn.*tun_(main|backup)"], capture_output=True)
    
    proxy_server.ACTIVE_BIND = tun_main.name
    
    try:
        req = urllib.request.Request(f"{C2_URL}/api/config", headers=get_c2_headers())
        with urllib.request.urlopen(req, timeout=10) as res:
            data = json.loads(res.read().decode("utf-8"))
            PROXY_PORT = int(data.get("port", 7920))
    except Exception as e: print(f"[!] 首次配置拉取失败，使用默认端口 {PROXY_PORT}: {type(e).__name__}: {e}", flush=True)

    print("========================================", flush=True)
    print(f"  Proxy Controller (主备双活引擎) 启动！端口: {PROXY_PORT}", flush=True)
    print("========================================", flush=True)

    threading.Thread(target=vpngate_fetch_loop, daemon=True).start()
    threading.Thread(target=update_config_loop, daemon=True).start()
    # 启用全局 IPv6 ANY 监听
    threading.Thread(target=proxy_server.start_proxy_server, args=("::", PROXY_PORT), daemon=True).start()
    threading.Thread(target=health_check_loop, daemon=True).start()
    threading.Thread(target=c2_heartbeat_loop, daemon=True).start()
    maintain_pool()

if __name__ == "__main__":
    main()
`;
      return new Response(MANAGER_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname === "/agent") {
      // L3: agent 脚本接收 SCRT token 占位符（由管理员复制纳管命令时填入），用后即弃，避免凭证明文落入脚本
      const agentScript = `#!/usr/bin/env bash
set -e
echo "=========================================================="
echo "     Proxy Controller (Active-Standby Multi-Tunnel)    "
echo "=========================================================="

SCRT="\${SCRT:-}"
if [ -z "$SCRT" ]; then echo "FATAL: 未提供纳管令牌(SCRT)。请在面板复制完整纳管命令后再执行。" >&2; exit 1; fi

echo "net.ipv4.conf.all.rp_filter=2" > /etc/sysctl.d/99-proxy-lite.conf
echo "net.ipv4.conf.default.rp_filter=2" >> /etc/sysctl.d/99-proxy-lite.conf
sysctl --system >/dev/null 2>&1 || true

apt-get update -q || true
apt-get install -y openvpn python3 curl iproute2 iptables cron psmisc

mkdir -p /opt/proxy_lite/configs
cd /opt/proxy_lite

echo "[1/3] 凭令牌从安全中心拉取双活极速引擎..."
curl -fsSL -H "Authorization: Bearer $SCRT" -o lite_manager.py ${bashQuote(domain + "/scripts/lite_manager.py")} || { echo "FATAL: 拉取 lite_manager.py 失败（令牌无效或已过期）" >&2; exit 1; }
curl -fsSL -H "Authorization: Bearer $SCRT" -o proxy_server.py ${bashQuote(domain + "/scripts/proxy_server.py")} || { echo "FATAL: 拉取 proxy_server.py 失败" >&2; exit 1; }
unset SCRT

echo "[2/3] 配置系统守护服务..."
cat > /lib/systemd/system/proxy-lite.service << 'EOF'
[Unit]
Description=Proxy Core Engine (Active-Standby)
After=network.target

[Service]
Type=simple
Environment="PYTHONIOENCODING=utf-8"
Environment="LANG=C.UTF-8"
WorkingDirectory=/opt/proxy_lite
ExecStart=/usr/bin/python3 -u lite_manager.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable proxy-lite.service
systemctl restart proxy-lite.service

echo "[+] 引擎更新成功！主备双活通道、异步刷IP逻辑已全量加载。"
`;
      return new Response(agentScript, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname.startsWith("/api/testisp-lookup/")) {
        const _gate = authGate();
        if (_gate) return _gate;
        const targetIp = decodeURIComponent(url.pathname.replace("/api/testisp-lookup/", ""));
        // #11 校验合法 IPv4/IPv6，防止参数注入与 SSRF（H2 统一复用 isValidIp，消除重复正则）
        if (!isValidIp(targetIp)) {
            return new Response("Invalid IP", { status: 400 });
        }
        try {
            const reqUrl = `https://testisp.info/api/check?ip=${targetIp}`;
            const resp = await fetch(reqUrl, {
                headers: {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                    "Accept": "application/json, text/plain, */*",
                    "Referer": "https://testisp.info/"
                }
            });
            const data = await resp.text();
            return new Response(data, { 
                status: resp.status,
                headers: { 
                    "Content-Type": resp.headers.get("content-type") || "application/json", 
                    "Access-Control-Allow-Origin": "*" 
                } 
            });
        } catch (err) {
            return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
        }
    }

    if (url.pathname === "/api/countries") {
        const now = Date.now();
        // L7: 命中内存缓存直接返回，避免每次请求都打 vpngate
        if (countryCache && (now - countryCache.at) < COUNTRY_CACHE_TTL) {
            return new Response(countryCache.data, { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=300" } });
        }
        try {
            const response = await fetch("https://www.vpngate.net/api/iphone/", { cf: { cacheTtl: 300 } });
            const text = await response.text();
            const lines = text.split('\n');
            const all = new Set(PREDEFINED_COUNTRIES);
            // L7: 容错解析——跳过注释行，列数不足自动跳过，避免硬编码列下标越界
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                if (!line || line.startsWith("*")) continue;
                const parts = line.split(',');
                const country = parts.length > 6 ? parts[6] : "";
                if (country && country.length === 2 && country !== "xx" && country !== "--") {
                    all.add(country.toUpperCase());
                }
            }
            const data = JSON.stringify(Array.from(all).sort());
            countryCache = { data, at: now };
            return new Response(data, { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=300" } });
        } catch(err) {
            return new Response(JSON.stringify(COUNTRY_FALLBACK), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
        }
    }

    if (url.pathname === "/" || url.pathname === "/api/config" || url.pathname === "/api/nodes" || url.pathname === "/api/proxies" || url.pathname === "/api/report" || url.pathname === "/api/rotate-scrt") {
      const _gate = authGate();
      if (_gate) return _gate;
    }

    if (url.pathname === "/api/config" && request.method === "GET") {
        const { results } = await env.DB.prepare(`SELECT value FROM global_config WHERE key = 'slot_map'`).all();
        if (results && results.length > 0) return new Response(results[0].value, { headers: { "Content-Type": "application/json" } });
        return new Response(JSON.stringify({ "0": "JP", "port": 7920 }), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/api/config" && request.method === "POST") {
        const data = await request.json();
        // M7: 严格校验端口范围（防绕过传负数/超范围导致节点失联）与国家代码合法性
        const port = isValidPort(data.port) ? Number(data.port) : 7920;
        const country = sanitizeCountry(data["0"]) || "JP";
        const sanitizedMap = { "0": country, "port": port };
        const trig = Number(data.switch_trigger);
        if (Number.isFinite(trig) && trig > 0 && trig <= Number.MAX_SAFE_INTEGER) sanitizedMap.switch_trigger = trig;
        await env.DB.prepare(`INSERT INTO global_config (key, value) VALUES ('slot_map', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).bind(JSON.stringify(sanitizedMap)).run();
        return new Response("OK");
    }

    if (url.pathname === "/api/report" && request.method === "POST") {
      try {
        const data = await request.json();
        // H2: 强制校验上报 IP 合法性，拒绝非法值写入 servers 表（防代理导出 URL 劫持）
        if (!isValidIp(data.ip)) {
          return new Response("Invalid report: bad ip", { status: 400 });
        }
        // #20 过期节点清理移到写路径，避免 GET /api/proxies、/api/nodes 每次轮询触发写入（原每天 1.7 万次写）
        const cutoff = Date.now() - 120000;
        await env.DB.prepare(`DELETE FROM servers WHERE last_seen < ?1`).bind(cutoff).run();
        await env.DB.prepare(`INSERT INTO servers (ip, details, last_seen) VALUES (?1, ?2, ?3) ON CONFLICT(ip) DO UPDATE SET details = excluded.details, last_seen = excluded.last_seen`).bind(data.ip, JSON.stringify(data.details || []), Date.now()).run();
        if (data.logs) {
          await env.DB.prepare(`INSERT INTO server_logs (ip, logs, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(ip) DO UPDATE SET logs = excluded.logs, updated_at = excluded.updated_at`).bind(data.ip, data.logs, Date.now()).run();
        }
        return new Response("OK", { status: 200 });
      } catch (err) { return new Response("Error", { status: 500 }); }
    }

    if (url.pathname === "/api/proxies") {
      const { results } = await env.DB.prepare(`SELECT ip, details FROM servers`).all();
      let proxyList = [];
      if (results) {
        for (let server of results) {
          // H2: 防御性校验 ip + 安全解析 details（顺带修复 details 字段损坏导致整接口 500 的问题）
          if (!isValidIp(server.ip)) continue;
          let details;
          try { details = JSON.parse(server.details || '[]'); } catch (e) { continue; }
          const activeNode = details.find(d => d.active) || details[0];
          if (!activeNode) continue;
          const port = Number(activeNode.port);
          if (!Number.isInteger(port) || port < 1 || port > 65535) continue; // H2: 端口范围校验
          // H5: 对凭证与 fragment 做 URL 编码，防止 PROXY_PASS 含 @:/# 等字符破坏 URL 解析，并阻断 fragment 注入
          proxyList.push(`socks5://${encodeURIComponent(PROXY_USER)}:${encodeURIComponent(PROXY_PASS)}@${server.ip}:${port}#${encodeURIComponent(activeNode.country + "_ActiveNode_" + (activeNode.node_ip || 'IP'))}`);
        }
      }
      return new Response(proxyList.join('\n'), { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname === "/api/nodes") {
      try {
        const { results } = await env.DB.prepare(`
          SELECT s.*, l.logs
          FROM servers s
          LEFT JOIN server_logs l ON s.ip = l.ip
          ORDER BY s.last_seen DESC
        `).all();
        return new Response(JSON.stringify(results || []), {
          headers: { "Content-Type": "application/json" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: String(err) }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }
    }

    if (url.pathname === "/api/rotate-scrt" && request.method === "POST") {
      const fresh = regenerateScriptToken();
      await env.DB.prepare(`INSERT INTO global_config (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).bind(SCRIPT_TOKEN_KEY, JSON.stringify(fresh)).run();
      return new Response(JSON.stringify({ ok: true, token: fresh.token }), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/") {
      // L4: 注入 CSP 头作为存储型 XSS 的纵深防御（仍保留前端 esc() 转义为第一道防线）
      //   注意：SCRT 由 esc() 转义后注入脚本块，必须在 default-src 中放行 'unsafe-inline' 才能执行。
      const csp = "default-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; base-uri 'self'; object-src 'none'";
      const scrt = await getOrCreateScrt(env);
      return new Response(await DASHBOARD_HTML(domain, WEB_USER, WEB_PASS, PROXY_USER, PROXY_PASS, scrt), {
        headers: { "Content-Type": "text/html;charset=UTF-8", "Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" }
      });
    }

    return new Response("Not Found", { status: 404 });
  }
};

const DASHBOARD_HTML = async (domain, webUser, webPass, proxyUser, proxyPass, scrt) => {
  // H4: 服务器端 HTML 转义，防止管理员配置的特殊字符用户名注入 HTML（XSS 纵深防御）
  const _esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
  webUser = _esc(webUser);
  proxyUser = _esc(proxyUser);
  return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Controller - 双活引擎总控</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: rgba(15, 23, 42, 0.5); }
        ::-webkit-scrollbar-thumb { background: rgba(51, 65, 85, 0.8); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(71, 85, 105, 1); }
        input[type=number]::-webkit-inner-spin-button, 
        input[type=number]::-webkit-outer-spin-button { -webkit-appearance: none; margin: 0; }
    </style>
</head>
<body class="min-h-screen bg-[#090E17] text-slate-300 relative overflow-x-hidden selection:bg-indigo-500/30">
    <div class="fixed top-[-20%] left-[-10%] w-[50%] h-[50%] bg-indigo-600/20 blur-[120px] rounded-full pointer-events-none z-0"></div>
    <div class="fixed bottom-[-20%] right-[-10%] w-[50%] h-[50%] bg-blue-600/10 blur-[120px] rounded-full pointer-events-none z-0"></div>

    <div class="max-w-7xl mx-auto p-6 relative z-10">
        <div class="flex flex-col md:flex-row justify-between items-start md:items-end mb-10 gap-6">
            <div>
                <h1 class="text-4xl font-extrabold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 via-indigo-400 to-purple-400 tracking-tight drop-shadow-sm">Proxy Controller</h1>
                <p class="text-slate-400 mt-2 text-sm flex items-center gap-2">
                    <svg class="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
                    直链提取 API: <a href="/api/proxies" target="_blank" class="text-indigo-400 hover:text-indigo-300 border-b border-indigo-400/30 hover:border-indigo-300 transition-colors">${domain}/api/proxies</a>
                </p>
            </div>
            
            <div class="flex flex-col gap-3 w-full md:flex-1">
                <div class="bg-slate-900/80 backdrop-blur-md border border-slate-700/50 rounded-xl overflow-hidden shadow-lg">
                    <div class="bg-slate-800/50 px-4 py-2 border-b border-slate-700/50 flex items-center gap-2">
                        <div class="flex gap-1.5">
                            <div class="w-3 h-3 rounded-full bg-rose-500/80"></div>
                            <div class="w-3 h-3 rounded-full bg-amber-500/80"></div>
                            <div class="w-3 h-3 rounded-full bg-emerald-500/80"></div>
                        </div>
                        <span class="text-xs text-slate-400 font-mono ml-2">VPS 纳管命令 (Root，含令牌)</span>
                        <button onclick="if(confirm('确定轮换 SCRT 令牌？旧令牌将立即失效。')){fetch('/api/rotate-scrt',{method:'POST'}).then(r=>{if(r.ok){alert('令牌已轮换，页面将刷新');location.reload()}else{alert('轮换失败')}}).catch(()=>alert('轮换失败'))}" class="ml-auto text-xs text-amber-400 hover:text-amber-300 border border-amber-500/30 hover:border-amber-400/50 rounded px-2 py-0.5 transition-colors">轮换令牌</button>
                    </div>
                    <div class="p-3 bg-[#0D1117] text-sm font-mono text-emerald-400 select-all overflow-x-auto whitespace-nowrap">
                        export SCRT="${scrt}" && bash <(curl -fsSL ${domain}/agent)
                    </div>
                </div>

                <div class="flex gap-4 text-xs font-mono">
                    <div class="bg-slate-900/50 border border-slate-800 rounded-lg px-3 py-2 flex-1 flex justify-between items-center shadow-sm">
                        <span class="text-slate-500">面板凭证</span>
                        <span class="text-indigo-300 font-bold ml-4">${webUser} <span class="text-slate-600">/</span> •••••• <span class="text-slate-600 text-[10px]">(见 CF 环境变量)</span></span>
                    </div>
                    <div class="bg-slate-900/50 border border-slate-800 rounded-lg px-3 py-2 flex-1 flex justify-between items-center shadow-sm">
                        <span class="text-slate-500">代理凭证</span>
                        <span class="text-amber-300 font-bold ml-4">${proxyUser} <span class="text-slate-600">/</span> •••••• <span class="text-slate-600 text-[10px]">(见 CF 环境变量)</span></span>
                    </div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-8">
            <div class="lg:col-span-1 bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl p-6 shadow-xl shadow-black/20">
                <div class="flex items-center gap-2 mb-4">
                    <svg class="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <h2 class="text-lg font-bold text-slate-200">全量国家代码库</h2>
                </div>
                <p class="text-xs text-slate-500 mb-4 leading-relaxed">系统已合并预设代码及实时的网络探测代码，提供最全面的目标锁定选择。</p>
                <div id="countries-list" class="flex flex-wrap gap-2 max-h-[160px] overflow-y-auto pr-1">
                    <span class="text-slate-600 text-sm animate-pulse">正在同步数据库...</span>
                </div>
            </div>

            <div class="lg:col-span-3 bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl p-6 shadow-xl shadow-black/20 flex flex-col justify-center relative overflow-hidden">
                <div class="absolute top-0 right-0 p-6 opacity-5 pointer-events-none">
                    <svg class="w-32 h-32" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
                </div>
                
                <div class="mb-6 relative z-10">
                    <h2 class="text-2xl font-bold text-slate-100 tracking-wide mb-1 flex items-center gap-2">主备双活调度引擎 <span class="bg-indigo-500/20 text-indigo-400 text-[10px] uppercase font-bold px-2 py-0.5 rounded-full border border-indigo-500/30">Active-Standby</span></h2>
                    <p class="text-sm text-slate-400">单路端口锁定，内置主备双路隧道 (tun_main / tun_backup)，通道死活将由软开关瞬间接管。</p>
                </div>
                
                <div class="flex flex-wrap items-center bg-slate-950/50 border border-slate-800/80 rounded-xl p-5 relative z-10 gap-y-4">
                    <div class="flex items-center gap-3 mr-3 border-r border-slate-700/50 pr-4">
                        <span class="text-slate-400 text-sm font-medium whitespace-nowrap">目标地区:</span>
                        <input type="text" id="slot-cfg-0" value="JP" maxlength="2" class="bg-slate-900 border border-slate-700 rounded-lg py-2 w-16 text-white font-bold text-lg uppercase text-center focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 outline-none transition-all shadow-inner" placeholder="US" />
                    </div>
                    
                    <div class="flex items-center gap-3 mr-4">
                        <span class="text-slate-400 text-sm font-medium whitespace-nowrap">服务端口:</span>
                        <input type="number" id="slot-port" value="7920" min="1024" max="65535" class="bg-slate-900 border border-slate-700 rounded-lg py-2 w-24 text-white font-bold text-lg text-center focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 outline-none transition-all shadow-inner" placeholder="7920" />
                    </div>
                    
                    <button onclick="saveConfig()" class="group relative px-6 py-2.5 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 text-white text-sm font-bold shadow-lg shadow-blue-900/20 hover:shadow-indigo-900/40 hover:-translate-y-0.5 transition-all duration-200 overflow-hidden ml-auto">
                        <div class="absolute inset-0 bg-white/20 group-hover:translate-x-full -translate-x-full transform transition-transform duration-300 ease-in-out skew-x-12"></div>
                        <span class="flex items-center gap-2">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"></path></svg>
                            下发策略
                        </span>
                    </button>
                    
                    <div class="h-8 w-px bg-slate-800 mx-2 hidden sm:block"></div>

                    <button onclick="switchIP()" class="group relative px-6 py-2.5 rounded-lg bg-gradient-to-r from-purple-600 to-pink-600 text-white text-sm font-bold shadow-lg shadow-purple-900/20 hover:shadow-pink-900/40 hover:-translate-y-0.5 transition-all duration-200 overflow-hidden">
                         <div class="absolute inset-0 bg-white/20 group-hover:translate-x-full -translate-x-full transform transition-transform duration-300 ease-in-out skew-x-12"></div>
                         <span class="flex items-center gap-2">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                            强制更换 IP
                         </span>
                    </button>
                </div>
            </div>
        </div>
        
        <div class="bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-xl overflow-hidden shadow-black/20 mb-8">
            <div class="px-6 py-4 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
                <h3 class="font-semibold text-slate-200 flex items-center gap-2">
                    <div class="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)] animate-pulse"></div>
                    活跃节点矩阵
                </h3>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="bg-slate-900/80 text-slate-400 text-xs uppercase tracking-wider">
                            <th class="py-4 px-6 font-medium w-1/5">母机宿主 IP</th>
                            <th class="py-4 px-6 font-medium">主备双路出口状态 (Active / Standby)</th>
                            <th class="py-4 px-6 font-medium w-32">心跳延迟</th>
                            <th class="py-4 px-6 font-medium text-right w-24">负载率</th>
                        </tr>
                    </thead>
                    <tbody id="nodes-table" class="divide-y divide-slate-800/50 text-sm">
                        <tr><td colspan="4" class="py-12 text-center text-slate-500">正在与 D1 数据库建立量子纠缠...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div id="ip-score-section" style="display: none;" class="bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-xl overflow-hidden shadow-black/20 mb-8">
            <div class="px-6 py-4 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
                <h3 class="font-semibold text-slate-200 flex items-center gap-2">
                    <svg class="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                    原生深度质检报告 (testisp.info)
                </h3>
                <a id="ip-score-link" href="#" class="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 transition-colors">
                    原版页面 <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
                </a>
            </div>
            
            <div id="native-score-container" class="p-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 bg-[#090E17]">
                <div class="col-span-full py-16 flex flex-col items-center justify-center text-slate-500">
                    <svg class="animate-spin h-8 w-8 text-indigo-500 mb-4" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                    <span>穿透请求中，正在构建原生质检报告...</span>
                </div>
            </div>
        </div>

        <div class="bg-slate-900/40 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-xl overflow-hidden shadow-black/20 pb-8">
            <div class="px-4 py-3 border-b border-slate-800 bg-slate-900/80 flex justify-between items-center">
                <span class="text-xs text-slate-400 font-mono flex items-center gap-2">
                    <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M4 17h16a2 2 0 002-2V5a2 2 0 00-2-2H4a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
                    VPS 实时运行日志 (Auto-Sync)
                </span>
                <span class="flex gap-1.5">
                    <div class="w-3 h-3 rounded-full bg-rose-500/80 shadow-[0_0_5px_rgba(244,63,94,0.5)]"></div>
                    <div class="w-3 h-3 rounded-full bg-amber-500/80 shadow-[0_0_5px_rgba(245,158,11,0.5)]"></div>
                    <div class="w-3 h-3 rounded-full bg-emerald-500/80 shadow-[0_0_5px_rgba(16,185,129,0.5)]"></div>
                </span>
            </div>
            <div class="p-4 h-64 overflow-y-auto bg-[#0D1117] font-mono text-[13px] leading-relaxed text-slate-300" id="terminal-output">
                <div class="text-slate-500 animate-pulse">等待 VPS 心跳回传日志数据...</div>
            </div>
        </div>
    </div>

    <script>
        // #9 HTML 转义：所有来自 D1/外部 API 的数据渲染前必须经过 esc()，防止存储型 XSS
        const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
        let currentScoreIp = "";

        async function fetchCountries() {
            try {
                const res = await fetch('/api/countries');
                const list = await res.json();
                const container = document.getElementById('countries-list');
                container.innerHTML = list.map(c => \`<span class="bg-slate-800/80 hover:bg-indigo-500/20 text-slate-300 hover:text-indigo-300 transition-colors border border-slate-700/50 px-2.5 py-1 rounded-md text-xs font-mono font-bold shadow-sm cursor-default">\${esc(c)}</span>\`).join('');
            } catch(e) {}
        }

        async function loadConfig() {
            try {
                const res = await fetch('/api/config');
                const map = await res.json();
                document.getElementById('slot-cfg-0').value = map["0"] || 'JP';
                document.getElementById('slot-port').value = map["port"] || 7920;
            } catch(e) {}
        }

        async function saveConfig() {
            const val = document.getElementById(\`slot-cfg-0\`).value.toUpperCase().trim() || 'JP';
            const port = parseInt(document.getElementById(\`slot-port\`).value) || 7920;
            await fetch('/api/config', {
                method: 'POST',
                body: JSON.stringify({ "0": val, "port": port })
            });
            alert('🚀 策略及端口已云端同步！Agent 将在下一心跳周期应用。');
        }

        async function switchIP() {
            const val = document.getElementById(\`slot-cfg-0\`).value.toUpperCase().trim() || 'JP';
            const port = parseInt(document.getElementById(\`slot-port\`).value) || 7920;
            await fetch('/api/config', {
                method: 'POST',
                body: JSON.stringify({ "0": val, "port": port, "switch_trigger": Date.now() })
            });
            alert('🔄 重拨指令已下发！VPS 将清退当前通道池重新并发建连...');
        }

        async function loadNativeIpScore(ip) {
            const container = document.getElementById('native-score-container');
            container.innerHTML = '<div class="col-span-full py-16 flex flex-col items-center justify-center text-slate-500"><svg class="animate-spin h-8 w-8 text-indigo-500 mb-4" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg><span>穿透请求中，正在构建原生质检报告...</span></div>';
            
            try {
                const res = await fetch('/api/testisp-lookup/' + encodeURIComponent(ip));
                const rawText = await res.text();
                
                let d;
                try {
                    d = JSON.parse(rawText);
                } catch (e) {
                    const safeText = rawText.substring(0, 500).replace(/</g, '&lt;').replace(/>/g, '&gt;');
                    throw new Error(\`目标接口返回了非 JSON 格式数据(可能 API 路径错误或被云端盾拦截)。<br>HTTP 状态码: \${res.status}<br><div class="mt-3 text-left bg-slate-900 p-3 rounded text-xs text-rose-300 font-mono break-all overflow-y-auto max-h-32 border border-rose-500/30">\${safeText}</div>\`);
                }
                
                if (!d || !d.geo || !d.isp) {
                    container.innerHTML = \`<div class="col-span-full text-center py-8 text-rose-400 bg-rose-500/10 rounded-xl border border-rose-500/20">无法获取报告: 接口返回数据结构异常 \${esc(d.error || '')}</div>\`;
                    return;
                }

                const isHosting = d.isp.flag === 'hosting';
                const threat = d.risk.threat_listed;
                const isNative = d.geo.is_native;
                
                const tags = isHosting 
                    ? '<span class="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/20 text-xs font-bold">机房IP</span>' 
                    : '<span class="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 text-xs font-bold">家庭宽带</span>';
                
                const locStr = [d.geo.country, d.geo.city].filter(Boolean).join(" ");
                const orgStr = d.isp.org || '-';

                container.innerHTML = \`
                    <div class="col-span-full bg-slate-800/60 border border-slate-700/80 p-5 rounded-2xl flex flex-wrap gap-4 justify-between items-center mb-2 shadow-lg">
                        <div class="flex items-center gap-4">
                            <span class="text-3xl font-extrabold font-mono text-white tracking-tight drop-shadow-sm">\${esc(ip)}</span>
                            <span class="text-slate-400 text-sm hidden sm:flex items-center border-l border-slate-700 pl-4 h-6">
                                <span class="uppercase tracking-widest text-indigo-400 mr-2 text-xs font-bold">\${esc(d.geo.country_code || 'N/A')}</span>
                                \${esc(locStr)} · \${esc(orgStr)}
                            </span>
                        </div>
                    </div>

                    <div class="bg-slate-800/40 border border-slate-700/60 p-6 rounded-2xl flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow hover:bg-slate-800/60">
                        <h4 class="text-xs font-bold text-slate-500 uppercase tracking-widest pb-3 border-b border-slate-700/50">基础物理画像</h4>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">IP 原生性</span> <span class="font-medium text-sm">\${isNative ? '<span class="px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-bold">原生 IP (Native)</span>' : \`<span class="px-2.5 py-1 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30 text-xs font-bold">\${esc(d.geo.native_type || '广播 IP')}</span>\`}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">业务标记</span> <div class="flex gap-1">\${tags}</div></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">运营类型</span> <span class="font-medium \${isHosting ? 'text-rose-400' : 'text-emerald-400'} text-sm">\${d.isp.type || '-'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">归属机构</span> <span class="font-medium text-slate-300 text-sm truncate max-w-[150px]" title="\${esc(orgStr)}">\${esc(orgStr)}</span></div>
                    </div>

                    <div class="bg-slate-800/40 border border-slate-700/60 p-6 rounded-2xl flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow hover:bg-slate-800/60">
                        <h4 class="text-xs font-bold text-slate-500 uppercase tracking-widest pb-3 border-b border-slate-700/50">ISP 网络底层</h4>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">ASN</span> <span class="font-medium text-indigo-300 text-sm font-mono">\${esc(d.isp.asn || '-')}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">解析时区</span> <span class="font-medium text-slate-300 text-sm font-mono">\${esc(d.geo.timezone || '-')}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">偏移量 (Drift)</span> <span class="font-medium \${d.geo.has_drift ? 'text-rose-400' : 'text-emerald-400'} text-sm">\${esc(d.geo.drift_km || 0)} km</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">反向 DNS (rDNS)</span> <span class="font-medium text-slate-400 text-xs font-mono truncate max-w-[150px]" title="\${esc(d.isp.rdns || '-')}">\${esc(d.isp.rdns || '-')}</span></div>
                    </div>

                    <div class="bg-slate-800/40 border border-slate-700/60 p-6 rounded-2xl flex flex-col gap-4 shadow-sm hover:shadow-md transition-shadow hover:bg-slate-800/60">
                        <h4 class="text-xs font-bold text-slate-500 uppercase tracking-widest pb-3 border-b border-slate-700/50">风险深度检测</h4>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">Spamhaus 情报</span> <span class="\${threat ? 'px-2.5 py-1 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30 text-xs font-bold' : 'px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-bold'}">\${threat ? '🚨 已在黑名单' : '✅ 纯净无异常'}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">代理/机房特征</span> <span class="font-medium text-xs font-bold \${d.isp.warning ? 'text-amber-400' : 'text-emerald-400'} truncate max-w-[150px]" title="\${esc(d.isp.warning || '')}">\${esc(d.isp.warning || '未检测到明显异常')}</span></div>
                        <div class="flex justify-between items-center"><span class="text-slate-400 text-sm">数据源</span> <span class="font-medium text-slate-400 text-xs">\${esc(d.data_source || 'Unknown')}</span></div>
                    </div>
                \`;
            } catch (e) {
                container.innerHTML = \`<div class="col-span-full text-left p-6 text-rose-400 bg-rose-500/10 rounded-xl border border-rose-500/20">\${e.message}</div>\`;
            }
        }

        async function fetchNodes() {
            try {
                const res = await fetch('/api/nodes');
                const servers = await res.json();
                const tbody = document.getElementById('nodes-table');
                const terminal = document.getElementById('terminal-output');
                
                if (!servers || servers.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="py-12 text-center text-slate-500 flex-col items-center justify-center"><svg class="w-12 h-12 mx-auto text-slate-700 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>未检测到在线母机，请在 VPS 运行纳管命令接入</td></tr>';
                    return;
                }

                tbody.innerHTML = servers.map(server => {
                    const details = JSON.parse(server.details || '[]');
                    const timeAgo = Math.floor((Date.now() - server.last_seen) / 1000);
                    
                    let proxyBadges = '';
                    if (details.length === 0) {
                        proxyBadges = \`
                        <div class="inline-flex items-center bg-slate-900 border border-amber-500/30 rounded-xl px-3 py-1.5 shadow-inner text-amber-400/90 text-sm">
                            <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-amber-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                            双路通道震荡熔断，正在全异步抢救拨号中...
                        </div>\`;
                    } else {
                        proxyBadges = '<div class="flex flex-col gap-2">' + details.map(d => {
                            const isActive = d.active;
                            const statusColorClass = isActive ? 'bg-emerald-500' : 'bg-sky-500';
                            const statusText = isActive ? 'ACTIVE (业务出口)' : 'STANDBY (热备就绪)';
                            const borderColorClass = isActive ? 'border-emerald-500/30' : 'border-sky-500/30';
                            const bgColorClass = isActive ? 'bg-emerald-500/10' : 'bg-sky-500/10';
                            const textColorClass = isActive ? 'text-emerald-400' : 'text-sky-400';
                            
                            return \`
                            <div class="inline-flex items-center bg-slate-950 border border-slate-800/80 rounded-xl px-2.5 py-1.5 shadow-inner">
                                <span class="bg-slate-800 text-slate-300 font-mono text-xs px-2 py-0.5 rounded-md mr-3 border border-slate-700 font-bold">\${esc(d.tunnel)}</span>
                                <span class="bg-indigo-500/20 text-indigo-400 font-bold font-mono text-xs px-2 py-0.5 rounded-md mr-3 border border-indigo-500/20">\${esc(d.country)}</span>
                                <span class="font-mono text-slate-300 text-sm tracking-wide mr-3" title="出口物理 IP">\${esc(d.node_ip || '---.---.---.---')}:\${esc(d.port)}</span>
                                <span class="flex items-center gap-1.5 \${textColorClass} \${bgColorClass} px-2 py-0.5 rounded-md border \${borderColorClass} text-xs font-medium">
                                    <span class="w-1.5 h-1.5 rounded-full \${statusColorClass} shadow-[0_0_5px_currentColor]"></span> \${statusText}
                                </span>
                            </div>\`;
                        }).join('') + '</div>';
                    }

                    return \`
                        <tr class="hover:bg-slate-800/30 transition-colors group">
                            <td class="py-5 px-6 font-mono text-indigo-300 align-middle">
                                <div class="flex items-center gap-2">
                                    <svg class="w-4 h-4 text-slate-600 group-hover:text-indigo-400 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path></svg>
                                    \${esc(server.ip)}
                                </div>
                            </td>
                            <td class="py-5 px-6 align-middle">\${proxyBadges}</td>
                            <td class="py-5 px-6 align-middle">
                                <span class="flex items-center gap-1.5 \${timeAgo < 20 ? 'text-emerald-400' : 'text-rose-400'} font-mono text-xs">
                                    <span class="w-1.5 h-1.5 rounded-full \${timeAgo < 20 ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}"></span>
                                    \${timeAgo}s 前
                                </span>
                            </td>
                            <td class="py-5 px-6 align-middle text-right">
                                <span class="\${details.length === 2 ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : (details.length === 1 ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30' : 'bg-rose-500/20 text-rose-400 border border-rose-500/30')} py-1 px-3 rounded-md text-xs font-mono font-bold">
                                    \${details.length} / 2
                                </span>
                            </td>
                        </tr>
                    \`;
                }).join('');

                if (servers.length > 0 && servers[0].details) {
                    const details = JSON.parse(servers[0].details);
                    // 深度质检报告：永远提取正在承载业务的 ACTIVE 网卡 IP 进行评分
                    const activeNode = details.find(d => d.active) || details[0];
                    if (activeNode && activeNode.node_ip) {
                        const newIp = activeNode.node_ip;
                        if (newIp !== currentScoreIp) {
                            currentScoreIp = newIp;
                            document.getElementById('ip-score-section').style.display = 'block';
                            
                            // 针对 testisp.info 前端默认仅查本机的防呆机制：自动复制 IP 到剪贴板，跳转后由用户粘贴
                            const scoreLink = document.getElementById('ip-score-link');
                            scoreLink.href = \`https://testisp.info/?ip=\${newIp}\`;
                            scoreLink.onclick = (e) => {
                                e.preventDefault();
                                navigator.clipboard.writeText(newIp).then(() => {
                                    alert('🟢 已自动复制隧道节点 IP: ' + newIp + '\\n\\n由于 testisp.info 官网默认仅检测本机，请在随后打开的网页【输入框】中【粘贴】并回车查询！');
                                    window.open(\`https://testisp.info/?ip=\${newIp}\`, '_blank');
                                }).catch(() => {
                                    window.open(\`https://testisp.info/?ip=\${newIp}\`, '_blank');
                                });
                            };

                            loadNativeIpScore(newIp);
                        }
                    }
                }
                
                if (servers[0] && servers[0].logs) {
                    const isAtBottom = terminal.scrollHeight - terminal.scrollTop <= terminal.clientHeight + 30;
                    
                    let logHTML = servers[0].logs
                        .replace(/</g, '&lt;').replace(/>/g, '&gt;')
                        .replace(/\\[\\*\\]/g, '<span class="text-indigo-400 font-bold">[*]</span>')
                        .replace(/\\[\\+\\]/g, '<span class="text-emerald-400 font-bold">[+]</span>')
                        .replace(/\\[\\-\\]/g, '<span class="text-rose-400 font-bold">[-]</span>')
                        .replace(/\\[\\!\\]/g, '<span class="text-amber-400 font-bold">[!]</span>');
                        
                    terminal.innerHTML = '<pre class="whitespace-pre-wrap break-all">' + logHTML + '</pre>';
                    
                    if (isAtBottom) {
                        terminal.scrollTop = terminal.scrollHeight;
                    }
                }
                
            } catch (err) {}
        }
        
        fetchCountries();
        loadConfig();
        // M2: 后台标签页暂停轮询，节省 D1 读配额与浏览器开销
        let pollTimer = null;
        const startPolling = () => { if (!pollTimer) { fetchNodes(); pollTimer = setInterval(fetchNodes, 5000); } };
        const stopPolling = () => { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } };
        document.addEventListener('visibilitychange', () => { if (document.hidden) stopPolling(); else startPolling(); });
        startPolling();
    </script>
</body>
</html>
`;
};

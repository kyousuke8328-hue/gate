#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线
============================
流程:
  1. 获取 VPN Gate 原始节点 (官方 api/iphone CSV, 失败时回退 GitHub 预解析镜像)
  2. 只保留「带 TCP 入口」的中继 = SSTP 可用节点
     (OpenVPN 配置里 proto tcp + remote <ip> <port>; UDP-only 中继无法走 SSTP/xray 链, 直接丢弃)
  3. 按 host+port+protocol 去重 -> 按官方 Score/速度/Ping/在线时长筛选 -> 本地 TCP+TLS 预检 (不占 Worker)
  4. 并发调用已部署的 Cloudflare Worker:  GET {WORKER}/check?proxyip=host:port
     (单节点 HTTP 成功 != 节点可用; 以 Worker 返回 JSON 的 success 字段为准)
  5. 保留 success=true 的节点, 按国家分组, 生成 public/data.json + public/index.html
  6. 网页端 (GitHub Pages) 读取 data.json 展示

退出码:
  0 = 正常完成 (允许部分节点检测失败)
  1 = 硬性失败 (数据源全挂 / 解析不出 SSTP 节点 / Worker 完全不可达 / 程序异常)
     这些情况绝不允许"假成功"
"""

import base64
import csv
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

import requests

# 保证日志在任何控制台编码下都能输出 (Windows GBK 控制台不会崩)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置 (均可用环境变量覆盖, 便于本地测试)
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

# 官方接口: 先 HTTPS, 失败再回退 HTTP (逗号分隔, 可用环境变量覆盖)
VPNGATE_APIS = [u.strip() for u in os.environ.get(
    "VPNGATE_API", "https://www.vpngate.net/api/iphone/,http://www.vpngate.net/api/iphone/").split(",") if u.strip()]
# 官方接口失败时的回退数据源: 预解析 JSON 镜像 (字段与官方 CSV 同源)
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
# 已部署的 Cloudflare Worker 检测接口 (GET /check?proxyip=host:port, 实测确认)
# Worker 地址属于敏感信息: 不写死在仓库里, 必须由环境变量 / GitHub Secret 提供
WORKER_CHECK_URL = os.environ.get("CHECK_WORKER", "").strip()
CHECK_AUTH = os.environ.get("CHECK_AUTH", "").strip()                  # 可选: Worker 支持时以 Bearer 令牌鉴权
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "8")))   # 低并发 = 更平滑的 Worker 负载
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "45"))          # 单请求客户端超时 (秒)
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))         # 0=不限; 本地测试可设小值
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))              # 拉取数据源超时
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

# --- 节点筛选: 只检测 / 只保留更快更稳的 (均可用环境变量覆盖) ---
MIN_SPEED_MBPS = float(os.environ.get("MIN_SPEED_MBPS", "10"))        # VPN Gate 官方测速下限
MAX_PING_MS = float(os.environ.get("MAX_PING_MS", "200"))             # VPN Gate 官方 Ping 上限
MIN_UPTIME_HOURS = float(os.environ.get("MIN_UPTIME_HOURS", "12"))    # 在线时长下限 (24h 一次检测, 要选稳的)
MAX_CANDIDATES = int(os.environ.get("MAX_CANDIDATES", "150"))         # 最多送 Worker 检测的节点数
PER_COUNTRY_CANDIDATES = int(os.environ.get("PER_COUNTRY_CANDIDATES", "15"))
KEEP_PER_COUNTRY = int(os.environ.get("KEEP_PER_COUNTRY", "8"))       # 每国最多保留 (够数即提前停止检测)
MAX_LATENCY_MS = float(os.environ.get("MAX_LATENCY_MS", "3000"))      # Worker 实测延迟上限
PRECHECK = os.environ.get("PRECHECK", "1") != "0"                     # 本地 TCP+TLS 预检, 先剔除死节点
PRECHECK_TIMEOUT = float(os.environ.get("PRECHECK_TIMEOUT", "6"))
PRECHECK_WORKERS = int(os.environ.get("PRECHECK_WORKERS", "64"))
CLASH_MAX_NODES = int(os.environ.get("CLASH_MAX_NODES", "40"))
# 含 UUID 的订阅文件放进「令牌目录」发布 (公开仓库的 Pages 是公开的, 不能让人直接猜到 sub.txt)
SUB_TOKEN = os.environ.get("SUB_TOKEN", "").strip()

# 出口数据中心的关键词启发 (判断"是否住宅 IP"用, 页面标注为估算)
DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
# 常见住宅宽带运营商关键词
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

# ISO 国家码 -> 中文名 (edgetunnel 清单展示用; 未收录则回退英文原名)
COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

# ---------------------------------------------------------------------------
# 日志 (用户要求的分区格式)
# ---------------------------------------------------------------------------
_section = None


def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)


def die(msg):
    """硬性失败: 明确报错并退出非 0, 绝不允许假成功。"""
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# 第 1 步: 获取 VPN Gate 原始节点
# ---------------------------------------------------------------------------
def fetch_vpngate():
    """返回 (rows, source)。rows: [{host, ip, country_long, country_short, config_b64}]
    官方 API 失败时回退镜像 JSON; 两个都失败 -> 直接 die (exit 1)。"""
    # --- 主源: 官方 CSV (先 HTTPS, 失败再 HTTP) ---
    for api in VPNGATE_APIS:
        try:
            log("VPN GATE", f"获取官方 API: {api}")
            resp = requests.get(
                api,
                timeout=HTTP_TIMEOUT,
                headers={"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"},
            )
            resp.raise_for_status()
            rows = parse_csv(resp.text)
            if rows:
                log("VPN GATE", f"主源(官方 API) 获取到 {len(rows)} 个原始节点")
                return rows, "vpngate.net/api/iphone"
            raise RuntimeError("官方 API 返回 0 行数据")
        except Exception as exc:
            log("VPN GATE", f"官方 API 获取失败: {exc}")

    # --- 回退源: GitHub 预解析镜像 ---
    try:
        log("VPN GATE", f"回退镜像: {VPNGATE_MIRROR}")
        resp = requests.get(VPNGATE_MIRROR, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        rows = parse_mirror_json(resp.json())
        if rows:
            log("VPN GATE", f"回退源(镜像) 获取到 {len(rows)} 个原始节点")
            return rows, "github-mirror"
    except Exception as exc:
        log("VPN GATE", f"回退镜像也失败: {exc}")
    die("VPN Gate 官方 API 与回退镜像均不可用, 数据源完全失败 (不生成空结果, 本次运行判定失败)")


def _num(v):
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None


def parse_csv(text):
    """解析官方 CSV。表头行含 'HostName'; 按列名映射, 列名缺失时用固定位置回退。"""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")

    header = lines[header_idx].lstrip("#").split(",")
    data_lines = lines[header_idx + 1:]
    # 列名映射 (不假设固定位置, 列名变化时自动适配; 全缺失时回退到已知位置)
    idx = {}
    for col in ("hostname", "ip", "countrylong", "countryshort", "openvpn_configdata_base64",
                "score", "ping", "speed", "uptime"):
        for i, h in enumerate(header):
            if h.strip().lstrip("*").lower() == col:
                idx[col] = i
                break
    if "openvpn_configdata_base64" not in idx:
        for i, h in enumerate(header):
            if "base64" in h.lower():
                idx["openvpn_configdata_base64"] = i
                break
    pos = {"hostname": idx.get("hostname", 0),
           "ip": idx.get("ip", 1),
           "countrylong": idx.get("countrylong", 5),
           "countryshort": idx.get("countryshort", 6),
           "openvpn_configdata_base64": idx.get("openvpn_configdata_base64", len(header) - 1),
           "score": idx.get("score", 2), "ping": idx.get("ping", 3),
           "speed": idx.get("speed", 4), "uptime": idx.get("uptime", 8)}

    rows = []
    for ln in data_lines:
        fields = next(csv.reader(io.StringIO(ln)))
        if len(fields) < 7:
            continue
        host = fields[pos["hostname"]].strip()
        ip = fields[pos["ip"]].strip()
        if not host or not ip:
            continue
        def g(k):
            return fields[pos[k]] if pos[k] < len(fields) else None
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": fields[pos["countrylong"]].strip(),
            "country_short": fields[pos["countryshort"]].strip(),
            "config_b64": fields[pos["openvpn_configdata_base64"]].strip(),
            "score": _num(g("score")),
            "ping": _num(g("ping")),
            "speed_bps": _num(g("speed")),
            "uptime_ms": _num(g("uptime")),
        })
    return rows


def parse_mirror_json(data):
    """解析 GitHub 镜像 JSON: [ { "servers": [ {hostname, ip, countrylong, countryshort, openvpn_configdata_base64} ] } ]"""
    servers = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("country") or "").strip(),
            "country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(),
            "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip(),
            "score": _num(s.get("score")),
            "ping": _num(s.get("ping")),
            "speed_bps": _num(s.get("speed")),
            "uptime_ms": _num(s.get("uptime")),
        })
    return rows


# ---------------------------------------------------------------------------
# 第 2 步: 筛选 SSTP 节点 (只保留带 TCP 入口的中继)
# ---------------------------------------------------------------------------
_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)


_HOST_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_host(raw):
    """只接受 *.opengw.net (VPN Gate 官方 DDNS) 且字符合法的主机名。
    防止第三方镜像 / 被篡改的数据把任意域名或换行注入到订阅文件里。"""
    h = (raw or "").strip().lower().rstrip(".")
    if not h:
        return None
    if "." not in h:
        h += ".opengw.net"
    if not h.endswith(".opengw.net") or len(h) > 253:
        return None
    if not all(_HOST_LABEL_RE.match(label) for label in h.split(".")):
        return None
    return h


def normalize_ip(raw):
    """只接受公网 IP (拒绝内网 / 回环 / 链路本地, 避免预检被诱导去探测内部地址)。"""
    try:
        a = ipaddress.ip_address((raw or "").strip())
    except ValueError:
        return None
    return str(a) if a.is_global else None


def clean_text(s, limit=40):
    return re.sub(r"[^\w .,'()\-]", "", s or "")[:limit].strip()


def clean_cc(s):
    s = (s or "").strip().upper()
    return s if re.fullmatch(r"[A-Z]{2}", s) else ""


def to_sstp_nodes(rows):
    """把原始行转成 SSTP 节点: 解码 OpenVPN 配置, 仅保留 proto tcp + remote 端口。
    host 统一为 <short>.opengw.net 形式; 返回去重前的节点列表。"""
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        if not _PROTO_TCP_RE.search(cfg):
            continue  # 无 TCP 入口 -> 不是 SSTP 可用节点, 丢弃
        m = _REMOTE_RE.search(cfg)
        if not m:
            continue
        port = int(m.group(1))
        if not (1 <= port <= 65535):
            continue
        host = normalize_host(r["host"])
        ip = normalize_ip(r["ip"])
        if not host or not ip:
            continue
        spd, upt = r.get("speed_bps"), r.get("uptime_ms")
        nodes.append({
            "host": host,
            "port": port,
            "ip": ip,
            "country": clean_text(r["country_long"]),
            "country_code": clean_cc(r["country_short"]),
            "score": r.get("score"),
            "ping": r.get("ping"),
            "speed_mbps": round(spd / 1e6, 1) if spd is not None else None,
            "uptime_h": round(upt / 3.6e6, 1) if upt is not None else None,
        })
    return nodes


def dedupe(nodes):
    """按 host+port+protocol 去重。"""
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "sstp")
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out


def select_candidates(nodes, limit):
    """按 VPN Gate 官方指标 (速度/Ping/在线时长) 筛出更快更稳的节点, 再按 Score 排序,
    每国限量。指标缺失 (如镜像数据) 的节点不当作不合格; 筛得太少时自动放宽, 不会出空结果。"""
    def ok(n):
        if n.get("speed_mbps") is not None and n["speed_mbps"] < MIN_SPEED_MBPS:
            return False
        if n.get("ping") is not None and n["ping"] > MAX_PING_MS:
            return False
        if n.get("uptime_h") is not None and n["uptime_h"] < MIN_UPTIME_HOURS:
            return False
        return True

    def rank(n):
        ping = n["ping"] if n.get("ping") is not None else 9999
        return (-(n.get("score") or 0), -(n.get("speed_mbps") or 0), ping)

    good = [n for n in nodes if ok(n)]
    if len(good) < 20:
        log("VPN GATE", f"达标节点仅 {len(good)} 个, 放宽阈值改按 Score 排序")
        good = list(nodes)
    good.sort(key=rank)
    picked, per = [], {}
    for n in good:
        c = n.get("country_code") or n.get("country") or "?"
        if per.get(c, 0) >= PER_COUNTRY_CANDIDATES:
            continue
        per[c] = per.get(c, 0) + 1
        picked.append(n)
        if len(picked) >= limit:
            break
    return picked


# 预检只做 TCP + TLS 握手 (活性探测), 不发送任何账号数据, 所以不校验自签证书
_TLS_CTX = ssl.create_default_context()
_TLS_CTX.check_hostname = False
_TLS_CTX.verify_mode = ssl.CERT_NONE


def precheck_one(node):
    try:
        with socket.create_connection((node["ip"], node["port"]), timeout=PRECHECK_TIMEOUT) as raw:
            raw.settimeout(PRECHECK_TIMEOUT)
            with _TLS_CTX.wrap_socket(raw, server_hostname=node["host"]):
                pass
        return node, True
    except Exception:
        return node, False


def precheck(nodes):
    """在 GitHub runner 上本地探测, 把明显已死的节点挡在 Worker 之外 (这一步不消耗 Cloudflare CPU)。"""
    if not PRECHECK or not nodes:
        return nodes
    alive = []
    with ThreadPoolExecutor(max_workers=PRECHECK_WORKERS) as pool:
        for node, ok in pool.map(precheck_one, nodes):
            if ok:
                alive.append(node)
    log("PRECHECK", f"本地 TCP+TLS 预检: {len(alive)}/{len(nodes)} 存活")
    if not alive:
        log("PRECHECK", "预检全部失败 (可能是运行环境网络受限), 跳过预检, 直接交给 Worker")
        return nodes
    return alive


# ---------------------------------------------------------------------------
# 第 3 步: 并发调用 Cloudflare Worker
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    """住宅/机房分类, 按可信度排序:
    1) Worker 返回的真实 is_datacenter 标志 (IP 情报库);
    2) 出口 ASN 组织名关键词;
    3) host 前缀启发式 (最后兜底, 属估算)。"""
    # 1) 真实数据中心标志 (SSTP 版 Worker 顶层 exit 直接给出)
    if is_datacenter is True:
        return "datacenter"
    if is_datacenter is False:
        return "residential"
    # 2) 出口组织名关键词
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS):
            return "residential"
    # 3) host 前缀启发式 (估算)
    h = host.lower()
    if h.startswith("public-vpn"):
        return "datacenter"      # VPN Gate 官方公共中继 (机房/托管)
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h):
        return "residential"     # 数字编号 = 注册的家用宽带中继 (家宽, 估算)
    return "unknown"


def check_one(node, session):
    """调用 Worker 检测单节点。返回节点+检测结果的合并 dict。
    单节点失败 (网络错误/非 200/坏 JSON) 不会抛出, 统一记 success=False。"""
    url = WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe="")
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    try:
        headers = {"User-Agent": "Mozilla/5.0 (gate-checker)"}
        if CHECK_AUTH:
            headers["Authorization"] = f"Bearer {CHECK_AUTH}"
        r = session.get(url, timeout=CHECK_TIMEOUT, headers=headers)
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            out["worker_error"] = True
            return out
        j = r.json()
        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = (None if ok else (j.get("error") or j.get("message") or "check failed"))
        # SSTP 版 Worker: 顶层直接返回 exit, 含真实 is_datacenter 标志 + 嵌套 asn 对象
        exit_info = j.get("exit") or {}
        if exit_info:
            asn = exit_info.get("asn") or {}
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {
                "ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "country_code": exit_info.get("country_code"),
                "city": exit_info.get("city"),
                "continent": exit_info.get("continent"),
                "asn": asn.get("asn"),
                "org": org,
                "type": asn.get("type"),
                "is_datacenter": exit_info.get("is_datacenter"),
            }
            out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        return out
    except Exception as exc:
        out["error"] = type(exc).__name__   # 不带异常正文: requests 的异常信息里会含 Worker URL
        out["worker_error"] = True
        return out


def check_all(nodes, session):
    """低并发检测。某国成功数已够 KEEP_PER_COUNTRY 就不再检测该国剩余节点 (节省 Worker CPU)。
    区分'节点不可用'与'Worker 异常'。"""
    done, lock = {}, threading.Lock()

    def work(n):
        c = n.get("country_code") or n.get("country") or "?"
        with lock:
            if done.get(c, 0) >= KEEP_PER_COUNTRY:
                return {"skipped": True}
        r = check_one(n, session)
        if r.get("success"):
            with lock:
                done[c] = done.get(c, 0) + 1
        return r

    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(work, n) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    skipped = sum(1 for r in results if r.get("skipped"))
    if skipped:
        log("CLOUDFLARE WORKER", f"已够数, 跳过检测: {skipped}")
    return [r for r in results if not r.get("skipped")]


# ---------------------------------------------------------------------------
# 第 4 步: 生成网页数据
# ---------------------------------------------------------------------------
def build_outputs(results, raw_count, sstp_count, source):
    all_ok = [r for r in results if r.get("success")]

    def lat(r):
        return _num(r.get("latency_ms"))

    # 只留够快的: 超过 MAX_LATENCY_MS 的丢弃 (延迟未知视为保留; 全被筛掉则不筛, 避免出空结果)
    fast = [r for r in all_ok if lat(r) is None or lat(r) <= MAX_LATENCY_MS] or all_ok
    fast.sort(key=lambda r: (lat(r) is None, lat(r) or 0, r["host"]))
    per, available = {}, []
    for r in fast:
        c = r["country"] or "未知"
        if per.get(c, 0) >= KEEP_PER_COUNTRY:
            continue
        per[c] = per.get(c, 0) + 1
        available.append(r)
    countries = {}
    for n in available:
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "success_total": len(all_ok),
        "failed": len(results) - len(all_ok),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
    }

    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
        grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))
        by_country[name] = grp

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "stats": stats,
        "countries": by_country,
        "available": available,
    }
    return data


CHAIN_URL = os.environ.get("CHAIN_URL", "https://jerylihub.github.io/gate/chains.txt")


def build_chains_text(data):
    """生成 edgetunnel 链式代理清单: 按国家分组, 每国编号固定, 住宅优先, 延迟升序。
    每行 = 「名字 + $sstp://vpn:vpn@host:port」, 名字不变, 指令每 24 小时自动换。"""
    countries = data["countries"]
    lines = [
        "# VPN Gate SSTP 节点 -> edgetunnel 链式代理清单",
        f"# 自动更新: {data['generated_at']} (每 24 小时重新检测)",
        f"# 固定地址: {CHAIN_URL}",
        "#",
        "# 用法: 在 edgetunnel 节点备注里直接粘贴下面任意一行 (名字与指令连写)",
        "#   例: 日本-住宅-01$sstp://vpn:vpn@vpnxxx.opengw.net:443",
        "# 名字保持不变, 只有 $sstp:// 后面的地址每 24 小时自动更换",
        "# 账号密码固定 vpn:vpn ; 端口必须保留",
        "# ========================================================",
    ]
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        lines.append("")
        lines.append(
            f"# ---- {zh} {code} · {grp['count']} 节点 (住宅 {grp['residential']} / 机房 {grp['datacenter']}) ----"
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            lines.append(f"{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            lines.append(f"{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


# edgetunnel 入口地址池: 客户端直连 Cloudflare 的优选 IP:端口 (循环分配给每个国家节点当入口)
# 可通过环境变量 EDGE_HOSTS 覆盖 (逗号分隔)
EDGE_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "EDGE_HOSTS",
        "stores.staples.com:443,neko.cloudd.eu.org:443,vps.cheng2001.top:443,lt.1930812.xyz:443,"
        "www.mfyx.cn:443,cf.090227.xyz:443,m.iyf.tv:443",
    ).split(",")
    if h.strip()
]

HOSTS_URL = os.environ.get("HOSTS_URL", "https://jerylihub.github.io/gate/hosts.txt")


def build_hosts_text(data):
    """生成可直接粘贴到 edgetunnel 后台「自定义优选IP」框的清单。
    每行 = 入口地址#名字$sstp://... ; 名字固定, 底下 SSTP 节点每 24 小时自动换。"""
    countries = data["countries"]
    # 入口: 默认用 7 个实测可用优选域名循环分配; 可用 HOSTS_ENTRY 覆盖(逗号分隔)
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    edge = [e.strip() for e in _entry.split(",") if e.strip()] or EDGE_HOSTS or ([f"{EDT_DOMAIN}:443"] if EDT_DOMAIN else [])
    if not edge:
        return "# 未配置入口地址 (EDGE_HOSTS / HOSTS_ENTRY / EDT_DOMAIN)\n"
    lines = [
        "# edgetunnel「自定义优选IP」清单 (整段复制, 追加到后台现有内容后面)",
        f"# 自动更新: {data['generated_at']} (每 24 小时重新检测)",
        f"# 固定地址: {HOSTS_URL}",
        "# 每行 = 入口地址#名字$sstp://vpn:vpn@节点:端口",
        "# 入口用 7 个实测可用优选域名循环分配",
        "# 名字 = 国家-住宅/机房-编号, 直接区分住宅与机房",
        "# 名字固定; 只有 $sstp:// 后面的节点地址每 24 小时自动更换",
        "# 账号密码固定 vpn:vpn ; 节点端口必须保留",
        "# ========================================================",
    ]
    idx = 0
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        lines.append("")
        lines.append(
            f"# ---- {zh} {code} · {grp['count']} 节点 (住宅 {grp['residential']} / 机房 {grp['datacenter']}) ----"
        )
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


# edgetunnel 完整订阅 (vless://) 配置
# UUID / 域名是你的 edgetunnel 凭据: 不写进仓库, 只从环境变量 (GitHub Secrets) 读取
EDT_UUID = os.environ.get("EDT_UUID", "").strip()
EDT_DOMAIN = os.environ.get("EDT_DOMAIN", "").strip()
EDT_FINGERPRINT = os.environ.get("EDT_FINGERPRINT", "chrome")
SUB_URL = os.environ.get("SUB_URL", "")


def _b64_secret_encode(plaintext, secret):
    """复刻 edgetunnel 的 base64SecretEncode: UTF-8 循环密钥 XOR + 标准 base64。"""
    data = plaintext.encode("utf-8")
    key = secret.encode("utf-8")
    mixed = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return base64.b64encode(mixed).decode("ascii")


def _socks5_account(address, default_port=80):
    """复刻 edgetunnel 的 获取SOCKS5账号: user:pass@host:port -> {username,password,hostname,port}。"""
    address = re.sub(r"^(socks5|http|https|turn|sstp)://", "", address.strip(), flags=re.I).split("#")[0].strip()
    at = address.rfind("@")
    auth, hostpart = (address[:at], address[at + 1:]) if at != -1 else ("", address)
    hostpart = hostpart.split("/")[0]
    username = password = None
    if auth:
        if ":" not in auth:
            try:
                auth = base64.b64decode(auth + "=" * (-len(auth) % 4)).decode("utf-8")
            except Exception:
                pass
        parts = auth.split(":", 1)
        username = parts[0]
        password = parts[1] if len(parts) > 1 else None
    hostname, port = hostpart, default_port
    if hostpart.count(":") == 1 and not hostpart.startswith("["):
        h, p = hostpart.rsplit(":", 1)
        if p.isdigit():
            hostname, port = h, int(p)
    return {"username": username, "password": password, "hostname": hostname, "port": port}


def _chain_path(n):
    chain = {"type": "sstp", **_socks5_account(f"vpn:vpn@{n['host']}:{n['port']}", 443)}
    chain_json = json.dumps(chain, separators=(",", ":"))
    return "/video/" + _b64_secret_encode(chain_json, EDT_UUID)


def build_sub_text(data):
    """生成 edgetunnel 完整 vless:// 订阅 (链式代理编码在 path)。
    填进 edgetunnel 后台「订阅链接」URL, 客户端定时拉取即可自动轮换。"""
    countries = data["countries"]
    lines = [
        "# edgetunnel 完整订阅 (vless://) —— 填进后台「订阅链接」URL",
        f"# 自动更新: {data['generated_at']} (每 24 小时重新检测)",
        f"# 固定地址: {SUB_URL or '(Pages 地址/<令牌>/sub.txt)'}",
        f"# 节点域名: {EDT_DOMAIN} (传输 ws / TLS / fingerprint {EDT_FINGERPRINT})",
        "# 名字固定; $sstp:// 链式代理(编码在 path)每 24 小时自动更换",
        "# 账号密码固定 vpn:vpn ; 节点端口已编码进 path",
        "# ========================================================",
    ]
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        for i, n in enumerate(nodes, 1):
            name = f"{zh}-{i:02d}"
            path = quote(_chain_path(n), safe="")
            link = (
                f"vless://{EDT_UUID}@{EDT_DOMAIN}:443?security=tls&type=ws"
                f"&host={EDT_DOMAIN}&fp={EDT_FINGERPRINT}&sni={EDT_DOMAIN}"
                f"&path={path}&encryption=none&alpn=#{quote(name, safe='')}"
            )
            lines.append(link)
    return "\n".join(lines) + "\n"


def build_clash_text(data):
    """生成 mihomo (Clash.Meta) 配置: 自带防 DNS 泄露设置。
    - fake-ip + 域名交给代理侧解析, DoH 走代理 (respect-rules), 不用系统/ISP DNS
    - 阻断 UDP/443 (QUIC) 且节点 udp:false, 避免 WebRTC/QUIC 绕过代理
    - 内网直连, 其余全部走代理 (MATCH)"""
    def key(n):
        v = _num(n.get("latency_ms"))
        return (v is None, v or 0, n.get("host") or "")

    nodes = sorted(data["available"], key=key)[:CLASH_MAX_NODES]
    if not nodes:
        return None
    q = lambda v: json.dumps(v, ensure_ascii=False)
    names, proxy_lines, seen = [], [], {}
    for n in nodes:
        code = str(n.get("country_code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or code
        seen[zh] = seen.get(zh, 0) + 1
        name = f"{zh}-{seen[zh]:02d}"
        names.append(name)
        proxy_lines += [
            f"  - name: {q(name)}",
            "    type: vless",
            f"    server: {q(EDT_DOMAIN)}",
            "    port: 443",
            f"    uuid: {q(EDT_UUID)}",
            "    udp: false",
            "    tls: true",
            f"    servername: {q(EDT_DOMAIN)}",
            f"    client-fingerprint: {EDT_FINGERPRINT}",
            "    skip-cert-verify: false",
            "    network: ws",
            "    ws-opts:",
            f"      path: {q(_chain_path(n))}",
            "      headers:",
            f"        Host: {q(EDT_DOMAIN)}",
        ]
    name_list = ", ".join(q(x) for x in names)
    lines = [
        f"# VPN Gate 节点 · mihomo(Clash.Meta) 配置 · 更新: {data['generated_at']} (每 24 小时)",
        "# 含你的 UUID, 请勿公开转发。需要 mihomo 内核 (Clash Verge Rev / FlClash / Clash Meta 等)。",
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: warning",
        "ipv6: false",
        "unified-delay: true",
        "tcp-concurrent: true",
        "",
        "dns:",
        "  enable: true",
        "  ipv6: false",
        "  enhanced-mode: fake-ip",
        "  fake-ip-range: 198.18.0.1/16",
        '  fake-ip-filter: ["*.lan", "*.local"]',
        "  default-nameserver: [1.1.1.1, 8.8.8.8]          # 仅用于启动引导 (全部是 IP, 不解析任何域名)",
        '  nameserver: ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]',
        '  proxy-server-nameserver: ["https://1.1.1.1/dns-query"]   # 只用来解析你的 Worker 域名',
        "  respect-rules: true                              # DNS 查询也走代理规则, 不走本地运营商 DNS",
        "",
        "sniffer:",
        "  enable: true",
        "  sniff:",
        "    HTTP: {ports: [80, 8080-8880]}",
        "    TLS: {ports: [443, 8443]}",
        "",
        "tun:",
        "  enable: false          # 想接管所有软件(含不走系统代理的)就改成 true, 需要管理员/root 权限",
        "  stack: mixed",
        "  auto-route: true",
        "  strict-route: true",
        "  auto-detect-interface: true",
        '  dns-hijack: ["any:53", "tcp://any:53"]',
        "",
        "proxies:",
        *proxy_lines,
        "",
        "proxy-groups:",
        "  - name: PROXY",
        "    type: select",
        f"    proxies: [\"AUTO\", {name_list}]",
        "  - name: AUTO",
        "    type: url-test",
        "    url: https://www.gstatic.com/generate_204",
        "    interval: 1800        # 每次测速都会经过你的 Worker, 间隔别调太小",
        "    tolerance: 150",
        "    lazy: true",
        f"    proxies: [{name_list}]",
        "",
        "rules:",
        "  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT      # 阻断 QUIC, 强制回落到 TCP 走代理",
        "  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "  - MATCH,PROXY",
    ]
    return "\n".join(lines) + "\n"


def build_sub_b64(data):
    """通用 base64 订阅 (去掉所有 # 注释行, 只留 vless:// 链接)。
    小火箭 / v2rayN / NekoBox 等都认这种格式, 比带注释的 sub.txt 兼容性更好。"""
    links = [ln for ln in build_sub_text(data).splitlines() if ln.strip() and not ln.startswith("#")]
    if not links:
        return None
    return base64.b64encode(("\n".join(links) + "\n").encode("utf-8")).decode("ascii") + "\n"


def build_shadowrocket_conf(data):
    """小火箭配置文件: 只放 DNS / IPv6 / 规则, 节点来自 sub_b64.txt 订阅。
    规则最后一条 FINAL,PROXY = 全部走你当前选中的节点。"""
    return "\n".join([
        f"# 小火箭配置 · 更新: {data['generated_at']} (每 24 小时)",
        "# 用法: 小火箭 -> 配置 -> 右上角 + -> 填本文件 URL 下载 -> 点选它 -> 选「使用配置」",
        "# 节点另外用 sub_b64.txt 订阅导入 (首页 -> 右上角 + -> 类型选 Subscribe)",
        "",
        "[General]",
        "bypass-system = true",
        "skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local",
        "ipv6 = false",
        "dns-server = https://1.1.1.1/dns-query, https://8.8.8.8/dns-query",
        "private-ip-answer = true",
        "udp-policy-not-supported-behaviour = REJECT",
        "",
        "[Rule]",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "FINAL,PROXY",
        "",
    ])


def write_outputs(data):
    """返回已写出文件的显示名列表 (含令牌的路径只显示占位符, 避免令牌进入公开的 Actions 日志)。"""
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    written = []

    def _write(path, text, label):
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        written.append(label)

    _write(os.path.join(PUBLIC_DIR, "data.json"),
           json.dumps(data, ensure_ascii=False, indent=1), "public/data.json")

    # 固定网页: 始终用 web/index.html 模板生成同一个 index.html (数据来自 data.json)
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = ("<html><head><meta charset='utf-8'><title>VPN Gate SSTP 节点</title></head>"
                "<body><h1>VPN Gate SSTP 节点</h1><pre id='out'></pre></body>"
                "<script>fetch('data.json').then(r=>r.json()).then(d=>out.textContent=JSON.stringify(d.stats)).catch(e=>out.textContent='加载失败:'+e)</script></html>")
    _write(os.path.join(PUBLIC_DIR, "index.html"), html, "public/index.html")

    # 不含凭据的清单 (只有 SSTP 节点地址, 公开无妨)
    _write(os.path.join(PUBLIC_DIR, "chains.txt"), build_chains_text(data), "public/chains.txt")
    _write(os.path.join(PUBLIC_DIR, "hosts.txt"), build_hosts_text(data), "public/hosts.txt")
    # 请搜索引擎别收录
    _write(os.path.join(PUBLIC_DIR, "robots.txt"), "User-agent: *\nDisallow: /\n", "public/robots.txt")

    # 含 UUID 的订阅 / Clash 配置: 配齐 EDT_UUID + EDT_DOMAIN + SUB_TOKEN 才生成, 且放进令牌目录
    if EDT_UUID and EDT_DOMAIN and SUB_TOKEN:
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,}", SUB_TOKEN):
            die("SUB_TOKEN 必须是 20 位以上的字母/数字/-/_ (建议 openssl rand -hex 16 以上)")
        priv = os.path.join(PUBLIC_DIR, SUB_TOKEN)
        os.makedirs(priv, exist_ok=True)
        _write(os.path.join(priv, "sub.txt"), build_sub_text(data), "public/<SUB_TOKEN>/sub.txt")
        clash = build_clash_text(data)
        if clash:
            _write(os.path.join(priv, "clash.yaml"), clash, "public/<SUB_TOKEN>/clash.yaml")
        b64 = build_sub_b64(data)
        if b64:
            _write(os.path.join(priv, "sub_b64.txt"), b64, "public/<SUB_TOKEN>/sub_b64.txt")
            _write(os.path.join(priv, "shadowrocket.conf"), build_shadowrocket_conf(data),
                   "public/<SUB_TOKEN>/shadowrocket.conf")
    else:
        log("WEBSITE", "未配置 EDT_UUID / EDT_DOMAIN / SUB_TOKEN: 不生成 sub.txt / clash.yaml 等含 UUID 的文件 "
                       "(按「hosts.txt 粘贴进 edgetunnel 后台」的流程使用时不需要它们)")
    return written


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    if not WORKER_CHECK_URL.startswith("https://"):
        die("未配置 CHECK_WORKER (必须是 https:// 开头)。请在仓库 Settings -> Secrets 里添加 CHECK_WORKER。")
    session = requests.Session()

    # 1) 数据源
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点 (数据源异常, 不允许生成空结果)")

    # 2) SSTP 筛选 + 去重
    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点 — 数据格式可能已变化, 需要人工适配")
    uniq = dedupe(sstp_nodes)
    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)}")

    # 先用官方指标筛, 再本地预检, 只把少量高质量候选交给 Worker (降低 Cloudflare CPU)
    pool = select_candidates(uniq, MAX_CANDIDATES * 2 if PRECHECK else MAX_CANDIDATES)
    log("VPN GATE", f"速度/延迟/在线时长筛选后: {len(pool)}")
    uniq = precheck(pool)[:MAX_CANDIDATES]
    if MAX_CHECK_NODES > 0:
        uniq = uniq[:MAX_CHECK_NODES]
    log("VPN GATE", f"提交 Worker 检测的候选: {len(uniq)}")

    # 3) 并发检测
    log("CLOUDFLARE WORKER", f"提交检测: {len(uniq)} (并发 {CONCURRENCY}, 单请求超时 {CHECK_TIMEOUT}s)")
    t0 = time.time()
    results = check_all(uniq, session)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}")
    log("CLOUDFLARE WORKER", f"检测失败: {len(failed)}" + (f" (其中 Worker 异常 {len(worker_errors)})" if worker_errors else ""))
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")

    # 硬性失败: Worker 完全不可达 (没有任何一个请求拿到正常响应)
    if uniq and not success and len(worker_errors) == len(uniq):
        die("Worker 全部请求异常, 检测服务不可用 — 本次运行判定失败 (不生成空结果)")

    # 4) 结果 + 网页
    data = build_outputs(results, raw_count, sstp_count, source)
    log("RESULT", f"可用节点: {len(success)}")
    log("RESULT", f"国家数量: {data['stats']['countries']}")

    for name in write_outputs(data):
        log("WEBSITE", f"生成 {name}")
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 执行)")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")

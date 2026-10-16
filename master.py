# ==================== NO CHANGE 🚫@MASTER_FF_01 ====================
import sys
import asyncio
import httpx
import random
import json
import socket
import struct
import time
import os
import uuid
import itertools
import secrets
import traceback
import base64
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# ==================== ORIGINAL IMPORTS ====================
from google_play_scraper import app as play_scraper
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser
from message_ids import MESSAGE_ID_TO_NAME
import MasterTeam_pb2
import MasterFF_pb2

# ==================== WEB DASHBOARD ====================
from dashboard_server import bot_state, start_web_dashboard, fill_slots, enforce_startup_cap, MAX_ACTIVE_ACCOUNTS, AUTO_DELETE_LEVEL

# ==================== CONFIGURATION ====================
WEB_HOST = "0.0.0.0"
WEB_PORT = int(os.getenv("PORT", "20337"))
ACCOUNTS_FILE = "accounts.json"
TOKEN_CACHE_FILE = "token_cache.json"
DEVICES_FILE = "devices.json"
TOKEN_CACHE_TTL = 1200

# Match control (HUMAN-LIKE)
START_MATCH_INTERVAL_MIN = 4.0
START_MATCH_INTERVAL_MAX = 8.0
START_MATCH_INTERVAL = 10.0
NEW_MATCH_DELAY = 6.0
MAX_MATCH_DURATION = 800
MATCH_IDLE_TIMEOUT = 20.0
MAX_CONCURRENT_MATCHES = 2  # legacy fallback
MAX_CONCURRENT_MATCHES_BR = 1
MAX_CONCURRENT_MATCHES_LW = 15
LEVEL_THRESHOLD = 3          # level >= 3 -> Lone Wolf, below -> Battle Royale
# Original Battle Royale bot timings (restored for BR accounts)
BR_START_MATCH_INTERVAL = 4.0
BR_NEW_MATCH_DELAY = 5.0
BR_MATCH_IDLE_TIMEOUT = 15.0
_LOGIN_SEMAPHORE = asyncio.Semaphore(15)   # original BR limited parallel logins to 4


def get_current_mode(uid):
    """Per-account mode from that account's OWN level. Returns ("BR"|"LW", level)."""
    try:
        lvl = int(bot_state.get_account_level(uid))
    except Exception:
        lvl = 1
    return ("BR" if lvl < LEVEL_THRESHOLD else "LW"), lvl


def max_concurrent_for(uid):
    try:
        lvl = bot_state.get_account_level(uid)
    except Exception:
        lvl = 1
    return MAX_CONCURRENT_MATCHES_BR if lvl < LEVEL_THRESHOLD else MAX_CONCURRENT_MATCHES_LW


def startup_params_for_mode(mode):
    """UDP loading-frame (mode_id, map_id) used for the match join."""
    return (1, 1) if mode == "BR" else (43, 11)
HUMAN_MODE = True
ANTI_AFK_FIRE_CHANCE = 0.45
ANTI_AFK_MIN_INTERVAL = 1.8
ANTI_AFK_MAX_INTERVAL = 3.5

# Force region
FORCE_REGION = "BD"

# Cache invalidation thresholds
MAX_CONSECUTIVE_PARSE_FAILURES = 5.0
NON_MATCH_RECONNECT_DELAY = 1.0

FALLBACK_UID = ""
FALLBACK_PASSWORD = ""


# ==================== HUMAN-LIKE HELPERS ====================
async def human_delay(base=1.0, variance=0.5):
    delay = base + random.uniform(-variance, variance)
    return max(0.1, delay)


async def human_jitter():
    return random.uniform(0.05, 0.35)


from device_pool import make_device


# ==================== ULTRA SAFE PERSISTENT DEVICE RANDOMIZER ====================
def get_device_for_account(account_identifier: str) -> dict:
    devices = {}
    if os.path.exists(DEVICES_FILE):
        try:
            with open(DEVICES_FILE, "r", encoding="utf-8") as f:
                devices = json.load(f)
        except Exception:
            pass

    acc_key = str(account_identifier)

    if acc_key in devices:
        return devices[acc_key]

    new_device = make_device(devices)

    devices[acc_key] = new_device

    try:
        with open(DEVICES_FILE, "w", encoding="utf-8") as f:
            json.dump(devices, f, indent=4)
    except Exception as e:
        log_err(f"Failed to save device: {e}")

    return new_device


# ==================== CLOUDFLARE DNS RESOLVER ====================
CLOUDFLARE_PRIMARY_DNS = "1.1.1.1"
CLOUDFLARE_SECONDARY_DNS = "1.0.0.1"
_DNS_CACHE: Dict[str, Tuple[str, float]] = {}
_DNS_CACHE_TTL = 300.0


async def resolve_host_cloudflare(hostname: str) -> str:
    if not hostname:
        return hostname

    parts = hostname.split('.')
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return hostname

    now = time.time()
    if hostname in _DNS_CACHE:
        ip, exp = _DNS_CACHE[hostname]
        if now < exp:
            return ip

    def _query_cloudflare(server_ip: str) -> Optional[str]:
        s = None
        try:
            tx_id = random.randint(1000, 65535)
            header = struct.pack(">HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
            qname = b"".join(bytes([len(part)]) + part.encode('ascii') for part in hostname.split('.')) + b"\x00"
            query_pkt = header + qname + struct.pack(">HH", 1, 1)

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.2)
            s.sendto(query_pkt, (server_ip, 53))
            resp, _ = s.recvfrom(1024)

            if len(resp) >= 12:
                ancount = struct.unpack(">H", resp[6:8])[0]
                if ancount > 0:
                    offset = 12 + len(qname) + 4
                    for _ in range(ancount):
                        if offset >= len(resp):
                            break
                        if (resp[offset] & 0xC0) == 0xC0:
                            offset += 2
                        else:
                            while offset < len(resp) and resp[offset] != 0:
                                offset += 1 + resp[offset]
                            offset += 1
                        if offset + 10 > len(resp):
                            break
                        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", resp[offset:offset+10])
                        offset += 10
                        if rtype == 1 and rdlen == 4 and offset + 4 <= len(resp):
                            return socket.inet_ntoa(resp[offset:offset+4])
                        offset += rdlen
        except Exception:
            pass
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
        return None

    loop = asyncio.get_running_loop()
    ip = await loop.run_in_executor(None, _query_cloudflare, CLOUDFLARE_PRIMARY_DNS)
    if not ip:
        ip = await loop.run_in_executor(None, _query_cloudflare, CLOUDFLARE_SECONDARY_DNS)
    if not ip:
        try:
            ip_info = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
            if ip_info:
                ip = ip_info[0][4][0]
        except Exception:
            ip = hostname

    if ip:
        _DNS_CACHE[hostname] = (ip, now + _DNS_CACHE_TTL)
    return ip or hostname


def optimize_tcp_socket(sock: socket.socket):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
    except Exception:
        pass


def optimize_udp_socket(sock: socket.socket):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 131072)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
        if hasattr(socket, 'SIO_UDP_CONNRESET') and os.name == 'nt':
            try:
                sock.ioctl(socket.SIO_UDP_CONNRESET, False)
            except Exception:
                pass
    except Exception:
        pass


# ==================== NETWORK & CRYPTO ====================
client = httpx.AsyncClient(
    verify=False,
    timeout=10.0,
    limits=httpx.Limits(max_connections=100, max_keepalive_connections=50)
)

headers = {
    'User-Agent': 'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Expect': '100-continue',
    'X-Unity-Version': '2018.4.12f1',
    'X-GA-SV': '1789535859',
    'X-GA': 'v1 1',
    'ReleaseVersion': 'OB55'
}

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

CRC7_TABLE = bytes([
    0, 9, 18, 27, 36, 45, 54, 63, 72, 65, 90, 83, 108, 101, 126, 119,
    25, 16, 11, 2, 61, 52, 47, 38, 81, 88, 67, 74, 117, 124, 103, 110,
    50, 59, 32, 41, 22, 31, 4, 13, 122, 115, 104, 97, 94, 87, 76, 69,
    43, 34, 57, 48, 15, 6, 29, 20, 99, 106, 113, 120, 71, 78, 85, 92,
    100, 109, 118, 127, 64, 73, 82, 91, 44, 37, 62, 55, 8, 1, 26, 19,
    125, 116, 111, 102, 89, 80, 75, 66, 53, 60, 39, 46, 17, 24, 3, 10,
    86, 95, 68, 77, 114, 123, 96, 105, 30, 23, 12, 5, 58, 51, 40, 33,
    79, 70, 93, 84, 107, 98, 121, 112, 7, 14, 21, 28, 35, 42, 49, 56,
    65, 72, 83, 90, 101, 108, 119, 126, 9, 0, 27, 18, 45, 36, 63, 54,
    88, 81, 74, 67, 124, 117, 110, 103, 16, 25, 2, 11, 52, 61, 38, 47,
    115, 122, 97, 104, 87, 94, 69, 76, 59, 50, 41, 32, 31, 22, 13, 4,
    106, 99, 120, 113, 78, 71, 92, 85, 34, 43, 48, 57, 6, 15, 20, 29,
    37, 44, 55, 62, 1, 8, 19, 26, 109, 100, 127, 118, 73, 64, 91, 82,
    60, 53, 46, 39, 24, 17, 10, 3, 116, 125, 102, 111, 80, 89, 66, 75,
    23, 30, 5, 12, 51, 58, 33, 40, 95, 86, 77, 68, 123, 114, 105, 96,
    14, 7, 28, 21, 42, 35, 56, 49, 70, 79, 84, 93, 98, 107, 112, 121,
])

_DELTA = 0x9E3779B9
_ROUNDS = 16
_FIELD_SIZES = {0: 1, 1: 2, 2: 2, 3: 1, 4: 2}
_FIELD_NAMES = {0: "sendOption", 1: "cmd", 2: "orderId", 3: "flags", 4: "length"}


# ==================== 🎨 CLEAN LOG SYSTEM ====================
class Colors:
    GREEN = '\033[92m'
    FAIL = '\033[91m'
    WARNING = '\033[93m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    ENDC = '\033[0m'


def cprint(text, color=Colors.WHITE):
    try:
        print(f"{color}{text}{Colors.ENDC}")
    except Exception:
        try:
            safe = text.encode('ascii', errors='replace').decode('ascii')
            print(f"{color}{safe}{Colors.ENDC}")
        except Exception:
            print(text)


# Tag-width: 8 chars for alignment
def log_info(text):
    """General info"""
    msg = f"{Colors.CYAN}[ INFO  ]{Colors.ENDC} {text}"
    print(msg)
    try:
        bot_state.log(text, "info")
    except Exception:
        pass


def log_ok(text):
    """Success"""
    msg = f"{Colors.GREEN}[   OK  ]{Colors.ENDC} {text}"
    print(msg)
    try:
        bot_state.log(text, "success")
    except Exception:
        pass


def log_warn(text):
    """Warning"""
    msg = f"{Colors.WARNING}[  WARN ]{Colors.ENDC} {text}"
    print(msg)
    try:
        bot_state.log(text, "warning")
    except Exception:
        pass


def log_err(text):
    """Error"""
    msg = f"{Colors.FAIL}[  FAIL ]{Colors.ENDC} {text}"
    print(msg)
    try:
        bot_state.log(text, "error")
    except Exception:
        pass


def log_login(text):
    """Login events"""
    msg = f"{Colors.MAGENTA}[ LOGIN ]{Colors.ENDC} {text}"
    print(msg)
    try:
        bot_state.log(text, "info")
    except Exception:
        pass


def log_match(text):
    """Match events"""
    msg = f"{Colors.GREEN}[ MATCH ]{Colors.ENDC} {text}"
    print(msg)
    try:
        bot_state.log(text, "success")
    except Exception:
        pass


def log_exp(text):
    """EXP gains"""
    msg = f"{Colors.GREEN}[  EXP  ]{Colors.ENDC} {text}"
    print(msg)
    try:
        bot_state.log(text, "success")
    except Exception:
        pass


def log_net(text):
    """Network events"""
    msg = f"{Colors.BLUE}[  NET  ]{Colors.ENDC} {text}"
    print(msg)
    try:
        bot_state.log(text, "info")
    except Exception:
        pass


def log_search(text):
    """Match search"""
    msg = f"{Colors.CYAN}[SEARCH ]{Colors.ENDC} {text}"
    print(msg)
    try:
        bot_state.log(text, "info")
    except Exception:
        pass


def log_afk(text):
    """Anti-AFK"""
    msg = f"{Colors.CYAN}[  AFK  ]{Colors.ENDC} {text}"
    print(msg)
    try:
        bot_state.log(text, "info")
    except Exception:
        pass


def log_cache(text):
    """Cache events"""
    msg = f"{Colors.MAGENTA}[ CACHE ]{Colors.ENDC} {text}"
    print(msg)
    try:
        bot_state.log(text, "info")
    except Exception:
        pass


def log_separator(title=""):
    """Big separator line"""
    line = "=" * 60
    print("")
    print(f"{Colors.CYAN}{line}{Colors.ENDC}")
    if title:
        print(f"{Colors.BOLD}{Colors.CYAN}{title.center(60)}{Colors.ENDC}")
        print(f"{Colors.CYAN}{line}{Colors.ENDC}")
    print("")


def log_banner():
    """Startup banner"""
    print("")
    print(f"{Colors.CYAN}+{'=' * 58}+{Colors.ENDC}")
    print(f"{Colors.CYAN}|{Colors.ENDC}{' ' * 58}{Colors.CYAN}|{Colors.ENDC}")
    print(f"{Colors.CYAN}|{Colors.ENDC}{Colors.BOLD}{Colors.MAGENTA}{'MASTER OFFICIAL - AUTO LEVEL UP BOT'.center(58)}{Colors.ENDC}{Colors.CYAN}|{Colors.ENDC}")
    print(f"{Colors.CYAN}|{Colors.ENDC}{Colors.DIM}{'Lone Wolf Mode | IND Region'.center(58)}{Colors.ENDC}{Colors.CYAN}|{Colors.ENDC}")
    print(f"{Colors.CYAN}|{Colors.ENDC}{' ' * 58}{Colors.CYAN}|{Colors.ENDC}")
    print(f"{Colors.CYAN}|{Colors.ENDC}{Colors.GREEN}{'Telegram: @FTC_GAMER_fortune'.center(58)}{Colors.ENDC}{Colors.CYAN}|{Colors.ENDC}")
    print(f"{Colors.CYAN}|{Colors.ENDC}{Colors.WHITE}{f'Dashboard: http://localhost:{WEB_PORT}'.center(58)}{Colors.ENDC}{Colors.CYAN}|{Colors.ENDC}")
    print(f"{Colors.CYAN}|{Colors.ENDC}{' ' * 58}{Colors.CYAN}|{Colors.ENDC}")
    print(f"{Colors.CYAN}+{'=' * 58}+{Colors.ENDC}")
    print("")


def log_match_banner(match_idx, uid, server):
    """Big banner when match found"""
    print("")
    print(f"{Colors.GREEN}{'+' + '-' * 58 + '+'}{Colors.ENDC}")
    print(f"{Colors.GREEN}|{Colors.ENDC}  {Colors.BOLD}MATCH #{match_idx} FOUND{Colors.ENDC}".ljust(69) + f"{Colors.GREEN}|{Colors.ENDC}")
    print(f"{Colors.GREEN}|{Colors.ENDC}  UID: {uid} | Server: {server}".ljust(69) + f"{Colors.GREEN}|{Colors.ENDC}")
    print(f"{Colors.GREEN}{'+' + '-' * 58 + '+'}{Colors.ENDC}")
    print("")


# Backwards-compat aliases (in case any code still calls these)
print_colored = cprint
print_success = log_ok
print_error = log_err
print_warning = log_warn
print_info = log_info


def get_proto_field(d, key, default=None):
    if not d or not isinstance(d, dict):
        return default
    if key in d:
        val = d[key].get('data')
        return val if val is not None else default
    if str(key) in d:
        val = d[str(key)].get('data')
        return val if val is not None else default
    return default


# ==================== PER-ACCOUNT MATCH COUNTER ====================
_match_counters: Dict[str, int] = {}
_match_counter_lock = asyncio.Lock()


async def _inc_match(uid: str) -> int:
    async with _match_counter_lock:
        _match_counters[uid] = _match_counters.get(uid, 0) + 1
        return _match_counters[uid]


async def _dec_match(uid: str) -> int:
    async with _match_counter_lock:
        if uid in _match_counters and _match_counters[uid] > 0:
            _match_counters[uid] -= 1
        return _match_counters.get(uid, 0)


async def _get_match_count(uid: str) -> int:
    async with _match_counter_lock:
        return _match_counters.get(uid, 0)


async def _get_total_match_count() -> int:
    async with _match_counter_lock:
        return sum(_match_counters.values())


# ==================== TOKEN CACHE ====================
_token_cache_memo: Dict[str, Any] = {}
_token_cache_memo_time: float = 0.0
_TOKEN_CACHE_MEMO_TTL = 5.0


def _json_serializer(obj):
    if isinstance(obj, (bytes, bytearray)):
        return {"__bytes_hex__": bytes(obj).hex()}
    raise TypeError(f"Type {type(obj)} not serializable")


def _json_deserializer(obj):
    if isinstance(obj, dict):
        if "__bytes_hex__" in obj and len(obj) == 1:
            try:
                return bytes.fromhex(obj["__bytes_hex__"])
            except Exception:
                return b""
        return {k: _json_deserializer(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_deserializer(x) for x in obj]
    return obj


def _load_token_cache() -> Dict[str, Any]:
    global _token_cache_memo, _token_cache_memo_time
    now = time.time()
    if _token_cache_memo and (now - _token_cache_memo_time) < _TOKEN_CACHE_MEMO_TTL:
        return _token_cache_memo

    if not os.path.exists(TOKEN_CACHE_FILE):
        return {}
    try:
        with open(TOKEN_CACHE_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
        if not content:
            return {}
        data = json.loads(content)
        if not isinstance(data, dict):
            raise ValueError("Cache root must be dict")
        parsed = _json_deserializer(data)
        _token_cache_memo = parsed
        _token_cache_memo_time = now
        return parsed
    except Exception as e:
        log_err(f"Token cache corrupt - deleting: {e}")
        try:
            os.remove(TOKEN_CACHE_FILE)
        except Exception:
            pass
        return {}


def _save_token_cache(cache: Dict[str, Any]):
    global _token_cache_memo, _token_cache_memo_time
    try:
        tmp_file = TOKEN_CACHE_FILE + ".tmp"
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, default=_json_serializer)
        os.replace(tmp_file, TOKEN_CACHE_FILE)
        _token_cache_memo = cache
        _token_cache_memo_time = time.time()
    except Exception as e:
        log_err(f"Token cache save error: {e}")


def cache_get(uid: str) -> Optional[Dict]:
    cache = _load_token_cache()
    entry = cache.get(str(uid))
    if not entry:
        return None
    if time.time() - entry.get("cached_at", 0) > TOKEN_CACHE_TTL:
        log_cache(f"UID {uid} expired - re-login needed")
        cache_invalidate(uid)
        return None
    if str(entry.get("account_id", "")).isdigit():
        entry["account_id"] = int(entry["account_id"])
    if not isinstance(entry.get("login_payload_data"), (bytes, bytearray)):
        log_warn(f"UID {uid} missing payload - invalidating")
        cache_invalidate(uid)
        return None
    return entry


def cache_set(uid: str, account_data: Dict):
    cache = _load_token_cache()
    entry = dict(account_data)
    entry["cached_at"] = time.time()
    cache[str(uid)] = entry
    _save_token_cache(cache)
    log_cache(f"Saved credentials for UID {uid}")


def cache_invalidate(uid: str):
    cache = _load_token_cache()
    if str(uid) in cache:
        del cache[str(uid)]
        _save_token_cache(cache)
        log_warn(f"Invalidated: {uid}")


# ==================== ENCRYPTION & PROTOBUF ====================
async def aes_encrypt(payload, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(payload, AES.block_size))


async def get_playstore_version():
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: play_scraper('com.dts.freefireth', lang='hi', country='id')
    )
    return result.get("version")


async def version_config():
    app_version = await get_playstore_version()
    api_url = (
        "https://version.ggwhitehawk.com/live/ver.php"
        f"?version={app_version}"
        "&lang=hi&device=android&channel=android"
        "&appstore=googleplay&region=BD"
        "&whitelist_version=1.3.0&whitelist_sp_version=1.0.0"
    )
    try:
        response = await client.get(api_url)
        response.raise_for_status()
        data = response.json()
        server_url = data.get("server_url")
        remote_version = data.get("remote_version")
        latest_release_version = data.get("latest_release_version")
        if not server_url or not remote_version or not latest_release_version:
            return None
        return latest_release_version, remote_version, server_url
    except Exception:
        return None


async def get_access_token(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    hdrs = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; SM-G998B Build/SP1A.210812.016)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    for attempt in range(5):
        try:
            response = await client.post(url, headers=hdrs, data=data)
            if response.status_code == 200:
                response_data = response.json()
                open_id = response_data.get("open_id")
                access_token = response_data.get("access_token")
                platform = response_data.get("platform", 4)
                if open_id and access_token:
                    return open_id, access_token, platform
            if response.status_code == 429:
                await asyncio.sleep(1)
                continue
        except Exception:
            pass
        await asyncio.sleep(0.5)
    return None


async def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {"wire_type": result.wire_type}
        if result.wire_type == "varint":
            field_data["data"] = result.data
        elif result.wire_type == "string":
            field_data["data"] = result.data
        elif result.wire_type == "bytes":
            field_data["data"] = result.data
        elif result.wire_type == "length_delimited":
            field_data["data"] = await parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict


async def decode_protobuf(data):
    parsed_results = Parser().parse(data)
    parsed_results_dict = await parse_results(parsed_results)
    return json.dumps(parsed_results_dict)


# ==================== MANUAL PROTOBUF WIRE FORMAT ====================
def encode_varint(n):
    if n < 0:
        return b''
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        out.append(b)
        if not n:
            break
    return bytes(out)


def build_proto(fields):
    parts = []
    for k, v in fields.items():
        if isinstance(v, dict):
            nested = build_proto(v)
            parts.append(encode_varint((k << 3) | 2) + encode_varint(len(nested)) + nested)
        elif isinstance(v, int):
            parts.append(encode_varint((k << 3) | 0) + encode_varint(v))
        elif isinstance(v, (str, bytes)):
            ev = v.encode() if isinstance(v, str) else v
            parts.append(encode_varint((k << 3) | 2) + encode_varint(len(ev)) + ev)
    return b''.join(parts)


def encrypt_api(plain_hex):
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(
        pad(bytes.fromhex(plain_hex), AES.block_size)
    ).hex()


def encrypt_api_bytes(plain_bytes):
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(
        pad(plain_bytes, AES.block_size)
    )


# ==================== build_majorlogin_payload (IND REGION) ====================
async def build_majorlogin_payload(open_id, access_token, platform, client_version, device_info):
    try:
        payload_dict = {
            3:   str(datetime.now())[:-7],
            4:   "free fire",
            5:   "1",
            7:   str(client_version) if client_version else "1.132.8",
            8:   str(device_info.get(
                     "system_software",
                     "Android OS 15 / API-35 (AP3A.240905.015.A2/OS2.0.202.0.VGTIDXM)"
                 )),
            9:   "Handheld",
            10:  "Telkomsel",
            11:  "CarrierDataNetwork",
            12:  str(device_info.get("screen_width", 1639)),
            13:  str(device_info.get("screen_height", 720)),
            14:  str(device_info.get("screen_dpi", 320)),
            15:  str(device_info.get("processor_details", "ARM64 FP ASIMD AES | 2000 | 8")),
            16:  str(device_info.get("memory", 5653)),
            17:  str(device_info.get("gpu_renderer", "Mali-G52 MC2")),
            18:  "OpenGL ES 3.2 v1.r49p1-03bet0.19498e0ae1d5dac223383c39a2e58f04",
            19:  str(device_info.get("unique_device_id", f"Google|{uuid.uuid4()}")),
            20:  str(device_info.get("client_ip", "182.5.135.225")),
            21:  "en",
            22:  str(open_id),
            23:  str(platform),
            24:  "Handheld",
            25:  str(device_info.get("model", "Xiaomi 2409BRN2CY")),
            26:  "ID",
            29:  str(access_token),
            30:  "1",
            41:  "Telkomsel",
            42:  "4G",
            57:  "7428b253defc164018c604a1ebbfebdf",
            60:  "109278",
            61:  "55402",
            62:  "868",
            64:  "55927",
            65:  "109278",
            66:  "55927",
            67:  "109278",
            73:  "2",
            74:  "/data/app/~~6Cw028g_ld-8Z0z2qhrOLA==/com.dts.freefireth-i3wiaEmpx8CbiRVhUMx_ag==/lib/arm64",
            76:  "1",
            77:  "b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~6Cw028g_ld-8Z0z2qhrOLA==/com.dts.freefireth-i3wiaEmpx8CbiRVhUMx_ag==/base.apk",
            78:  "3",
            79:  "2",
            81:  "64",
            83:  "2019121229",
            85:  "3",
            86:  "OpenGLES2",
            87:  "8191",
            88:  str(platform),
            90:  "Cirebon",
            91:  "JB",
            92:  "14466",
            93:  "android",
            94:  "KqsHTyb7yHjsAiyNWUUZa0DSOD6U0AhDQ76smAo1WeHHHpSmJ8KMRyRrxb2ttgJqO9YOqO/K6AORAvDMAX/qBS8+JahIkrM7kHfzlfULbgRAoZ9r",
            95:  "111207",
            96:  "{\"cur_rate\":[60,90,120],\"support_etc2\":false}",
            97:  "1",
            98:  "1",
            99:  str(platform),
            100: str(platform),
            102: "D]C\x15\x05T\x0eU3",
            103: "1",
            104: "52837",
            105: "1",
            106: "https://dl.gmc.freefiremobile.com/live/ABHotUpdates/|https://core-gmc.freefiremobile.com/live/ABHotUpdates/|211c933168f55902c7dfbfd8c4e2957d",
            107: "1.3fb8adbf45f44ce9",
        }

        raw_proto = build_proto(payload_dict)
        encrypted = encrypt_api_bytes(raw_proto)
        return encrypted

    except Exception as e:
        log_err(f"MajorLogin payload build failed: {e}")
        traceback.print_exc()
        return None


# ==================== send_majorlogin ====================
async def send_majorlogin(data, release_version, server_url):
    try:
        if not data:
            log_err("[MajorLogin] Empty payload - aborting")
            return None
        if not server_url:
            log_err("[MajorLogin] Missing server_url - aborting")
            return None

        base = server_url.rstrip('/')
        url = f"{base}/MajorLogin"

        req_headers = headers.copy()
        req_headers["ReleaseVersion"] = release_version
        response = await client.post(url, headers=req_headers, data=data)

        if response.status_code != 200:
            log_err(f"[MajorLogin] HTTP {response.status_code}")
            return None

        response_content = response.content
        if len(response_content) < 40:
            log_err(f"[MajorLogin] Response too small ({len(response_content)} bytes)")
            return None

        res_proto = MasterTeam_pb2.MajorLoginRes()
        try:
            res_proto.ParseFromString(response_content)
            if res_proto.region and res_proto.token:
                return res_proto
        except Exception:
            pass

        if len(response_content) > 64:
            try:
                res_proto = MasterTeam_pb2.MajorLoginRes()
                res_proto.ParseFromString(response_content[64:])
                if res_proto.region and res_proto.token:
                    return res_proto
            except Exception:
                pass

        for offset in range(min(128, len(response_content))):
            try:
                candidate = MasterTeam_pb2.MajorLoginRes()
                candidate.ParseFromString(response_content[offset:])
                if candidate.region and candidate.token:
                    return candidate
            except Exception:
                pass

        res_proto = MasterTeam_pb2.MajorLoginRes()
        res_proto.ParseFromString(response_content)
        return res_proto
    except Exception as e:
        log_err(f"[MajorLogin] Exception: {e}")
        return None


# ==================== send_getlogin ====================
async def send_getlogin(data, base_url, token, release_version):
    try:
        if not data:
            log_err("[GetLoginData] Empty payload - aborting")
            return None

        base = base_url.rstrip('/')
        url = f"{base}/GetLoginData"

        req_headers = headers.copy()
        req_headers["ReleaseVersion"] = release_version
        req_headers['Authorization'] = f"Bearer {token}"
        req_headers['Host'] = "clientbp.ppmainecoonghj.com"
        response = await client.post(url, headers=req_headers, data=data)

        if response.status_code != 200:
            log_err(f"[GetLoginData] HTTP {response.status_code}")
            return None

        response_content = response.content

        res_proto = MasterTeam_pb2.GetLoginDataRes()
        parsed_successfully = False
        try:
            res_proto.ParseFromString(response_content)
            if res_proto.functional_addrs or res_proto.informational_addrs:
                parsed_successfully = True
        except Exception:
            pass

        if not parsed_successfully:
            for offset in range(min(128, len(response_content))):
                try:
                    candidate = MasterTeam_pb2.GetLoginDataRes()
                    candidate.ParseFromString(response_content[offset:])
                    if candidate.functional_addrs or candidate.informational_addrs:
                        res_proto = candidate
                        break
                except Exception:
                    pass

        dict_res = {}
        try:
            parsed = Parser().parse(response_content.hex())
            dict_res = await parse_results(parsed)
        except Exception:
            pass

        return res_proto, dict_res
    except Exception as e:
        log_err(f"[GetLoginData] Exception: {e}")
        return None


async def build_tcp_startup_packet(account_id, token, server_time, key, iv, region="BD", typ='OnLine'):
    uid_hex = f"{int(account_id):016x}"
    timestamp_hex = f"{int(server_time):08x}"
    encode_token = token.encode()
    encrypted_packet = (await aes_encrypt(encode_token, key, iv)).hex()
    encrypted_packet_length = f"{len(encrypted_packet) // 2:08x}"
    reg = str(region).upper() if region else "BD"
    if typ == 'OnLine':
        prefix = '7219' if reg == 'BD' else ('7114' if reg == 'IND' else '7115')
        return f"{prefix}{uid_hex}{timestamp_hex}00000000{encrypted_packet_length}{encrypted_packet}"
    else:
        prefix = '8119' if reg == 'BD' else ('9214' if reg == 'IND' else '9215')
        return f"{prefix}{uid_hex}{timestamp_hex}{encrypted_packet_length}{encrypted_packet}"


async def send_keep_alive(region="BD"):
    try:
        reg = str(region).upper() if region else "BD"
        if reg == "BD":
            ka_hex = "0219"
        elif reg in ("IND", "IN"):
            ka_hex = "0214"
        else:
            ka_hex = "0215"
        return bytes.fromhex(ka_hex)
    except Exception:
        return bytes.fromhex("0219")


async def start_game_lone_wolf(region, client_version, writer, key, iv):
    packet = bytes.fromhex("080112800a0a010b102b3a110a044944433110aa011a064555524f50453a100a044944433210311a064555524f504540014a0801090a0b1219202758016291090a8001303838463832424630324139363736373032303130313030303030303030303030303136303030313030313530303032323246393745454530463030303030303436373632353134303030303030303030303030303030303030303030303030303030303030303030303030303066663030303030303030636163666131366410241afb02735d5e571400024a775d45414d1a041b1c001f11010449715f4243481a001e1d071c1703004b1a4066785c524570735c51486775421b5c5a4c07504042685a63610816054e19025e75196001477c015165406370195f5547404e4550640103020f1304064863754268676c755f65576e40467e5f0a417a4701026d675d6e73670b1108495a4c6a0b78470b740065645e525a057258425f584a447d4e6759440c11044e7c596d7f4b625f7d04055a47505c4e1d6b5b4107447d7201057d7f0f14084e430457674f7e517d72015172415d027473577c4d615f79535256780911030f4d5e027a797f614165067806505d53777750475e75064257076500460817014e741e7e5078487e7a7c465e7669767153497064605a7376677773550d160148037e18675966787f4c42607a645f577e7b441b460776026b18685d0b110205490060020f70676175654674706671797f41067346677c4e06585e780f15074c57047b40517075415f6364027259674b5b0166407f7340600407770a22047a5d5c52300b3a0a167305067162727516134208312e3133302e3232480350015ae90403626253513635686e556f4e36416456324b796f566c636f477776484f624e56526c4d727073504b4f43654177616848494176795556497273743752737149734a7a786b3247525268377a2f637664626d504f6a73552f79626d38547a4c69586d2f474351696d494b53486833447955726f39515152756c34545350626d6d624b7949565937545671577059455372323646572f59624578507338514f706d317372785455736c30796a434144444d4f34616a654b615753366361496c554b4963797a494e396d52516f715277687939797257476d337a644345337a6a61436f492f5a585233656f65365a42647a64677654636b6b665733356e4d4c6a6a565072564b6433523172756174394e50514150724a5546627859696c4c5a3859707336654d5447666b6649793574666a526c314d4648706b51774c6373374439656378566c41636f374e664f6d2b30654756466c4434744478706771385533595973587645384842502f70666c767a737138316a32524f4d7857437556445442492f684735625462773166456e4249725162762b636144775147696f74554e316d4c4b77734379456f4766706746614251457645672b736a764c4c78704743334c304a5344532f74526169504354553344374e6249306547516651622f5a466f4c36455630775a324d6f583932414c572f5049752f56634663584e70596b356f7966326151416a536971486a2f363276354843644f525551303578754e6171795251625653704654303137655237675255636b4966366c6f447476342b514e4a4670766d74757077707774396a5a5974437a4b56743657726d6e36785837706658456251555434684f3758a201050803108703a201050804108103a20105080510c001a20105081d10cc01a2010408161078a20105080e10af01a201020815")
    proto = MasterTeam_pb2.StartMatch()
    proto.ParseFromString(packet)
    if hasattr(proto.main, 'region_list') and len(proto.main.region_list) > 0:
        proto.main.region_list[0].region = region
        if len(proto.main.region_list) > 1:
            proto.main.region_list[1].region = region
    if hasattr(proto.main, 'client_version'):
        proto.main.client_version.remote_version = client_version
    packet = proto.SerializeToString()
    encrypted_packet = (await aes_encrypt(packet, key, iv)).hex()
    packet_length = len(encrypted_packet) // 2
    hex_length = hex(packet_length)[2:]
    hex_length = hex_length if len(hex_length) > 1 else "0" + hex_length
    reg = str(region).upper() if region else "BD"
    reg_prefix = "031900" if reg == "BD" else ("031400" if reg == "IND" else "031500")
    final_packet = reg_prefix + "0" * (6 - len(hex_length)) + hex_length + encrypted_packet
    writer.write(bytes.fromhex(final_packet))
    await writer.drain()
    log_search(f"LW Search Packet Sent ({packet_length} bytes) | Region: {reg}")


async def start_game_battle_royale(region, client_version, writer, key, iv):
    packet = bytes.fromhex("080112800a0a010110013a110a044944433110aa011a064555524f50453a100a044944433210311a064555524f504540014a0801090a0b1219202758016291090a8001303838463832424630324139363736373032303130313030303030303030303030303136303030313030313530303032323246393745454530463030303030303436373632353134303030303030303030303030303030303030303030303030303030303030303030303030303066663030303030303030636163666131366410241afb02735d5e571400024a775d45414d1a041b1c001f11010449715f4243481a001e1d071c1703004b1a4066785c524570735c51486775421b5c5a4c07504042685a63610816054e19025e75196001477c015165406370195f5547404e4550640103020f1304064863754268676c755f65576e40467e5f0a417a4701026d675d6e73670b1108495a4c6a0b78470b740065645e525a057258425f584a447d4e6759440c11044e7c596d7f4b625f7d04055a47505c4e1d6b5b4107447d7201057d7f0f14084e430457674f7e517d72015172415d027473577c4d615f79535256780911030f4d5e027a797f614165067806505d53777750475e75064257076500460817014e741e7e5078487e7a7c465e7669767153497064605a7376677773550d160148037e18675966787f4c42607a645f577e7b441b460776026b18685d0b110205490060020f70676175654674706671797f41067346677c4e06585e780f15074c57047b40517075415f6364027259674b5b0166407f7340600407770a22047a5d5c52300b3a0a167305067162727516134208312e3133302e3232480350015ae90403626253513635686e556f4e36416456324b796f566c636f477776484f624e56526c4d727073504b4f43654177616848494176795556497273743752737149734a7a786b3247525268377a2f637664626d504f6a73552f79626d38547a4c69586d2f474351696d494b53486833447955726f39515152756c34545350626d6d624b7949565937545671577059455372323646572f59624578507338514f706d317372785455736c30796a434144444d4f34616a654b615753366361496c554b4963797a494e396d52516f715277687939797257476d337a644345337a6a61436f492f5a585233656f65365a42647a64677654636b6b665733356e4d4c6a6a565072564b6433523172756174394e50514150724a5546627859696c4c5a3859707336654d5447666b6649793574666a526c314d4648706b51774c6373374439656378566c41636f374e664f6d2b30654756466c4434744478706771385533595973587645384842502f70666c767a737138316a32524f4d7857437556445442492f684735625462773166456e4249725162762b636144775147696f74554e316d4c4b77734379456f4766706746614251457645672b736a764c4c78704743334c304a5344532f74526169504354553344374e6249306547516651622f5a466f4c36455630775a324d6f583932414c572f5049752f56634663584e70596b356f7966326151416a536971486a2f363276354843644f525551303578754e6171795251625653704654303137655237675255636b4966366c6f447476342b514e4a4670766d74757077707774396a5a5974437a4b56743657726d6e36785837706658456251555434684f3758a201050803108703a201050804108103a20105080510c001a20105081d10cc01a2010408161078a20105080e10af01a201020815")
    proto = MasterTeam_pb2.StartMatch()
    proto.ParseFromString(packet)
    if hasattr(proto.main, 'region_list') and len(proto.main.region_list) > 0:
        proto.main.region_list[0].region = region
        if len(proto.main.region_list) > 1:
            proto.main.region_list[1].region = region
    if hasattr(proto.main, 'client_version'):
        proto.main.client_version.remote_version = client_version
    packet = proto.SerializeToString()
    encrypted_packet = (await aes_encrypt(packet, key, iv)).hex()
    packet_length = len(encrypted_packet) // 2
    hex_length = hex(packet_length)[2:]
    hex_length = hex_length if len(hex_length) > 1 else "0" + hex_length
    reg = str(region).upper() if region else "BD"
    reg_prefix = "031900" if reg == "BD" else ("031400" if reg == "IND" else "031500")
    final_packet = reg_prefix + "0" * (6 - len(hex_length)) + hex_length + encrypted_packet
    writer.write(bytes.fromhex(final_packet))
    await writer.drain()
    log_search(f"BR Search Packet Sent ({packet_length} bytes) | Region: {reg}")


async def has_ssan_zig(n):
    z = (n << 1) & 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    while z >= 0x80:
        out.append((z & 0x7F) | 0x80)
        z >>= 7
    out.append(z)
    return bytes(out)


async def uleb_encode(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        out.append(b)
        if not n:
            break
    return bytes(out)


async def tea_enc(v0, v1, k0, k1, k2, k3):
    s = 0
    for _ in range(_ROUNDS):
        s = (s + _DELTA) & 0xFFFFFFFF
        v0 = (v0 + (((((v1 << 4) & 0xFFFFFFFF) + k0) & 0xFFFFFFFF ^
                      ((v1 + s) & 0xFFFFFFFF) ^
                      (((v1 >> 5) + k1) & 0xFFFFFFFF)))) & 0xFFFFFFFF
        v1 = (v1 + (((((v0 << 4) & 0xFFFFFFFF) + k2) & 0xFFFFFFFF ^
                      ((v0 + s) & 0xFFFFFFFF) ^
                      (((v0 >> 5) + k3) & 0xFFFFFFFF)))) & 0xFFFFFFFF
    return v0, v1


async def tea_dec(v0, v1, k0, k1, k2, k3):
    s = (_DELTA * _ROUNDS) & 0xFFFFFFFF
    for _ in range(_ROUNDS):
        v1 = (v1 - (((((v0 << 4) & 0xFFFFFFFF) + k2) & 0xFFFFFFFF ^
                      ((v0 + s) & 0xFFFFFFFF) ^
                      (((v0 >> 5) + k3) & 0xFFFFFFFF)))) & 0xFFFFFFFF
        v0 = (v0 - (((((v1 << 4) & 0xFFFFFFFF) + k0) & 0xFFFFFFFF ^
                      ((v1 + s) & 0xFFFFFFFF) ^
                      (((v1 >> 5) + k1) & 0xFFFFFFFF)))) & 0xFFFFFFFF
        s = (s - _DELTA) & 0xFFFFFFFF
    return v0, v1


async def tea_cbc_encrypt(padded, key_bytes):
    k0, k1, k2, k3 = (struct.unpack_from("<I", key_bytes, o)[0] for o in (0, 4, 8, 12))
    out = bytearray(len(padded))
    prev_cipher = bytearray(8)
    prev_intermediate = bytearray(8)
    for i in range(0, len(padded), 8):
        xored = bytearray(8)
        for j in range(8):
            xored[j] = padded[i + j] ^ prev_cipher[j]
        e0, e1 = await tea_enc(
            struct.unpack_from("<I", xored, 0)[0],
            struct.unpack_from("<I", xored, 4)[0],
            k0, k1, k2, k3,
        )
        enc = bytearray(8)
        struct.pack_into("<I", enc, 0, e0)
        struct.pack_into("<I", enc, 4, e1)
        for j in range(8):
            out[i + j] = enc[j] ^ prev_intermediate[j]
        prev_cipher[:] = out[i:i + 8]
        prev_intermediate[:] = xored
    return bytes(out)


async def build_padded(content):
    pad_len = (8 - (len(content) + 10) % 8) % 8
    return bytes([pad_len, 0, 0]) + b"\x00" * pad_len + content + b"\x00" * 7


async def encode_header(layout, send_option, cmd, order_id, flags, length, k, v80):
    out = bytearray()
    for code in layout:
        value = {0: send_option, 1: cmd, 2: order_id, 3: flags, 4: length}[code]
        if _FIELD_SIZES[code] == 1:
            out.append((value & 0xFF) ^ k)
        else:
            v = ((value & 0xFFFF) ^ v80) & 0xFFFF
            out.append(v & 0xFF)
            out.append((v >> 8) & 0xFF)
    return bytes(out)


async def crc7_buff(crc, buf):
    c = crc & 0x7F
    for b in buf:
        c = CRC7_TABLE[((2 * (c & 0xFF)) ^ (b & 0xFF)) & 0xFF] & 0x7F
    return c & 0x7F


async def sv_frame(msg_key, layout, send_option, cmd, order_id, flags, content, key, encrypted=True):
    k = key[0]
    v80 = ((k << 8) | k) & 0xFFFF
    body = await tea_cbc_encrypt(await build_padded(content), key) if encrypted else content
    hdr = bytearray([msg_key, 0]) + await encode_header(layout, send_option, cmd, order_id, flags, len(body), k, v80)
    packet = bytearray(hdr + body)
    packet[1] = await crc7_buff(0, bytes(packet[2:])) & 0x7F
    return bytes(packet)


async def build_match_startup_packets(token, udp_key, match_code, account_id, block_val,
                                      server_ip="", region="BD", client_version="1.132.6",
                                      client_version_code="2019121229", access_token="",
                                      mode_id=43, map_id=11):
    token = token.strip()
    udp_key = bytes.fromhex(udp_key)
    match_code = [int(ch) for ch in str(match_code).strip()]

    thunder_jwt = token[:660] if len(token) > 660 else token
    sharma_jwt = token[660:] if len(token) > 660 else ""
    encoded_thunder_jwt = thunder_jwt.encode() if isinstance(thunder_jwt, str) else thunder_jwt
    encoded_sharma_jwt = sharma_jwt.encode() if isinstance(sharma_jwt, str) else sharma_jwt

    garena420 = await has_ssan_zig(len(encoded_thunder_jwt)) + encoded_thunder_jwt

    reg = str(region).upper() if region else "BD"
    csoversea_block = bytes.fromhex(
        "ca0163736f7665727365612e7374726f6e67686f6c642e66726565666972656d6f62696c652e636f6d"
        "3b302e302e302e303b33342e3132362e37362e34353b33342e38372e3137372e31343b33342e38372e"
        "3137302e3233303b33352e3138352e3138332e35370000000000000100000000000000000000000001"
        "00000800000100000000000100a8a2d7bebd8d8bdf110200"
    )

    mid = bytes.fromhex('0000000001000102030101') + await has_ssan_zig(len(reg)) + reg.encode()
    mid += bytes.fromhex('0001030003000004')
    mid += await has_ssan_zig(len(client_version)) + client_version.encode()
    mid += await has_ssan_zig(len(client_version_code)) + client_version_code.encode()
    mid += csoversea_block

    clean_ip = server_ip.split(':')[0] if server_ip else "0.0.0.0"
    mid += await has_ssan_zig(len(clean_ip)) + clean_ip.encode()

    clean_acc_tok = access_token.strip() if access_token else ""
    if clean_acc_tok:
        mid += await has_ssan_zig(len(clean_acc_tok)) + clean_acc_tok.encode()

    mid += await has_ssan_zig(len(encoded_sharma_jwt)) + encoded_sharma_jwt

    tg_garena420 = (
        await uleb_encode(int(account_id)) +
        await uleb_encode(int(block_val)) +
        await uleb_encode(1) +
        await uleb_encode(int(mode_id)) +
        await uleb_encode(int(block_val)) +
        await uleb_encode(int(map_id)) +
        mid
    )

    process = await sv_frame(0x5E, match_code, 2, 447, 0, 1, garena420, udp_key)
    loading = await sv_frame(0x5A, match_code, 2, 448, 1, 1, tg_garena420, udp_key)
    return process.hex(), loading.hex()


async def produce_xor_key(secret_key):
    k = secret_key[0] if secret_key and len(secret_key) > 0 else 10
    return k, ((k << 8) | k) & 0xFFFF


async def parse_layout(layout):
    if isinstance(layout, str):
        return [int(ch) for ch in layout.strip()]
    return list(layout)


async def tea_cbc_decrypt(body, key_bytes):
    k0, k1, k2, k3 = (struct.unpack_from("<I", key_bytes, o)[0] for o in (0, 4, 8, 12))
    out = bytearray(len(body))
    prev_intermediate = bytearray(8)
    prev_cipher = bytearray(8)
    xored = bytearray(8)
    dec = bytearray(8)
    for i in range(0, len(body), 8):
        for j in range(8):
            xored[j] = body[i + j] ^ prev_intermediate[j]
        d0, d1 = await tea_dec(
            struct.unpack_from("<I", xored, 0)[0],
            struct.unpack_from("<I", xored, 4)[0],
            k0, k1, k2, k3
        )
        struct.pack_into("<I", dec, 0, d0)
        struct.pack_into("<I", dec, 4, d1)
        for j in range(8):
            out[i + j] = dec[j] ^ prev_cipher[j]
        prev_cipher[:] = body[i:i + 8]
        prev_intermediate[:] = dec
    return bytes(out)


async def build_hello_packet(text, key, layout):
    data = text.encode("utf-8")
    if len(data) > 25:
        raise ValueError(f"Text is too long ({len(data)} bytes)")
    content = b"\x10\x00\x00\x00" + data + b"\x00" * (29 - 4 - len(data))
    k, v80 = await produce_xor_key(key)
    layout = await parse_layout(layout)
    padded = await build_padded(content)
    enc_body = await tea_cbc_encrypt(padded, key)
    header_bytes = await encode_header(layout, 1, 1, 0, 1, len(enc_body), k, v80)
    packet = bytearray([0x63, 0x00]) + header_bytes + enc_body
    packet[1] = await crc7_buff(0, packet[2:]) & 0x7F
    return bytes(packet).hex()


async def classify(frame):
    cmd = frame["cmd"]
    msg_name = MESSAGE_ID_TO_NAME.get(cmd, f"UNKNOWN_{cmd}")
    if msg_name == "UDP_HELLO":
        return "HELLO"
    if msg_name == "UDP_ACK":
        return "ACK"
    if msg_name == "UDP_PING":
        return "PING"
    if msg_name == "RUDP_JOIN_MATCH":
        return "JOIN_MATCH"
    if msg_name.startswith("RUDP_"):
        return msg_name
    if msg_name.startswith("UDP_"):
        return msg_name
    return "DATA"


async def build_packet(msg_key, layout, send_option, cmd, order_id, flags, content, key, encrypted=True):
    k = key[0]
    v80 = ((k << 8) | k) & 0xFFFF
    body = await tea_cbc_encrypt(await build_padded(content), key) if encrypted else content
    hdr = bytearray([msg_key, 0])
    for code in layout:
        value = {0: send_option, 1: cmd, 2: order_id, 3: flags, 4: len(body)}[code]
        if _FIELD_SIZES[code] == 1:
            hdr.append((value & 0xFF) ^ k)
        else:
            v = ((value & 0xFFFF) ^ v80) & 0xFFFF
            hdr.append(v & 0xFF)
            hdr.append((v >> 8) & 0xFF)
    packet = bytearray(hdr + body)
    packet[1] = await crc7_buff(0, bytes(packet[2:])) & 0x7F
    return bytes(packet)


async def layouts_from_mask(mask):
    ru = [int(c) for c in str(mask).strip()]
    nr = [c for c in ru if c != 2]
    return ru, nr


async def reply_for(frame, key, mask, ack_key=0x68, ping_key=0x6D, hello_key=0x5B, ack_style="short"):
    ru, nr = await layouts_from_mask(mask)
    typ = await classify(frame)
    if typ == "HELLO":
        if ack_style == "echo":
            content = frame["content"] if frame["content"] else b"\x10\x00\x00\x00"
            return typ, await build_packet(hello_key, nr, 1, 1, None, 1, content, key)
        return typ, await build_packet(ack_key, nr, 0, 2, None, 1, b"\x01\x00", key)
    if typ == "ACK":
        content = frame["content"] if frame["content"] else b"\x01\x00"
        return typ, await build_packet(ack_key, nr, 0, 2, None, 1, content, key)
    if typ == "PING":
        c = frame["content"]
        counter = c[:4] if len(c) >= 4 else c
        return typ, await build_packet(ping_key, nr, 0, 3, None, 0, counter + b"\x00\x00\x00", key, encrypted=False)
    if typ == "JOIN_MATCH":
        return typ, await build_packet(ack_key, nr, 0, 2, None, 1, b"\x02\x00", key)
    return typ, None


async def keepalive_ping(sock, ip, port, key_bytes, mask, stop_event):
    nr = (await layouts_from_mask(mask))[1]
    ping_keys = [0x66, 0x6D, 0x69, 0x6C, 0x6B, 0x6E, 0x6F, 0x70]
    loop = asyncio.get_event_loop()
    i = 0
    while not stop_event.is_set():
        pk = ping_keys[i % len(ping_keys)]
        counter = int(time.time() * 1000) & 0xFFFFFFFF
        pkt = await build_packet(pk, nr, 0, 3, None, 0, struct.pack("<I", counter) + b"\x00\x00\x00", key_bytes, encrypted=False)
        try:
            await loop.sock_sendto(sock, pkt, (ip, port))
        except Exception:
            pass
        i += 1
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=3.0)
        except asyncio.TimeoutError:
            pass


async def try_header(buf, layout, k, v80):
    off = 2
    out = {}
    for code in layout:
        size = _FIELD_SIZES[code]
        if off + size > len(buf):
            return None
        out[_FIELD_NAMES[code]] = (buf[off] ^ k) if size == 1 else ((buf[off] | (buf[off + 1] << 8)) ^ v80) & 0xFFFF
        off += size
    out["headerLen"] = off
    return out


async def oicq_unpad(padded):
    if not padded or len(padded) < 8:
        return None
    if not all(padded[-1 - i] == 0 for i in range(7)):
        return None
    pad_len = padded[0] & 0x07
    s = 3 + pad_len
    e = len(padded) - 7
    return padded[s:e] if s < e else b""


async def decode_packet(packet, key, mask=None):
    data = bytes(packet) if isinstance(packet, bytes) else bytes.fromhex(packet)
    if len(data) < 8:
        return None
    k = key[0]
    v80 = ((k << 8) | k) & 0xFFFF
    crc_ok = (data[1] & 0x7F) == await crc7_buff(0, data[2:])
    candidates = []
    if mask:
        ru, nr = await layouts_from_mask(mask)
        layouts = [("RUDP", ru), ("nonRUDP", nr)]
    else:
        layouts = [("RUDP", list(p)) for p in itertools.permutations([0, 1, 2, 3, 4])]
        layouts += [("nonRUDP", list(p)) for p in itertools.permutations([0, 1, 3, 4])]
    for kind, layout in layouts:
        f = await try_header(data, layout, k, v80)
        if not f:
            continue
        if f["flags"] > 7 or f["sendOption"] > 7:
            continue
        if f["length"] != len(data) - f["headerLen"]:
            continue
        body = data[f["headerLen"]:f["headerLen"] + f["length"]]
        content = None
        padded = None
        if f["flags"] & 1:
            if len(body) < 8 or len(body) % 8 != 0:
                continue
            padded = await tea_cbc_decrypt(body, key)
            content = await oicq_unpad(padded)
            if content is None:
                continue
        else:
            content = body
        score = (1 if crc_ok else 0) + (1 if content is not None else 0)
        candidates.append({
            "kind": kind, "layout": layout, "headerLen": f["headerLen"],
            "msgKey": data[0], "cmd": f["cmd"], "flags": f["flags"],
            "sendOption": f["sendOption"], "orderId": f.get("orderId"),
            "length": f["length"], "content": content, "crcOk": crc_ok,
            "padded": padded, "score": score, "total": len(data),
        })
    if not candidates:
        return None
    candidates.sort(key=lambda c: (c["kind"] == "RUDP" or c["kind"] == "nonRUDP", c["score"]), reverse=True)
    return candidates[0]


# ============================================================
# play_game — UDP MATCH
# ============================================================
async def send_anti_afk_movement(sock, server_addr, udp_key_bytes, match_code, account_id):
    try:
        nr = (await layouts_from_mask(match_code))[1]
        rand_x = random.randint(-100, 100)
        rand_y = random.randint(-50, 50)
        rand_z = random.randint(-100, 100)
        ts = int(time.time() * 1000) & 0xFFFFFFFF
        try:
            player_id = int(account_id)
        except Exception:
            player_id = 0
        body = struct.pack("<IIiiiH", player_id & 0xFFFFFFFF, ts, rand_x, rand_y, rand_z, 1)
        pkt = await build_packet(
            0x6B, nr, 0, 2001, None, 0,
            body, udp_key_bytes, encrypted=False
        )
        loop = asyncio.get_event_loop()
        await loop.sock_sendto(sock, pkt, server_addr)
        return True
    except Exception:
        return False


async def send_anti_afk_fire(sock, server_addr, udp_key_bytes, match_code, account_id):
    try:
        nr = (await layouts_from_mask(match_code))[1]
        try:
            player_id = int(account_id)
        except Exception:
            player_id = 0
        ts = int(time.time() * 1000) & 0xFFFFFFFF
        weapon_id = random.choice([101, 102, 103, 201, 202])
        fire_body = struct.pack("<IIHB", player_id & 0xFFFFFFFF, ts, weapon_id, 1)
        fire_pkt = await build_packet(
            0x68, nr, 0, 104, None, 0,
            fire_body, udp_key_bytes, encrypted=False
        )
        loop = asyncio.get_event_loop()
        await loop.sock_sendto(sock, fire_pkt, server_addr)
        # 🛡️ Jitter fire-stop (timing-only bypass)
        await asyncio.sleep(random.uniform(0.15, 0.30))
        stop_body = struct.pack("<IIHB", player_id & 0xFFFFFFFF, ts + 200, weapon_id, 0)
        stop_pkt = await build_packet(
            0x68, nr, 0, 105, None, 0,
            stop_body, udp_key_bytes, encrypted=False
        )
        await loop.sock_sendto(sock, stop_pkt, server_addr)
        return True
    except Exception:
        return False


async def anti_afk_worker(sock, resolved_ip, port, udp_key_bytes, match_code,
                          account_id, stop_event, match_index):
    loop = asyncio.get_event_loop()
    server_addr = (resolved_ip, port)
    fire_count = 0
    move_count = 0
    try:
        await asyncio.sleep(random.uniform(2.0, 3.0))
        while not stop_event.is_set():
            try:
                roll = random.random()
                if roll < ANTI_AFK_FIRE_CHANCE:
                    ok = await send_anti_afk_fire(
                        sock, server_addr, udp_key_bytes, match_code, account_id
                    )
                    if ok:
                        fire_count += 1
                    if random.random() < 0.4:
                        await send_anti_afk_movement(
                            sock, server_addr, udp_key_bytes, match_code, account_id
                        )
                        move_count += 1
                else:
                    ok = await send_anti_afk_movement(
                        sock, server_addr, udp_key_bytes, match_code, account_id
                    )
                    if ok:
                        move_count += 1
                wait_time = random.uniform(ANTI_AFK_MIN_INTERVAL, ANTI_AFK_MAX_INTERVAL)
                wait_time = wait_time * random.uniform(0.8, 1.2)
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=wait_time)
                    break
                except asyncio.TimeoutError:
                    pass
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(1.0)
    except asyncio.CancelledError:
        pass
    finally:
        try:
            if fire_count + move_count > 0:
                log_afk(
                    f"[🎮] Anti-AFK #{match_index} | Fires: {fire_count} | Moves: {move_count} | UID: {str(account_id)}"
                )
        except Exception:
            pass




async def play_game(server_ip_port, thunder, sharma, udp_key, match_code,
                    account_id, player_region, client_version, key, iv,
                    match_index: int, mode: str = "LW"):
    anti_afk_task = None
    anti_afk_stop = asyncio.Event()
    anti_afk_started = False
    end_reason = "cancelled/unknown"
    match_start_time = time.time()
    ping_task = None
    sock = None
    ping_stop = asyncio.Event()
    uid_str = str(account_id)
    completed_cleanly = False

    try:
        ip, port = server_ip_port.split(":")
        port = int(port)
        resolved_ip = await resolve_host_cloudflare(ip)

        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        optimize_udp_socket(sock)
        sock.setblocking(False)

        udp_key_bytes = bytes.fromhex(udp_key)
        if mode == "BR":
            try:
                sock.bind(('0.0.0.0', 0))
            except Exception:
                pass
            await asyncio.sleep(random.uniform(0.05, 0.45))
        hello_packet = await build_hello_packet(f"{account_id}_2585", udp_key_bytes, match_code)
        await loop.sock_sendto(sock, bytes.fromhex(hello_packet), (resolved_ip, port))

        ack_state = "waiting_for_hello_reply"
        thunder_sent = False
        sharma_sent = False
        join_match_received = False
        local_closed = False
        send_lock = asyncio.Lock()

        ping_task = asyncio.create_task(
            keepalive_ping(sock, resolved_ip, port, udp_key_bytes, match_code, ping_stop)
        )
        last_activity = time.time()
        MAX_IDLE_BEFORE_HELLO_RESEND = 7.0

        log_match(f"[MATCH #{match_index}] UDP connected -> {server_ip_port} | {mode}")

        async def start_anti_afk_once():
            nonlocal anti_afk_task, anti_afk_started
            if anti_afk_started:
                return
            anti_afk_started = True
            anti_afk_task = asyncio.create_task(
                anti_afk_worker(sock, resolved_ip, port, udp_key_bytes, match_code,
                                account_id, anti_afk_stop, match_index)
            )
            log_afk(f"Anti-AFK worker started | Match #{match_index}")

        async def send_thunder_sharma_inline():
            nonlocal ack_state, thunder_sent, sharma_sent
            if thunder_sent:
                return
            async with send_lock:
                if thunder_sent:
                    return
                try:
                    if HUMAN_MODE and mode != "BR":
                        await human_delay(base=0.15, variance=0.08)
                    await loop.sock_sendto(sock, bytes.fromhex(thunder), (resolved_ip, port))
                    thunder_sent = True
                    await asyncio.sleep(random.uniform(0.2, 0.4) if mode == "BR" else (0.15 if HUMAN_MODE else 0.1))
                    prepare_ack = await build_packet(
                        0x68, (await layouts_from_mask(match_code))[1],
                        0, 2, None, 1, b"\x01\x00", udp_key_bytes
                    )
                    await loop.sock_sendto(sock, prepare_ack, (resolved_ip, port))
                    await asyncio.sleep(random.uniform(0.3, 0.5) if mode == "BR" else (0.25 if HUMAN_MODE else 0.2))
                    await loop.sock_sendto(sock, bytes.fromhex(sharma), (resolved_ip, port))
                    sharma_sent = True
                    ack_state = "thunder_sharma_sent"
                    log_match(f"[MATCH #{match_index}] Thunder+Sharma sent OK")
                    if mode == "BR":
                        await start_anti_afk_once()
                except Exception as e:
                    log_err(f"[MATCH #{match_index}] send error: {e}")

        while not local_closed:
            if time.time() - match_start_time > MAX_MATCH_DURATION:
                end_reason = f"max duration {MAX_MATCH_DURATION}s"
                if mode == "BR":
                    completed_cleanly = True
                break
            try:
                response, server_addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 65535), timeout=(2.0 if mode == "BR" else 1.5)
                )
                if response:
                    last_activity = time.time()
                    frame = await decode_packet(response, udp_key_bytes, match_code)
                    if frame:
                        ptype = await classify(frame)

                        if frame['cmd'] in [103, 107]:
                            log_match(f"[MATCH #{match_index}] Server ended match (cmd {frame['cmd']})")
                            end_reason = f"server sent end cmd {frame['cmd']}"
                            completed_cleanly = True
                            local_closed = True
                            continue

                        if frame['cmd'] == 101:
                            try:
                                ack_pkt = await build_packet(
                                    0x68, (await layouts_from_mask(match_code))[1],
                                    0, 2, None, 1, b"\x01\x00", udp_key_bytes
                                )
                                await loop.sock_sendto(sock, ack_pkt, server_addr)
                            except Exception:
                                pass
                            continue

                        if ptype in ["ACK", "PING", "HELLO", "JOIN_MATCH"]:
                            if ptype == "HELLO" and ack_state == "waiting_for_hello_reply":
                                typ, reply = await reply_for(
                                    frame, udp_key_bytes, match_code, ack_style="short"
                                )
                                if reply:
                                    await loop.sock_sendto(sock, reply, server_addr)
                                ack_state = "ack_sent_waiting"
                            elif ptype == "ACK":
                                if ack_state == "waiting_for_hello_reply":
                                    typ, reply = await reply_for(frame, udp_key_bytes, match_code)
                                    if reply:
                                        await loop.sock_sendto(sock, reply, server_addr)
                                    ack_state = "ready_to_send_thunder"
                                elif ack_state == "ack_sent_waiting":
                                    ack_state = "ready_to_send_thunder"
                                else:
                                    typ, reply = await reply_for(frame, udp_key_bytes, match_code)
                                    if reply:
                                        await loop.sock_sendto(sock, reply, server_addr)
                            elif ptype == "PING":
                                typ, reply = await reply_for(frame, udp_key_bytes, match_code)
                                if reply:
                                    await loop.sock_sendto(sock, reply, server_addr)
                            elif ptype == "JOIN_MATCH" and not join_match_received:
                                typ, reply = await reply_for(frame, udp_key_bytes, match_code)
                                if reply:
                                    await loop.sock_sendto(sock, reply, server_addr)
                                    join_match_received = True
            except asyncio.TimeoutError:
                if ack_state == "ready_to_send_thunder" and not thunder_sent:
                    await send_thunder_sharma_inline()
                elif ack_state == "waiting_for_hello_reply":
                    if (time.time() - last_activity) > MAX_IDLE_BEFORE_HELLO_RESEND:
                        try:
                            pkt = await build_hello_packet(
                                f"{account_id}_2585", udp_key_bytes, match_code
                            )
                            await loop.sock_sendto(sock, bytes.fromhex(pkt), (resolved_ip, port))
                        except Exception:
                            pass
                        last_activity = time.time()
                    if (time.time() - match_start_time) > 25.0:
                        log_warn(f"[MATCH #{match_index}] Handshake timeout")
                        end_reason = "handshake timeout"
                        break
                elif ack_state == "thunder_sharma_sent":
                    if (time.time() - last_activity) > (BR_MATCH_IDLE_TIMEOUT if mode == "BR" else MATCH_IDLE_TIMEOUT):
                        log_match(f"[MATCH #{match_index}] Finished naturally")
                        end_reason = f"no server packets for {int(time.time() - last_activity)}s (idle limit {int(MATCH_IDLE_TIMEOUT)}s)"
                        completed_cleanly = True
                        break
                continue
            except BlockingIOError:
                await asyncio.sleep(0.05)
            except OSError:
                await asyncio.sleep(0.5)
                continue
            except Exception:
                await asyncio.sleep(0.5)
                continue

            if ack_state == "ready_to_send_thunder" and not thunder_sent:
                await send_thunder_sharma_inline()

        return f"match #{match_index} finished"
    except Exception as e:
        log_err(f"[MATCH #{match_index}] error: {e}")
        end_reason = f"error: {e}"
        return f"match #{match_index} error"
    finally:
        log_match(f"[MATCH #{match_index}] [{mode}] ENDED after {int(time.time() - match_start_time)}s | reason: {end_reason} | UID {uid_str}")
        if completed_cleanly:
            try:
                bot_state.increment_match(uid_str)
            except Exception:
                pass
            try:
                async def _post_match_refresh(u):
                    await asyncio.sleep(2.0)
                    await refresh_account_profile(u)
                asyncio.create_task(_post_match_refresh(uid_str))
            except Exception:
                pass
        anti_afk_stop.set()
        if anti_afk_task:
            try:
                await asyncio.wait_for(anti_afk_task, timeout=2.0)
            except BaseException:
                anti_afk_task.cancel()
        ping_stop.set()
        if ping_task:
            ping_task.cancel()
            try:
                await ping_task
            except asyncio.CancelledError:
                pass
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        remaining = await _dec_match(uid_str)
        total = await _get_total_match_count()
        log_info(
            f"[MATCH #{match_index}] Closed | UID active: {remaining} | Total active: {total}"
        )
        try:
            bot_state.update_status(uid_str, "IN_MATCH" if remaining > 0 else "ONLINE", remaining)
        except Exception:
            pass


# ============================================================
# functional_lone_wolf — TCP + Match handler
# ============================================================
async def functional_lone_wolf(addrs, starter_packet, account_region, client_version,
                                key, iv, account_id="", account_data=None,
                                max_reconnects=10):
    """
    Per-account TCP gateway + match handler.

    Mode is decided PER ACCOUNT from that account's own level (bot_state.get_account_level):
        level < LEVEL_THRESHOLD  -> BR        (1 concurrent match)
        level >= LEVEL_THRESHOLD -> LONE WOLF (up to 15 concurrent matches)
    The mode is re-evaluated continuously inside the inner loop. On a change the old
    mode's UDP matches are cancelled, all per-connection search state is reset and the
    gateway socket is rebuilt, so nothing from the old mode can block or leak into the new one.
    """
    reconnects = 0
    ip, port = addrs.split(":")
    play_matches: List[asyncio.Task] = []
    no_response_count = 0
    search_attempts = 0
    last_start_time = 0.0
    uid_str = str(account_id)

    consecutive_parse_failures = 0

    current_token = starter_packet
    current_key = key
    current_iv = iv
    current_account_data = account_data

    forced_region = FORCE_REGION

    async def _stop_all_matches(reason: str):
        """Cancel every running UDP match of this account and wait for them to unwind."""
        pending = [m for m in play_matches if not m.done()]
        for m in pending:
            m.cancel()
        if pending:
            log_warn(f"[{uid_str}] Stopping {len(pending)} running match(es): {reason}")
            await asyncio.gather(*pending, return_exceptions=True)
        play_matches.clear()

    try:
        while True:
            writer = None
            gateway_ping_task = None
            try:
                # ---------- pause handling (dashboard) ----------
                while bot_state.is_paused(uid_str):
                    try:
                        bot_state.update_status(uid_str, "PAUSED", 0)
                    except Exception:
                        pass
                    await asyncio.sleep(1.0)

                # ---------- decide mode for THIS connection ----------
                conn_mode, conn_level = get_current_mode(uid_str)
                mode_tag = "BR" if conn_mode == "BR" else "LW"
                mode_cap = max_concurrent_for(uid_str)
                log_info(f"[{uid_str}] Mode: {conn_mode} (Lvl {conn_level}) | max parallel matches: {mode_cap}")

                if current_account_data:
                    fresh = None
                    if current_account_data.get('auth_type') == 'guest' and current_account_data.get('auth_uid'):
                        fresh = cache_get(str(current_account_data['auth_uid']))
                    elif current_account_data.get('auth_type') == 'token' and current_account_data.get('auth_token'):
                        fresh = cache_get(f"tok_{current_account_data['auth_token'][:20]}")

                    if fresh:
                        current_account_data = fresh
                        current_key = fresh['aes_ak']
                        current_iv = fresh['iv_i']
                        current_token = await build_tcp_startup_packet(
                            fresh['account_id'],
                            fresh['token'],
                            fresh['server_time'],
                            current_key,
                            current_iv,
                            region=forced_region,
                            typ='OnLine'
                        )
                    else:
                        log_warn(f"Cache miss for {uid_str} - re-login needed")
                        try:
                            if current_account_data.get('auth_uid'):
                                cache_invalidate(str(current_account_data['auth_uid']))
                            if current_account_data.get('auth_token'):
                                cache_invalidate(f"tok_{current_account_data['auth_token'][:20]}")
                        except Exception:
                            pass
                        raise ConnectionError("Cache expired, triggering fresh login")

                resolved_ip = await resolve_host_cloudflare(ip)
                reader, writer = await asyncio.open_connection(resolved_ip, int(port))
                bot_state.register_writer(uid_str, writer)

                raw_sock = writer.get_extra_info('socket')
                if raw_sock:
                    optimize_tcp_socket(raw_sock)

                if conn_mode == "BR":
                    await asyncio.sleep(random.uniform(0.05, 0.45))
                writer.write(bytes.fromhex(current_token))
                await writer.drain()

                try:
                    init_ka = await send_keep_alive(forced_region)
                    if init_ka and writer and not writer.is_closing():
                        writer.write(init_ka)
                        await asyncio.wait_for(writer.drain(), timeout=3)
                except Exception:
                    pass

                async def func_gateway_keepalive(_w=writer):
                    ka_bytes = await send_keep_alive(forced_region)
                    while True:
                        await asyncio.sleep(random.uniform(4.0, 6.0))
                        try:
                            if _w and not _w.is_closing():
                                _w.write(ka_bytes)
                                await _w.drain()
                            else:
                                break
                        except Exception:
                            break

                gateway_ping_task = asyncio.create_task(func_gateway_keepalive())

                log_net(f"TCP connected | UID: {uid_str} | Region: {forced_region} | Mode: {conn_mode}")
                reconnects = 0
                no_response_count = 0
                last_start_time = 0.0
                search_attempts = 0
                br_had_match = False

                async def send_start_match():
                    nonlocal search_attempts, last_start_time
                    # hard concurrency cap (mode-aware, re-read every time)
                    play_matches[:] = [m for m in play_matches if not m.done()]
                    if len(play_matches) >= max_concurrent_for(uid_str):
                        last_start_time = asyncio.get_running_loop().time()
                        return
                    search_attempts += 1
                    try:
                        if conn_mode == "BR":
                            await human_delay(base=0.3, variance=0.2)
                        elif HUMAN_MODE:
                            await human_delay(base=1.2, variance=0.6)
                        else:
                            await asyncio.sleep(random.uniform(0.3, 0.6))
                        if conn_mode == "BR":
                            await start_game_battle_royale(
                                forced_region, client_version, writer,
                                current_key, current_iv
                            )
                        else:
                            await start_game_lone_wolf(
                                forced_region, client_version, writer,
                                current_key, current_iv
                            )
                        if HUMAN_MODE and conn_mode != "BR":
                            await human_jitter()
                        active = await _get_match_count(uid_str)
                        try:
                            bot_state.update_status(uid_str, f"SEARCHING ({mode_tag})", active)
                        except Exception:
                            pass
                    except Exception as e:
                        log_err(f"StartMatch error: {e}")
                    last_start_time = asyncio.get_running_loop().time()

                await send_start_match()

                while True:
                    play_matches[:] = [m for m in play_matches if not m.done()]

                    # ---------- BR: match finished -> drop this gateway session, start a fresh one ----------
                    if conn_mode == "BR" and br_had_match and not play_matches:
                        log_info(f"[{uid_str}] BR match concluded -> fresh gateway session in ~{BR_NEW_MATCH_DELAY}s")
                        await asyncio.sleep(max(0.5, BR_NEW_MATCH_DELAY + random.uniform(-1.5, 1.5)))
                        reconnects = 0
                        break

                    # ---------- pause ----------
                    if bot_state.is_paused(uid_str):
                        try:
                            bot_state.update_status(uid_str, "PAUSED", 0)
                        except Exception:
                            pass
                        await _stop_all_matches("paused")
                        break

                    # ---------- LIVE MODE SWITCH CHECK (this account only) ----------
                    new_mode, new_level = get_current_mode(uid_str)
                    if new_mode != conn_mode:
                        log_ok(
                            f"[{uid_str}] LEVEL {new_level} reached -> switching "
                            f"{conn_mode} -> {new_mode}"
                        )
                        try:
                            bot_state.log(
                                f"🔀 UID {uid_str}: mode switch {conn_mode} -> {new_mode} (Lvl {new_level})",
                                "success", uid_str
                            )
                        except Exception:
                            pass
                        # Old-mode matches must not block the new mode
                        await _stop_all_matches(f"mode switch {conn_mode}->{new_mode}")
                        consecutive_parse_failures = 0
                        no_response_count = 0
                        last_start_time = 0.0
                        search_attempts = 0
                        break  # rebuild the gateway connection in the new mode

                    active_count = await _get_match_count(uid_str)
                    try:
                        bot_state.update_status(
                            uid_str,
                            "ONLINE" if active_count == 0 else "IN_MATCH",
                            active_count
                        )
                    except Exception:
                        pass

                    now = asyncio.get_running_loop().time()
                    if conn_mode == "BR":
                        current_interval = BR_START_MATCH_INTERVAL
                    elif HUMAN_MODE:
                        current_interval = random.uniform(START_MATCH_INTERVAL_MIN, START_MATCH_INTERVAL_MAX)
                    else:
                        current_interval = START_MATCH_INTERVAL
                    can_search = len(play_matches) < max_concurrent_for(uid_str)
                    if can_search and now - last_start_time >= current_interval:
                        await send_start_match()

                    try:
                        data = await asyncio.wait_for(reader.read(8192), timeout=0.5)
                    except asyncio.TimeoutError:
                        no_response_count += 1
                        if not can_search:
                            # at the match cap on purpose: silence is expected
                            no_response_count = 0
                        elif no_response_count > 80:
                            log_warn(f"Gateway silent ({uid_str}). Reconnecting...")
                            raise ConnectionError("Gateway idle timeout")
                        continue

                    if not data:
                        raise ConnectionError("Connection closed by server")

                    hex_data = data.hex()
                    packet_length = len(data)
                    no_response_count = 0

                    if hex_data.startswith("0300") and 10 < packet_length < 30:
                        log_info("Match starting, please wait...")
                        continue

                    if hex_data.startswith("0300") and packet_length >= 300:
                        log_match("=" * 50)
                        log_match(f"MATCH FOUND! UID: {uid_str} | {conn_mode}")
                        log_match("=" * 50)

                        # cap reached between search and answer -> do not exceed the limit
                        play_matches[:] = [m for m in play_matches if not m.done()]
                        if len(play_matches) >= max_concurrent_for(uid_str):
                            log_warn(f"[{uid_str}] Match cap ({max_concurrent_for(uid_str)}) reached - ignoring found match")
                            continue

                        try:
                            res = json.loads(await decode_protobuf(hex_data[10:]))
                            token = None
                            udp_key = None
                            match_code = None
                            server_ip_port = None
                            match_account_id = None
                            block_val = None

                            if '42' in res and 'data' in res['42']:
                                match_code = res['42']['data']
                            if '5' in res and 'data' in res['5']:
                                res_field5 = res['5']['data']
                                server_ip_port = res_field5.get('2', {}).get('data')
                                udp_key = res_field5.get('3', {}).get('data')
                                token = res_field5.get('4', {}).get('data')
                                if '42' in res_field5:
                                    match_code = res_field5['42']['data']
                            if '1' in res and 'data' in res['1']:
                                match_account_id = res['1']['data']
                            if '5' in res and 'data' in res['5']:
                                block_val = res['5']['data'].get('1', {}).get('data')

                            effective_acc_id = match_account_id or account_id or "BD_BOT"

                            if token and udp_key and match_code and server_ip_port:
                                acc_tok = ""
                                if current_account_data:
                                    acc_tok = current_account_data.get('access_token', '') or ""
                                m_mode_id, m_map_id = startup_params_for_mode(conn_mode)
                                thunder, sharma = await build_match_startup_packets(
                                    token, udp_key, match_code, effective_acc_id, block_val or 0,
                                    server_ip=server_ip_port,
                                    region=forced_region,
                                    client_version=client_version,
                                    access_token=acc_tok,
                                    mode_id=m_mode_id,
                                    map_id=m_map_id
                                )

                                match_index = await _inc_match(uid_str)
                                total = await _get_total_match_count()
                                log_match(f"Match #{match_index} [{mode_tag}] -> UDP starting -> {server_ip_port}")
                                try:
                                    bot_state.increment_match_started()
                                except Exception:
                                    pass

                                new_match = asyncio.create_task(
                                    play_game(
                                        server_ip_port,
                                        thunder,
                                        sharma,
                                        udp_key,
                                        match_code,
                                        effective_acc_id,
                                        forced_region,
                                        client_version,
                                        current_key,
                                        current_iv,
                                        match_index=match_index,
                                        mode=conn_mode
                                    )
                                )
                                play_matches.append(new_match)

                                consecutive_parse_failures = 0

                                if conn_mode == "BR":
                                    # BR: keep the gateway TCP session alive while the match runs
                                    # (closing it drops the account to lobby/online without playing)
                                    log_ok(f"[{uid_str}] BR match #{match_index} running - gateway held open")
                                    last_start_time = asyncio.get_running_loop().time()
                                    br_had_match = True
                                    continue

                                try:
                                    bot_state.unregister_writer(uid_str, writer)
                                    writer.close()
                                    await writer.wait_closed()
                                except Exception:
                                    pass

                                log_info(f"Offline {NEW_MATCH_DELAY}s -> reload token -> new StartMatch")
                                await asyncio.sleep(NEW_MATCH_DELAY)
                                reconnects = 0
                                break

                            else:
                                consecutive_parse_failures += 1
                                log_warn(
                                    f"Non-match big packet "
                                    f"(#{consecutive_parse_failures}/{int(MAX_CONSECUTIVE_PARSE_FAILURES)}) "
                                    f"-> reconnecting"
                                )

                                if consecutive_parse_failures >= MAX_CONSECUTIVE_PARSE_FAILURES:
                                    log_err(
                                        f"{int(MAX_CONSECUTIVE_PARSE_FAILURES)}x parse failures "
                                        f"-> invalidating cache"
                                    )
                                    if current_account_data:
                                        try:
                                            if current_account_data.get('auth_uid'):
                                                cache_invalidate(str(current_account_data['auth_uid']))
                                            if current_account_data.get('auth_token'):
                                                cache_invalidate(f"tok_{current_account_data['auth_token'][:20]}")
                                        except Exception:
                                            pass
                                    consecutive_parse_failures = 0

                                try:
                                    writer.close()
                                    await writer.wait_closed()
                                except Exception:
                                    pass
                                await asyncio.sleep(NON_MATCH_RECONNECT_DELAY)
                                break

                        except Exception as e:
                            log_err(f"Match packet error: {e}")
                            consecutive_parse_failures += 1
                            if consecutive_parse_failures >= MAX_CONSECUTIVE_PARSE_FAILURES:
                                if current_account_data:
                                    try:
                                        if current_account_data.get('auth_uid'):
                                            cache_invalidate(str(current_account_data['auth_uid']))
                                        if current_account_data.get('auth_token'):
                                            cache_invalidate(f"tok_{current_account_data['auth_token'][:20]}")
                                    except Exception:
                                        pass
                                consecutive_parse_failures = 0
                            try:
                                writer.close()
                                await writer.wait_closed()
                            except Exception:
                                pass
                            await asyncio.sleep(NON_MATCH_RECONNECT_DELAY)
                            break

                    if 30 <= packet_length <= 40:
                        continue

                # inner loop left (match found / mode switch / pause / parse failure):
                # tidy this connection before the outer loop rebuilds it
                if gateway_ping_task:
                    gateway_ping_task.cancel()
                    gateway_ping_task = None
                try:
                    bot_state.unregister_writer(uid_str, writer)
                    if writer and not writer.is_closing():
                        writer.close()
                        await writer.wait_closed()
                except Exception:
                    pass

            except asyncio.CancelledError:
                log_warn(f"Cancelled - stopping {len(play_matches)} UDP matches")
                if gateway_ping_task:
                    gateway_ping_task.cancel()
                bot_state.unregister_writer(uid_str, writer)
                await _stop_all_matches("worker cancelled")
                raise
            except Exception as e:
                log_err(f"TCP state ({uid_str}): {e}")

                play_matches[:] = [m for m in play_matches if not m.done()]

                if gateway_ping_task:
                    gateway_ping_task.cancel()
                    gateway_ping_task = None

                if writer:
                    try:
                        bot_state.unregister_writer(uid_str, writer)
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

                if "Cache expired" in str(e):
                    log_warn(f"Triggering re-login for {uid_str}")
                    break

                reconnects += 1
                if reconnects > max_reconnects:
                    log_err("Max reconnects reached, retrying...")
                    reconnects = 0
                    await asyncio.sleep(3)
                    continue

                await asyncio.sleep(min(reconnects, 2))

    except asyncio.CancelledError:
        log_warn(f"Outer cancelled. {len(play_matches)} UDP matches still running.")
        await _stop_all_matches("outer cancelled")
        raise


async def safe_close_writer(writer):
    if writer is None:
        return
    try:
        if not writer.is_closing():
            writer.close()
        await writer.wait_closed()
    except Exception:
        pass


async def informational(addrs, starter_packet, key, iv, region="BD", account_id="", max_reconnects=3):
    uid_str = str(account_id)
    reconnects = 0
    ip, port = addrs.split(":")
    while True:
        while uid_str and bot_state.is_paused(uid_str):
            await asyncio.sleep(1.0)

        writer = None
        ping_task = None
        try:
            resolved_ip = await resolve_host_cloudflare(ip)
            reader, writer = await asyncio.open_connection(resolved_ip, int(port))
            if uid_str:
                bot_state.register_writer(uid_str, writer)

            raw_sock = writer.get_extra_info('socket')
            if raw_sock:
                optimize_tcp_socket(raw_sock)

            writer.write(bytes.fromhex(starter_packet))
            await writer.drain()
            reconnects = 0

            try:
                init_ka = await send_keep_alive(region)
                if init_ka and writer and not writer.is_closing():
                    writer.write(init_ka)
                    await asyncio.wait_for(writer.drain(), timeout=3)
            except Exception:
                pass

            async def info_keepalive():
                ka_bytes = await send_keep_alive(region)
                while True:
                    await asyncio.sleep(random.uniform(4.2, 6.2))
                    try:
                        if writer and not writer.is_closing():
                            writer.write(ka_bytes)
                            await writer.drain()
                    except Exception:
                        break

            ping_task = asyncio.create_task(info_keepalive())

            while True:
                if uid_str and bot_state.is_paused(uid_str):
                    if ping_task:
                        ping_task.cancel()
                    if uid_str:
                        bot_state.unregister_writer(uid_str, writer)
                    await safe_close_writer(writer)
                    writer = None
                    while bot_state.is_paused(uid_str):
                        await asyncio.sleep(1.0)
                    break

                try:
                    data = await asyncio.wait_for(reader.read(8192), timeout=1.0)
                except asyncio.TimeoutError:
                    continue

                if not data:
                    raise ConnectionError("Connection closed")
        except asyncio.CancelledError:
            if ping_task:
                ping_task.cancel()
            if uid_str:
                bot_state.unregister_writer(uid_str, writer)
            await safe_close_writer(writer)
            raise
        except Exception:
            if ping_task:
                ping_task.cancel()
            if uid_str:
                bot_state.unregister_writer(uid_str, writer)
            await safe_close_writer(writer)
            reconnects += 1
            if reconnects > max_reconnects:
                await asyncio.sleep(3)
                reconnects = 0
            else:
                await asyncio.sleep(1)


# ==================== ACCOUNT PROCESSORS ====================
def _register_credentials(account_data: Dict):
    try:
        acc_id = str(account_data['account_id'])
        bot_state.account_credentials[acc_id] = account_data
        if account_data.get('auth_uid'):
            bot_state.account_credentials[str(account_data['auth_uid'])] = account_data
        if account_data.get('auth_token'):
            bot_state.account_credentials[f"tok_{account_data['auth_token'][:20]}"] = account_data
    except Exception:
        pass


async def refresh_account_profile(account_data_or_uid: Any):
    try:
        if isinstance(account_data_or_uid, str):
            uid = str(account_data_or_uid)
            account_data = bot_state.account_credentials.get(uid)
        else:
            account_data = account_data_or_uid
            uid = str(account_data.get('account_id'))

        if not account_data:
            return

        url = account_data.get('server_url')
        token = account_data.get('token')
        release_version = account_data.get('release_version')
        payload = account_data.get('login_payload_data')

        if not (url and token and release_version and payload):
            return

        res = await send_getlogin(payload, url, token, release_version)
        if res:
            res_proto, dict_res = res
            level = int(get_proto_field(dict_res, 6, 1))
            exp = int(get_proto_field(dict_res, 7, 0))
            likes = int(get_proto_field(dict_res, 8, 0))
            nickname = res_proto.nickname or get_proto_field(dict_res, 4, "")

            acc_id = str(account_data['account_id'])
            if exp > 0 or level > 0:
                old_exp = bot_state.accounts.get(acc_id, {}).get("current_exp", 0)
                bot_state.update_exp(acc_id, exp, level)
                if old_exp and exp > old_exp:
                    diff = exp - old_exp
                    acc_state = bot_state.accounts.get(acc_id, {})
                    rem_e = acc_state.get('remaining_exp', 0)
                    nxt_l = acc_state.get('next_level', (level or 1) + 1)
                    pct_val = acc_state.get('progress_pct', 0)
                    log_exp(f"+{diff:,} EXP | UID: {acc_id} | Lvl {acc_state.get('level', level)} ({pct_val}% - {rem_e:,} to Lvl {nxt_l})")
            if likes > 0 and acc_id in bot_state.accounts:
                bot_state.accounts[acc_id]["likes"] = likes
            if nickname and acc_id in bot_state.accounts:
                bot_state.accounts[acc_id]["nickname"] = nickname
    except Exception as e:
        log_err(f"refresh_account_profile: {e}")


async def process_account_uid_pass(uid: str, password: str) -> Optional[Dict]:
    cached = cache_get(uid)
    if cached:
        acc_id = str(cached['account_id'])
        nick = cached.get('nickname', f"Player_{acc_id}")
        lvl = cached.get('level', 1)
        exp_val = cached.get('exp', 0)
        log_cache(f"Loaded UID {acc_id} | {nick} | Lvl {lvl} | EXP: {exp_val:,}")
        bot_state.register_account(
            uid=acc_id,
            nickname=nick,
            region='BD',
            level=lvl,
            exp=exp_val,
            likes=cached.get('likes', 0)
        )
        _register_credentials(cached)
        return cached

    log_login(f"Authenticating UID {uid}...")
    try:
        verconfig_res = await version_config()
        if verconfig_res is None:
            log_err(f"version_config failed for UID {uid}")
            return None
        release_version, client_version, server_url = verconfig_res

        tokengrant_response = await get_access_token(uid, password)
        if tokengrant_response is None:
            log_err(f"get_access_token failed for UID {uid}")
            return None
        open_id, access_token, platform = tokengrant_response

        device_info = get_device_for_account(uid)

        login_payload_data = await build_majorlogin_payload(
            open_id, access_token, platform, client_version, device_info
        )
        if not login_payload_data:
            log_err(f"MajorLogin payload build failed for UID {uid}")
            return None

        majorlogin_response = await send_majorlogin(
            login_payload_data, release_version, server_url
        )
        if majorlogin_response is None:
            log_err(f"MajorLogin rejected for UID {uid}")
            return None

        getlogin_result = await send_getlogin(
            login_payload_data,
            majorlogin_response.url,
            majorlogin_response.token,
            release_version
        )
        if getlogin_result is None:
            log_err(f"GetLoginData failed for UID {uid}")
            return None
        res_proto, dict_res = getlogin_result

        acc_id = str(majorlogin_response.account_id)
        level = int(get_proto_field(dict_res, 6, 1))
        exp = int(get_proto_field(dict_res, 7, 0))
        likes = int(get_proto_field(dict_res, 8, 0))
        nickname = res_proto.nickname or get_proto_field(dict_res, 4, f"Player_{acc_id}")
        region = "BD"

        bot_state.register_account(uid=acc_id, nickname=nickname, region=region, level=level, exp=exp, likes=likes)

        log_ok(f"Login success | UID: {acc_id} | {nickname} | Lvl {level} | EXP: {exp:,}")

        account_data = {
            'account_id': majorlogin_response.account_id,
            'nickname': nickname,
            'region': region,
            'level': level,
            'exp': exp,
            'likes': likes,
            'open_id': open_id,
            'access_token': access_token,
            'platform': str(platform),
            'token': majorlogin_response.token,
            'server_time': majorlogin_response.server_time,
            'aes_ak': majorlogin_response.aes_ak,
            'iv_i': majorlogin_response.iv_i,
            'functional_addrs': res_proto.functional_addrs or get_proto_field(dict_res, 14),
            'informational_addrs': res_proto.informational_addrs or get_proto_field(dict_res, 32),
            'release_version': release_version,
            'client_version': client_version,
            'server_url': majorlogin_response.url,
            'login_payload_data': login_payload_data,
            'auth_type': 'guest',
            'auth_uid': uid,
            'auth_password': password
        }
        _register_credentials(account_data)
        cache_set(uid, account_data)
        return account_data
    except Exception as e:
        log_err(f"process_account_uid_pass: {e}")
        traceback.print_exc()
        return None


async def process_account_token(access_token: str) -> Optional[Dict]:
    cache_key = f"tok_{access_token[:20]}"
    cached = cache_get(cache_key)
    if cached:
        acc_id = str(cached['account_id'])
        nick = cached.get('nickname', f"Player_{acc_id}")
        lvl = cached.get('level', 1)
        exp_val = cached.get('exp', 0)
        log_cache(f"Loaded token | UID {acc_id} | {nick} | Lvl {lvl} | EXP: {exp_val:,}")
        bot_state.register_account(
            uid=acc_id,
            nickname=nick,
            region='BD',
            level=lvl,
            exp=exp_val,
            likes=cached.get('likes', 0)
        )
        _register_credentials(cached)
        return cached

    log_login("Authenticating with Access Token...")
    try:
        verconfig_res = await version_config()
        if verconfig_res is None:
            log_err("version_config failed (token)")
            return None
        release_version, client_version, server_url = verconfig_res

        import requests
        url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
        hdrs = {
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)"
        }
        resp = await asyncio.to_thread(requests.get, url, headers=hdrs, timeout=10)
        data = resp.json()

        if 'error' in data:
            log_err(f"Token inspect error: {data.get('error')}")
            return None

        open_id = data.get('open_id')
        platform = data.get('platform', 4)

        if not open_id:
            log_err("No open_id in token inspect response")
            return None

        device_info = get_device_for_account(open_id)

        login_payload_data = await build_majorlogin_payload(
            open_id, access_token, str(platform), client_version, device_info
        )
        if not login_payload_data:
            log_err("MajorLogin payload build failed (token)")
            return None

        majorlogin_response = await send_majorlogin(
            login_payload_data, release_version, server_url
        )
        if majorlogin_response is None:
            log_err("MajorLogin rejected (token)")
            return None

        getlogin_result = await send_getlogin(
            login_payload_data,
            majorlogin_response.url,
            majorlogin_response.token,
            release_version
        )
        if getlogin_result is None:
            log_err("GetLoginData failed (token)")
            return None

        res_proto, dict_res = getlogin_result
        acc_id = str(majorlogin_response.account_id)
        level = int(get_proto_field(dict_res, 6, 1))
        exp = int(get_proto_field(dict_res, 7, 0))
        likes = int(get_proto_field(dict_res, 8, 0))
        nickname = res_proto.nickname or get_proto_field(dict_res, 4, f"Player_{acc_id}")
        region = "BD"

        bot_state.register_account(uid=acc_id, nickname=nickname, region=region, level=level, exp=exp, likes=likes)

        log_ok(f"Token login OK | UID: {acc_id} | {nickname} | Lvl {level} | EXP: {exp:,}")

        account_data = {
            'account_id': majorlogin_response.account_id,
            'nickname': nickname,
            'region': region,
            'level': level,
            'exp': exp,
            'likes': likes,
            'open_id': open_id,
            'access_token': access_token,
            'platform': str(platform),
            'token': majorlogin_response.token,
            'server_time': majorlogin_response.server_time,
            'aes_ak': majorlogin_response.aes_ak,
            'iv_i': majorlogin_response.iv_i,
            'functional_addrs': res_proto.functional_addrs or get_proto_field(dict_res, 14),
            'informational_addrs': res_proto.informational_addrs or get_proto_field(dict_res, 32),
            'release_version': release_version,
            'client_version': client_version,
            'server_url': majorlogin_response.url,
            'login_payload_data': login_payload_data,
            'auth_type': 'token',
            'auth_token': access_token
        }
        _register_credentials(account_data)
        cache_set(cache_key, account_data)
        return account_data
    except Exception as e:
        log_err(f"process_account_token: {e}")
        traceback.print_exc()
        return None


async def run_account_worker(account_data: Dict, label: str):
    acc_id = str(account_data['account_id'])
    informational_task = None
    exp_task = None
    try:
        reg = "BD"

        tcp_packet_online = await build_tcp_startup_packet(
            account_data['account_id'],
            account_data['token'],
            account_data['server_time'],
            account_data['aes_ak'],
            account_data['iv_i'],
            region=reg,
            typ='OnLine'
        )

        tcp_packet_chat = await build_tcp_startup_packet(
            account_data['account_id'],
            account_data['token'],
            account_data['server_time'],
            account_data['aes_ak'],
            account_data['iv_i'],
            region=reg,
            typ='ChaT'
        )

        informational_task = asyncio.create_task(
            informational(
                account_data['informational_addrs'],
                tcp_packet_chat,
                account_data['aes_ak'],
                account_data['iv_i'],
                region=reg,
                account_id=acc_id
            )
        )

        async def exp_refresher():
            while True:
                await asyncio.sleep(random.uniform(55, 65))
                fresh = bot_state.account_credentials.get(acc_id)
                if fresh:
                    await refresh_account_profile(fresh)

        exp_task = asyncio.create_task(exp_refresher())

        functional_task = asyncio.create_task(
            functional_lone_wolf(
                account_data['functional_addrs'],
                tcp_packet_online,
                reg,
                account_data['client_version'],
                account_data['aes_ak'],
                account_data['iv_i'],
                account_id=acc_id,
                account_data=account_data
            )
        )

        await functional_task

    except asyncio.CancelledError:
        raise
    except Exception as e:
        log_err(f"run_account_worker [{label}]: {e}")
    finally:
        for t in (informational_task, exp_task):
            if t and not t.done():
                t.cancel()
        for t in (informational_task, exp_task):
            if t:
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass


async def account_loop_guest(uid: str, password: str):
    while True:
        try:
            log_login(f"Starting login for Guest UID: {uid}")
            try:
                bot_state.update_status(str(uid), "CONNECTING")
            except Exception:
                pass
            async with _LOGIN_SEMAPHORE:
                account_data = await process_account_uid_pass(uid, password)
            if not account_data:
                log_err(f"Login failed for UID: {uid}. Retry in 15s...")
                try:
                    bot_state.update_status(str(uid), "ERROR")
                except Exception:
                    pass
                await asyncio.sleep(15)
                continue

            await run_account_worker(account_data, uid)
            log_warn(f"Session finished for {uid}. Reconnect in 3s...")
            await asyncio.sleep(3)
        except asyncio.CancelledError:
            log_warn(f"Worker for {uid} stopped.")
            try:
                bot_state.update_status(str(uid), "OFFLINE")
            except Exception:
                pass
            break
        except Exception as e:
            log_err(f"Error for UID {uid}: {e}. Retry in 10s...")
            await asyncio.sleep(10)


async def account_loop_token(token: str):
    token_label = token[:10]
    while True:
        try:
            log_login("Starting login with Access Token...")
            async with _LOGIN_SEMAPHORE:
                account_data = await process_account_token(token)
            if not account_data:
                log_err("Login failed for Token. Retry in 15s...")
                await asyncio.sleep(15)
                continue

            acc_id = str(account_data['account_id'])
            await run_account_worker(account_data, acc_id)
            log_warn("Token session finished. Reconnect in 3s...")
            await asyncio.sleep(3)
        except asyncio.CancelledError:
            log_warn(f"Worker for token {token_label} stopped.")
            break
        except Exception as e:
            log_err(f"Token error: {e}. Retry in 10s...")
            await asyncio.sleep(10)


# ==================== ACCOUNTS LOADER ====================
def load_accounts():
    accounts = []
    if os.path.exists(ACCOUNTS_FILE):
        try:
            with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    accounts = data
        except Exception as e:
            log_err(f"Could not load {ACCOUNTS_FILE}: {e}")

    if not accounts and FALLBACK_UID and FALLBACK_PASSWORD:
        accounts.append({"uid": FALLBACK_UID, "password": FALLBACK_PASSWORD})

    return accounts


# ==================== MAIN ====================
async def main():
    log_banner()

    log_separator("CONFIGURATION")
    log_info(f"Start Match Interval : {START_MATCH_INTERVAL_MIN}-{START_MATCH_INTERVAL_MAX}s (random)")
    log_info(f"Offline Wait         : {NEW_MATCH_DELAY}s")
    log_info(f"Non-match Reconnect  : {NON_MATCH_RECONNECT_DELAY}s")
    log_info(f"Cache Invalidation   : {int(MAX_CONSECUTIVE_PARSE_FAILURES)}x failures")
    log_info(f"Parallel Matches     : BR={MAX_CONCURRENT_MATCHES_BR} | Lone Wolf={MAX_CONCURRENT_MATCHES_LW} (switch at Lvl {LEVEL_THRESHOLD})")
    log_info(f"Cache TTL            : {TOKEN_CACHE_TTL}s ({TOKEN_CACHE_TTL//60} min)")
    log_info(f"HUMAN MODE           : {'ON' if HUMAN_MODE else 'OFF'}")
    log_info(f"FORCED REGION        : {FORCE_REGION}")

    try:
        await start_web_dashboard(host=WEB_HOST, port=WEB_PORT)
        log_ok(f"Web Dashboard live -> http://localhost:{WEB_PORT}")
    except Exception as e:
        log_err(f"Could not start web dashboard: {e}")

    async def on_account_added_handler(data):
        if "token" in data and data["token"]:
            t = str(data["token"]).strip()
            task = asyncio.create_task(account_loop_token(t))
            bot_state.account_workers[t[:10]] = task
        elif "uid" in data and "password" in data:
            u = str(data["uid"]).strip()
            p = str(data["password"]).strip()
            task = asyncio.create_task(account_loop_guest(u, p))
            bot_state.account_workers[u] = task

    async def on_refresh_account_handler(uid):
        await refresh_account_profile(uid)

    async def on_restart_account_handler(uid):
        uid_str = str(uid)
        resolved = {uid_str}
        if uid_str in bot_state.game_to_auth_id:
            resolved.add(str(bot_state.game_to_auth_id[uid_str]))
        if uid_str in bot_state.auth_to_game_id:
            resolved.add(str(bot_state.auth_to_game_id[uid_str]))
        for u in resolved:
            w = bot_state.account_workers.pop(u, None)
            if w:
                try:
                    w.cancel()
                except Exception:
                    pass
        for acc in load_accounts():
            acc_u = str(acc.get("uid", ""))
            if acc_u in resolved and acc.get("password"):
                bot_state.account_workers[acc_u] = asyncio.create_task(account_loop_guest(acc_u, acc["password"]))
                break
            elif acc.get("token"):
                tok = str(acc["token"]).strip()
                if any(bot_state.account_token_map.get(u) == tok for u in resolved):
                    bot_state.account_workers[tok[:10]] = asyncio.create_task(account_loop_token(tok))
                    break

    async def on_account_deleted_handler(deleted_ids):
        for d_id in deleted_ids:
            try:
                bot_state.close_writers_for_account(str(d_id))
            except Exception:
                pass
            cache_invalidate(str(d_id))

    async def on_pause_toggle_handler(uid, is_paused):
        if is_paused:
            bot_state.close_writers_for_account(str(uid))

    bot_state.refresh_callbacks["on_account_added"] = on_account_added_handler
    bot_state.refresh_callbacks["on_account_deleted"] = on_account_deleted_handler
    bot_state.refresh_callbacks["on_refresh_account"] = on_refresh_account_handler
    bot_state.refresh_callbacks["on_restart_account"] = on_restart_account_handler
    bot_state.refresh_callbacks["on_pause_toggle"] = on_pause_toggle_handler

    enforce_startup_cap()   # extra accounts beyond the active limit go to the queue
    accounts = load_accounts()

    if not accounts:
        log_warn(f"No accounts found in {ACCOUNTS_FILE}!")
        log_warn(f"Add accounts via Dashboard: http://localhost:{WEB_PORT}")
    else:
        log_separator(f"LOADING {len(accounts)} ACCOUNTS")

        for acc in accounts:
            if "token" in acc and acc["token"]:
                t = asyncio.create_task(account_loop_token(acc["token"]))
                bot_state.account_workers[acc["token"][:10]] = t
            elif "uid" in acc and "password" in acc and acc["uid"]:
                u = str(acc["uid"])
                t = asyncio.create_task(account_loop_guest(u, acc["password"]))
                bot_state.account_workers[u] = t

        log_ok(f"All {len(accounts)} accounts launched")
        log_info("Watching for matches... (wait 2-5 minutes)")

    log_info(f"Active limit         : {MAX_ACTIVE_ACCOUNTS} accounts | auto-delete at level {AUTO_DELETE_LEVEL}")
    try:
        started_from_queue = await fill_slots()   # free slots are filled from queue.json
        if started_from_queue:
            log_ok(f"{started_from_queue} account(s) started from storage queue")
    except Exception as e:
        log_warn(f"Could not fill slots from queue: {e}")

    try:
        while True:
            await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        log_warn("Shutting down all accounts...")
        for t in list(bot_state.account_workers.values()):
            t.cancel()
        await asyncio.gather(*bot_state.account_workers.values(), return_exceptions=True)
        log_ok("All sessions cleanly closed.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log_warn("Program stopped by user.")

#!/usr/bin/env python3
"""
shape-api — локальный HTTP-интерфейс к шейперу ЭТОЙ ноды.

Что это такое и чем не является
───────────────────────────────
Это тонкая оболочка над уже существующим кодом Shape. Своей логики
ограничения здесь нет ни строчки: все действия выполняются функциями из
shaperctl.py — теми же самыми, которыми пользуются меню и сторож.

    CLI  ─┐
    меню ─┼→  shaperctl.py  →  карты BPF
    API  ─┘

Поэтому расхождения между «ограничил через меню» и «ограничил через API»
быть не может: это один и тот же вызов.

Нода ничего не знает о других нодах. Никакого общего состояния, никаких
идентификаторов кластера, никакой базы. На всех ста нодах может стоять
один и тот же порт 8765 на 127.0.0.1 — это разные машины, конфликтовать
нечему. Центральная система сама знает, к какой ноде обращаться.

Почему стандартная библиотека, а не FastAPI
───────────────────────────────────────────
FastAPI тянет за собой starlette, pydantic, uvicorn, anyio и их зависимости —
около полутора десятков пакетов, которые придётся ставить и обновлять на
каждой из сотни нод, где живёт одноядерная VPS с 2 ГБ памяти. Весь Shape
специально написан на голой стандартной библиотеке: установка не зависит
ни от pip, ни от состояния PyPI, ни от версии Debian.

Здесь нужен десяток endpoint'ов с плоскими телами запросов. Валидацию для
них проще и надёжнее написать явно, чем тащить ради этого целый фреймворк:
схема OpenAPI отдаётся как есть, а проверки входа видно глазами в одном
месте — их и проверять аудитом легче.

Запускается сервисом shape-api.service. Shape работает и без него.
"""

import contextlib
import hmac
import importlib.util
import ipaddress
import json
import os
import platform
import re
import secrets
import socket
import socketserver
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote_plus

API_VERSION = "1.0"
APP_DIR = os.environ.get("SHAPE_APP_DIR", "/opt/shaper")
ETC_DIR = os.environ.get("SHAPE_ETC_DIR", "/etc/shaper")
API_CONF = os.path.join(ETC_DIR, "api.json")

# Предел на тело запроса. Больше для этого API не нужно никому: самое
# объёмное тело — создание ограничения, это пара сотен байт.
MAX_BODY = 64 * 1024
# Одновременных обработчиков. Каждый может дёрнуть bpftool, поэтому число
# небольшое: сотня параллельных дампов карт положит слабую ноду быстрее,
# чем любой сетевой флуд.
MAX_WORKERS = 16
# Кэш тяжёлых чтений. Дамп карт стоит десятки миллисекунд, а опрашивать
# статус центральная система будет часто.
CACHE_TTL = 2.0


# ── подключаем существующий код Shape ────────────────────────────────────
def load_shape():
    """
    shaperctl.py лежит рядом как обычный скрипт, пакетом он не оформлен.
    Импортируем его по пути: так API получает ровно те функции, которыми
    пользуется CLI, без копирования логики.
    """
    path = os.path.join(APP_DIR, "shaperctl.py")
    spec = importlib.util.spec_from_file_location("shaperctl", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"не найден {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


S = load_shape()


# ── конфигурация API ──────────────────────────────────────────────────────
API_DEFAULT = {
    # Наружу по умолчанию не смотрим. Чтобы отдать API в приватную сеть
    # (WireGuard и подобное), сюда вписывают адрес этого интерфейса —
    # 0.0.0.0 остаётся возможным, но только осознанным решением.
    "bind_address": "127.0.0.1",
    "port": 8765,
    # Пусто = пускаем всех, кто смог достучаться до сокета. При bind на
    # приватный интерфейс сюда стоит вписать сеть центральной системы.
    "allowed_ips": [],
    "rate_read_per_min": 240,
    "rate_write_per_min": 60,
    "auth_fail_per_min": 15,
    "expose_docs": True,
    # Prometheus умеет ходить с bearer-токеном, поэтому по умолчанию метрики
    # закрыты как и всё остальное. Открыть можно осознанно — например когда
    # API и так виден только внутри WireGuard.
    "metrics_public": False,
    # Токены. Генерируются установщиком, в исходниках их нет и быть не может.
    #
    # previous — прежняя пара, которая ещё какое-то время принимается. Без
    # этого смена токена на 28 нодах означала бы 28 одновременных правок в
    # центральной системе: пока обновляешь последнюю, первые уже отвечают 401.
    "tokens": {"read": "", "write": "", "read_previous": "", "write_previous": "",
               "previous_until": 0},
}

# Ключи, которые разрешено менять через PATCH /config. Всё, что связано с
# путями, командами и файлами, сюда не попадает намеренно: API не должен
# уметь переназначить исполняемый файл или каталог.
CONFIG_WRITABLE = {
    "speed_mbps":  ("shape", float, 0, S.MAX_MBPS),
    "guard_enabled": ("guard", bool, None, None),
    "penalty_mbps": ("guard", float, 0.1, 1000),
    "penalty_min":  ("guard", int, 1, 10080),
    "score_needed": ("guard", int, 1, 6),
    "download_gb_per_day":  ("guard", float, 0, 10000),
    "download_gb_per_hour": ("guard", float, 0, 1000),
    "both_ways_min": ("guard", int, 1, 120),
    "watch_interval": ("guard", int, 5, 60),
}


def api_config():
    try:
        with open(API_CONF) as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict):
            cfg = {}
    except Exception:
        cfg = {}
    out = dict(API_DEFAULT)
    out.update({k: v for k, v in cfg.items() if k in API_DEFAULT})
    tokens = dict(API_DEFAULT["tokens"])
    if isinstance(cfg.get("tokens"), dict):
        for k, v in cfg["tokens"].items():
            if k == "previous_until":
                try:
                    tokens[k] = float(v)
                except (TypeError, ValueError):
                    tokens[k] = 0
            elif k in tokens:
                tokens[k] = str(v)
    out["tokens"] = tokens
    return out


def save_api_config(cfg):
    os.makedirs(ETC_DIR, exist_ok=True)
    tmp = API_CONF + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, API_CONF)
    os.chmod(API_CONF, 0o600)


# ── ошибки ────────────────────────────────────────────────────────────────
class ApiError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def bad(code, message):
    return ApiError(400, code, message)


# ── валидация входа ───────────────────────────────────────────────────────
# Ни одно поле отсюда не попадает в оболочку: shaperctl запускает bpftool
# списком аргументов. Но проверяем всё равно строго — значение должно быть
# отвергнуто на границе, а не «как-нибудь обработано» внутри.

REASON_RE = re.compile(r"^[\w \-.,:/()\[\]#@+*]{1,64}$", re.UNICODE)
# Ярлык человека приходит из панели и попадает в сообщение с parse_mode=HTML.
# Экранирует его offender_card, но угловые скобки лучше не пускать вовсе.
LABEL_RE = re.compile(r"^[^\x00-\x1f<>&]{1,64}$", re.UNICODE)


def v_ip(raw, field="ip"):
    if not isinstance(raw, str) or len(raw) > 45:
        raise ApiError(422, "INVALID_IP", f"{field}: адрес не похож на IP")
    ip = S.valid_ip(raw)
    if ip is None:
        raise ApiError(422, "INVALID_IP", f"{field}: «{raw[:45]}» не является IP-адресом")
    return ip


def v_speed(raw, field="download_mbps"):
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise ApiError(422, "INVALID_SPEED", f"{field}: нужно число в Мбит/с")
    val = float(raw)
    if val != val or val in (float("inf"), float("-inf")):
        raise ApiError(422, "INVALID_SPEED", f"{field}: недопустимое число")
    if not 0.05 <= val <= S.MAX_MBPS:
        raise ApiError(422, "INVALID_SPEED",
                       f"{field}: допустимо от 0.05 до {S.MAX_MBPS} Мбит/с")
    return val


def v_duration(raw, field="duration"):
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ApiError(422, "INVALID_DURATION", f"{field}: нужно целое число секунд")
    if not 10 <= raw <= 30 * 24 * 3600:
        raise ApiError(422, "INVALID_DURATION",
                       f"{field}: допустимо от 10 секунд до 30 суток")
    return raw


def v_reason(raw, field="reason"):
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raise ApiError(422, "INVALID_REASON", f"{field}: нужна строка")
    val = raw.strip()
    if not val:
        return ""
    if not REASON_RE.match(val):
        raise ApiError(422, "INVALID_REASON",
                       f"{field}: до 64 символов, без управляющих знаков")
    return val


# ── кэш тяжёлых чтений ────────────────────────────────────────────────────
_cache = {}
_cache_lock = threading.Lock()


def cached(key, ttl, producer):
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
    value = producer()
    with _cache_lock:
        _cache[key] = (now, value)
    return value


# ── состояние Shape ───────────────────────────────────────────────────────
# Факты о ноде живут в shaperctl: ими пользуются и метрики из CLI, и API.
# Здесь только кэш — HTTP-запросов бывает много, а systemctl и разбор
# журнала событий стоят заметно дороже, чем чтение файла.
engine_loaded = S.engine_loaded
shape_version = S.shape_version
active_iface = S.active_iface


def systemd_active(unit):
    return cached("unit:" + unit, 5.0, lambda: S.systemd_active(unit))


def engine_started_at():
    return cached("engine_started", 15.0, S.engine_started_at)


PROC_STARTED = time.time()


# ── представление ограничений ─────────────────────────────────────────────
def limit_view(ip, p):
    """
    Одна запись штрафа в виде, пригодном для внешней системы.

    Ядро держит на адрес одну скорость и применяет её в обе стороны, поэтому
    download и upload здесь совпадают. Поля разведены сознательно: если
    когда-нибудь скорости разделятся, формат ответа не изменится.
    """
    now = time.time()
    until = float(p.get("until", 0))
    mbps = float(p.get("mbps", 0))
    try:
        ver = ipaddress.ip_address(ip).version
    except ValueError:
        ver = None
    return {
        "ip": ip,
        "family": f"ipv{ver}" if ver else None,
        "download_mbps": mbps,
        "upload_mbps": mbps,
        "created_at": round(float(p["since"]), 3) if p.get("since") else None,
        "expires_at": round(until, 3),
        "remaining_seconds": max(0, round(until - now)),
        "reason": p.get("reason") or (",".join(p.get("reasons") or []) or None),
        "source": p.get("source", "watchdog"),
        "type": p.get("kind", "auto"),
        "score": p.get("score"),
        # Кто стоит за адресом. Прикрепляется в момент выдачи ограничения:
        # позже человек отключится, и связь потеряется.
        "subject": p.get("subject") or S.owner_of(ip),
    }


def apply_limit(ip, mbps, duration, reason, source, kind, request_id):
    """
    Единственная точка создания ограничения в API.

    Работает через те же функции, что и меню: запись в карту ядра плюс
    запись в penalties.json под общим замком. Сторож эту запись увидит и
    снимет её сам, когда истечёт срок.
    """
    if not engine_loaded():
        raise ApiError(503, "ENGINE_NOT_RUNNING",
                       "движок не запущен, ограничение применить некуда")
    if ip in S.whitelist_ips():
        raise ApiError(409, "IP_WHITELISTED",
                       "адрес в белом списке — ограничения к нему не применяются")

    now = time.time()
    until = now + duration
    entry = {"until": until, "mbps": mbps, "since": now,
             "source": source, "kind": kind, "reason": reason or None,
             "request_id": request_id}
    who = S.owner_of(ip)
    if who:
        entry["subject"] = who
    try:
        S.penalty_apply(ip, mbps, until)
    except SystemExit:
        # shaperctl.die() внутри — до клиента это доходить не должно
        raise ApiError(503, "ENGINE_ERROR",
                       "не удалось записать ограничение в ядро") from None
    S.penalties_update(lambda pens: pens.__setitem__(ip, entry))
    S.log_event("limit_applied", ip=ip, source=source, mbps=mbps,
                seconds=duration, reason=reason or None, request_id=request_id)
    return limit_view(ip, entry)


def drop_limit(ip, source, request_id):
    existing = S.load_penalties().get(ip)
    if not existing or S.is_personal(existing):
        # Персональную скорость снимают через /personal, чтобы её нельзя было
        # погасить случайно, разбирая список ограничений.
        raise ApiError(404, "LIMIT_NOT_FOUND", "для этого адреса ограничения нет")
    with contextlib.suppress(SystemExit):
        S.penalty_clear(ip)
    S.penalties_update(lambda pens: pens.pop(ip, None))
    S.log_event("limit_released", ip=ip, source=source, request_id=request_id)
    return limit_view(ip, existing)


# ── обработчики ───────────────────────────────────────────────────────────
def h_health(req):
    """Живость процесса и ничего больше: этот ответ видят без токена."""
    return 200, {"status": "ok"}


def h_status(req):
    cfg = S.load_config()
    started = engine_started_at()
    return 200, {
        "shape": {
            "service": systemd_active("shaper"),
            "watchdog": systemd_active("shaper-watch"),
            "engine_loaded": engine_loaded(),
            "interface": active_iface(),
            "started_at": round(started, 3) if started else None,
            "uptime_seconds": round(time.time() - started) if started else None,
        },
        "api": {
            "version": API_VERSION,
            "uptime_seconds": round(time.time() - PROC_STARTED),
        },
        "node": {
            "id": S.node_id(),
            "config_hash": S.config_hash(cfg),
        },
        "versions": {"shape": shape_version(), "api": API_VERSION},
        "limits": {
            "speed_mbps": cfg["speed_mbps"],
            "ports": cfg["ports"],
            "limited_ips": len(S.load_penalties()),
        },
        "auto_limiter": {
            "enabled": bool(cfg["guard"]["enabled"]),
            "penalty_mbps": cfg["guard"]["penalty_mbps"],
            "penalty_min": cfg["guard"]["penalty_min"],
            "download_gb_per_hour": cfg["guard"].get("download_gb_per_hour", 0),
            "download_gb_per_day": cfg["guard"].get("download_gb_per_day", 0),
        },
    }


def h_node(req):
    def build():
        iface = active_iface()
        ipv4 = ipv6 = None
        if iface:
            try:
                p = subprocess.run(["ip", "-o", "addr", "show", "dev", iface],
                                   capture_output=True, text=True, timeout=5)
                for line in p.stdout.splitlines():
                    parts = line.split()
                    if len(parts) > 3 and parts[2] == "inet" and not ipv4:
                        ipv4 = parts[3].split("/")[0]
                    if len(parts) > 3 and parts[2] == "inet6" and not ipv6:
                        addr = parts[3].split("/")[0]
                        if not addr.startswith("fe80"):
                            ipv6 = addr
            except Exception:
                pass
        os_name = "unknown"
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        os_name = line.split("=", 1)[1].strip().strip('"')
        except Exception:
            pass
        return {
            # Идентификатор идёт первым не случайно: имя хоста меняют, а он
            # остаётся — по нему централь и узнаёт узел после переезда.
            "id": S.node_id(),
            "config_hash": S.config_hash(),
            "hostname": socket.gethostname(),
            "os": os_name,
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "versions": {"shape": shape_version(), "api": API_VERSION},
            "network": {
                "interface": iface,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "ipv6_enabled": os.path.exists("/proc/net/if_inet6"),
            },
            "bpf": {"loaded": engine_loaded(), "pin_dir": S.PIN_DIR},
        }
    return 200, cached("node", 30.0, build)


def h_limits_list(req):
    # Персональные скорости живут в той же карте, но это не наказание —
    # у них свой endpoint /personal.
    pens = {ip: p for ip, p in S.load_penalties().items() if not S.is_personal(p)}
    items = [limit_view(ip, p) for ip, p in
             sorted(pens.items(), key=lambda kv: -float(kv[1].get("since") or 0))]
    return 200, {"items": items, "count": len(items)}


def h_limit_get(req, ip):
    ip = v_ip(ip)
    p = S.load_penalties().get(ip)
    if not p:
        raise ApiError(404, "LIMIT_NOT_FOUND", "для этого адреса ограничения нет")
    return 200, limit_view(ip, p)


def _limit_body(body, ip=None):
    ip = v_ip(ip if ip is not None else body.get("ip"))
    down = v_speed(body.get("download_mbps"), "download_mbps")
    up = body.get("upload_mbps")
    if up is not None:
        up = v_speed(up, "upload_mbps")
        # Честно отказываем вместо того, чтобы молча применить одно значение:
        # в карте ядра на адрес лежит одна скорость на оба направления.
        if abs(up - down) > 1e-9:
            raise ApiError(422, "ASYMMETRIC_NOT_SUPPORTED",
                           "движок применяет одну скорость в обе стороны: "
                           "download_mbps и upload_mbps должны совпадать")
    duration = v_duration(body.get("duration", 3600))
    reason = v_reason(body.get("reason"))
    return ip, down, duration, reason


def h_limit_create(req, ip=None):
    body = req["body"]
    if not isinstance(body, dict):
        raise bad("INVALID_BODY", "тело запроса должно быть объектом JSON")
    ip, mbps, duration, reason = _limit_body(body, ip)
    view = apply_limit(ip, mbps, duration, reason, "api", "temporary",
                       req["request_id"])
    return 201, view


def h_limit_delete(req, ip):
    return 200, drop_limit(v_ip(ip), "api", req["request_id"])


def h_stats(req):
    """
    Скорости считаем по разнице с прошлым снимком, не засыпая внутри запроса:
    иначе десяток параллельных запросов держал бы столько же потоков секундами.
    """
    if not engine_loaded():
        raise ApiError(503, "ENGINE_NOT_RUNNING", "движок не запущен")

    def snapshot():
        return {"t": time.monotonic(), "users": S.read_users()}

    cur = cached("stats_snapshot", CACHE_TTL, snapshot)
    with _cache_lock:
        prev = _cache.get("stats_prev")
    dl_mbps = ul_mbps = None
    if prev and 0.5 <= cur["t"] - prev["t"] <= 120:
        dt = cur["t"] - prev["t"]
        dl_mbps = round(sum(max(0, c["down"] - prev["users"].get(ip, {}).get("down", 0))
                            for ip, c in cur["users"].items()) * 8 / 1e6 / dt, 3)
        ul_mbps = round(sum(max(0, c["up"] - prev["users"].get(ip, {}).get("up", 0))
                            for ip, c in cur["users"].items()) * 8 / 1e6 / dt, 3)
    if not prev or cur["t"] - prev["t"] >= CACHE_TTL:
        with _cache_lock:
            _cache["stats_prev"] = cur

    now_ns = S.mono_ns()
    active = sum(1 for c in cur["users"].values()
                 if c["seen"] and (now_ns - c["seen"]) / S.NS < 60)
    cfg = S.load_config()
    started = engine_started_at()
    return 200, {
        "traffic": {
            "download_bytes": sum(c["down"] for c in cur["users"].values()),
            "upload_bytes": sum(c["up"] for c in cur["users"].values()),
            "download_mbps": dl_mbps,
            "upload_mbps": ul_mbps,
            "note": None if dl_mbps is not None else
                    "скорость появится со второго запроса: считается по разнице",
        },
        "ips": {
            "known": len(cur["users"]),
            "active_last_minute": active,
            "limited": len(S.load_penalties()),
            "whitelisted": len(S.whitelist_ips()),
        },
        "auto_limiter": {
            "enabled": bool(cfg["guard"]["enabled"]),
            "watchdog": systemd_active("shaper-watch"),
        },
        "uptime_seconds": round(time.time() - started) if started else None,
    }


# Сколько строк отдавать по умолчанию и максимум. Смысл эндпоинта в том,
# чтобы централь не тянула все адреса: на сотне нод по три сотни строк
# каждые полминуты — это тридцать тысяч строк на цикл ни за чем.
TOP_DEFAULT = 20
TOP_MAX = 200

TOP_SORTS = ("download", "upload", "total")


def h_top(req):
    """
    Верхушка адресов по текущей нагрузке.

    Скорости берём из того же снимка, что и /stats: два чтения карт подряд
    с разницей во времени. Отдельного замера здесь не делаем намеренно —
    иначе два эндпоинта дёргали бы bpftool вдвое чаще без всякой пользы.

    До второго обращения скоростей ещё нет, разницу считать не с чем. В этом
    случае честно сортируем по накопленному объёму и говорим об этом в поле
    sorted_by, а не выдаём нули за правду.
    """
    if not engine_loaded():
        raise ApiError(503, "ENGINE_NOT_RUNNING", "движок не запущен")

    q = req["query"]

    raw_limit = q.get("limit")
    if raw_limit in (None, ""):
        limit = TOP_DEFAULT
    else:
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            raise bad("INVALID_QUERY", "limit: нужно целое число") from None
        if not 1 <= limit <= TOP_MAX:
            raise bad("INVALID_QUERY", f"limit: от 1 до {TOP_MAX}")

    sort = q.get("sort") or "download"
    if sort not in TOP_SORTS:
        raise bad("INVALID_QUERY",
                  "sort: " + ", ".join(TOP_SORTS))

    def snapshot():
        return {"t": time.monotonic(), "users": S.read_users()}

    cur = cached("stats_snapshot", CACHE_TTL, snapshot)
    with _cache_lock:
        prev = _cache.get("stats_prev")

    dt = None
    if prev and 0.5 <= cur["t"] - prev["t"] <= 120:
        dt = cur["t"] - prev["t"]
    if not prev or cur["t"] - prev["t"] >= CACHE_TTL:
        with _cache_lock:
            _cache["stats_prev"] = cur

    pens = S.load_penalties()
    wl = S.whitelist_ips()
    owners = S.load_owners()
    now_ns = S.mono_ns()

    rows = []
    for ip, c in cur["users"].items():
        was = prev["users"].get(ip, {}) if dt else {}
        dl_mbps = ul_mbps = None
        if dt:
            dl_mbps = round(max(0, c["down"] - was.get("down", 0)) * 8 / 1e6 / dt, 3)
            ul_mbps = round(max(0, c["up"] - was.get("up", 0)) * 8 / 1e6 / dt, 3)

        entry = pens.get(ip)
        row = {
            "ip": ip,
            "download_mbps": dl_mbps,
            "upload_mbps": ul_mbps,
            "download_bytes": c["down"],
            "upload_bytes": c["up"],
            "idle_seconds": round((now_ns - c["seen"]) / S.NS, 1) if c["seen"] else None,
            "whitelisted": ip in wl,
            "limited": bool(entry) and not S.is_personal(entry),
            "personal": bool(entry) and S.is_personal(entry),
            "limit_mbps": float(entry["mbps"]) if entry else None,
            "subject": S.owner_of(ip, owners),
        }
        rows.append(row)

    if dt:
        keys = {"download": lambda r: r["download_mbps"],
                "upload": lambda r: r["upload_mbps"],
                "total": lambda r: r["download_mbps"] + r["upload_mbps"]}
        sorted_by = {"download": "download_mbps", "upload": "upload_mbps",
                     "total": "download_mbps+upload_mbps"}[sort]
    else:
        keys = {"download": lambda r: r["download_bytes"],
                "upload": lambda r: r["upload_bytes"],
                "total": lambda r: r["download_bytes"] + r["upload_bytes"]}
        sorted_by = {"download": "download_bytes", "upload": "upload_bytes",
                     "total": "download_bytes+upload_bytes"}[sort]

    rows.sort(key=keys[sort], reverse=True)
    return 200, {
        "items": rows[:limit],
        "count": len(rows[:limit]),
        "total_known": len(rows),
        "sorted_by": sorted_by,
        "note": None if dt else
                "скорости появятся со второго запроса: считаются по разнице",
    }


def h_events(req):
    q = req["query"]

    def num(name, cast, default=None):
        raw = q.get(name)
        if raw is None or raw == "":
            return default
        try:
            return cast(raw)
        except (TypeError, ValueError):
            raise bad("INVALID_QUERY", f"{name}: неверное значение") from None

    etype = q.get("type")
    if etype and etype not in S.EVENT_TYPES:
        raise bad("INVALID_QUERY",
                  "type: допустимо " + ", ".join(sorted(S.EVENT_TYPES)))
    ip = v_ip(q["ip"]) if q.get("ip") else None
    items, more = S.read_events(after=num("cursor", int, 0) or 0,
                                limit=num("limit", int, 100),
                                etype=etype, ip=ip,
                                since=num("since", float),
                                until=num("until", float))
    return 200, {
        "items": items,
        "count": len(items),
        "next_cursor": max((e.get("id", 0) for e in items), default=0),
        "has_more": more,
    }


def h_config_get(req):
    cfg = S.load_config()
    g = cfg["guard"]
    acfg = api_config()
    return 200, {
        "shape": {"speed_mbps": cfg["speed_mbps"], "ports": cfg["ports"]},
        "guard": {k: g.get(k) for k in (
            "enabled", "score_needed", "penalty_mbps", "penalty_min",
            "both_ways_min", "both_dl_percent", "both_ul_percent",
            "hours_per_day", "upload_gb_per_day", "download_gb_per_day",
            "download_gb_per_hour", "watch_interval", "packet_bytes")},
        # Раздел telegram сюда не попадает намеренно: там лежит токен бота.
        "api": {"bind_address": acfg["bind_address"], "port": acfg["port"],
                "allowed_ips": acfg["allowed_ips"],
                "rate_read_per_min": acfg["rate_read_per_min"],
                "rate_write_per_min": acfg["rate_write_per_min"]},
        "writable": sorted(CONFIG_WRITABLE),
    }


def h_config_patch(req):
    body = req["body"]
    if not isinstance(body, dict) or not body:
        raise bad("INVALID_BODY", "передай объект с изменяемыми полями")
    unknown = [k for k in body if k not in CONFIG_WRITABLE]
    if unknown:
        raise ApiError(422, "FIELD_NOT_WRITABLE",
                       "через API нельзя менять: " + ", ".join(sorted(unknown)[:10]))

    cfg = S.load_config()
    changed = {}
    for key, raw in body.items():
        section, kind, lo, hi = CONFIG_WRITABLE[key]
        if kind is bool:
            if not isinstance(raw, bool):
                raise ApiError(422, "INVALID_VALUE", f"{key}: нужно true или false")
            val = raw
        else:
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise ApiError(422, "INVALID_VALUE", f"{key}: нужно число")
            val = kind(raw)
            if val != val or val in (float("inf"), float("-inf")) \
                    or not lo <= val <= hi:
                raise ApiError(422, "INVALID_VALUE",
                               f"{key}: допустимо от {lo} до {hi}")
        if section == "shape":
            cfg["speed_mbps"] = val
        elif key == "guard_enabled":
            cfg["guard"]["enabled"] = val
        else:
            cfg["guard"][key] = val
        changed[key] = val

    # Скорость живёт ещё и в карте ядра — иначе изменение не подействует.
    if "speed_mbps" in changed:
        if not engine_loaded():
            raise ApiError(503, "ENGINE_NOT_RUNNING", "движок не запущен")
        try:
            S.write_to_kernel(cfg)
        except SystemExit:
            raise ApiError(503, "ENGINE_ERROR",
                           "не удалось записать скорость в ядро") from None
    S.save_config(cfg)
    S.log_event("config_changed", source="api", request_id=req["request_id"],
                message=",".join(f"{k}={v}" for k, v in changed.items())[:200])
    return 200, {"changed": changed}


def h_bpf_status(req):
    loaded = engine_loaded()
    maps = []
    if loaded:
        for name in ("config_map", "port_map", "whitelist_map", "penalty_map",
                     "trusted_map", "pp_conn_map",
                     "user_state_map_down", "user_state_map_up"):
            path = S.map_path(name)
            if not os.path.exists(path):
                maps.append({"name": name, "pinned": False, "entries": None})
                continue
            try:
                entries = len(S.map_dump(name))
            except Exception:
                entries = None
            maps.append({"name": name, "pinned": True, "entries": entries})
    return 200, {
        "loaded": loaded,
        "pin_dir": S.PIN_DIR,
        "interface": active_iface(),
        "maps": maps,
        "error": None if loaded else "карты не закреплены — движок не запущен",
    }



def h_history(req):
    q = req["query"]
    try:
        days = int(q.get("days", 30))
    except (TypeError, ValueError):
        raise bad("INVALID_QUERY", "days: нужно число") from None
    rows = S.read_history(limit=max(1, min(days, S.HISTORY_MAX_DAYS)))
    return 200, {
        "items": rows,
        "count": len(rows),
        "totals": {
            "download_bytes": sum(r.get("down", 0) for r in rows),
            "upload_bytes": sum(r.get("up", 0) for r in rows),
        },
        "note": "строка появляется при смене суток; текущие сутки — в /stats",
    }


def h_owners_list(req):
    owners = S.load_owners()
    items = []
    for ip in sorted(owners):
        who = S.owner_of(ip, owners) or {}
        items.append(dict(who, ip=ip, updated=owners[ip].get("updated")))
    return 200, {"items": items, "count": len(items)}


def _owner_record(raw):
    """Проверка одной записи о владельце. Ничего лишнего не сохраняем."""
    if not isinstance(raw, dict):
        raise ApiError(422, "INVALID_OWNER", "запись должна быть объектом")
    out = {}
    label = raw.get("label")
    if label is not None:
        if not isinstance(label, str) or not LABEL_RE.match(label.strip()):
            raise ApiError(422, "INVALID_OWNER",
                           "label: до 64 символов, без управляющих знаков")
        out["label"] = label.strip()
    uid = raw.get("user_id")
    if uid is not None:
        uid = str(uid).strip()
        if not re.fullmatch(r"[\w.:-]{1,64}", uid):
            raise ApiError(422, "INVALID_OWNER", "user_id: до 64 символов [A-Za-z0-9_.:-]")
        out["user_id"] = uid
    tg = raw.get("telegram_id")
    if tg is not None:
        if isinstance(tg, bool) or not isinstance(tg, (int, str)) or \
                not str(tg).isdigit() or not 1 <= int(tg) <= 2 ** 53:
            raise ApiError(422, "INVALID_OWNER", "telegram_id: положительное число")
        out["telegram_id"] = int(tg)
    if raw.get("shared") is not None:
        if not isinstance(raw["shared"], bool):
            raise ApiError(422, "INVALID_OWNER", "shared: true или false")
        out["shared"] = raw["shared"]
    if not out:
        raise ApiError(422, "INVALID_OWNER",
                       "нужно хотя бы одно поле: label, user_id, telegram_id")
    out["updated"] = round(time.time())
    return out


def h_owners_put(req):
    """
    Загрузка карты «адрес → человек» целиком или по частям.

    Сюда будет писать резолвер панели, когда он появится: Shape сам никуда
    за этими сведениями не ходит и ходить не должен.
    """
    body = req["body"]
    if not isinstance(body, dict):
        raise bad("INVALID_BODY", "тело запроса должно быть объектом JSON")
    items = body.get("items", body)
    if not isinstance(items, dict) or not items:
        raise bad("INVALID_BODY", "передай {\"items\": {\"1.2.3.4\": {...}}}")
    if len(items) > 5000:
        raise ApiError(413, "TOO_MANY_ITEMS", "не больше 5000 адресов за раз")

    prepared = {v_ip(ip): _owner_record(rec) for ip, rec in items.items()}
    replace = bool(body.get("replace"))

    def apply(owners):
        if replace:
            owners.clear()
        owners.update(prepared)
        return len(owners)

    total = S.owners_update(apply)
    S.log_event("api_action", source="api", request_id=req["request_id"],
                message=f"owners {'replace' if replace else 'update'} "
                        f"{len(prepared)}")
    return 200, {"updated": len(prepared), "total": total, "replaced": replace}


def h_owner_delete(req, ip):
    ip = v_ip(ip)
    if ip not in S.load_owners():
        raise ApiError(404, "OWNER_NOT_FOUND", "для этого адреса сведений нет")
    S.owners_update(lambda o: o.pop(ip, None))
    S.log_event("api_action", ip=ip, source="api",
                request_id=req["request_id"], message="owner removed")
    return 200, {"ip": ip, "removed": True}


def h_personal_list(req):
    items = [S.limit_row(ip, p) for ip, p in sorted(S.personal_list().items())]
    return 200, {"items": items, "count": len(items)}


def h_personal_put(req, ip):
    """Постоянная скорость для адреса — выше или ниже общего лимита."""
    ip = v_ip(ip)
    body = req["body"] if isinstance(req["body"], dict) else {}
    mbps = v_speed(body.get("mbps", body.get("download_mbps")), "mbps")
    note = v_reason(body.get("note"), "note")
    if not engine_loaded():
        raise ApiError(503, "ENGINE_NOT_RUNNING", "движок не запущен")
    if ip in S.whitelist_ips():
        raise ApiError(409, "IP_WHITELISTED",
                       "адрес в белом списке — шейпер его не трогает")
    existing = S.load_penalties().get(ip)
    if existing and not S.is_personal(existing):
        raise ApiError(409, "LIMIT_ACTIVE",
                       "на адресе действует ограничение, сними его сначала")
    try:
        entry = S.personal_set(ip, mbps, note, subject=S.owner_of(ip))
    except SystemExit:
        raise ApiError(503, "ENGINE_ERROR", "не удалось записать в ядро") from None
    S.log_event("api_action", ip=ip, source="api", request_id=req["request_id"],
                message=f"personal {mbps:g}")
    return 200, S.limit_row(ip, entry)


def h_personal_delete(req, ip):
    ip = v_ip(ip)
    if S.personal_clear(ip) is None:
        raise ApiError(404, "PERSONAL_NOT_FOUND",
                       "у этого адреса нет персональной скорости")
    S.log_event("api_action", ip=ip, source="api",
                request_id=req["request_id"], message="personal off")
    return 200, {"ip": ip, "removed": True}


# ── метрики для Prometheus ────────────────────────────────────────────────
def h_metrics(req):
    """
    Тот же текст, что печатает `shaperctl.py metrics`. Сборка живёт в общем
    слое, здесь только подстановка уже прочитанного: у API есть свой кэш
    тяжёлых чтений, и дважды дампить карты на каждый запрос незачем.

    Возвращает строку, а не словарь — отдаётся как text/plain.
    """
    users = {}
    if engine_loaded():
        users = cached("stats_snapshot", CACHE_TTL,
                       lambda: {"t": time.monotonic(), "users": S.read_users()})["users"]

    def day_events():
        rows, _ = S.read_events(limit=1000, since=time.time() - 86400)
        counted = {}
        for r in rows:
            key = r.get("type", "unknown")
            counted[key] = counted.get(key, 0) + 1
        return counted

    text = S.build_metrics(
        users=users,
        unit_state=systemd_active("shaper-watch"),
        started=engine_started_at(),
        events=cached("metrics_events", 30.0, day_events),
    )
    # Метрика самого API: её нет в общем слое, потому что без API её просто
    # не существует. Дописываем к общему тексту перед последней пустой строкой.
    node = S.node_label(S.load_config()["telegram"])
    extra = (f"# HELP shape_api_up 1 if the node API is running\n"
             f"# TYPE shape_api_up gauge\n"
             f'shape_api_up{{node="{S.metrics_escape(node)}",'
             f'version="{API_VERSION}"}} 1\n'
             f"# HELP shape_api_uptime_seconds Seconds since the API started\n"
             f"# TYPE shape_api_uptime_seconds gauge\n"
             f'shape_api_uptime_seconds{{node="{S.metrics_escape(node)}"}} '
             f"{round(time.time() - PROC_STARTED)}\n")
    return 200, text + extra


# ── OpenAPI ───────────────────────────────────────────────────────────────
def openapi_spec():
    def resp(code, desc):
        return {str(code): {"description": desc,
                            "content": {"application/json": {"schema": {"type": "object"}}}}}

    errors = {}
    for code, desc in ((400, "Некорректный запрос"), (401, "Нет или неверный токен"),
                       (403, "Токен без нужных прав"), (404, "Не найдено"),
                       (409, "Конфликт состояния"), (422, "Ошибка валидации"),
                       (429, "Слишком много запросов"), (503, "Движок недоступен")):
        errors.update(resp(code, desc))

    def op(summary, scope, params=None, body=None, ok_code=200, ok_desc="Успех"):
        o = {"summary": summary, "tags": ["shape"],
             "security": [] if scope is None else [{"bearerAuth": []}],
             "responses": dict(resp(ok_code, ok_desc), **errors)}
        if scope:
            o["description"] = f"Требуется токен с правом {scope}."
        if params:
            o["parameters"] = params
        if body:
            o["requestBody"] = {"required": True, "content":
                                {"application/json": {"schema": body}}}
        return o

    ip_param = [{"name": "ip", "in": "path", "required": True,
                 "schema": {"type": "string"}, "example": "203.0.113.10"}]
    limit_body = {
        "type": "object",
        "required": ["ip", "download_mbps"],
        "properties": {
            "ip": {"type": "string", "example": "203.0.113.10"},
            "download_mbps": {"type": "number", "minimum": 0.05, "example": 1},
            "upload_mbps": {"type": "number",
                            "description": "если задан, должен совпадать с download_mbps"},
            "duration": {"type": "integer", "minimum": 10, "maximum": 2592000,
                         "default": 3600, "example": 43200},
            "reason": {"type": "string", "maxLength": 64, "example": "torrent"},
        },
    }
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Shape Node API",
            "version": API_VERSION,
            "description": (
                "Локальный интерфейс управления шейпером одной ноды. "
                "Каждая нода самостоятельна: общего состояния между нодами нет."),
        },
        "servers": [{"url": "/api/v1"}],
        "components": {"securitySchemes": {"bearerAuth": {
            "type": "http", "scheme": "bearer",
            "description": "Токен чтения или записи из /etc/shaper/api.json"}}},
        "paths": {
            "/health": {"get": op("Живость сервиса", None)},
            "/status": {"get": op("Состояние Shape и API", "чтения")},
            "/node": {"get": op("Сведения о ноде", "чтения")},
            "/limits": {
                "get": op("Список активных ограничений", "чтения"),
                "post": op("Создать ограничение", "записи", body=limit_body,
                           ok_code=201, ok_desc="Ограничение создано"),
            },
            "/limits/{ip}": {
                "get": op("Ограничение конкретного адреса", "чтения", ip_param),
                "delete": op("Снять ограничение", "записи", ip_param),
            },
            "/limits/{ip}/temporary": {
                "post": op("Временное ограничение адреса", "записи", ip_param,
                           limit_body, 201, "Ограничение создано"),
                "delete": op("Снять временное ограничение", "записи", ip_param),
            },
            "/stats": {"get": op("Статистика трафика", "чтения")},
            "/top": {"get": op("Верхушка адресов по текущей нагрузке", "чтения", [
                {"name": "limit", "in": "query",
                 "schema": {"type": "integer", "minimum": 1,
                            "maximum": TOP_MAX, "default": TOP_DEFAULT}},
                {"name": "sort", "in": "query",
                 "schema": {"type": "string", "enum": list(TOP_SORTS),
                            "default": "download"}},
            ])},
            "/events": {"get": op("Журнал событий", "чтения", [
                {"name": "cursor", "in": "query", "schema": {"type": "integer"}},
                {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                {"name": "type", "in": "query", "schema": {
                    "type": "string", "enum": sorted(S.EVENT_TYPES)}},
                {"name": "ip", "in": "query", "schema": {"type": "string"}},
                {"name": "since", "in": "query", "schema": {"type": "number"}},
                {"name": "until", "in": "query", "schema": {"type": "number"}},
            ])},
            "/config": {
                "get": op("Безопасная часть настроек", "чтения"),
                "patch": op("Изменить разрешённые настройки", "записи", body={
                    "type": "object",
                    "properties": {k: {"type": "boolean" if v[1] is bool else "number"}
                                   for k, v in CONFIG_WRITABLE.items()}}),
            },
            "/bpf/status": {"get": op("Состояние eBPF и карт", "чтения")},
            "/history": {"get": op("Трафик по суткам", "чтения", [
                {"name": "days", "in": "query", "schema": {"type": "integer"},
                 "description": "сколько последних суток вернуть, по умолчанию 30"},
            ])},
            "/owners": {
                "get": op("Кто стоит за адресами", "чтения"),
                "put": op("Загрузить карту «адрес → человек»", "записи", body={
                    "type": "object",
                    "properties": {
                        "items": {"type": "object", "additionalProperties": {
                            "type": "object",
                            "properties": {
                                "label": {"type": "string", "maxLength": 64},
                                "user_id": {"type": "string", "maxLength": 64},
                                "telegram_id": {"type": "integer"},
                                "shared": {"type": "boolean",
                                           "description": "за адресом несколько человек"},
                            }}},
                        "replace": {"type": "boolean",
                                    "description": "true — заменить карту целиком"},
                    }}),
            },
            "/owners/{ip}": {"delete": op("Забыть владельца адреса", "записи",
                                          ip_param)},
            "/personal": {"get": op("Постоянные персональные скорости", "чтения")},
            "/personal/{ip}": {
                "put": op("Назначить адресу постоянную скорость", "записи",
                          ip_param, {
                              "type": "object",
                              "required": ["mbps"],
                              "properties": {
                                  "mbps": {"type": "number", "example": 25,
                                           "description": "выше или ниже общего лимита"},
                                  "note": {"type": "string", "maxLength": 64},
                              }}),
                "delete": op("Снять персональную скорость", "записи", ip_param),
            },
            "/metrics": {"get": {
                "summary": "Метрики в формате Prometheus",
                "description": "Текст, не JSON. Доступен также по /metrics без "
                               "префикса /api/v1. Требует токен чтения, если в "
                               "настройках не включён metrics_public.",
                "tags": ["shape"],
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "Метрики",
                                      "content": {"text/plain": {}}}},
            }},
        },
    }


DOCS_HTML = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><title>Shape Node API</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head><body><div id="ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({url:"/api/v1/openapi.json",dom_id:"#ui"});</script>
</body></html>"""


# ── маршруты ──────────────────────────────────────────────────────────────
# scope: None — без токена, "read" — токен чтения или записи, "write" — только
# токен записи. Разделение прав заложено здесь: добавить третью роль позже
# значит дописать строку в таблицу, а не переделывать проверку.
ROUTES = [
    ("GET",    r"^/api/v1/health$",                    None,    h_health),
    ("GET",    r"^/api/v1/status$",                    "read",  h_status),
    ("GET",    r"^/api/v1/node$",                      "read",  h_node),
    ("GET",    r"^/api/v1/limits$",                    "read",  h_limits_list),
    ("POST",   r"^/api/v1/limits$",                    "write", h_limit_create),
    ("GET",    r"^/api/v1/limits/([^/]{1,45})$",       "read",  h_limit_get),
    ("DELETE", r"^/api/v1/limits/([^/]{1,45})$",       "write", h_limit_delete),
    ("POST",   r"^/api/v1/limits/([^/]{1,45})/temporary$",   "write", h_limit_create),
    ("DELETE", r"^/api/v1/limits/([^/]{1,45})/temporary$",   "write", h_limit_delete),
    ("GET",    r"^/api/v1/stats$",                     "read",  h_stats),
    ("GET",    r"^/api/v1/top$",                       "read",  h_top),
    ("GET",    r"^/api/v1/events$",                    "read",  h_events),
    ("GET",    r"^/api/v1/config$",                    "read",  h_config_get),
    ("PATCH",  r"^/api/v1/config$",                    "write", h_config_patch),
    ("GET",    r"^/api/v1/bpf/status$",                "read",  h_bpf_status),
    ("GET",    r"^/api/v1/history$",                   "read",  h_history),
    ("GET",    r"^/api/v1/owners$",                    "read",  h_owners_list),
    ("PUT",    r"^/api/v1/owners$",                    "write", h_owners_put),
    ("DELETE", r"^/api/v1/owners/([^/]{1,45})$",       "write", h_owner_delete),
    ("GET",    r"^/api/v1/personal$",                  "read",  h_personal_list),
    ("PUT",    r"^/api/v1/personal/([^/]{1,45})$",     "write", h_personal_put),
    ("DELETE", r"^/api/v1/personal/([^/]{1,45})$",     "write", h_personal_delete),
    # Метрики отдаются и по короткому пути: так их ждёт Prometheus по умолчанию.
    ("GET",    r"^/api/v1/metrics$",                   "read",  h_metrics),
    ("GET",    r"^/metrics$",                          "read",  h_metrics),
]
COMPILED = [(m, re.compile(p), scope, fn) for m, p, scope, fn in ROUTES]
WRITE_METHODS = {"POST", "PATCH", "PUT", "DELETE"}


# ── ограничение частоты ───────────────────────────────────────────────────
class RateLimiter:
    """
    Скользящее окно в минуту на клиента. Словарь ограничен по размеру:
    иначе поток запросов с разных адресов сам стал бы утечкой памяти.
    """

    MAX_CLIENTS = 4096

    def __init__(self):
        self.hits = {}
        self.lock = threading.Lock()

    def allow(self, client, bucket, per_min):
        now = time.monotonic()
        key = (client, bucket)
        with self.lock:
            if len(self.hits) > self.MAX_CLIENTS:
                cutoff = now - 60
                self.hits = {k: v for k, v in self.hits.items()
                             if v and v[-1] > cutoff}
                if len(self.hits) > self.MAX_CLIENTS:
                    self.hits.clear()
            times = [t for t in self.hits.get(key, []) if now - t < 60]
            if len(times) >= per_min:
                self.hits[key] = times
                return False, int(60 - (now - times[0])) + 1
            times.append(now)
            self.hits[key] = times
            return True, 0


LIMITER = RateLimiter()


def log(**fields):
    """Одна строка JSON в journald. Токенов здесь нет и быть не может."""
    fields.setdefault("ts", round(time.time(), 3))
    try:
        sys.stdout.write(json.dumps(fields, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    except Exception:
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = "shape-api"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ── служебное ──
    def log_message(self, fmt, *args):
        pass                      # свой журнал, стандартный не нужен

    def _client(self):
        try:
            return self.client_address[0]
        except Exception:
            return "?"

    def _send(self, status, payload, request_id=None, extra_headers=()):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if request_id:
            self.send_header("X-Request-Id", request_id)
        for k, v in extra_headers:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_text(self, status, text, request_id=None):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if request_id:
            self.send_header("X-Request-Id", request_id)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _error(self, err, request_id):
        # Тело запроса при ошибке мы обычно не читаем (например, отказали по
        # токену или по размеру). Оставлять такое соединение живым нельзя:
        # непрочитанные байты уедут в разбор следующего запроса.
        self.close_connection = True
        self._send(err.status,
                   {"error": {"code": err.code, "message": err.message,
                              "request_id": request_id}},
                   request_id,
                   extra_headers=(("WWW-Authenticate", "Bearer"),)
                   if err.status == 401 else ())

    # ── разбор запроса ──
    def _read_body(self):
        raw_len = self.headers.get("Content-Length", "")
        if not raw_len:
            if self.headers.get("Transfer-Encoding"):
                raise ApiError(411, "LENGTH_REQUIRED",
                               "нужен заголовок Content-Length")
            return None
        try:
            length = int(raw_len)
        except ValueError:
            raise bad("INVALID_LENGTH", "некорректный Content-Length") from None
        if length < 0:
            raise bad("INVALID_LENGTH", "некорректный Content-Length")
        if length > MAX_BODY:
            raise ApiError(413, "BODY_TOO_LARGE",
                           f"тело больше {MAX_BODY} байт")
        if length == 0:
            return None
        raw = self.rfile.read(length)
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if ctype and ctype != "application/json":
            raise ApiError(415, "UNSUPPORTED_MEDIA_TYPE",
                           "тело должно быть application/json")
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise bad("INVALID_JSON",
                      "тело запроса не является корректным JSON") from None

    def _authorize(self, scope, cfg, client, request_id):
        if scope is None:
            return "anonymous"
        header = self.headers.get("Authorization", "")
        token = header[7:].strip() if header[:7].lower() == "bearer " else ""
        if not token:
            raise ApiError(401, "UNAUTHORIZED", "нужен заголовок Authorization: Bearer")

        tokens = cfg["tokens"]
        # compare_digest, а не ==: сравнение по первому различию выдаёт токен
        # по времени ответа. Проверяем оба, чтобы время не зависело от роли.
        accept_old = float(tokens.get("previous_until") or 0) > time.time()

        def match(role):
            if bool(tokens.get(role)) and hmac.compare_digest(token, tokens[role]):
                return True
            prev = tokens.get(role + "_previous")
            return accept_old and bool(prev) and hmac.compare_digest(token, prev)

        is_write = match("write")
        is_read = match("read")
        if is_write:
            return "write"
        if is_read and scope == "read":
            return "read"
        if is_read:
            raise ApiError(403, "FORBIDDEN", "нужен токен с правом записи")

        ok, _ = LIMITER.allow(client, "authfail", cfg["auth_fail_per_min"])
        if not ok:
            raise ApiError(429, "RATE_LIMITED",
                           "слишком много неудачных попыток, подожди минуту")
        raise ApiError(401, "UNAUTHORIZED", "неверный токен")

    def _dispatch(self, method):
        request_id = uuid.uuid4().hex[:16]
        started = time.monotonic()
        client = self._client()
        cfg = api_config()
        path, _, raw_query = self.path.partition("?")
        path = path.rstrip("/") or "/"
        status = 500
        scope_used = "-"
        try:
            # доступ по адресу — до всего остального
            if cfg["allowed_ips"] and not ip_allowed(client, cfg["allowed_ips"]):
                raise ApiError(403, "FORBIDDEN", "адрес не в списке разрешённых")

            if path in ("/api/v1/openapi.json", "/api/v1/docs"):
                if not cfg["expose_docs"]:
                    raise ApiError(404, "NOT_FOUND", "документация отключена")
                if path.endswith("docs"):
                    body = DOCS_HTML.encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    status = 200
                    return
                status = 200
                self._send(200, openapi_spec(), request_id)
                return

            match = args = None
            allowed_methods = set()
            for m, rx, scope, fn in COMPILED:
                hit = rx.match(path)
                if hit:
                    allowed_methods.add(m)
                    if m == method:
                        match, args = (scope, fn), hit.groups()
            if match is None:
                if allowed_methods:
                    raise ApiError(405, "METHOD_NOT_ALLOWED",
                                   "допустимо: " + ", ".join(sorted(allowed_methods)))
                raise ApiError(404, "NOT_FOUND", "нет такого метода API")

            scope, fn = match
            if fn is h_metrics and cfg.get("metrics_public"):
                scope = None
            scope_used = self._authorize(scope, cfg, client, request_id)

            if scope is None:
                # health опрашивает мониторинг, и резать его теми же цифрами,
                # что и обычные чтения, нельзя: одна проверка раз в 10 секунд
                # с трёх систем уже упёрлась бы в лимит. Но и без потолка
                # оставлять нельзя — endpoint открыт без токена.
                bucket, per_min = "public", 600
            elif method in WRITE_METHODS:
                bucket, per_min = "write", cfg["rate_write_per_min"]
            else:
                bucket, per_min = "read", cfg["rate_read_per_min"]
            ok, retry = LIMITER.allow(client, bucket, per_min)
            if not ok:
                raise ApiError(429, "RATE_LIMITED",
                               f"превышен предел запросов, повтори через {retry} с")

            body = self._read_body()
            query = {}
            for part in raw_query.split("&"):
                if not part:
                    continue
                k, _, v = part.partition("=")
                if len(k) < 32 and len(v) < 128:
                    query[unquote_plus(k)] = unquote_plus(v)

            req = {"body": body, "query": query, "request_id": request_id,
                   "client": client, "scope": scope_used}
            status, payload = fn(req, *args)
            if isinstance(payload, str):
                # метрики Prometheus — простой текст, не JSON
                self._send_text(status, payload, request_id)
            else:
                self._send(status, payload, request_id)

        except ApiError as e:
            status = e.status
            self._error(e, request_id)
        except (BrokenPipeError, ConnectionResetError):
            status = 499
        except Exception as e:
            # Наружу — только код. Подробности остаются в журнале ноды.
            status = 500
            log(level="error", request_id=request_id, path=path, method=method,
                error=type(e).__name__, detail=str(e)[:300])
            with contextlib.suppress(Exception):
                self._error(ApiError(500, "INTERNAL_ERROR",
                                     "внутренняя ошибка, подробности в журнале ноды"),
                            request_id)
        finally:
            log(level="info", request_id=request_id, client=client,
                method=method, path=path[:200], status=status, scope=scope_used,
                duration_ms=round((time.monotonic() - started) * 1000, 1))

    def do_GET(self):     self._dispatch("GET")
    def do_POST(self):    self._dispatch("POST")
    def do_DELETE(self):  self._dispatch("DELETE")
    def do_PATCH(self):   self._dispatch("PATCH")
    def do_PUT(self):     self._dispatch("PUT")

    def do_HEAD(self):
        self._dispatch("GET")


def ip_allowed(client, allowed):
    try:
        addr = ipaddress.ip_address(client)
    except ValueError:
        return False
    for entry in allowed:
        try:
            if addr in ipaddress.ip_network(str(entry), strict=False):
                return True
        except ValueError:
            continue
    return False


class Server(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    # Очередь на приём: за ней клиент получит отказ соединения, а не будет
    # копиться в памяти процесса.
    request_queue_size = 32
    allow_reuse_address = True

    def __init__(self, *a, **kw):
        self._slots = threading.Semaphore(MAX_WORKERS)
        super().__init__(*a, **kw)

    def process_request_thread(self, request, client_address):
        # Больше MAX_WORKERS одновременных обработчиков не запускаем: каждый
        # может дёрнуть bpftool, а ядро у ноды бывает одно.
        if not self._slots.acquire(timeout=5):
            with contextlib.suppress(Exception):
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\n"
                                b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            self.shutdown_request(request)
            return
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def finish_request(self, request, client_address):
        request.settimeout(30)
        super().finish_request(request, client_address)


def ensure_tokens():
    """
    Токены генерируются на самой ноде и нигде больше не появляются: ни в
    репозитории, ни в образе, ни в журнале. Если файла нет — создаём.
    """
    cfg = api_config()
    changed = False
    for role in ("read", "write"):
        if not cfg["tokens"].get(role):
            cfg["tokens"][role] = secrets.token_urlsafe(32)
            changed = True
    if changed or not os.path.exists(API_CONF):
        save_api_config(cfg)
    return cfg


def main():
    if os.geteuid() != 0:
        print("shape-api: нужны права root (доступ к картам BPF)", file=sys.stderr)
        return 1
    cfg = ensure_tokens()

    if len(sys.argv) > 1 and sys.argv[1] == "--print-tokens":
        print(f"read:  {cfg['tokens']['read']}")
        print(f"write: {cfg['tokens']['write']}")
        return 0

    bind, port = cfg["bind_address"], int(cfg["port"])
    try:
        ipaddress.ip_address(bind)
    except ValueError:
        print(f"shape-api: некорректный bind_address «{bind}»", file=sys.stderr)
        return 1
    if not 1 <= port <= 65535:
        print(f"shape-api: некорректный port {port}", file=sys.stderr)
        return 1

    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    Server.address_family = family
    srv = Server((bind, port), Handler)
    log(level="info", event="started", bind=bind, port=port,
        shape_version=shape_version(), api_version=API_VERSION,
        docs=f"http://{bind}:{port}/api/v1/docs" if cfg["expose_docs"] else None)
    try:
        srv.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        log(level="info", event="stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())

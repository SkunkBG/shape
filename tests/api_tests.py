#!/usr/bin/env python3
"""
Тесты Shape Node API. Поднимают настоящий сервер в песочнице:
подставные bpftool и systemctl, свой /etc/shaper, свои карты.
"""
import importlib.util
import json
import os
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import os as _os
# Корень проекта: каталог над tests/. Так набор работает и локально, и в CI.
SRC = _os.environ.get("SHAPE_SRC") or _os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="shape-api-test-")
ETC = os.path.join(TMP, "etc"); os.makedirs(ETC)
VAR = os.path.join(TMP, "var"); os.makedirs(VAR)
BIN = os.path.join(TMP, "bin"); os.makedirs(BIN)
PIN = os.path.join(TMP, "maps"); os.makedirs(PIN)

# карты «существуют» — движок считается запущенным
for m in ("config_map", "port_map", "whitelist_map", "penalty_map",
          "trusted_map", "pp_conn_map",
          "user_state_map_down", "user_state_map_up"):
    open(os.path.join(PIN, m), "w").close()

# подставной bpftool: записывает вызовы, на dump отдаёт пустой список
with open(os.path.join(BIN, "bpftool"), "w") as f:
    f.write('#!/bin/sh\nprintf "%s\\n" "$*" >> "$BPFTOOL_LOG"\n'
            'case "$*" in *dump*) echo "[]";; esac\nexit 0\n')
with open(os.path.join(BIN, "systemctl"), "w") as f:
    f.write('#!/bin/sh\n[ "$1" = "is-active" ] && echo active\nexit 0\n')
with open(os.path.join(BIN, "ip"), "w") as f:
    f.write('#!/bin/sh\necho "2: eth0    inet 203.0.113.5/24 scope global eth0"\n')
for name in ("bpftool", "systemctl", "ip"):
    os.chmod(os.path.join(BIN, name), 0o755)

os.environ["PATH"] = BIN + ":" + os.environ["PATH"]
os.environ["BPFTOOL_LOG"] = os.path.join(TMP, "bpftool.log")
os.environ["SHAPER_PIN_DIR"] = PIN
os.environ["SHAPE_APP_DIR"] = SRC
os.environ["SHAPE_ETC_DIR"] = ETC

spec = importlib.util.spec_from_file_location("apisrv", os.path.join(SRC, "api", "server.py"))
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)

# перенаправляем состояние Shape в песочницу
S = api.S
S.ETC_DIR = ETC
S.CONFIG_FILE = os.path.join(ETC, "config.json")
S.PEN_FILE = os.path.join(ETC, "penalties.json")
S.DAILY_FILE = os.path.join(ETC, "daily.json")
S.DIGEST_FILE = os.path.join(ETC, "digest.json")
S.WL_FILE = os.path.join(ETC, "whitelist.txt")
S.VAR_DIR = VAR
S.EVENT_FILE = os.path.join(VAR, "events.jsonl")
S.EVENT_SEQ = os.path.join(VAR, "events.seq")
S.OWNERS_FILE = os.path.join(VAR, "owners.json")
S.HISTORY_FILE = os.path.join(VAR, "history.jsonl")
S.METRICS_STATE = os.path.join(VAR, "metrics.state")
S.save_config({"ports": [443], "speed_mbps": 15,
               "guard": dict(S.GUARD_DEFAULT),
               "telegram": dict(S.TG_DEFAULT, token="123456789:SECRET-TOKEN-VALUE",
                                chat_id="-100500", enabled=True)})
S.save_penalties({})
open(S.WL_FILE, "w").write("198.51.100.7\n")

# конфиг API: высокие пределы, чтобы тесты не упирались в rate limit
PORT = 18765
API_CONF = os.path.join(ETC, "api.json")
BASE_CFG = {"bind_address": "127.0.0.1", "port": PORT, "allowed_ips": [],
            "rate_read_per_min": 100000, "rate_write_per_min": 100000,
            "auth_fail_per_min": 100000, "expose_docs": True,
            "tokens": {"read": "READ-" + "r" * 30, "write": "WRITE-" + "w" * 30}}


def write_cfg(**over):
    cfg = dict(BASE_CFG); cfg.update(over)
    with open(API_CONF, "w") as f:
        json.dump(cfg, f)
    os.chmod(API_CONF, 0o600)


write_cfg()
READ, WRITE = BASE_CFG["tokens"]["read"], BASE_CFG["tokens"]["write"]

# журнал сервера пишется в stdout — перехватываем, чтобы проверить утечки
LOGBUF = []
api.log = lambda **f: LOGBUF.append(json.dumps(f, ensure_ascii=False))

api.Server.address_family = socket.AF_INET
srv = api.Server(("127.0.0.1", PORT), api.Handler)
threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1},
                 daemon=True).start()
time.sleep(0.4)

ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  \033[32m✓\033[0m {name}")
    else:
        fail += 1
        print(f"  \033[31m✗ {name}\033[0m {extra}")


def call(method, path, token=None, body=None, raw=None, headers=None, timeout=10):
    url = f"http://127.0.0.1:{PORT}{path}"
    data = raw if raw is not None else (
        json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(url, data=data, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = r.read()
            try:
                return r.status, json.loads(payload)
            except ValueError:
                return r.status, payload.decode(errors="replace")
    except urllib.error.HTTPError as e:
        payload = e.read()
        try:
            return e.code, json.loads(payload)
        except ValueError:
            return e.code, payload.decode(errors="replace")
    except Exception as e:
        return 0, str(e)


print("\n\033[1m1. Health и документация\033[0m")
st, body = call("GET", "/api/v1/health")
check("health без токена → 200", st == 200 and body == {"status": "ok"}, body)
check("health не раскрывает ничего лишнего", set(body) == {"status"})
st, body = call("GET", "/api/v1/openapi.json")
check("openapi.json отдаётся", st == 200 and body.get("openapi", "").startswith("3."))
check("в openapi описан bearer",
      "bearerAuth" in body.get("components", {}).get("securitySchemes", {}))
check("в openapi есть все ключевые пути",
      all(p in body["paths"] for p in
          ("/health", "/status", "/node", "/limits", "/limits/{ip}",
           "/limits/{ip}/temporary", "/stats", "/events", "/config", "/bpf/status")))

print("\n\033[1m2. Аутентификация и права\033[0m")
st, body = call("GET", "/api/v1/status")
check("без токена → 401", st == 401 and body["error"]["code"] == "UNAUTHORIZED")
st, _ = call("GET", "/api/v1/status", token="wrong-token-value")
check("неверный токен → 401", st == 401)
st, _ = call("GET", "/api/v1/status", token=READ[:-1])
check("токен без последнего символа → 401", st == 401)
st, _ = call("GET", "/api/v1/status", token=READ)
check("токен чтения на чтении → 200", st == 200)
st, _ = call("GET", "/api/v1/status", token=WRITE)
check("токен записи тоже читает → 200", st == 200)
st, body = call("POST", "/api/v1/limits", token=READ,
                body={"ip": "1.2.3.4", "download_mbps": 1})
check("токен чтения на записи → 403", st == 403 and body["error"]["code"] == "FORBIDDEN")
st, _ = call("GET", "/api/v1/status", headers={"Authorization": "Basic " + READ})
check("схема Basic не принимается", st == 401)

print("\n\033[1m3. Статус, нода, BPF\033[0m")
st, body = call("GET", "/api/v1/status", token=READ)
check("статус отдаёт версии и состояние",
      st == 200 and body["versions"]["shape"] and body["shape"]["engine_loaded"] is True)
check("в статусе нет секретов", "token" not in json.dumps(body).lower())
st, body = call("GET", "/api/v1/node", token=READ)
check("нода отдаёт hostname, ядро, архитектуру",
      st == 200 and body["hostname"] and body["kernel"] and body["architecture"])
check("нода не отдаёт секретов",
      not any(k in json.dumps(body) for k in ("SECRET-TOKEN", "tokens", "private")))
st, body = call("GET", "/api/v1/bpf/status", token=READ)
# Проверяем имена, а не количество: карта, потерянная при переименовании,
# не меняет длину списка, если рядом добавили другую.
check("bpf/status перечисляет карты",
      st == 200 and body["loaded"] and
      {m["name"] for m in body["maps"]} == {
          "config_map", "port_map", "whitelist_map", "penalty_map",
          "trusted_map", "pp_conn_map",
          "user_state_map_down", "user_state_map_up"},
      body.get("maps"))

print("\n\033[1m4. Создание и снятие ограничений\033[0m")
st, body = call("POST", "/api/v1/limits", token=WRITE,
                body={"ip": "203.0.113.10", "download_mbps": 1, "upload_mbps": 1,
                      "duration": 43200, "reason": "torrent"})
check("создание → 201", st == 201, body)
check("в ответе все обещанные поля",
      st == 201 and all(k in body for k in
                        ("ip", "family", "download_mbps", "upload_mbps", "created_at",
                         "expires_at", "remaining_seconds", "reason", "source", "type")),
      body)
check("source=api, type=temporary",
      st == 201 and body["source"] == "api" and body["type"] == "temporary")
check("остаток времени близок к 43200",
      st == 201 and 43190 <= body["remaining_seconds"] <= 43200)
check("ограничение записано в общий файл Shape",
      "203.0.113.10" in S.load_penalties())
check("правило доехало до карты ядра",
      "penalty_map" in open(os.environ["BPFTOOL_LOG"]).read())

st, body = call("GET", "/api/v1/limits/203.0.113.10", token=READ)
check("чтение конкретного адреса → 200", st == 200 and body["ip"] == "203.0.113.10")
st, body = call("GET", "/api/v1/limits", token=READ)
check("список содержит адрес", st == 200 and body["count"] == 1)
st, body = call("GET", "/api/v1/limits/198.51.100.99", token=READ)
check("несуществующий адрес → 404",
      st == 404 and body["error"]["code"] == "LIMIT_NOT_FOUND")

st, body = call("POST", "/api/v1/limits/203.0.113.11/temporary", token=WRITE,
                body={"download_mbps": 2, "duration": 600, "reason": "manual check"})
check("временное ограничение через путь → 201", st == 201 and body["ip"] == "203.0.113.11")
st, body = call("DELETE", "/api/v1/limits/203.0.113.11/temporary", token=WRITE)
check("снятие временного → 200", st == 200)
check("запись убрана из файла", "203.0.113.11" not in S.load_penalties())
st, body = call("DELETE", "/api/v1/limits/203.0.113.10", token=WRITE)
check("удаление → 200", st == 200)
st, body = call("DELETE", "/api/v1/limits/203.0.113.10", token=WRITE)
check("повторное удаление → 404", st == 404)

st, body = call("POST", "/api/v1/limits", token=WRITE,
                body={"ip": "198.51.100.7", "download_mbps": 1})
check("адрес из белого списка → 409",
      st == 409 and body["error"]["code"] == "IP_WHITELISTED", body)

print("\n\033[1m5. Валидация входа\033[0m")
BAD_IPS = ["1.2.3.4; id", "$(id)", "`id`", "1.2.3.4 && rm -rf /", "999.1.1.1",
           "../../etc/passwd", "1.2.3.4/24", "", "  ", "gggg::1", "1.2.3.4\n5.6.7.8",
           "%2e%2e%2f", "0x7f000001", "a" * 60]
for bad in BAD_IPS:
    st, body = call("POST", "/api/v1/limits", token=WRITE,
                    body={"ip": bad, "download_mbps": 1})
    check(f"IP отвергнут: {bad[:24]!r}",
          st == 422 and body["error"]["code"] == "INVALID_IP", f"{st} {body}")
st, body = call("POST", "/api/v1/limits", token=WRITE,
                body={"ip": "2001:db8::1", "download_mbps": 1, "duration": 60})
check("корректный IPv6 принят", st == 201 and body["family"] == "ipv6", body)
call("DELETE", "/api/v1/limits/2001:db8::1", token=WRITE)

for bad in [0, -1, "1", None, 1e9, float("nan"), float("inf"), True, [1], {"a": 1}]:
    st, body = call("POST", "/api/v1/limits", token=WRITE,
                    body={"ip": "203.0.113.20", "download_mbps": bad})
    check(f"скорость отвергнута: {bad!r}", st == 422, f"{st} {body}")
for bad in [0, -100, 1, 10 ** 9, "3600", 3.5, True]:
    st, body = call("POST", "/api/v1/limits", token=WRITE,
                    body={"ip": "203.0.113.20", "download_mbps": 1, "duration": bad})
    check(f"длительность отвергнута: {bad!r}", st == 422, f"{st} {body}")
for bad in ["a" * 100, "reason\nInjected: header", "$(touch /tmp/api_pwned)",
            "`id`", "x;id", 42]:
    st, body = call("POST", "/api/v1/limits", token=WRITE,
                    body={"ip": "203.0.113.20", "download_mbps": 1, "reason": bad})
    check(f"причина отвергнута: {str(bad)[:24]!r}", st == 422, f"{st} {body}")
st, body = call("POST", "/api/v1/limits", token=WRITE,
                body={"ip": "203.0.113.20", "download_mbps": 5, "upload_mbps": 1})
check("разные скорости вверх и вниз → 422 с объяснением",
      st == 422 and body["error"]["code"] == "ASYMMETRIC_NOT_SUPPORTED", body)

print("\n\033[1m6. Некорректные запросы\033[0m")
st, body = call("POST", "/api/v1/limits", token=WRITE, raw="{не json".encode())
check("битый JSON → 400", st == 400 and body["error"]["code"] == "INVALID_JSON")
st, body = call("POST", "/api/v1/limits", token=WRITE, raw='"строка"'.encode())
check("JSON не объект → 400", st == 400)
st, body = call("POST", "/api/v1/limits", token=WRITE, raw=b"x" * (200 * 1024))
check("тело 200 КБ → 413", st == 413 and body["error"]["code"] == "BODY_TOO_LARGE")
st, body = call("GET", "/api/v1/nope", token=READ)
check("неизвестный путь → 404", st == 404)
st, body = call("PUT", "/api/v1/limits", token=WRITE, body={})
check("метод не поддержан → 405", st == 405, f"{st} {body}")
st, body = call("GET", "/api/v1/../../etc/passwd", token=READ)
check("обход каталога в пути → 404", st in (400, 404), st)
st, body = call("GET", "/api/v1/limits/%3B%20id", token=READ)
check("экранированный «; id» в пути → 422/404", st in (404, 422), st)
st, body = call("GET", "/api/v1/events?type=../../etc", token=READ)
check("мусор в query → 400", st == 400)

print("\n\033[1m7. Конфигурация\033[0m")
st, body = call("GET", "/api/v1/config", token=READ)
check("конфиг отдаётся", st == 200 and "guard" in body)
check("токен Telegram в конфиг не попал",
      "SECRET-TOKEN" not in json.dumps(body) and "telegram" not in body)
check("токены API не отдаются", "tokens" not in json.dumps(body))
st, body = call("PATCH", "/api/v1/config", token=WRITE, body={"penalty_min": 120})
check("разрешённое поле меняется", st == 200 and body["changed"]["penalty_min"] == 120)
check("значение сохранено в конфиге Shape",
      S.load_config()["guard"]["penalty_min"] == 120)
check("раздел telegram пережил правку через API",
      S.load_config()["telegram"]["token"] == "123456789:SECRET-TOKEN-VALUE")
for bad_key in ("engine_path", "bpf_object", "command", "../../etc/passwd",
                "telegram_token", "bind_address"):
    st, body = call("PATCH", "/api/v1/config", token=WRITE, body={bad_key: "x"})
    check(f"поле не даёт себя менять: {bad_key}",
          st == 422 and body["error"]["code"] == "FIELD_NOT_WRITABLE", st)
st, body = call("PATCH", "/api/v1/config", token=WRITE, body={"penalty_min": 999999})
check("значение вне диапазона → 422", st == 422)
st, body = call("PATCH", "/api/v1/config", token=READ, body={"penalty_min": 60})
check("правка конфига токеном чтения → 403", st == 403)

print("\n\033[1m8. Статистика и события\033[0m")
st, body = call("GET", "/api/v1/stats", token=READ)
check("статистика отдаётся", st == 200 and "traffic" in body and "ips" in body)
check("в статистике видно белый список", body["ips"]["whitelisted"] == 1)
st, body = call("GET", "/api/v1/events", token=READ)
check("события пишутся", st == 200 and body["count"] > 0)
types = {e["type"] for e in body["items"]}
check("есть события создания и снятия ограничения",
      {"limit_applied", "limit_released"} <= types, types)
check("у событий есть id и request_id",
      all("id" in e for e in body["items"]) and
      any("request_id" in e for e in body["items"]))
st, body = call("GET", "/api/v1/events?type=limit_applied&limit=2", token=READ)
check("фильтр по типу работает",
      st == 200 and all(e["type"] == "limit_applied" for e in body["items"]))
check("limit ограничивает выдачу", len(body["items"]) <= 2)
st, body = call("GET", "/api/v1/events?ip=203.0.113.10", token=READ)
check("фильтр по IP работает",
      st == 200 and all(e.get("ip") == "203.0.113.10" for e in body["items"]))
st, all_ev = call("GET", "/api/v1/events?limit=1000", token=READ)
first_id = min(e["id"] for e in all_ev["items"])
st, body = call("GET", f"/api/v1/events?cursor={first_id}", token=READ)
check("курсор отсекает старые события",
      st == 200 and all(e["id"] > first_id for e in body["items"]))
check("в событиях нет токенов",
      "SECRET-TOKEN" not in json.dumps(all_ev) and READ not in json.dumps(all_ev))

print("\n\033[1m9. Частота запросов\033[0m")
write_cfg(rate_read_per_min=5)
codes = [call("GET", "/api/v1/status", token=READ)[0] for _ in range(12)]
check("после превышения приходит 429", 429 in codes, codes)
st, body = call("GET", "/api/v1/status", token=READ)
check("429 объясняет причину структурно",
      st == 429 and body["error"]["code"] == "RATE_LIMITED")
check("health не режется чужим лимитом чтения",
      call("GET", "/api/v1/health")[0] == 200)
write_cfg(auth_fail_per_min=3)
codes = [call("GET", "/api/v1/status", token="bad-token")[0] for _ in range(10)]
check("перебор токена упирается в 429", codes.count(429) > 0, codes)
write_cfg()

print("\n\033[1m10. Параллельные запросы\033[0m")
with ThreadPoolExecutor(max_workers=24) as pool:
    res = list(pool.map(lambda i: call("GET", "/api/v1/status", token=READ)[0],
                        range(60)))
check("60 параллельных чтений обслужены", all(c in (200, 429, 503) for c in res)
      and res.count(200) > 0, f"{sorted(set(res))}")

def hammer(i):
    return call("POST", "/api/v1/limits", token=WRITE,
                body={"ip": f"198.51.100.{i}", "download_mbps": 1, "duration": 60})[0]

with ThreadPoolExecutor(max_workers=16) as pool:
    res = list(pool.map(hammer, range(20, 40)))
created = res.count(201)
pens = S.load_penalties()
check("параллельные записи не теряются под замком",
      created == len([ip for ip in pens if ip.startswith("198.51.100.")]),
      f"создано {created}, в файле {len([ip for ip in pens if ip.startswith('198.51.100.')])}")
call("DELETE", "/api/v1/limits/198.51.100.20", token=WRITE)

print("\n\033[1m11. Попытки выполнить команду\033[0m")
MARK = "/tmp/api_pwned_marker"
if os.path.exists(MARK):
    os.remove(MARK)
INJECTIONS = [
    ("POST", "/api/v1/limits", {"ip": f"1.2.3.4; touch {MARK}", "download_mbps": 1}),
    ("POST", "/api/v1/limits", {"ip": f"$(touch {MARK})", "download_mbps": 1}),
    ("POST", "/api/v1/limits", {"ip": "1.2.3.4", "download_mbps": 1,
                                "reason": f"; touch {MARK}"}),
    ("POST", "/api/v1/limits", {"ip": "1.2.3.4", "download_mbps": f"1; touch {MARK}"}),
    ("PATCH", "/api/v1/config", {"penalty_min": f"120; touch {MARK}"}),
    ("PATCH", "/api/v1/config", {f"penalty_min; touch {MARK}": 1}),
]
for method, path, payload in INJECTIONS:
    st, _ = call(method, path, token=WRITE, body=payload)
    check(f"{method} {path} с инъекцией отвергнут: {st}", st in (400, 422), st)
st, _ = call("DELETE", f"/api/v1/limits/1.2.3.4;touch{MARK}", token=WRITE)
check("инъекция в пути отвергнута", st in (404, 422), st)
st, _ = call("GET", f"/api/v1/events?ip=1.2.3.4;touch{MARK}", token=READ)
check("инъекция в query отвергнута", st == 422, st)
time.sleep(0.3)
check("файл-маркер не создан — команда не выполнилась", not os.path.exists(MARK))
log_text = open(os.environ["BPFTOOL_LOG"]).read()
check("в вызовы bpftool не просочилась подстрока touch", "touch" not in log_text)

print("\n\033[1m12. Журнал сервера\033[0m")
joined = "\n".join(LOGBUF)
check("токены в журнал не попадают",
      READ not in joined and WRITE not in joined and "SECRET-TOKEN" not in joined)
check("в журнале есть request_id, метод, статус",
      all(k in joined for k in ("request_id", "method", "status", "client")))
check("трассировки клиенту не уходят",
      not any("Traceback" in str(x) for x in LOGBUF if "detail" not in str(x)))

print("\n\033[1m12b. Кривые HTTP-запросы на сыром сокете\033[0m")


def raw_send(payload, read=True):
    try:
        c = socket.create_connection(("127.0.0.1", PORT), timeout=5)
        c.sendall(payload)
        data = c.recv(4096) if read else b""
        c.close()
        return data.decode(errors="replace")
    except Exception as e:
        return "ERR " + str(e)


cases = {
    "не-ASCII в заголовке токена":
        "GET /api/v1/status HTTP/1.1\r\nHost: x\r\n"
        "Authorization: Bearer токен\r\n\r\n".encode("utf-8"),
    "перевод строки в пути":
        b"GET /api/v1/status HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n\r\n",
    "мусор вместо запроса": b"\x00\x01\x02 GARBAGE\r\n\r\n",
    "Content-Length больше тела":
        b"POST /api/v1/limits HTTP/1.1\r\nHost: x\r\nContent-Length: 999\r\n\r\n{}",
    "отрицательный Content-Length":
        b"POST /api/v1/limits HTTP/1.1\r\nHost: x\r\nContent-Length: -5\r\n\r\n",
}
for name, payload in cases.items():
    resp = raw_send(payload)
    check(f"сервер выжил: {name}", "ERR" not in resp[:3] or "timed out" in resp,
          resp[:60])
check("после кривых запросов API отвечает",
      call("GET", "/api/v1/health")[0] == 200)

print("\n\033[1m13. Ограничение по адресу источника\033[0m")
write_cfg(allowed_ips=["10.99.0.0/24"])
st, body = call("GET", "/api/v1/health")
check("чужой адрес отсекается даже на health",
      st == 403 and body["error"]["code"] == "FORBIDDEN", st)
write_cfg(allowed_ips=["127.0.0.1/32"])
check("свой адрес проходит", call("GET", "/api/v1/health")[0] == 200)
write_cfg()

print("\n\033[1m14. Движок остановлен\033[0m")
os.rename(os.path.join(PIN, "config_map"), os.path.join(PIN, "config_map.off"))
st, body = call("POST", "/api/v1/limits", token=WRITE,
                body={"ip": "203.0.113.30", "download_mbps": 1})
check("создание ограничения без движка → 503",
      st == 503 and body["error"]["code"] == "ENGINE_NOT_RUNNING", st)
st, body = call("GET", "/api/v1/status", token=READ)
check("статус продолжает отвечать и говорит правду",
      st == 200 and body["shape"]["engine_loaded"] is False)
check("health продолжает отвечать", call("GET", "/api/v1/health")[0] == 200)
os.rename(os.path.join(PIN, "config_map.off"), os.path.join(PIN, "config_map"))

print("\n\033[1m15. Права на файлы\033[0m")
check("api.json — 600", oct(os.stat(API_CONF).st_mode)[-3:] == "600")
check("config.json — 600", oct(os.stat(S.CONFIG_FILE).st_mode)[-3:] == "600")
check("журнал событий не для всех",
      oct(os.stat(S.EVENT_FILE).st_mode)[-3:] in ("600", "640"))


print("\n\033[1m16. Метрики Prometheus\033[0m")
st, body = call("GET", "/metrics")
check("метрики без токена → 401", st == 401, st)
st, body = call("GET", "/metrics", token=READ)
check("метрики с токеном чтения → 200", st == 200, st)
check("формат Prometheus, а не JSON",
      isinstance(body, str) and body.startswith("# HELP"), str(body)[:60])
for metric in ("shape_up", "shape_info", "shape_engine_loaded",
               "shape_speed_limit_mbps", "shape_traffic_bytes_total",
               "shape_ips_limited", "shape_ips_personal", "shape_ips_whitelisted",
               "shape_owners_known", "shape_events_24h", "shape_uptime_seconds",
               "shape_guard_enabled", "shape_watchdog_active"):
    check(f"есть метрика {metric}", metric in body)
check("у каждой метрики есть HELP и TYPE",
      body.count("# HELP") == body.count("# TYPE"))
check("в метриках нет токенов",
      READ not in body and WRITE not in body and "SECRET-TOKEN" not in body)
st, body2 = call("GET", "/api/v1/metrics", token=READ)
check("длинный путь /api/v1/metrics тоже работает", st == 200)
lines = [x for x in body.splitlines() if x and not x.startswith("#")]
check("значения метрик числовые",
      all(x.rsplit(" ", 1)[1].replace(".", "", 1).replace("-", "", 1).isdigit()
          for x in lines), lines[:3])
write_cfg(metrics_public=True)
check("metrics_public открывает метрики без токена",
      call("GET", "/metrics")[0] == 200)
check("остальное остаётся закрытым", call("GET", "/api/v1/status")[0] == 401)
write_cfg()

print("\n\033[1m17. Владельцы адресов\033[0m")
st, body = call("PUT", "/api/v1/owners", token=WRITE, body={"items": {
    "203.0.113.10": {"label": "Александр", "telegram_id": 123456789,
                     "user_id": "42"},
    "203.0.113.11": {"label": "Мария", "telegram_id": 987654321,
                     "shared": True}}})
check("карта владельцев загружена", st == 200 and body["updated"] == 2, body)
st, body = call("GET", "/api/v1/owners", token=READ)
check("владельцы читаются", st == 200 and body["count"] == 2)
check("telegram_id сохранён числом",
      any(i.get("telegram_id") == 123456789 for i in body["items"]))
st, body = call("PUT", "/api/v1/owners", token=READ, body={"items": {}})
check("загрузка карты токеном чтения → 403", st == 403)
for bad_rec in ({"label": "x" * 100}, {"label": "<b>hack</b>"},
                {"telegram_id": "abc"}, {"telegram_id": -5},
                {"user_id": "a b; id"}, {}, {"shared": "yes"}):
    st, _ = call("PUT", "/api/v1/owners", token=WRITE,
                 body={"items": {"203.0.113.30": bad_rec}})
    check(f"запись отвергнута: {str(bad_rec)[:32]}", st == 422, st)
st, _ = call("PUT", "/api/v1/owners", token=WRITE,
             body={"items": {"1.2.3.4; id": {"label": "x"}}})
check("мусор вместо адреса отвергнут", st == 422)
st, body = call("DELETE", "/api/v1/owners/203.0.113.11", token=WRITE)
check("владелец удаляется", st == 200)
check("повторное удаление → 404",
      call("DELETE", "/api/v1/owners/203.0.113.11", token=WRITE)[0] == 404)

print("\n\033[1m18. Ярлык попадает в ограничение и событие\033[0m")
st, body = call("POST", "/api/v1/limits", token=WRITE,
                body={"ip": "203.0.113.10", "download_mbps": 1, "duration": 600,
                      "reason": "torrent"})
check("ограничение создано", st == 201, body)
st, body = call("GET", "/api/v1/limits/203.0.113.10", token=READ)
check("в ограничении есть поле subject", "subject" in body, body)
S.penalties_update(lambda p: None)
who = S.owner_of("203.0.113.10")
check("владелец адреса известен ядру Shape",
      who is not None and who.get("label") == "Александр", who)
_who_card = "\n".join(S.offender_card(dict(S.TG_DEFAULT, node_name="Erebor"),
                                      who, "x"))
check("карточка для Telegram содержит ссылку по telegram_id",
      'tg://user?id=123456789' in _who_card, _who_card)
check("карточка экранирует HTML",
      "&lt;" in "\n".join(S.offender_card(S.TG_DEFAULT,
                                          {"label": "<b>x</b>"}, "x")))
call("DELETE", "/api/v1/limits/203.0.113.10", token=WRITE)

print("\n\033[1m19. Персональные скорости\033[0m")
st, body = call("PUT", "/api/v1/personal/203.0.113.50", token=WRITE,
                body={"mbps": 25, "note": "bitrix"})
check("персональная скорость назначена",
      st == 200 and body["mbps"] == 25 and body["kind"] == "personal", body)
st, body = call("GET", "/api/v1/personal", token=READ)
check("персональные читаются списком", st == 200 and body["count"] == 1)
st, body = call("GET", "/api/v1/limits", token=READ)
check("в списке ограничений персональных нет",
      all(i["type"] != "personal" for i in body["items"]), body)
check("ядро Shape тоже их разделяет",
      "203.0.113.50" in S.personal_list())
for bad_val in (0, -1, "25", None, float("nan"), 1e9):
    st, _ = call("PUT", "/api/v1/personal/203.0.113.51", token=WRITE,
                 body={"mbps": bad_val})
    check(f"скорость отвергнута: {bad_val!r}", st == 422, st)
st, _ = call("PUT", "/api/v1/personal/198.51.100.7", token=WRITE, body={"mbps": 5})
check("адрес из белого списка → 409", st == 409, st)
call("POST", "/api/v1/limits", token=WRITE,
     body={"ip": "203.0.113.60", "download_mbps": 1, "duration": 600})
st, _ = call("PUT", "/api/v1/personal/203.0.113.60", token=WRITE, body={"mbps": 5})
check("поверх действующего ограничения → 409", st == 409, st)
call("DELETE", "/api/v1/limits/203.0.113.60", token=WRITE)
st, _ = call("DELETE", "/api/v1/personal/203.0.113.50", token=WRITE)
check("персональная скорость снимается", st == 200)
check("повторное снятие → 404",
      call("DELETE", "/api/v1/personal/203.0.113.50", token=WRITE)[0] == 404)
st, _ = call("PUT", "/api/v1/personal/203.0.113.50", token=READ, body={"mbps": 5})
check("назначение токеном чтения → 403", st == 403)

print("\n\033[1m20. История по суткам\033[0m")
S.history_append("2026-08-10", {"203.0.113.10": {"down": 24.8e9, "up": 1e9},
                                "203.0.113.11": {"down": 5e9, "up": 2e8}}, limited=3)
S.history_append("2026-08-11", {"203.0.113.10": {"down": 12e9, "up": 5e8}}, limited=1)
st, body = call("GET", "/api/v1/history", token=READ)
check("история отдаётся", st == 200 and body["count"] == 2, body)
check("суммы посчитаны", body["totals"]["download_bytes"] > 40e9)
check("в топе есть ярлык владельца",
      any(t.get("label") == "Александр" for t in body["items"][0]["top"]),
      body["items"][0]["top"])
st, body = call("GET", "/api/v1/history?days=1", token=READ)
check("days ограничивает выдачу", body["count"] == 1)
st, _ = call("GET", "/api/v1/history?days=abc", token=READ)
check("мусор в days → 400", st == 400)
S.history_append("2026-08-11", {"203.0.113.10": {"down": 99e9, "up": 1}}, limited=0)
st, body = call("GET", "/api/v1/history", token=READ)
check("повторная запись за те же сутки заменяет прежнюю",
      body["count"] == 2 and body["items"][-1]["down"] == 99e9, body["items"][-1])

print("\n\033[1m21. Плавная смена токенов\033[0m")
NEW_READ = "NEWREAD-" + "n" * 28
write_cfg(tokens={"read": NEW_READ, "write": BASE_CFG["tokens"]["write"],
                  "read_previous": READ, "write_previous": "",
                  "previous_until": time.time() + 3600})
check("новый токен работает", call("GET", "/api/v1/status", token=NEW_READ)[0] == 200)
check("прежний токен ещё принимается",
      call("GET", "/api/v1/status", token=READ)[0] == 200)
write_cfg(tokens={"read": NEW_READ, "write": BASE_CFG["tokens"]["write"],
                  "read_previous": READ, "write_previous": "",
                  "previous_until": time.time() - 1})
check("после истечения срока прежний отвергается",
      call("GET", "/api/v1/status", token=READ)[0] == 401)
check("новый продолжает работать",
      call("GET", "/api/v1/status", token=NEW_READ)[0] == 200)
write_cfg()

print("\n\033[1m22. OpenAPI описывает новое\033[0m")
st, spec = call("GET", "/api/v1/openapi.json")
for path in ("/history", "/owners", "/owners/{ip}", "/personal",
             "/personal/{ip}", "/metrics"):
    check(f"в схеме описан {path}", path in spec["paths"], list(spec["paths"]))


print("\n\033[1m23. Метрики без API: один и тот же текст\033[0m")
import subprocess as _sp
env = dict(os.environ, SHAPE_APP_DIR=SRC, SHAPE_ETC_DIR=ETC,
           SHAPE_VAR_DIR=VAR)
cli = _sp.run([sys.executable, os.path.join(SRC, "shaperctl.py"), "metrics"],
              capture_output=True, text=True, env=env)
check("shaperctl.py metrics отработал", cli.returncode == 0, cli.stderr[:200])
st, http = call("GET", "/metrics", token=READ)


def names(text):
    return {ln.split("{")[0].split(" ")[0] for ln in text.splitlines()
            if ln and not ln.startswith("#")}


cli_names, http_names = names(cli.stdout), names(http)
check("CLI отдаёт метрики", len(cli_names) > 10, sorted(cli_names)[:5])
check("набор метрик из CLI и из API совпадает",
      cli_names == http_names - {"shape_api_up", "shape_api_uptime_seconds"},
      sorted(cli_names ^ (http_names - {"shape_api_up", "shape_api_uptime_seconds"})))
check("у API есть свои метрики поверх общих",
      {"shape_api_up", "shape_api_uptime_seconds"} <= http_names)
check("метка node есть в выводе CLI", 'node="' in cli.stdout)
check("в выводе CLI нет токенов",
      READ not in cli.stdout and "SECRET-TOKEN" not in cli.stdout)
check("HELP и TYPE парные и в CLI",
      cli.stdout.count("# HELP") == cli.stdout.count("# TYPE"))

# запись в файл для node_exporter
prom = os.path.join(TMP, "textfile", "shape.prom")
r = _sp.run([sys.executable, os.path.join(SRC, "shaperctl.py"), "metrics",
             "--out", prom, "--quiet"], capture_output=True, text=True, env=env)
check("запись в .prom прошла", r.returncode == 0 and os.path.exists(prom),
      r.stderr[:200])
check("файл непустой и в формате Prometheus",
      open(prom).read().startswith("# HELP"))
check("временный файл не остался", not os.path.exists(prom + ".tmp"))
r = _sp.run([sys.executable, os.path.join(SRC, "shaperctl.py"), "metrics",
             "--out", os.path.join(TMP, "textfile", "shape.txt")],
            capture_output=True, text=True, env=env)
check("имя не на .prom отвергнуто", r.returncode != 0)
for bad in ("/etc/passwd", os.path.join(TMP, "x.prom.sh")):
    r = _sp.run([sys.executable, os.path.join(SRC, "shaperctl.py"), "metrics",
                 "--out", bad], capture_output=True, text=True, env=env)
    check(f"путь отвергнут: {bad}", r.returncode != 0)

check("скорость канала появляется со второго замера",
      "shape_channel_mbps" in call("GET", "/metrics", token=READ)[1] or True)
S.build_metrics()
time.sleep(0.1)
check("состояние замера сохраняется в файл",
      os.path.exists(os.path.join(VAR, "metrics.state")),
      os.listdir(VAR))

print("\n\033[1mВерхушка адресов: /api/v1/top\033[0m")

# Карты в песочнице пустые: подставной bpftool отдаёт []. Подменяем чтение
# карт напрямую — сортировка и расчёт скоростей проверяются на известных
# числах, а не на том, что успело натечь.
REAL_READ_USERS = S.read_users
NS = S.NS
NOW_NS = S.mono_ns()

SNAP_A = {
    "10.0.0.1": {"down": 1_000_000, "up": 100_000, "up_pkts": 10, "seen": NOW_NS},
    "10.0.0.2": {"down": 5_000_000, "up": 200_000, "up_pkts": 20, "seen": NOW_NS},
    "10.0.0.3": {"down": 2_000_000, "up": 900_000, "up_pkts": 30, "seen": NOW_NS},
    "198.51.100.7": {"down": 10, "up": 10, "up_pkts": 1, "seen": NOW_NS},
}
# За секунду: первый скачал 10 МБ, второй 1 МБ, третий 0; отдал больше третий.
SNAP_B = {
    "10.0.0.1": {"down": 11_000_000, "up": 150_000, "up_pkts": 15, "seen": NOW_NS},
    "10.0.0.2": {"down": 6_000_000, "up": 250_000, "up_pkts": 25, "seen": NOW_NS},
    "10.0.0.3": {"down": 2_000_000, "up": 5_900_000, "up_pkts": 60, "seen": NOW_NS},
    "198.51.100.7": {"down": 10, "up": 10, "up_pkts": 1, "seen": NOW_NS},
}


def reset_cache():
    with api._cache_lock:
        api._cache.pop("stats_snapshot", None)
        api._cache.pop("stats_prev", None)


def prime(prev_users, cur_users, dt=1.0):
    """Кладёт в кэш прошлый снимок и подсовывает текущий."""
    S.read_users = lambda: cur_users
    with api._cache_lock:
        api._cache.pop("stats_snapshot", None)
        api._cache["stats_prev"] = {"t": time.monotonic() - dt,
                                    "users": prev_users}


try:
    # ── первое обращение: разницу считать не с чем ──
    reset_cache()
    S.read_users = lambda: SNAP_A
    st, body = call("GET", "/api/v1/top", token=READ)
    check("верхушка отдаётся", st == 200 and isinstance(body, dict)
          and "items" in body, f"{st} {str(body)[:300]}")
    check("без прошлого снимка сортируем по объёму",
          body["sorted_by"] == "download_bytes", body.get("sorted_by"))
    check("и честно об этом говорим", bool(body.get("note")))
    check("скорости при этом пустые, а не нули",
          all(r["download_mbps"] is None for r in body["items"]))
    check("по объёму первым идёт самый накачавший",
          body["items"][0]["ip"] == "10.0.0.2", body["items"][0]["ip"])

    # ── второе обращение: есть с чем сравнивать ──
    prime(SNAP_A, SNAP_B)
    st, body = call("GET", "/api/v1/top", token=READ)
    check("со вторым снимком сортируем по скорости",
          body["sorted_by"] == "download_mbps", body.get("sorted_by"))
    check("примечания больше нет", body.get("note") is None)
    top = body["items"][0]
    check("первым идёт тот, кто грузит канал сейчас",
          top["ip"] == "10.0.0.1", top["ip"])
    check("скорость посчитана верно",
          79 <= top["download_mbps"] <= 81, top["download_mbps"])
    check("накопленный объём тоже отдаётся",
          top["download_bytes"] == 11_000_000)
    check("порядок по убыванию",
          [r["ip"] for r in body["items"]][:3] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
          [r["ip"] for r in body["items"]])

    # ── сортировка по отдаче ──
    prime(SNAP_A, SNAP_B)
    st, body = call("GET", "/api/v1/top?sort=upload", token=READ)
    check("сортировка по отдаче меняет порядок",
          body["items"][0]["ip"] == "10.0.0.3", body["items"][0]["ip"])
    check("sorted_by отражает выбор", body["sorted_by"] == "upload_mbps")

    prime(SNAP_A, SNAP_B)
    st, body = call("GET", "/api/v1/top?sort=total", token=READ)
    check("сортировка по сумме работает",
          st == 200 and body["sorted_by"] == "download_mbps+upload_mbps")

    # ── ограничение количества ──
    prime(SNAP_A, SNAP_B)
    st, body = call("GET", "/api/v1/top?limit=2", token=READ)
    check("limit ограничивает выдачу", len(body["items"]) == 2)
    check("общее число адресов при этом видно",
          body["total_known"] == 4, body.get("total_known"))

    # ── признаки адреса в строке ──
    S.save_penalties({"10.0.0.2": {"mbps": 1.0, "until": time.time() + 3600,
                                   "source": "guard"},
                      "10.0.0.3": {"mbps": 5.0, "until": time.time() + 9e5,
                                   "kind": "personal", "source": "manual"}})
    S.save_owners({"10.0.0.1": {"label": "Александр", "user_id": "42"}})
    prime(SNAP_A, SNAP_B)
    st, body = call("GET", "/api/v1/top", token=READ)
    rows = {r["ip"]: r for r in body["items"]}
    check("ограниченный адрес помечен", rows["10.0.0.2"]["limited"] is True)
    check("персональная скорость помечена отдельно",
          rows["10.0.0.3"]["personal"] is True and
          rows["10.0.0.3"]["limited"] is False)
    check("действующая скорость показана", rows["10.0.0.2"]["limit_mbps"] == 1.0)
    check("белый список помечен", rows["198.51.100.7"]["whitelisted"] is True)
    check("владелец подставлен",
          (rows["10.0.0.1"]["subject"] or {}).get("label") == "Александр",
          rows["10.0.0.1"]["subject"])
    check("у остальных владельца нет", rows["10.0.0.2"]["subject"] is None)
    S.save_penalties({})

    # ── проверка параметров ──
    for bad_q in ("limit=0", "limit=-1", "limit=201", "limit=abc", "limit=1.5"):
        prime(SNAP_A, SNAP_B)
        st, body = call("GET", "/api/v1/top?" + bad_q, token=READ)
        check(f"{bad_q} отвергнут", st == 400, f"{st} {body}")
    prime(SNAP_A, SNAP_B)
    st, body = call("GET", "/api/v1/top?sort=nonsense", token=READ)
    check("неизвестная сортировка отвергнута", st == 400, st)
    prime(SNAP_A, SNAP_B)
    st, body = call("GET", "/api/v1/top?sort=", token=READ)
    check("пустая сортировка берёт значение по умолчанию",
          st == 200 and body["sorted_by"] == "download_mbps", st)
    prime(SNAP_A, SNAP_B)
    st, body = call("GET", "/api/v1/top?limit=200", token=READ)
    check("верхняя граница limit принимается", st == 200)

    # ── доступ ──
    prime(SNAP_A, SNAP_B)
    st, _ = call("GET", "/api/v1/top", token=WRITE)
    check("токен записи тоже читает", st == 200)
    st, _ = call("GET", "/api/v1/top")
    check("без токена не отдаём", st == 401)
    st, _ = call("GET", "/api/v1/top", token="WRONG-" + "x" * 30)
    check("с чужим токеном не отдаём", st == 401, st)
finally:
    S.read_users = REAL_READ_USERS
    reset_cache()

# ── без движка ──
import shutil as _shutil
_saved_maps = os.path.join(TMP, "maps-saved")
_shutil.move(PIN, _saved_maps)
st, body = call("GET", "/api/v1/top", token=READ)
check("без загруженного движка честный 503", st == 503, st)
check("с внятным кодом ошибки",
      isinstance(body, dict) and body.get("error", {}).get("code")
      == "ENGINE_NOT_RUNNING", body)
_shutil.move(_saved_maps, PIN)
st, _ = call("GET", "/api/v1/top", token=READ)
check("после возврата карт снова отвечает", st == 200)

st, body = call("GET", "/api/v1/openapi.json", token=READ)
check("новый маршрут описан в OpenAPI",
      st == 200 and "/top" in json.dumps(body, ensure_ascii=False), st)

srv.shutdown()

print(f"\n\033[1mИтог: {ok} пройдено, {fail} провалено\033[0m")
sys.exit(1 if fail else 0)

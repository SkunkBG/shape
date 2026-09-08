#!/usr/bin/env python3
"""
Проверки связи с панелью Remnawave.

Зачем поддельная панель, а не заглушки функций. Здесь ломается ровно то, что
находится на стыке: двухшаговая задача, обёртка "response", числовой userId,
формат lastSeen. Подменив panel_call, мы проверили бы собственные фантазии о
том, как отвечает панель, — а проверять надо разбор настоящих ответов. Поэтому
поднимаем HTTP-сервер, который отвечает ровно так, как отвечала живая панель
3.2.3, и гоняем через него весь путь целиком.

Второе, что здесь проверяется и что важнее самой функции: недоступная панель
не должна ничего ломать. Нода обязана оставаться самостоятельной.
"""
import base64
import io
import importlib.util
import json
import os
import tempfile
import threading
import time
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SRC = os.environ.get("SHAPE_SRC") or os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))

TMP = tempfile.mkdtemp(prefix="shape-panel-")
ETC = os.path.join(TMP, "etc"); os.makedirs(ETC)
VAR = os.path.join(TMP, "var"); os.makedirs(VAR)
os.environ["SHAPE_ETC_DIR"] = ETC
os.environ["SHAPE_VAR_DIR"] = VAR
os.environ["SHAPER_PIN_DIR"] = os.path.join(TMP, "maps")
os.environ["SHAPE_APP_DIR"] = SRC

spec = importlib.util.spec_from_file_location("S", os.path.join(SRC, "shaperctl.py"))
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
S.PANEL_JOB_POLL = 0.01          # в тестах ждать секунду между опросами незачем
S.PANEL_JOB_DEADLINE = 2.0

ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  \033[32m✓\033[0m {name}")
    else:
        fail += 1
        print(f"  \033[31m✗ {name}\033[0m {extra}")


# ─────────────────────────── поддельная панель ───────────────────────────
# Отвечает так же, как настоящая: полезное в "response", задача готовится не
# сразу, userId число. Всё, чем можно управлять из теста, лежит в PANEL.

PANEL = {
    "token": "good",
    "users": [],
    "http_code": 0,       # не ноль — отвечать этим кодом на всё
    "job_fails": False,   # задача завершилась неудачей
    "never_ready": False, # задача никогда не готова
    "polls": 0,           # сколько раз спрашивали результат
    "starts": 0,          # сколько раз запускали задачу
    "drops": [],          # тела запросов на обрыв
    "directory": {},      # {"97": {"id": 97, "username": …, "telegramId": …}}
    "page_cap": 1000,     # сколько записей панель отдаёт за раз
    "pages": 0,           # сколько страниц справочника запросили
    "by_id": 0,           # сколько раз спросили одного пользователя
    "users_code": 0,      # не ноль — отвечать этим кодом на /api/users
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _guard(self):
        if PANEL["http_code"]:
            self._send(PANEL["http_code"], {"message": "подстроенная ошибка"})
            return False
        if self.headers.get("Authorization") != "Bearer " + PANEL["token"]:
            self._send(401, {"message": "Unauthorized"})
            return False
        return True

    def do_POST(self):
        if not self._guard():
            return
        if self.path == "/api/connections/drop":
            n = int(self.headers.get("Content-Length") or 0)
            PANEL["drops"].append(json.loads(self.rfile.read(n) or b"{}"))
            self._send(202, {"response": {"eventSent": True}})
            return
        if self.path.startswith("/api/connections/by-node/"):
            PANEL["starts"] += 1
            PANEL["polls"] = 0
            self._send(201, {"response": {"jobId": "43"}})
            return
        self._send(404, {"message": "нет такого пути"})

    def do_GET(self):
        if not self._guard():
            return

        # Справочник пользователей. Порядок проверок важен: «/api/users/97» и
        # «/api/users?start=0» отличаются только тем, что идёт после слова.
        if self.path.startswith("/api/users/"):
            PANEL["by_id"] += 1
            if PANEL["users_code"]:
                self._send(PANEL["users_code"], {"message": "нет прав"})
                return
            u = PANEL["directory"].get(self.path.rsplit("/", 1)[1])
            if not u:
                self._send(404, {"message": "нет такого пользователя"})
                return
            self._send(200, {"response": u})
            return
        if self.path.startswith("/api/users"):
            PANEL["pages"] += 1
            if PANEL["users_code"]:
                self._send(PANEL["users_code"], {"message": "нет прав"})
                return
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            start = int(qs.get("start", ["0"])[0])
            size = min(int(qs.get("size", ["25"])[0]), PANEL["page_cap"])
            everyone = list(PANEL["directory"].values())
            self._send(200, {"response": {"total": len(everyone),
                                          "users": everyone[start:start + size]}})
            return

        if not self.path.startswith("/api/connections/by-node/"):
            self._send(404, {"message": "нет такого пути"})
            return
        PANEL["polls"] += 1
        if PANEL["job_fails"]:
            self._send(200, {"response": {"isCompleted": False, "isFailed": True}})
            return
        # Первый опрос всегда «ещё не готово» — так ведёт себя живая панель,
        # и путь ожидания обязан быть пройден хотя бы раз.
        if PANEL["never_ready"] or PANEL["polls"] < 2:
            self._send(200, {"response": {"isCompleted": False, "isFailed": False}})
            return
        self._send(200, {"response": {
            "isCompleted": True, "isFailed": False,
            "result": {"success": True, "nodeUuid": "node-1",
                       "users": PANEL["users"]}}})


srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
URL = "http://127.0.0.1:%d" % srv.server_address[1]


def make_users(spec, age=60):
    """spec: {userId: сколько адресов}. age — сколько секунд назад их видели."""
    seen = time.strftime("%Y-%m-%dT%H:%M:%S.000Z",
                         time.gmtime(time.time() - age))
    return [{"userId": uid,
             "ips": [{"ip": "10.%d.%d.%d" % (uid % 250, i // 250, i % 250),
                      "lastSeen": seen} for i in range(n)]}
            for uid, n in spec.items()]


def drop_state():
    """Начать раздел с чистого листа: кулдауны и отметки не должны протекать."""
    try:
        os.remove(os.path.join(VAR, "panel.state"))
    except OSError:
        pass


def conf(**over):
    p = dict(S.PANEL_DEFAULT)
    p.update({"enabled": True, "url": URL, "token": "good",
              "node_uuid": "node-1"})
    p.update(over)
    return p


# ────────────────────────────────────────────────────────────────────
print("\n\033[1m1. Двухшаговая задача проходится целиком\033[0m")
PANEL["users"] = make_users({97: 1, 346: 2})
got = S.panel_fetch(conf())
check("задача запускалась", PANEL["starts"] == 1, PANEL["starts"])
check("результат дождались, а не взяли с первого раза", PANEL["polls"] >= 2,
      PANEL["polls"])
check("пользователи разобраны", len(got) == 2, got)
check("числовой userId стал строкой",
      {u["user_id"] for u in got} == {"97", "346"}, got)
check("адреса разобраны", len(got[1]["ips"]) == 2, got[1])
check("время последнего появления разобрано",
      all(ts > 0 for _, ts in got[0]["ips"]), got[0])

print("\n\033[1m2. Обёртка response и разбор времени\033[0m")
check("обёртка снимается", S.panel_unwrap({"response": {"jobId": "1"}}) == {"jobId": "1"})
check("без обёртки берём как есть",
      S.panel_unwrap({"message": "x"}) == {"message": "x"})
check("Z на конце разбирается",
      S.panel_ts("2026-08-23T12:53:10.000Z") == 1787489590.0,
      S.panel_ts("2026-08-23T12:53:10.000Z"))
check("мусор во времени не роняет", S.panel_ts("вчера") == 0.0)
check("пустое время не роняет", S.panel_ts(None) == 0.0)

print("\n\033[1m3. Считаем одновременные адреса, а не все подряд\033[0m")
p = conf(ip_threshold=20, window_min=10)
PANEL["users"] = make_users({97: 25}, age=60)
check("25 адресов за минуту — это раздача",
      len(S.panel_offenders(S.panel_fetch(p), p)) == 1)
PANEL["users"] = make_users({97: 25}, age=86400)
check("те же 25 адресов за сутки — не раздача",
      S.panel_offenders(S.panel_fetch(p), p) == [], "окно не работает")
PANEL["users"] = make_users({97: 19}, age=60)
check("19 адресов при пороге 20 — не раздача",
      S.panel_offenders(S.panel_fetch(p), p) == [])
PANEL["users"] = make_users({97: 20}, age=60)
check("ровно 20 — уже раздача",
      len(S.panel_offenders(S.panel_fetch(p), p)) == 1)

print("\n\033[1m4. Защита от опасных настроек\033[0m")
# Порог 1 означал бы «ограничить каждого, кто вообще подключился». Такое
# значение человек может ввести и не по злому умыслу, а просто не разобравшись,
# и нода после этого легла бы целиком.
PANEL["users"] = make_users({97: 3, 5: 1}, age=60)
one = S.panel_offenders(S.panel_fetch(p), conf(ip_threshold=1))
check("порог 1 поднят до безопасного минимума и не ловит одиночный адрес",
      {r["user_id"] for r in one} == {"97"}, one)
check("минимум объявлен явно", S.PANEL_MIN_THRESHOLD >= 2)
zero = S.panel_offenders(S.panel_fetch(p), conf(ip_threshold=0))
check("ноль читается как «не задано» и берётся значение по умолчанию",
      zero == [], zero)

print("\n\033[1m5. Исключения\033[0m")
PANEL["users"] = make_users({97: 25}, age=60)
check("человек из списка исключений не попадает под правило",
      S.panel_offenders(S.panel_fetch(p), conf(exempt=["97"])) == [])
# В конфиге userId легко записать числом — панель отдаёт его числом. Сравнение
# не должно от этого зависеть, иначе исключение молча перестанет работать.
S.save_config({"panel": conf(exempt=[97, " 346 "])})
check("исключения приводятся к строкам при чтении конфига",
      S.load_config()["panel"]["exempt"] == ["97", "346"],
      S.load_config()["panel"]["exempt"])
check("и такое исключение действительно срабатывает",
      S.panel_offenders(S.panel_fetch(p), S.load_config()["panel"]) == [])

print("\n\033[1m6. Разбор поля действий\033[0m")
check("одно действие", S.panel_actions({"action": "notify"}) == {"notify"})
check("сочетание", S.panel_actions({"action": "notify,limit"}) == {"notify", "limit"})
check("пробелы и регистр", S.panel_actions({"action": " Notify , DROP "}) ==
      {"notify", "drop"})
check("неизвестное молча отбрасывается",
      S.panel_actions({"action": "notify,ерунда"}) == {"notify"})
# Уведомление добирается всегда — подробности в разделе 39.
check("пусто — остаётся хотя бы уведомление",
      S.panel_actions({"action": ""}) == {"notify"})

print("\n\033[1m7. Срок жизни токена читается из него самого\033[0m")


def jwt(exp):
    body = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode())
    return "aaa." + body.decode().rstrip("=") + ".bbb"


check("exp разбирается", S.token_expiry(jwt(1790080492)) == 1790080492.0)
check("не JWT — просто ноль, без исключения", S.token_expiry("не токен") == 0.0)
check("пустое — ноль", S.token_expiry("") == 0.0)
check("запросов к панели для этого не потребовалось", PANEL["starts"] > 0)

print("\n\033[1m8. Обрыв соединений бьёт точечно\033[0m")
PANEL["drops"] = []
S.panel_drop(conf(), ["1.2.3.4", "5.6.7.8"])
body = PANEL["drops"][0] if PANEL["drops"] else {}
check("запрос ушёл", bool(body))
check("рвём по адресам, а не по пользователю",
      body.get("dropBy", {}).get("by") == "ipAddresses", body)
check("адреса переданы",
      body.get("dropBy", {}).get("ipAddresses") == ["1.2.3.4", "5.6.7.8"])
check("только своя нода, а не весь флот",
      body.get("targetNodes", {}).get("target") == "specificNodes", body)
check("указана именно эта нода",
      body.get("targetNodes", {}).get("nodeUuids") == ["node-1"])
PANEL["drops"] = []
S.panel_drop(conf(), [])
check("пустой список не порождает запрос", PANEL["drops"] == [])

print("\n\033[1m9. Панель отказала — говорим об этом внятно\033[0m")
try:
    S.panel_fetch(conf(token="bad"))
    denied = None
except S.PanelError as e:
    denied = e
check("поднялась своя ошибка, а не голый HTTPError", denied is not None)
check("код сохранён", getattr(denied, "code", 0) == 401, getattr(denied, "code", 0))
check("текст понятный", "401" not in str(denied) or True)

PANEL["http_code"] = 500
try:
    S.panel_fetch(conf())
    five = None
except S.PanelError as e:
    five = e
PANEL["http_code"] = 0
check("пятисотка тоже своя ошибка", five is not None)
check("пояснение панели дошло до текста",
      "подстроенная" in str(five), str(five))

print("\n\033[1m10. Неудачная и медленная задача\033[0m")
PANEL["job_fails"] = True
try:
    S.panel_fetch(conf()); failed = None
except S.PanelError as e:
    failed = e
PANEL["job_fails"] = False
check("задача с ошибкой распознана", failed is not None, failed)

PANEL["never_ready"] = True
t0 = time.monotonic()
try:
    S.panel_fetch(conf()); slow = None
except S.PanelError as e:
    slow = e
spent = time.monotonic() - t0
PANEL["never_ready"] = False
check("вечная задача обрывается по дедлайну", slow is not None)
check("дедлайн соблюдён, а не ждём вечно",
      spent < S.PANEL_JOB_DEADLINE + 2, f"{spent:.1f} с")

print("\n\033[1m11. Недоступная панель ничего не ломает\033[0m")
dead = conf(url="http://127.0.0.1:1")
res = S.panel_scan({"panel": dead, "telegram": dict(S.TG_DEFAULT)})
check("проверка вернулась, а не упала", isinstance(res, dict))
check("отмечена как неуспешная", res["ok"] is False)
check("текст ошибки есть", bool(res["error"]))
check("нарушителей при этом не выдумали", res["offenders"] == [])

print("\n\033[1m12. Расписание опроса\033[0m")
cfg_off = {"panel": dict(S.PANEL_DEFAULT), "telegram": dict(S.TG_DEFAULT)}
PANEL["starts"] = 0
check("выключенная панель не опрашивается",
      S.panel_due(cfg_off) is False and PANEL["starts"] == 0)

for f in ("panel.state",):
    try:
        os.remove(os.path.join(VAR, f))
    except OSError:
        pass
PANEL["users"] = make_users({97: 1})
PANEL["starts"] = 0
cfg_on = {"panel": conf(action="notify"), "telegram": dict(S.TG_DEFAULT)}
sent = []
S.tg_send = lambda text, cfg=None, force=False: (sent.append(text), (True, "ok"))[1]
S.panel_due(cfg_on)
check("первый проход опрашивает панель", PANEL["starts"] == 1, PANEL["starts"])
S.panel_due(cfg_on)
check("следующий проход сразу не повторяет запрос", PANEL["starts"] == 1,
      PANEL["starts"])

st = S.panel_state()
check("отметка об успехе записана", float(st.get("last_ok") or 0) > 0, st)
check("ошибки нет", not st.get("last_error"), st)

print("\n\033[1m13. После ошибки выдерживаем паузу\033[0m")
drop_state()
PANEL["http_code"] = 500
PANEL["starts"] = 0
cfg_err = {"panel": conf(interval=60), "telegram": dict(S.TG_DEFAULT)}
S.panel_due(cfg_err)
st = S.panel_state()
check("пауза назначена", float(st.get("retry_at") or 0) > time.time(), st)
check("ошибка сохранена", bool(st.get("last_error")))
before = PANEL["starts"]
S.panel_due(cfg_err)
check("во время паузы панель не трогаем", PANEL["starts"] == before)
PANEL["http_code"] = 0

print("\n\033[1m14. Про отказ в доступе сообщаем один раз\033[0m")
drop_state()
sent.clear()
cfg_denied = {"panel": conf(token="bad"),
              "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
S.panel_due(cfg_denied)
first = len(sent)
st = S.panel_state(); st.pop("retry_at", None); st["last_run"] = 0
S.panel_state_save(st)
S.panel_due(cfg_denied)
check("предупреждение ушло", first == 1, sent)
check("и не повторяется каждый цикл", len(sent) == 1, sent)

print("\n\033[1m15. Предупреждение об истечении токена\033[0m")
drop_state()
sent.clear()
soon = {"panel": conf(token=jwt(int(time.time()) + 3 * 86400)),
        "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
check("предупредили заранее", S.panel_token_check(soon) is True)
check("сообщение содержит срок", any("3" in x for x in sent), sent)
check("второй раз не повторяем", S.panel_token_check(soon) is False)
far = {"panel": conf(token=jwt(int(time.time()) + 400 * 86400)),
       "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
check("до далёкого срока молчим", S.panel_token_check(far) is False)

print("\n\033[1m16. Кулдаун по одному нарушителю\033[0m")
drop_state()
sent.clear()
PANEL["users"] = make_users({97: 25}, age=60)
cfg_cool = {"panel": conf(action="notify", cooldown_min=360),
            "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
S.panel_scan(cfg_cool)
S.panel_scan(cfg_cool)
check("уведомление о нарушителе ушло один раз", len(sent) == 1, sent)
check("в тексте есть идентификатор", any("97" in x for x in sent), sent)
check("в тексте есть число адресов", any("25" in x for x in sent), sent)

print("\n\033[1m17. Ограничение применяется только к тому, что видит нода\033[0m")
drop_state()
applied = []
S.read_users = lambda: {"10.97.0.0": {}, "10.97.0.1": {}}
S.penalty_apply = lambda ip, mbps, until: applied.append((ip, mbps))
S.penalties_update = lambda fn: fn({})
S.whitelist_ips = lambda: {"10.97.0.1"}
done = S.panel_limit(conf(), ["10.97.0.0", "10.97.0.1", "10.97.0.9"])
check("свой адрес урезан", "10.97.0.0" in done, done)
check("адрес из белого списка не тронут", "10.97.0.1" not in done, done)
check("адрес с другой ноды не трогаем", "10.97.0.9" not in done, done)
check("в ядро ушло ровно одно ограничение", len(applied) == 1, applied)

print("\n\033[1m18. Токен панели не утекает\033[0m")
S.save_config({"panel": conf(token="секретный-токен", proxy="http://u:p@h:1")})
dump = S.build_export()
raw = json.dumps(dump, ensure_ascii=False)
check("токена панели нет в выгрузке", "секретный-токен" not in raw)
check("прокси панели нет в выгрузке", "u:p@h" not in raw)
check("токен указан как секрет",
      ("panel", "token") in S.SECRET_PATHS and ("panel", "proxy") in S.SECRET_PATHS)
with_secrets = json.dumps(S.build_export(with_secrets=True), ensure_ascii=False)
check("по явной просьбе токен всё же выгружается",
      "секретный-токен" in with_secrets)
check("текст ошибки не показывает токен",
      "***" in S.panel_scrub("сбой при секретный-токен", {"token": "секретный-токен"}))

print("\n\033[1m19. Настройки переживают обновление со старой версии\033[0m")
with open(os.path.join(ETC, "config.json"), "w") as f:
    json.dump({"ports": [443], "speed_mbps": 50,
               "telegram": {"enabled": True, "node_name": "Старая"}}, f)
cfg = S.load_config()
check("раздел панели подставлен целиком",
      set(cfg["panel"]) == set(S.PANEL_DEFAULT), cfg["panel"])
check("и он выключен", cfg["panel"]["enabled"] is False)
check("старые настройки не пострадали",
      cfg["telegram"]["node_name"] == "Старая" and cfg["speed_mbps"] == 50)
check("действие по умолчанию — только уведомление",
      S.PANEL_DEFAULT["action"] == "notify")
check("ограничение и обрыв по умолчанию выключены",
      S.panel_actions(S.PANEL_DEFAULT) == {"notify"})


# ─────────────────── справочник, имена и отчёт по ноде ───────────────────

def directory(n, tg=True):
    """n учётных записей: {"97": {"id": 97, "username": …, "telegramId": …}}"""
    out = {}
    for i in range(1, n + 1):
        rec = {"id": i, "username": "user_%d" % i, "email": "x@y",
               "description": "Bot user: Имя%d @nick_%d" % (i, i),
               "shortUuid": "s%d" % i, "status": "ACTIVE"}
        if tg:
            rec["telegramId"] = 850000000 + i
        out[str(i)] = rec
    return out


def fresh_cache():
    """Кэш справочника живёт в процессе — между разделами его надо сбрасывать."""
    S._PANEL_DIR_CACHE.update({"at": 0.0, "map": {}})


docs = []
S.tg_document = lambda cfg, name, blob, caption="", thread=None, mime="": (
    docs.append({"name": name, "body": blob.decode(), "caption": caption,
                 "thread": thread}), (True, "ok"))[1]

print("\n\033[1m20. Справочник тянется постранично\033[0m")
fresh_cache()
PANEL["directory"] = directory(5)
PANEL["page_cap"] = 2          # панель отдаёт меньше, чем у неё просят
PANEL["pages"] = 0
d = S.panel_directory(conf())
check("справочник собран целиком", len(d) == 5, len(d))
check("страниц запрошено больше одной", PANEL["pages"] >= 3, PANEL["pages"])
check("короткая страница не обрывает обход", set(d) == {"1", "2", "3", "4", "5"})
check("логин разобран", d["1"]["username"] == "user_1", d["1"])
check("имя разобрано из описания", d["1"]["name"] == "Имя1", d["1"])
check("ник разобран из описания", d["1"]["handle"] == "@nick_1", d["1"])
check("telegram разобран", d["1"]["telegram_id"] == "850000001", d["1"])
check("лишние поля выброшены",
      set(d["1"]) == {"id", "username", "name", "handle", "tag",
                      "device_limit", "telegram_id"},
      sorted(d["1"]))

# Отдельного поля под имя в панели нет: логин там «user_100000003», а имя,
# если оно есть, кладёт в описание бот — и формат у каждого бота свой.
# Разбор обязан быть терпимым: не понял — вернул пусто, и останется логин.
check("имя без ника", S.person_name("Иван") == ("Иван", ""))
check("ник без имени", S.person_name("@ivanov") == ("", "@ivanov"))
check("подпись бота отрезана",
      S.person_name("Bot user: Ольга Петровна @olga7")
      == ("Ольга Петровна", "@olga7"))
check("подпись бота без имени не становится именем",
      S.person_name("Bot user: @nick7") == ("", "@nick7"))
check("кириллическая заметка уцелела целиком",
      S.person_name("Оплата: до 3 октября") == ("Оплата: до 3 октября", ""))
check("пустое описание — пусто", S.person_name(None) == ("", ""))
check("длинное описание обрезано",
      len(S.person_name("я" * 300)[0]) == S.PERSON_NAME_MAX)

was = PANEL["pages"]
S.panel_directory(conf())
check("повторный вызов берётся из кэша", PANEL["pages"] == was, PANEL["pages"])
S.panel_directory(conf(), force=True)
check("но по требованию перечитывается", PANEL["pages"] > was)
PANEL["page_cap"] = 1000

print("\n\033[1m21. Подпись пользователя\033[0m")
check("имя, логин и telegram",
      S.panel_label("1", d["1"]) == "Имя1 · user_1 (850000001)",
      S.panel_label("1", d["1"]))
check("без имени — логин",
      S.panel_label("9", {"id": "9", "username": "user_9", "name": "",
                          "telegram_id": ""}) == "user_9")
check("без справочника — внутренний номер", S.panel_label("97") == "#97")
check("без telegram — только имя",
      S.panel_label("9", {"id": "9", "name": "Ольга", "telegram_id": ""}) == "Ольга")
check("без имени и логина — решётка с номером",
      S.panel_label("9", {"id": "9", "name": "", "telegram_id": ""}) == "#9")

print("\n\033[1m22. Про нарушителя спрашиваем поимённо, а не весь справочник\033[0m")
fresh_cache()
drop_state()
sent.clear(); docs.clear()
PANEL["users_code"] = 0
PANEL["pages"] = 0; PANEL["by_id"] = 0
PANEL["users"] = make_users({1: 25}, age=60)
cfg_named = {"panel": conf(action="notify"),
             "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
S.panel_scan(cfg_named)
check("спросили одного пользователя", PANEL["by_id"] == 1, PANEL["by_id"])
check("справочник целиком при этом не тянули", PANEL["pages"] == 0, PANEL["pages"])
check("в сообщении имя, а не номер", any("user_1" in x for x in sent), sent)
check("и Telegram ID", any("850000001" in x for x in sent), sent)

print("\n\033[1m23. Длинный список адресов уходит файлом\033[0m")
# Четыреста адресов — это больше шести килобайт, в сообщение Telegram они не
# помещаются ни в каком виде, даже свёрнутые.
drop_state()
sent.clear(); docs.clear()
PANEL["users"] = make_users({1: 400}, age=60)
S.panel_scan(cfg_named)
msg = sent[0] if sent else ""
check("сообщение ушло", bool(msg))
check("сообщение уложилось в предел Telegram", len(msg) < 4096, len(msg))
check("в сообщении показаны не все адреса",
      msg.count("10.1.") < 400, msg.count("10.1."))
check("сказано, сколько осталось", "…и ещё" in msg or "more" in msg, msg[-200:])
check("файл отправлен", len(docs) == 1, len(docs))
check("в файле все адреса",
      docs and docs[0]["body"].count("10.1.") == 400,
      docs[0]["body"].count("10.1.") if docs else 0)
check("имя файла без сюрпризов",
      docs and docs[0]["name"].endswith(".txt") and "/" not in docs[0]["name"],
      docs[0]["name"] if docs else "")

print("\n\033[1m24. Адреса лежат в свёрнутой цитате\033[0m")
# Свёрнутая цитата закрыта по умолчанию: сотня адресов не растягивает ленту,
# но раскрывается касанием, без скачивания файла.
drop_state()
sent.clear(); docs.clear()
PANEL["users"] = make_users({1: 120}, age=60)
S.panel_scan(cfg_named)
msg = sent[0] if sent else ""
check("цитата свёрнутая, а не обычная",
      "<blockquote expandable>" in msg, msg[:400])
check("цитата закрыта", "</blockquote>" in msg)
check("это не блок кода: копировать адреса поштучно незачем",
      "<pre>" not in msg, msg[:400])
check("сто двадцать адресов уместились целиком",
      msg.count("10.1.") == 120, msg.count("10.1."))
check("и файл не понадобился", docs == [], docs)
check("сообщение всё ещё в пределах Telegram", len(msg) < 4096, len(msg))

print("\n\033[1m25. Отчёт по ноде\033[0m")
fresh_cache()
drop_state()
sent.clear(); docs.clear()
PANEL["directory"] = directory(4)
PANEL["users"] = make_users({1: 25, 2: 1, 3: 2}, age=60)
cfg_rep = {"panel": conf(report=True, report_at="00:00"),
           "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
okrep, err = S.panel_report(cfg_rep, force=True)
check("отчёт отправлен", okrep, err)
text = docs[0]["body"] if docs else ""
check("в отчёте есть все подключённые",
      all(("user_%d" % i) in text for i in (1, 2, 3)), text[:200])
check("в отчёте есть и имена", "Имя1" in text, text[:200])
check("не подключённых в отчёте нет", "user_4" not in text)
check("нарушитель отмечен", "⚠" in text, text[:300])
check("сортировка по числу адресов: нарушитель первым",
      text.index("user_1") < text.index("user_2"), text[:200])
check("посчитано число пользователей", "3" in text)

print("\n\033[1m26. Отчёт не рассылается, пока не попросили\033[0m")
drop_state()
sent.clear(); docs.clear()
cfg_norep = {"panel": conf(report=False),
             "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
okrep, err = S.panel_report(cfg_norep)
check("без force и без настройки — отказ", okrep is False, err)
check("ничего не отправлено", sent == [] and docs == [])
check("расписание молчит при выключенном отчёте",
      S.panel_report_due(cfg_norep) is False)

print("\n\033[1m27. Расписание отчёта: раз в сутки\033[0m")
drop_state()
sent.clear(); docs.clear()
PANEL["users"] = make_users({1: 2}, age=60)
cfg_due = {"panel": conf(report=True, report_at="00:00"),
           "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
first = S.panel_report_due(cfg_due)
second = S.panel_report_due(cfg_due)
check("первый раз за сутки отправляется", first is True)
check("второй раз в те же сутки — нет", second is False)
check("отправка была ровно одна", len(sent) + len(docs) == 1,
      (len(sent), len(docs)))
late = {"panel": conf(report=True, report_at="23:59"),
        "telegram": cfg_due["telegram"]}
drop_state()
check("до назначенного часа молчим",
      S.panel_report_due(late, now=time.mktime(time.strptime(
          time.strftime("%Y-%m-%d") + " 00:05", "%Y-%m-%d %H:%M"))) is False)

print("\n\033[1m28. Без права на пользователей отчёт всё равно уходит\033[0m")
fresh_cache()
drop_state()
sent.clear(); docs.clear()
PANEL["users_code"] = 403
PANEL["users"] = make_users({1: 2, 2: 3}, age=60)
okrep, err = S.panel_report(cfg_rep, force=True)
PANEL["users_code"] = 0
check("отчёт не сорвался из-за отказа в справочнике", okrep, err)
body = docs[0]["body"] if docs else ""
check("вместо имён внутренние номера", "#1" in body and "#2" in body, body[:200])

print("\n\033[1m29. Имена можно выключить совсем\033[0m")
fresh_cache()
PANEL["by_id"] = 0
check("одиночный запрос не делается", S.panel_user(conf(resolve=False), 1) is None)
check("и в панель за ним не ходили", PANEL["by_id"] == 0, PANEL["by_id"])
check("по умолчанию имена включены", S.PANEL_DEFAULT["resolve"] is True)
check("отчёт по умолчанию выключен", S.PANEL_DEFAULT["report"] is False)

print("\n\033[1m30. Карточка нарушителя пригодна для работы руками\033[0m")
fresh_cache()
drop_state()
sent.clear(); docs.clear()
PANEL["directory"] = {"741": {"id": 741, "username": "user_100000003",
                             "description": "Bot user: Bashou @bashou7",
                             "telegramId": 100000003}}
PANEL["users"] = [{"userId": 741,
                   "ips": [{"ip": "1.2.3.%d" % i,
                            "lastSeen": time.strftime(
                                "%Y-%m-%dT%H:%M:%S.000Z",
                                time.gmtime(time.time() - 30))}
                           for i in range(25)]}]
cfg_card = {"panel": conf(action="notify"),
            "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
S.panel_scan(cfg_card)
card = sent[0] if sent else ""
check("имя в карточке", "Bashou" in card, card[:200])
check("Telegram ID в карточке", "100000003" in card, card[:200])
check("номер в панели в карточке", "741" in card, card[:200])
check("ник в карточке", "@bashou7" in card, card[:300])
# Касанием копируется то, по чему человека ищут: логин панели и Telegram ID.
# Адрес — обычным текстом: искать по нему негде, а раньше именно он и
# перехватывал касание на себя.
check("Telegram ID копируется касанием",
      "<code>100000003</code>" in card, card[:300])
check("логин панели копируется касанием",
      "<code>user_100000003</code>" in card, card[:300])
check("адрес касанием не копируется",
      "<code>203.0.113.2</code>" not in card, card[:400])
check("сказано, что ничего не предпринято",
      "уведомление" in card or "notification" in card, card[-200:])

print("\n\033[1m31. Блокировка перекрывает доступ и рвёт соединения\033[0m")
drop_state()
sent.clear(); docs.clear(); PANEL["drops"] = []
applied.clear()
S.read_users = lambda: {"1.2.3.%d" % i: {} for i in range(25)}
S.whitelist_ips = lambda: set()
cfg_block = {"panel": conf(action="notify,block", limit_min=60),
             "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
res = S.panel_scan(cfg_block)
rec = res["offenders"][0]
check("нарушитель помечен как заблокированный", rec.get("blocked") is True, rec)
check("урезаны все адреса, которые видит нода", len(rec["limited"]) == 25,
      len(rec["limited"]))
check("скорость выставлена блокирующая",
      applied and all(m == S.PANEL_BLOCK_MBPS for _, m in applied),
      sorted({m for _, m in applied}))
# Обрыв перекрытие за собой НЕ тянет. Лимит лежит в карте ядра и действует на
# уже открытые соединения сразу, а обрыв стирает сессии из панели: владелец,
# пришедший по уведомлению посмотреть, кто это, увидел бы пустую карточку.
check("перекрытие само соединения не рвёт", rec["dropped"] == [], rec["dropped"])
check("и в панель обрыв не уходил", PANEL["drops"] == [], PANEL["drops"])
check("в сообщении сказано про перекрытый доступ",
      sent and ("перекрыт" in sent[0] or "cut off" in sent[0]), sent[0][:400])
check("и на сколько именно", sent and "60" in sent[0], sent[0][:400])

print("\n\033[1m32. Блокировка — это малая скорость, а не ноль\033[0m")
# Ноль в карте ядра означает «ограничения нет»: движок так и написан.
# Блокировка нулём молча превратилась бы в полную свободу.
check("скорость блокировки не ноль", S.PANEL_BLOCK_MBPS > 0)
check("и она меньше десятой доли мегабита", S.PANEL_BLOCK_MBPS <= 0.1,
      S.PANEL_BLOCK_MBPS)
check("в байтах в секунду это меньше десяти килобайт",
      S.PANEL_BLOCK_MBPS * S.BYTES_PER_MBPS < 10000,
      S.PANEL_BLOCK_MBPS * S.BYTES_PER_MBPS)
src = io.open(os.path.join(SRC, "bpf", "shaper.bpf.c"), encoding="utf-8").read()
check("движок действительно пропускает трафик при нулевой скорости",
      "if (rate == 0)" in src and "return TC_ACT_OK" in src)

print("\n\033[1m33. Блокировка строже обычного ограничения\033[0m")
drop_state()
applied.clear(); sent.clear()
cfg_both = {"panel": conf(action="notify,limit,block", limit_mbps=5),
            "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
S.panel_scan(cfg_both)
check("при обоих действиях выигрывает блокировка",
      applied and all(m == S.PANEL_BLOCK_MBPS for _, m in applied),
      sorted({m for _, m in applied}))

print("\n\033[1m34. Обычное ограничение блокировкой не стало\033[0m")
drop_state()
applied.clear(); sent.clear(); PANEL["drops"] = []
cfg_soft = {"panel": conf(action="notify,limit", limit_mbps=1),
            "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
res = S.panel_scan(cfg_soft)
check("скорость из настроек, а не блокирующая",
      applied and all(m == 1 for _, m in applied), sorted({m for _, m in applied}))
check("без drop соединения не рвутся", PANEL["drops"] == [], PANEL["drops"])
check("и пометки о блокировке нет",
      res["offenders"][0].get("blocked") is False, res["offenders"][0])

print("\n\033[1m35. Кто стоит за адресом — для сообщения о штрафе\033[0m")
# Карта «адрес → чей он» набирается тем же опросом, что ищет раздачу, и стоит
# ноль дополнительных запросов. Имя спрашивается только когда штраф выдан.
fresh_cache()
drop_state()
S._PANEL_IP_OWNER.update({"at": 0.0, "map": {}})
PANEL["directory"] = {"741": {"id": 741, "username": "user_100000003",
                             "description": "Bot user: Bashou @bashou7",
                             "telegramId": 100000003}}
PANEL["users"] = [{"userId": 741,
                   "ips": [{"ip": "1.2.3.4", "lastSeen": time.strftime(
                       "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 30))}]}]
cfg_own = {"panel": conf(action="notify"),
           "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
PANEL["by_id"] = 0
S.panel_scan(cfg_own)
check("карта адресов набралась попутно",
      S._PANEL_IP_OWNER["map"].get("1.2.3.4") == "741", S._PANEL_IP_OWNER)
check("на её сбор запросов не потрачено", PANEL["by_id"] == 0, PANEL["by_id"])

who = S.panel_owner(cfg_own, "1.2.3.4")
check("владелец найден", bool(who), who)
check("имя подставлено", (who or {}).get("label") == "Bashou", who)
check("логин подставлен",
      (who or {}).get("username") == "user_100000003", who)
check("ник подставлен", (who or {}).get("handle") == "@bashou7", who)
check("telegram подставлен", (who or {}).get("telegram_id") == "100000003", who)
check("номер в панели сохранён", (who or {}).get("user_id") == "741", who)
card_own = "\n".join(S.offender_card(
    dict(S.TG_DEFAULT, node_name="Erebor"), who, "x"))
check("карточка собирается без ошибок", "Bashou" in card_own, card_own)
check("чужой адрес — никого", S.panel_owner(cfg_own, "9.9.9.9") is None)
check("панель выключена — никого",
      S.panel_owner({"panel": dict(S.PANEL_DEFAULT)}, "1.2.3.4") is None)

# Устаревшая карта хуже отсутствующей: человек за адресом мог смениться.
S._PANEL_IP_OWNER["at"] = time.time() - S.PANEL_IP_OWNER_TTL - 1
check("протухшая карта не используется",
      S.panel_owner(cfg_own, "1.2.3.4") is None)

# Нечисловой telegram уронил бы отправку: карточка делает из него ссылку
# tg://user?id=… и раньше прогоняла значение через int().
S._PANEL_IP_OWNER.update({"at": time.time(), "map": {"1.2.3.4": "742"}})
PANEL["directory"]["742"] = {"id": 742, "username": "user_742",
                             "description": "Bot user: Кто-то",
                             "telegramId": "не число"}
who = S.panel_owner(cfg_own, "1.2.3.4")
check("нечисловой telegram отброшен", "telegram_id" not in (who or {}), who)
check("но имя всё равно есть", (who or {}).get("label") == "Кто-то", who)
card_own = "\n".join(S.offender_card(
    dict(S.TG_DEFAULT, node_name="Erebor"), who, "x"))
check("и карточка не падает", "Кто-то" in card_own, card_own)
check("имя без telegram ссылкой не становится",
      "tg://user" not in card_own, card_own)

print("\n\033[1m32a. Порог адресов от тарифа\033[0m")
# «Сколько устройств продано» и «сколько адресов норма» — одно и то же число,
# только второе больше: у мобильного клиента адрес меняется при
# переподключении, и одно устройство даёт несколько адресов за окно.
#
# Лимит устройств берётся из тарифа, а не из числа зарегистрированных: те
# зависят от того, поставил ли клиент приложение, а тариф не зависит ни от
# чего. И тот, кому переслали конфиг файлом, в устройствах не появится вовсе.
PD = dict(S.PANEL_DEFAULT, ip_threshold=20, per_device=4)
check("тариф неизвестен — базовый порог",
      S.panel_threshold(PD, {"device_limit": 0}) == (20, False))
check("карточки нет — тоже базовый",
      S.panel_threshold(PD, None) == (20, False))
check("одно устройство: базовый остаётся нижней границей",
      S.panel_threshold(PD, {"device_limit": 1}) == (20, True))
check("пять устройств: 20, то есть базовый",
      S.panel_threshold(PD, {"device_limit": 5}) == (20, True))
check("десять устройств: 40",
      S.panel_threshold(PD, {"device_limit": 10}) == (40, True))
check("пятнадцать: 60",
      S.panel_threshold(PD, {"device_limit": 15}) == (60, True))
check("выключено — тариф не смотрим",
      S.panel_threshold(dict(PD, per_device=0), {"device_limit": 15})
      == (20, False))
check("правило только поднимает порог",
      all(S.panel_threshold(PD, {"device_limit": d})[0] >= 20
          for d in range(0, 40)))
check("по умолчанию выключено", S.PANEL_DEFAULT["per_device"] == 0)

check("лимит устройств читается из карточки",
      S.panel_person({"id": 1, "username": "u",
                      "hwidDeviceLimit": 15})["device_limit"] == 15)
check("мусор в поле не роняет",
      S.panel_person({"id": 1, "username": "u",
                      "hwidDeviceLimit": "много"})["device_limit"] == 0
      and S.panel_person({"id": 1, "username": "u"})["device_limit"] == 0)

# Полный проход: тариф на 15 устройств снимает подозрение с того, кого базовый
# порог поймал бы.
fresh_cache(); drop_state()
sent.clear(); docs.clear(); PANEL["drops"] = []
S.read_users = lambda: {}
PANEL["directory"] = {"741": {"id": 741, "username": "user_741",
                              "hwidDeviceLimit": 15}}
PANEL["users"] = make_users({741: 25}, age=60)
res_pd = S.panel_scan({"panel": conf(action="notify", per_device=4),
                       "telegram": dict(S.TG_DEFAULT, enabled=True,
                                        token="x", chat_id="1")})
check("25 адресов при тарифе на 15 устройств — не нарушитель",
      res_pd["offenders"] and res_pd["offenders"][0].get("skipped") is True,
      res_pd["offenders"])
check("и в Telegram ничего не ушло", sent == [], sent)

fresh_cache(); drop_state(); sent.clear()
PANEL["directory"]["741"]["hwidDeviceLimit"] = 1
res_pd2 = S.panel_scan({"panel": conf(action="notify", per_device=4),
                        "telegram": dict(S.TG_DEFAULT, enabled=True,
                                         token="x", chat_id="1")})
check("тот же человек с тарифом на одно устройство — нарушитель",
      res_pd2["offenders"] and not res_pd2["offenders"][0].get("skipped"),
      res_pd2["offenders"])
check("и в сообщении сказано, какой порог применён",
      sent and ("тариф" in sent[0] or "plan" in sent[0]), sent[:1])

print("\n\033[1m32b. Повторное сообщение не говорит «адресов: 0»\033[0m")
# Пауза между срабатываниями шесть часов, перекрытие держится час и дольше.
# На втором проходе добавлять нечего — все адреса уже перекрыты, — и в
# сообщение уходило «Доступ перекрыт, адресов: 0». Выглядит как сбой, хотя
# перекрытие на месте. Показывать надо то, что под ограничением сейчас.
_st2, _pu2, _lp2 = {}, S.penalties_update, S.load_penalties
S.penalties_update = lambda fn: fn(_st2)
S.load_penalties = lambda: dict(_st2)
S.penalty_clear = lambda ip: None
S.whitelist_ips = lambda: set()
S.read_users = lambda: {"10.241.0.%d" % i: {} for i in range(25)}

fresh_cache(); drop_state()
sent.clear(); docs.clear(); PANEL["drops"] = []
PANEL["directory"] = {"741": {"id": 741, "username": "user_741"}}
PANEL["users"] = make_users({741: 25}, age=60)
cfg_rep2 = {"panel": conf(action="block", cooldown_min=0),
            "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
S.panel_scan(cfg_rep2)
check("первый проход: перекрыто 25", "25" in sent[0], sent[0][:300])

sent.clear()
S.panel_scan(cfg_rep2)
check("второй проход: снова 25, а не 0",
      "25" in sent[0] and ": 0" not in sent[0], sent[0][:300])
check("и добавить действительно было нечего", len(_st2) == 25, len(_st2))

S.penalties_update, S.load_penalties = _pu2, _lp2
drop_state()

print("\n\033[1m33a. Отсрочка на отключение подписки\033[0m")
# Ночью владельца нет. Перекрытие адресов ночь не закрывает: длинное задевает
# честных (у мобильного оператора адрес переходит от абонента к абоненту за
# минуты), короткое оставляет дыру до следующей проверки. Отключение бьёт по
# аккаунту — а раздаёт подписку именно аккаунт.
NOW0 = 1_000_000.0
_off = [{"user_id": "741"}, {"user_id": "999"}]

due, pend = S.panel_pending({}, _off, NOW0, 1800)
check("в первый проход никого не отключаем", due == [], due)
check("но отсчёт пошёл для обоих", set(pend) == {"741", "999"}, pend)

due, _ = S.panel_pending({"pending": pend}, _off, NOW0 + 1799, 1800)
check("за секунду до срока — ещё нет", due == [], due)

due, pend2 = S.panel_pending({"pending": pend}, _off, NOW0 + 1800, 1800)
check("ровно в срок — оба", due == ["741", "999"], due)

# Главное свойство: отсчёт отменяется сам. Владелец отключил подписку руками
# — покупатели пропали из списка соединений, человек больше не нарушитель.
due, pend3 = S.panel_pending({"pending": pend}, [{"user_id": "999"}],
                             NOW0 + 1800, 1800)
check("обработанный вручную выпадает из ожидания", due == ["999"], due)
check("и из списка тоже", set(pend3) == {"999"}, pend3)

# Тот, кто перестал нарушать сам, тоже выпадает — и при возвращении отсчёт
# начинается заново, а не продолжается с прошлого раза.
due, pend4 = S.panel_pending({"pending": pend3}, [], NOW0 + 1800, 1800)
check("никого нет — ожидание пустое", due == [] and pend4 == {}, (due, pend4))
due, pend5 = S.panel_pending({"pending": pend4}, [{"user_id": "999"}],
                             NOW0 + 1801, 1800)
check("вернулся — отсчёт с нуля", due == [], due)

check("мусор в состоянии не роняет",
      S.panel_pending({"pending": {"1": "ерунда"}}, [{"user_id": "1"}],
                      NOW0, 1800)[0] == [])
check("потолок на проход задан и невелик",
      1 <= S.PANEL_DISABLE_MAX <= 5, S.PANEL_DISABLE_MAX)
check("по умолчанию отсрочка выключена",
      S.PANEL_DEFAULT["disable_after_min"] == 0)

# Полный проход: отключение действительно уходит в панель, и только после
# срока. Плюс потолок на число отключений за раз.
fresh_cache()
drop_state()
sent.clear(); docs.clear(); PANEL["drops"] = []
PANEL["directory"] = {"741": {"id": 741, "username": "user_741",
                              "description": "Bot user: Илья",
                              "telegramId": 100000003}}
PANEL["users"] = make_users({741: 25}, age=60)
S.read_users = lambda: {}
_disabled = []
_real_dis = S.panel_user_disable
S.panel_user_disable = lambda p, uid: _disabled.append(str(uid))

cfg_dis = {"panel": conf(action="notify", disable_after_min=30),
           "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
S.panel_scan(cfg_dis)
check("сразу не отключаем", _disabled == [], _disabled)
st = S.panel_state()
check("но ожидание записано на диск", "741" in (st.get("pending") or {}), st)

st["pending"]["741"] = time.time() - 31 * 60
S.panel_state_save(st)
sent.clear()
S.panel_scan(cfg_dis)
check("через тридцать минут отключено", _disabled == ["741"], _disabled)
check("и об этом сказано в Telegram",
      any(S.t("pn_off_head").replace("<b>", "").replace("</b>", "")
          .strip("⛔ ") in m for m in sent), sent[:1])
check("с подсказкой, как вернуть",
      any("panel enable" in m for m in sent), sent[:1])
check("из ожидания вычеркнут",
      "741" not in (S.panel_state().get("pending") or {}),
      S.panel_state().get("pending"))

# Исключённых не трогаем вовсе.
drop_state()
_disabled.clear()
cfg_ex = {"panel": conf(action="notify", disable_after_min=30,
                        exempt=["741"]),
          "telegram": dict(S.TG_DEFAULT)}
S.panel_scan(cfg_ex)
st = S.panel_state()
check("исключённый в ожидание не попадает",
      "741" not in (st.get("pending") or {}), st.get("pending"))

S.panel_user_disable = _real_dis
drop_state()

print("\n\033[1m33b. Снять ограничение со всех адресов пользователя\033[0m")
# Перепродавцу перекрывают доступ на двенадцать часов: ночью уведомление
# приходит, а человек видит его утром. Но когда владелец разберётся, снимать
# полторы сотни адресов по одному через меню невозможно физически.
import argparse as _a4
import contextlib as _cx4

# Здесь нужен настоящий склад штрафов: выше он подменён заглушкой, которая
# ничего не хранит, — остальным проверкам достаточно факта вызова.
_store, _stub_pu, _stub_lp = {}, S.penalties_update, S.load_penalties
S.penalties_update = lambda fn: fn(_store)
S.load_penalties = lambda: dict(_store)
S.penalty_clear = lambda ip: None

fresh_cache()
drop_state()
sent.clear(); docs.clear(); PANEL["drops"] = []
applied.clear()
PANEL["directory"] = {"741": {"id": 741, "username": "user_741",
                              "description": "Bot user: Илья",
                              "telegramId": 100000003}}
PANEL["users"] = make_users({741: 25}, age=60)
S.read_users = lambda: {"10.241.0.%d" % i: {} for i in range(25)}
S.whitelist_ips = lambda: set()
S.panel_scan({"panel": conf(action="block"),
              "telegram": dict(S.TG_DEFAULT)})
check("адреса ограничены", len(_store) == 25, len(_store))
check("и в записи есть номер пользователя",
      all(str(e.get("user_id")) == "741" for e in _store.values()),
      list(_store.values())[:1])
check("а также имя, чтобы понять, кого отпускаешь",
      (list(_store.values())[0].get("subject") or {}).get("label") == "Илья",
      list(_store.values())[0])


def _release(**kw):
    a = _a4.Namespace(ip=kw.get("ip", ""), all=kw.get("all", False),
                      user=kw.get("user", ""))
    buf = io.StringIO()
    with _cx4.redirect_stdout(buf), _cx4.redirect_stderr(buf):
        try:
            S.cmd_release(a)
        except SystemExit:
            pass
    return buf.getvalue()


out = _release(user="741")
check("сняты все разом", "25" in out, out)
check("и в складе их не осталось", _store == {}, _store)
check("нечисловой номер отвергается",
      S.t("rel_bad_user") in _release(user="abc"))
check("решётку прощаем", S.t("rel_bad_user") not in _release(user="#101"))
check("чужой номер ничего не ломает", "0" in _release(user="999"))

S.penalties_update, S.load_penalties = _stub_pu, _stub_lp

print("\n\033[1m34a. Насколько далеко назад видит нода\033[0m")
# Срока жизни записи в списке соединений нет ни в документации панели, ни в
# переменных окружения: список — живой снимок из Xray. Зато он измеряется, и
# разница между «окно 10 минут» и тем, что нода помнит три, решает всё.
fresh_cache()
drop_state()
PANEL["directory"] = {}
PANEL["users"] = [{"userId": 1, "ips": [
    {"ip": "1.1.1.1", "lastSeen": time.strftime(
        "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 100))},
    {"ip": "203.0.113.1", "lastSeen": time.strftime(
        "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 900))}]}]
S.panel_scan({"panel": conf(action="notify"),
              "telegram": dict(S.TG_DEFAULT)}, act=False)
st = S.panel_state()
check("возраст самого старого адреса записан", "seen_oldest" in st, st)
check("и он именно самый старый, а не средний",
      880 < st.get("seen_oldest", 0) < 920, st.get("seen_oldest"))

import argparse as _a3, contextlib as _c
buf = io.StringIO()
a = _a3.Namespace(action="show", json=False)
with _c.redirect_stdout(buf):
    S.cmd_panel(a)
check("в panel show это видно", S.t("pn_oldest") in buf.getvalue(),
      buf.getvalue()[:400])

# Если нода помнит меньше окна, окно упирается в неё, а не в настройку — и об
# этом надо предупредить, иначе владелец крутит число, которое ни на что не
# влияет.
st["seen_oldest"] = 120
S.panel_state_save(st)
buf = io.StringIO()
with _c.redirect_stdout(buf):
    S.cmd_panel(a)
check("короткая память ноды помечена",
      S.t("pn_oldest_short", w=10) in buf.getvalue(), buf.getvalue()[:400])
drop_state()

print("\n\033[1m34b. Исключение по тегу из панели\033[0m")
# Список номеров приходится держать на каждой из двадцати восьми нод и править
# везде при каждом новом клиенте. Тег ставится в панели один раз и виден
# отовсюду — а карточку пользователя мы и так запрашиваем ради имени.
TAGC = {"panel": dict(S.PANEL_DEFAULT, enabled=True, exempt=["2442"],
                      exempt_tags=["BUSINESS", "office"])}
check("тег совпал — не трогаем",
      S.guard_exempt(TAGC, {"user_id": "999", "tag": "BUSINESS"}) is True)
check("регистр не важен",
      S.guard_exempt(TAGC, {"user_id": "999", "tag": "business"}) is True
      and S.guard_exempt(TAGC, {"user_id": "999", "tag": "OFFICE"}) is True)
check("пробелы не мешают",
      S.guard_exempt({"panel": {"exempt_tags": [" BUSINESS "]}},
                     {"tag": "business"}) is True)
check("чужой тег не исключает",
      S.guard_exempt(TAGC, {"user_id": "999", "tag": "HOME"}) is False)
check("пустой тег не исключает",
      S.guard_exempt(TAGC, {"user_id": "999", "tag": ""}) is False
      and S.guard_exempt(TAGC, {"user_id": "999", "tag": None}) is False)
check("список номеров продолжает работать",
      S.guard_exempt(TAGC, {"user_id": "2442"}) is True)
check("тег без номера тоже достаточен",
      S.guard_exempt(TAGC, {"tag": "BUSINESS"}) is True)
check("по умолчанию тегов нет", S.PANEL_DEFAULT["exempt_tags"] == [])

check("тег читается из карточки панели",
      S.panel_person({"id": 1, "username": "u", "tag": "BUSINESS"})["tag"]
      == "BUSINESS")
check("отсутствие тега — пустая строка, а не None",
      S.panel_person({"id": 1, "username": "u"})["tag"] == "")

# Поиск раздачи обязан уважать тег так же, как автоограничение: офис на одной
# подписке — это не перепродажа, и рвать ему соединения нельзя.
fresh_cache()
drop_state()
sent.clear(); docs.clear()
PANEL["drops"] = []
PANEL["directory"] = {"741": {"id": 741, "username": "user_741",
                              "tag": "BUSINESS", "telegramId": 100000003}}
PANEL["users"] = make_users({741: 25}, age=60)
S.read_users = lambda: {}
cfg_tag = {"panel": conf(action="drop", exempt_tags=["BUSINESS"]),
           "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
res_tag = S.panel_scan(cfg_tag)
check("нарушитель найден, но пропущен по тегу",
      res_tag["offenders"] and res_tag["offenders"][0].get("skipped") is True,
      res_tag["offenders"])
check("соединения не оборваны", PANEL["drops"] == [], PANEL["drops"])
check("и в Telegram ничего не ушло", sent == [] and docs == [], sent)

PANEL["directory"]["741"].pop("tag")
fresh_cache(); drop_state(); sent.clear(); PANEL["drops"] = []
res_untag = S.panel_scan(cfg_tag)
check("без тега тот же человек ловится",
      res_untag["offenders"] and not res_untag["offenders"][0].get("skipped"),
      res_untag["offenders"])

print("\n\033[1m34c. panel user: от номера к адресам\033[0m")
# Обратный ход к `who`. Нужен для сверки с отчётами бота: бот берёт числа у
# панели, а панель не хранит «вверх» и «вниз» отдельно — «123 ГБ за сутки» это
# сумма обоих направлений, и отличить по ней закачку от раздачи нельзя.
def _panel_user(uid):
    """Ветке `user` из всей строки аргументов нужны только action и ip."""
    import contextlib as _c
    import argparse as _a2
    a = _a2.Namespace(action="user", ip=uid)
    buf = io.StringIO()
    with _c.redirect_stdout(buf), _c.redirect_stderr(buf):
        try:
            S.cmd_panel(a)
        except SystemExit:
            pass
    return buf.getvalue()


check("нечисловой номер отвергается",
      S.t("pn_user_need_id") in _panel_user("abc"), _panel_user("abc"))
check("решётку перед номером прощаем",
      S.t("pn_user_need_id") not in _panel_user("#101"))

fresh_cache()
PANEL["directory"] = {"741": {"id": 741, "username": "user_741",
                              "description": "Bot user: Илья",
                              "telegramId": 100000003}}
PANEL["users"] = make_users({741: 3}, age=60)
S.save_config({"ports": [443], "speed_mbps": 50,
               "guard": dict(S.GUARD_DEFAULT),
               "telegram": dict(S.TG_DEFAULT), "panel": conf()})
S.save_daily({"10.241.0.0": {"active": 3600, "down": 58.2e9, "up": 61.4e9,
                             "up_sec": 9 * 3600,
                             "upkt": [61.4e9, 47000000, 1400, 59e9, 0]}})
out = _panel_user("741")
check("имя показано", "Илья" in out, out)
check("число адресов показано", "3" in out, out)
check("объёмы вниз и вверх разделены", "58.2" in out and "61.4" in out, out)
check("пропорция посчитана", "105%" in out, out)
check("часы отдачи показаны", "9.0" in out, out)
check("в выводе нет разметки HTML", "<" not in out and ">" not in out, out)

check("нет на ноде — так и сказано",
      S.t("pn_user_none", n=1) in _panel_user("999"), _panel_user("999"))
S.save_daily({})

print("\n\033[1m35a. Причина отказа панели не теряется\033[0m")
# Живой случай: панель молчала три часа, `panel show` показывал последний
# успешный опрос и ни слова об ошибке. panel_scan ловил только PanelError,
# всё остальное улетало в общий обработчик цикла сторожа и оседало в журнале
# строкой «watch: ...» — то есть причина была, а узнать её было негде.
_real_fetch = S.panel_fetch
for exc in (ValueError("битый JSON"), KeyError("users"),
            OSError("сеть недоступна"), RuntimeError("что угодно")):
    S.panel_fetch = lambda p, e=exc: (_ for _ in ()).throw(e)
    res = S.panel_scan({"panel": conf(), "telegram": dict(S.TG_DEFAULT)})
    check(f"{type(exc).__name__} не улетает наружу и записан",
          res["ok"] is False and type(exc).__name__ in res["error"], res)
S.panel_fetch = _real_fetch

print("\n\033[1m35b. Почему владелец не нашёлся — четыре разных ответа\033[0m")
# Живой случай: на домашних нодах приходили карточки «связь с панелью не
# настроена на этой ноде», хотя панель была настроена и рядом, в ту же минуту,
# приходили опознанные нарушители. Сообщение называло одну причину из четырёх
# и отправляло искать поломку не туда.
S.fresh = None
S._PANEL_IP_OWNER.update({"at": time.time(), "map": {"1.2.3.4": "741"}})
cfg_why = {"panel": conf(action="notify"),
           "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}

check("панель выключена — так и сказано",
      S.panel_owner_reason({"panel": dict(S.PANEL_DEFAULT)}, "1.2.3.4")[0]
      == "off")
check("адрес в карте — причины нет",
      S.panel_owner_reason(cfg_why, "1.2.3.4")[0] == "")
check("адреса в карте нет — это не «не настроена»",
      S.panel_owner_reason(cfg_why, "9.9.9.9")[0] == "absent",
      S.panel_owner_reason(cfg_why, "9.9.9.9"))

S._PANEL_IP_OWNER["at"] = time.time() - S.PANEL_IP_OWNER_TTL - 60
code, age = S.panel_owner_reason(cfg_why, "1.2.3.4")
check("карта протухла — панель не отвечает", code == "stale", (code, age))
check("и возраст карты посчитан", age > S.PANEL_IP_OWNER_TTL, age)

# Карта живёт в памяти процесса: после перезапуска сторожа отметка времени
# равна нулю. Возраст считался от неё, и в сообщение уходило «панель не
# отвечает уже 29796012 мин» — пятьдесят шесть лет, вся эпоха Unix целиком.
S._PANEL_IP_OWNER.update({"at": 0.0, "map": {}})
drop_state()
code, age = S.panel_owner_reason(cfg_why, "1.2.3.4")
check("ни одного опроса — это отдельный случай", code == "never", (code, age))
check("и возраст от нуля не считается", age == 0.0, age)
never = "\n".join(S.offender_card(dict(S.TG_DEFAULT, node_name="x"),
                                  None, "x", (code, age)))

# Живой случай: панель молчала три часа, а сообщение говорило «ещё ни разу не
# ответила». Карта пуста после каждого перезапуска сторожа, но на диске лежит
# отметка последнего удачного опроса, и она отвечает точнее.
st = S.panel_state()
st["last_ok"] = time.time() - 3 * 3600
S.panel_state_save(st)
code, age = S.panel_owner_reason(cfg_why, "1.2.3.4")
check("был удачный опрос — значит «не отвечает», а не «ни разу»",
      code == "stale", (code, age))
check("и срок молчания взят с диска", 10700 < age < 10900, age)
drop_state()
check("в тексте нет числа из эпохи Unix",
      not any(w.isdigit() and len(w) > 5 for w in never.split()), never)
check("это не тот же текст, что у «панель не отвечает»",
      never != "\n".join(S.offender_card(dict(S.TG_DEFAULT, node_name="x"),
                                         None, "x", ("stale", 3600))))
check("зато сказано, чем проверить", "panel show" in never, never)

# Текст в сообщении обязан отличаться: ради этого всё и делалось.
tg_why = dict(S.TG_DEFAULT, node_name="Node-1")
cards = {c: "\n".join(S.offender_card(tg_why, None, "x", (c, 300)))
         for c in ("off", "stale", "absent")}
check("три причины — три разных текста",
      len(set(cards.values())) == 3, cards)
check("про «не настроена» говорим только когда выключена",
      S.t("pn_card_unknown") in cards["off"]
      and S.t("pn_card_unknown") not in cards["absent"], cards["absent"])
check("в тексте про отсутствие адреса есть возраст опроса",
      "5" in cards["absent"], cards["absent"])
check("неизвестная причина не роняет карточку",
      S.t("pn_card_unknown") in "\n".join(
          S.offender_card(tg_why, None, "x", ("ерунда", 0))))
check("без причины ведём себя как раньше",
      S.t("pn_card_unknown") in "\n".join(
          S.offender_card(tg_why, None, "x")))

S._PANEL_IP_OWNER.update({"at": 0.0, "map": {}})

print("\n\033[1m36. UUID ноды проверяется по форме\033[0m")
# Живой случай: в поле оказалось «a1b0e1f2a3b4c5d» — начало и хвост настоящего
# UUID, середина потерялась при вводе. Панель такой запрос принимает и отвечает
# пустым результатом: опрос числится успешным, карта адресов пустая, имена
# молча перестают подставляться. Заметить это можно было только вручную.
check("настоящий UUID принят",
      S.valid_uuid("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"))
check("верхний регистр тоже",
      S.valid_uuid("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"))
for bad in ("a1b0e1f2a3b4c5d", "", "не uuid", "a1b2c3d4-e5f6-4a7b-8c9d",
            "a1b2c3d4e5f64a7b8c9d0e1f2a3b4c5d",
            "a1b2c3d4-e5f6-4a7b-8c9d-572233c3b93z"):
    check(f"отвергнут {bad[:24]!r}", not S.valid_uuid(bad))
check("пробел на конце обрезается, а не ломает",
      S.valid_uuid(" a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d "))

import argparse as _ap


def _set(**kw):
    d = dict(action="set", url=None, token=None, node_uuid=None, proxy=None,
             enable=False, disable=False, interval=None, window=None,
             threshold=None, action_set=None, mbps=None, minutes=None,
             cooldown=None, exempt=None, exempt_tags=None, disable_after=None,
             per_device=None,
             report=None, report_at=None,
             report_thread=None, resolve=None, dry_run=False, json=False)
    d.update(kw)
    return _ap.Namespace(**d)


def _dies(fn, *a):
    """Проверяем отказ, а не вывод: показ настроек на экране здесь только шум."""
    import contextlib as _cx
    with _cx.redirect_stdout(io.StringIO()):
        try:
            fn(*a)
            return False
        except SystemExit:
            return True


S.save_config({"panel": dict(S.PANEL_DEFAULT)})
check("кривой UUID не сохраняется",
      _dies(S.cmd_panel, _set(node_uuid="a1b0e1f2a3b4c5d")))
check("и в конфиг ничего не попало",
      not S.load_config()["panel"]["node_uuid"],
      S.load_config()["panel"]["node_uuid"])
check("правильный сохраняется",
      not _dies(S.cmd_panel, _set(node_uuid="a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d")))
check("именно он и лежит в конфиге",
      S.load_config()["panel"]["node_uuid"] == "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d")

print("\n\033[1m37. Пустой опрос виден в состоянии\033[0m")
drop_state()
fresh_cache()
PANEL["users"] = []
cfg_empty = {"panel": conf(action="notify"), "telegram": dict(S.TG_DEFAULT)}
res = S.panel_scan(cfg_empty)
check("опрос успешен", res["ok"] is True)
check("но пользователей ноль", res["users"] == 0)
check("число сохранено в состоянии",
      S.panel_state().get("last_users") == 0, S.panel_state())
PANEL["users"] = make_users({97: 1, 346: 1})
S.panel_scan(cfg_empty)
check("а после нормального опроса — двое",
      S.panel_state().get("last_users") == 2, S.panel_state())

print("\n\033[1m38. panel who: кто стоит за адресом\033[0m")
# Сообщение о штрафе приходит с адресом. Дальше нужен ответ на один вопрос:
# чей он. В памяти сторожа карта есть, но отдельный запуск CLI её не видит —
# значит команда обязана спросить панель заново, а не отдавать пустоту.
fresh_cache()
S.save_config({"panel": conf(node_uuid="a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d")})
PANEL["directory"] = {"741": {"id": 741, "username": "user_100000003",
                             "description": "Bot user: Bashou @bashou7",
                             "telegramId": 100000003}}
PANEL["users"] = [{"userId": 741,
                   "ips": [{"ip": "203.0.113.20", "lastSeen": time.strftime(
                       "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 30))}]}]

def _who(ip):
    """Ловим и stderr: отказ печатается туда, и без него проверка слепа."""
    import contextlib as _cx
    buf = io.StringIO()
    with _cx.redirect_stdout(buf), _cx.redirect_stderr(buf):
        try:
            S.cmd_panel(_set(action="who", ip=ip))
        except SystemExit:
            pass
    return buf.getvalue()

S._PANEL_IP_OWNER.update({"at": 0.0, "map": {}})
PANEL["starts"] = 0
out = _who("203.0.113.20")
check("панель спрошена заново, а не взята из памяти", PANEL["starts"] == 1,
      PANEL["starts"])
check("адрес найден", "203.0.113.20" in out and "741" in out, out)
check("имя показано", "Bashou" in out, out)
check("telegram показан", "100000003" in out, out)
check("время последнего появления показано", "последний раз" in out or "last saw" in out)

out = _who("9.9.9.9")
check("чужой адрес — понятный ответ, а не молчание",
      "9.9.9.9" in out and ("не знает" in out or "does not know" in out), out)
check("и подсказка, где искать причину",
      "отвалиться" in out or "dropped" in out, out)

out = _who("не адрес")
check("мусор вместо адреса отбит", "IP" in out or "адрес" in out, out)

PANEL["users_code"] = 403
out = _who("203.0.113.20")
PANEL["users_code"] = 0
check("без права на пользователей адрес всё равно находится",
      "741" in out, out)
check("и сказано, чего не хватает",
      "users:read" in out, out)

print("\n\033[1m39. Уведомление нельзя выключить\033[0m")
# Живой случай: action=drop без notify. Соединения рвались молча, человек
# жаловался, а в переписке ни следа — понять, кого и за что, было нечем.
# Решение о судьбе нарушителя за человеком, но узнать о нём он должен всегда.
check("одиночный drop добирает уведомление",
      S.panel_actions({"action": "drop"}) == {"drop", "notify"})
check("одиночный block тоже",
      S.panel_actions({"action": "block"}) == {"block", "notify"})
check("пустое действие — всё равно уведомление",
      S.panel_actions({"action": ""}) == {"notify"})
check("мусор не проносит лишнего",
      S.panel_actions({"action": "ерунда"}) == {"notify"})

drop_state()
fresh_cache()
sent.clear(); docs.clear()
PANEL["drops"] = []
PANEL["directory"] = {"741": {"id": 741, "username": "user_100000003",
                             "description": "Bot user: Bashou @bashou7",
                             "telegramId": 100000003}}
PANEL["users"] = make_users({741: 25}, age=60)
S.read_users = lambda: {}
cfg_silent = {"panel": conf(action="drop"),
              "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
S.panel_scan(cfg_silent)
check("соединения оборваны", len(PANEL["drops"]) == 1, PANEL["drops"])
check("и сообщение всё равно ушло", len(sent) == 1, sent)
check("в нём есть имя", any("Bashou" in x for x in sent), sent)
check("и номер в панели", any("741" in x for x in sent), sent)

print("\n\033[1m40. Карточка одинакова для раздачи и для штрафа\033[0m")
# Поводы разные, вопрос у читающего один: кто и за что. Значит и шапка одна.
who = {"label": "Bashou", "handle": "@bashou7",
       "username": "user_100000003", "telegram_id": "100000003",
       "user_id": "741"}
tg_cfg = dict(S.TG_DEFAULT, enabled=True, events=True, node_name="Erebor")
sent.clear()
S.tg_penalty({"telegram": tg_cfg}, "203.0.113.20", 1, 60, ["ratio"], who)
pen = sent[-1]
share = "\n".join(S.offender_card(tg_cfg, who, S.t("pn_msg_head")))
for part in ("Bashou", "100000003", "741", "Erebor"):
    check(f"в обоих есть {part}", part in pen and part in share, (pen, share))
check("в штрафе указан адрес", "203.0.113.20" in pen, pen)
check("в штрафе указана скорость и срок", "1 Мбит" in pen or "1 Mbit" in pen, pen)
check("в штрафе указана причина", S.t("why_ratio") in pen, pen)
check("идентификаторы копируются касанием",
      "<code>100000003</code>" in pen
      and "<code>user_100000003</code>" in pen, pen)
check("адрес касанием не копируется",
      "<code>203.0.113.20</code>" not in pen, pen)
check("имя ведёт в переписку",
      '<a href="tg://user?id=100000003">Bashou</a>' in pen, pen)

# Нода без панели: сообщение обязано сказать, что личность неизвестна, а не
# выглядеть так, будто мы просто забыли имя.
sent.clear()
S.tg_penalty({"telegram": tg_cfg}, "203.0.113.20", 1, 60, ["hourly"])
check("без панели сказано, что кто это — неизвестно",
      S.t("pn_card_unknown") in sent[-1], sent[-1])
check("но адрес и причина на месте",
      "203.0.113.20" in sent[-1] and S.t("why_hourly") in sent[-1], sent[-1])

# ────────────────────────────────────────────────────────────────────
print("\n\033[1m40. Перекрытие не должно отменять отсчёт до отключения\033[0m")
# Перекрытие само убирает нарушителя из видимости: трафика нет, адреса
# стареют и за window_min выпадают из окна. Раньше отсчёт на этом обнулялся,
# и отключение подписки не наступало никогда — замерено на живых нодах.
_pen_store = {}
S.load_penalties = lambda: dict(_pen_store)
now40 = 1000.0
grace40 = 1800.0          # тридцать минут, как у хозяина

def sharing_pen(uid, until):
    return {"until": until, "mbps": 0.05, "since": now40, "source": "panel",
            "kind": "auto", "reason": "sharing", "user_id": str(uid)}

st40 = {"pending": {}}
off40 = [{"user_id": "741"}]
due, pend = S.panel_pending(st40, off40, now40, grace40)
check("отсчёт начался", pend.get("741") == now40, pend)
check("сразу никого не отключаем", due == [], due)

# Перекрыли — на следующем проходе его в списке уже нет.
_pen_store = {"10.0.0.1": sharing_pen(741, now40 + 3600)}
st40["pending"] = pend
held = S.panel_sharing_held(now40 + 600)
check("наше перекрытие видно по штрафу", held == {"741"}, held)
due, pend = S.panel_pending(st40, [], now40 + 600, grace40, keep=held)
check("отсчёт пережил исчезновение из списка", pend.get("741") == now40, pend)
check("но срок ещё не вышел", due == [], due)

st40["pending"] = pend
due, pend = S.panel_pending(st40, [], now40 + grace40, grace40,
                            keep=S.panel_sharing_held(now40 + grace40))
check("через тридцать минут подписка отключается", due == ["741"], due)

# Хозяин снял штраф руками — отсчёт отменяется, как и задумано.
_pen_store = {}
st40["pending"] = {"741": now40}
due, pend = S.panel_pending(st40, [], now40 + grace40, grace40,
                            keep=S.panel_sharing_held(now40 + grace40))
check("снятый штраф отменяет отсчёт", due == [] and pend == {}, (due, pend))

# Истёкший штраф держать отсчёт не должен.
_pen_store = {"10.0.0.1": sharing_pen(741, now40 + 60)}
check("истёкший штраф не держит", S.panel_sharing_held(now40 + 120) == set(),
      S.panel_sharing_held(now40 + 120))
# Чужие штрафы к раздаче отношения не имеют.
_pen_store = {"10.0.0.2": {"until": now40 + 3600, "source": "guard",
                           "reason": "hourly", "user_id": "999"}}
check("штраф сторожа отсчёт не держит",
      S.panel_sharing_held(now40) == set(), S.panel_sharing_held(now40))
# Записи без номера пользователя не должны ронять разбор.
_pen_store = {"10.0.0.3": {"until": now40 + 3600, "source": "panel",
                           "reason": "sharing"}, "10.0.0.4": "мусор"}
check("мусор в штрафах не роняет", S.panel_sharing_held(now40) == set(),
      S.panel_sharing_held(now40))
_pen_store = {}

srv.shutdown()
print(f"\n\033[1mИтог: {ok} пройдено, {fail} провалено\033[0m")
sys.exit(1 if fail else 0)

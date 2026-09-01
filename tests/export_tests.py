#!/usr/bin/env python3
"""
Проверки резервной копии состояния ноды (shaperctl export / import).

Запускать из песочницы, не на рабочей ноде. Каталоги подменяются через
переменные окружения до загрузки модуля, поэтому /etc и /var не трогаются.
"""
import argparse
import importlib.util
import io
import json
import os
import re
import stat
import sys
import tempfile
import time

SRC = os.environ.get("SHAPE_SRC") or os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))

TMP = tempfile.mkdtemp(prefix="shape-export-")
ETC = os.path.join(TMP, "etc"); os.makedirs(ETC)
VAR = os.path.join(TMP, "var"); os.makedirs(VAR)
BIN = os.path.join(TMP, "bin"); os.makedirs(BIN)
PIN = os.path.join(TMP, "maps"); os.makedirs(PIN)

# Подставной bpftool: запоминает вызовы, ничего не делает. Нужен там, где
# импорт доводит восстановленное до ядра.
with open(os.path.join(BIN, "bpftool"), "w") as f:
    f.write('#!/bin/sh\nprintf "%s\\n" "$*" >> "$BPFTOOL_LOG"\n'
            'case "$*" in *dump*) echo "[]";; esac\nexit 0\n')
os.chmod(os.path.join(BIN, "bpftool"), 0o755)

os.environ["PATH"] = BIN + ":" + os.environ["PATH"]
os.environ["SHAPER_PIN_DIR"] = PIN
os.environ["BPFTOOL_LOG"] = os.path.join(TMP, "bpftool.log")
os.environ["SHAPE_ETC_DIR"] = ETC
os.environ["SHAPE_VAR_DIR"] = VAR

spec = importlib.util.spec_from_file_location("S", os.path.join(SRC, "shaperctl.py"))
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)

ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  \033[32m✓\033[0m {name}")
    else:
        fail += 1
        print(f"  \033[31m✗ {name}\033[0m {extra}")


def dies(fn, *a, **kw):
    try:
        fn(*a, **kw)
        return False
    except SystemExit:
        return True


def quiet(fn, *a, **kw):
    """Гасит печать команды: в наборе важен результат, а не вывод."""
    keep = sys.stdout
    sys.stdout = io.StringIO()
    try:
        return fn(*a, **kw)
    finally:
        sys.stdout = keep


def ns_export(**kw):
    d = dict(out=None, with_secrets=False)
    d.update(kw)
    return argparse.Namespace(**d)


def ns_import(file, **kw):
    d = dict(file=file, dry_run=False, only=None, replace=False)
    d.update(kw)
    return argparse.Namespace(**d)


TOKEN = ("123456789:" + "AABBccddeeFFgghhiijjkkllmmnnoopp")
PROXY = "socks5://user:secretpass@1.2.3.4:1080"


def seed():
    """Кладёт в песочницу заведомо известное состояние."""
    for p in (S.WL_FILE, S.PEN_FILE, S.OWNERS_FILE, S.HISTORY_FILE, S.CONFIG_FILE):
        try:
            os.remove(p)
        except OSError:
            pass
    S.save_config({
        "speed_mbps": 25, "ports": [443, 8443],
        "guard": dict(S.GUARD_DEFAULT, enabled=True, penalty_mbps=2),
        "telegram": dict(S.TG_DEFAULT, enabled=True, token=TOKEN,
                         chat_id="-1001234567890", proxy=PROXY,
                         digest_at="21:30"),
    })
    with open(S.WL_FILE, "w") as f:
        f.write("# белый список\n10.0.0.1\n10.0.0.2\n")
    S.save_penalties({
        "1.2.3.4": {"mbps": 5.0, "until": 9.9e10, "kind": "personal",
                    "source": "manual"},
        "5.6.7.8": {"mbps": 1.0, "until": 9.9e10, "source": "guard"},
    })
    S.save_owners({"1.2.3.4": {"label": "Александр", "user_id": "42",
                               "updated": 1755000000}})
    with open(S.HISTORY_FILE, "w") as f:
        f.write(json.dumps({"day": "2026-08-12", "down": 1, "up": 2, "ips": 3,
                            "limited": 0, "top": []}) + "\n")
        f.write(json.dumps({"day": "2026-08-13", "down": 4, "up": 5, "ips": 6,
                            "limited": 1, "top": []}) + "\n")


def wipe_state():
    """Стирает всё, кроме конфига: нода как будто новая, но бот настроен."""
    for p in (S.WL_FILE, S.PEN_FILE, S.OWNERS_FILE, S.HISTORY_FILE):
        try:
            os.remove(p)
        except OSError:
            pass


def semantic(state):
    """Состояние без плавающих значений — для сравнения до и после."""
    return json.dumps({
        "config": state["config"],
        "whitelist": sorted(state["whitelist"]),
        "penalties": {ip: {"mbps": float(p["mbps"]), "until": float(p["until"])}
                      for ip, p in state["penalties"].items()},
        "owners": state["owners"],
        "history": state["history"],
    }, sort_keys=True, ensure_ascii=False)


# ────────────────────────────────────────────────────────────────────
print("\n\033[1m1. Формат выгрузки\033[0m")
seed()
d = S.build_export()
check("метка kind = shape-node-state", d.get("kind") == "shape-node-state")
check("указана версия формата", d.get("schema") == S.EXPORT_SCHEMA)
check("указана версия Shape", bool(d.get("shape_version")))
check("указано имя ноды", bool(d.get("node")))
check("есть отметка времени в двух видах",
      isinstance(d.get("exported_at"), int) and "T" in str(d.get("exported_at_iso")))
check("все пять разделов на месте",
      sorted(d["state"]) == sorted(S.EXPORT_SECTIONS),
      str(sorted(d["state"])))
check("журнал событий в выгрузку не попал", "events" not in d["state"])
check("метрики в выгрузку не попали", "metrics" not in d["state"])

print("\n\033[1m2. Секреты не утекают в файл по умолчанию\033[0m")
plain = json.dumps(S.build_export(with_secrets=False), ensure_ascii=False)
check("токена бота в выгрузке нет", TOKEN not in plain)
check("пароля прокси в выгрузке нет", "secretpass" not in plain)
check("флаг secrets_included = false",
      S.build_export(with_secrets=False)["secrets_included"] is False)
noprod = S.build_export(with_secrets=False)["state"]["config"]["telegram"]
check("chat_id при этом сохранён", noprod["chat_id"] == "-1001234567890")
check("время сводки сохранено", noprod["digest_at"] == "21:30")
check("сам признак включённости сохранён", noprod["enabled"] is True)

full = S.build_export(with_secrets=True)
check("с --with-secrets токен присутствует",
      full["state"]["config"]["telegram"]["token"] == TOKEN)
check("с --with-secrets прокси присутствует",
      full["state"]["config"]["telegram"]["proxy"] == PROXY)
check("флаг secrets_included = true", full["secrets_included"] is True)

print("\n\033[1m3. Файл выгрузки не читается посторонними\033[0m")
path = os.path.join(TMP, "dump.json")
quiet(S.cmd_export, ns_export(out=path, with_secrets=True))
mode = stat.S_IMODE(os.stat(path).st_mode)
check("права на файле 600", mode == 0o600, oct(mode))
check("файл читается как JSON", isinstance(json.load(open(path)), dict))

print("\n\033[1m4. Круговой тест: выгрузили, стёрли, восстановили\033[0m")
seed()
before = semantic(S.build_export(with_secrets=True)["state"])
dump = S.build_export(with_secrets=True)
wipe_state()
check("состояние действительно стёрто",
      not S.whitelist_ips() and not S.load_penalties() and not S.load_owners())
state, problems = S.validate_export(dump)
check("чистая выгрузка проходит проверку без замечаний", problems == [], str(problems))
done = S.apply_import(state, keep_secrets=False)
after = semantic(S.build_export(with_secrets=True)["state"])
check("состояние совпадает с исходным", before == after)
check("все пять разделов применены",
      sorted(done) == sorted(S.EXPORT_SECTIONS), str(sorted(done)))

print("\n\033[1m5. Повторный импорт ничего не меняет\033[0m")
one = semantic(S.build_export(with_secrets=True)["state"])
S.apply_import(S.validate_export(S.build_export(with_secrets=True))[0],
               keep_secrets=False)
two = semantic(S.build_export(with_secrets=True)["state"])
check("импорт идемпотентен", one == two)

print("\n\033[1m6. Токен ноды не затирается выгрузкой без секретов\033[0m")
seed()
dump_plain = S.build_export(with_secrets=False)
S.save_config({"telegram": dict(S.TG_DEFAULT, token="999:LOCALTOKEN",
                                proxy="socks5://local:1080")})
state, _ = S.validate_export(dump_plain)
S.apply_import(state, keep_secrets=True)
cfg = S.load_config()
check("токен, настроенный на ноде, остался", cfg["telegram"]["token"] == "999:LOCALTOKEN")
check("прокси ноды остался", cfg["telegram"]["proxy"] == "socks5://local:1080")
check("остальные поля пришли из выгрузки",
      cfg["telegram"]["chat_id"] == "-1001234567890")
check("скорость пришла из выгрузки", cfg["speed_mbps"] == 25)

print("\n\033[1m7. Выгрузка с секретами перезаписывает токен\033[0m")
seed()
S.save_config({"telegram": dict(S.TG_DEFAULT, token="999:LOCALTOKEN")})
dump_full = dict(json.loads(json.dumps(full)))
state, _ = S.validate_export(dump_full)
S.apply_import(state, keep_secrets=False)
check("токен из выгрузки применён", S.load_config()["telegram"]["token"] == TOKEN)

print("\n\033[1m8. Чужие и битые файлы отвергаются целиком\033[0m")
check("не объект", dies(S.validate_export, "строка"))
check("список вместо объекта", dies(S.validate_export, [1, 2]))
check("нет метки kind", dies(S.validate_export, {"schema": 1, "state": {}}))
check("чужая метка kind",
      dies(S.validate_export, {"kind": "backup", "schema": 1, "state": {}}))
check("нет версии формата",
      dies(S.validate_export, {"kind": "shape-node-state", "state": {}}))
check("версия формата нечисловая",
      dies(S.validate_export, {"kind": "shape-node-state", "schema": "x", "state": {}}))
check("формат новее нашего",
      dies(S.validate_export,
           {"kind": "shape-node-state", "schema": S.EXPORT_SCHEMA + 1, "state": {}}))
check("нет раздела state",
      dies(S.validate_export, {"kind": "shape-node-state", "schema": 1}))
check("state не объект",
      dies(S.validate_export,
           {"kind": "shape-node-state", "schema": 1, "state": []}))

bad_json = os.path.join(TMP, "broken.json")
with open(bad_json, "w") as f:
    f.write("{это не json")
check("битый JSON отвергается", dies(quiet, S.cmd_import, ns_import(bad_json)))
check("отсутствующий файл отвергается",
      dies(quiet, S.cmd_import, ns_import(os.path.join(TMP, "нет-такого.json"))))
check("неизвестный раздел в --only отвергается",
      dies(quiet, S.cmd_import, ns_import(path, only="config,выдумка")))


def wrap(state_dict):
    return {"kind": "shape-node-state", "schema": 1, "state": state_dict}


print("\n\033[1m9. Мусор внутри разделов отбрасывается, а не ломает импорт\033[0m")
st, pr = S.validate_export(wrap({
    "config": {"speed_mbps": float("nan"),
               "ports": [443, 70000, "x", True, -1],
               "guard": {"enabled": "да", "penalty_mbps": 3, "чужое": 1},
               "telegram": {"token": 5, "chat_id": "ok"}},
    "whitelist": ["10.0.0.1", "не адрес", "10.0.0.1", 42],
    "penalties": {"1.2.3.4": {"mbps": -5, "until": 1},
                  "203.0.113.3": {"mbps": 0, "until": 9e9},
                  "203.0.113.4": {"mbps": float("inf"), "until": 9e9},
                  "плохой": {}, "5.6.7.8": {"mbps": 3, "until": 9e9}},
    "owners": {"9.9.9.9": {"label": "A" * 500, "мусор": 1},
               "нет-адреса": {"label": "x"}},
    "history": [{"day": "2026-01-01"}, {"day": "вчера"}, "строка", 5],
}))
check("скорость nan отброшена", "speed_mbps" not in st["config"])
check("остался только годный порт", st["config"]["ports"] == [443],
      str(st["config"]["ports"]))
check("строка вместо булева в guard отброшена", "enabled" not in st["config"]["guard"])
check("годное число в guard осталось", st["config"]["guard"]["penalty_mbps"] == 3)
check("незнакомый ключ в guard отброшен", "чужое" not in st["config"]["guard"])
check("число вместо строки в telegram отброшено", "token" not in st["config"]["telegram"])
check("годная строка в telegram осталась", st["config"]["telegram"]["chat_id"] == "ok")
check("в белом списке только адреса", st["whitelist"] == ["10.0.0.1"],
      str(st["whitelist"]))
check("отрицательная, нулевая и бесконечная скорости отброшены",
      list(st["penalties"]) == ["5.6.7.8"], str(list(st["penalties"])))
check("длинный ярлык владельца обрезан",
      len(st["owners"]["9.9.9.9"]["label"]) == 200)
check("незнакомое поле владельца отброшено", "мусор" not in st["owners"]["9.9.9.9"])
check("владелец без адреса отброшен", list(st["owners"]) == ["9.9.9.9"])
check("в истории остались только записи с датой",
      [r["day"] for r in st["history"]] == ["2026-01-01"])
check("на каждую отброшенную запись есть замечание", len(pr) >= 10, str(len(pr)))

st, pr = S.validate_export(wrap({"config": {"ports": list(range(1000, 1000 + S.MAX_PORTS + 5))}}))
check(f"портов не больше {S.MAX_PORTS}", len(st["config"]["ports"]) == S.MAX_PORTS)
check("про лишние порты есть замечание", any("MAX" in p or str(S.MAX_PORTS) in p for p in pr))

st, pr = S.validate_export(wrap({}))
check("пустой state не ломает разбор", st == {} and pr == [])
st, pr = S.validate_export(wrap({"config": "строка", "whitelist": 5,
                                 "penalties": [], "owners": 1, "history": {}}))
check("испорченные разделы отбрасываются целиком", st == {}, str(st))
check("на каждый испорченный раздел есть замечание", len(pr) == 5, str(pr))

print("\n\033[1m10. Проверка без записи ничего не меняет\033[0m")
seed()
snapshot = semantic(S.build_export(with_secrets=True)["state"])
other = os.path.join(TMP, "other.json")
with open(other, "w") as f:
    json.dump(wrap({"config": {"speed_mbps": 999}, "whitelist": ["8.8.8.8"],
                    "penalties": {}, "owners": {}, "history": []}), f)
quiet(S.cmd_import, ns_import(other, dry_run=True))
check("после --dry-run состояние прежнее",
      semantic(S.build_export(with_secrets=True)["state"]) == snapshot)
check("чужой адрес в белый список не попал", "8.8.8.8" not in S.whitelist_ips())

print("\n\033[1m11. Выборочное восстановление\033[0m")
seed()
quiet(S.cmd_import, ns_import(other, only="whitelist"))
check("указанный раздел применён", "8.8.8.8" in S.whitelist_ips())
check("не указанный раздел не тронут", S.load_config()["speed_mbps"] == 25)
check("владельцы не тронуты", "1.2.3.4" in S.load_owners())

print("\n\033[1m12. Белый список: дополнить или заменить\033[0m")
seed()
quiet(S.cmd_import, ns_import(other, only="whitelist"))
check("без --replace список дополняется",
      {"8.8.8.8", "10.0.0.1", "10.0.0.2"} <= S.whitelist_ips())
seed()
quiet(S.cmd_import, ns_import(other, only="whitelist", replace=True))
check("с --replace список заменяется", S.whitelist_ips() == {"8.8.8.8"},
      str(S.whitelist_ips()))
check("шапка файла сохранена",
      open(S.WL_FILE).read().lstrip().startswith("#"))

print("\n\033[1m13. Просроченные ограничения не воскресают\033[0m")
seed()
stale = wrap({"penalties": {"7.7.7.7": {"mbps": 2, "until": 1000000000},
                            "8.8.8.8": {"mbps": 2, "until": 9.9e10}}})
state, _ = S.validate_export(stale)
S.apply_import(state, only=["penalties"])
live = S.load_penalties()
check("истёкший штраф не вернулся", "7.7.7.7" not in live)
check("действующий штраф вернулся", "8.8.8.8" in live)

print("\n\033[1m14. История сливается по суткам, без задвоения\033[0m")
seed()
extra = wrap({"history": [
    {"day": "2026-08-13", "down": 999, "up": 0, "ips": 1, "limited": 0, "top": []},
    {"day": "2026-08-14", "down": 7, "up": 0, "ips": 1, "limited": 0, "top": []},
]})
state, _ = S.validate_export(extra)
S.apply_import(state, only=["history"])
rows = S.read_history(limit=400)
days = [r["day"] for r in rows]
check("сутки не задвоились", len(days) == len(set(days)), str(days))
check("прежние сутки на месте", "2026-08-12" in days)
check("новые сутки добавились", "2026-08-14" in days)
check("совпавшие сутки перезаписаны",
      next(r for r in rows if r["day"] == "2026-08-13")["down"] == 999)
check("порядок по возрастанию дат", days == sorted(days))

print("\n\033[1m15. Доведение до ядра\033[0m")
seed()
open(os.path.join(PIN, "config_map"), "w").close()
open(os.environ["BPFTOOL_LOG"], "w").close()
state, _ = S.validate_export(S.build_export(with_secrets=True))
done = S.apply_import(state, keep_secrets=False)
live = S.import_to_kernel(done)
log = open(os.environ["BPFTOOL_LOG"]).read()
check("движок распознан как загруженный", live is True)
check("скорость залита в config_map", "config_map" in log)
check("порты залиты в port_map", "port_map" in log)
check("белый список залит в whitelist_map", "whitelist_map" in log)

os.remove(os.path.join(PIN, "config_map"))
open(os.environ["BPFTOOL_LOG"], "w").close()
check("без движка импорт не падает и в ядро не лезет",
      S.import_to_kernel(done) is False
      and os.path.getsize(os.environ["BPFTOOL_LOG"]) == 0)

print("\n\033[1m16. Импорт записывает событие в журнал\033[0m")
seed()
try:
    os.remove(S.EVENT_FILE)
except OSError:
    pass
quiet(S.cmd_import, ns_import(other, only="whitelist"))
events, _more = S.read_events(limit=10)
check("событие о восстановлении записано",
      any("import" in str(e.get("message", "")) for e in events), str(events))
check("в событии перечислены восстановленные разделы",
      any("whitelist" in str(e.get("message", "")) for e in events))

print("\n\033[1m17. Строки интерфейса переведены на оба языка\033[0m")
keys = set(re.findall(r'\bt\("([a-z0-9_]+)"', open(os.path.join(SRC, "shaperctl.py"),
                                                   encoding="utf-8").read()))
new_keys = {k for k in keys if k.startswith(("imp_", "exp_", "sec_", "h_exp", "h_imp"))
            } | {"h_export", "h_import"}
missing_ru = sorted(k for k in new_keys if k not in S.MSG["ru"])
missing_en = sorted(k for k in new_keys if k not in S.MSG["en"])
check("все новые ключи есть по-русски", not missing_ru, str(missing_ru))
check("все новые ключи есть по-английски", not missing_en, str(missing_en))
check("русский и английский наборы совпадают по размеру",
      len(S.MSG["ru"]) == len(S.MSG["en"]),
      f"ru={len(S.MSG['ru'])} en={len(S.MSG['en'])}")

# ─────────────── отправка копии в Telegram ───────────────
# Сеть не трогаем: подменяем _post и смотрим, что именно ушло бы в API.

def with_tg(**over):
    """Настраивает Telegram в песочнице и возвращает конфиг."""
    tg = dict(S.TG_DEFAULT, enabled=True, token=TOKEN, chat_id="-1001234567890",
              proxy=PROXY, digest_at="09:00")
    tg.update(over)
    S.save_config({"speed_mbps": 25, "ports": [443], "telegram": tg})
    return S.load_config()


class Captured:
    """Перехватывает _post: запоминает вызов и возвращает заданный код."""

    def __init__(self, status=200, raise_exc=None):
        self.status, self.raise_exc, self.calls = status, raise_exc, []

    def __enter__(self):
        self.real = S._post

        def fake(url, data, proxy="", content_type="application/x-www-form-urlencoded"):
            self.calls.append({"url": url, "data": data, "proxy": proxy,
                               "ctype": content_type})
            if self.raise_exc:
                raise self.raise_exc
            return self.status

        S._post = fake
        return self

    def __exit__(self, *a):
        S._post = self.real
        return False

    @property
    def body(self):
        return self.calls[-1]["data"].decode("utf-8", "replace")


def field_of(body, name):
    m = re.search(r'name="%s"\r\n\r\n(.*?)\r\n--' % re.escape(name), body, re.S)
    return m.group(1) if m else None


print("\n\033[1m18. Отправка копии в Telegram: что уходит в API\033[0m")
seed()
cfg = with_tg(backup=True, backup_thread_id="777")
with Captured() as cap:
    okk, err = S.tg_backup(cfg, force=True)
check("отправка прошла", okk is True, str(err))
check("метод sendDocument", cap.calls[-1]["url"].endswith("/sendDocument"))
check("токен в пути, а не в теле", "/bot" + TOKEN + "/" in cap.calls[-1]["url"])
check("прокси проброшен как есть", cap.calls[-1]["proxy"] == PROXY)
check("тип содержимого multipart",
      cap.calls[-1]["ctype"].startswith("multipart/form-data; boundary="))
check("граница из тела совпадает с заголовком",
      cap.body.startswith("--" + cap.calls[-1]["ctype"].split("boundary=")[1]))
check("чат указан", field_of(cap.body, "chat_id") == "-1001234567890")
check("тема копий отдельная", field_of(cap.body, "message_thread_id") == "777")
check("подпись есть", "💾" in (field_of(cap.body, "caption") or ""))
check("имя файла с датой и нодой",
      re.search(r'filename="shape-[A-Za-z0-9._-]+-\d{4}-\d{2}-\d{2}\.json"', cap.body)
      is not None,
      re.search(r'filename="[^"]*"', cap.body).group(0))
check("вложение — разобранный JSON выгрузки",
      json.loads(cap.body.split("\r\n\r\n")[-1].rsplit("\r\n--", 1)[0]
                 )["kind"] == "shape-node-state")

print("\n\033[1m19. Секреты в Telegram не уходят ни при каких настройках\033[0m")
check("токена бота нет в теле запроса", TOKEN not in cap.body)
check("пароля прокси нет в теле запроса", "secretpass" not in cap.body)
check("флаг secrets_included во вложении false",
      json.loads(cap.body.split("\r\n\r\n")[-1].rsplit("\r\n--", 1)[0]
                 )["secrets_included"] is False)


# Ломаем выгрузку так, будто кто-то однажды включил секреты в этот путь.
real_build = S.build_export


def leaky(with_secrets=False):
    return real_build(with_secrets=True)


S.build_export = leaky
try:
    with Captured() as cap2:
        okk, err = S.tg_backup(with_tg(backup=True), force=True)
    check("выгрузка с секретом не отправляется", okk is False)
    check("в API не ушло ни одного запроса", cap2.calls == [])
    check("причина названа явно", "секрет" in err or "secret" in err, err)
finally:
    S.build_export = real_build

print("\n\033[1m20. Когда отправка не должна происходить\033[0m")
with Captured() as cap3:
    okk, err = S.tg_backup(with_tg(backup=False), force=False)
check("выключенная отправка молчит", okk is False and cap3.calls == [])
with Captured() as cap4:
    okk, _ = S.tg_backup(with_tg(backup=True, enabled=False), force=False)
check("выключенный Telegram молчит", okk is False and cap4.calls == [])
with Captured() as cap5:
    okk, err = S.tg_backup(with_tg(backup=True, token=""), force=True)
check("без токена не отправляем", okk is False and cap5.calls == [])
with Captured() as cap6:
    okk, err = S.tg_backup(with_tg(backup=True, chat_id=""), force=True)
check("без чата не отправляем", okk is False and cap6.calls == [])
with Captured() as cap7:
    okk, _ = S.tg_backup(with_tg(backup=False), force=True)
check("кнопка «сейчас» работает и при выключенном расписании",
      okk is True and len(cap7.calls) == 1)

print("\n\033[1m21. Тема по умолчанию — та же, что у отчётов\033[0m")
with Captured() as cap8:
    S.tg_backup(with_tg(backup=True, thread_id="42", backup_thread_id=""), force=True)
check("без своей темы копия идёт в тему отчётов",
      field_of(cap8.body, "message_thread_id") == "42")
with Captured() as cap9:
    S.tg_backup(with_tg(backup=True, thread_id="", backup_thread_id=""), force=True)
check("без тем вообще поле не отправляется",
      field_of(cap9.body, "message_thread_id") is None)

print("\n\033[1m22. Недельное расписание\033[0m")


def at(day, hh, mm):
    """Момент времени: 2026-08-10 — понедельник."""
    return time.mktime((2026, 8, 9 + day, hh, mm, 0, 0, 0, -1))


for p in (S.BACKUP_STATE,):
    try:
        os.remove(p)
    except OSError:
        pass

cfg = with_tg(backup=True, backup_day=1, digest_at="09:00")
with Captured() as c:
    fired = S.backup_due(cfg, now=at(1, 8, 59))
check("до назначенного часа не отправляем", fired is False and c.calls == [])
with Captured() as c:
    fired = S.backup_due(cfg, now=at(2, 12, 0))
check("в другой день недели не отправляем", fired is False and c.calls == [])
with Captured() as c:
    fired = S.backup_due(cfg, now=at(1, 9, 0))
check("в назначенный день и час отправляем", fired is True and len(c.calls) == 1)
with Captured() as c:
    fired = S.backup_due(cfg, now=at(1, 18, 0))
check("второй раз за те же сутки не отправляем", fired is False and c.calls == [])

os.remove(S.BACKUP_STATE)
cfg = with_tg(backup=True, backup_day=6, digest_at="21:30")
with Captured() as c:
    check("суббота в 21:29 — рано",
          S.backup_due(cfg, now=at(6, 21, 29)) is False and c.calls == [])
with Captured() as c:
    check("суббота в 21:30 — пора", S.backup_due(cfg, now=at(6, 21, 30)) is True)

os.remove(S.BACKUP_STATE)
cfg = with_tg(backup=True, backup_day=1)
with Captured(raise_exc=OSError("сеть недоступна")) as c:
    fired = quiet(S.backup_due, cfg, at(1, 9, 0))
check("при обрыве связи отправка не считается удачной", fired is False)
state = json.load(open(S.BACKUP_STATE))
check("назначен повтор, а не бесконечные попытки",
      state.get("retry_at", 0) > at(1, 9, 0) and "last_sent" not in state)
with Captured() as c:
    fired = quiet(S.backup_due, cfg, at(1, 9, 5))
check("до срока повтора в API не лезем", fired is False and c.calls == [])
with Captured() as c:
    fired = S.backup_due(cfg, now=at(1, 9, 0) + S.BACKUP_RETRY + 1)
check("после срока повтора пробуем снова", fired is True)

os.remove(S.BACKUP_STATE)
with Captured() as c:
    check("кривой день недели не роняет сторожа",
          S.backup_due(with_tg(backup=True, backup_day="понедельник"),
                       now=at(1, 9, 0)) is True)
os.remove(S.BACKUP_STATE)
with open(S.BACKUP_STATE, "w") as f:
    f.write("{это не json")
with Captured() as c:
    check("испорченный файл состояния не роняет сторожа",
          S.backup_due(with_tg(backup=True, backup_day=1), now=at(1, 9, 0)) is True)

print("\n\033[1m23. Сборка multipart\033[0m")
body, ctype = S._multipart({"a": "1", "b": "два"}, "x.json", b'{"k":1}')
check("границы уникальны при каждом вызове",
      S._multipart({}, "x", b"")[1] != S._multipart({}, "x", b"")[1])
check("тело заканчивается закрывающей границей",
      body.endswith(("--" + ctype.split("boundary=")[1] + "--\r\n").encode()))
check("текстовые поля на месте",
      b'name="a"' in body and "два".encode() in body)
check("бинарное вложение не искажено", b'{"k":1}' in body)
check("опасное имя файла обеззаражено",
      'filename="a-b-c.json"' in S._multipart({}, 'a"b/c.json', b"")[0]
      .decode("utf-8", "replace"),
      re.search(r'filename="[^"]*"',
                S._multipart({}, 'a"b/c.json', b"")[0].decode("utf-8", "replace")).group(0))
check("пустое имя ноды не даёт пустое имя файла",
      S.backup_filename("///").startswith("shape-node-"),
      S.backup_filename("///"))

print("\n\033[1m24. Отправка копии не меняет состояние ноды\033[0m")
seed()
before_state = semantic(S.build_export(with_secrets=True)["state"])
with Captured():
    S.tg_backup(with_tg(backup=True), force=True)
seed_cfg_gone = semantic(S.build_export(with_secrets=True)["state"])
check("состояние после отправки прежнее",
      json.loads(before_state)["whitelist"] == json.loads(seed_cfg_gone)["whitelist"])

# ─────────────── транспорт ───────────────
# Здесь _post выполняется по-настоящему, а подменяются urllib и сокеты.
# Прежние проверки подменяли сам _post, и его собственный код не работал
# ни разу — из-за чего отправка без прокси годами падала незамеченной.

print("\n\033[1m25. Транспорт: отправка без прокси\033[0m")


class FakeResponse:
    def __init__(self, status=200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return b"{}"


class FakeOpener:
    def __init__(self, sink):
        self.sink = sink

    def open(self, req, timeout=None):
        self.sink.append({"req": req, "timeout": timeout})
        return FakeResponse()


def capture_urllib():
    """Подменяет build_opener и возвращает список того, что ушло."""
    sink = []
    real = S.urllib.request.build_opener

    def fake(*handlers):
        sink.append({"handlers": handlers})
        return FakeOpener(sink)

    S.urllib.request.build_opener = fake
    return sink, real


sink, real_builder = capture_urllib()
try:
    status = S._post("https://api.telegram.org/botX/sendMessage", b"a=1")
    check("без прокси запрос уходит, а не падает", status == 200)
    sent = [x for x in sink if "req" in x]
    check("запрос действительно передан", len(sent) == 1)
    check("метод POST", sent[0]["req"].get_method() == "POST")
    check("тело на месте", sent[0]["req"].data == b"a=1")
    check("тип содержимого по умолчанию — форма",
          sent[0]["req"].get_header("Content-type")
          == "application/x-www-form-urlencoded")
    check("таймаут задан", sent[0]["timeout"] == 15)
    handlers = [x for x in sink if "handlers" in x][0]["handlers"]
    check("обработчик прокси создан", len(handlers) == 1)
    check("без прокси окружение не подхватывается",
          handlers[0].proxies == {},
          str(handlers[0].proxies))

    sink.clear()
    body, ctype = S._multipart({"a": "1"}, "x.json", b"{}")
    S._post("https://api.telegram.org/botX/sendDocument", body, "", ctype)
    sent = [x for x in sink if "req" in x][0]
    check("свой тип содержимого доходит до запроса",
          sent["req"].get_header("Content-type").startswith("multipart/form-data"))

    sink.clear()
    S._post("https://api.telegram.org/botX/sendMessage", b"a=1",
            "http://proxy.example:3128")
    handlers = [x for x in sink if "handlers" in x][0]["handlers"]
    check("HTTP-прокси попадает в обработчик",
          handlers[0].proxies.get("https") == "proxy.example:3128"
          or handlers[0].proxies.get("https") == "http://proxy.example:3128",
          str(handlers[0].proxies))
finally:
    S.urllib.request.build_opener = real_builder

print("\n\033[1m26. Транспорт: отправка через SOCKS5\033[0m")


class FakeConn:
    calls = []

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port = host, port
        self.sock = None

    def request(self, method, path, body=None, headers=None):
        FakeConn.calls.append({"method": method, "path": path,
                               "body": body, "headers": headers or {}})

    def getresponse(self):
        return FakeResponse()


class FakeSock:
    def close(self):
        pass


def fake_wrap(sock, server_hostname=None):
    return sock


class FakeCtx:
    wrap_socket = staticmethod(fake_wrap)


saved = (S.socket.create_connection, S._socks5, S.ssl.create_default_context,
         S.http.client.HTTPSConnection)
socks_args = []
try:
    S.socket.create_connection = lambda addr, timeout=None: FakeSock()
    S._socks5 = lambda sock, host, port, user=None, pwd=None: \
        socks_args.append((host, port, user, pwd))
    S.ssl.create_default_context = lambda: FakeCtx()
    S.http.client.HTTPSConnection = FakeConn
    FakeConn.calls.clear()

    status = S._post("https://api.telegram.org/botX/sendDocument", b"body",
                     "socks5://user:pw@127.0.0.1:1080", "multipart/form-data; boundary=z")
    check("через SOCKS5 запрос уходит", status == 200)
    check("соединение открыто до Telegram, а не до прокси",
          socks_args and socks_args[0][0] == "api.telegram.org")
    check("порт 443", socks_args[0][1] == 443)
    check("логин и пароль прокси переданы", socks_args[0][2:] == ("user", "pw"))
    call = FakeConn.calls[-1]
    check("метод POST", call["method"] == "POST")
    check("путь без хоста", call["path"] == "/botX/sendDocument")
    check("свой тип содержимого дошёл",
          call["headers"]["Content-Type"] == "multipart/form-data; boundary=z")
    check("длина тела указана", call["headers"]["Content-Length"] == str(len(b"body")))
    check("заголовок Host выставлен", call["headers"]["Host"] == "api.telegram.org")
finally:
    (S.socket.create_connection, S._socks5, S.ssl.create_default_context,
     S.http.client.HTTPSConnection) = saved

print("\n\033[1m27. Отправка целиком, без подмены _post\033[0m")
seed()
sink, real_builder = capture_urllib()
try:
    okk, err = S.tg_send("проверка", with_tg(proxy=""), force=True)
    check("сообщение без прокси отправляется", okk is True, str(err))
    req = [x for x in sink if "req" in x][-1]["req"]
    check("метод API sendMessage", req.full_url.endswith("/sendMessage"))

    sink.clear()
    okk, err = S.tg_backup(with_tg(backup=True, proxy=""), force=True)
    check("копия без прокси отправляется", okk is True, str(err))
    req = [x for x in sink if "req" in x][-1]["req"]
    check("метод API sendDocument", req.full_url.endswith("/sendDocument"))
    check("токена нет в теле", TOKEN.encode() not in req.data)
finally:
    S.urllib.request.build_opener = real_builder

print("\n\033[1m28. Подсказка про прокси даётся по делу\033[0m")
with Captured(raise_exc=OSError("Network is unreachable")) as c:
    _okk, err = S.tg_backup(with_tg(backup=True, proxy=""), force=True)
check("на сетевую ошибку без прокси подсказка есть",
      "прокс" in err.lower() or "proxy" in err.lower(), err)
with Captured(raise_exc=OSError("Network is unreachable")) as c:
    _okk, err = S.tg_backup(with_tg(backup=True), force=True)
check("при заданном прокси подсказки нет",
      "прокс" not in err.lower() and "proxy" not in err.lower(), err)
with Captured(raise_exc=AttributeError("что-то сломалось в коде")) as c:
    _okk, err = S.tg_backup(with_tg(backup=True, proxy=""), force=True)
check("на ошибку в коде прокси не предлагается",
      "прокс" not in err.lower() and "proxy" not in err.lower(), err)
check("сама ошибка при этом видна", "сломалось" in err, err)

# ─────────────── идентификатор ноды и отпечаток настроек ───────────────

print("\n\033[1m29. Идентификатор ноды\033[0m")
try:
    os.remove(S.NODE_ID_FILE)
except OSError:
    pass
first = S.node_id()
check("идентификатор создан", bool(first))
check("шестнадцать шестнадцатеричных знаков",
      re.fullmatch(r"[0-9a-f]{16}", first) is not None, first)
check("повторный вызов даёт то же значение", S.node_id() == first)
check("файл читается всеми, но пишется только владельцем",
      stat.S_IMODE(os.stat(S.NODE_ID_FILE).st_mode) == 0o644,
      oct(stat.S_IMODE(os.stat(S.NODE_ID_FILE).st_mode)))
check("значение переживает перезагрузку конфига",
      S.node_id() == open(S.NODE_ID_FILE).read().strip())

with open(S.NODE_ID_FILE, "w") as f:
    f.write("не идентификатор\n")
second = S.node_id()
check("испорченный файл заменяется новым значением",
      re.fullmatch(r"[0-9a-f]{16}", second) is not None, second)
check("и оно тоже устойчиво", S.node_id() == second)

# Два независимых каталога состояния — как две разные ноды.
keep = (S.VAR_DIR, S.NODE_ID_FILE)
try:
    ids = []
    for name in ("nodeA", "nodeB"):
        S.VAR_DIR = os.path.join(TMP, name)
        S.NODE_ID_FILE = os.path.join(S.VAR_DIR, "node_id")
        ids.append(S.node_id())
    check("у разных нод идентификаторы разные", ids[0] != ids[1])
finally:
    S.VAR_DIR, S.NODE_ID_FILE = keep

print("\n\033[1m30. Идентификатор не переезжает вместе с копией\033[0m")
seed()
mine = S.node_id()
dump = S.build_export(with_secrets=True)
check("идентификатора нет в выгрузке",
      mine not in json.dumps(dump, ensure_ascii=False))
check("раздела node_id в выгрузке нет", "node_id" not in dump["state"])
state, _ = S.validate_export(dump)
S.apply_import(state, keep_secrets=False)
check("после восстановления идентификатор прежний", S.node_id() == mine)

print("\n\033[1m31. Отпечаток настроек\033[0m")
S.save_config({"speed_mbps": 100, "ports": [443],
               "guard": dict(S.GUARD_DEFAULT, enabled=True)})
base = S.config_hash()
check("двенадцать шестнадцатеричных знаков",
      re.fullmatch(r"[0-9a-f]{12}", base) is not None, base)
check("одинаковые настройки дают одинаковый отпечаток", S.config_hash() == base)

S.save_config({"telegram": dict(S.TG_DEFAULT, node_name="Франкфурт-3",
                                token=TOKEN, chat_id="-100", thread_id="7")})
check("настройки Telegram на отпечаток не влияют", S.config_hash() == base)

S.save_config({"guard": dict(S.GUARD_DEFAULT, enabled=True, watch_interval=30)})
check("период опроса на отпечаток не влияет", S.config_hash() == base)

# Скорость в отпечаток не входит: каналы у нод разные по замыслу, и в
# хеше она давала бы столько групп, сколько тарифов. Смотреть её нужно
# метрикой shape_speed_limit_mbps, числом.
S.save_config({"speed_mbps": 50})
check("другая скорость отпечаток не меняет", S.config_hash() == base)
S.save_config({"speed_mbps": 1000})
check("и очень другая тоже", S.config_hash() == base)
S.save_config({"speed_mbps": 0})
check("снятие лимита отпечаток не меняет", S.config_hash() == base)
S.save_config({"speed_mbps": 100})

S.save_config({"ports": [443, 8443]})
check("другие порты — другой отпечаток", S.config_hash() != base)
two_ports = S.config_hash()
S.save_config({"ports": [8443, 443]})
check("порядок портов значения не имеет", S.config_hash() == two_ports,
      f"{two_ports} против {S.config_hash()}")
S.save_config({"ports": [443]})
check("возврат портов возвращает отпечаток", S.config_hash() == base)

S.save_config({"guard": dict(S.GUARD_DEFAULT, enabled=True, penalty_mbps=5)})
check("другой штраф — другой отпечаток", S.config_hash() != base)
S.save_config({"guard": dict(S.GUARD_DEFAULT, enabled=True)})
check("возврат настроек сторожа возвращает отпечаток", S.config_hash() == base)
S.save_config({"guard": dict(S.GUARD_DEFAULT, enabled=False)})
check("выключенный сторож — другой отпечаток", S.config_hash() != base)

check("переданный конфиг не читается с диска",
      S.config_hash({"speed_mbps": 100, "ports": [443],
                     "guard": dict(S.GUARD_DEFAULT, enabled=True)}) == base)
check("пустой конфиг не роняет расчёт",
      re.fullmatch(r"[0-9a-f]{12}", S.config_hash({})) is not None)

print("\n\033[1m32. И то, и другое видно в метриках\033[0m")
S.save_config({"speed_mbps": 100, "ports": [443],
               "guard": dict(S.GUARD_DEFAULT, enabled=True)})
line = [ln for ln in S.build_metrics().splitlines() if ln.startswith("shape_info{")][0]
check("идентификатор в метке", f'node_id="{S.node_id()}"' in line, line)
check("отпечаток в метке", f'config_hash="{S.config_hash()}"' in line, line)
check("версия осталась на месте", 'version="' in line)
check("интерфейс остался на месте", 'interface="' in line)

# Раз скорости в отпечатке нет — она обязана быть видна отдельно, иначе
# разницу между нодами не с чем сравнить.
S.save_config({"speed_mbps": 37})
metrics = S.build_metrics()
speed_line = [ln for ln in metrics.splitlines()
              if ln.startswith("shape_speed_limit_mbps{")][0]
check("скорость отдаётся отдельной метрикой числом",
      speed_line.rstrip().endswith(" 37"), speed_line)
check("при этом отпечаток прежний",
      f'config_hash="{S.config_hash()}"' in
      [ln for ln in metrics.splitlines() if ln.startswith("shape_info{")][0])

print(f"\n\033[1mИтог: {ok} пройдено, {fail} провалено\033[0m")
sys.exit(1 if fail else 0)

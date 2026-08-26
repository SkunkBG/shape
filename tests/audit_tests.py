#!/usr/bin/env python3
"""Проверки после аудита Shape. Запускать из песочницы, не на ноде."""
import json, os, re, subprocess, sys, tempfile, time, importlib.util

import os as _os
# Корень проекта: каталог над tests/. Так набор работает и локально, и в CI.
SRC = _os.environ.get("SHAPE_SRC") or _os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="shape-audit-")
ETC = os.path.join(TMP, "etc"); os.makedirs(ETC)
BIN = os.path.join(TMP, "bin"); os.makedirs(BIN)
PIN = os.path.join(TMP, "maps"); os.makedirs(PIN)
open(os.path.join(PIN, "config_map"), "w").close()

# Подставной bpftool: пишет вызовы в файл, ничего не делает.
with open(os.path.join(BIN, "bpftool"), "w") as f:
    f.write('#!/bin/sh\nprintf "%s\\n" "$*" >> "$BPFTOOL_LOG"\n'
            'case "$*" in *dump*) echo "[]";; esac\nexit 0\n')
os.chmod(os.path.join(BIN, "bpftool"), 0o755)
os.environ["PATH"] = BIN + ":" + os.environ["PATH"]
os.environ["SHAPER_PIN_DIR"] = PIN
os.environ["BPFTOOL_LOG"] = os.path.join(TMP, "bpftool.log")

spec = importlib.util.spec_from_file_location("S", os.path.join(SRC, "shaperctl.py"))
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
S.ETC_DIR = ETC
S.CONFIG_FILE = os.path.join(ETC, "config.json")
S.PEN_FILE = os.path.join(ETC, "penalties.json")
S.DAILY_FILE = os.path.join(ETC, "daily.json")
S.DIGEST_FILE = os.path.join(ETC, "digest.json")
S.WL_FILE = os.path.join(ETC, "whitelist.txt")

import argparse
ok = fail = 0
def check(name, cond, extra=""):
    global ok, fail
    if cond: ok += 1; print(f"  \033[32m✓\033[0m {name}")
    else:    fail += 1; print(f"  \033[31m✗ {name}\033[0m {extra}")

def dies(fn, *a, **kw):
    try: fn(*a, **kw); return False
    except SystemExit: return True

def guard(**kw):
    d = dict(enable=False, disable=False, score=None, both_min=None, both_dl=None,
             both_ul=None, percent=None, sustain=None, penalty_mbps=None,
             penalty_min=None, hours=None, upload_gb=None, download_gb=None,
             download_gbh=None, interval=None, packet=None, require_packet=None,
             upload_ratio=None, upload_ratio_mb=None,
             volume_needs_upload=None, volume_mbps=None, quiet=True)
    d.update(kw); return argparse.Namespace(**d)

def tg(**kw):
    d = dict(action="set", at=None, token=None, chat=None, thread=None, name=None,
             proxy=None, enable=False, disable=False, events=None, daily=None,
             backup=None, backup_thread=None, backup_day=None, quiet=True)
    d.update(kw); return argparse.Namespace(**d)

print("\n\033[1m1. Регрессия: правка автоограничения стирала настройки Telegram\033[0m")
S.save_config({"ports": [443], "speed_mbps": 15, "guard": dict(S.GUARD_DEFAULT),
               "telegram": dict(S.TG_DEFAULT, token=("123456789:" + "AABBccddeeFFgghhiijjkkllmmnnoopp"),
                                chat_id="-1001234567890", enabled=True, digest_at="21:30")})
S.cmd_guard(guard(score=4))
after = json.load(open(S.CONFIG_FILE))
check("токен на месте после смены баллов",
      after.get("telegram", {}).get("token", "").startswith("123456789:"))
check("время сводки не сброшено", after.get("telegram", {}).get("digest_at") == "21:30")
check("новое значение записано", after["guard"]["score_needed"] == 4)

print("\n\033[1m2. Конфиг: чужие разделы и права\033[0m")
raw = json.load(open(S.CONFIG_FILE)); raw["future_section"] = {"x": 1}
open(S.CONFIG_FILE, "w").write(json.dumps(raw))
S.cmd_guard(guard(penalty_min=30))
check("незнакомый раздел пережил запись",
      "future_section" in json.load(open(S.CONFIG_FILE)))
check("права config.json = 600", oct(os.stat(S.CONFIG_FILE).st_mode)[-3:] == "600",
      oct(os.stat(S.CONFIG_FILE).st_mode))

print("\n\033[1m3. Валидация IP\033[0m")
for good in ("1.2.3.4", "203.0.113.10", "2001:db8::1", "::1"):
    check(f"принят {good}", S.valid_ip(good) is not None)
for bad in ("1.2.3.4; rm -rf /", "$(id)", "`id`", "999.1.1.1", "1.2.3.4/24",
            "../../etc/passwd", "", "   ", "1.2.3.4\n5.6.7.8", "0x7f000001"):
    check(f"отвергнут {bad!r}", S.valid_ip(bad) is None)
check("release с мусором не падает трассировкой",
      dies(S.cmd_release, argparse.Namespace(ip="1.2.3.4; id", all=False)))
check("whitelist add с мусором не падает трассировкой",
      dies(S.cmd_whitelist, argparse.Namespace(action="add", ip="$(touch /tmp/pwned)")))
check("файл /tmp/pwned не создан", not os.path.exists("/tmp/pwned"))

print("\n\033[1m4. Валидация портов и скорости\033[0m")
check("443,80 разобраны", S.parse_ports("443,80") == [443, 80])
for bad in ("443; rm -rf /", "-1", "99999", "443,$(id)", "port"):
    check(f"порт {bad!r} отвергнут", dies(S.parse_ports, bad))
check("дубликаты схлопнуты", S.parse_ports("443,443,80") == [443, 80])
for bad in (float("nan"), float("inf"), -1.0, 1e9):
    check(f"скорость {bad} отвергнута",
          dies(S.cmd_apply, argparse.Namespace(ports=None, speed=bad, quiet=True)))

print("\n\033[1m5. Валидация Telegram\033[0m")
for bad in ("abc", "123:short", "123456789:aa/../../botOTHER", "токен",
            "123456789:AABB ccdd", "123456789:AA\nBB"):
    check(f"токен {bad!r} отвергнут", dies(S.cmd_telegram, tg(token=bad)))
check("нормальный токен принят",
      not dies(S.cmd_telegram, tg(token=("987654321:" + "AABBccddeeFFgghhiijjkkllmmnnoopp"))))
for bad in ("chat; id", "abc", "@x"):
    check(f"chat_id {bad!r} отвергнут", dies(S.cmd_telegram, tg(chat=bad)))
check("chat_id -100... принят", not dies(S.cmd_telegram, tg(chat="-1001234567890")))
for bad in ("2; id", "-5", "abc"):
    check(f"тема {bad!r} отвергнута", dies(S.cmd_telegram, tg(thread=bad)))
for bad in ("socks5://", "socks5://host:99999", "https://t.me/proxy?secret=ee11",
            "javascript:alert(1)", "socks4://1.2.3.4:1080"):
    check(f"прокси {bad!r} отвергнут", dies(S.cmd_telegram, tg(proxy=bad)))
check("socks5://127.0.0.1:1080 принят",
      not dies(S.cmd_telegram, tg(proxy="socks5://127.0.0.1:1080")))
for bad in ("25:00", "9", "abc", "-1:00", "12:99"):
    check(f"время {bad!r} отвергнуто", dies(S.cmd_telegram, tg(at=bad)))
check("21:07 принято", not dies(S.cmd_telegram, tg(at="21:07")))
check("подпись длиной 200 символов отвергнута", dies(S.cmd_telegram, tg(name="x" * 200)))

print("\n\033[1m6. Утечка токена и HTML в сообщениях\033[0m")
tok = ("123456789:" + "AABBccddeeFFgghhiijjkkllmmnnoopp")
leak = f"<urlopen error https://api.telegram.org/bot{tok}/sendMessage failed>"
check("токен вычищен из текста ошибки", tok not in S.scrub(leak, {"telegram": {"token": tok}}))
check("токен вычищен и без знания конфига", tok not in S.scrub(leak))
check("подпись ноды экранируется",
      S.node_label({"node_name": "<b>RU</b> & Co"}) == "&lt;b&gt;RU&lt;/b&gt; &amp; Co")

print("\n\033[1m7. Повреждённые файлы состояния\033[0m")
for junk in ('{"1.2.3.4": {"until": "завтра", "mbps": 1}}',
             '[1,2,3]', 'не json вовсе', '{"$(id)": {"until": 99999999999, "mbps": 1}}',
             '{"1.2.3.4": {"until": 99999999999}}'):
    open(S.PEN_FILE, "w").write(junk)
    try:
        S.load_penalties(); good = True
    except Exception as e:
        good = False; err = e
    check(f"штрафы: пережит мусор {junk[:28]!r}", good)
open(S.PEN_FILE, "w").write(json.dumps(
    {"1.2.3.4": {"until": time.time() + 600, "mbps": 1, "since": time.time()}}))
check("живой штраф прочитан", "1.2.3.4" in S.load_penalties())

print("\n\033[1m8. Внешние команды выполняются без оболочки\033[0m")
S.map_dump("config_map; touch /tmp/injected")
check("подставленное имя карты не выполнилось", not os.path.exists("/tmp/injected"))
out, rc = S.run(["echo", "$(id)", "&&", "touch", "/tmp/injected2"])
check("метасимволы переданы как текст", out == "$(id) && touch /tmp/injected2")
check("файл /tmp/injected2 не создан", not os.path.exists("/tmp/injected2"))

print("\n\033[1m9. Сводка: расписание\033[0m")
S.digest_stash("2026-08-12", {"1.1.1.1": {"down": 9e10, "up": 2e9, "active": 3600}})
sent = []
S.tg_send = lambda text, cfg=None, force=False: (sent.append(text), (True, "ok"))[1]
cfg = {"telegram": {"enabled": True, "daily": True, "digest_at": "09:00", "node_name": "n"}}
base = time.mktime(time.strptime("2026-08-13", "%Y-%m-%d"))
real_time = time.time
for label, now in (("00:10", base + 600), ("08:59", base + 8 * 3600 + 3540),
                   ("09:00", base + 9 * 3600), ("09:00 повтор", base + 9 * 3600 + 30)):
    S.time.time = lambda n=now: n
    S.digest_due(cfg)
    check(f"{label}: отправлено {len(sent)}",
          len(sent) == (0 if label in ("00:10", "08:59") else 1))
S.time.time = real_time

print("\n\033[1m10. Расчёт задержки в ядре (модель eBPF)\033[0m")
def edt(limit_mbps, packets, flows=1, horizon_ns=2_000_000_000):
    """Повторяет арифметику process_packet: EDT на скачивание."""
    rate = int(limit_mbps * 125_000)
    dep = [0] * flows
    now, passed, dropped = 0, 0, 0
    for i, size in enumerate(packets):
        f = i % flows
        d = max(max(dep), now)
        delay = size * 1_000_000_000 // rate
        d += delay
        if d - now > horizon_ns:
            dropped += 1
            continue
        for k in range(flows):
            dep[k] = d
        passed += size
    span = max(dep) / 1e9 or 1e-9
    return passed * 8 / 1e6 / span, dropped

for flows in (1, 4, 64):
    mbps, drop = edt(10, [1500] * 4000, flows=flows)
    check(f"{flows:>2} потоков: {mbps:.2f} Мбит/с при лимите 10", 9.0 <= mbps <= 11.0,
          f"получено {mbps:.2f}")

print("\n\033[1mКрупные пакеты вверх как обязательное условие\033[0m")
# Смысл всей затеи: порог отдачи можно опустить до единиц процентов, только
# если подтверждения через него не проходят. Отличает их размер пакета —
# он один не зависит от скорости канала.

CAP = 50.0


def gate(sample, guard):
    """Повторяет условие из cmd_watch: два направления плюс размер пакета."""
    dl_floor = CAP * guard["both_dl_percent"] / 100
    ul_floor = CAP * guard["both_ul_percent"] / 100
    both = sample["dl"] >= dl_floor and sample["ul"] >= ul_floor
    if guard.get("require_packet") and sample["up_pkt"] < guard["packet_bytes"]:
        both = False
    return both


g_off = dict(S.GUARD_DEFAULT, enabled=True, both_ul_percent=3, require_packet=False)
g_on = dict(S.GUARD_DEFAULT, enabled=True, both_ul_percent=3, require_packet=True)

# Подтверждения при 37.9 Мбит/с скачивания: около двух мегабит, пакет ~140 байт.
ack = {"dl": 37.9, "ul": 1.9, "up_pkt": 140}
# Раздача: тот же объём вниз, но вверх идут данные.
seed = {"dl": 37.9, "ul": 4.6, "up_pkt": 1280}

check("без признака подтверждения открывают шлюз", gate(ack, g_off) is True)
check("с признаком подтверждения шлюз не открывают", gate(ack, g_on) is False)
check("раздача проходит и с признаком", gate(seed, g_on) is True)
check("раздача проходит и без него", gate(seed, g_off) is True)

# На быстрой ноде подтверждений больше — ради этого случая всё и делалось.
CAP = 100.0
fast_ack = {"dl": 88.6, "ul": 4.2, "up_pkt": 150}
check("на быстрой ноде подтверждений хватает на 3% порога",
      gate(fast_ack, g_off) is True)
check("но признак их всё равно отсекает", gate(fast_ack, g_on) is False)
CAP = 50.0

# Пограничные значения размера пакета.
check("пакет ровно на пороге проходит",
      gate({"dl": 30, "ul": 2, "up_pkt": 600}, g_on) is True)
check("пакет на байт меньше не проходит",
      gate({"dl": 30, "ul": 2, "up_pkt": 599}, g_on) is False)
check("нулевой пакет не проходит",
      gate({"dl": 30, "ul": 2, "up_pkt": 0}, g_on) is False)

# Признак не подменяет собой двусторонность.
check("крупные пакеты без скачивания шлюз не открывают",
      gate({"dl": 1, "ul": 5, "up_pkt": 1400}, g_on) is False)
check("крупные пакеты без отдачи шлюз не открывают",
      gate({"dl": 40, "ul": 0.1, "up_pkt": 1400}, g_on) is False)

print("\n\033[1mНастройка порога отдачи\033[0m")
S.save_config({"speed_mbps": 50, "ports": [443], "guard": dict(S.GUARD_DEFAULT)})
check("три процента принимаются", not dies(S.cmd_guard, guard(both_ul=3)))
check("и записались", S.load_config()["guard"]["both_ul_percent"] == 3)
check("один процент принимается", not dies(S.cmd_guard, guard(both_ul=1)))
check("ноль отвергается", dies(S.cmd_guard, guard(both_ul=0)))
check("больше ста отвергается", dies(S.cmd_guard, guard(both_ul=101)))

S.cmd_guard(guard(require_packet="on"))
check("признак включается", S.load_config()["guard"]["require_packet"] is True)
S.cmd_guard(guard(require_packet="off"))
check("и выключается", S.load_config()["guard"]["require_packet"] is False)
check("по умолчанию выключен", S.GUARD_DEFAULT["require_packet"] is False)
check("входит в отпечаток настроек",
      "require_packet" not in S.GUARD_HASH_SKIP)

print("\n\033[1mСтроки помощи не роняют argparse\033[0m")
# Одинокий знак процента в help ронял `guard --help` с ValueError: argparse
# прогоняет строки через %-форматирование.
import argparse as _ap
_parser = S.build_parser()
_bad = [k for k, v in S.MSG["ru"].items() if k.startswith("h_") and "%" in v]
check("в русских строках помощи нет голого процента", not _bad, str(_bad))
_bad_en = [k for k, v in S.MSG["en"].items() if k.startswith("h_") and "%" in v]
check("в английских тоже", not _bad_en, str(_bad_en))
import contextlib as _ctx
import io as _io
_out = _io.StringIO()
try:
    with _ctx.redirect_stdout(_out):
        _parser.parse_args(["guard", "--help"])
except SystemExit:
    check("guard --help отрабатывает", "--require-packet" in _out.getvalue())
except Exception as exc:
    check("guard --help отрабатывает", False, repr(exc))

print("\n\033[1mПереключатели Telegram видны на экране\033[0m")
# Выключённые «события» молчат: штраф выдан, ограничение стоит, а сообщения
# нет. На экране настроек этого переключателя не было вообще, и «почему не
# приходит» превращалось в угадайку. Тот же класс ошибки, что и с признаком
# отношения: настройка есть, влияет, а увидеть её негде.
import contextlib as _cx2


def _tg_show(**kw):
    S.save_config({"telegram": dict(S.TG_DEFAULT, enabled=True,
                                    token="1:aa", chat_id="-100", **kw)})
    buf = _io.StringIO()
    with _cx2.redirect_stdout(buf):
        S.cmd_telegram(argparse.Namespace(action="show"))
    return buf.getvalue()


_off = _tg_show(events=False)
_on = _tg_show(events=True)
check("выключенные события видны", S.t("tg_ev") in _off, _off)
check("и объяснено, чем это грозит", S.t("tg_ev_off_hint") in _off, _off)
check("включённые события тоже показаны", S.t("tg_ev") in _on)
check("при включённых предупреждения нет", S.t("tg_ev_off_hint") not in _on, _on)
check("сводка показана", S.t("tg_dg") in _on, _on)
check("подписи переведены на оба языка",
      S.MSG["ru"]["tg_ev"] != S.MSG["en"]["tg_ev"]
      and S.MSG["ru"]["tg_dg"] != S.MSG["en"]["tg_dg"])

# Сама причина молчания: без events сообщение не отправляется вовсе.
_sent = []
_real_send = S.tg_send
S.tg_send = lambda text, cfg=None, force=False: (_sent.append(text), (True, "ok"))[1]
S.tg_penalty({"telegram": dict(S.TG_DEFAULT, enabled=True, events=False)},
             "1.2.3.4", 1, 60, ["ratio"])
check("без events сообщение о штрафе не уходит", _sent == [], _sent)
S.tg_penalty({"telegram": dict(S.TG_DEFAULT, enabled=True, events=True)},
             "1.2.3.4", 1, 60, ["ratio"])
check("с events уходит", len(_sent) == 1, _sent)
check("и причина в тексте человеческая",
      _sent and S.t("why_ratio") in _sent[0], _sent)
S.tg_send = _real_send

print("\n\033[1mКарточка нарушителя в сообщении\033[0m")
# Сообщение о штрафе должно давать хоть что-то, за что можно зацепиться в
# панели. Номер там есть почти всегда — он приходит вместе со списком
# соединений, до всякого запроса карточки. Раньше он молча терялся.
_tg = dict(S.TG_DEFAULT, node_name="Erebor")


def _card(subject):
    return "\n".join(S.offender_card(_tg, subject, "x"))


check("имя и telegram — ссылка на человека",
      "tg://user?id=637181482" in _card({"label": "Bashou",
                                         "telegram_id": "637181482"}))
check("только имя — имя на месте, ссылки нет",
      "Bashou" in _card({"label": "Bashou"})
      and "tg://user" not in _card({"label": "Bashou"}),
      _card({"label": "Bashou"}))
check("только telegram", "637181482" in _card({"telegram_id": 637181482}))
check("логин панели копируется касанием",
      "<code>user_741</code>" in _card({"username": "user_741"}),
      _card({"username": "user_741"}))
check("только номер в панели не теряется",
      "741" in _card({"user_id": "741"}), _card({"user_id": "741"}))
check("пусто — сказано, что личность неизвестна",
      S.t("pn_card_unknown") in _card({}), _card({}))
check("нет владельца — то же самое",
      S.t("pn_card_unknown") in _card(None), _card(None))

# owners.json правят руками, и туда попадает что угодно. Раньше нечисловой
# идентификатор ронял int() и сообщение о штрафе не уходило вообще.
for junk in ("не число", "", None, "12 34", "id42"):
    try:
        _out = _card({"label": "Кто-то", "telegram_id": junk})
        _fine = "Кто-то" in _out and "tg://user" not in _out
    except Exception as exc:
        _fine = False
        _out = repr(exc)
    check(f"мусор в telegram_id не роняет отправку: {junk!r}", _fine, _out)
check("отрицательный telegram_id принимается",
      "tg://user?id=-100" in _card({"label": "Кто-то", "telegram_id": "-100"}))
check("имя экранируется", "&lt;b&gt;" in _card({"label": "<b>x</b>"}))
check("логин экранируется", "&lt;b&gt;" in _card({"username": "<b>x</b>"}))

print("\n\033[1mРаспределение отношения отдачи\033[0m")
# Порог между честным и раздающим не выводится из теории — он виден как разрыв
# в распределении. Данные ниже сняты с двух живых нод: на первой честные
# кончаются на 26%, раздающие начинаются с 46%, между ними пусто. Ровно этот
# разрыв отчёт и обязан показывать.
_MB, _GB = 1e6, 1e9
NODE1 = {
    "178.178.197.245": {"down": 7.6 * _GB, "up": 113.8 * _MB},
    "95.167.210.34":   {"down": 6.5 * _GB, "up": 1.1 * _GB},
    "80.115.192.57":   {"down": 2.0 * _GB, "up": 205 * _MB},
    "94.77.22.209":    {"down": 1.8 * _GB, "up": 251.5 * _MB},
    "188.66.34.198":   {"down": 1.1 * _GB, "up": 280.5 * _MB},
    "95.26.73.25":     {"down": 1.1 * _GB, "up": 500.5 * _MB},
    "176.59.54.33":    {"down": 1014.7 * _MB, "up": 489.1 * _MB},
    "95.32.199.197":   {"down": 857.2 * _MB, "up": 756.3 * _MB},
    "шум":             {"down": 10 * _MB, "up": 8 * _MB},
}
_rows, _counts = S.ratio_report(NODE1, 100 * _MB, 35)
check("шум с мелкой отдачей отсеян", len(_rows) == 8, len(_rows))
check("верхний — раздающий с 88 процентами",
      _rows[0][0] == "95.32.199.197", _rows[0][0])
check("порядок по убыванию отношения",
      [r[0] for r in _rows[:3]] == ["95.32.199.197", "176.59.54.33", "95.26.73.25"],
      [r[0] for r in _rows[:3]])

_bucket = dict(zip(["0-10", "10-20", "20-30", "30-40", "40-50", "50-75",
                    "75-100", "100+"], _counts))
check("корзина 30-40 пуста — это и есть разрыв", _bucket["30-40"] == 0, _bucket)
check("двое в корзине 40-50", _bucket["40-50"] == 2, _bucket)
check("один в корзине 75-100", _bucket["75-100"] == 1, _bucket)
check("сумма по корзинам сходится с числом адресов",
      sum(_counts) == len(_rows), (sum(_counts), len(_rows)))

# Вторая нода была чистой: там никого выше 22%.
NODE2 = {
    "188.162.143.41": {"down": 3.3 * _GB, "up": 99.2 * _MB},
    "85.26.234.65":   {"down": 2.3 * _GB, "up": 281.1 * _MB},
    "92.36.126.226":  {"down": 1.6 * _GB, "up": 254.2 * _MB},
    "95.167.210.34":  {"down": 1.2 * _GB, "up": 258 * _MB},
    "95.27.163.73":   {"down": 1.0 * _GB, "up": 167 * _MB},
}
_rows2, _counts2 = S.ratio_report(NODE2, 100 * _MB, 35)
check("на чистой ноде никого выше порога",
      all(r[3] < 35 for r in _rows2), [round(r[3]) for r in _rows2])
check("и все корзины от 30 и выше пусты", sum(_counts2[3:]) == 0, _counts2)

# Отдача без скачивания не должна делить на ноль.
_rows3, _ = S.ratio_report({"x": {"down": 0, "up": 500 * _MB}}, 100 * _MB, 35)
check("отдача без скачивания не роняет отчёт", _rows3[0][3] >= 1e8, _rows3)

_src_mon = _io.open(os.path.join(SRC, "shaperctl.py"), encoding="utf-8").read()
check("отчёт доступен ключом --ratio", '"--ratio"' in _src_mon)
check("порог в пресете опущен до 35",
      "--upload-ratio 35" in _io.open(os.path.join(SRC, "menu.sh"),
                                      encoding="utf-8").read())

print("\n\033[1mКолонка объёма в мониторе\033[0m")
# В мониторе видно только скорость. «Сейчас 0.1» у того, кто за сутки вынес
# двадцать гигабайт, и у того, кто зашёл на минуту, выглядит одинаково —
# отличить их без накопленного объёма нельзя.
_mon = _io.StringIO()
_src = _io.open(os.path.join(SRC, "shaperctl.py"), encoding="utf-8").read()
check("колонка объёма есть в шапке", "t('mon_total')" in _src)
check("значение берётся из карт, а не считается заново",
      'c.get("down", 0) + c.get("up", 0)' in _src)
check("объём показывается человекочитаемо", "fmt_bytes(vol)" in _src)
check("у колонки есть пояснение внизу", "mon_leg_total" in _src)
check("подпись переведена на оба языка",
      S.MSG["ru"]["mon_total"] != S.MSG["en"]["mon_total"])

# Ширина линейки должна расти вместе с колонками, иначе таблица разъедется.
_w = re.search(r"^    width = (\d+)$", _src, re.M)
check("ширина монитора задана одним числом", _w is not None)
check("и она увеличена под новую колонку", _w and int(_w.group(1)) >= 86,
      _w.group(1) if _w else "—")

print("\n\033[1mОтношение отдачи к скачиванию за сутки\033[0m")
# Цифры взяты из живой статистики ноды на 6143 адреса. Порог обязан разделять
# именно их, а не абстрактные примеры: между честными и раздающими там разрыв
# от 21% до 59%, и подгонять правило под середину этого разрыва — не то же
# самое, что придумать число.
MB = 1e6
RATIO_G = dict(S.GUARD_DEFAULT, upload_ratio_percent=50, upload_ratio_min_mb=300)


def verdict(down_mb, up_mb, g=RATIO_G, ul=0.5):
    """ul — отдача прямо сейчас: сидер отдаёт, отвалившийся нет."""
    daily = {"x": {"active": 0, "up": up_mb * MB, "down": down_mb * MB}}
    score, why = S.evaluate("x", {"dl": 0, "ul": ul, "up_pkt": 0}, g, 10, 0, 0,
                            daily)
    return why


check("сидер 379↓/916↑ пойман", verdict(379.4, 916.3) == ["ratio"])
check("сидер 785↓/461↑ пойман", verdict(785.4, 460.9) == ["ratio"])
check("честный 1000↓/213↑ не тронут", verdict(1000, 213) == [])
check("честный 1200↓/204↑ не тронут", verdict(1200, 204.2) == [])
check("честный 2200↓/371↑ не тронут", verdict(2200, 370.9) == [])
check("мелочь 10↓/8↑ не тронута, хотя отношение 80%", verdict(10, 8) == [])
check("отдача без скачивания — это тоже перекос", verdict(0, 500) == ["ratio"])
check("ровно на пороге ловится", verdict(1000, 500) == ["ratio"])
check("чуть ниже порога — нет", verdict(1000, 499) == [])
check("ровно на нижней границе объёма ловится", verdict(100, 300) == ["ratio"])
check("на грамм меньше — нет", verdict(100, 299.9) == [])

check("по умолчанию признак выключен",
      S.GUARD_DEFAULT["upload_ratio_percent"] == 0)
check("и с умолчаниями сидер проходит мимо",
      verdict(379.4, 916.3, S.GUARD_DEFAULT) == [])
check("вес признака хватает на штраф в одиночку",
      S.SIGNAL_WEIGHTS["ratio"] >= S.GUARD_DEFAULT["score_needed"])

# Карта ядра — LRU: адрес, который качал утром и отвалился в обед, лежит в
# ней до полуночи вместе со своими суточными цифрами. Признак смотрел на них
# и выдавал штраф адресу, за которым уже никого нет: панель такого не знает
# («кто это — неизвестно»), толку ноль, а если адрес переназначили — страдает
# посторонний. Живой сидер отдаёт непрерывно, отвалившийся не отдаёт ничего.
check("отвалившийся адрес не наказывается",
      verdict(379.4, 916.3, ul=0) == [], verdict(379.4, 916.3, ul=0))
check("еле слышная отдача — тоже не он",
      verdict(379.4, 916.3, ul=S.RATIO_LIVE_MBPS / 2) == [])
check("ровно на пороге живости — уже он",
      verdict(379.4, 916.3, ul=S.RATIO_LIVE_MBPS) == ["ratio"])
check("порог живости низкий: сидер под штрафом отдаёт около мегабита",
      S.RATIO_LIVE_MBPS <= 0.1, S.RATIO_LIVE_MBPS)

# Путь должен быть независимым: тихий сидер не набирает двустороннего счётчика
# никогда, и если признак спрятать за обязательное условие, он не сработает.
daily = {"x": {"active": 0, "up": 916.3 * MB, "down": 379.4 * MB}}
score, why = S.evaluate("x", {"dl": 0, "ul": 0.5, "up_pkt": 0}, RATIO_G, 10,
                        0, 0, daily)
check("работает при нулевом двустороннем счётчике", why == ["ratio"], why)
check("у причины есть человекочитаемое название",
      S.t("why_ratio") != "why_ratio")

print("\n\033[1mЦифры в сообщении о штрафе\033[0m")
# «Отдал непропорционально много» не отвечает на вопрос, за что человека
# ограничили: торрент это или он залил бэкап в облако. Ответ дают три числа,
# и все три у сторожа на руках в момент штрафа.
GiB = 1024 ** 3


def figures(down_gb, up_gb, pkt=None):
    day = {"down": down_gb * GiB, "up": up_gb * GiB}
    if pkt:
        day["upkts"] = int(up_gb * GiB / pkt)
        day["upkb"] = up_gb * GiB
    return S.penalty_figures(day)


seeder = figures(2.1, 3.4, 1310)
check("объёмы за сутки на месте", "2.1" in seeder and "3.4" in seeder, seeder)
check("пропорция посчитана", "162%" in seeder, seeder)
check("размер пакета показан", "1310" in seeder, seeder)

# Тот же вопрос, другой ответ: сорок гигабайт вниз и подтверждения вверх —
# это закачка, а не раздача. По одной пропорции этого было не понять.
game = figures(40, 0.4, 150)
check("у закачки пропорция мизерная", "1%" in game, game)
check("и пакет короткий", "150" in game, game)

check("без данных строки нет", S.penalty_figures(None) == ""
      and S.penalty_figures({}) == "")
check("пустые счётчики — тоже нет",
      S.penalty_figures({"down": 0, "up": 0}) == "")
check("без скачивания пропорцию не считаем, а не делим на ноль",
      "%" not in figures(0, 1.5), figures(0, 1.5))
check("без счётчика пакетов строка всё равно собирается",
      figures(2.1, 3.4) == "↓ 2.1 " + S.t("units")[3] + " · ↑ 3.4 "
      + S.t("units")[3] + " (162%)", figures(2.1, 3.4))

# Живой случай: «пакет вверх 168750 Б» при физическом максимуме в полторы
# тысячи. Байты брались из d["up"], где после обновления лежал весь день, а
# пакеты начали считаться только что. Два счётчика обязаны расти вместе.
check("байты для среднего берутся из своего счётчика, а не из суточного",
      S.penalty_figures({"down": 411e6, "up": 580.8e6,
                         "upkts": 3612, "upkb": 0}).count("·") == 1,
      S.penalty_figures({"down": 411e6, "up": 580.8e6,
                         "upkts": 3612, "upkb": 0}))
check("невозможное среднее не печатается",
      "168" not in S.penalty_figures({"down": 411e6, "up": 580.8e6,
                                      "upkts": 3612, "upkb": 580.8e6}))
check("а возможное — печатается",
      "1452" in S.penalty_figures({"down": 411e6, "up": 580.8e6,
                                   "upkts": 400000, "upkb": 580.8e6}))
check("потолок — джамбо-кадр", S.MAX_PACKET_BYTES == 9000)

# Средний пакет обязан считаться за сутки, а не по последнему замеру: в
# момент штрафа адрес мог как раз молчать вверх, и вышло бы «0 Б».
check("замер отдаёт число пакетов, а не только средний размер",
      "up_pkts" in S.traffic_sample(
          {"x": {"down": 0, "up": 0, "up_pkts": 0}},
          {"x": {"down": 100, "up": 1300, "up_pkts": 1}}, 1.0)["x"])

print("\n\033[1mПовторные уведомления об одном адресе\033[0m")
# Живой случай: шесть сообщений про один и тот же перекос отдачи за вечер.
# Штраф снимается через час, суточные счётчики за этот час не меняются — и
# всё повторяется до полуночи.
seen = {}
T0 = 1_000_000.0
check("в первый раз рассказываем",
      S.notify_due(seen, "1.2.3.4", ["ratio"], T0) is True)
check("через минуту — молчим",
      S.notify_due(seen, "1.2.3.4", ["ratio"], T0 + 60) is False)
check("через час, когда штраф снялся, — всё ещё молчим",
      S.notify_due(seen, "1.2.3.4", ["ratio"], T0 + 3600) is False)
check("через шесть часов — напоминаем",
      S.notify_due(seen, "1.2.3.4", ["ratio"], T0 + S.GUARD_NOTIFY_COOLDOWN)
      is True)
check("кулдаун ровно шесть часов",
      S.GUARD_NOTIFY_COOLDOWN == 6 * 3600, S.GUARD_NOTIFY_COOLDOWN)

# Другая причина — это новость, и она не должна ждать шести часов.
seen2 = {}
S.notify_due(seen2, "1.2.3.4", ["ratio"], T0)
check("та же причина в другом порядке — та же причина",
      S.notify_due(seen2, "1.2.3.4", ["ratio"], T0 + 60) is False)
check("новая причина проходит сразу",
      S.notify_due(seen2, "1.2.3.4", ["packet", "peak"], T0 + 60) is True)
check("порядок причин не создаёт новости",
      S.notify_due(seen2, "1.2.3.4", ["peak", "packet"], T0 + 120) is False)
check("другой адрес не задет",
      S.notify_due(seen2, "5.6.7.8", ["ratio"], T0 + 60) is True)

# Карта не должна расти бесконечно на ноде, которая живёт месяцами.
big = {("10.0.%d.%d" % (i // 256, i % 256)): (T0, "ratio")
       for i in range(S.NOTIFY_MAX + 10)}
S.notify_due(big, "9.9.9.9", ["ratio"], T0 + S.GUARD_NOTIFY_COOLDOWN + 1)
check("старые записи вычищаются", len(big) == 1, len(big))

print("\n\033[1mЧасовой объём против покупки в Steam\033[0m")
# Порог, заданный долей канала, срабатывает ровно через полчаса на полной
# скорости — на любом канале, потому что это и есть определение половины.
# Современная игра весит под сто двадцать гигабайт, то есть человек, честно
# купивший её, получал штраф гарантированно. Отличить закачку из магазина от
# торрента по одному объёму нельзя — только по размеру пакета вверх.
GB = 1e9
VOL_G = dict(S.GUARD_DEFAULT, download_gb_per_hour=22.5,
             volume_needs_upload=True, volume_penalty_mbps=30,
             download_gb_per_day=0)
HOUR = {"x": {0: 23 * GB}}
STEAM = {"dl": 95, "ul": 1.2, "up_pkt": 150}     # подтверждения TCP
TORRENT = {"dl": 40, "ul": 4.0, "up_pkt": 1310}  # куски данных


def hourly_verdict(sample, g=VOL_G):
    return S.evaluate("x", sample, g, 100, 0, 0, {}, HOUR)[1]


check("закачка из магазина проходит мимо", hourly_verdict(STEAM) == [],
      hourly_verdict(STEAM))
check("торрент на том же объёме пойман",
      hourly_verdict(TORRENT) == ["hourly", "packet"], hourly_verdict(TORRENT))
check("без настройки ловятся оба — как было раньше",
      hourly_verdict(STEAM, dict(VOL_G, volume_needs_upload=False)) == ["hourly"])
check("вялая отдача не считается за торрент",
      hourly_verdict({"dl": 95, "ul": 0.1, "up_pkt": 1310}) == [])
check("объёма всё ещё должно хватать",
      S.evaluate("x", TORRENT, VOL_G, 100, 0, 0, {},
                 {"x": {0: 5 * GB}})[1] == [], "сработало ниже порога")
check("по умолчанию настройка выключена",
      S.GUARD_DEFAULT["volume_needs_upload"] is False)

# Объём — единственный признак, который срабатывает и на честном поведении.
# Значит и наказание за него не может быть тем же, что за торрент.
check("за один часовой объём режем мягко",
      S.penalty_rate(VOL_G, ["hourly"]) == 30)
check("за суточный объём тоже",
      S.penalty_rate(VOL_G, ["download"]) == 30)
check("за объём с торрент-пакетами — полный штраф",
      S.penalty_rate(VOL_G, ["hourly", "packet"]) == VOL_G["penalty_mbps"])
check("за торрент без объёма — полный штраф",
      S.penalty_rate(VOL_G, ["packet", "peak"]) == VOL_G["penalty_mbps"])
check("без мягкой скорости всё как раньше",
      S.penalty_rate(dict(VOL_G, volume_penalty_mbps=0), ["hourly"])
      == VOL_G["penalty_mbps"])
check("пустая причина не выбирает мягкую скорость",
      S.penalty_rate(VOL_G, []) == VOL_G["penalty_mbps"])
check("по умолчанию мягкой скорости нет",
      S.GUARD_DEFAULT["volume_penalty_mbps"] == 0)

print("\n\033[1mГотовность к ограничению скачивания\033[0m")
# Движок расставляет время отправки, но придержать пакет умеет только fq.
# fq_codel — умолчание Debian и Ubuntu — это поле игнорирует, и скачивание
# перестаёт ограничиваться, при том что всё остальное выглядит здоровым.
# Поэтому проверяем разбор именно вывода tc, а не свои представления о нём.
import subprocess as _sp
import types as _types

_REAL_RUN = _sp.run


def _tc(output, code=0):
    def run(cmd, *a, **kw):
        if cmd[:1] == ["tc"]:
            return _types.SimpleNamespace(returncode=code, stdout=output, stderr="")
        return _REAL_RUN(cmd, *a, **kw)
    return run


MQ_FQ = """qdisc mq 0: root
qdisc fq 8001: parent :1 limit 10000p flow_limit 100p
qdisc fq 8002: parent :2 limit 10000p flow_limit 100p
qdisc clsact ffff: parent ffff:fff1
"""
# Ровно то, что пришло с живой ноды: mq с fq_codel на очередях.
MQ_CODEL = """qdisc mq 0: root
qdisc fq_codel 0: parent :2 limit 10240p flows 1024 quantum 1514
qdisc fq_codel 0: parent :1 limit 10240p flows 1024 quantum 1514
qdisc clsact ffff: parent ffff:fff1
"""
PLAIN_FQ = """qdisc fq 8001: root refcnt 2 limit 10000p flow_limit 100p
qdisc clsact ffff: parent ffff:fff1
"""
PFIFO = """qdisc pfifo_fast 0: root refcnt 2 bands 3
qdisc clsact ffff: parent ffff:fff1
"""

_sp.run = _tc(MQ_FQ)
check("mq с fq на очередях — готово", S.edt_ready("eth0") == (True, ""))
_sp.run = _tc(PLAIN_FQ)
check("одиночный fq — готово", S.edt_ready("eth0") == (True, ""))

_sp.run = _tc(MQ_CODEL)
ready, bad = S.edt_ready("eth0")
check("fq_codel на очередях распознан как беда", ready is False)
check("и назван по имени", bad == "fq_codel", bad)

_sp.run = _tc(PFIFO)
ready, bad = S.edt_ready("eth0")
check("pfifo_fast тоже не годится", ready is False)
check("и он тоже назван", bad == "pfifo_fast", bad)

# Неизвестность не повод пугать: без интерфейса и при сломанном tc молчим.
_sp.run = _tc("", code=1)
check("сломанный tc не поднимает ложную тревогу",
      S.edt_ready("eth0") == (True, ""))
_sp.run = _REAL_RUN
check("без интерфейса тоже молчим", S.edt_ready(None) == (True, ""))
check("clsact и noqueue сами по себе не беда",
      set(("clsact", "noqueue")) <= set(S.FQ_OK_KINDS))

print(f"\n\033[1mИтог: {ok} пройдено, {fail} провалено\033[0m")
sys.exit(1 if fail else 0)

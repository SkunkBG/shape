#!/usr/bin/env python3
"""Проверки после аудита Shape. Запускать из песочницы, не на ноде."""
import json, os, re, shutil, subprocess, sys, tempfile, time, importlib.util

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
    # ok — счётчик, и он глобальный. Живой случай: в одном из блоков ниже
    # написали «ok, err = ...», булево легло в счётчик, итог показал 189
    # вместо 441, и все проверки при этом были зелёными. Поэтому тип
    # сверяется на каждом шаге: молчаливая потеря счёта хуже падения.
    global ok, fail
    if not isinstance(ok, int) or isinstance(ok, bool):
        raise SystemExit("счётчик ok затёрт присваиванием — ищите «ok, ... =»")
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
             upload_ratio=None, upload_ratio_mb=None, upload_ratio_hours=None,
             volume_needs_upload=None, volume_mbps=None,
             ratio_needs_packet=None, upload_warn=None, upload_day=None,
             upload_hours=None, upload_hours_mbps=None, upload_gbh=None,
             quiet=True)
    d.update(kw); return argparse.Namespace(**d)

def tg(**kw):
    d = dict(action="set", at=None, token=None, chat=None, thread=None, name=None,
             proxy=None, enable=False, disable=False, events=None, daily=None,
             backup=None, backup_thread=None, backup_day=None, updates=None,
             quiet=True)
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
      "tg://user?id=100000003" in _card({"label": "Bashou",
                                         "telegram_id": "100000003"}))
check("только имя — имя на месте, ссылки нет",
      "Bashou" in _card({"label": "Bashou"})
      and "tg://user" not in _card({"label": "Bashou"}),
      _card({"label": "Bashou"}))
check("только telegram", "100000003" in _card({"telegram_id": 100000003}))
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
    "203.0.113.41": {"down": 7.6 * _GB, "up": 113.8 * _MB},
    "203.0.113.31":   {"down": 6.5 * _GB, "up": 1.1 * _GB},
    "203.0.113.10":   {"down": 2.0 * _GB, "up": 205 * _MB},
    "203.0.113.27":    {"down": 1.8 * _GB, "up": 251.5 * _MB},
    "203.0.113.44":   {"down": 1.1 * _GB, "up": 280.5 * _MB},
    "203.0.113.28":     {"down": 1.1 * _GB, "up": 500.5 * _MB},
    "203.0.113.37":    {"down": 1014.7 * _MB, "up": 489.1 * _MB},
    "203.0.113.30":   {"down": 857.2 * _MB, "up": 756.3 * _MB},
    "шум":             {"down": 10 * _MB, "up": 8 * _MB},
}
_rows, _counts = S.ratio_report(NODE1, 100 * _MB, 35)
check("шум с мелкой отдачей отсеян", len(_rows) == 8, len(_rows))
check("верхний — раздающий с 88 процентами",
      _rows[0][0] == "203.0.113.30", _rows[0][0])
check("порядок по убыванию отношения",
      [r[0] for r in _rows[:3]] == ["203.0.113.30", "203.0.113.37", "203.0.113.28"],
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
    "203.0.113.45": {"down": 3.3 * _GB, "up": 99.2 * _MB},
    "203.0.113.12":   {"down": 2.3 * _GB, "up": 281.1 * _MB},
    "203.0.113.26":  {"down": 1.6 * _GB, "up": 254.2 * _MB},
    "203.0.113.31":  {"down": 1.2 * _GB, "up": 258 * _MB},
    "203.0.113.29":   {"down": 1.0 * _GB, "up": 167 * _MB},
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

# ── отношение требует длительности ──────────────────────────────────────────
#
# Пропорция ловит перекос, но молчит о том, за какое время он набрался.
# Живой случай на мобильной ноде: 418.8 МБ вниз, 326.0 вверх — отношение 78%,
# доля данных ровно 55% при пороге 55, всё это за 2.1 часа. Отправленное в чат
# видео даёт ровно такую картину. Отличает раздачу длительность, и часы теперь
# считают именно отдачу данными.
RATIO_H = dict(RATIO_G, upload_ratio_min_hours=2)


def verdict_h(down_mb, up_mb, hours, g=RATIO_H):
    daily = {"x": {"active": 0, "up": up_mb * MB, "down": down_mb * MB,
                   "up_sec": hours * 3600}}
    return S.evaluate("x", {"dl": 0, "ul": 0.5, "up_pkt": 0}, g, 10, 0, 0,
                      daily)[1]


check("отправка видео: тот же перекос за полчаса — не штрафуем",
      verdict_h(418.8, 326.0, 0.5) == [])
check("раздача: тот же перекос за восемь часов — штрафуем",
      verdict_h(418.8, 326.0, 8) == ["ratio"])
check("ровно на пороге часов — штрафуем", verdict_h(418.8, 326.0, 2) == ["ratio"])
check("минутой меньше — нет", verdict_h(418.8, 326.0, 1.98) == [])
check("нулевые часы не проходят", verdict_h(418.8, 326.0, 0) == [])

# Условие необязательное: пока его не включили, поведение прежнее.
check("по умолчанию условия нет",
      S.GUARD_DEFAULT["upload_ratio_min_hours"] == 0)
check("без условия получасовой перекос ловится как раньше",
      verdict_h(418.8, 326.0, 0.5, RATIO_G) == ["ratio"])
check("отсутствие счётчика часов равно нулю часов",
      S.evaluate("x", {"dl": 0, "ul": 0.5, "up_pkt": 0}, RATIO_H, 10, 0, 0,
                 {"x": {"active": 0, "up": 916.3 * MB,
                        "down": 379.4 * MB}})[1] == [])
check("мусор в настройке не роняет проверку",
      verdict_h(418.8, 326.0, 8, dict(RATIO_G,
                                      upload_ratio_min_hours=None)) == ["ratio"])

# Настройка должна быть достижима не только из пресета.
_src_ctl = open(os.path.join(SRC, "shaperctl.py")).read()
check("флаг есть в командной строке", "--upload-ratio-hours" in _src_ctl)
check("значение видно в выводе настроек", "guard_ratio_hrs" in _src_ctl)
check("оба пресета требуют часов",
      open(os.path.join(SRC, "menu.sh")).read().count(
          "--upload-ratio-hours 2") == 2)

print("\n\033[1mРаспределение доли данных\033[0m")
# Порог отношения в 35% попал в цель потому, что мы смотрели распределение по
# шести тысячам адресов и увидели, где пусто. Порог доли в 70% поставлен по
# трём точкам из уведомлений — это гадание, и крутить его надо по тем же
# данным, а не по случайным карточкам.
BT = 3_000_000.0


def bday(up_mb, share, down_mb=1000, pkt=700):
    up = up_mb * 1e6
    return {"down": down_mb * 1e6, "up": up,
            "upkt": [up, up / pkt, 1400, up * share / 100.0, BT]}


sample = {"a": bday(500, 1), "b": bday(500, 32), "c": bday(500, 78),
          "d": bday(500, 100), "e": bday(5, 100)}
rows, counts = S.bulk_report(sample, 100 * 1e6)
check("мелочь ниже пола не считается", len(rows) == 4, rows)
check("сортировка по доле, крупнейшая сверху",
      [round(r[3]) for r in rows] == [100, 78, 32, 1], rows)
check("корзины разложены", sum(counts) == 4, counts)
check("звонок попал в третью корзину", counts[3] == 1, counts)
check("раздача — в последнюю", counts[-1] == 1, counts)

check("испорченное поле не ломает отчёт",
      len(S.bulk_report({"x": {"up": 1e9, "upkt": "мусор"}}, 0)[0]) == 0)
check("поля нет — адрес не в отчёте",
      len(S.bulk_report({"x": {"up": 1e9}}, 0)[0]) == 0)
check("пустой день не роняет", S.bulk_report({}, 0) == ([], [0] * 10)
      or S.bulk_report(None, 0)[0] == [])
check("корзин столько же, сколько границ, плюс хвост",
      len(counts) == len(S.BULK_BUCKETS) + 1)

# Отчёт печатается целиком, включая случай «считать не из чего».
import io as _io
from contextlib import redirect_stdout
_buf = _io.StringIO()
with redirect_stdout(_buf):
    S.print_bulk_report({"guard": {"ratio_needs_packet": True}}, sample, 100)
_out = _buf.getvalue()
check("в отчёте виден текущий порог", str(S.RATIO_BULK_PERCENT) in _out, _out[:200])
check("и число адресов", "4" in _out)
_buf = _io.StringIO()
with redirect_stdout(_buf):
    S.print_bulk_report({"guard": {}}, {}, 100)
check("пустой день печатает объяснение, а не пустоту",
      S.t("bulk_none") in _buf.getvalue(), _buf.getvalue())

print("\n\033[1mОтношение отдачи против видеосвязи\033[0m")
# Живой случай, три адреса за один вечер. Непропорциональная отдача бывает не
# только у раздачи: разговор симметричен по определению, обе стороны говорят
# поровну. Штраф получали Discord, Telegram и WhatsApp.
#
# Отличает их размер пакета, но только МАКСИМАЛЬНЫЙ за сутки: кусок торрента
# всегда набивается до предела сегмента, голос пишется мелкими порциями.
T0 = 1_000_000.0          # фиксированная точка отсчёта для всех проверок
RNP_G = dict(S.GUARD_DEFAULT, upload_ratio_percent=35, upload_ratio_min_mb=300,
             ratio_needs_packet=True)
SAMPLE = {"dl": 0.2, "ul": 0.5, "up_pkt": 300}


def rnp(down, up, bulk_pct, top=1400, g=RNP_G):
    """bulk_pct — какая доля отдачи ушла крупными пакетами."""
    daily = {"x": {"active": 0, "down": down, "up": up,
                   "upkt": [up, 1, top, up * bulk_pct / 100.0, T0]}}
    return S.evaluate("x", SAMPLE, g, 100, 0, 0, daily)[1]


check("звонок 329↓/328↑ (100%), данными 0% — не трогаем",
      rnp(329.4e6, 328.1e6, 0, top=349) == [])
check("видеосвязь 1.2ГБ↓/479МБ↑ (38%), данными 0% — тоже",
      rnp(1.2e9, 478.8e6, 0, top=697) == [])
check("сидер 379↓/916↑ (242%), данными 96% — ловим",
      rnp(379e6, 916e6, 96) == ["ratio"])

# Максимума мало: его ставит одно десятисекундное окно. Отправил человек
# видео в мессенджере — и весь день его звонки проходят фильтр как раздача.
check("звонок с одним вложением: максимум 1539, но данными 1%",
      rnp(341.7e6, 347.5e6, 1.4, top=1539) == [],
      rnp(341.7e6, 347.5e6, 1.4, top=1539))

# Живые точки, по которым порог и поставлен. Видеосвязь идёт пакетами под
# тысячу, поэтому доля у неё не единицы процентов, а треть — первый порог в
# тридцать процентов она прошла с запасом в два пункта.
check("Ольга: 660% отношения, данными 100% — раздача",
      rnp(157.1e6, 1.0e9, 100, top=1384) == ["ratio"])
check("Николай: 100% отношения, данными 32% — видеозвонок",
      rnp(361.5e6, 361.5e6, 32, top=1354) == [],
      rnp(361.5e6, 361.5e6, 32, top=1354))
check("сидер с параллельным звонком всё ещё ловится",
      rnp(379e6, 916e6, 75) == ["ratio"])

# Распределение по двум нодам, 26 адресов: до 39 честные, от 66 раздача,
# между ними ни одного. Порог в 70 стоял не в середине разрыва, а вплотную к
# нижнему краю верхнего кластера — и первый же сидер похуже среднего (66% при
# отношении 392%) в него не влез.
check("порог в середине разрыва между 39 и 66",
      39 < S.RATIO_BULK_PERCENT < 66, S.RATIO_BULK_PERCENT)
check("сидер на 66% при отношении 392% ловится",
      rnp(150.6e6, 589.7e6, 66) == ["ratio"])
check("честный на 39% — нет", rnp(1.0e9, 400e6, 39) == [])
for _name, _d, _u, _b in (("203.0.113.35", 524.7e6, 454.3e6, 1),
                          ("203.0.113.8", 266.9e6, 400e6, 2),
                          ("203.0.113.43", 346.1e6, 400e6, 6)):
    check(f"звонок {_name} проходит мимо", rnp(_d, _u, _b) == [])
check("ровно на пороге доли — ловим",
      rnp(379e6, 916e6, S.RATIO_BULK_PERCENT) == ["ratio"])
check("чуть ниже — нет",
      rnp(379e6, 916e6, S.RATIO_BULK_PERCENT - 0.1) == [])
check("без настройки всё как было: звонок ловится",
      rnp(329.4e6, 328.1e6, 0, top=349, g=dict(RNP_G, ratio_needs_packet=False))
      == ["ratio"])
check("по умолчанию настройка выключена",
      S.GUARD_DEFAULT["ratio_needs_packet"] is False)

# Крупным считается пакет от 1000 байт, а не от 600 как у мгновенного
# признака: на суточном максимуме видеосвязь доходила до семисот.
check("порог крупного пакета выше мгновенного",
      S.RATIO_PACKET_BYTES > S.GUARD_DEFAULT["packet_bytes"],
      (S.RATIO_PACKET_BYTES, S.GUARD_DEFAULT["packet_bytes"]))
check("и выше живого звонка на 697", S.RATIO_PACKET_BYTES > 697)
# Живой ложный срабат: маркетолог с 621 МБ отдачи за десять часов, пропорция
# 38%, данными 85%. Порог в 35 стоял ниже всей пустоты, у самого её дна, и в
# неё провалился единственный подтверждённый невиновный. Самый низкий из
# восьми настоящих сидеров на двух нодах — 64%.
check("маркетолог на 38% проходит при пороге 50",
      rnp(1.6e9, 621.3e6, 85, g=dict(RNP_G, upload_ratio_percent=50)) == [],
      rnp(1.6e9, 621.3e6, 85, g=dict(RNP_G, upload_ratio_percent=50)))
check("он же ловился при пороге 35",
      rnp(1.6e9, 621.3e6, 85, g=dict(RNP_G, upload_ratio_percent=35))
      == ["ratio"])
# Порог по объёму отдачи в 300 МБ отсекает больше половины списка: реально
# до проверки пропорции доходят только четверо, и их отношения — 38 (ложное),
# 75, 229 и 392. Разрыв между 38 и 75, середина 56.
check("самый низкий из настоящих, 75%, при пороге 50 остаётся",
      rnp(698.2e6, 520.7e6, 77, g=dict(RNP_G, upload_ratio_percent=50))
      == ["ratio"])
check("порог стоит в разрыве между ложным 38 и настоящим 75",
      38 < 50 < 75)
check("отдача ниже 300 МБ до проверки пропорции вообще не доходит",
      rnp(235.6e6, 150.6e6, 93, g=dict(RNP_G, upload_ratio_percent=35)) == [],
      "адрес с 150 МБ отдачи не должен оцениваться")

check("порог доли оставляет запас на смешанные окна",
      40 <= S.RATIO_BULK_PERCENT <= 80, S.RATIO_BULK_PERCENT)

# Доля должна считаться от байтов ТОГО ЖЕ окна, а не от суточных: поле с
# пакетами обнуляется при смене формата, и после обновления суточный объём
# старше него.
check("доля считается от своих байтов",
      round(S.bulk_share({"upkt": [1000, 1, 1400, 700, T0]})) == 70)
check("испорченное поле — ноль, а не исключение",
      S.bulk_share({"upkt": "мусор"}) == 0
      and S.bulk_share({"upkt": [1, 2, 3]}) == 0
      and S.bulk_share({}) == 0 and S.bulk_share(None) == 0)
check("нулевая отдача не делит на ноль",
      S.bulk_share({"upkt": [0, 0, 0, 0, T0]}) == 0)
check("доля не может быть больше ста",
      S.bulk_share({"upkt": [100, 1, 1400, 500, T0]}) == 100)

# Пол, при котором максимум вообще обновляется, должен пропускать тихого
# сидера: он отдаёт полмегабита, а совсем тихий и того меньше. Со ста
# килобайт за замер он не набрал бы ни одного окна и проскочил бы мимо
# проверки, которая как раз для него и ставится.
# Поле с пакетами обнуляется при смене формата: сразу после обновления оно
# покрывает минуты, а не сутки. Подписывать такое «за сутки» — врать.
_line, _win = S.penalty_packets({"up": 1e9, "upkt": [1e9, 800000, 1400, 9.6e8,
                                                    T0 - 1080]}, T0)
check("срок окна возвращается отдельно", 1070 < _win < 1090, _win)
check("и доля в строке есть", "96" in _line, _line)
check("поля нет — строки нет", S.penalty_packets({"up": 1e9})[0] == "")
check("байтов нет — строки нет",
      S.penalty_packets({"up": 0, "upkt": [0, 0, 0, 0, T0]})[0] == "")

check("пол обновления максимума пропускает тихого сидера",
      S.UPKT_MAX_FLOOR <= 0.05 * 1e6 / 8 * 10, S.UPKT_MAX_FLOOR)
check("но не пропускает единичные пакеты", S.UPKT_MAX_FLOOR >= 10_000)

check("испорченное поле не роняет проверку",
      S.day_upkt_max({"upkt": "мусор"}) == 0
      and S.day_upkt_max({"upkt": [1, 2, 3]}) == 0
      and S.day_upkt_max({}) == 0
      and S.day_upkt_max(None) == 0)
check("а целое — читается", S.day_upkt_max({"upkt": [1, 2, 1340, 0, 0]}) == 1340)

print("\n\033[1mЦифры в сообщении о штрафе\033[0m")
# «Отдал непропорционально много» не отвечает на вопрос, за что человека
# ограничили: торрент это или он залил бэкап в облако. Ответ дают числа, и
# все они у сторожа на руках в момент штрафа.
#
# Строк две, и это принципиально: у объёмов срок — сутки, у пакетов свой,
# потому что их поле обнуляется при смене формата. Одна строка на два срока
# врала бы про один из них.
GiB = 1e9          # гигабайт десятичный: так же, как все пороги в коде


def figures(down_gb, up_gb, pkt=None, top=0, bulk=0):
    day = {"down": down_gb * GiB, "up": up_gb * GiB}
    if pkt:
        day["upkt"] = [up_gb * GiB, int(up_gb * GiB / pkt), top,
                       up_gb * GiB * bulk / 100.0, T0]
    return S.penalty_figures(day)


def packets(down_gb, up_gb, pkt=None, top=0, bulk=0):
    day = {"down": down_gb * GiB, "up": up_gb * GiB}
    if pkt:
        day["upkt"] = [up_gb * GiB, int(up_gb * GiB / pkt), top,
                       up_gb * GiB * bulk / 100.0, T0]
    return S.penalty_packets(day, T0)[0]


seeder = figures(2.1, 3.4, 1310)
check("объёмы за сутки на месте", "2.1" in seeder and "3.4" in seeder, seeder)
check("пропорция посчитана", "162%" in seeder, seeder)
check("размер пакета в строке про объёмы не смешивается",
      "1310" not in seeder, seeder)
check("а во второй строке — есть",
      "1310" in packets(2.1, 3.4, 1310, top=1400, bulk=96),
      packets(2.1, 3.4, 1310, top=1400, bulk=96))
check("и доля тоже", "96" in packets(2.1, 3.4, 1310, top=1400, bulk=96))

# Тот же вопрос, другой ответ: сорок гигабайт вниз и подтверждения вверх —
# это закачка, а не раздача. По одной пропорции этого было не понять.
game_v, game_p = figures(40, 0.4, 150), packets(40, 0.4, 150, top=200)
check("у закачки пропорция мизерная", "1%" in game_v, game_v)
check("и пакет короткий", "150" in game_p, game_p)
check("и данными почти ничего", "0%" in game_p, game_p)

check("без данных строки нет", S.penalty_figures(None) == ""
      and S.penalty_figures({}) == "")
check("пустые счётчики — тоже нет",
      S.penalty_figures({"down": 0, "up": 0}) == "")
check("без скачивания пропорцию не считаем, а не делим на ноль",
      "%" not in figures(0, 1.5), figures(0, 1.5))
check("строка объёмов не зависит от поля пакетов",
      figures(2.1, 3.4) == "↓ 2.1 " + S.t("units")[3] + " · ↑ 3.4 "
      + S.t("units")[3] + " (162%)", figures(2.1, 3.4))

# Два живых случая подряд, оба от разъехавшихся счётчиков: «168750 Б» когда
# байтов слишком много на пакет, и «11 Б» когда слишком мало. Первый раз я
# поставил только потолок — и получил вторую половину той же ошибки.
D = {"down": 305.5e6, "up": 302.5e6}


def pk(upkt):
    return S.penalty_packets(dict(D, upkt=upkt), T0)[0]


check("невозможно большое среднее не печатается",
      "168" not in pk([302.5e6, 3612, 0, 0, T0]), pk([302.5e6, 3612, 0, 0, T0]))
check("невозможно малое — тоже",
      "11 " not in pk([302.5e6, 27500000, 0, 0, T0]),
      pk([302.5e6, 27500000, 0, 0, T0]))
check("а правдоподобное печатается",
      "1315" in pk([302.5e6, 230000, 0, 0, T0]), pk([302.5e6, 230000, 0, 0, T0]))
check("границы: от подтверждения до джамбо-кадра",
      (S.MIN_PACKET_BYTES, S.MAX_PACKET_BYTES) == (40, 9000))

# Пять чисел — ОДНО поле. Половину такого поля получить нельзя, а два поля
# можно, и мы это уже проходили дважды.
check("испорченное поле не роняет строку", pk("мусор") == "")
check("поле не той длины тоже", pk([302.5e6, 230000]) == ""
      and pk([302.5e6, 230000, 0]) == "")
check("нулевое число пакетов не делит на ноль",
      "·" not in pk([1, 0, 0, 0, T0]))
check("поля нет вовсе — второй строки нет",
      S.penalty_packets(dict(D), T0)[0] == "")

# Живой случай, из-за которого максимум и появился: 1.5 ГБ вниз, 997 МБ вверх
# и «пакет вверх 109 Б». Среднее за сутки арифметическое, а мелких пакетов в
# потоке на порядок больше крупных — 440 МБ кусками по 1400 и 550 МБ
# подтверждениями по 60 дают ровно такое среднее. Ответить «отдавал ли он
# данные» по нему нельзя, а печаталось оно именно за этим.
mixed = [997.2e6, 9146788, 1340, 4.4e8, T0]
check("среднее показывает поток целиком", "109" in pk(mixed), pk(mixed))
check("максимум отвечает, доходило ли до предела сегмента",
      "1340" in pk(mixed), pk(mixed))
check("а доля — сколько этого было", "44" in pk(mixed), pk(mixed))
check("максимума нет — и строки про него нет",
      "макс" not in pk([997.2e6, 9146788, 0, 0, T0])
      and "max" not in pk([997.2e6, 9146788, 0, 0, T0]))
check("невозможный максимум не печатается",
      "99999" not in pk([1e6, 1000, 99999, 0, T0]))
check("пол по объёму мешает случайным пакетам назначить максимум",
      S.UPKT_MAX_FLOOR >= 10_000, S.UPKT_MAX_FLOOR)

# Средний пакет обязан считаться за сутки, а не по последнему замеру: в
# момент штрафа адрес мог как раз молчать вверх, и вышло бы «0 Б».
check("замер отдаёт число пакетов, а не только средний размер",
      "up_pkts" in S.traffic_sample(
          {"x": {"down": 0, "up": 0, "up_pkts": 0}},
          {"x": {"down": 100, "up": 1300, "up_pkts": 1}}, 1.0)["x"])

print("\n\033[1mЕдиницы объёма\033[0m")
# Живой случай: карточка «отдано 286.2 МБ» при пороге признака в 300 МБ.
# Выглядело ошибкой правила, но правило было право: вывод делил на 1024, а
# порог на 1000, и 286.2 · 1024² это ровно 300.1 миллиона байт.
#
# Число, по которому человек проверяет решение, обязано быть в тех же
# единицах, что и решение. Провайдер считает гигабайт миллиардом байт, и все
# пороги в коде заданы так же.
check("килобайт это тысяча байт", S.fmt_bytes(1000).startswith("1.0"))
check("999 байт остаются байтами",
      S.fmt_bytes(999) == "999.0 " + S.t("units")[0])
check("гигабайт это миллиард",
      S.fmt_bytes(1e9) == "1.0 " + S.t("units")[3], S.fmt_bytes(1e9))
check("порог в 30 ГБ показывается как 30 ГБ",
      S.fmt_bytes(30e9).startswith("30.0"), S.fmt_bytes(30e9))
check("значение чуть выше порога отдачи и выглядит выше",
      S.fmt_bytes(300_143_000).startswith("300."), S.fmt_bytes(300_143_000))
check("шаг именно тысяча, а не 1024", S.BYTE_STEP == 1000.0)

# Порог и его отображение должны сходиться: если признак сработал на 300 МБ,
# в карточке не может стоять 286. Проверка считает число обратно из строки,
# а не сверяет его с записанным в тесте: иначе тест ломается от смены порога
# и говорит «не совпало» там, где всё в порядке.
_UNITS = {"КБ": 1e3, "МБ": 1e6, "ГБ": 1e9, "ТБ": 1e12,
          "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12, "B": 1, "Б": 1}


def _bytes_back(txt):
    num, _, unit = txt.strip().partition(" ")
    return float(num) * _UNITS.get(unit.strip(), 0)


for _mb in (300, 500, 1000, 3000, S.GUARD_DEFAULT["upload_ratio_min_mb"]):
    _floor = _mb * 1e6
    _shown = S.fmt_bytes(_floor)
    check(f"порог {_mb} МБ показан без потери величины",
          abs(_bytes_back(_shown) - _floor) <= _floor * 0.01,
          f"{_shown} -> {_bytes_back(_shown):.0f}, ждали {_floor:.0f}")

print("\n\033[1mДанные живых людей в репозитории\033[0m")
# Примеры пишутся с натуры: берёшь карточку с ноды, вставляешь в README, и
# вместе с ней уезжают имя клиента, ник, номер подписки и адрес. Глазами в
# документе на сотню страниц такое не ловится. Проверка должна ловить —
# поэтому здесь проверяется сама проверка, на подложенных данных.
_pspec = importlib.util.spec_from_file_location(
    "PS", os.path.join(SRC, "tests", "privacy_scan.py"))
PS = importlib.util.module_from_spec(_pspec); _pspec.loader.exec_module(PS)

_pdir = tempfile.mkdtemp(prefix="shape-privacy-")


def planted(text, name="doc.md"):
    for old in os.listdir(_pdir):
        os.remove(os.path.join(_pdir, old))
    with open(os.path.join(_pdir, name), "w") as f:
        f.write(text)
    return PS.scan(_pdir)


# Образцы собираются из кусков: написанные целиком, они лежали бы в этом же
# файле и проверка нашла бы саму себя. Ровно та ловушка, от которой она и
# защищает — «данные ведь для дела».
_IP = "46." + "138.65." + "124"
_NICK = "@" + "Trifonova_Dasha"
_ID = "1576" + "55577"

check("настоящий адрес найден", planted(f"клиент {_IP} качает\n"))
check("и назван адресом", planted(_IP + "\n")[0][2] == "адрес")
check("документационный адрес не тревога", not planted("203.0.113.7\n"))
check("приватный адрес не тревога", not planted("10.100.0.2 и 192.168.1.1\n"))
check("резолвер не тревога", not planted("1.1.1.1 8.8.8.8 9.9.9.9\n"))

check("ник клиента найден", planted(f"👤 Мария · {_NICK}\n"))
check("и назван ником", planted(_NICK + "\n")[0][2] == "ник")
check("разрешённый ник молчит", not planted("👤 Иван · @ivan_k\n"))
check("@BotFather молчит", not planted("возьми токен у @BotFather\n"))
check("декоратор python не ник",
      not planted("@" + "contextlib.contextmanager\ndef f(): pass\n", "x.py"))
check("а в markdown строка с ника — ник",
      planted(_NICK + " держит канал\n")[0][2] == "ник")

check("telegram id найден", planted(f"🆔 Telegram: {_ID}\n"))
check("и назван идентификатором",
      planted(f"Telegram: {_ID}\n")[0][2] == "идентификатор")
check("логин панели найден", planted(f"В панели: user_{_ID}\n"))
check("ссылка tg://user найдена", planted(f'href="tg://user?id={_ID}"\n'))
check("заглушка 123456789 молчит", not planted("Telegram: 123456789\n"))
check("гигабайты в байтах — не идентификатор",
      not planted("порог 5368709120 байт\n"))

check("строка и вид беды в отчёте", planted(f"ок\nещё\n{_IP}\n")[0][1] == 3)
check("файлы не тех расширений пропускаются",
      not planted(_IP + "\n", "notes.txt"))
check("проверка не жалуется сама на себя",
      not [x for x in PS.scan(SRC) if x[0].endswith("privacy_scan.py")])
check("на самом репозитории проверка чистая", not PS.scan(SRC),
      str(PS.scan(SRC)[:3]))
shutil.rmtree(_pdir, ignore_errors=True)

print("\n\033[1mОтправка метрик наружу\033[0m")
# Ноды стоят за NAT и в странах, где WireGuard блокируют по отпечатку.
# Поэтому не сервер приходит за метриками, а нода отправляет сама обычным
# исходящим HTTPS.
check("по умолчанию отправка выключена",
      S.METRICS_DEFAULT["push_url"] == "")
check("пустой адрес — это не ошибка, а выключатель",
      S.valid_push_url("") == ("", None))
check("https принимается",
      S.valid_push_url("https://m.example.com/api/v1/import/prometheus")[1] is None)
check("простой http наружу запрещён",
      S.valid_push_url("http://m.example.com/x")[1] == "met_need_https")
check("к себе http можно", S.valid_push_url("http://127.0.0.1:8428/x")[1] is None)
check("в приватную сеть http можно",
      S.valid_push_url("http://10.100.0.2:8428/x")[1] is None)
check("localhost по имени тоже свой",
      S.valid_push_url("http://localhost:8428/x")[1] is None)
check("к публичному адресу по http нельзя",
      S.valid_push_url("http://8.8.8.8/x")[1] == "met_need_https")
for _bad in ("ftp://m.example.com/x", "не адрес", "https://", "://x"):
    check(f"«{_bad}» отвергнут", S.valid_push_url(_bad)[1] == "met_bad_url", _bad)
check("у обеих бед есть человеческий текст",
      S.t("met_bad_url") != "met_bad_url" and S.t("met_need_https") != "met_need_https")

# Секция должна доезжать до load_config и переживать запись других секций.
_saved = open(S.CONFIG_FILE).read() if os.path.exists(S.CONFIG_FILE) else None
try:
    with open(S.CONFIG_FILE, "w") as f:
        json.dump({"telegram": {"token": "keep"}}, f)
    check("секция появляется с умолчаниями",
          S.load_config()["metrics"] == S.METRICS_DEFAULT)
    S.save_config({"metrics": dict(S.METRICS_DEFAULT,
                                   push_url="https://m.example.com/i",
                                   push_token="secret-token-value")})
    _cfg = S.load_config()
    check("настройка сохраняется",
          _cfg["metrics"]["push_url"] == "https://m.example.com/i")
    check("и не стирает соседние секции",
          _cfg["telegram"]["token"] == "keep")

    # Отправка: подменяем транспорт, сеть в тестах не трогаем.
    _sent = []

    def _fake_post(url, data, proxy="", content_type="", headers=None):
        _sent.append((url, data, proxy, content_type, headers or {}))
        return 200

    _real_post = S._post
    S._post = _fake_post
    # ВАЖНО: не «ok» — так называется счётчик пройденных проверок в этом
    # файле, и присваивание сюда булева значения тихо обнуляет весь итог.
    sent_ok, err = S.metrics_push(_cfg, "shape_up{node=\"n\"} 1\n")
    check("отправка проходит", sent_ok is True, err)
    check("ушло на заданный адрес", _sent[0][0] == "https://m.example.com/i")
    check("тело — это байты", isinstance(_sent[0][1], bytes))
    check("тело не переписано", b"shape_up" in _sent[0][1])
    check("токен ушёл заголовком",
          _sent[0][4].get("Authorization") == "Bearer secret-token-value")
    check("тип содержимого текстовый", "text/plain" in _sent[0][3])

    # Без токена заголовка быть не должно — пустой Bearer это не «нет токена».
    S.save_config({"metrics": dict(S.METRICS_DEFAULT,
                                   push_url="https://m.example.com/i")})
    _sent.clear()
    S.metrics_push(S.load_config(), "x 1\n")
    check("без токена заголовка нет", "Authorization" not in _sent[0][4])

    # Выключенная отправка молчит и в сеть не лезет.
    S.save_config({"metrics": dict(S.METRICS_DEFAULT)})
    _sent.clear()
    sent_ok, err = S.metrics_push(S.load_config(), "x 1\n")
    check("выключенная отправка не отправляет",
          sent_ok is False and not _sent)
    check("и объясняет почему", err == S.t("met_push_off"), err)

    # Ошибка сети не роняет и не выносит токен в журнал.
    S.save_config({"metrics": dict(S.METRICS_DEFAULT,
                                   push_url="https://m.example.com/i",
                                   push_token="secret-token-value")})

    def _boom(*a, **kw):
        raise OSError("нет связи с secret-token-value")

    S._post = _boom
    sent_ok, err = S.metrics_push(S.load_config(), "x 1\n")
    check("сбой не роняет программу", sent_ok is False)
    check("токен в тексте ошибки замаскирован",
          "secret-token-value" not in err, err)
    S._post = _real_post
finally:
    if _saved is None:
        os.path.exists(S.CONFIG_FILE) and os.remove(S.CONFIG_FILE)
    else:
        open(S.CONFIG_FILE, "w").write(_saved)

check("токен отправки помечен как секрет",
      ("metrics", "push_token") in S.SECRET_PATHS)
check("прокси отправки тоже",
      ("metrics", "push_proxy") in S.SECRET_PATHS)
# scrub раньше знал только про токен бота, и каждый новый секрет пришлось бы
# вспоминать отдельно в каждом месте, где печатается ошибка.
check("scrub чистит любой секрет из списка",
      "abcdefgh12345" not in S.scrub("упало на abcdefgh12345",
                                     {"panel": {"token": "abcdefgh12345"}}))
check("короткое значение не маскируется целиком",
      S.scrub("ошибка 42", {"panel": {"token": "42"}}) == "ошибка 42")

_src_units = os.path.join(SRC, "systemd")
check("таймер отправки есть",
      os.path.exists(os.path.join(_src_units, "shape-push.timer")))
check("служба отправки есть",
      os.path.exists(os.path.join(_src_units, "shape-push.service")))
_unit = open(os.path.join(_src_units, "shape-push.service")).read()
check("секрета в юните нет", "Bearer" not in _unit and "http" not in _unit.lower()
      or "config.json" in _unit)
check("установщик кладёт оба файла",
      open(os.path.join(SRC, "install.sh")).read().count("shape-push") == 2)
check("удаление их убирает",
      open(os.path.join(SRC, "uninstall.sh")).read().count("shape-push") >= 3)
_timer = open(os.path.join(_src_units, "shape-push.timer")).read()
check("у таймера есть разброс: 28 нод не должны приходить в одну секунду",
      "RandomizedDelaySec" in _timer)

print("\n\033[1mКолонка «данными» в мониторе\033[0m")
# Мгновенный размер пакета говорит про «сейчас» и скачет: отправил человек
# вложение — и на десять секунд в колонке тысяча. Доля за сутки скачков не
# знает, и по ней видно поведение, а не момент.
def _day(total, bulk_pct):
    return {"upkt": [total, total / 900, 1800, total * bulk_pct / 100,
                     time.time() - 3600]}


check("нет записи — прочерк", S.bulk_cell(None)[0] == "—")
check("пустая запись — прочерк", S.bulk_cell({})[0] == "—")
check("нулевая отдача — прочерк, а не ноль процентов",
      S.bulk_cell(_day(0, 0))[0] == "—", S.bulk_cell(_day(0, 0))[0])
check("испорченное поле — прочерк", S.bulk_cell({"upkt": [1, 2]})[0] == "—")
check("подтверждения показаны как 1%", S.bulk_cell(_day(26.9e6, 1))[0] == "1%")
check("раздача показана как 95%", S.bulk_cell(_day(335e6, 95))[0] == "95%")
check("доля не может превысить сто",
      S.bulk_cell({"upkt": [100, 1, 1800, 500, time.time()]})[0] == "100%")

check("ниже порога сторожа — серым",
      S.bulk_cell(_day(1e6, 54))[1] == S.C["gry"])
check("ровно на пороге — жёлтым",
      S.bulk_cell(_day(1e6, S.RATIO_BULK_PERCENT))[1] == S.C["byel"])
check("совсем высокая доля — красным",
      S.bulk_cell(_day(1e6, S.BULK_LOUD_PERCENT))[1] == S.C["bred"])
check("громкий порог выше порога сторожа",
      S.BULK_LOUD_PERCENT > S.RATIO_BULK_PERCENT)

# Заголовок и строка собираются двумя разными f-строками. Колонку легко
# добавить в одну и забыть в другой — таблица разъедется, а синтаксис
# промолчит. Сверяем ширины полей одну за одной.
_mon = re.search(r"def cmd_monitor.*?\n(?=\ndef )", _src_ctl2 := open(
    os.path.join(SRC, "shaperctl.py")).read(), re.S).group(0)
_head = re.search(r'out\.append\(f"\{C\[.gry.\]\}   \{.IP.*?\)\n', _mon, re.S)
_row = re.search(r'out\.append\(f" \{mark\} \{ip.*?\)\n', _mon, re.S)
check("заголовок таблицы найден", _head is not None)
check("строка таблицы найдена", _row is not None)
if _head and _row:
    _hw = re.findall(r"[<>](\d+)", _head.group(0))
    _rw = re.findall(r"[<>](\d+)", _row.group(0))
    check("колонок в заголовке и в строке поровну",
          len(_hw) == len(_rw), f"{_hw} против {_rw}")
    check("ширины колонок совпадают", _hw == _rw, f"{_hw} против {_rw}")
    check("колонка «данными» есть в заголовке", "mon_bulk" in _head.group(0))
    check("и заполняется в строке", "bulk_txt" in _row.group(0))
    _sum = sum(int(x) for x in _rw)
    _wid = int(re.search(r"width = (\d+)", _mon).group(1))
    check("разделитель не короче колонок", _wid >= _sum, f"{_wid} < {_sum}")

check("у колонки есть подпись под таблицей",
      "mon_leg_bulk" in _mon and S.t("mon_leg_bulk", n=55) != "mon_leg_bulk")
check("суточные счётчики монитор перечитывает, а не читает раз",
      _mon.count("load_daily()") == 2, _mon.count("load_daily()"))

print("\n\033[1mПовторный штраф за суточный признак\033[0m")
# Живой случай: человек снимает ограничение из меню, и через десять секунд оно
# возвращается. Суточный счётчик не уменьшается никогда, поэтому признак
# срабатывал заново до самой полуночи. Для часовых окон это уже было решено
# очисткой окна (hourly.pop) — суточные пропустили.
RG = dict(S.GUARD_DEFAULT, upload_ratio_percent=50, upload_ratio_min_mb=300)
RGD = dict(RG, download_gb_per_day=2)      # плюс суточное скачивание
RGU = dict(RG, upload_day_gb=1)            # плюс суточная отдача


def day_of(up_mb=900, down_mb=300, pen=None):
    d = {"active": 0, "up": up_mb * MB, "down": down_mb * MB, "up_sec": 9 * 3600}
    if pen is not None:
        d["pen"] = pen
    return d


def why_of(day, g=RG):
    return S.evaluate("x", {"dl": 0, "ul": 0.5, "up_pkt": 0}, g, 10, 0, 0,
                      {"x": day})[1]


check("без отметки признак работает как раньше",
      why_of(day_of()) == ["ratio"])
check("сразу после штрафа тот же признак молчит",
      why_of(day_of(pen={"ratio": 900 * MB})) == [])
check("вырос на десятую — всё ещё молчит",
      why_of(day_of(up_mb=990, pen={"ratio": 900 * MB})) == [])
check("вырос на четверть — штраф возвращается",
      why_of(day_of(up_mb=1125, pen={"ratio": 900 * MB})) == ["ratio"])
check("отметка одного признака не глушит другой",
      why_of(day_of(up_mb=1200, down_mb=2500,
                    pen={"ratio": 1200 * MB}), RGD) == ["download"])
check("суточный объём отдачи тоже не повторяется",
      why_of(day_of(up_mb=1200, down_mb=100,
                    pen={"ratio": 1200 * MB,
                         "upload_day": 1200 * MB}), RGU) == [])
check("а без отметки — срабатывает",
      why_of(day_of(up_mb=1200, down_mb=100), RGU) == ["upload_day"])
check("мусор в отметке не роняет проверку",
      why_of(day_of(pen={"ratio": "нет"})) == ["ratio"])
check("отметка не того типа не роняет",
      why_of(day_of(pen="сломано")) == ["ratio"])

check("часовые признаки отметкой не управляются",
      S.daily_retrigger_ok({"pen": {"hourly": 1}}, "hourly") is True)
check("рост считается от четверти", S.RETRIGGER_GROWTH == 1.25)
check("суточных признаков ровно три",
      set(S.DAILY_SIGNALS) == {"ratio", "upload_day", "download"})
check("каждый смотрит в свой счётчик",
      S.DAILY_SIGNALS["download"] == "down"
      and S.DAILY_SIGNALS["upload_day"] == "up")

_d = day_of()
S.daily_mark(_d, ["ratio"])
check("отметка запоминает счётчик на момент штрафа",
      _d["pen"]["ratio"] == 900 * MB, _d.get("pen"))
check("и не трогает признаки, которые не сработали",
      "download" not in _d["pen"], _d.get("pen"))
S.daily_mark(_d, S.DAILY_SIGNALS)
check("амнистия отмечает все суточные признаки сразу",
      set(_d["pen"]) == set(S.DAILY_SIGNALS), _d.get("pen"))
S.daily_mark(None, ["ratio"])
check("отсутствие записи не роняет отметку", True)

print("\n\033[1mЧасы отдачи в карточке\033[0m")
# Признак, который отделяет раздачу от выгрузки, в карточку не попадал: были
# проценты и байты, а времени не было. По такой карточке нельзя понять, почему
# человек под ограничением, а сосед с теми же процентами нет.
def card(up_sec, window_h=16.4):
    day = {"up": 306_900_000, "down": 519_000_000, "up_sec": up_sec,
           "upkt": [306_900_000, 341_000, 1853, 279_279_000,
                    time.time() - window_h * 3600]}
    return S.penalty_packets(day)[0]


check("часы попали в карточку", "9.4" in card(9.4 * 3600), card(9.4 * 3600))
check("минуты тоже видны", "0.4" in card(0.4 * 3600), card(0.4 * 3600))
check("нулевые часы не печатаются лишней строкой",
      S.t("tg_pen_hrs", h="0") not in card(0), card(0))
check("испорченный счётчик не печатается",
      S.t("tg_pen_hrs", h="9999") not in card(99 * 3600))
check("часы стоят после доли и пакетов",
      card(9.4 * 3600).index("9.4") > card(9.4 * 3600).index("1853"))
check("подпись часов не повторяет слово «данными»",
      card(9.4 * 3600).count("данными") == 1, card(9.4 * 3600))

# В `panel user` часы печатаются своей подписью следующим полем. Пока карточка
# добавляла их безусловно, в одной строке выходило два одинаковых числа под
# разными названиями — читается как две разные величины.
def card_nohrs(up_sec):
    day = {"up": 306_900_000, "down": 519_000_000, "up_sec": up_sec,
           "upkt": [306_900_000, 341_000, 1853, 279_279_000,
                    time.time() - 16.4 * 3600]}
    return S.penalty_packets(day, hours=False)[0]


check("часы выключаются параметром", "9.4" not in card_nohrs(9.4 * 3600),
      card_nohrs(9.4 * 3600))
check("остальные поля при этом на месте",
      "1853" in card_nohrs(9.4 * 3600) and "91%" in card_nohrs(9.4 * 3600))
check("в panel user часы печатаются один раз",
      (card_nohrs(9.4 * 3600) + " · "
       + S.t("pn_user_uphours", h="9.4")).count("9.4") == 1)
check("по умолчанию часы включены — карточка их печатает",
      "9.4" in card(9.4 * 3600))
_src_ctl2 = open(os.path.join(SRC, "shaperctl.py")).read()
check("panel user зовёт разбор пакетов без часов",
      "penalty_packets(d, hours=False)" in _src_ctl2)

print("\n\033[1mУведомление об обновлении\033[0m")
check("номер версии разбирается", S.version_tuple("3.48") == (3, 48))
check("мусор не роняет", S.version_tuple("x") == ()
      and S.version_tuple(None) == () and S.version_tuple("") == ())
check("новее — это новее", S.update_newer("3.48", "3.49") is True)
check("та же версия — нет", S.update_newer("3.48", "3.48") is False)
check("старее — нет", S.update_newer("3.48", "3.47") is False)
check("сравнение числовое, а не строковое",
      S.update_newer("3.5", "3.48") is True, "3.48 новее 3.5")
check("смена мажорной версии видна", S.update_newer("3.48", "4.0") is True)
check("неизвестная установленная версия не даёт ложной тревоги",
      S.update_newer("unknown", "3.49") is False)
check("пустой ответ репозитория тоже", S.update_newer("3.48", "") is False)

_real_fetch, _real_ver, _real_send = S.update_fetch, S.shape_version, S.tg_send
_ups = []
S.tg_send = lambda m, c=None: (_ups.append(m), (True, ""))[1]
S.shape_version = lambda: "3.48"
S.update_fetch = lambda p="": "3.49"
_cfg = {"telegram": dict(S.TG_DEFAULT, enabled=True, node_name="Node-2")}
_st = {}
check("в первый раз сообщаем", S.update_due(_cfg, _st, T0) is True)
check("и запоминаем, о чём", _st.get("seen") == "3.49", _st)
check("сразу второй раз — молчим", S.update_due(_cfg, _st, T0 + 60) is False)
check("через шесть часов, версия та же — тоже молчим",
      S.update_due(_cfg, _st, T0 + S.UPDATE_INTERVAL + 1) is False)
S.update_fetch = lambda p="": "3.50"
check("новая версия — снова сообщаем",
      S.update_due(_cfg, _st, T0 + 3 * S.UPDATE_INTERVAL) is True)
S.update_fetch = lambda p="": ""
check("репозиторий недоступен — молчим, а не паникуем",
      S.update_due(_cfg, _st, T0 + 6 * S.UPDATE_INTERVAL) is False)
check("выключено в настройках — не проверяем вовсе",
      S.update_due({"telegram": dict(S.TG_DEFAULT, enabled=True,
                                     updates=False)}, {}, T0) is False)
check("Telegram выключен — тем более",
      S.update_due({"telegram": dict(S.TG_DEFAULT, updates=True)}, {}, T0)
      is False)
check("в сообщении обе версии", "3.48" in _ups[0] and "3.49" in _ups[0], _ups[0])
check("и сказано, чем обновлять", "shaper" in _ups[0], _ups[0])
check("по умолчанию включено", S.TG_DEFAULT["updates"] is True)
S.update_fetch, S.shape_version, S.tg_send = _real_fetch, _real_ver, _real_send

print("\n\033[1mЧасы отдачи: уведомление, а не штраф\033[0m")
# Первичный бэкап телефона неотличим от раздачи по всем признакам сразу:
# человек, впервые включивший выгрузку плёнки за десять лет, отдаёт сотню
# гигабайт сутки напролёт, и у него сходится и пропорция, и доля данных, и
# часы. Различает их только то, что бэкап кончается, — а этого мы не считаем.
UPH_G = dict(S.GUARD_DEFAULT, upload_hours=6)


def uph(hours, g=UPH_G):
    daily = {"x": {"active": 0, "down": 1e9, "up": 5e9, "up_sec": hours * 3600}}
    return S.evaluate("x", {"dl": 0, "ul": 0, "up_pkt": 0}, g, 100, 0, 0,
                      daily)[1]


check("двадцать часов отдачи штрафа не дают", uph(20) == [], uph(20))
check("порог сам по себе не путь к ограничению", uph(6) == [])
check("веса у этого признака нет вовсе",
      "up_hours" not in S.SIGNAL_WEIGHTS, sorted(S.SIGNAL_WEIGHTS))

_sent = []
_real = S.tg_send
S.tg_send = lambda m, c=None: (_sent.append(m), (True, ""))[1]
S.tg_upload_hours(
    {"telegram": dict(S.TG_DEFAULT, enabled=True, events=True, node_name="N"),
     "guard": UPH_G}, "1.2.3.4", subject={"label": "Чопикс", "user_id": "6085"},
    day={"active": 0, "down": 4.2e9, "up": 11.3e9, "up_sec": 9.4 * 3600})
S.tg_send = _real
check("в уведомлении есть часы", "9.4" in _sent[-1], _sent[-1])
check("и порог", "6" in _sent[-1])
check("и сказано, что ограничения нет",
      S.t("tg_uph_note") in _sent[-1], _sent[-1])

# Испорченная отметка времени не должна давать «за 496620 ч».
_line, _win = S.penalty_packets({"up": 1e9, "upkt": [1e9, 8e5, 1400, 9e8, 0]})
check("окно длиннее суток — строки нет", _line == "", _line)
_ok, _w = S.penalty_packets({"up": 1e9,
                             "upkt": [1e9, 8e5, 1400, 9e8, T0 - 600]}, T0)
check("нормальное окно печатается", _ok != "" and 590 < _w < 610, (_ok, _w))


print("\n\033[1mОтдача за час: зеркало скачивания\033[0m")
# Нодам, где трафик оплачивается, счёт приходит за оба направления, а
# ограничение стояло только на одно. Там вопрос «торрент или бэкап» не имеет
# значения вовсе: гигабайт стоит одинаково.
UGH_G = dict(S.GUARD_DEFAULT, upload_gb_per_hour=3)


def ugh(gb, g=UGH_G):
    return S.evaluate("x", {"dl": 0, "ul": 0, "up_pkt": 0}, g, 10, 0, 0,
                      {"x": {"active": 0, "down": 1e9, "up": 9e9}},
                      None, {"x": {0: gb * 1e9}})[1]


check("ниже порога — не он", ugh(2.9) == [])
check("ровно на пороге — он", ugh(3) == ["up_hourly"])
check("выше — тем более", ugh(9) == ["up_hourly"])
check("по умолчанию выключено",
      S.GUARD_DEFAULT["upload_gb_per_hour"] == 0)
check("и с умолчаниями девять гигабайт проходят",
      ugh(9, S.GUARD_DEFAULT) == [])
check("пустое окно не роняет",
      S.evaluate("x", {"dl": 0, "ul": 0, "up_pkt": 0}, UGH_G, 10, 0, 0,
                 {"x": {"active": 0, "down": 1e9, "up": 9e9}})[1] == [])
check("вес хватает на штраф в одиночку",
      S.SIGNAL_WEIGHTS["up_hourly"] >= S.GUARD_DEFAULT["score_needed"])
check("у причины есть человекочитаемое название",
      S.t("why_up_hourly") != "why_up_hourly")

_b = _io.StringIO()
with redirect_stdout(_b):
    S.cmd_guard_show(10, dict(UGH_G, upload_hours=6))
check("часовой порог отдачи виден",
      S.t("guard_uphourly", d="3") in _b.getvalue(), _b.getvalue())
check("и часы названы уведомлением, а не ограничением",
      S.t("guard_uphours", h="6") in _b.getvalue(), _b.getvalue())

print("\n\033[1mАбсолютный объём отдачи за сутки\033[0m")
# Единственный признак, который не зависит ни от пропорции, ни от размера
# пакета, ни от протокола. Отношение отдачи задевает разговоры, доля данных
# зависит от того, склеивает ли пакеты ядро, — а тридцать гигабайт вверх это
# просто тридцать гигабайт вверх.
UP_G = dict(S.GUARD_DEFAULT, upload_day_gb=30, upload_warn_gb=10)


def upday(up_gb, g=UP_G, down_gb=1):
    daily = {"x": {"active": 0, "down": down_gb * 1e9, "up": up_gb * 1e9}}
    return S.evaluate("x", {"dl": 0, "ul": 0, "up_pkt": 0}, g, 100, 0, 0,
                      daily)[1]


check("ниже порога не трогаем", upday(29.9) == [], upday(29.9))
check("ровно на пороге ловим", upday(30) == ["upload_day"])
check("выше тем более", upday(45) == ["upload_day"])
check("по умолчанию признак выключен",
      S.GUARD_DEFAULT["upload_day_gb"] == 0
      and S.GUARD_DEFAULT["upload_warn_gb"] == 0)
check("и с умолчаниями сто гигабайт проходят мимо",
      upday(100, S.GUARD_DEFAULT) == [])

# Признак обязан работать независимо: скачивания может не быть вовсе, текущей
# активности тоже, пакеты могут быть любыми.
check("работает без скачивания", upday(30, down_gb=0) == ["upload_day"])
check("не зависит от доли данных и текущей отдачи",
      S.evaluate("x", {"dl": 0, "ul": 0, "up_pkt": 60}, UP_G, 100, 0, 0,
                 {"x": {"active": 0, "down": 1e9, "up": 31e9,
                        "upkt": [31e9, 1, 100, 0, 0]}})[1] == ["upload_day"])
check("вес хватает на штраф в одиночку",
      S.SIGNAL_WEIGHTS["upload_day"] >= S.GUARD_DEFAULT["score_needed"])
check("у причины есть человекочитаемое название",
      S.t("why_upload_day") != "why_upload_day")

# Уровень уведомления штрафом не является и в evaluate не попадает вовсе.
check("порог уведомления сам по себе не ограничивает",
      upday(11, dict(S.GUARD_DEFAULT, upload_warn_gb=10)) == [])

_b = _io.StringIO()
_sent = []
_real = S.tg_send
S.tg_send = lambda m, c=None: (_sent.append(m), (True, ""))[1]
S.tg_upload_notice(
    {"telegram": dict(S.TG_DEFAULT, enabled=True, events=True, node_name="N"),
     "guard": UP_G}, "1.2.3.4",
    subject={"label": "Мария", "user_id": "3710"},
    day={"down": 4.2e9, "up": 11.3e9})
S.tg_send = _real
check("в предупреждении есть имя", "Мария" in _sent[-1], _sent[-1])
check("и объём отдачи", "11.3" in _sent[-1], _sent[-1])
check("и сказано, что ограничения нет",
      S.t("tg_up_note", n="30") in _sent[-1], _sent[-1])
check("и назван порог ограничения", "30" in _sent[-1])

# Настройки меняют исход — значит видны на экране автоограничения.
_b = _io.StringIO()
with redirect_stdout(_b):
    S.cmd_guard_show(50, UP_G)
check("оба уровня видны на экране",
      "10" in _b.getvalue() and "30" in _b.getvalue()
      and S.t("guard_upday", w="10", d="30") in _b.getvalue(), _b.getvalue())
_b = _io.StringIO()
with redirect_stdout(_b):
    S.cmd_guard_show(50, dict(S.GUARD_DEFAULT, upload_warn_gb=10))
check("уровень без ограничения назван честно",
      S.t("guard_upwarn", w="10") in _b.getvalue(), _b.getvalue())

print("\n\033[1mДеловые аккаунты не ограничиваем автоматически\033[0m")
# Бюро адвокатов и агентство недвижимости выглядят нарушителями по обеим
# проверкам сразу: двадцать сотрудников на одной подписке — это двадцать
# адресов, а выгрузка рабочих файлов на сетевом уровне неотличима от раздачи.
# Порогом это не лечится: разделяет только знание о том, кто это.
EX_CFG = {"panel": dict(S.PANEL_DEFAULT, enabled=True, exempt=["2442", "152"])}
check("исключённого не трогаем",
      S.guard_exempt(EX_CFG, {"user_id": "2442", "label": "Бюро"}) is True)
check("остальных трогаем",
      S.guard_exempt(EX_CFG, {"user_id": "999"}) is False)
check("номер числом тоже подходит",
      S.guard_exempt(EX_CFG, {"user_id": 2442}) is True)
check("без номера решить нельзя — значит не исключение",
      S.guard_exempt(EX_CFG, {"label": "кто-то"}) is False
      and S.guard_exempt(EX_CFG, None) is False
      and S.guard_exempt(EX_CFG, {}) is False)
check("без панели список пуст и никто не исключён",
      S.guard_exempt({"panel": dict(S.PANEL_DEFAULT)}, {"user_id": "2442"})
      is False)
check("отсутствие раздела панели не роняет",
      S.guard_exempt({}, {"user_id": "2442"}) is False)
check("пробелы в списке не мешают",
      S.guard_exempt({"panel": {"exempt": [" 2442 "]}},
                     {"user_id": "2442"}) is True)

# Список тот же, что у поиска раздачи: одна настройка, одно значение.
check("список общий с поиском раздачи",
      "exempt" in S.PANEL_DEFAULT and S.PANEL_DEFAULT["exempt"] == [])

# Настройка меняет исход и живёт в чужом разделе — значит обязана быть видна
# на экране автоограничения.
_b = _io.StringIO()
with redirect_stdout(_b):
    S.cmd_guard_show(50, dict(S.GUARD_DEFAULT, enabled=True), 2)
check("число исключений видно на экране автоограничения",
      "2" in _b.getvalue() and S.t("guard_exempt_n", n=2) in _b.getvalue(),
      _b.getvalue())
_b = _io.StringIO()
with redirect_stdout(_b):
    S.cmd_guard_show(50, dict(S.GUARD_DEFAULT, enabled=True), 0)
check("без исключений строки нет",
      S.t("guard_exempt_n", n=0) not in _b.getvalue())

print("\n\033[1mПамять сторожа переживает перезапуск\033[0m")
# Живой случай: в 20:18 адрес был подписан именем из панели, в 20:34 тот же
# адрес и та же причина пришли безымянными. Панель знает человека, только
# пока он на ноде, а ответ мы получали и выбрасывали.
#
# Второй случай тем же вечером: кулдаун в шесть часов не сработал, потому что
# жил в памяти, а владелец ноды обновлялся по пять раз за вечер.
CACHE_T = 2_000_000.0
WHO = {"label": "Ольга", "username": "user_100000004",
       "telegram_id": "100000004", "user_id": "2891"}
cache = {}
S.owner_remember(cache, "203.0.113.25", WHO, CACHE_T)
recalled, at = S.owner_recall(cache, "203.0.113.25", CACHE_T + 16 * 60)
check("через шестнадцать минут владелец ещё помнится",
      (recalled or {}).get("label") == "Ольга", recalled)
check("и время опознания вернулось", at == CACHE_T, at)
check("через двенадцать часов забываем",
      S.owner_recall(cache, "203.0.113.25",
                     CACHE_T + S.OWNER_CACHE_TTL + 1) == (None, 0.0))
check("чужой адрес не помним",
      S.owner_recall(cache, "9.9.9.9", CACHE_T) == (None, 0.0))
check("мусор в карте не роняет",
      S.owner_recall({"x": "ерунда"}, "x") == (None, 0.0)
      and S.owner_recall({"x": [1]}, "x") == (None, 0.0)
      and S.owner_recall({"x": [CACHE_T, "не словарь"]}, "x") == (None, 0.0))
check("пустого владельца не запоминаем",
      (S.owner_remember(cache, "8.8.8.8", {}, CACHE_T),
       "8.8.8.8" not in cache)[1])

# Карта не должна расти без предела: чистка по сроку на ноде с тысячами
# адресов её не уменьшает, потому что там всё свежее.
big = {}
for i in range(S.OWNER_CACHE_MAX + 50):
    S.owner_remember(big, "10.0.%d.%d" % (i // 256, i % 256), WHO, CACHE_T - i)
check("карта обрезается по размеру", len(big) <= S.OWNER_CACHE_MAX, len(big))
check("и выбрасывает самое старое",
      "10.0.%d.%d" % ((S.OWNER_CACHE_MAX + 49) // 256,
                      (S.OWNER_CACHE_MAX + 49) % 256) not in big)

# В карточке несвежие сведения обязаны быть помечены: за адресом мог
# оказаться уже другой человек.
TGC = dict(S.TG_DEFAULT, node_name="Node-2")
fresh_card = "\n".join(S.offender_card(TGC, WHO, "x"))
stale_card = "\n".join(S.offender_card(TGC, dict(WHO, seen_at=CACHE_T), "x"))
check("свежая карточка без оговорки", "20:" not in fresh_card, fresh_card)
check("несвежая — с оговоркой", stale_card != fresh_card
      and "Ольга" in stale_card, stale_card)
check("метка без личности ничего не печатает",
      S.t("pn_card_unknown") in "\n".join(
          S.offender_card(TGC, {"seen_at": CACHE_T}, "x")))
check("битая метка не роняет карточку",
      "Ольга" in "\n".join(S.offender_card(TGC, dict(WHO, seen_at="вчера"),
                                           "x")))

print("\n\033[1mПовторные уведомления об одном адресе\033[0m")
# Живой случай: шесть сообщений про один и тот же перекос отдачи за вечер.
# Штраф снимается через час, суточные счётчики за этот час не меняются — и
# всё повторяется до полуночи.
seen = {}
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


# ── интерфейс без Ethernet-заголовка ────────────────────────────────────────
#
# Второй способ выглядеть здоровым, ничего не ограничивая. Фильтр читает
# L2-заголовок безусловно, а у ipip (768), gre (778), tun и wireguard (65534)
# его нет: h_proto попадает в середину IP-заголовка, и программа отдаёт
# TC_ACT_OK на каждом пакете. Заметить это было нечем — у туннельных устройств
# корневой qdisc noqueue, то есть и edt_ready показывает единицу.
import os as _os
import tempfile as _tf

_sysnet = _tf.mkdtemp()


def _fake_iface(name, arphrd):
    d = _os.path.join(_sysnet, name)
    _os.makedirs(d, exist_ok=True)
    with open(_os.path.join(d, "type"), "w") as f:
        f.write(f"{arphrd}\n")
    return d


_fake_iface("eth0", 1)
_fake_iface("tunl0", 768)
_fake_iface("wg0", 65534)

_REAL_OPEN = open


def _open_sysnet(path, *a, **kw):
    p = str(path)
    if p.startswith("/sys/class/net/"):
        p = _os.path.join(_sysnet, p[len("/sys/class/net/"):])
    return _REAL_OPEN(p, *a, **kw)


import builtins as _bi
_bi.open = _open_sysnet
try:
    check("Ethernet распознан", S.iface_arphrd("eth0") == 1)
    check("ipip-туннель распознан", S.iface_arphrd("tunl0") == 768)
    check("wireguard распознан", S.iface_arphrd("wg0") == 65534)
    check("несуществующий интерфейс не роняет",
          S.iface_arphrd("нетакого") is None)
    check("мусор вместо числа не роняет",
          (_fake_iface("junk0", "не-число") and S.iface_arphrd("junk0")) is None)
    check("константа Ethernet это единица", S.ARPHRD_ETHER == 1)
finally:
    _bi.open = _REAL_OPEN

# ── разбор per-CPU карты счётчиков ──────────────────────────────────────────
#
# bpftool с -j отдаёт значение МАССИВОМ БАЙТОВ, а не числом: у карты нет BTF на
# тип значения. Разбор через _int молча возвращал ноль на каждой ячейке, и
# счётчики выглядели пустыми при живых цифрах в ядре — метрики печатались,
# просто все нули. Такую ошибку не видно ниоткуда, кроме сравнения с
# `bpftool map dump` руками, поэтому проверяем оба формата.
_REAL_MDP = S.map_dump_percpu


def _percpu(payload):
    import json as _js
    S.run = lambda cmd, check=True: (_js.dumps(payload), 0)
    S.os.path.exists = lambda p: True
    try:
        return _REAL_MDP("stat_map")
    finally:
        S.run = _REAL_RUN_CMD
        S.os.path.exists = _REAL_EXISTS


_REAL_RUN_CMD = S.run
_REAL_EXISTS = S.os.path.exists

# Ровно то, что отдаёт живой bpftool 7.x на ядре 6.12.
_bytes_form = [{"key": ["0x00", "0x00", "0x00", "0x00"],
                "values": [{"cpu": 0, "value": ["0x96", "0xa8"] + ["0x00"] * 6},
                           {"cpu": 1, "value": ["0xb7", "0x88"] + ["0x00"] * 6}]}]
check("значение массивом байтов складывается по всем CPU",
      _percpu(_bytes_form) == {0: 43158 + 34999},
      _percpu(_bytes_form))

# Сборки с BTF печатают число. Понимать надо оба вида.
_int_form = [{"key": 2, "values": [{"cpu": 0, "value": 100},
                                   {"cpu": 1, "value": 23}]}]
check("значение числом тоже понимается", _percpu(_int_form) == {2: 123})

check("пустой ответ не роняет", _percpu([]) == {})
check("имена счётчиков совпадают с индексами в shaper.bpf.c",
      S.STAT_NAMES == ("down_pass", "down_drop", "up_pass", "up_drop",
                       "pp_resolved", "pp_unresolved"))


# Предупреждение должно быть на обоих языках и не совпадать дословно —
# иначе перевода нет, а есть копия.
for _k in ("eth_off", "eth_fix", "too_slow"):
    check(f"строка {_k} есть по-русски", _k in S.MSG["ru"])
    check(f"строка {_k} есть по-английски", _k in S.MSG["en"])
    check(f"строка {_k} действительно переведена",
          S.MSG["ru"].get(_k) != S.MSG["en"].get(_k))

# Нижняя граница скорости: всё, что усекается в ноль байт в секунду, ядро
# читает как «ограничение выключено». Граница обязана совпадать с той, что
# давно стоит в API, иначе CLI и API разойдутся в поведении.
check("0.05 Мбит/с даёт ненулевую скорость в байтах",
      int(0.05 * S.BYTES_PER_MBPS) > 0)
check("а всё ниже 0.000008 усекается в ноль",
      int(0.000004 * S.BYTES_PER_MBPS) == 0)


# ── часы отдачи: три условия, каждое на свой класс ──────────────────────────
#
# Признак «отдавал N часов» до 3.64 стоял на одной проверке — скорость выше
# 0.3 Мбит/с — и не работал. Живой случай: 1.2 ГБ за 12.7 часа ровным слоем
# по 0.21 Мбит/с, ни один замер порога не достиг, карточка показала «0.0 ч».
# При этом порог не отсекал и того, ради чего ставился: у скачивающего на
# десять мегабит подтверждения дают около 0.33 Мбит вверх, то есть больше.
def tick(ul, dl, pkt, **g):
    d = {"upload_hours_mbps": 0.05, "ratio_needs_packet": True}
    d.update(g)
    return S.up_hours_tick({"ul": ul, "dl": dl, "up_pkt": pkt}, d)

check("тихий сидер: 0.21 вверх при 0.31 вниз — засчитан",
      tick(0.21, 0.31, 1300) is True)
check("он же на старой границе 0.3 — потерян",
      tick(0.21, 0.31, 1300, upload_hours_mbps=0.3) is False)

# Подтверждения обычной закачки отсекает доля, а не скорость: их объём растёт
# вместе со скоростью скачивания, и по абсолютной величине они перекрывают
# любую границу, за которой ещё виден тихий сидер.
check("подтверждения на 10 Мбит вниз не считаются отдачей",
      tick(0.33, 10.0, 100) is False)
check("и не считаются, даже когда GRO склеил их в крупные пакеты",
      tick(0.33, 10.0, 1400) is False)
check("подтверждения на гигабите — тоже нет",
      tick(30.0, 900.0, 1400) is False)

# Разговор отсекает размер пакета: вверх и вниз поровну, доля не спасает.
check("видеосвязь 1:1 с пакетом 267 — не отдача",
      tick(1.0, 1.0, 267) is False)
check("она же на QUIC-ноде (проверка пакета выключена) — засчитана",
      tick(1.0, 1.0, 267, ratio_needs_packet=False) is True)
check("сидер на QUIC с мелкими пакетами не потерян",
      tick(0.5, 0.1, 180, ratio_needs_packet=False) is True)

check("чистая раздача без скачивания — засчитана",
      tick(0.5, 0.0, 1300) is True)
check("шум ниже границы не считается", tick(0.01, 0.0, 1300) is False)
check("ровно на границе — считается", tick(0.05, 0.0, 1300) is True)
check("ровно на доле — считается", tick(0.2, 1.0, 1300) is True)
check("чуть ниже доли — нет", tick(0.19, 1.0, 1300) is False)
check("пустой замер не роняет", S.up_hours_tick({}, {}) is False)
check("замер без настроек не роняет",
      S.up_hours_tick({"ul": 1.0, "dl": 0, "up_pkt": 1400}, None) is True)

check("доля вчетверо выше верхней границы подтверждений",
      S.UPLOAD_HOURS_ACK_SHARE >= 0.05 * 4)
check("новое умолчание границы — 0.05",
      S.GUARD_DEFAULT["upload_hours_mbps"] == 0.05)

# Старое умолчание считаем «не настроено»: его никто не выбирал руками.
# Любое другое число — выбор владельца ноды, и трогать его нельзя.
_saved = open(S.CONFIG_FILE).read() if os.path.exists(S.CONFIG_FILE) else None
try:
    for was, want, name in ((0.3, 0.05, "старое умолчание заменено"),
                            (0.15, 0.15, "выбранное вручную не тронуто"),
                            (0.05, 0.05, "новое умолчание на месте")):
        with open(S.CONFIG_FILE, "w") as f:
            json.dump({"guard": {"upload_hours_mbps": was}}, f)
        got = S.load_config()["guard"]["upload_hours_mbps"]
        check(name, got == want, f"{was} -> {got}, ждали {want}")
finally:
    if _saved is None:
        os.path.exists(S.CONFIG_FILE) and os.remove(S.CONFIG_FILE)
    else:
        open(S.CONFIG_FILE, "w").write(_saved)

# Пресеты должны ставить границу явно: миграция чинит уже установленные ноды,
# пресет — те, где значение когда-то правили руками.
_menu = open(os.path.join(SRC, "menu.sh")).read()
check("оба пресета задают границу часов явно",
      _menu.count("--upload-hours-mbps 0.05") == 2,
      str(_menu.count("--upload-hours-mbps 0.05")))

print("\n\033[1mДоверенные источники: туннели и релеи CDN\033[0m")
# Команда гоняется по-настоящему, а не проверяется грепом по исходнику.
# Наличие строки в файле ничего не доказывает — на этом уже обжигались
# трижды: экран [18]/[19], пункт [2] в удалении и таблица монитора.
S.TRUST_FILE = os.path.join(ETC, "trusted.txt")

check("пустой список — обе развёртки выключены", S.trusted_sources() == {})

_a = argparse.Namespace(action="add", ip="198.51.100.7", tunnel=True, relay=False)
S.cmd_trusted(_a)
check("конец туннеля записан",
      S.trusted_sources() == {"198.51.100.7": S.TRUST_TUNNEL},
      str(S.trusted_sources()))

_a = argparse.Namespace(action="add", ip="198.51.100.20", tunnel=False, relay=True)
S.cmd_trusted(_a)
check("релей записан отдельным видом",
      S.trusted_sources().get("198.51.100.20") == S.TRUST_RELAY)

# Один адрес может быть и тем и другим — флаги должны складываться, а не
# затирать друг друга.
_a = argparse.Namespace(action="add", ip="198.51.100.7", tunnel=False, relay=True)
S.cmd_trusted(_a)
check("виды складываются, а не заменяются",
      S.trusted_sources().get("198.51.100.7") ==
      (S.TRUST_TUNNEL | S.TRUST_RELAY))

# Файл должен переживать круговой путь: запись → чтение → запись.
_before = S.trusted_sources()
S._write_trusted(_before)
check("круговой путь через файл ничего не теряет", S.trusted_sources() == _before)

check("без вида команда отказывается работать",
      dies(S.cmd_trusted, argparse.Namespace(action="add", ip="198.51.100.9",
                                             tunnel=False, relay=False)))
check("мусор вместо адреса не принимается",
      dies(S.cmd_trusted, argparse.Namespace(action="add", ip="не адрес",
                                             tunnel=True, relay=False)))

_a = argparse.Namespace(action="del", ip="198.51.100.20", tunnel=False, relay=False)
S.cmd_trusted(_a)
check("удаление убирает адрес", "198.51.100.20" not in S.trusted_sources())
check("и не задевает соседей", "198.51.100.7" in S.trusted_sources())

# Битые строки не должны молча пропадать: незамеченный релей означает, что
# все его клиенты делят один лимит, а по симптомам этого не понять.
with open(S.TRUST_FILE, "a") as f:
    f.write("198.51.100.30 непонятно-что\n")
check("строка с неизвестным видом в список не попадает",
      "198.51.100.30" not in S.trusted_sources())

# Значение в карте — это байт флагов, и он должен доехать до ядра целым.
open(os.environ["BPFTOOL_LOG"], "w").close()
S.cmd_trusted(argparse.Namespace(action="sync", ip="", tunnel=False, relay=False))
_log = open(os.environ["BPFTOOL_LOG"]).read()
check("sync грузит список в карту", "trusted_map" in _log, _log[:200])
check("флаги едут значением, а не именем",
      f"value hex 0{S.TRUST_TUNNEL | S.TRUST_RELAY}" in _log or
      f"value hex {S.TRUST_TUNNEL | S.TRUST_RELAY:02x}" in _log or
      "value hex 03" in _log, _log[:400])

# Движок обязан перезагружать список при старте: карта перезапуск не переживает.
_eng = open(os.path.join(SRC, "engine.sh")).read()
check("движок делает trusted sync при запуске", "trusted sync" in _eng)

print(f"\n\033[1mИтог: {ok} пройдено, {fail} провалено\033[0m")
sys.exit(1 if fail else 0)

# -*- coding: utf-8 -*-
"""Проверка логики тревог на выдуманных сценариях, без сети и без Telegram."""
import importlib.util, os, sys

spec = importlib.util.spec_from_file_location(
    "nw", os.path.join(os.path.dirname(os.path.abspath(__file__)), "watchman.py"))
nw = importlib.util.module_from_spec(spec); spec.loader.exec_module(nw)

CFG = {}


def node(uuid, name, online, connected=True, disabled=False, connecting=False):
    return {"uuid": uuid, "name": name, "usersOnline": online,
            "isConnected": connected, "isDisabled": disabled,
            "isConnecting": connecting, "xrayUptime": 999999}


def run(title, steps, expect_alert, needle=None):
    """steps — список списков нод, по одному на проход раз в минуту."""
    state = {"nodes": {}}
    t = 1_700_000_000.0
    fired = []
    for s in steps:
        fired += nw.check(CFG, state, s, t)
        t += 60
    got = [m for m in fired if m.startswith(("🔴", "🟠"))]
    ok = bool(got) == expect_alert
    if ok and needle:
        ok = any(needle in m for m in got)
    print("%-46s %s" % (title, "OK" if ok else "ПРОВАЛ"))
    if not ok:
        for m in fired:
            print("      |", m.split("\n")[0])
    return ok


FLEET = [("u%02d" % i, "Нода-%02d" % i, 120) for i in range(24)]

# 1. Спокойный парк: ничего не происходит.
steady = [[node(u, n, v) for u, n, v in FLEET] for _ in range(20)]
r = [run("спокойный парк — тишины не нарушаем", steady, False)]

# 2. Ночь: все ноды плавно теряют 80% людей.
night = list(steady)
for k in range(1, 16):
    f = max(0.2, 1.0 - 0.055 * k)
    night.append([node(u, n, int(v * f)) for u, n, v in FLEET])
r.append(run("ночь: просели все — тревоги быть не должно", night, False))

# 3. Обвал одной ноды при спокойном парке.
crash = list(steady)
for _ in range(5):
    crash.append([node(u, n, 2 if u == "u00" else v) for u, n, v in FLEET])
r.append(run("обвал одной ноды — тревога", crash, True, "клиенты пропали"))

# 4. Обвал ночью: парк упал вдвое, а одна нода — в ноль.
mixed = list(night)
for _ in range(5):
    mixed.append([node(u, n, 0 if u == "u00" else int(v * 0.2)) for u, n, v in FLEET])
r.append(run("обвал ночью — всё равно тревога", mixed, True, "клиенты пропали"))

# 5. Мелкая нода: с шести до нуля — статистически ничто.
small = [[node("s1", "Мелкая", 6)] + [node(u, n, v) for u, n, v in FLEET]
         for _ in range(20)]
for _ in range(6):
    small.append([node("s1", "Мелкая", 0)] + [node(u, n, v) for u, n, v in FLEET])
r.append(run("мелкая нода 6->0 — молчим", small, False))

# 6. Потеря связи с панелью по одной ноде.
disc = list(steady)
for _ in range(4):
    disc.append([node(u, n, 0, connected=False) if u == "u00"
                 else node(u, n, v) for u, n, v in FLEET])
r.append(run("панель потеряла ноду — тревога", disc, True, "потеряла ноду"))

# 7. Выключенную вручную ноду не трогаем.
off = list(steady)
for _ in range(6):
    off.append([node(u, n, 0, connected=False, disabled=True) if u == "u00"
                else node(u, n, v) for u, n, v in FLEET])
r.append(run("нода выключена вами — молчим", off, False))

# 8. Отбой после обвала.
back = list(crash)
for _ in range(4):
    back.append([node(u, n, v) for u, n, v in FLEET])
state = {"nodes": {}}
t = 1_700_000_000.0
msgs = []
for s in back:
    msgs += nw.check(CFG, state, s, t); t += 60
ok = any("вернулись" in m for m in msgs)
print("%-46s %s" % ("после обвала — сообщение об отбое", "OK" if ok else "ПРОВАЛ"))
r.append(ok)

print("\nИтог: %d из %d" % (sum(r), len(r)))
sys.exit(0 if all(r) else 1)

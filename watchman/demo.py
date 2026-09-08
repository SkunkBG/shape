#!/usr/bin/env python3
"""
Показать образцы сообщений в чате, не дожидаясь настоящей аварии.

Сводка строится по живому состоянию, тревога — по его КОПИИ: настоящий
state.json не трогается, иначе проверка оформления сбила бы сторожу историю.
"""
import copy
import importlib.util
import json
import os
import sys
import time

APP = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("nw", os.path.join(APP, "watchman.py"))
nw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nw)

cfg = json.load(open(os.path.join(APP, "config.json")))


def public_samples():
    """
    Те же сообщения, но на выдуманных нодах.

    Снимок экрана с настоящими именами нод публиковать нельзя: имена видны на
    картинке ровно так же, как в тексте, а README лежит в открытом
    репозитории. Поэтому для документации данные берутся не из панели, а
    отсюда — панель при этом вообще не опрашивается.
    """
    now = time.time()
    names = ["🇩🇪 Frankfurt-1", "🇳🇱 Amsterdam-2", "🇫🇮 Helsinki-1",
             "🇸🇪 Stockholm-1", "🇵🇱 Warsaw-1", "🇪🇪 Tallinn-1"]
    base = [148, 131, 96, 74, 63, 52]
    nodes, state = [], {"nodes": {}, "alerts_today": 1}
    for i, (name, b) in enumerate(zip(names, base)):
        uuid = "demo-%d" % i
        nodes.append({"uuid": uuid, "name": name, "usersOnline": b,
                      "isConnected": True, "isDisabled": False,
                      "isConnecting": False, "xrayUptime": 900000})
        state["nodes"][uuid] = {
            "samples": [[now - 60 * (60 - j), b] for j in range(60)],
            "disc_streak": 0, "collapse_streak": 0,
            "alert_collapse": 0, "alert_disc": 0, "xray": 900000}

    btn = nw.panel_button(cfg)
    ok, err = nw.tg_send(cfg, nw.daily_card(cfg, state, nodes, now), btn)
    print("сводка:", "отправлена" if ok else err)

    # Обвал первой ноды: три прохода подряд, как в жизни.
    st = copy.deepcopy(state)
    fall = [2, 2, 2]
    msgs = []
    for k, v in enumerate(fall):
        fake = [dict(n, usersOnline=v) if n["uuid"] == "demo-0" else n for n in nodes]
        msgs = nw.check(cfg, st, fake, now + 60 * (k + 1))
    for m in msgs:
        if m[:1] == "🟠":
            ok, err = nw.tg_send(cfg, m, btn)
            print("тревога:", "отправлена" if ok else err)

    st = copy.deepcopy(state)
    for k in range(nw.CONFIRM):
        dead = [dict(n, isConnected=False, isConnecting=False,
                     lastStatusMessage="dial tcp 203.0.113.10:2222: connect: connection refused")
                if n["uuid"] == "demo-1" else n for n in nodes]
        msgs = nw.check(cfg, st, dead, now + 60 * (k + 1))
    for m in msgs:
        if m[:1] == "🔴":
            ok, err = nw.tg_send(cfg, m, btn)
            print("потеря связи:", "отправлена" if ok else err)


if "--public" in sys.argv:
    public_samples()
    raise SystemExit(0)

real = json.load(open(os.path.join(APP, "state.json")))
real.setdefault("nodes", {})
nodes = nw.panel_nodes(cfg)
now = time.time()
btn = nw.panel_button(cfg)

ok, err = nw.tg_send(cfg, "🧪 <i>образец: суточная сводка, живые данные</i>\n\n"
                     + nw.daily_card(cfg, real, nodes, now), btn)
print("сводка:", "отправлена" if ok else err)

st = copy.deepcopy(real)
victim = max(nodes, key=lambda n: int(n.get("usersOnline") or 0))
fake = [dict(n, usersOnline=2) if n["uuid"] == victim["uuid"] else n for n in nodes]
msgs = []
for _ in range(nw.CONFIRM):
    msgs = nw.check(cfg, st, fake, now)
    now += 60
for m in msgs:
    if m[:1] == "🟠":
        ok, err = nw.tg_send(cfg, "🧪 <i>образец: тревога</i>\n\n" + m, btn)
        print("тревога:", "отправлена" if ok else err)

st = copy.deepcopy(real)
dead = [dict(n, isConnected=False, isConnecting=False,
             lastStatusMessage="dial tcp 1.2.3.4:2222: connect: connection refused")
        if n["uuid"] == victim["uuid"] else n for n in nodes]
msgs = []
for _ in range(nw.CONFIRM):
    msgs = nw.check(cfg, st, dead, time.time())
for m in msgs:
    if m[:1] == "🔴":
        ok, err = nw.tg_send(cfg, "🧪 <i>образец: нода пропала со связи</i>\n\n" + m, btn)
        print("потеря связи:", "отправлена" if ok else err)

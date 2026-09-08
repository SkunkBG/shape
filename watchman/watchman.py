#!/usr/bin/env python3
"""
watchman — сторож тишины для парка нод Remnawave.

Раз в минуту спрашивает у панели /api/nodes и сравнивает число людей на
каждой ноде с её собственной историей. Пишет в Telegram, когда нода теряет
клиентов или пропадает со связи.

Почему смотрим на онлайн, а не на молчание метрик. 2026-09-04 нода была
полностью здорова — Xray работал трое суток, панель её видела, шейпер держал
лимиты, — а подключения упали с 723 до двух, потому что сломалось выше края
CDN. Сторож, следящий за отправкой метрик, промолчал бы: нода отправляла их
исправно. Обвал онлайна ловит и этот случай, и обычное падение ноды.

Сторож живёт ВНЕ нод и ничего на них не меняет: он только читает панель.
Упал сторож — на нодах не изменилось ничего.

Ничего не слушает, входящих портов не открывает. Только стандартная
библиотека: лишние зависимости на сторожевой машине — лишние поводы сломаться.
"""
import html
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(APP_DIR, "config.json")
STATE = os.path.join(APP_DIR, "state.json")

# ── Пороги ────────────────────────────────────────────────────────────────
#
# Все числа здесь выбраны против ложных тревог. Сторож, который врёт, глушат
# через неделю, и дальше он бесполезен — так что цена ложной тревоги выше,
# чем цена пропущенной: пропущенную поймает следующий проход через минуту.

WINDOW_SEC = 900        # окно, по которому считается норма — четверть часа
KEEP_SEC = 3600         # сколько истории храним вообще — час, ради спарклайна
ALERT_SPARK_MIN = 20    # окно спарклайна в тревоге, минуты
BASELINE_LAG = 180      # база считается по замерам старше трёх минут
MIN_BASELINE = 10       # ноды меньше этого не тревожим вовсе
COLLAPSE_RATIO = 0.25   # ниже четверти ожидаемого — обвал
RECOVER_RATIO = 0.50    # выше половины ожидаемого — отбой
CONFIRM = 3             # столько проходов подряд должно держаться условие
COOLDOWN = 3600         # не повторять тревогу об одной ноде чаще раза в час
HEARTBEAT_HOUR = 12     # час, в который сторож сообщает, что жив
HTTP_TIMEOUT = 15


# Пороги можно переопределить в config.json, раздел "tuning" — их правит
# меню. Значения выше остаются умолчаниями и документацией: увидев файл без
# раздела tuning, человек читает работающие числа, а не пустые ссылки.
TUNABLES = ("MIN_BASELINE", "COLLAPSE_RATIO", "RECOVER_RATIO", "CONFIRM",
            "COOLDOWN", "HEARTBEAT_HOUR", "ALERT_SPARK_MIN")


def apply_tuning(cfg):
    """
    Переопределяет пороги из конфига.

    Меняем глобальные значения, а не тащим объект настроек через каждый
    вызов: watchman — разовый проход по таймеру, живёт секунду, и
    протаскивание настроек сквозь десяток функций стоило бы дороже, чем
    даёт. Место одно, и оно здесь.
    """
    for key, val in (cfg.get("tuning") or {}).items():
        if key in TUNABLES and isinstance(val, (int, float)) and not isinstance(val, bool):
            globals()[key] = type(globals()[key])(val)


def load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def save_state(data):
    """Пишем через временный файл: оборванная запись оставила бы битый JSON,
    и следующий проход начал бы историю с нуля — как раз посреди аварии."""
    tmp = STATE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.replace(tmp, STATE)


def panel_nodes(cfg):
    base = str(cfg.get("panel_url") or "").strip().rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    req = urllib.request.Request(base + "/api/nodes")
    req.add_header("Authorization", "Bearer " + str(cfg.get("panel_token") or ""))
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
        return json.loads(r.read().decode())["response"]


def tg_send(cfg, text, buttons=None):
    """Возвращает (получилось, пояснение). Токен из пояснения вычищается:
    текст уходит в journalctl, а там ему не место."""
    token = str(cfg.get("tg_token") or "").strip()
    chat = str(cfg.get("tg_chat") or "").strip()
    if not token or not chat:
        return False, "не заданы tg_token или tg_chat"
    fields = {"chat_id": chat, "text": text, "parse_mode": "HTML",
              "disable_web_page_preview": "true"}
    if buttons:
        fields["reply_markup"] = json.dumps({"inline_keyboard": buttons})
    thread = str(cfg.get("tg_thread") or "").strip()
    if thread:
        fields["message_thread_id"] = thread
    url = "https://api.telegram.org/bot%s/sendMessage" % token
    proxy = str(cfg.get("tg_proxy") or "").strip()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(
        {"http": proxy, "https": proxy} if proxy else {}))
    try:
        opener.open(url, urllib.parse.urlencode(fields).encode(),
                    timeout=HTTP_TIMEOUT)
        return True, ""
    except Exception as e:
        return False, str(e).replace(token, "<токен>")[:200]


SPARK = "▁▂▃▄▅▆▇█"


def spark(samples, now, top=None, cells=12, window=None):
    """
    Спарклайн онлайна за час: час делим на cells корзин и берём среднее.

    Высота считается от нуля, а не от минимума в окне: иначе обвал до двух
    человек нарисовался бы такой же ровной строкой, как спокойный час, — минимум
    и максимум просто съехали бы вниз вместе с ним.
    """
    win = float(window or KEEP_SEC)
    pts = [(ts, v) for ts, v in samples if now - ts <= win]
    if not pts:
        return ""
    step = win / float(cells)
    buckets = [[] for _ in range(cells)]
    for ts, v in pts:
        i = int((win - (now - ts)) / step)
        buckets[min(max(i, 0), cells - 1)].append(v)
    vals = [sum(b) / len(b) for b in buckets if b]
    if not vals:
        return ""
    hi = float(top or max(vals) or 1)
    if hi <= 0:
        hi = 1.0
    return "".join(SPARK[min(7, max(0, int(round(v / hi * 7))))] for v in vals)


def bar(part, whole, cells=10):
    """Полоса заполнения: [███░░░░░░░]."""
    if whole <= 0:
        return "░" * cells
    n = int(round(part / float(whole) * cells))
    # Ненулевое значение обязано быть видно хотя бы одной клеткой: пустая
    # полоса означает «никого», и путать её с «мало» нельзя.
    if part > 0:
        n = max(1, n)
    n = min(cells, max(0, n))
    return "█" * n + "░" * (cells - n)


def plural(n, one, few, many):
    """1 проход, 2 прохода, 5 проходов — сообщения читают люди, а не машины."""
    n = abs(int(n))
    if n % 10 == 1 and n % 100 != 11:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


def panel_button(cfg):
    """Кнопка-ссылка на панель. Ссылке приёмник не нужен — сторож по-прежнему
    только отправляет и ничего не слушает."""
    url = str(cfg.get("panel_url") or "").strip()
    if not url.startswith(("http://", "https://")):
        return None
    return [[{"text": "📊 Панель", "url": url}]]


def median(values):
    v = sorted(values)
    n = len(v)
    if not n:
        return 0.0
    return float(v[n // 2]) if n % 2 else (v[n // 2 - 1] + v[n // 2]) / 2.0


def baseline_of(samples, now):
    """
    Норма для ноды — медиана замеров старше BASELINE_LAG.

    Медиана, а не среднее: одна провалившаяся минута не должна утаскивать
    норму за собой. Свежие замеры исключены намеренно — иначе начавшийся
    обвал сам опустил бы планку, по которой его же и оценивают, и тревога
    не сработала бы никогда.
    """
    vals = [v for ts, v in samples
            if BASELINE_LAG <= now - ts <= WINDOW_SEC]
    return median(vals) if len(vals) >= 5 else None


def fleet_factor(nodes, state, now):
    """
    Во сколько раз просел парк целиком — множитель «сейчас вечер».

    Онлайн падает ночью везде и сразу. Без этой поправки сторож будил бы
    каждую ночь: с двухсот до сорока — это минус восемьдесят процентов, и
    любой абсолютный порог такое считает аварией. Сравнение с парком делает
    вопрос правильным: «просела ли эта нода сильнее, чем все остальные».

    Считается только по нодам с настоящей историей и заметным размером,
    иначе мелочь и новички размывают картину.
    """
    now_sum = base_sum = 0.0
    for n in nodes:
        st = state["nodes"].get(n["uuid"])
        if not st or not n.get("isConnected"):
            continue
        base = baseline_of(st["samples"], now)
        if base is None or base < MIN_BASELINE:
            continue
        now_sum += int(n.get("usersOnline") or 0)
        base_sum += base
    if base_sum <= 0:
        return 1.0
    # Границы намеренно широкие, но не бесконечные: если парк лёг целиком,
    # множитель ушёл бы в ноль и обвал перестал бы считаться обвалом — то
    # есть сторож промолчал бы ровно в самой крупной аварии.
    return max(0.15, min(1.5, now_sum / base_sum))


def check(cfg, state, nodes, now):
    """Возвращает список сообщений. Состояние правит на месте."""
    out = []
    factor = fleet_factor(nodes, state, now)
    seen = set()

    for n in nodes:
        uuid = n.get("uuid")
        if not uuid:
            continue
        seen.add(uuid)
        name = html.escape(str(n.get("name") or uuid[:8]))
        online = int(n.get("usersOnline") or 0)
        st = state["nodes"].setdefault(uuid, {
            "samples": [], "disc_streak": 0, "collapse_streak": 0,
            "alert_collapse": 0, "alert_disc": 0, "xray": None})

        # ── Панель потеряла ноду ──────────────────────────────────────────
        # Отключённые вручную не трогаем: это не авария, а ваше решение.
        if n.get("isDisabled"):
            st["disc_streak"] = 0
        elif not n.get("isConnected") and not n.get("isConnecting"):
            st["disc_streak"] += 1
        else:
            if st["alert_disc"] and st["disc_streak"] >= CONFIRM:
                out.append("✅ <b>%s</b> снова на связи" % name)
            st["disc_streak"] = 0
            st["alert_disc"] = 0

        if st["disc_streak"] == CONFIRM or (
                st["disc_streak"] > CONFIRM and now - st["alert_disc"] > COOLDOWN):
            st["alert_disc"] = now
            why = html.escape(str(n.get("lastStatusMessage") or "").strip()[:150])
            d = st["disc_streak"]
            out.append(
                "🔴 <b>%s</b> — панель потеряла ноду\n"
                "<blockquote>Не на связи <b>%d %s</b>%s</blockquote>"
                % (name, d, plural(d, "минуту", "минуты", "минут"),
                   ("\nПанель говорит: <i>%s</i>" % why) if why else ""))

        # ── Обвал онлайна при живой связи ─────────────────────────────────
        st["samples"].append([now, online])
        st["samples"] = [s for s in st["samples"] if now - s[0] <= KEEP_SEC]

        base = baseline_of(st["samples"], now)
        if base is None or base < MIN_BASELINE or not n.get("isConnected"):
            # Нет истории, нода мелкая или уже не на связи — обвал не считаем:
            # про потерю связи скажет проверка выше, дублировать незачем.
            st["collapse_streak"] = 0
            continue

        expected = base * factor
        if online < expected * COLLAPSE_RATIO:
            st["collapse_streak"] += 1
        elif online >= expected * RECOVER_RATIO:
            if st["alert_collapse"]:
                out.append("✅ <b>%s</b> — клиенты вернулись: %d (норма %d)"
                           % (name, online, round(base)))
                st["alert_collapse"] = 0
            st["collapse_streak"] = 0

        if st["collapse_streak"] == CONFIRM or (
                st["collapse_streak"] > CONFIRM
                and now - st["alert_collapse"] > COOLDOWN):
            st["alert_collapse"] = now
            out.append(
                "🟠 <b>%s</b> — клиенты пропали\n"
                "<blockquote>Сейчас <b>%d</b> · обычно <b>%d</b> · парк <b>%d%%</b>\n"
                "За %d мин: %s\n"
                "[<code>%s</code>] %d%% от нормы</blockquote>\n"
                "Панель ноду <b>видит</b> — значит сама нода жива. Смотреть путь "
                "до клиентов: CDN, резолв домена, маршрут до края."
                % (name, online, round(base), round(factor * 100),
                   ALERT_SPARK_MIN, spark(st["samples"], now, top=base,
                                          window=ALERT_SPARK_MIN * 60),
                   bar(online, base), round(online / base * 100)))

        # ── Перезапуск Xray ───────────────────────────────────────────────
        # Не тревога, а факт: контейнер перезапустился, счётчик пошёл с нуля.
        up = n.get("xrayUptime")
        try:
            up = int(up)
        except (TypeError, ValueError):
            up = None
        if up is not None:
            if st["xray"] is not None and up < st["xray"] and st["xray"] - up > 60:
                out.append("ℹ️ <b>%s</b> — Xray перезапустился" % name)
            st["xray"] = up

    # Нода исчезла из панели целиком — её удалили или переименовали. Молча
    # забываем: тревожить тут не о чем, а держать мусор в состоянии незачем.
    for uuid in list(state["nodes"]):
        if uuid not in seen:
            del state["nodes"][uuid]
    return out


def daily_card(cfg, state, nodes, now):
    """
    Суточная сводка. Она же — доказательство, что сторож жив.

    Список нод убран в раскрывающуюся врезку намеренно: в чате видна короткая
    шапка, а двадцать четыре строки разворачиваются по желанию. Иначе
    ежедневное сообщение занимало бы весь экран и его начали бы пролистывать
    не читая — а вместе с ним пролистали бы однажды и тревогу.
    """
    live = sum(1 for n in nodes if n.get("isConnected"))
    people = sum(int(n.get("usersOnline") or 0) for n in nodes)
    alerts = int(state.get("alerts_today") or 0)
    text = ("🟢 <b>Сторож жив</b>\n"
            "<blockquote>Нод <b>%d</b> · на связи <b>%d</b> · людей <b>%d</b>\n"
            "Парк <b>%d%%</b> от нормы · тревог за сутки <b>%d</b></blockquote>"
            % (len(nodes), live, people,
               round(fleet_factor(nodes, state, now) * 100), alerts))

    rows = []
    for n in sorted(nodes, key=lambda x: -int(x.get("usersOnline") or 0)):
        st = state["nodes"].get(n.get("uuid")) or {}
        base = baseline_of(st.get("samples") or [], now)
        if base is None or base < MIN_BASELINE:
            continue
        rows.append("%s — %d / %d  %s"
                    % (html.escape(str(n.get("name") or "?")),
                       int(n.get("usersOnline") or 0), round(base),
                       spark(st.get("samples") or [], now, top=base, cells=6)))
    if rows:
        text += ("\n<blockquote expandable><b>По нодам</b>\n"
                 + "\n".join(rows) + "</blockquote>")
    return text


def heartbeat_due(state, now):
    """
    Раз в сутки сторож сообщает, что он жив.

    Без этого его собственная смерть выглядит как «всё спокойно»: тревоги
    просто перестают приходить, и заметить это нечем. Ровно та ловушка, ради
    выхода из которой сторож и написан, — глупо было бы попасть в неё самим.
    """
    # Раз в календарные сутки, в первый проход после назначенного часа.
    #
    # Раньше условие было «час в точности равен назначенному». Тогда сервер,
    # выключенный ровно с 12:00 до 13:00, съедал сводку целиком, и это
    # выглядело бы как смерть самого watchman — то есть давало ложную тревогу
    # ровно того рода, ради которой сводка и заведена.
    lt = time.localtime(now)
    if lt.tm_hour < HEARTBEAT_HOUR:
        return False
    return state.get("heartbeat_day") != time.strftime("%Y-%m-%d", lt)


def cmd_status(cfg, state):
    """
    Что сторож видит прямо сейчас — одной командой.

    Нужен не для красоты: без него любая проверка состояния превращается в
    двадцать строк питона, вставленных в терминал руками, а такие проверки
    не повторяются и теряются.
    """
    now = time.time()
    nodes = panel_nodes(cfg)
    factor = fleet_factor(nodes, state, now)
    last = float(state.get("last_run") or 0)
    hb = float(state.get("heartbeat") or 0)

    print("последний проход : %s" % (
        "%d с назад" % (now - last) if last else "ещё не было"))
    print("нод в панели     : %d, на связи %d, людей %d"
          % (len(nodes), sum(1 for n in nodes if n.get("isConnected")),
             sum(int(n.get("usersOnline") or 0) for n in nodes)))
    print("парк сейчас      : %d%% от нормы" % round(factor * 100))
    print("«сторож жив»     : %s" % (
        time.strftime("%d.%m %H:%M", time.localtime(hb)) if hb else "ещё не было"))
    if state.get("panel_fail"):
        print("панель не отвечала подряд: %d раз" % state["panel_fail"])
    print()

    rows = []
    for n in nodes:
        st = state["nodes"].get(n.get("uuid")) or {}
        samples = st.get("samples") or []
        base = baseline_of(samples, now) if samples else None
        online = int(n.get("usersOnline") or 0)
        if n.get("isDisabled"):
            note = "выключена вами"
        elif not n.get("isConnected"):
            d = st.get("disc_streak", 0)
            note = "НЕТ СВЯЗИ (%d %s)" % (d, plural(d, "проход", "прохода", "проходов"))
        elif st.get("alert_collapse"):
            note = "ТРЕВОГА: клиенты пропали"
        elif base is None:
            note = "копит историю (%d)" % len(samples)
        elif base < MIN_BASELINE:
            note = "мелкая, обвал не считаем"
        elif st.get("collapse_streak"):
            note = "проседает (%d из %d)" % (st["collapse_streak"], CONFIRM)
        else:
            note = "под присмотром"
        rows.append((online, str(n.get("name") or "?")[:24], len(samples),
                     ("%.0f" % base) if base is not None else "—", online, note))

    print("%-24s %8s %7s %7s  %s" % ("нода", "замеров", "норма", "сейчас", "состояние"))
    for _, name, cnt, base, online, note in sorted(rows, reverse=True):
        print("%-24s %8d %7s %7d  %s" % (name, cnt, base, online, note))
    return 0


def main(argv):
    dry = "--dry-run" in argv
    if "--status" in argv:
        cfg = load(CONFIG, None)
        if cfg is None:
            print("не читается %s" % CONFIG, file=sys.stderr)
            return 2
        apply_tuning(cfg)
        st = load(STATE, {})
        st.setdefault("nodes", {})
        return cmd_status(cfg, st)
    cfg = load(CONFIG, None)
    if cfg is None:
        print("не читается %s" % CONFIG, file=sys.stderr)
        return 2

    apply_tuning(cfg)
    state = load(STATE, {})
    state.setdefault("nodes", {})
    now = time.time()
    msgs = []

    try:
        nodes = panel_nodes(cfg)
        if state.get("panel_fail", 0) >= CONFIRM:
            msgs.append("✅ Панель снова отвечает")
        state["panel_fail"] = 0
    except Exception as e:
        # Недоступная панель — это слепота, и молчать о ней нельзя. Но и
        # тревожить с первой же осечки не стоит: сеть моргает.
        state["panel_fail"] = int(state.get("panel_fail", 0)) + 1
        if state["panel_fail"] == CONFIRM:
            msgs.append("🔴 Панель не отвечает %d мин — сторож ослеп.\n<i>%s</i>"
                        % (CONFIRM, str(e)[:150]))
        for m in msgs:
            print(m) if dry else tg_send(cfg, m)
        save_state(state)
        return 0

    msgs += check(cfg, state, nodes, now)
    state["last_run"] = now

    # Считаем тревоги за сутки до сводки: она о них и рассказывает.
    state["alerts_today"] = int(state.get("alerts_today") or 0) + sum(
        1 for m in msgs if m[:1] in ("🔴", "🟠"))

    if heartbeat_due(state, now):
        msgs.append(daily_card(cfg, state, nodes, now))
        state["heartbeat"] = now
        state["heartbeat_day"] = time.strftime("%Y-%m-%d", time.localtime(now))
        state["alerts_today"] = 0

    btn = panel_button(cfg)
    for m in msgs:
        if dry:
            plain = m
            for tag in ("<b>", "</b>", "<i>", "</i>", "<code>", "</code>",
                        "<blockquote>", "<blockquote expandable>", "</blockquote>"):
                plain = plain.replace(tag, "")
            print(plain)
        else:
            # Кнопка нужна там, где по ней пойдут разбираться: тревога и
            # сводка. К сообщениям об отбое она лишняя.
            ok, err = tg_send(cfg, m, btn if m[:1] in ("🔴", "🟠", "🟢") else None)
            if not ok:
                print("telegram: %s" % err, file=sys.stderr)

    save_state(state)
    if dry and not msgs:
        print("тревог нет; нод %d, людей %d, парк %d%% от нормы"
              % (len(nodes), sum(int(n.get("usersOnline") or 0) for n in nodes),
                 round(fleet_factor(nodes, state, now) * 100)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

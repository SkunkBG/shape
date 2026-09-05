#!/usr/bin/env python3
"""
Меню Watchman — настройка без правки JSON руками.

Заведено не для красоты. Конфиг правился через nano, и один лишний `/api`
в адресе панели уже стоил круга разбирательств: панель отвечала 404, а
причина была не видна. Меню проверяет введённое сразу и показывает результат.

Пишется на Python, а не на bash, намеренно: watchman и так питоновский, а
подстановка пользовательского ввода в текст программы — та самая дыра,
которую в Shape пришлось чинить отдельной правкой в menu.sh.
"""
import json
import os
import subprocess
import sys
import time

# realpath, а не abspath: меню запускается через симлинк /usr/local/bin/watchman,
# и abspath оставил бы каталог симлинка — конфиг искался бы в /usr/local/bin.
APP = os.path.dirname(os.path.realpath(__file__))
CONFIG = os.path.join(APP, "config.json")
STATE = os.path.join(APP, "state.json")
USER = "watchman"

if sys.stdout.isatty():
    G, Y, R, D, B, N = ("\033[32m", "\033[33m", "\033[31m",
                        "\033[2m", "\033[1m", "\033[0m")
else:
    G = Y = R = D = B = N = ""

TUNING_HELP = [
    ("MIN_BASELINE", "ниже скольких человек ноду не проверяем на обвал",
     "на ноде с пятью клиентами ноль ничего не доказывает"),
    ("COLLAPSE_RATIO", "доля от ожидаемого, ниже которой это обвал",
     "0.25 — упало ниже четверти нормы"),
    ("CONFIRM", "сколько проходов подряд держится условие до тревоги",
     "3 прохода это 3 минуты"),
    ("COOLDOWN", "не повторять тревогу об одной ноде чаще, секунд",
     "3600 — раз в час"),
    ("HEARTBEAT_HOUR", "час суточной сводки, по времени сервера", "12"),
    ("ALERT_SPARK_MIN", "окно спарклайна в тревоге, минут",
     "20 — на часовой шкале трёхминутный провал не разглядеть"),
]


def load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def save(cfg):
    """Пишем через временный файл с правами 600: в конфиге два токена, и он
    не должен ни мгновения побыть читаемым для всех."""
    tmp = CONFIG + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CONFIG)
    try:
        import pwd
        u = pwd.getpwnam(USER)
        os.chown(CONFIG, u.pw_uid, u.pw_gid)
    except Exception:
        pass


def mask(value):
    """Токен не печатаем даже владельцу: экран видит камера, снимок уходит в
    переписку. Хвоста хватает, чтобы отличить один токен от другого."""
    v = str(value or "").strip()
    return (G + "задан" + N + D + " (…%s)" % v[-4:] + N) if v else R + "не задан" + N


def module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("w", os.path.join(APP, "watchman.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def banner():
    host = subprocess.run(["hostname", "-s"], capture_output=True,
                          text=True).stdout.strip() or "?"
    print("  %s╦ ╦╔═╗╔╦╗╔═╗╦ ╦╔╦╗╔═╗╔╗╔%s   %sсторож тишины%s"
          % (G, N, D, N))
    print("  %s║║║╠═╣ ║ ║  ╠═╣║║║╠═╣║║║%s   %s🦨 SkunkBG%s" % (G, N, D, N))
    print("  %s╚╩╝╩ ╩ ╩ ╚═╝╩ ╩╩ ╩╩ ╩╝╚╝%s   %sсервер: %s%s%s"
          % (G, N, D, B, host, N))


def hr():
    print(D + "  " + "─" * 60 + N)


def title(text):
    os.system("clear")
    print()
    print("  " + B + text + N)
    hr()


def pause():
    input("\n  " + D + "Enter — назад " + N)


def unit_active(unit):
    """Состояние юнита. Отсутствие systemctl не должно ронять весь экран:
    меню обязано открыться и на машине, где что-то не так."""
    try:
        return subprocess.run(["systemctl", "is-active", unit],
                              capture_output=True, text=True).stdout.strip()
    except Exception:
        return "неизвестно"


def status_lines(cfg):
    """
    Состояние на главном экране — без единого обращения в сеть.

    Всё берётся из конфига и файла состояния. Запрос к панели на каждой
    перерисовке подвесил бы меню на таймаут ровно тогда, когда панель лежит,
    то есть в самый неподходящий момент.
    """
    st = load(STATE, {})
    nodes = st.get("nodes") or {}
    active = unit_active("watchman.timer") == "active"
    last = float(st.get("last_run") or 0)
    now = time.time()

    if active:
        if last:
            age = int(now - last)
            when = "%d с назад" % age if age < 120 else "%d мин назад" % (age // 60)
            # Проход раз в минуту. Если последний был давно, таймер включён,
            # но что-то мешает ему отработать — это важнее, чем «работает».
            colour = G if age < 180 else Y
            print("  🟢  Таймер %sработает%s   %sпоследний проход: %s%s%s"
                  % (G, N, D, colour, when, N))
        else:
            print("  🟡  Таймер %sвключён%s   %sни одного прохода ещё не было%s"
                  % (Y, N, D, N))
    else:
        print("  🔴  Таймер %sостановлен%s   %sтревоги не приходят%s" % (R, N, D, N))

    ready = all(str(cfg.get(k) or "").strip()
                for k in ("panel_url", "panel_token", "tg_token", "tg_chat"))
    if ready:
        watched = 0
        m = module()
        m.apply_tuning(cfg)
        for s in nodes.values():
            base = m.baseline_of(s.get("samples") or [], now)
            if base is not None and base >= m.MIN_BASELINE:
                watched += 1
        print("  🟢  Настройки %sзаполнены%s   %sнод: %s%d%s%s, под присмотром %s%d%s"
              % (G, N, D, B, len(nodes), N + D, N + D, B, watched, N))
    else:
        print("  🔴  Настройки %sне заполнены%s   %swatchman пока ничего не делает%s"
              % (R, N, D, N))

    alerts = int(st.get("alerts_today") or 0)
    hb = float(st.get("heartbeat") or 0)
    print("  %s    Тревог с последней сводки: %s%d%s   %sсводка: %s%s"
          % (D, B if alerts else D, alerts, N, D,
             time.strftime("%d.%m %H:%M", time.localtime(hb)) if hb else "ещё не было",
             N))


def ask(prompt, current="", secret=False):
    shown = mask(current) if secret else (current or D + "пусто" + N)
    print("\n  " + prompt)
    print("  %sсейчас:%s %s" % (D, N, shown))
    val = input("  %sновое значение (Enter — оставить):%s " % (D, N)).strip()
    return current if val == "" else val


def run_as_user(args):
    cmd = ["runuser", "-u", USER, "--"] + args if os.geteuid() == 0 else args
    try:
        return subprocess.call(cmd)
    except FileNotFoundError:
        return subprocess.call(args)


def screen_status():
    title("Состояние")
    print()
    run_as_user(["python3", os.path.join(APP, "watchman.py"), "--status"])
    pause()


def screen_panel(cfg):
    while True:
        title("Панель Remnawave")
        print("  Адрес : %s" % (cfg.get("panel_url") or D + "пусто" + N))
        print("  Токен : %s" % mask(cfg.get("panel_token")))
        print()
        print("  [1] Адрес")
        print("  [2] Токен")
        print("  [3] Проверить связь")
        print("  [0] Назад")
        c = input("\n  > ").strip()
        if c == "1":
            url = ask("Адрес панели, например https://admin.example.com",
                      cfg.get("panel_url", "")).strip().rstrip("/")
            # Хвост /api — ошибка, которая уже случалась: путь дописывается
            # сам, и получалось /api/api/nodes с ответом 404.
            if url.endswith("/api"):
                url = url[:-4].rstrip("/")
                print("  %sубрал /api с конца — путь дописывается сам%s" % (Y, N))
            if url and not url.startswith(("http://", "https://")):
                url = "https://" + url
                print("  %sдобавил https://%s" % (Y, N))
            cfg["panel_url"] = url
            save(cfg)
        elif c == "2":
            cfg["panel_token"] = ask("Токен панели с правом читать ноды",
                                     cfg.get("panel_token", ""), secret=True)
            save(cfg)
        elif c == "3":
            print()
            check_panel(cfg)
            pause()
        elif c == "0":
            return


def check_panel(cfg):
    try:
        nodes = module().panel_nodes(cfg)
        print("  %sсвязь есть%s: нод %d, на связи %d, людей %d"
              % (G, N, len(nodes), sum(1 for n in nodes if n.get("isConnected")),
                 sum(int(n.get("usersOnline") or 0) for n in nodes)))
    except Exception as e:
        code = getattr(e, "code", "")
        print("  %sне получилось%s: %s %s" % (R, N, type(e).__name__, code))
        if str(code) == "404":
            print("  %s404 бывает и при нехватке прав у токена, а не только"
                  " при неверном адресе%s" % (D, N))


def screen_telegram(cfg):
    while True:
        title("Telegram")
        print("  Токен бота : %s" % mask(cfg.get("tg_token")))
        print("  Чат        : %s" % (cfg.get("tg_chat") or D + "пусто" + N))
        print("  Тема       : %s" % (cfg.get("tg_thread") or D + "общий чат" + N))
        print("  Прокси     : %s" % (cfg.get("tg_proxy") or D + "напрямую" + N))
        print()
        print("  [1] Токен бота")
        print("  [2] Чат")
        print("  [3] Тема")
        print("  [4] Прокси")
        print("  [5] Проверить отправку")
        print("  [0] Назад")
        c = input("\n  > ").strip()
        if c == "1":
            cfg["tg_token"] = ask("Токен бота от @BotFather",
                                  cfg.get("tg_token", ""), secret=True)
        elif c == "2":
            cfg["tg_chat"] = ask("ID чата (для групп — со знаком минус)",
                                 cfg.get("tg_chat", ""))
        elif c == "3":
            cfg["tg_thread"] = ask("ID темы; пусто — писать в общий чат",
                                   cfg.get("tg_thread", ""))
        elif c == "4":
            # socks5 не поддержан намеренно: стандартная библиотека его не
            # умеет, а тащить зависимость ради редкого случая не стоит.
            cfg["tg_proxy"] = ask("Прокси http:// или https://, пусто — напрямую",
                                  cfg.get("tg_proxy", ""))
        elif c == "5":
            ok, err = module().tg_send(cfg, "🧪 <b>Watchman</b>: проверка связи")
            print("\n  " + (G + "сообщение отправлено" + N if ok else R + err + N))
            pause()
            continue
        elif c == "0":
            return
        save(cfg)


def screen_tuning(cfg):
    m = module()
    while True:
        tun = cfg.get("tuning") or {}
        title("Пороги")
        print("  %sПусто — работает умолчание, оно и показано.%s" % (D, N))
        print()
        for i, (key, what, hint) in enumerate(TUNING_HELP, 1):
            cur = tun.get(key, getattr(m, key))
            mark = "" if key in tun else D + "  (умолчание)" + N
            print("  [%d] %-16s %s%s%s%s" % (i, key, B, cur, N, mark))
            print("      %s%s; %s%s" % (D, what, hint, N))
        print()
        print("  [9] Вернуть все умолчания")
        print("  [0] Назад")
        c = input("\n  > ").strip()
        if c == "0":
            return
        if c == "9":
            cfg.pop("tuning", None)
            save(cfg)
            continue
        if not c.isdigit() or not 1 <= int(c) <= len(TUNING_HELP):
            continue
        key, what, hint = TUNING_HELP[int(c) - 1]
        default = getattr(m, key)
        print("\n  %s%s%s — %s" % (B, key, N, what))
        val = input("  новое значение (Enter — умолчание %s): " % default).strip()
        tun = dict(tun)
        if val == "":
            tun.pop(key, None)
        else:
            try:
                tun[key] = float(val) if isinstance(default, float) else int(val)
            except ValueError:
                print("  %sнужно число%s" % (R, N))
                pause()
                continue
        cfg["tuning"] = tun
        if not tun:
            cfg.pop("tuning", None)
        save(cfg)


def screen_service():
    while True:
        title("Служба и таймер")
        active = unit_active("watchman.timer")
        print("  Таймер: %s" % (G + "работает" + N if active == "active"
                                else R + active + N))
        print()
        subprocess.call(["systemctl", "list-timers", "watchman.timer", "--no-pager"])
        print()
        print("  [1] Включить")
        print("  [2] Выключить")
        print("  [3] Один проход сейчас, без отправки")
        print("  [0] Назад")
        c = input("\n  > ").strip()
        if c == "1":
            subprocess.call(["systemctl", "enable", "--now", "watchman.timer"])
        elif c == "2":
            # Выключение — не мелочь: пока таймер стоит, об авариях никто не
            # скажет. Поэтому спрашиваем прямо, а не молча выполняем.
            print("\n  %sПока таймер выключен, тревог не будет.%s" % (Y, N))
            if input("  Точно выключить? [y/N]: ").strip().lower() in ("y", "д"):
                subprocess.call(["systemctl", "disable", "--now", "watchman.timer"])
        elif c == "3":
            print()
            run_as_user(["python3", os.path.join(APP, "watchman.py"), "--dry-run"])
            pause()
        elif c == "0":
            return


def screen_demo():
    while True:
        title("Образцы сообщений")
        print("  В чат уйдут три образца: суточная сводка, обвал клиентов")
        print("  и потеря связи с нодой.")
        print()
        print("  %sНастоящее состояние watchman не портится: тревоги строятся%s" % (D, N))
        print("  %sна копии, файл состояния не трогается.%s" % (D, N))
        print()
        print("  [1] На ваших нодах — посмотреть, как это будет выглядеть")
        print("  [2] На выдуманных нодах — для снимков в документацию")
        print("  [0] Назад")
        c = input("\n  > ").strip()
        if c == "1":
            print()
            run_as_user(["python3", os.path.join(APP, "demo.py")])
            pause()
        elif c == "2":
            # Имена нод видны на снимке ровно так же, как в тексте, а
            # документация лежит в открытом репозитории. Поэтому для снимков
            # данные выдуманные, и панель при этом не опрашивается вовсе.
            print("\n  %sИмена нод будут выдуманные — такой снимок можно"
                  " публиковать.%s" % (D, N))
            print()
            run_as_user(["python3", os.path.join(APP, "demo.py"), "--public"])
            pause()
        elif c == "0":
            return


def main():
    if os.geteuid() != 0:
        print(R + "  нужен root: sudo watchman" + N)
        return 1
    while True:
        cfg = load(CONFIG, {})
        os.system("clear")
        print()
        banner()
        hr()
        status_lines(cfg)
        hr()
        print("""
  [1] Состояние по нодам
  [2] Панель Remnawave
  [3] Telegram
  [4] Пороги
  [5] Образцы сообщений
  [6] Служба и таймер
  [7] Журнал

  [0] Выход""")
        c = input("\n  > ").strip()
        if c == "1":
            screen_status()
        elif c == "2":
            screen_panel(cfg)
        elif c == "3":
            screen_telegram(cfg)
        elif c == "4":
            screen_tuning(cfg)
        elif c == "5":
            screen_demo()
        elif c == "6":
            screen_service()
        elif c == "7":
            title("Журнал")
            subprocess.call(["journalctl", "-u", "watchman.service",
                             "-n", "30", "--no-pager"])
            pause()
        elif c == "0":
            os.system("clear")
            return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        # Ctrl+C в меню — обычный способ выйти, а не происшествие.
        # Трассировка Python на экране пугает и ничего не сообщает.
        print()
        sys.exit(0)

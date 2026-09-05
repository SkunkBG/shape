#!/usr/bin/env python3
"""
Проверки обновления: состояние, оставшееся от старой версии, должно
читаться текущим кодом без потерь.

Зачем отдельный набор. Установщик запускать в CI нельзя — ему нужен root,
он ставит пакеты и регистрирует юниты. Но ломается при обновлении не
установщик, а чтение старого состояния: в конфиге нет полей, появившихся
позже, в штрафах лежит формат прошлой версии, идентификатора ноды ещё нет.
Здесь мы кладём в песочницу состояние в том виде, в каком его писала версия
3.4, и проверяем, что текущий Shape поднимает его целиком.

Отдельно проверяется единственное место установщика, которое может тихо
испортить ноду: создание node_id. Перезапись существующего файла порвала бы
историю метрик, и заметить это было бы нечем.
"""
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time

SRC = os.environ.get("SHAPE_SRC") or os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))

TMP = tempfile.mkdtemp(prefix="shape-upgrade-")
ETC = os.path.join(TMP, "etc"); os.makedirs(ETC)
VAR = os.path.join(TMP, "var"); os.makedirs(VAR)
BIN = os.path.join(TMP, "bin"); os.makedirs(BIN)
PIN = os.path.join(TMP, "maps"); os.makedirs(PIN)

with open(os.path.join(BIN, "bpftool"), "w") as f:
    f.write('#!/bin/sh\ncase "$*" in *dump*) echo "[]";; esac\nexit 0\n')
os.chmod(os.path.join(BIN, "bpftool"), 0o755)

os.environ["PATH"] = BIN + ":" + os.environ["PATH"]
os.environ["SHAPER_PIN_DIR"] = PIN
os.environ["SHAPE_ETC_DIR"] = ETC
os.environ["SHAPE_VAR_DIR"] = VAR
os.environ["SHAPE_APP_DIR"] = SRC

ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  \033[32m✓\033[0m {name}")
    else:
        fail += 1
        print(f"  \033[31m✗ {name}\033[0m {extra}")


# ─────────── состояние в том виде, в каком его писала версия 3.4 ───────────
# Ключевое отличие: в telegram нет backup/backup_thread_id/backup_day,
# в guard нет download_gb_per_hour, а файла node_id не существует вовсе.

OLD_CONFIG = {
    "ports": [443],
    "speed_mbps": 15,
    "guard": {
        "enabled": True,
        "score_needed": 3,
        "penalty_mbps": 1,
        "penalty_min": 60,
        "both_dl_percent": 50,
        "both_ul_percent": 15,
        "both_ways_min": 10,
        "packet_bytes": 600,
        "trigger_percent": 80,
        "sustain_min": 5,
        "hours_per_day": 4,
        "upload_gb_per_day": 2,
        "watch_interval": 10,
    },
    "telegram": {
        "enabled": True,
        "token": "123456789:" + "AABBccddeeFFgghhiijjkkllmmnnoopp",
        "chat_id": "-1001234567890",
        "thread_id": "42",
        "node_name": "Франкфурт-1",
        "events": True,
        "daily": True,
        "digest_at": "09:00",
        "proxy": "",
    },
}

with open(os.path.join(ETC, "config.json"), "w") as f:
    json.dump(OLD_CONFIG, f, indent=2)
os.chmod(os.path.join(ETC, "config.json"), 0o600)

with open(os.path.join(ETC, "whitelist.txt"), "w") as f:
    f.write("# белый список: по одному адресу в строке\n"
            "203.0.113.10\n198.51.100.7\n")

with open(os.path.join(ETC, "penalties.json"), "w") as f:
    json.dump({
        "203.0.113.50": {"mbps": 1, "until": time.time() + 3600,
                         "since": time.time() - 60, "source": "guard",
                         "reason": "packet,hours"},
        "203.0.113.51": {"mbps": 5, "until": time.time() + 9e5,
                         "since": time.time() - 86400, "kind": "personal",
                         "source": "manual", "reason": "друг"},
        "203.0.113.52": {"mbps": 1, "until": time.time() - 10, "source": "guard"},
    }, f)

with open(os.path.join(VAR, "owners.json"), "w") as f:
    json.dump({"203.0.113.50": {"label": "Александр", "user_id": "42",
                                "updated": 1750000000}}, f, ensure_ascii=False)

with open(os.path.join(VAR, "history.jsonl"), "w") as f:
    for day, down in (("2026-08-10", 111), ("2026-08-11", 222)):
        f.write(json.dumps({"day": day, "down": down, "up": 1, "ips": 3,
                            "limited": 1, "top": []}) + "\n")

with open(os.path.join(VAR, "events.jsonl"), "w") as f:
    f.write(json.dumps({"id": 1, "ts": time.time() - 100, "type": "limit_applied",
                        "ip": "203.0.113.50", "source": "guard"}) + "\n")

spec = importlib.util.spec_from_file_location("S", os.path.join(SRC, "shaperctl.py"))
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)

# ────────────────────────────────────────────────────────────────────
print("\n\033[1m1. Старый конфиг читается и дополняется умолчаниями\033[0m")
cfg = S.load_config()
check("скорость на месте", cfg["speed_mbps"] == 15)
check("порты на месте", cfg["ports"] == [443])
check("настройки сторожа сохранены", cfg["guard"]["penalty_min"] == 60)
check("подпись ноды сохранена", cfg["telegram"]["node_name"] == "Франкфурт-1")
check("тема отчётов сохранена", cfg["telegram"]["thread_id"] == "42")

missing_guard = [k for k in S.GUARD_DEFAULT if k not in OLD_CONFIG["guard"]]
check("в старом конфиге действительно не было новых полей сторожа",
      bool(missing_guard), str(missing_guard))
check("новые поля сторожа подставились из умолчаний",
      all(k in cfg["guard"] for k in S.GUARD_DEFAULT))

missing_tg = [k for k in S.TG_DEFAULT if k not in OLD_CONFIG["telegram"]]
check("в старом конфиге не было новых полей Telegram",
      "backup" in missing_tg, str(missing_tg))
check("отправка копии по умолчанию выключена",
      cfg["telegram"]["backup"] is False)
check("день отправки копии подставлен", cfg["telegram"]["backup_day"] == 1)

# Связь с панелью появилась позже: в старом конфиге раздела нет вовсе.
# Обновление обязано подставить его целиком и выключенным — нода, которая
# после обновления вдруг начала бы сама ходить в панель и резать людей, это
# худшее, что может сделать установщик.
check("в старом конфиге раздела панели не было", "panel" not in OLD_CONFIG)
check("раздел панели подставлен целиком",
      set(cfg["panel"]) == set(S.PANEL_DEFAULT), sorted(cfg["panel"]))
check("и он выключен", cfg["panel"]["enabled"] is False)
check("адрес и токен панели пусты",
      not cfg["panel"]["url"] and not cfg["panel"]["token"])
check("действие по умолчанию — только уведомить",
      S.panel_actions(cfg["panel"]) == {"notify"})

print("\n\033[1m2. Ограничения и персональные скорости выжили\033[0m")
pens = S.load_penalties()
check("действующий штраф на месте", "203.0.113.50" in pens)
check("персональная скорость на месте", "203.0.113.51" in pens)
check("персональная распознана как персональная",
      S.is_personal(pens["203.0.113.51"]))
check("истёкший штраф не воскрес", "203.0.113.52" not in pens)
check("причина ограничения сохранена",
      pens["203.0.113.50"].get("reason") == "packet,hours")

print("\n\033[1m3. Белый список, владельцы и история\033[0m")
check("белый список прочитан",
      S.whitelist_ips() == {"203.0.113.10", "198.51.100.7"}, S.whitelist_ips())
check("владелец прочитан",
      (S.owner_of("203.0.113.50") or {}).get("label") == "Александр")
rows = S.read_history(limit=400)
check("история прочитана целиком", len(rows) == 2, len(rows))
check("порядок истории сохранён",
      [r["day"] for r in rows] == ["2026-08-10", "2026-08-11"])
events, _ = S.read_events(limit=10)
check("журнал событий прочитан", len(events) == 1)

print("\n\033[1m4. Новое считается на старом состоянии\033[0m")
check("идентификатора ноды в старом состоянии не было",
      not os.path.exists(os.path.join(VAR, "node_id")))
nid = S.node_id()
check("идентификатор создан при первом обращении",
      re.fullmatch(r"[0-9a-f]{16}", nid) is not None, nid)
check("и он устойчив", S.node_id() == nid)
h = S.config_hash()
check("отпечаток считается", re.fullmatch(r"[0-9a-f]{12}", h) is not None, h)

metrics = S.build_metrics()
check("метрики строятся", "shape_up{" in metrics)
info = [ln for ln in metrics.splitlines() if ln.startswith("shape_info{")][0]
check("в метриках есть идентификатор", f'node_id="{nid}"' in info)
check("в метриках есть отпечаток", f'config_hash="{h}"' in info)
check("подпись ноды из старого конфига попала в метки",
      'node="Франкфурт-1"' in info, info)

print("\n\033[1m5. Резервная копия со старого состояния\033[0m")
dump = S.build_export(with_secrets=True)
check("выгрузка собирается", dump["kind"] == "shape-node-state")
state, problems = S.validate_export(dump)
check("выгрузка старого состояния проходит проверку без замечаний",
      problems == [], str(problems))
check("белый список попал в выгрузку", len(state["whitelist"]) == 2)
check("владельцы попали в выгрузку", "203.0.113.50" in state["owners"])
done = S.apply_import(state, keep_secrets=False)
check("восстановление проходит", sorted(done) == sorted(S.EXPORT_SECTIONS))
check("после восстановления идентификатор прежний", S.node_id() == nid)
check("после восстановления отпечаток прежний", S.config_hash() == h)

print("\n\033[1m6. Установщик не перезаписывает идентификатор ноды\033[0m")
# Берём кусок из настоящего install.sh, а не переписываем его логику здесь:
# проверять надо то, что поедет на ноды.
inst = io.open(os.path.join(SRC, "install.sh"), encoding="utf-8").read()
m = re.search(r'if \[\[ ! -s /var/lib/shape/node_id \]\]; then\n(.*?)\nfi',
              inst, re.S)
check("фрагмент создания идентификатора найден в install.sh", m is not None)

if m:
    sandbox = os.path.join(TMP, "installer")
    os.makedirs(sandbox, exist_ok=True)
    snippet = m.group(0).replace("/var/lib/shape", sandbox)
    script = "set -euo pipefail\n" + snippet + "\n"

    subprocess.run(["bash", "-c", script], check=True)
    first = io.open(os.path.join(sandbox, "node_id")).read().strip()
    check("идентификатор создаётся при первой установке",
          re.fullmatch(r"[0-9a-f]{16}", first) is not None, first)

    subprocess.run(["bash", "-c", script], check=True)
    second = io.open(os.path.join(sandbox, "node_id")).read().strip()
    check("повторная установка его не трогает", first == second,
          f"{first} → {second}")

    mode = oct(os.stat(os.path.join(sandbox, "node_id")).st_mode & 0o777)
    check("права на файле 644", mode == "0o644", mode)

    # Пустой файл — это не идентификатор: его надо заполнить.
    io.open(os.path.join(sandbox, "node_id"), "w").write("")
    subprocess.run(["bash", "-c", script], check=True)
    third = io.open(os.path.join(sandbox, "node_id")).read().strip()
    check("пустой файл заполняется заново",
          re.fullmatch(r"[0-9a-f]{16}", third) is not None, third)

    check("формат совпадает с тем, что ждёт код",
          re.fullmatch(r"[0-9a-f]{16}", third) is not None)

print("\n\033[1m7. Версия в файлах согласована\033[0m")
version = io.open(os.path.join(SRC, "VERSION"), encoding="utf-8").read().strip()
check("VERSION непустой", bool(version), version)
for name, pattern in (("README.md", r"^# Shape v" + re.escape(version) + r"$"),
                      ("README.en.md", r"^# Shape v" + re.escape(version) + r"$"),
                      ("CHANGELOG.md", r"^## " + re.escape(version) + r"$"),
                      ("CHANGELOG.en.md", r"^## " + re.escape(version) + r"$")):
    text = io.open(os.path.join(SRC, name), encoding="utf-8").read()
    check(f"{name} говорит про {version}",
          re.search(pattern, text, re.M) is not None)

print(f"\n\033[1mИтог: {ok} пройдено, {fail} провалено\033[0m")
sys.exit(1 if fail else 0)

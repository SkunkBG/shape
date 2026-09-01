#!/usr/bin/env bash
# Главная проверка после добавления API: Shape остаётся самостоятельным.
set -uo pipefail
SRC="${SHAPE_SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ok=0; fail=0
G='\033[32m'; R='\033[31m'; B='\033[1m'; N='\033[0m'
check() { if eval "$2"; then ok=$((ok+1)); echo -e "  ${G}✓${N} $1"
          else fail=$((fail+1)); echo -e "  ${R}✗ $1${N}"; fi; }

echo -e "\n${B}1. Shape не зависит от API на уровне кода${N}"
check "shaperctl.py не упоминает api/server.py" \
      '! grep -q "api/server" "$SRC/shaperctl.py"'
check "shaperctl.py не импортирует модуль API" \
      '! grep -qE "^import (api|server)|from api" "$SRC/shaperctl.py"'
check "engine.sh не обращается к API" '! grep -q "shape-api" "$SRC/engine.sh"'
check "menu.sh работает и без каталога api (проверка наличия файла)" \
      'grep -q "api/server.py.*\]\]" "$SRC/menu.sh"'
check "API импортирует Shape, а не наоборот" \
      'grep -q "load_shape" "$SRC/api/server.py"'

echo -e "\n${B}2. Зависимости systemd развязаны${N}"
check "shape-api.service не содержит Requires" \
      '! grep -qE "^(Requires|BindsTo|PartOf)=" "$SRC/systemd/shape-api.service"'
check "shape-api.service лишь After=shaper.service" \
      'grep -q "^After=.*shaper.service" "$SRC/systemd/shape-api.service"'
check "shaper.service ничего не знает про API" \
      '! grep -q "api" "$SRC/systemd/shaper.service"'
check "shaper-watch.service ничего не знает про API" \
      '! grep -q "api" "$SRC/systemd/shaper-watch.service"'
check "у API есть автоперезапуск" 'grep -q "^Restart=always" "$SRC/systemd/shape-api.service"'
check "API слушает локально по умолчанию" \
      'grep -q "\"bind_address\": \"127.0.0.1\"" "$SRC/api/server.py"'

echo -e "\n${B}3. Установка: API опционален${N}"
check "install.sh понимает --with-api" 'grep -q -- "--with-api" "$SRC/install.sh"'
check "install.sh понимает --uninstall-api" 'grep -q -- "--uninstall-api" "$SRC/install.sh"'
check "без флага сервис API не включается" \
      'grep -A2 "if (( WITH_API ))" "$SRC/install.sh" | grep -q "step"'
check "удаление API не трогает shaper.service" \
      '! sed -n "/uninstall-api/,/^fi/p" "$SRC/install.sh" | grep -qE "disable.*shaper\b|rm.*shaper.service"'
# Полное удаление живёт в uninstall.sh — туда и смотрим. Важно, что API
# снимается вместе со всем остальным: оставленный сервис продолжал бы
# слушать порт на ноде, с которой Shape уже удалён.
check "полное удаление останавливает службу API" \
      'grep -q "shape-api" "$SRC/uninstall.sh"'
check "полное удаление убирает юнит API" \
      'grep -q "shape-api.service" "$SRC/uninstall.sh"'
check "установщик передаёт удаление в uninstall.sh" \
      'sed -n "/== \"--uninstall\"/,/^fi/p" "$SRC/install.sh" | grep -q "uninstall.sh"'

echo -e "\n${B}4. Shape работает при отсутствующем каталоге api${N}"
TMP="$(mktemp -d)"
cp -r "$SRC" "$TMP/shape"
rm -rf "$TMP/shape/api"                      # имитируем «API удалён»
check "shaperctl.py компилируется без каталога api" \
      "python3 -m py_compile '$TMP/shape/shaperctl.py'"
check "menu.sh синтаксически цел без каталога api" "bash -n '$TMP/shape/menu.sh'"
check "engine.sh синтаксически цел без каталога api" "bash -n '$TMP/shape/engine.sh'"

# CLI Shape в песочнице без API: настройки, штрафы, события
export SHAPER_PIN_DIR="$TMP/maps"; mkdir -p "$SHAPER_PIN_DIR"
touch "$SHAPER_PIN_DIR/config_map"
export BPFTOOL_LOG="$TMP/bpftool.log"
mkdir -p "$TMP/bin"
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "$BPFTOOL_LOG"\ncase "$*" in *dump*) echo "[]";; esac\nexit 0\n' > "$TMP/bin/bpftool"
chmod +x "$TMP/bin/bpftool"; export PATH="$TMP/bin:$PATH"

out="$(python3 - "$TMP" <<'PYEOF'
import importlib.util, json, os, sys, time
tmp = sys.argv[1]
spec = importlib.util.spec_from_file_location("s", os.path.join(tmp, "shape", "shaperctl.py"))
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
etc = os.path.join(tmp, "etc"); os.makedirs(etc, exist_ok=True)
S.ETC_DIR = etc
S.CONFIG_FILE = os.path.join(etc, "config.json")
S.PEN_FILE = os.path.join(etc, "penalties.json")
S.VAR_DIR = os.path.join(tmp, "var")
S.EVENT_FILE = os.path.join(S.VAR_DIR, "events.jsonl")
S.EVENT_SEQ = os.path.join(S.VAR_DIR, "events.seq")
S.save_config({"ports": [443], "speed_mbps": 20, "guard": dict(S.GUARD_DEFAULT),
               "telegram": dict(S.TG_DEFAULT)})
S.penalties_update(lambda p: p.__setitem__(
    "203.0.113.99", {"until": time.time() + 60, "mbps": 1, "since": time.time()}))
S.log_event("limit_applied", ip="203.0.113.99", source="cli")
ev, _ = S.read_events(limit=5)
print(json.dumps({
    "speed": S.load_config()["speed_mbps"],
    "pens": list(S.load_penalties()),
    "events": len(ev),
}))
PYEOF
)"
check "конфиг читается и пишется без API" '[[ "$(echo "$out" | python3 -c "import json,sys;print(json.load(sys.stdin)[\"speed\"])")" == "20.0" ]]'
check "штраф ставится без API" '[[ "$out" == *203.0.113.99* ]]'
check "события пишутся без API" '[[ "$(echo "$out" | python3 -c "import json,sys;print(json.load(sys.stdin)[\"events\"])")" -ge 1 ]]'
rm -rf "$TMP"

echo -e "\n${B}5. Одинаковая установка на разных нодах${N}"
check "порт не привязан к имени хоста" \
      '! grep -qE "hostname|uname\(\).nodename" "$SRC/api/server.py" || ! grep -q "port.*hostname" "$SRC/api/server.py"'
check "токены генерируются на ноде, а не зашиты в код" \
      'grep -q "secrets.token_urlsafe" "$SRC/api/server.py"'
check "в репозитории нет ни одного токена" \
      '! grep -rqE "\"(read|write)\": \"[A-Za-z0-9_-]{20,}\"" "$SRC"'
check "api.json в .gitignore не нужен — он живёт в /etc" \
      'grep -q "/etc/shaper" "$SRC/api/server.py"'
# Смысл проверки — ноды не связаны общим ключом или общим состоянием.
# Собственный идентификатор у ноды при этом быть должен: без него история
# метрик рвётся при переезде. Важно, что он случайный и локальный.
check "нет общих для нод идентификаторов" \
      '! grep -qiE "cluster_id|global_state|shared_secret" "$SRC/api/server.py"'
check "идентификатор ноды генерируется случайно на самой ноде" \
      'grep -A32 "^def node_id" "$SRC/shaperctl.py" | grep -q "os.urandom"'
# Комментарий про machine-id в коде есть — важно, что файл не читается:
# у нод, развёрнутых из одного образа, machine-id совпадает.
check "идентификатор не выводится из machine-id — у клонов он одинаковый" \
      '! grep -q "/etc/machine-id" "$SRC/shaperctl.py"'
check "идентификатор не уезжает в выгрузку состояния" \
      '! grep -q "node_id" <<< "$(grep -A3 "^EXPORT_SECTIONS" "$SRC/shaperctl.py")"'

echo -e "\n${B}Итог: $ok пройдено, $fail провалено${N}"
[[ $fail -eq 0 ]]

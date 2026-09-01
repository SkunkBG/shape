#!/usr/bin/env bash
# Проверки удаления Shape.
#
# Скрипт разрушительный, поэтому гоняем его целиком в песочнице: пути берутся
# из SHAPE_*_DIR, systemctl и tc подменены заглушками. Проверять такое грепом
# по исходнику — самообман: важен не текст, а порядок действий и то, что
# осталось на диске.
set -uo pipefail

SRC="${SHAPE_SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
G='\033[32m'; R='\033[31m'; B='\033[1m'; N='\033[0m'
ok=0; fail=0

check() {
    if eval "$2"; then
        ok=$((ok+1)); echo -e "  ${G}✓${N} $1"
    else
        fail=$((fail+1)); echo -e "  ${R}✗ $1${N} ${3:-}"
    fi
}

TMP="$(mktemp -d -t shape-uninstall-tests.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

# ── песочница: подставные systemctl и tc, они же пишут журнал вызовов ──
BIN="$TMP/bin"; mkdir -p "$BIN"
cat > "$BIN/systemctl" <<'EOF'
#!/bin/sh
printf 'systemctl %s\n' "$*" >> "$CALL_LOG"
exit 0
EOF
cat > "$BIN/tc" <<'EOF'
#!/bin/sh
printf 'tc %s\n' "$*" >> "$CALL_LOG"
exit 0
EOF
chmod +x "$BIN/systemctl" "$BIN/tc"
export PATH="$BIN:$PATH"

# ── разворачиваем «установленный» Shape ──
setup() {
    local root="$1"
    rm -rf "$root"; mkdir -p "$root"/{opt,etc,var,units,collector}
    mkdir -p "$root/opt/bpf"

    # engine.sh, который отмечается в журнале — так видно порядок шагов
    cat > "$root/opt/engine.sh" <<'EOF'
#!/bin/sh
printf 'engine %s\n' "$*" >> "$CALL_LOG"
exit 0
EOF
    chmod +x "$root/opt/engine.sh"
    cp "$SRC/uninstall.sh" "$root/opt/uninstall.sh"
    chmod +x "$root/opt/uninstall.sh"
    echo "3.11" > "$root/opt/VERSION"

    # lo существует на любой машине — на нём и проверяем снятие фильтров
    printf 'IFACE="lo"\n' > "$root/etc/.active_iface"
    printf '{"speed_mbps": 10}\n' > "$root/etc/config.json"
    printf 'SHAPE_TEXTFILE=%s/shape.prom\n' "$root/collector" > "$root/etc/metrics.env"
    printf '# метрики ноды\nshape_up{node="x"} 1\n' > "$root/collector/shape.prom"

    printf 'abcdef0123456789\n' > "$root/var/node_id"
    printf '{"day":"2026-01-01"}\n' > "$root/var/history.jsonl"

    for u in shaper.service shaper-watch.service shape-api.service \
             shape-metrics.service shape-metrics.timer shape-tunnel.service; do
        printf '[Unit]\n' > "$root/units/$u"
    done
    printf 'shaper\n' > "$root/bin-shaper"
}

run_uninstall() {
    local root="$1"; shift
    SHAPE_APP_DIR="$root/opt" \
    SHAPE_ETC_DIR="$root/etc" \
    SHAPE_VAR_DIR="$root/var" \
    SHAPE_UNIT_DIR="$root/units" \
    SHAPER_PIN_ROOT="$root/pin" \
    SHAPE_BIN="$root/bin-shaper" \
    CALL_LOG="$CALL_LOG" \
    bash "$root/opt/uninstall.sh" "$@" > "$root/output.txt" 2>&1
}

echo -e "\n${B}1. Обычное удаление: программа снимается, настройки остаются${N}"
ROOT="$TMP/case1"
export CALL_LOG="$TMP/calls1.log"; : > "$CALL_LOG"
setup "$ROOT"
mkdir -p "$ROOT/pin/maps"
run_uninstall "$ROOT"
rc=$?

check "скрипт отработал без ошибки" '[[ '"$rc"' -eq 0 ]]' "код $rc"
check "каталог программы удалён" '[[ ! -d "'"$ROOT"'/opt" ]]'
check "команда shaper удалена" '[[ ! -e "'"$ROOT"'/bin-shaper" ]]'
check "юниты удалены" '[[ -z "$(ls -A "'"$ROOT"'/units" 2>/dev/null)" ]]' \
      "$(ls -A "$ROOT/units" 2>/dev/null)"
check "закреплённые карты убраны" '[[ ! -d "'"$ROOT"'/pin" ]]'
check "настройки оставлены" '[[ -f "'"$ROOT"'/etc/config.json" ]]'
check "идентификатор ноды оставлен" '[[ -f "'"$ROOT"'/var/node_id" ]]'
check "история оставлена" '[[ -f "'"$ROOT"'/var/history.jsonl" ]]'

echo -e "\n${B}2. Файл метрик убран — иначе Prometheus считает ноду живой${N}"
check "shape.prom удалён" '[[ ! -f "'"$ROOT"'/collector/shape.prom" ]]'
check "каталог сборщика не тронут" '[[ -d "'"$ROOT"'/collector" ]]'

echo -e "\n${B}3. Порядок шагов${N}"
# Самое важное: снять eBPF надо, пока файлы на месте. Если engine.sh вызвали
# после удаления каталога, программа осталась бы висеть на интерфейсе.
check "engine.sh unload вызван" 'grep -q "^engine unload$" "$CALL_LOG"'
check "службы остановлены до снятия с интерфейса" \
      '[[ $(grep -n "systemctl disable" "$CALL_LOG" | head -1 | cut -d: -f1) \
          -lt $(grep -n "^engine unload$" "$CALL_LOG" | head -1 | cut -d: -f1) ]]'
check "сторож остановлен" 'grep -q "systemctl disable --now shaper-watch" "$CALL_LOG"'
check "движок остановлен" 'grep -q "systemctl disable --now shaper" "$CALL_LOG"'
check "API остановлен" 'grep -q "systemctl disable --now shape-api" "$CALL_LOG"'
check "таймер метрик остановлен" \
      'grep -q "systemctl disable --now shape-metrics.timer" "$CALL_LOG"'
check "systemd перечитал юниты" 'grep -q "systemctl daemon-reload" "$CALL_LOG"'
check "фильтры сняты с интерфейса из .active_iface" \
      'grep -q "tc filter del dev lo egress" "$CALL_LOG"'
check "clsact снят" 'grep -q "tc qdisc del dev lo clsact" "$CALL_LOG"'
check "корневой qdisc не трогали" '! grep -q "qdisc del dev lo root" "$CALL_LOG"'

echo -e "\n${B}4. Режим --purge удаляет и настройки${N}"
ROOT="$TMP/case2"
export CALL_LOG="$TMP/calls2.log"; : > "$CALL_LOG"
setup "$ROOT"
run_uninstall "$ROOT" --purge
check "программа удалена" '[[ ! -d "'"$ROOT"'/opt" ]]'
check "настройки удалены" '[[ ! -d "'"$ROOT"'/etc" ]]'
check "состояние удалено" '[[ ! -d "'"$ROOT"'/var" ]]'
check "файл метрик всё равно убран" '[[ ! -f "'"$ROOT"'/collector/shape.prom" ]]'

echo -e "\n${B}5. Скрипт переживает удаление собственного каталога${N}"
# uninstall.sh лежит внутри /opt/shaper и удаляет его же. Bash дочитывает
# файл по ходу выполнения, поэтому скрипт обязан работать с копией.
ROOT="$TMP/case3"
export CALL_LOG="$TMP/calls3.log"; : > "$CALL_LOG"
setup "$ROOT"
run_uninstall "$ROOT"
check "дошёл до конца, несмотря на самоудаление" \
      'grep -q "Готово" "'"$ROOT"'/output.txt"' "$(tail -3 "$ROOT/output.txt")"
check "временная копия за собой убрана" \
      '[[ -z "$(ls /tmp/shape-uninstall.* 2>/dev/null)" ]]' \
      "$(ls /tmp/shape-uninstall.* 2>/dev/null)"

echo -e "\n${B}6. Работает и без установленного engine.sh${N}"
ROOT="$TMP/case4"
export CALL_LOG="$TMP/calls4.log"; : > "$CALL_LOG"
setup "$ROOT"
rm -f "$ROOT/opt/engine.sh"
run_uninstall "$ROOT"; rc=$?
check "скрипт не упал" '[[ '"$rc"' -eq 0 ]]' "код $rc"
check "фильтры всё равно сняты вручную" \
      'grep -q "tc filter del dev lo ingress" "$CALL_LOG"'
check "каталог программы удалён" '[[ ! -d "'"$ROOT"'/opt" ]]'

echo -e "\n${B}7. Одна реализация удаления${N}"
# Установщик не должен снимать то, что принадлежит удалению. Откат неудачной
# сборки он делает своим rm -rf, и цепляться за него здесь было бы неверно —
# смотрим на юниты и команду, которые убирает только uninstall.sh.
check "install.sh не снимает юниты движка сам" \
      '! grep -qE "rm -f.*(shaper\.service|shaper-watch\.service)" "$SRC/install.sh"'
check "install.sh не удаляет команду shaper сам" \
      '! grep -qE "rm -f.*/usr/local/bin/shaper" "$SRC/install.sh"'

# Живой случай: подсказка в Telegram советовала «shaperctl.py panel show», а
# такой команды не было — файл лежит в /opt/shaper и в PATH не входит.
check "установщик кладёт вторую команду в PATH" \
      'grep -q "/usr/local/bin/shaperctl" "$SRC/install.sh"'
check "и псевдоним с .py для старых записей" \
      'grep -q "ln -sf /usr/local/bin/shaperctl /usr/local/bin/shaperctl.py" "$SRC/install.sh"'
check "удаление уносит обе" \
      'grep -q "/usr/local/bin/shaperctl /usr/local/bin/shaperctl.py" "$SRC/uninstall.sh"'
check "подсказка советует существующую команду" \
      '! grep -q "<code>shaperctl.py panel show</code>" "$SRC/shaperctl.py"'
check "install.sh --uninstall делегирует" \
      'grep -A6 "\-\-uninstall\"" "$SRC/install.sh" | grep -q "uninstall.sh"'
check "установщик кладёт uninstall.sh на ноду" \
      'grep -q "install -m 755 .*uninstall.sh" "$SRC/install.sh"'
check "меню зовёт тот же файл" \
      'grep -q "uninstall.sh" "$SRC/menu.sh"'
check "в меню есть пункт удаления" \
      'grep -q "screen_uninstall" "$SRC/menu.sh"'
check "удаление требует ввода слова, а не y/N" \
      'grep -q "un_word" "$SRC/menu.sh"'

echo -e "\n${B}Экран удаления: переключатель проверяется запуском${N}"
# Живой случай: [2] «Удалить заодно настройки и историю» выглядел сломанным.
# Механизм работал, но пункт не показывал своего состояния — человек нажимал,
# экран перерисовывался почти без изменений, и казалось, что ничего не вышло.
# Грепом такое не поймать: строка на месте. Поэтому — вызов функции.
render_un() {   # $1 — purge, $2 — язык
    bash -c '
        R=""; G=""; D=""; N=""; B=""; Y=""
        hr() { :; }
        source '"$SRC"'/lang.sh
        ui_lang_load '"$2"'
        eval "$(sed -n "/^uninstall_menu()/,/^}/p" '"$SRC"'/menu.sh)"
        uninstall_menu '"$1"'
    ' 2>/dev/null
}

for lang in ru en; do
    OFF="$(render_un 0 "$lang")"
    ON="$(render_un 1 "$lang")"
    check "[$lang] экран рисуется в обоих состояниях" \
          '[[ -n "'"$OFF"'" && -n "'"$ON"'" ]]'
    check "[$lang] состояние переключателя видно: экраны различаются" \
          '[[ "'"$OFF"'" != "'"$ON"'" ]]'
    check "[$lang] у пункта [2] есть значение после двоеточия" \
          'echo "'"$OFF"'" | grep -qE "^  \[2\] .+: +[^ ]"'
    check "[$lang] и во включённом состоянии тоже" \
          'echo "'"$ON"'" | grep -qE "^  \[2\] .+: +[^ ]"'
    check "[$lang] строка [2] меняется вместе с переключателем" \
          '[[ "$(echo "'"$OFF"'" | sed -n "/\[2\]/p")" \
             != "$(echo "'"$ON"'" | sed -n "/\[2\]/p")" ]]'
    check "[$lang] строка [3] меняется вместе с переключателем" \
          '[[ "$(echo "'"$OFF"'" | sed -n "/\[3\]/p")" \
             != "$(echo "'"$ON"'" | sed -n "/\[3\]/p")" ]]'
    check "[$lang] пункты 1,2,3,0 на месте в обоих состояниях" \
          'for i in 1 2 3 0; do
               echo "'"$OFF"'" | grep -q "\[$i\]" || exit 1
               echo "'"$ON"'"  | grep -q "\[$i\]" || exit 1
           done'
    check "[$lang] ни одного пункта, обрывающегося на двоеточии" \
          '! printf "%s\n%s\n" "'"$OFF"'" "'"$ON"'" \
             | grep -E "^  \[[0-9]\]" | grep -qE ": *$"'
done

check "по умолчанию удаление настроек выключено" \
      'grep -q "local purge=0" "$SRC/menu.sh"'
check "нажатие [2] переключает, а не удаляет" \
      'grep -q "2) purge=" "$SRC/menu.sh"'
check "--purge уходит в uninstall.sh только при включённом переключателе" \
      'grep -B2 -e "--purge" "$SRC/menu.sh" | grep -q "if (( purge ))"'
check "и без переключателя вызывается без --purge" \
      'grep -A2 -e "--purge" "$SRC/menu.sh" | grep -qE "uninstall\\.sh\"$"'

echo -e "\n${B}Строки интерфейса: русский и английский в паре${N}"
# Ключ, добавленный в один блок и забытый в другом, даёт пустое место на
# экране вместо текста — и только на одном языке, то есть незаметно.
PARITY="$(python3 "$SRC/tests/lang_parity.py" "$SRC/lang.sh")"
check "у каждого ключа есть перевод" '[[ "'"$PARITY"'" == "ok" ]]' "разошлись: $PARITY"

echo -e "\n${B}Итог: $ok пройдено, $fail провалено${N}"
[[ $fail -eq 0 ]]

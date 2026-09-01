#!/usr/bin/env bash
# Строка состояния на главном экране — проверка запуском, а не поиском строк.
#
# Живой случай: пункты меню были на экране, а обработчики в другой функции.
# grep по файлу такое не видит. Здесь функция действительно вызывается на
# подставном конфиге, и проверяется то, что она напечатала.
set -u
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0
G=$'\e[32m'; R=$'\e[31m'; N=$'\e[0m'

check() {
    if eval "$2" >/dev/null 2>&1; then
        echo -e "  ${G}✓${N} $1"; PASS=$((PASS+1))
    else
        echo -e "  ${R}✗ $1${N}"; FAIL=$((FAIL+1))
    fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/etc" "$TMP/app"
cp "$SRC/menu.sh" "$SRC/lang.sh" "$TMP/app/"

run_status() {   # $1 — json конфига
    printf '%s' "$1" > "$TMP/etc/config.json"
    APP_DIR="$TMP/app" ETC_DIR="$TMP/etc" ENGINE=/bin/false UI_LANG=ru \
    bash -c '
        G=""; R=""; Y=""; B=""; D=""; N=""
        APP_DIR='"$TMP"'/app; ETC_DIR='"$TMP"'/etc; ENGINE=/bin/false
        source '"$TMP"'/app/lang.sh
        ui_lang_load ru
        eval "$(sed -n "/^read_state()/,/^}/p" '"$TMP"'/app/menu.sh)"
        eval "$(sed -n "/^links_state()/,/^}/p" '"$TMP"'/app/menu.sh)"
        eval "$(sed -n "/^status_line()/,/^}/p" '"$TMP"'/app/menu.sh)"
        status_line
    ' 2>/dev/null
}

echo -e "\n\033[1mСтрока состояния: всё включено\033[0m"
ON='{"ports":[443],"speed_mbps":50,"guard":{"enabled":false},
 "telegram":{"enabled":true,"token":"1:AA","chat_id":"-100","node_name":"Node-1"},
 "panel":{"enabled":true,"token":"t","node_uuid":"u","disable_after_min":60}}'
OUT="$(run_status "$ON")"
check "Telegram показан включённым"  '[[ "$OUT" == *"Telegram"* && "$OUT" == *"включён"* ]]'
check "и с подписью ноды"            '[[ "$OUT" == *"Node-1"* ]]'
check "панель показана подключённой" '[[ "$OUT" == *"подключена"* ]]'
check "и отсрочка отключения видна"  '[[ "$OUT" == *"60"* ]]'
check "API показан"                  '[[ "$OUT" == *"API"* ]]'
check "строк состояния восемь"       '[[ $(printf "%s" "$OUT" | grep -c .) -eq 8 ]]'

echo -e "\n\033[1mВсё выключено\033[0m"
OFF='{"ports":[443],"speed_mbps":50,"guard":{"enabled":false},
 "telegram":{"enabled":false},"panel":{"enabled":false}}'
OUT="$(run_status "$OFF")"
check "Telegram выключен"     '[[ "$OUT" == *"уведомления никуда не уходят"* ]]'
check "панель выключена"      '[[ "$OUT" == *"раздачу подписки не ищем"* ]]'
check "про отсрочку молчим"   '[[ "$OUT" != *"отключает подписку через"* ]]'

echo -e "\n\033[1mВключено, но не настроено\033[0m"
# Половина настройки хуже, чем ничего: человек уверен, что работает.
HALF='{"ports":[443],"speed_mbps":50,"guard":{"enabled":false},
 "telegram":{"enabled":true,"token":"","chat_id":""},
 "panel":{"enabled":true,"token":"","node_uuid":""}}'
OUT="$(run_status "$HALF")"
check "Telegram без токена — выключен"  '[[ "$OUT" == *"уведомления никуда не уходят"* ]]'
check "панель без UUID — выключена"     '[[ "$OUT" == *"раздачу подписки не ищем"* ]]'

echo -e "\n\033[1mБитый конфиг\033[0m"
OUT="$(run_status '{ не json')"
check "строка состояния всё равно печатается" '[[ $(printf "%s" "$OUT" | grep -c .) -eq 8 ]]'
check "и ничего не включено"                  '[[ "$OUT" == *"раздачу подписки не ищем"* ]]'

echo -e "\n\033[1mПункты меню и обработчики\033[0m"
check "у каждого пункта есть ветка в том же экране" \
      'python3 "$SRC/tests/menu_wiring.py" "$SRC/menu.sh"'

echo
echo -e "\033[1mИтог: $PASS пройдено, $FAIL провалено\033[0m"
[[ $FAIL -eq 0 ]]

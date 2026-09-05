#!/usr/bin/env bash
# menu.sh — текстовый интерфейс шейпера. Запускается командой `shaper`.
set -uo pipefail

APP_DIR="/opt/shaper"
ETC_DIR="/etc/shaper"
CONF="$ETC_DIR/shaper.conf"
CTL="$APP_DIR/shaperctl.py"
ENGINE="$APP_DIR/engine.sh"
REPO_URL="https://github.com/SkunkBG/shape.git"
DONATE_URL="https://web.tribute.tg/d/OHz"
VERSION="$(cat "$APP_DIR/VERSION" 2>/dev/null || echo '?')"

B='\033[1m'; N='\033[0m'; D='\033[90m'
G='\033[32m'; R='\033[31m'; Y='\033[33m'; C='\033[36m'

# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"
UI_LANG="${UI_LANG:-}"

# shellcheck disable=SC1090
source "$APP_DIR/lang.sh"
ui_lang_load "${UI_LANG:-ru}"

[[ $EUID -eq 0 ]] || { echo -e "${R}${T[need_root]}${N}"; exit 1; }

# Шрифтовой знак вместо картинки: рисовать скунса псевдографикой в терминале
# смысла нет, а стоимость вывода нулевая — это статический текст.
banner() {
    local host; host="$(hostname -s 2>/dev/null || echo '?')"
    echo -e "  ${G}╔═╗╦ ╦╔═╗╔═╗╔═╗${N}   ${D}v$VERSION ${T[subtitle]}${N}"
    echo -e "  ${G}╚═╗╠═╣╠═╣╠═╝║╣ ${N}   ${D}🦨 SkunkBG${N}"
    echo -e "  ${G}╚═╝╩ ╩╩ ╩╩  ╚═╝${N}   ${D}${T[node]}: ${B}${host}${N}"
}

hr()    { echo -e "${D}  ────────────────────────────────────────────────────────────${N}"; }
title() { clear; echo; echo -e "  ${B}$1${N}"; hr; }
pause() { echo; read -rsp "  ${T[back]} " _; }
ask()   { local p="$1" d="${2:-}" v; read -rp "  $p${d:+ [$d]}: " v; echo "${v:-$d}"; }
cfg()   { python3 -c "
import json, sys
# Значения приходят аргументами, а не подстановкой в текст программы: одинарная
# кавычка в ключе или в умолчании иначе закрыла бы строку, и всё, что дальше,
# выполнилось бы от root. Сейчас все вызовы передают литералы, но защита не
# должна держаться на дисциплине вызывающих.
try: c = json.load(open(sys.argv[1]))
except Exception: c = {}
print(c.get(sys.argv[2], sys.argv[3]))" "$ETC_DIR/config.json" "$1" "$2" 2>/dev/null || echo "$2"; }

# shaper.conf читается через `source` и в меню, и в engine.sh — то есть его
# содержимое выполняется от root при каждом старте сервиса. Значит в файл не
# должно попасть ничего, кроме простого KEY="значение": кавычка внутри
# значения разорвала бы строку и всё, что дальше, стало бы командой.
# Поэтому: ключ — только буквы и подчёркивания, значение — без спецсимволов,
# запись через awk, а не sed (в sed «&» и «|» в замене имеют свой смысл).
conf_safe() { [[ "$1" =~ ^[A-Za-z0-9_.:@/-]*$ ]]; }

conf_set() {
    local key="$1" val="$2"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 1
    conf_safe "$val" || return 1
    touch "$CONF"; chmod 600 "$CONF" 2>/dev/null
    local tmp; tmp="$(mktemp "${CONF}.XXXXXX")" || return 1
    awk -v k="$key" -v v="$val" '
        $0 ~ "^"k"=" { if (!done) { print k"=\"" v "\""; done=1 } ; next }
        { print }
        END { if (!done) print k"=\"" v "\"" }
    ' "$CONF" > "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$CONF"
}

# ── Выбор языка ───────────────────────────────────────────────────────
screen_lang() {
    clear; echo
    banner
    hr
    echo -e "  ${B}Выбери язык / Choose language${N}"
    echo
    echo "  [1] 🇷🇺  Русский"
    echo "  [2] 🇬🇧  English"
    echo
    local a
    read -rp "  1-2 [1]: " a
    case "${a:-1}" in
        2) UI_LANG="en" ;;
        *) UI_LANG="ru" ;;
    esac
    conf_set UI_LANG "$UI_LANG"
    ui_lang_load "$UI_LANG"
    echo -e "  ${G}✓ ${T[lang_saved]}${N}"
    sleep 1
}

# ── Статус на главном экране ──────────────────────────────────────────
# Все значения читаются одним вызовом python: экран перерисовывается часто,
# плодить по семь процессов на кадр незачем. Разделитель — вертикальная черта.
read_state() {
    python3 - <<'PY' 2>/dev/null || echo "0|?|0|50|15|10|1|60|3|50|0|0"
import json
try:
    c = json.load(open("/etc/shaper/config.json"))
except Exception:
    c = {}
g = {"enabled": False, "both_dl_percent": 50, "both_ul_percent": 15,
     "both_ways_min": 10, "penalty_mbps": 1, "penalty_min": 60,
     "score_needed": 3, "download_gb_per_day": 50,
     "download_gb_per_hour": 0, "upload_ratio_percent": 0}
g.update(c.get("guard", {}))
ports = c.get("ports", [])
print("|".join([
    f"{float(c.get('speed_mbps', 0)):g}",
    ", ".join(map(str, ports)) if ports and ports != [0] else "*",
    "1" if g["enabled"] else "0",
    f"{g['both_dl_percent']:g}", f"{g['both_ul_percent']:g}",
    f"{g['both_ways_min']:g}",
    f"{g['penalty_mbps']:g}", f"{g['penalty_min']:g}", f"{g['score_needed']:g}",
    f"{g['download_gb_per_day']:g}", f"{g['download_gb_per_hour']:g}",
    f"{g['upload_ratio_percent']:g}",
]))
PY
}

status_line() {
    local ifc speed ports g_on bdl bul bmin pen dur score dgb dgbh urp
    local dlv ulv vol
    local auto_on=0 run_on=0

    "$ENGINE" state >/dev/null 2>&1 && run_on=1
    systemctl is-enabled shaper >/dev/null 2>&1 && auto_on=1

    ifc="$(sed -n 's/^IFACE="\(.*\)"$/\1/p' "$ETC_DIR/.active_iface" 2>/dev/null)"
    [[ -z "$ifc" ]] && ifc="$(ip route get 1.1.1.1 2>/dev/null |
                              sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)"

    IFS='|' read -r speed ports g_on bdl bul bmin pen dur score dgb dgbh urp \
        <<< "$(read_state)"
    [[ "$ports" == "*" ]] && ports="${T[st_all]}"

    if (( run_on )); then
        echo -e "  🟢  ${T[st_shaper]} ${G}${T[st_running]}${N}   ${D}${T[st_iface]} ${ifc:-?}${N}"
    else
        echo -e "  🔴  ${T[st_shaper]} ${R}${T[st_stopped]}${N}  ${D}${T[st_nolimit]}${N}"
    fi

    if (( auto_on )); then
        echo -e "  🔁  ${T[st_auto]} ${G}${T[st_auto_on]}${N}    ${D}${T[st_auto_ok]}${N}"
    else
        echo -e "  ⚠️   ${T[st_auto]} ${Y}${T[st_auto_off]}${N}   ${D}${T[st_auto_warn]}${N}"
    fi

    if [[ "$speed" == "0" ]]; then
        echo -e "  ⚪  ${T[st_speed]} ${Y}${T[st_unlimited]}${N}"
    else
        echo -e "  🚀  ${T[st_speed]} ${B}${speed} Mbit/s${N} ${D}${T[st_peruser]}${N}"
    fi
    echo -e "  🔌  ${T[st_port]} ${B}${ports}${N}"

    if [[ "$g_on" == "1" ]]; then
        if [[ "$speed" == "0" ]]; then
            echo -e "  🚦  ${T[st_guard]} ${G}${T[st_g_on]}${N}    ${Y}${T[st_g_nolimit]}${N}"
        else
            dlv="$(awk "BEGIN{printf \"%g\", $speed*$bdl/100}")"
            ulv="$(awk "BEGIN{printf \"%g\", $speed*$bul/100}")"
            echo -e "  🚦  ${T[st_guard]} ${G}${T[st_g_on]}${N}" \
                    "${D}${T[st_g_both]} ↓${dlv} ↑${ulv} Mbit/s ${bmin} ${T[min]}" \
                    "+ ${score} ${T[st_g_pts]} → ${pen} Mbit/s ${T[g_for]} ${dur} ${T[min]}${N}"
            vol=""
            [[ "$dgbh" != "0" ]] && vol="${dgbh} ${T[st_g_gbh]}"
            [[ "$dgb"  != "0" ]] && vol="${vol:+$vol · }${dgb} ${T[st_g_gbd]}"
            [[ "$urp"  != "0" ]] && vol="${vol:+$vol · }${T[st_g_ratio]} ${urp}%"
            [[ -n "$vol" ]] && echo -e "      ${D}${T[st_g_or]} ${vol}${N}"
        fi
    else
        echo -e "  🚦  ${T[st_guard]} ${D}${T[st_g_off]}${N}   ${D}${T[st_g_none]}${N}"
    fi

    # Связь с внешним миром. Раньше главный экран о ней молчал, и понять, что
    # Telegram не настроен или API лежит, можно было только зайдя в раздел.
    local tg_on tg_name pn_on pn_dis api_st
    IFS='|' read -r tg_on tg_name pn_on pn_dis api_st <<< "$(links_state)"

    if [[ "$tg_on" == "1" ]]; then
        echo -e "  ✉️   ${T[st_tg]} ${G}${T[st_on]}${N}   ${D}${T[st_tg_as]} ${tg_name}${N}"
    else
        echo -e "  ✉️   ${T[st_tg]} ${D}${T[st_off]}${N}  ${D}${T[st_tg_no]}${N}"
    fi

    if [[ "$pn_on" == "1" ]]; then
        if [[ "$pn_dis" == "0" ]]; then
            echo -e "  🛰  ${T[st_pn]} ${G}${T[st_pn_on]}${N} ${D}${T[st_pn_nodis]}${N}"
        else
            echo -e "  🛰  ${T[st_pn]} ${G}${T[st_pn_on]}${N} ${R}${T[st_pn_dis]} ${pn_dis} ${T[min]}${N}"
        fi
    else
        echo -e "  🛰  ${T[st_pn]} ${D}${T[st_pn_offw]}${N} ${D}${T[st_pn_no]}${N}"
    fi

    case "$api_st" in
        run)  echo -e "  🔑  ${T[st_api]} ${G}${T[st_running]}${N}" ;;
        dead) echo -e "  🔑  ${T[st_api]} ${R}${T[st_stopped]}${N}  ${D}${T[st_api_dead]}${N}" ;;
        *)    echo -e "  🔑  ${T[st_api]} ${D}${T[st_api_none]}${N}" ;;
    esac
}

links_state() {
    # Telegram, панель и API одной строкой: включён|подпись|включена|отсрочка|api
    local api="none"
    if [[ -f "$APP_DIR/api/server.py" ]]; then
        if systemctl is-active shape-api >/dev/null 2>&1; then api="run"
        else api="dead"; fi
    fi
    # Путь берём из ETC_DIR, а не вписываем: только так эту строку можно
    # прогнать тестом на подставном конфиге, не трогая настоящий /etc.
    python3 - "$api" "$ETC_DIR/config.json" <<'PY' 2>/dev/null || echo "0|—|0|0|$api"
import json, os, sys
try:
    c = json.load(open(sys.argv[2]))
except Exception:
    c = {}
tg = c.get("telegram") or {}
pn = c.get("panel") or {}
print("|".join([
    "1" if tg.get("enabled") and tg.get("token") and tg.get("chat_id") else "0",
    str(tg.get("node_name") or os.uname().nodename),
    "1" if pn.get("enabled") and pn.get("token") and pn.get("node_uuid") else "0",
    "%g" % float(pn.get("disable_after_min") or 0),
    sys.argv[1],
]))
PY
}

# ── Настройка лимита ──────────────────────────────────────────────────
show_listening() {
    echo -e "  ${D}${T[listening]}${N}"
    ss -tulnpH 2>/dev/null | awk '
        {
            split($5, a, ":"); port = a[length(a)]
            name = ""
            if (match($0, /users:\(\("[^"]+/)) {
                name = substr($0, RSTART+9, RLENGTH-9); gsub(/"/, "", name)
            }
            if (port ~ /^[0-9]+$/ && !(port in seen)) { seen[port] = name }
        }
        END { for (p in seen) printf "    %-6s %s\n", p, seen[p] }
    ' | sort -n | head -12
}

screen_limit() {
    local speed port cur_port ans
    cur_port="$(python3 -c "
import json
try: p = json.load(open('$ETC_DIR/config.json'))['ports']
except Exception: p = [443]
print(','.join(map(str, p)))" 2>/dev/null || echo 443)"

    title "${T[lim_title]}"
    echo -e "  ${D}${T[lim_h1]}${N}"
    echo -e "  ${D}${T[lim_h2]}${N}"
    echo
    echo -e "  ${B}[1]${N}  10 Mbit/s   ${D}${T[lim_d10]}${N}"
    echo -e "  ${B}[2]${N}  15 Mbit/s   ${D}${T[lim_d15]}${N}"
    echo -e "  ${B}[3]${N}  20 Mbit/s   ${D}${T[lim_d20]}${N}"
    echo -e "  ${B}[4]${N}  ${T[lim_own]}"
    echo -e "  ${B}[5]${N}  ${T[lim_off]}"
    echo -e "  ${B}[0]${N}  ${T[cancel]}"
    echo

    case "$(ask "${T[choice]}" 2)" in
        1) speed=10 ;;
        2) speed=15 ;;
        3) speed=20 ;;
        4) speed="$(ask "${T[lim_ask]}" 15)"
           [[ "$speed" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
               echo -e "  ${R}${T[need_num]}${N}"; pause; return; } ;;
        5) speed=0 ;;
        *) return ;;
    esac

    echo
    echo -e "  ${D}${T[port_h1]}${N}"
    echo -e "  ${D}${T[port_h2]}${N}"
    echo
    show_listening
    echo
    port="$(ask "${T[port_ask]}" "$cur_port")"

    echo
    if [[ "$speed" == "0" ]]; then
        echo -e "  ${Y}${T[conf_off]}${N}"
    else
        echo -e "  ${T[conf_on1]} ${B}${speed} Mbit/s${N} ${T[conf_on2]} ${B}${port}${N}."
    fi
    echo
    read -rp "  ${T[apply_q]}: " ans
    [[ "$ans" =~ ^[NnНн] ]] && { echo "  ${T[cancelled]}"; pause; return; }

    "$CTL" apply --ports "$port" --speed "$speed"
    pause
}

# ── Автоограничение ───────────────────────────────────────────────────
# Все настройки читаются одним вызовом: запуск python3 стоит десятки
# миллисекунд, а раньше их было десять на каждую отрисовку экрана.
guard_read() {
    python3 - <<'PY' 2>/dev/null || echo "0|3|50|15|10|1|60|4|2|50|0|600|0|300|0|0|0|0|0|0|0|0"
import json
try:
    _cfg = json.load(open("/etc/shaper/config.json"))
    g = _cfg.get("guard", {})
    _ex = len((_cfg.get("panel") or {}).get("exempt") or [])
except Exception:
    g, _ex = {}, 0
d = {"enabled": False, "score_needed": 3, "both_dl_percent": 50,
     "both_ul_percent": 15, "both_ways_min": 10, "penalty_mbps": 1,
     "penalty_min": 60, "hours_per_day": 4, "upload_gb_per_day": 2,
     "download_gb_per_day": 50, "download_gb_per_hour": 0, "packet_bytes": 600,
     "upload_ratio_percent": 0, "upload_ratio_min_mb": 300,
     "volume_needs_upload": False, "volume_penalty_mbps": 0,
     "ratio_needs_packet": False,
     "upload_warn_gb": 0, "upload_day_gb": 0, "upload_hours": 0,
     "upload_gb_per_hour": 0}
d.update(g)
print("|".join([
    "1" if d["enabled"] else "0",
    f"{d['score_needed']:g}", f"{d['both_dl_percent']:g}", f"{d['both_ul_percent']:g}",
    f"{d['both_ways_min']:g}", f"{d['penalty_mbps']:g}", f"{d['penalty_min']:g}",
    f"{d['hours_per_day']:g}", f"{d['upload_gb_per_day']:g}",
    f"{d['download_gb_per_day']:g}", f"{d['download_gb_per_hour']:g}",
    f"{d['packet_bytes']:g}",
    f"{d['upload_ratio_percent']:g}", f"{d['upload_ratio_min_mb']:g}",
    "1" if d["volume_needs_upload"] else "0",
    f"{d['volume_penalty_mbps']:g}",
    "1" if d["ratio_needs_packet"] else "0",
    str(_ex),
    f"{d['upload_warn_gb']:g}", f"{d['upload_day_gb']:g}",
    f"{d['upload_hours']:g}", f"{d['upload_gb_per_hour']:g}",
]))
PY
}

# ── Готовые пресеты ───────────────────────────────────────────────────
# Каждый пресет — один вызов shaperctl со всеми флагами сразу. Ручная
# настройка остаётся: пресет только расставляет числа, дальше правь что хочешь.
guard_preset() {
    # Два пресета вместо пяти, и названы они по типу ноды, а не по механизму.
    #
    # Раньше их было пять — «мобильная», «универсальная», «торренты»,
    # «быстрая», «всё сразу», — и выбрать между ними было нельзя: они
    # различались внутренностями, а не тем, к какой ноде подходят. Задача же
    # всегда одна и та же: торренты и раздача подписки. Отличается только
    # канал и то, что за ним стоит — телефон или домашний интернет.
    #
    # Поэтому каждый пресет настраивает политику ноды целиком, включая
    # раздачу. Настраивать её отдельно на другом экране означало забыть
    # половину — что и происходило.
    local speed ans gbh gbd full soft
    speed="$(cfg speed_mbps 0)"
    while :; do
        title "${T[gp_title]}"
        echo -e "  ${D}${T[gp_h1]}${N}"
        echo -e "  ${D}${T[gp_h2]}${N}"
        echo
        echo -e "  ${B}[1]${N} 📱 ${T[gp_mob]}"
        echo -e "      ${D}${T[gp_mob_d1]}${N}"
        echo -e "      ${D}${T[gp_mob_d2]}${N}"
        echo
        echo -e "  ${B}[2]${N} 🖥  ${T[gp_home]}"
        echo -e "      ${D}${T[gp_home_d1]}${N}"
        echo -e "      ${D}${T[gp_home_d2]}${N}"
        echo
        echo -e "  ${B}[0]${N} ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) # Три гигабайта в час — то, что мы посчитали для телефона:
               # 1080p помещается дважды, а закачка упирается за сорок минут.
               # Число не вычисляется от канала намеренно: мобильные ноды все
               # примерно одной полосы, а смысл порога здесь в том, сколько
               # нужно человеку, а не сколько влезает в канал.
               echo -e "\n  ${T[gp_will]}:"
               echo -e "  ${D}  · ${T[gp_w_torrent]}${N}"
               echo -e "  ${D}  · ${T[gp_w_ratio]}${N}"
               echo -e "  ${D}    ${T[gp_h_ratio]}${N}"
               echo -e "  ${D}  · ${T[gp_p_hour]} ${B}3 GB${N}${D} — ${T[gp_m1]}${N}"
               echo -e "  ${D}  · ${T[gp_p_day]} 25 GB — ${T[gp_m2]}${N}"
               echo -e "  ${D}  · ${T[gp_up_hour]} ${B}3 GB${N}${D} · ${T[gp_up_day]} ${B}25 GB${N}"
               echo -e "  ${D}  · ${T[gp_w_share]} 20${N}"
               echo -e "  ${D}  · ${T[gp_p_pen]} 1 Mbit/s × 60 ${T[min]}${N}"
               if [[ "$speed" != "0" ]]; then
                   full="$(awk "BEGIN{printf \"%.1f\", $speed/8/1000*3600}")"
                   echo
                   echo -e "  ${D}${T[gp_hint_full]} ${B}${full} GB${N}"
                   echo -e "  ${D}${T[gp_m3]} $(awk "BEGIN{printf \"%.0f\", 3/($speed/8/1000)/60}") ${T[min]}${N}"
               fi
               echo
               read -rp "  ${T[apply_q]}: " ans
               [[ "$ans" =~ ^[NnНн] ]] && continue
               # На телефоне порог в 3 ГБ/час — это «сколько нужно человеку»,
               # а не «сколько влезает в канал», и закачка игр сюда не
               # относится: на десяти мегабитах игра качается сутки в любом
               # случае. Поэтому проверка отдачи и мягкая скорость здесь
               # выключены — но выключены ЯВНО, чтобы переключение с
               # домашнего пресета не оставляло его хвостов.
               "$CTL" guard --enable --score 3 --both-dl 10 --both-ul 3 --both-min 10 \
                   --packet 600 --require-packet on --hours 4 --upload-gb 2 \
                   --download-gb 25 --download-gbh 3 \
                   --upload-ratio 35 --upload-ratio-mb 3000 --upload-ratio-hours 2 \
                   --volume-needs-upload off --volume-mbps 0 \
                   --ratio-needs-packet on \
                   --upload-gbh 3 --upload-day 25 \
                   --upload-warn 0 --upload-hours 6 --upload-hours-mbps 0.05 \
                   --penalty-mbps 1 --penalty-min 60 >/dev/null || { pause; continue; }
               "$CTL" panel set --threshold 20 --window 10 \
                   --minutes 60 --per-device 4 --action-set block >/dev/null || true
               echo -e "  ${G}✓ ${T[gp_done]}${N}"
               pause; return ;;

            2) # Домашний канал шире мобильного в пять-десять раз, и фиксированный
               # порог здесь бессмыслен: три гигабайта в час на стомегабитной
               # ноде — это один фильм. Поэтому час считается от канала.
               #
               # Но сам по себе часовой объём здесь ловит не торрент, а покупку
               # в Steam: порог в половину канала срабатывает ровно через
               # полчаса на полной скорости, а игра весит под сто двадцать
               # гигабайт. Поэтому часовой порог требует крупных пакетов
               # вверх, объём в одиночку режет мягко (треть канала), а сутки
               # подняты до шестнадцати часов — одна игра проходит, ферма нет.
               if [[ "$speed" == "0" ]]; then
                   gbh=20; gbd=150; soft=25
                   echo -e "\n  ${Y}${T[gp_nolimit]}${N}"
                   echo -e "  ${D}${T[gp_nolimit_d]}${N}"
               else
                   full="$(awk "BEGIN{printf \"%.1f\", $speed/8/1000*3600}")"
                   gbh="$(awk "BEGIN{printf \"%.1f\", $speed/8/1000*3600*0.5}")"
                   # Суточный порог — число, а не производная от канала.
                   # Выведенный арифметикой давал 180 ГБ на пятидесяти
                   # мегабитах и 360 на ста; владелец ноды сказал, что и сто
                   # уже перебор. Честное потребление таких цифр не набирает:
                   # 4K это 7-16 ГБ в час, игра в Steam — 120 ГБ разово.
                   gbd=150
                   soft="$(awk "BEGIN{printf \"%.0f\", $speed*0.3}")"
                   echo -e "\n  ${D}${T[gp_hint_full]} ${B}${full} GB${N}"
                   echo -e "  ${D}${T[gp_home_calc]} ${B}${gbh} GB${N}${D} ${T[gp_home_why]}${N}"
               fi
               echo -e "\n  ${T[gp_will]}:"
               echo -e "  ${D}  · ${T[gp_w_torrent]}${N}"
               echo -e "  ${D}  · ${T[gp_w_ratio50]}${N}"
               echo -e "  ${D}    ${T[gp_h_ratio]}${N}"
               echo -e "  ${D}  · ${T[gp_p_hour]} ${B}${gbh} GB${N}${D} — ${T[gp_h_vol]}${N}"
               echo -e "  ${D}  · ${T[gp_p_day]} ${gbd} GB${N}"
               echo -e "  ${D}  · ${T[gp_w_share]} 10${N}"
               echo -e "  ${D}  · ${T[gp_up_warn]} ${B}10 GB${N}${D} → ${T[gp_up_warn2]}${N}"
               echo -e "  ${D}  · ${T[gp_up_day]} ${B}30 GB${N}"
               echo -e "  ${D}  · ${T[gp_up_hours]} ${B}6 ${T[hour]}${N}"
               echo -e "  ${D}  · ${T[gp_p_pen]} 1 Mbit/s × 60 ${T[min]}${N}"
               echo -e "  ${D}  · ${T[gp_h_soft]} ${B}${soft} Mbit/s${N}"
               echo
               read -rp "  ${T[apply_q]}: " ans
               [[ "$ans" =~ ^[NnНн] ]] && continue
               "$CTL" guard --enable --score 3 --both-dl 10 --both-ul 3 --both-min 10 \
                   --packet 600 --require-packet on --hours 4 --upload-gb 2 \
                   --download-gb "$gbd" --download-gbh "$gbh" \
                   --upload-ratio 50 --upload-ratio-mb 3000 --upload-ratio-hours 2 \
                   --volume-needs-upload on --volume-mbps "$soft" \
                   --ratio-needs-packet on \
                   --upload-gbh 0 --upload-day 30 \
                   --upload-warn 10 --upload-hours 6 --upload-hours-mbps 0.05 \
                   --penalty-mbps 1 --penalty-min 60 >/dev/null || { pause; continue; }
               # --per-device 4 защищает офисы: пятнадцать проданных устройств
               # дают порог 60, и легальная контора на одной ноде под правило не
               # попадает. Семье с пятью устройствами он ничего не меняет —
               # 5*4 = 20, то есть базовый порог. Раздающему он тоже не помогает:
               # у него тариф на пять устройств, а адресов сотня.
               #
               # Двадцать, а не десять: домашняя нода это не только вайфай,
               # с мобильного заходят на любую. У оператора адрес меняется
               # при переподключении, и семья из пяти телефонов за десять
               # минут легко даёт полтора-два десятка адресов. Настоящие
               # перепродавцы при этом дают 146 и 230 — запас десятикратный.
               "$CTL" panel set --threshold 20 --window 10 \
                   --minutes 60 --per-device 4 --action-set block >/dev/null || true
               echo -e "  ${G}✓ ${T[gp_done]}${N}"
               pause; return ;;
            0|"") return ;;
        esac
    done
}

screen_guard() {
    local on score both_min bdl bul pen dur hours gb dgb dgbh pkt urp urm speed v
    local vnu vmb rnp gex uw ud uh ugh
    while :; do
        speed="$(cfg speed_mbps 0)"
        IFS='|' read -r on score bdl bul both_min pen dur hours gb dgb dgbh pkt \
            urp urm vnu vmb rnp gex uw ud uh ugh <<< "$(guard_read)"

        title "${T[g_title]}"
        echo -e "  ${D}${T[g_h1]}${N}"
        echo -e "  ${D}${T[g_h2]}${N}"
        echo -e "  ${D}${T[g_h3]}${N}"
        echo
        if [[ "$on" == "1" ]]; then
            echo -e "  ${T[g_state]} : ${G}${T[g_on]}${N}"
        else
            echo -e "  ${T[g_state]} : ${D}${T[g_off]}${N}"
        fi
        if [[ "$speed" != "0" && -n "$speed" ]]; then
            echo -e "  ${T[g_req]} : ${B}↓$(awk "BEGIN{printf \"%g\", $speed*$bdl/100}")" \
                    "↑$(awk "BEGIN{printf \"%g\", $speed*$bul/100}") Mbit/s${N}" \
                    "${D}${T[g_bothways]}${N} ${B}${both_min}${N} ${T[min]}"
        else
            echo -e "  ${Y}${T[g_need_limit]}${N}"
        fi
        echo -e "  ${T[g_pen]} : ${B}${pen} Mbit/s${N} ${T[g_for]} ${B}${dur}${N} ${T[min]}"
        echo -e "  ${D}${T[g_notify_cd]}${N}"
        # Исключения задаются на экране панели, а действуют и здесь.
        [[ "$gex" != "0" ]] && echo -e "  ${D}${T[g_exempt_n]} ${B}${gex}${N}"
        hr
        echo -e "  ${D}${T[g_signals]}  ${T[g_score_now]} ${score}${N}"
        echo -e "  ${D}  +2  ${T[why_packet]}${N}"
        echo -e "  ${D}  +1  ${T[why_peak]}${N}"
        echo -e "  ${D}  +2  ${T[why_hours]} (>${hours} ${T[hour]})${N}"
        echo -e "  ${D}  +1  ${T[why_upload]} (>${gb} GB)${N}"
        [[ "$dgb" != "0" ]] && echo -e "  ${D}${T[g_orpath]} ${T[why_download]} (>${dgb} GB)${N}"
        [[ "$dgbh" != "0" ]] && echo -e "  ${D}${T[g_orpath]} ${T[why_hourly]} (>${dgbh} GB)${N}"
        [[ "$ugh" != "0" ]] && echo -e "  ${D}${T[g_orpath]} ${T[why_up_hourly_menu]} (>${ugh} GB)${N}"
        [[ "$uh" != "0" ]] && echo -e "  ${D}${T[g_note]} ${T[why_up_hours_menu]} (>${uh} ${T[hour]})${N}"
        [[ "$ud" != "0" ]] && echo -e "  ${D}${T[g_orpath]} ${T[why_upload_day_menu]} (>${ud} GB)${N}"
        [[ "$uw" != "0" ]] && echo -e "  ${D}      └ ${T[g_up_warn]} ${B}${uw} GB${N}"
        [[ "$urp" != "0" ]] && echo -e "  ${D}${T[g_orpath]} ${T[why_ratio_menu]} (>${urp}%, >${urm} MB)${N}"
        # Условие «отдаёт прямо сейчас» решает, кому прилетит штраф, а из
        # строки выше его не видно. Такое уже терялось трижды.
        [[ "$urp" != "0" ]] && echo -e "  ${D}      └ ${T[g_ratio_live]}${N}"
        [[ "$urp" != "0" && "$rnp" == "1" ]] && \
            echo -e "  ${D}      └ ${T[g_ratio_pkt]}${N}"
        # Обе настройки меняют исход, и обеих не видно из строк выше. Ровно
        # так уже терялись признак отношения и действие панели.
        [[ "$dgbh" != "0" && "$vnu" == "1" ]] && \
            echo -e "  ${D}      └ ${T[g_vol_needs]}${N}"
        [[ "$vmb" != "0" ]] && echo -e "  ${D}${T[g_vol_soft]} ${B}${vmb} Mbit/s${N}"
        hr
        echo "  [1] ${T[g_toggle]}"
        echo "  [2] ${T[g_set_score]}"
        echo "  [3] ${T[g_set_both]}"
        echo "  [4] ${T[g_set_pen]}"
        echo "  [5] ${T[g_set_dur]}"
        echo "  [6] ${T[g_set_hours]}"
        echo "  [7] ${T[g_set_gb]}"
        echo -e "  [8] ${T[g_set_dl]} ${D}(${bdl}%)${N}"
        echo -e "  [9] ${T[g_set_ul]} ${D}(${bul}%)${N}"
        echo -e " [10] ${T[g_set_dgb]} ${D}(${dgb} GB)${N}"
        echo -e " [11] ${T[g_set_dgbh]} ${D}(${dgbh} GB)${N}"
        echo -e " [12] ${T[g_set_ratio]} ${D}(${urp}%)${N}"
        if [[ "$vnu" == "1" ]]; then
            echo -e " [13] ${T[g_set_vnu]} ${D}(${T[g_on]})${N}"
        else
            echo -e " [13] ${T[g_set_vnu]} ${D}(${T[g_off]})${N}"
        fi
        echo -e " [14] ${T[g_set_vmb]} ${D}(${vmb} Mbit/s)${N}"
        echo -e " [17] ${T[g_set_upday]} ${D}(${ud} GB)${N}"
        echo -e " [18] ${T[g_set_upwarn]} ${D}(${uw} GB)${N}"
        echo -e " [19] ${T[g_set_uphours]} ${D}(${uh} ${T[hour]})${N}"
        echo -e " [20] ${T[g_set_upgbh]} ${D}(${ugh} GB)${N}"
        if [[ "$rnp" == "1" ]]; then
            echo -e " [15] ${T[g_set_rnp]} ${D}(${T[g_on]})${N}"
        else
            echo -e " [15] ${T[g_set_rnp]} ${D}(${T[g_off]})${N}"
        fi
        hr
        echo -e " ${B}[16]${N} ⚡ ${T[gp_menu]}"
        echo "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) if [[ "$on" == "1" ]]; then "$CTL" guard --disable --quiet
               else "$CTL" guard --enable --quiet; fi ;;
            2) v="$(ask "${T[g_set_score]}" "$score")"
               [[ "$v" =~ ^[1-6]$ ]] && "$CTL" guard --score "$v" --quiet ;;
            3) v="$(ask "${T[g_set_both]}" "$both_min")"
               [[ "$v" =~ ^[0-9]+$ ]] && "$CTL" guard --both-min "$v" --quiet ;;
            4) v="$(ask "${T[g_set_pen]}" "$pen")"
               [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] && "$CTL" guard --penalty-mbps "$v" --quiet ;;
            5) v="$(ask "${T[g_set_dur]}" "$dur")"
               [[ "$v" =~ ^[0-9]+$ ]] && "$CTL" guard --penalty-min "$v" --quiet ;;
            6) v="$(ask "${T[g_set_hours]}" "$hours")"
               [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] && "$CTL" guard --hours "$v" --quiet ;;
            7) v="$(ask "${T[g_set_gb]}" "$gb")"
               [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] && "$CTL" guard --upload-gb "$v" --quiet ;;
            8) echo -e "  ${D}${T[g_hint_dl]}${N}"
               v="$(ask "${T[g_set_dl]}" "$bdl")"
               [[ "$v" =~ ^[0-9]+$ ]] && "$CTL" guard --both-dl "$v" --quiet ;;
            9) echo -e "  ${D}${T[g_hint_ul]}${N}"
               v="$(ask "${T[g_set_ul]}" "$bul")"
               [[ "$v" =~ ^[0-9]+$ ]] && "$CTL" guard --both-ul "$v" --quiet ;;
            10) echo -e "  ${D}${T[g_hint_dgb]}${N}"
                v="$(ask "${T[g_set_dgb]}" "$dgb")"
                [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] && "$CTL" guard --download-gb "$v" --quiet ;;
            11) echo -e "  ${D}${T[g_hint_dgbh]}${N}"
                [[ "$speed" != "0" ]] && echo -e "  ${D}${T[g_hint_max]}" \
                    "$(awk "BEGIN{printf \"%.1f\", $speed*3600/8/1000}") GB${N}"
                v="$(ask "${T[g_set_dgbh]}" "$dgbh")"
                [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] && "$CTL" guard --download-gbh "$v" --quiet ;;
            12) echo -e "  ${D}${T[g_hint_ratio]}${N}"
                v="$(ask "${T[g_set_ratio]}" "$urp")"
                [[ "$v" =~ ^[0-9]+$ ]] && "$CTL" guard --upload-ratio "$v" --quiet ;;
            13) echo -e "  ${D}${T[g_hint_vnu]}${N}"
                if [[ "$vnu" == "1" ]]; then
                    "$CTL" guard --volume-needs-upload off --quiet
                else
                    "$CTL" guard --volume-needs-upload on --quiet
                fi ;;
            14) echo -e "  ${D}${T[g_hint_vmb]}${N}"
                [[ "$speed" != "0" ]] && echo -e "  ${D}${T[g_hint_vmb2]}" \
                    "$(awk "BEGIN{printf \"%.0f\", $speed*0.3}") Mbit/s${N}"
                v="$(ask "${T[g_set_vmb]}" "$vmb")"
                [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] && "$CTL" guard --volume-mbps "$v" --quiet ;;
            20) echo -e "  ${D}${T[g_hint_upgbh]}${N}"
                v="$(ask "${T[g_set_upgbh]}" "$ugh")"
                [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] && "$CTL" guard --upload-gbh "$v" --quiet ;;
            19) echo -e "  ${D}${T[g_hint_uphours]}${N}"
                v="$(ask "${T[g_set_uphours]}" "$uh")"
                [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] && "$CTL" guard --upload-hours "$v" --quiet ;;
            17) echo -e "  ${D}${T[g_hint_upday]}${N}"
                v="$(ask "${T[g_set_upday]}" "$ud")"
                [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] && "$CTL" guard --upload-day "$v" --quiet ;;
            18) echo -e "  ${D}${T[g_hint_upwarn]}${N}"
                v="$(ask "${T[g_set_upwarn]}" "$uw")"
                [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] && "$CTL" guard --upload-warn "$v" --quiet ;;
            15) echo -e "  ${D}${T[g_hint_rnp]}${N}"
                if [[ "$rnp" == "1" ]]; then
                    "$CTL" guard --ratio-needs-packet off --quiet
                else
                    "$CTL" guard --ratio-needs-packet on --quiet
                fi ;;
            16) guard_preset ;;
            0|"") return ;;
        esac
    done
}

# ── Telegram ──────────────────────────────────────────────────────────
tg_read() {
    python3 - <<'PY' 2>/dev/null || echo "0|—|—|—|—|1|1|—|09:00|1"
import json, os
try:
    g = json.load(open("/etc/shaper/config.json")).get("telegram", {})
except Exception:
    g = {}
d = {"enabled": False, "token": "", "chat_id": "", "thread_id": "",
     "node_name": "", "events": True, "daily": True, "proxy": "",
     "digest_at": "09:00", "updates": True}
d.update(g)
print("|".join([
    "1" if d["enabled"] else "0",
    d["node_name"] or os.uname().nodename,
    (d["token"][:10] + "…") if d["token"] else "—",
    d["chat_id"] or "—",
    d["thread_id"] or "—",
    "1" if d["events"] else "0",
    "1" if d["daily"] else "0",
    d["proxy"] or "—",
    d.get("digest_at") or "09:00",
    "1" if d["updates"] else "0",
]))
PY
}

# ── SSH-туннель для прокси ────────────────────────────────────────────
# На российских нодах api.telegram.org недоступен, а MTProto-прокси для Bot API
# не годится. Самый короткий путь — поднять SOCKS через SSH на своей же
# зарубежной ноде: нового софта почти не надо, трафик копеечный.
TUN_KEY="/root/.ssh/shape_tunnel"
TUN_KNOWN="/root/.ssh/shape_tunnel_known_hosts"
TUN_UNIT="/etc/systemd/system/shape-tunnel.service"

# Всё, что здесь введут, попадает в две опасные точки: в ExecStart юнита
# systemd и в shaper.conf, который потом выполняется через source. Перевод
# строки в адресе дописал бы в юнит свою директиву, кавычка — свою команду
# в конфиг. Поэтому проверяем формат до того, как что-то запишем.
tn_bad() { echo -e "  ${R}✗ ${T[tn_bad_value]} ${B}$1${N}"; pause; }

tunnel_setup() {
    local host port user lport ans

    title "${T[tn_title]}"
    echo -e "  ${D}${T[tn_h1]}${N}"
    echo -e "  ${D}${T[tn_h2]}${N}"
    echo
    host="$(ask "${T[tn_host]}" "${TUNNEL_HOST:-}")"
    [[ -z "$host" ]] && return
    # имя хоста или IP: буквы, цифры, точка, дефис, двоеточие для IPv6
    [[ "$host" =~ ^[A-Za-z0-9.:_-]{1,253}$ ]] || { tn_bad "${T[tn_host]}"; return; }
    port="$(ask "${T[tn_port]}" "${TUNNEL_PORT:-22}")"
    [[ "$port" =~ ^[0-9]{1,5}$ ]] && (( port >= 1 && port <= 65535 )) \
        || { tn_bad "${T[tn_port]}"; return; }
    user="$(ask "${T[tn_user]}" "${TUNNEL_USER:-root}")"
    [[ "$user" =~ ^[A-Za-z_][A-Za-z0-9_-]{0,31}$ ]] || { tn_bad "${T[tn_user]}"; return; }
    lport="$(ask "${T[tn_lport]}" "${TUNNEL_LPORT:-1080}")"
    [[ "$lport" =~ ^[0-9]{1,5}$ ]] && (( lport >= 1 && lport <= 65535 )) \
        || { tn_bad "${T[tn_lport]}"; return; }

    # ключ
    if [[ ! -f "$TUN_KEY" ]]; then
        echo -e "\n  ${D}${T[tn_keygen]}${N}"
        mkdir -p /root/.ssh && chmod 700 /root/.ssh
        ssh-keygen -t ed25519 -N "" -C "shape-tunnel" -f "$TUN_KEY" -q || {
            tn_bad "${T[tn_keygen]}"; return; }
    fi
    chmod 600 "$TUN_KEY" 2>/dev/null

    # Ключ хоста сверяем глазами один раз и запоминаем. Через этот туннель
    # пойдёт токен бота, а StrictHostKeyChecking=accept-new молча доверяет
    # тому, кто ответил первым — если подменили именно первое соединение,
    # подмену уже никто не заметит.
    local hostopt="-o StrictHostKeyChecking=accept-new"
    echo -e "\n  ${D}${T[tn_fp_get]}${N}"
    if ssh-keyscan -T 8 -p "$port" "$host" > "$TUN_KNOWN.new" 2>/dev/null \
       && [[ -s "$TUN_KNOWN.new" ]]; then
        echo -e "  ${B}${T[tn_fp]}${N}"
        ssh-keygen -lf "$TUN_KNOWN.new" 2>/dev/null | sed 's/^/    /'
        echo
        read -rp "  ${T[tn_fp_q]} [y/N]: " ans
        if [[ ! "$ans" =~ ^[YyДд] ]]; then
            rm -f "$TUN_KNOWN.new"; echo "  ${T[cancelled]}"; pause; return
        fi
        mv -f "$TUN_KNOWN.new" "$TUN_KNOWN"; chmod 600 "$TUN_KNOWN"
        hostopt="-o StrictHostKeyChecking=yes -o UserKnownHostsFile=$TUN_KNOWN"
    else
        rm -f "$TUN_KNOWN.new"
        echo -e "  ${Y}⚠ ${T[tn_fp_skip]}${N}"
    fi

    echo
    echo -e "  ${B}${T[tn_pub]}${N}"
    echo -e "  ${G}$(cat "$TUN_KEY.pub")${N}"
    echo
    echo -e "  ${D}${T[tn_how1]}${N}"
    echo -e "  ${D}${T[tn_how2]}${N}"
    echo
    echo "  [1] ${T[tn_copy]}"
    echo "  [2] ${T[tn_manual]}"
    echo "  [0] ${T[cancel]}"
    echo
    case "$(ask "${T[choice]}" 1)" in
        1) echo
           # shellcheck disable=SC2086
           ssh-copy-id -i "$TUN_KEY.pub" -p "$port" $hostopt "$user@$host" || {
               echo -e "  ${R}${T[tn_copy_fail]}${N}"; pause; return; } ;;
        2) echo; read -rsp "  ${T[tn_wait]} " _ ;;
        *) return ;;
    esac

    # autossh держит туннель живым лучше голого ssh, но не обязателен
    local exe="/usr/bin/ssh" extra=""
    if command -v autossh >/dev/null || apt-get install -y -qq autossh >/dev/null 2>&1; then
        exe="$(command -v autossh)"; extra="-M 0"
    fi

    cat > "$TUN_UNIT" <<EOF
[Unit]
Description=Shape SOCKS tunnel for Telegram
After=network-online.target
Wants=network-online.target

[Service]
Environment=AUTOSSH_GATETIME=0
ExecStart=$exe $extra -N -D 127.0.0.1:$lport -i $TUN_KEY -p $port \\
    -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \\
    -o ExitOnForwardFailure=yes -o IdentitiesOnly=yes $hostopt \\
    $user@$host
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now shape-tunnel >/dev/null 2>&1
    conf_set TUNNEL_HOST "$host"; conf_set TUNNEL_PORT "$port"
    conf_set TUNNEL_USER "$user"; conf_set TUNNEL_LPORT "$lport"
    TUNNEL_HOST="$host"; TUNNEL_PORT="$port"
    TUNNEL_USER="$user"; TUNNEL_LPORT="$lport"

    echo -e "\n  ${D}${T[tn_starting]}${N}"
    sleep 4
    if tunnel_check "$lport"; then
        "$CTL" telegram set --proxy "socks5://127.0.0.1:$lport" --quiet
        echo -e "  ${G}✓ ${T[tn_ok]}${N}"
        echo -e "  ${D}${T[tn_set]} socks5://127.0.0.1:$lport${N}"
    else
        echo -e "  ${R}✗ ${T[tn_fail]}${N}"
        echo -e "  ${D}journalctl -u shape-tunnel -n 20${N}"
    fi
    pause
}

tunnel_check() {
    local lport="${1:-${TUNNEL_LPORT:-1080}}" code
    command -v curl >/dev/null || return 1
    # 401 — это успех: связь есть, просто токен 0:0 заведомо липовый
    code="$(curl -sS --socks5-hostname "127.0.0.1:$lport" -o /dev/null -m 12 \
            -w '%{http_code}' https://api.telegram.org/bot0:0/getMe 2>/dev/null)"
    [[ "$code" == "401" ]]
}

screen_tunnel() {
    while :; do
        title "${T[tn_title]}"
        if [[ -f "$TUN_UNIT" ]]; then
            if systemctl is-active shape-tunnel >/dev/null 2>&1; then
                echo -e "  ${T[tn_state]} : ${G}${T[dr_running]}${N}"
            else
                echo -e "  ${T[tn_state]} : ${R}${T[dr_stopped]}${N}"
            fi
            echo -e "  ${T[tn_server]}: ${B}${TUNNEL_USER:-root}@${TUNNEL_HOST:-?}:${TUNNEL_PORT:-22}${N}"
            echo -e "  ${T[tn_socks]} : ${B}socks5://127.0.0.1:${TUNNEL_LPORT:-1080}${N}"
        else
            echo -e "  ${T[tn_state]} : ${D}${T[tn_none]}${N}"
            echo
            echo -e "  ${D}${T[tn_h1]}${N}"
            echo -e "  ${D}${T[tn_h2]}${N}"
        fi
        hr
        echo "  [1] ${T[tn_setup]}"
        echo "  [2] ${T[tn_test]}"
        echo "  [3] ${T[sv_logs]}"
        echo "  [4] ${T[tn_remove]}"
        echo "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) tunnel_setup ;;
            2) echo -e "\n  ${D}${T[tn_checking]}${N}"
               if tunnel_check; then echo -e "  ${G}✓ ${T[tn_ok]}${N}"
               else echo -e "  ${R}✗ ${T[tn_fail]}${N}"; fi
               pause ;;
            3) title "${T[sv_logs]}"
               journalctl -u shape-tunnel -n 30 --no-pager | sed 's/^/  /'; pause ;;
            4) systemctl disable --now shape-tunnel >/dev/null 2>&1
               rm -f "$TUN_UNIT"; systemctl daemon-reload
               "$CTL" telegram set --proxy "" --quiet
               echo -e "  ${G}✓ ${T[tn_removed]}${N}"; sleep 2 ;;
            0|"") return ;;
        esac
    done
}

screen_telegram() {
    local on name tok chat thread ev dg proxy at v upd
    while :; do
        IFS='|' read -r on name tok chat thread ev dg proxy at upd <<< "$(tg_read)"
        title "${T[tg_title]}"
        echo -e "  ${D}${T[tg_h1]}${N}"
        echo -e "  ${D}${T[tg_h2]}${N}"
        echo
        if [[ "$on" == "1" ]]; then
            echo -e "  ${T[tg_state]} : ${G}${T[g_on]}${N}"
        else
            echo -e "  ${T[tg_state]} : ${D}${T[g_off]}${N}"
        fi
        echo -e "  ${T[tg_node]} : ${B}${name}${N}"
        echo -e "  ${T[tg_token]} : ${tok}"
        echo -e "  ${T[tg_chat]} : ${chat}${D}   ${T[tg_thread]}: ${thread}${N}"
        echo -e "  ${T[tg_proxy]} : ${proxy}"
        hr
        echo "  [1] ${T[g_toggle]}"
        echo "  [2] ${T[tg_set_token]}"
        echo "  [3] ${T[tg_set_chat]}"
        echo "  [4] ${T[tg_set_thread]}"
        echo "  [5] ${T[tg_set_name]}"
        echo "  [6] ${T[tg_set_proxy]}"
        if [[ "$ev" == "1" ]]; then
            echo -e "  [7] ${T[tg_ev]}: ${G}${T[tg_on]}${N} ${D}${T[tg_press]}${N}"
        else
            echo -e "  [7] ${T[tg_ev]}: ${Y}${T[tg_off]}${N} ${D}${T[tg_press]}${N}"
        fi
        if [[ "$dg" == "1" ]]; then
            echo -e "  [8] ${T[tg_dg]}: ${G}${T[tg_on]}${N} ${D}${T[tg_press]}${N}"
        else
            echo -e "  [8] ${T[tg_dg]}: ${Y}${T[tg_off]}${N} ${D}${T[tg_press]}${N}"
        fi
        echo -e "  [9] ${T[tg_set_at]}: ${B}${at}${N}"
        if [[ "$upd" == "1" ]]; then
            echo -e " [13] ${T[tg_upd]}: ${G}${T[tg_on]}${N} ${D}${T[tg_press]}${N}"
        else
            echo -e " [13] ${T[tg_upd]}: ${Y}${T[tg_off]}${N} ${D}${T[tg_press]}${N}"
        fi
        echo " [10] ${T[tg_send_now]}"
        echo " [11] ${T[tg_test]}"
        echo -e " [12] 🔌 ${T[tn_menu]}"
        echo "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) if [[ "$on" == "1" ]]; then "$CTL" telegram set --disable --quiet
               else "$CTL" telegram set --enable --quiet; fi ;;
            2) echo -e "  ${D}${T[tg_hint_token]}${N}"
               v="$(ask "${T[tg_set_token]}")"
               [[ -n "$v" ]] && "$CTL" telegram set --token "$v" --quiet ;;
            3) echo -e "  ${D}${T[tg_hint_chat]}${N}"
               v="$(ask "${T[tg_set_chat]}")"
               [[ -n "$v" ]] && "$CTL" telegram set --chat "$v" --quiet ;;
            4) echo -e "  ${D}${T[tg_hint_thread]}${N}"
               v="$(ask "${T[tg_set_thread]}")"
               "$CTL" telegram set --thread "$v" --quiet ;;
            5) echo -e "  ${D}${T[tg_hint_name]}${N}"
               v="$(ask "${T[tg_set_name]}" "$name")"
               "$CTL" telegram set --name "$v" --quiet ;;
            6) echo -e "  ${D}${T[tg_hint_proxy]}${N}"
               v="$(ask "${T[tg_set_proxy]}")"
               "$CTL" telegram set --proxy "$v" --quiet ;;
            7) "$CTL" telegram set --events "$([[ "$ev" == 1 ]] && echo off || echo on)" --quiet ;;
            8) "$CTL" telegram set --daily "$([[ "$dg" == 1 ]] && echo off || echo on)" --quiet ;;
           13) "$CTL" telegram set --updates "$([[ "$upd" == 1 ]] && echo off || echo on)" --quiet ;;
            9) echo -e "  ${D}${T[tg_hint_at]}${N}"
               v="$(ask "${T[tg_set_at]}" "$at")"
               [[ -n "$v" ]] && { "$CTL" telegram set --at "$v" --quiet || pause; } ;;
            10) echo; "$CTL" telegram digest; pause ;;
            11) echo; "$CTL" telegram test; pause ;;
            12) screen_tunnel ;;
            0|"") return ;;
        esac
    done
}

# ── Панель Remnawave ──────────────────────────────────────────────────
# Признак включённости нужен на экране «Сервис», где рисуется список: гонять
# ради одной галочки полный pn_read с разбором токена незачем.
pn_enabled() {
    python3 -c "
import json, sys
try: d = json.load(open('$ETC_DIR/config.json')).get('panel', {})
except Exception: d = {}
sys.exit(0 if d.get('enabled') else 1)" 2>/dev/null
}

# Читаем одним заходом, как и настройки Telegram: дёргать shaperctl по разу
# на каждое поле — это девять запусков питона на отрисовку одного экрана.
pn_read() {
    # Одним заходом, как и настройки Telegram: дёргать shaperctl по разу на
    # каждое поле — это полтора десятка запусков питона на отрисовку экрана.
    # Значения отдаём по одному на поле, без склеек вида «1/60»: собрать их
    # здесь и разобрать обратно в меню — верный способ однажды показать мусор.
    python3 - <<PY 2>/dev/null || echo "0|-|-|-|-|300|10|20|notify|360|-|1|60|0|09:00|1"
import base64, json, time
try:
    d = json.load(open("$ETC_DIR/config.json")).get("panel", {})
except Exception:
    d = {}


def until(tok):
    """Срок жизни токена — из него самого. Не разобралось, и ладно."""
    try:
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        e = float(json.loads(base64.urlsafe_b64decode(p)).get("exp") or 0)
        return time.strftime("%Y-%m-%d", time.localtime(e)) if e else "?"
    except Exception:
        return "?"


tok = d.get("token") or ""
print("|".join([
    "1" if d.get("enabled") else "0",
    d.get("url") or "-",
    (d.get("node_uuid") or "-")[:8],
    (tok[:6] + "\u2026") if tok else "-",
    until(tok) if tok else "-",
    str(d.get("interval") or 300),
    str(d.get("window_min") or 10),
    str(d.get("ip_threshold") or 20),
    d.get("action") or "notify",
    str(d.get("cooldown_min") or 360),
    ", ".join(str(x) for x in (d.get("exempt") or [])) or "-",
    str(d.get("limit_mbps") or 1),
    str(d.get("limit_min") or 60),
    "1" if d.get("report") else "0",
    d.get("report_at") or "09:00",
    "0" if d.get("resolve") is False else "1",
    str(d.get("disable_after_min") or 0),
    "%g" % float(d.get("per_device") or 0),
    ", ".join(str(x) for x in (d.get("exempt_tags") or [])) or "-",
]))
PY
}

cdn_enabled() {
    python3 -c "
import json,sys
try: d = json.load(open('$ETC_DIR/config.json')).get('cdn', {})
except Exception: d = {}
sys.exit(0 if d.get('enabled') else 1)" 2>/dev/null
}

# Читаем одним заходом, как и остальные экраны: дёргать shaperctl по разу на
# каждое поле — это лишние запуски питона на отрисовку.
cdn_read() {
    python3 - <<PY 2>/dev/null || echo "0|-|-|-"
import json
try:
    d = json.load(open("$ETC_DIR/config.json")).get("cdn", {})
except Exception:
    d = {}
tok = d.get("token") or ""
print("|".join([
    "1" if d.get("enabled") else "0",
    d.get("url") or "-",
    str(d.get("resource_id") or "-"),
    (tok[:6] + "\u2026") if tok else "-",
]))
PY
}

screen_cdn() {
    local on url res tok v
    while :; do
        IFS='|' read -r on url res tok <<< "$(cdn_read)"
        title "${T[cdn_title]}"
        echo -e "  ${D}${T[cdn_h1]}${N}"
        echo -e "  ${D}${T[cdn_h2]}${N}"
        echo
        if [[ "$on" == "1" ]]; then
            echo -e "  ${T[cdn_l_state]}: ${G}${T[g_on]}${N}"
        else
            echo -e "  ${T[cdn_l_state]}: ${D}${T[g_off]}${N}"
        fi
        echo -e "  ${T[cdn_l_url]}: ${B}${url}${N}"
        echo -e "  ${T[cdn_l_res]}: ${B}${res}${N}"
        echo -e "  ${T[cdn_l_token]}: ${D}${tok}${N}"
        echo
        echo "  [1] ${T[g_toggle]}"
        echo "  [2] ${T[cdn_set_url]}"
        echo "  [3] ${T[cdn_set_token]}"
        echo "  [4] ${T[cdn_set_res]}"
        echo "  [5] ${T[cdn_test]}"
        echo "  [6] ${T[cdn_list]}"
        echo "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) if [[ "$on" == "1" ]]; then "$CTL" cdn set --disable
               else "$CTL" cdn set --enable; fi >/dev/null ;;
            2) echo -e "  ${D}${T[cdn_hint_url]}${N}"
               v="$(ask "${T[cdn_set_url]}")"
               [[ -n "$v" ]] && { "$CTL" cdn set --url "$v" >/dev/null || pause; } ;;
            3) echo -e "  ${D}${T[cdn_hint_token]}${N}"
               v="$(ask "${T[cdn_set_token]}")"
               [[ -n "$v" ]] && "$CTL" cdn set --token "$v" >/dev/null ;;
            4) echo -e "  ${D}${T[cdn_hint_res]}${N}"
               v="$(ask "${T[cdn_set_res]}" "$res")"
               [[ -n "$v" ]] && { "$CTL" cdn set --resource-id "$v" >/dev/null || pause; } ;;
            5) "$CTL" cdn test; pause ;;
            6) "$CTL" cdn list; pause ;;
            0|"") return ;;
        esac
    done
}

screen_panel() {
    local on url uuid tok texp every win thr act act_txt cool exempt mbps lmin
    local rep rep_at names v dis etags pdev
    while :; do
        IFS='|' read -r on url uuid tok texp every win thr act cool exempt \
            mbps lmin rep rep_at names dis pdev etags <<< "$(pn_read)"
        title "${T[pn_title]}"
        echo -e "  ${D}${T[pn_h1]}${N}"
        echo -e "  ${D}${T[pn_h2]}${N}"
        echo -e "  ${D}${T[pn_h3]}${N}"
        echo
        # Подписи выровнены пробелами в самих строках, а не через printf:
        # %-14s в bash считает байты, а кириллица в UTF-8 занимает по два —
        # колонка разъезжалась бы ровно на русском языке.
        if [[ "$on" == "1" ]]; then
            echo -e "  ${T[pn_l_state]}: ${G}${T[g_on]}${N}"
        else
            echo -e "  ${T[pn_l_state]}: ${D}${T[g_off]}${N}"
        fi
        echo -e "  ${T[pn_l_url]}: ${url}"
        echo -e "  ${T[pn_l_uuid]}: ${uuid}"
        if [[ "$tok" == "-" ]]; then
            echo -e "  ${T[pn_l_token]}: ${Y}${T[pn_none]}${N}"
        else
            echo -e "  ${T[pn_l_token]}: ${tok} ${D}\u00b7${N} ${T[pn_u_until]} ${texp}"
        fi
        echo -e "  ${T[pn_l_every]}: ${every} ${T[pn_u_sec]}"
        echo -e "  ${T[pn_l_thr]}: ${B}${thr}${N} ${T[pn_u_addr]} / ${win} ${T[pn_u_min]}"
        case "$act" in
            *block*) act_txt="${T[pn_act_block]}" ;;
            *drop*)  act_txt="${T[pn_act_drop]}"  ;;
            *limit*) act_txt="${T[pn_act_limit]}" ;;
            *)       act_txt="${T[pn_act_notify]}" ;;
        esac
        echo -e "  ${T[pn_l_act]}: ${B}${act_txt}${N} ${D}(${act})${N}"
        # Скорость и срок относятся только к тем действиям, которые режут.
        # При «оборвать» и «только сообщить» это лишние числа на экране.
        if [[ "$act" == *limit* || "$act" == *block* ]]; then
            echo -e "  ${T[pn_l_lim]}: ${mbps} ${T[pn_u_mbps]} ${D}\u00b7${N} ${lmin} ${T[pn_u_min]}"
        fi
        echo -e "  ${T[pn_l_cool]}: ${cool} ${T[pn_u_min]}"
        if [[ "$names" == "1" ]]; then
            echo -e "  ${T[pn_l_names]}: ${G}${T[g_on]}${N}"
        else
            echo -e "  ${T[pn_l_names]}: ${D}${T[g_off]}${N}"
        fi
        if [[ "$rep" == "1" ]]; then
            echo -e "  ${T[pn_l_rep]}: ${G}${rep_at}${N}"
        else
            echo -e "  ${T[pn_l_rep]}: ${D}${T[g_off]}${N}"
        fi
        echo -e "  ${T[pn_l_exempt]}: ${exempt}"
        hr
        echo "  [1] ${T[g_toggle]}"
        echo "  [2] ${T[pn_set_url]}"
        echo "  [3] ${T[pn_set_token]}"
        echo "  [4] ${T[pn_set_uuid]}"
        echo "  [5] ${T[pn_set_thr]}"
        echo "  [6] ${T[pn_set_win]}"
        echo "  [7] ${T[pn_set_act]}"
        echo "  [8] ${T[pn_set_speed]}"
        echo "  [9] ${T[pn_set_min]}"
        echo " [10] ${T[pn_set_cool]}"
        echo " [11] ${T[pn_set_exempt]}"
        if [[ "$rep" == "1" ]]; then
            echo -e " [12] ${T[pn_rep]}: ${G}${T[tg_on]}${N} ${D}${T[tg_press]}${N}"
        else
            echo -e " [12] ${T[pn_rep]}: ${Y}${T[tg_off]}${N} ${D}${T[tg_press]}${N}"
        fi
        echo -e " [13] ${T[pn_rep_at]}: ${B}${rep_at}${N}"
        echo " [14] ${T[pn_rep_now]}"
        if [[ "$names" == "1" ]]; then
            echo -e " [15] ${T[pn_names]}: ${G}${T[tg_on]}${N} ${D}${T[tg_press]}${N}"
        else
            echo -e " [15] ${T[pn_names]}: ${Y}${T[tg_off]}${N} ${D}${T[tg_press]}${N}"
        fi
        echo " [16] ${T[pn_test]}"
        echo " [17] ${T[pn_scan]}"
        if [[ "$dis" == "0" ]]; then
            echo -e " [18] ${T[pn_set_dis]}: ${D}${T[tg_off]}${N}"
        else
            echo -e " [18] ${T[pn_set_dis]}: ${R}${dis} ${T[pn_min]}${N}"
        fi
        if [[ "$pdev" == "0" ]]; then
            echo -e " [20] ${T[pn_set_pdev]}: ${D}${T[tg_off]}${N}"
        else
            echo -e " [20] ${T[pn_set_pdev]}: ${B}×${pdev}${N}"
        fi
        echo " [19] ${T[pn_enable_user]}"
        echo "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) if [[ "$on" == "1" ]]; then "$CTL" panel set --disable
               else "$CTL" panel set --enable; fi >/dev/null ;;
            2) echo -e "  ${D}${T[pn_hint_url]}${N}"
               v="$(ask "${T[pn_set_url]}")"
               [[ -n "$v" ]] && { "$CTL" panel set --url "$v" >/dev/null || pause; } ;;
            3) echo -e "  ${D}${T[pn_hint_token]}${N}"
               v="$(ask "${T[pn_set_token]}")"
               [[ -n "$v" ]] && "$CTL" panel set --token "$v" >/dev/null ;;
            4) echo -e "  ${D}${T[pn_hint_uuid]}${N}"
               v="$(ask "${T[pn_set_uuid]}")"
               [[ -n "$v" ]] && "$CTL" panel set --node-uuid "$v" >/dev/null ;;
            5) echo -e "  ${D}${T[pn_hint_thr]}${N}"
               v="$(ask "${T[pn_set_thr]}" "$thr")"
               [[ -n "$v" ]] && "$CTL" panel set --threshold "$v" >/dev/null ;;
            6) v="$(ask "${T[pn_set_win]}" "$win")"
               [[ -n "$v" ]] && "$CTL" panel set --window "$v" >/dev/null ;;
            7) title "${T[pn_set_act]}"
               echo -e "  ${D}${T[pn_act_h1]}${N}"
               echo -e "  ${D}${T[pn_act_h2]}${N}"
               echo
               echo -e "  [1] ${T[pn_act_notify]}"
               echo -e "      ${D}${T[pn_act_notify_d]}${N}"
               echo -e "  [2] ${T[pn_act_drop]}   ${G}${T[pn_act_best]}${N}"
               echo -e "      ${D}${T[pn_act_drop_d]}${N}"
               echo -e "  [3] ${T[pn_act_limit]}"
               echo -e "      ${D}${T[pn_act_limit_d]}${N}"
               echo -e "  [4] ${T[pn_act_block]}"
               echo -e "      ${D}${T[pn_act_block_d]}${N}"
               echo -e "  [0] ← ${T[m0]}"
               echo
               case "$(ask "${T[choice]}")" in
                   1) "$CTL" panel set --action-set notify >/dev/null ;;
                   2) "$CTL" panel set --action-set drop   >/dev/null ;;
                   3) "$CTL" panel set --action-set limit  >/dev/null ;;
                   4) "$CTL" panel set --action-set block  >/dev/null ;;
               esac ;;
            8) v="$(ask "${T[pn_set_speed]}" "$mbps")"
               [[ -n "$v" ]] && "$CTL" panel set --mbps "$v" >/dev/null ;;
            9) v="$(ask "${T[pn_set_min]}" "$lmin")"
               [[ -n "$v" ]] && "$CTL" panel set --minutes "$v" >/dev/null ;;
           10) v="$(ask "${T[pn_set_cool]}" "$cool")"
               [[ -n "$v" ]] && "$CTL" panel set --cooldown "$v" >/dev/null ;;
           11) echo -e "  ${D}${T[pn_hint_exempt]}${N}"
               v="$(ask "${T[pn_set_exempt]}")"
               "$CTL" panel set --exempt "$v" >/dev/null ;;
           12) echo -e "  ${D}${T[pn_hint_rep]}${N}"
               "$CTL" panel set --report "$([[ "$rep" == 1 ]] && echo off || echo on)" \
                   >/dev/null ;;
           13) v="$(ask "${T[pn_rep_at]}" "$rep_at")"
               [[ -n "$v" ]] && { "$CTL" panel set --report-at "$v" >/dev/null || pause; } ;;
           14) echo; "$CTL" panel report; pause ;;
           15) echo -e "  ${D}${T[pn_hint_names]}${N}"
               "$CTL" panel set --resolve "$([[ "$names" == 1 ]] && echo off || echo on)" \
                   >/dev/null ;;
           16) echo; "$CTL" panel test; pause ;;
           17) echo; "$CTL" panel scan --dry-run; pause ;;
           18) echo -e "  ${D}${T[pn_hint_dis]}${N}"
               v="$(ask "${T[pn_set_dis]}" "$dis")"
               [[ "$v" =~ ^[0-9]+$ ]] && "$CTL" panel set --disable-after "$v" >/dev/null ;;
           20) echo -e "  ${D}${T[pn_hint_pdev]}${N}"
               v="$(ask "${T[pn_set_pdev]}" "$pdev")"
               [[ "$v" =~ ^[0-9]+$ ]] && "$CTL" panel set --per-device "$v" >/dev/null ;;
           19) v="$(ask "${T[pn_ask_id]}")"
               [[ -n "$v" ]] && { echo; "$CTL" panel enable "$v"; pause; } ;;
            0|"") return ;;
        esac
    done
}

# ── Ограниченные пользователи ─────────────────────────────────────────
limited_count() {
    python3 -c "
import json, time
try: p = json.load(open('$ETC_DIR/penalties.json'))
except Exception: p = {}
now = time.time()
print(sum(1 for v in p.values() if isinstance(v, dict)
          and v.get('until', 0) > now and v.get('kind') != 'personal'))
" 2>/dev/null || echo 0
}

screen_limited() {
    local ip ans
    while :; do
        title "${T[lm_title]}"
        "$CTL" limited
        hr
        echo "  [1] ${T[lm_release]}"
        echo "  [2] ${T[lm_release_user]}"
        echo "  [3] ${T[lm_release_all]}"
        echo "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) ip="$(ask "${T[lm_ask]}")"
               [[ -n "$ip" ]] && { "$CTL" release "$ip"; sleep 1; } ;;
            2) echo -e "  ${D}${T[lm_hint_user]}${N}"
               ip="$(ask "${T[lm_ask_user]}")"
               [[ -n "$ip" ]] && { "$CTL" release --user "$ip"; sleep 1; } ;;
            3) read -rp "  ${T[lm_confirm]} [y/N]: " ans
               [[ "$ans" =~ ^[YyДд] ]] && { "$CTL" release --all; sleep 1; } ;;
            0|"") return ;;
        esac
    done
}

# ── Статистика ────────────────────────────────────────────────────────
screen_stats() {
    while :; do
        title "${T[stats_title]}"
        echo -e "  ${D}${T[stats_d1]}${N}"
        echo -e "  ${D}${T[stats_d2]}${N}"
        echo
        echo "  [1] ${T[stats_top]}"
        echo "  [2] ${T[stats_full]}"
        echo "  [3] 🔍 ${T[stats_ratio]}"
        echo "  [4] 📦 ${T[stats_bulk]}"
        echo "  [5] 📅 ${T[hist_title]}"
        echo "  [6] 🎯 ${T[pers_title]}"
        echo "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) title "${T[stats_title]}"; "$CTL" status; pause ;;
            2) title "${T[stats_title]}"; "$CTL" status --full; pause ;;
            3) title "${T[stats_ratio]}"; "$CTL" status --ratio; pause ;;
            4) title "${T[stats_bulk]}"; "$CTL" status --bulk; pause ;;
            5) screen_history ;;
            6) screen_personal ;;
            0|"") return ;;
        esac
    done
}

# ── Белый список ──────────────────────────────────────────────────────
screen_whitelist() {
    local ip
    while :; do
        title "${T[wl_title]}"
        echo -e "  ${D}${T[wl_d]}${N}"
        echo
        "$CTL" whitelist list
        hr
        echo "  [1] ${T[wl_add]}"
        echo "  [2] ${T[wl_del]}"
        echo "  [3] ${T[tr_more]}"
        echo "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) ip="$(ask "${T[wl_ask]}")"
               [[ -n "$ip" ]] && { "$CTL" whitelist add "$ip"; sleep 1; } ;;
            2) ip="$(ask "${T[wl_ask]}")"
               [[ -n "$ip" ]] && { "$CTL" whitelist del "$ip"; sleep 1; } ;;
            3) screen_trusted ;;
            0|"") return ;;
        esac
    done
}

# ── Доверенные источники ──────────────────────────────────────────────
# Белый список говорит «этого не ограничивать». Этот список — про другое:
# «этому можно верить, когда он говорит, чей это трафик». Два разных
# вопроса, поэтому и два разных экрана.
screen_trusted() {
    local ip
    while :; do
        title "${T[tr_title]}"
        echo -e "  ${D}${T[tr_d]}${N}"
        echo -e "  ${D}${T[tr_d2]}${N}"
        echo
        "$CTL" trusted list
        hr
        echo "  [1] ${T[tr_add_t]}"
        echo "  [2] ${T[tr_add_r]}"
        echo "  [3] ${T[tr_del]}"
        echo "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) ip="$(ask "${T[tr_ask]}")"
               [[ -n "$ip" ]] && { "$CTL" trusted add "$ip" --tunnel; sleep 1; } ;;
            2) ip="$(ask "${T[tr_ask]}")"
               [[ -n "$ip" ]] && { "$CTL" trusted add "$ip" --relay; sleep 1; } ;;
            3) ip="$(ask "${T[tr_ask]}")"
               [[ -n "$ip" ]] && { "$CTL" trusted del "$ip"; sleep 1; } ;;
            0|"") return ;;
        esac
    done
}

# ── Персональные скорости ─────────────────────────────────────────────
# Карта штрафов в ядре не проверяет, ниже персональная скорость общей или
# выше. Значит тем же механизмом выдаётся и постоянная скорость: сотруднику
# с рабочей системой больше общего лимита, проблемному адресу — меньше.
screen_personal() {
    local ip speed note
    while :; do
        title "${T[pers_title]}"
        echo -e "  ${D}${T[pers_h1]}${N}"
        echo -e "  ${D}${T[pers_h2]}${N}"
        "$CTL" personal list
        hr
        echo "  [1] ${T[pers_add]}"
        echo "  [2] ${T[pers_del]}"
        echo "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) ip="$(ask "${T[wl_ask]}")"
               [[ -z "$ip" ]] && continue
               speed="$(ask "${T[pers_speed]}")"
               if [[ ! "$speed" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
                   echo -e "  ${R}${T[need_num]}${N}"; pause; continue
               fi
               note="$(ask "${T[pers_note]}")"
               echo
               "$CTL" personal set "$ip" --speed "$speed" --note "$note"
               pause ;;
            2) ip="$(ask "${T[wl_ask]}")"
               [[ -n "$ip" ]] && { "$CTL" personal del "$ip"; sleep 1; } ;;
            0|"") return ;;
        esac
    done
}

# ── История по суткам ─────────────────────────────────────────────────
screen_history() {
    local d
    title "${T[hist_title]}"
    echo -e "  ${D}${T[hist_h1]}${N}"
    echo
    d="$(ask "${T[hist_days]}" 30)"
    [[ "$d" =~ ^[0-9]+$ ]] || d=30
    title "${T[hist_title]}"
    "$CTL" history --days "$d"
    pause
}

# ── Обновление из GitHub ──────────────────────────────────────────────
installed_version() {
    local v h
    v="$(cat "$APP_DIR/VERSION" 2>/dev/null || echo '?')"
    h="$(cat "$APP_DIR/.commit" 2>/dev/null)"
    echo "v$v${h:+ · $h}"
}

screen_update() {
    local tmp new_ver cur_hash ans
    title "${T[up_title]}"
    echo -e "  ${D}${T[up_src]} $REPO_URL${N}"
    echo -e "  ${D}${T[up_installed]} $(installed_version)${N}"
    echo

    if ! command -v git >/dev/null; then
        echo -e "  ${D}${T[up_git]}${N}"
        apt-get install -y -qq git >/dev/null 2>&1 ||
            dnf install -y -q git >/dev/null 2>&1 ||
            yum install -y -q git >/dev/null 2>&1 || {
                echo -e "  ${R}✗ ${T[up_nogit]}${N}"; pause; return; }
    fi

    # Предсказуемый шаблон: после exec install.sh каталог убрать уже некому,
    # поэтому чистим прошлые клоны при следующем обновлении.
    rm -rf /tmp/shape-update.* 2>/dev/null
    tmp="$(mktemp -d -t shape-update.XXXXXX)" || { pause; return; }
    echo -e "  ${D}${T[up_dl]}${N}"
    if ! git clone --depth 20 --quiet "$REPO_URL" "$tmp" 2>/dev/null; then
        echo -e "  ${R}✗ ${T[up_fail]}${N}"
        rm -rf "$tmp"; pause; return
    fi

    # Скачанное запускаем от root, поэтому сначала убеждаемся, что это
    # действительно Shape, а не пустой или оборвавшийся клон.
    for f in install.sh engine.sh shaperctl.py VERSION bpf/shaper.bpf.c; do
        [[ -s "$tmp/$f" ]] || {
            echo -e "  ${R}✗ ${T[up_broken]} $f${N}"
            rm -rf "$tmp"; pause; return; }
    done

    new_ver="$(git -C "$tmp" rev-parse --short HEAD)"
    cur_hash="$(cat "$APP_DIR/.commit" 2>/dev/null)"
    if [[ "$new_ver" == "$cur_hash" ]]; then
        echo -e "  ${G}✓ ${T[up_latest]} ($new_ver)${N}"
        rm -rf "$tmp"; pause; return
    fi

    echo
    echo -e "  ${B}${T[up_new]} $(cat "$tmp/VERSION" 2>/dev/null || echo '?') · $new_ver${N}"
    echo -e "  ${D}${T[up_changes]}${N}"
    git -C "$tmp" log --oneline -5 | sed 's/^/    /'
    echo
    echo -e "  ${D}${T[up_k1]}${N}"
    echo -e "  ${D}${T[up_k2]}${N}"
    echo -e "  ${D}${T[up_k3]}${N}"
    echo
    read -rp "  ${T[up_q]}: " ans
    if [[ ! "$ans" =~ ^[YyДд] ]]; then
        echo "  ${T[cancelled]}"; rm -rf "$tmp"; pause; return
    fi

    rm -rf "$APP_DIR.bak"
    cp -a "$APP_DIR" "$APP_DIR.bak" 2>/dev/null || true
    echo -e "  ${D}${T[up_backup]} $APP_DIR.bak${N}"
    echo

    # exec, а не вызов: bash не должен дочитывать menu.sh после того,
    # как установщик перезапишет этот файл.
    exec bash "$tmp/install.sh"
}

# ── API ───────────────────────────────────────────────────────────────
# Экран управления необязательным сервисом shape-api. Сам шейпер про API
# ничего не знает: остановка или удаление API его не касаются.
API_UNIT="/etc/systemd/system/shape-api.service"

api_read() {
    python3 - <<'PYAPI' 2>/dev/null || echo "127.0.0.1|8765|0|—"
import json
try:
    c = json.load(open("/etc/shaper/api.json"))
except Exception:
    c = {}
allowed = c.get("allowed_ips") or []
print("|".join([
    str(c.get("bind_address", "127.0.0.1")),
    str(c.get("port", 8765)),
    "1" if (c.get("tokens") or {}).get("write") else "0",
    ", ".join(map(str, allowed)) if allowed else "—",
]))
PYAPI
}

screen_api() {
    local bind port has_tok allowed v
    while :; do
        IFS='|' read -r bind port has_tok allowed <<< "$(api_read)"
        title "${T[api_title]}"
        echo -e "  ${D}${T[api_h1]}${N}"
        echo -e "  ${D}${T[api_h2]}${N}"
        echo
        if [[ -f "$API_UNIT" ]]; then
            if systemctl is-active shape-api >/dev/null 2>&1; then
                echo -e "  ${T[api_state]} : ${G}${T[dr_running]}${N}"
            else
                echo -e "  ${T[api_state]} : ${R}${T[dr_stopped]}${N}"
            fi
            echo -e "  ${T[api_addr]} : ${B}${bind}:${port}${N}"
            echo -e "  ${T[api_allow]} : ${allowed}"
            echo -e "  ${T[api_docs]} : ${D}http://${bind}:${port}/api/v1/docs${N}"
            hr
            echo "  [1] ${T[api_tokens]}"
            echo "  [2] ${T[api_rotate]}"
            echo "  [3] ${T[api_bind]}"
            echo "  [4] ${T[api_port]}"
            echo "  [5] ${T[api_allow_set]}"
            echo "  [6] ${T[sv_restart]}"
            echo "  [7] ${T[sv_logs]}"
            echo "  [8] ${T[api_test]}"
            echo "  [9] ${T[api_remove]}"
        else
            echo -e "  ${T[api_state]} : ${D}${T[api_none]}${N}"
            hr
            echo "  [1] ${T[api_install]}"
        fi
        echo "  [0] ← ${T[m0]}"
        echo
        if [[ ! -f "$API_UNIT" ]]; then
            case "$(ask "${T[choice]}")" in
                1) api_install ;;
                0|"") return ;;
            esac
            continue
        fi
        case "$(ask "${T[choice]}")" in
            1) echo; "$APP_DIR/api/server.py" --print-tokens | sed 's/^/  /'
               echo -e "\n  ${D}${T[api_tok_hint]}${N}"; pause ;;
            2) read -rp "  ${T[api_rotate_q]} [y/N]: " v
               [[ "$v" =~ ^[YyДд] ]] && { api_rotate; pause; } ;;
            3) echo -e "  ${D}${T[api_bind_hint]}${N}"
               v="$(ask "${T[api_bind]}" "$bind")"
               api_set bind_address "$v"; pause ;;
            4) v="$(ask "${T[api_port]}" "$port")"
               api_set port "$v"; pause ;;
            5) echo -e "  ${D}${T[api_allow_hint]}${N}"
               v="$(ask "${T[api_allow_set]}")"
               api_set allowed_ips "$v"; pause ;;
            6) systemctl restart shape-api; sleep 1 ;;
            7) title "${T[sv_logs]}"
               journalctl -u shape-api -n 40 --no-pager | sed 's/^/  /'; pause ;;
            8) echo; api_test; pause ;;
            9) read -rp "  ${T[api_remove_q]} [y/N]: " v
               if [[ "$v" =~ ^[YyДд] ]]; then
                   systemctl disable --now shape-api >/dev/null 2>&1
                   rm -f "$API_UNIT"; rm -rf "$APP_DIR/api"
                   systemctl daemon-reload
                   echo -e "  ${G}✓ ${T[api_removed]}${N}"; sleep 2; return
               fi ;;
            0|"") return ;;
        esac
    done
}

api_install() {
    if [[ ! -f "$APP_DIR/api/server.py" ]]; then
        echo -e "  ${Y}${T[api_need_update]}${N}"; pause; return
    fi
    if [[ -f "$APP_DIR/api/shape-api.service" ]]; then
        install -m 644 "$APP_DIR/api/shape-api.service" "$API_UNIT"
    else
        echo -e "  ${Y}${T[api_need_update]}${N}"; pause; return
    fi
    systemctl daemon-reload
    systemctl enable --now shape-api >/dev/null 2>&1
    sleep 1
    if systemctl is-active shape-api >/dev/null 2>&1; then
        echo -e "  ${G}✓ ${T[api_installed]}${N}"
    else
        echo -e "  ${R}✗ ${T[api_failed]}${N}"
    fi
    pause
}

# Значения проверяем здесь же: они попадают в конфиг сервиса, который слушает
# сеть. Адрес и порт — строго по формату, список сетей — через ipaddress,
# а не «как ввели».
api_set() {
    python3 - "$1" "$2" <<'PYAPI'
import ipaddress, json, os, sys
key, raw = sys.argv[1], sys.argv[2].strip()
path = "/etc/shaper/api.json"
try:
    cfg = json.load(open(path))
except Exception:
    cfg = {}
if key == "bind_address":
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        print("  \033[31m✗ это не IP-адрес\033[0m"); sys.exit(1)
    cfg[key] = raw
elif key == "port":
    if not raw.isdigit() or not 1 <= int(raw) <= 65535:
        print("  \033[31m✗ порт вне диапазона 1..65535\033[0m"); sys.exit(1)
    cfg[key] = int(raw)
elif key == "allowed_ips":
    nets = []
    for part in raw.replace(",", " ").split():
        try:
            nets.append(str(ipaddress.ip_network(part, strict=False)))
        except ValueError:
            print(f"  \033[31m✗ «{part[:40]}» — не адрес и не сеть\033[0m")
            sys.exit(1)
    cfg[key] = nets
else:
    sys.exit(1)
tmp = path + ".tmp"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(cfg, f, indent=2)
os.replace(tmp, path)
print("  \033[32m✓ сохранено\033[0m")
PYAPI
    systemctl restart shape-api 2>/dev/null
    sleep 1
}

api_rotate() {
    python3 - <<'PYAPI'
import json, os, secrets, time
path = "/etc/shaper/api.json"
try:
    cfg = json.load(open(path))
except Exception:
    cfg = {}
old = cfg.get("tokens") or {}
# Прежняя пара принимается ещё сутки: иначе смена токена на десятках нод
# означала бы, что часть из них отвечает 401, пока обновляешь остальные.
cfg["tokens"] = {"read": secrets.token_urlsafe(32),
                 "write": secrets.token_urlsafe(32),
                 "read_previous": old.get("read", ""),
                 "write_previous": old.get("write", ""),
                 "previous_until": time.time() + 86400}
tmp = path + ".tmp"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(cfg, f, indent=2)
os.replace(tmp, path)
print("  \033[32m✓ токены перевыпущены, прежние больше не действуют\033[0m")
PYAPI
    systemctl restart shape-api 2>/dev/null
}

api_test() {
    local bind port tok code
    IFS='|' read -r bind port _ _ <<< "$(api_read)"
    command -v curl >/dev/null || { echo -e "  ${Y}curl не установлен${N}"; return; }
    code="$(curl -s -o /dev/null -m 5 -w '%{http_code}' \
            "http://${bind}:${port}/api/v1/health" 2>/dev/null)"
    if [[ "$code" == "200" ]]; then
        echo -e "  ${G}✓ /api/v1/health → 200${N}"
    else
        echo -e "  ${R}✗ /api/v1/health → ${code:-нет ответа}${N}"; return
    fi
    tok="$(python3 -c "
import json
try: print(json.load(open('/etc/shaper/api.json'))['tokens']['read'])
except Exception: print('')" 2>/dev/null)"
    code="$(curl -s -o /dev/null -m 5 -w '%{http_code}' \
            -H "Authorization: Bearer $tok" \
            "http://${bind}:${port}/api/v1/status" 2>/dev/null)"
    [[ "$code" == "200" ]] && echo -e "  ${G}✓ /api/v1/status → 200${N}" \
                           || echo -e "  ${R}✗ /api/v1/status → ${code}${N}"
    code="$(curl -s -o /dev/null -m 5 -w '%{http_code}' \
            -H "Authorization: Bearer wrong" \
            "http://${bind}:${port}/api/v1/status" 2>/dev/null)"
    [[ "$code" == "401" ]] && echo -e "  ${G}✓ ${T[api_t_bad]} → 401${N}" \
                           || echo -e "  ${R}✗ ${T[api_t_bad]} → ${code}${N}"
}

# ── Мониторинг ────────────────────────────────────────────────────────
# Метрики Prometheus можно отдавать двумя путями. Через API — если он
# установлен и виден мониторингу. Через textfile collector node_exporter —
# если node_exporter на ноде уже есть; тогда ни API, ни открытых портов не
# нужно вовсе, файл заберёт сам node_exporter.
MET_ENV="$ETC_DIR/metrics.env"
MET_TIMER="/etc/systemd/system/shape-metrics.timer"

# Каталоги, куда разные сборки node_exporter кладут *.prom
met_guess_dir() {
    local d
    for d in /var/lib/node_exporter/textfile_collector \
             /var/lib/prometheus/node-exporter \
             /var/lib/node_exporter/textfile \
             /var/lib/prometheus/textfile_collector; do
        [[ -d "$d" ]] && { echo "$d"; return; }
    done
    # каталога нет — смотрим, с каким аргументом запущен сам node_exporter
    d="$(ps -eo args 2>/dev/null | grep -o -- '--collector.textfile.directory[= ][^ ]*' |
         head -1 | sed 's/.*[= ]//')"
    [[ -n "$d" ]] && echo "$d"
}

met_current_dir() {
    sed -n 's/^SHAPE_TEXTFILE=\(.*\)\/shape\.prom$/\1/p' "$MET_ENV" 2>/dev/null | head -1
}

screen_metrics() {
    local dir guess ans have_ne
    while :; do
        title "${T[met_title]}"
        echo -e "  ${D}${T[met_h1]}${N}"
        echo -e "  ${D}${T[met_h2]}${N}"
        echo

        have_ne=0
        pgrep -x node_exporter >/dev/null 2>&1 && have_ne=1
        dir="$(met_current_dir)"

        if [[ -f "$API_UNIT" ]] && systemctl is-active shape-api >/dev/null 2>&1; then
            echo -e "  ${T[met_via_api]} : ${G}${T[g_on]}${N}"
        else
            echo -e "  ${T[met_via_api]} : ${D}${T[met_no_api]}${N}"
        fi

        if [[ -f "$MET_TIMER" ]] && systemctl is-active shape-metrics.timer >/dev/null 2>&1; then
            echo -e "  ${T[met_via_file]}: ${G}${T[g_on]}${N}   ${D}${dir:-?}${N}"
            if [[ -n "$dir" && -f "$dir/shape.prom" ]]; then
                echo -e "  ${T[met_file]}   : ${D}$(wc -l < "$dir/shape.prom" 2>/dev/null) ${T[met_lines]}," \
                        "$(date -r "$dir/shape.prom" '+%H:%M:%S' 2>/dev/null)${N}"
            fi
        else
            echo -e "  ${T[met_via_file]}: ${D}${T[g_off]}${N}"
        fi

        if (( have_ne )); then
            echo -e "  node_exporter : ${G}${T[met_found]}${N}"
        else
            echo -e "  node_exporter : ${D}${T[met_notfound]}${N}"
        fi
        hr
        echo "  [1] ${T[met_show]}"
        if [[ -f "$MET_TIMER" ]]; then
            echo "  [2] ${T[met_off]}"
            echo "  [3] ${T[met_now]}"
        else
            echo "  [2] ${T[met_on]}"
        fi
        echo "  [4] ${T[met_scrape]}"
        echo "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) title "${T[met_title]}"
               "$CTL" metrics | head -40
               echo -e "\n  ${D}${T[met_more]}${N}"; pause ;;
            2) if [[ -f "$MET_TIMER" ]]; then
                   systemctl disable --now shape-metrics.timer >/dev/null 2>&1
                   rm -f "$MET_TIMER" /etc/systemd/system/shape-metrics.service
                   [[ -n "$dir" ]] && rm -f "$dir/shape.prom"
                   systemctl daemon-reload
                   echo -e "  ${G}✓ ${T[met_removed]}${N}"; sleep 2
               else
                   met_enable
               fi ;;
            3) [[ -f "$MET_TIMER" ]] && { systemctl start shape-metrics.service
                   sleep 1; echo -e "  ${G}✓${N}"; sleep 1; } ;;
            4) title "${T[met_scrape]}"; met_scrape_example; pause ;;
            0|"") return ;;
        esac
    done
}

met_enable() {
    local dir guess
    guess="$(met_guess_dir)"
    echo
    if [[ -z "$guess" ]]; then
        echo -e "  ${Y}${T[met_nodir]}${N}"
        echo -e "  ${D}${T[met_nodir2]}${N}"
        echo
    fi
    dir="$(ask "${T[met_ask_dir]}" "${guess:-/var/lib/node_exporter/textfile_collector}")"
    # Путь уходит в systemd-юнит: пробелы и кавычки здесь недопустимы.
    if [[ ! "$dir" =~ ^/[A-Za-z0-9._/-]{1,120}$ ]]; then
        echo -e "  ${R}${T[met_bad_dir]}${N}"; pause; return
    fi
    mkdir -p "$dir" || { echo -e "  ${R}${T[met_mkdir_fail]}${N}"; pause; return; }

    printf 'SHAPE_TEXTFILE=%s/shape.prom\n' "$dir" > "$MET_ENV"
    chmod 644 "$MET_ENV"
    install -m 644 "$APP_DIR/systemd/shape-metrics.service" /etc/systemd/system/ 2>/dev/null ||
        cp "$APP_DIR/systemd/shape-metrics.service" /etc/systemd/system/
    install -m 644 "$APP_DIR/systemd/shape-metrics.timer" /etc/systemd/system/ 2>/dev/null ||
        cp "$APP_DIR/systemd/shape-metrics.timer" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now shape-metrics.timer >/dev/null 2>&1
    systemctl start shape-metrics.service >/dev/null 2>&1
    sleep 1
    if [[ -s "$dir/shape.prom" ]]; then
        echo -e "  ${G}✓ ${T[met_enabled]}${N}"
        echo -e "  ${D}$dir/shape.prom${N}"
    else
        echo -e "  ${R}✗ ${T[met_failed]}${N}"
        echo -e "  ${D}journalctl -u shape-metrics -n 20${N}"
    fi
    pause
}

met_scrape_example() {
    local bind port
    IFS='|' read -r bind port _ _ <<< "$(api_read)"
    echo -e "  ${D}${T[met_sc1]}${N}"
    echo
    echo -e "${C}  scrape_configs:"
    echo "    - job_name: shape"
    echo "      static_configs:"
    echo "        - targets: ['${bind}:${port}']"
    echo "      authorization:"
    echo "        type: Bearer"
    echo "        credentials: \"<${T[met_read_token]}>\"${N}"
    echo
    hr
    echo -e "  ${D}${T[met_sc2]}${N}"
    echo
    echo -e "${C}  scrape_configs:"
    echo "    - job_name: node"
    echo "      static_configs:"
    echo "        - targets: ['10.100.0.7:9100']${N}"
    echo
    echo -e "  ${D}${T[met_sc3]}${N}"
}

# ── Сервис ────────────────────────────────────────────────────────────
doctor() {
    local k ifc
    k="$(uname -r)"
    echo -e "  ${T[dr_kernel]}: $k $(awk -v v="${k%%-*}" -v msg="${T[dr_need]}" \
        'BEGIN{split(v,a,".");print (a[1]>5||(a[1]==5&&a[2]>=4))?"\033[32m✓\033[0m":"\033[31m✗ "msg"\033[0m"}')"
    for b in clang bpftool tc python3; do
        printf "  %-17s: %s\n" "$b" "$(command -v "$b" >/dev/null &&
            echo -e "${G}✓${N} $(command -v "$b")" || echo -e "${R}✗ ${T[dr_notinst]}${N}")"
    done
    echo -e "  ${T[dr_bpffs]}: $(mountpoint -q /sys/fs/bpf &&
        echo -e "${G}✓ ${T[dr_mounted]}${N}" || echo -e "${R}✗ ${T[dr_notmounted]}${N}")"
    ifc="$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)"
    echo -e "  ${T[dr_iface]}: ${B}${ifc:-${T[dr_undetected]}}${N}"
    # Смотреть только корневой qdisc мало: у многоочередной карты корень —
    # это mq, а придерживать пакеты будут её дети. Именно там и оказывался
    # fq_codel, из-за которого скачивание переставало ограничиваться, а
    # доктор при этом показывал бодрое «mq».
    if [[ -n "$ifc" ]]; then
        local qall qbad
        qall="$(tc qdisc show dev "$ifc" 2>/dev/null | awk '{print $2}' |
                sort -u | tr '\n' ' ')"
        qbad="$(tc qdisc show dev "$ifc" 2>/dev/null |
                awk '$2!="fq" && $2!="mq" && $2!="clsact" && $2!="noqueue" {print $2}' |
                sort -u | tr '\n' ' ')"
        if [[ -n "$qbad" ]]; then
            echo -e "  ${T[dr_qdisc]}: ${R}✗ ${qbad% }${N} — ${T[dr_qdisc_bad]}"
            echo -e "  ${D}   ${T[dr_qdisc_fix]}${N}"
        else
            echo -e "  ${T[dr_qdisc]}: ${G}✓${N} ${qall% }"
        fi
    fi
    printf "  %-17s: %s\n" "${T[dr_watch]}" "$(systemctl is-active shaper-watch >/dev/null 2>&1 &&
        echo -e "${G}✓ ${T[dr_running]}${N}" || echo -e "${Y}⚠ ${T[dr_stopped]}${N}")"
    echo -e "  ${T[dr_maps]}: $([[ -d /sys/fs/bpf/shaper/maps ]] &&
        echo -e "${G}✓${N}" || echo -e "${D}${T[dr_nosvc]}${N}")"
}

# Настройки отправки копии: включена, тема, день, готов ли Telegram вообще.
bk_read() {
    python3 - <<'PY' 2>/dev/null || echo "0|—|1|0"
import json
try:
    g = json.load(open("/etc/shaper/config.json")).get("telegram", {})
except Exception:
    g = {}
day = g.get("backup_day", 1)
try:
    day = int(day)
except (TypeError, ValueError):
    day = 1
if not 1 <= day <= 7:
    day = 1
print("|".join([
    "1" if g.get("backup") else "0",
    str(g.get("backup_thread_id") or "") or "—",
    str(day),
    "1" if (g.get("token") and g.get("chat_id")) else "0",
]))
PY
}

# ── Резервная копия состояния ─────────────────────────────────────────
# Копия по умолчанию идёт без токена бота: файл почти всегда уезжает с
# сервера — в загрузки, в переписку, иногда в репозиторий. Токен включается
# отдельным пунктом, чтобы это было осознанным действием, а не побочным
# эффектом нажатия «сохранить».
screen_backup() {
    local f ans def bk_on bk_topic bk_day bk_ready
    def="/root/shape-$(hostname -s 2>/dev/null || echo node)-$(date +%Y%m%d).json"
    while :; do
        title "${T[bk_title]}"
        echo -e "  ${D}${T[bk_h1]}${N}"
        echo -e "  ${D}${T[bk_h2]}${N}"
        echo -e "  ${D}${T[bk_h3]}${N}"
        echo -e "  ${D}${T[bk_h4]}${N}"
        hr
        IFS='|' read -r bk_on bk_topic bk_day bk_ready <<< "$(bk_read)"
        echo "  [1] ${T[bk_save]}"
        echo "  [2] ${T[bk_load]}"
        echo "  [3] ${T[bk_check]}"
        hr
        if [[ "$bk_ready" != "1" ]]; then
            echo -e "  ${D}${T[bk_tg_need]}${N}"
        elif [[ "$bk_on" == "1" ]]; then
            echo -e "  [4] ${T[bk_tg_on]}: ${G}${T[tg_on]}${N} ${D}${T[tg_press]}${N}"
            echo -e "  [5] ${T[bk_tg_day]}: ${B}${T[dow$bk_day]}${N}"
            echo -e "  [6] ${T[bk_tg_topic]}: ${B}${bk_topic}${N}"
        else
            echo -e "  [4] ${T[bk_tg_on]}: ${Y}${T[tg_off]}${N} ${D}${T[tg_press]}${N}"
        fi
        [[ "$bk_ready" == "1" ]] && echo "  [7] ${T[bk_tg_now]}"
        echo "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) f="$(ask "${T[bk_where]}" "$def")"
               [[ -z "$f" ]] && continue
               echo
               echo -e "  ${D}${T[bk_secret_warn]}${N}"
               ans="$(ask "${T[bk_secret_ask]}")"
               echo
               if [[ "$ans" =~ ^[YyДд]$ ]]; then
                   "$CTL" export --out "$f" --with-secrets
               else
                   "$CTL" export --out "$f"
               fi
               echo
               echo -e "  ${D}${T[bk_hint]}${N}"
               pause ;;
            2) f="$(ask "${T[bk_where]}")"
               [[ -z "$f" ]] && continue
               if [[ ! -f "$f" ]]; then
                   echo -e "  ${R}${T[bk_missing]}${N}"; pause; continue
               fi
               "$CTL" import "$f" --dry-run
               echo
               ans="$(ask "${T[bk_confirm]}")"
               [[ "$ans" =~ ^[YyДд]$ ]] || continue
               "$CTL" import "$f"
               pause ;;
            3) f="$(ask "${T[bk_where]}")"
               [[ -z "$f" ]] && continue
               if [[ ! -f "$f" ]]; then
                   echo -e "  ${R}${T[bk_missing]}${N}"; pause; continue
               fi
               "$CTL" import "$f" --dry-run
               pause ;;
            4) [[ "$bk_ready" != "1" ]] && continue
               if [[ "$bk_on" == "1" ]]; then
                   "$CTL" telegram set --backup off --quiet
               else
                   echo
                   echo -e "  ${D}${T[bk_tg_w1]}${N}"
                   echo -e "  ${D}${T[bk_tg_w2]}${N}"
                   echo -e "  ${D}${T[bk_tg_w3]}${N}"
                   echo -e "  ${Y}${T[bk_tg_w4]}${N}"
                   echo
                   ans="$(ask "${T[bk_confirm]}")"
                   [[ "$ans" =~ ^[YyДд]$ ]] || continue
                   "$CTL" telegram set --backup on --quiet
               fi ;;
            5) [[ "$bk_on" == "1" ]] || continue
               echo -e "  ${D}${T[bk_tg_day_h]}${N}"
               ans="$(ask "${T[bk_tg_day]}" "$bk_day")"
               if [[ "$ans" =~ ^[1-7]$ ]]; then
                   "$CTL" telegram set --backup-day "$ans" --quiet
               else
                   echo -e "  ${R}${T[need_num]}${N}"; pause
               fi ;;
            6) [[ "$bk_on" == "1" ]] || continue
               echo -e "  ${D}${T[bk_tg_topic_h]}${N}"
               ans="$(ask "${T[bk_tg_topic]}")"
               "$CTL" telegram set --backup-thread "$ans" --quiet || pause ;;
            7) [[ "$bk_ready" != "1" ]] && continue
               echo
               "$CTL" telegram backup
               pause ;;
            0|"") return ;;
        esac
    done
}

# ── Удаление Shape ────────────────────────────────────────────────────
# Действие необратимое и мгновенно снимает ограничение со всех клиентов,
# поэтому здесь три преграды: показ последствий, предложение сделать копию
# и ввод слова целиком. Обычного «y/N» для такого мало — его жмут не глядя.
# Тело экрана удаления вынесено отдельной функцией по одной причине: его надо
# проверять запуском. Пункт [2] — переключатель, и ошибка в нём не видна ни
# синтаксисом, ни грепом: «Удалить заодно настройки и историю» без состояния
# читается как команда, человек нажимает, экран перерисовывается — и пункт
# выглядит сломанным. Тест вызывает эту функцию с обоими значениями.
uninstall_menu() {
    local purge="${1:-0}"
    echo -e "  ${R}${T[un_h1]}${N}"
    echo -e "  ${R}${T[un_h2]}${N}"
    echo -e "  ${R}${T[un_h3]}${N}"
    echo
    echo -e "  ${B}${T[un_what]}:${N}"
    echo -e "    ${D}· ${T[un_w1]}${N}"
    echo -e "    ${D}· ${T[un_w2]}${N}"
    echo -e "    ${D}· ${T[un_w3]}${N}"
    echo -e "    ${D}· ${T[un_w4]}${N}"
    echo
    if (( purge )); then
        echo -e "  ${T[un_keep]}: ${R}${T[un_keep_no]}${N}"
    else
        echo -e "  ${T[un_keep]}: ${G}${T[un_keep_yes]}${N}"
    fi
    hr
    echo "  [1] ${T[un_backup]}"
    if (( purge )); then
        echo -e "  [2] ${T[un_toggle]}: ${R}${T[un_also_yes]}${N}" \
                "${D}${T[tg_press]}${N}"
        echo -e "  [3] ${R}${T[un_go_purge]}${N}"
    else
        echo -e "  [2] ${T[un_toggle]}: ${G}${T[un_also_no]}${N}" \
                "${D}${T[tg_press]}${N}"
        echo -e "  [3] ${R}${T[un_go]}${N}"
    fi
    echo "  [0] ← ${T[m0]}"
    echo
}


screen_uninstall() {
    local purge=0 ans f
    while :; do
        title "${T[un_title]}"
        uninstall_menu "$purge"
        case "$(ask "${T[choice]}")" in
            1) f="/root/shape-$(hostname -s 2>/dev/null || echo node)-$(date +%Y%m%d).json"
               f="$(ask "${T[bk_where]}" "$f")"
               [[ -z "$f" ]] && continue
               echo
               "$CTL" export --out "$f" --with-secrets
               pause ;;
            2) purge=$(( 1 - purge )) ;;
            3) echo
               echo -e "  ${Y}${T[un_word_ask]}: ${B}${T[un_word]}${N}"
               ans="$(ask "${T[choice]}")"
               if [[ "$ans" != "${T[un_word]}" ]]; then
                   echo -e "  ${G}${T[un_aborted]}${N}"; pause; continue
               fi
               echo
               if (( purge )); then
                   bash "$APP_DIR/uninstall.sh" --purge
               else
                   bash "$APP_DIR/uninstall.sh"
               fi
               echo
               echo -e "  ${G}✓ ${T[un_done]}${N}"
               echo -e "  ${D}${T[un_fq]}${N}"
               echo
               read -rsp "  ${T[back]} " _
               clear
               exit 0 ;;
            0|"") return ;;
        esac
    done
}

screen_service() {
    local auto_lbl
    while :; do
        if systemctl is-enabled shaper >/dev/null 2>&1; then
            auto_lbl="🔁 ${T[sv_auto]} ${G}${T[st_auto_on]}${N} ${D}${T[sv_to_off]}${N}"
        else
            auto_lbl="⚠️  ${T[sv_auto]} ${Y}${T[st_auto_off]}${N} ${D}${T[sv_to_on]}${N}"
        fi

        title "${T[sv_title]}"
        systemctl status shaper --no-pager 2>/dev/null | head -4 | sed 's/^/  /'
        hr
        echo -e "  [1] ▶️  ${T[sv_start]}"
        echo -e "  [2] ⏹  ${T[sv_stop]}"
        echo -e "  [3] 🔄 ${T[sv_restart]} ${D}${T[sv_restart_d]}${N}"
        echo -e "  [4] $auto_lbl"
        echo -e "  [5] 📜 ${T[sv_logs]}"
        echo -e "  [6] 🩺 ${T[sv_doctor]}"
        echo -e "  [7] ⬆️  ${T[sv_update]} ${D}(${T[sv_version]} $(installed_version))${N}"
        echo -e "  [8] 🌐 ${T[sv_lang]}"
        if [[ -f "$MET_TIMER" ]] || { [[ -f "$API_UNIT" ]] &&
             systemctl is-active shape-api >/dev/null 2>&1; }; then
            echo -e "  [9] 📈 ${T[met_title]} ${G}${T[tg_on]}${N}"
        else
            echo -e "  [9] 📈 ${T[met_title]} ${D}${T[g_off]}${N}"
        fi
        if [[ -f "$API_UNIT" ]]; then
            if systemctl is-active shape-api >/dev/null 2>&1; then
                echo -e " [10] 🔗 ${T[api_menu]} ${G}${T[tg_on]}${N}"
            else
                echo -e " [10] 🔗 ${T[api_menu]} ${R}${T[dr_stopped]}${N}"
            fi
        else
            echo -e " [10] 🔗 ${T[api_menu]} ${D}${T[api_none]}${N}"
        fi
        echo -e " [11] 💾 ${T[bk_title]}"
        echo -e " [12] 🗑  ${R}${T[un_title]}${N}"
        echo -e "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) systemctl start shaper; sleep 1 ;;
            2) systemctl stop shaper; sleep 1 ;;
            3) rm -f "$APP_DIR/bpf/shaper.bpf.o"; systemctl restart shaper; sleep 2 ;;
            4) if systemctl is-enabled shaper >/dev/null 2>&1; then
                   systemctl disable shaper >/dev/null 2>&1
                   echo -e "  ${Y}⚠ ${T[sv_auto_no]}${N}"
               else
                   systemctl enable shaper >/dev/null 2>&1
                   echo -e "  ${G}✓ ${T[sv_auto_yes]}${N}"
               fi
               sleep 2 ;;
            5) title "${T[sv_logs]}"
               # оба юнита: движок и сторож — штрафы пишет именно сторож
               journalctl -u shaper -u shaper-watch -n 40 --no-pager |
                   sed 's/^/  /'; pause ;;
            6) title "${T[dr_title]}"; doctor; pause ;;
            7) screen_update ;;
            8) screen_lang ;;
            9) screen_metrics ;;
           10) screen_api ;;
           11) screen_backup ;;
           12) screen_uninstall ;;
            0|"") return ;;
        esac
    done
}

# ── Главное меню ──────────────────────────────────────────────────────
[[ -z "$UI_LANG" ]] && screen_lang     # первый запуск — спросить язык

nlim=0
while :; do
    clear
    echo
    banner
    hr
    status_line
    hr
    echo
    nlim="$(limited_count)"
    echo -e "  [1] 🎚  ${T[m1]} ${D}${T[m1d]}${N}"
    echo -e "  [2] 🚦 ${T[m2]} ${D}${T[m2d]}${N}"
    echo -e "  [3] 📡 ${T[m3]} ${D}${T[m3d]}${N}"
    echo -e "  [4] 📊 ${T[m4]} ${D}${T[m4d]}${N}"
    echo -e "  [5] 📨 ${T[m5]} ${D}${T[m5d]}${N}"
    if [[ "$nlim" != "0" ]]; then
        echo -e "  [6] 🚫 ${T[m6]} ${R}($nlim)${N}"
    else
        echo -e "  [6] 🚫 ${T[m6]} ${D}(0)${N}"
    fi
    echo -e "  [7] 🤍 ${T[m7]}"
    echo -e "  [8] 🔧 ${T[m8]} ${D}${T[m8d]}${N}"
    # Панель переехала сюда из «Сервиса»: ею пользуются каждый день, а Сервис —
    # это редкие операции вроде обновления и удаления.
    if pn_enabled; then
        echo -e "  [9] 🛰  ${T[pn_menu]} ${G}${T[g_on]}${N}"
    else
        echo -e "  [9] 🛰  ${T[pn_menu]} ${D}${T[pn_menu_d]}${N}"
    fi
    if cdn_enabled; then
        echo -e " [10] 🌐 ${T[cdn_menu]} ${G}${T[g_on]}${N}"
    else
        echo -e " [10] 🌐 ${T[cdn_menu]} ${D}${T[cdn_menu_d]}${N}"
    fi
    echo -e "  [0] 🚪 ${T[m0]}"
    hr
    # Ссылка живёт только здесь, в подвале главного экрана: на рабочих
    # экранах ей не место — они и так плотные.
    echo -e "  ☕ ${D}${T[credit]} · ${T[donate]}: ${DONATE_URL}${N}"
    echo
    case "$(ask "${T[choice]}")" in
        1) screen_limit ;;
        2) screen_guard ;;
        3) "$CTL" monitor ;;
        4) screen_stats ;;
        5) screen_telegram ;;
        6) screen_limited ;;
        7) screen_whitelist ;;
        8) screen_service ;;
        9) screen_panel ;;
        10) screen_cdn ;;
        0|"") clear; exit 0 ;;
    esac
done

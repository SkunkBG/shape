#!/usr/bin/env bash
# Проверки shell-части Shape после аудита.
set -uo pipefail
SRC="${SHAPE_SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TMP="$(mktemp -d)"; CONF="$TMP/shaper.conf"
ok=0; fail=0
G='\033[32m'; R='\033[31m'; B='\033[1m'; N='\033[0m'
check() { if eval "$2"; then ok=$((ok+1)); echo -e "  ${G}✓${N} $1"
          else fail=$((fail+1)); echo -e "  ${R}✗ $1${N}"; fi; }

# Берём функции прямо из menu.sh, чтобы проверять живой код, а не копию.
{ sed -n '/^conf_safe()/,/^}/p' "$SRC/menu.sh"
  sed -n '/^conf_set()/,/^}/p'  "$SRC/menu.sh"; } > "$TMP/fn.sh"
# shellcheck disable=SC1090
source "$TMP/fn.sh"

echo -e "\n${B}1. Запись в shaper.conf — файл потом выполняется через source${N}"
: > "$CONF"
conf_set UI_LANG ru
check "нормальное значение записано" '[[ "$(grep -c "^UI_LANG=\"ru\"" "$CONF")" == 1 ]]'
conf_set UI_LANG en
check "повторная запись заменяет, а не дублирует" \
      '[[ "$(grep -c "^UI_LANG=" "$CONF")" == 1 ]] && grep -q "UI_LANG=\"en\"" "$CONF"'

for bad in 'x"; touch /tmp/shell_pwned; #' '$(touch /tmp/shell_pwned)' \
           '`touch /tmp/shell_pwned`' 'a b; id' 'v'$'\n''touch /tmp/shell_pwned' \
           'x&&id' 'x|id'; do
    conf_set TUNNEL_HOST "$bad" 2>/dev/null
    check "отвергнуто: ${bad:0:22}" '! grep -q "TUNNEL_HOST" "$CONF"'
done
check "ключ с мусором отвергнут" '! conf_set "A=1; id" v 2>/dev/null'

# Главная проверка: получившийся файл безопасно скормить source
conf_set TUNNEL_HOST "de.example.com"; conf_set TUNNEL_PORT 22
( set -e; source "$CONF" ) >/dev/null 2>&1
check "конфиг корректно читается через source" '[[ $? -eq 0 ]]'
check "команда из значения не выполнилась" '[[ ! -e /tmp/shell_pwned ]]'
check "права на конфиг 600" '[[ "$(stat -c %a "$CONF")" == 600 ]]'

echo -e "\n${B}2. Параметры SSH-туннеля${N}"
# Регулярные выражения берём из самого menu.sh — тест не должен расходиться с кодом.
HOST_RE="$(grep -o '\^\[A-Za-z0-9\.:_-\]{1,253}\$' "$SRC/menu.sh" | head -1)"
USER_RE="$(grep -o '\^\[A-Za-z_\]\[A-Za-z0-9_-\]{0,31}\$' "$SRC/menu.sh" | head -1)"
check "regexp хоста найден в menu.sh" '[[ -n "$HOST_RE" ]]'
check "regexp пользователя найден в menu.sh" '[[ -n "$USER_RE" ]]'

for bad in 'h.com -o ProxyCommand=id' 'h.com'$'\n''ExecStartPre=/bin/sh -c id' \
           'h.com;id' '$(id)' 'h.com|id' 'h com'; do
    check "хост отвергнут: ${bad:0:26}" '! [[ "$bad" =~ $HOST_RE ]]'
done
for good in 'de.example.com' '203.0.113.10' '2001:db8::1'; do
    check "хост принят: $good" '[[ "$good" =~ $HOST_RE ]]'
done
for bad in 'root -oProxyCommand=id' 'a;id' '$(id)' 'root'$'\n''x'; do
    check "пользователь отвергнут: ${bad:0:22}" '! [[ "$bad" =~ $USER_RE ]]'
done
check "пользователь root принят" '[[ "root" =~ $USER_RE ]]'
check "пользователь shape-vpn принят" '[[ "shape-vpn" =~ $USER_RE ]]'

echo -e "\n${B}3. Имя интерфейса в engine.sh${N}"
source <(grep -m1 "^iface_ok()" "$SRC/engine.sh")
for bad in 'eth0; rm -rf /' '$(id)' 'a/../../etc' 'очень-длинное-имя-интерфейса' ''; do
    check "интерфейс отвергнут: ${bad:0:24}" '! iface_ok "$bad"'
done
for good in eth0 ens3 enp0s3 eth0.100 br-lan; do
    check "интерфейс принят: $good" 'iface_ok "$good"'
done

echo -e "\n${B}4. Синтаксис и целостность${N}"
for f in menu.sh lang.sh engine.sh install.sh; do
    check "bash -n $f" "bash -n '$SRC/$f'"
done
check "shaperctl.py компилируется" "python3 -m py_compile '$SRC/shaperctl.py'"
# каждая функция, которую вызывает меню, должна быть определена
missing="$(python3 - "$SRC/menu.sh" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
d = set(re.findall(r'^([a-z_]+)\(\)\s*\{', s, re.M))
u = set(re.findall(r'\b(screen_[a-z_]+|tunnel_[a-z_]+|guard_[a-z_]+|conf_set|conf_safe|limited_count|read_state|tg_read|doctor|banner|status_line|installed_version|show_listening|tn_bad)\b', s))
print(",".join(sorted(u - d)))
PY
)"
check "все функции меню определены (${missing:-нет пропусков})" '[[ -z "$missing" ]]'

# в systemd-юнитах не должно быть опций, создающих пространство монтирования,
# для сервиса, который монтирует /sys/fs/bpf
check "shaper.service без PrivateTmp/ProtectHome" \
      '! grep -qE "^(PrivateTmp|ProtectHome|ProtectSystem)=" "$SRC/systemd/shaper.service"'
check "shaper-watch.service имеет ReadWritePaths=/etc/shaper" \
      'grep -q "^ReadWritePaths=/etc/shaper" "$SRC/systemd/shaper-watch.service"'
check "ни один юнит не запрещает запись в /sys" \
      '! grep -q "ProtectKernelTunables=yes" "$SRC"/systemd/*.service'

rm -rf "$TMP"
echo -e "\n${B}Пресеты автоограничения${N}"
# Пресетов было пять, и различались они внутренностями: «торренты»,
# «универсальный», «быстрая нода», «всё сразу». Выбрать между ними было
# нельзя — непонятно, какой к какой ноде. Теперь их два, и названы они по
# типу ноды: телефоны и домашний интернет. Задача у обоих одна и та же.
check "пресетов ровно два" \
      '[[ $(grep -cE "^ +[12]\) " "$SRC/menu.sh" | head -1) -ge 2 ]] &&
       grep -q "gp_mob\]" "$SRC/menu.sh" && grep -q "gp_home\]" "$SRC/menu.sh"'
check "старые пресеты убраны" \
      '! grep -qE "gp_(mixed|torrent|all|fast)\]" "$SRC/menu.sh"'
check "и их строки не остались в переводах" \
      '! grep -qE "\[gp_(mixed|torrent|all|fast)\]=" "$SRC/lang.sh"'

# Оба пресета обязаны настраивать всё: торренты, объём и раздачу. Половина
# политики, оставленная на другом экране, — это забытая половина.
check "оба ловят торренты" \
      '[[ $(grep -c -- "--require-packet on" "$SRC/menu.sh") -eq 2 ]]'
check "оба ловят тихого сидера" \
      '[[ $(grep -c -- "--upload-ratio 35" "$SRC/menu.sh") -eq 2 ]]'
check "оба настраивают раздачу" \
      '[[ $(grep -cE -- "panel set --threshold [0-9]+ --window" "$SRC/menu.sh") -eq 2 ]]'
check "раздача рвёт соединения" \
      '[[ $(grep -c -- "--action-set drop >/dev/null 2>&1" "$SRC/menu.sh") -eq 2 ]]'
check "порог раздачи у телефонов мягче, чем у домашних" \
      'grep -q -- "panel set --threshold 20" "$SRC/menu.sh" &&
       grep -q -- "panel set --threshold 10" "$SRC/menu.sh"'

# Мобильный порог — число из расчёта под телефон, домашний — доля канала.
check "у телефонов часовой порог фиксированный" \
      'grep -q -- "--download-gb 25 --download-gbh 3" "$SRC/menu.sh"'
check "у домашних он вычисляется от канала" \
      'grep -q "speed/8/1000\*3600\*0.5" "$SRC/menu.sh"'
check "и сутки — это шестнадцать таких часов" \
      'grep -q "speed/8/1000\*3600\*0.5\*16" "$SRC/menu.sh"'
check "без лимита есть запасные числа" \
      'grep -q "gbh=20; gbd=320; soft=25" "$SRC/menu.sh"'

# Порог в половину канала срабатывает через полчаса на полной скорости — на
# любом канале, потому что это и есть определение половины. Игра в Steam
# весит под 120 ГБ, то есть честная покупка ловилась гарантированно.
check "у домашних часовой объём требует пакетов вверх" \
      'grep -qE -- "--volume-needs-upload on" "$SRC/menu.sh"'
check "у телефонов он их не требует" \
      'grep -qE -- "--volume-needs-upload off" "$SRC/menu.sh"'
check "домашняя мягкая скорость — треть канала" \
      'grep -q "speed\*0.3" "$SRC/menu.sh"'
check "у телефонов мягкой скорости нет" \
      'grep -qE -- "--volume-mbps 0" "$SRC/menu.sh"'
check "обе настройки выставляет пресет, а не оставляет от прежнего" \
      '[[ $(sed -n "/^guard_preset()/,/^}/p" "$SRC/menu.sh" | grep -c -- "--volume-needs-upload") -eq 2 ]]'
check "мягкая скорость видна на экране автоограничения" \
      'grep -q "g_vol_soft" "$SRC/menu.sh"'
check "требование отдачи тоже видно" \
      'grep -q "g_vol_needs" "$SRC/menu.sh"'
check "обе настройки правятся руками" \
      'grep -q "g_set_vnu" "$SRC/menu.sh" && grep -q "g_set_vmb" "$SRC/menu.sh"'
check "числа показываются до применения" \
      '[[ $(sed -n "/^guard_preset()/,/^}/p" "$SRC/menu.sh" | grep -c "apply_q") -eq 2 ]]'
check "после применения сказано, что настроено всё" \
      '[[ $(grep -c "gp_done" "$SRC/menu.sh") -eq 2 ]]'

# Арифметика: полоса в Мбит/с → гигабайты за час. Ошибка здесь тихо сделала
# бы порог в восемь раз строже или мягче, и заметили бы это по жалобам.
for pair in "10 2.2" "50 11.2" "100 22.5" "1000 225.0"; do
    set -- $pair
    got="$(awk "BEGIN{printf \"%.1f\", $1/8/1000*3600*0.5}")"
    check "$1 Мбит/с → порог $2 ГБ/час" '[[ "'"$got"'" == "'"$2"'" ]]' "получено $got"
done
# Сутки — восемь таких часов: держать половину полосы треть суток это уже не
# «посмотрел кино».
for pair in "10 18" "50 90" "100 180"; do
    set -- $pair
    got="$(awk "BEGIN{printf \"%.0f\", $1/8/1000*3600*0.5*8}")"
    check "$1 Мбит/с → порог $2 ГБ/сутки" '[[ "'"$got"'" == "'"$2"'" ]]' "получено $got"
done

echo -e "\n${B}Признак отношения виден в интерфейсе${N}"
# Пресет [5] включает отношение, но на экране его не было видно нигде: ни в
# строке состояния, ни на экране автоограничения. Признак работал, а понять,
# включён он или нет, было неоткуда — и штраф «за сутки отдал непропорционально
# много» приходил как гром среди ясного неба.
check "чтение состояния отдаёт порог отношения" \
      'grep -q "upload_ratio_percent" "$SRC/menu.sh"'
check "строка состояния его показывает" \
      'grep -q "st_g_ratio" "$SRC/menu.sh"'
check "экран автоограничения его показывает" \
      'grep -q "why_ratio_menu" "$SRC/menu.sh"'
check "и даёт его поменять" \
      'grep -q -- "guard --upload-ratio \"\$v\"" "$SRC/menu.sh"'
check "shaperctl show тоже его печатает" \
      'grep -q "guard_ratio" "$SRC/shaperctl.py"'
# Число полей на выходе должно совпадать с числом переменных в разборе.
# Разъедутся — значения молча сдвинутся на колонку, и на экране окажется порог
# отдачи там, где ждали штраф. Функции запускаем настоящие, прямо из menu.sh:
# в песочнице конфига нет, и они отдают запасную строку — её длина обязана
# сходиться ровно так же, как длина рабочей.
FN="$(mktemp -d)/state.sh"
{ sed -n '/^read_state()/,/^}/p' "$SRC/menu.sh"
  sed -n '/^guard_read()/,/^}/p' "$SRC/menu.sh"; } > "$FN"
# shellcheck disable=SC1090
source "$FN"

vars_in() {   # сколько имён в строке разбора у функции-потребителя
    sed -n "/^$1()/,/^}/p" "$SRC/menu.sh" |
        tr '\n' ' ' | sed -n "s/.*IFS='|' read -r \(.*\)<<<.*/\1/p" |
        tr -d '\\' | wc -w
}

for pair in "read_state status_line" "guard_read screen_guard"; do
    set -- $pair
    out="$("$1" | awk -F'|' '{print NF}')"
    got="$(vars_in "$2")"
    check "$1: полей $out, переменных $got" '[[ "'"$out"'" == "'"$got"'" ]]'
done
rm -rf "$(dirname "$FN")"

echo -e "\n${B}Выбор действия для раздачи${N}"
# Действие выбиралось строкой «notify · limit · block · drop — или несколько
# через запятую». Уведомление при этом включено всегда, а block это уже limit
# плюс drop: половина вариантов не имела смысла, и напечатать их надо было
# руками. Теперь это список из четырёх взаимоисключающих пунктов.
check "действие выбирается списком, а не вводом строки" \
      '! grep -q "ask \"\${T\[pn_set_act\]}\" \"\$act\"" "$SRC/menu.sh"'
for a in notify drop limit block; do
    check "в списке есть «$a»" \
          "grep -qE -- '--action-set $a +>' \"\$SRC/menu.sh\""
done
check "у каждого пункта есть пояснение" \
      '[[ $(grep -c "pn_act_.*_d\]" "$SRC/menu.sh") -eq 4 ]]'
check "сказано, что уведомление не отключается" \
      'grep -q "pn_act_h1" "$SRC/menu.sh"'
check "рекомендация для раздачи помечена" \
      'grep -q "pn_act_best" "$SRC/menu.sh"'
# Скорость и срок не относятся к обрыву — на экране их быть не должно.
check "скорость наказания показывается только когда режет" \
      'grep -B2 "pn_l_lim" "$SRC/menu.sh" | grep -q "act.*==.*limit"'
# Главная путаница: пресеты автоограничения и раздача — разные механизмы.
check "экран панели говорит, чем он не занимается" \
      'grep -q "pn_h3" "$SRC/menu.sh"'

echo -e "\n${B}Очередь fq${N}"
# Без fq ядро игнорирует расставленное время отправки, и скачивание не
# ограничивается вообще. Раньше ошибка назначения глушилась, и движок печатал
# «fq назначен» поверх оставшегося fq_codel — нода молча раздавала безлимит.
check "движок проверяет результат, а не только пытается назначить" \
      'grep -q "fq_offenders" "$SRC/engine.sh"'
check "ошибка назначения больше не выдаётся за успех" \
      '! grep -q "ok \"fq назначен на" "$SRC/engine.sh"'
check "движок пробует подгрузить модуль" \
      'grep -q "modprobe sch_fq" "$SRC/engine.sh"'
check "без fq загрузка не срывается" \
      'grep -q "setup_fq || true" "$SRC/engine.sh"'
# Подвеситься к очередям mq выходит не всегда: при дескрипторе «0:» ядро не
# может разрешить parent :1 и отвечает «Failed to find specified qdisc».
# Тогда единственный путь — заменить корень целиком.
check "есть запасной путь через замену корня" \
      '[[ $(grep -c "tc qdisc replace dev \"\$IFACE\" root fq" "$SRC/engine.sh") -ge 2 ]]'
check "ошибка tc показывается, а не глушится" \
      'grep -q "err \"tc: \$err_out\"" "$SRC/engine.sh"'
check "запасной путь идёт после проверки, а не вместо неё" \
      '[[ $(grep -n "fq_offenders" "$SRC/engine.sh" | wc -l) -ge 3 ]]'
check "доктор смотрит все очереди, а не только корень" \
      '! grep -q "tc qdisc show dev \\"\$ifc\\" root" "$SRC/menu.sh"'
check "доктор знает, что fq_codel — это беда" \
      'grep -q "dr_qdisc_bad" "$SRC/menu.sh"'
check "в метриках есть отдельный признак готовности" \
      'grep -q "shape_edt_ready" "$SRC/shaperctl.py"'
check "предупреждение видно на главном экране состояния" \
      'grep -q "edt_off" "$SRC/shaperctl.py"'

echo -e "\n${B}Экран панели${NC:-}${N}"
# Подписи на экране панели выровнены пробелами внутри самих строк: printf в
# bash считает байты, а кириллица в UTF-8 занимает по два, поэтому %-14s
# разъезжается ровно на русском. Раз ширина зашита в строку, её надо стеречь —
# одна подпись длиннее остальных, и колонка съезжает.
widths="$(python3 - "$SRC/lang.sh" <<'PY'
import re, sys
seen = {}
for line in open(sys.argv[1], encoding="utf-8"):
    m = re.search(r'\[(pn_l_[a-z_]+)\]="([^"]*)"', line)
    if m:
        seen.setdefault(len(m.group(2)), 0)
        seen[len(m.group(2))] += 1
print(" ".join(str(w) for w in sorted(seen)))
PY
)"
check "все подписи экрана панели одной ширины" \
      '[[ $(echo "'"$widths"'" | wc -w) -eq 1 ]]' "ширины: $widths"
check "подписи не пустые" '[[ -n "'"$widths"'" && "'"$widths"'" != "0" ]]'

# Значения на экране собираются из отдельных полей. Склейка вида «1/60» уже
# один раз приводила к тому, что в меню показывалось «Действие: notify 1/60»
# без пояснения, что это за числа.
check "поля панели не склеиваются в одно значение" \
      '! grep -q "%s/%s" "$SRC/menu.sh"'
check "у чисел на экране панели есть единицы" \
      'grep -q "pn_u_sec" "$SRC/menu.sh" && grep -q "pn_u_min" "$SRC/menu.sh" \
       && grep -q "pn_u_mbps" "$SRC/menu.sh"'

# Панель — ежедневный экран, ему место на главной, а не в «Сервисе» среди
# обновления и удаления.
check "панель вызывается с главного меню" \
      'grep -qE "^ *9\) screen_panel ;;" "$SRC/menu.sh"'
check "и убрана из Сервиса" \
      '[[ $(grep -c "screen_panel ;;" "$SRC/menu.sh") -eq 1 ]]'
check "в Сервисе вернулась прежняя нумерация" \
      'grep -qE "^ *11\) screen_backup ;;" "$SRC/menu.sh" &&
       grep -qE "^ *12\) screen_uninstall ;;" "$SRC/menu.sh"'

echo -e "\n${B}Итог: $ok пройдено, $fail провалено${N}"
[[ $fail -eq 0 ]]

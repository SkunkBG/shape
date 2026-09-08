#!/usr/bin/env bash
# engine.sh — сборка, загрузка и снятие eBPF-шейпера.
#   load | unload | reload | build | state
set -euo pipefail

APP_DIR="/opt/shaper"
ETC_DIR="/etc/shaper"
CONF="$ETC_DIR/shaper.conf"
BPF_SRC="$APP_DIR/bpf/shaper.bpf.c"
BPF_OBJ="$APP_DIR/bpf/shaper.bpf.o"
PIN_ROOT="/sys/fs/bpf/shaper"
PIN_MAPS="$PIN_ROOT/maps"
PIN_PROGS="$PIN_ROOT/progs"

G='\033[32m'; R='\033[31m'; Y='\033[33m'; N='\033[0m'
ok()   { echo -e "  ${G}✓${N} $*"; }
warn() { echo -e "  ${Y}⚠${N} $*"; }
err()  { echo -e "  ${R}✗${N} $*" >&2; }
die()  { err "$*"; exit 1; }

[[ $EUID -eq 0 ]] || die "нужны права root"

# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"
IFACE="${IFACE:-}"

# Имя интерфейса подставляется в команды tc и в пути внутри /sys. Даже если в
# конфиг попадёт мусор, дальше этой строки он не пройдёт: длина имени в Linux
# ограничена 15 символами, и ничего кроме букв, цифр, точки, дефиса и @ там
# быть не может (@ бывает у VLAN-интерфейсов вида eth0@if2).
iface_ok() { [[ "$1" =~ ^[A-Za-z0-9._@-]{1,15}$ ]]; }
if [[ -n "$IFACE" ]] && ! iface_ok "$IFACE"; then
    err "недопустимое имя интерфейса в $CONF — определяю автоматически"
    IFACE=""
fi

need_iface() {
    [[ -n "$IFACE" ]] || IFACE="$(ip route get 1.1.1.1 2>/dev/null |
                                  sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)"
    [[ -n "$IFACE" ]] || die "не удалось определить интерфейс, задай IFACE в $CONF"
    iface_ok "$IFACE" || die "недопустимое имя интерфейса: $IFACE"
    [[ -d "/sys/class/net/$IFACE" ]] || die "интерфейс $IFACE не существует"

    # Фильтр читает L2-заголовок безусловно. На туннельных и tun-устройствах
    # его нет, eth->h_proto попадает в середину IP-заголовка, и программа
    # отдаёт TC_ACT_OK на каждом пакете. Снаружи это неотличимо от здоровья:
    # движок загружен, фильтры на месте, qdisc noqueue, edt_ready единица.
    #
    # Не die: где-то такие ноды уже стоят, и уронить им сервис при обновлении
    # хуже, чем оставить как есть с предупреждением.
    local arphrd
    arphrd="$(cat "/sys/class/net/$IFACE/type" 2>/dev/null || echo '?')"
    if [[ "$arphrd" != "1" ]]; then
        err "интерфейс $IFACE не Ethernet (type=$arphrd)"
        err "НИЧЕГО НЕ БУДЕТ ОГРАНИЧЕНО: фильтр читает L2-заголовок, а на"
        err "туннельных и tun-устройствах его нет"
        warn "задайте физический интерфейс: IFACE=\"eth0\" в $CONF"
    fi
}

# ── Сборка ────────────────────────────────────────────────────────────
build() {
    command -v clang >/dev/null || die "clang не установлен"
    mkdir -p "$(dirname "$BPF_OBJ")"

    local arch
    case "$(uname -m)" in
        x86_64)  arch=x86   ;;
        aarch64) arch=arm64 ;;
        armv7l)  arch=arm   ;;
        *)       arch="$(uname -m)" ;;
    esac

    # -g обязателен: карты описаны современным синтаксисом в секции .maps,
    # без BTF libbpf откажется открывать объект («BTF is required»).
    clang -O2 -g -target bpf \
          -D__TARGET_ARCH_"$arch" \
          -I/usr/include/"$(uname -m)"-linux-gnu \
          -c "$BPF_SRC" -o "$BPF_OBJ" 2>&1 | sed 's/^/    /' || die "не собралось"

    bpftool btf dump file "$BPF_OBJ" >/dev/null 2>&1 \
        || warn "в объекте нет BTF — проверь, что установлен libbpf-dev"
    ok "eBPF собран: $BPF_OBJ"
}

# ── qdisc ─────────────────────────────────────────────────────────────
# Какие qdisc допустимы на интерфейсе, кроме самого fq. mq — контейнер для
# очередей многоочередной карты, clsact — точка подвеса наших фильтров,
# noqueue — заглушка. Всё остальное означает, что скачивание не ограничивается.
FQ_OK_KINDS="fq mq clsact noqueue"

fq_offenders() {
    tc qdisc show dev "$IFACE" 2>/dev/null | awk -v ok="$FQ_OK_KINDS" '
        BEGIN { split(ok, a, " "); for (i in a) good[a[i]] = 1 }
        $2 != "" && !($2 in good) { print $2 }' | sort -u | tr '\n' ' '
}

setup_fq() {
    # EDT работает, только если пакет уходит через fq: единственный qdisc,
    # который читает skb->tstamp и придерживает пакет до назначенного времени.
    #
    # fq_codel, стоящий по умолчанию в Debian и Ubuntu, это поле игнорирует.
    # Движок будет исправно расставлять время отправки, а ядро отправит всё
    # сразу — ограничение скачивания просто не работает. Отдача при этом
    # работает: она сделана на ведре с отбрасыванием, ей fq не нужен.
    #
    # Поэтому мало попытаться назначить fq — надо проверить, что назначилось.
    # Раньше ошибка глушилась и печаталось «fq назначен», хотя на очередях
    # оставался fq_codel. Нода молча раздавала безлимит вниз, а в мониторе
    # висели полтораста процентов от лимита, и понять причину было нечем.
    local root n
    modprobe sch_fq 2>/dev/null || true
    root="$(tc qdisc show dev "$IFACE" root 2>/dev/null | head -1)"

    # Сначала пробуем не трогать mq: он раздаёт очереди по ядрам процессора,
    # и заменять его целиком стоит только если иначе никак.
    if [[ "$root" == qdisc\ mq\ * ]]; then
        n="$(find "/sys/class/net/$IFACE/queues" -maxdepth 1 -name 'tx-*' | wc -l)"
        for ((i = 1; i <= n; i++)); do
            tc qdisc replace dev "$IFACE" parent ":$i" fq 2>/dev/null || true
        done
    elif [[ "$root" != *" fq "* && "$root" != *" fq" ]]; then
        tc qdisc replace dev "$IFACE" root fq 2>/dev/null || true
    fi

    # Запасной путь: заменить корень целиком.
    #
    # Нужен потому, что подвеситься к очередям mq выходит не всегда. Бывает
    # дескриптор «0:» — тогда parent :1 ядру не разрешить, и tc отвечает
    # «Failed to find specified qdisc». Это не отсутствие fq, а невозможность
    # найти родителя, и по сообщению это неочевидно.
    #
    # Один fq на весь интерфейс вместо очереди на ядро — небольшая потеря
    # параллелизма, незаметная на десятках мегабит. Скачивание без
    # ограничения — потеря куда большая.
    local bad err_out
    bad="$(fq_offenders)"
    if [[ -n "$bad" ]]; then
        warn "к очередям $IFACE подвеситься не вышло, заменяю корневой qdisc"
        err_out="$(tc qdisc replace dev "$IFACE" root fq 2>&1)" || true
        bad="$(fq_offenders)"
        [[ -n "$bad" && -n "$err_out" ]] && err "tc: $err_out"
    fi

    if [[ -n "$bad" ]]; then
        err "на $IFACE остались очереди: ${bad% }"
        err "СКАЧИВАНИЕ НЕ ОГРАНИЧИВАЕТСЯ — fq не встал, а без него ядро"
        err "игнорирует расставленное время отправки. Отдача при этом работает."
        warn "если fq нет в ядре, поможет пакет linux-modules-extra"
        return 1
    fi
    ok "fq активен — скачивание ограничивается"
}

# ── Привязки PROXY protocol переживают перезагрузку ────────────────────
#
# Заголовок PROXY приходит один раз, в начале TCP-соединения, и больше не
# повторяется. Раньше unload_quiet сносил pp_conn_map вместе с остальными
# картами, и все живые сессии через CDN до самого закрытия шли мимо
# ограничения. Замерено 03.09: через шесть минут после reload 20% байт без
# шейпинга, средний пакет 1100 байт — настоящие данные, а не хендшейки.
# Спад медленный, часами: через 443 идут долгоживущие сессии.
#
# Поэтому содержимое карты снимаем до выгрузки и возвращаем после загрузки.
#
# Восстановление добровольное: любая осечка означает ровно то, что было
# раньше, и ронять из-за неё загрузку шейпера нельзя. Отсюда `|| true` и
# `return 0` в каждой ветке.
#
# ВАЖНО: если менять раскладку struct pp_key или struct pp_conn — старые
# байты в новую карту класть нельзя, они будут разобраны как другой клиент,
# и чужой трафик пойдёт в учёт. Размеры ключа и значения сверяются ниже, но
# перестановку полей той же длины проверка не поймает. Меняете раскладку —
# уберите вызов pp_restore на это одно обновление.
# Куда сбрасывается карта, когда выгрузка и загрузка — РАЗНЫЕ процессы.
#
# `engine.sh reload` спасает привязки сам: там pp_save и pp_restore живут в
# одном вызове. А `systemctl restart shaper` — это ExecStop (`unload`) и
# ExecStart (`load`) по отдельности, и к моменту загрузки карты уже нет.
# Через неё же идёт обновление: install.sh заканчивается restart.
# Замерено 05.09 на живом обновлении: доля трафика без привязки 10,8% → 22,8%.
#
# Файл в /run намеренно: он переживает перезапуск службы и умирает при
# перезагрузке машины — а после перезагрузки восстанавливать нечего, там и
# соединений уже нет.
PP_SPILL_DIR="/run/shaper"
PP_SPILL="$PP_SPILL_DIR/pp_conn.json"
# Дамп старше этого не берём: соединений давно нет, а порт релея уже мог
# достаться другому клиенту — вернув такую привязку, мы приписали бы ему
# чужой трафик. Ровно та ошибка, что чинилась в fins, только другой дверью.
PP_SPILL_MAX_AGE=120

PP_PIN=""
PP_DUMP=""

pp_save() {
    PP_PIN="$PIN_MAPS/pp_conn_map"
    PP_DUMP=""
    [[ -e "$PP_PIN" ]] || return 0
    local d
    d="$(mktemp /run/shaper-pp.XXXXXX 2>/dev/null)" || return 0
    chmod 600 "$d" 2>/dev/null || true
    # В дампе адреса клиентов, поэтому файл 600 и удаляется сразу после.
    if bpftool map dump pinned "$PP_PIN" -j >"$d" 2>/dev/null \
       && bpftool map show pinned "$PP_PIN" -j >"$d.meta" 2>/dev/null; then
        chmod 600 "$d.meta" 2>/dev/null || true
        PP_DUMP="$d"
    else
        rm -f "$d" "$d.meta" 2>/dev/null || true
    fi
    return 0
}

pp_adopt_spill() {
    # Подобрать то, что оставил предыдущий процесс при выгрузке.
    [[ -s "$PP_SPILL" && -s "$PP_SPILL.meta" ]] || return 0
    local age now mtime
    now="$(date +%s 2>/dev/null || echo 0)"
    mtime="$(stat -c %Y "$PP_SPILL" 2>/dev/null || echo 0)"
    age=$(( now - mtime ))
    if (( age < 0 || age > PP_SPILL_MAX_AGE )); then
        warn "привязки PROXY из прошлого запуска устарели (${age} с) — не восстанавливаю"
        rm -f "$PP_SPILL" "$PP_SPILL.meta" 2>/dev/null || true
        return 0
    fi
    PP_DUMP="$PP_SPILL"
    return 0
}

pp_restore() {
    # В памяти пусто — значит выгрузка была отдельным процессом
    # (systemctl restart, обновление). Берём то, что она оставила.
    [[ -n "$PP_DUMP" && -s "$PP_DUMP" ]] || pp_adopt_spill
    [[ -n "$PP_DUMP" && -s "$PP_DUMP" ]] || { ok "привязок PROXY не нашлось"; pp_forget; return 0; }
    local batch n
    batch="$(mktemp /run/shaper-pp.XXXXXX 2>/dev/null)" || { pp_forget; return 0; }
    chmod 600 "$batch" 2>/dev/null || true
    n="$(PP_PIN="$PP_PIN" python3 "$APP_DIR/pp_restore.py" \
            "$PP_DUMP" "$PP_DUMP.meta" "$batch" 2>/dev/null)" || n=""
    if [[ -z "$n" ]]; then
        warn "привязки PROXY не восстановлены — раскладка карты изменилась или дамп не разобрался"
    elif [[ "$n" == "0" ]]; then
        ok "привязок PROXY не было — восстанавливать нечего"
    elif bpftool batch file "$batch" >/dev/null 2>&1; then
        ok "привязки PROXY восстановлены: $n"
    else
        warn "привязки PROXY не восстановились — сессии через CDN пойдут без ограничения до переустановки"
    fi
    rm -f "$batch" 2>/dev/null || true
    pp_forget
    return 0
}

pp_forget() {
    [[ -n "$PP_DUMP" ]] && rm -f "$PP_DUMP" "$PP_DUMP.meta" 2>/dev/null || true
    rm -f "$PP_SPILL" "$PP_SPILL.meta" 2>/dev/null || true
    PP_DUMP=""
    return 0
}

# ── Загрузка ──────────────────────────────────────────────────────────
load() {
    need_iface
    for b in clang bpftool tc ip; do
        command -v "$b" >/dev/null || die "не найден $b — запусти install.sh"
    done

    mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
    [[ -f "$BPF_OBJ" && "$BPF_OBJ" -nt "$BPF_SRC" ]] || build

    # Снимаем привязки PROXY ДО выгрузки: unload_quiet сносит карты.
    pp_save
    unload_quiet
    mkdir -p "$PIN_ROOT"

    # libbpf 1.0+ не понимает SEC("classifier/down") — «unrecognized ELF
    # section name». Явный `type classifier` снимает вопрос. На старых libbpf
    # аргумент тоже поддерживается, но на всякий случай пробуем и без него.
    local out
    if ! out="$(bpftool prog loadall "$BPF_OBJ" "$PIN_PROGS" type classifier \
                   pinmaps "$PIN_MAPS" 2>&1)"; then
        rm -rf "$PIN_PROGS" "$PIN_MAPS" 2>/dev/null || true
        warn "загрузка с явным типом не прошла, пробую по имени секции"
        echo "$out" | sed 's/^/      /'
        if ! out="$(bpftool prog loadall "$BPF_OBJ" "$PIN_PROGS" \
                       pinmaps "$PIN_MAPS" 2>&1)"; then
            echo "$out" | sed 's/^/      /' >&2
            err "bpftool не смог загрузить eBPF-программу"
            echo "      • «BTF is required»         — объект собран без -g" >&2
            echo "      • «unrecognized ELF section» — несовместимость libbpf" >&2
            echo "      • «Operation not permitted»  — ядро без поддержки BPF" >&2
            exit 1
        fi
    fi

    [[ -e "$PIN_PROGS/shaper_down" && -e "$PIN_PROGS/shaper_up" ]] \
        || die "программы не нашлись в $PIN_PROGS: $(ls "$PIN_PROGS" 2>/dev/null | tr '\n' ' ')"
    ok "программа загружена, карты закреплены в $PIN_MAPS"

    # Возвращаем привязки до того, как фильтры пойдут в дело: иначе первые
    # пакеты живых сессий успеют уехать без ограничения.
    pp_restore

    # Без fq загрузку не отменяем: учёт, отдача и белый список работают и
    # так, а нода без шейпера вообще — хуже, чем нода с половиной шейпера.
    # Но и молчать нельзя, поэтому setup_fq кричит сам.
    setup_fq || true
    tc qdisc add dev "$IFACE" clsact 2>/dev/null || true

    tc filter add dev "$IFACE" egress  bpf da pinned "$PIN_PROGS/shaper_down" \
        || die "не прицепился фильтр на egress"
    tc filter add dev "$IFACE" ingress bpf da pinned "$PIN_PROGS/shaper_up" \
        || die "не прицепился фильтр на ingress"
    ok "фильтры повешены на $IFACE (egress + ingress)"

    "$APP_DIR/shaperctl.py" restore | sed 's/^/  /'
    [[ -f "$ETC_DIR/whitelist.txt" ]] && "$APP_DIR/shaperctl.py" whitelist sync | sed 's/^/  /'
    # Список доверенных источников: без него развёртка IPIP и разбор PROXY
    # protocol не работают вовсе, и клиенты за туннелем или за CDN разом
    # теряют лимиты. Карта не переживает перезагрузку движка — грузим заново.
    [[ -f "$ETC_DIR/trusted.txt" ]] && "$APP_DIR/shaperctl.py" trusted sync | sed 's/^/  /'

    echo "IFACE=\"$IFACE\"" > "$ETC_DIR/.active_iface"
    # Событие в общий журнал: его читает API, а в будущем — центральная система.
    "$APP_DIR/shaperctl.py" event engine_started --source engine \
        --message "iface=$IFACE" 2>/dev/null || true
    ok "шейпер запущен"
}

unload_quiet() {
    local prev="" ifc
    if [[ -f "$ETC_DIR/.active_iface" ]]; then
        # Файл пишем сами, но читаем его как чужой: он попадает в source.
        prev="$(sed -n 's/^IFACE="\([A-Za-z0-9._@-]\{1,15\}\)"$/\1/p' \
                "$ETC_DIR/.active_iface" | head -1)"
    fi
    # И с текущего интерфейса, и с прошлого. Раньше снимали только с текущего,
    # и после смены IFACE в конфиге программа оставалась висеть на прежнем:
    # если оба интерфейса живы, трафик шейпился дважды. Повтор при совпадении
    # безвреден — второй del просто не найдёт, что удалять.
    for ifc in "${IFACE:-}" "$prev"; do
        [[ -n "$ifc" ]] || continue
        iface_ok "$ifc" || continue
        [[ -d "/sys/class/net/$ifc" ]] || continue
        tc filter del dev "$ifc" egress  2>/dev/null || true
        tc filter del dev "$ifc" ingress 2>/dev/null || true
        tc qdisc  del dev "$ifc" clsact  2>/dev/null || true
    done
    pp_spill
    rm -rf "$PIN_PROGS" "$PIN_MAPS" 2>/dev/null || true
}

pp_spill() {
    # Сохранить привязки для следующего процесса. Осечка ничего не ломает:
    # получится ровно прежнее поведение, поэтому все ветки возвращают 0.
    local pin="$PIN_MAPS/pp_conn_map"
    [[ -e "$pin" ]] || return 0
    mkdir -p "$PP_SPILL_DIR" 2>/dev/null || return 0
    chmod 700 "$PP_SPILL_DIR" 2>/dev/null || true
    # В дампе адреса клиентов, поэтому файл создаётся сразу закрытым.
    ( umask 077
      bpftool map dump pinned "$pin" -j >"$PP_SPILL" 2>/dev/null &&
      bpftool map show pinned "$pin" -j >"$PP_SPILL.meta" 2>/dev/null ) ||
        { rm -f "$PP_SPILL" "$PP_SPILL.meta" 2>/dev/null; return 0; }
    return 0
}

unload() {
    unload_quiet
    "$APP_DIR/shaperctl.py" event engine_stopped --source engine 2>/dev/null || true
    ok "шейпер выгружен (qdisc fq оставлен — он безвреден)"
}

state() {
    need_iface
    local loaded=no filters
    [[ -d "$PIN_MAPS" ]] && loaded=yes
    filters="$(tc filter show dev "$IFACE" egress 2>/dev/null | grep -c shaper || true)"
    echo "iface=$IFACE loaded=$loaded egress_filters=$filters"
    [[ "$loaded" == yes && "$filters" -gt 0 ]]
}

case "${1:-}" in
    load)   load ;;
    unload) unload ;;
    # Без отдельного unload_quiet: load() выгружает сам, а до этого успевает
    # снять привязки PROXY. Раньше карты сносились здесь, и снимать было нечего.
    reload) load ;;
    build)  build ;;
    state)  state ;;
    *) echo "использование: $0 {load|unload|reload|build|state}"; exit 1 ;;
esac

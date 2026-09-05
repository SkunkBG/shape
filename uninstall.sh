#!/usr/bin/env bash
# uninstall.sh — снятие Shape с ноды.
#
# Одна реализация на всех: её вызывает и меню (Сервис → Удалить Shape), и
# `install.sh --uninstall`. Дублировать такие вещи нельзя — разойдутся, и
# один из путей однажды оставит на ноде висящую eBPF-программу.
#
# Порядок здесь важнее, чем кажется:
#   1. остановить службы;
#   2. снять программу с интерфейса, пока /opt/shaper ещё на месте —
#      после удаления файлов engine.sh уже не запустить, и фильтры
#      останутся на nic до перезагрузки;
#   3. убрать файл метрик из каталога node_exporter — иначе Prometheus
#      будет вечно показывать снятую ноду живой;
#   4. и только потом удалять сами файлы.
set -uo pipefail

# Пути переопределяются переменными окружения — так же, как в shaperctl.
# Нужно это ровно для одного: прогнать удаление целиком в песочнице. Скрипт
# разрушительный, и проверять его грепом по исходнику — самообман.
APP_DIR="${SHAPE_APP_DIR:-/opt/shaper}"
ETC_DIR="${SHAPE_ETC_DIR:-/etc/shaper}"
VAR_DIR="${SHAPE_VAR_DIR:-/var/lib/shape}"
UNIT_DIR="${SHAPE_UNIT_DIR:-/etc/systemd/system}"
BPF_PIN="${SHAPER_PIN_ROOT:-/sys/fs/bpf/shaper}"

G='\033[32m'; R='\033[31m'; Y='\033[33m'; B='\033[1m'; D='\033[90m'; N='\033[0m'
ok()   { echo -e "  ${G}✓${N} $*"; }
warn() { echo -e "  ${Y}⚠${N} $*"; }
step() { echo; echo -e "${B}$*${N}"; }

# Root нужен, только когда трогаем настоящие системные пути. С заданными
# SHAPE_*_DIR мы работаем в песочнице и ничего системного не касаемся.
if [[ "$APP_DIR" == "/opt/shaper" ]]; then
    [[ $EUID -eq 0 ]] || { echo -e "${R}запускай от root${N}" >&2; exit 1; }
fi

PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1

# Скрипт живёт внутри каталога, который сам же и удаляет. Bash дочитывает
# файл по ходу выполнения, поэтому работаем с копией во временном каталоге —
# иначе удаление /opt/shaper способно оборвать нас на середине.
if [[ "$(readlink -f "$0")" == "$(readlink -f "$APP_DIR")"/* && -z "${SHAPE_UNINSTALL_DETACHED:-}" ]]; then
    tmp="$(mktemp /tmp/shape-uninstall.XXXXXX)" || exit 1
    cp "$0" "$tmp" && chmod +x "$tmp"
    SHAPE_UNINSTALL_DETACHED=1 exec bash "$tmp" "$@"
fi
[[ -n "${SHAPE_UNINSTALL_DETACHED:-}" ]] && trap 'rm -f "$0"' EXIT

step "Остановка служб"
for unit in shaper-watch shaper shape-api shape-metrics.timer shape-metrics \
            shape-push.timer shape-push shape-tunnel; do
    if systemctl list-unit-files "$unit"* >/dev/null 2>&1; then
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
    fi
done
ok "службы остановлены и сняты с автозапуска"

step "Снятие программы с интерфейса"
# Пока файлы на месте: engine.sh знает, какой интерфейс трогать, и убирает
# и фильтры, и pinned-карты. Корневой qdisc fq он намеренно оставляет —
# он безвреден и часто нужен другому софту на той же машине.
if [[ -x "$APP_DIR/engine.sh" ]]; then
    "$APP_DIR/engine.sh" unload >/dev/null 2>&1 && ok "eBPF снят с интерфейса" \
        || warn "engine.sh отработал с ошибкой, проверим вручную"
else
    warn "engine.sh не найден — снимаю вручную"
fi

# Подстраховка на случай, когда engine.sh отсутствует или упал.
iface="$(sed -n 's/^IFACE="\([A-Za-z0-9._@-]\{1,15\}\)"$/\1/p' \
         "$ETC_DIR/.active_iface" 2>/dev/null | head -1)"
if [[ -n "$iface" && -d "/sys/class/net/$iface" ]]; then
    tc filter del dev "$iface" egress  2>/dev/null || true
    tc filter del dev "$iface" ingress 2>/dev/null || true
    tc qdisc  del dev "$iface" clsact  2>/dev/null || true
fi
rm -rf "$BPF_PIN" 2>/dev/null || true

left=""
[[ -n "$iface" ]] && left="$(tc filter show dev "$iface" egress 2>/dev/null)"
if [[ -n "$left" ]]; then
    warn "на $iface остались фильтры — посмотрите: tc filter show dev $iface egress"
else
    ok "фильтров на интерфейсе не осталось"
fi

step "SSH-туннель"
# Туннель ставится мастером из меню и тоже принадлежит Shape: оставить его
# после удаления значит оставить работающее ssh-соединение наружу. Ключ не
# трогаем — он может быть заведён и для другого, а генерируется отдельно.
if [[ -f "$UNIT_DIR/shape-tunnel.service" ]]; then
    rm -f "$UNIT_DIR/shape-tunnel.service"
    ok "туннель убран (ключ /root/.ssh/shape_tunnel оставлен)"
else
    ok "туннеля не было"
fi

step "Метрики"
# Файл в каталоге node_exporter надо убрать обязательно: он статический,
# и Prometheus продолжал бы отдавать по нему цифры снятой ноды как живые.
prom="$(sed -n 's/^SHAPE_TEXTFILE=//p' "$ETC_DIR/metrics.env" 2>/dev/null | head -1)"
if [[ -n "$prom" && -f "$prom" ]]; then
    rm -f "$prom"
    ok "убран $prom"
else
    ok "файла метрик не было"
fi

step "Удаление юнитов"
rm -f "$UNIT_DIR/shaper.service" \
      "$UNIT_DIR/shaper-watch.service" \
      "$UNIT_DIR/shape-api.service" \
      "$UNIT_DIR/shape-metrics.service" \
      "$UNIT_DIR/shape-metrics.timer" \
      "$UNIT_DIR/shape-push.service" \
      "$UNIT_DIR/shape-push.timer" \
      "$UNIT_DIR/shape-tunnel.service"
systemctl daemon-reload
ok "юниты удалены"

step "Удаление файлов"
rm -rf "$APP_DIR" "${SHAPE_BIN:-/usr/local/bin/shaper}" \
    /usr/local/bin/shaperctl /usr/local/bin/shaperctl.py
ok "программа удалена"

if (( PURGE )); then
    rm -rf "$ETC_DIR" "$VAR_DIR"
    ok "настройки, токены, идентификатор ноды и история удалены"
else
    echo -e "  ${D}настройки оставлены: $ETC_DIR и $VAR_DIR${N}"
    echo -e "  ${D}при повторной установке нода сохранит свой идентификатор${N}"
fi

step "Готово"
echo -e "  ${D}корневой qdisc fq оставлен намеренно — он безвреден${N}"
echo -e "  ${D}вернуть Shape: git clone … && bash install.sh${N}"
echo

#!/usr/bin/env bash
# install.sh — установка шейпера. Запускать из распакованной папки проекта.
set -euo pipefail

APP_DIR="/opt/shaper"
ETC_DIR="/etc/shaper"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

G='\033[32m'; R='\033[31m'; Y='\033[33m'; B='\033[1m'; D='\033[90m'; N='\033[0m'
ok()   { echo -e "  ${G}✓${N} $*"; }
step() { echo; echo -e "${B}$*${N}"; }
die()  { echo -e "  ${R}✗ $*${N}" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "запускай от root: sudo bash install.sh"

# Установка API — по флагу. Без него Shape ставится ровно как раньше:
# API не должен становиться обязательной частью ни для кого.
WITH_API=0
[[ "${1:-}" == "--with-api" ]] && { WITH_API=1; shift; }
# Обновление не должно тихо оставлять старый код API: если сервис уже стоит,
# обновляем его вместе с остальным, даже когда флаг не передали.
[[ -f /etc/systemd/system/shape-api.service ]] && WITH_API=1

api_remove() {
    systemctl disable --now shape-api >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/shape-api.service
    systemctl daemon-reload
}

if [[ "${1:-}" == "--uninstall-api" ]]; then
    step "Удаление API"
    api_remove
    # Конфиг с токенами оставляем: переустановят — токены не поменяются,
    # и центральной системе не придётся ничего перевыпускать.
    ok "API удалён, Shape продолжает работать"
    systemctl is-active shaper >/dev/null 2>&1 \
        && ok "shaper.service работает" \
        || echo -e "  ${Y}⚠ shaper.service не запущен — это не связано с API${N}"
    exit 0
fi

# Полное снятие Shape. Сама логика живёт в uninstall.sh — одна реализация
# и для командной строки, и для меню. Держать её в двух местах нельзя: они
# разойдутся, и один из путей однажды оставит на ноде висящую eBPF-программу
# или файл метрик, по которому Prometheus будет считать ноду живой.
if [[ "${1:-}" == "--uninstall" ]]; then
    shift
    for candidate in "$SRC/uninstall.sh" "$APP_DIR/uninstall.sh"; do
        [[ -f "$candidate" ]] && exec bash "$candidate" "$@"
    done
    die "uninstall.sh не найден — возьмите его из репозитория"
fi

step "Проверка ядра"
KV="$(uname -r)"
awk -v v="${KV%%-*}" 'BEGIN{split(v,a,".");exit !(a[1]>5||(a[1]==5&&a[2]>=4))}' \
    || die "нужно ядро 5.4+, у тебя $KV"
ok "ядро $KV подходит"

step "Установка зависимостей"
if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq clang llvm libbpf-dev linux-libc-dev \
        iproute2 python3 >/dev/null
    command -v bpftool >/dev/null || apt-get install -y -qq bpftool >/dev/null 2>&1 \
        || apt-get install -y -qq "linux-tools-$(uname -r)" >/dev/null 2>&1 || true
elif command -v dnf >/dev/null; then
    dnf install -y -q clang llvm libbpf-devel kernel-headers iproute python3 bpftool >/dev/null
elif command -v yum >/dev/null; then
    yum install -y -q clang llvm libbpf-devel kernel-headers iproute python3 bpftool >/dev/null
else
    die "не знаю твой пакетный менеджер — поставь: clang, llvm, libbpf-dev, bpftool, iproute2"
fi

for b in clang bpftool tc python3; do
    command -v "$b" >/dev/null || die "$b так и не установился"
done
ok "clang, bpftool, tc, python3 на месте"

step "Очистка от прошлых версий"
# Демон Telegram-уведомлений и файлы правил из старой модели с правилами 0-7.
if [[ -f /etc/systemd/system/shaper-notify.service ]]; then
    systemctl disable --now shaper-notify >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/shaper-notify.service
    ok "убран shaper-notify.service"
fi
rm -f /var/lib/shaper/notify.state "$ETC_DIR/rules.json" "$ETC_DIR/rules.json.mib.bak"
rmdir /var/lib/shaper 2>/dev/null || true
# Объект пересобираем всегда: структуры карт могли поменяться между версиями.
rm -f "$APP_DIR/bpf/shaper.bpf.o"
ok "старые файлы убраны"

step "Копирование файлов"
mkdir -p "$APP_DIR/bpf" "$ETC_DIR"
# В config.json лежит токен бота, в shaper.conf — адрес зарубежной ноды.
# Читать это кому-то кроме root незачем, а сам каталог доступен только root.
chmod 750 "$ETC_DIR"
# Изменчивое состояние: журнал событий. Отдельно от настроек.
mkdir -p /var/lib/shape && chmod 750 /var/lib/shape

# Постоянный идентификатор ноды. Создаётся один раз и переживает обновления:
# по нему мониторинг узнаёт узел даже после переезда на другой сервер и смены
# имени хоста. Существующий не перезаписываем — иначе история порвётся.
if [[ ! -s /var/lib/shape/node_id ]]; then
    head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n' > /var/lib/shape/node_id
    echo >> /var/lib/shape/node_id
    chmod 644 /var/lib/shape/node_id
fi
install -m 755 "$SRC/shaperctl.py"     "$APP_DIR/shaperctl.py"
install -m 755 "$SRC/engine.sh"        "$APP_DIR/engine.sh"
install -m 755 "$SRC/pp_restore.py"    "$APP_DIR/pp_restore.py"
# Удаление должно быть доступно с самой ноды: меню вызывает именно этот файл.
install -m 755 "$SRC/uninstall.sh"     "$APP_DIR/uninstall.sh"
install -m 755 "$SRC/menu.sh"          "$APP_DIR/menu.sh"
install -m 644 "$SRC/lang.sh"          "$APP_DIR/lang.sh"
install -m 644 "$SRC/VERSION"          "$APP_DIR/VERSION"
install -m 644 "$SRC/bpf/shaper.bpf.c" "$APP_DIR/bpf/shaper.bpf.c"

[[ -f "$ETC_DIR/config.json" ]] || echo '{"ports": [443], "speed_mbps": 0}' > "$ETC_DIR/config.json"
[[ -f "$ETC_DIR/penalties.json" ]] || echo '{}' > "$ETC_DIR/penalties.json"
chmod 600 "$ETC_DIR/config.json" "$ETC_DIR/penalties.json" 2>/dev/null || true
[[ -f "$ETC_DIR/shaper.conf" ]] || cat > "$ETC_DIR/shaper.conf" <<'EOF'
# Сетевой интерфейс. Пусто = определить автоматически по маршруту в интернет.
IFACE=""
EOF
[[ -f "$ETC_DIR/whitelist.txt" ]] || cat > "$ETC_DIR/whitelist.txt" <<'EOF'
# IP, к которым не применяется лимит. По одному в строке.
# Их трафик по-прежнему виден в мониторе и статистике — считаем всех,
# ограничиваем не всех.
# 203.0.113.10
EOF
chmod 600 "$ETC_DIR/shaper.conf" 2>/dev/null || true
chmod 640 "$ETC_DIR/whitelist.txt" 2>/dev/null || true
ok "файлы в $APP_DIR, конфиг в $ETC_DIR"

# Хеш коммита, из которого ставим: по нему пункт «Обновить» понимает,
# есть ли в репозитории что-то новее. Номер версии лежит в файле VERSION.
if [[ -d "$SRC/.git" ]] && command -v git >/dev/null; then
    git -C "$SRC" rev-parse --short HEAD > "$APP_DIR/.commit" 2>/dev/null || true
fi
rm -f "$APP_DIR/.version"   # имя из версий до 1.3

step "Сборка eBPF"
if ! "$APP_DIR/engine.sh" build; then
    if [[ -d "$APP_DIR.bak" ]]; then
        echo -e "  ${Y}⚠ откатываюсь на прошлую версию${N}"
        rm -rf "$APP_DIR"
        mv "$APP_DIR.bak" "$APP_DIR"
        systemctl restart shaper 2>/dev/null || true
        die "новая версия не собралась, вернул прежнюю — она работает"
    fi
    die "eBPF не собрался"
fi

step "Регистрация сервиса"
install -m 644 "$SRC/systemd/shaper.service"       /etc/systemd/system/
install -m 644 "$SRC/systemd/shaper-watch.service" /etc/systemd/system/
systemctl daemon-reload

# Автостарт обязателен: без него после перезагрузки сервера лимит не применится,
# а клиенты молча получат безлимит. Проверяем результат, а не надеемся на него.
systemctl enable shaper >/dev/null 2>&1 || true
systemctl enable shaper-watch >/dev/null 2>&1 || true
if systemctl is-enabled shaper >/dev/null 2>&1; then
    ok "автостарт включён — переживёт перезагрузку сервера"
else
    echo -e "  ${R}✗ автостарт включить не удалось${N}"
    echo -e "  ${Y}  после ребута шейпер не поднимется, включи вручную:${N}"
    echo -e "  ${Y}  systemctl enable shaper${N}"
fi

# Файлы API кладём всегда, а сервис включаем только по флагу. Так API можно
# включить потом из меню, ничего не скачивая, и при этом обычная установка
# Shape остаётся установкой Shape: ни одного лишнего работающего процесса.
mkdir -p "$APP_DIR/api"
install -m 750 "$SRC/api/server.py" "$APP_DIR/api/server.py"
install -m 644 "$SRC/systemd/shape-api.service" "$APP_DIR/api/shape-api.service"
# Юниты для метрик кладём всегда: мастер мониторинга из меню берёт их отсюда,
# а сам мониторинг может понадобиться и без API.
mkdir -p "$APP_DIR/systemd"
install -m 644 "$SRC/systemd/shape-metrics.service" "$APP_DIR/systemd/"
install -m 644 "$SRC/systemd/shape-metrics.timer"   "$APP_DIR/systemd/"
install -m 644 "$SRC/systemd/shape-push.service"    "$APP_DIR/systemd/"
install -m 644 "$SRC/systemd/shape-push.timer"      "$APP_DIR/systemd/"

if (( WITH_API )); then
    step "Установка API"
    install -m 644 "$SRC/systemd/shape-api.service" /etc/systemd/system/
    systemctl daemon-reload
    # Токены генерирует сам сервис при первом запуске и кладёт в api.json
    # с правами 600. В репозитории и в установщике их нет.
    "$APP_DIR/api/server.py" --print-tokens >/dev/null 2>&1 || true
    systemctl enable --now shape-api >/dev/null 2>&1 || true
    if systemctl is-active shape-api >/dev/null 2>&1; then
        ok "API работает на $(python3 -c "
import json
try:
    c = json.load(open('$ETC_DIR/api.json'))
    print('%s:%s' % (c.get('bind_address','127.0.0.1'), c.get('port',8765)))
except Exception: print('127.0.0.1:8765')" 2>/dev/null)"
        echo -e "  ${D}токены: shaper → Сервис → API${N}"
    else
        echo -e "  ${Y}⚠ API не стартанул: journalctl -u shape-api -n 30${N}"
        echo -e "  ${D}на работу шейпера это не влияет${N}"
    fi
fi

cat > /usr/local/bin/shaper <<'EOF'
#!/usr/bin/env bash
if [[ $EUID -ne 0 ]] && command -v sudo >/dev/null; then exec sudo /opt/shaper/menu.sh "$@"; fi
exec /opt/shaper/menu.sh "$@"
EOF
chmod +x /usr/local/bin/shaper

# Вторая команда — для того, что описано в README и в подсказках. Её не было,
# и «shaperctl.py panel show» из сообщения в Telegram отвечало «command not
# found»: сам файл лежит в /opt/shaper и в PATH не входит.
#
# Псевдоним с .py — ради обратной совместимости: этим именем команда названа
# в семидесяти местах документации и во всех прошлых release notes.
cat > /usr/local/bin/shaperctl <<'EOF'
#!/usr/bin/env bash
if [[ $EUID -ne 0 ]] && command -v sudo >/dev/null; then exec sudo /opt/shaper/shaperctl.py "$@"; fi
exec /opt/shaper/shaperctl.py "$@"
EOF
chmod +x /usr/local/bin/shaperctl
ln -sf /usr/local/bin/shaperctl /usr/local/bin/shaperctl.py
ok "команды shaper и shaperctl созданы"

step "Запуск"
# Именно restart: при обновлении сервис уже запущен, и `start` был бы пустышкой —
# в ядре осталась бы eBPF-программа прошлой версии.
if systemctl restart shaper; then
    ok "движок запущен"
    systemctl restart shaper-watch 2>/dev/null || true
    rm -rf "$APP_DIR.bak"
    "$APP_DIR/shaperctl.py" show
else
    echo -e "  ${Y}⚠ не стартанул — смотри: journalctl -u shaper -n 40${N}"
    [[ -d "$APP_DIR.bak" ]] && echo -e "  ${D}прошлая версия лежит в $APP_DIR.bak${N}"
fi

echo
echo -e "${B}Готово.${N} Shape v$(cat "$APP_DIR/VERSION" 2>/dev/null || echo '?')$(
    [[ -f "$APP_DIR/.commit" ]] && echo " · $(cat "$APP_DIR/.commit")")"
echo -e "  Запусти ${B}shaper${N}$([[ "$(python3 -c "
import json
try: print(json.load(open('$ETC_DIR/config.json'))['speed_mbps'])
except Exception: print(0)" 2>/dev/null)" == "0" ]] && echo " → «Настроить лимит»" || echo "")"
echo

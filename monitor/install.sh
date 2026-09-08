#!/usr/bin/env bash
# Разворачивание сервера мониторинга Shape на чистой VPS.
#
# Спрашивает три вещи — домен, почту и пароль — и дальше не трогает человека
# вообще. Хеш пароля считает сам, файлы пишет сам, стек поднимает сам.
#
# Так было не всегда. Первая версия копировала пример с ненастоящим хешем и
# оставляла человека наедине с шестью шагами в двух консолях; на середине
# выяснялось, что коды подтверждения лежат в файле внутри контейнера. Всё,
# что можно посчитать за человека, здесь считается за человека.
#
# Запускать НА СЕРВЕРЕ МОНИТОРИНГА, а не на ноде.
set -euo pipefail

B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; D=$'\e[90m'; N=$'\e[0m'
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$HERE/.env"
USERS_FILE="$HERE/authelia/users.yml"
AUTHELIA_IMAGE="authelia/authelia:4.38"

say()   { echo -e "  $*"; }
head_() { echo; echo -e "${B}$*${N}"; }
die()   { echo -e "  ${R}$*${N}" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "нужен root: sudo bash monitor/install.sh"

head_ "Проверка окружения"
command -v docker >/dev/null || die "docker не установлен: https://docs.docker.com/engine/install/"
docker compose version >/dev/null 2>&1 || die "нужен docker compose v2 (плагин compose)"
say "${G}✓${N} docker и compose на месте"

# Секреты берём у ядра, а не у $RANDOM: $RANDOM даёт 15 бит и предсказуем.
gen() { head -c 48 /dev/urandom | base64 | tr -d '/+=' | head -c "${1:-40}"; }

# Хеш пароля считает сама Authelia — своим же алгоритмом и своими же
# параметрами. Способа два, потому что флаг --password появился не во всех
# сборках, а пароль в аргументах виден в ps. Сначала пробуем через stdin.
hash_password() {
    local pw="$1" out=""
    out="$(printf '%s\n%s\n' "$pw" "$pw" \
           | docker run --rm -i "$AUTHELIA_IMAGE" \
             authelia crypto hash generate argon2 2>/dev/null \
           | grep -oE '\$argon2id\$[^[:space:]]+' | head -1 || true)"
    if [[ -z "$out" ]]; then
        out="$(docker run --rm "$AUTHELIA_IMAGE" \
               authelia crypto hash generate argon2 --password "$pw" 2>/dev/null \
               | grep -oE '\$argon2id\$[^[:space:]]+' | head -1 || true)"
    fi
    [[ -n "$out" ]] || return 1
    printf '%s' "$out"
}

head_ "Настройка"
if [[ -f "$ENV_FILE" ]]; then
    say "${Y}!${N} $ENV_FILE уже есть — оставляю как есть"
    say "${D}удалите его, если хотите начать заново${N}"
    # shellcheck disable=SC1090
    set -a; source "$ENV_FILE"; set +a
else
    read -rp "  Домен, без поддомена (например example.com): " DOMAIN
    [[ -n "$DOMAIN" ]] || die "без домена сертификаты не выпустить"
    case "$DOMAIN" in
        http*|*/*) die "нужно только имя: example.com, без https:// и без /" ;;
        *.*) : ;;
        *)   die "в домене должна быть точка" ;;
    esac

    read -rp "  Почта (Let's Encrypt и вход в гейт): " ACME_EMAIL
    [[ "$ACME_EMAIL" == *@*.* ]] || die "адрес нужен настоящий, с точкой в домене"

    # Пароль спрашиваем сразу, здесь. Раньше его задавали потом, отдельной
    # командой, и половина установок останавливалась на этом месте.
    echo
    say "${D}Пароль для входа на страницу гейта. Логин будет: admin${N}"
    say "${D}Пустой ввод — сгенерирую случайный и покажу.${N}"
    read -rsp "  Пароль: " GATE_PW; echo
    if [[ -z "$GATE_PW" ]]; then
        GATE_PW="$(gen 20)"
        GATE_SHOWN=1
    else
        read -rsp "  Ещё раз: " GATE_PW2; echo
        [[ "$GATE_PW" == "$GATE_PW2" ]] || die "пароли не совпали"
        [[ ${#GATE_PW} -ge 8 ]] || die "пароль короче восьми знаков — так нельзя"
        GATE_SHOWN=0
    fi

    say "${D}считаю хеш…${N}"
    GATE_HASH="$(hash_password "$GATE_PW")" \
        || die "не удалось посчитать хеш — проверьте, что docker тянет образы"

    PUSH_TOKEN="$(gen 48)"
    GRAFANA_PW="$(gen 24)"
    umask 077
    cat > "$ENV_FILE" <<EOF
# Создан $(date -Is). Секреты — не для репозитория.
SHAPE_DOMAIN=$DOMAIN
ACME_EMAIL=$ACME_EMAIL

# Токен, которым ноды подписывают отправку метрик.
SHAPE_PUSH_TOKEN=$PUSH_TOKEN

# Пароль администратора Grafana — второй слой после гейта.
GRAFANA_ADMIN_PASSWORD=$GRAFANA_PW

AUTHELIA_SESSION_SECRET=$(gen 64)
AUTHELIA_STORAGE_ENCRYPTION_KEY=$(gen 64)
AUTHELIA_JWT_SECRET=$(gen 64)
EOF
    say "${G}✓${N} $ENV_FILE создан, права 600"

    cat > "$USERS_FILE" <<EOF
# Создан установщиком $(date -Is). Пароль задан вами, здесь только хеш.
#
# Сменить пароль:
#   docker run --rm -it $AUTHELIA_IMAGE authelia crypto hash generate argon2
# и заменить строку password ниже, затем:
#   docker compose --project-directory $HERE restart authelia
users:
  admin:
    disabled: false
    displayname: 'Владелец'
    password: '$GATE_HASH'
    email: '$ACME_EMAIL'
    groups:
      - admins
EOF
    chmod 600 "$USERS_FILE"
    say "${G}✓${N} $USERS_FILE создан, пароль внутри уже рабочий"
    # shellcheck disable=SC1090
    set -a; source "$ENV_FILE"; set +a
fi

# Стек не поднимается с нерабочим паролем. Authelia не может разобрать чужой
# хеш и падает при старте — раз в минуту, бесконечно; Caddy при этом не
# находит контейнер по имени и отдаёт 502 на всё подряд. Человек видит
# «no such host» и ищет беду в сети, а беда в файле паролей.
if [[ ! -f "$USERS_FILE" ]] || ! grep -q 'argon2id' "$USERS_FILE"; then
    die "в $USERS_FILE нет рабочего хеша пароля — удалите .env и запустите заново"
fi

head_ "Что получится"
say "  Графики   : ${B}https://grafana.$SHAPE_DOMAIN${N}"
say "  Вход      : ${B}https://auth.$SHAPE_DOMAIN${N}"
say "  Приём     : ${B}https://push.$SHAPE_DOMAIN/api/v1/import/prometheus${N}"
echo
say "${D}Все три имени должны уже указывать на этот сервер:${N}"
say "${D}Caddy выпускает сертификаты при первом запуске, а Let's Encrypt${N}"
say "${D}ограничивает число неудачных попыток на домен.${N}"
echo
read -rp "  Продолжить? [y/N]: " ans
[[ "$ans" =~ ^[YyДд] ]] || { say "отменено"; exit 0; }

head_ "Проверка конфигурации Authelia"
if docker compose --project-directory "$HERE" run --rm authelia \
        authelia validate-config --config /config/configuration.yml; then
    say "${G}✓${N} конфигурация принята"
else
    die "Authelia не приняла конфигурацию — правьте authelia/configuration.yml"
fi

head_ "Запуск"
docker compose --project-directory "$HERE" up -d
say "${G}✓${N} поднято"

head_ "Готово"
echo
say "  Откройте ${B}https://grafana.$SHAPE_DOMAIN${N}"
echo
say "  Гейт    — логин ${B}admin${N}, пароль тот, что вы задали"
if [[ "${GATE_SHOWN:-0}" == "1" ]]; then
    say "            ${Y}пароль сгенерирован: ${B}$GATE_PW${N}"
    say "            ${D}запишите его — второй раз он нигде не покажется${N}"
fi
say "  Grafana — логин ${B}admin${N}, пароль ${B}${GRAFANA_ADMIN_PASSWORD}${N}"
echo
say "  ${D}Оба пароля лежат в $ENV_FILE (права 600).${N}"
echo
say "  Дальше на каждой ноде:"
echo
say "    ${B}shaperctl metrics set \\\\${N}"
say "    ${B}    --url https://push.$SHAPE_DOMAIN/api/v1/import/prometheus \\\\${N}"
say "    ${B}    --token '$SHAPE_PUSH_TOKEN'${N}"
say "    ${B}shaperctl metrics push${N}"
say "    ${B}systemctl enable --now shape-push.timer${N}"
echo
say "  ${D}Токен даёт право ТОЛЬКО писать метрики: ни читать, ни удалять,${N}"
say "  ${D}ни трогать ноды им нельзя.${N}"
echo

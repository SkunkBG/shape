#!/usr/bin/env bash
# Разворачивание сервера мониторинга Shape на чистой VPS.
#
# Ничего не решает за вас молча: спрашивает домен и почту, генерирует
# секреты, показывает, что получилось, и только потом поднимает.
#
# Запускать НА СЕРВЕРЕ МОНИТОРИНГА, а не на ноде.
set -euo pipefail

B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; D=$'\e[90m'; N=$'\e[0m'
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$HERE/.env"
USERS_FILE="$HERE/authelia/users.yml"

say()  { echo -e "  $*"; }
head_() { echo; echo -e "${B}$*${N}"; }
die()  { echo -e "  ${R}$*${N}" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "нужен root: sudo bash monitor/install.sh"

head_ "Проверка окружения"
command -v docker >/dev/null || die "docker не установлен: https://docs.docker.com/engine/install/"
docker compose version >/dev/null 2>&1 || die "нужен docker compose v2 (плагин compose)"
say "${G}✓${N} docker и compose на месте"

# Секреты берём у ядра, а не у $RANDOM: $RANDOM даёт 15 бит и предсказуем.
gen() { head -c 48 /dev/urandom | base64 | tr -d '/+=' | head -c "${1:-40}"; }

head_ "Настройка"
if [[ -f "$ENV_FILE" ]]; then
    say "${Y}!${N} $ENV_FILE уже есть — оставляю как есть"
    say "${D}удалите его, если хотите начать заново${N}"
else
    read -rp "  Домен (например example.com): " DOMAIN
    [[ -n "$DOMAIN" ]] || die "без домена сертификаты не выпустить"
    # Три имени должны указывать на этот сервер ДО первого запуска: Caddy
    # выпускает сертификаты сразу, а Let's Encrypt ограничивает число
    # неудачных попыток на домен.
    read -rp "  Почта для Let's Encrypt: " ACME_EMAIL
    [[ -n "$ACME_EMAIL" ]] || die "адрес нужен для писем об истечении сертификата"

    PUSH_TOKEN="$(gen 48)"
    umask 077
    cat > "$ENV_FILE" <<EOF
# Создан $(date -Is). Секреты — не для репозитория.
SHAPE_DOMAIN=$DOMAIN
ACME_EMAIL=$ACME_EMAIL

# Токен, которым ноды подписывают отправку метрик.
SHAPE_PUSH_TOKEN=$PUSH_TOKEN

# Пароль администратора Grafana — второй слой после гейта.
GRAFANA_ADMIN_PASSWORD=$(gen 24)

AUTHELIA_SESSION_SECRET=$(gen 64)
AUTHELIA_STORAGE_ENCRYPTION_KEY=$(gen 64)
AUTHELIA_JWT_SECRET=$(gen 64)
EOF
    say "${G}✓${N} $ENV_FILE создан, права 600"
fi

if [[ ! -f "$USERS_FILE" ]]; then
    cp "$HERE/authelia/users.yml.example" "$USERS_FILE"
    chmod 600 "$USERS_FILE"
    say "${Y}!${N} $USERS_FILE создан из примера — пароль в нём нерабочий"
fi

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

head_ "Что получится"
say "  Графики   : ${B}https://grafana.$SHAPE_DOMAIN${N}"
say "  Вход      : ${B}https://auth.$SHAPE_DOMAIN${N}"
say "  Приём      : ${B}https://push.$SHAPE_DOMAIN/api/v1/import/prometheus${N}"
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

head_ "Что дальше"
cat <<EOF
  1. Задайте пароль гейта. Хеш считается так:

       docker run --rm -it authelia/authelia:4.38 \\
           authelia crypto hash generate argon2

     и вписывается в ${B}$USERS_FILE${N}, затем:

       docker compose --project-directory $HERE restart authelia

  2. Зайдите на https://auth.$SHAPE_DOMAIN и настройте второй фактор.
     Ссылка на настройку ложится в файл внутри контейнера:

       docker compose --project-directory $HERE exec authelia \\
           cat /data/notification.txt

  3. Пароль администратора Grafana лежит в $ENV_FILE
     (GRAFANA_ADMIN_PASSWORD). Смените его после первого входа.

  4. На каждой ноде:

       shaperctl metrics set --url https://push.$SHAPE_DOMAIN/api/v1/import/prometheus \\
                             --token '$SHAPE_PUSH_TOKEN'
       shaperctl metrics push
       systemctl enable --now shape-push.timer

  Токен виден и здесь, и в $ENV_FILE. Он даёт право ТОЛЬКО писать метрики:
  ни читать, ни удалять, ни трогать ноды им нельзя.
EOF
echo

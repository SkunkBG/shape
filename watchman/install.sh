#!/usr/bin/env bash
#
# Watchman — установка сторожа тишины для парка нод Remnawave.
#   sudo bash install.sh
#
# Ставится НЕ на ноду. Watchman следит за нодами снаружи и обязан падать
# отдельно от них: сторож, живущий на ноде, молчит ровно тогда, когда нужен.
#
# Повторный запуск безопасен: настройки и накопленная история сохраняются.
set -Eeuo pipefail

APP_DIR="/opt/watchman"
OLD_DIR="/opt/nodewatch"
USER_NAME="watchman"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -t 1 ]]; then
  G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; D=$'\033[2m'; N=$'\033[0m'
else
  G=''; Y=''; R=''; D=''; N=''
fi
ok()   { echo "  ${G}✓${N} $*"; }
warn() { echo "  ${Y}⚠${N} $*"; }
die()  { echo "  ${R}✗${N} $*" >&2; exit 1; }
step() { echo; echo "${D}── $* ─────────────────────────────${N}"; }

[[ $EUID -eq 0 ]] || die "нужен root: sudo bash install.sh"
command -v python3 >/dev/null || die "не найден python3"
command -v systemctl >/dev/null || die "нужен systemd"

# Watchman не должен стоять на ноде. Это не вкусовщина: нода, следящая за
# собой, не сообщит о собственной смерти.
if [[ -d /opt/shaper ]]; then
  warn "на этой машине установлен Shape — похоже, это нода."
  warn "Watchman должен стоять ОТДЕЛЬНО, иначе он умрёт вместе с тем,"
  warn "за чем следит."
  read -rp "  Всё равно продолжить? [y/N]: " a
  [[ "$a" =~ ^[YyДд] ]] || exit 1
fi

step "Пользователь"
if id "$USER_NAME" >/dev/null 2>&1; then
  ok "пользователь $USER_NAME уже есть"
else
  useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
  ok "создан системный пользователь $USER_NAME"
fi

step "Файлы"
mkdir -p "$APP_DIR"
install -m 755 -o "$USER_NAME" -g "$USER_NAME" "$SRC/watchman.py" "$APP_DIR/watchman.py"
install -m 755 -o "$USER_NAME" -g "$USER_NAME" "$SRC/menu.py"     "$APP_DIR/menu.py"
install -m 644 -o "$USER_NAME" -g "$USER_NAME" "$SRC/selftest.py" "$APP_DIR/selftest.py"
install -m 644 -o "$USER_NAME" -g "$USER_NAME" "$SRC/demo.py"     "$APP_DIR/demo.py"
chown "$USER_NAME:$USER_NAME" "$APP_DIR"
chmod 750 "$APP_DIR"
ok "файлы в $APP_DIR"

step "Настройки"
# Перенос с прежнего имени. Конфиг и история дороже: без истории сторож
# восемь минут не может судить ни о чём.
if [[ ! -f "$APP_DIR/config.json" && -f "$OLD_DIR/config.json" ]]; then
  cp -a "$OLD_DIR/config.json" "$APP_DIR/config.json"
  [[ -f "$OLD_DIR/state.json" ]] && cp -a "$OLD_DIR/state.json" "$APP_DIR/state.json"
  ok "настройки и история перенесены из $OLD_DIR"
fi
if [[ ! -f "$APP_DIR/config.json" ]]; then
  install -m 600 -o "$USER_NAME" -g "$USER_NAME" /dev/null "$APP_DIR/config.json"
  cat > "$APP_DIR/config.json" <<'EOF'
{
  "panel_url":   "",
  "panel_token": "",
  "tg_token":    "",
  "tg_chat":     "",
  "tg_thread":   ""
}
EOF
  ok "создан пустой config.json — заполнить через меню"
else
  ok "config.json на месте, не тронут"
fi
# Права выставляем всегда: в файле два токена, и один неудачный
# редактор мог оставить их читаемыми для всех.
chown "$USER_NAME:$USER_NAME" "$APP_DIR/config.json"
chmod 600 "$APP_DIR/config.json"
[[ -f "$APP_DIR/state.json" ]] && { chown "$USER_NAME:$USER_NAME" "$APP_DIR/state.json"; chmod 600 "$APP_DIR/state.json"; }

step "Служба"
install -m 644 "$SRC/systemd/watchman.service" /etc/systemd/system/watchman.service
install -m 644 "$SRC/systemd/watchman.timer"   /etc/systemd/system/watchman.timer
systemctl daemon-reload

# Старое имя убираем, иначе два сторожа будут писать в один чат.
if systemctl list-unit-files 2>/dev/null | grep -q '^nodewatch\.timer'; then
  systemctl disable --now nodewatch.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/nodewatch.{service,timer}
  systemctl daemon-reload
  warn "прежний nodewatch остановлен и снят с автозапуска"
  warn "каталог $OLD_DIR оставлен — удалите руками, когда убедитесь"
fi

systemctl enable --now watchman.timer >/dev/null
ok "таймер включён — опрос раз в минуту, переживёт перезагрузку"

ln -sf "$APP_DIR/menu.py" /usr/local/bin/watchman
ok "команда watchman создана"

step "Готово"
if python3 -c "
import json,sys
c=json.load(open('$APP_DIR/config.json'))
sys.exit(0 if all(str(c.get(k) or '').strip() for k in ('panel_url','panel_token','tg_token','tg_chat')) else 1)
" 2>/dev/null; then
  ok "настройки заполнены"
  echo
  echo "  Проверить: ${G}watchman${N}"
else
  warn "настройки пусты — watchman пока ничего не делает"
  echo
  echo "  Заполнить: ${G}watchman${N} → Панель, затем Telegram"
fi
echo

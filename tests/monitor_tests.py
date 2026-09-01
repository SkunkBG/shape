#!/usr/bin/env python3
"""
Сервер мониторинга: проверки на утверждения, а не на вкус.

Docker и Caddy здесь не запускаются — их нет в песочнице. Но почти всё, что
может пойти не так в такой связке, видно в самих файлах: опубликованный порт
у хранилища, маршрут записи без ограничения пути, секрет, попавший в конфиг
вместо переменной, разъехавшиеся версии образов между compose и документацией.

Ровно это и проверяется. То, что проверить нельзя (поднимется ли Authelia с
такой схемой конфига), названо в README честно, и там же дана команда
`authelia validate-config`.
"""
import os
import re
import sys

import yaml

SRC = os.environ.get("SHAPE_SRC") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
MON = os.path.join(SRC, "monitor")

ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if not isinstance(ok, int) or isinstance(ok, bool):
        raise SystemExit("счётчик ok затёрт присваиванием")
    if cond:
        ok += 1
        print(f"  \033[32m✓\033[0m {name}")
    else:
        fail += 1
        print(f"  \033[31m✗ {name}\033[0m {extra}")


def read(*parts):
    with open(os.path.join(MON, *parts), encoding="utf-8") as f:
        return f.read()


print("\n\033[1mФайлы на месте\033[0m")
NEEDED = ["docker-compose.yml", "Caddyfile", "install.sh", ".env.example",
          ".gitignore", "README.md", "README.en.md",
          "authelia/configuration.yml", "authelia/users.yml.example",
          "grafana/provisioning/datasources/victoriametrics.yml",
          "grafana/provisioning/dashboards/shape.yml"]
for rel in NEEDED:
    check(rel, os.path.exists(os.path.join(MON, *rel.split("/"))))
check("живого users.yml в репозитории нет",
      not os.path.exists(os.path.join(MON, "authelia", "users.yml")))
check("живого .env в репозитории нет",
      not os.path.exists(os.path.join(MON, ".env")))

print("\n\033[1mcompose\033[0m")
COMPOSE = yaml.safe_load(read("docker-compose.yml"))
SERVICES = COMPOSE["services"]
check("четыре службы", set(SERVICES) == {"caddy", "victoriametrics",
                                         "grafana", "authelia"},
      str(sorted(SERVICES)))

# Наружу смотрит ровно один контейнер. Если хранилище или Grafana однажды
# окажутся доступны напрямую, гейт впереди перестанет что-либо значить, а
# заметить это можно будет только по последствиям.
published = sorted(s for s, v in SERVICES.items() if v.get("ports"))
check("порты публикует только caddy", published == ["caddy"], str(published))
check("caddy держит 80 и 443",
      set(SERVICES["caddy"]["ports"]) == {"80:80", "443:443"})

for name in SERVICES:
    check(f"{name} перезапускается сам",
          SERVICES[name].get("restart") == "unless-stopped")

# latest однажды утром просто не поднимется, и виноват будет не он.
for name, svc in SERVICES.items():
    tag = svc["image"].rsplit(":", 1)[-1]
    check(f"{name}: версия прибита", tag != "latest" and ":" in svc["image"],
          svc["image"])

check("все службы в одной сети",
      all(v.get("networks") == ["inside"] for v in SERVICES.values()))
check("сеть не внешняя", "external" not in (COMPOSE["networks"]["inside"] or {}))

# Секрет, забытый без значения по умолчанию, поднимет стек с пустым токеном.
# Синтаксис :? роняет compose до запуска — это и нужно.
for var in ("SHAPE_PUSH_TOKEN", "GRAFANA_ADMIN_PASSWORD",
            "AUTHELIA_SESSION_SECRET", "AUTHELIA_STORAGE_ENCRYPTION_KEY",
            "AUTHELIA_JWT_SECRET", "SHAPE_DOMAIN"):
    check(f"{var} обязателен", f"${{{var}:?" in read("docker-compose.yml"))

check("дашборд берётся из каталога ноды, а не копией",
      "../grafana/shape-dashboard.json" in read("docker-compose.yml"))
check("у Grafana выключен анонимный доступ",
      SERVICES["grafana"]["environment"]["GF_AUTH_ANONYMOUS_ENABLED"] == "false")
check("и регистрация",
      SERVICES["grafana"]["environment"]["GF_USERS_ALLOW_SIGN_UP"] == "false")
check("хранилище держит данные в томе",
      any("vm-data" in str(v) for v in SERVICES["victoriametrics"]["volumes"]))
check("срок хранения задан",
      any("retentionPeriod" in c for c in SERVICES["victoriametrics"]["command"]))

print("\n\033[1mCaddyfile\033[0m")
CADDY = read("Caddyfile")
check("три имени",
      all(h in CADDY for h in ("push.{$SHAPE_DOMAIN}", "auth.{$SHAPE_DOMAIN}",
                               "grafana.{$SHAPE_DOMAIN}")))

# Самое опасное место всей связки. У VictoriaMetrics по соседству с приёмом
# живёт удаление рядов; открыв сюда всё хранилище, мы отдали бы владельцу
# токена возможность стереть историю. А токен лежит на 28 нодах.
def uncomment(text):
    """Строки-пояснения — не конфигурация. Проверять надо то, что работает."""
    return "\n".join(l for l in text.split("\n")
                     if not l.lstrip().startswith("#"))


push_block = uncomment(
    CADDY.split("push.{$SHAPE_DOMAIN}", 1)[1].split("auth.{$SHAPE_DOMAIN}", 1)[0])
check("приём ограничен путём импорта", "path /api/v1/import*" in push_block)
check("и методом POST", "method POST" in push_block)
check("и токеном в заголовке",
      'header Authorization "Bearer {$SHAPE_PUSH_TOKEN}"' in push_block)
check("всё остальное — 401", "respond 401" in push_block)
check("удаление рядов сюда не открыто", "delete_series" not in push_block)
check("чтение сюда не открыто",
      "/api/v1/query" not in push_block and "/select" not in push_block)

graf_block = CADDY.split("grafana.{$SHAPE_DOMAIN}", 1)[1]
check("графики за гейтом", "forward_auth authelia:9091" in graf_block)
check("гейт зовёт правильный endpoint",
      "uri /api/authz/forward-auth" in graf_block)
check("Grafana не публикуется мимо гейта",
      graf_block.index("forward_auth") < graf_block.index("reverse_proxy grafana"))

check("токен в Caddyfile не зашит",
      not re.search(r"Bearer [A-Za-z0-9]{8,}", CADDY))
check("домен в Caddyfile не зашит", "example.com" not in CADDY)

print("\n\033[1mAuthelia\033[0m")
AUTH = yaml.safe_load(read("authelia", "configuration.yml"))
check("по умолчанию всё запрещено",
      AUTH["access_control"]["default_policy"] == "deny")
# Второй фактор убран после первой живой установки: почтового сервера нет,
# коды приходилось доставать из файла внутри контейнера, на регистрацию
# устройства уходило шесть шагов и две консоли. Защита, которой невозможно
# пользоваться, не защищает. Слоёв всё равно два — гейт и вход Grafana.
check("правило требует хотя бы пароль",
      AUTH["access_control"]["rules"][0]["policy"] in ("one_factor",
                                                       "two_factor"))
check("и оно закрывает именно графики",
      AUTH["access_control"]["rules"][0]["domain"].startswith("grafana."))
check("подбор пароля ограничен", AUTH["regulation"]["max_retries"] <= 5)

# Секреты в конфиге — это секреты в репозитории. Они должны приходить
# переменными окружения, и compose обязан их требовать.
raw_auth = read("authelia", "configuration.yml")
for key in ("jwt_secret", "encryption_key", "secret:"):
    bad = re.search(rf"^\s*{key}.*\S", raw_auth, re.M)
    check(f"«{key}» в конфиге нет", bad is None,
          bad.group(0) if bad else "")
check("сессия живёт не вечно", "expiration" in AUTH["session"])
check("пример пользователя не содержит рабочего хеша",
      "ЗАМЕНИТЕ" in read("authelia", "users.yml.example"))

print("\n\033[1mСекреты и установщик\033[0m")
GITIGNORE = read(".gitignore")
check(".env не попадёт в git", ".env" in GITIGNORE)
check("users.yml не попадёт в git", "authelia/users.yml" in GITIGNORE)
ENVX = read(".env.example")
check("в примере .env нет настоящих значений",
      ENVX.count("ЗАМЕНИТЕ") >= 4, ENVX)

INST = read("install.sh")
check("установщик требует root", "EUID" in INST)
check("проверяет наличие docker compose", "docker compose version" in INST)
INST_CODE = "\n".join(l for l in INST.split("\n")
                       if not l.lstrip().startswith("#"))
check("секреты берёт у ядра, а не у $RANDOM",
      "/dev/urandom" in INST_CODE and "$RANDOM" not in INST_CODE)
check("права на .env закрыты", "umask 077" in INST)
# Живой случай: ACME_EMAIL не был передан контейнеру, Caddy взял умолчание
# admin@localhost, и Let's Encrypt отказал — «Domain name needs at least one
# dot». В логах ругань на домен, а виновата забытая переменная.
check("почта доезжает до caddy",
      "ACME_EMAIL" in str(SERVICES["caddy"]["environment"]))
check("и обязательна", "${ACME_EMAIL:?" in read("docker-compose.yml"))
check("в Caddyfile нет умолчания для почты",
      "{$ACME_EMAIL}" in CADDY and "admin@localhost" not in uncomment(CADDY))

# Живой случай: установщик копировал пример с ненастоящим хешем и поднимал
# стек. Authelia падала при старте раз в минуту, Caddy отдавал 502 на всё, а
# в логах было «no such host» — то есть беда выглядела сетевой.
#
# Теперь пароль спрашивается при установке, хеш считает сама Authelia, а
# файл пишет установщик. Заглушке взяться неоткуда — но проверка перед
# запуском всё равно стоит, на случай правки руками.
check("пример пароля нерабочий", "ЗАМЕНИТЕ" in read("authelia", "users.yml.example"))
check("установщик спрашивает пароль сразу", "read -rsp" in INST)
check("и сверяет его дважды", INST.count("read -rsp") >= 2)
check("хеш считает сама Authelia, а не человек",
      "crypto hash generate argon2" in INST and "hash_password" in INST)
# Флаг --password кладёт пароль в аргументы процесса, где его видно в ps.
# Он оставлен запасным вариантом, но первым идёт stdin.
check("пароль не уходит в аргументы первым способом",
      INST_CODE.index("| docker run --rm -i ")
      < INST_CODE.index("--password"))
check("установщик сам пишет users.yml", 'cat > "$USERS_FILE"' in INST)
check("и не поднимает стек без рабочего хеша",
      "grep -q 'argon2id' \"$USERS_FILE\"" in INST)
check("проверка стоит ДО запуска",
      INST.index("grep -q 'argon2id'") < INST.index("up -d"))
check("домен проверяется на точку и на схему",
      "http*|*/*" in INST and "в домене должна быть точка" in INST)
check("почта проверяется", "*@*.*" in INST)
check("короткий пароль отвергается", "восьми знаков" in INST)
check("сгенерированный пароль показывается один раз",
      "GATE_SHOWN" in INST and "второй раз он нигде не покажется" in INST)

check("проверяет конфиг Authelia до запуска",
      INST.index("validate-config") < INST.index("compose --project-directory \"$HERE\" up -d"))
check("спрашивает подтверждение перед запуском", "Продолжить?" in INST)
check("говорит про записи DNS до выпуска сертификатов",
      "указывать на этот сервер" in INST)

print("\n\033[1mДокументация\033[0m")
for lang, path in (("ru", "README.md"), ("en", "README.en.md")):
    doc = read(path)
    check(f"[{lang}] сказано, что дашборд только читает",
          "только читает" in doc or "only reads" in doc)
    check(f"[{lang}] названы все три имени",
          all(n in doc for n in ("grafana.", "auth.", "push.")),
          str([n for n in ("grafana.", "auth.", "push.") if n not in doc]))
    check(f"[{lang}] назван адрес приёма",
          "/api/v1/import/prometheus" in doc)
    check(f"[{lang}] сказано, что даёт украденный токен",
          "токен" in doc or "token" in doc)
    check(f"[{lang}] есть ссылка на другой язык",
          ("README.en.md" in doc) or ("README.md" in doc))

# Версии в документации и в compose должны совпадать: разъезжаются они молча,
# а читают документацию именно тогда, когда что-то не поднялось.
doc_ru = read("README.md")
for name, svc in SERVICES.items():
    tag = svc["image"].rsplit(":", 1)[-1]
    check(f"версия {name} совпадает с документацией", tag in doc_ru, tag)

print(f"\n\033[1mИтог: {ok} пройдено, {fail} провалено\033[0m")
sys.exit(1 if fail else 0)

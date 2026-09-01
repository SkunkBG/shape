#!/usr/bin/env python3
"""
В публичном репозитории не должно быть данных живых людей.

Примеры пишутся с натуры — берёшь настоящую карточку с ноды, вставляешь в
README, и вместе с ней уезжают имя клиента, его ник в Telegram, номер
подписки и адрес. Заметить это глазами нельзя: в тексте на сотню страниц
такая строка ничем не выделяется, а живут документы годами.

Поэтому список разрешённого задан явно и он короткий. Любой новый адрес, ник
или номер надо внести сюда руками — и в этот момент задать себе вопрос,
откуда он взялся.

Адреса берём из диапазонов, отведённых под документацию (RFC 5737):
203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24. Они не маршрутизируются в
интернете и принадлежать никому не могут.
"""
import os
import re
import sys

# Диапазоны, которые не могут указывать на живого человека.
SAFE_PREFIXES = (
    "203.0.113.", "198.51.100.", "192.0.2.",          # RFC 5737, документация
    "10.", "192.168.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.",                   # RFC 1918, приватные
    "127.", "100.64.", "169.254.", "224.", "0.",
)

# Публичные резолверы и заведомо выдуманные адреса из примеров.
SAFE_IPS = {
    "1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
    "1.2.3.4", "5.6.7.8", "7.7.7.7", "255.255.255.255", "999.1.1.1",
    # 203.0.113.5 задом наперёд. Это не адрес, а последствие ошибки порядка
    # байт: так выглядел бы клиент из заголовка PROXY protocol, если собрать
    # его сдвигами вместо копирования байтами (3.75). Стоит в тесте, который
    # эту ошибку ловит, и в CHANGELOG, который её объясняет.
    "5.113.0.203",
}

# Ники, которые заведомо не принадлежат клиентам.
SAFE_HANDLES = {
    "@BotFather",
    # примеры в документации
    "@ivan_k", "@maria_p", "@olga_v", "@petr_s", "@ilya",
    # выдуманные в тестах
    "@bashou7", "@nick_", "@nick_1", "@nick7", "@olga7", "@ivanov",
}

# Числа, которые выглядят как идентификатор Telegram или номер подписки.
SAFE_NUMBERS = {
    "123456789", "987654321", "1001234567890",   # общепринятые заглушки
    "100000001", "100000002", "100000003", "100000004",
    "100000005", "100000006", "100000007", "100000008",
}

EXTS = (".md", ".py", ".sh", ".json", ".c", ".service", ".timer")
SKIP_DIRS = {"__pycache__", ".git", ".github"}
SELF = os.path.basename(__file__)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HANDLE_RE = re.compile(r"(?:^|[^A-Za-z0-9_./@])(@[A-Za-z][A-Za-z0-9_]{4,31})")
# Идентификатор человека ищем не по любому длинному числу — иначе в отчёт
# попадут байты и миллисекунды, — а по соседству с тем, что его называет.
ID_RE = re.compile(
    r"(?:Telegram:\s*|tg://user\?id=|user_|telegram_id\D{0,4})(\d{6,})")


def safe_ip(ip):
    if ip in SAFE_IPS or ip.startswith(SAFE_PREFIXES):
        return True
    parts = ip.split(".")
    # Не адрес, а что-то похожее: версия, число с точками.
    return any(not p.isdigit() or int(p) > 255 for p in parts)


def scan(root):
    problems = []
    for cur, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in sorted(names):
            if not name.endswith(EXTS) or name == SELF:
                continue
            path = os.path.join(cur, name)
            rel = os.path.relpath(path, root)
            with open(path, encoding="utf-8", errors="replace") as f:
                for num, line in enumerate(f, 1):
                    for ip in IP_RE.findall(line):
                        if not safe_ip(ip):
                            problems.append((rel, num, "адрес", ip))
                    # Декораторы Python — не ники. Но только в Python:
                    # в Markdown строка вполне может начинаться с ника, и
                    # именно так выглядит карточка нарушителя.
                    decorator = name.endswith(".py") and \
                        line.lstrip().startswith("@")
                    if not decorator:
                        for h in HANDLE_RE.findall(line):
                            if h not in SAFE_HANDLES:
                                problems.append((rel, num, "ник", h))
                    for ident in ID_RE.findall(line):
                        if ident not in SAFE_NUMBERS:
                            problems.append((rel, num, "идентификатор", ident))
    return problems


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))
    problems = scan(root)
    if not problems:
        print("  \033[32m✓\033[0m данных живых людей не найдено")
        return 0
    print(f"  \033[31m✗ найдено {len(problems)}\033[0m")
    for rel, num, kind, value in problems:
        print(f"    {rel}:{num}  {kind}: {value}")
    print("\n  Замените на пример или внесите в список разрешённого "
          "в tests/privacy_scan.py")
    return 1


if __name__ == "__main__":
    sys.exit(main())

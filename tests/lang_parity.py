#!/usr/bin/env python3
"""Ключи интерфейса должны быть в обоих языковых блоках lang.sh.

Ключ, добавленный в один блок и забытый в другом, не ломает ничего явно:
bash подставляет пустую строку, и на экране появляется дыра — но только на
одном языке, поэтому заметить её можно лишь случайно.
"""
import re
import sys


def keys(path):
    blocks, cur = [], None
    for line in open(path, encoding="utf-8"):
        if re.search(r"^\s*T=\($", line):
            cur = set()
            blocks.append(cur)
        m = re.search(r"^\s*\[([a-z0-9_]+)\]=", line)
        if m and cur is not None:
            cur.add(m.group(1))
    return blocks


def main(path):
    blocks = keys(path)
    if len(blocks) != 2:
        print(f"блоков не два: {len(blocks)}")
        return 1
    a, b = blocks
    diff = sorted(a ^ b)
    print("|".join(diff) if diff else "ok")
    return 1 if diff else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

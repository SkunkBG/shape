#!/usr/bin/env python3
"""
Готовит пакет команд для bpftool, возвращающий привязки PROXY protocol в
свежезагруженную pp_conn_map. Вызывается из engine.sh между выгрузкой и
загрузкой шейпера; сам ничего не меняет, только печатает число записей и
пишет файл для `bpftool batch file`.

Отдельный файл, а не heredoc в engine.sh: разбор JSON на sed и awk читается
хуже и ломается тише.

Печатает число записей в stdout. Ненулевой код возврата означает «не
восстанавливать»: engine.sh тогда просто продолжит без привязок — это ровно
то поведение, которое было до появления этого файла.
"""
import json
import os
import subprocess
import sys


def sizes(path):
    """(размер ключа, размер значения) закреплённой карты или (None, None)."""
    try:
        out = subprocess.run(["bpftool", "map", "show", "pinned", path, "-j"],
                             capture_output=True, text=True, timeout=10).stdout
        return sizes_of(json.loads(out))
    except Exception:
        return None, None


def sizes_of(j):
    # У разных сборок bpftool поля называются по-разному, поэтому смотрим оба
    # написания. Не нашлось ни одного — значит проверить нечем.
    if isinstance(j, list):
        j = j[0] if j else {}
    if not isinstance(j, dict):
        return None, None
    k = j.get("bytes_key", j.get("key_size"))
    v = j.get("bytes_value", j.get("value_size"))
    return k, v


def as_bytes(cells):
    """Ячейки из дампа -> список строк вида 0x0a. bpftool отдаёт то строки, то числа."""
    out = []
    for c in cells:
        if isinstance(c, str):
            out.append(c if c.startswith("0x") else "0x" + c)
        else:
            out.append("0x%02x" % (int(c) & 0xFF))
    return out


def main():
    dump_path, meta_path, batch_path = sys.argv[1], sys.argv[2], sys.argv[3]
    pin = os.environ["PP_PIN"]

    with open(meta_path) as f:
        old_k, old_v = sizes_of(json.load(f))
    new_k, new_v = sizes(pin)

    # Размеры не сошлись или не выяснились — отказываемся молча и в безопасную
    # сторону. Класть старые байты в карту с другой раскладкой нельзя: они
    # разберутся как другой клиент, и чужой трафик уйдёт ему в учёт.
    if None in (old_k, old_v, new_k, new_v) or (old_k, old_v) != (new_k, new_v):
        return 1

    with open(dump_path) as f:
        rows = json.load(f)
    if not isinstance(rows, list):
        return 1

    lines = []
    for e in rows:
        if not isinstance(e, dict):
            continue
        k, v = as_bytes(e.get("key") or []), as_bytes(e.get("value") or [])
        if len(k) != old_k or len(v) != old_v:
            continue
        lines.append("map update pinned %s key hex %s value hex %s"
                     % (pin, " ".join(k), " ".join(v)))

    with open(batch_path, "w") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    print(len(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())

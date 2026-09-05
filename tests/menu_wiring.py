"""Пункты меню и обработчики должны жить в одном экране.

Живой случай: пункты «Отключать подписку через» и «Включить подписку обратно»
были нарисованы в экране панели, а ветки case уехали в экран белого списка.
Пункты видны, нажатие не делает ничего.

Ловится это только сопоставлением внутри экрана: grep по всему файлу находит и
то, и другое, и остаётся доволен. Причём сравнивать надо именно с тем case,
который читает выбор пользователя, — в экране бывают и другие, вложенные, и
их «*)» не должна выключать проверку целиком.
"""
import re
import sys


def choice_cases(body):
    """
    Тела всех case, читающих выбор пользователя.

    Их бывает несколько: в экране API сначала спрашивают «ставить ли», и
    только потом показывают меню. Пункт, обработанный в любом из них,
    обработан.
    """
    out = []
    for m in re.finditer(r'case\s+"\$\(ask [^\n]*choice[^\n]*\)"\s+in\n',
                         body):
        depth, chunk = 1, []
        for line in body[m.end():].splitlines(True):
            stripped = line.strip()
            if stripped.startswith("case ") or " case " in stripped:
                depth += 1
            if stripped.startswith("esac"):
                depth -= 1
                if depth == 0:
                    break
            chunk.append(line)
        out.append("".join(chunk))
    return out


def main(path):
    src = open(path, encoding="utf-8").read()
    bad = []
    for m in re.finditer(r"^(screen_\w+|guard_preset)\(\) \{\n(.*?)^\}$",
                         src, re.M | re.S):
        name, body = m.group(1), m.group(2)
        blocks = choice_cases(body)
        if not blocks:
            continue
        # «*)» ловит всё оставшееся — тогда непокрытых пунктов не бывает.
        if any(re.search(r"^\s*\*\)", b, re.M) for b in blocks):
            continue
        shown = set(re.findall(r"echo[^\n]*?\[\s*(\d+)\s*\]", body))
        handled = set()
        for b in blocks:
            handled |= set(re.findall(r"^\s*(\d+)(?:\|[^)\n]*)?\)", b, re.M))
        missing = sorted(shown - handled, key=int)
        if missing:
            bad.append("%s: показаны без обработчика %s" % (name, missing))
    if bad:
        print("\n".join(bad))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

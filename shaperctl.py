#!/usr/bin/env python3
"""
shaperctl — управление eBPF-шейпером через pinned BPF-карты.

Одна настройка: порты и скорость в Мбит/с на каждый IP-адрес.
Только стандартная библиотека и bpftool.
"""

import argparse
import base64
import calendar
import contextlib
import fcntl
import hashlib
import html
import http.client
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PIN_DIR     = os.environ.get("SHAPER_PIN_DIR", "/sys/fs/bpf/shaper/maps")
ETC_DIR     = os.environ.get("SHAPE_ETC_DIR", "/etc/shaper")
CONFIG_FILE = os.path.join(ETC_DIR, "config.json")
WL_FILE     = os.path.join(ETC_DIR, "whitelist.txt")
TRUST_FILE  = os.path.join(ETC_DIR, "trusted.txt")
PEN_FILE    = os.path.join(ETC_DIR, "penalties.json")
DAILY_FILE  = os.path.join(ETC_DIR, "daily.json")
DIGEST_FILE = os.path.join(ETC_DIR, "digest.json")
# Изменчивое состояние — отдельно от настроек: журнал событий пухнет,
# а /etc принято держать маленьким и бэкапить целиком.
# Каталог изменчивого состояния. Переопределяется переменной окружения —
# это нужно тестам, чтобы гонять настоящий CLI, не трогая систему.
VAR_DIR     = os.environ.get("SHAPE_VAR_DIR", "/var/lib/shape")
EVENT_FILE  = os.path.join(VAR_DIR, "events.jsonl")
EVENT_SEQ   = os.path.join(VAR_DIR, "events.seq")
# Кто стоит за адресом. Заполняется извне — сейчас руками или через API,
# позже сюда будет складывать карту резолвер панели. Shape сам никуда за
# этими данными не ходит: его дело — подставить ярлык в сообщение.
OWNERS_FILE = os.path.join(VAR_DIR, "owners.json")
# По строке JSON на прошедшие сутки. За год ~40 КБ.
# Постоянный идентификатор ноды. Имя хоста и адрес для этого не годятся:
# их меняют, а после смены метрики выглядят как метрики новой ноды и история
# рвётся. Файл создаётся один раз — при установке или при первом обращении.
NODE_ID_FILE = os.path.join(VAR_DIR, "node_id")

HISTORY_FILE = os.path.join(VAR_DIR, "history.jsonl")
HISTORY_MAX_DAYS = 400
# Три числа для расчёта текущей скорости канала: когда мерили и сколько
# было всего. Файл общий для CLI и API — кто бы ни собирал метрики,
# разница считается от последнего замера.
METRICS_STATE = os.path.join(VAR_DIR, "metrics.state")
METRICS_MIN_GAP = 10        # чаще этого замер не обновляем
METRICS_MAX_GAP = 300       # старше этого — считать скорость бессмысленно

# Версия схемы метрик. Меняется, если поменяются имена или смысл значений;
# по ней центральная система поймёт, что дашборд пора обновить.
METRICS_VERSION = "1"

NS = 1_000_000_000
# Мбит/с -> байт/с. Мегабит десятичный: 1 Мбит = 1 000 000 бит = 125 000 байт.
BYTES_PER_MBPS = 125_000
MAX_MBPS = 100_000          # 100 Гбит/с — заведомо выше любого разумного канала
MAX_PORTS = 64              # должно совпадать с max_entries port_map в shaper.bpf.c

# Флаги в значении port_map. Должны совпадать с shaper.bpf.c.
PORT_SHAPE = 0x01
PORT_PROXY = 0x02

# Счётчики обработки, индексы в stat_map. Тоже из shaper.bpf.c.
STAT_NAMES = ("down_pass", "down_drop", "up_pass", "up_drop",
              "pp_resolved", "pp_unresolved")

CONFIG_FMT = "<Q"           # struct config, 8 байт
PEN_FMT = "<2Q"             # struct penalty: rate_bytes_per_sec, until_ns
USER_FMT, USER_SIZE = "<4Q", 32   # struct user_state

C = {
    "r": "\033[0m", "b": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "grn": "\033[32m", "yel": "\033[33m", "gry": "\033[90m",
    # Яркие оттенки для монитора: на тёмной теме обычный красный сливается
    # с фоном, а на светлой жёлтый становится нечитаемым.
    "cyan": "\033[36m", "bred": "\033[91m", "bgrn": "\033[92m",
    "byel": "\033[93m",
}


# ─────────────────────────── языки ───────────────────────────
# Язык берётся из UI_LANG в /etc/shaper/shaper.conf, его пишет меню.

MSG = {
    "ru": {
        "root": "нужны права root",
        "h_req_packet": "требовать крупные пакеты вверх: on/off",
        "guard_req_packet": "и только при пакетах вверх от {n} байт — подтверждения не в счёт",
        "mon_pkt": "пакет",
        "mon_bulk": "данными",
        "mon_leg_pkt": "пакет — средний размер в отдаче, байт; от {n} это данные, а не подтверждения",
        "mon_leg_bulk": "данными — доля суточной отдачи крупными пакетами; от {n}% это уже не подтверждения",
        "id_node": "нода",
        "id_config": "отпечаток",
        "id_none": "не создан",
        "h_tg_backup": "включить или выключить отправку копии: on/off",
        "h_tg_bk_thread": "тема для копий, если отдельная от отчётов",
        "h_tg_bk_day": "день недели для копии: 1 понедельник … 7 воскресенье",
        "tg_backup": "копия",
        "tg_bk_state": "Копия",
        "tg_bk_when": "по {day}, в {at}",
        "tg_bk_thread": "тема копий",
        "bk_tg_caption": "Резервная копия состояния",
        "bk_tg_counts": "адресов в белом списке {w}, ограничений {p}, владельцев {o}",
        "bk_tg_nosec": "без токена бота — восстанавливать через shaperctl.py import",
        "bk_tg_secrets": "отправка отменена: в копию попал секрет, а в Telegram такое не уходит",
        "bk_tg_sent": "копия отправлена в Telegram",
        "bk_tg_off": "отправка копий выключена",
        "bk_tg_send_now": "Отправить копию в Telegram сейчас",
        "bk_tg_toggle": "Отправка копии в Telegram",
        "bk_tg_hint1": "Копия уходит файлом раз в неделю, в то же время, что и сводка.",
        "bk_tg_hint2": "Токен бота в неё не попадает никогда: бот пишет в эту же тему,",
        "bk_tg_hint3": "и любой её участник получил бы управление ботом.",
        "bk_tg_hint4": "В файле есть IP-адреса клиентов — тему держите закрытой.",
        "dow1": "понедельникам", "dow2": "вторникам", "dow3": "средам",
        "dow4": "четвергам", "dow5": "пятницам", "dow6": "субботам",
        "dow7": "воскресеньям",
        "tg_bad_day": "день недели: от 1 (понедельник) до 7 (воскресенье)",
        "h_export": "выгрузить состояние ноды в файл",
        "h_import": "восстановить состояние ноды из файла",
        "h_exp_out": "куда писать; по умолчанию на экран",
        "h_exp_secrets": "включить токен бота и пароль прокси",
        "h_imp_dry": "показать, что изменится, и ничего не менять",
        "h_imp_only": "только эти разделы через запятую",
        "h_imp_replace": "заменить белый список, а не дополнить",
        "exp_done": "состояние выгружено: {path}",
        "exp_counts": "белый список {w}, ограничения {p}, владельцы {o}, суток истории {h}",
        "exp_secrets": "в файле лежит токен бота — храните его как пароль",
        "exp_no_secrets": "токен и прокси не включены, добавьте --with-secrets при переносе ноды",
        "sec_config": "настройки",
        "sec_whitelist": "белый список",
        "sec_penalties": "ограничения",
        "sec_owners": "владельцы адресов",
        "sec_history": "история по суткам",
        "imp_not_object": "файл не похож на выгрузку Shape",
        "imp_not_shape": "это не выгрузка Shape: нет метки shape-node-state",
        "imp_no_schema": "в файле не указана версия формата",
        "imp_newer": "файл из более новой версии Shape (формат {got}, здесь {ours}) — обновите Shape",
        "imp_no_state": "в файле нет раздела state",
        "imp_no_file": "файл не открывается: {path} {err}",
        "imp_bad_json": "файл не читается как JSON: {err}",
        "imp_bad_only": "нет такого раздела: {s}; есть: {all}",
        "imp_bad_speed": "скорость отброшена: {v}",
        "imp_bad_port": "порт отброшен: {v}",
        "imp_many_ports": "портов больше {n}, лишние отброшены",
        "imp_bad_ports": "список портов испорчен и отброшен",
        "imp_bad_section": "раздел {s} испорчен и отброшен",
        "imp_bad_field": "{s}.{k} — неподходящее значение, отброшено",
        "imp_unknown_keys": "{s}: незнакомые ключи отброшены: {k}",
        "imp_bad_ip": "адрес отброшен: {v}",
        "imp_bad_entry": "запись для {v} отброшена",
        "imp_from": "выгрузка с ноды {node}, Shape {v}, от {when}",
        "imp_no_secrets": "токена в файле нет — тот, что настроен здесь, останется на месте",
        "imp_yes": "будет применено",
        "imp_skip": "пропущено",
        "imp_more_problems": "и ещё {n} замечаний",
        "imp_dry": "ничего не изменено: это была проверка",
        "imp_done": "восстановлено: {s}",
        "imp_live": "движок загружен — изменения уже в ядре",
        "imp_offline": "движок не загружен — настройки применятся при следующем запуске",
        "tg_mtproto": "это MTProto-прокси из ссылки t.me/proxy",
        "tg_mtproto2": "он умеет только протокол мессенджера, Bot API через него не пройдёт",
        "tg_mtproto3": "нужен SOCKS5 или HTTP: socks5://логин:пароль@хост:1080",
        "tg_proxy_scheme": "прокси должен начинаться с socks5:// или http://",
        "h_telegram": "уведомления в Telegram",
        "h_tg_name": "как подписывать ноду в сообщениях",
        "h_tg_proxy": "socks5://… или http://… — нужен на российских нодах",
        "tg_state": "Уведомления", "tg_node": "Подпись ноды",
        "tg_chat": "Чат", "tg_thread": "тема", "tg_proxy": "Прокси",
        "tg_direct": "напрямую",
        "tg_off": "уведомления выключены",
        "tg_no_creds": "не заданы токен или chat_id",
        "tg_bad_token": "токен неверный — проверь у @BotFather",
        "tg_bad_chat": "неверный chat_id, либо бота не добавили в группу",
        "tg_bad_thread": "нет такой темы — проверь ID темы",
        "tg_forbidden": "бота заблокировали или выгнали из чата",
        "tg_need_proxy": "похоже на блокировку — задай прокси",
        "tg_sent": "сообщение отправлено",
        "tg_test_text": "Проверка связи прошла успешно.",
        "tg_pen_head": "🚦 <b>Ограничение</b>",
        "tg_pen_addr": "📍 Адрес: <a href=\"https://ipinfo.io/{ip}\">{ip}</a>",
        "tg_pen_speed": "🐌 Скорость снижена до {mbps} Мбит/с на {d}",
        "tg_pen_why": "Причина: <i>{why}</i>",
        "tg_upd_head": "⬆️ <b>Доступно обновление</b>",
        "tg_upd_have": "Установлено: <code>{v}</code>",
        "tg_upd_new": "В репозитории: <code>{v}</code>",
        "tg_upd_how": "<i>Обновить: shaper → Сервис → Обновление из GitHub</i>",
        "tg_upd": "Обновления",
        "tg_pen_stat": "📈 За сутки: {s}",
        "tg_pen_pkts": "📦 Отдача за {d}: {s}",
        "tg_pen_hrs": "длилась {h} ч",
        "tg_pen_bulk": "данными {p}%",
        "tg_pen_pkt": "пакет {n} Б",
        "tg_pen_pkt_max": "макс {n}",
        "pn_card_unknown": "<i>кто это — неизвестно: связь с панелью не настроена на этой ноде</i>",
        "pn_card_never": "<i>кто это — неизвестно: панель ещё ни разу не ответила — проверьте её командой <code>shaperctl panel show</code></i>",
        "pn_card_seen": "<i>панель его сейчас не видит — имя из опроса в {at}</i>",
        "pn_card_stale": "<i>кто это — неизвестно: панель не отвечает уже {m} мин</i>",
        "pn_card_absent": "<i>кто это — неизвестно: при последнем опросе панели ({m} мин назад) этого адреса не было среди подключённых</i>",
        "tg_ev": "События  ",
        "tg_dg": "Сводка   ",
        "tg_ev_off_hint": "— сообщения о штрафах не приходят",
        "pn_who_found": "адрес {ip} принадлежит:",
        "pn_who_name": "Имя",
        "pn_who_seen": "последний раз панель видела его",
        "pn_who_noname": "имя не получено — проверьте право users:read у токена",
        "pn_who_none": "панель не знает адрес {ip}; всего на ноде адресов у {n} пользователей",
        "pn_who_hint": "адрес мог отвалиться, либо нода в панели не та, через которую он ходит",
        "h_pn_who_ip": "адрес для команды who",
        "pn_bad_uuid": "UUID ноды должен выглядеть как a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d — 36 знаков с дефисами",
        "pn_seen": "Пользователей на опросе",
        "pn_seen_none": "ноль при успешном опросе почти всегда значит, что UUID указывает не на ту ноду",
        "guard_ratio": "отдельно: отдал за сутки больше {p} процентов от скачанного, начиная с {mb} МБ",
        "ratio_title": "Отношение отдачи к скачиванию",
        "ratio_sub": "адресов с отдачей от {mb} МБ: {n}",
        "ratio_top": "Верхние по отношению:",
        "ratio_now": "порог сейчас: {p} процентов",
        "ratio_off": "признак выключен: guard --upload-ratio 35",
        "h_ratio": "показать распределение отношения отдачи вместо списка",
        "h_ratio_mb": "не учитывать адреса с отдачей меньше стольких мегабайт",
        "mon_total": "всего",
        "mon_leg_total": "всего — прокачано с момента загрузки движка, вниз и вверх вместе",
        "st_share": "отдал",
        "st_share_hint": "выделено адресов: {n} — отдали больше {p} процентов от скачанного, это похоже на раздачу",
        "h_upload_ratio": "отдал за сутки столько-то процентов от скачанного, 0 = признак выключен",
        "h_upload_ratio_mb": "не считать отношение, пока отдача меньше стольких мегабайт",
        "why_ratio": "за сутки отдал непропорционально много",
        "why_upload_day": "отдал десятки гигабайт за сутки",
        "why_up_hourly": "отдал гигабайты за час",
        "h_upload_gbh": "гигабайт отдачи за час, 0 = выкл",
        "tg_uph_head": "🔔 <b>Долгая отдача</b>",
        "tg_uph_warn": "Отдавал данные {h} ч за сутки — порог {n} ч",
        "tg_uph_note": "<i>Ограничения нет. Так выглядит и раздача, и первый бэкап телефона: решайте сами.</i>",
        "h_upload_hours": "часов отдачи за сутки для ограничения, 0 = выкл",
        "h_upload_ratio_hours": "часов отдачи данными, без которых отношение не штрафует, 0 = выкл",
        "h_upload_hours_mbps": "ниже какой отдачи замер не считается отдачей данных",
        "guard_uphours": "отдача дольше {h} ч за сутки — только уведомление, без штрафа",
        "guard_uphourly": "отдача за час: ограничение на {d} ГБ",
        "tg_up_head": "🔔 <b>Много отдачи</b>",
        "tg_up_warn": "За сутки отдано {gb} — порог уведомления {n} ГБ",
        "tg_up_note": "<i>Ограничения нет, это предупреждение. При {n} ГБ скорость будет снижена.</i>",
        "h_upload_warn": "гигабайт отдачи за сутки для уведомления без штрафа, 0 = выкл",
        "h_upload_day": "гигабайт отдачи за сутки для ограничения, 0 = выкл",
        "guard_upday": "отдача за сутки: уведомление на {w} ГБ, ограничение на {d} ГБ",
        "guard_upwarn": "отдача за сутки: уведомление на {w} ГБ, ограничения нет",
        "guard_uplim": "отдача за сутки: ограничение на {d} ГБ",
        "edt_off": "СКАЧИВАНИЕ НЕ ОГРАНИЧИВАЕТСЯ: на интерфейсе {kinds}, а не fq",
        "edt_fix": "только fq придерживает пакеты по времени отправки. Почините: modprobe sch_fq, затем systemctl restart shaper",
        "pp_ports": "PROXY",
        "pp_hint": "— на этих портах заголовку верят от любого адреса",
        "pp_not_shaped": "порт {p} не в списке ограничиваемых — доверять PROXY там не на чем",
        "h_proxy_ports": "порты, где заголовку PROXY верят от любого адреса (только для портов CDN)",
        "eth_off": "НИЧЕГО НЕ ОГРАНИЧИВАЕТСЯ: {iface} не Ethernet (type={t})",
        "eth_fix": "фильтр читает L2-заголовок, а на туннельных и tun-устройствах его нет. Задайте физический интерфейс в IFACE",
        "too_slow": "{v} Мбит/с округляется до нуля байт в секунду, а ноль означает «без ограничения». Минимум 0.05",

        # Панель Remnawave
        "pn_no_url": "адрес панели не задан",
        "pn_no_token": "токен панели не задан",
        "pn_no_uuid": "не указан UUID ноды в панели",
        "pn_no_job": "панель не вернула идентификатор задачи",
        "pn_job_failed": "панель сообщила об ошибке задачи {job}",
        "pn_job_slow": "панель не успела подготовить результат задачи {job}",
        "pn_denied": "панель отказала в доступе: {detail}",
        "pn_bad_json": "панель ответила не в формате JSON",
        "pn_socks": "для панели поддержан только http-прокси, socks5 — нет",
        "pn_state": "Связь с панелью",
        "pn_url": "Адрес",
        "pn_uuid": "UUID ноды",
        "pn_win": "Окно",
        "pn_thr": "Порог адресов",
        "pn_act": "Действие",
        "pn_cool": "Пауза между сигналами",
        "pn_exempt": "Исключения",
        "pn_every": "Опрос",
        "pn_token_exp": "Токен действует до",
        "pn_token_none": "срок не определяется",
        "pn_token_gone": "истёк",
        "pn_last": "Последний успешный опрос",
        "pn_never": "ещё не было",
        "pn_oldest": "Самый старый адрес в списке",
        "pn_oldest_short": "нода помнит меньше, чем окно в {w} мин — окно упирается в неё, а не в настройку",
        "pn_last_err": "Последняя ошибка",
        "pn_min": "мин",
        "pn_sec": "с",
        "pn_scanning": "Спрашиваю панель…",
        "pn_scan_ok": "Пользователей на ноде: {n}",
        "pn_scan_none": "Раздачи не обнаружено.",
        "pn_scan_found": "Найдено раздающих: {n}",
        "pn_scan_row": "  {user} — адресов {n}, из них видит нода {here}",
        "pn_dry": "Ничего не предпринято: это пробный запуск.",
        "pn_msg_head": "🔎 <b>Похоже на раздачу подписки</b>",
        "cdn_no_url": "адрес API провайдера CDN не задан",
        "cdn_no_token": "ключ API провайдера CDN не задан",
        "cdn_v_off": "🛑 Ресурс у провайдера CDN в состоянии «{s}» — он выключен, а не сломан.",
        "cdn_v_empty": "🛑 <b>До края CDN не доходит ни один запрос.</b> Это провайдер: у него пусто и по запросам, и по адресам. Нода тут ни при чём.",
        "cdn_v_alive": "✅ До края CDN запросы доходят: {r} за последние минуты. Значит клиенты не доезжают уже до ноды — смотреть здесь.",
        "clients_msg": "🟠 <b>{node} — клиенты пропали</b>\n\nСейчас {n}, обычно около {norm}. Нода жива: процессы работают, ошибок нет.",
        "cdn_state": "Связь с CDN",
        "h_cdn": "связь с API провайдера CDN: чья беда, когда клиенты пропали",
        "h_cdn_url": "адрес API провайдера, например https://api.example.com/v1",
        "h_cdn_token": "ключ из личного кабинета провайдера",
        "h_cdn_res": "номер ресурса, за которым стоит эта нода",
        "cdn_ask": "Спрашиваю провайдера…",
        "cdn_bad_res": "номер ресурса — это число",
        "cdn_bad_key": "ключ не принят: возьмите его в личном кабинете, раздел API",
        "cdn_no_res": "связь есть, но ресурс не отвечает — проверьте его номер",
        "cdn_no_list": "у ключа нет ни одного ресурса",
        "cdn_quiet": "Ответа нет: проверьте адрес, ключ и номер ресурса.",
        "cdn_url": "Адрес API",
        "cdn_res": "Номер ресурса",
        "relay_msg": "⚠️ <b>{node} — похоже, релей CDN сменил адрес</b>\n\nЗа последние минуты <b>{share}%</b> трафика на портах {ports} пришло без разбора заголовка PROXY. Настоящие адреса клиентов не распознаются, и все они делят <b>один лимит на всех</b>.\n\nБольше всего соединений с <code>{ip}</code> — их {n}.\n\nЕсли это ваш новый релей, добавьте его:\n<code>shaperctl trusted add {ip} --relay</code>",
        "pn_off_head": "⛔ <b>Подписка отключена</b>",
        "pn_off_why": "🤖 Отключил Shape: адресов было {n}, реакции не было {m} мин.",
        "pn_off_how": "<i>Включить обратно: <code>shaperctl panel enable {id}</code> или в панели.</i>",
        "pn_off_refused": "нарушителей больше потолка ({n}) — ничего не отключено, только сообщено",
        "h_pn_disable_after": "через сколько минут без реакции отключать подписку, 0 = никогда",
        "pn_disable_after": "Отключать подписку через",
        "pn_enabled_ok": "подписка #{id} включена",
        "pn_disabled_ok": "подписка #{id} отключена",
        "pn_need_id": "нужен числовой номер из панели: panel enable 741",
        "pn_card_name": "👤 {name}",
        "pn_card_tg": "🆔 Telegram: <code>{id}</code>",
        "pn_card_login": "🔑 В панели: <code>{login}</code>",
        "pn_card_login_plain": "Логин в панели: {login}",
        "pn_user_need_id": "нужен числовой номер из панели: panel user 6085",
        "pn_off": "связь с панелью выключена: panel set --enable",
        "pn_user_none": "сейчас на этой ноде его нет (проверено пользователей: {n})",
        "pn_user_ips": "Адресов на ноде",
        "pn_user_noday": "за сутки на этой ноде ничего не прокачано",
        "pn_user_uphours": "отдавал данные {h} ч",
        "pn_user_tag": "Тег",
        "h_pn_user": "номер пользователя из панели",
        "pn_card_panel": "🔑 ID в панели: <code>{id}</code>",
        "pn_card_panel_plain": "ID в панели: {id}",
        "pn_msg_blocked": "🚫 Доступ к ноде перекрыт на {m} мин, адресов: {n}",
        "pn_msg_nothing": "Ничего не предпринято: включено только уведомление.",
        "pn_msg_ips": "Адресов одновременно: <b>{n}</b> за последние {w} мин",
        "pn_grace_long": "отсрочка длиннее перекрытия ({m} мин) — штраф истечёт раньше срока, и отсчёт оборвётся",
        "pn_msg_tariff": "<i>Порог для его тарифа: {t} — продано устройств {d}</i>",
        "h_pn_per_device": "во сколько раз порог адресов больше числа устройств в тарифе, 0 = один порог на всех",
        "pn_per_device": "Порог от тарифа",
        "pn_per_device_v": "×{k} к числу устройств",
        "pn_msg_limited": "Ограничено адресов: {n} — до {mbps} Мбит/с на {m} мин",
        "pn_msg_dropped": "Соединения оборваны: {n}",
        "pn_msg_more": "…и ещё {n}. Полный список — файлом следом.",
        "pn_msg_file": "📄 Все адреса: {user} — {n} шт.",
        "pn_rep_off": "отчёт по ноде выключен",
        "pn_rep_head": "Отчёт по ноде {node} · {at}",
        "pn_rep_users": "Подключено пользователей: {n}",
        "pn_rep_ips": "Адресов всего: {n}",
        "pn_rep_window": "Окно: {w} мин",
        "pn_rep_caption": "📋 <b>{node}</b> · подключено {users}, адресов {ips}",
        "pn_rep_state": "Отчёт по ноде",
        "pn_rep_at": "Время отчёта",
        "pn_rep_sent": "отчёт отправлен",
        "pn_resolve": "Имена из панели",
        "h_pn_report": "присылать отчёт по ноде: on или off",
        "h_pn_report_at": "во сколько присылать отчёт, ЧЧ:ММ",
        "h_pn_report_thread": "ID темы для отчёта по ноде",
        "h_pn_resolve": "подставлять имя и Telegram ID вместо номера: on или off",
        "pn_token_soon": "⏳ {node}: токен панели истекает через {days} дн. "
                         "После этого поиск раздачи остановится.",
        "pn_denied_msg": "⚠️ {node}: панель отказала в доступе — поиск "
                         "раздачи остановлен.\n{detail}",
        "h_panel": "связь с панелью Remnawave: поиск раздачи подписки",
        "h_pn_url": "адрес панели, например https://panel.example.com",
        "h_pn_token": "токен панели с правами connections",
        "h_pn_uuid": "UUID этой ноды в панели",
        "h_pn_on": "включить опрос панели",
        "h_pn_off": "выключить опрос панели",
        "h_pn_interval": "как часто спрашивать панель, в секундах",
        "h_pn_window": "окно одновременности в минутах",
        "h_pn_threshold": "сколько адресов считать раздачей",
        "h_pn_action": "notify, limit, block, drop или их сочетание через запятую",
        "h_pn_mbps": "до скольких мегабит резать нарушителя",
        "h_pn_minutes": "на сколько минут резать",
        "h_pn_cooldown": "пауза между сигналами по одному человеку, в минутах",
        "h_pn_exempt": "кого не трогать вовсе: userId через запятую, действует и на автоограничение",
        "h_pn_exempt_tags": "то же самое по тегу из панели: BUSINESS,OFFICE",
        "pn_exempt_tags": "Теги-исключения",
        "h_pn_proxy": "http-прокси до панели",
        "h_pn_dry": "только показать найденное, ничего не делать",
        "pn_bad_action": "действие — это notify, limit, block, drop или их сочетание",
        "pn_bad_url": "адрес панели должен начинаться с http:// или https://",
        "tg_limited": "Ограничен",
        "tg_shared": "за адресом может стоять несколько человек",
        "bad_ip": "«{ip}» — это не IP-адрес",
        "tg_bad_token_fmt": "токен выглядит как 123456789:AAF… — возьми его у @BotFather",
        "tg_bad_chat_fmt": "chat_id — это число (часто со знаком минус) или @имя",
        "tg_bad_thread_fmt": "ID темы — число из ссылки на тему",
        "tg_bad_proxy": "в адресе прокси нет хоста или порт вне диапазона",
        "tg_name_long": "подпись ноды — до 64 символов",
        "tg_at": "Время сводки",
        "tg_digest_now": "сводка за текущие сутки",
        "tg_no_data": "за сегодня ещё нечего показать",
        "tg_bad_time": "время указывают как ЧЧ:ММ, например 09:00",
        "h_tg_at": "во сколько присылать сводку, ЧЧ:ММ",
        "tg_digest": "сводка за", "tg_traffic": "Трафик",
        "tg_addresses": "Адресов", "tg_top": "Больше всех скачали",
        "lim_why": "за что",
        "lim_when": "с",
        "lim_total": "всего адресов",
        "lim_speed": "скорость нарушителя",
        "h_score": "баллов для штрафа (1-6)",
        "h_both_min": "минут одновременной нагрузки в обе стороны",
        "h_both_dl": "порог скачивания для двусторонней нагрузки, в процентах",
        "h_both_ul": "порог отдачи для двусторонней нагрузки, в процентах",
        "h_hours": "часов активности за сутки",
        "h_upload_gb": "гигабайт отдачи за сутки",
        "h_download_gb": "гигабайт скачивания за сутки, 0 = выкл",
        "h_download_gbh": "гигабайт скачивания за час, 0 = выкл",
        "h_volume_needs": "часовой объём срабатывает только с крупными пакетами вверх",
        "h_volume_mbps": "скорость штрафа, когда сработал только объём, 0 = обычная",
        "h_ratio_needs": "отношение срабатывает только если отдача шла данными",
        "h_bulk": "распределение доли отдачи крупными пакетами",
        "bulk_title": "Распределение доли данных в отдаче",
        "bulk_sub": "адресов: {n} · отдача от {mb} МБ · за текущие сутки",
        "bulk_none": "пока не из чего считать: суточные счётчики пусты либо отдача мала",
        "bulk_top": "верх списка          скачано    отдано  данными  средн   макс",
        "bulk_now": "порог сейчас: {p}% — красным то, что попадает под него",
        "bulk_off": "признак выключен: guard --ratio-needs-packet on",
        "guard_ratio_pkt": "и только если крупными пакетами ушло больше {n}% отдачи: звонки проходят мимо",
        "guard_vol_needs": "часовой объём — только с пакетами вверх от {n} Б: закачка из магазина проходит мимо",
        "guard_vol_soft": "за один объём режем до {mbps} Мбит/с, а не до штрафной",
        "guard_ratio_live": "и только пока адрес отдаёт: за отвалившегося штраф не выдаём",
        "guard_ratio_hrs": "и только если отдавал данные дольше {h} ч за сутки: отправка видео так долго не идёт",
        "guard_notify_cd": "повторное уведомление об одном адресе — не чаще раза в {h} ч",
        "guard_exempt_n": "исключений панели: {n} — этих не ограничиваем вовсе",
        "why_hourly": "выкачал гигабайты за час",
        "h_watch_iv": "период опроса карт, сек (больше = легче процессору)",
        "why_download": "выкачал десятки гигабайт за сутки",
        "h_packet": "средний размер пакета в отдаче, байт",
        "guard_both": "Обе стороны сразу",
        "guard_score": "Баллов для штрафа",
        "why_packet": "отдаёт данные, а не подтверждения",
        "why_peak": "держит потолок скачивания",
        "why_hours": "часами не отпускает канал",
        "why_upload": "много отдал за сутки",
        "h_guard": "автоограничение нарушителей",
        "h_percent": "порог в процентах от лимита",
        "h_sustain": "сколько минут держать нагрузку до штрафа",
        "h_pen_mbps": "скорость нарушителя, Мбит/с",
        "h_pen_min": "на сколько минут ограничивать",
        "h_watch": "демон слежения (запускается сервисом)",
        "h_limited": "кто сейчас ограничен",
        "h_release": "снять ограничение с IP",
        "guard_state": "Автоограничение",
        "guard_on": "включено", "guard_off": "выключено",
        "guard_trigger": "Порог", "guard_of_limit": "от лимита",
        "guard_during": "непрерывно", "guard_penalty": "Штраф",
        "guard_for": "на", "guard_range": "{k}: допустимо от {lo} до {hi}",
        "lim_title": "Ограниченные адреса",
        "lim_none": "ограниченных нет",
        "lim_left": "осталось",
        "rel_one": "ограничение с {ip} снято",
        "rel_all": "снято ограничений: {n}",
        "rel_need_ip": "укажи IP или --all",
        "rel_bad_user": "нужен числовой номер из панели: release --user 741",
        "rel_user": "снято ограничений: {n} (пользователь #{id})",
        "h_rel_user": "снять со всех адресов пользователя панели",
        "restored_pen": "восстановлено штрафов: {n}",
        "watch_start": "сторож запущен",
        "watch_hit": "{ip} ограничен до {mbps:g} Мбит/с на {m} мин",
        "units": ["Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ"],
        "sec": "с", "min": "мин", "hour": "ч",
        "measuring": "замер скорости {i} с…",
        "desc": "eBPF-шейпер: лимит скорости по IP-адресу. Всё в Мбит/с.",
        "h_apply": "задать порты и скорость",
        "h_ports": "через запятую, 0 = все порты",
        "h_speed": "Мбит/с на IP-адрес, 0 = снять ограничение",
        "h_show": "показать текущие настройки",
        "h_restore": "залить настройки в карты",
        "h_monitor": "кто грузит канал прямо сейчас",
        "h_interval": "период обновления, сек",
        "h_status": "статистика по IP",
        "h_live": "замерить текущую скорость",
        "h_full": "показать все IP",
        "h_json": "вывод в JSON",
        "h_whitelist": "белый список IP",
        "h_event": "записать событие в журнал",
        "h_personal": "постоянная скорость для адреса",
        "h_pers_speed": "Мбит/с, выше или ниже общего лимита",
        "h_owners": "кто стоит за адресом",
        "h_history": "трафик по суткам",
        "h_metrics": "метрики в формате Prometheus",
        "h_met_out": "записать в файл для node_exporter (*.prom)",
        "met_need_prom": "имя файла должно оканчиваться на .prom — так его ищет node_exporter",
        "met_bad_url": "адрес отправки — это http:// или https:// с именем хоста",
        "met_need_https": "наружу только https: по http токен уйдёт открытым текстом",
        "met_push_off": "отправка выключена: адрес не задан",
        "met_push_ok": "метрики отправлены: {n} строк на {u}",
        "met_push_fail": "отправить не вышло: {e}",
        "met_push_head": "Отправка метрик",
        "met_push_url": "Адрес",
        "met_push_token": "Токен",
        "met_push_proxy": "Прокси",
        "met_push_wait": "Ждать ответа",
        "met_push_none": "не задан",
        "met_push_set": "задан",
        "met_sec": "с",
        "h_met_url": "куда отправлять метрики; пустая строка выключает отправку",
        "h_met_token": "токен для заголовка Authorization: Bearer",
        "h_met_proxy": "socks5://… или http://… — если до сервера иначе не достучаться",
        "h_met_timeout": "сколько секунд ждать ответа, 1..120",
        "met_written": "метрики записаны: {p} ({n} строк)",
        "pers_none": "персональных скоростей нет",
        "pers_set": "{ip}: персональная скорость {s:g} Мбит/с",
        "pers_removed": "{ip}: персональная скорость снята",
        "pers_absent": "у {ip} нет персональной скорости",
        "pers_need_speed": "укажи скорость: --speed 25",
        "pers_range": "скорость от {lo} до {hi} Мбит/с",
        "own_none": "владельцы адресов не заданы",
        "own_set": "{ip}: сведения сохранены",
        "own_removed": "{ip}: сведения удалены",
        "own_bad_tg": "telegram_id — это число",
        "hist_none": "история пока пуста, первая запись появится в полночь",
        "hist_day": "Дата", "hist_limited": "ограничений",
        "hist_total": "всего за {n} сут",
        "no_engine": "движок не запущен — карты не найдены в {d}\n  запусти: systemctl start shaper",
        "cmd_fail": "команда не выполнилась: {c}\n  {e}",
        "port_nan": "порт «{p}» не число",
        "port_range": "порт {p} вне диапазона 0..65535",
        "too_many_ports": "портов не больше {n}",
        "no_ports": "не указан ни один порт (0 = все порты)",
        "neg_speed": "скорость не может быть отрицательной",
        "too_fast": "{v} Мбит/с — это больше 100 Гбит/с, проверь значение",
        "speed": "Скорость", "ports": "Порты", "all_ports": "ВСЕ ПОРТЫ",
        "per_user": "на каждый IP-адрес, в обе стороны",
        "unlimited": "не ограничена",
        "restored": "лимит {s:g} Мбит/с на портах {p}",
        "limit": "Лимит", "no_limit": "не ограничено",
        "total_ips": "всего IP", "active_min": "активных за минуту",
        "no_traffic": "трафика через шейпер ещё не было",
        "downloaded": "скачал", "uploaded": "отдал", "now": "сейчас",
        "more_ips": "… ещё {n} IP, полный список: shaperctl status --full",
        "idle_note": "· — нет трафика больше 5 минут",
        "wl_added": "{ip} добавлен в белый список",
        "wl_removed": "{ip} убран из белого списка",
        "wl_loaded": "загружено в белый список: {n}",
        "wl_bad": "пропущен неверный адрес: {ip}",
        "wl_empty": "белый список пуст",
        "h_trusted": "доверенные источники: туннели и релеи CDN",
        "h_tr_tunnel": "конец IPIP-туннеля — разворачивать его обёртку",
        "h_tr_relay": "релей CDN — верить его заголовку PROXY protocol",
        "tr_added": "{ip} добавлен как {what}",
        "tr_removed": "{ip} убран из доверенных",
        "tr_loaded": "загружено доверенных источников: {n}",
        "tr_bad": "пропущена неверная строка: {s}",
        "tr_empty": "доверенных источников нет — обе развёртки выключены",
        "tr_need_kind": "укажите --tunnel или --relay",
        "tr_tunnel": "конец туннеля",
        "tr_relay": "релей CDN",
        "mon_title": "Монитор", "mon_hint": "обновление {i} с · Ctrl+C — выход",
        "mon_channel": "Канал сейчас", "mon_limit": "Лимит {s:g} Мбит/с на IP",
        "mon_nolimit": "Лимит не задан", "mon_loading": "нагружают канал",
        "mon_of": "из", "mon_idle": "сейчас никто не качает",
        "mon_up": "отдача", "mon_avg": "средн", "mon_hold": "держит",
        "mon_bar": "загрузка", "mon_more": "… ещё {n} активных",
        "mon_share": "доля лимита",
        "mon_minute": "за минуту",
        "mon_limit_row": "Лимит на адрес",
        "mon_per_ip": "на каждый IP",
        "mon_shown": "показано {a} из {b}",
        "mon_leg_hold": "держит больше 30 с",
        "mon_leg_wl": "белый список",
        "mon_leg_limited": "ограничен",
        "mon_legend": "жёлтым — держит нагрузку больше 30 с, красным — упёрся в лимит",
    },
    "en": {
        "root": "root privileges required",
        "h_req_packet": "require large upload packets: on/off",
        "guard_req_packet": "and only with upload packets from {n} bytes — acknowledgements do not count",
        "mon_pkt": "packet",
        "mon_bulk": "data",
        "mon_leg_pkt": "packet — average upload size in bytes; from {n} it is data, not acknowledgements",
        "mon_leg_bulk": "data — share of the daily upload sent in large packets; from {n}% it is no longer acknowledgements",
        "id_node": "node",
        "id_config": "fingerprint",
        "id_none": "not created",
        "h_tg_backup": "turn the backup upload on or off: on/off",
        "h_tg_bk_thread": "topic for backups, if separate from reports",
        "h_tg_bk_day": "weekday for the backup: 1 Monday … 7 Sunday",
        "tg_backup": "backup",
        "tg_bk_state": "Backup",
        "tg_bk_when": "on {day}, at {at}",
        "tg_bk_thread": "backup topic",
        "bk_tg_caption": "Node state backup",
        "bk_tg_counts": "whitelisted {w}, limits {p}, owners {o}",
        "bk_tg_nosec": "no bot token inside — restore with shaperctl.py import",
        "bk_tg_secrets": "upload cancelled: a secret ended up in the copy, and those do not go to Telegram",
        "bk_tg_sent": "backup sent to Telegram",
        "bk_tg_off": "backup upload is off",
        "bk_tg_send_now": "Send a backup to Telegram now",
        "bk_tg_toggle": "Backup upload to Telegram",
        "bk_tg_hint1": "The copy is uploaded as a file once a week, at the digest time.",
        "bk_tg_hint2": "The bot token never goes into it: the bot posts to that same topic,",
        "bk_tg_hint3": "so anyone in it would gain control of the bot.",
        "bk_tg_hint4": "The file holds client IP addresses — keep the topic private.",
        "dow1": "Mondays", "dow2": "Tuesdays", "dow3": "Wednesdays",
        "dow4": "Thursdays", "dow5": "Fridays", "dow6": "Saturdays",
        "dow7": "Sundays",
        "tg_bad_day": "weekday: from 1 (Monday) to 7 (Sunday)",
        "h_export": "export node state to a file",
        "h_import": "restore node state from a file",
        "h_exp_out": "where to write; prints to screen by default",
        "h_exp_secrets": "include the bot token and proxy password",
        "h_imp_dry": "show what would change and change nothing",
        "h_imp_only": "these sections only, comma separated",
        "h_imp_replace": "replace the whitelist instead of merging",
        "exp_done": "state exported: {path}",
        "exp_counts": "whitelist {w}, limits {p}, owners {o}, days of history {h}",
        "exp_secrets": "the file holds the bot token — keep it like a password",
        "exp_no_secrets": "token and proxy left out; add --with-secrets when moving a node",
        "sec_config": "settings",
        "sec_whitelist": "whitelist",
        "sec_penalties": "limits",
        "sec_owners": "address owners",
        "sec_history": "daily history",
        "imp_not_object": "this file does not look like a Shape export",
        "imp_not_shape": "not a Shape export: the shape-node-state marker is missing",
        "imp_no_schema": "the file carries no format version",
        "imp_newer": "file comes from a newer Shape (format {got}, this one reads {ours}) — update Shape",
        "imp_no_state": "the file has no state section",
        "imp_no_file": "cannot open the file: {path} {err}",
        "imp_bad_json": "the file is not valid JSON: {err}",
        "imp_bad_only": "no such section: {s}; available: {all}",
        "imp_bad_speed": "speed dropped: {v}",
        "imp_bad_port": "port dropped: {v}",
        "imp_many_ports": "more than {n} ports, the extra ones were dropped",
        "imp_bad_ports": "the port list is malformed and was dropped",
        "imp_bad_section": "section {s} is malformed and was dropped",
        "imp_bad_field": "{s}.{k} holds an unusable value and was dropped",
        "imp_unknown_keys": "{s}: unknown keys dropped: {k}",
        "imp_bad_ip": "address dropped: {v}",
        "imp_bad_entry": "the entry for {v} was dropped",
        "imp_from": "export from node {node}, Shape {v}, made {when}",
        "imp_no_secrets": "no token in the file — the one configured here stays",
        "imp_yes": "will be applied",
        "imp_skip": "skipped",
        "imp_more_problems": "and {n} more notes",
        "imp_dry": "nothing changed: this was a check",
        "imp_done": "restored: {s}",
        "imp_live": "engine is loaded — changes are already in the kernel",
        "imp_offline": "engine is not loaded — settings apply on the next start",
        "tg_mtproto": "this is an MTProto proxy from a t.me/proxy link",
        "tg_mtproto2": "it only speaks the messenger protocol, the Bot API will not pass",
        "tg_mtproto3": "you need SOCKS5 or HTTP: socks5://user:pass@host:1080",
        "tg_proxy_scheme": "proxy must start with socks5:// or http://",
        "h_telegram": "Telegram notifications",
        "h_tg_name": "how to label this node in messages",
        "h_tg_proxy": "socks5://… or http://… — needed on Russian nodes",
        "tg_state": "Notifications", "tg_node": "Node label",
        "tg_chat": "Chat", "tg_thread": "topic", "tg_proxy": "Proxy",
        "tg_direct": "direct",
        "tg_off": "notifications are disabled",
        "tg_no_creds": "token or chat_id is missing",
        "tg_bad_token": "invalid token — check with @BotFather",
        "tg_bad_chat": "wrong chat_id, or the bot is not in the group",
        "tg_bad_thread": "no such topic — check the thread ID",
        "tg_forbidden": "the bot was blocked or removed from the chat",
        "tg_need_proxy": "looks like blocking — set a proxy",
        "tg_sent": "message sent",
        "tg_test_text": "Connection test passed.",
        "tg_pen_head": "🚦 <b>Limited</b>",
        "tg_pen_addr": "📍 Address: <a href=\"https://ipinfo.io/{ip}\">{ip}</a>",
        "tg_pen_speed": "🐌 Speed cut to {mbps} Mbit/s for {d}",
        "tg_pen_why": "Reason: <i>{why}</i>",
        "tg_upd_head": "⬆️ <b>An update is available</b>",
        "tg_upd_have": "Installed: <code>{v}</code>",
        "tg_upd_new": "In the repository: <code>{v}</code>",
        "tg_upd_how": "<i>To update: shaper → Service → Update from GitHub</i>",
        "tg_upd": "Updates",
        "tg_pen_stat": "📈 For the day: {s}",
        "tg_pen_pkts": "📦 Upload over {d}: {s}",
        "tg_pen_hrs": "lasted {h} h",
        "tg_pen_bulk": "{p}% as data",
        "tg_pen_pkt": "packet {n} B",
        "tg_pen_pkt_max": "max {n}",
        "pn_card_unknown": "<i>identity unknown: the panel link is not set up on this node</i>",
        "pn_card_never": "<i>identity unknown: the panel has never answered yet — check it with <code>shaperctl panel show</code></i>",
        "pn_card_seen": "<i>the panel does not see it now — name from the {at} poll</i>",
        "pn_card_stale": "<i>identity unknown: the panel has not answered for {m} min</i>",
        "pn_card_absent": "<i>identity unknown: at the last panel poll ({m} min ago) this address was not among the connected ones</i>",
        "tg_ev": "Events   ",
        "tg_dg": "Digest   ",
        "tg_ev_off_hint": "— penalty messages are not sent",
        "pn_who_found": "address {ip} belongs to:",
        "pn_who_name": "Name",
        "pn_who_seen": "the panel last saw it at",
        "pn_who_noname": "no name returned — check the users:read scope on the token",
        "pn_who_none": "the panel does not know {ip}; the node has addresses for {n} users",
        "pn_who_hint": "the address may have dropped, or this is not the node it connects through",
        "h_pn_who_ip": "address for the who command",
        "pn_bad_uuid": "the node UUID must look like a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d — 36 characters with dashes",
        "pn_seen": "Users on the last poll",
        "pn_seen_none": "zero on a successful poll almost always means the UUID points at a different node",
        "guard_ratio": "separately: uploaded over {p} percent of the download in a day, from {mb} MB",
        "ratio_title": "Upload-to-download ratio",
        "ratio_sub": "addresses with at least {mb} MB uploaded: {n}",
        "ratio_top": "Highest by ratio:",
        "ratio_now": "threshold now: {p} percent",
        "ratio_off": "signal is off: guard --upload-ratio 35",
        "h_ratio": "show the upload ratio distribution instead of the list",
        "h_ratio_mb": "ignore addresses that uploaded less than this many megabytes",
        "mon_total": "total",
        "mon_leg_total": "total — transferred since the engine loaded, down and up together",
        "st_share": "up/down",
        "st_share_hint": "{n} address(es) highlighted — uploaded over {p} percent of what they downloaded, which looks like seeding",
        "h_upload_ratio": "uploaded this percent of what was downloaded in a day, 0 = signal off",
        "h_upload_ratio_mb": "ignore the ratio until upload reaches this many megabytes",
        "why_ratio": "uploaded disproportionately much in 24h",
        "why_upload_day": "uploaded tens of gigabytes in 24h",
        "why_up_hourly": "uploaded gigabytes within an hour",
        "h_upload_gbh": "gigabytes uploaded per hour, 0 = off",
        "tg_uph_head": "🔔 <b>Long upload</b>",
        "tg_uph_warn": "Sent data for {h} h in 24h — the threshold is {n} h",
        "tg_uph_note": "<i>No limit applied. Seeding and a phone's first backup look the same: it is your call.</i>",
        "h_upload_hours": "hours of upload per day for a limit, 0 = off",
        "h_upload_ratio_hours": "hours of data upload required before the ratio penalises, 0 = off",
        "h_upload_hours_mbps": "below this upload rate a sample is not counted as data",
        "guard_uphours": "uploading for more than {h} h a day — a notice only, no penalty",
        "guard_uphourly": "hourly upload: limit at {d} GB",
        "tg_up_head": "🔔 <b>Heavy upload</b>",
        "tg_up_warn": "{gb} uploaded in 24h — the notice threshold is {n} GB",
        "tg_up_note": "<i>No limit applied, this is a warning. At {n} GB the speed will be reduced.</i>",
        "h_upload_warn": "gigabytes uploaded per day for a notice without a penalty, 0 = off",
        "h_upload_day": "gigabytes uploaded per day for a limit, 0 = off",
        "guard_upday": "daily upload: notice at {w} GB, limit at {d} GB",
        "guard_upwarn": "daily upload: notice at {w} GB, no limit",
        "guard_uplim": "daily upload: limit at {d} GB",
        "edt_off": "DOWNLOADS ARE NOT LIMITED: the interface has {kinds}, not fq",
        "edt_fix": "only fq holds packets until their departure time. Fix: modprobe sch_fq, then systemctl restart shaper",
        "pp_ports": "PROXY",
        "pp_hint": "— on these ports the header is trusted from any address",
        "pp_not_shaped": "port {p} is not in the shaped list — there is nothing to trust PROXY on",
        "h_proxy_ports": "ports where the PROXY header is trusted from any address (CDN ports only)",
        "eth_off": "NOTHING IS LIMITED: {iface} is not Ethernet (type={t})",
        "eth_fix": "the filter reads an L2 header, and tunnel or tun devices have none. Set a physical interface in IFACE",
        "too_slow": "{v} Mbit/s rounds down to zero bytes per second, and zero means «no limit». The minimum is 0.05",

        # Remnawave panel
        "pn_no_url": "the panel address is not set",
        "pn_no_token": "the panel token is not set",
        "pn_no_uuid": "the node UUID in the panel is not set",
        "pn_no_job": "the panel returned no job id",
        "pn_job_failed": "the panel reported job {job} as failed",
        "pn_job_slow": "the panel did not finish job {job} in time",
        "pn_denied": "the panel denied access: {detail}",
        "pn_bad_json": "the panel replied with something that is not JSON",
        "pn_socks": "only an http proxy is supported for the panel, not socks5",
        "pn_state": "Panel link",
        "pn_url": "Address",
        "pn_uuid": "Node UUID",
        "pn_win": "Window",
        "pn_thr": "Address threshold",
        "pn_act": "Action",
        "pn_cool": "Pause between alerts",
        "pn_exempt": "Exceptions",
        "pn_every": "Polling",
        "pn_token_exp": "Token valid until",
        "pn_token_none": "expiry unknown",
        "pn_token_gone": "expired",
        "pn_last": "Last successful poll",
        "pn_never": "never",
        "pn_oldest": "Oldest address in the list",
        "pn_oldest_short": "the node remembers less than the {w} min window — the window is capped by the node, not by the setting",
        "pn_last_err": "Last error",
        "pn_min": "min",
        "pn_sec": "s",
        "pn_scanning": "Asking the panel…",
        "pn_scan_ok": "Users on this node: {n}",
        "pn_scan_none": "No sharing found.",
        "pn_scan_found": "Sharing found: {n}",
        "pn_scan_row": "  {user} — {n} addresses, {here} of them seen by this node",
        "pn_dry": "Nothing was done: this was a dry run.",
        "pn_msg_head": "🔎 <b>Looks like a shared subscription</b>",
        "cdn_no_url": "the CDN provider API address is not set",
        "cdn_no_token": "the CDN provider API key is not set",
        "cdn_v_off": "🛑 The resource at the CDN provider is in state {s} — switched off, not broken.",
        "cdn_v_empty": "🛑 <b>Not a single request reaches the CDN edge.</b> This is the provider: empty both by requests and by addresses. The node has nothing to do with it.",
        "cdn_v_alive": "✅ Requests do reach the CDN edge: {r} in the last minutes. So clients are failing to reach the node itself — look here.",
        "clients_msg": "🟠 <b>{node} — clients are gone</b>\n\nNow {n}, usually about {norm}. The node is alive: processes running, no errors.",
        "cdn_state": "CDN link",
        "h_cdn": "link to the CDN provider API: whose fault it is when clients vanish",
        "h_cdn_url": "provider API address, for example https://api.example.com/v1",
        "h_cdn_token": "key from the provider dashboard",
        "h_cdn_res": "id of the resource this node sits behind",
        "cdn_ask": "Asking the provider…",
        "cdn_bad_res": "the resource id is a number",
        "cdn_bad_key": "the key was rejected: take it from the dashboard, API section",
        "cdn_no_res": "the link works, but the resource does not answer — check its id",
        "cdn_no_list": "the key has no resources",
        "cdn_quiet": "No answer: check the address, the key and the resource id.",
        "cdn_url": "API address",
        "cdn_res": "Resource id",
        "relay_msg": "⚠️ <b>{node} — the CDN relay seems to have changed address</b>\n\nOver the last minutes <b>{share}%</b> of the traffic on ports {ports} arrived without the PROXY header being parsed. Real client addresses are not recognised, so they all share <b>one limit between them</b>.\n\nMost connections come from <code>{ip}</code> — {n} of them.\n\nIf this is your new relay, add it:\n<code>shaperctl trusted add {ip} --relay</code>",
        "pn_off_head": "⛔ <b>Subscription disabled</b>",
        "pn_off_why": "🤖 Disabled by Shape: there were {n} addresses and no reaction for {m} min.",
        "pn_off_how": "<i>To turn it back on: <code>shaperctl panel enable {id}</code> or in the panel.</i>",
        "pn_off_refused": "more offenders than the cap ({n}) — nothing disabled, only reported",
        "h_pn_disable_after": "minutes without a reaction before the subscription is disabled, 0 = never",
        "pn_disable_after": "Disable subscription after",
        "pn_enabled_ok": "subscription #{id} enabled",
        "pn_disabled_ok": "subscription #{id} disabled",
        "pn_need_id": "a numeric panel id is required: panel enable 741",
        "pn_card_name": "👤 {name}",
        "pn_card_tg": "🆔 Telegram: <code>{id}</code>",
        "pn_card_login": "🔑 Panel login: <code>{login}</code>",
        "pn_card_login_plain": "Panel login: {login}",
        "pn_user_need_id": "a numeric panel id is required: panel user 6085",
        "pn_off": "the panel link is off: panel set --enable",
        "pn_user_none": "not on this node right now (users checked: {n})",
        "pn_user_ips": "Addresses on the node",
        "pn_user_noday": "nothing transferred on this node today",
        "pn_user_uphours": "sent data for {h} h",
        "pn_user_tag": "Tag",
        "h_pn_user": "the user's numeric panel id",
        "pn_card_panel": "🔑 Panel ID: <code>{id}</code>",
        "pn_card_panel_plain": "Panel ID: {id}",
        "pn_msg_blocked": "🚫 Access to the node cut off for {m} min, addresses: {n}",
        "pn_msg_nothing": "Nothing was done: only notification is enabled.",
        "pn_msg_ips": "Simultaneous addresses: <b>{n}</b> over the last {w} min",
        "pn_grace_long": "the grace period is longer than the block ({m} min) — the penalty expires first and the countdown breaks",
        "pn_msg_tariff": "<i>Threshold for his plan: {t} — devices sold: {d}</i>",
        "h_pn_per_device": "how many times the address threshold exceeds the plan's device count, 0 = one threshold for all",
        "pn_per_device": "Threshold from the plan",
        "pn_per_device_v": "×{k} the device count",
        "pn_msg_limited": "Addresses limited: {n} — to {mbps} Mbit/s for {m} min",
        "pn_msg_dropped": "Connections dropped: {n}",
        "pn_msg_more": "…and {n} more. The full list follows as a file.",
        "pn_msg_file": "📄 All addresses: {user} — {n}",
        "pn_rep_off": "the node report is off",
        "pn_rep_head": "Node report {node} · {at}",
        "pn_rep_users": "Users connected: {n}",
        "pn_rep_ips": "Addresses in total: {n}",
        "pn_rep_window": "Window: {w} min",
        "pn_rep_caption": "📋 <b>{node}</b> · {users} connected, {ips} addresses",
        "pn_rep_state": "Node report",
        "pn_rep_at": "Report time",
        "pn_rep_sent": "report sent",
        "pn_resolve": "Names from the panel",
        "h_pn_report": "send the node report: on or off",
        "h_pn_report_at": "when to send the report, HH:MM",
        "h_pn_report_thread": "topic ID for the node report",
        "h_pn_resolve": "use the name and Telegram ID instead of the number: on or off",
        "pn_token_soon": "⏳ {node}: the panel token expires in {days} day(s). "
                         "After that the sharing search will stop.",
        "pn_denied_msg": "⚠️ {node}: the panel denied access — the sharing "
                         "search has stopped.\n{detail}",
        "h_panel": "Remnawave panel link: find shared subscriptions",
        "h_pn_url": "panel address, e.g. https://panel.example.com",
        "h_pn_token": "panel token with the connections scopes",
        "h_pn_uuid": "UUID of this node in the panel",
        "h_pn_on": "enable panel polling",
        "h_pn_off": "disable panel polling",
        "h_pn_interval": "how often to ask the panel, in seconds",
        "h_pn_window": "simultaneity window, in minutes",
        "h_pn_threshold": "how many addresses count as sharing",
        "h_pn_action": "notify, limit, block, drop, or a comma-separated combination",
        "h_pn_mbps": "megabits to throttle an offender down to",
        "h_pn_minutes": "for how many minutes to throttle",
        "h_pn_cooldown": "pause between alerts about one person, in minutes",
        "h_pn_exempt": "who is left alone entirely: comma-separated userIds, applies to the auto-limiter too",
        "h_pn_exempt_tags": "the same by panel tag: BUSINESS,OFFICE",
        "pn_exempt_tags": "Tag exceptions",
        "h_pn_proxy": "http proxy to reach the panel",
        "h_pn_dry": "only show what was found, change nothing",
        "pn_bad_action": "action is notify, limit, block, drop, or a combination",
        "pn_bad_url": "the panel address must start with http:// or https://",
        "tg_limited": "Limited",
        "tg_shared": "this address may be shared by several people",
        "bad_ip": "«{ip}» is not an IP address",
        "tg_bad_token_fmt": "a token looks like 123456789:AAF… — get it from @BotFather",
        "tg_bad_chat_fmt": "chat_id is a number (often negative) or @name",
        "tg_bad_thread_fmt": "topic ID is the number from the topic link",
        "tg_bad_proxy": "the proxy address has no host, or the port is out of range",
        "tg_name_long": "node label is limited to 64 characters",
        "tg_at": "Digest time",
        "tg_digest_now": "digest for the current day",
        "tg_no_data": "nothing to report for today yet",
        "tg_bad_time": "time is written as HH:MM, for example 09:00",
        "h_tg_at": "when to send the digest, HH:MM",
        "tg_digest": "digest for", "tg_traffic": "Traffic",
        "tg_addresses": "Addresses", "tg_top": "Top downloaders",
        "lim_why": "why",
        "lim_when": "since",
        "lim_total": "addresses total",
        "lim_speed": "offender speed",
        "h_score": "score needed for a penalty (1-6)",
        "h_both_min": "minutes of simultaneous two-way load",
        "h_both_dl": "download floor for two-way load, percent",
        "h_both_ul": "upload floor for two-way load, percent",
        "h_hours": "hours of activity per day",
        "h_upload_gb": "gigabytes uploaded per day",
        "h_download_gb": "gigabytes downloaded per day, 0 = off",
        "h_download_gbh": "gigabytes downloaded per hour, 0 = off",
        "h_volume_needs": "hourly volume fires only alongside large upload packets",
        "h_volume_mbps": "penalty speed when volume alone fired, 0 = the usual one",
        "h_ratio_needs": "the ratio fires only if the upload was actual data",
        "h_bulk": "distribution of the share of upload in large packets",
        "bulk_title": "Distribution of the data share in uploads",
        "bulk_sub": "addresses: {n} · upload from {mb} MB · for the current day",
        "bulk_none": "nothing to count yet: daily counters are empty or the upload is small",
        "bulk_top": "top of the list          down        up  as data    avg    max",
        "bulk_now": "threshold now: {p}% — what falls under it is in red",
        "bulk_off": "signal is off: guard --ratio-needs-packet on",
        "guard_ratio_pkt": "and only if over {n}% of the upload went in large packets: calls go free",
        "guard_vol_needs": "hourly volume needs upload packets from {n} B: a store download goes free",
        "guard_vol_soft": "volume alone is cut to {mbps} Mbit/s, not to the penalty speed",
        "guard_ratio_live": "and only while the address is uploading: no penalty for one that left",
        "guard_ratio_hrs": "and only if it sent data for over {h} h in a day: an upload does not run that long",
        "guard_notify_cd": "a repeat notification about one address — at most once every {h} h",
        "guard_exempt_n": "panel exceptions: {n} — these are never limited",
        "why_hourly": "downloaded gigabytes within an hour",
        "h_watch_iv": "map polling period, sec (higher = lighter on CPU)",
        "why_download": "downloaded tens of gigabytes in 24h",
        "h_packet": "average upload packet size, bytes",
        "guard_both": "Both ways at once",
        "guard_score": "Score needed",
        "why_packet": "sends real data, not just ACKs",
        "why_peak": "holds the download ceiling",
        "why_upload": "uploaded a lot in 24h",
        "why_hours": "keeps the channel busy for hours",
        "h_guard": "automatic limiting of heavy users",
        "h_percent": "threshold as a percent of the limit",
        "h_sustain": "minutes of sustained load before the penalty",
        "h_pen_mbps": "offender speed, Mbit/s",
        "h_pen_min": "penalty duration, minutes",
        "h_watch": "watchdog daemon (started by the service)",
        "h_limited": "who is currently limited",
        "h_release": "release an IP",
        "guard_state": "Auto-limit",
        "guard_on": "enabled", "guard_off": "disabled",
        "guard_trigger": "Threshold", "guard_of_limit": "of the limit",
        "guard_during": "sustained for", "guard_penalty": "Penalty",
        "guard_for": "for", "guard_range": "{k}: allowed from {lo} to {hi}",
        "lim_title": "Limited addresses",
        "lim_none": "nobody is limited",
        "lim_left": "left",
        "rel_one": "{ip} released",
        "rel_all": "released: {n}",
        "rel_need_ip": "specify an IP or --all",
        "rel_bad_user": "a numeric panel id is required: release --user 741",
        "rel_user": "limits lifted: {n} (user #{id})",
        "h_rel_user": "lift limits from every address of a panel user",
        "restored_pen": "penalties restored: {n}",
        "watch_start": "watchdog started",
        "watch_hit": "{ip} limited to {mbps:g} Mbit/s for {m} min",
        "units": ["B", "KB", "MB", "GB", "TB", "PB"],
        "sec": "s", "min": "min", "hour": "h",
        "measuring": "measuring speed for {i} s…",
        "desc": "eBPF shaper: per-IP speed limit. Everything in Mbit/s.",
        "h_apply": "set ports and speed",
        "h_ports": "comma separated, 0 = all ports",
        "h_speed": "Mbit/s per IP address, 0 = remove the limit",
        "h_show": "show current settings",
        "h_restore": "push settings into the maps",
        "h_monitor": "who is loading the channel right now",
        "h_interval": "refresh period, seconds",
        "h_status": "per-IP statistics",
        "h_live": "measure current speed",
        "h_full": "show all IPs",
        "h_json": "JSON output",
        "h_whitelist": "IP whitelist",
        "h_event": "write a line into the event log",
        "h_personal": "permanent speed for an address",
        "h_pers_speed": "Mbit/s, above or below the shared limit",
        "h_owners": "who is behind an address",
        "h_history": "traffic per day",
        "h_metrics": "metrics in Prometheus format",
        "h_met_out": "write to a file for node_exporter (*.prom)",
        "met_need_prom": "the file name must end with .prom — that is what node_exporter looks for",
        "met_bad_url": "the push address must be http:// or https:// with a host name",
        "met_need_https": "https only for the outside world: over http the token travels in clear text",
        "met_push_off": "pushing is off: no address is set",
        "met_push_ok": "metrics pushed: {n} lines to {u}",
        "met_push_fail": "the push failed: {e}",
        "met_push_head": "Metrics push",
        "met_push_url": "Address",
        "met_push_token": "Token",
        "met_push_proxy": "Proxy",
        "met_push_wait": "Response timeout",
        "met_push_none": "not set",
        "met_push_set": "set",
        "met_sec": "s",
        "h_met_url": "where to push metrics; an empty string turns pushing off",
        "h_met_token": "token for the Authorization: Bearer header",
        "h_met_proxy": "socks5://… or http://… — if the server is unreachable otherwise",
        "h_met_timeout": "how many seconds to wait for an answer, 1..120",
        "met_written": "metrics written: {p} ({n} lines)",
        "pers_none": "no personal speeds set",
        "pers_set": "{ip}: personal speed {s:g} Mbit/s",
        "pers_removed": "{ip}: personal speed removed",
        "pers_absent": "{ip} has no personal speed",
        "pers_need_speed": "give a speed: --speed 25",
        "pers_range": "speed from {lo} to {hi} Mbit/s",
        "own_none": "no address owners known",
        "own_set": "{ip}: details saved",
        "own_removed": "{ip}: details removed",
        "own_bad_tg": "telegram_id must be a number",
        "hist_none": "history is empty, the first row appears at midnight",
        "hist_day": "Date", "hist_limited": "limits",
        "hist_total": "total over {n} days",
        "no_engine": "engine is not running — no maps in {d}\n  start it: systemctl start shaper",
        "cmd_fail": "command failed: {c}\n  {e}",
        "port_nan": "port \u00ab{p}\u00bb is not a number",
        "port_range": "port {p} is out of range 0..65535",
        "too_many_ports": "no more than {n} ports",
        "no_ports": "no ports given (0 = all ports)",
        "neg_speed": "speed cannot be negative",
        "too_fast": "{v} Mbit/s is over 100 Gbit/s, check the value",
        "speed": "Speed", "ports": "Ports", "all_ports": "ALL PORTS",
        "per_user": "per IP address, both directions",
        "unlimited": "unlimited",
        "restored": "limit {s:g} Mbit/s on ports {p}",
        "limit": "Limit", "no_limit": "unlimited",
        "total_ips": "total IPs", "active_min": "active in the last minute",
        "no_traffic": "no traffic through the shaper yet",
        "downloaded": "down", "uploaded": "up", "now": "now",
        "more_ips": "… {n} more IPs, full list: shaperctl status --full",
        "idle_note": "· — no traffic for over 5 minutes",
        "wl_added": "{ip} added to the whitelist",
        "wl_removed": "{ip} removed from the whitelist",
        "wl_loaded": "loaded into the whitelist: {n}",
        "wl_bad": "skipped invalid address: {ip}",
        "wl_empty": "whitelist is empty",
        "h_trusted": "trusted sources: tunnels and CDN relays",
        "h_tr_tunnel": "tunnel endpoint — unwrap its IPIP wrapper",
        "h_tr_relay": "CDN relay — trust its PROXY protocol header",
        "tr_added": "{ip} added as {what}",
        "tr_removed": "{ip} removed from trusted sources",
        "tr_loaded": "trusted sources loaded: {n}",
        "tr_bad": "skipped invalid line: {s}",
        "tr_empty": "no trusted sources — both unwrappings are off",
        "tr_need_kind": "specify --tunnel or --relay",
        "tr_tunnel": "tunnel endpoint",
        "tr_relay": "CDN relay",
        "mon_title": "Monitor", "mon_hint": "refresh every {i} s · Ctrl+C to exit",
        "mon_channel": "Channel now", "mon_limit": "Limit {s:g} Mbit/s per IP",
        "mon_nolimit": "No limit set", "mon_loading": "loading the channel",
        "mon_of": "of", "mon_idle": "nobody is downloading right now",
        "mon_up": "upload", "mon_avg": "avg", "mon_hold": "holding",
        "mon_bar": "load", "mon_more": "… {n} more active",
        "mon_share": "share of limit",
        "mon_minute": "last minute",
        "mon_limit_row": "Limit per address",
        "mon_per_ip": "for every IP",
        "mon_shown": "showing {a} of {b}",
        "mon_leg_hold": "holding over 30 s",
        "mon_leg_wl": "whitelisted",
        "mon_leg_limited": "limited",
        "mon_legend": "yellow — holding load over 30 s, red — hitting the limit",
    },
}


def _detect_lang():
    try:
        for line in open(os.path.join(ETC_DIR, "shaper.conf")):
            if line.strip().startswith("UI_LANG"):
                v = line.split("=", 1)[1].strip().strip('"').strip("'")
                if v in MSG:
                    return v
    except Exception:
        pass
    return "ru"


LANG = _detect_lang()


def t(key, **kw):
    s = MSG.get(LANG, MSG["ru"]).get(key, key)
    return s.format(**kw) if kw else s


# ────────────────────────────── утилиты ──────────────────────────────

def die(msg, code=1):
    print(f"{C['red']}✗ {msg}{C['r']}", file=sys.stderr)
    sys.exit(code)


def run(cmd, check=True):
    """
    Запуск внешней команды списком аргументов, без оболочки.

    shell=True здесь был бы миной: аргументы собираются из имён карт и
    hex-строк, и достаточно одного невнимательного вызова, чтобы значение
    из конфига попало в /bin/sh с правами root. Без оболочки такой класс
    ошибок невозможен в принципе.
    """
    p = subprocess.run(cmd, shell=False, capture_output=True, text=True)
    if check and p.returncode != 0:
        die(t("cmd_fail", c=" ".join(cmd), e=p.stderr.strip()))
    return p.stdout.strip(), p.returncode


def hexs(data):
    """Байты -> отдельные аргументы 'de ad be ef' для bpftool."""
    return [f"{b:02x}" for b in data]


def map_path(name):
    return os.path.join(PIN_DIR, name)


def require_engine():
    if not os.path.exists(map_path("config_map")):
        die(t("no_engine", d=PIN_DIR))


def map_update(name, key, value):
    require_engine()
    run(["bpftool", "map", "update", "pinned", map_path(name),
         "key", "hex", *hexs(key), "value", "hex", *hexs(value)])


def map_delete(name, key):
    run(["bpftool", "map", "delete", "pinned", map_path(name),
         "key", "hex", *hexs(key)], check=False)


def map_dump(name):
    """
    Пары (key, value) как их отдал bpftool. Формат зависит от наличия BTF:
    с BTF — словари с именами полей, без BTF — списки байтов. Разборщики
    ниже понимают оба варианта.
    """
    path = map_path(name)
    if not os.path.exists(path):
        return []
    out, rc = run(["bpftool", "map", "dump", "pinned", path, "-j"], check=False)
    if rc != 0 or not out:
        return []
    try:
        raw = json.loads(out)
    except json.JSONDecodeError:
        return []
    return [(e["key"], e.get("value")) for e in raw
            if isinstance(e, dict) and "key" in e]


def map_dump_percpu(name):
    """
    {индекс: сумма по всем CPU} для карты типа PERCPU_ARRAY.

    bpftool отдаёт такие карты иначе, чем обычные: вместо "value" приходит
    список "values" по одному на ядро. Обычный разборщик увидел бы там None
    и молча вернул нули — то есть «трафика не было» вместо «мы не поняли
    формат». Поэтому отдельная функция, а не ветка в map_dump.
    """
    path = map_path(name)
    if not os.path.exists(path):
        return {}
    out, rc = run(["bpftool", "map", "dump", "pinned", path, "-j"], check=False)
    if rc != 0 or not out:
        return {}
    try:
        raw = json.loads(out)
    except json.JSONDecodeError:
        return {}
    res = {}
    for e in raw:
        if not isinstance(e, dict) or "key" not in e:
            continue
        idx = parse_u32(e["key"])
        total = 0
        for cell in (e.get("values") or []):
            if not isinstance(cell, dict):
                continue
            raw_v = cell.get("value", 0)
            # С -j значение приходит массивом байтов, а не числом: у карты нет
            # BTF на тип значения, и bpftool отдаёт сырьё. Разбор через _int
            # молча давал ноль на каждой ячейке — счётчики выглядели пустыми
            # при живых цифрах в ядре. Рядом лежит "formatted" с готовым
            # числом, но полагаться на него нельзя: его печатают не все сборки.
            b = _raw(raw_v)
            if b is not None and len(b) >= 8:
                total += struct.unpack("<Q", b[:8])[0]
            else:
                total += _int(raw_v)
        res[idx] = total
    return res


def read_stats():
    """{имя счётчика: значение}. Пустой словарь, если карты нет."""
    raw = map_dump_percpu("stat_map")
    return {n: raw.get(i, 0) for i, n in enumerate(STAT_NAMES)} if raw else {}


def _int(x):
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        return int(x, 16) if x.startswith("0x") else int(x)
    return 0


def _raw(x):
    """Список байтов -> bytes. Для структурного вида возвращает None."""
    if isinstance(x, list) and (not x or not isinstance(x[0], (dict, list))):
        try:
            return bytes(_int(v) & 0xFF for v in x)
        except (ValueError, TypeError):
            return None
    return None


def parse_u32(x):
    b = _raw(x)
    if b is not None and len(b) >= 4:
        return struct.unpack("<I", b[:4])[0]
    if isinstance(x, dict):
        return _int(next(iter(x.values()), 0))
    return _int(x)


def parse_ip_key(k):
    """struct ip_key -> (адрес строкой, 16 байт ключа)."""
    b = _raw(k)
    if b is not None and len(b) >= 16:
        words = struct.unpack("<4I", b[:16])
    elif isinstance(k, dict):
        words = tuple((list(map(_int, k.get("addr", []))) + [0, 0, 0, 0])[:4])
    else:
        return None, None
    kb = struct.pack("<4I", *words)
    if words[1] == 0 and words[2] == 0 and words[3] == 0:
        return str(ipaddress.IPv4Address(kb[:4])), kb
    return str(ipaddress.IPv6Address(kb)), kb


def parse_user_state(v):
    b = _raw(v)
    if b is not None and len(b) >= USER_SIZE:
        _dep, total, seen, pkts = struct.unpack(USER_FMT, b[:USER_SIZE])
        return {"total": total, "seen": seen, "pkts": pkts}
    if isinstance(v, dict):
        return {"total": _int(v.get("total_bytes", 0)),
                "seen":  _int(v.get("last_seen_ns", 0)),
                "pkts":  _int(v.get("packets", 0))}
    return {"total": 0, "seen": 0, "pkts": 0}


# Гигабайт здесь ровно миллиард байт, а не 2^30. Так считает провайдер, так
# написано в тарифе, и так же — по 1e9 и 1e6 — заданы все пороги в этом файле.
#
# Пока вывод делил на 1024, а пороги на 1000, они расходились на семь
# процентов, и это выглядело как ошибка правила: в карточке «отдано 286.2 МБ»
# при пороге 300 МБ, хотя порог был перейдён — 286.2 · 1024² это 300.1
# миллиона байт. Число, по которому человек проверяет решение, обязано быть в
# тех же единицах, что и решение.
BYTE_STEP = 1000.0


def fmt_bytes(n):
    n = float(n)
    units = t("units")
    for u in units[:-1]:
        if n < BYTE_STEP:
            return f"{n:.1f} {u}"
        n /= BYTE_STEP
    return f"{n:.1f} {units[-1]}"


def mono_ns():
    return int(time.clock_gettime(time.CLOCK_MONOTONIC) * NS)


# ───────────────────────────── конфигурация ─────────────────────────────
# config.json:  {"ports": [443], "speed_mbps": 15}
# speed_mbps = 0 означает «ограничение выключено», трафик проходит свободно.

# Настройки сторожа. Порог в процентах от лимита: YouTube 1080p выдаёт
# в среднем 30-40% от канала в 10 Мбит/с, торрент и закачка — все 100%.
GUARD_DEFAULT = {
    "enabled": False,
    "score_needed": 3,        # баллов для штрафа
    "penalty_mbps": 1,        # хватает на переписку и звонок в мессенджере
    "penalty_min": 60,

    # Обязательное условие. Торрент — почти единственное бытовое занятие,
    # которое часами тянет данные ВНИЗ И ВВЕРХ одновременно. Стриминг молчит
    # вверх, облачный бэкап молчит вниз — оба не проходят это условие вообще.
    # Пороги разные: торрент забирает ВСЁ скачивание, а видеозвонок держит
    # скромный битрейт. Верхний порог низкий — у мобильных операторов отдача
    # всего 3-20 Мбит, и при лимите 10 сидирование даёт лишь треть канала.
    "both_dl_percent": 50,    # % от лимита вниз
    "both_ul_percent": 15,    # % от лимита вверх
    "both_ways_min": 10,      # минут одновременной нагрузки

    # Признаки, за которые начисляются баллы
    "packet_bytes": 600,      # +2 средний размер пакета в отдаче

    # Делает размер пакета не признаком, а обязательным условием: без
    # крупных пакетов вверх двусторонний счётчик не растёт вообще.
    #
    # Зачем. Порог отдачи задан в процентах от лимита, и опускать его, чтобы
    # ловить торрент со слабой раздачей, само по себе опасно: скачивание
    # порождает подтверждения вверх, а их объём растёт вместе со скоростью
    # скачивания. На ста мегабитах это несколько мегабит "отдачи", в которой
    # нет ни байта пользовательских данных.
    #
    # Размер пакета от скорости канала не зависит: подтверждение остаётся
    # коротким и на десяти мегабитах, и на гигабите. Поэтому с включённым
    # признаком порог отдачи можно опускать до единиц процентов, не боясь
    # поймать обычную закачку.
    "require_packet": False,
    "trigger_percent": 80,    # +1 держит потолок скачивания
    "sustain_min": 5,
    "hours_per_day": 4,       # +2 часов активности за сутки
    "upload_gb_per_day": 2,   # +1 гигабайт отдачи за сутки

    # Отдельный путь к штрафу, в обход обязательного условия. Торрент с
    # выключенной раздачей с точки зрения сети неотличим от обычной тяжёлой
    # закачки — выдаёт его только объём за сутки. 0 = признак выключен.
    "download_gb_per_day": 50,

    # Часовой порог — самый быстрый объёмный признак. При лимите 10 Мбит/с
    # час на полной скорости даёт ровно 4.5 ГБ, поэтому значение около 4
    # означает «держал канал почти весь час». По умолчанию выключен: на
    # капнутом канале столько же дают 4K-стриминг и загрузка игры.
    "download_gb_per_hour": 0,

    # Часовой порог сам по себе не отличает торрент от покупки в Steam.
    #
    # Порог, заданный долей канала, срабатывает ровно через полчаса на полной
    # скорости — на любом канале, потому что это и есть определение половины.
    # Современная игра весит под сто двадцать гигабайт, и человек, который её
    # честно купил, получал штраф через тридцать минут.
    #
    # С этим признаком часовой объём требует ещё и крупных пакетов вверх.
    # Закачка из магазина отдаёт подтверждения по 100-170 байт, торрент —
    # куски данных по 1200-1400. Цена известна и принята: торрент с наглухо
    # выключенной раздачей в час не поймается, потому что на сетевом уровне
    # он и есть обычная закачка. Его ловит суточный порог.
    "volume_needs_upload": False,

    # Признак отношения требует, чтобы отдача была ДАННЫМИ.
    #
    # Непропорциональная отдача бывает не только у раздачи. Живой случай:
    # 329 МБ вниз и 328 вверх, ровно 100%, средний пакет 267 байт, максимум за
    # сутки 349 — это разговор, где обе стороны говорят поровну, а не торрент.
    # Штраф получали Discord, Telegram и WhatsApp.
    #
    # С этим признаком отношение срабатывает, только если максимальный размер
    # пакета вверх за сутки дошёл до RATIO_PACKET_BYTES. Сидер до него дойдёт
    # в первое же окно передачи, разговор — никогда.
    "ratio_needs_packet": False,

    # Скорость штрафа, когда сработал ТОЛЬКО объём.
    #
    # Объём — единственный признак, который срабатывает и на честном
    # поведении. Резать за него до мессенджерных 1 Мбит/с значит наказывать
    # за покупку игры. Мягкая скорость (треть канала) закачку не убивает —
    # она докачается медленнее, — но канал от неё уже не страдает.
    # 0 = мягкой скорости нет, действует обычный penalty_mbps.
    "volume_penalty_mbps": 0,

    # Абсолютный объём отдачи за сутки. Два уровня: на первом только
    # уведомление, на втором ограничение.
    #
    # Единственный признак, который не зависит ни от пропорции, ни от размера
    # пакета, ни от протокола. Отношение отдачи ловит перекос и потому задевает
    # разговоры; доля данных ловит крупные пакеты и потому зависит от того,
    # склеивает ли их ядро. Тридцать гигабайт вверх — это просто тридцать
    # гигабайт вверх, и объяснить это клиенту можно одной фразой.
    #
    # Уровень уведомления нужен, чтобы видеть подходящих к границе раньше, чем
    # они её перейдут. Штрафа на нём нет.
    #
    # 0 = уровень выключен. По умолчанию выключены оба: на мобильной ноде такие
    # числа бессмысленны, там канал сам по себе потолок.
    # Часовой и суточный пороги на ОТДАЧУ — зеркало тех же порогов на
    # скачивание.
    #
    # Нужны нодам, где трафик оплачивается: счёт там идёт за оба направления,
    # а ограничение стояло только на одно, и бюджет тёк в другую сторону.
    #
    # На таких нодах вопрос «торрент это или бэкап» не имеет значения вовсе:
    # гигабайт стоит одинаково, чем бы он ни был. Намерение важно только там,
    # где трафик бесплатный.
    "upload_gb_per_hour": 0,

    "upload_warn_gb": 0,
    "upload_day_gb": 0,

    # Сколько часов за сутки адрес отдавал, прежде чем сообщить об этом.
    #
    # Только уведомление, штрафа нет. Причина в том, что первичный бэкап
    # телефона неотличим от раздачи по всем признакам сразу: человек, впервые
    # включивший выгрузку плёнки за десять лет, отдаёт сотню гигабайт сутки
    # напролёт, и у него сходится всё — и пропорция, и доля данных, и часы.
    #
    # Различает их только то, что бэкап кончается, а раздача нет. Пока мы
    # этого не считаем, решение остаётся за владельцем ноды.
    #
    # Меряет не «сколько», а «как долго»: выгрузка кончается — три гигабайта
    # на пятидесяти мегабитах уходят за восемь минут, архив клиенту за
    # двадцать, — а раздача идёт двенадцать часов и больше.
    #
    # От величины отдачи не зависит: считаются часы, а не гигабайты.
    # От размера пакета не зависит, пока выключен ratio_needs_packet — с ним
    # признак получает защиту от разговоров ценой независимости от протокола
    # (см. up_sec в watchdog).
    #
    # 0 = признак выключен.
    "upload_hours": 0,

    # Ниже какой отдачи замер не считается «отдавал».
    #
    # Здесь нижняя граница нужна только чтобы отбросить шум: отсекать
    # подтверждения обычной закачки скоростью нельзя. Их объём растёт вместе
    # со скоростью скачивания, и любая граница, отсекающая подтверждения на
    # быстром канале, отсекает вместе с ними тихого сидера.
    #
    # Живой случай, из-за которого граница опущена с 0.3 до 0.05: адрес отдал
    # 1.2 ГБ за 12.7 часа ровным слоем по 0.21 Мбит/с. Ни один десятисекундный
    # замер до 0.3 не дотянул, и признак, сделанный ровно для таких, показал
    # «отдавал 0.0 ч». А граница в 0.3 при этом всё равно ничего не отсекала:
    # у скачивающего на 10 Мбит подтверждения дают около 0.33 Мбит вверх.
    #
    # Подтверждения отсекает не скорость, а доля от скачивания —
    # UPLOAD_HOURS_ACK_SHARE.
    "upload_hours_mbps": 0.05,

    # Четвёртый отдельный путь: за сутки отдал больше, чем скачал.
    #
    # Тихий сидер не попадает ни под одно другое правило. Он отдаёт по
    # полмегабита круглосуточно: мгновенные пороги для него слишком высоки, а
    # абсолютный объём отдачи слишком мал — 900 мегабайт за сутки против
    # порога в два гигабайта. При этом он отдал вдвое больше, чем скачал, а
    # так не ведёт себя ничто, кроме раздачи.
    #
    # Почему именно отношение. У обычного клиента отдача — это подтверждения
    # TCP, и их доля определяется размером пакета, а не поведением человека:
    # 5-15% от скачанного, хоть на десяти мегабитах, хоть на гигабите. Выше
    # половины оно не поднимается ни при каком скачивании.
    #
    # Нижний порог по объёму обязателен: у адреса с 10 МБ вниз и 8 МБ вверх
    # отношение 80%, и это ничего не значит.
    #
    # 0 = признак выключен.
    "upload_ratio_percent": 0,
    # Три гигабайта, а не триста мегабайт.
    #
    # Триста ставились как «лишь бы отсечь мелочь», и это оказалось слишком
    # низко: за один вечер под ограничение попали трое с 306, 302 и 336 МБ
    # отдачи. Все трое перешагнули порог и сразу попались — то есть ловил не
    # признак, а сам порог. Триста мегабайт не стоят ни канала, ни трафика,
    # ни разбирательства с человеком.
    #
    # Цена решения названа прямо: тихий сидер, отдающий меньше трёх гигабайт
    # в сутки, теперь не ловится. Он и не мешает.
    "upload_ratio_min_mb": 3000,

    # Сколько часов за сутки адрес должен был отдавать данные, чтобы
    # непропорциональная отдача считалась поводом для штрафа.
    #
    # Пропорция ловит перекос, но не говорит, за какое время он набрался.
    # Живой случай: 418 МБ вниз, 326 вверх, отношение 78%, доля данных ровно
    # 55% при пороге 55 — прошёл впритык, а всего отдачи 326 мегабайт за два
    # часа. Отправленное в чат видео даёт ровно такую картину, и по пропорции
    # оно от раздачи неотличимо.
    #
    # Отличает их длительность: выгрузка кончается за минуты, раздача идёт
    # часами. Часы считаются тем же счётчиком, что и признак upload_hours, —
    # только отдача ДАННЫМИ, подтверждения и разговоры туда не попадают
    # (см. up_hours_tick).
    #
    # 0 = условия нет, отношение штрафует само по себе (поведение до 3.65).
    "upload_ratio_min_hours": 0,

    # Период опроса карт. Каждый цикл — два дампа bpftool и разбор JSON;
    # на одноядерных VPS есть смысл поднять до 20-30 секунд, детект от этого
    # почти не страдает, потому что счётчики считаются в замерах, а не в секундах.
    "watch_interval": 10,
}

# Веса признаков. Размер пакета — самый надёжный: он не зависит от скорости
# канала, а у мобильных операторов отдача гуляет от 3 до 20 Мбит.
# Отдача, ниже которой считаем, что за адресом никого нет.
#
# Признак отношения считается по суточным счётчикам, и до 3.35 у него не было
# условия «человек сейчас здесь». Карта ядра — LRU на 8192 записи: адрес,
# который качал утром и отвалился в обед, лежит в ней до полуночи вместе со
# своими цифрами. Вечером признак смотрел на них и выдавал штраф адресу, за
# которым уже никого нет: панель такого не знает, толку ноль, а если адрес
# успели переназначить — страдает посторонний.
#
# Настоящий сидер отдаёт непрерывно, отвалившийся не отдаёт ничего. Порог
# низкий нарочно: тихий сидер держит полмегабита, а под ограничением — один.
# Куда ведёт адрес в сообщении. Без явной ссылки Telegram делает её сам — и
# ведёт на http://<адрес>, то есть в браузере открывается попытка зайти на
# машину клиента. Так же, как в Remnawave, ведём на ipinfo.
#
# Это внешний сервис: переход по ссылке сообщает ему адрес. Само по себе
# ничего никуда не уходит — только когда вы нажимаете.
IPINFO_URL = "https://ipinfo.io/{ip}"

RATIO_LIVE_MBPS = 0.05

# Отправка метрик наружу.
#
# Ноды стоят за NAT и в странах, где WireGuard блокируют по отпечатку
# рукопожатия. Поэтому не «сервер приходит за метриками», а «нода отправляет
# сама»: исходящий HTTPS на обычный домен с настоящим сертификатом
# неотличим от того, что человек открыл сайт.
#
# Адрес задаётся целиком, вместе с путём: привязываться к endpoint'у
# конкретного хранилища нельзя — сегодня VictoriaMetrics, завтра что угодно,
# а нода про это знать не должна.
#
# push_url пуст — отправка выключена. Это и есть выключатель.
METRICS_DEFAULT = {
    "push_url": "",
    "push_token": "",
    "push_proxy": "",
    "push_timeout": 10,
}

# Суточные признаки и счётчик, по которому они считаются.
#
# Часовые окна после штрафа чистятся (hourly.pop), и человек получает
# передышку. У суточных такого не было: счётчик за сутки не уменьшается
# никогда, поэтому штраф истекал — и через десять секунд выдавался снова, до
# самой полуночи. Снятие штрафа руками не помогало по той же причине.
DAILY_SIGNALS = {"ratio": "up", "upload_day": "up", "download": "down"}

# Насколько должен вырасти суточный счётчик, чтобы наказать повторно.
#
# Ноль означал бы «штрафовать вечно», бесконечность — «один раз в сутки и
# гуляй». Четверть выбрана так, чтобы продолжающий раздачу возвращался через
# час-полтора, а переставший не возвращался вовсе.
RETRIGGER_GROWTH = 1.25

# Границы правдоподобия для среднего размера пакета. Ниже сорока байт не
# бывает даже голое подтверждение (20 IP + 20 TCP), выше джамбо-кадра не
# бывает ничего. Значение за этими границами означает, что счётчики байтов и
# пакетов разъехались, и печатать его — значит соврать.
#
# Проверять надо ОБЕ стороны. В 3.36 счётчики разъехались в одну сторону и
# вышло «168750 Б»; я поставил только потолок — и в 3.37 они разъехались в
# другую, дав «11 Б». Односторонняя проверка ловит половину случаев по
# определению.
MIN_PACKET_BYTES = 40
MAX_PACKET_BYTES = 9000

# Ниже какого объёма за замер не обновляем максимум размера пакета.
#
# Средний пакет ЗА СУТКИ отвечает не на тот вопрос, на который я его выдал.
# Он арифметический, а мелких пакетов в потоке на порядок больше, чем
# крупных: 440 МБ кусками по 1400 и 550 МБ подтверждениями по 60 дают
# среднее 109 байт. По нему нельзя сказать, отдавал ли человек данные —
# а именно за этим он и печатался.
#
# Максимум за десятисекундное окно отвечает: если хоть раз за сутки средний
# пакет в окне дошёл до 1300, значит куски данных вверх шли. Пол по объёму
# нужен, чтобы десяток случайных пакетов не назначил максимум.
#
# Двадцать килобайт за замер — это 16 Кбит/с. Выше брать нельзя: тихий сидер
# отдаёт полмегабита, а совсем тихий и того меньше, и со ста килобайт он не
# набирал бы ни одного подходящего окна за сутки — то есть проскакивал бы
# мимо проверки, которая как раз для него и ставится.
UPKT_MAX_FLOOR = 20_000

# До какого размера должен дойти максимум, чтобы считать отдачу данными.
#
# Тысяча, а не шестьсот как у мгновенного признака. Шестьсот выбирались для
# среднего за десять секунд активной передачи; на суточном максимуме видеосвязь
# доходит до семисот, и порог в шестьсот её не отсекает. Кусок торрента всегда
# набивается до предела сегмента — это 1300-1400 и на проводе, и внутри
# туннеля, потому что шифрование размер не уменьшает.
RATIO_PACKET_BYTES = 1000

# Какая часть скачанного должна уйти обратно, чтобы замер считался отдачей.
#
# Это защита «часов отдачи» от подтверждений обычной закачки, и она устроена
# как отношение, а не как скорость. Причина простая: объём подтверждений
# определяется скоростью скачивания, а не поведением человека. Один пакет
# подтверждения примерно на сотню байт приходится на два сегмента по 1500 —
# три-пять процентов от скачанного, одинаково и на десяти мегабитах, и на
# гигабите. Порог по скорости на быстром канале подтверждения пропускает, на
# медленном отсекает вместе с ними тихого сидера; порог по доле не зависит от
# скорости вовсе.
#
# Двадцать процентов — с запасом вчетверо от верхней границы подтверждений.
# От протокола не зависит: у QUIC доля подтверждений того же порядка.
UPLOAD_HOURS_ACK_SHARE = 0.2

# Умолчание границы часов отдачи с 3.52 по 3.63. Нужно, чтобы отличить
# «стояло по умолчанию» от «владелец ноды выбрал это число сам».
UPLOAD_HOURS_MBPS_WAS = 0.3

# Какая доля отдачи должна уйти крупными пакетами, чтобы считать её данными.
#
# Максимума мало. Максимум — отметка «хоть раз дошло», и её ставит одно
# десятисекундное окно: отправил человек видео в мессенджере, и весь день
# после этого его звонки проходят фильтр как раздача.
#
# Доля отвечает на правильный вопрос. Порог поставлен в середину разрыва,
# видного в распределении по двум нодам (`status --bulk`, 26 адресов):
#
#     0-39   15 адресов   честные: звонки лежат в 1-6%
#    40-65    ни одного
#    66-100  11 адресов   раздача
#
# Двигался он трижды, и каждый раз потому, что предыдущее значение ставилось
# по слишком малой выборке:
#
#   30 — по трём карточкам из Telegram. Видеозвонок прошёл его, набрав 32.
#   70 — по тем же трём точкам, но с другого края. Стояло не в середине
#        разрыва, а вплотную к нижнему краю верхнего кластера, и первый же
#        сидер похуже среднего (66% при отношении 392%) в него не влез.
#   55 — середина настоящего разрыва между 39 и 66.
#
# Мораль записана здесь, а не в истории изменений: порог, поставленный по
# нескольким наблюдениям, почти наверняка стоит не там. Распределение
# смотрится командой `status --bulk`, и двигать его надо по ней.
RATIO_BULK_PERCENT = 55

# С какой доли красить колонку монитора красным, а не жёлтым.
# Жёлтый — «дошёл до порога сторожа», красный — «сомнений почти нет».
BULK_LOUD_PERCENT = 80

# Как часто напоминать об одном и том же адресе с той же причиной.
#
# Штраф снимается через час, суточные счётчики за этот час не меняются — и
# признак срабатывает снова, и так до полуночи. Ограничение выдаётся каждый
# раз, как и раньше; молчит только Telegram.
GUARD_NOTIFY_COOLDOWN = 6 * 3600

SIGNAL_WEIGHTS = {"packet": 2, "peak": 1, "hours": 2, "upload": 1,
                  "download": 3, "hourly": 3, "ratio": 3, "upload_day": 3,
                  "up_hourly": 3}

# Веса признаков. Одной нагрузки (3) не хватает — нужен второй признак.
# Так разовая большая закачка проходит мимо, а торрент набирает 7 из 7.
SCORE_LOAD, SCORE_RATIO, SCORE_PACKETS = 3, 2, 2
# Окно усреднения для соотношения и размера пакета.
SCORE_WINDOW_SEC = 60


# Уведомления. По умолчанию выключены: свежая установка ничего никуда не шлёт.
TG_DEFAULT = {
    "enabled": False,
    "token": "",
    "chat_id": "",
    "thread_id": "",      # message_thread_id для супергрупп с темами
    "node_name": "",      # как подписывать ноду, пусто = имя хоста
    "events": True,       # сообщение при каждом ограничении
    "daily": True,        # сводка за прошедшие сутки
    "updates": True,      # сообщение, когда в репозитории появилась версия новее
    "digest_at": "09:00", # во сколько её присылать, местное время ноды
    "proxy": "",          # socks5://… или http://… — нужен на российских нодах

    # Резервная копия состояния файлом. По умолчанию выключена; включённая
    # уходит раз в неделю в digest_at того же дня. Своей темы может не иметь —
    # тогда идёт туда же, куда отчёты.
    "backup": False,
    "backup_thread_id": "",
    "backup_day": 1,      # 1 понедельник … 7 воскресенье
}


# Связь с панелью Remnawave. Нужна ровно для одного: нода видит адреса, но не
# знает, кому они принадлежат. Панель знает. Из этого получается поиск тех, кто
# раздал свою подписку: у обычного человека на одной ноде живёт один-два адреса
# одновременно, у перепродавца — десятки.
#
# Раздел необязательный и по умолчанию выключен. Панель недоступна, токен
# протух, версия API другая — Shape продолжает работать ровно как раньше.
# Ограничение скорости и сторож от панели не зависят и зависеть не должны:
# нода обязана оставаться самостоятельной.
PANEL_DEFAULT = {
    "enabled": False,
    "url": "",            # https://panel.example.com, без /api
    "token": "",          # токен панели; нужны права connections
    "node_uuid": "",      # какая нода в панели соответствует этой машине
    "proxy": "",          # http(s)-прокси; socks5 здесь не поддержан

    "interval": 300,      # как часто спрашивать панель, секунды
    "window_min": 10,     # окно «одновременности» по lastSeen, минуты
    "ip_threshold": 20,   # адресов в окне, выше которых считаем раздачей

    # notify | limit | drop — и любые сочетания через запятую.
    # По умолчанию только уведомление: резать чужих клиентов без ведома
    # владельца ноды нельзя, это должно включаться руками.
    "action": "notify",
    "limit_mbps": 1,
    "limit_min": 60,
    "cooldown_min": 360,  # не долбить одним и тем же нарушителем
    # userId, которых не трогает ни поиск раздачи, ни автоограничение.
    # Деловые аккаунты: офис на одной подписке и выгрузка рабочих файлов
    # выглядят нарушением по обеим проверкам, и порогом это не лечится.
    "exempt": [],

    # То же самое, но по тегу из панели. Список номеров приходится держать на
    # каждой из двадцати восьми нод и править везде при каждом новом клиенте;
    # тег ставится в панели один раз и виден отовсюду.
    "exempt_tags": [],

    # Во сколько раз порог адресов больше числа устройств в тарифе. 0 = не
    # учитывать тариф вовсе и держать один порог на всех.
    #
    # Смысл в том, что «сколько устройств продано» и «сколько адресов норма» —
    # это одно и то же число, только второе больше: у мобильного клиента адрес
    # меняется при переподключении и хендовере, и одно устройство даёт
    # несколько адресов за окно.
    #
    # Правило только ПОДНИМАЕТ порог и никогда не опускает: базовый остаётся
    # нижней границей. Новых срабатываний оно не добавляет — только убирает
    # ложные у тех, кому продано много устройств.
    "per_device": 0,

    # Через сколько минут без реакции владельца отключить подписку целиком.
    # 0 = никогда. По умолчанию выключено: это единственное действие Shape,
    # которое меняет что-то в панели, а не у себя.
    "disable_after_min": 0,

    # Имя и Telegram ID вместо внутреннего номера пользователя. Требует у
    # токена права users:read. Выключишь — в сообщениях останутся номера,
    # всё остальное продолжит работать.
    "resolve": True,

    # Отчёт по ноде: кто подключён и с каких адресов. Отдельно от суточной
    # сводки Telegram — это другой отчёт и, как правило, в другое время.
    "report": False,
    "report_at": "09:00",
    "report_thread_id": "",
}


def load_config():
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    guard = dict(GUARD_DEFAULT)
    guard.update(cfg.get("guard", {}))
    # Старая граница часов отдачи (0.3 Мбит/с) не отсекала подтверждения и
    # при этом не пропускала тихого сидера — то есть не делала ничего, кроме
    # вреда. Её никто не выбирал руками: она стояла умолчанием с 3.52 до 3.64.
    # Ровно это значение считаем «не настроено» и заменяем новым умолчанием;
    # любое другое — выбор владельца ноды и остаётся как есть.
    if guard.get("upload_hours_mbps") == UPLOAD_HOURS_MBPS_WAS:
        guard["upload_hours_mbps"] = GUARD_DEFAULT["upload_hours_mbps"]
    tg = dict(TG_DEFAULT)
    tg.update(cfg.get("telegram", {}))
    panel = dict(PANEL_DEFAULT)
    panel.update(cfg.get("panel", {}))
    # exempt приходит из файла и правится руками — приведём к списку строк,
    # чтобы сравнение с userId из панели не зависело от того, записали там
    # число или строку.
    panel["exempt"] = [str(x).strip() for x in (panel.get("exempt") or [])
                       if str(x).strip()]
    panel["exempt_tags"] = [str(x).strip() for x in
                            (panel.get("exempt_tags") or []) if str(x).strip()]
    cdn = dict(CDN_DEFAULT)
    cdn.update(cfg.get("cdn", {}))
    met = dict(METRICS_DEFAULT)
    met.update(cfg.get("metrics", {}))
    # Порты, на которых заголовку PROXY верят от кого угодно. Отдельно от
    # ports: доверие и ограничение — разные вещи, и совпадают они не всегда.
    proxy_ports = [int(x) for x in (cfg.get("proxy_ports") or [])
                   if str(x).strip().isdigit()]
    return {"ports": cfg.get("ports", [443]),
            "proxy_ports": proxy_ports,
            "speed_mbps": float(cfg.get("speed_mbps", 0)),
            "guard": guard, "telegram": tg, "panel": panel, "metrics": met,
            "cdn": cdn}


def save_config(cfg):
    """
    Пишет конфиг целиком, сохраняя незнакомые разделы.

    Слияние с тем, что уже лежит на диске, — страховка от того самого класса
    ошибок, из-за которого правка автоограничения когда-то стирала настройки
    Telegram: вызывающий передал не все разделы, и остальные исчезли.
    """
    os.makedirs(ETC_DIR, exist_ok=True)
    try:
        with open(CONFIG_FILE) as f:
            merged = json.load(f)
        if not isinstance(merged, dict):
            merged = {}
    except Exception:
        merged = {}
    merged.update(cfg)

    tmp = CONFIG_FILE + ".tmp"
    # Права ставим до записи: между open и chmod иначе есть окно, в котором
    # файл с токеном лежит доступным на чтение всем.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(merged, f, indent=2)
    os.replace(tmp, CONFIG_FILE)
    # В конфиге лежит токен бота — читать его посторонним незачем.
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass


def valid_ip(s):
    """Строка -> нормализованный адрес или None. Единственная точка правды."""
    try:
        return str(ipaddress.ip_address(str(s).strip()))
    except ValueError:
        return None


def parse_ports(s):
    out = []
    for part in str(s).split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            die(t("port_nan", p=part))
        p = int(part)
        if not 0 <= p <= 65535:
            die(t("port_range", p=p))
        if p not in out:
            out.append(p)
    if len(out) > MAX_PORTS:
        die(t("too_many_ports", n=MAX_PORTS))
    return out


def write_to_kernel(cfg):
    """Заливает скорость и список портов в BPF-карты."""
    require_engine()
    bps = int(cfg["speed_mbps"] * BYTES_PER_MBPS)
    map_update("config_map", struct.pack("<I", 0), struct.pack(CONFIG_FMT, bps))

    live = {parse_u32(k) for k, _ in map_dump("port_map")}
    proxy = set(cfg.get("proxy_ports") or [])
    for p in live - set(cfg["ports"]):
        map_delete("port_map", struct.pack("<I", p))
    for p in cfg["ports"]:
        flags = PORT_SHAPE | (PORT_PROXY if p in proxy else 0)
        map_update("port_map", struct.pack("<I", p), bytes([flags]))


def cmd_apply(a):
    cfg = load_config()
    if a.ports is not None:
        ports = parse_ports(a.ports)
        if not ports:
            die(t("no_ports"))
        cfg["ports"] = ports
    if getattr(a, "proxy_ports", None) is not None:
        pp = parse_ports(a.proxy_ports) if a.proxy_ports.strip() else []
        unknown = [p for p in pp if p not in cfg["ports"]]
        if unknown:
            die(t("pp_not_shaped", p=",".join(map(str, unknown))))
        cfg["proxy_ports"] = pp
    if a.speed is not None:
        # nan и inf проходят любые сравнения: nan < 0 ложь, nan > MAX ложь.
        # Без явной проверки такое значение доехало бы до int() и уронило
        # команду с трассировкой прямо посреди применения настроек.
        if a.speed != a.speed or a.speed in (float("inf"), float("-inf")):
            die(t("neg_speed"))
        if a.speed < 0:
            die(t("neg_speed"))
        if a.speed > MAX_MBPS:
            die(t("too_fast", v=a.speed))
        # Ноль в карте ядра означает «ограничение выключено». int() усекает
        # вниз, поэтому любая скорость ниже 0.000008 Мбит/с превращалась в
        # безлимит — при ненулевом числе на экране. Граница та же, что в API.
        if 0 < a.speed < 0.05:
            die(t("too_slow", v=a.speed))
        cfg["speed_mbps"] = a.speed

    write_to_kernel(cfg)
    save_config(cfg)
    if not a.quiet:
        cmd_show(a)


def cmd_show(a):
    cfg = load_config()
    ports = ", ".join(map(str, cfg["ports"])) if cfg["ports"] != [0] else t("all_ports")
    print()
    if cfg["speed_mbps"] > 0:
        print(f"  {t('speed'):<9}: {C['b']}{cfg['speed_mbps']:g} Mbit/s{C['r']} "
              f"{t('per_user')}")
    else:
        print(f"  {t('speed'):<9}: {C['yel']}{t('unlimited')}{C['r']}")
    print(f"  {t('ports'):<9}: {ports}")
    if cfg.get("proxy_ports"):
        pp = ", ".join(map(str, cfg["proxy_ports"]))
        print(f"  {t('pp_ports'):<9}: {pp} {C['gry']}{t('pp_hint')}{C['r']}")
    # Предупреждение стоит здесь, на самом ходовом экране: нода без fq
    # выглядит здоровой во всём остальном, и заметить это больше негде.
    ready, bad = edt_ready()
    if not ready:
        print(f"  {C['red']}⚠ {t('edt_off', kinds=bad)}{C['r']}")
        print(f"    {C['gry']}{t('edt_fix')}{C['r']}")
    arphrd = iface_arphrd()
    if arphrd is not None and arphrd != ARPHRD_ETHER:
        print(f"  {C['red']}⚠ {t('eth_off', iface=active_iface(), t=arphrd)}{C['r']}")
        print(f"    {C['gry']}{t('eth_fix')}{C['r']}")
    cmd_guard_show(cfg["speed_mbps"], cfg["guard"])
    # Строка для сверки нод между собой: одинаковый отпечаток — одинаковая
    # политика. Держим её приглушённой, повседневной работе она не мешает.
    nid = node_id()
    print(f"  {C['gry']}{t('id_node')} {nid or t('id_none')}"
          f"  ·  {t('id_config')} {config_hash(cfg)}{C['r']}")
    print()


def cmd_restore(a):
    """Вызывается сервисом при старте: заливает config.json в свежие карты."""
    cfg = load_config()
    write_to_kernel(cfg)
    n = restore_penalties()
    print(t("restored", s=cfg["speed_mbps"], p=",".join(map(str, cfg["ports"]))))
    if n:
        print(t("restored_pen", n=n))


# ───────────────────────────── статистика ─────────────────────────────

def read_users():
    """{ip: {"down": байт, "up": байт, "up_pkts": шт, "seen": нс}}"""
    users = {}
    for map_name, direction in (("user_state_map_down", "down"),
                                ("user_state_map_up", "up")):
        for k, v in map_dump(map_name):
            ip, _ = parse_ip_key(k)
            if ip is None:
                continue
            st = parse_user_state(v)
            e = users.setdefault(ip, {"down": 0, "up": 0, "up_pkts": 0, "seen": 0})
            e[direction] = st["total"]
            if direction == "up":
                e["up_pkts"] = st["pkts"]
            e["seen"] = max(e["seen"], st["seen"])
    return users


RATIO_BUCKETS = (10, 20, 30, 40, 50, 75, 100)


def ratio_report(users, floor_bytes, threshold):
    """
    Распределение отношения отдачи к скачиванию по корзинам.

    Зачем отдельный вид. Порог между честным клиентом и раздающим не
    вычисляется из теории — он виден как разрыв в распределении: у одних
    отдача 2-17%, у других 45-88%, а между ними пусто. Но увидеть этот разрыв
    по списку, отсортированному по объёму, нельзя: раздающих единицы на
    тысячи адресов, и они разбросаны по всему списку.

    Здесь же он виден сразу, и порог ставится по факту, а не на глаз.

    floor_bytes отсекает шум: у адреса с 10 МБ вниз и 8 МБ вверх отношение
    80%, и в статистике это только мешает.
    """
    rows = []
    for ip, c in users.items():
        up, down = c.get("up", 0), c.get("down", 0)
        if up < floor_bytes:
            continue
        rows.append((ip, down, up, 1e9 if not down else up * 100.0 / down))
    rows.sort(key=lambda r: -r[3])

    counts = [0] * (len(RATIO_BUCKETS) + 1)
    for _ip, _d, _u, r in rows:
        for i, edge in enumerate(RATIO_BUCKETS):
            if r < edge:
                counts[i] += 1
                break
        else:
            counts[-1] += 1
    return rows, counts


BULK_BUCKETS = (10, 20, 30, 40, 50, 60, 70, 80, 90)


def bulk_report(daily, floor_bytes):
    """
    Распределение доли отдачи, ушедшей крупными пакетами.

    То же самое, что ratio_report, но для второго признака. Порог отношения в
    35% мы поставили правильно, потому что смотрели на распределение по шести
    тысячам адресов и увидели, где пусто. Порог доли в 70% поставлен по трём
    точкам из уведомлений в Telegram — это гадание, и оно уже подозрительно
    близко к живому адресу с 78%.

    Считается по суточным счётчикам, а не по карте ядра: разбивка байтов на
    крупные и мелкие живёт только там.

    Адреса нужны только для верхних строк списка; само распределение их не
    использует, и в нём нет ничего, что относилось бы к конкретному человеку.
    """
    rows = []
    for ip, c in (daily or {}).items():
        parsed = day_upkt(c)
        if not parsed or parsed[0] < floor_bytes:
            continue
        b, n, top, bulk, _since = parsed
        up, down = c.get("up", 0), c.get("down", 0)
        rows.append((ip, down, up, min(100.0, bulk * 100.0 / b),
                     (b / n) if n else 0, top))
    rows.sort(key=lambda r: -r[3])

    counts = [0] * (len(BULK_BUCKETS) + 1)
    for r in rows:
        for i, edge in enumerate(BULK_BUCKETS):
            if r[3] < edge:
                counts[i] += 1
                break
        else:
            counts[-1] += 1
    return rows, counts


def print_bulk_report(cfg, daily, floor_mb, top=10):
    floor_bytes = float(floor_mb) * 1e6
    rows, counts = bulk_report(daily, floor_bytes)
    threshold = RATIO_BULK_PERCENT if cfg["guard"].get("ratio_needs_packet") \
        else 0

    print(f"\n  {C['b']}{t('bulk_title')}{C['r']}")
    print(f"  {C['gry']}{t('bulk_sub', n=len(rows), mb=f'{floor_mb:g}')}{C['r']}")
    if not rows:
        print(f"  {C['gry']}{t('bulk_none')}{C['r']}\n")
        return

    peak = max(counts) or 1
    edges = ["0"] + [str(e) for e in BULK_BUCKETS]
    for i, n in enumerate(counts):
        label = f"{edges[i]}-{edges[i + 1]}" if i < len(BULK_BUCKETS) \
            else f"{BULK_BUCKETS[-1]}+"
        lo = 0 if i == 0 else BULK_BUCKETS[i - 1]
        hot = threshold and lo >= threshold
        col = C["red"] if hot else (C["gry"] if not n else C["b"])
        print(f"  {label:>8}  {col}{'█' * int(round(n * 24 / peak)) if n else ''}"
              f"{'' if n else '·'} {n}{C['r']}")

    print(f"\n  {C['gry']}{t('bulk_top')}{C['r']}")
    for ip, down, up, share, avg, mx in rows[:top]:
        col = C["red"] if threshold and share >= threshold else C["gry"]
        print(f"  {ip:<20}{fmt_bytes(down):>10} ↓{fmt_bytes(up):>10} ↑"
              f"{col}{share:>6.0f}%{C['r']}"
              f"{C['gry']}{int(avg):>7}{int(mx):>7}{C['r']}")
    print(f"\n  {C['gry']}"
          + (t("bulk_now", p=threshold) if threshold else t("bulk_off"))
          + f"{C['r']}\n")


def print_ratio_report(cfg, users, floor_mb, top=10):
    floor_bytes = float(floor_mb) * 1e6
    threshold = cfg["guard"].get("upload_ratio_percent", 0) or 0
    rows, counts = ratio_report(users, floor_bytes, threshold)

    print(f"\n  {C['b']}{t('ratio_title')}{C['r']}")
    print(f"  {C['gry']}{t('ratio_sub', n=len(rows), mb=f'{floor_mb:g}')}{C['r']}")
    if not rows:
        print()
        return

    peak = max(counts) or 1
    edges = ["0"] + [str(e) for e in RATIO_BUCKETS]
    for i, n in enumerate(counts):
        if i < len(RATIO_BUCKETS):
            label = f"{edges[i]}-{edges[i + 1]}"
        else:
            label = f"{RATIO_BUCKETS[-1]}+"
        lo = 0 if i == 0 else RATIO_BUCKETS[i - 1]
        hot = threshold and lo >= threshold
        col = C["red"] if hot else (C["gry"] if not n else C["b"])
        print(f"  {label:>8}  {col}{'█' * int(round(n * 24 / peak)) if n else ''}"
              f"{'' if n else '·'} {n}{C['r']}")

    print(f"\n  {C['gry']}{t('ratio_top')}{C['r']}")
    for ip, down, up, r in rows[:top]:
        col = C["red"] if threshold and r >= threshold else C["gry"]
        shown = "∞" if r >= 1e8 else f"{r:.0f}%"
        print(f"  {ip:<20}{fmt_bytes(down):>11} ↓{fmt_bytes(up):>11} ↑"
              f"{col}{shown:>7}{C['r']}")
    if threshold:
        print(f"\n  {C['gry']}{t('ratio_now', p=threshold)}{C['r']}")
    else:
        print(f"\n  {C['gry']}{t('ratio_off')}{C['r']}")
    print()


def cmd_status(a):
    require_engine()
    cfg = load_config()

    if getattr(a, "ratio", False):
        print_ratio_report(cfg, read_users(), a.ratio_mb)
        return

    if getattr(a, "bulk", False):
        print_bulk_report(cfg, load_daily(), a.ratio_mb)
        return

    first = read_users()
    if a.live:
        print(f"{C['gry']}  {t('measuring', i=a.interval)}{C['r']}")
        time.sleep(a.interval)
        second = read_users()
    else:
        second = first

    now = mono_ns()
    rows = []
    for ip, cur in second.items():
        prev = first.get(ip, {"down": 0, "up": 0})
        # байты за интервал -> Мбит/с
        dl = max(0, cur["down"] - prev["down"]) * 8 / 1e6 / a.interval if a.live else None
        ul = max(0, cur["up"] - prev["up"]) * 8 / 1e6 / a.interval if a.live else None
        idle = (now - cur["seen"]) / NS if cur["seen"] else 0
        rows.append((ip, cur, dl, ul, idle))

    if a.json:
        print(json.dumps([
            {"ip": ip, "downloaded_bytes": c["down"], "uploaded_bytes": c["up"],
             "download_mbps": dl, "upload_mbps": ul, "idle_sec": round(idle, 1)}
            for ip, c, dl, ul, idle in rows], indent=2))
        return

    # Отношение отдачи к скачиванию — то, по чему раздающий виден сразу.
    #
    # Без него он теряется: сортировка идёт по объёму, а сидер по определению
    # качает мало и проваливается в хвост из тысяч адресов. Живой пример —
    # 379 МБ вниз против 916 МБ вверх стояли шестнадцатыми среди шести тысяч,
    # хотя это единственная строка в списке, которая вообще не похожа на
    # обычного клиента.
    ratio_floor = float(cfg["guard"].get("upload_ratio_min_mb", 300)) * 1e6
    ratio_percent = cfg["guard"].get("upload_ratio_percent", 0) or 50

    def share(c):
        """Отдача в процентах от скачанного. Отдачи почти нет — None."""
        if c["up"] < ratio_floor / 10:
            return None
        return 1e9 if not c["down"] else c["up"] * 100.0 / c["down"]

    def suspect(c):
        sh = share(c)
        return sh is not None and sh >= ratio_percent and c["up"] >= ratio_floor

    # Подозрительные — наверх, остальные по объёму как раньше. Сортировать
    # весь список по отношению нельзя: тогда вниз уедут те, кто действительно
    # грузит канал, а список нужен и для этого тоже.
    rows.sort(key=(lambda x: ((x[2] or 0) + (x[3] or 0))) if a.live
              else (lambda x: x[1]["down"] + x[1]["up"]), reverse=True)
    rows.sort(key=lambda x: suspect(x[1]), reverse=True)
    active = [x for x in rows if x[4] < 60]

    limit = (f"{cfg['speed_mbps']:g} Mbit/s" if cfg["speed_mbps"] > 0
             else t("no_limit"))
    ports = ", ".join(map(str, cfg["ports"])) if cfg["ports"] != [0] else t("all_ports")
    print(f"\n  {t('limit')} {C['b']}{limit}{C['r']} · {t('ports').lower()} {ports} · "
          f"{t('total_ips')}: {len(rows)} · {t('active_min')}: {len(active)}")
    print("  " + "─" * 70)

    if not rows:
        print(f"  {C['gry']}{t('no_traffic')}{C['r']}\n")
        return

    head = (f"  {'IP':<30}{t('downloaded'):>12}{t('uploaded'):>12}"
            f"{t('st_share'):>9}")
    head += f"{t('now'):>14}" if a.live else ""
    print(f"{C['gry']}{head}{C['r']}")

    shown = rows if a.full else rows[:a.top]
    flagged = 0
    for ip, c, dl, _ul, idle in shown:
        mark = f"{C['gry']}·{C['r']}" if idle > 300 else " "
        sh = share(c)
        if sh is None:
            col = f"{C['gry']}{'—':>9}{C['r']}"
        elif suspect(c):
            flagged += 1
            col = f"{C['red']}{min(sh, 9999):>8.0f}%{C['r']}"
        else:
            col = f"{min(sh, 9999):>8.0f}%"
        line = f" {mark}{ip:<30}{fmt_bytes(c['down']):>12}{fmt_bytes(c['up']):>12}{col}"
        if a.live:
            line += f"{dl:>9.1f} Mbit/s"
        print(line)

    if not a.full and len(rows) > a.top:
        print(f"  {C['gry']}{t('more_ips', n=len(rows) - a.top)}{C['r']}")
    if flagged:
        print(f"  {C['red']}{t('st_share_hint', n=flagged, p=ratio_percent)}{C['r']}")
    print(f"  {C['gry']}{t('idle_note')}{C['r']}\n")


# ────────────────────────────── монитор ──────────────────────────────

def rates(prev, cur, dt):
    """
    По каждому IP за прошедший интервал: скорости в Мбит/с и средний размер
    пакета в отдаче.

    Размер пакета здесь не для красоты. Это единственное число, которое
    отличает раздачу от обычной закачки, и оно не зависит от скорости канала:
    подтверждение остаётся коротким и на десяти мегабитах, и на гигабите.
    """
    out = {}
    for ip, c in cur.items():
        p = prev.get(ip, {"down": 0, "up": 0, "up_pkts": 0})
        up_bytes = max(0, c["up"] - p["up"])
        up_pkts = max(0, c.get("up_pkts", 0) - p.get("up_pkts", 0))
        out[ip] = (max(0, c["down"] - p["down"]) * 8 / 1e6 / dt,
                   up_bytes * 8 / 1e6 / dt,
                   (up_bytes / up_pkts) if up_pkts else 0)
    return out


def fmt_hold(sec):
    """Сколько времени подряд IP держит нагрузку."""
    if sec < 1:
        return "—"
    if sec < 60:
        return f"{int(sec)} {t('sec')}"
    if sec < 3600:
        return f"{int(sec // 60)} {t('min')}"
    return f"{sec / 3600:.1f} {t('hour')}"


# Дробные блоки: восьмушки ширины символа. Обычная полоса из целых блоков
# при ширине 12 различает всего двенадцать уровней — разница между 7.3 и 7.4
# на ней не видна вовсе. С восьмушками уровней 96 при той же ширине.
# Выше этого среднего размера пакета отдача перестаёт быть подтверждениями и
# становится данными. Подтверждение в туннеле занимает 100-170 байт, кусок
# торрента — больше тысячи. Число служит только подсветкой в мониторе;
# решение сторож принимает по своему packet_bytes.
PKT_DATA_HINT = 600

EIGHTHS = "▏▎▍▌▋▊▉█"
SPARK = "▁▂▃▄▅▆▇█"


def bar(value, scale, width=14):
    if scale <= 0:
        return ""
    units = max(0.0, min(1.0, value / scale)) * width
    full = int(units)
    rest = units - full
    out = "█" * full
    if full < width and rest > 0.06:
        out += EIGHTHS[min(7, int(rest * 8))]
    return out + "·" * max(0, width - len(out))


def spark(values, width=12):
    """Мини-график последних значений. Пусто, если рисовать нечего."""
    vals = [v for v in values if v is not None][-width:]
    if len(vals) < 2:
        return ""
    top = max(vals)
    if top <= 0:
        return "▁" * len(vals)
    return "".join(SPARK[min(7, int(v / top * 7.999))] for v in vals)


def load_color(share):
    """
    Цвет по доле от лимита. Раньше цвет зависел от того, «держит» ли адрес
    нагрузку дольше тридцати секунд, и на спокойной ноде экран был
    одноцветным — глазу не за что зацепиться.
    """
    if share >= 0.8:
        return C["bred"]
    if share >= 0.5:
        return C["byel"]
    if share >= 0.2:
        return C["bgrn"]
    return C["gry"]


def cmd_monitor(a):
    require_engine()
    cfg = load_config()
    limit = cfg["speed_mbps"]
    # «Держит нагрузку» — выше половины лимита. Без лимита берём 5 Мбит/с.
    busy_at = max(1.0, limit * 0.5) if limit > 0 else 5.0
    keep = max(3, int(60 / a.interval))     # усреднение примерно за минуту
    spark_keep = max(8, int(60 / a.interval))

    history, since, chan = {}, {}, []
    prev, prev_t = read_users(), time.monotonic()
    pens, pens_at = load_penalties(), 0.0
    # Суточные счётчики пишет сторож; монитор их только читает. Обновляем
    # вместе со штрафами, раз в пять секунд: доля за сутки меняется медленно.
    daily = load_daily()
    wl = whitelist_ips()
    # Ширина разделителя привязана к сумме колонок: строка длиннее его на три
    # знака отступа. Меняете колонки — меняйте и это число, тест сверит.
    width = 96

    print("\033[?25l", end="", flush=True)   # спрятать курсор
    try:
        while True:
            time.sleep(a.interval)
            cur = read_users()
            now_t = time.monotonic()
            dt = max(0.1, now_t - prev_t)
            rt = rates(prev, cur, dt)
            prev, prev_t = cur, now_t

            # Список штрафов меняется редко — перечитываем раз в пять секунд.
            if now_t - pens_at > 5:
                pens, pens_at = load_penalties(), now_t
                wl = whitelist_ips()
                daily = load_daily()

            rows = []
            for ip, (dl, ul, up_pkt) in rt.items():
                h = history.setdefault(ip, [])
                h.append(dl)
                del h[:-keep]
                if dl >= busy_at:
                    since.setdefault(ip, now_t)
                else:
                    since.pop(ip, None)
                c = cur.get(ip) or {}
                rows.append((ip, dl, ul, sum(h) / len(h),
                             now_t - since[ip] if ip in since else 0, up_pkt,
                             c.get("down", 0) + c.get("up", 0)))

            active = [r for r in rows if r[1] + r[2] > 0.05]
            active.sort(key=lambda r: r[1] + r[2], reverse=True)
            total_dl = sum(r[1] for r in rows)
            total_ul = sum(r[2] for r in rows)
            chan.append(total_dl)
            del chan[:-spark_keep]
            scale = limit if limit > 0 else max([r[1] for r in active] + [10])

            out = ["\033[H\033[2J"]
            out.append(f"\n  {C['b']}{t('mon_title')}{C['r']}"
                       f"{C['gry']}{t('mon_hint', i=a.interval):>{width - 8}}{C['r']}")
            out.append(f"  {C['gry']}{'─' * width}{C['r']}")

            line = spark(chan)
            out.append(f"   {t('mon_channel'):<16}"
                       f"{C['b']}↓ {total_dl:>6.1f}{C['r']}   ↑ {total_ul:>5.1f} Mbit/s"
                       f"   {C['cyan']}{line}{C['r']}"
                       f"{('  ' + t('mon_minute')) if line else ''}")
            if limit > 0:
                out.append(f"   {t('mon_limit_row'):<16}{C['b']}{limit:g} Mbit/s{C['r']}"
                           f"   {C['gry']}{t('mon_per_ip')}{C['r']}"
                           f"      {t('mon_loading')} {C['b']}{len(active)}{C['r']}"
                           f" {t('mon_of')} {len(rows)}")
            else:
                out.append(f"   {t('mon_limit_row'):<16}{C['yel']}{t('mon_nolimit')}{C['r']}"
                           f"          {t('mon_loading')} {C['b']}{len(active)}{C['r']}"
                           f" {t('mon_of')} {len(rows)}")
            out.append(f"  {C['gry']}{'─' * width}{C['r']}")
            out.append(f"{C['gry']}   {'IP':<21}{t('now'):>8}{t('mon_up'):>8}"
                       f"{t('mon_pkt'):>7}{t('mon_bulk'):>9}"
                       f"{t('mon_avg'):>8}{t('mon_total'):>9}"
                       f"{t('mon_hold'):>7}  {t('mon_share')}{C['r']}")

            if not active:
                out.append(f"\n   {C['gry']}{t('mon_idle')}{C['r']}")

            for ip, dl, ul, avg, hold, up_pkt, vol in active[:a.top]:
                share = dl / scale if scale > 0 else 0
                col = load_color(share)
                # Значок слева вместо колонки «держит»: в спокойный час она
                # была сплошь из прочерков и занимала девять знаков впустую.
                if ip in pens:
                    mark = f"{C['bred']}⊘{C['r']}"
                elif ip in wl:
                    # Адрес из белого списка: считаем, но не ограничиваем.
                    # Видеть его нагрузку важнее всего — именно он может
                    # незаметно съесть канал, оставаясь вне лимита.
                    mark = f"{C['cyan']}✓{C['r']}"
                elif hold >= 30:
                    mark = f"{C['byel']}▪{C['r']}"
                else:
                    mark = " "
                pct = f"{share * 100:>3.0f}%" if limit > 0 else "   "
                # Отдачу красим по своей шкале: у мобильных операторов канал
                # вверх узкий, и заметная отдача — первый признак раздачи.
                ul_col = C["gry"]
                if limit > 0 and ul >= limit * 0.15:
                    ul_col = C["bred"] if ul >= limit * 0.4 else C["byel"]
                # Время удержания вернулось отдельной колонкой: по нему
                # видно разницу между всплеском и постоянной нагрузкой,
                # а значок слева этого не показывает.
                hold_txt = fmt_hold(hold) if hold >= 1 else "—"
                hold_col = C["byel"] if hold >= 30 else C["gry"]
                # Средний размер пакета в отдаче — единственное число, по
                # которому раздача отличается от обычной закачки, и оно не
                # зависит от скорости канала. Подтверждения занимают около
                # сотни байт, данные — за тысячу; красим по порогу сторожа.
                if up_pkt < 1:
                    pkt_txt, pkt_col = "—", C["gry"]
                else:
                    pkt_txt = f"{up_pkt:.0f}"
                    pkt_col = C["byel"] if up_pkt >= PKT_DATA_HINT else C["gry"]
                # Сколько адрес прокачал всего, вниз и вверх вместе. В
                # мониторе видно только скорость, а «сейчас 0.1» у того, кто
                # за сутки вынес двадцать гигабайт, и у того, кто зашёл на
                # минуту, выглядит одинаково.
                vol_col = C["gry"]
                if vol >= 20e9:
                    vol_col = C["bred"]
                elif vol >= 5e9:
                    vol_col = C["byel"]
                # Доля отдачи данными за сутки. Рядом с мгновенным пакетом
                # намеренно: одно число про сейчас, другое про поведение, и
                # расходятся они как раз у тех, кого стоит посмотреть.
                bulk_txt, bulk_col = bulk_cell(daily.get(ip))
                out.append(f" {mark} {ip:<21}{col}{dl:>8.1f}{C['r']}"
                           f"{ul_col}{ul:>8.1f}{C['r']}"
                           f"{pkt_col}{pkt_txt:>7}{C['r']}"
                           f"{bulk_col}{bulk_txt:>9}{C['r']}"
                           f"{C['gry']}{avg:>8.1f}{C['r']}"
                           f"{vol_col}{fmt_bytes(vol):>9}{C['r']}"
                           f"{hold_col}{hold_txt:>7}{C['r']}"
                           f"  {col}{bar(dl, scale, 12)}{C['r']} {C['gry']}{pct}{C['r']}")

            out.append(f"  {C['gry']}{'─' * width}{C['r']}")
            shown = min(len(active), a.top)
            out.append(f"   {C['gry']}{t('mon_shown', a=shown, b=len(active))}"
                       f"   ▪ {t('mon_leg_hold')}   ✓ {t('mon_leg_wl')}"
                       f"   ⊘ {t('mon_leg_limited')}{C['r']}")
            out.append(f"   {C['gry']}{t('mon_leg_pkt', n=PKT_DATA_HINT)}{C['r']}")
            out.append(f"   {C['gry']}"
                       f"{t('mon_leg_bulk', n=RATIO_BULK_PERCENT)}{C['r']}")
            out.append(f"   {C['gry']}{t('mon_leg_total')}{C['r']}")
            print("\n".join(out), flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        print("\033[?25h", end="", flush=True)   # вернуть курсор
        print()


# ─────────────────────── штрафы и сторож ───────────────────────
# Сторож раз в WATCH_INTERVAL секунд смотрит скорость каждого IP. Если она
# держится выше порога дольше заданного времени — это не стриминг, а закачка,
# и адрес получает персональный лимит на время.
#
# Счётчик с допуском: замер выше порога прибавляет очко, ниже — отнимает.
# Короткие провалы (буферизация, смена сегмента) штраф не отменяют, а вот
# нормальный сёрфинг с паузами очков не накопит.

WATCH_INTERVAL = 10          # значение по умолчанию, живое берётся из конфига


def load_penalties():
    """{ip: {"until": epoch, "mbps": float}} — только живые записи."""
    try:
        with open(PEN_FILE) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
    except Exception:
        return {}
    now = time.time()
    out = {}
    for ip, p in data.items():
        # Файл могли покорёжить руками. Сторож перезапускается каждые 15 с,
        # и одна строка «until»: «завтра» иначе крутила бы его в вечном цикле.
        if not isinstance(p, dict) or valid_ip(ip) is None:
            continue
        try:
            if float(p.get("until", 0)) > now and float(p.get("mbps", 0)) > 0:
                out[ip] = p
        except (TypeError, ValueError):
            continue
    return out


def save_penalties(pens):
    tmp = PEN_FILE + ".tmp"
    os.makedirs(ETC_DIR, exist_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(pens, f, indent=2)
    os.replace(tmp, PEN_FILE)


@contextlib.contextmanager
def file_lock(path):
    """
    Блокировка на время «прочитал — изменил — записал».

    Раньше штрафы правил только сторож, и гонки быть не могло. Теперь их
    правят ещё CLI и API: без замка сторож, сохраняя свой штраф, затирал бы
    чужую запись, сделанную секунду назад, — в карте ядра она осталась бы,
    а в файле исчезла.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def penalties_update(fn):
    """
    Атомарно меняет список штрафов: fn получает словарь и правит его на месте.
    Возвращает то, что вернул fn. Единственный правильный способ записи —
    им пользуются и сторож, и CLI, и API.
    """
    with file_lock(PEN_FILE + ".lock"):
        pens = load_penalties()
        result = fn(pens)
        save_penalties(pens)
    return result


# ───────────────────────────── журнал событий ─────────────────────────────
# Одна строка JSON на событие. Пишут сторож, CLI, движок и API — читают
# оттуда же, чтобы у всех была одна версия истории. Базы данных для этого
# заводить незачем: файл с ротацией по размеру переживает и сотню нод.

EVENT_TYPES = {
    "limit_applied",     # адрес получил ограничение
    "limit_released",    # ограничение снято
    "limit_expired",     # ограничение истекло само
    "guard_triggered",   # сработало автоограничение
    "config_changed",    # изменены настройки
    "engine_started",    # движок загрузил eBPF
    "engine_stopped",    # движок выгружен
    "api_action",        # действие через API
    "sharing_found",     # панель показала раздачу подписки
    "relay_changed",     # релей CDN сменил адрес и перестал быть доверенным
    "clients_gone",      # клиенты пропали, хотя нода жива
    # Ниже — панельные события, которые не были объявлены и потому писались
    # типом "error": log_event заменяет неизвестный тип. Отличить отказ
    # отключения от настоящей ошибки было нельзя, а в shape_events_24h всё
    # это лилось в серию type="error".
    "panel_exempt",          # исключён по тегу или номеру
    "panel_under_tariff",    # адресов меньше, чем разрешает его тариф
    "panel_disabled",        # подписка отключена по отсрочке
    "panel_disable_refused", # за проход набралось больше потолка — не трогаем
    "panel_disable_failed",  # панель не приняла отключение
    "panel_user_enable",     # подписку включили обратно
    "panel_user_disable",    # подписку отключили руками
    "error",                 # ошибка
}
EVENT_MAX_BYTES = 4 * 1024 * 1024      # больше — половина уезжает в .1


def log_event(etype, ip=None, source="shape", **fields):
    """
    Добавляет событие. Никогда не бросает исключение: журнал не должен
    ронять ни сторож, ни API. Секретов здесь быть не может — в fields
    попадают только заранее известные поля вызывающего кода.
    """
    try:
        if etype not in EVENT_TYPES:
            etype = "error"
        rec = {"ts": round(time.time(), 3), "type": etype, "source": str(source)[:32]}
        if ip:
            rec["ip"] = str(ip)[:45]
        for k, v in fields.items():
            if v is None:
                continue
            rec[str(k)[:32]] = v if isinstance(v, (int, float, bool)) else str(v)[:200]

        os.makedirs(VAR_DIR, exist_ok=True)
        with file_lock(os.path.join(VAR_DIR, "events.lock")):
            seq = 0
            try:
                with open(EVENT_SEQ) as f:
                    seq = int(f.read().strip() or 0)
            except Exception:
                seq = 0
            seq += 1
            rec["id"] = seq

            if os.path.exists(EVENT_FILE) and os.path.getsize(EVENT_FILE) > EVENT_MAX_BYTES:
                os.replace(EVENT_FILE, EVENT_FILE + ".1")
            fd = os.open(EVENT_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
            with os.fdopen(fd, "a") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            tmp = EVENT_SEQ + ".tmp"
            with open(tmp, "w") as f:
                f.write(str(seq))
            os.replace(tmp, EVENT_SEQ)
        return rec["id"]
    except Exception:
        return 0


def read_events(after=0, limit=100, etype=None, ip=None, since=None, until=None):
    """
    Возвращает (список событий, есть ли ещё). Читаем с конца — свежие нужны
    чаще. Ротированный файл подхватываем, только если в свежем не хватило.
    """
    limit = max(1, min(int(limit or 100), 1000))
    out = []
    for path in (EVENT_FILE, EVENT_FILE + ".1"):
        if not os.path.exists(path):
            continue
        try:
            with open(path, errors="replace") as f:
                lines = f.readlines()
        except OSError:
            continue
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if not isinstance(rec, dict):
                continue
            if after and rec.get("id", 0) <= after:
                continue
            if etype and rec.get("type") != etype:
                continue
            if ip and rec.get("ip") != ip:
                continue
            if since and rec.get("ts", 0) < since:
                continue
            if until and rec.get("ts", 0) > until:
                continue
            out.append(rec)
            if len(out) > limit:
                return out[:limit], True
        if len(out) >= limit:
            break
    return out[:limit], False



# ─────────────────────────── владельцы адресов ───────────────────────────
# За IP-адресом стоит человек, но шейпер об этом знать не может: он работает
# на сетевом уровне. Зато об этом знает панель. Здесь лежит готовое место,
# куда эти сведения складываются, и одна функция, которой пользуются
# уведомления, журнал событий и API.
#
# Формат: {"1.2.3.4": {"label": "Александр", "user_id": "42",
#                      "telegram_id": 123456789, "updated": 1755100000}}

OWNER_FIELDS = ("label", "user_id", "telegram_id")


def load_owners():
    try:
        with open(OWNERS_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_owners(owners):
    os.makedirs(VAR_DIR, exist_ok=True)
    tmp = OWNERS_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w") as f:
        json.dump(owners, f, ensure_ascii=False, indent=1)
    os.replace(tmp, OWNERS_FILE)


def owners_update(fn):
    """Атомарная правка карты владельцев: её пишут и API, и CLI."""
    with file_lock(OWNERS_FILE + ".lock"):
        owners = load_owners()
        result = fn(owners)
        save_owners(owners)
    return result


def owner_of(ip, owners=None):
    """Сведения о владельце адреса или None. Никогда не бросает исключение."""
    try:
        rec = (owners if owners is not None else load_owners()).get(ip)
        if not isinstance(rec, dict):
            return None
        out = {k: rec[k] for k in OWNER_FIELDS if rec.get(k) not in (None, "")}
        return out or None
    except Exception:
        return None


# ──────────────────────────── история по суткам ───────────────────────────
# Суточные счётчики обнуляются в полночь, и до сих пор от них не оставалось
# ничего. Одна строка в день стоит около сотни байт — зато появляется ответ
# на вопрос «сколько мы отдали за прошлый месяц», который рано или поздно
# задаёт хостер.

def history_append(day, snapshot, limited=0):
    try:
        if not snapshot:
            return
        owners = load_owners()
        top = sorted(snapshot.items(), key=lambda kv: -kv[1].get("down", 0))[:5]
        rec = {
            "day": day,
            "down": int(sum(v.get("down", 0) for v in snapshot.values())),
            "up": int(sum(v.get("up", 0) for v in snapshot.values())),
            "ips": len(snapshot),
            "limited": int(limited),
            "top": [{"ip": ip,
                     "down": int(v.get("down", 0)),
                     "label": (owner_of(ip, owners) or {}).get("label")}
                    for ip, v in top],
        }
        os.makedirs(VAR_DIR, exist_ok=True)
        with file_lock(HISTORY_FILE + ".lock"):
            rows = read_history(limit=HISTORY_MAX_DAYS)
            rows = [r for r in rows if r.get("day") != day]
            rows.append(rec)
            rows.sort(key=lambda r: r.get("day", ""))
            rows = rows[-HISTORY_MAX_DAYS:]
            tmp = HISTORY_FILE + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
            with os.fdopen(fd, "w") as f:
                for r in rows:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
            os.replace(tmp, HISTORY_FILE)
    except Exception:
        pass


def read_history(limit=30):
    """Свежие сутки в конце списка."""
    try:
        with open(HISTORY_FILE) as f:
            rows = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict) and rec.get("day"):
                    rows.append(rec)
        return rows[-max(1, int(limit)):]
    except Exception:
        return []


def penalty_apply(ip, mbps, until_epoch):
    """Пишет штраф в BPF-карту. until пересчитывается в шкалу ядра."""
    left = max(1.0, until_epoch - time.time())
    until_ns = mono_ns() + int(left * NS)
    map_update("penalty_map", ip_key(ip),
               struct.pack(PEN_FMT, int(mbps * BYTES_PER_MBPS), until_ns))


def penalty_clear(ip):
    map_delete("penalty_map", ip_key(ip))



# ───────────────────────── персональные скорости ─────────────────────────
# Карта штрафов в ядре хранит «этому адресу такая-то скорость до такого-то
# времени» и не проверяет, ниже она общей или выше. Значит тем же механизмом
# выдаётся и постоянная персональная скорость: сотруднику с рабочей системой
# больше общего лимита, проблемному адресу — меньше. Отдельного кода в ядре
# для этого не нужно.
#
# Отличаются такие записи полем kind: "personal". Срок им ставится далёкий и
# продлевается сторожем — бессрочных записей в ядре не бывает.

PERSONAL_TTL = 30 * 24 * 3600      # на сколько вперёд ставится срок в ядре
PERSONAL_RENEW = 3600              # как часто сторож его продлевает


def is_personal(entry):
    return isinstance(entry, dict) and entry.get("kind") == "personal"


def personal_set(ip, mbps, note="", subject=None):
    """Назначить адресу постоянную скорость. Возвращает запись."""
    now = time.time()
    entry = {"until": now + PERSONAL_TTL, "mbps": float(mbps), "since": now,
             "kind": "personal", "source": "manual", "reason": note or None}
    if subject:
        entry["subject"] = subject
    penalty_apply(ip, mbps, entry["until"])
    penalties_update(lambda pens: pens.__setitem__(ip, entry))
    log_event("config_changed", ip=ip, source="manual",
              message=f"personal {mbps:g} Mbit/s")
    return entry


def personal_clear(ip):
    existing = load_penalties().get(ip)
    if not is_personal(existing):
        return None
    penalty_clear(ip)
    penalties_update(lambda pens: pens.pop(ip, None))
    log_event("config_changed", ip=ip, source="manual", message="personal off")
    return existing


def personal_list():
    return {ip: p for ip, p in load_penalties().items() if is_personal(p)}


def restore_penalties():
    """Перезаливает живые штрафы в карту — после рестарта движка."""
    pens = load_penalties()
    for ip, p in pens.items():
        try:
            penalty_apply(ip, p["mbps"], p["until"])
        except Exception:
            pass
    save_penalties(pens)
    return len(pens)


def cmd_limited(a):
    # Персональные скорости — не наказание, им место в своём списке.
    pens = {ip: p for ip, p in load_penalties().items() if not is_personal(p)}
    if a.json:
        print(json.dumps([{"ip": ip, "mbps": p["mbps"],
                           "since": p.get("since"),
                           "seconds_left": round(p["until"] - time.time()),
                           "score": p.get("score"),
                           "reasons": p.get("reasons", [])}
                          for ip, p in pens.items()], indent=2))
        return
    if not pens:
        print(f"\n  {C['gry']}{t('lim_none')}{C['r']}\n")
        return

    print(f"\n{C['gry']}  {'IP':<24}{t('lim_when'):>8}{t('lim_left'):>12}"
          f"   {t('lim_why')}{C['r']}")
    print("  " + "─" * 68)
    # свежие сверху: интереснее всего то, что произошло только что
    for ip, p in sorted(pens.items(), key=lambda x: -x[1].get("since", 0)):
        since = p.get("since")
        when = time.strftime("%H:%M", time.localtime(since)) if since else "—"
        why = ", ".join(t("why_" + r) for r in p.get("reasons") or []) or "—"
        print(f"  {C['red']}{ip:<24}{C['r']}{when:>8}"
              f"{fmt_hold(p['until'] - time.time()):>12}   {C['gry']}{why}{C['r']}")
    speeds = sorted({float(p.get("mbps", 0)) for p in pens.values()})
    speed_txt = " / ".join(f"{s:g}" for s in speeds)
    print(f"\n  {C['gry']}{t('lim_total')}: {len(pens)} · "
          f"{t('lim_speed')} {speed_txt} Mbit/s{C['r']}\n")


def release_daily_amnesty(ips):
    """
    Снятие штрафа руками освобождает от суточных признаков до полуночи.

    Без этого очистка списка не значила ничего: суточный счётчик остаётся на
    месте, и следующий проход сторожа — через десять секунд — ставит штраф
    заново. Человек, снявший ограничение, видел, что оно вернулось само, и
    решал, что программа сломана. Она работала как написана; написана была
    неверно.

    Освобождение не вечное: счётчик, выросший ещё на четверть, штраф вернёт.
    """
    ips = [ip for ip in ips if ip]
    if not ips:
        return
    daily = load_daily()
    touched = False
    for ip in ips:
        day = daily.get(ip)
        if day is None:
            continue
        daily_mark(day, DAILY_SIGNALS)
        touched = True
    if touched:
        save_daily(daily)


def cmd_release(a):
    if a.all:
        def drop_all(pens):
            for ip in list(pens):
                penalty_clear(ip)
                log_event("limit_released", ip=ip, source="cli")
            n = len(pens)
            pens.clear()
            return n
        n = penalties_update(drop_all)
        release_daily_amnesty(list(load_daily()))
        print(f"{C['grn']}✓ {t('rel_all', n=n)}{C['r']}")
        return
    uid = str(getattr(a, "user", "") or "").strip().lstrip("#")
    if uid:
        if not uid.isdigit():
            die(t("rel_bad_user"))

        freed = []

        def drop_user(pens):
            hit = [ip for ip, e in pens.items()
                   if str(e.get("user_id")
                          or (e.get("subject") or {}).get("user_id")
                          or "") == uid]
            for ip in hit:
                penalty_clear(ip)
                pens.pop(ip, None)
                log_event("limit_released", ip=ip, source="cli", user_id=uid)
                freed.append(ip)
            return len(hit)
        n = penalties_update(drop_user)
        release_daily_amnesty(freed)
        col = C["grn"] if n else C["yel"]
        print(f"{col}{'✓' if n else '·'} {t('rel_user', n=n, id=uid)}{C['r']}")
        return

    if not a.ip:
        die(t("rel_need_ip"))
    ip = valid_ip(a.ip)
    if ip is None:
        die(t("bad_ip", ip=a.ip[:60]))
    penalty_clear(ip)

    def drop_one(pens):
        pens.pop(ip, None)
        pens.pop(a.ip, None)
    penalties_update(drop_one)
    release_daily_amnesty([ip])
    log_event("limit_released", ip=ip, source="cli")
    print(f"{C['grn']}✓ {t('rel_one', ip=ip)}{C['r']}")


def cmd_guard(a):
    cfg = load_config()
    g = cfg["guard"]
    if a.enable:
        g["enabled"] = True
    if a.disable:
        g["enabled"] = False

    limits = (
        (a.score,      "score_needed",      1, 6),
        (a.both_min,   "both_ways_min",     1, 120),
        (a.both_dl,    "both_dl_percent",   10, 100),
        (a.both_ul,    "both_ul_percent",   1, 100),
        (a.percent,    "trigger_percent",   10, 100),
        (a.sustain,    "sustain_min",       1, 1440),
        (a.penalty_mbps, "penalty_mbps",    0.1, 1000),
        (a.penalty_min,  "penalty_min",     1, 10080),
        (a.hours,      "hours_per_day",     1, 24),
        (a.upload_gb,  "upload_gb_per_day", 0.1, 1000),
        (a.upload_warn, "upload_warn_gb",    0, 10000),
        (a.upload_day,  "upload_day_gb",     0, 10000),
        (a.upload_hours, "upload_hours",     0, 24),
        (a.upload_gbh,  "upload_gb_per_hour", 0, 1000),
        (a.upload_hours_mbps, "upload_hours_mbps", 0.01, 1000),
        (a.download_gb, "download_gb_per_day", 0, 10000),
        (a.download_gbh, "download_gb_per_hour", 0, 1000),
        (a.upload_ratio, "upload_ratio_percent", 0, 1000),
        (a.upload_ratio_mb, "upload_ratio_min_mb", 1, 100000),
        (a.upload_ratio_hours, "upload_ratio_min_hours", 0, 24),
        (a.volume_mbps, "volume_penalty_mbps", 0, 1000),
        (a.interval,   "watch_interval",     5, 60),
        (a.packet,     "packet_bytes",      100, 1500),
    )
    for val, key, lo, hi in limits:
        if val is not None:
            if not lo <= val <= hi:
                die(t("guard_range", k=key, lo=lo, hi=hi))
            g[key] = val

    if a.require_packet is not None:
        g["require_packet"] = a.require_packet == "on"
    if a.volume_needs_upload is not None:
        g["volume_needs_upload"] = a.volume_needs_upload == "on"
    if a.ratio_needs_packet is not None:
        g["ratio_needs_packet"] = a.ratio_needs_packet == "on"

    # Секцию telegram сюда обязательно: раньше её здесь не было, и любая
    # правка автоограничения молча стирала токен, чат, прокси и время сводки.
    cfg["guard"] = g
    save_config(cfg)
    if not a.quiet:
        _p = cfg.get("panel") or {}
        cmd_guard_show(cfg["speed_mbps"], g,
                       len(_p.get("exempt") or []) + len(_p.get("exempt_tags") or []))


def cmd_guard_show(speed, g, exempt=0):
    print()
    state = f"{C['grn']}{t('guard_on')}{C['r']}" if g["enabled"] \
        else f"{C['gry']}{t('guard_off')}{C['r']}"
    print(f"  {t('guard_state')}: {state}")
    if speed > 0:
        print(f"  {t('guard_both')}: ↓{speed * g['both_dl_percent'] / 100:g} "
              f"↑{speed * g['both_ul_percent'] / 100:g} Mbit/s "
              f"{t('guard_during')} {g['both_ways_min']} {t('min')}")
        if g.get("require_packet"):
            print(f"  {C['gry']}{t('guard_req_packet', n=g['packet_bytes'])}{C['r']}")
        print(f"  {t('guard_score')}: {g['score_needed']}")
    # Признаки в обход обязательного условия. Их не видно из строки про
    # «обе стороны», а работают они независимо — и человек, глядя на экран,
    # должен понимать, за что ещё может прилететь штраф.
    if g.get("upload_ratio_percent"):
        line = t("guard_ratio", p=g["upload_ratio_percent"],
                 mb=g.get("upload_ratio_min_mb", 300))
        print(f"  {C['gry']}{line}{C['r']}")
        print(f"  {C['gry']}{t('guard_ratio_live')}{C['r']}")
        if g.get("ratio_needs_packet"):
            print(f"  {C['gry']}"
                  f"{t('guard_ratio_pkt', n=RATIO_BULK_PERCENT)}{C['r']}")
        if g.get("upload_ratio_min_hours"):
            hrs = t("guard_ratio_hrs",
                    h=f"{g['upload_ratio_min_hours']:g}")
            print(f"  {C['gry']}{hrs}{C['r']}")
    w, dgb = g.get("upload_warn_gb", 0), g.get("upload_day_gb", 0)
    if w and dgb:
        print(f"  {C['gry']}{t('guard_upday', w=f'{w:g}', d=f'{dgb:g}')}{C['r']}")
    elif w:
        print(f"  {C['gry']}{t('guard_upwarn', w=f'{w:g}')}{C['r']}")
    elif dgb:
        print(f"  {C['gry']}{t('guard_uplim', d=f'{dgb:g}')}{C['r']}")
    if g.get("upload_gb_per_hour"):
        line = t("guard_uphourly", d=f"{g['upload_gb_per_hour']:g}")
        print(f"  {C['gry']}{line}{C['r']}")
    if g.get("upload_hours"):
        line = t("guard_uphours", h=f"{g['upload_hours']:g}")
        print(f"  {C['gry']}{line}{C['r']}")
    if g.get("download_gb_per_hour") and g.get("volume_needs_upload"):
        print(f"  {C['gry']}{t('guard_vol_needs', n=g['packet_bytes'])}{C['r']}")
    print(f"  {t('guard_penalty')}: {g['penalty_mbps']:g} Mbit/s "
          f"{t('guard_for')} {g['penalty_min']} {t('min')}")
    # Мягкая скорость меняет исход, а из строки выше её не видно. Ровно так
    # уже терялись признак отношения и действие панели.
    if g.get("volume_penalty_mbps"):
        soft = t("guard_vol_soft", mbps=f"{g['volume_penalty_mbps']:g}")
        print(f"  {C['gry']}{soft}{C['r']}")
    print(f"  {C['gry']}"
          f"{t('guard_notify_cd', h=GUARD_NOTIFY_COOLDOWN // 3600)}{C['r']}")
    # Исключения живут в разделе панели, а действуют и здесь. Настройка,
    # меняющая исход и невидимая на этом экране, — ровно тот класс ошибок,
    # который мы ловим отдельными тестами.
    if exempt:
        print(f"  {C['gry']}{t('guard_exempt_n', n=exempt)}{C['r']}")
    print()


def traffic_sample(prev, cur, dt):
    """
    Замер за интервал по каждому IP:
      dl, ul   — Мбит/с
      up_pkt   — средний размер пакета в отдаче, байт
      up_pkts  — сколько пакетов отдано за интервал
      up_bytes — сколько отдано за интервал
    """
    out = {}
    for ip, c in cur.items():
        p = prev.get(ip, {"down": 0, "up": 0, "up_pkts": 0})
        d_bytes = max(0, c["down"] - p["down"])
        u_bytes = max(0, c["up"] - p["up"])
        u_pkts = max(0, c["up_pkts"] - p["up_pkts"])
        out[ip] = {
            "dl": d_bytes * 8 / 1e6 / dt,
            "ul": u_bytes * 8 / 1e6 / dt,
            "up_pkt": (u_bytes / u_pkts) if u_pkts else 0,
            "up_pkts": u_pkts,
            "up_bytes": u_bytes,
            "dl_bytes": d_bytes,
        }
    return out


def load_daily():
    """Суточные счётчики: секунды активности и объём отдачи. Сброс в полночь."""
    try:
        with open(DAILY_FILE) as f:
            data = json.load(f)
    except Exception:
        return {}
    if data.get("day") != time.strftime("%Y-%m-%d"):
        return {}
    return data.get("ips", {})


def save_daily(ips):
    tmp = DAILY_FILE + ".tmp"
    os.makedirs(ETC_DIR, exist_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"day": time.strftime("%Y-%m-%d"), "ips": ips}, f)
    os.replace(tmp, DAILY_FILE)


HOUR_BUCKET = 300          # окно из двенадцати пятиминутных корзин


def hourly_add(hourly, ip, nbytes, now):
    """Копит скачанное за последний час корзинами по 5 минут."""
    b = int(now // HOUR_BUCKET)
    d = hourly.setdefault(ip, {})
    d[b] = d.get(b, 0) + nbytes
    for old in [k for k in d if k <= b - 12]:
        del d[old]


def daily_retrigger_ok(day, reason):
    """Можно ли наказать повторно за суточный признак."""
    field = DAILY_SIGNALS.get(reason)
    if not field:
        return True
    marks = (day or {}).get("pen")
    if not isinstance(marks, dict):
        return True
    was = marks.get(reason)
    if was is None:
        return True
    try:
        was = float(was)
    except (TypeError, ValueError):
        return True
    return (day or {}).get(field, 0) >= was * RETRIGGER_GROWTH


def daily_mark(day, reasons):
    """Запомнить суточные счётчики на момент штрафа."""
    if day is None:
        return
    marks = day.get("pen")
    if not isinstance(marks, dict):
        marks = day["pen"] = {}
    for r in reasons:
        field = DAILY_SIGNALS.get(r)
        if field:
            marks[r] = day.get(field, 0)


def up_hours_tick(s, g):
    """
    Считать ли этот замер за «отдавал» — три условия, каждое на свой класс.

    Скорость отсекает только шум. Отсекать ею подтверждения обычной закачки
    нельзя: их объём растёт вместе со скоростью скачивания, и граница,
    достаточная для быстрого канала, съедает вместе с ними тихого сидера.
    Живой случай — 1.2 ГБ за 12.7 часа ровным слоем по 0.21 Мбит/с при
    границе 0.3: признак, сделанный ровно для такого, показал «0.0 ч».

    Доля от скачивания отсекает подтверждения. У них она структурно 3-5% и
    от скорости канала не зависит; у отдачи данных выше в разы. Скачивания
    нет вовсе — условие выполнено сразу: чистая раздача так и выглядит.

    Размер пакета отсекает разговоры. Видеосвязь даёт вверх столько же,
    сколько вниз, и по доле от раздачи неотличима; отличает её пакет в 267
    байт против 1300 у куска торрента. Условие необязательное: на QUIC-нодах
    пакеты мелкие у всех, и там ratio_needs_packet выключен — часы тогда
    теряют защиту от разговоров, но остаются независимыми от протокола.
    """
    g = g or {}
    if s.get("ul", 0) < g.get("upload_hours_mbps", 0.05):
        return False
    dl = s.get("dl", 0)
    if dl > 0 and s.get("ul", 0) < dl * UPLOAD_HOURS_ACK_SHARE:
        return False
    if g.get("ratio_needs_packet") and s.get("up_pkt", 0) < RATIO_PACKET_BYTES:
        return False
    return True


def day_upkt(day):
    """
    Поле с пакетами: (байты, пакеты, максимум, данными, начало). Иначе None.

    Пять чисел живут ОДНИМ полем и начинаются вместе. Половину такого поля
    получить нельзя — а два поля можно, и мы это уже проходили дважды.
    """
    upkt = (day or {}).get("upkt")
    if not (isinstance(upkt, list) and len(upkt) == 5):
        return None
    try:
        b, n, top, bulk, since = (float(x or 0) for x in upkt)
    except (TypeError, ValueError):
        return None
    if b < 0 or n < 0 or bulk < 0:
        return None
    return b, n, top, bulk, since


def day_upkt_max(day):
    """Самый крупный средний пакет вверх за окно. Нет данных — ноль."""
    parsed = day_upkt(day)
    return parsed[2] if parsed else 0.0


def bulk_share(day):
    """Доля отдачи, ушедшей крупными пакетами, 0..100. Нет данных — ноль."""
    parsed = day_upkt(day)
    if not parsed or not parsed[0]:
        return 0.0
    return min(100.0, parsed[3] * 100.0 / parsed[0])


def bulk_cell(day):
    """
    Колонка «данными» в мониторе: (текст, цвет).

    Мгновенный размер пакета отвечает на вопрос «что идёт вверх прямо сейчас»
    и скачет от окна к окну: человек отправил вложение — и в колонке «пакет»
    на десять секунд тысяча с лишним. Доля за сутки скачков не знает, и по ней
    видно поведение, а не момент.

    Нет отдачи вовсе — прочерк, а не ноль: ноль означал бы «отдавал, но
    подтверждениями», а это другое утверждение.
    """
    parsed = day_upkt(day)
    if not parsed or not parsed[0]:
        return "—", C["gry"]
    share = min(100.0, parsed[3] * 100.0 / parsed[0])
    if share >= BULK_LOUD_PERCENT:
        col = C["bred"]
    elif share >= RATIO_BULK_PERCENT:
        col = C["byel"]
    else:
        col = C["gry"]
    return f"{share:.0f}%", col


def evaluate(ip, s, g, cap, both_streak, peak_streak, daily, hourly=None,
             hourly_up=None):
    """
    Решает, нарушитель ли это. Возвращает (баллы, сработавшие признаки).

    Обязательное условие — трафик в обе стороны одновременно. Без него ноль
    баллов, каким бы тяжёлым трафик ни был: так из-под удара выходят стриминг
    (молчит вверх) и облачный бэкап (молчит вниз).
    """
    day = daily.get(ip, {"active": 0, "up": 0, "down": 0})

    # Независимый путь: качает десятками гигабайт в сутки. Отдача не важна —
    # торрент с выключенной раздачей выглядит как обычная тяжёлая закачка,
    # и единственное, что его выдаёт, это объём.
    gb = g.get("download_gb_per_day", 0)
    if gb and day.get("down", 0) >= gb * 1e9 \
            and daily_retrigger_ok(day, "download"):
        return max(g["score_needed"], SIGNAL_WEIGHTS["download"]), ["download"]

    # Отдача за скользящий час. Зеркало часового порога на скачивание.
    up_gbh = g.get("upload_gb_per_hour", 0)
    if up_gbh and hourly_up and sum(hourly_up.get(ip, {}).values()) \
            >= up_gbh * 1e9:
        return (max(g["score_needed"], SIGNAL_WEIGHTS["up_hourly"]),
                ["up_hourly"])

    # То же самое, но по скользящему часу: реагирует за час вместо суток.
    #
    # С volume_needs_upload часовой объём перестаёт быть самостоятельным
    # поводом и требует крупных пакетов вверх. Иначе он бьёт по закачке из
    # Steam: порог в половину канала срабатывает через полчаса на полной
    # скорости, а игра весит столько, что качается часами.
    gbh = g.get("download_gb_per_hour", 0)
    if gbh and hourly and sum(hourly.get(ip, {}).values()) >= gbh * 1e9:
        if not g.get("volume_needs_upload"):
            return max(g["score_needed"], SIGNAL_WEIGHTS["hourly"]), ["hourly"]
        if s["up_pkt"] >= g["packet_bytes"] and s["ul"] >= 0.3:
            return (max(g["score_needed"],
                        SIGNAL_WEIGHTS["hourly"] + SIGNAL_WEIGHTS["packet"]),
                    ["hourly", "packet"])

    # Отдельный путь: за сутки отдано столько-то гигабайт. Без условий про
    # пропорцию, размер пакета и текущую активность — важен только объём.
    up_gb = g.get("upload_day_gb", 0)
    if up_gb and day.get("up", 0) >= up_gb * 1e9 \
            and daily_retrigger_ok(day, "upload_day"):
        return (max(g["score_needed"], SIGNAL_WEIGHTS["upload_day"]),
                ["upload_day"])

    # Четвёртый независимый путь: за сутки отдал непропорционально много.
    #
    # Считается от скачанного, а не в абсолюте, потому что тихого сидера
    # выдаёт именно перекос: 916 МБ вверх против 379 МБ вниз. В абсолютных
    # гигабайтах это мелочь, а по отношению — 242% там, где у обычного
    # клиента 5-15%.
    #
    # Условие «отдаёт прямо сейчас» обязательно: см. RATIO_LIVE_MBPS.
    # Условие по длительности необязательное, но именно оно отделяет раздачу
    # от отправленного в чат видео: пропорция у них одинаковая, время — нет.
    ratio = g.get("upload_ratio_percent", 0)
    floor_bytes = float(g.get("upload_ratio_min_mb", 300)) * 1e6
    min_hours = float(g.get("upload_ratio_min_hours", 0) or 0)
    if ratio and day.get("up", 0) >= floor_bytes \
            and daily_retrigger_ok(day, "ratio") \
            and s["ul"] >= RATIO_LIVE_MBPS \
            and day.get("up_sec", 0) >= min_hours * 3600 \
            and (not g.get("ratio_needs_packet")
                 or bulk_share(day) >= RATIO_BULK_PERCENT):
        # Нулевое скачивание при заметной отдаче — это тем более перекос,
        # делить на ноль ради такого вывода незачем.
        down = day.get("down", 0)
        if not down or day["up"] * 100 >= down * ratio:
            return max(g["score_needed"], SIGNAL_WEIGHTS["ratio"]), ["ratio"]

    iv = g.get("watch_interval", WATCH_INTERVAL)
    if both_streak < max(1, int(g["both_ways_min"] * 60 / iv)):
        return 0, []

    reasons = []

    # Крупные пакеты вверх = клиент отдаёт данные, а не подтверждения.
    # Нижний порог по отдаче нужен, чтобы редкие пакеты не давали случайных
    # средних. Признак не зависит от скорости канала — это его главная ценность.
    if s["up_pkt"] >= g["packet_bytes"] and s["ul"] >= 0.3:
        reasons.append("packet")
    if peak_streak >= max(1, int(g["sustain_min"] * 60 / iv)):
        reasons.append("peak")
    if day["active"] >= g["hours_per_day"] * 3600:
        reasons.append("hours")
    if day["up"] >= g["upload_gb_per_day"] * 1e9:
        reasons.append("upload")

    return sum(SIGNAL_WEIGHTS[r] for r in reasons), reasons


NOTIFY_MAX = 4096

# Состояние сторожа, которое обязано пережить перезапуск.
#
# Обе карты жили в памяти, и это было сознательным решением: «перезапуск стоит
# одного лишнего сообщения, а файл на диске — своего кода и своих поломок».
# Решение оказалось неверным. Владелец ноды обновляется по нескольку раз за
# вечер, и при такой частоте кулдаун не работал вовсе.
GUARD_STATE = os.path.join(VAR_DIR, "guard.state")

# Сколько помним, кто стоял за адресом.
#
# Панель знает человека, только пока он на ноде. Через шестнадцать минут после
# опознания карточка про того же нарушителя приходила уже безымянной — хотя
# ответ был получен и выброшен. Двенадцати часов хватает на сутки работы и
# мало для того, чтобы за адресом успел оказаться другой человек; на всякий
# случай в сообщении честно пишется, когда именно его видели.
OWNER_CACHE_TTL = 12 * 3600
OWNER_CACHE_MAX = 2048


def guard_state():
    try:
        with open(GUARD_STATE) as f:
            st = json.load(f)
        return st if isinstance(st, dict) else {}
    except Exception:
        return {}


def guard_state_save(state):
    try:
        os.makedirs(VAR_DIR, exist_ok=True)
        tmp = GUARD_STATE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
        os.replace(tmp, GUARD_STATE)
    except OSError:
        pass


def owner_remember(cache, ip, who, now=None):
    """Запомнить владельца адреса: панель знает его только пока он на ноде."""
    if not isinstance(who, dict) or not who:
        return
    now = now if now is not None else time.time()
    cache[ip] = [now, who]
    if len(cache) <= OWNER_CACHE_MAX:
        return
    # Сначала выбрасываем протухшее. Если и после этого карта велика — самое
    # старое: иначе на ноде с тысячами адресов она росла бы без предела,
    # потому что чистка по сроку такую карту не уменьшает.
    cut = now - OWNER_CACHE_TTL
    for k in [i for i, v in cache.items()
              if not (isinstance(v, list) and len(v) == 2)
              or float(v[0] or 0) < cut]:
        cache.pop(k, None)
    if len(cache) > OWNER_CACHE_MAX:
        for k, _ in sorted(cache.items(), key=lambda kv: float(kv[1][0] or 0)
                           )[:len(cache) - OWNER_CACHE_MAX]:
            cache.pop(k, None)


def owner_recall(cache, ip, now=None):
    """Последний известный владелец: (кто, когда). Не помним — (None, 0)."""
    rec = cache.get(ip)
    if not (isinstance(rec, list) and len(rec) == 2):
        return None, 0.0
    try:
        at, who = float(rec[0] or 0), rec[1]
    except (TypeError, ValueError):
        return None, 0.0
    now = now if now is not None else time.time()
    if not isinstance(who, dict) or not who or now - at > OWNER_CACHE_TTL:
        return None, 0.0
    return who, at


def notify_due(notified, ip, reasons, now=None):
    """
    Пора ли рассказывать про этот адрес. Побочно отмечает, что рассказали.

    Штраф снимается через час, суточные счётчики за этот час не меняются — и
    признак срабатывает снова, и так до полуночи. Ограничение при этом
    выдаётся каждый раз, как и раньше: молчит только Telegram.

    Причина входит в ключ намеренно. Тот же адрес, попавшийся уже за другое,
    — это новость, и её надо рассказать сразу.
    """
    now = now if now is not None else time.time()
    key = ",".join(sorted(reasons))
    seen_at, seen_key = notified.get(ip, (0.0, ""))
    if key == seen_key and now - seen_at < GUARD_NOTIFY_COOLDOWN:
        return False
    notified[ip] = (now, key)
    # Чистим по возрасту, а не по «адрес пропал из карты ядра»: смысл записи
    # ровно в том, что адрес из этой карты не пропадает.
    if len(notified) > NOTIFY_MAX:
        cut = now - GUARD_NOTIFY_COOLDOWN
        for k in [i for i, (ts, _) in notified.items() if ts < cut]:
            notified.pop(k, None)
    return True


def guard_exempt(cfg, who):
    """
    Деловой аккаунт: автоограничение его не трогает.

    Список тот же, что у поиска раздачи, — `panel set --exempt`. Он и там, и
    здесь означает одно: «про этого человека мы знаем, что он такой».

    Зачем это нужно. Бюро адвокатов или агентство недвижимости выглядят
    нарушителями по обеим проверкам сразу. По раздаче — потому что двадцать
    сотрудников на одной подписке это двадцать адресов у одного пользователя.
    По отношению отдачи — потому что выгрузка видео объектов на сетевом уровне
    неотличима от раздачи торрента: та же пропорция, те же набитые доверху
    пакеты, та же доля данных. Разделить их порогом нельзя в принципе,
    разделяет только знание о том, кто это.

    Без панели не работает: узнать, чей это адрес, больше неоткуда.
    """
    p = cfg.get("panel") or {}
    who = who or {}
    tag = str(who.get("tag") or "").strip().upper()
    if tag and tag in {str(x).strip().upper()
                       for x in (p.get("exempt_tags") or [])}:
        return True
    uid = str(who.get("user_id") or "").strip()
    if not uid:
        return False
    return uid in {str(x).strip() for x in (p.get("exempt") or [])}


VOLUME_ONLY = {"download", "hourly"}


def penalty_rate(g, reasons):
    """
    Скорость штрафа: за один объём — мягкая, за торрент — заданная.

    Объём срабатывает и на честном поведении: человек купил игру и качает её
    на полной скорости. Отличить это от торрента по одному объёму нельзя, а
    значит и наказывать одинаково нельзя.
    """
    soft = float(g.get("volume_penalty_mbps") or 0)
    if soft and reasons and set(reasons) <= VOLUME_ONLY:
        return soft
    return g["penalty_mbps"]


def cmd_watch(a):
    """Демон: следит за нагрузкой и выдаёт штрафы. Запускается сервисом."""
    require_engine()
    print(t("watch_start"), flush=True)
    restore_penalties()

    both_streak, peak_streak, hourly, hourly_up = {}, {}, {}, {}
    # Когда в последний раз рассказывали про адрес, и кто за адресом стоял.
    # Обе карты переживают перезапуск: обновление посреди вечера не должно ни
    # сбрасывать кулдаун, ни терять уже полученное от панели имя.
    _gs = guard_state()
    notified = {k: (float(v[0]), str(v[1]))
                for k, v in (_gs.get("notified") or {}).items()
                if isinstance(v, list) and len(v) == 2}
    owners_seen = {k: v for k, v in (_gs.get("owners") or {}).items()
                   if isinstance(v, list) and len(v) == 2}
    # Кому уже сообщали про объём отдачи и в какой день. Хранится дата, а не
    # флаг: тогда сутки закрываются сами, без отдельной чистки в полночь.
    noticed = {k: str(v) for k, v in (_gs.get("noticed") or {}).items()
               if isinstance(v, str)}
    upd = _gs.get("update") if isinstance(_gs.get("update"), dict) else {}
    daily = load_daily()
    today = time.strftime("%Y-%m-%d")
    prev, prev_t = read_users(), time.monotonic()
    last_daily_save = time.time()
    last_personal_renew = 0.0
    interval = load_config()["guard"].get("watch_interval", WATCH_INTERVAL)

    while True:
        time.sleep(interval)
        try:
            cfg = load_config()
            g = cfg["guard"]
            interval = g.get("watch_interval", WATCH_INTERVAL)
            cap = cfg["speed_mbps"]

            # Сутки закрылись: откладываем срез и обнуляем счётчики.
            day_now = time.strftime("%Y-%m-%d")
            if day_now != today:
                digest_stash(today, daily)
                # Та же точка — единственная, где сутки видны целиком.
                history_append(today, daily,
                               limited=len([p for p in load_penalties().values()
                                            if not is_personal(p)]))
                daily = {}
                save_daily(daily)
                today = day_now
            digest_due(cfg)
            backup_due(cfg)
            # Раз в шесть часов, и только если что-то изменилось: сохраняем
            # состояние проверки обновлений тем же файлом, что и остальное.
            if update_due(cfg, upd):
                guard_state_save({"notified": {k: list(v) for k, v
                                               in notified.items()},
                                  "owners": owners_seen, "noticed": noticed,
                                  "update": upd})
            # Опрос панели. Сторож она не роняет — внутри свой дедлайн и
            # своя пауза после ошибки. Но проход растягивает: POST плюс опрос
            # задачи до PANEL_JOB_DEADLINE, причём дедлайн проверяется ПОСЛЕ
            # запроса, так что последний GET выходит за него почти на полный
            # таймаут. Худший случай около 40 с против watch_interval в 10 —
            # то есть три-четыре пропущенных прохода, и только в том проходе
            # из panel.interval, где опрос вообще идёт. На пороги сторожа это
            # не влияет: они измеряются минутами, а не проходами.
            panel_due(cfg)
            panel_report_due(cfg)
            # Смена релея CDN. Наружу не ходит, ошибок не выпускает, стоит
            # ноль запросов: сверяет свои же счётчики раз в пять минут.
            try:
                relay_watch(cfg)
            except Exception:
                pass
            # Обвал клиентов при живой ноде. Спрашивает провайдера CDN, если
            # раздел включён, и кладёт вердикт в то же сообщение.
            try:
                clients_watch(cfg)
            except Exception:
                pass

            # Персональные скорости живут в ядре с далёким, но конечным
            # сроком. Продлеваем раз в час, чтобы они не истекли молча.
            if time.time() - last_personal_renew > PERSONAL_RENEW:
                last_personal_renew = time.time()
                for pip, pentry in personal_list().items():
                    try:
                        penalty_apply(pip, pentry["mbps"],
                                      time.time() + PERSONAL_TTL)
                    except Exception:
                        pass

            cur = read_users()
            now_t = time.monotonic()
            dt = max(1.0, now_t - prev_t)
            sample = traffic_sample(prev, cur, dt)
            prev, prev_t = cur, now_t

            # забываем тех, кто отвалился
            for d in (both_streak, peak_streak, hourly, hourly_up):
                for ip in [i for i in d if i not in cur]:
                    d.pop(ip, None)

            # снимаем истёкшие штрафы из карты ядра
            pens = load_penalties()
            in_map = {ip for ip, _ in
                      [(parse_ip_key(k)[0], v) for k, v in map_dump("penalty_map")]}
            for ip in in_map - set(pens):
                penalty_clear(ip)
                log_event("limit_expired", ip=ip, source="watchdog")

            # Автоограничение выключено — штрафов не выдаём, но счёт трафика
            # продолжаем: на нём держится суточная сводка в Telegram, и раньше
            # при выключенном стороже она приходила пустой.
            guard_on = bool(g["enabled"]) and cap > 0
            if not guard_on:
                both_streak.clear()
                peak_streak.clear()

            dl_floor = cap * g["both_dl_percent"] / 100
            ul_floor = cap * g["both_ul_percent"] / 100
            peak_floor = cap * g["trigger_percent"] / 100
            active_floor = cap * 0.25 if cap > 0 else 1.0
            need_score = g["score_needed"]
            wl = whitelist_ips()

            for ip, s in sample.items():
                # суточные счётчики ведём для всех, даже для уже наказанных
                d = daily.setdefault(ip, {"active": 0, "up": 0, "down": 0})
                d.setdefault("down", 0)
                d.setdefault("up_sec", 0)
                # Средний размер пакета за сутки — то самое, что отличает
                # отдачу данных от подтверждений. Мгновенный сюда не годится:
                # в момент штрафа адрес мог как раз молчать вверх.
                # Байты и пакеты для среднего размера — ОДНО поле из двух
                # чисел, а не два поля. Два поля можно получить наполовину:
                # запись от прошлой версии, где было только одно из них, и
                # деление даёт бессмыслицу. Одного поля либо нет целиком,
                # либо оно есть целиком.
                upkt = d.get("upkt")
                if not (isinstance(upkt, list) and len(upkt) == 5):
                    upkt = d["upkt"] = [0, 0, 0, 0, time.time()]
                # Прибавляем ФАКТИЧЕСКОЕ время прохода, а не заданный период.
                # Они расходятся всякий раз, когда цикл затянулся: опрос
                # панели, отправка сводки, загруженный процессор. Раньше здесь
                # стоял interval, и часы активности занижались ровно тогда,
                # когда нода нагружена, — то есть когда признак нужнее всего.
                if max(s["dl"], s["ul"]) >= active_floor:
                    d["active"] += dt
                # Секунды, в которые адрес действительно отдавал данные.
                if up_hours_tick(s, g):
                    d["up_sec"] = d.get("up_sec", 0) + dt
                d["up"] += s["up_bytes"]
                d["down"] += s["dl_bytes"]
                upkt[0] += s["up_bytes"]
                upkt[1] += s["up_pkts"]
                if s["up_bytes"] >= UPKT_MAX_FLOOR:
                    upkt[2] = max(upkt[2], int(s["up_pkt"]))
                # Байты, ушедшие крупными пакетами. Пола по объёму здесь нет
                # намеренно: маленькое окно с крупными пакетами — это тоже
                # данные, просто их мало, и доля это учтёт сама.
                if s["up_pkt"] >= RATIO_PACKET_BYTES:
                    upkt[3] += s["up_bytes"]
                if s["dl_bytes"]:
                    hourly_add(hourly, ip, s["dl_bytes"], time.time())
                if s["up_bytes"]:
                    hourly_add(hourly_up, ip, s["up_bytes"], time.time())

                # Адрес с персональной скоростью автоограничению не подлежит:
                # решение по нему уже принято человеком.
                if not guard_on or ip in pens or ip in wl:
                    continue

                # Уровень уведомления по объёму отдачи. Один раз в сутки на
                # адрес: смысл в том, чтобы заметить подходящего к границе, а
                # не напоминать о нём каждые десять секунд.
                # Два уведомления без штрафа: по объёму и по длительности.
                # Ключ у каждого свой, чтобы одно не глушило другое.
                warn_gb = g.get("upload_warn_gb", 0)
                warn_h = g.get("upload_hours", 0)
                due_gb = bool(warn_gb) and d["up"] >= warn_gb * 1e9 \
                    and noticed.get(ip) != today
                due_h = bool(warn_h) and d.get("up_sec", 0) >= warn_h * 3600 \
                    and noticed.get("h:" + ip) != today
                if due_gb or due_h:
                    if due_gb:
                        noticed[ip] = today
                    if due_h:
                        noticed["h:" + ip] = today
                    nwho = owner_of(ip) or panel_owner(cfg, ip)
                    nunknown = None
                    nsubject = None
                    if nwho:
                        owner_remember(owners_seen, ip, nwho)
                        nsubject = nwho
                    else:
                        nold, nat = owner_recall(owners_seen, ip)
                        if nold:
                            nwho, nsubject = nold, dict(nold, seen_at=nat)
                        else:
                            nunknown = panel_owner_reason(cfg, ip)
                    if not guard_exempt(cfg, nwho):
                        if due_gb:
                            log_event("guard_upload_notice", ip=ip,
                                      source="watchdog", up=int(d["up"]),
                                      subject=(nwho or {}).get("label"))
                            tg_upload_notice(cfg, ip, subject=nsubject,
                                             unknown=nunknown, day=d)
                        if due_h:
                            log_event("guard_hours_notice", ip=ip,
                                      source="watchdog",
                                      hours=round(d.get("up_sec", 0) / 3600, 1),
                                      subject=(nwho or {}).get("label"))
                            tg_upload_hours(cfg, ip, subject=nsubject,
                                            unknown=nunknown, day=d)
                    guard_state_save({"notified": {k: list(v) for k, v
                                                   in notified.items()},
                                      "owners": owners_seen,
                                      "noticed": noticed, "update": upd})

                # счётчики с допуском: короткий провал не обнуляет наблюдение
                both = s["dl"] >= dl_floor and s["ul"] >= ul_floor
                # Крупные пакеты вверх как часть обязательного условия, а не
                # как балл: иначе низкий порог отдачи ловил бы подтверждения
                # обычной закачки, которых тем больше, чем быстрее качают.
                if g.get("require_packet") and s["up_pkt"] < g["packet_bytes"]:
                    both = False
                both_streak[ip] = (both_streak.get(ip, 0) + 1) if both \
                    else max(0, both_streak.get(ip, 0) - 1)
                peak = s["dl"] >= peak_floor
                peak_streak[ip] = (peak_streak.get(ip, 0) + 1) if peak \
                    else max(0, peak_streak.get(ip, 0) - 1)

                score, reasons = evaluate(ip, s, g, cap, both_streak[ip],
                                          peak_streak[ip], daily, hourly,
                                          hourly_up)
                if score >= need_score:
                    # Владельца выясняем ДО штрафа, а не после: деловой
                    # аккаунт трогать нельзя вообще, а не «ограничить и потом
                    # подписать именем».
                    #
                    # Сначала свой список владельцев — он заполняется руками и
                    # потому точнее. Не нашлось — спрашиваем панель: она знает
                    # всех, но только пока адрес активен.
                    subject, unknown = None, None
                    who = owner_of(ip) or panel_owner(cfg, ip)
                    if who:
                        owner_remember(owners_seen, ip, who)
                        subject = who
                    else:
                        # Панель знает человека, только пока он на ноде. Тот
                        # же нарушитель через двадцать минут приходил уже
                        # безымянным, хотя ответ был получен и выброшен.
                        old, at = owner_recall(owners_seen, ip)
                        if old:
                            who, subject = old, dict(old, seen_at=at)
                        else:
                            unknown = panel_owner_reason(cfg, ip)

                    # Исключения панели действуют и здесь. Офис на одной
                    # подписке — это не нарушитель: агентство, заливающее
                    # видео объектов, по сети неотличимо от раздачи, и
                    # разделить их порогом нельзя в принципе. Разделяет
                    # только знание о том, кто это.
                    if guard_exempt(cfg, who):
                        log_event("guard_exempt", ip=ip, source="watchdog",
                                  reason=",".join(reasons),
                                  user_id=str((who or {}).get("user_id") or ""),
                                  subject=(who or {}).get("label"))
                        continue

                    until = time.time() + g["penalty_min"] * 60
                    mbps = penalty_rate(g, reasons)
                    penalty_apply(ip, mbps, until)
                    entry = {"until": until, "mbps": mbps,
                             "since": time.time(), "source": "watchdog",
                             "kind": "auto", "reason": ",".join(reasons),
                             "score": score, "reasons": reasons}
                    if subject:
                        entry["subject"] = subject
                    # Под замком: файл теперь правит ещё и API.
                    penalties_update(lambda p, i=ip, e=entry: p.__setitem__(i, e))
                    pens[ip] = entry
                    log_event("guard_triggered", ip=ip, source="watchdog",
                              mbps=mbps, minutes=g["penalty_min"],
                              score=score, reason=",".join(reasons),
                              subject=(entry.get("subject") or {}).get("label"),
                              telegram_id=(entry.get("subject") or {}).get("telegram_id"))
                    both_streak[ip] = peak_streak[ip] = 0
                    # Окно очищаем: иначе после снятия штрафа те же гигабайты
                    # в скользящем часе тут же уронили бы человека повторно.
                    hourly.pop(ip, None)
                    hourly_up.pop(ip, None)
                    # Суточные счётчики очистить нельзя — они и есть признак.
                    # Вместо этого запоминаем, на чём человека поймали: пока
                    # счётчик не вырастет, второй раз за то же не наказываем.
                    daily_mark(d, reasons)
                    save_daily(daily)
                    print(t("watch_hit", ip=ip, mbps=mbps,
                            m=g["penalty_min"]) +
                          f" [{score}: {','.join(reasons)}]", flush=True)
                    # Ограничение выдаётся каждый раз, а рассказываем о нём
                    # не чаще раза в шесть часов.
                    guard_state_save({"notified": {k: list(v) for k, v
                                                   in notified.items()},
                                      "owners": owners_seen,
                                      "noticed": noticed, "update": upd})
                    if notify_due(notified, ip, reasons):
                        tg_penalty(cfg, ip, mbps, g["penalty_min"],
                                   reasons, subject=entry.get("subject"),
                                   unknown=unknown, day=daily.get(ip))

            if time.time() - last_daily_save > 60:
                # чистим тех, кто за сутки не набрал ничего заметного
                daily = {k: v for k, v in daily.items()
                         if v["active"] > 0 or v["up"] > 1e6 or v.get("down", 0) > 1e6}
                save_daily(daily)
                last_daily_save = time.time()
        except SystemExit as e:
            # die() внутри penalty_apply -> map_update поднимает SystemExit, а
            # он не наследует Exception и мимо обработчика ниже проходил
            # насквозь. Переполненная penalty_map или сбой bpftool убивали
            # демон целиком, а Restart=always превращал это в перезапуск раз в
            # пятнадцать секунд: автоограничение не работало, но сервис
            # выглядел то активным, то поднимающимся.
            print(f"watch: прервана операция с ядром ({e}), продолжаю",
                  flush=True)
        except Exception as e:
            print(f"watch: {e}", flush=True)


def whitelist_ips():
    out = set()
    try:
        for line in open(WL_FILE):
            s = line.split("#")[0].strip()
            if s:
                out.add(s)
    except Exception:
        pass
    return out


# ──────────────────────── доверенные источники ────────────────────────
# Адреса, чьей обёртке разрешено верить. Их всего два вида, и оба про одно:
# настоящий адрес клиента спрятан, и достать его можно только из данных,
# которые пишет отправитель.
#
#   tunnel — второй конец IPIP-туннеля. Хостер отдаёт ноде белый адрес
#            через туннель, клиенты лежат внутри обёртки.
#   relay  — релей CDN. Клиент к ноде не подключается вовсе, его адрес
#            приходит в заголовке PROXY protocol.
#
# Почему это список, а не выключатель. Заголовок пишет отправитель. Пока
# верим всем подряд, любой, кто открыл соединение на шейпируемый порт,
# сам выбирает, на чей адрес записать трафик: свой лимит обойдёт, чужой
# адрес отправит в блок. Пустой список — обе развёртки не работают вовсе.
#
# Формат файла: «адрес вид[,вид]», решётка — комментарий.
#   198.51.100.7   tunnel
#   198.51.100.20  relay      # фронт, который ходит к нам с PROXY

TRUST_TUNNEL = 0x01
TRUST_RELAY  = 0x02
TRUST_KINDS  = {"tunnel": TRUST_TUNNEL, "relay": TRUST_RELAY}


def trusted_sources():
    """{адрес: флаги}. Битые строки молча пропускаются — их покажет sync."""
    out = {}
    try:
        for line in open(TRUST_FILE):
            s = line.split("#")[0].strip()
            if not s:
                continue
            parts = s.split()
            if len(parts) != 2:
                continue
            ip = valid_ip(parts[0])
            if ip is None:
                continue
            flags = 0
            for kind in parts[1].split(","):
                flags |= TRUST_KINDS.get(kind.strip(), 0)
            if flags:
                out[ip] = out.get(ip, 0) | flags
    except Exception:
        pass
    return out


def _write_trusted(entries):
    lines = ["# Доверенные источники Shape. Строка: «адрес вид[,вид]».\n",
             "# tunnel — конец IPIP-туннеля, relay — релей CDN с PROXY protocol.\n"]
    for ip in sorted(entries):
        kinds = [k for k, bit in TRUST_KINDS.items() if entries[ip] & bit]
        lines.append(f"{ip} {','.join(sorted(kinds))}\n")
    with open(TRUST_FILE, "w") as f:
        f.writelines(lines)


# ─────────────────────── отправка в Telegram ───────────────────────
# Только stdlib. SOCKS5 реализован здесь же: на российских нодах
# api.telegram.org режется по SNI, и без прокси сообщения не уходят.

def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("прокси закрыл соединение")
        buf += chunk
    return buf


def _socks5(sock, host, port, user=None, pwd=None):
    """Минимальный SOCKS5 CONNECT. Имя хоста резолвит прокси, не мы."""
    sock.sendall(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
    ver, method = _recvn(sock, 2)
    if ver != 5:
        raise OSError("это не SOCKS5-прокси")
    if method == 0x02:
        u, p = user.encode(), (pwd or "").encode()
        sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        if _recvn(sock, 2)[1] != 0:
            raise OSError("SOCKS5: неверный логин или пароль")
    elif method != 0x00:
        raise OSError("SOCKS5: прокси требует неподдерживаемую авторизацию")
    h = host.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + port.to_bytes(2, "big"))
    rep = _recvn(sock, 4)
    if rep[1] != 0:
        codes = {2: "запрещено правилами", 3: "сеть недоступна",
                 4: "хост недоступен", 5: "соединение отклонено"}
        raise OSError(f"SOCKS5: {codes.get(rep[1], f'код {rep[1]}')}")
    atyp = rep[3]
    _recvn(sock, (4 if atyp == 1 else 16 if atyp == 4 else _recvn(sock, 1)[0]) + 2)


def _get(url, proxy="", timeout=15):
    """GET с теми же правилами прокси, что и у отправки в Telegram."""
    u = urllib.parse.urlsplit(url)
    if proxy.startswith(("socks5://", "socks5h://")):
        p = urllib.parse.urlsplit(proxy)
        sock = socket.create_connection((p.hostname, p.port or 1080),
                                        timeout=timeout)
        try:
            _socks5(sock, u.hostname, 443, p.username, p.password)
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(u.hostname, 443,
                                               timeout=timeout, context=ctx)
            conn.sock = ctx.wrap_socket(sock, server_hostname=u.hostname)
            conn.request("GET", u.path, headers={"Host": u.hostname})
            r = conn.getresponse()
            body = r.read()
            if r.status != 200:
                raise OSError(f"HTTP {r.status}")
            return body.decode("utf-8", "replace")
        finally:
            try:
                sock.close()
            except Exception:
                pass

    opener = urllib.request.build_opener(urllib.request.ProxyHandler(
        {"http": proxy, "https": proxy} if proxy else {}))
    with opener.open(urllib.request.Request(url), timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _post(url, data, proxy="", content_type="application/x-www-form-urlencoded",
          headers=None):
    u = urllib.parse.urlsplit(url)
    if proxy.startswith(("socks5://", "socks5h://")):
        p = urllib.parse.urlsplit(proxy)
        sock = socket.create_connection((p.hostname, p.port or 1080), timeout=15)
        try:
            _socks5(sock, u.hostname, 443, p.username, p.password)
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(u.hostname, 443, timeout=15, context=ctx)
            conn.sock = ctx.wrap_socket(sock, server_hostname=u.hostname)
            head = {"Host": u.hostname, "Content-Type": content_type,
                    "Content-Length": str(len(data))}
            head.update(headers or {})
            conn.request("POST", u.path, body=data, headers=head)
            r = conn.getresponse()
            body = r.read()
            if r.status != 200:
                raise urllib.error.HTTPError(url, r.status, r.reason, r.headers,
                                             io.BytesIO(body))
            return r.status
        finally:
            try:
                sock.close()
            except Exception:
                pass

    head = {"Content-Type": content_type}
    head.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=head)
    # Открыватель строим всегда, даже без прокси. Раньше в этой ветке стоял
    # сам модуль urllib.request: у него есть urlopen, но нет open, и отправка
    # без прокси падала на AttributeError. На российских нодах прокси задан
    # всегда, поэтому ветка не выполнялась и ошибка не всплывала до первой
    # ноды, которой прокси не нужен.
    #
    # Пустой ProxyHandler отключает подхват http_proxy из окружения: прокси у
    # Shape свой, в настройках, и брать его откуда-то ещё он не должен.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(
        {"http": proxy, "https": proxy} if proxy else {}))
    with opener.open(req, timeout=15) as r:
        return r.status


# Проверка обновлений. Тянем один маленький файл, а не клонируем репозиторий:
# клон в фоновом сторожа — это десятки мегабайт и минуты на медленной ноде.
#
# Веток две намеренно: у публичного репозитория основная может называться
# и main, и master, а гадать в коде, который работает на чужих нодах, нельзя.
UPDATE_URLS = (
    "https://raw.githubusercontent.com/SkunkBG/shape/main/VERSION",
    "https://raw.githubusercontent.com/SkunkBG/shape/master/VERSION",
)
UPDATE_INTERVAL = 6 * 3600
VERSION_RE = re.compile(r"^\d+(\.\d+){0,3}$")


def version_tuple(v):
    """«3.48» → (3, 48). Не разобралось — пустой кортеж."""
    try:
        return tuple(int(x) for x in str(v).strip().split(".")[:4])
    except (TypeError, ValueError):
        return ()


def update_newer(local, remote):
    """Есть ли в репозитории версия новее установленной."""
    lt, rt = version_tuple(local), version_tuple(remote)
    return bool(lt and rt and rt > lt)


def update_fetch(proxy=""):
    """Номер версии из репозитория. Не вышло — пустая строка, и это не ошибка."""
    for url in UPDATE_URLS:
        try:
            body = _get(url, proxy, timeout=10)
        except Exception:
            continue
        v = (body or "").strip().splitlines()
        v = v[0].strip() if v else ""
        if VERSION_RE.match(v):
            return v
    return ""


def tg_update_notice(cfg, remote):
    """Сообщение о доступном обновлении. Одно на версию."""
    tg = cfg["telegram"]
    lines = [f"{t('tg_upd_head')} · <b>{node_label(tg)}</b>", "",
             t("tg_upd_have", v=html.escape(shape_version())),
             t("tg_upd_new", v=html.escape(remote)), "",
             t("tg_upd_how")]
    ok, err = tg_send("\n".join(lines), cfg)
    if not ok:
        print(f"telegram: {err}", flush=True)
    return ok


def update_due(cfg, state, now=None):
    """
    Раз в шесть часов: не появилась ли версия новее. Сообщаем один раз на
    версию — иначе напоминание превратилось бы в четыре сообщения в сутки.

    Состояние правится на месте: {"at": когда проверяли, "seen": о чём уже
    сообщили}.
    """
    tg = cfg["telegram"]
    if not tg.get("enabled") or not tg.get("updates"):
        return False
    now = now if now is not None else time.time()
    if now - float(state.get("at") or 0) < UPDATE_INTERVAL:
        return False
    state["at"] = now
    remote = update_fetch(tg.get("proxy") or "")
    if not remote or remote == state.get("seen"):
        return False
    if not update_newer(shape_version(), remote):
        return False
    state["seen"] = remote
    return tg_update_notice(cfg, remote)


def node_label(tg):
    """
    Подпись ноды для сообщения. Пусто — берём имя хоста.

    Экранируем: сообщения уходят с parse_mode=HTML, и одинокий «<» в подписи
    или в имени хоста заставляет Telegram отвечать 400 «can't parse entities».
    Уведомления после этого молча перестают приходить.
    """
    return html.escape(tg.get("node_name") or os.uname().nodename)


def scrub(text, cfg=None):
    """
    Убирает секреты из текста ошибки — журнал читают не только свои.

    Список секретов один на всю программу — SECRET_PATHS. Раньше здесь был
    зашит только токен бота, и каждый новый секрет пришлось бы вспоминать
    отдельно в каждом месте, где печатается ошибка. Такое не вспоминают.
    """
    s = str(text)
    for section, field in SECRET_PATHS:
        try:
            value = str((cfg or {}).get(section, {}).get(field, "") or "")
        except Exception:
            value = ""
        # Короткие значения не маскируем: подстрока в два знака заменила бы
        # пол-сообщения. Секретов такой длины не бывает.
        if len(value) >= 8:
            s = s.replace(value, "***")
    # На случай, если токен просочился из другого источника: /bot<цифры>:<...>
    return re.sub(r"(?<=/bot)\d+:[A-Za-z0-9_-]+", "***", s)


def tg_send(text, cfg=None, force=False):
    """Возвращает (успех, пояснение). force — для кнопки «проверить»."""
    tg = (cfg or load_config())["telegram"]
    if not force and not tg.get("enabled"):
        return False, t("tg_off")
    if not tg.get("token") or not tg.get("chat_id"):
        return False, t("tg_no_creds")

    fields = {"chat_id": tg["chat_id"], "text": text,
              "parse_mode": "HTML", "disable_web_page_preview": "true"}
    if str(tg.get("thread_id") or "").strip():
        fields["message_thread_id"] = str(tg["thread_id"]).strip()
    data = urllib.parse.urlencode(fields).encode()
    url = f"https://api.telegram.org/bot{tg['token']}/sendMessage"

    try:
        return _post(url, data, tg.get("proxy", "")) == 200, "ok"
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:200]
        hint = ""
        if e.code in (401, 404):
            hint = "\n  " + t("tg_bad_token")
        elif "chat not found" in body:
            hint = "\n  " + t("tg_bad_chat")
        elif "message thread not found" in body:
            hint = "\n  " + t("tg_bad_thread")
        elif e.code == 403:
            hint = "\n  " + t("tg_forbidden")
        # Текст ошибки уходит в journalctl: токен из него вычищаем.
        return False, scrub(f"HTTP {e.code}: {body}{hint}", {"telegram": tg})
    except Exception as e:
        # Подсказку про прокси даём только на сетевые ошибки. Раньше она
        # висела на любом исключении, и ошибка в самом Shape выглядела как
        # блокировка Telegram — диагностика уходила не туда.
        # OSError покрывает и URLError, и SSLError, и таймаут сокета.
        hint = "" if tg.get("proxy") or not isinstance(e, OSError) \
            else "\n  " + t("tg_need_proxy")
        return False, scrub(f"{e}{hint}", {"telegram": tg})


PANEL_WHY_KEY = {"off": "pn_card_unknown", "never": "pn_card_never",
                 "stale": "pn_card_stale", "absent": "pn_card_absent"}


def offender_card(tg, subject, head, why=None):
    """
    Шапка сообщения о нарушителе: кто это, одинаково для всех поводов.

    Раздача подписки и превышение по трафику — разные проверки, но вопрос у
    человека, который читает сообщение, один и тот же: кто и за что. Поэтому
    шапка общая, а различается только то, что ниже.

    Касанием копируется только то, по чему человека ищут: логин панели и
    Telegram ID. Адрес — обычным текстом. Раньше он тоже был в <code>, и
    касание по карточке отдавало в буфер именно его — а искать по адресу
    негде: ни панель, ни бот его не знают.
    """
    subject = subject or {}
    out = [f"{head} · <b>{node_label(tg)}</b>", ""]

    name = html.escape(str(subject.get("label") or "")).strip()
    handle = html.escape(str(subject.get("handle") or "")).strip()
    tg_id = str(subject.get("telegram_id") or "").strip()

    # Имя — ссылкой на профиль: открыть переписку одним касанием проще, чем
    # искать человека по идентификатору руками.
    if name and tg_id.lstrip("-").isdigit():
        name = f'<a href="tg://user?id={tg_id}">{name}</a>'
    if name or handle:
        out.append(t("pn_card_name",
                     name=" · ".join(x for x in (name, handle) if x)))
    if tg_id:
        out.append(t("pn_card_tg", id=html.escape(tg_id)))

    login = html.escape(str(subject.get("username") or "")).strip()
    uid = html.escape(str(subject.get("user_id") or "")).strip()
    if login:
        # Логин — то самое, что вставляют в поиск панели. Внутренний номер
        # рядом и без <code>: он нужен глазам, а не буферу.
        out.append(t("pn_card_login", login=login)
                   + (f" · #{uid}" if uid else ""))
    elif uid:
        out.append(t("pn_card_panel", id=uid))
    # Сведения не свежие: панель сейчас этого адреса не показывает, имя взято
    # из прошлого опроса. Выдавать это за текущее нельзя — за адресом мог
    # оказаться уже другой человек. Строка идёт последней в блоке личности,
    # чтобы относиться ко всему блоку, а не к одному Telegram ID.
    seen_at = subject.get("seen_at")
    if seen_at and len(out) > 2:
        try:
            when = time.strftime("%H:%M", time.localtime(float(seen_at)))
            out.append(t("pn_card_seen", at=when))
        except (TypeError, ValueError, OSError):
            pass

    if len(out) == 2:          # ничего, кроме заголовка, не нашлось
        code, age = why if why else ("off", 0.0)
        key = PANEL_WHY_KEY.get(code, "pn_card_unknown")
        out.append(t(key, m=int(age // 60))
                   if key in ("pn_card_stale", "pn_card_absent") else t(key))
    out.append("")
    return out


def penalty_figures(day):
    """
    Строка с цифрами за сутки — или пусто, если считать не из чего.

    «Отдал непропорционально много» не отвечает на вопрос, за что человека
    ограничили: торрент это или он залил бэкап в облако. Ответ дают три числа,
    и все три у сторожа на руках в момент штрафа.

    Размер пакета решающий: 1200-1400 байт — это данные, 100-170 — подтвержде-
    ния обычной закачки. Пропорция одна и та же, а поводы разные.
    """
    if not day:
        return ""
    down, up = float(day.get("down", 0)), float(day.get("up", 0))
    if not (down or up):
        return ""
    out = f"↓ {fmt_bytes(down)} · ↑ {fmt_bytes(up)}"
    if down:
        out += f" ({up * 100 / down:.0f}%)"
    return out


def penalty_packets(day, now=None, hours=True):
    """
    Вторая строка: чем именно была отдача. Не из чего считать — пусто.

    hours=False — для тех мест, где часы уже печатаются своей подписью.
    Одно и то же число под двумя разными названиями в одной строке читается
    как две разные величины; в `panel user` так и вышло.

    Отдельной строкой, потому что срок у неё свой. Поле с пакетами
    обнуляется при смене формата, и сразу после обновления оно покрывает
    минуты, а не сутки. Подписывать такое «за сутки» — врать; поэтому срок
    печатается всегда, какой есть.
    """
    parsed = day_upkt(day)
    if not parsed:
        return "", 0.0
    b, n, top, _bulk, since = parsed
    if not b:
        return "", 0.0
    now = now if now is not None else time.time()
    # Суточные счётчики обнуляются в полночь, поэтому окно длиннее суток
    # означает испорченную отметку времени, а не долгую отдачу. Печатать
    # «за 496620 ч» нельзя — это не срок, это мусор.
    if not 0 <= now - since <= 25 * 3600:
        return "", 0.0

    parts = [t("tg_pen_bulk", p=f"{bulk_share(day):.0f}")]
    if n:
        avg = b / n
        if MIN_PACKET_BYTES <= avg <= MAX_PACKET_BYTES:
            parts.append(t("tg_pen_pkt", n=int(avg)))
    # Максимум оставлен рядом с долей: он говорит, доходило ли вообще, а
    # доля — сколько. Вместе они читаются, порознь каждый вводит в
    # заблуждение, и оба раза ввёл.
    if MIN_PACKET_BYTES <= top <= MAX_PACKET_BYTES:
        parts.append(t("tg_pen_pkt_max", n=int(top)))
    # Часы отдачи данными — тот самый признак, которым отделяют раздачу от
    # выгрузки. Его не было в карточке, и по ней нельзя было понять, почему
    # человек попал под ограничение, а сосед с теми же процентами нет.
    up_sec = (day or {}).get("up_sec", 0)
    if hours and isinstance(up_sec, (int, float)) and 0 < up_sec <= 25 * 3600:
        parts.append(t("tg_pen_hrs", h=f"{up_sec / 3600:.1f}"))
    return " · ".join(parts), max(0.0, now - since)


def tg_upload_notice(cfg, ip, subject=None, unknown=None, day=None):
    """
    Событие: адрес много отдал за сутки. Ограничения нет.

    Отдельное сообщение, а не штраф с нулевой скоростью: смысл уровня в том,
    чтобы владелец ноды увидел подходящих к границе раньше, чем они её
    перейдут, и сам решил, что с ними делать.
    """
    tg = cfg["telegram"]
    if not tg.get("enabled") or not tg.get("events"):
        return
    g = cfg["guard"]
    lines = offender_card(tg, subject, t("tg_up_head"), unknown)
    lines.append(t("tg_pen_addr", ip=html.escape(ip)))
    lines.append(t("tg_up_warn", gb=fmt_bytes((day or {}).get("up", 0)),
                   n=f"{g.get('upload_warn_gb', 0):g}"))
    figures = penalty_figures(day)
    if figures:
        lines.append(t("tg_pen_stat", s=figures))
    pkts, window = penalty_packets(day)
    if pkts:
        lines.append(t("tg_pen_pkts", d=fmt_hold(window), s=pkts))
    if g.get("upload_day_gb"):
        lines.append("")
        lines.append(t("tg_up_note", n=f"{g['upload_day_gb']:g}"))
    ok, err = tg_send("\n".join(lines), cfg)
    if not ok:
        print(f"telegram: {err}", flush=True)


def tg_upload_hours(cfg, ip, subject=None, unknown=None, day=None):
    """
    Событие: адрес отдавал слишком долго. Ограничения нет и не будет.

    Штрафа здесь нет намеренно: первичный бэкап телефона по всем признакам
    совпадает с раздачей, и различает их только то, что бэкап кончается.
    Пока мы этого не считаем, решение остаётся за владельцем ноды.
    """
    tg = cfg["telegram"]
    if not tg.get("enabled") or not tg.get("events"):
        return
    g = cfg["guard"]
    lines = offender_card(tg, subject, t("tg_uph_head"), unknown)
    lines.append(t("tg_pen_addr", ip=html.escape(ip)))
    lines.append(t("tg_uph_warn",
                   h=f"{(day or {}).get('up_sec', 0) / 3600:.1f}",
                   n=f"{g.get('upload_hours', 0):g}"))
    figures = penalty_figures(day)
    if figures:
        lines.append(t("tg_pen_stat", s=figures))
    pkts, window = penalty_packets(day)
    if pkts:
        lines.append(t("tg_pen_pkts", d=fmt_hold(window), s=pkts))
    lines.append("")
    lines.append(t("tg_uph_note"))
    ok, err = tg_send("\n".join(lines), cfg)
    if not ok:
        print(f"telegram: {err}", flush=True)


def tg_penalty(cfg, ip, mbps, minutes, reasons, subject=None, unknown=None,
               day=None):
    """Событие: адрес получил ограничение."""
    tg = cfg["telegram"]
    if not tg.get("enabled") or not tg.get("events"):
        return
    why = ", ".join(t("why_" + r) for r in reasons) or "—"
    lines = offender_card(tg, subject, t("tg_pen_head"), unknown)
    lines.append(t("tg_pen_addr", ip=html.escape(ip)))
    lines.append(t("tg_pen_speed", mbps=f"{mbps:g}", d=fmt_hold(minutes * 60)))
    lines.append(t("tg_pen_why", why=why))
    figures = penalty_figures(day)
    if figures:
        lines.append(t("tg_pen_stat", s=figures))
    pkts, window = penalty_packets(day)
    if pkts:
        lines.append(t("tg_pen_pkts", d=fmt_hold(window), s=pkts))
    # За одним адресом может сидеть несколько человек — предупреждаем прямо
    # в сообщении, чтобы никто не обвинил не того.
    if subject and subject.get("shared"):
        lines.append(f"<i>{t('tg_shared')}</i>")
    ok, err = tg_send("\n".join(lines), cfg)
    if not ok:
        print(f"telegram: {err}", flush=True)


def digest_text(cfg, day, snapshot, partial=False):
    """Текст сводки. partial — сутки ещё не закончились."""
    tg = cfg["telegram"]
    down = sum(v.get("down", 0) for v in snapshot.values())
    up = sum(v.get("up", 0) for v in snapshot.values())
    top = sorted(snapshot.items(), key=lambda x: -x[1].get("down", 0))[:5]
    head = t("tg_digest_now") if partial else f"{t('tg_digest')} {day}"
    lines = [f"📊 <b>{node_label(tg)}</b> · {head}",
             f"{t('tg_traffic')}: ↓ {fmt_bytes(down)} · ↑ {fmt_bytes(up)}",
             f"{t('tg_addresses')}: {len(snapshot)}"]
    if top:
        lines.append("")
        lines.append(t("tg_top") + ":")
        owners = load_owners()
        for i, (ip, v) in enumerate(top, 1):
            who = owner_of(ip, owners)
            name = html.escape(str(who["label"])) + " · " if who and who.get("label") else ""
            lines.append(f"{i}. {name}<code>{ip}</code> — {fmt_bytes(v.get('down', 0))}")
    return "\n".join(lines)


def parse_hhmm(s, fallback=(9, 0)):
    """'09:30' -> (9, 30). Кривое значение не должно ронять сторожа."""
    try:
        h, m = str(s).strip().split(":")
        h, m = int(h), int(m)
        if 0 <= h <= 23 and 0 <= m <= 59:
            return h, m
    except Exception:
        pass
    return fallback


def digest_stash(day, snapshot):
    """Закрываем сутки: откладываем срез до назначенного часа."""
    if not snapshot:
        return
    tmp = DIGEST_FILE + ".tmp"
    os.makedirs(ETC_DIR, exist_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"day": day, "ips": snapshot}, f)
    os.replace(tmp, DIGEST_FILE)


def digest_due(cfg):
    """
    Раз в цикл проверяем, не пора ли отправить отложенную сводку.

    Отправляем не раньше назначенного времени следующих суток. Если нода
    была выключена и момент пропущен больше чем на сутки — сводку роняем,
    позавчерашние цифры никому не нужны.
    """
    try:
        with open(DIGEST_FILE) as f:
            d = json.load(f)
    except Exception:
        return
    tg = cfg["telegram"]
    day, ips = d.get("day", ""), d.get("ips", {})
    h, m = parse_hhmm(tg.get("digest_at", "09:00"))
    try:
        base = time.mktime(time.strptime(day, "%Y-%m-%d"))
    except Exception:
        os.remove(DIGEST_FILE)
        return
    due = base + 86400 + h * 3600 + m * 60
    now = time.time()
    if now < max(due, d.get("retry_at", 0)):
        return
    if now <= due + 86400 and ips and tg.get("enabled") and tg.get("daily"):
        ok, err = tg_send(digest_text(cfg, day, ips), cfg)
        if not ok:
            # связи нет — не долбим API каждые десять секунд
            print(f"telegram: {err}", flush=True)
            d["retry_at"] = now + 900
            with open(DIGEST_FILE, "w") as f:
                json.dump(d, f)
            return
    try:
        os.remove(DIGEST_FILE)
    except OSError:
        pass



# ──────────────── резервная копия в Telegram ────────────────
# Копия, лежащая на том же диске, который однажды умрёт, копией не является.
# Отдельный сервер под 200 килобайт заводить незачем, а Telegram на ноде уже
# настроен — вместе с прокси, который на российских нодах всё равно нужен.
#
# Жёсткое правило: секреты сюда не уходят никогда. Токен бота в чате, куда
# этот же бот пишет, означает, что любой участник темы — сейчас или добавленный
# через полгода — забирает управление ботом и всю переписку разом. Копия с
# токеном существует только как файл на диске, для переноса ноды.

BACKUP_STATE = os.path.join(VAR_DIR, "backup.state")
BACKUP_RETRY = 3600        # связи нет — пробуем через час, а не каждый цикл


def _safe_name(s, fallback="node"):
    """Имя файла без сюрпризов: только буквы, цифры, точка, дефис."""
    s = re.sub(r"[^A-Za-z0-9._-]", "-", str(s))[:40].strip("-.")
    return s or fallback


def _multipart(fields, filename, content, field="document",
               mime="application/json"):
    """
    Собирает multipart/form-data. Возвращает (тело, значение Content-Type).

    Своими руками, потому что весь Shape живёт на стандартной библиотеке, а
    в ней готового сборщика нет. Граница берётся из os.urandom: угадать её и
    подсунуть в имя файла или в подпись свою секцию не выйдет.
    """
    boundary = "----shape" + os.urandom(16).hex()
    out = []
    for k, v in fields.items():
        out.append(f"--{boundary}\r\n"
                   f'Content-Disposition: form-data; name="{k}"\r\n\r\n'
                   f"{v}\r\n".encode())
    out.append(f"--{boundary}\r\n"
               f'Content-Disposition: form-data; name="{field}"; '
               f'filename="{_safe_name(filename, "backup.json")}"\r\n'
               f"Content-Type: {mime}\r\n\r\n".encode())
    out.append(content)
    out.append(f"\r\n--{boundary}--\r\n".encode())
    return b"".join(out), f"multipart/form-data; boundary={boundary}"


def backup_filename(node=None):
    node = _safe_name(node or socket.gethostname())
    return f"shape-{node}-{time.strftime('%Y-%m-%d')}.json"


def tg_backup(cfg=None, force=False):
    """
    Отправляет копию состояния файлом. Возвращает (успех, пояснение).

    force — для кнопки «отправить сейчас»: она работает и когда еженедельная
    отправка выключена, но сам Telegram должен быть настроен.
    """
    cfg = cfg or load_config()
    tg = cfg["telegram"]
    if not force and not (tg.get("enabled") and tg.get("backup")):
        return False, t("bk_tg_off")
    if not tg.get("token") or not tg.get("chat_id"):
        return False, t("tg_no_creds")

    data = build_export(with_secrets=False)
    blob = json.dumps(data, ensure_ascii=False, indent=1).encode()

    # Последняя проверка перед отправкой, а не вера в флаг выше. Если код
    # когда-нибудь поменяют так, что секрет просочится в выгрузку, отправка
    # должна сорваться здесь — а не после того, как токен уже улетел в чат.
    text = blob.decode("utf-8", "replace")
    for section, field in SECRET_PATHS:
        secret = str((cfg.get(section) or {}).get(field) or "")
        if secret and secret in text:
            return False, t("bk_tg_secrets")
    if data.get("secrets_included"):
        return False, t("bk_tg_secrets")

    st = data["state"]
    caption = (f"💾 <b>{node_label(tg)}</b> · {t('bk_tg_caption')}\n"
               f"{t('bk_tg_counts', w=len(st['whitelist']), p=len(st['penalties']), o=len(st['owners']))}\n"
               f"<i>{t('bk_tg_nosec')}</i>")

    return tg_document(cfg, backup_filename(data.get("node")), blob, caption,
                       thread=tg.get("backup_thread_id") or tg.get("thread_id"))


def tg_document(cfg, filename, blob, caption="", thread=None,
                mime="application/json"):
    """
    Отправляет файл в Telegram. Возвращает (успех, пояснение).

    Выделено из отправки резервной копии, когда файлов стало больше одного.
    Причина у всех одна: в сообщении Telegram 4096 символов, и список из
    четырёхсот адресов туда не помещается — это семь килобайт. Что не влезло
    в сообщение, уходит вложением.
    """
    tg = cfg["telegram"]
    if not tg.get("token") or not tg.get("chat_id"):
        return False, t("tg_no_creds")

    fields = {"chat_id": tg["chat_id"], "parse_mode": "HTML"}
    if caption:
        # У подписи к файлу свой предел, вчетверо меньше, чем у сообщения.
        fields["caption"] = caption[:1024]
    th = str(thread if thread is not None else tg.get("thread_id") or "").strip()
    if th:
        fields["message_thread_id"] = th

    body, ctype = _multipart(fields, filename, blob, mime=mime)
    url = f"https://api.telegram.org/bot{tg['token']}/sendDocument"
    try:
        return _post(url, body, tg.get("proxy", ""), ctype) == 200, "ok"
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:200]
        return False, scrub(f"HTTP {e.code}: {detail}", {"telegram": tg})
    except Exception as e:
        # Подсказку про прокси даём только на сетевые ошибки. Раньше она
        # висела на любом исключении, и ошибка в самом Shape выглядела как
        # блокировка Telegram — диагностика уходила не туда.
        # OSError покрывает и URLError, и SSLError, и таймаут сокета.
        hint = "" if tg.get("proxy") or not isinstance(e, OSError) \
            else "\n  " + t("tg_need_proxy")
        return False, scrub(f"{e}{hint}", {"telegram": tg})


def backup_due(cfg, now=None):
    """
    Раз в цикл сторожа: не пора ли отправить недельную копию.

    Отправляем в назначенный день недели, не раньше времени сводки, и не
    чаще раза в сутки. Если нода была выключена и день пропущен — ждём
    следующего: догонять пропущенную копию смысла нет, состояние всё равно
    берётся текущее, а не то, что было в понедельник.
    """
    tg = cfg["telegram"]
    if not (tg.get("enabled") and tg.get("backup")):
        return False
    now = now if now is not None else time.time()
    lt = time.localtime(now)
    try:
        want_day = int(tg.get("backup_day", 1))
    except (TypeError, ValueError):
        want_day = 1
    if not 1 <= want_day <= 7:
        want_day = 1
    if lt.tm_wday + 1 != want_day:
        return False

    h, m = parse_hhmm(tg.get("digest_at", "09:00"))
    if (lt.tm_hour, lt.tm_min) < (h, m):
        return False

    today = time.strftime("%Y-%m-%d", lt)
    state = {}
    try:
        with open(BACKUP_STATE) as f:
            state = json.load(f)
        if not isinstance(state, dict):
            state = {}
    except Exception:
        state = {}
    if state.get("last_sent") == today:
        return False
    if now < float(state.get("retry_at") or 0):
        return False

    ok, err = tg_backup(cfg)
    if ok:
        state = {"last_sent": today}
    else:
        # Связи нет — пробуем через час, а не каждые десять секунд.
        print(f"telegram backup: {err}", flush=True)
        state["retry_at"] = now + BACKUP_RETRY
    try:
        os.makedirs(VAR_DIR, exist_ok=True)
        tmp = BACKUP_STATE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
        os.replace(tmp, BACKUP_STATE)
    except OSError:
        pass
    return ok


# ─────────────────────── связь с панелью Remnawave ───────────────────────
#
# Зачем это здесь. Нода видит адреса, но не знает, кому они принадлежат.
# Панель знает. Пересечение двух знаний даёт то, чего нельзя получить ни там,
# ни там по отдельности: сколько адресов одного пользователя живёт на этой
# ноде прямо сейчас. Десятки одновременных адресов у одной подписки — это не
# человек с телефоном, это раздача ключа на сторону.
#
# Запрос двухшаговый, и это не наша прихоть — так устроен API панели:
#   POST /api/connections/by-node/{nodeUuid} → {"response": {"jobId": "43"}}
#   GET  /api/connections/by-node/{jobId}    → {"response": {isCompleted, result}}
# Панель опрашивает ноду в фоне, поэтому результат приходит не сразу. Ответы
# завёрнуты в "response" — в опубликованном SDK этой обёртки нет, проверено на
# живой панели 3.2.3. userId там число, а не строка, вопреки тому же SDK.
#
# Ключевое поле — lastSeen у каждого адреса. Именно оно отличает раздачу от
# честного мобильного интернета: у человека с телефоном за сутки набегают
# десятки адресов, но одновременно живёт один. Поэтому считаем не все адреса,
# а только те, что видели за последние window_min минут.
#
# Раздел необязательный. Панель недоступна, токен протух, версия API другая —
# сторож и ограничение скорости продолжают работать как ни в чём не бывало.
# Это главное свойство: нода не должна зависеть от внешней службы.

# ── Связь с API провайдера CDN ─────────────────────────────────────────
#
# Нужна ровно для одного: когда клиенты с ноды пропали, сказать вслух, чья
# это беда. Нода здорова, процессы работают, ошибок нет — и по ней не понять,
# то ли край CDN лёг, то ли что-то у нас. Разбор такого случая занимает час;
# провайдер отвечает за две секунды, если его спросить.
#
# Раздел необязательный и выключен по умолчанию. Провайдер недоступен, ключ
# протух, API у него другой — сообщение уйдёт как раньше, просто без строки
# с вердиктом. Ни шейпер, ни сторож, ни штрафы этого пути не касаются.
#
# Пути соответствуют API вида `/v1/resources/{id}` — если у вашего провайдера
# они другие, раздел просто не включайте.
CDN_HTTP_TIMEOUT = 8            # на один запрос, секунд
CDN_RETRY = 900                 # пауза после ошибки, чтобы не долбить

CDN_DEFAULT = {
    "enabled": False,
    "url": "",            # база API провайдера, например https://api.example.com
    "token": "",          # ключ из личного кабинета провайдера
    "resource_id": "",    # номер ресурса, за которым стоит эта нода
    "proxy": "",          # http(s)-прокси; socks5 здесь не поддержан
}


class CdnError(Exception):
    """Ошибка обращения к API провайдера. code — HTTP-код, если он был."""

    def __init__(self, msg, code=0):
        super().__init__(msg)
        self.code = code


def cdn_scrub(text, c=None):
    """Убирает ключ из текста ошибки — журнал читают не только свои."""
    s = str(text)
    token = str((c or {}).get("token") or "")
    if len(token) > 8:
        s = s.replace(token, "***")
    return s


def cdn_call(c, path):
    """Один GET к API провайдера. Возвращает разобранный ответ словарём."""
    base = str(c.get("url") or "").strip().rstrip("/")
    if not base:
        raise CdnError(t("cdn_no_url"))
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    # Провайдер в своей документации пишет базу вместе с версией — вида
    # https://api.example.com/v1. Пути мы строим со своим /v1, и склеилось бы
    # /v1/v1. Понимаем обе формы: лишний хвост убираем, а человека не
    # заставляем помнить, какую именно из них мы ждём.
    if base.endswith("/v1"):
        base = base[:-3]
    token = str(c.get("token") or "").strip()
    if not token:
        raise CdnError(t("cdn_no_token"))

    proxy = str(c.get("proxy") or "").strip()
    if proxy.startswith(("socks5://", "socks5h://")):
        raise CdnError(t("pn_socks"))

    req = urllib.request.Request(base + path, method="GET")
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("Accept", "application/json")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(
        {"http": proxy, "https": proxy} if proxy else {}))
    try:
        with opener.open(req, timeout=CDN_HTTP_TIMEOUT) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        raise CdnError(cdn_scrub("HTTP %d" % e.code, c), e.code) from e
    except Exception as e:
        raise CdnError(cdn_scrub(e, c)) from e
    try:
        got = json.loads(raw.decode() or "{}")
    except ValueError:
        raise CdnError(t("pn_bad_json")) from None
    return got if isinstance(got, dict) else {}


PANEL_STATE = os.path.join(VAR_DIR, "panel.state")
PANEL_RETRY = 900           # пауза после ошибки, чтобы не долбить панель
PANEL_JOB_DEADLINE = 20.0   # сколько всего ждём готовности задачи, секунд
PANEL_JOB_POLL = 1.0        # пауза между опросами задачи
PANEL_HTTP_TIMEOUT = 10     # на один запрос, секунд
PANEL_ACTIONS = ("notify", "limit", "block", "drop")

# Отключение подписки — не действие в одном ряду с остальными, а отсрочка.
#
# Владелец ноды видит уведомление и отключает нарушителя сам, за минуту. Но
# ночью его нет, а перекрытие адресов ночь не закрывает: длинное задевает
# честных (у мобильного оператора адрес переходит от абонента к абоненту за
# минуты), короткое оставляет дыру до следующей проверки.
#
# Отключение бьёт по аккаунту, а не по адресу — а раздаёт подписку именно
# аккаунт. Посторонние не задеты вовсе, и действует оно на всех нодах сразу.
#
# Отсчёт отменяется сам: если владелец успел отключить или переиздать
# подписку, покупатели пропадают из списка соединений, и при следующей
# проверке человек уже не нарушитель.
PANEL_DISABLE_MAX = 3


def panel_threshold(p, person):
    """
    Порог адресов для конкретного человека: базовый или от его тарифа.

    Возвращает (порог, от_тарифа_ли). Тариф неизвестен — базовый: гадать за
    владельца, сколько устройств он продал, нельзя.
    """
    base = max(PANEL_MIN_THRESHOLD, int(p.get("ip_threshold") or 20))
    k = float(p.get("per_device") or 0)
    dev = int((person or {}).get("device_limit") or 0)
    if k <= 0 or dev <= 0:
        return base, False
    return max(base, int(dev * k)), True


# «Перекрыть доступ» — это очень маленькая скорость, а не ноль.
#
# Ноль в карте ядра означает «ограничения нет»: движок так и написан, и это
# намеренно — между проверкой и применением лимит могли снять из userspace, и
# пакет с нулевой скоростью уехал бы мимо всякого учёта. Поэтому блокировка
# делается минимальной скоростью.
#
# 0.05 Мбит/с — это 6250 байт в секунду. Полуторакилобайтный пакет при такой
# скорости занимает 240 мс, а горизонт очереди в движке — 2 секунды, то есть
# в очереди помещается восемь пакетов, остальные отбрасываются. Рукопожатие
# TLS до конца не доходит. Снаружи это выглядит как «интернета нет».
PANEL_BLOCK_MBPS = 0.05
PANEL_TOKEN_WARN = 7 * 86400    # предупредить за неделю до истечения токена
PANEL_MIN_THRESHOLD = 2     # ниже этого порог не опускаем ни при каких настройках


class PanelError(Exception):
    """Ошибка обращения к панели. code — HTTP-код, если он был."""

    def __init__(self, msg, code=0):
        super().__init__(msg)
        self.code = code


UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def valid_uuid(s):
    """Похоже ли это на UUID. Проверяем форму, существование — дело панели."""
    return bool(UUID_RE.match(str(s or "").strip()))


def panel_actions(p):
    """
    Разбирает поле action в набор.

    Строкой, а не тремя флагами, потому что сочетания осмысленны: обрыв без
    уведомления оставит владельца в неведении, а ограничение без обрыва —
    самый частый рабочий вариант. Неизвестные слова молча отбрасываем: чужая
    опечатка в конфиге не повод останавливать сторож.
    """
    raw = str(p.get("action") or "").replace(";", ",").split(",")
    out = {w.strip().lower() for w in raw if w.strip().lower() in PANEL_ACTIONS}
    # Уведомление включено всегда и выключить его нельзя.
    #
    # Действие без уведомления — это то, что невозможно объяснить: соединения
    # оборваны, человек жалуется, а в переписке ни следа. Именно так и вышло
    # на живой ноде с action=drop: Shape молча рвал коннекты, и понять, кого
    # и за что, было нечем. Что делать с нарушителем, решает человек, но
    # узнать о нём он должен в любом случае.
    out.add("notify")
    return out


def token_expiry(token):
    """
    Когда истекает токен панели — из него самого, без обращения к панели.

    Токен это JWT: три части через точку, средняя — base64url с полем exp.
    Подпись не проверяем и проверять не должны: это не наш секрет, нам нужна
    только дата, чтобы предупредить владельца заранее. Не разобралось — 0, и
    предупреждение просто не показывается.
    """
    try:
        payload = str(token).split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return float(json.loads(base64.urlsafe_b64decode(payload)).get("exp") or 0)
    except Exception:
        return 0.0


def panel_ts(value):
    """
    lastSeen вида 2026-08-23T12:53:10.000Z в секунды UTC.

    Разбираем вручную: datetime.fromisoformat научился понимать «Z» только в
    Python 3.11, а ноды бывают и на старых системах. Не разобралось — 0, такой
    адрес в окно «сейчас» не попадёт. Это правильная сторона ошибки: лучше не
    заметить нарушителя, чем наказать невиновного.
    """
    s = str(value or "").strip()
    if s.endswith("Z"):
        s = s[:-1]
    s = s.split(".")[0].split("+")[0]
    try:
        return float(calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%S")))
    except Exception:
        return 0.0


def panel_unwrap(payload):
    """Панель заворачивает полезное в response. Обёртки нет — берём как есть."""
    if isinstance(payload, dict) and isinstance(payload.get("response"), dict):
        return payload["response"]
    return payload if isinstance(payload, dict) else {}


def panel_scrub(text, p=None):
    """Убирает токен панели из текста ошибки — журнал читают не только свои."""
    s = str(text)
    token = str((p or {}).get("token") or "")
    if len(token) > 8:
        s = s.replace(token, "***")
    return s


def panel_call(p, method, path, body=None):
    """
    Один запрос к панели. Возвращает распакованный ответ словарём.

    Прокси поддержан только http(s). Для Telegram socks5 реализован вручную,
    но там один известный адрес и один метод; городить то же самое ради панели
    незачем — панель это машина того же владельца, до неё нода ходит напрямую.
    Если socks5 всё-таки указан, честно говорим об этом, а не молча ходим мимо
    прокси.
    """
    base = str(p.get("url") or "").strip().rstrip("/")
    if not base:
        raise PanelError(t("pn_no_url"))
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    token = str(p.get("token") or "").strip()
    if not token:
        raise PanelError(t("pn_no_token"))

    proxy = str(p.get("proxy") or "").strip()
    if proxy.startswith(("socks5://", "socks5h://")):
        raise PanelError(t("pn_socks"))

    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")

    # Пустой ProxyHandler отключает подхват http_proxy из окружения: прокси у
    # Shape свой, в настройках, и брать его откуда-то ещё он не должен.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(
        {"http": proxy, "https": proxy} if proxy else {}))
    try:
        with opener.open(req, timeout=PANEL_HTTP_TIMEOUT) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        # Тело ошибки читается ровно один раз: поток одноразовый, и повторный
        # read() вернул бы пустоту, из-за чего пояснение панели потерялось бы.
        detail = ""
        try:
            body = json.loads(e.read() or b"{}")
            detail = str(panel_unwrap(body).get("message")
                         or (body.get("message") if isinstance(body, dict) else "")
                         or "")
        except Exception:
            detail = ""
        if e.code in (401, 403):
            raise PanelError(t("pn_denied", detail=detail or e.reason),
                             e.code) from e
        raise PanelError(panel_scrub(f"HTTP {e.code}: {detail or e.reason}", p),
                         e.code) from e
    except Exception as e:
        raise PanelError(panel_scrub(e, p)) from e

    try:
        return panel_unwrap(json.loads(raw.decode() or "{}"))
    except ValueError:
        raise PanelError(t("pn_bad_json")) from None


def panel_fetch(p):
    """
    Полный цикл: запустить задачу и дождаться результата.

    Возвращает [{"user_id": строка, "ips": [(адрес, когда видели)]}].

    Дедлайн общий и жёсткий. Нас зовут из цикла сторожа, и повиснуть там
    нельзя: пока мы ждём панель, ограничения не выдаются. Лучше пропустить
    один проход, чем задержать штраф.
    """
    uuid = str(p.get("node_uuid") or "").strip()
    if not uuid:
        raise PanelError(t("pn_no_uuid"))

    started = panel_call(p, "POST", "/api/connections/by-node/" + uuid)
    job = str(started.get("jobId") or "").strip()
    if not job:
        raise PanelError(t("pn_no_job"))

    deadline = time.monotonic() + PANEL_JOB_DEADLINE
    while True:
        got = panel_call(p, "GET", "/api/connections/by-node/" + job)
        if got.get("isFailed"):
            raise PanelError(t("pn_job_failed", job=job))
        if got.get("isCompleted"):
            break
        if time.monotonic() >= deadline:
            raise PanelError(t("pn_job_slow", job=job))
        time.sleep(PANEL_JOB_POLL)

    out = []
    for u in ((got.get("result") or {}).get("users") or []):
        ips = [(str(e.get("ip") or ""), panel_ts(e.get("lastSeen")))
               for e in (u.get("ips") or []) if e.get("ip")]
        out.append({"user_id": str(u.get("userId")), "ips": ips})
    return out


def panel_offenders(users, p, now=None):
    """
    Кто раздал подписку: считаем адреса, живые в окне window_min.

    Порог ниже PANEL_MIN_THRESHOLD не опускаем ни при каких настройках. Ноль
    или единица в конфиге означали бы «ограничить вообще всех», и человек,
    который просто не разобрался в настройке, положил бы себе ноду.
    """
    now = now if now is not None else time.time()
    window = max(1, int(p.get("window_min") or 10)) * 60
    threshold = max(PANEL_MIN_THRESHOLD, int(p.get("ip_threshold") or 20))
    exempt = {str(x) for x in (p.get("exempt") or [])}

    out = []
    for u in users:
        if u["user_id"] in exempt:
            continue
        fresh = sorted({ip for ip, ts in u["ips"] if ts and now - ts <= window})
        if len(fresh) >= threshold:
            out.append({"user_id": u["user_id"], "ips": fresh,
                        "count": len(fresh), "total": len(u["ips"])})
    out.sort(key=lambda r: -r["count"])
    return out


# ── справочник пользователей ──────────────────────────────────────────
#
# Держим в памяти процесса и не пишем на диск. Это чужие персональные данные,
# и хранить их на ноде мы не подряжались: понадобились — спросили, отправили,
# забыли. Сторож живёт долго, часа кэша достаточно — имена меняются реже.

_PANEL_DIR_CACHE = {"at": 0.0, "map": {}}

# Кто стоит за адресом — по последнему опросу панели. Нужно ровно для одного:
# когда сторож выдаёт штраф, сказать в сообщении не «203.0.113.7», а имя
# человека. Сторож — процесс долгоживущий, и карта от опроса пятиминутной
# давности у него под рукой; на диск она не пишется.
_PANEL_IP_OWNER = {"at": 0.0, "map": {}}
PANEL_IP_OWNER_TTL = 1800
PANEL_DIR_TTL = 3600
PANEL_PAGE = 1000           # предел панели на одну страницу
PANEL_DIR_MAX_PAGES = 40    # страховка от бесконечной постраничности
PANEL_MSG_LIMIT = 3500      # предел сообщения в Telegram 4096, берём с запасом


PERSON_NAME_MAX = 48
PERSON_HANDLE_RE = re.compile(r"@([A-Za-z0-9_]{4,32})")


def person_name(desc):
    """
    Имя и @ник из описания учётной записи. Не разобралось — две пустые строки.

    Отдельного поля под имя в панели нет: логин там вида «user_100000003», а
    имя, если оно вообще есть, кладёт в описание бот. Формат у каждого бота
    свой — «Bot user: Иван @ivan», «Иван», просто «@ivan», — поэтому разбираем
    осторожно и на удачу не рассчитываем: не вышло, и в сообщении останется
    логин, как было раньше.
    """
    s = " ".join(str(desc or "").split())
    if not s:
        return "", ""

    # «Bot user: Иван @ivan» → «Иван @ivan». Подпись отрезаем первой и только
    # если она короткая и написана латиницей: описание вроде «Оплата: до 3
    # октября» так уцелеет целиком, а свою метку бот ставит по-английски.
    # Порядок важен: сделай это после @ника — от «Bot user: @ivan» осталось
    # бы имя «Bot user:».
    head, sep, tail = s.partition(":")
    if sep and tail.strip() and len(head) <= 16 and head.isascii():
        s = tail

    m = PERSON_HANDLE_RE.search(s)
    handle = "@" + m.group(1) if m else ""
    if m:
        s = s[:m.start()] + s[m.end():]

    return " ".join(s.split()).strip(" ·,-:")[:PERSON_NAME_MAX], handle


def panel_person(u):
    """Из карточки панели оставляем семь полей. Остальные два десятка — мимо."""
    if not isinstance(u, dict) or u.get("id") is None:
        return None
    name, handle = person_name(u.get("description"))
    # Лимит устройств — это тариф, который владелец продал. Не путать с числом
    # зарегистрированных устройств: те зависят от того, поставил ли клиент
    # приложение, а тариф не зависит ни от чего.
    try:
        dev = int(u.get("hwidDeviceLimit"))
    except (TypeError, ValueError):
        dev = 0
    return {"id": str(u.get("id")),
            "device_limit": max(0, dev),
            "username": str(u.get("username") or ""),
            "name": name,
            "handle": handle,
            # Тег ставится в панели один раз и виден со всех нод. Список
            # номеров пришлось бы держать на каждой из них отдельно.
            "tag": str(u.get("tag") or "").strip(),
            "telegram_id": str(u.get("telegramId") or "")}


def panel_label(uid, person=None):
    """
    «Ольга · user_97 (100000008)» — сколько известно, столько и пишем.

    Логин остаётся в подписи даже когда имя известно: имя нужно глазам, а
    ищут человека в панели по логину, и отчёт открывают именно для этого.
    """
    if not person:
        return "#" + str(uid)
    head = " · ".join(x for x in (person.get("name"), person.get("username"))
                      if x) or ("#" + str(uid))
    tg = person.get("telegram_id")
    return f"{head} ({tg})" if tg else head


def panel_user(p, uid):
    """
    Имя и Telegram ID одного человека. Не вышло — None, и это не ошибка:
    без справочника в сообщении просто останется внутренний номер.
    """
    if not p.get("resolve"):
        return None
    try:
        return panel_person(panel_call(p, "GET", "/api/users/%s" % uid))
    except PanelError:
        return None


def panel_owner_reason(cfg, ip, now=None):
    """
    Почему владелец не нашёлся: ("", 0) — нашёлся, иначе код и возраст карты.

    Причин четыре, и раньше сообщение называло одну — «связь с панелью не
    настроена». Это верно только для первой; в остальных трёх текст врал и
    отправлял искать поломку не туда.

      off    — панель на этой ноде выключена
      never  — ни одного успешного опроса с момента запуска сторожа
      stale  — карта адресов устарела: панель давно не отвечает
      absent — карта свежая, но этого адреса в ней нет

    «never» отделено от «stale» не ради красоты. Карта живёт в памяти
    процесса, и после перезапуска сторожа отметка времени равна нулю. Возраст
    считался от неё, и в сообщение уходило «панель не отвечает уже 29796012
    мин» — то есть пятьдесят шесть лет, весь Unix-эпох целиком.
    """
    p = cfg.get("panel") or {}
    if not p.get("enabled"):
        return "off", 0.0
    now = now if now is not None else time.time()
    at = float(_PANEL_IP_OWNER.get("at") or 0)
    if at <= 0:
        # Карта живёт в памяти процесса и после перезапуска пуста. Но на диске
        # лежит отметка последнего удачного опроса, и она отвечает на вопрос
        # точнее: «не отвечает уже три часа» — это диагноз, а «ещё ни разу» —
        # только про текущий процесс.
        at = float((panel_state() or {}).get("last_ok") or 0)
        if at <= 0:
            return "never", 0.0
    age = now - at
    if age > PANEL_IP_OWNER_TTL:
        return "stale", age
    if not (_PANEL_IP_OWNER.get("map") or {}).get(ip):
        return "absent", age
    return "", age


def panel_owner(cfg, ip, now=None):
    """
    Кто стоит за адресом, по данным панели. Формат тот же, что у owners.json.

    Нужно для сообщения о штрафе: «Ограничен 203.0.113.7» говорит куда меньше,
    чем «Ограничен Bashou · 203.0.113.7». Карта адресов берётся из последнего
    опроса панели и стоит ноль запросов; имя спрашивается поимённо и только
    когда штраф действительно выдан — то есть редко.

    Ничего не нашлось — None, и сообщение уйдёт как раньше, с адресом.
    """
    why, _ = panel_owner_reason(cfg, ip, now)
    if why:
        return None
    p = cfg["panel"]
    uid = _PANEL_IP_OWNER["map"][ip]

    out = {"user_id": str(uid)}
    person = panel_user(p, uid)
    if person:
        for src, dst in (("name", "label"), ("username", "username"),
                         ("handle", "handle"), ("tag", "tag")):
            if person.get(src):
                out[dst] = person[src]
        # Карточка делает из идентификатора ссылку tg://user?id=… — нечисловое
        # значение уронило бы отправку сообщения о штрафе целиком.
        if str(person.get("telegram_id") or "").isdigit():
            out["telegram_id"] = person["telegram_id"]
    return out


def panel_directory(p, now=None, force=False):
    """
    Справочник {номер: {имя, telegram}} по всей панели, постранично.

    Целиком — потому что так дешевле. На ноде полторы сотни подключённых, и
    спрашивать про каждого отдельно значит сделать полторы сотни запросов;
    панель на шесть тысяч учётных записей укладывается в шесть страниц по
    тысяче. Из каждой записи оставляем три поля, остальные два десятка
    выбрасываем сразу: на ноде с 512 МБ памяти разница заметна.

    Зовёт это только отчёт, раз в сутки. Обычный поиск раздачи справочник
    целиком не трогает — нарушители редки, и про них спрашивают поимённо.
    """
    now = now if now is not None else time.time()
    if not force and _PANEL_DIR_CACHE["map"] \
            and now - _PANEL_DIR_CACHE["at"] < PANEL_DIR_TTL:
        return _PANEL_DIR_CACHE["map"]

    out, start = {}, 0
    for _ in range(PANEL_DIR_MAX_PAGES):
        page = panel_call(p, "GET",
                          "/api/users?start=%d&size=%d" % (start, PANEL_PAGE))
        users = page.get("users") or []
        for u in users:
            person = panel_person(u)
            if person:
                out[person["id"]] = person
        start += len(users)
        # Выходим по пустой странице и по счётчику total. По «страница короче
        # запрошенного» — намеренно нет: панель вправе отдать меньше, чем у неё
        # попросили, и тогда справочник оборвался бы на первой же странице.
        if not users or start >= int(page.get("total") or 0):
            break

    _PANEL_DIR_CACHE.update({"at": now, "map": out})
    return out


# ── отчёт по ноде ─────────────────────────────────────────────────────

def panel_report_rows(users, directory, p, now=None):
    """
    Кто подключён к ноде и с каких адресов. Возвращает (строки, всего адресов).

    Сортировка по числу одновременных адресов: самое интересное сверху, а
    самое интересное здесь — это как раз тот, у кого адресов слишком много.
    """
    now = now if now is not None else time.time()
    window = max(1, int(p.get("window_min") or 10)) * 60

    rows = []
    for u in users:
        fresh = sorted({ip for ip, ts in u["ips"] if ts and now - ts <= window})
        # Если свежих нет вовсе (например, панель не отдала время), показываем
        # что есть: пустая строка в отчёте бесполезна.
        shown = fresh or sorted({ip for ip, _ in u["ips"]})
        rows.append({"user_id": u["user_id"],
                     "label": panel_label(u["user_id"],
                                          directory.get(u["user_id"])),
                     "ips": shown, "count": len(fresh)})
    rows.sort(key=lambda r: (-r["count"], r["label"]))
    return rows, len({ip for r in rows for ip in r["ips"]})


def panel_report_text(cfg, rows, total_ips, now=None):
    """Полный текст отчёта. Он же уходит вложением, если не влез в сообщение."""
    p, tg = cfg["panel"], cfg["telegram"]
    now = now if now is not None else time.time()
    threshold = max(PANEL_MIN_THRESHOLD, int(p.get("ip_threshold") or 20))
    window = max(1, int(p.get("window_min") or 10))

    out = [t("pn_rep_head", node=node_label(tg),
             at=time.strftime("%Y-%m-%d %H:%M", time.localtime(now))),
           t("pn_rep_users", n=len(rows)),
           t("pn_rep_ips", n=total_ips),
           t("pn_rep_window", w=window), ""]
    for r in rows:
        mark = "  ⚠" if r["count"] >= threshold else ""
        out.append(f"{r['label']} — {r['count']}{mark}")
        out.extend("    " + ip for ip in r["ips"])
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def panel_report(cfg, now=None, force=False):
    """
    Отчёт по ноде: кто подключён и с каких адресов. Возвращает (успех, пояснение).

    force — для кнопки «отправить сейчас»: она работает и при выключенном
    расписании, лишь бы Telegram был настроен.
    """
    p = cfg["panel"]
    now = now if now is not None else time.time()
    if not force and not p.get("report"):
        return False, t("pn_rep_off")

    try:
        users = panel_fetch(p)
    except PanelError as e:
        return False, str(e)

    directory = {}
    if p.get("resolve"):
        try:
            directory = panel_directory(p, now)
        except PanelError as e:
            # Без имён отчёт всё равно полезен — уйдёт с номерами.
            print(f"panel report: {e}", flush=True)

    rows, total_ips = panel_report_rows(users, directory, p, now)
    body = panel_report_text(cfg, rows, total_ips, now)
    head = t("pn_rep_caption", node=node_label(cfg["telegram"]),
             users=len(rows), ips=total_ips)

    thread = str(p.get("report_thread_id") or "").strip() or None
    # Отчёт всегда файлом, даже когда он короткий.
    #
    # Раньше короткий уходил сообщением, длинный — вложением, и на разных
    # нодах один и тот же отчёт выглядел по-разному: где-то текст в ленте,
    # где-то файл. Сравнивать их между собой становилось неудобно, а на ноде,
    # которая подросла, форма менялась сама собой. Единообразие здесь важнее
    # экономии одного касания.
    name = "shape-%s-%s.txt" % (_safe_name(node_label(cfg["telegram"])),
                                time.strftime("%Y-%m-%d", time.localtime(now)))
    return tg_document(cfg, name, body.encode(), head, thread=thread,
                       mime="text/plain; charset=utf-8")


# ── Обвал клиентов: чья это беда ───────────────────────────────────────
#
# Нода не может сообщить о собственной смерти, но об исчезновении клиентов —
# вполне: она жива, а людей нет. Норму берём как медиану последнего часа,
# исключая самые свежие отсчёты: иначе начавшийся обвал сам опускал бы планку,
# по которой его оценивают. Маленькие ноды не проверяем — там ноль ничего не
# доказывает.
ONLINE_EVERY = 300              # как часто берём отсчёт, секунд
ONLINE_KEEP = 12                # сколько отсчётов держим — час
ONLINE_SKIP_FRESH = 2           # свежие в норму не берём
ONLINE_MIN_NORMAL = 10          # ниже этой нормы ноду не судим
ONLINE_COLLAPSE = 0.2           # доля от нормы, ниже которой это обвал
ONLINE_ALERT_EVERY = 3600       # не чаще раза в час


def cdn_verdict(cfg):
    """
    Спросить провайдера, доходят ли до его края клиенты.

    Возвращает готовую строку для сообщения или пустую, если спросить не
    вышло. Наружу не выпускает ничего: это украшение уведомления, а не
    условие его отправки.
    """
    c = cfg.get("cdn") or {}
    if not c.get("enabled"):
        return ""
    rid = str(c.get("resource_id") or "").strip()
    if not rid:
        return ""
    try:
        res = (cdn_call(c, "/v1/resources/" + rid) or {}).get("resource") or {}
        if str(res.get("status") or "") not in ("", "active"):
            return t("cdn_v_off", s=str(res.get("status")))

        aud = cdn_call(c, "/v1/resources/" + rid + "/audience") or {}
        seen = len(aud.get("top_ips") or [])

        st = cdn_call(c, "/v1/resources/" + rid + "/stats?hours=1") or {}
        reqs = 0
        for p in (st.get("points") or [])[-3:]:
            try:
                reqs += int(p.get("requests") or 0)
            except (TypeError, ValueError):
                pass
    except Exception:
        return ""

    # Опираемся на запросы, а не на список адресов: у ресурсов типа TCP
    # провайдер адреса не ведёт вовсе, и там всегда пусто. Сказать «клиентов
    # нет» на основании пустого списка означало бы врать при живом трафике.
    if not reqs and not seen:
        return t("cdn_v_empty")
    return t("cdn_v_alive", r=reqs)


def clients_watch(cfg, now=None):
    """
    Не пропали ли клиенты. Возвращает текущее число или -1, если не судим.

    Считаем по адресам, которые видит ядро: это те, кто прямо сейчас гонит
    трафик через ноду. Ошибок наружу не выпускает.
    """
    now = now if now is not None else time.time()
    state = guard_state()
    prev = state.get("online") or {}
    if now - float(prev.get("at") or 0) < ONLINE_EVERY:
        return -1

    n = len(read_users() or {})
    hist = [int(x) for x in (prev.get("hist") or []) if str(x).isdigit()]
    hist = (hist + [n])[-ONLINE_KEEP:]
    prev.update({"at": now, "hist": hist})
    state["online"] = prev
    guard_state_save(state)

    if len(hist) < ONLINE_KEEP:
        return -1
    base = sorted(hist[:-ONLINE_SKIP_FRESH])
    norm = base[len(base) // 2]
    if norm < ONLINE_MIN_NORMAL:
        return -1

    if n > norm * ONLINE_COLLAPSE:
        if prev.pop("alerted", None) is not None:
            state["online"] = prev
            guard_state_save(state)
        return n
    if now - float(prev.get("alerted") or 0) < ONLINE_ALERT_EVERY:
        return n

    prev["alerted"] = now
    state["online"] = prev
    guard_state_save(state)

    log_event("clients_gone", now=n, normal=norm)
    tail = cdn_verdict(cfg)
    tg_send(t("clients_msg", node=node_label(cfg["telegram"]), n=n, norm=norm)
            + (("\n\n" + tail) if tail else ""), cfg)
    return n


# ── Смена релея CDN ────────────────────────────────────────────────────
#
# Край CDN однажды переезжает на другой адрес — провайдер меняет узел, и
# предупредить об этом забывает. Новый адрес не значится в trusted.txt, а заголовок
# PROXY разбирается ТОЛЬКО для доверенных источников. Дальше происходит вот
# что: настоящие адреса клиентов не распознаются, весь трафик за CDN
# складывается в один адрес — сам релей, — и сотня человек делит один лимит
# на всех. Снаружи это выглядит как «интернет пропал», а в журнале тишина:
# нода здорова, Xray работает, ошибок нет.
#
# Признак чисто локальный, наружу нода не ходит. Заголовки разбираются —
# растёт pp_resolved. Перестали — весь прирост уходит в pp_unresolved, а
# pp_resolved стоит. Здоровая доля неразрешённых на живой ноде 8-10% (это
# рукопожатия новых соединений и служебный трафик релея), так что порог в
# 95% при остановившемся pp_resolved шумом не берётся.
RELAY_CHECK_EVERY = 300         # как часто сверяем, секунд
RELAY_MIN_PACKETS = 2000        # меньше — выборка ничего не значит
RELAY_BAD_SHARE = 0.95          # доля неразрешённых, выше которой это не шум
RELAY_ALERT_EVERY = 6 * 3600    # не чаще раза в шесть часов на один адрес


def _hex_ip(h):
    """Адрес из /proc/net/tcp. IPv4 — 8 знаков, IPv6 — 32, порядок обратный."""
    try:
        b = bytes.fromhex(h)
    except ValueError:
        return ""
    if len(b) == 4:
        return socket.inet_ntop(socket.AF_INET, b[::-1])
    if len(b) == 16:
        # Ядро хранит адрес четвёрками байт, каждая в обратном порядке.
        w = b"".join(b[i:i + 4][::-1] for i in range(0, 16, 4))
        if w[:12] == b"\x00" * 10 + b"\xff\xff":
            return socket.inet_ntop(socket.AF_INET, w[12:])
        return socket.inet_ntop(socket.AF_INET6, w)
    return ""


def proc_peers(ports):
    """Кто держит соединения на эти порты прямо сейчас: {адрес: сколько}."""
    out = {}
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f, None)
                for line in f:
                    p = line.split()
                    if len(p) < 4 or p[3] != "01":      # 01 — ESTABLISHED
                        continue
                    try:
                        if int(p[1].rsplit(":", 1)[1], 16) not in ports:
                            continue
                        ip = _hex_ip(p[2].rsplit(":", 1)[0])
                    except (ValueError, IndexError):
                        continue
                    if ip:
                        out[ip] = out.get(ip, 0) + 1
        except OSError:
            continue
    return out


def relay_watch(cfg, now=None):
    """
    Не сменился ли релей CDN. Возвращает адрес-подозреваемый или пустую строку.

    Наружу не ходит и ошибок не выпускает: это сторожевая проверка, она не
    имеет права уронить цикл. Работает только там, где CDN вообще есть, —
    то есть заданы порты с заголовком PROXY и хотя бы один доверенный релей.
    """
    now = now if now is not None else time.time()
    ports = {int(x) for x in (cfg.get("proxy_ports") or []) if str(x).isdigit()}
    if not ports:
        return ""
    trusted = {ip for ip, fl in trusted_sources().items() if fl & TRUST_RELAY}
    if not trusted:
        return ""

    st = read_stats()
    if not st:
        return ""

    state = guard_state()
    prev = state.get("relay") or {}
    at = float(prev.get("at") or 0)
    if now - at < RELAY_CHECK_EVERY:
        return ""

    dr = st["pp_resolved"] - int(prev.get("resolved") or 0)
    du = st["pp_unresolved"] - int(prev.get("unresolved") or 0)
    prev.update({"at": now, "resolved": st["pp_resolved"],
                 "unresolved": st["pp_unresolved"]})
    state["relay"] = prev
    guard_state_save(state)

    # Движок перезагрузили — счётчики начались заново, сравнивать нечего.
    if dr < 0 or du < 0 or dr + du < RELAY_MIN_PACKETS:
        return ""
    if du / float(dr + du) < RELAY_BAD_SHARE:
        return ""

    # Заголовки не разбираются. Кто же тогда к нам ходит на эти порты.
    unknown = {ip: n for ip, n in proc_peers(ports).items() if ip not in trusted}
    if not unknown:
        return ""
    ip = max(unknown, key=lambda k: unknown[k])

    # Про адрес, о котором ещё не писали, сообщаем сразу: сравнивать «сейчас
    # минус ноль» с паузой нельзя — это верно только потому, что время
    # большое число, и разваливается на любом другом отсчёте времени.
    alerted = prev.get("alerted") or {}
    last = alerted.get(ip)
    if last is not None and now - float(last) < RELAY_ALERT_EVERY:
        return ip
    alerted = {k: v for k, v in alerted.items()
               if now - float(v or 0) < RELAY_ALERT_EVERY * 4}
    alerted[ip] = now
    prev["alerted"] = alerted
    state["relay"] = prev
    guard_state_save(state)

    share = int(round(100 * du / float(dr + du)))
    log_event("relay_changed", ip=ip, share=share, conns=unknown[ip])
    tg_send(t("relay_msg", node=node_label(cfg["telegram"]), share=share,
              ports=", ".join(str(p) for p in sorted(ports)),
              ip=html.escape(ip), n=unknown[ip]), cfg)
    return ip


def panel_report_due(cfg, now=None):
    """
    Раз в цикл сторожа: не пора ли отправить отчёт по ноде.

    Правила те же, что у недельной копии: не раньше назначенного часа и не
    чаще раза в сутки. Нода была выключена и час прошёл — ждём завтра.
    Догонять пропущенный отчёт бессмысленно: он про то, кто подключён сейчас.
    """
    p = cfg["panel"]
    if not (p.get("enabled") and p.get("report")):
        return False
    now = now if now is not None else time.time()
    lt = time.localtime(now)
    h, m = parse_hhmm(p.get("report_at", "09:00"))
    if (lt.tm_hour, lt.tm_min) < (h, m):
        return False

    today = time.strftime("%Y-%m-%d", lt)
    state = panel_state()
    if state.get("report_sent") == today:
        return False
    if now < float(state.get("report_retry_at") or 0):
        return False

    ok, err = panel_report(cfg, now)
    state = panel_state()
    if ok:
        state["report_sent"] = today
        state.pop("report_retry_at", None)
    else:
        print(f"panel report: {err}", flush=True)
        state["report_retry_at"] = now + PANEL_RETRY
    panel_state_save(state)
    return ok


def panel_state():
    try:
        with open(PANEL_STATE) as f:
            s = json.load(f)
        return s if isinstance(s, dict) else {}
    except Exception:
        return {}


def panel_state_save(state):
    try:
        os.makedirs(VAR_DIR, exist_ok=True)
        tmp = PANEL_STATE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
        os.replace(tmp, PANEL_STATE)
    except OSError:
        pass


def panel_user_disable(p, uid):
    """Отключить подписку. Ошибку не глушим: молчаливый отказ здесь опасен."""
    panel_call(p, "POST", "/api/users/%s/actions/disable" % uid)


def panel_user_enable(p, uid):
    """Включить обратно."""
    panel_call(p, "POST", "/api/users/%s/actions/enable" % uid)


def panel_sharing_held(now=None):
    """
    Номера тех, кого прямо сейчас держит наше же перекрытие за раздачу.

    Нужно ровно для одного. Перекрытие само убирает нарушителя из видимости:
    трафика нет, lastSeen не обновляется, и за window_min его адреса выпадают
    из окна. Он перестаёт числиться нарушителем — и отсчёт до отключения
    подписки обнулялся, не доходя до конца НИКОГДА. Замерено 05.09: адреса
    стареют за десять минут, отсрочка в тридцать не наступала ни разу.

    Отмена отсчёта задумана для другого случая — когда владелец разобрался
    сам. Его и оставляем: снял штраф через `release --user`, переиздал
    подписку — запись уходит. А пока штраф жив, исчезновение из списка
    объясняется нами, и отсчёт продолжается.
    """
    now = now if now is not None else time.time()
    out = set()
    for _ip, e in (load_penalties() or {}).items():
        if not isinstance(e, dict):
            continue
        if e.get("source") != "panel" or e.get("reason") != "sharing":
            continue
        try:
            if float(e.get("until") or 0) <= now:
                continue
        except (TypeError, ValueError):
            continue
        uid = str(e.get("user_id")
                  or (e.get("subject") or {}).get("user_id") or "")
        if uid:
            out.add(uid)
    return out


def panel_pending(state, offenders, now, grace_sec, keep=()):
    """
    Кого пора отключать, и обновлённый список ожидающих.

    Ожидание живёт в состоянии панели и проверяется на каждом проходе, минуя
    паузу между срабатываниями: пауза управляет уведомлениями, а здесь речь о
    сроке, который владелец сам себе отвёл.

    Из ожидания выпадают те, кто нарушителем больше не числится. Это и есть
    отмена: успел владелец — отсчёт прекращается сам.

    Кроме тех, кто в `keep`: их держит наше собственное перекрытие, и их
    исчезновение из списка ничего про владельца не говорит. Новых записей
    для них не заводим — только не даём стереть уже начатый отсчёт.
    """
    live = {str(r["user_id"]) for r in offenders}
    held = {str(x) for x in keep}
    pend = {k: float(v) for k, v in (state.get("pending") or {}).items()
            if isinstance(v, (int, float, str)) and str(v).replace(".", "", 1)
            .replace("-", "", 1).isdigit() and (k in live or k in held)}
    for uid in live:
        pend.setdefault(uid, now)
    due = sorted(uid for uid, at in pend.items() if now - at >= grace_sec)
    return due, pend


def panel_drop(p, ips):
    """
    Обрыв соединений — точечно: только эти адреса и только на этой ноде.

    По адресам, а не по userIds: адреса у нас точные, а обрыв по пользователю
    выкинул бы его и с тех нод, где он ничего не нарушал. targetNodes тоже
    сужаем до своей ноды по той же причине.
    """
    ips = list(ips)
    if not ips:
        return
    panel_call(p, "POST", "/api/connections/drop", {
        "dropBy": {"by": "ipAddresses", "ipAddresses": ips},
        "targetNodes": {"target": "specificNodes",
                        "nodeUuids": [str(p.get("node_uuid") or "").strip()]}})


def panel_limit(p, ips, mbps=None, uid=None, person=None):
    """
    Локальный штраф на адреса нарушителя. Возвращает те, что реально урезаны.

    mbps задаётся явно только блокировкой; в обычном случае берётся из настроек.

    Режем только то, что нода видит сама: панель отдаёт и адреса, которые уже
    отвалились, а карта ядра — то, что есть сейчас. Белый список и уже
    выданные ограничения не трогаем: решение по ним принято раньше и, вполне
    возможно, человеком.
    """
    wl = whitelist_ips()
    known = set(read_users())
    pens = load_penalties()
    mbps = float(mbps if mbps is not None else (p.get("limit_mbps") or 1))
    minutes = max(1, int(p.get("limit_min") or 60))
    until = time.time() + minutes * 60

    done = []
    for ip in ips:
        if ip in wl or ip in pens or ip not in known:
            continue
        try:
            penalty_apply(ip, mbps, until)
        except Exception:
            continue
        entry = {"until": until, "mbps": mbps, "since": time.time(),
                 "source": "panel", "kind": "auto", "reason": "sharing"}
        # Номер пользователя в записи — чтобы потом снять ограничение со всех
        # его адресов разом. У перепродавца их полторы сотни, и снимать по
        # одному через меню невозможно физически.
        if uid:
            entry["user_id"] = str(uid)
            entry["subject"] = {"user_id": str(uid),
                                "label": (person or {}).get("name") or "",
                                "username": (person or {}).get("username") or ""}
        penalties_update(lambda pp, i=ip, e=entry: pp.__setitem__(i, e))
        log_event("limit_applied", ip=ip, source="panel", mbps=mbps,
                  minutes=minutes, reason="sharing")
        done.append(ip)
    return done


def tg_panel_disabled(cfg, uid, person, ips):
    """
    Подписка отключена автоматически. Сообщение обязано быть громким.

    Это единственное место, где Shape меняет что-то в панели, а не у себя.
    Человек, читающий его ночью или утром, должен сразу видеть, что
    произошло и как это отменить.
    """
    tg = cfg["telegram"]
    if not tg.get("enabled"):
        return
    who = {"label": (person or {}).get("name"),
           "handle": (person or {}).get("handle"),
           "username": (person or {}).get("username"),
           "tag": (person or {}).get("tag"),
           "telegram_id": (person or {}).get("telegram_id"),
           "user_id": str(uid)}
    lines = offender_card(tg, who, t("pn_off_head"))
    lines.append(t("pn_off_why", n=ips,
                   m=f"{cfg['panel'].get('disable_after_min', 0):g}"))
    lines.append("")
    lines.append(t("pn_off_how", id=html.escape(str(uid))))
    ok, err = tg_send("\n".join(lines), cfg)
    if not ok:
        print(f"telegram: {err}", flush=True)


def panel_notify(cfg, rec):
    """
    Карточка нарушителя в Telegram.

    Адресов у перепродавца бывают сотни, а в сообщении Telegram 4096 символов.
    Поэтому в тексте — первые двадцать, а полный список уходит следом файлом.
    Обрезать молча нельзя: список адресов и есть то, ради чего это писалось.
    """
    p, tg = cfg["panel"], cfg["telegram"]
    person = rec.get("person") or {}
    minutes = max(1, int(p.get("limit_min") or 60))

    lines = offender_card(tg, {"label": person.get("name"),
                               "handle": person.get("handle"),
                               "username": person.get("username"),
                               "telegram_id": person.get("telegram_id"),
                               "user_id": rec["user_id"]}, t("pn_msg_head"))
    lines.append(t("pn_msg_ips", n=rec["count"],
                   w=max(1, int(p.get("window_min") or 10))))
    if rec.get("by_tariff"):
        lines.append(t("pn_msg_tariff", t=rec.get("threshold", 0),
                       d=(rec.get("person") or {}).get("device_limit", 0)))

    # Показываем то, что под ограничением сейчас, а не прирост за проход.
    now_n = rec.get("limited_now", len(rec.get("limited") or []))
    if rec.get("blocked"):
        lines.append(t("pn_msg_blocked", n=now_n, m=minutes))
    elif rec.get("limited") or now_n:
        lines.append(t("pn_msg_limited", n=now_n,
                       mbps=p.get("limit_mbps", 1), m=minutes))
    if rec.get("dropped"):
        lines.append(t("pn_msg_dropped", n=len(rec["dropped"])))
    if not (rec.get("blocked") or rec.get("limited") or rec.get("dropped")):
        lines.append(t("pn_msg_nothing"))

    # Адреса — в сворачиваемой цитате. Она закрыта по умолчанию, поэтому не
    # растягивает ленту на сотню строк, но раскрывается касанием — файл
    # скачивать не нужно. В Bot API это entity expandable_blockquote,
    # в разметке HTML — <blockquote expandable>.
    #
    # Кладём столько адресов, сколько влезает в сообщение: раз список всё
    # равно свёрнут, показывать меньше, чем можно, смысла нет.
    head = "\n".join(lines)
    shown, rest = [], list(rec["ips"])
    room = PANEL_MSG_LIMIT - len(head)
    while rest and room - (len(rest[0]) + 1) > 0:
        room -= len(rest[0]) + 1
        shown.append(rest.pop(0))

    if shown:
        head += ("\n\n<blockquote expandable>"
                 + html.escape("\n".join(shown)) + "</blockquote>")
    extra = len(rest)
    if extra > 0:
        head += "\n" + t("pn_msg_more", n=extra)
    tg_send(head, cfg)

    if extra > 0:
        who = panel_label(rec["user_id"], rec.get("person"))
        # Шапка внутри файла — чтобы вложение оставалось понятным само по
        # себе: его пересылают и открывают отдельно от сообщения.
        head = [who]
        if (rec.get("person") or {}).get("username"):
            head.append(t("pn_card_login_plain",
                          login=rec["person"]["username"]))
        head += [t("pn_card_panel_plain", id=rec["user_id"]),
                t("pn_rep_head", node=node_label(tg),
                  at=time.strftime("%Y-%m-%d %H:%M")), ""]
        body = "\n".join(head + list(rec["ips"])) + "\n"
        fname = "shape-sharing-%s-%s.txt" % (
            _safe_name(rec["user_id"]), time.strftime("%Y-%m-%d"))
        ok, err = tg_document(cfg, fname, body.encode(),
                              t("pn_msg_file", user=html.escape(who),
                                n=len(rec["ips"])),
                              mime="text/plain; charset=utf-8")
        if not ok:
            print(f"panel notify: {err}", flush=True)


def panel_warn_token(cfg, detail):
    """Панель отказала в доступе — сказать об этом один раз, а не каждый цикл."""
    state = panel_state()
    if state.get("denied_warned"):
        return
    state["denied_warned"] = True
    panel_state_save(state)
    tg_send(t("pn_denied_msg", node=node_label(cfg["telegram"]),
              detail=html.escape(str(detail)[:200])), cfg)


def panel_token_check(cfg, now=None):
    """
    Предупреждение об истечении токена — один раз на токен.

    Считается из самого токена, запрос к панели не нужен. Смысл простой: без
    этого функция однажды замолчала бы разом на всех нодах, и владелец узнал
    бы об этом только по тому, что нарушители перестали находиться.
    """
    p = cfg["panel"]
    if not p.get("enabled"):
        return False
    exp = token_expiry(p.get("token"))
    if not exp:
        return False
    now = now if now is not None else time.time()
    if exp - now > PANEL_TOKEN_WARN:
        return False
    state = panel_state()
    if state.get("token_warned") == int(exp):
        return False
    state["token_warned"] = int(exp)
    panel_state_save(state)
    # Округляем вверх: до истечения двое с половиной суток — это «через 3 дня»,
    # а не «через 2». Занижать срок в предупреждении незачем.
    tg_send(t("pn_token_soon", node=node_label(cfg["telegram"]),
              days=max(0, int((exp - now + 86399) // 86400))), cfg)
    return True


def panel_scan(cfg, now=None, act=True):
    """
    Один проход: спросить панель, найти нарушителей, выполнить действия.

    Исключений наружу не выпускает. Нас зовут из цикла сторожа, и недоступная
    панель не должна останавливать всё остальное — возвращаем сводку с
    пометкой об ошибке, а решение, что с ней делать, принимает вызывающий.
    """
    p = cfg["panel"]
    now = now if now is not None else time.time()
    try:
        users = panel_fetch(p)
    except PanelError as e:
        return {"ok": False, "error": str(e), "code": e.code,
                "users": 0, "offenders": []}
    except Exception as e:
        # Ловим всё, а не только PanelError. Живой случай: панель молчала три
        # часа, `panel show` показывал последний успешный опрос и НИ СЛОВА об
        # ошибке — потому что не-PanelError улетал наружу, в общий обработчик
        # цикла сторожа, и оседал в журнале строкой «watch: ...». Причина
        # была, узнать её было негде.
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "code": 0,
                "users": 0, "offenders": []}

    # Побочный, но полезный итог опроса: карта «адрес → чей он». Стоила она
    # ноль запросов — данные уже пришли, — а сторожу позволяет подписать штраф
    # именем, а не голым адресом.
    _PANEL_IP_OWNER.update(
        {"at": now,
         "map": {ip: u["user_id"] for u in users for ip, _ in u["ips"]}})

    # Насколько далеко назад видит нода. Ответа на это нет ни в документации
    # панели, ни в переменных окружения: список соединений — живой снимок из
    # Xray, и срок жизни записи определяет он. Зато он измеряется, и разница
    # между «окно 10 минут» и тем, что нода помнит три, решает всё.
    ages = [now - ts for u in users for _ip, ts in u["ips"] if ts]
    if ages:
        st = panel_state()
        st["seen_oldest"] = int(max(ages))
        st["seen_at"] = now
        panel_state_save(st)

    found = panel_offenders(users, p, now)
    res = {"ok": True, "error": "", "code": 0,
           "users": len(users), "offenders": found}
    # Сколько нарушителей на ЭТОМ опросе. Метрика раньше отдавала len(seen), а
    # seen — учёт пауз между сигналами, записи в нём живут до двух суток: после
    # единственного срабатывания график держал единицу двое суток.
    st_found = panel_state()
    st_found["last_found"] = len(found)
    panel_state_save(st_found)
    if not act:
        return res

    actions = panel_actions(p)
    state = panel_state()
    seen = state.get("seen") or {}
    cooldown = max(0, int(p.get("cooldown_min") or 0)) * 60

    # Отсрочка на отключение подписки. Считается до всего остального и минуя
    # паузу между срабатываниями: пауза про уведомления, а здесь про срок,
    # который владелец сам себе отвёл.
    grace = max(0, float(p.get("disable_after_min") or 0)) * 60
    if grace:
        # Исключённых в ожидание не берём вовсе.
        live = [r for r in found
                if not guard_exempt(cfg, {"user_id": r["user_id"]})]
        due, pend = panel_pending(state, live, now, grace,
                                  keep=panel_sharing_held(now))
        state["pending"] = pend
        panel_state_save(state)

        # Потолок на проход. Если панель однажды отдаст мусор и в нарушители
        # попадут сотни, автоматика их не отключит — только сообщит. Ошибка
        # такого рода стоит слишком дорого, чтобы надеяться, что её не будет.
        if len(due) > PANEL_DISABLE_MAX:
            res["disable_refused"] = len(due)
            log_event("panel_disable_refused", n=len(due))
            due = []

        for uid in due:
            rec = next((r for r in live if str(r["user_id"]) == uid), None)
            person = panel_user(p, uid)
            # Тег проверяем здесь, а не при наборе `live`: тег живёт в карточке,
            # а её до этого места не запрашивали — иначе на каждом проходе ушёл
            # бы запрос за каждого кандидата. Без этой проверки исключение по
            # тегу защищало от ограничения и обрыва, но НЕ от отключения
            # подписки: в guard_exempt выше уходит только номер, без тега.
            # Отключение — самое дорогое действие, и деловой аккаунт, помеченный
            # в панели, обязан быть защищён и от него.
            if guard_exempt(cfg, {"user_id": uid,
                                  "tag": (person or {}).get("tag")}):
                pend.pop(uid, None)
                state["pending"] = pend
                panel_state_save(state)
                if rec is not None:
                    rec["skipped"] = True
                log_event("panel_exempt", user_id=uid, stage="disable")
                continue
            try:
                panel_user_disable(p, uid)
            except PanelError as e:
                log_event("panel_disable_failed", user_id=uid, error=str(e))
                res.setdefault("disable_errors", []).append(str(e))
                continue
            pend.pop(uid, None)
            state["pending"] = pend
            panel_state_save(state)
            if rec is not None:
                rec["disabled"] = True
            log_event("panel_disabled", user_id=uid,
                      ips=len(rec.get("ips") or []) if rec else 0,
                      subject=(person or {}).get("name"))
            tg_panel_disabled(cfg, uid, person,
                              len(rec.get("ips") or []) if rec else 0)

    for rec in found:
        rec.setdefault("limited", [])
        rec.setdefault("dropped", [])
        rec.setdefault("blocked", False)
        # Кулдаун: один и тот же перепродавец не должен приходить в Telegram
        # каждые пять минут — иначе уведомления перестают читать.
        if now - float(seen.get(rec["user_id"]) or 0) < cooldown:
            rec["skipped"] = True
            continue
        seen[rec["user_id"]] = now
        # Имя спрашиваем поимённо и только про нарушителя: тянуть ради этого
        # весь справочник в шесть тысяч записей каждые пять минут незачем.
        rec["person"] = panel_user(p, rec["user_id"])

        # Порог от тарифа — второй этап. Базовый работает пре-фильтром: он
        # только нижняя граница, поэтому кандидат, у которого тариф на
        # пятнадцать устройств, сюда дойдёт и отсеется здесь. Спрашивать
        # тариф у всех шести тысяч ради этого не надо.
        rec["threshold"], from_tariff = panel_threshold(p, rec.get("person"))
        rec["by_tariff"] = from_tariff
        if rec["count"] < rec["threshold"]:
            rec["skipped"] = True
            log_event("panel_under_tariff", user_id=rec["user_id"],
                      ips=rec["count"], threshold=rec["threshold"])
            continue

        # Тег проверяем здесь, а не в panel_offenders: там карточка ещё не
        # запрошена, а тянуть её ради каждого пользователя панели — шесть
        # тысяч запросов вместо одного на нарушителя.
        if guard_exempt(cfg, {"user_id": rec["user_id"],
                              "tag": (rec["person"] or {}).get("tag")}):
            rec["skipped"] = True
            log_event("panel_exempt", user_id=rec["user_id"],
                      ips=len(rec.get("ips") or []),
                      subject=(rec["person"] or {}).get("name"))
            continue

        # Блокировка старше обычного ограничения: если задано и то и другое,
        # выигрывает более строгое. Обрыв к ней НЕ прилагается: лимит лежит в
        # карте ядра по адресу и придавливает уже открытые соединения сразу,
        # а обрыв стёр бы сессии из панели — владелец, пришедший по
        # уведомлению, увидел бы пустую карточку вместо адресов и нод.
        if "block" in actions:
            rec["blocked"] = True
            rec["limited"] = panel_limit(p, rec["ips"], PANEL_BLOCK_MBPS,
                                         rec["user_id"], rec.get("person"))
        elif "limit" in actions:
            rec["limited"] = panel_limit(p, rec["ips"], None,
                                         rec["user_id"], rec.get("person"))
        # Сколько его адресов под ограничением ПРЯМО СЕЙЧАС, а не сколько
        # добавилось этим проходом. На повторном срабатывании все они уже
        # перекрыты, добавлять нечего, и в сообщение уходило «адресов: 0» —
        # будто ничего не сделано, хотя перекрытие держится.
        pens_now = load_penalties()
        rec["limited_now"] = sum(1 for ip in rec["ips"] if ip in pens_now)

        # Обрыв — только по явному указанию. Раньше его тянуло за собой
        # перекрытие, и это вредило дважды. Во-первых, он не нужен: лимит
        # лежит в карте ядра по адресу и действует на уже открытые соединения
        # немедленно, рвать их незачем. Во-вторых, он стирает картину: сессии
        # пропадают из панели, и владелец, открыв карточку человека, видит
        # пустоту вместо адресов и нод. А смотреть он идёт именно тогда, когда
        # пришло уведомление. Заодно исчезновение адресов обнуляло отсчёт до
        # отключения подписки.
        if "drop" in actions:
            try:
                panel_drop(p, rec["ips"])
                rec["dropped"] = list(rec["ips"])
            except PanelError as e:
                print(f"panel drop: {e}", flush=True)
        log_event("sharing_found", source="panel", user_id=rec["user_id"],
                  ips=rec["count"], limited=len(rec["limited"]),
                  dropped=len(rec["dropped"]))
        if "notify" in actions:
            panel_notify(cfg, rec)

    # Файл не должен расти вечно: забываем тех, кого давно не видели.
    keep = max(cooldown, 86400) * 2
    state["seen"] = {k: v for k, v in seen.items()
                     if now - float(v or 0) < keep}
    state["last_ok"] = now
    state["last_users"] = len(users)
    state["last_error"] = ""
    state.pop("retry_at", None)
    state.pop("denied_warned", None)
    panel_state_save(state)
    return res


def panel_due(cfg, now=None):
    """
    Раз в цикл сторожа: не пора ли спросить панель.

    Отметку о запуске ставим до самого запроса. Если панель отвечает медленно
    или нода перезапустилась в неудачный момент, это не должно превратиться в
    поток запросов — лучше пропустить проход.
    """
    p = cfg["panel"]
    if not p.get("enabled"):
        return False
    now = now if now is not None else time.time()

    state = panel_state()
    if now < float(state.get("retry_at") or 0):
        return False
    if now - float(state.get("last_run") or 0) < max(60, int(p.get("interval") or 300)):
        return False
    state["last_run"] = now
    panel_state_save(state)

    panel_token_check(cfg, now)
    res = panel_scan(cfg, now)
    if not res["ok"]:
        print(f"panel: {res['error']}", flush=True)
        state = panel_state()
        state["last_error"] = res["error"]
        state["retry_at"] = now + PANEL_RETRY
        panel_state_save(state)
        if res.get("code") in (401, 403):
            panel_warn_token(cfg, res["error"])
    return res["ok"]


def cmd_panel(a):
    cfg = load_config()
    p = cfg["panel"]

    if a.action == "show":
        exp = token_expiry(p.get("token"))
        if not p.get("token"):
            when = "—"
        elif not exp:
            when = t("pn_token_none")
        elif exp <= time.time():
            when = f"{C['red']}{t('pn_token_gone')}{C['r']}"
        else:
            when = time.strftime("%Y-%m-%d", time.localtime(exp))
        st = panel_state()
        last = float(st.get("last_ok") or 0)
        oldest = st.get("seen_oldest")
        print()
        print(f"  {t('pn_state')}  : " + (f"{C['grn']}{t('guard_on')}{C['r']}"
              if p["enabled"] else f"{C['gry']}{t('guard_off')}{C['r']}"))
        print(f"  {t('pn_url')}   : {p['url'] or '—'}")
        print(f"  {t('pn_uuid')}  : {p['node_uuid'] or '—'}")
        print(f"  {t('pn_token_exp')} : {when}")
        print(f"  {t('pn_every')}  : {p['interval']} {t('pn_sec')}")
        print(f"  {t('pn_thr')}    : {p['ip_threshold']} / {p['window_min']} {t('pn_min')}")
        print(f"  {t('pn_act')}    : {p['action']}")
        print(f"  {t('pn_cool')}   : {p['cooldown_min']} {t('pn_min')}")
        if p.get("report"):
            print(f"  {t('pn_rep_state')} : {C['grn']}{p.get('report_at', '09:00')}{C['r']}"
                  + (f"  · {t('tg_thread')} {p['report_thread_id']}"
                     if str(p.get("report_thread_id") or "").strip() else ""))
        else:
            print(f"  {t('pn_rep_state')} : {C['gry']}{t('guard_off')}{C['r']}")
        print(f"  {t('pn_resolve')} : "
              + (t("guard_on") if p.get("resolve") else t("guard_off")))
        if p.get("exempt"):
            print(f"  {t('pn_exempt')} : {', '.join(p['exempt'])}")
        if p.get("exempt_tags"):
            print(f"  {t('pn_exempt_tags')} : {', '.join(p['exempt_tags'])}")
        if p.get("per_device"):
            pd = t("pn_per_device_v", k=f"{p['per_device']:g}")
            print(f"  {t('pn_per_device')} : {pd}")
        if p.get("disable_after_min"):
            print(f"  {t('pn_disable_after')} : "
                  f"{C['red']}{p['disable_after_min']:g} {t('pn_min')}{C['r']}")
            # Отсчёт держится, пока жив наш штраф: перекрытие само убирает
            # нарушителя из видимости. Отсрочка длиннее перекрытия означает,
            # что штраф истечёт раньше срока и отсчёт оборвётся молча.
            if float(p["disable_after_min"]) >= float(p.get("limit_min") or 60):
                print(f"    {C['yel']}"
                      f"{t('pn_grace_long', m=p.get('limit_min', 60))}{C['r']}")
        print(f"  {t('pn_last')} : " + (time.strftime("%Y-%m-%d %H:%M",
              time.localtime(last)) if last else t("pn_never")))
        if last:
            seen_n = int(st.get("last_users") or 0)
            col = C["red"] if not seen_n else ""
            print(f"  {t('pn_seen')} : {col}{seen_n}{C['r']}")
            if not seen_n:
                print(f"    {C['gry']}{t('pn_seen_none')}{C['r']}")
        if p.get("node_uuid") and not valid_uuid(p["node_uuid"]):
            print(f"  {C['red']}⚠ {t('pn_bad_uuid')}{C['r']}")
        if oldest is not None:
            print(f"  {t('pn_oldest')} : {fmt_hold(int(oldest))}")
            if int(oldest) < 60 * max(1, int(p.get("window_min") or 10)):
                print(f"    {C['yel']}"
                      f"{t('pn_oldest_short', w=p.get('window_min', 10))}"
                      f"{C['r']}")
        if st.get("last_error"):
            print(f"  {t('pn_last_err')} : {C['red']}{st['last_error']}{C['r']}")
        print()
        return

    if a.action == "set":
        if a.url is not None:
            url = a.url.strip().rstrip("/")
            if url and not url.startswith(("http://", "https://")):
                die(t("pn_bad_url"))
            p["url"] = url
        if a.token is not None:
            p["token"] = a.token.strip()
        if a.node_uuid is not None:
            v = a.node_uuid.strip()
            # UUID проверяем по форме. Панель на неправильный принимает запрос
            # и отвечает пустым результатом — опрос считается успешным, карта
            # адресов остаётся пустой, и имена молча перестают подставляться.
            # Поймать это потом можно только вручную, поэтому ловим здесь.
            if v and not valid_uuid(v):
                die(t("pn_bad_uuid"))
            p["node_uuid"] = v
        if a.proxy is not None:
            p["proxy"] = a.proxy.strip()
        if a.interval is not None:
            p["interval"] = max(60, a.interval)
        if a.window is not None:
            p["window_min"] = max(1, a.window)
        if a.threshold is not None:
            p["ip_threshold"] = max(PANEL_MIN_THRESHOLD, a.threshold)
        if a.action_set is not None:
            want = {w.strip().lower() for w in a.action_set.replace(";", ",").split(",")
                    if w.strip()}
            if not want or want - set(PANEL_ACTIONS):
                die(t("pn_bad_action"))
            p["action"] = ",".join(x for x in PANEL_ACTIONS if x in want)
        if a.mbps is not None:
            p["limit_mbps"] = max(0.1, a.mbps)
        if a.minutes is not None:
            p["limit_min"] = max(1, a.minutes)
        if a.cooldown is not None:
            p["cooldown_min"] = max(0, a.cooldown)
        if a.exempt is not None:
            p["exempt"] = [w.strip() for w in a.exempt.split(",") if w.strip()]
        if a.per_device is not None:
            if not 0 <= a.per_device <= 100:
                die(t("guard_range", k="per_device", lo=0, hi=100))
            p["per_device"] = a.per_device
        if a.disable_after is not None:
            if not 0 <= a.disable_after <= 1440:
                die(t("guard_range", k="disable_after_min", lo=0, hi=1440))
            p["disable_after_min"] = a.disable_after
        if a.exempt_tags is not None:
            p["exempt_tags"] = [w.strip() for w in a.exempt_tags.split(",")
                                if w.strip()]
        if a.report is not None:
            p["report"] = a.report == "on"
        if a.report_at is not None:
            v = a.report_at.strip()
            if parse_hhmm(v, None) is None:
                die(t("tg_bad_time"))
            p["report_at"] = "%02d:%02d" % parse_hhmm(v)
        if a.report_thread is not None:
            p["report_thread_id"] = a.report_thread.strip()
        if a.resolve is not None:
            p["resolve"] = a.resolve == "on"
        if a.enable:
            p["enabled"] = True
        if a.disable:
            p["enabled"] = False
        save_config({"panel": p})
        log_event("config_changed", source="cli", section="panel")
        return cmd_panel(argparse.Namespace(**{**vars(a), "action": "show"}))

    if a.action in ("enable", "disable"):
        uid = str(a.ip or "").strip().lstrip("#")
        if not uid.isdigit():
            die(t("pn_need_id"))
        if not p.get("enabled"):
            die(t("pn_off"))
        try:
            if a.action == "enable":
                panel_user_enable(p, uid)
            else:
                panel_user_disable(p, uid)
        except PanelError as e:
            die(str(e))
        key = "pn_enabled_ok" if a.action == "enable" else "pn_disabled_ok"
        # Из ожидания вычёркиваем: решение принято человеком.
        st = panel_state()
        (st.get("pending") or {}).pop(uid, None)
        panel_state_save(st)
        log_event("panel_user_" + a.action, user_id=uid, source="cli")
        print(f"\n  {C['grn']}✓ {t(key, id=uid)}{C['r']}\n")
        return

    if a.action == "user":
        # Обратный ход к `who`: там адрес → человек, здесь человек → адреса.
        #
        # Нужен для сверки с отчётами бота. Бот берёт числа у панели, а панель
        # не хранит «вверх» и «вниз» отдельно — в её отчёте «123 ГБ за сутки»
        # это сумма обоих направлений, и по ней нельзя отличить закачку от
        # раздачи. Shape эти числа знает, не хватало только связи между
        # номером пользователя и его адресами.
        uid = str(a.ip or "").strip().lstrip("#")
        if not uid.isdigit():
            die(t("pn_user_need_id"))
        if not p.get("enabled"):
            die(t("pn_off"))
        print(f"\n  {t('pn_scanning')}", flush=True)
        try:
            users = panel_fetch(p)
        except PanelError as e:
            die(str(e))

        rec = next((u for u in users if str(u["user_id"]) == uid), None)
        person = panel_user(p, uid)
        print()
        print(f"  {C['b']}{panel_label(uid, person)}{C['r']}")
        if person and person.get("username"):
            print(f"  {C['gry']}"
                  f"{t('pn_card_login_plain', login=person['username'])}"
                  f"{C['r']}")
        if person and person.get("tag"):
            print(f"  {C['gry']}{t('pn_user_tag')}: {person['tag']}{C['r']}")
        if not rec:
            print(f"\n  {C['yel']}{t('pn_user_none', n=len(users))}{C['r']}\n")
            return

        ips = sorted({ip for ip, _ in rec["ips"]})
        print(f"  {t('pn_user_ips')}: {C['b']}{len(ips)}{C['r']}\n")

        # Счётчики берём свои, суточные: у панели их нет ни в каком виде.
        daily = load_daily()
        for ip in ips:
            d = daily.get(ip) or {}
            down, up = d.get("down", 0), d.get("up", 0)
            if not (down or up):
                print(f"  {ip:<18}{C['gry']}{t('pn_user_noday')}{C['r']}")
                continue
            pct = f" ({up * 100 / down:.0f}%)" if down else ""
            print(f"  {ip:<18}↓ {fmt_bytes(down)} · ↑ {fmt_bytes(up)}{pct}")
            # Часы печатает следующая строка своей подписью — здесь они
            # выключены, иначе одно число выходит дважды.
            pk, _win = penalty_packets(d, hours=False)
            extra = []
            if pk:
                extra.append(re.sub(r"<[^>]+>", "", pk))
            if d.get("up_sec"):
                extra.append(t("pn_user_uphours",
                               h=f"{d['up_sec'] / 3600:.1f}"))
            if extra:
                print(f"  {'':<18}{C['gry']}{' · '.join(extra)}{C['r']}")
        print()
        return

    if a.action == "who":
        # Спрашиваем панель заново, а не берём карту из памяти: она живёт в
        # процессе сторожа, а здесь отдельный запуск, и там пусто.
        ip = valid_ip(a.ip or "")
        if not ip:
            die(t("bad_ip", ip=a.ip or ""))
        print(f"\n  {t('pn_scanning')}", flush=True)
        try:
            users = panel_fetch(p)
        except PanelError as e:
            die(str(e))

        hit = None
        for u in users:
            for addr, ts in u["ips"]:
                if addr == ip:
                    hit = (u["user_id"], ts)
                    break
            if hit:
                break

        if not hit:
            print(f"  {C['yel']}{t('pn_who_none', ip=ip, n=len(users))}{C['r']}")
            print(f"    {C['gry']}{t('pn_who_hint')}{C['r']}\n")
            return 1

        uid, ts = hit
        person = panel_user(p, uid)
        print(f"  {C['grn']}✓{C['r']} {t('pn_who_found', ip=ip)}")
        print(f"      {t('pn_card_panel_plain', id=uid)}")
        if person and person.get("username"):
            print(f"      {t('pn_card_login_plain', login=person['username'])}")
        if person and (person.get("name") or person.get("handle")):
            who = " · ".join(x for x in (person.get("name"),
                                         person.get("handle")) if x)
            print(f"      {t('pn_who_name')}: {C['b']}{who}{C['r']}")
        if person and person.get("telegram_id"):
            print(f"      Telegram: {C['b']}{person['telegram_id']}{C['r']}")
        if not person:
            print(f"      {C['yel']}{t('pn_who_noname')}{C['r']}")
        if ts:
            print(f"      {C['gry']}{t('pn_who_seen')}: "
                  f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))}{C['r']}")
        print()
        return

    if a.action == "report":
        # force: кнопка «отправить сейчас» работает и при выключенном
        # расписании — иначе проверить настройку было бы нечем.
        if not a.json:
            print(f"\n  {t('pn_scanning')}", flush=True)
        ok, err = panel_report(cfg, force=True)
        if not ok:
            die(err)
        print(f"  {C['grn']}✓{C['r']} {t('pn_rep_sent')}\n")
        return

    # test и scan отличаются одним: test ничего не меняет и ничего не шлёт,
    # он нужен, чтобы проверить адрес, токен и UUID до включения.
    dry = a.dry_run or a.action == "test"
    if not a.json:
        print(f"\n  {t('pn_scanning')}", flush=True)
    res = panel_scan(cfg, act=not dry)

    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res["ok"] else 1
    if not res["ok"]:
        die(res["error"])

    known = set(read_users()) if res["offenders"] else set()
    print(f"  {C['grn']}✓{C['r']} {t('pn_scan_ok', n=res['users'])}")
    if not res["offenders"]:
        print(f"  {t('pn_scan_none')}\n")
        return
    print(f"  {C['red']}{t('pn_scan_found', n=len(res['offenders']))}{C['r']}")
    for rec in res["offenders"]:
        here = len([x for x in rec["ips"] if x in known])
        print(t("pn_scan_row", user=rec["user_id"], n=rec["count"], here=here))
    if dry:
        print(f"  {C['gry']}{t('pn_dry')}{C['r']}")
    print()


def cmd_telegram(a):
    cfg = load_config()
    tg = cfg["telegram"]
    if a.action == "show":
        print()
        state = f"{C['grn']}{t('guard_on')}{C['r']}" if tg["enabled"] \
            else f"{C['gry']}{t('guard_off')}{C['r']}"
        print(f"  {t('tg_state')}   : {state}")
        print(f"  {t('tg_node')}    : {node_label(tg)}")
        print(f"  {t('tg_chat')}    : {tg['chat_id'] or '—'}"
              f"{'  · ' + t('tg_thread') + ' ' + str(tg['thread_id']) if tg['thread_id'] else ''}")
        print(f"  {t('tg_proxy')}   : {tg['proxy'] or t('tg_direct')}")

        # События и сводка — отдельные переключатели, и выключенные они
        # молчат: штрафы выдаются, а сообщений нет. Раньше их не было видно
        # на этом экране вообще, и «почему не приходит» превращалось в
        # угадайку. Выключенные события подсвечиваем: именно они отвечают за
        # сообщения о штрафах, ради которых Telegram обычно и включают.
        if tg.get("events"):
            print(f"  {t('tg_ev')}  : {C['grn']}{t('guard_on')}{C['r']}")
        else:
            print(f"  {t('tg_ev')}  : {C['yel']}{t('guard_off')}{C['r']}"
                  f"  {C['gry']}{t('tg_ev_off_hint')}{C['r']}")
        print(f"  {t('tg_dg')}  : "
              + (t("guard_on") if tg.get("daily") else t("guard_off")))
        print(f"  {t('tg_at')}   : {tg.get('digest_at', '09:00')}")
        if tg.get("backup"):
            day = t("dow%d" % max(1, min(7, int(tg.get("backup_day", 1) or 1))))
            extra = ""
            if str(tg.get("backup_thread_id") or "").strip():
                extra = f"  · {t('tg_bk_thread')} {tg['backup_thread_id']}"
            print(f"  {t('tg_bk_state')}   : {C['grn']}"
                  f"{t('tg_bk_when', day=day, at=tg.get('digest_at', '09:00'))}"
                  f"{C['r']}{extra}")
        else:
            print(f"  {t('tg_bk_state')}   : {C['gry']}{t('guard_off')}{C['r']}")
        print()
        return
    if a.action == "test":
        ok, err = tg_send(
            f"🦨 <b>{node_label(tg)}</b>\n{t('tg_test_text')}", cfg, force=True)
        print(f"{C['grn']}✓ {t('tg_sent')}{C['r']}" if ok
              else f"{C['red']}✗ {err}{C['r']}")
        return
    if a.action == "backup":
        ok, err = tg_backup(cfg, force=True)
        print(f"{C['grn']}✓ {t('bk_tg_sent')}{C['r']}" if ok
              else f"{C['red']}✗ {err}{C['r']}")
        return
    if a.action == "digest":
        # Сводка по горячим следам: сторож пишет daily.json раз в минуту.
        snap = load_daily()
        if not snap:
            print(f"{C['gry']}{t('tg_no_data')}{C['r']}")
            return
        ok, err = tg_send(digest_text(cfg, time.strftime("%Y-%m-%d"), snap,
                                      partial=True), cfg, force=True)
        print(f"{C['grn']}✓ {t('tg_sent')}{C['r']}" if ok
              else f"{C['red']}✗ {err}{C['r']}")
        return
    # set
    if a.at is not None:
        v = a.at.strip()
        if parse_hhmm(v, None) is None:
            die(t("tg_bad_time"))
        tg["digest_at"] = "%02d:%02d" % parse_hhmm(v)
    if a.proxy is not None:
        p = a.proxy.strip()
        # MTProto-прокси из ссылки t.me/proxy умеет только протокол мессенджера.
        # Bot API — обычный HTTPS, через такой прокси он не пройдёт.
        if p and ("t.me/proxy" in p or "secret=" in p or p.startswith("tg://")):
            die(t("tg_mtproto") + "\n  " + t("tg_mtproto2") + "\n  " + t("tg_mtproto3"))
        if p and not p.startswith(("socks5://", "socks5h://", "http://", "https://")):
            die(t("tg_proxy_scheme"))
        # Адрес прокси уходит в socket.create_connection и в ProxyHandler.
        # Мусор вместо хоста или порта должен отсекаться здесь, а не всплывать
        # исключением внутри сторожа раз в десять секунд.
        if p:
            try:
                u = urllib.parse.urlsplit(p)
                if not u.hostname or (u.port is not None and not 1 <= u.port <= 65535):
                    raise ValueError
            except ValueError:
                die(t("tg_bad_proxy"))

    # Токен уходит прямо в путь URL: /bot<TOKEN>/sendMessage. Символ «/» или
    # пробел в нём увёл бы запрос на другой метод API, поэтому формат строгий.
    if a.token is not None and a.token.strip() \
            and not re.fullmatch(r"\d{5,}:[A-Za-z0-9_-]{20,}", a.token.strip()):
        die(t("tg_bad_token_fmt"))
    if a.chat is not None and a.chat.strip() \
            and not re.fullmatch(r"-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31}", a.chat.strip()):
        die(t("tg_bad_chat_fmt"))
    if a.thread is not None and a.thread.strip() \
            and not re.fullmatch(r"\d{1,19}", a.thread.strip()):
        die(t("tg_bad_thread_fmt"))
    if a.backup_thread is not None and a.backup_thread.strip() \
            and not re.fullmatch(r"\d{1,19}", a.backup_thread.strip()):
        die(t("tg_bad_thread_fmt"))
    if a.backup_day is not None and not 1 <= a.backup_day <= 7:
        die(t("tg_bad_day"))
    if a.name is not None and len(a.name.strip()) > 64:
        die(t("tg_name_long"))

    for key, val in (("token", a.token), ("chat_id", a.chat), ("thread_id", a.thread),
                     ("node_name", a.name), ("proxy", a.proxy),
                     ("backup_thread_id", a.backup_thread)):
        if val is not None:
            tg[key] = val.strip()
    if a.backup_day is not None:
        tg["backup_day"] = int(a.backup_day)
    if a.backup is not None:
        tg["backup"] = a.backup == "on"
    if a.enable:
        tg["enabled"] = True
    if a.disable:
        tg["enabled"] = False
    if a.events is not None:
        tg["events"] = a.events == "on"
    if a.updates is not None:
        tg["updates"] = a.updates == "on"
    if a.daily is not None:
        tg["daily"] = a.daily == "on"
    cfg["telegram"] = tg
    save_config(cfg)
    if not a.quiet:
        cmd_telegram(argparse.Namespace(action="show"))


# ────────────────────────────── whitelist ──────────────────────────────

def ip_key(ip_str):
    ip = ipaddress.ip_address(ip_str)
    return ip.packed + b"\x00" * 12 if ip.version == 4 else ip.packed



# ────────────────────────── факты о ноде ──────────────────────────
# Ими пользуются и метрики, и API: имя интерфейса, версия, состояние
# движка и сервисов. Здесь они без кэша — кэширует тот, кому это нужно.

# ────────────── кто эта нода и чем её настройки отличаются ──────────────

def node_id():
    """
    Постоянный идентификатор ноды. Пустая строка, если создать не удалось.

    Зачем вообще: при сотне узлов ноду переносят на другой сервер, меняют ей
    имя хоста и адрес. Всё это ломает привязку метрик к узлу, и годовой
    график превращается в две половины от «разных» нод. Идентификатор живёт
    в /var/lib/shape и переживает и переезд, и переустановку Shape.

    Почему не machine-id: ноды разворачивают из образа, и у клонов он
    одинаковый — то есть ровно в том случае, ради которого всё и затевалось,
    он бы и подвёл.
    """
    try:
        with open(NODE_ID_FILE) as f:
            value = f.read().strip()
        if re.fullmatch(r"[0-9a-f]{16}", value):
            return value
    except OSError:
        pass

    fresh = os.urandom(8).hex()
    try:
        os.makedirs(VAR_DIR, exist_ok=True)
        tmp = NODE_ID_FILE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w") as f:
            f.write(fresh + "\n")
        os.replace(tmp, NODE_ID_FILE)
        return fresh
    except OSError:
        # Записать некуда — например, метрики читают без root, а каталога ещё
        # нет. Возвращать каждый раз новое случайное значение нельзя: в
        # Prometheus это плодило бы новый ряд на каждый замер. Лучше честно
        # признаться, что идентификатора нет.
        return ""


# Поля автоограничения, которые в отпечаток не входят. watch_interval — это
# настройка нагрузки на процессор, а не политики: на слабой VPS его штатно
# поднимают, и держать такую ноду вечно «разъехавшейся» значит приучить себя
# не смотреть на этот показатель вообще.
GUARD_HASH_SKIP = ("watch_interval",)


def config_hash(cfg=None):
    """
    Двенадцать шестнадцатеричных знаков от политики ноды: порты и настройки
    автоограничения.

    Смысл один: при сотне нод кто-нибудь однажды поправит пороги руками на
    одной из них, и узнать об этом будет неоткуда — жалоба придёт через
    месяц. Одинаковый отпечаток означает одинаковую политику, разный виден
    в мониторинге сразу.

    Чего здесь нет намеренно:

      • скорость — она у каждой ноды своя по замыслу, каналы разные. В
        отпечатке она давала бы столько групп, сколько тарифов, и сигнал
        «где-то разъехалось» тонул бы в них. Смотреть её удобнее числом:
        для этого есть отдельная метрика shape_speed_limit_mbps;

      • раздел telegram — подпись ноды и тема там разные по замыслу, и
        отпечаток стал бы уникальным на каждой ноде, то есть бесполезным;

      • watch_interval — см. GUARD_HASH_SKIP.
    """
    cfg = cfg if cfg is not None else load_config()
    guard = cfg.get("guard") or {}
    payload = {
        "ports": sorted(cfg.get("ports") or []),
        "guard": {k: guard[k] for k in sorted(guard) if k not in GUARD_HASH_SKIP},
    }
    # Только когда список непуст: иначе отпечаток сменился бы разом на всех
    # нодах, где про CDN и не слышали, и сигнал «где-то разъехалось» утонул бы
    # в одной большой ложной тревоге.
    if cfg.get("proxy_ports"):
        payload["proxy_ports"] = sorted(cfg["proxy_ports"])
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()[:12]


def app_dir():
    return os.environ.get("SHAPE_APP_DIR", "/opt/shaper")


def engine_loaded():
    return os.path.exists(map_path("config_map"))


def shape_version():
    try:
        with open(os.path.join(app_dir(), "VERSION")) as f:
            return f.read().strip()
    except Exception:
        return "unknown"


def active_iface():
    try:
        with open(os.path.join(ETC_DIR, ".active_iface")) as f:
            m = re.search(r'IFACE="([A-Za-z0-9._@-]{1,15})"', f.read())
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


# Какие qdisc допустимы на интерфейсе, кроме самого fq: mq — контейнер очередей
# многоочередной карты, clsact — точка подвеса фильтров, noqueue — заглушка.
FQ_OK_KINDS = ("fq", "mq", "clsact", "noqueue")


def edt_ready(iface=None):
    """
    Ограничивается ли скачивание. Возвращает (готово, что мешает).

    Движок расставляет время отправки в skb->tstamp, но придержать пакет до
    этого времени умеет только fq. Стоящий по умолчанию в Debian и Ubuntu
    fq_codel поле игнорирует и отправляет всё сразу: движок работает, штрафы
    выдаются, а скачивание при этом не ограничено ничем.

    Снаружи это выглядит как «лимит 10, а в мониторе 160%», и без отдельной
    проверки причину не найти — всё остальное показывает полное здоровье.

    Неизвестно (нет интерфейса, нет tc) — (True, ""): пугать на пустом месте
    хуже, чем промолчать.
    """
    iface = iface or active_iface()
    if not iface:
        return True, ""
    try:
        out = subprocess.run(["tc", "qdisc", "show", "dev", iface],
                             capture_output=True, text=True, timeout=5)
    except Exception:
        return True, ""
    if out.returncode != 0:
        return True, ""

    bad = []
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) > 1 and parts[0] == "qdisc" and parts[1] not in FQ_OK_KINDS:
            if parts[1] not in bad:
                bad.append(parts[1])
    return (not bad), ", ".join(bad)


ARPHRD_ETHER = 1


def iface_arphrd(iface=None):
    """
    Тип интерфейса из /sys. 1 = Ethernet. None = определить не удалось.

    Фильтр читает L2-заголовок безусловно: `struct ethhdr *eth = data`. На
    интерфейсах без него — ipip (768), gre (778), tun и wireguard (65534) —
    eth->h_proto попадает в середину IP-заголовка, ни ETH_P_IP, ни ETH_P_IPV6
    оттуда не получается, и программа отдаёт TC_ACT_OK на каждом пакете.

    Метрика нужна отдельная ровно по той же причине, что и shape_edt_ready:
    такая нода выглядит совершенно здоровой. Движок загружен, фильтры на
    месте, qdisc у туннельных устройств noqueue — то есть и edt_ready
    покажет единицу. Не ограничивается при этом никто.
    """
    iface = iface or active_iface()
    if not iface:
        return None
    try:
        with open(f"/sys/class/net/{iface}/type") as f:
            return int(f.read().strip())
    except Exception:
        return None


def systemd_active(unit):
    """Только заранее известные имена юнитов — параметр не приходит извне."""
    if unit not in ("shaper", "shaper-watch", "shape-api"):
        return "unknown"
    try:
        p = subprocess.run(["systemctl", "is-active", unit],
                           capture_output=True, text=True, timeout=5)
        return p.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def engine_started_at():
    """Когда движок поднялся: из журнала событий, иначе по времени карт."""
    events, _ = read_events(limit=1, etype="engine_started")
    if events:
        return events[0].get("ts")
    try:
        return os.path.getmtime(map_path("config_map"))
    except OSError:
        return None


# ─────────────────────────── метрики Prometheus ───────────────────────────
# Текст собирается здесь, а не в API: без API метрики тоже должны быть
# доступны — через `shaperctl.py metrics` и textfile collector node_exporter.

def _metrics_rate(down_total, up_total):
    """
    Текущая скорость канала по разнице с прошлым замером.

    Замер лежит в файле, а не в памяти процесса: иначе одноразовый запуск
    из CLI никогда бы не смог посчитать скорость. Файл общий, поэтому
    неважно, кто мерил в прошлый раз — API или таймер.
    """
    now = time.time()
    prev = None
    try:
        with open(METRICS_STATE) as f:
            prev = json.load(f)
        if not isinstance(prev, dict):
            prev = None
    except Exception:
        prev = None

    dl = ul = None
    if prev:
        dt = now - float(prev.get("t", 0))
        # Счётчики обнуляются при перезапуске движка: отрицательная разница
        # означает не отрицательную скорость, а новый отсчёт.
        if METRICS_MIN_GAP / 4 <= dt <= METRICS_MAX_GAP \
                and down_total >= prev.get("down", 0) \
                and up_total >= prev.get("up", 0):
            dl = (down_total - prev["down"]) * 8 / 1e6 / dt
            ul = (up_total - prev["up"]) * 8 / 1e6 / dt

    if not prev or now - float(prev.get("t", 0)) >= METRICS_MIN_GAP:
        try:
            os.makedirs(VAR_DIR, exist_ok=True)
            tmp = METRICS_STATE + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
            with os.fdopen(fd, "w") as f:
                json.dump({"t": now, "down": down_total, "up": up_total}, f)
            os.replace(tmp, METRICS_STATE)
        except Exception:
            pass
    return dl, ul


def metrics_escape(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def build_metrics(users=None, unit_state=None, started=None, events=None):
    """
    Текст в формате Prometheus.

    Аргументы нужны только API: он держит собственный кэш тяжёлых чтений и
    передаёт готовое. При вызове из CLI всё читается на месте.
    """
    cfg = load_config()
    pens = load_penalties()
    limited = {ip: p for ip, p in pens.items() if not is_personal(p)}
    personal = {ip: p for ip, p in pens.items() if is_personal(p)}
    loaded = engine_loaded()
    node = node_label(cfg["telegram"])
    iface = active_iface() or ""

    # Без root карты не прочитать. Тогда честно поднимаем флаг, а не выдаём
    # нули за правду: «ноль трафика» и «мы не смогли посмотреть» — разные вещи.
    complete = 1
    if users is None:
        if loaded and os.geteuid() != 0:
            users, complete = {}, 0
        else:
            users = read_users() if loaded else {}
    if started is None:
        started = engine_started_at()
    if unit_state is None:
        unit_state = systemd_active("shaper-watch")
    if events is None:
        rows, _ = read_events(limit=1000, since=time.time() - 86400)
        events = {}
        for r in rows:
            key = r.get("type", "unknown")
            events[key] = events.get(key, 0) + 1

    down_total = sum(c["down"] for c in users.values())
    up_total = sum(c["up"] for c in users.values())
    dl, ul = _metrics_rate(down_total, up_total)

    now_ns = mono_ns() if loaded else 0
    active = sum(1 for c in users.values()
                 if c["seen"] and (now_ns - c["seen"]) / NS < 60)

    out = []

    def labels(extra=None):
        pairs = [("node", node)] + sorted((extra or {}).items())
        return "{" + ",".join(f'{k}="{metrics_escape(v)}"' for k, v in pairs) + "}"

    def add(name, kind, help_text, value, extra=None):
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} {kind}")
        out.append(f"{name}{labels(extra)} {value}")

    def series(name, kind, help_text, rows):
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} {kind}")
        for extra, value in rows:
            out.append(f"{name}{labels(extra)} {value}")

    add("shape_up", "gauge", "1 if metrics were produced", 1)
    add("shape_metrics_complete", "gauge",
        "1 if BPF maps could be read; 0 means the numbers are incomplete",
        complete)
    # node_id и config_hash живут метками info-метрики, а не отдельными
    # показателями: значение у них строковое, а Prometheus хранит числа.
    # Запрос вида count by (config_hash) (shape_info) сразу показывает,
    # сколько нод разъехалось по политике. Скорость в отпечаток не входит
    # и живёт рядом числом — shape_speed_limit_mbps.
    add("shape_info", "gauge", "Static node information", 1,
        {"version": shape_version(), "metrics_version": METRICS_VERSION,
         "interface": iface, "node_id": node_id(),
         "config_hash": config_hash(cfg)})
    add("shape_engine_loaded", "gauge", "1 if eBPF maps are pinned", int(loaded))
    add("shape_watchdog_active", "gauge", "1 if the watchdog service runs",
        int(unit_state == "active"))
    add("shape_uptime_seconds", "gauge", "Seconds since the engine started",
        round(time.time() - started) if started else 0)
    add("shape_speed_limit_mbps", "gauge", "Shared per-IP limit in Mbit/s",
        f"{cfg['speed_mbps']:g}")
    add("shape_guard_enabled", "gauge", "1 if auto-limiting is on",
        int(bool(cfg["guard"]["enabled"])))

    series("shape_traffic_bytes_total", "counter",
           "Bytes since the engine started",
           [({"direction": "download"}, down_total),
            ({"direction": "upload"}, up_total)])

    if dl is not None:
        series("shape_channel_mbps", "gauge", "Current channel load in Mbit/s",
               [({"direction": "download"}, f"{dl:.3f}"),
                ({"direction": "upload"}, f"{ul:.3f}")])

    add("shape_ips_known", "gauge", "Addresses seen since the engine started",
        len(users))
    add("shape_ips_active", "gauge", "Addresses with traffic in the last minute",
        active)
    add("shape_ips_limited", "gauge", "Addresses under an auto or temporary limit",
        len(limited))
    add("shape_ips_personal", "gauge", "Addresses with a personal speed",
        len(personal))
    add("shape_ips_whitelisted", "gauge", "Addresses on the whitelist",
        len(whitelist_ips()))
    add("shape_owners_known", "gauge", "Addresses with a known owner",
        len(load_owners()))

    series("shape_events_24h", "gauge", "Events written in the last 24 hours",
           [({"type": etype}, events.get(etype, 0))
            for etype in sorted(EVENT_TYPES)])

    hist = read_history(limit=1)
    if hist:
        series("shape_last_day_bytes", "gauge", "Traffic of the last closed day",
               [({"direction": "download"}, hist[-1].get("down", 0)),
                ({"direction": "upload"}, hist[-1].get("up", 0))])

    # Готовность к ограничению скачивания. Метрика нужна именно отдельная:
    # нода без fq выглядит совершенно здоровой — движок загружен, штрафы
    # выдаются, трафик считается, — и только скачивание не ограничено ничем.
    # На флоте в сотню нод найти такую иначе нечем.
    if loaded:
        add("shape_edt_ready", "gauge",
            "1 if downloads are actually paced (fq present)",
            1 if edt_ready(iface)[0] else 0)
        # Второй способ выглядеть здоровым, ничего не ограничивая: интерфейс
        # без L2-заголовка. См. iface_arphrd.
        st = read_stats()
        if st:
            series("shape_packets_total", "counter",
                   "Packets seen by the shaper since the engine started",
                   [({"direction": "download", "action": "pass"}, st["down_pass"]),
                    ({"direction": "download", "action": "drop"}, st["down_drop"]),
                    ({"direction": "upload", "action": "pass"}, st["up_pass"]),
                    ({"direction": "upload", "action": "drop"}, st["up_drop"])])
            # Доля неразрешённых говорит, живы ли заголовки PROXY. Если она
            # растёт, порт с флагом молча раздаёт безлимит.
            series("shape_proxy_packets_total", "counter",
                   "Packets on trusted relays, by whether the client was known",
                   [({"state": "resolved"}, st["pp_resolved"]),
                    ({"state": "unresolved"}, st["pp_unresolved"])])

        arphrd = iface_arphrd(iface)
        if arphrd is not None:
            add("shape_iface_ethernet", "gauge",
                "1 if the shaped interface carries an Ethernet header",
                int(arphrd == ARPHRD_ETHER), {"arphrd": arphrd})

    # Связь с панелью. Метрики отдаём только когда она включена: на ноде без
    # панели нули означали бы поломку, а её нет.
    #
    # shape_panel_up нужен именно как отдельная метрика: без него молчащая
    # панель выглядит точно так же, как панель, на которой никто не нарушает.
    # Отличить «всё тихо» от «мы ослепли» иначе нечем.
    pan = load_config()["panel"]
    if pan.get("enabled"):
        st = panel_state()
        add("shape_panel_up", "gauge",
            "1 if the last panel poll succeeded",
            0 if st.get("last_error") else 1)
        add("shape_panel_last_success_seconds", "gauge",
            "Seconds since the last successful panel poll",
            int(time.time() - float(st.get("last_ok") or 0))
            if st.get("last_ok") else -1)
        exp = token_expiry(pan.get("token"))
        if exp:
            add("shape_panel_token_expires_seconds", "gauge",
                "Seconds until the panel token expires",
                int(exp - time.time()))
        add("shape_panel_sharing_found", "gauge",
            "Users flagged as sharing on the last poll",
            int(st.get("last_found") or 0))

    return "\n".join(out) + "\n"


def cmd_metrics_show(m):
    """Что настроено. Токен и прокси не печатаем: их читают через плечо."""
    print()
    print(f"  {C['b']}{t('met_push_head')}{C['r']}")
    url = m.get("push_url") or ""
    shown = url if url else f"{C['gry']}{t('met_push_none')}{C['r']}"
    print(f"  {t('met_push_url'):<16}: {shown}")
    for key, label in (("push_token", "met_push_token"),
                       ("push_proxy", "met_push_proxy")):
        val = t("met_push_set") if m.get(key) else t("met_push_none")
        col = C["r"] if m.get(key) else C["gry"]
        print(f"  {t(label):<16}: {col}{val}{C['r']}")
    print(f"  {t('met_push_wait'):<16}: "
          f"{int(m.get('push_timeout') or 10)} {t('met_sec')}")
    print()


def cmd_metrics_set(a):
    cfg = load_config()
    m = dict(cfg["metrics"])
    if a.url is not None:
        url, bad = valid_push_url(a.url)
        if bad:
            die(t(bad))
        m["push_url"] = url
    if a.token is not None:
        m["push_token"] = a.token.strip()
    if a.proxy is not None:
        m["push_proxy"] = a.proxy.strip()
    if a.timeout is not None:
        if not 1 <= a.timeout <= 120:
            die(t("guard_range", k="push_timeout", lo=1, hi=120))
        m["push_timeout"] = a.timeout
    save_config({"metrics": m})
    log_event("config_changed", source="cli", section="metrics")
    if not a.quiet:
        cmd_metrics_show(m)


def valid_push_url(url):
    """
    Разбирает адрес отправки. Возвращает (адрес, беда) — беда это ключ строки.

    Простой http разрешён только к своим: 127.0.0.1, приватные сети. Наружу
    он означал бы, что токен уходит открытым текстом по чужим маршрутам, и
    поймать это глазами в конфиге невозможно — проще запретить.
    """
    url = str(url or "").strip()
    if not url:
        return "", None
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        return None, "met_bad_url"
    if u.scheme == "http":
        try:
            addr = ipaddress.ip_address(u.hostname)
            private = addr.is_private or addr.is_loopback
        except ValueError:
            private = u.hostname in ("localhost",)
        if not private:
            return None, "met_need_https"
    return url, None


def metrics_push(cfg, text=None):
    """
    Отправляет метрики на заданный адрес. Возвращает (получилось, ошибка).

    Тело — тот же текст, что уходит в файл для node_exporter. Каждый ряд уже
    несёт метку node, поэтому получателю не нужно ничего дописывать и не важно,
    сколько нод пишет в одно хранилище.
    """
    m = (cfg or {}).get("metrics") or {}
    url, bad = valid_push_url(m.get("push_url"))
    if bad:
        return False, t(bad)
    if not url:
        return False, t("met_push_off")
    if text is None:
        text = build_metrics()
    token = str(m.get("push_token") or "").strip()
    headers = {"Authorization": "Bearer " + token} if token else {}
    try:
        _post(url, text.encode("utf-8"), m.get("push_proxy") or "",
              content_type="text/plain; charset=utf-8", headers=headers)
    except urllib.error.HTTPError as e:
        detail = ""
        with contextlib.suppress(Exception):
            detail = ": " + e.read().decode("utf-8", "replace")[:200]
        return False, scrub(f"HTTP {e.code}{detail}", {"metrics": m})
    except Exception as e:
        return False, scrub(str(e), {"metrics": m})
    return True, ""


def cmd_metrics(a):
    """
    Метрики в stdout или в файл для textfile collector node_exporter.

    Запись в файл — обязательно через временный и переименование: иначе
    node_exporter однажды прочитает половину файла и отдаст мусор.
    """
    action = getattr(a, "action", None)
    if action == "set":
        return cmd_metrics_set(a)
    if action == "show":
        return cmd_metrics_show(load_config()["metrics"])
    if action == "push":
        cfg = load_config()
        text = build_metrics()
        ok, err = metrics_push(cfg, text)
        if not ok:
            die(t("met_push_fail", e=err))
        if not a.quiet:
            print(f"{C['grn']}✓ "
                  f"{t('met_push_ok', n=text.count(chr(10)), u=cfg['metrics']['push_url'])}"
                  f"{C['r']}")
        return

    text = build_metrics()
    if not a.out:
        sys.stdout.write(text)
        return
    path = os.path.abspath(a.out)
    if not path.endswith(".prom"):
        die(t("met_need_prom"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)
    if not a.quiet:
        print(t("met_written", p=path, n=text.count("\n")))


def cmd_history(a):
    rows = read_history(limit=max(1, min(a.days, HISTORY_MAX_DAYS)))
    if a.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return
    if not rows:
        print(f"\n  {C['gry']}{t('hist_none')}{C['r']}\n")
        return
    print(f"\n{C['gry']}  {t('hist_day'):<12}{t('downloaded'):>12}{t('uploaded'):>12}"
          f"{t('total_ips'):>10}{t('hist_limited'):>12}{C['r']}")
    print("  " + "─" * 60)
    for r in rows:
        print(f"  {r['day']:<12}{fmt_bytes(r.get('down', 0)):>12}"
              f"{fmt_bytes(r.get('up', 0)):>12}{r.get('ips', 0):>10}"
              f"{r.get('limited', 0):>12}")
    total = sum(r.get("down", 0) + r.get("up", 0) for r in rows)
    print(f"\n  {C['gry']}{t('hist_total', n=len(rows))}: "
          f"{fmt_bytes(total)}{C['r']}\n")


def cmd_personal(a):
    """Постоянная скорость для адреса — выше или ниже общего лимита."""
    if a.action == "list":
        items = personal_list()
        if a.json:
            print(json.dumps([dict(limit_row(ip, p)) for ip, p in items.items()],
                             ensure_ascii=False, indent=2))
            return
        if not items:
            print(f"\n  {C['gry']}{t('pers_none')}{C['r']}\n")
            return
        print(f"\n{C['gry']}  {'IP':<24}{t('speed'):>12}   {t('lim_why')}{C['r']}")
        print("  " + "─" * 60)
        for ip, p in sorted(items.items()):
            who = (p.get("subject") or {}).get("label") or \
                  (owner_of(ip) or {}).get("label") or ""
            note = p.get("reason") or ""
            tail = " · ".join(x for x in (who, note) if x)
            print(f"  {C['b']}{ip:<24}{C['r']}{p['mbps']:>9g} Mbit/s   "
                  f"{C['gry']}{tail}{C['r']}")
        print()
        return

    ip = valid_ip(a.ip)
    if ip is None:
        die(t("bad_ip", ip=str(a.ip)[:60]))

    if a.action == "del":
        if personal_clear(ip) is None:
            die(t("pers_absent", ip=ip))
        print(f"{C['grn']}✓ {t('pers_removed', ip=ip)}{C['r']}")
        return

    require_engine()
    if a.speed is None:
        die(t("pers_need_speed"))
    if a.speed != a.speed or a.speed in (float("inf"), float("-inf")):
        die(t("neg_speed"))
    if not 0.05 <= a.speed <= MAX_MBPS:
        die(t("pers_range", lo=0.05, hi=MAX_MBPS))
    personal_set(ip, a.speed, a.note or "")
    print(f"{C['grn']}✓ {t('pers_set', ip=ip, s=a.speed)}{C['r']}")


def cmd_owners(a):
    """Кто стоит за адресом. Наполняется вручную или извне через API."""
    if a.action == "list":
        owners = load_owners()
        if a.json:
            print(json.dumps(owners, ensure_ascii=False, indent=2))
            return
        if not owners:
            print(f"\n  {C['gry']}{t('own_none')}{C['r']}\n")
            return
        print()
        for ip, _rec in sorted(owners.items()):
            who = owner_of(ip, owners) or {}
            print(f"  {ip:<24}{who.get('label', '—')}"
                  f"{'  tg:' + str(who['telegram_id']) if who.get('telegram_id') else ''}")
        print()
        return

    ip = valid_ip(a.ip)
    if ip is None:
        die(t("bad_ip", ip=str(a.ip)[:60]))
    if a.action == "del":
        owners_update(lambda o: o.pop(ip, None))
        print(f"{C['grn']}✓ {t('own_removed', ip=ip)}{C['r']}")
        return

    rec = {"updated": round(time.time())}
    if a.label:
        rec["label"] = a.label.strip()[:64]
    if a.user_id:
        rec["user_id"] = a.user_id.strip()[:64]
    if a.telegram_id:
        if not str(a.telegram_id).isdigit():
            die(t("own_bad_tg"))
        rec["telegram_id"] = int(a.telegram_id)
    owners_update(lambda o: o.__setitem__(ip, rec))
    print(f"{C['grn']}✓ {t('own_set', ip=ip)}{C['r']}")


def limit_row(ip, p):
    """Одна запись в машинном виде. Используется и CLI, и API."""
    return {"ip": ip, "mbps": float(p.get("mbps", 0)),
            "kind": p.get("kind", "auto"), "source": p.get("source", "watchdog"),
            "since": p.get("since"), "until": p.get("until"),
            "reason": p.get("reason"), "subject": p.get("subject")}


def cmd_event(a):
    """Записать событие в журнал. Вызывается из engine.sh при старте и стопе."""
    ip = valid_ip(a.ip) if a.ip else None
    log_event(a.type, ip=ip, source=a.source, message=a.message)


def cmd_whitelist(a):
    require_engine()

    if a.action == "add":
        # Проверяем и нормализуем до записи: в файл не должно попасть ничего,
        # кроме адреса. Иначе строка вернётся при sync и будет отвергнута.
        ip = valid_ip(a.ip)
        if ip is None:
            die(t("bad_ip", ip=str(a.ip)[:60]))
        if ip not in whitelist_ips():
            with open(WL_FILE, "a") as f:
                f.write(ip + "\n")
        map_update("whitelist_map", ip_key(ip), b"\x01")
        print(f"{C['grn']}✓ {t('wl_added', ip=ip)}{C['r']}")

    elif a.action == "del":
        ip = valid_ip(a.ip)
        if ip is None:
            die(t("bad_ip", ip=str(a.ip)[:60]))
        if os.path.exists(WL_FILE):
            with open(WL_FILE) as f:
                kept = [l for l in f if valid_ip(l.split("#")[0].strip()) != ip]
            with open(WL_FILE, "w") as f:
                f.writelines(kept)
        map_delete("whitelist_map", ip_key(ip))
        print(f"{C['grn']}✓ {t('wl_removed', ip=ip)}{C['r']}")

    elif a.action == "sync":
        for k, _ in map_dump("whitelist_map"):
            _ip, kb = parse_ip_key(k)
            if kb:
                map_delete("whitelist_map", kb)
        n = 0
        if os.path.exists(WL_FILE):
            for line in open(WL_FILE):
                s = line.split("#")[0].strip()
                if not s:
                    continue
                try:
                    map_update("whitelist_map", ip_key(s), b"\x01")
                    n += 1
                except ValueError:
                    print(f"{C['yel']}⚠ {t('wl_bad', ip=s)}{C['r']}")
        print(t("wl_loaded", n=n))

    elif a.action == "list":
        found = False
        if os.path.exists(WL_FILE):
            for line in open(WL_FILE):
                if line.strip() and not line.startswith("#"):
                    print("  " + line.strip())
                    found = True
        if not found:
            print(f"  {C['gry']}{t('wl_empty')}{C['r']}")


def cmd_cdn(a):
    """Связь с API провайдера CDN: показать, настроить, спросить."""
    cfg = load_config()
    c = cfg["cdn"]

    if a.action == "set":
        if a.url is not None:
            u = a.url.strip().rstrip("/")
            if u and not u.startswith(("http://", "https://")):
                die(t("pn_bad_url"))
            c["url"] = u
        if a.token is not None:
            c["token"] = a.token.strip()
        if a.resource_id is not None:
            r = str(a.resource_id).strip()
            if r and not r.isdigit():
                die(t("cdn_bad_res"))
            c["resource_id"] = r
        if a.proxy is not None:
            c["proxy"] = a.proxy.strip()
        if a.enable:
            c["enabled"] = True
        if a.disable:
            c["enabled"] = False
        cfg["cdn"] = c
        save_config(cfg)
        log_event("config_changed", section="cdn", source="cli")

    if a.action == "list":
        # Чтобы номер ресурса не приходилось искать в личном кабинете руками.
        try:
            got = cdn_call(c, "/v1/resources")
        except CdnError as e:
            die(str(e))
        rows = got.get("resources") or []
        print()
        if not rows:
            print(f"  {C['gry']}{t('cdn_no_list')}{C['r']}\n")
            return
        for r in rows:
            mark = C["grn"] if str(r.get("status")) == "active" else C["gry"]
            print(f"  {C['b']}{r.get('id')}{C['r']}  {r.get('domain') or '—'}"
                  f"  {mark}{r.get('status')}{C['r']}")
        print()
        return

    if a.action == "test":
        print(f"\n  {C['gry']}{t('cdn_ask')}{C['r']}")
        # Сначала простой запрос: он называет причину отказа. Вердикт молчит
        # обо всех ошибках намеренно — это украшение уведомления, — но здесь
        # человек как раз и хочет знать, почему не отвечает.
        try:
            cdn_call(c, "/v1/ping")
        except CdnError as e:
            print(f"  {C['red']}✗ {e}{C['r']}")
            if getattr(e, "code", 0) in (401, 403):
                print(f"  {C['gry']}{t('cdn_bad_key')}{C['r']}")
            print()
            return
        got = cdn_verdict(cfg)
        if got:
            print(f"  {got}\n")
        else:
            print(f"  {C['yel']}{t('cdn_no_res')}{C['r']}\n")
        return

    print()
    print(f"  {t('cdn_state')} : " + (f"{C['grn']}{t('guard_on')}{C['r']}"
          if c["enabled"] else f"{C['gry']}{t('guard_off')}{C['r']}"))
    print(f"  {t('cdn_url')}   : {c['url'] or '—'}")
    print(f"  {t('cdn_res')}   : {c['resource_id'] or '—'}")
    print()


def cmd_trusted(a):
    require_engine()

    if a.action == "add":
        ip = valid_ip(a.ip)
        if ip is None:
            die(t("bad_ip", ip=str(a.ip)[:60]))
        flags = (TRUST_TUNNEL if a.tunnel else 0) | (TRUST_RELAY if a.relay else 0)
        if not flags:
            die(t("tr_need_kind"))
        entries = trusted_sources()
        entries[ip] = entries.get(ip, 0) | flags
        _write_trusted(entries)
        map_update("trusted_map", ip_key(ip), bytes([entries[ip]]))
        what = ", ".join(n for n, bit in ((t("tr_tunnel"), TRUST_TUNNEL),
                                          (t("tr_relay"), TRUST_RELAY))
                         if flags & bit)
        print(f"{C['grn']}✓ {t('tr_added', ip=ip, what=what)}{C['r']}")

    elif a.action == "del":
        ip = valid_ip(a.ip)
        if ip is None:
            die(t("bad_ip", ip=str(a.ip)[:60]))
        entries = trusted_sources()
        entries.pop(ip, None)
        _write_trusted(entries)
        map_delete("trusted_map", ip_key(ip))
        print(f"{C['grn']}✓ {t('tr_removed', ip=ip)}{C['r']}")

    elif a.action == "sync":
        # Карта переживает перезапуск движка, файл — источник истины.
        for k, _ in map_dump("trusted_map"):
            _ip, kb = parse_ip_key(k)
            if kb:
                map_delete("trusted_map", kb)
        entries = trusted_sources()
        for ip, flags in entries.items():
            map_update("trusted_map", ip_key(ip), bytes([flags]))
        # Про пропущенные строки надо сказать вслух: молча проигнорированный
        # релей означает, что все его клиенты делят один лимит, и понять это
        # по симптомам почти невозможно.
        if os.path.exists(TRUST_FILE):
            for line in open(TRUST_FILE):
                s = line.split("#")[0].strip()
                if not s:
                    continue
                parts = s.split()
                if len(parts) != 2 or valid_ip(parts[0]) is None or \
                        not any(k.strip() in TRUST_KINDS
                                for k in parts[1].split(",")):
                    print(f"{C['yel']}⚠ {t('tr_bad', s=s[:60])}{C['r']}")
        print(t("tr_loaded", n=len(entries)))

    elif a.action == "list":
        entries = trusted_sources()
        if not entries:
            print(f"  {C['gry']}{t('tr_empty')}{C['r']}")
            return
        for ip in sorted(entries):
            kinds = ", ".join(n for n, bit in ((t("tr_tunnel"), TRUST_TUNNEL),
                                               (t("tr_relay"), TRUST_RELAY))
                              if entries[ip] & bit)
            print(f"  {ip:<40} {C['gry']}{kinds}{C['r']}")


# ─────────────────── резервная копия состояния ноды ───────────────────
# Всё, что делает ноду именно этой нодой, в одном файле: настройки, белый
# список, персональные скорости и действующие ограничения, владельцы
# адресов и суточная история.
#
# Зачем это нужно: перенос ноды на новый сервер, восстановление после
# смерти диска и разворачивание новых нод из готового образца. При сотне
# узлов третье важнее первых двух — руками повторять настройку негде.
#
# Чего здесь нет намеренно:
#   • журнал событий — это лог, а не состояние, и он на четыре мегабайта;
#   • metrics.state — пересчитается сам при первом же замере;
#   • суточные счётчики — переносить половину дня в другой день бессмысленно.

EXPORT_SCHEMA = 1
EXPORT_KIND = "shape-node-state"
EXPORT_SECTIONS = ("config", "whitelist", "penalties", "owners", "history")

# Поля конфига, в которых лежат секреты: токен даёт полный доступ к боту,
# а в строке прокси почти всегда есть пароль. По умолчанию не выгружаются.
SECRET_PATHS = (("telegram", "token"), ("telegram", "proxy"),
                ("panel", "token"), ("panel", "proxy"),
                ("metrics", "push_token"), ("metrics", "push_proxy"))


def _strip_secrets(cfg):
    """Копия конфига без токена и прокси. Оригинал не трогает."""
    out = json.loads(json.dumps(cfg))
    for section, field in SECRET_PATHS:
        if isinstance(out.get(section), dict) and out[section].get(field):
            out[section][field] = ""
    return out


def build_export(with_secrets=False):
    cfg = load_config()
    if not with_secrets:
        cfg = _strip_secrets(cfg)
    return {
        "kind": EXPORT_KIND,
        "schema": EXPORT_SCHEMA,
        "shape_version": shape_version(),
        "node": socket.gethostname(),
        "exported_at": int(time.time()),
        "exported_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "secrets_included": bool(with_secrets),
        "state": {
            "config": cfg,
            "whitelist": sorted(whitelist_ips()),
            "penalties": load_penalties(),
            "owners": load_owners(),
            "history": read_history(limit=HISTORY_MAX_DAYS),
        },
    }


def cmd_export(a):
    data = build_export(with_secrets=a.with_secrets)
    text = json.dumps(data, ensure_ascii=False, indent=2)

    if a.out in (None, "-"):
        print(text)
        return

    path = os.path.abspath(a.out)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    # Права до записи, а не после: с --with-secrets в файле лежит токен, и
    # окна, в котором он доступен на чтение кому угодно, быть не должно.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text + "\n")
    os.replace(tmp, path)

    st = data["state"]
    print(f"{C['grn']}✓ {t('exp_done', path=path)}{C['r']}")
    print("  " + t("exp_counts", w=len(st["whitelist"]), p=len(st["penalties"]),
                   o=len(st["owners"]), h=len(st["history"])))
    if a.with_secrets:
        print(f"{C['yel']}⚠ {t('exp_secrets')}{C['r']}")
    else:
        print(f"  {C['gry']}{t('exp_no_secrets')}{C['r']}")


def _finite(v):
    """Число или None. nan и inf не проходят, bool тоже не число."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    if v != v or v in (float("inf"), float("-inf")):
        return None
    return v


def _clean_like(src, defaults, label, problems):
    """
    Оставляет только знакомые ключи, тип которых совпадает с умолчанием.

    Разделы guard и telegram попадают из файла прямо в load_config(), где
    ложатся поверх умолчаний. Строка вместо числа в пороге сторожа уронила
    бы не импорт, а сторож — через час, в цикле и без внятной причины.
    """
    out = {}
    for key, default in defaults.items():
        if key not in src:
            continue
        val = src[key]
        ok = False
        if isinstance(default, bool):
            ok = isinstance(val, bool)
        elif isinstance(default, (int, float)):
            ok = _finite(val) is not None
        elif isinstance(default, str):
            ok = isinstance(val, str) and len(val) <= 512
        else:
            ok = True
        if ok:
            out[key] = val
        else:
            problems.append(t("imp_bad_field", s=label, k=key))
    unknown = sorted(k for k in src if k not in defaults)
    if unknown:
        problems.append(t("imp_unknown_keys", s=label,
                          k=", ".join(unknown[:5])))
    return out


def validate_export(data):
    """
    Разбирает выгрузку и возвращает (состояние, список замечаний).

    Импорт не доверяет файлу ничего: он мог прийти с чужой ноды, из другой
    версии или быть поправлен руками. Всё, что не проходит те же проверки,
    что и обычный ввод, отбрасывается и попадает в замечания — вместо того
    чтобы уронить команду на середине записи, оставив половину состояния.
    """
    problems = []
    if not isinstance(data, dict):
        die(t("imp_not_object"))
    if data.get("kind") != EXPORT_KIND:
        die(t("imp_not_shape"))
    try:
        schema = int(data.get("schema", 0))
    except (TypeError, ValueError):
        schema = 0
    if schema < 1:
        die(t("imp_no_schema"))
    if schema > EXPORT_SCHEMA:
        die(t("imp_newer", got=schema, ours=EXPORT_SCHEMA))
    raw = data.get("state")
    if not isinstance(raw, dict):
        die(t("imp_no_state"))

    state = {}

    # ── настройки ──
    cfg = raw.get("config")
    if isinstance(cfg, dict):
        clean = {}
        if "speed_mbps" in cfg:
            sp = _finite(cfg["speed_mbps"])
            if sp is None or not 0 <= sp <= MAX_MBPS:
                problems.append(t("imp_bad_speed", v=str(cfg["speed_mbps"])[:40]))
            else:
                clean["speed_mbps"] = float(sp)
        ports = cfg.get("ports")
        if isinstance(ports, list):
            good = []
            for p in ports:
                if isinstance(p, bool) or not isinstance(p, int) \
                        or not 0 <= p <= 65535:
                    problems.append(t("imp_bad_port", v=str(p)[:20]))
                elif p not in good:
                    good.append(p)
            if len(good) > MAX_PORTS:
                problems.append(t("imp_many_ports", n=MAX_PORTS))
                good = good[:MAX_PORTS]
            if good:
                clean["ports"] = good
        elif ports is not None:
            problems.append(t("imp_bad_ports"))
        for name, defaults in (("guard", GUARD_DEFAULT), ("telegram", TG_DEFAULT)):
            sect = cfg.get(name)
            if isinstance(sect, dict):
                clean[name] = _clean_like(sect, defaults, name, problems)
            elif sect is not None:
                problems.append(t("imp_bad_section", s=name))
        state["config"] = clean
    elif cfg is not None:
        problems.append(t("imp_bad_section", s="config"))

    # ── белый список ──
    wl = raw.get("whitelist")
    if isinstance(wl, list):
        good = []
        for item in wl:
            ip = valid_ip(item) if isinstance(item, str) else None
            if ip is None:
                problems.append(t("imp_bad_ip", v=str(item)[:60]))
            elif ip not in good:
                good.append(ip)
        state["whitelist"] = good
    elif wl is not None:
        problems.append(t("imp_bad_section", s="whitelist"))

    # ── ограничения, включая персональные скорости ──
    pens = raw.get("penalties")
    if isinstance(pens, dict):
        good = {}
        for ip_raw, rec in pens.items():
            ip = valid_ip(ip_raw)
            if ip is None:
                problems.append(t("imp_bad_ip", v=str(ip_raw)[:60]))
                continue
            if not isinstance(rec, dict):
                problems.append(t("imp_bad_entry", v=ip))
                continue
            mbps = _finite(rec.get("mbps"))
            until = _finite(rec.get("until"))
            if mbps is None or not 0 < mbps <= MAX_MBPS or until is None:
                problems.append(t("imp_bad_entry", v=ip))
                continue
            entry = {"mbps": float(mbps), "until": float(until)}
            for key in ("since", "kind", "source", "reason", "subject"):
                if rec.get(key) is not None:
                    entry[key] = rec[key]
            good[ip] = entry
        state["penalties"] = good
    elif pens is not None:
        problems.append(t("imp_bad_section", s="penalties"))

    # ── владельцы адресов ──
    owners = raw.get("owners")
    if isinstance(owners, dict):
        good = {}
        for ip_raw, rec in owners.items():
            ip = valid_ip(ip_raw)
            if ip is None:
                problems.append(t("imp_bad_ip", v=str(ip_raw)[:60]))
                continue
            if not isinstance(rec, dict):
                problems.append(t("imp_bad_entry", v=ip))
                continue
            entry = {}
            for key in OWNER_FIELDS:
                val = rec.get(key)
                if val in (None, ""):
                    continue
                entry[key] = str(val)[:200]
            if entry:
                entry["updated"] = int(_finite(rec.get("updated")) or time.time())
                good[ip] = entry
        state["owners"] = good
    elif owners is not None:
        problems.append(t("imp_bad_section", s="owners"))

    # ── суточная история ──
    hist = raw.get("history")
    if isinstance(hist, list):
        good = []
        for rec in hist:
            if isinstance(rec, dict) and isinstance(rec.get("day"), str) \
                    and re.fullmatch(r"\d{4}-\d{2}-\d{2}", rec["day"]):
                good.append(rec)
            else:
                problems.append(t("imp_bad_entry", v=str(rec)[:40]))
        state["history"] = good[-HISTORY_MAX_DAYS:]
    elif hist is not None:
        problems.append(t("imp_bad_section", s="history"))

    return state, problems


def _write_whitelist(ips):
    """Переписывает файл, сохраняя шапку с пояснением от установщика."""
    head = []
    try:
        with open(WL_FILE) as f:
            for line in f:
                if line.lstrip().startswith("#"):
                    head.append(line.rstrip("\n"))
                elif line.strip():
                    break
    except OSError:
        pass
    os.makedirs(ETC_DIR, exist_ok=True)
    tmp = WL_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        for line in head:
            f.write(line + "\n")
        for ip in ips:
            f.write(ip + "\n")
    os.replace(tmp, WL_FILE)


def apply_import(state, only=None, replace_wl=False, keep_secrets=True):
    """
    Пишет разобранное состояние — через штатные функции записи, не в файлы.

    Именно через штатные: в save_config уже есть слияние с диском, в
    penalties_update и owners_update — блокировка файла. Импорт, пишущий
    напрямую, обошёл бы всё, что защищает эти файлы от одновременной
    правки сторожем, и делал бы это ровно в тот момент, когда состояние
    меняется целиком.
    """
    want = set(only or EXPORT_SECTIONS)
    done = {}

    if "config" in want and "config" in state:
        cfg = json.loads(json.dumps(state["config"]))
        if keep_secrets:
            # В файле секретов нет. Затирать пустой строкой то, что на этой
            # ноде уже настроено, нельзя: уведомления молча замолчали бы.
            current = load_config()
            for section, field in SECRET_PATHS:
                incoming = (cfg.get(section) or {}).get(field, "")
                have = (current.get(section) or {}).get(field, "")
                if not incoming and have:
                    cfg.setdefault(section, {})[field] = have
        save_config(cfg)
        done["config"] = 1

    if "whitelist" in want and "whitelist" in state:
        ips = list(state["whitelist"])
        if not replace_wl:
            ips = sorted(set(ips) | whitelist_ips())
        _write_whitelist(ips)
        done["whitelist"] = len(ips)

    if "penalties" in want and "penalties" in state:
        incoming = state["penalties"]
        penalties_update(lambda pens: pens.update(incoming))
        done["penalties"] = len(incoming)

    if "owners" in want and "owners" in state:
        incoming = state["owners"]
        owners_update(lambda ow: ow.update(incoming))
        done["owners"] = len(incoming)

    if "history" in want and "history" in state:
        incoming = state["history"]
        if incoming:
            with file_lock(HISTORY_FILE + ".lock"):
                by_day = {r.get("day"): r for r in read_history(limit=HISTORY_MAX_DAYS)}
                for rec in incoming:
                    by_day[rec["day"]] = rec
                rows = sorted(by_day.values(), key=lambda r: r.get("day", ""))
                rows = rows[-HISTORY_MAX_DAYS:]
                os.makedirs(VAR_DIR, exist_ok=True)
                tmp = HISTORY_FILE + ".tmp"
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
                with os.fdopen(fd, "w") as f:
                    for rec in rows:
                        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                os.replace(tmp, HISTORY_FILE)
        done["history"] = len(incoming)

    return done


def import_to_kernel(done):
    """
    Доводит восстановленное до ядра, если движок сейчас загружен.

    Если не загружен — ничего страшного и ничего не делаем: config.json
    заливается в карты при старте службы, этим занимается cmd_restore.
    """
    if not engine_loaded():
        return False
    if "config" in done:
        write_to_kernel(load_config())
    if "whitelist" in done:
        for k, _ in map_dump("whitelist_map"):
            _ip, kb = parse_ip_key(k)
            if kb:
                map_delete("whitelist_map", kb)
        for ip in whitelist_ips():
            try:
                map_update("whitelist_map", ip_key(ip), b"\x01")
            except ValueError:
                pass
    if "penalties" in done:
        restore_penalties()
    return True


def cmd_import(a):
    try:
        with open(a.file) as f:
            data = json.load(f)
    except OSError as e:
        die(t("imp_no_file", path=str(a.file)[:120], err=e.strerror or ""))
    except ValueError as e:
        die(t("imp_bad_json", err=str(e)[:120]))

    only = None
    if a.only:
        only = [s.strip() for s in a.only.split(",") if s.strip()]
        bad = [s for s in only if s not in EXPORT_SECTIONS]
        if bad:
            die(t("imp_bad_only", s=", ".join(bad),
                  all=", ".join(EXPORT_SECTIONS)))

    state, problems = validate_export(data)
    want = set(only or EXPORT_SECTIONS)

    counts = {"config": len(state.get("config", {})),
              "whitelist": len(state.get("whitelist", [])),
              "penalties": len(state.get("penalties", {})),
              "owners": len(state.get("owners", {})),
              "history": len(state.get("history", []))}

    print()
    print("  " + t("imp_from",
                   node=str(data.get("node", "?"))[:40],
                   v=str(data.get("shape_version", "?"))[:20],
                   when=str(data.get("exported_at_iso", "?"))[:20]))
    if not data.get("secrets_included"):
        print(f"  {C['gry']}{t('imp_no_secrets')}{C['r']}")
    print()

    for name in EXPORT_SECTIONS:
        if name not in state:
            continue
        on = name in want
        col = C["b"] if on else C["gry"]
        flag = t("imp_yes") if on else t("imp_skip")
        print(f"  {col}{t('sec_' + name):<20}{C['r']}"
              f"{counts[name]:>6}   {col}{flag}{C['r']}")

    if problems:
        print()
        for p in problems[:20]:
            print(f"  {C['yel']}⚠ {p}{C['r']}")
        if len(problems) > 20:
            print(f"  {C['yel']}⚠ {t('imp_more_problems', n=len(problems) - 20)}{C['r']}")

    print()
    if a.dry_run:
        print(f"  {C['gry']}{t('imp_dry')}{C['r']}")
        return

    done = apply_import(state, only=only, replace_wl=a.replace,
                        keep_secrets=not data.get("secrets_included"))
    live = import_to_kernel(done)
    log_event("config_changed", source="cli",
              message="import " + ",".join(sorted(done)))
    print(f"{C['grn']}✓ {t('imp_done', s=', '.join(sorted(done)) or '—')}{C['r']}")
    print(f"  {C['gry']}{t('imp_live') if live else t('imp_offline')}{C['r']}")


# ──────────────────────────────── CLI ────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="shaperctl",
        description=t("desc"))
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("apply", help=t("h_apply"))
    a.add_argument("--ports", default=None, help=t("h_ports"))
    a.add_argument("--proxy-ports", dest="proxy_ports", default=None,
                   help=t("h_proxy_ports"))
    a.add_argument("--speed", type=float, default=None,
                   help=t("h_speed"))
    a.add_argument("--quiet", action="store_true")
    a.set_defaults(func=cmd_apply)

    sub.add_parser("show", help=t("h_show")).set_defaults(func=cmd_show)
    sub.add_parser("restore", help=t("h_restore")).set_defaults(func=cmd_restore)

    m = sub.add_parser("monitor", help=t("h_monitor"))
    m.add_argument("--interval", type=int, default=2, help=t("h_interval"))
    m.add_argument("--top", type=int, default=20)
    m.set_defaults(func=cmd_monitor)

    st = sub.add_parser("status", help=t("h_status"))
    st.add_argument("--live", action="store_true", help=t("h_live"))
    st.add_argument("--interval", type=int, default=3)
    st.add_argument("--top", type=int, default=20)
    st.add_argument("--full", action="store_true", help=t("h_full"))
    st.add_argument("--json", action="store_true", help=t("h_json"))
    st.add_argument("--ratio", action="store_true", help=t("h_ratio"))
    st.add_argument("--bulk", action="store_true", help=t("h_bulk"))
    st.add_argument("--ratio-mb", dest="ratio_mb", type=float, default=100,
                    help=t("h_ratio_mb"))
    st.set_defaults(func=cmd_status)

    g = sub.add_parser("guard", help=t("h_guard"))
    g.add_argument("--enable", action="store_true")
    g.add_argument("--disable", action="store_true")
    g.add_argument("--score", type=int, default=None, help=t("h_score"))
    g.add_argument("--both-min", type=int, default=None, help=t("h_both_min"))
    g.add_argument("--both-dl", type=float, default=None, help=t("h_both_dl"))
    g.add_argument("--both-ul", type=float, default=None, help=t("h_both_ul"))
    g.add_argument("--percent", type=float, default=None, help=t("h_percent"))
    g.add_argument("--sustain", type=int, default=None, help=t("h_sustain"))
    g.add_argument("--penalty-mbps", type=float, default=None, help=t("h_pen_mbps"))
    g.add_argument("--penalty-min", type=int, default=None, help=t("h_pen_min"))
    g.add_argument("--hours", type=float, default=None, help=t("h_hours"))
    g.add_argument("--upload-gb", type=float, default=None, help=t("h_upload_gb"))
    g.add_argument("--upload-warn", dest="upload_warn", type=float,
                   default=None, help=t("h_upload_warn"))
    g.add_argument("--upload-day", dest="upload_day", type=float,
                   default=None, help=t("h_upload_day"))
    g.add_argument("--upload-hours", dest="upload_hours", type=float,
                   default=None, help=t("h_upload_hours"))
    g.add_argument("--upload-gbh", dest="upload_gbh", type=float,
                   default=None, help=t("h_upload_gbh"))
    g.add_argument("--upload-hours-mbps", dest="upload_hours_mbps", type=float,
                   default=None, help=t("h_upload_hours_mbps"))
    g.add_argument("--upload-ratio-hours", dest="upload_ratio_hours", type=float,
                   default=None, help=t("h_upload_ratio_hours"))
    g.add_argument("--download-gb", type=float, default=None, help=t("h_download_gb"))
    g.add_argument("--download-gbh", type=float, default=None, help=t("h_download_gbh"))
    g.add_argument("--upload-ratio", dest="upload_ratio", type=float, default=None,
                   help=t("h_upload_ratio"))
    g.add_argument("--upload-ratio-mb", dest="upload_ratio_mb", type=float,
                   default=None, help=t("h_upload_ratio_mb"))
    g.add_argument("--volume-needs-upload", dest="volume_needs_upload",
                   choices=["on", "off"], default=None,
                   help=t("h_volume_needs"))
    g.add_argument("--volume-mbps", dest="volume_mbps", type=float,
                   default=None, help=t("h_volume_mbps"))
    g.add_argument("--ratio-needs-packet", dest="ratio_needs_packet",
                   choices=["on", "off"], default=None,
                   help=t("h_ratio_needs"))
    g.add_argument("--interval", type=int, default=None, help=t("h_watch_iv"))
    g.add_argument("--packet", type=int, default=None, help=t("h_packet"))
    g.add_argument("--require-packet", dest="require_packet",
                   choices=["on", "off"], default=None, help=t("h_req_packet"))
    g.add_argument("--quiet", action="store_true")
    g.set_defaults(func=cmd_guard)

    sub.add_parser("watch", help=t("h_watch")).set_defaults(func=cmd_watch)

    li = sub.add_parser("limited", help=t("h_limited"))
    li.add_argument("--json", action="store_true", help=t("h_json"))
    li.set_defaults(func=cmd_limited)

    rl = sub.add_parser("release", help=t("h_release"))
    rl.add_argument("ip", nargs="?", default="")
    rl.add_argument("--all", action="store_true")
    rl.add_argument("--user", default="", help=t("h_rel_user"))
    rl.set_defaults(func=cmd_release)

    tg = sub.add_parser("telegram", help=t("h_telegram"))
    tg.add_argument("action", choices=["show", "set", "test", "digest", "backup"],
                    nargs="?", default="show")
    tg.add_argument("--at", default=None, help=t("h_tg_at"))
    tg.add_argument("--token", default=None)
    tg.add_argument("--chat", default=None)
    tg.add_argument("--thread", default=None)
    tg.add_argument("--name", default=None, help=t("h_tg_name"))
    tg.add_argument("--proxy", default=None, help=t("h_tg_proxy"))
    tg.add_argument("--enable", action="store_true")
    tg.add_argument("--disable", action="store_true")
    tg.add_argument("--events", choices=["on", "off"], default=None)
    tg.add_argument("--updates", choices=["on", "off"], default=None)
    tg.add_argument("--daily", choices=["on", "off"], default=None)
    tg.add_argument("--backup", choices=["on", "off"], default=None,
                    help=t("h_tg_backup"))
    tg.add_argument("--backup-thread", dest="backup_thread", default=None,
                    help=t("h_tg_bk_thread"))
    tg.add_argument("--backup-day", dest="backup_day", type=int, default=None,
                    help=t("h_tg_bk_day"))
    tg.add_argument("--quiet", action="store_true")
    tg.set_defaults(func=cmd_telegram)

    pn = sub.add_parser("panel", help=t("h_panel"))
    pn.add_argument("action",
                    choices=["show", "set", "test", "scan", "report", "who",
                             "user", "enable", "disable"],
                    nargs="?", default="show")
    pn.add_argument("ip", nargs="?", default="", help=t("h_pn_who_ip"))
    pn.add_argument("--report", choices=["on", "off"], default=None,
                    help=t("h_pn_report"))
    pn.add_argument("--report-at", dest="report_at", default=None,
                    help=t("h_pn_report_at"))
    pn.add_argument("--report-thread", dest="report_thread", default=None,
                    help=t("h_pn_report_thread"))
    pn.add_argument("--resolve", choices=["on", "off"], default=None,
                    help=t("h_pn_resolve"))
    pn.add_argument("--url", default=None, help=t("h_pn_url"))
    pn.add_argument("--token", default=None, help=t("h_pn_token"))
    pn.add_argument("--node-uuid", dest="node_uuid", default=None,
                    help=t("h_pn_uuid"))
    pn.add_argument("--proxy", default=None, help=t("h_pn_proxy"))
    pn.add_argument("--enable", action="store_true", help=t("h_pn_on"))
    pn.add_argument("--disable", action="store_true", help=t("h_pn_off"))
    pn.add_argument("--interval", type=int, default=None, help=t("h_pn_interval"))
    pn.add_argument("--window", type=int, default=None, help=t("h_pn_window"))
    pn.add_argument("--threshold", type=int, default=None, help=t("h_pn_threshold"))
    pn.add_argument("--action-set", dest="action_set", default=None,
                    help=t("h_pn_action"))
    pn.add_argument("--mbps", type=float, default=None, help=t("h_pn_mbps"))
    pn.add_argument("--minutes", type=int, default=None, help=t("h_pn_minutes"))
    pn.add_argument("--cooldown", type=int, default=None, help=t("h_pn_cooldown"))
    pn.add_argument("--exempt", default=None, help=t("h_pn_exempt"))
    pn.add_argument("--exempt-tags", dest="exempt_tags", default=None,
                    help=t("h_pn_exempt_tags"))
    pn.add_argument("--disable-after", dest="disable_after", type=float,
                    default=None, help=t("h_pn_disable_after"))
    pn.add_argument("--per-device", dest="per_device", type=float,
                    default=None, help=t("h_pn_per_device"))
    pn.add_argument("--dry-run", dest="dry_run", action="store_true",
                    help=t("h_pn_dry"))
    pn.add_argument("--json", action="store_true")
    pn.set_defaults(func=cmd_panel)

    pr = sub.add_parser("personal", help=t("h_personal"))
    pr.add_argument("action", choices=["set", "del", "list"])
    pr.add_argument("ip", nargs="?", default="")
    pr.add_argument("--speed", type=float, default=None, help=t("h_pers_speed"))
    pr.add_argument("--note", default=None)
    pr.add_argument("--json", action="store_true")
    pr.set_defaults(func=cmd_personal)

    ow = sub.add_parser("owners", help=t("h_owners"))
    ow.add_argument("action", choices=["set", "del", "list"])
    ow.add_argument("ip", nargs="?", default="")
    ow.add_argument("--label", default=None)
    ow.add_argument("--user-id", dest="user_id", default=None)
    ow.add_argument("--telegram-id", dest="telegram_id", default=None)
    ow.add_argument("--json", action="store_true")
    ow.set_defaults(func=cmd_owners)

    mt = sub.add_parser("metrics", help=t("h_metrics"))
    # Действие необязательное: без него команда печатает метрики, как и
    # печатала. Ломать вызов из таймера и из чужих скриптов нельзя.
    mt.add_argument("action", nargs="?", choices=["show", "set", "push"],
                    default=None)
    mt.add_argument("--out", default=None, help=t("h_met_out"))
    mt.add_argument("--url", default=None, help=t("h_met_url"))
    mt.add_argument("--token", default=None, help=t("h_met_token"))
    mt.add_argument("--proxy", default=None, help=t("h_met_proxy"))
    mt.add_argument("--timeout", type=int, default=None,
                    help=t("h_met_timeout"))
    mt.add_argument("--quiet", action="store_true")
    mt.set_defaults(func=cmd_metrics)

    hs = sub.add_parser("history", help=t("h_history"))
    hs.add_argument("--days", type=int, default=30)
    hs.add_argument("--json", action="store_true")
    hs.set_defaults(func=cmd_history)

    ev = sub.add_parser("event", help=t("h_event"))
    ev.add_argument("type", choices=sorted(EVENT_TYPES))
    ev.add_argument("--ip", default=None)
    ev.add_argument("--source", default="cli")
    ev.add_argument("--message", default=None)
    ev.set_defaults(func=cmd_event)

    ex = sub.add_parser("export", help=t("h_export"))
    ex.add_argument("--out", default=None, help=t("h_exp_out"))
    ex.add_argument("--with-secrets", dest="with_secrets", action="store_true",
                    help=t("h_exp_secrets"))
    ex.set_defaults(func=cmd_export)

    im = sub.add_parser("import", help=t("h_import"))
    im.add_argument("file")
    im.add_argument("--dry-run", dest="dry_run", action="store_true",
                    help=t("h_imp_dry"))
    im.add_argument("--only", default=None, help=t("h_imp_only"))
    im.add_argument("--replace", action="store_true", help=t("h_imp_replace"))
    im.set_defaults(func=cmd_import)

    w = sub.add_parser("whitelist", help=t("h_whitelist"))
    w.add_argument("action", choices=["add", "del", "sync", "list"])
    w.add_argument("ip", nargs="?", default="")
    w.set_defaults(func=cmd_whitelist)

    cd = sub.add_parser("cdn", help=t("h_cdn"))
    cd.add_argument("action", nargs="?",
                    choices=["show", "set", "test", "list"],
                    default="show")
    cd.add_argument("--url", default=None, help=t("h_cdn_url"))
    cd.add_argument("--token", default=None, help=t("h_cdn_token"))
    cd.add_argument("--resource-id", dest="resource_id", default=None,
                    help=t("h_cdn_res"))
    cd.add_argument("--proxy", default=None, help=t("h_met_proxy"))
    cd.add_argument("--enable", action="store_true")
    cd.add_argument("--disable", action="store_true")
    cd.set_defaults(func=cmd_cdn)

    tr = sub.add_parser("trusted", help=t("h_trusted"))
    tr.add_argument("action", choices=["add", "del", "sync", "list"])
    tr.add_argument("ip", nargs="?", default="")
    tr.add_argument("--tunnel", action="store_true", help=t("h_tr_tunnel"))
    tr.add_argument("--relay", action="store_true", help=t("h_tr_relay"))
    tr.set_defaults(func=cmd_trusted)

    return p


# Команды, которым root не обязателен. Карты BPF без него не прочитать, но
# метрики всё равно стоит отдать: в них есть shape_metrics_complete, по
# которому мониторинг увидит, что цифры неполные. Иначе таймер пришлось бы
# гонять от root ради одного чтения.
NO_ROOT_OK = {"metrics", "history"}


def main():
    args = build_parser().parse_args()
    if os.geteuid() != 0 and args.cmd not in NO_ROOT_OK:
        die(t("root"))
    args.func(args)


if __name__ == "__main__":
    main()

/*
 * Shape — ограничитель скорости на пользователя (eBPF + EDT)
 *
 * Одна настройка: список портов и скорость в Мбит/с. Каждый IP-адрес,
 * работающий через эти порты, получает свой независимый лимит.
 *
 * Download (egress): Earliest Departure Time — пакеты не теряются,
 *                    а равномерно растягиваются во времени, отдаёт fq qdisc.
 * Upload  (ingress): Token Bucket — лишние пакеты дропаются, TCP снизит окно.
 *
 * Единицы. Наружу скорость в Мбит/с, ядру нужны байты в секунду, поэтому в
 * карте лежит пересчитанное значение: bytes_per_sec = Мбит/с * 125000.
 * Пересчёт делает shaperctl.py.
 *
 * Карты:
 *   config_map     : 0 -> struct config     (bytes_per_sec, 0 = выключено)
 *   port_map       : port (u32) -> u8       (порт 0 = все порты)
 *   whitelist_map  : ip (4x u32) -> u8      (к этим IP лимит не применяется,
 *                                            но их трафик всё равно считается)
 *   penalty_map    : ip -> struct penalty   (штраф нарушителю на время)
 *   user_state_map_down/up : ip -> struct user_state
 *   trusted_map    : ip -> u8 флаги        (чьей обёртке мы верим:
 *                                            1 — конец IPIP-туннеля,
 *                                            2 — релей CDN с PROXY protocol)
 *   pp_conn_map    : релей ip:порт -> клиент (соединение CDN ↔ настоящий IP)
 *
 * Карты состояний — LRU: упёрлись в потолок, ядро само вытесняет давно
 * неактивные адреса. Фоновая чистка не нужна.
 *
 * Развёртка IPIP и разбор PROXY protocol — вклад Gy9vin (github.com/Gy9vin),
 * здесь они переработаны: порядок байт и список доверенных источников.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Карты LRU набиваются до потолка и остаются полными, а сторож дампит их
 * целиком каждые несколько секунд. Поэтому размер определяет не память, а
 * процессорное время на разбор JSON: 65536 записей — это 10 МБ и почти
 * секунда на слабом ядре, 8192 — полтора мегабайта и десятки миллисекунд.
 * Запас всё равно огромный: на ноду со 150 клиентами приходится 300-500
 * адресов в сутки с учётом смены мобильных IP. */
/* Номера заголовков расширения IPv6. Приходят из linux/in6.h, но на части
 * дистрибутивов этот заголовок в цепочку не попадает — подстрахуемся. */
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS   0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING   43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT  44
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS   60
#endif
/* Номера протоколов туннелей. Тоже приходят из linux/in.h, но подстрахуемся
 * ровно так же, как с заголовками расширения. */
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP      4
#endif
#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6      41
#endif

#define MAX_USERS      8192
/* Если EDT уводит отправку больше чем на 2 с вперёд — очередь безнадёжна. */
#define EDT_HORIZON_NS 2000000000ULL
/* Допустимый всплеск на upload: 200 мс «в долг». */
#define UL_BUCKET_NS   200000000ULL

/* 8 байт: bytes_per_sec */
struct config {
    __u64 bytes_per_sec;
};

/* 16 байт: IPv4 в addr[0], IPv6 целиком */
struct ip_key {
    __u32 addr[4];
};

/* 16 байт: персональный штраф для нарушителя.
 * Записи создаёт сторож из userspace, здесь только читаем.
 * until_ns — в шкале bpf_ktime_get_ns (CLOCK_MONOTONIC). */
struct penalty {
    __u64 rate_bytes_per_sec;
    __u64 until_ns;
};

/* 32 байта: last_departure_ns, total_bytes, last_seen_ns, packets
 * packets нужен, чтобы посчитать средний размер пакета. В карте отдачи
 * это отделяет раздачу (полные пакеты 1200-1400 байт) от просмотра видео,
 * где вверх уходят только ACK по 60-80 байт. */
struct user_state {
    __u64 last_departure_ns;
    __u64 total_bytes;
    __u64 last_seen_ns;
    __u64 packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct config);
} config_map SEC(".maps");

/* Значение port_map — набор флагов, а не просто «порт в списке».
 *
 * PORT_PROXY нужен из-за того, что адреса CDN меняются. Список доверенных
 * источников привязан к адресу, и в день смены он промахивается молча: разбор
 * PROXY выключается, все клиенты за релеем схлопываются в один ключ, этот ключ
 * получает общий лимит, а через час — ещё и автоограничение. Весь путь через
 * CDN падает до мессенджерной скорости, и ни одна проверка об этом не скажет.
 *
 * Порт — признак устойчивый. Если у Xray на инбаунде стоит acceptProxyProtocol,
 * то соединение без заголовка он и сам отвергнет: заголовок на этом порту есть
 * по построению, и спрашивать «с того ли адреса он пришёл» незачем.
 *
 * Цена названа прямо: доверие переезжает с адреса на порт. Если на том же порту
 * есть ПРЯМЫЕ клиенты, любой из них припишет себе чужой адрес — обойдёт свой
 * лимит и отправит в блок соседа. Безопасно ровно тогда, когда порт только для
 * релея, и проверяется это по конфигурации Xray: acceptProxyProtocol стоит или
 * нет. Поэтому флаг задаётся на каждый порт отдельно, а не одним выключателем.
 */
#define PORT_SHAPE  0x01   /* порт под ограничением */
#define PORT_PROXY  0x02   /* на этом порту верим PROXY protocol от кого угодно */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key,   __u32);
    __type(value, __u8);
} port_map SEC(".maps");

/* Счётчики обработки. Per-CPU: гонки нет по построению, атомарность не нужна.
 *
 * Без них нельзя отличить «лимит держится мягко» от «лимит рубит четверть
 * трафика», а с появлением PORT_PROXY добавился и второй слепой участок: если
 * заголовки перестанут приходить, весь порт тихо станет безлимитным. Считаем
 * оба случая. */
#define STAT_DOWN_PASS     0
#define STAT_DOWN_DROP     1
#define STAT_UP_PASS       2
#define STAT_UP_DROP       3
#define STAT_PP_RESOLVED   4   /* пакет учтён по адресу из заголовка */
#define STAT_PP_UNRESOLVED 5   /* релей доверенный, а привязки нет */
#define STAT_MAX           6

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key,   __u32);
    __type(value, __u64);
} stat_map SEC(".maps");

static __always_inline void stat_inc(__u32 idx)
{
    __u64 *c = bpf_map_lookup_elem(&stat_map, &idx);
    if (c)
        (*c)++;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   struct ip_key);
    __type(value, __u8);
} whitelist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   struct ip_key);
    __type(value, struct penalty);
} penalty_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_USERS);
    __type(key,   struct ip_key);
    __type(value, struct user_state);
} user_state_map_down SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_USERS);
    __type(key,   struct ip_key);
    __type(value, struct user_state);
} user_state_map_up SEC(".maps");

/* ── Кому мы верим, когда настоящий адрес клиента спрятан ──
 *
 * Есть два случая, когда адрес в IP-заголовке — не клиент:
 * пакет приехал внутри IPIP-туннеля, или клиент сидит за CDN и его
 * настоящий адрес приходит в заголовке PROXY protocol.
 *
 * И там, и там адрес клиента берётся из данных, которые пишет отправитель.
 * Поэтому разворачивать обёртку можно только у тех, кто имеет на это право:
 * иначе любой, кто открыл соединение на шейпируемый порт, приписывал бы
 * заголовок и сам выбирал, на чей адрес записать трафик — обходил бы свой
 * лимит и отправлял в блок чужого. Список пуст по умолчанию: пока в нём
 * никого, обе развёртки не работают вовсе, и ключ берётся из IP-заголовка,
 * как всегда.
 */
#define TRUST_TUNNEL  0x01   /* этому адресу можно снимать обёртку IPIP */
#define TRUST_RELAY   0x02   /* этому адресу можно верить PROXY protocol */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key,   struct ip_key);
    __type(value, __u8);
} trusted_map SEC(".maps");

/* PROXY protocol: «адрес и порт релея» → настоящий клиент.
 *
 * Заголовок лежит в первых байтах TCP-потока и приходит один раз. Значит
 * соединение надо запомнить: пара «IP релея + его порт» уникальна, пока
 * соединение живо. LRU — страховка от утечки, если соединение оборвалось
 * без всякого закрытия. */
struct pp_key {
    __u32 addr[4];    /* адрес релея */
    __u16 port;       /* порт релея в этом соединении */
    __u16 pad;
};

/* fins считает половинки закрытия. Удалять запись по первому же FIN нельзя:
 * TCP закрывается по одной стороне за раз, и встречное направление может
 * ещё передавать данные — они ушли бы в учёт релею. Ждём обе половинки. */
struct pp_conn {
    struct ip_key client;
    __u32 fins;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_USERS);
    __type(key,   struct pp_key);
    __type(value, struct pp_conn);
} pp_conn_map SEC(".maps");


/*
 * Разбор заголовка PROXY protocol из начала TCP-потока.
 * Возвращает 1 и адрес клиента в out, если заголовок нашёлся.
 *
 * v2 — двоичный: 12 байт сигнатуры, потом версия с командой, семейство,
 * длина и адреса. Команда LOCAL (соединение самого релея, клиента за ним
 * нет) пропускается. v1 — текстовый «PROXY TCP4 a.b.c.d …».
 *
 * Адрес копируется байтами, а не собирается сдвигами. Это важно: во всём
 * остальном коде ключ — это сырые байты из IP-заголовка (сетевой порядок),
 * и адрес, собранный через <<24, лёг бы в карту задом наперёд. Клиент
 * 203.0.113.5 стал бы 5.113.0.203 — лимиты, белый список и статистика
 * промахнулись бы мимо него навсегда, а в мониторе появился бы адрес,
 * которого нет на свете.
 */
static __always_inline int parse_pp(__u8 *p, void *data_end, struct ip_key *out)
{
    if ((void *)(p + 28) > data_end)
        return 0;                   /* короче минимальной головы v2/TCP4 */

    if (p[0] == 0x0D && p[1] == 0x0A && p[2] == 0x0D && p[3] == 0x0A &&
        p[4] == 0x00 && p[5] == 0x0D && p[6] == 0x0A && p[7] == 0x51 &&
        p[8] == 0x55 && p[9] == 0x49 && p[10] == 0x54 && p[11] == 0x0A) {
        if ((p[12] >> 4) != 2)      /* версия 2 */
            return 0;
        if ((p[12] & 0x0F) != 1)    /* команда PROXY, не LOCAL */
            return 0;
        if (p[13] == 0x11) {        /* TCP над IPv4: адрес клиента с 16-го байта */
            __builtin_memcpy(&out->addr[0], p + 16, 4);
            return 1;
        }
        if (p[13] == 0x21) {        /* TCP над IPv6: 16 байт адреса */
            if ((void *)(p + 32) > data_end)
                return 0;
            __builtin_memcpy(out->addr, p + 16, 16);
            return 1;
        }
        return 0;
    }

    /* v1: «PROXY TCP4 a.b.c.d …».
     *
     * Октеты собираются сдвигами в одно число, и только в самом конце оно
     * переворачивается в сетевой порядок. Массива на стеке здесь нет
     * намеренно: запись oct[part++] с переменным индексом верификатор
     * ядра не пропускает — clang превращает её в арифметику по указателю
     * стека через OR, а «bitwise operator |= on pointer prohibited».
     * Компилятор такое собирает молча, ловится только на живом ядре. */
    if (p[0] == 'P' && p[1] == 'R' && p[2] == 'O' && p[3] == 'X' &&
        p[4] == 'Y' && p[5] == ' ' && p[6] == 'T' && p[7] == 'C' &&
        p[8] == 'P' && p[9] == '4' && p[10] == ' ') {
        __u32 ip = 0, cur = 0;
        int part = 0, digits = 0;
#pragma unroll
        for (int i = 11; i < 27; i++) {
            __u8 ch = p[i];
            if (ch >= '0' && ch <= '9') {
                cur = cur * 10 + (__u32)(ch - '0');
                if (cur > 255 || ++digits > 3)
                    return 0;
            } else if (ch == '.' && part < 3 && digits > 0) {
                ip = (ip << 8) | cur;
                cur = 0; digits = 0; part++;
            } else if (ch == ' ' && part == 3 && digits > 0) {
                out->addr[0] = bpf_htonl((ip << 8) | cur);
                return 1;
            } else {
                return 0;
            }
        }
    }
    return 0;
}


/*
 * direction: 0 = download (egress, пакет ИДЁТ к пользователю  → ключ по daddr)
 *            1 = upload   (ingress, пакет ИДЁТ от пользователя → ключ по saddr)
 */
static __always_inline int process_packet(struct __sk_buff *skb,
                                          __u32 direction,
                                          void *user_map)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    /* ── Развёртка IPIP ──
     * Часть хостеров отдаёт ноде белый адрес через туннель: на внешнем
     * интерфейсе каждый пакет обёрнут лишним IP-заголовком с протоколом 4
     * (IPv4 в IPv4) или 41 (IPv6 в IPv4). Наружные адреса — это концы
     * туннеля, а не клиенты; не сняв обёртку, шейпер видит «протокол не TCP
     * и не UDP» и пропускает весь трафик ноды мимо учёта и лимита.
     *
     * Снимается ровно один уровень и только у доверенного конца туннеля.
     * Без этой проверки протокол 4 стал бы дырой: кто угодно шлёт на ноду
     * пакет с протоколом 4, а внутренний адрес — какой захочет.
     *
     * Границы внутреннего заголовка проверяются в ветках ниже. */
    void *l3 = (void *)(eth + 1);
    __u16 eth_type = eth->h_proto;
    if (eth_type == bpf_htons(ETH_P_IP)) {
        struct iphdr *outer = l3;
        if ((void *)(outer + 1) > data_end)
            return TC_ACT_OK;
        if (outer->ihl >= 5 &&
            (outer->protocol == IPPROTO_IPIP ||
             outer->protocol == IPPROTO_IPV6)) {
            /* Второй конец туннеля: на входе это отправитель, на выходе —
             * получатель. Он и должен стоять в списке доверенных. */
            struct ip_key peer = {0};
            peer.addr[0] = (direction == 0) ? outer->daddr : outer->saddr;
            __u8 *tr = bpf_map_lookup_elem(&trusted_map, &peer);
            if (tr && (*tr & TRUST_TUNNEL)) {
                l3 = (void *)l3 + ((__u32)outer->ihl * 4);
                if (outer->protocol == IPPROTO_IPV6)
                    eth_type = bpf_htons(ETH_P_IPV6);
            }
        }
    }

    struct ip_key key = {0};
    __u16 sport = 0, dport = 0;
    __u8  proto = 0;
    void *l4 = 0;
    /* Порты не удалось прочитать: не первый фрагмент или незнакомый L4.
     * Такой пакет всё равно принадлежит клиенту, поэтому шейпим его, если
     * включено правило «все порты», и пропускаем, если правило по портам. */
    __u32 no_ports = 0;

    if (eth_type == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = l3;
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;
        if (ip->ihl < 5)
            return TC_ACT_OK;

        key.addr[0] = (direction == 0) ? ip->daddr : ip->saddr;
        proto = ip->protocol;
        l4 = (void *)ip + (ip->ihl * 4);

        /* Не первый фрагмент: на месте заголовка L4 лежат данные. Раньше эти
         * байты читались как порты — и полезная нагрузка иногда случайно
         * совпадала с 443, а иногда нет. Смещение фрагмента — младшие 13 бит
         * frag_off; старшие три это флаги, их отбрасываем. */
        if (ip->frag_off & bpf_htons(0x1FFF))
            no_ports = 1;

    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = l3;
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_OK;

        if (direction == 0)
            __builtin_memcpy(key.addr, ip6->daddr.in6_u.u6_addr32, 16);
        else
            __builtin_memcpy(key.addr, ip6->saddr.in6_u.u6_addr32, 16);

        proto = ip6->nexthdr;
        l4 = (void *)(ip6 + 1);

        /* Цепочка заголовков расширения. Без неё пакет с любым hop-by-hop
         * впереди выглядел бы как «протокол не TCP и не UDP» и уходил мимо
         * шейпера — клиенту достаточно добавить один пустой заголовок, чтобы
         * получить безлимит на отдачу. Глубина ограничена: верификатору нужен
         * конечный цикл, а больше двух-трёх заголовков в жизни не встречается. */
#pragma unroll
        for (int i = 0; i < 3; i++) {
            if (proto == IPPROTO_TCP || proto == IPPROTO_UDP)
                break;
            if (proto == IPPROTO_FRAGMENT) {
                /* Заголовок фрагмента: 8 байт, дальше либо первый фрагмент
                 * с портами, либо продолжение без них. */
                struct frag_hdr {
                    __u8  nexthdr;
                    __u8  reserved;
                    __be16 frag_off;
                    __be32 identification;
                } *fh = l4;
                if ((void *)(fh + 1) > data_end)
                    return TC_ACT_OK;
                if (fh->frag_off & bpf_htons(0xFFF8))
                    no_ports = 1;
                proto = fh->nexthdr;
                l4 = (void *)(fh + 1);
            } else if (proto == IPPROTO_HOPOPTS || proto == IPPROTO_ROUTING ||
                       proto == IPPROTO_DSTOPTS) {
                struct ext_hdr {
                    __u8 nexthdr;
                    __u8 hdrlen;    /* длина в восьмёрках байт, не считая первой */
                } *eh = l4;
                if ((void *)(eh + 1) > data_end)
                    return TC_ACT_OK;
                proto = eh->nexthdr;
                l4 = (void *)l4 + ((__u32)(eh->hdrlen + 1) << 3);
            } else {
                break;
            }
        }
    } else {
        return TC_ACT_OK;   /* ARP, VLAN и прочее — не трогаем */
    }

    /* ── Скорость. Ноль = ограничение выключено ── */
    __u32 zero = 0;
    struct config *conf = bpf_map_lookup_elem(&config_map, &zero);
    if (!conf || conf->bytes_per_sec == 0)
        return TC_ACT_OK;

    /* ── Порты ── */
    if (no_ports) {
        /* нечего читать, решение примет проверка правила «все порты» */
    } else if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
    } else {
        return TC_ACT_OK;   /* ICMP и прочее не шейпим */
    }

    /* Матчим строго по направлению, а не «sport или dport»:
     *   download (egress к клиенту)  : порт сервера = sport
     *   upload   (ingress от клиента): порт сервера = dport
     *
     * Иначе под правило «443» попал бы ещё и исходящий трафик самой ноды
     * к чужим сайтам на 443 (там dport=443) — он шейпился бы второй раз
     * и учитывался под IP этого сайта.
     */
    __u32 key_port = (direction == 0) ? sport : dport;
    __u8 *pf = 0;
    if (!no_ports)
        pf = bpf_map_lookup_elem(&port_map, &key_port);
    if (!pf)
        pf = bpf_map_lookup_elem(&port_map, &zero);   /* порт 0 = все порты */
    if (!pf)
        return TC_ACT_OK;
    __u8 port_flags = *pf;

    /* ── PROXY protocol: клиенты за CDN ──
     * CDN завершает соединение клиента у себя и открывает к ноде своё.
     * На уровне пакетов отправитель — релей, и все клиенты за ним делили бы
     * один лимит на всех. Настоящий адрес приходит только в заголовке PROXY
     * protocol, в первых байтах потока — том же, который читает Xray с
     * acceptProxyProtocol.
     *
     * Заголовок разбирается один раз, на сегменте, который его принёс; пара
     * «IP релея + порт» запоминается, и дальше все пакеты соединения в обе
     * стороны учитываются по адресу клиента.
     *
     * Работает только для адресов из списка доверенных: заголовок пишет
     * отправитель, и без списка любой желающий назначал бы себе чужой адрес.
     * Прямым клиентам это не мешает — их адреса в списке нет, ключ берётся
     * из IP-заголовка, как раньше.
     */
    __u32 relay_unresolved = 0;
    if (proto == IPPROTO_TCP && !no_ports) {
        __u8 *tr = bpf_map_lookup_elem(&trusted_map, &key);
        /* Два независимых основания доверять заголовку: адрес в списке или
         * флаг на порту. Второй переживает смену адресов CDN. */
        if ((tr && (*tr & TRUST_RELAY)) || (port_flags & PORT_PROXY)) {
            struct tcphdr *tcp = l4;    /* границы проверены при разборе портов */
            struct pp_key ck = {0};
            __builtin_memcpy(ck.addr, key.addr, sizeof(ck.addr));
            ck.port = (direction == 0) ? dport : sport;

            struct pp_conn *conn = bpf_map_lookup_elem(&pp_conn_map, &ck);
            if (conn) {
                __builtin_memcpy(key.addr, conn->client.addr, sizeof(key.addr));
            } else if (direction == 1) {
                /* Записи нет — этот сегмент мог принести заголовок.
                 * Ищем только на входе: заголовок шлёт релей, не нода. */
                __u8 doff = ((__u8 *)tcp)[12] >> 4;
                struct pp_conn fresh = {0};
                if (doff >= 5 &&
                    parse_pp((__u8 *)tcp + ((__u32)doff << 2), data_end,
                             &fresh.client)) {
                    bpf_map_update_elem(&pp_conn_map, &ck, &fresh, BPF_ANY);
                    __builtin_memcpy(key.addr, fresh.client.addr,
                                     sizeof(key.addr));
                    conn = bpf_map_lookup_elem(&pp_conn_map, &ck);
                }
            }

            /* Соединение закрылось — запись пора убрать: тот же порт релей
             * скоро отдаст другому клиенту, и чужой трафик пошёл бы в учёт
             * предыдущему. RST рвёт сразу, FIN закрывает по одной половине,
             * поэтому их считаем: две половины — конец. */
            if (conn)
                stat_inc(STAT_PP_RESOLVED);
            else
                relay_unresolved = 1;

            __u8 flags = ((__u8 *)tcp)[13];
            if (flags & 0x04) {                     /* RST */
                bpf_map_delete_elem(&pp_conn_map, &ck);
            } else if ((flags & 0x01) && conn) {    /* FIN */
                /* Складываем атомарно. Половинки закрытия обрабатываются
                 * разными программами — FIN клиента приходит на ingress, FIN
                 * ноды уходит с egress, — и попадают на разные ядра почти
                 * одновременно. Обычный ++ терял одно из двух приращений:
                 * обе стороны читали 0, обе писали 1, до двойки не доходило
                 * никогда. Запись оставалась висеть до вытеснения из LRU, а
                 * разбор нового заголовка стоит в else if выше и для занятого
                 * ключа не выполняется — трафик следующего клиента на том же
                 * порту релея уходил бы в учёт прежнему.
                 *
                 * Измерено 04.09: из 53 записей с fins=1 у 51 не было живого
                 * сокета, то есть соединений давно нет. У здоровых записей
                 * без сокета было 14% — столько умирает без FIN и RST.
                 *
                 * Результат сложения намеренно не забираем: возвращающий
                 * вариант требует BPF_ATOMIC с FETCH — ядро 5.12+ и -mcpu=v3,
                 * а -mcpu в сборке не задан. Простой BPF_XADD есть везде, и
                 * перечитывание безопасно: приращения больше не теряются,
                 * значит вторая по счёту сторона увидит 2 и удалит запись.
                 * Увидели обе — второй delete просто ничего не найдёт. */
                __sync_fetch_and_add(&conn->fins, 1);
                if (conn->fins >= 2)
                    bpf_map_delete_elem(&pp_conn_map, &ck);
            }
        }
    }

    __u64 now = bpf_ktime_get_ns();
    __u32 len = skb->len;

    struct user_state *st = bpf_map_lookup_elem(user_map, &key);
    if (!st) {
        struct user_state fresh = {
            .last_departure_ns = now,
            .last_seen_ns      = now,
            .total_bytes       = len,
            .packets           = 1,
        };
        bpf_map_update_elem(user_map, &key, &fresh, BPF_ANY);
        return TC_ACT_OK;   /* первый пакет пропускаем без задержки */
    }

    __sync_fetch_and_add(&st->total_bytes, len);
    __sync_fetch_and_add(&st->packets, 1);
    st->last_seen_ns = now;

    /* ── Белый список ──
     * Проверяется здесь, а не в начале: счётчики адреса должны вестись в
     * любом случае. Раньше проверка стояла до учёта, и адрес из белого
     * списка исчезал отовсюду — из монитора, статистики и метрик. Понять,
     * сколько канала он съедает, было нельзя вообще никак, хотя съедать он
     * может сколько угодно: лимит к нему не применяется.
     *
     * Теперь считаем всех, а ограничиваем не всех.
     */
    if (bpf_map_lookup_elem(&whitelist_map, &key)) {
        /* Адрес релея мог попасть в белый список. Без этой строки счётчик
         * unresolved замолчал бы, и пропажа заголовков PROXY перестала бы
         * быть заметной — ровно тогда, когда порт раздаёт безлимит. */
        if (relay_unresolved)
            stat_inc(STAT_PP_UNRESOLVED);
        return TC_ACT_OK;
    }

    /* Заголовок PROXY приходит один раз, в первых байтах соединения, и
     * повторно не придёт никогда. Значит после каждой перезагрузки движка все
     * живые соединения CDN остаются без привязки: pp_conn_map пересоздаётся
     * пустой. Раньше такой трафик шейпился по адресу релея — то есть все
     * клиенты за CDN делили один лимит на всех, часами, до переустановки
     * соединений. Сюда же попадали рукопожатия и служебные проверки релея.
     *
     * Считаем такой трафик, но не ограничиваем: релей и не должен
     * ограничиваться, он не клиент. Сколько этого трафика — видно по
     * счётчику, и если он вдруг станет заметной долей, значит заголовки
     * перестали приходить и порт молча раздаёт безлимит. */
    if (relay_unresolved) {
        stat_inc(STAT_PP_UNRESOLVED);
        return TC_ACT_OK;
    }

    /* Персональный штраф важнее общего лимита. Просроченные записи вычищает
     * сторож; здесь просто игнорируем их по времени. */
    __u64 rate = conf->bytes_per_sec;
    struct penalty *pen = bpf_map_lookup_elem(&penalty_map, &key);
    if (pen && pen->rate_bytes_per_sec > 0 && now < pen->until_ns)
        rate = pen->rate_bytes_per_sec;

    /* Значение перечитано из карты, а не то, что проверяли в начале: между
     * проверкой и этой строкой лимит могли снять из userspace. Деление на
     * ноль в BPF даёт ноль, а не панику, но пакет тогда уехал бы с нулевой
     * задержкой мимо всякого учёта — лучше честно пропустить. */
    if (rate == 0)
        return TC_ACT_OK;

    __u64 delay_ns  = ((__u64)len * 1000000000ULL) / rate;
    __u64 departure = st->last_departure_ns;
    if (now > departure)
        departure = now;

    if (direction == 0) {
        /* Download: сдвигаем время отправки, fq придержит пакет. */
        departure += delay_ns;
        if (departure - now > EDT_HORIZON_NS) {
            stat_inc(STAT_DOWN_DROP);
            return TC_ACT_SHOT;
        }
        st->last_departure_ns = departure;
        skb->tstamp = departure;
        stat_inc(STAT_DOWN_PASS);
    } else {
        /* Upload: ведро на 200 мс, переполнилось — дроп. */
        if (departure - now > UL_BUCKET_NS) {
            stat_inc(STAT_UP_DROP);
            return TC_ACT_SHOT;
        }
        st->last_departure_ns = departure + delay_ns;
        stat_inc(STAT_UP_PASS);
    }

    return TC_ACT_OK;
}

SEC("classifier/down")
int shaper_down(struct __sk_buff *skb)
{
    return process_packet(skb, 0, &user_state_map_down);
}

SEC("classifier/up")
int shaper_up(struct __sk_buff *skb)
{
    return process_packet(skb, 1, &user_state_map_up);
}

char _license[] SEC("license") = "GPL";

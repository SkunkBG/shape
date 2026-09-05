#define _GNU_SOURCE
/*
 * Стенд для shaper.bpf.c: тот же исходник собирается обычным gcc, карты
 * подменяются простой таблицей в памяти. Так можно прогнать через реальный
 * код разбора пакеты, которых на живой ноде не дождёшься — фрагменты,
 * заголовки расширения IPv6, обрезанные заголовки.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#define _GNU_SOURCE
#include <sys/mman.h>

/* inet_pton объявлен здесь, а не через <arpa/inet.h>: этот заголовок тянет
 * свою struct in6_addr, и она конфликтует с той, что приходит из заглушек
 * linux/ipv6.h. Нам нужна только сама функция — она в libc. */
#define AF_INET   2
#define AF_INET6  10
int inet_pton(int af, const char *src, void *dst);

/* ── заглушки хелперов ── */
static unsigned long long fake_now = 1000000000ULL;
void *bpf_map_lookup_elem(void *map, const void *key);
long  bpf_map_update_elem(void *map, const void *key, const void *value,
                          unsigned long long flags);
long  bpf_map_delete_elem(void *map, const void *key);
static unsigned long long bpf_ktime_get_ns_impl(void) { return fake_now; }
#define bpf_ktime_get_ns bpf_ktime_get_ns_impl

#define SEC(NAME)
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#include "../bpf/shaper.bpf.c"

/* ── карта в памяти ── */
struct ent { void *map; unsigned char key[32]; unsigned char val[32]; int used; };
static struct ent table[4096];
static int keysize(void *m) {
    if (m == (void *)&config_map || m == (void *)&port_map ||
        m == (void *)&stat_map) return 4;
    if (m == (void *)&pp_conn_map) return sizeof(struct pp_key);
    return 16;
}
void *bpf_map_lookup_elem(void *map, const void *key) {
    int ks = keysize(map);
    for (int i = 0; i < 4096; i++)
        if (table[i].used && table[i].map == map && !memcmp(table[i].key, key, ks))
            return table[i].val;
    return NULL;
}
long bpf_map_update_elem(void *map, const void *key, const void *value,
                         unsigned long long flags) {
    (void)flags;
    int ks = keysize(map);
    for (int i = 0; i < 4096; i++)
        if (table[i].used && table[i].map == map && !memcmp(table[i].key, key, ks)) {
            memcpy(table[i].val, value, 32); return 0;
        }
    for (int i = 0; i < 4096; i++)
        if (!table[i].used) {
            table[i].used = 1; table[i].map = map;
            memcpy(table[i].key, key, ks); memcpy(table[i].val, value, 32);
            return 0;
        }
    return -1;
}
long bpf_map_delete_elem(void *map, const void *key) {
    int ks = keysize(map);
    for (int i = 0; i < 4096; i++)
        if (table[i].used && table[i].map == map &&
            !memcmp(table[i].key, key, ks)) {
            table[i].used = 0;
            return 0;
        }
    return -1;
}
static void map_put(void *m, const void *k, const void *v) {
    bpf_map_update_elem(m, k, v, 0);
}

/* Адрес как он лежит на проводе и в ключах карт: сырые байты.
 * Именно так его кладёт ip_key() в shaperctl.py (ip.packed) и так же
 * приходит ip->saddr. Все константы стенда строятся только через эту
 * функцию — иначе стенд проверял бы согласие кода с самим собой. */
static unsigned v4(const char *s) {
    unsigned a; if (inet_pton(AF_INET, s, &a) != 1) { abort(); } return a;
}

/* ── сборка пакетов ── */
/* data и data_end в struct __sk_buff — 32-битные: в ядре их подменяет
 * верификатор, а в обычной программе указатель просто обрежется. Поэтому
 * буфер кладём в младшие 4 ГБ адресного пространства. */
static unsigned char *pkt;
static struct __sk_buff skb;
static void pkt_alloc(void) {
    /* MAP_32BIT есть только на x86_64, поэтому просто просим конкретный
     * низкий адрес — он свободен в любом обычном процессе. */
    pkt = mmap((void *)0x20000000UL, 4096, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (pkt == MAP_FAILED || (unsigned long)pkt >> 32) {
        perror("mmap"); exit(2);
    }
}

static int run_pkt(int len, int direction) {
    skb.data = (unsigned long)pkt;
    skb.data_end = (unsigned long)pkt + len;
    skb.len = len;
    skb.tstamp = 0;
    return direction == 0 ? shaper_down(&skb) : shaper_up(&skb);
}

/* IPv4 + TCP/UDP. frag_off — сырое значение поля (в хостовом порядке). */
static int build_v4(unsigned proto, unsigned sport, unsigned dport,
                    unsigned frag_off, int payload, unsigned dst, unsigned src)
{
    memset(pkt, 0, 2048);
    pkt[12] = 0x08; pkt[13] = 0x00;                 /* ethertype IPv4 */
    struct iphdr *ip = (struct iphdr *)(pkt + 14);
    ip->version = 4; ip->ihl = 5; ip->protocol = proto;
    ip->frag_off = __builtin_bswap16(frag_off);
    ip->daddr = dst; ip->saddr = src;
    unsigned char *l4 = pkt + 14 + 20;
    if (!(frag_off & 0x1FFF)) {
        l4[0] = sport >> 8; l4[1] = sport & 0xFF;
        l4[2] = dport >> 8; l4[3] = dport & 0xFF;
    } else {
        /* «полезная нагрузка», случайно похожая на порт 443 */
        l4[0] = 0x01; l4[1] = 0xBB; l4[2] = 0x01; l4[3] = 0xBB;
    }
    return 14 + 20 + (proto == IPPROTO_TCP ? 20 : 8) + payload;
}

/* IPv6 с цепочкой заголовков расширения перед TCP */
static int build_v6_ext(int n_ext, unsigned sport, unsigned dport, int payload)
{
    memset(pkt, 0, 2048);
    pkt[12] = 0x86; pkt[13] = 0xDD;
    struct ipv6hdr *ip6 = (struct ipv6hdr *)(pkt + 14);
    ip6->version = 6;
    ip6->daddr.in6_u.u6_addr32[0] = 0x0120;
    ip6->daddr.in6_u.u6_addr32[3] = 0x99;
    ip6->saddr.in6_u.u6_addr32[0] = 0x0120;
    ip6->saddr.in6_u.u6_addr32[3] = 0x99;
    unsigned char *p = pkt + 14 + 40;
    ip6->nexthdr = n_ext ? IPPROTO_HOPOPTS : IPPROTO_TCP;
    for (int i = 0; i < n_ext; i++) {
        p[0] = (i == n_ext - 1) ? IPPROTO_TCP : IPPROTO_DSTOPTS;
        p[1] = 0;               /* hdrlen 0 => 8 байт */
        p += 8;
    }
    p[0] = sport >> 8; p[1] = sport & 0xFF;
    p[2] = dport >> 8; p[3] = dport & 0xFF;
    return (int)(p - pkt) + 20 + payload;
}

/* IPv4 + TCP с настоящими doff и флагами и точной полезной нагрузкой.
 * У build_v4 поле doff нулевое, поэтому прочитать из него полезную
 * нагрузку нельзя — а для PROXY protocol нужна именно она. */
static int build_tcp_raw(unsigned dst, unsigned src, unsigned sport,
                         unsigned dport, unsigned char flags,
                         const void *payload, int payload_len)
{
    memset(pkt, 0, 2048);
    pkt[12] = 0x08; pkt[13] = 0x00;
    struct iphdr *ip = (struct iphdr *)(pkt + 14);
    ip->version = 4; ip->ihl = 5; ip->protocol = IPPROTO_TCP;
    ip->daddr = dst; ip->saddr = src;
    unsigned char *t = pkt + 14 + 20;
    t[0] = sport >> 8; t[1] = sport & 0xFF;
    t[2] = dport >> 8; t[3] = dport & 0xFF;
    t[12] = 5 << 4;                     /* doff = 5, заголовок без опций */
    t[13] = flags;
    if (payload_len > 0)
        memcpy(t + 20, payload, payload_len);
    return 14 + 20 + 20 + payload_len;
}

/* Наружный IPIP-заголовок, внутри — обычный IPv4 + TCP. */
static int build_ipip(unsigned outer_dst, unsigned outer_src,
                      unsigned dst, unsigned src,
                      unsigned sport, unsigned dport, int payload)
{
    memset(pkt, 0, 2048);
    pkt[12] = 0x08; pkt[13] = 0x00;
    struct iphdr *out = (struct iphdr *)(pkt + 14);
    out->version = 4; out->ihl = 5; out->protocol = IPPROTO_IPIP;
    out->daddr = outer_dst; out->saddr = outer_src;
    struct iphdr *in = (struct iphdr *)(pkt + 14 + 20);
    in->version = 4; in->ihl = 5; in->protocol = IPPROTO_TCP;
    in->daddr = dst; in->saddr = src;
    unsigned char *l4 = pkt + 14 + 20 + 20;
    l4[0] = sport >> 8; l4[1] = sport & 0xFF;
    l4[2] = dport >> 8; l4[3] = dport & 0xFF;
    return 14 + 20 + 20 + 20 + payload;
}

/* Наружный IPv4 (протокол 41), внутри IPv6 + TCP. */
static int build_ipip_v6(unsigned outer_dst, unsigned outer_src,
                         unsigned sport, unsigned dport, int payload)
{
    memset(pkt, 0, 2048);
    pkt[12] = 0x08; pkt[13] = 0x00;
    struct iphdr *out = (struct iphdr *)(pkt + 14);
    out->version = 4; out->ihl = 5; out->protocol = IPPROTO_IPV6;
    out->daddr = outer_dst; out->saddr = outer_src;
    struct ipv6hdr *ip6 = (struct ipv6hdr *)(pkt + 14 + 20);
    ip6->version = 6; ip6->nexthdr = IPPROTO_TCP;
    inet_pton(AF_INET6, "2001:db8::99", &ip6->daddr);
    inet_pton(AF_INET6, "2001:db8::99", &ip6->saddr);
    unsigned char *l4 = pkt + 14 + 20 + 40;
    l4[0] = sport >> 8; l4[1] = sport & 0xFF;
    l4[2] = dport >> 8; l4[3] = dport & 0xFF;
    return 14 + 20 + 40 + 20 + payload;
}

/* ── заголовки PROXY protocol, как их пишет настоящий релей ──
 * Адрес кладётся сырыми байтами через inet_pton: ровно то, что придёт
 * с провода. Если разбор соберёт его сдвигами, тест это увидит. */
static const unsigned char ppsig[12] = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
    0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
};

static int ppv2_tcp4(void *buf, const char *client)
{
    unsigned char *p = buf;
    memset(p, 0, 28);
    memcpy(p, ppsig, 12);
    p[12] = 0x21;                       /* версия 2, команда PROXY */
    p[13] = 0x11;                       /* TCP над IPv4 */
    p[14] = 0x00; p[15] = 0x0C;         /* длина адресной части */
    if (inet_pton(AF_INET, client, p + 16) != 1) abort();
    return 28;
}

static int ppv2_tcp6(void *buf, const char *client)
{
    unsigned char *p = buf;
    memset(p, 0, 52);
    memcpy(p, ppsig, 12);
    p[12] = 0x21;
    p[13] = 0x21;                       /* TCP над IPv6 */
    p[14] = 0x00; p[15] = 0x24;
    if (inet_pton(AF_INET6, client, p + 16) != 1) abort();
    return 52;
}

static int ppv2_local(void *buf)
{
    unsigned char *p = buf;
    memset(p, 0, 28);
    memcpy(p, ppsig, 12);
    p[12] = 0x20;                       /* версия 2, команда LOCAL */
    p[13] = 0x11;
    p[14] = 0x00; p[15] = 0x0C;
    return 28;
}

static int ppv1_tcp4(void *buf, const char *client)
{
    return sprintf((char *)buf, "PROXY TCP4 %s 10.0.0.9 1111 443\r\n", client);
}

/* Счётчики per-CPU в стенде обычные: одна «CPU», значение прямо в ячейке.
 * Нулевую запись надо завести заранее — в ядре карта типа ARRAY существует
 * целиком с самого начала, а таблица стенда заводит записи по требованию. */
static void stat_init(void)
{
    unsigned long long z = 0;
    for (unsigned i = 0; i < STAT_MAX; i++)
        map_put(&stat_map, &i, &z);
}

static unsigned long long stat_get(unsigned idx)
{
    unsigned long long *c = bpf_map_lookup_elem(&stat_map, &idx);
    return c ? *c : 0;
}

static int ok = 0, fail = 0;
static void check(const char *name, int cond) {
    if (cond) { ok++; printf("  \033[32m✓\033[0m %s\n", name); }
    else      { fail++; printf("  \033[31m✗ %s\033[0m\n", name); }
}

int main(void)
{
    pkt_alloc();
    struct config cfg = { .bytes_per_sec = 10 * 125000 };   /* 10 Мбит/с */
    unsigned zero = 0, p443 = 443;
    unsigned char one = 1;
    map_put(&config_map, &zero, &cfg);
    map_put(&port_map, &p443, &one);
    stat_init();

    unsigned CLIENT = 0x0100007F, SERVER = 0x0200007F;
    int len;

    printf("\n\033[1m1. Базовый разбор\033[0m\n");
    len = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, CLIENT, SERVER);
    check("download на порт 443 принят к учёту", run_pkt(len, 0) == TC_ACT_OK);
    struct ip_key k = {0}; k.addr[0] = CLIENT;
    check("состояние клиента заведено", bpf_map_lookup_elem(&user_state_map_down, &k) != NULL);

    len = build_v4(IPPROTO_TCP, 51000, 8080, 0, 1400, CLIENT, SERVER);
    struct ip_key k2 = {0}; k2.addr[0] = 0x0300007F;
    len = build_v4(IPPROTO_TCP, 51000, 8080, 0, 1400, 0x0300007F, SERVER);
    run_pkt(len, 0);
    check("чужой порт не учитывается",
          bpf_map_lookup_elem(&user_state_map_down, &k2) == NULL);

    printf("\n\033[1m2. Задержка растёт пропорционально размеру\033[0m\n");
    unsigned long long t0, t1;
    fake_now = 2000000000ULL;
    len = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, CLIENT, SERVER);
    run_pkt(len, 0); t0 = skb.tstamp;
    run_pkt(len, 0); t1 = skb.tstamp;
    /* 1454 байта при 1.25 МБ/с ≈ 1.16 мс на пакет */
    check("шаг между отправками близок к 1.16 мс",
          (t1 - t0) > 1000000 && (t1 - t0) < 1400000);
    check("время отправки не в прошлом", t1 >= fake_now);

    printf("\n\033[1m3. Фрагменты IPv4 (была дыра: порты читались из данных)\033[0m\n");
    struct ip_key kf = {0}; kf.addr[0] = 0x0A00007F;
    len = build_v4(IPPROTO_TCP, 0, 0, 0x00B9, 1400, 0x0A00007F, SERVER);  /* offset != 0 */
    int r = run_pkt(len, 0);
    check("не первый фрагмент не считается трафиком порта 443",
          bpf_map_lookup_elem(&user_state_map_down, &kf) == NULL && r == TC_ACT_OK);

    /* с правилом «все порты» тот же фрагмент обязан шейпиться */
    map_put(&port_map, &zero, &one);
    len = build_v4(IPPROTO_TCP, 0, 0, 0x00B9, 1400, 0x0A00007F, SERVER);
    run_pkt(len, 0);
    check("при правиле «все порты» фрагмент шейпится",
          bpf_map_lookup_elem(&user_state_map_down, &kf) != NULL);
    /* убираем правило «все порты» обратно */
    for (int i = 0; i < 4096; i++)
        if (table[i].used && table[i].map == (void *)&port_map &&
            *(unsigned *)table[i].key == 0) table[i].used = 0;

    printf("\n\033[1m4. Заголовки расширения IPv6 (была дыра: пакет уходил мимо)\033[0m\n");
    struct ip_key k6 = {0}; k6.addr[0] = 0x0120; k6.addr[3] = 0x99;
    for (int n = 0; n <= 2; n++) {
        for (int i = 0; i < 4096; i++)
            if (table[i].used && table[i].map == (void *)&user_state_map_up)
                table[i].used = 0;
        len = build_v6_ext(n, 51000, 443, 1200);
        run_pkt(len, 1);
        char msg[80];
        snprintf(msg, sizeof msg, "upload с %d заголовками расширения учтён", n);
        check(msg, bpf_map_lookup_elem(&user_state_map_up, &k6) != NULL);
    }

    printf("\n\033[1m5. Обрезанные и битые пакеты\033[0m\n");
    check("пустой кадр не роняет разбор", run_pkt(4, 0) == TC_ACT_OK);
    check("только ethernet-заголовок", run_pkt(14, 0) == TC_ACT_OK);
    len = build_v4(IPPROTO_TCP, 443, 51000, 0, 0, CLIENT, SERVER);
    check("IPv4 без места под TCP", run_pkt(14 + 20 + 4, 0) == TC_ACT_OK);
    len = build_v6_ext(2, 51000, 443, 0);
    check("IPv6 с оборванной цепочкой", run_pkt(14 + 40 + 8, 1) == TC_ACT_OK);
    struct iphdr *ip = (struct iphdr *)(pkt + 14);
    len = build_v4(IPPROTO_TCP, 443, 51000, 0, 100, CLIENT, SERVER);
    ip->ihl = 3;   /* невозможная длина заголовка */
    check("IPv4 с ihl < 5 отброшен из разбора", run_pkt(len, 0) == TC_ACT_OK);
    len = build_v4(IPPROTO_ICMP, 0, 0, 0, 100, CLIENT, SERVER);
    check("ICMP не шейпится", run_pkt(len, 0) == TC_ACT_OK);

    printf("\n\033[1m6. Белый список и штраф\033[0m\n");
    struct ip_key kw = {0}; kw.addr[0] = 0x0B00007F;
    map_put(&whitelist_map, &kw, &one);
    len = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, 0x0B00007F, SERVER);
    run_pkt(len, 0);                       /* первый пакет заводит запись */
    check("адрес из белого списка попадает в учёт",
          bpf_map_lookup_elem(&user_state_map_down, &kw) != NULL);
    struct user_state *wst = bpf_map_lookup_elem(&user_state_map_down, &kw);
    unsigned long long before = wst->total_bytes;
    skb.tstamp = 0;
    run_pkt(len, 0);
    check("его байты считаются", wst->total_bytes > before);
    check("но время отправки ему не назначается", skb.tstamp == 0);
    len = build_v4(IPPROTO_TCP, 51000, 443, 0, 1400, SERVER, 0x0B00007F);
    run_pkt(len, 1);
    struct user_state *wup = bpf_map_lookup_elem(&user_state_map_up, &kw);
    check("отдача тоже считается", wup != NULL && wup->total_bytes > 0);

    struct penalty pen = { .rate_bytes_per_sec = 1 * 125000,
                           .until_ns = fake_now + 60000000000ULL };
    struct ip_key kp = {0}; kp.addr[0] = 0x0C00007F;
    map_put(&penalty_map, &kp, &pen);
    len = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, 0x0C00007F, SERVER);
    run_pkt(len, 0);                       /* первый пакет заводит запись */
    run_pkt(len, 0); t0 = skb.tstamp;
    run_pkt(len, 0); t1 = skb.tstamp;
    check("штрафник тормозится в 10 раз сильнее",
          (t1 - t0) > 10000000 && (t1 - t0) < 14000000);

    pen.until_ns = fake_now - 1;           /* штраф истёк */
    map_put(&penalty_map, &kp, &pen);
    run_pkt(len, 0); t0 = skb.tstamp;
    run_pkt(len, 0); t1 = skb.tstamp;
    check("после истечения штрафа скорость общая",
          (t1 - t0) > 1000000 && (t1 - t0) < 1400000);

    printf("\n\033[1m7. Лимит снят на ходу\033[0m\n");
    struct config off = { .bytes_per_sec = 0 };
    map_put(&config_map, &zero, &off);
    len = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, CLIENT, SERVER);
    check("нулевой лимит пропускает без деления на ноль",
          run_pkt(len, 0) == TC_ACT_OK);

    /* Hysteria2 и вообще QUIC — это UDP/443, а не TCP. Ветка UDP в разборе
     * есть с самого начала, но до появления первой такой ноды её ничто не
     * проверяло: весь набор гонял только TCP. */
    printf("\n\033[1m8. UDP: QUIC на том же порту\033[0m\n");
    map_put(&config_map, &zero, &cfg);           /* вернуть лимит 10 Мбит/с */
    unsigned QCLIENT = 0x1100007F;
    struct ip_key ku = {0}; ku.addr[0] = QCLIENT;

    len = build_v4(IPPROTO_UDP, 443, 51000, 0, 1200, QCLIENT, SERVER);
    check("download по UDP/443 принят к учёту", run_pkt(len, 0) == TC_ACT_OK);
    struct user_state *su = bpf_map_lookup_elem(&user_state_map_down, &ku);
    check("состояние клиента QUIC заведено", su != NULL);
    check("байты посчитаны", su && su->total_bytes > 0);
    /* Первый пакет нового адреса пропускается без задержки намеренно —
     * задержку считаем со второго, как и для TCP. */
    check("первый пакет не задержан", skb.tstamp == 0);
    len = build_v4(IPPROTO_UDP, 443, 51000, 0, 1200, QCLIENT, SERVER);
    run_pkt(len, 0);
    check("со второго пакета отправка откладывается", skb.tstamp > 0);

    fake_now = 5000000000ULL;
    len = build_v4(IPPROTO_UDP, 443, 51000, 0, 1200, QCLIENT, SERVER);
    run_pkt(len, 0); t0 = skb.tstamp;
    run_pkt(len, 0); t1 = skb.tstamp;
    /* 1254 байта при 1.25 МБ/с ≈ 1.0 мс на пакет */
    check("шаг между UDP-пакетами соответствует лимиту",
          (t1 - t0) > 850000 && (t1 - t0) < 1200000);

    unsigned QUP = 0x1200007F;
    struct ip_key ku2 = {0}; ku2.addr[0] = QUP;
    len = build_v4(IPPROTO_UDP, 51000, 443, 0, 1200, SERVER, QUP);
    run_pkt(len, 1);
    check("upload по UDP/443 учтён по адресу отправителя",
          bpf_map_lookup_elem(&user_state_map_up, &ku2) != NULL);

    unsigned QOTHER = 0x1300007F;
    struct ip_key ku3 = {0}; ku3.addr[0] = QOTHER;
    len = build_v4(IPPROTO_UDP, 4444, 51000, 0, 1200, QOTHER, SERVER);
    run_pkt(len, 0);
    check("UDP на чужом порту не учитывается",
          bpf_map_lookup_elem(&user_state_map_down, &ku3) == NULL);

    /* Исходящий QUIC самой ноды к чужому сайту: dport=443 на egress.
     * Под правило «443» он попасть не должен — иначе трафик ноды шейпился
     * бы повторно и записывался на адрес чужого сайта. */
    unsigned SITE = 0x1400007F;
    struct ip_key ku4 = {0}; ku4.addr[0] = SITE;
    len = build_v4(IPPROTO_UDP, 51000, 443, 0, 1200, SITE, SERVER);
    run_pkt(len, 0);
    check("исходящий QUIC ноды под правило не попадает",
          bpf_map_lookup_elem(&user_state_map_down, &ku4) == NULL);

    /* Обрезанный UDP-заголовок: восьми байт нет. Должно быть решение
     * «пропустить», а не чтение за границей пакета. */
    unsigned TRUNC = 0x1500007F;
    len = build_v4(IPPROTO_UDP, 443, 51000, 0, 0, TRUNC, SERVER);
    check("обрезанный UDP-заголовок не роняет разбор",
          run_pkt(14 + 20 + 4, 0) == TC_ACT_OK);

    /* Белый список работает одинаково для обоих протоколов. */
    unsigned QWL = 0x1600007F;
    struct ip_key kwu = {0}; kwu.addr[0] = QWL;
    map_put(&whitelist_map, &kwu, &one);
    len = build_v4(IPPROTO_UDP, 443, 51000, 0, 1200, QWL, SERVER);
    run_pkt(len, 0);                       /* первый — заводит состояние */
    run_pkt(len, 0);                       /* второй — доходит до проверки */
    struct user_state *sw = bpf_map_lookup_elem(&user_state_map_down, &kwu);
    check("адрес из белого списка по UDP считается", sw != NULL);
    check("его байты растут", sw && sw->total_bytes > 1200);
    check("но задержка не применяется", skb.tstamp == 0);

    /* Часть хостеров отдаёт ноде белый адрес через IPIP. Без развёртки
     * наружный заголовок с протоколом 4 выглядит как «не TCP и не UDP», и
     * весь трафик такой ноды уходит мимо учёта и лимита.
     * Идея правки — Gy9vin (github.com/Gy9vin); здесь добавлена проверка,
     * что обёртку прислал доверенный конец туннеля. */
    printf("\n\033[1m9. IPIP-туннель\033[0m\n");
    unsigned PEER    = v4("198.51.100.7");    /* другой конец туннеля */
    unsigned STRANGE = v4("198.51.100.8");    /* посторонний */
    unsigned TCLIENT = v4("203.0.113.11");    /* клиент внутри туннеля */
    struct ip_key kti = {0}; kti.addr[0] = TCLIENT;
    unsigned char tflags[32] = {0};

    len = build_ipip(SERVER, PEER, SERVER, TCLIENT, 51000, 443, 1200);
    run_pkt(len, 1);
    check("без доверия туннель не разворачивается",
          bpf_map_lookup_elem(&user_state_map_up, &kti) == NULL);

    tflags[0] = TRUST_TUNNEL;
    struct ip_key kpeer = {0}; kpeer.addr[0] = PEER;
    map_put(&trusted_map, &kpeer, tflags);
    len = build_ipip(SERVER, PEER, SERVER, TCLIENT, 51000, 443, 1200);
    run_pkt(len, 1);
    check("клиент внутри туннеля учтён по внутреннему адресу",
          bpf_map_lookup_elem(&user_state_map_up, &kti) != NULL);
    struct ip_key kpk = {0}; kpk.addr[0] = PEER;
    check("адрес конца туннеля в учёт не попадает",
          bpf_map_lookup_elem(&user_state_map_up, &kpk) == NULL);

    /* Протокол 4 может прислать кто угодно, и внутренний адрес там любой.
     * Если разворачивать без разбора, это подмена учёта в одну строку. */
    unsigned FAKE = v4("203.0.113.12");
    struct ip_key kfake = {0}; kfake.addr[0] = FAKE;
    len = build_ipip(SERVER, STRANGE, SERVER, FAKE, 51000, 443, 1200);
    run_pkt(len, 1);
    check("обёртка от постороннего не разворачивается",
          bpf_map_lookup_elem(&user_state_map_up, &kfake) == NULL);

    struct ip_key k6t = {0};
    inet_pton(AF_INET6, "2001:db8::99", k6t.addr);
    for (int i = 0; i < 4096; i++)
        if (table[i].used && table[i].map == (void *)&user_state_map_up &&
            !memcmp(table[i].key, &k6t, 16)) table[i].used = 0;
    len = build_ipip_v6(SERVER, PEER, 51000, 443, 1200);
    run_pkt(len, 1);
    check("IPv6 внутри туннеля (протокол 41) тоже учтён",
          bpf_map_lookup_elem(&user_state_map_up, &k6t) != NULL);

    /* Клиент за CDN: пакеты приходят от релея, настоящий адрес — только в
     * заголовке PROXY protocol. Идея правки тоже Gy9vin; здесь исправлен
     * порядок байт и добавлен список доверенных релеев. */
    printf("\n\033[1m10. PROXY protocol (клиенты за CDN)\033[0m\n");
    unsigned p9080 = 9080;
    map_put(&port_map, &p9080, &one);
    unsigned RELAY = v4("198.51.100.20");
    const char *PPCLI = "203.0.113.5";
    unsigned PPCLI_RAW = v4(PPCLI);
    unsigned char pay[128];
    static unsigned char pay1400[1400];
    memset(pay1400, 0x41, sizeof pay1400);
    struct ip_key kcli = {0}; kcli.addr[0] = PPCLI_RAW;
    struct ip_key krel = {0}; krel.addr[0] = RELAY;
    struct pp_key ckk = {0}; ckk.addr[0] = RELAY; ckk.port = 60001;

    /* Пока релей не в списке, заголовок — просто данные. */
    int plen = ppv2_tcp4(pay, PPCLI);
    len = build_tcp_raw(SERVER, RELAY, 60001, 9080, 0x18, pay, plen);
    run_pkt(len, 1);
    check("без доверия заголовок не читается",
          bpf_map_lookup_elem(&user_state_map_up, &kcli) == NULL);
    check("трафик записан релею, как обычному адресу",
          bpf_map_lookup_elem(&user_state_map_up, &krel) != NULL);

    tflags[0] = TRUST_RELAY;
    map_put(&trusted_map, &krel, tflags);

    /* Главная проверка. Адрес в заголовке лежит сырыми байтами, ключ в
     * карте — тоже сырые байты. Соберёшь его сдвигами — 203.0.113.5
     * превратится в 5.113.0.203, и ни лимит, ни белый список в него уже
     * никогда не попадут. Оба адреса здесь построены independently через
     * inet_pton, поэтому расхождение видно сразу. */
    len = build_tcp_raw(SERVER, RELAY, 60001, 9080, 0x18, pay, plen);
    run_pkt(len, 1);
    check("upload за CDN учтён по настоящему адресу клиента",
          bpf_map_lookup_elem(&user_state_map_up, &kcli) != NULL);
    struct ip_key krev = {0}; krev.addr[0] = v4("5.113.0.203");
    check("адрес не перевёрнут (порядок байт совпадает с ip->saddr)",
          bpf_map_lookup_elem(&user_state_map_up, &krev) == NULL);
    check("соединение релея запомнено",
          bpf_map_lookup_elem(&pp_conn_map, &ckk) != NULL);

    /* Середина потока: заголовка больше нет, ключ берётся из карты. */
    struct user_state *pst = bpf_map_lookup_elem(&user_state_map_up, &kcli);
    unsigned long long pbefore = pst ? pst->total_bytes : 0;
    len = build_tcp_raw(SERVER, RELAY, 60001, 9080, 0x18,
                        "\x17\x03\x03\x00\x10", 5);
    run_pkt(len, 1);
    pst = bpf_map_lookup_elem(&user_state_map_up, &kcli);
    check("пакеты без заголовка сходятся к тому же клиенту",
          pst != NULL && pst->total_bytes > pbefore);

    /* Отдача идёт к релею, а считаться должна клиенту. */
    fake_now = 7000000000ULL;
    len = build_tcp_raw(RELAY, SERVER, 9080, 60001, 0x18, pay1400, 1400);
    run_pkt(len, 0);
    check("download за CDN учтён по адресу клиента",
          bpf_map_lookup_elem(&user_state_map_down, &kcli) != NULL);
    run_pkt(len, 0); t0 = skb.tstamp;
    run_pkt(len, 0); t1 = skb.tstamp;
    check("download за CDN тормозится как обычный пакет",
          (t1 - t0) > 1000000 && (t1 - t0) < 1400000);

    /* Закрытие. Одна половина — соединение ещё живо: встречное направление
     * может передавать данные, и они должны идти клиенту, а не релею. */
    len = build_tcp_raw(SERVER, RELAY, 60001, 9080, 0x11, NULL, 0);
    run_pkt(len, 1);
    check("один FIN запись не убирает",
          bpf_map_lookup_elem(&pp_conn_map, &ckk) != NULL);
    len = build_tcp_raw(RELAY, SERVER, 9080, 60001, 0x11, NULL, 0);
    run_pkt(len, 0);
    check("вторая половина закрытия убирает",
          bpf_map_lookup_elem(&pp_conn_map, &ckk) == NULL);

    /* RST рвёт соединение сразу, ждать нечего. */
    plen = ppv2_tcp4(pay, PPCLI);
    len = build_tcp_raw(SERVER, RELAY, 60001, 9080, 0x18, pay, plen);
    run_pkt(len, 1);
    check("соединение заведено заново",
          bpf_map_lookup_elem(&pp_conn_map, &ckk) != NULL);
    len = build_tcp_raw(SERVER, RELAY, 60001, 9080, 0x04, NULL, 0);
    run_pkt(len, 1);
    check("RST убирает запись сразу",
          bpf_map_lookup_elem(&pp_conn_map, &ckk) == NULL);

    /* IPv6-клиент за тем же релеем. */
    const char *PP6 = "2001:db8:1::7";
    plen = ppv2_tcp6(pay, PP6);
    len = build_tcp_raw(SERVER, RELAY, 60003, 9080, 0x18, pay, plen);
    run_pkt(len, 1);
    struct ip_key k6c = {0};
    inet_pton(AF_INET6, PP6, k6c.addr);
    check("IPv6-клиент из заголовка v2 учтён",
          bpf_map_lookup_elem(&user_state_map_up, &k6c) != NULL);

    /* Текстовый вариант v1 — его до сих пор шлют старые балансировщики. */
    const char *PPV1 = "203.0.113.77";
    plen = ppv1_tcp4(pay, PPV1);
    len = build_tcp_raw(SERVER, RELAY, 60004, 9080, 0x18, pay, plen);
    run_pkt(len, 1);
    struct ip_key kv1 = {0}; kv1.addr[0] = v4(PPV1);
    check("текстовый заголовок v1 разобран",
          bpf_map_lookup_elem(&user_state_map_up, &kv1) != NULL);

    /* LOCAL — это служебное соединение самого релея, клиента за ним нет. */
    plen = ppv2_local(pay);
    len = build_tcp_raw(SERVER, RELAY, 60005, 9080, 0x18, pay, plen);
    run_pkt(len, 1);
    struct pp_key ck5 = {0}; ck5.addr[0] = RELAY; ck5.port = 60005;
    check("команда LOCAL клиента не создаёт",
          bpf_map_lookup_elem(&pp_conn_map, &ck5) == NULL);

    /* И то, ради чего весь список: обычный клиент, приписавший себе
     * заголовок с чужим адресом, ничего этим не добивается. */
    unsigned CHEAT = v4("203.0.113.90");
    struct ip_key kcheat = {0}; kcheat.addr[0] = CHEAT;
    struct ip_key kvictim = {0}; kvictim.addr[0] = v4("203.0.113.91");
    plen = ppv2_tcp4(pay, "203.0.113.91");
    len = build_tcp_raw(SERVER, CHEAT, 60006, 9080, 0x18, pay, plen);
    run_pkt(len, 1);
    check("чужой заголовок от недоверенного адреса игнорируется",
          bpf_map_lookup_elem(&user_state_map_up, &kvictim) == NULL);
    check("такой трафик остаётся на своём отправителе",
          bpf_map_lookup_elem(&user_state_map_up, &kcheat) != NULL);

    /* Ключ карты сравнивается побайтово, вместе с дырами от выравнивания.
     * Дыра в структуре означает, что один и тот же логический ключ иногда
     * находится, а иногда нет — в зависимости от мусора на стеке. Ошибка
     * редкая, невоспроизводимая и очень дорогая, поэтому размеры сверяются. */
    printf("\n\033[1m11. Раскладка ключей\033[0m\n");
    check("в ключе соединения нет дыр от выравнивания",
          sizeof(struct pp_key) == sizeof(((struct pp_key *)0)->addr) +
                                   sizeof(((struct pp_key *)0)->port) +
                                   sizeof(((struct pp_key *)0)->pad));
    check("в значении соединения нет дыр",
          sizeof(struct pp_conn) == sizeof(struct ip_key) + sizeof(__u32));
    check("ключ доверенных совпадает с обычным ключом адреса",
          sizeof(struct ip_key) == 16);

    /* ── Доверие PROXY по порту ───────────────────────────────────────
     *
     * Список доверенных источников привязан к адресу, а адреса CDN меняются.
     * В день смены разбор выключается молча: клиенты схлопываются в один
     * ключ, ключ получает лимит, через час — автоограничение. Флаг на порту
     * от смены адресов не зависит.
     *
     * Проверяем три вещи: что флаг включает разбор без всякого списка, что
     * без флага и без списка чужой заголовок по-прежнему игнорируется, и что
     * трафик доверенного релея без привязки считается, но не ограничивается. */
    printf("\n\033[1m12. Доверие PROXY по порту\033[0m\n");

    unsigned PPORT = 9443;
    unsigned char pp_flags = PORT_SHAPE | PORT_PROXY;
    map_put(&port_map, &PPORT, &pp_flags);

    unsigned RELAY_NEW = v4("198.51.100.77");   /* НЕТ в trusted_map */
    unsigned CLI_CDN   = v4("203.0.113.150");
    struct ip_key kcdn = {0}; kcdn.addr[0] = CLI_CDN;
    struct ip_key krelay = {0}; krelay.addr[0] = RELAY_NEW;

    plen = ppv2_tcp4(pay, "203.0.113.150");
    len = build_tcp_raw(SERVER, RELAY_NEW, 40001, PPORT, 0x18, pay, plen);
    run_pkt(len, 1);
    check("заголовок разобран без записи в списке доверенных",
          bpf_map_lookup_elem(&user_state_map_up, &kcdn) != NULL);
    check("адрес релея под свой ключ не попал",
          bpf_map_lookup_elem(&user_state_map_up, &krelay) == NULL);

    len = build_tcp_raw(SERVER, RELAY_NEW, 40001, PPORT, 0x10, pay, 0);
    run_pkt(len, 1);
    struct user_state *cdnst = bpf_map_lookup_elem(&user_state_map_up, &kcdn);
    check("следующие пакеты соединения идут туда же", cdnst && cdnst->packets >= 2);

    len = build_tcp_raw(RELAY_NEW, SERVER, PPORT, 40001, 0x10, pay1400, 1400);
    check("download к релею тормозится по адресу клиента",
          run_pkt(len, 0) == TC_ACT_OK &&
          bpf_map_lookup_elem(&user_state_map_down, &kcdn) != NULL);

    /* Соединение, открытое до загрузки движка: заголовок прошёл давно и
     * второй раз не придёт. Раньше такой трафик шейпился по адресу релея —
     * то есть все клиенты за CDN делили один лимит. */
    unsigned long long unres0 = stat_get(STAT_PP_UNRESOLVED);
    len = build_tcp_raw(SERVER, RELAY_NEW, 40777, PPORT, 0x10, pay1400, 1400);
    /* Первый пакет любого адреса выходит раньше — он заводит состояние и
     * уходит без задержки. Счётчик считается со второго. */
    run_pkt(len, 1);
    check("соединение без привязки пропускается без ограничения",
          run_pkt(len, 1) == TC_ACT_OK);
    check("и это видно по счётчику",
          stat_get(STAT_PP_UNRESOLVED) > unres0);
    check("но байты релея посчитаны",
          bpf_map_lookup_elem(&user_state_map_up, &krelay) != NULL);

    /* Порт без флага: доверия нет ни по адресу, ни по порту. */
    unsigned NPORT = 9444;
    map_put(&port_map, &NPORT, &one);
    unsigned CHEAT2 = v4("198.51.100.200");
    unsigned VICTIM2 = v4("203.0.113.201");
    struct ip_key kv2 = {0}; kv2.addr[0] = VICTIM2;
    struct ip_key kc2 = {0}; kc2.addr[0] = CHEAT2;
    plen = ppv2_tcp4(pay, "203.0.113.201");
    len = build_tcp_raw(SERVER, CHEAT2, 40002, NPORT, 0x18, pay, plen);
    run_pkt(len, 1);
    check("на порту без флага поддельный заголовок игнорируется",
          bpf_map_lookup_elem(&user_state_map_up, &kv2) == NULL);
    check("трафик остаётся на своём отправителе",
          bpf_map_lookup_elem(&user_state_map_up, &kc2) != NULL);

    /* ── Счётчики обработки ──────────────────────────────────────────── */
    printf("\n\033[1m13. Счётчики обработки\033[0m\n");
    check("пропущенные вниз считаются", stat_get(STAT_DOWN_PASS) > 0);
    check("пропущенные вверх считаются", stat_get(STAT_UP_PASS) > 0);
    check("разобранные заголовки считаются", stat_get(STAT_PP_RESOLVED) > 0);

    /* Горизонт: гоним пакеты, пока EDT не уйдёт больше чем на две секунды
     * вперёд. При 10 Мбит/с полуторакилобайтный пакет стоит 1.2 мс, значит
     * дроп наступит примерно на тысяча семисотом. Раньше дроп не проверялся
     * вовсе — ни один тест не доходил до TC_ACT_SHOT. */
    unsigned FLOOD = v4("203.0.113.250");
    int shot = 0;
    for (int i = 0; i < 4000 && !shot; i++) {
        len = build_v4(IPPROTO_TCP, 443, 52000, 0, 1400, FLOOD, SERVER);
        if (run_pkt(len, 0) == TC_ACT_SHOT)
            shot = 1;
    }
    check("за горизонтом EDT пакет отбрасывается", shot);
    check("и дроп посчитан", stat_get(STAT_DOWN_DROP) > 0);

    /* Ведро отдачи: 200 мс в долг, дальше дроп. */
    unsigned FLOODU = v4("203.0.113.251");
    int ushot = 0;
    for (int i = 0; i < 4000 && !ushot; i++) {
        len = build_v4(IPPROTO_TCP, 52001, 443, 0, 1400, FLOODU, SERVER);
        if (run_pkt(len, 1) == TC_ACT_SHOT)
            ushot = 1;
    }
    check("переполненное ведро отдачи роняет пакет", ushot);
    check("и этот дроп посчитан", stat_get(STAT_UP_DROP) > 0);

    printf("\n\033[1mИтог: %d пройдено, %d провалено\033[0m\n", ok, fail);
    return fail ? 1 : 0;
}

/*
 * Host test for the debug event ring (src/ringtrace.h, #89): plain cc, no
 * Amiga headers.  Covers the record layout, fill before the first wrap, the
 * wrap and overwrite count, a dump into too little room, a dump taken while
 * a writer runs (a mutex stands in for Forbid), and seq past 2^16.
 *
 *   cc -std=c11 -O2 -Wall -Wextra -Werror -pthread -o host_ringtrace tests/host_ringtrace.c
 *   ./host_ringtrace       -> "RESULT host_ringtrace checks=N failures=0"
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>

typedef uint8_t UBYTE;
typedef uint16_t UWORD;
typedef uint32_t ULONG;

#include "../src/ringtrace.h"

static int checks, failures;

#define EXPECT(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

static struct RtRing *mkring(ULONG log2)
{
    ULONG size = sizeof(struct RtRing) + (sizeof(struct RtRec) << log2);
    struct RtRing *r = malloc(size);
    rt_init(r, log2, size);
    return r;
}

/* record n carries n in every field it can, so a dump can be checked whole */
static void put_n(struct RtRing *r, ULONG n)
{
    rt_put(r, n * 7u, (UBYTE)(n % 13 + 1), (UBYTE)n, (UWORD)(n ^ 0x5a5a), n, ~n);
}

static int rec_ok(const struct RtRec *e, ULONG n)
{
    return e->r_Clo == n * 7u && e->r_Kind == (UBYTE)(n % 13 + 1) && e->r_A == (UBYTE)n &&
           e->r_B == (UWORD)(n ^ 0x5a5a) && e->r_C == n && e->r_D == (ULONG)~n;
}

/* every record in a dump is the one its sequence number says, in order */
static int dump_ok(const void *buf, ULONG bytes)
{
    const struct RtDumpHeader *h = buf;
    const struct RtRec *e = (const struct RtRec *)(h + 1);
    ULONG i;

    if (h->rd_Magic != RT_DUMP_MAGIC || h->rd_RecSize != 16 || h->rd_Version != RT_DUMP_VERSION)
        return 0;
    if (bytes != sizeof(*h) + h->rd_Count * 16u)
        return 0;
    if (h->rd_First + h->rd_Count != h->rd_Seq || h->rd_Lost != h->rd_First)
        return 0;
    for (i = 0; i < h->rd_Count; i++)
        if (!rec_ok(&e[i], h->rd_First + i))
            return 0;
    return 1;
}

static void test_layout(void)
{
    EXPECT(sizeof(struct RtRec) == 16);
    EXPECT(offsetof(struct RtRec, r_Clo) == 0);
    EXPECT(offsetof(struct RtRec, r_Kind) == 4);
    EXPECT(offsetof(struct RtRec, r_A) == 5);
    EXPECT(offsetof(struct RtRec, r_B) == 6);
    EXPECT(offsetof(struct RtRec, r_C) == 8);
    EXPECT(offsetof(struct RtRec, r_D) == 12);
    EXPECT(sizeof(struct RtDumpHeader) == 32);
    EXPECT(offsetof(struct RtDumpHeader, rd_Capacity) == 8);
    EXPECT(offsetof(struct RtDumpHeader, rd_Seq) == 12);
    EXPECT(offsetof(struct RtDumpHeader, rd_First) == 16);
    EXPECT(offsetof(struct RtDumpHeader, rd_Count) == 20);
    EXPECT(offsetof(struct RtDumpHeader, rd_Lost) == 24);
    EXPECT(offsetof(struct RtDumpHeader, rd_Clo) == 28);
    EXPECT(offsetof(struct RtRing, rt_Rec) == 16);
}

static void test_fill_and_wrap(void)
{
    struct RtRing *r = mkring(RT_MIN_LOG2);            /* 4096 */
    ULONG cap = 4096, n;
    size_t full = sizeof(struct RtDumpHeader) + cap * 16;
    void *buf = malloc(full);
    const struct RtDumpHeader *h = buf;
    ULONG bytes;

    /* empty */
    bytes = rt_snapshot(r, 123, buf, full);
    EXPECT(bytes == 32 && h->rd_Count == 0 && h->rd_Seq == 0 && h->rd_Lost == 0 && h->rd_Clo == 123);
    EXPECT(h->rd_Capacity == cap);

    /* header-only probe */
    for (n = 0; n < 10; n++) put_n(r, n);
    bytes = rt_snapshot(r, 5, buf, 32);
    EXPECT(bytes == 32 && h->rd_Count == 0 && h->rd_Seq == 10 && h->rd_Lost == 10);
    EXPECT(rt_snapshot(r, 5, buf, 31) == 0);

    /* one short of full, full, one past, many laps */
    for (; n < cap - 1; n++) put_n(r, n);
    bytes = rt_snapshot(r, 0, buf, full);
    EXPECT(dump_ok(buf, bytes) && h->rd_Count == cap - 1 && h->rd_Lost == 0);
    put_n(r, n++);
    bytes = rt_snapshot(r, 0, buf, full);
    EXPECT(dump_ok(buf, bytes) && h->rd_Count == cap && h->rd_Lost == 0 && h->rd_First == 0);
    put_n(r, n++);
    bytes = rt_snapshot(r, 0, buf, full);
    EXPECT(dump_ok(buf, bytes) && h->rd_Count == cap && h->rd_Lost == 1 && h->rd_First == 1);
    for (; n < 5 * cap + 17; n++) put_n(r, n);
    bytes = rt_snapshot(r, 0, buf, full);
    EXPECT(dump_ok(buf, bytes) && h->rd_Count == cap && h->rd_Lost == 4 * cap + 17);
    EXPECT(h->rd_Seq == 5 * cap + 17);

    /* too little room: the newest that fit, the rest counted lost */
    bytes = rt_snapshot(r, 0, buf, 32 + 100 * 16 + 15);
    EXPECT(dump_ok(buf, bytes) && h->rd_Count == 100 && h->rd_Lost == 5 * cap + 17 - 100);

    /* a dump is a copy: later writes leave it alone */
    bytes = rt_snapshot(r, 0, buf, full);
    for (ULONG k = 0; k < cap / 2; k++) put_n(r, n++);
    EXPECT(dump_ok(buf, bytes) && h->rd_Seq == 5 * cap + 17);

    free(buf);
    free(r);
}

/* A writer and a dumper at once; the mutex is Forbid() on the Amiga */
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct RtRing *shared;
static volatile int stop;

static void *writer(void *arg)
{
    ULONG n = 0;
    (void)arg;
    while (!stop)
    {
        pthread_mutex_lock(&lock);
        put_n(shared, n++);
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

static void test_dump_while_recording(void)
{
    pthread_t t;
    size_t full = sizeof(struct RtDumpHeader) + 4096 * 16;
    void *buf = malloc(full);
    int i, bad = 0, lapped = 0;
    ULONG seq, first = 0, last = 0;

    shared = mkring(RT_MIN_LOG2);
    stop = 0;
    pthread_create(&t, NULL, writer, NULL);
    /* start once the writer has lapped the ring three times */
    do
    {
        pthread_mutex_lock(&lock);
        seq = shared->rt_Seq;
        pthread_mutex_unlock(&lock);
        sched_yield();
    } while (seq < 3 * 4096);
    for (i = 0; i < 2000; i++)
    {
        ULONG bytes;
        pthread_mutex_lock(&lock);
        bytes = rt_snapshot(shared, (ULONG)i, buf, (i & 1) ? full : 32 + 1000 * 16);
        pthread_mutex_unlock(&lock);
        if (!dump_ok(buf, bytes))
            bad++;
        if (((struct RtDumpHeader *)buf)->rd_Lost)
            lapped++;
        if (i == 0)
            first = ((struct RtDumpHeader *)buf)->rd_Seq;
        last = ((struct RtDumpHeader *)buf)->rd_Seq;
        sched_yield();
    }
    stop = 1;
    pthread_join(t, NULL);
    EXPECT(bad == 0);
    EXPECT(lapped == 2000);    /* every dump saw a ring already overwritten */
    EXPECT(last > first);      /* and the writer ran between the dumps */
    free(buf);
    free(shared);
}

static void test_mask_index(void)
{
    struct RtRing *r = mkring(RT_MIN_LOG2);
    ULONG i;

    /* rt_Seq near 2^32: indexes by mask, counts stay modular */
    r->rt_Seq = 0xFFFFFFFFu - 2000;
    for (i = 0; i < 1000; i++)
        put_n(r, r->rt_Seq);
    EXPECT(r->rt_Seq == 0xFFFFFFFFu - 1000);
    EXPECT(rec_ok(&r->rt_Rec[(0xFFFFFFFFu - 1001) & r->rt_Mask], 0xFFFFFFFFu - 1001));
    free(r);
}

/* An IPv4 TCP frame from the IP header on: ihl in words, payload bytes after a 20-byte TCP header */
static ULONG mk_tcp(UBYTE *b, int ihl, ULONG payload, UWORD id, ULONG seq, ULONG ack, UBYTE flags, UWORD frag)
{
    ULONG hl = ihl * 4, tot = hl + 20 + payload, i;
    memset(b, 0, tot);
    b[0] = 0x40 | ihl; b[2] = tot >> 8; b[3] = tot; b[4] = id >> 8; b[5] = id;
    b[6] = frag >> 8; b[7] = frag; b[8] = 64; b[9] = 6;
    b[12] = 192; b[13] = 168; b[14] = 1; b[15] = 137; b[16] = 192; b[17] = 168; b[18] = 1; b[19] = 136;
    b[hl] = 0x1d; b[hl + 1] = 0x4e; b[hl + 2] = 0x9e; b[hl + 3] = 0x0e;      /* 7502 -> 40462 */
    for (i = 0; i < 4; i++) { b[hl + 4 + i] = seq >> (24 - 8 * i); b[hl + 8 + i] = ack >> (24 - 8 * i); }
    b[hl + 12] = 5 << 4; b[hl + 13] = flags;
    return tot;
}

static void test_txid(void)
{
    UBYTE b[256];
    struct RtTx t;
    struct RtRing *r = mkring(RT_MIN_LOG2);
    size_t full = sizeof(struct RtDumpHeader) + 4096 * 16;
    void *buf = malloc(full);
    const struct RtRec *e = (const struct RtRec *)((struct RtDumpHeader *)buf + 1);
    ULONG n;

    /* plain ACK, then options in the IP header, both parse */
    n = mk_tcp(b, 5, 0, 0x1234, 0xA1B2C3D4, 0x0102F0F0, 0x10, 0);
    EXPECT(rt_parse_tx(b, n, 0x0800, &t) == 1);
    EXPECT(t.tx_IPId == 0x1234 && t.tx_Ack == 0x0102F0F0 && t.tx_Seq == 0xA1B2C3D4 && t.tx_Flags == 0x10);
    EXPECT(t.tx_SPort == 7502 && t.tx_DPort == 40462 && t.tx_Src == 137 && t.tx_Dst == 136 && t.tx_Payload == 0);
    n = mk_tcp(b, 6, 100, 7, 1, 2, 0x18, 0);
    EXPECT(rt_parse_tx(b, n, 0x0800, &t) == 1 && t.tx_SPort == 7502 && t.tx_Payload == 100 && t.tx_IPId == 7);
    /* IP length past the bytes given: clipped to them */
    EXPECT(rt_parse_tx(b, n - 50, 0x0800, &t) == 1 && t.tx_Payload == 50);

    /* refused, with what is known */
    n = mk_tcp(b, 5, 0, 1, 1, 1, 0x10, 0);
    EXPECT(rt_parse_tx(b, n, 0x86dd, &t) == 0 && t.tx_Proto == 0xff);          /* not IPv4 ethertype */
    EXPECT(rt_parse_tx(b, 19, 0x0800, &t) == 0 && t.tx_Proto == 0xff);         /* short of an IP header */
    EXPECT(rt_parse_tx(b, 30, 0x0800, &t) == 0 && t.tx_Proto == 6);            /* short of a TCP header */
    b[0] = 0x45 + 0x10;
    EXPECT(rt_parse_tx(b, n, 0x0800, &t) == 0 && t.tx_Proto == 0xff);          /* version 5 */
    b[0] = 0x44;
    EXPECT(rt_parse_tx(b, n, 0x0800, &t) == 0 && t.tx_Proto == 0xff);          /* ihl 4 */
    b[0] = 0x4f;
    EXPECT(rt_parse_tx(b, n, 0x0800, &t) == 0 && t.tx_Proto == 0xff);          /* ihl past the frame */
    n = mk_tcp(b, 5, 0, 1, 1, 1, 0x10, 0x0010);
    EXPECT(rt_parse_tx(b, n, 0x0800, &t) == 0 && t.tx_Proto == 6);             /* not the first fragment */
    n = mk_tcp(b, 5, 0, 1, 1, 1, 0x10, 0); b[9] = 17;
    EXPECT(rt_parse_tx(b, n, 0x0800, &t) == 0 && t.tx_Proto == 17);            /* UDP */
    n = mk_tcp(b, 5, 8, 1, 1, 1, 0x10, 0); b[32] = 0x20;
    EXPECT(rt_parse_tx(b, n, 0x0800, &t) == 1 && t.tx_Payload == 0);           /* data offset 8 words: no payload claimed */

    /* records: a TCP frame is a TXID1/TXID2 pair, anything else one TXO */
    n = mk_tcp(b, 5, 0, 0xBEEF, 0x11111111, 0x22222222, 0x10, 0);
    rt_put_tx(r, 500, &t, rt_parse_tx(b, n, 0x0800, &t), 3, 7, 0xC4, 0x0800, n);
    t.tx_Proto = 17;
    rt_put_tx(r, 501, &t, 0, 4, 7, 0xC5, 0x0800, 60);
    EXPECT(rt_snapshot(r, 0, buf, full) == 32 + 3 * 16);
    EXPECT(e[0].r_Kind == RT_TXID1 && e[0].r_Clo == 500 && e[0].r_A == 0x10 && e[0].r_B == 0xBEEF &&
           e[0].r_C == 0x22222222 && e[0].r_D == 0x11111111);
    EXPECT(e[1].r_Kind == RT_TXID2 && e[1].r_Clo == 500 && e[1].r_A == 3 && e[1].r_B == ((7 << 8) | 0xC4) &&
           e[1].r_C == ((7502UL << 16) | 40462) && e[1].r_D == ((137UL << 24) | (136UL << 16)));
    EXPECT(e[2].r_Kind == RT_TXO && e[2].r_A == 4 && e[2].r_B == ((7 << 8) | 0xC5) &&
           e[2].r_C == ((0x0800UL << 16) | 17) && e[2].r_D == 60);
    /* RX: the same pair shape, outcome in b's high byte */
    n = mk_tcp(b, 5, 200, 0x0BAD, 0x33333333, 0x44444444, 0x10, 0);
    rt_put_rx(r, 600, &t, rt_parse_tx(b, n, 0x0800, &t), 2, RT_RX_READ, 0x7E, 0x0800, n + 14);
    t.tx_Proto = 0xff;
    rt_put_rx(r, 601, &t, 0, 0, RT_RX_DROPPED, 0x7F, 0x0806, 60);
    EXPECT(rt_snapshot(r, 0, buf, full) == 32 + 6 * 16);
    EXPECT(e[3].r_Kind == RT_RXID1 && e[3].r_A == 0x10 && e[3].r_B == 0x0BAD && e[3].r_C == 0x44444444 && e[3].r_D == 0x33333333);
    EXPECT(e[4].r_Kind == RT_RXID2 && e[4].r_A == 2 && e[4].r_B == ((RT_RX_READ << 8) | 0x7E) &&
           e[4].r_D == ((137UL << 24) | (136UL << 16) | 200));
    EXPECT(e[5].r_Kind == RT_RXO && e[5].r_B == ((RT_RX_DROPPED << 8) | 0x7F) && e[5].r_C == ((0x0806UL << 16) | 0xff) && e[5].r_D == 60);
    free(buf);
    free(r);
}

int main(void)
{
    test_layout();
    test_fill_and_wrap();
    test_dump_while_recording();
    test_mask_index();
    test_txid();
    printf("RESULT host_ringtrace checks=%d failures=%d\n", checks, failures);
    return failures ? 1 : 0;
}

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

    shared = mkring(RT_MIN_LOG2);
    stop = 0;
    pthread_create(&t, NULL, writer, NULL);
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
    }
    stop = 1;
    pthread_join(t, NULL);
    EXPECT(bad == 0);
    EXPECT(lapped > 0);        /* the writer did lap the ring meanwhile */
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

int main(void)
{
    test_layout();
    test_fill_and_wrap();
    test_dump_while_recording();
    test_mask_index();
    printf("RESULT host_ringtrace checks=%d failures=%d\n", checks, failures);
    return failures ? 1 : 0;
}

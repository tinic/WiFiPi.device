/*
 * TX glom head split decision (#89), on the host:
 *   cc -O2 -Wall -Wextra -o test_glomsplit tests/test_glomsplit.c && ./test_glomsplit
 * Prints RESULT pass=N fail=M; exit status 0 only when nothing failed.
 */
#include <stdio.h>
#include <string.h>

#include "../src/glomsplit.h"

static int checks, failures;

static void expect(int got, int want, const char *what)
{
    checks++;
    if (got == want) return;
    failures++;
    printf("FAIL %s: got %d, want %d\n", what, got, want);
}

#define ACK 0x10
#define PSH 0x08
#define FIN 0x01
#define SYN 0x02
#define RST 0x04

/* Ethernet + IPv4 + TCP; optlen bytes of TCP options, dlen of payload */
static unsigned long v4(unsigned char *f, unsigned int src, unsigned int sport,
                        unsigned int dport, unsigned int flags, unsigned int optlen,
                        unsigned int dlen)
{
    unsigned char *ip = f + 14, *t = ip + 20;
    unsigned int thl = 20 + optlen, iplen = 20 + thl + dlen;

    memset(f, 0, 14 + iplen + 16);
    f[12] = 0x08; f[13] = 0x00;
    ip[0] = 0x45; ip[2] = iplen >> 8; ip[3] = iplen;
    ip[6] = 0x40;                                   /* DF */
    ip[8] = 64; ip[9] = 6;
    ip[12] = 192; ip[13] = 168; ip[14] = 1; ip[15] = src;
    ip[16] = 192; ip[17] = 168; ip[18] = 1; ip[19] = 2;
    t[0] = sport >> 8; t[1] = sport; t[2] = dport >> 8; t[3] = dport;
    t[12] = (thl / 4) << 4; t[13] = flags;
    return 14 + iplen;
}

/* Ethernet + IPv6 + TCP */
static unsigned long v6(unsigned char *f, unsigned int src, unsigned int nh,
                        unsigned int sport, unsigned int flags, unsigned int dlen)
{
    unsigned char *ip = f + 14, *t = ip + 40;
    unsigned int plen = 20 + dlen;

    memset(f, 0, 14 + 40 + plen + 16);
    f[12] = 0x86; f[13] = 0xdd;
    ip[0] = 0x60; ip[4] = plen >> 8; ip[5] = plen; ip[6] = nh; ip[7] = 64;
    ip[8] = 0xfe; ip[9] = 0x80; ip[23] = src;
    ip[24] = 0xfe; ip[25] = 0x80; ip[39] = 2;
    t[0] = sport >> 8; t[1] = sport; t[2] = 0x14; t[3] = 0x51;
    t[12] = 5 << 4; t[13] = flags;
    return 14 + 40 + plen;
}

static unsigned char a[1600], b[1600];
static const unsigned char *fr[2] = { a, b };
static unsigned long ln[2];

static int split(unsigned long count) { return wifipi_glom_head_split(fr, ln, count); }

/* a queue as the driver sends it: glom sizes into sizes[], returns the count */
#define MAXQ 33
static unsigned char q[MAXQ][192];
static const unsigned char *qf[MAXQ];
static unsigned long ql[MAXQ];

static int emit(unsigned long n, unsigned long *sizes)
{
    unsigned long h = 0;
    int k = 0;

    while (h < n)
    {
        unsigned long take = wifipi_glom_take(qf + h, ql + h, n - h);

        /* nothing of 3+ leaves with a same-flow pure-ACK head pair */
        if (take >= 3 && wifipi_glom_head_split(qf + h, ql + h, take)) return -1;
        sizes[k++] = take;
        h += take;
    }
    return k;
}

/* acks same-flow pure ACKs, then tail frames of data (1) or UDP (2) */
static void queue(unsigned long acks, unsigned long tail, int kind)
{
    unsigned long i;

    for (i = 0; i < acks + tail; i++)
    {
        ql[i] = v4(q[i], 10, 5001, 50000, ACK, 0, i < acks ? 0 : 100);
        if (i >= acks && kind == 2) q[i][14 + 9] = 17;
        qf[i] = q[i];
    }
}

static void expect_emit(unsigned long n, const unsigned long *want, int wantk, const char *what)
{
    unsigned long got[MAXQ];
    int k = emit(n, got), i, same = k == wantk;

    for (i = 0; same && i < k; i++) same = got[i] == want[i];
    expect(same, 1, what);
    if (!same)
    {
        printf("   got");
        for (i = 0; i < k; i++) printf(" %lu", got[i]);
        printf(" (k=%d)\n", k);
    }
}

static void runs(void)
{
    static const unsigned long r3[] = { 2, 1 }, r4[] = { 2, 2 }, r8[] = { 2, 2, 2, 2 };
    static const unsigned long r3d[] = { 2, 2 }, r4d[] = { 2, 2, 1 }, r2d[] = { 2, 1 };
    static const unsigned long d32[] = { 32 }, one2[] = { 2 }, a1d[] = { 3 };
    unsigned long r32[16], r32d[17], mix[] = { 2, 31 };
    int i;

    for (i = 0; i < 16; i++) r32[i] = r32d[i] = 2;
    r32d[16] = 1;

    queue(3, 0, 0);  expect_emit(3, r3, 2, "run 3: 2+1");
    queue(4, 0, 0);  expect_emit(4, r4, 2, "run 4: 2+2");
    queue(8, 0, 0);  expect_emit(8, r8, 4, "run 8: 4 pairs");
    queue(32, 0, 0); expect_emit(32, r32, 16, "run 32: 16 pairs");
    queue(3, 1, 1);  expect_emit(4, r3d, 2, "run 3 + data: 2+2");
    queue(4, 1, 1);  expect_emit(5, r4d, 3, "run 4 + data: 2+2+1");
    queue(32, 1, 1); expect_emit(33, r32d, 17, "run 32 + data: 16 pairs + 1");
    queue(2, 1, 2);  expect_emit(3, r2d, 2, "2 ACKs + UDP: 2+1");
    queue(2, 0, 0);  expect_emit(2, one2, 1, "2 ACKs: one glom of 2");
    queue(1, 2, 1);  expect_emit(3, a1d, 1, "ACK + 2 data: one glom of 3");
    queue(0, 32, 1); expect_emit(32, d32, 1, "32 data frames: one glom of 32");
    /* 2 ACKs, then 31 data frames: the pair goes alone, the bulk stays whole */
    queue(2, 31, 1); expect_emit(33, mix, 2, "2 ACKs + 31 data: 2+31");
}

int main(void)
{
    /* two same-flow pure ACKs heading 3 and 32 frames: split */
    ln[0] = v4(a, 10, 5001, 50000, ACK, 0, 0);
    ln[1] = v4(b, 10, 5001, 50000, ACK, 0, 0);
    expect(split(3), 1, "A40,A40 count 3");
    expect(split(32), 1, "A40,A40 count 32");
    /* two frames, or one: no split */
    expect(split(2), 0, "A40,A40 count 2");
    expect(split(1), 0, "count 1");
    /* the Ethernet frame may be longer than the IP datagram */
    ln[0] += 6;
    expect(split(3), 1, "Ethernet tail beyond IP length");
    /* a truncated frame is not read past its end */
    ln[0] = 14 + 39;
    expect(split(3), 0, "truncated head");

    /* timestamps and SACK options: still pure ACKs */
    ln[0] = v4(a, 10, 5001, 50000, ACK, 12, 0);
    ln[1] = v4(b, 10, 5001, 50000, ACK, 20, 0);
    expect(split(3), 1, "ACKs with options");
    /* PSH on an empty segment: still pure */
    ln[0] = v4(a, 10, 5001, 50000, ACK | PSH, 0, 0);
    expect(split(3), 1, "ACK|PSH no payload");

    /* different flows: no split */
    ln[0] = v4(a, 10, 5001, 50000, ACK, 0, 0);
    ln[1] = v4(b, 10, 5002, 50000, ACK, 0, 0);
    expect(split(3), 0, "different source port");
    ln[1] = v4(b, 10, 5001, 50001, ACK, 0, 0);
    expect(split(3), 0, "different destination port");
    ln[1] = v4(b, 11, 5001, 50000, ACK, 0, 0);
    expect(split(3), 0, "different source address");
    ln[1] = v4(b, 10, 5001, 50000, ACK, 0, 0);
    b[14 + 19] = 3;
    expect(split(3), 0, "different destination address");

    /* data at the head, or second: no split */
    ln[0] = v4(a, 10, 5001, 50000, ACK, 0, 1);
    ln[1] = v4(b, 10, 5001, 50000, ACK, 0, 0);
    expect(split(3), 0, "data segment at the head");
    ln[0] = v4(a, 10, 5001, 50000, ACK | PSH, 0, 1460);
    expect(split(32), 0, "bulk data head");
    ln[0] = v4(a, 10, 5001, 50000, ACK, 0, 0);
    ln[1] = v4(b, 10, 5001, 50000, ACK, 0, 1460);
    expect(split(32), 0, "data segment second");

    /* FIN, SYN, RST, no ACK: no split */
    ln[1] = v4(b, 10, 5001, 50000, ACK, 0, 0);
    ln[0] = v4(a, 10, 5001, 50000, ACK | FIN, 0, 0);
    expect(split(3), 0, "ACK|FIN at the head");
    ln[0] = v4(a, 10, 5001, 50000, ACK, 0, 0);
    ln[1] = v4(b, 10, 5001, 50000, ACK | FIN, 0, 0);
    expect(split(3), 0, "ACK|FIN second");
    ln[0] = v4(a, 10, 5001, 50000, ACK | SYN, 0, 0);
    ln[1] = v4(b, 10, 5001, 50000, ACK, 0, 0);
    expect(split(3), 0, "SYN|ACK at the head");
    ln[0] = v4(a, 10, 5001, 50000, ACK | RST, 0, 0);
    expect(split(3), 0, "RST|ACK at the head");
    ln[0] = v4(a, 10, 5001, 50000, 0, 0, 0);
    expect(split(3), 0, "no ACK flag");

    /* UDP, ARP, IPv4 fragment: no split */
    ln[0] = v4(a, 10, 5001, 50000, ACK, 0, 0);
    a[14 + 9] = 17;
    expect(split(3), 0, "UDP head");
    ln[0] = v4(a, 10, 5001, 50000, ACK, 0, 0);
    a[12] = 0x08; a[13] = 0x06;
    expect(split(3), 0, "ARP head");
    ln[0] = v4(a, 10, 5001, 50000, ACK, 0, 0);
    a[14 + 6] = 0x20;
    expect(split(3), 0, "MF fragment head");
    ln[0] = v4(a, 10, 5001, 50000, ACK, 0, 0);
    a[14 + 20 + 12] = 4 << 4;            /* TCP data offset 16 */
    expect(split(3), 0, "bad TCP data offset");
    /* IPv4 header options: still pure */
    ln[0] = v4(a, 10, 5001, 50000, ACK, 0, 0);
    memmove(a + 14 + 24, a + 14 + 20, 20);
    memset(a + 14 + 20, 1, 4);
    a[14] = 0x46; a[14 + 3] = 44; ln[0] += 4;
    expect(split(3), 1, "IPv4 header options");

    /* IPv6 */
    ln[0] = v6(a, 10, 6, 5001, ACK, 0);
    ln[1] = v6(b, 10, 6, 5001, ACK, 0);
    expect(split(3), 1, "IPv6 ACK,ACK count 3");
    expect(split(2), 0, "IPv6 ACK,ACK count 2");
    ln[1] = v6(b, 11, 6, 5001, ACK, 0);
    expect(split(3), 0, "IPv6 different source address");
    ln[1] = v6(b, 10, 6, 5002, ACK, 0);
    expect(split(3), 0, "IPv6 different port");
    ln[1] = v6(b, 10, 6, 5001, ACK, 100);
    expect(split(3), 0, "IPv6 data second");
    ln[1] = v6(b, 10, 6, 5001, ACK | FIN, 0);
    expect(split(3), 0, "IPv6 ACK|FIN second");
    ln[1] = v6(b, 10, 0, 5001, ACK, 0);
    expect(split(3), 0, "IPv6 extension header");
    /* IPv4 then IPv6: no split */
    ln[0] = v4(a, 10, 5001, 50000, ACK, 0, 0);
    ln[1] = v6(b, 10, 6, 5001, ACK, 0);
    expect(split(3), 0, "IPv4 then IPv6");

    runs();

    printf("RESULT pass=%d fail=%d\n", checks - failures, failures);
    return failures != 0;
}

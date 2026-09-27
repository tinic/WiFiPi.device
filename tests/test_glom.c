/*
 * wifipi.device TX glom framing (#89), run under an emulator: no Pi hardware.
 * The real SendGlomDataPacket is linked in and a fake SendPKT takes the
 * superframe as the card would.  Each case builds the expected image on its
 * own and compares every byte sent.
 *
 * The rule, from Linux brcmf_sdio_txpkt_prep/_sg: a chain of more than one
 * frame is a whole number of 512-byte F2 blocks.  The last frame's tail pad
 * takes the chain up to the next block, (512 - total % 512) % 512 bytes, so
 * an aligned chain gets nothing added; those bytes are zero, and the first
 * frame's hardware length covers them.  One frame, as Linux sends a queue of
 * one, declares its own length and no tail pad; the transfer still runs to
 * the next word.
 *
 * Covered: count 1, 2, 3, 4 and 32; each of the four subframe residues
 * (length % 4); a chain that is already a multiple of 512; one that spans
 * blocks; 32 frames of the largest payload; the sequence numbers across the
 * 255 -> 0 wrap; every request replied and counted.
 */
#include <exec/exec.h>
#include <exec/io.h>
#include <devices/sana2.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <string.h>

#include "../src/wifipi.h"
#include "../src/packet.h"

int SendGlomDataPacket(struct SDIO *sdio, struct IOSana2Req **ioList, UBYTE count);

static int checks, failures;

static void rawput(char c)
{
    register struct ExecBase *a6 __asm("a6") = SysBase;
    register char d0 __asm("d0") = c;
    __asm volatile ("jsr -516(%%a6)" : "+r"(d0) : "r"(a6) : "d1", "a0", "a1", "cc", "memory");
}
static void out(const char *s)
{
    const char *p;
    for (p = s; *p; p++) { if (*p == '\n') rawput('\r'); rawput(*p); }
    PutStr((CONST_STRPTR)s);
}
#undef PutStr
#define PutStr(s) out(s)
static void num(LONG v) { char b[12]; int i = 11; ULONG u = v < 0 ? -v : v; b[i] = 0; do { b[--i] = '0' + u % 10; u /= 10; } while (u); if (v < 0) b[--i] = '-'; PutStr(b + i); }
static void expect(int ok, const char *what)
{
    checks++;
    if (ok) return;
    failures++;
    PutStr("FAIL "); PutStr(what); PutStr("\n");
}
static void expect_eq(LONG got, LONG want, const char *what)
{
    checks++;
    if (got == want) return;
    failures++;
    PutStr("FAIL "); PutStr(what); PutStr(": got "); num(got); PutStr(", want "); num(want); PutStr("\n");
}

static struct WiFiBase fbase;
static struct WiFiUnit funit;
static struct SDIO fsdio;
static struct Opener fopener;

#define TXBUF   65536
#define FILL    0xAA            /* what the TX buffer holds before each send */
#define MAXF    32
#define MAXDATA 1500

static UBYTE *txbuf, *sent, *want;
static volatile ULONG sentLen;
static volatile int sends;

static void fake_sendpkt(UBYTE *pkt, ULONG length, struct SDIO *sdio)
{
    (void)sdio;
    sentLen = length;
    CopyMem(pkt, sent, length <= TXBUF ? length : TXBUF);
    sends++;
}

static BOOL copyfn(REGARG(APTR to, "a0"), REGARG(APTR from, "a1"), REGARG(ULONG len, "d0"))
{
    CopyMem(from, to, len);
    return TRUE;
}

static struct IOSana2Req ios[MAXF];
static struct IOSana2Req *iolist[MAXF];
static UBYTE payload[MAXF][MAXDATA];
static struct MsgPort *replyPort;

static const UBYTE dst[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };

static void le16(UBYTE *p, UWORD v) { p[0] = v & 0xff; p[1] = v >> 8; }
static ULONG rd16(const UBYTE *p) { return p[0] | (p[1] << 8); }

/* one case: count frames with these data lengths, first sequence seq0 */
static void run(const char *name, UBYTE count, const UWORD *dl, UBYTE seq0)
{
    ULONG off[MAXF], pl[MAXF], sum = 0, pad, total, i, j, replies = 0;
    ULONG sentBefore = funit.wu_Stats.PacketsSent;
    struct Message *m;
    int bad;

    PutStr("case "); PutStr(name); PutStr("\n");

    for (i = 0; i < count; i++)
    {
        pl[i] = dl[i] + 12 + 8 + 4 + 14;    /* hw+sw, glom ext, BDC, Ethernet */
        off[i] = sum;
        sum += (pl[i] + 3) & ~3;
    }
    pad = count > 1 ? (512 - sum % 512) % 512 : 0;
    total = sum + pad;

    /* the expected image: FILL where the driver writes nothing */
    memset(want, FILL, TXBUF);
    for (i = 0; i < count; i++)
    {
        UBYTE *f = want + off[i];
        ULONG hl = count == 1 ? pl[0] : i == 0 ? total : pl[i];
        ULONG tp = count == 1 ? 0 : ((-pl[i]) & 3) + (i == count - 1 ? pad : 0);
        le16(f + 0, hl);
        le16(f + 2, ~hl);
        le16(f + 4, pl[i] - 4);
        f[6] = 0;
        f[7] = i == count - 1;
        le16(f + 8, 0);
        le16(f + 10, tp);
        f[12] = (UBYTE)(seq0 + i);
        f[13] = 2;                          /* SDPCM_DATA_CHANNEL */
        f[14] = 0;
        f[15] = 20;                         /* data offset: 12 + 8 */
        f[16] = 0; f[17] = 0; f[18] = 0; f[19] = 0;
        f[20] = 0x20; f[21] = 0; f[22] = 0; f[23] = 0;
        memcpy(f + 24, dst, 6);
        memcpy(f + 30, funit.wu_EtherAddr, 6);
        f[36] = 0x08; f[37] = 0x00;
        memcpy(f + 38, payload[i], dl[i]);
    }
    for (j = 0; j < pad; j++) want[sum + j] = 0;

    for (i = 0; i < count; i++)
    {
        ios[i].ios2_Req.io_Message.mn_ReplyPort = replyPort;
        ios[i].ios2_Req.io_Message.mn_Node.ln_Type = NT_MESSAGE;
        ios[i].ios2_Req.io_Flags = 0;
        ios[i].ios2_BufferManagement = &fopener;
        ios[i].ios2_Data = payload[i];
        ios[i].ios2_DataLength = dl[i];
        ios[i].ios2_PacketType = 0x0800;
        memcpy(ios[i].ios2_DstAddr, dst, 6);
        iolist[i] = &ios[i];
    }

    memset(txbuf, FILL, TXBUF);
    memset(sent, 0x55, TXBUF);
    fsdio.s_TXSeq = seq0;
    sends = 0;
    SendGlomDataPacket(&fsdio, iolist, count);

    expect_eq(sends, 1, "one SendPKT per chain");
    expect_eq(sentLen, total, "transfer length");
    if (count > 1)
    {
        expect_eq(rd16(sent), total & 0xffff, "first hw length = chain total");
        expect_eq(rd16(sent + 2), (~total) & 0xffff, "first hw complement");
        expect_eq(sentLen % 512, 0, "a chain is whole 512-byte blocks");
        expect_eq(rd16(sent + off[count - 1] + 10), ((-pl[count - 1]) & 3) + pad, "last TailPad");
    }
    else
    {
        expect_eq(rd16(sent), pl[0], "one frame: hw length is the frame's own");
        expect_eq(rd16(sent + 2), (~pl[0]) & 0xffff, "one frame: hw complement");
        expect_eq(rd16(sent + 10), 0, "one frame: no tail pad declared");
        expect_eq(sentLen, (pl[0] + 3) & ~3, "one frame: transfer to the next word");
    }
    expect_eq(sent[off[count - 1] + 7], 1, "last-frame flag on the last");
    for (i = 0, bad = 0; i + 1 < count; i++)
        if (sent[off[i] + 7] != 0) bad++;
    expect_eq(bad, 0, "no last-frame flag before it");
    for (i = 0, bad = 0; i < count; i++)
        if (rd16(sent + off[i] + 4) != pl[i] - 4) bad++;
    expect_eq(bad, 0, "per-frame ext lengths unchanged");
    for (i = 1, bad = 0; i < count; i++)
        if (rd16(sent + off[i]) != pl[i] || rd16(sent + off[i] + 2) != ((~pl[i]) & 0xffff)) bad++;
    expect_eq(bad, 0, "later frames' hw length/complement unchanged");
    for (i = 0, bad = 0; i < count; i++)
        if (sent[off[i] + 12] != (UBYTE)(seq0 + i)) bad++;
    expect_eq(bad, 0, "sequence numbers");
    for (i = 0, bad = 0; i < count; i++)
        if (memcmp(sent + off[i] + 38, payload[i], dl[i]) != 0) bad++;
    expect_eq(bad, 0, "payloads");
    for (j = 0, bad = 0; j < pad && sum + j < TXBUF; j++)
        if (sent[sum + j] != 0) bad++;
    expect_eq(bad, 0, "chain pad bytes are zero");
    expect_eq(fsdio.s_TXSeq, (UBYTE)(seq0 + count), "TX seq advanced by count");
    expect(sentLen <= TXBUF && memcmp(sent, want, total) == 0, "every byte as expected");

    while ((m = GetMsg(replyPort)) != NULL) replies++;
    expect_eq(replies, count, "every request replied");
    expect_eq(funit.wu_Stats.PacketsSent - sentBefore, count, "every request counted");
}

int main(void)
{
    /* frame length = data + 38: residues 0, 1, 2, 3 mod 4; 40 bytes of data
       is the 78-byte TCP ACK frame the A1200 sent (hw 78, not 80) */
    static const UWORD one2[] = { 2 }, one3[] = { 3 }, ack[] = { 40 }, one5[] = { 5 };
    static const UWORD two[] = { 3, 4 }, three[] = { 2, 3, 5 }, four[] = { 2, 3, 4, 5 };
    static const UWORD aligned[] = { 218, 218 };        /* 2 x 256 = 512 */
    static const UWORD aligned2[] = { 474, 474, 474, 474 }; /* 4 x 512 */
    static const UWORD span[] = { 1000, 701 };
    static const UWORD acks[] = { 40, 40, 40 };         /* TCP ACK size, as in the arm */
    static UWORD big[MAXF];
    ULONG i, j;

    fbase.w_SysBase = SysBase;
    fbase.w_Unit = &funit;
    fbase.w_SDIO = &fsdio;
    funit.wu_Base = &fbase;
    for (i = 0; i < 6; i++) funit.wu_EtherAddr[i] = 0xe0 + i;
    fsdio.s_SysBase = SysBase;
    fsdio.s_WiFiBase = &fbase;
    fsdio.SendPKT = fake_sendpkt;
    fopener.o_TXFunc = copyfn;

    txbuf = AllocMem(TXBUF, MEMF_ANY);
    sent = AllocMem(TXBUF, MEMF_ANY);
    want = AllocMem(TXBUF, MEMF_ANY);
    replyPort = CreateMsgPort();
    PutStr("wifipi.device TX glom framing\n");
    if (txbuf == NULL || sent == NULL || want == NULL || replyPort == NULL)
    {
        PutStr("RESULT FAIL setup\n");
        return 20;
    }
    fsdio.s_TXBuffer = txbuf;
    for (i = 0; i < MAXF; i++)
        for (j = 0; j < MAXDATA; j++) payload[i][j] = (UBYTE)(i * 31 + j * 7 + 1);
    for (i = 0; i < MAXF; i++) big[i] = MAXDATA;

    run("1 frame, residue 0", 1, one2, 7);
    run("1 frame, residue 1", 1, one3, 7);
    run("1 frame, residue 2: the 78-byte TCP ACK", 1, ack, 7);
    run("1 frame, residue 3", 1, one5, 7);
    run("2 frames", 2, two, 7);
    run("3 frames", 3, three, 254);         /* sequence wraps */
    run("4 frames, all residues", 4, four, 0);
    run("3 ACK-sized frames", 3, acks, 100);
    run("2 frames, already 512", 2, aligned, 9);
    run("4 frames, already 2048", 4, aligned2, 9);
    run("2 frames across blocks", 2, span, 9);
    run("32 frames of 1500", 32, big, 240);

    DeleteMsgPort(replyPort);
    FreeMem(want, TXBUF);
    FreeMem(sent, TXBUF);
    FreeMem(txbuf, TXBUF);

    PutStr(failures ? "RESULT FAIL " : "RESULT PASS "); num(checks); PutStr(" checks, "); num(failures); PutStr(" failures\n");
    return failures ? 20 : 0;
}

/*
 * wifipi.device control frames and the 1518-byte cap (#89), run under an
 * emulator: no Pi hardware.  The real PacketGetVarMin/PacketSetVar/
 * PacketSetVarAsync/PacketCtrlQueue/PacketCtrlComplete are linked in; a
 * helper task stands in for the receiver, takes each frame as the card would
 * and answers it with a reply of a chosen length.
 *
 * Linux bcdc (brcmf_proto_bcdc_msg) advertises the whole output size in
 * msg->len but sends at most BRCMF_TX_IOCTL_MAX_MSG_SIZE = 1518 BCDC bytes.
 * A 'counters' GET of 2048 used to send 16 + 2048.  Covered:
 *   - GET 2048 / 1503 / 1502 / 100, plain and glommed: bytes sent, c_Length
 *     kept at the requested size, the name whole, the rest sent zero, the
 *     allocation rounded up to 4 past what is sent (#97);
 *   - the reply copy bounded by the caller's buffer, by the bytes received
 *     and by the reply's own c_Length, with a canary behind the buffer, for
 *     long, short and truncated replies;
 *   - a name of exactly 1501 characters (1502 with its NUL) sent, one of 1502
 *     refused with PACKET_CTRL_TOOBIG and nothing sent;
 *   - SET at exactly 1518 BCDC bytes sent whole, one byte more refused with
 *     PACKET_CTRL_TOOBIG, nothing sent, not a dead link; negative and huge
 *     sizes refused; the async SET the same, silently;
 *   - a mcast_list SET of 249 groups (the size UpdateMCastList sends) refused.
 */
#include <exec/exec.h>
#include <exec/io.h>
#include <devices/sana2.h>
#include <devices/timer.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <dos/dostags.h>
#include <string.h>

#include "../src/wifipi.h"
#include "../src/packet.h"

/* so the same test runs on a tree from before the cap, which must fail it */
#ifndef PACKET_CTRL_MAX_MSG
#define PACKET_CTRL_MAX_MSG 1518
#endif
#ifndef PACKET_CTRL_TOOBIG
#define PACKET_CTRL_TOOBIG  0x7fff0004
#endif

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
static struct Chip fchip;
static struct MinList waitList;

/* ------------------------------------------------------------------ */
/* The card: what was sent                                             */

#define SENTMAX 2400
static UBYTE sent[SENTMAX];
static volatile ULONG sentLen, sentHw, sentAlloc, sends;
static volatile int sentAsync;

static void fake_sendpkt(UBYTE *pkt, ULONG length, struct SDIO *sdio)
{
    ULONG i, n = length + 3 > SENTMAX ? SENTMAX : length + 3;
    (void)sdio;
    sentLen = length;
    sentHw = pkt[0] | (pkt[1] << 8);
    /* a synchronous request's block size sits 12 bytes before its frame
       (pm_AllocSize); an async frame is its own AllocMem block */
    sentAlloc = sentAsync ? 0 : *(ULONG *)(pkt - 12);
    for (i = 0; i < n; i++) sent[i] = pkt[i];
    sends++;
}

/* ------------------------------------------------------------------ */
/* The receiver: queue the request, answer it                          */

#define REPLYMAX (12 + 16 + 2200)
static UBYTE replyFrame[REPLYMAX];
static volatile ULONG replyData, replyPkt;      /* c_Length in the reply; frame length given */
static volatile int answer;                     /* 0: none */
static struct MsgPort * volatile ctrlPort;
static struct Task *mainTask;
static struct Task * volatile helperTask;
static volatile int quit;

static UBYTE pattern(ULONG i) { return (UBYTE)(i * 7 + 3); }

static void answer_last(struct SDIO *sdio)
{
    int glom = (sent[7] != 12 && sent[15] == 20);
    UBYTE *sc = sent + (glom ? 20 : 12);
    UBYTE *c = replyFrame + 12;
    ULONG i;
    for (i = 0; i < REPLYMAX; i++) replyFrame[i] = 0;
    replyFrame[7] = 12;
    for (i = 0; i < 12; i++) c[i] = sc[i];          /* command, length, flags, id */
    *(ULONG *)(c + 4) = LE32(replyData);
    *(ULONG *)(c + 12) = 0;
    for (i = 0; i < replyData && 28 + i < REPLYMAX; i++) c[16 + i] = pattern(i);
    PacketCtrlComplete(sdio, (struct Packet *)replyFrame, replyPkt);
}

static void helper(void)
{
    struct MsgPort *port = CreateMsgPort();
    struct Message *m;
    ctrlPort = port;
    helperTask = FindTask(NULL);
    Signal(mainTask, SIGBREAKF_CTRL_E);
    while (!quit)
    {
        Wait((1UL << port->mp_SigBit) | SIGBREAKF_CTRL_F);
        while ((m = GetMsg(port)) != NULL)
        {
            PacketCtrlQueue(&fsdio, m);
            if (answer) answer_last(&fsdio);
        }
    }
    PacketCtrlShutdown(&fsdio, port);
    DeleteMsgPort(port);
    Forbid();
    helperTask = NULL;
    Signal(mainTask, SIGBREAKF_CTRL_E);
}

/* ------------------------------------------------------------------ */

#define CANARY 0xB7
static UBYTE out_[2048 + 64];

static int canary_ok(ULONG from)
{
    ULONG i;
    for (i = from; i < sizeof(out_); i++) if (out_[i] != CANARY) return 0;
    return 1;
}

static ULONG le32(const UBYTE *p) { return p[0] | (p[1] << 8) | ((ULONG)p[2] << 16) | ((ULONG)p[3] << 24); }

/* one GET: the frame sent, then the copy */
static void get_case(const char *name, int glom, int getSize, ULONG rData, ULONG rPkt, ULONG wantCopied)
{
    ULONG hdr = glom ? 20 : 12, before = sends, txData, i;
    ULONG max = (ULONG)getSize > 9 ? (ULONG)getSize : 9;     /* "counters" + NUL */
    LONG err;
    int bad;

    PutStr("case "); PutStr(name); PutStr("\n");
    fsdio.s_GlomEnabled = glom;
    memset(out_, CANARY, sizeof(out_));
    replyData = rData;
    replyPkt = rPkt;
    answer = 1;
    err = PacketGetVarMin(&fsdio, "counters", out_, getSize, 0);
    txData = max > 1502 ? 1502 : max;

    expect_eq(err, 0, "GET answered");
    expect_eq(sends - before, 1, "one frame sent");
    expect_eq(sentHw, hdr + 16 + txData, "hw length = header + 16 + min(max, 1502)");
    expect(sentHw - hdr <= PACKET_CTRL_MAX_MSG, "BCDC bytes sent <= 1518");
    expect_eq(le32(sent + hdr + 4), max, "c_Length = the whole requested size");
    expect(memcmp(sent + hdr + 16, "counters", 9) == 0, "name sent whole with its NUL");
    for (i = 9, bad = 0; i < txData; i++) if (sent[hdr + 16 + i] != 0) bad++;
    for (i = sentHw; i < ((sentHw + 3) & ~3); i++) if (sent[i] != 0) bad++;
    expect_eq(bad, 0, "everything sent after the name is zero");
    expect(sentAlloc >= 44 + ((sentHw + 3) & ~3), "allocation covers the send rounded up to 4");
    expect(sentAlloc <= 44 + ((hdr + 16 + 1502 + 3) & ~3), "allocation no bigger than a capped frame");
    for (i = 0, bad = 0; i < wantCopied; i++) if (out_[i] != pattern(i)) bad++;
    expect_eq(bad, 0, "reply bytes copied");
    for (i = wantCopied, bad = 0; i < (ULONG)getSize; i++) if (out_[i] != 0) bad++;
    expect_eq(bad, 0, "rest of the caller buffer zeroed");
    expect(canary_ok(getSize), "nothing written past the caller buffer");
}

static char longName[1600];

int main(void)
{
    static UBYTE setbuf[2000];
    ULONG before;
    LONG err;
    int i;

    mainTask = FindTask(NULL);
    fbase.w_SysBase = SysBase;
    fbase.w_Unit = &funit;
    fbase.w_SDIO = &fsdio;
    fbase.w_MemPool = CreatePool(MEMF_ANY | MEMF_CLEAR, 16384, 8192);
    funit.wu_Base = &fbase;
    waitList.mlh_Head = (struct MinNode *)&waitList.mlh_Tail;
    waitList.mlh_Tail = NULL;
    waitList.mlh_TailPred = (struct MinNode *)&waitList.mlh_Head;
    fsdio.s_SysBase = SysBase;
    fsdio.s_WiFiBase = &fbase;
    fsdio.s_CtrlWaitList = &waitList;
    fsdio.SendPKT = fake_sendpkt;
    fsdio.s_Chip = &fchip;
    fsdio.s_MaxTXSeq = 0x40;

    PutStr("wifipi.device control frames and the 1518-byte cap\n");
    SetSignal(0, SIGBREAKF_CTRL_E);
    if (CreateNewProcTags(NP_Entry, (ULONG)helper, NP_Name, (ULONG)"ctrlcap-receiver", NP_Priority, 5, TAG_DONE) == NULL)
    {
        PutStr("RESULT FAIL no helper\n");
        return 20;
    }
    Wait(SIGBREAKF_CTRL_E);
    fsdio.s_ReceiverPort = (struct MsgPort *)ctrlPort;

    /* GET: sizes, both layouts, a full reply */
    get_case("GET 2048, full reply", 0, 2048, 2048, 12 + 16 + 2048, 2048);
    get_case("GET 2048 glommed, full reply", 1, 2048, 2048, 12 + 16 + 2048, 2048);
    get_case("GET 1503", 0, 1503, 1503, 12 + 16 + 1503, 1503);
    get_case("GET 1502", 0, 1502, 1502, 12 + 16 + 1502, 1502);
    get_case("GET 100", 0, 100, 100, 12 + 16 + 100, 100);
    /* the copy's three bounds */
    get_case("GET 100, reply longer than the buffer", 0, 100, 2048, 12 + 16 + 2048, 100);
    get_case("GET 2048, reply says 50", 0, 2048, 50, 12 + 16 + 2048, 50);
    get_case("GET 2048, frame truncated at 200", 0, 2048, 2048, 12 + 16 + 200, 200);
    fsdio.s_GlomEnabled = 0;

    PutStr("case name of exactly 1502 bytes with its NUL\n");
    for (i = 0; i < 1501; i++) longName[i] = 'a' + i % 26;
    longName[1501] = 0;
    before = sends;
    replyData = 4; replyPkt = 12 + 16 + 4; answer = 1;
    err = PacketGetVarMin(&fsdio, longName, out_, 4, 0);
    expect_eq(err, 0, "exact-fit name: GET answered");
    expect_eq(sends - before, 1, "exact-fit name: sent");
    expect_eq(sentHw, 12 + 16 + 1502, "exact-fit name: 1518 BCDC bytes");
    expect(memcmp(sent + 12 + 16, longName, 1502) == 0, "exact-fit name: whole, NUL included");

    PutStr("case name one byte too long\n");
    longName[1501] = 'x'; longName[1502] = 0;
    before = sends;
    err = PacketGetVarMin(&fsdio, longName, out_, 4, 0);
    expect_eq(err, PACKET_CTRL_TOOBIG, "overlong name: TOOBIG");
    expect_eq(sends - before, 0, "overlong name: nothing sent");
    expect(!PACKET_CTRL_DEAD(err), "overlong name: not a dead link");

    PutStr("case SET at the cap and one byte over\n");
    for (i = 0; i < (int)sizeof(setbuf); i++) setbuf[i] = (UBYTE)(i + 1);
    before = sends;
    replyData = 0; replyPkt = 12 + 16; answer = 1;
    err = PacketSetVar(&fsdio, "abc", setbuf, 1502 - 4);
    expect_eq(err, 0, "SET of exactly 1518 BCDC bytes answered");
    expect_eq(sends - before, 1, "SET at the cap: sent");
    expect_eq(sentHw, 12 + 1518, "SET at the cap: whole");
    expect_eq(le32(sent + 12 + 4), 1502, "SET at the cap: c_Length");
    expect(memcmp(sent + 12 + 16 + 4, setbuf, 1502 - 4) == 0, "SET at the cap: data whole");
    before = sends;
    err = PacketSetVar(&fsdio, "abc", setbuf, 1502 - 4 + 1);
    expect_eq(err, PACKET_CTRL_TOOBIG, "SET one byte over: TOOBIG");
    expect_eq(sends - before, 0, "SET one byte over: nothing sent");
    expect(!PACKET_CTRL_DEAD(err), "SET one byte over: not a dead link");
    before = sends;
    expect_eq(PacketSetVar(&fsdio, "abc", setbuf, -1), PACKET_CTRL_TOOBIG, "SET of -1 bytes: TOOBIG");
    expect_eq(PacketSetVar(&fsdio, "abc", setbuf, 70000), PACKET_CTRL_TOOBIG, "SET of 70000 bytes: TOOBIG (no UWORD wrap)");
    expect_eq(PacketSetVar(&fsdio, "mcast_list", setbuf, 249 * 6 + 4), PACKET_CTRL_TOOBIG,
              "mcast_list of 249 groups: TOOBIG, so UpdateMCastList turns allmulti on");
    expect_eq(sends - before, 0, "none of them sent");

    PutStr("case async SET at the cap and one byte over\n");
    sentAsync = 1;
    before = sends;
    PacketSetVarAsync(&fsdio, "abc", setbuf, 1502 - 4);
    expect_eq(sends - before, 1, "async SET at the cap: sent");
    expect_eq(sentHw, 12 + 1518, "async SET at the cap: whole");
    before = sends;
    PacketSetVarAsync(&fsdio, "abc", setbuf, 1502 - 4 + 1);
    PacketSetVarAsync(&fsdio, "abc", setbuf, -1);
    expect_eq(sends - before, 0, "async SET over the cap or negative: nothing sent");
    sentAsync = 0;

    quit = 1;
    Signal((struct Task *)helperTask, SIGBREAKF_CTRL_F);
    Wait(SIGBREAKF_CTRL_E);
    DeletePool(fbase.w_MemPool);

    PutStr(failures ? "RESULT FAIL " : "RESULT PASS "); num(checks); PutStr(" checks, "); num(failures); PutStr(" failures\n");
    return failures ? 20 : 0;
}

/*
 * wifipi.device special statistics, run under an emulator: no Pi hardware
 * is touched.  The driver's own WiFi_Open/WiFi_BeginIO/WiFi_Close are linked
 * in and called against a fake WiFiBase/WiFiUnit/SDIO.
 *
 * S2_GETSPECIALSTATS reads the firmware's wl_cnt counters only for a caller
 * asking past the driver's own records (#89).  AmiNetXDuo's RX reader asks
 * for 24 records and NetDevStats for 64, repeatedly and on an online unit:
 * those must never queue a firmware command.  In steps 1-2 nobody answers
 * s_ReceiverPort, so a gate that let one through would time out there.
 *
 * Steps 3-5 put a receiver behind the port (PacketCtrlQueue/Complete, as in
 * test_ctrl): the full reader's 'counters' GET goes out capped at 1518 BCDC
 * bytes; a v30 (XTLV, block 0x100) and a legacy v10 answer are decoded; no
 * answer at all ends in PACKET_CTRL_TIMEOUT after the 2.5 s deadline with
 * every firmware record unavailable, and the unit answers the stack's
 * queries afterwards.
 */
#include <exec/exec.h>
#include <exec/io.h>
#include <devices/sana2.h>
#include <devices/sana2wireless.h>
#include <devices/newstyle.h>
#include <devices/timer.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <string.h>

#include "../src/wifipi.h"
#include "../src/packet.h"
#include <dos/dostags.h>

void  WiFi_Open(REGARG(struct IOSana2Req *io, "a1"), REGARG(LONG unitNumber, "d0"), REGARG(ULONG flags, "d1"));
ULONG WiFi_Close(REGARG(struct IOSana2Req *io, "a1"));
void  WiFi_BeginIO(REGARG(struct IOSana2Req *io, "a1"));

static int checks, failures;

/* Every line also goes out the serial port, through RawPutChar: a run that
   hangs the machine never closes its stdout file, and the serial log is then
   the only record of how far it got. */
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

static ULONG lowsum(void)
{
    const volatile UBYTE *p = (const volatile UBYTE *)0;
    ULONG s = 0, i;
    for (i = 0; i < 0x400; i++) s = s * 31 + p[i];
    return s;
}

#define TAIL 64
typedef struct { UBYTE req[sizeof(struct IOSana2Req)]; UBYTE tail[TAIL]; } Frame;

static struct WiFiBase fbase;
static struct WiFiUnit funit;
static struct SDIO fsdio;

static struct IOSana2Req *frame(Frame *f, UWORD mn_length)
{
    struct IOSana2Req *io = (struct IOSana2Req *)f;
    memset(f, 0, sizeof(*f));
    memset(f->req + mn_length, 0xA5, sizeof(f->req) - mn_length);   /* past the request */
    memset(f->tail, 0xA5, TAIL);
    io->ios2_Req.io_Message.mn_Length = mn_length;
    io->ios2_Req.io_Device = (struct Device *)&fbase;
    return io;
}

/* ------------------------------------------------------------------ */
/* A receiver behind s_ReceiverPort, answering 'counters'              */

enum { R_V30, R_V10, R_NONE };
static volatile int rmode, rquit, rsends;
static volatile ULONG rHw;
static struct MinList waitList;
static struct Task *mainTask;
static struct Task * volatile rtask;
static struct MsgPort * volatile rport;
static UBYTE sentHdr[32];
static UBYTE reply[12 + 16 + 2048];

static void fake_sendpkt(UBYTE *pkt, ULONG length, struct SDIO *sdio)
{
    ULONG i;
    (void)length; (void)sdio;
    rHw = pkt[0] | (pkt[1] << 8);
    for (i = 0; i < sizeof(sentHdr); i++) sentHdr[i] = pkt[i];
    rsends++;
}

static void put32(UBYTE *p, ULONG v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static void put16(UBYTE *p, UWORD v) { p[0] = v; p[1] = v >> 8; }

static void answer(void)
{
    int glom = (sentHdr[7] != 12 && sentHdr[15] == 20);
    UBYTE *sc = sentHdr + (glom ? 20 : 12), *c = reply + 12, *d = c + 16;
    ULONG i, len = 2048;
    for (i = 0; i < sizeof(reply); i++) reply[i] = 0;
    reply[7] = 12;
    for (i = 0; i < 12; i++) c[i] = sc[i];
    put32(c + 4, len);
    if (rmode == R_V30)
    {
        put16(d, 30); put16(d + 2, 8 + 228);
        put16(d + 4, 0x55); put16(d + 6, 0);                /* an unrelated XTLV, empty */
        put16(d + 8, 0x100); put16(d + 10, 228);            /* wl_cnt_wlc_t */
        put32(d + 12 + 0, 111); put32(d + 12 + 8, 222); put32(d + 12 + 12, 333);
        put32(d + 12 + 28, 444); put32(d + 12 + 200, 555); put32(d + 12 + 204, 666);
        put32(d + 12 + 224, 777);
    }
    else
    {
        put16(d, 10); put16(d + 2, 200);
        put32(d + 4, 1111); put32(d + 12, 2222); put32(d + 16, 3333); put32(d + 32, 4444);
    }
    PacketCtrlComplete(&fsdio, (struct Packet *)reply, 12 + 16 + len);
}

static void receiver(void)
{
    struct MsgPort *port = CreateMsgPort();
    struct Message *m;
    rport = port;
    rtask = FindTask(NULL);
    Signal(mainTask, SIGBREAKF_CTRL_E);
    while (!rquit)
    {
        Wait((1UL << port->mp_SigBit) | SIGBREAKF_CTRL_F);
        PacketCtrlSweep(&fsdio);
        while ((m = GetMsg(port)) != NULL)
        {
            PacketCtrlQueue(&fsdio, m);
            if (rmode != R_NONE) answer();
        }
    }
    PacketCtrlShutdown(&fsdio, port);
    DeleteMsgPort(port);
    Forbid();
    rtask = NULL;
    Signal(mainTask, SIGBREAKF_CTRL_E);
}

static struct Sana2SpecialStatRecord *stats(struct IOSana2Req *io, ULONG max, ULONG *supplied)
{
    static struct { struct Sana2SpecialStatHeader h; struct Sana2SpecialStatRecord r[256]; } st;
    memset(&st, 0, sizeof(st));
    st.h.RecordCountMax = max;
    io->ios2_Req.io_Command = S2_GETSPECIALSTATS;
    io->ios2_Req.io_Flags = IOF_QUICK;
    io->ios2_StatData = &st;
    WiFi_BeginIO(io);
    *supplied = st.h.RecordCountSupplied;
    return st.r;
}

static int named(const struct Sana2SpecialStatRecord *r, const char *want)
{
    return r->String != NULL && strcmp((const char *)r->String, want) == 0;
}

int main(void)
{
    static Frame f;
    struct IOSana2Req *io;
    struct Sana2SpecialStatRecord *r;
    ULONG low0, lib0, unit0, supplied, k;
    const UWORD FULL = sizeof(struct IOSana2Req);

    fbase.w_SysBase = SysBase;
    fbase.w_Unit = &funit;
    fbase.w_SDIO = &fsdio;
    fbase.w_UtilityBase = OpenLibrary((CONST_STRPTR)"utility.library", 37);
    funit.wu_Base = &fbase;
    funit.wu_Flags = IFF_STARTED;
    InitSemaphore(&funit.wu_Lock);
    funit.wu_CmdQueue = CreateMsgPort();
    /* A real pool: with none the firmware read's buffer allocation fails
       and the read is skipped, which would hide an ungated read. */
    fbase.w_MemPool = CreatePool(MEMF_PUBLIC | MEMF_CLEAR, 16384, 8192);
    fsdio.s_SysBase = SysBase;
    fsdio.s_WiFiBase = &fbase;
    fsdio.s_ReceiverPort = CreateMsgPort();
    funit.wu_Openers.mlh_Head = (struct MinNode *)&funit.wu_Openers.mlh_Tail;
    funit.wu_Openers.mlh_Tail = NULL;
    funit.wu_Openers.mlh_TailPred = (struct MinNode *)&funit.wu_Openers.mlh_Head;

    PutStr("wifipi.device special statistics\n");
    if (funit.wu_CmdQueue == NULL || fsdio.s_ReceiverPort == NULL || fbase.w_MemPool == NULL)
    {
        PutStr("RESULT FAIL no ports\n");
        return 20;
    }
    low0 = lowsum();
    lib0 = fbase.w_Device.dd_Library.lib_OpenCnt;
    unit0 = funit.wu_Unit.unit_OpenCnt;

    io = frame(&f, FULL);
    WiFi_Open(io, 0, 0);
    expect_eq(io->ios2_Req.io_Error, 0, "full Open succeeds");

    PutStr("step 1 stack and NetDevStats queries, online, repeated\n");
    funit.wu_Flags |= IFF_UP | IFF_ONLINE;
    fsdio.s_StatFwRoute = 0xdead;
    for (k = 0; k < 5; k++)
    {
        r = stats(io, 24, &supplied);
        expect_eq(io->ios2_Req.io_Error, 0, "24-record query answered");
        expect_eq(supplied, 24, "24 records supplied");
        r = stats(io, 64, &supplied);
        expect_eq(io->ios2_Req.io_Error, 0, "64-record query answered");
        expect_eq(supplied, 64, "64 records supplied");
        expect(named(&r[35], "tx CMD53s failed"), "record 35 is the first TX counter");
        expect(named(&r[63], "orphans multicast"), "record 63 is the last before the firmware block");
    }
    expect((struct Message *)GetMsg(fsdio.s_ReceiverPort) == NULL, "no firmware command queued");
    expect_eq(fsdio.s_StatFwRoute, 0xdead, "firmware counters not read");

    PutStr("step 2 full reader, unit offline\n");
    funit.wu_Flags &= ~IFF_ONLINE;
    r = stats(io, 256, &supplied);
    expect_eq(io->ios2_Req.io_Error, 0, "256-record query answered");
    expect_eq(supplied, 203, "all 203 records supplied");
    expect(named(&r[64], "fw counters route"), "record 64 is the firmware route");
    expect_eq(r[64].Count, 0, "offline: route 0, no firmware read");
    expect(named(&r[202], "fw raw +1fc"), "record 202 is the last raw word");
    expect((struct Message *)GetMsg(fsdio.s_ReceiverPort) == NULL, "still no firmware command queued");

    /* the receiver takes the port over from here */
    mainTask = FindTask(NULL);
    waitList.mlh_Head = (struct MinNode *)&waitList.mlh_Tail;
    waitList.mlh_Tail = NULL;
    waitList.mlh_TailPred = (struct MinNode *)&waitList.mlh_Head;
    fsdio.s_CtrlWaitList = &waitList;
    fsdio.SendPKT = fake_sendpkt;
    fsdio.s_MaxTXSeq = 0x40;
    SetSignal(0, SIGBREAKF_CTRL_E);
    if (CreateNewProcTags(NP_Entry, (ULONG)receiver, NP_Name, (ULONG)"stats-receiver", NP_Priority, 5, TAG_DONE) == NULL)
    {
        PutStr("RESULT FAIL no receiver\n");
        return 20;
    }
    Wait(SIGBREAKF_CTRL_E);
    fsdio.s_ReceiverPort = (struct MsgPort *)rport;
    funit.wu_Flags |= IFF_ONLINE;

    PutStr("step 3 full reader online, v30 answer\n");
    rmode = R_V30; rsends = 0;
    r = stats(io, 256, &supplied);
    expect_eq(io->ios2_Req.io_Error, 0, "v30: query answered");
    expect_eq(rsends, 1, "v30: one 'counters' GET sent");
    expect_eq(rHw, 12 + 1518, "v30: GET capped at 1518 BCDC bytes");
    expect_eq(r[64].Count, 1, "v30: route 1");
    expect_eq(r[65].Count, 0, "v30: no error");
    expect_eq(r[66].Count, 30, "v30: version");
    expect_eq(r[68].Count, 111, "v30: txframe");
    expect_eq(r[69].Count, 222, "v30: txretrans");
    expect_eq(r[70].Count, 333, "v30: txerror");
    expect_eq(r[71].Count, 444, "v30: txnobuf");
    expect_eq(r[72].Count, 555, "v30: txfail");
    expect_eq(r[73].Count, 666, "v30: txretry");
    expect_eq(r[74].Count, 777, "v30: txnoack");

    PutStr("step 4 legacy v10 answer\n");
    rmode = R_V10;
    r = stats(io, 256, &supplied);
    expect_eq(r[66].Count, 10, "v10: version");
    expect_eq(r[68].Count, 1111, "v10: txframe");
    expect_eq(r[71].Count, 4444, "v10: txnobuf");
    expect_eq(r[72].Count, (LONG)0xffffffff, "v10: txfail unavailable");

    PutStr("step 5 no answer: bounded, then the unit still answers\n");
    rmode = R_NONE;
    {
        struct DateStamp a, b;
        LONG ticks;
        DateStamp(&a);
        r = stats(io, 256, &supplied);
        DateStamp(&b);
        ticks = (b.ds_Minute - a.ds_Minute) * 3000 + (b.ds_Tick - a.ds_Tick);
        expect(ticks >= 115 && ticks <= 200, "no answer: returns after the 2.5 s deadline");
        expect_eq(io->ios2_Req.io_Error, 0, "no answer: the query itself completes");
        expect_eq(r[64].Count, 255, "no answer: route 255");
        expect_eq(r[65].Count, (LONG)PACKET_CTRL_TIMEOUT, "no answer: error PACKET_CTRL_TIMEOUT");
        for (k = 68; k <= 74; k++)
            if (r[k].Count != (LONG)0xffffffff) break;
        expect_eq(k, 75, "no answer: every firmware record unavailable");
    }
    Signal((struct Task *)rtask, SIGBREAKF_CTRL_F);     /* sweep the abandoned request */
    rsends = 0;
    r = stats(io, 24, &supplied);
    expect_eq(io->ios2_Req.io_Error, 0, "after the timeout: a stack query answered");
    expect_eq(supplied, 24, "after the timeout: 24 records");
    r = stats(io, 64, &supplied);
    expect_eq(supplied, 64, "after the timeout: NetDevStats' 64 records");
    expect_eq(rsends, 0, "after the timeout: still no firmware command for them");

    rquit = 1;
    Signal((struct Task *)rtask, SIGBREAKF_CTRL_F);
    Wait(SIGBREAKF_CTRL_E);

    WiFi_Close(io);
    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, lib0, "Close balances the device count");
    expect_eq(funit.wu_Unit.unit_OpenCnt, unit0, "Close balances the unit count");
    expect(lowsum() == low0, "low memory [0, 0x400) unchanged across the run");

    PutStr(failures ? "RESULT FAIL " : "RESULT PASS "); num(checks); PutStr(" checks, "); num(failures); PutStr(" failures\n");
    return failures ? 20 : 0;
}

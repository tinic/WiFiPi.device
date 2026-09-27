/*
 * wifipi.device OpenDevice when the unit cannot start (#95), run under an
 * emulator: no Pi hardware.  The real WiFi_Open/WiFi_Close/StartUnit and the
 * real control path are linked in; a helper task stands in for the receiver
 * and answers the cur_etheraddr get as each step scripts it.
 *
 * Covered: a lost and a short address reply fail the open with nothing
 * changed; a whole reply opens, and Close balances; a retry after a failure;
 * exclusive against shared on a running unit (no restart, nothing touched);
 * limited opens; an open started and then refused as busy; a second open
 * arriving while the first waits inside StartUnit; and a first open whose
 * reply is lost or short while a second one starts the unit; and two opens
 * whose replies are both lost.
 */
#include <exec/exec.h>
#include <exec/io.h>
#include <devices/sana2.h>
#include <dos/dostags.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <string.h>

#include "../src/wifipi.h"
#include "../src/packet.h"

void  WiFi_Open(REGARG(struct IOSana2Req *io, "a1"), REGARG(LONG unitNumber, "d0"), REGARG(ULONG flags, "d1"));
ULONG WiFi_Close(REGARG(struct IOSana2Req *io, "a1"));

static int checks, failures;

/* lines also go out the serial port: a hung run never closes stdout */
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

typedef struct { UBYTE req[sizeof(struct IOSana2Req)]; UBYTE tail[64]; } Frame;

static struct WiFiBase fbase;
static struct WiFiUnit funit;
static struct SDIO fsdio;
static struct Chip fchip;
static struct MinList waitList;

static struct IOSana2Req *frame(Frame *f, UWORD mn_length)
{
    struct IOSana2Req *io = (struct IOSana2Req *)f;
    memset(f, 0, sizeof(*f));
    io->ios2_Req.io_Message.mn_Length = mn_length;
    io->ios2_Req.io_Device = (struct Device *)&fbase;
    io->ios2_Req.io_Unit = (struct Unit *)0xdeadbeef;     /* must be cleared on failure */
    return io;
}

/* ------------------------------------------------------------------ */
/* The helper: the receiver's control half                            */

enum { M_NOREPLY, M_SHORT4, M_WHOLE, M_DELAY, M_FIRST_LOST, M_FIRST_SHORT };
static struct MsgPort * volatile ctrlPort;
static struct Task *mainTask;
static struct Task * volatile helperTask;
static volatile int mode, delayTicks, sends, helperCmd, nth;
static volatile UWORD lastID, firstID;
static volatile ULONG lastCmd;
#define CMD_SWEEP 1
#define CMD_QUIT  2

static void fake_sendpkt(UBYTE *pkt, ULONG length, struct SDIO *sdio)
{
    UBYTE *c = pkt + 12;
    (void)length; (void)sdio;
    lastCmd = *(ULONG *)(c + 0);
    lastID = *(UWORD *)(c + 10);
    sends++;
}

static UBYTE replyFrame[128];
static void reply(struct SDIO *sdio, ULONG dataLen)
{
    UBYTE *c = replyFrame + 12;
    int i;
    for (i = 0; i < (int)sizeof(replyFrame); i++) replyFrame[i] = 0;
    replyFrame[7] = 12;
    *(ULONG *)(c + 0) = lastCmd;
    *(ULONG *)(c + 4) = LE32(dataLen);
    *(UWORD *)(c + 10) = lastID;
    c[16] = 0x02; c[17] = 0x11; c[18] = 0x22; c[19] = 0x33; c[20] = 0x44; c[21] = 0x55;
    PacketCtrlComplete(sdio, (struct Packet *)replyFrame, 12 + 16 + dataLen);
}

static void helper(void)
{
    struct SDIO *sdio = &fsdio;
    struct MsgPort *port = CreateMsgPort();
    struct Message *m;

    ctrlPort = port;
    helperTask = FindTask(NULL);
    Signal(mainTask, SIGBREAKF_CTRL_E);
    for (;;)
    {
        ULONG sig = Wait((1UL << port->mp_SigBit) | SIGBREAKF_CTRL_F);
        if (sig & SIGBREAKF_CTRL_F)
        {
            int c = helperCmd;
            helperCmd = 0;
            if (c == CMD_SWEEP) PacketCtrlSweep(sdio);
            Signal(mainTask, SIGBREAKF_CTRL_E);
            if (c == CMD_QUIT) break;
        }
        while ((m = GetMsg(port)) != NULL)
        {
            PacketCtrlQueue(sdio, m);
            switch (mode)
            {
                case M_SHORT4: reply(sdio, 4); break;
                case M_WHOLE:  reply(sdio, 6); break;
                case M_DELAY:  Delay(delayTicks); reply(sdio, 6); break;
                /* the first get is held; the second is answered whole, then
                   the first is lost (its deadline passes) or answered short */
                case M_FIRST_LOST:
                    if (nth++ != 0) reply(sdio, 6);
                    break;
                case M_FIRST_SHORT:
                    if (nth++ == 0) { firstID = lastID; break; }
                    reply(sdio, 6);
                    Delay(25);                  /* the second open finishes */
                    lastID = firstID;
                    reply(sdio, 4);
                    break;
                default: break;
            }
        }
    }
    DeleteMsgPort(port);
    Forbid();
    Signal(mainTask, SIGBREAKF_CTRL_E);
}

static void helper_cmd(int c)
{
    helperCmd = c;
    Signal((struct Task *)helperTask, SIGBREAKF_CTRL_F);
    Wait(SIGBREAKF_CTRL_E);
}

static int openers(void)
{
    struct MinNode *n;
    int k = 0;
    for (n = funit.wu_Openers.mlh_Head; n->mln_Succ; n = n->mln_Succ) k++;
    return k;
}

/* the state a refused open must leave exactly as it found it */
typedef struct { UWORD lib, unit; ULONG flags; int op; UBYTE orig[6], eth[6]; int sends; } Snap;
static void snap(Snap *s)
{
    s->lib = fbase.w_Device.dd_Library.lib_OpenCnt;
    s->unit = funit.wu_Unit.unit_OpenCnt;
    s->flags = funit.wu_Flags;
    s->op = openers();
    memcpy(s->orig, funit.wu_OrigEtherAddr, 6);
    memcpy(s->eth, funit.wu_EtherAddr, 6);
    s->sends = sends;
}
static void unchanged(const Snap *a, int sent, const char *what)
{
    Snap b;
    snap(&b);
    expect_eq(b.lib, a->lib, what);
    expect_eq(b.unit, a->unit, what);
    expect_eq(b.flags, a->flags, what);
    expect_eq(b.op, a->op, what);
    expect(memcmp(b.orig, a->orig, 6) == 0 && memcmp(b.eth, a->eth, 6) == 0, what);
    expect_eq(b.sends - a->sends, sent, what);
}

static void refused(struct IOSana2Req *io, BYTE err, const char *what)
{
    expect_eq(io->ios2_Req.io_Error, err, what);
    expect(io->ios2_Req.io_Unit == NULL, "refused: io_Unit NULL");
    expect(io->ios2_BufferManagement == NULL, "refused: no opener handed out");
}

static void reset_unit(void)
{
    funit.wu_Flags = 0;
    memset(funit.wu_OrigEtherAddr, 0xa5, 6);
    memset(funit.wu_EtherAddr, 0xa5, 6);
}

/* the other opener, for step 7 */
static Frame fx;
static volatile BYTE errX;
static void openerX(void)
{
    struct IOSana2Req *io = frame(&fx, sizeof(struct IOSana2Req));
    WiFi_Open(io, 0, 0);                    /* shared */
    errX = io->ios2_Req.io_Error;
    if (errX == 0)
    {
        static const UBYTE cfg[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
        memcpy(funit.wu_EtherAddr, cfg, 6);     /* as S2_CONFIGINTERFACE would */
    }
    Signal(mainTask, SIGBREAKF_CTRL_D);
}

int main(void)
{
    static Frame f1, f2, f3;
    struct IOSana2Req *io, *io2, *io3;
    const UWORD FULL = sizeof(struct IOSana2Req), SHORT = sizeof(struct IOStdReq);
    static const UBYTE mac[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
    struct DateStamp ds;
    ULONG t0, t1;
    Snap s;

    mainTask = FindTask(NULL);
    fbase.w_SysBase = SysBase;
    fbase.w_Unit = &funit;
    fbase.w_SDIO = &fsdio;
    fbase.w_UtilityBase = OpenLibrary((CONST_STRPTR)"utility.library", 37);
    fbase.w_MemPool = CreatePool(MEMF_ANY | MEMF_CLEAR, 16384, 8192);
    funit.wu_Base = &fbase;
    InitSemaphore(&funit.wu_Lock);
    funit.wu_Openers.mlh_Head = (struct MinNode *)&funit.wu_Openers.mlh_Tail;
    funit.wu_Openers.mlh_Tail = NULL;
    funit.wu_Openers.mlh_TailPred = (struct MinNode *)&funit.wu_Openers.mlh_Head;
    waitList.mlh_Head = (struct MinNode *)&waitList.mlh_Tail;
    waitList.mlh_Tail = NULL;
    waitList.mlh_TailPred = (struct MinNode *)&waitList.mlh_Head;
    fsdio.s_SysBase = SysBase;
    fsdio.s_WiFiBase = &fbase;
    fsdio.s_CtrlWaitList = &waitList;
    fsdio.SendPKT = fake_sendpkt;
    fsdio.s_Chip = &fchip;

    PutStr("wifipi.device open when the unit cannot start\n");
    SetSignal(0, SIGBREAKF_CTRL_E | SIGBREAKF_CTRL_D);
    if (CreateNewProcTags(NP_Entry, (ULONG)helper, NP_Name, (ULONG)"open-receiver", NP_Priority, 5, TAG_DONE) == NULL)
    {
        PutStr("RESULT FAIL no helper\n");
        return 20;
    }
    Wait(SIGBREAKF_CTRL_E);
    fsdio.s_ReceiverPort = (struct MsgPort *)ctrlPort;

#define NOW() (DateStamp(&ds), (ULONG)(ds.ds_Minute * 3000 + ds.ds_Tick))

    PutStr("step 1 address lost: the open fails, nothing changed\n");
    reset_unit();
    snap(&s);
    mode = M_NOREPLY;
    io = frame(&f1, FULL);
    t0 = NOW();
    WiFi_Open(io, 0, 0);
    t1 = NOW();
    refused(io, IOERR_OPENFAIL, "lost address: IOERR_OPENFAIL");
    expect(t1 - t0 >= 120 && t1 - t0 <= 150, "after the 2.5 s deadline");
    unchanged(&s, 1, "lost address: counters, flags, openers, addresses untouched");
    helper_cmd(CMD_SWEEP);

    PutStr("step 2 4 of 6 address bytes: the open fails, nothing changed\n");
    snap(&s);
    mode = M_SHORT4;
    io = frame(&f1, FULL);
    WiFi_Open(io, 0, SANA2OPF_MINE | SANA2OPF_PROM);
    refused(io, IOERR_OPENFAIL, "short address: IOERR_OPENFAIL");
    unchanged(&s, 1, "short address: counters, flags, openers, addresses untouched");

    PutStr("step 3/4 retry with the whole address: opens, Close balances\n");
    snap(&s);
    mode = M_WHOLE;
    io = frame(&f1, FULL);
    WiFi_Open(io, 0, 0);
    expect_eq(io->ios2_Req.io_Error, 0, "retry after failures succeeds");
    expect(io->ios2_Req.io_Unit == &funit.wu_Unit, "io_Unit set");
    expect(io->ios2_BufferManagement != NULL &&
           (APTR)funit.wu_Openers.mlh_Head == io->ios2_BufferManagement, "its opener on the list");
    expect((funit.wu_Flags & (IFF_STARTED | IFF_SHARED)) == (IFF_STARTED | IFF_SHARED), "started, shared");
    expect(memcmp(funit.wu_OrigEtherAddr, mac, 6) == 0, "permanent address copied whole");
    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, s.lib + 1, "lib_OpenCnt +1");
    expect_eq(funit.wu_Unit.unit_OpenCnt, s.unit + 1, "unit_OpenCnt +1");
    WiFi_Close(io);
    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, s.lib, "Close: lib_OpenCnt back");
    expect_eq(funit.wu_Unit.unit_OpenCnt, s.unit, "Close: unit_OpenCnt back");
    expect_eq(openers(), 0, "Close: list empty");

    PutStr("step 5 exclusive against shared on a running unit\n");
    mode = M_NOREPLY;                       /* a restart attempt would show */
    io = frame(&f1, FULL);
    WiFi_Open(io, 0, 0);
    expect_eq(io->ios2_Req.io_Error, 0, "shared open on the running unit");
    snap(&s);
    io2 = frame(&f2, FULL);
    WiFi_Open(io2, 0, SANA2OPF_MINE);
    refused(io2, IOERR_UNITBUSY, "exclusive after shared: IOERR_UNITBUSY");
    unchanged(&s, 0, "exclusive refused: running unit untouched, nothing sent");
    WiFi_Close(io);
    funit.wu_Flags &= ~IFF_SHARED;          /* as a fresh unit: Close leaves it */
    io = frame(&f1, FULL);
    WiFi_Open(io, 0, SANA2OPF_MINE);
    expect_eq(io->ios2_Req.io_Error, 0, "exclusive open on the running unit");
    snap(&s);
    io2 = frame(&f2, FULL);
    WiFi_Open(io2, 0, 0);
    refused(io2, IOERR_UNITBUSY, "shared after exclusive: IOERR_UNITBUSY");
    unchanged(&s, 0, "shared refused: running unit untouched, nothing sent");
    io2 = frame(&f2, FULL);
    WiFi_Open(io2, 0, SANA2OPF_MINE);
    refused(io2, IOERR_UNITBUSY, "exclusive after exclusive: IOERR_UNITBUSY");
    unchanged(&s, 0, "exclusive refused: running unit untouched");
    WiFi_Close(io);
    expect(funit.wu_Unit.unit_OpenCnt == 0 && openers() == 0, "balanced");

    PutStr("step 6 limited opens do not start the unit\n");
    reset_unit();
    snap(&s);
    mode = M_WHOLE;
    io3 = frame(&f3, SHORT);
    WiFi_Open(io3, 0, 0);
    expect_eq(io3->ios2_Req.io_Error, 0, "limited open succeeds on an unstarted unit");
    expect_eq(sends - s.sends, 0, "and sends nothing");
    expect((funit.wu_Flags & IFF_STARTED) == 0, "and does not start it");
    expect_eq(funit.wu_Unit.unit_OpenCnt, s.unit + 1, "limited: unit_OpenCnt +1");
    expect_eq(openers(), 0, "limited: no opener");

    PutStr("step 6b a full open starts the unit, then is refused as busy\n");
    snap(&s);
    io = frame(&f1, FULL);
    WiFi_Open(io, 0, 0);
    refused(io, IOERR_UNITBUSY, "limited holder, not shared: IOERR_UNITBUSY");
    expect((funit.wu_Flags & IFF_STARTED) != 0, "the unit was started meanwhile");
    expect(memcmp(funit.wu_OrigEtherAddr, mac, 6) == 0, "with its whole address");
    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, s.lib, "lib_OpenCnt unchanged");
    expect_eq(funit.wu_Unit.unit_OpenCnt, s.unit, "unit_OpenCnt unchanged");
    expect_eq(openers(), 0, "no opener");
    /* a limited open does not set io_Unit, which Close reads: set it here */
    io3->ios2_Req.io_Unit = &funit.wu_Unit;
    WiFi_Close(io3);
    expect_eq(funit.wu_Unit.unit_OpenCnt, 0, "limited Close balances");

    PutStr("step 7 a second open while the first waits in StartUnit\n");
    reset_unit();
    mode = M_DELAY; delayTicks = 50;
    SetSignal(0, SIGBREAKF_CTRL_D);
    if (CreateNewProcTags(NP_Entry, (ULONG)openerX, NP_Name, (ULONG)"opener-X", NP_Priority, 0, TAG_DONE) != NULL)
    {
        Delay(10);                          /* X is inside StartUnit */
        io = frame(&f1, FULL);
        WiFi_Open(io, 0, SANA2OPF_MINE);    /* starts too; answered after X */
        Wait(SIGBREAKF_CTRL_D);
        expect_eq(errX, 0, "the first (shared) open succeeds");
        refused(io, IOERR_UNITBUSY, "the exclusive one, answered later, is busy");
        expect_eq(funit.wu_Unit.unit_OpenCnt, 1, "one unit opener");
        expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, 1, "one device opener");
        expect_eq(openers(), 1, "one opener on the list");
        expect((funit.wu_Flags & IFF_STARTED) != 0, "started");
        expect(funit.wu_EtherAddr[1] == 0xaa && funit.wu_EtherAddr[5] == 0xee,
               "the late StartUnit left X's configured address alone");
        WiFi_Close((struct IOSana2Req *)&fx);
        expect(funit.wu_Unit.unit_OpenCnt == 0 && openers() == 0, "balanced");
    }
    else
        expect(0, "opener X started");

    {
        static const int m8[2] = { M_FIRST_LOST, M_FIRST_SHORT };
        int i;
        for (i = 0; i < 2; i++)
        {
            PutStr(i == 0 ? "step 8 first reply lost, a second open starts the unit meanwhile\n"
                          : "step 8b first reply short, a second open starts the unit meanwhile\n");
            reset_unit();
            mode = m8[i]; nth = 0;
            SetSignal(0, SIGBREAKF_CTRL_D);
            if (CreateNewProcTags(NP_Entry, (ULONG)openerX, NP_Name, (ULONG)"opener-X", NP_Priority, 0, TAG_DONE) != NULL)
            {
                Delay(10);                      /* X waits on the held get */
                io = frame(&f1, FULL);
                WiFi_Open(io, 0, 0);            /* shared; answered whole */
                expect_eq(io->ios2_Req.io_Error, 0, "8 the second open succeeds");
                expect((funit.wu_Flags & IFF_STARTED) != 0, "8 it started the unit");
                Wait(SIGBREAKF_CTRL_D);
                expect_eq(errX, 0, "8 the first open goes on to a started unit");
                expect(((struct IOSana2Req *)&fx)->ios2_Req.io_Unit == &funit.wu_Unit,
                       "8 first open has its unit");
                expect_eq(funit.wu_Unit.unit_OpenCnt, 2, "8 two unit openers");
                expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, 2, "8 two device openers");
                expect_eq(openers(), 2, "8 two openers on the list");
                expect(memcmp(funit.wu_OrigEtherAddr, mac, 6) == 0, "8 permanent address from the whole reply");
                WiFi_Close((struct IOSana2Req *)&fx);
                WiFi_Close(io);
                expect(funit.wu_Unit.unit_OpenCnt == 0 && openers() == 0 &&
                       fbase.w_Device.dd_Library.lib_OpenCnt == 0, "8 balanced");
            }
            else
                expect(0, "opener X started");
            helper_cmd(CMD_SWEEP);
        }
    }

    PutStr("step 9 two opens, both replies lost: both fail, nothing changed\n");
    reset_unit();
    snap(&s);
    mode = M_NOREPLY;
    errX = 99;
    SetSignal(0, SIGBREAKF_CTRL_D);
    if (CreateNewProcTags(NP_Entry, (ULONG)openerX, NP_Name, (ULONG)"opener-X", NP_Priority, 0, TAG_DONE) != NULL)
    {
        Delay(10);                              /* X waits on its lost get */
        expect_eq(sends - s.sends, 1, "9 the first get is in flight");
        expect_eq(errX, 99, "9 the first open has not failed yet");
        io = frame(&f1, FULL);
        t0 = NOW();
        WiFi_Open(io, 0, 0);                    /* sends while X still waits */
        t1 = NOW();
        expect(t1 - t0 >= 120, "9 the second open waited its whole deadline");
        Wait(SIGBREAKF_CTRL_D);
        expect_eq(errX, IOERR_OPENFAIL, "9 the first open fails");
        refused((struct IOSana2Req *)&fx, IOERR_OPENFAIL, "9 the first open: IOERR_OPENFAIL");
        refused(io, IOERR_OPENFAIL, "9 the second open: IOERR_OPENFAIL");
        expect((funit.wu_Flags & IFF_STARTED) == 0, "9 not started");
        unchanged(&s, 2, "9 counters, flags, openers, addresses untouched");
    }
    else
        expect(0, "opener X started");
    helper_cmd(CMD_SWEEP);

    helper_cmd(CMD_QUIT);
    PutStr(failures ? "RESULT FAIL " : "RESULT PASS "); num(checks); PutStr(" checks, "); num(failures); PutStr(" failures\n");
    return failures ? 20 : 0;
}

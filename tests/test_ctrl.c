/*
 * wifipi.device synchronous control requests, run under an emulator:
 * no Pi hardware.  The real PacketCmdIntGet/PacketGetVar/PacketSetVar and the
 * real receiver-side PacketCtrlQueue/Complete/Sweep/Shutdown are linked in; a
 * helper task at a higher priority stands in for the receiver task, and a
 * fake SendPKT records each control frame's c_ID and command.
 *
 * Covered: success; firmware error; no reply (timeout, then the sweep frees
 * the abandoned block); a late reply after the timeout (dropped: the caller's
 * buffer and port are not touched); replies around the 2.5 s boundary (each
 * call ends as exactly one of success or timeout); a short reply and a
 * truncated frame; the timer failing to open (nothing queued); a timeout
 * while the receiver is still inside SendPKT (the block stays valid until the
 * receiver frees it); two callers in two tasks at once; the quarantine of an
 * abandoned c_ID; S2_GETSIGNALQUALITY timing out and a CMD_READ getting
 * through afterwards; and receiver shutdown with a caller waiting.
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

#include <dos/dostags.h>
#include "../src/packet.h"

extern int wifipi_test_fail_timer;

/* ------------------------------------------------------------------ */
/* The helper: the receiver's control half, driven by a script        */

enum { M_SUCCESS, M_FWERR, M_NOREPLY, M_LATE, M_SHORT, M_TRUNC, M_DELAY, M_SENDBLOCK, M_ECHO,
       M_HOLD, M_WRONGCMD, M_MACONLY, M_UPDEAD, M_SHORTN };
static volatile int shortN;

static struct MinList waitList;
static struct MsgPort * volatile ctrlPort;
static struct Task *mainTask;
static struct Task * volatile helperTask;
static volatile int mode, delayTicks, sendBlockTicks, sends;
static volatile UWORD lastID;            /* raw, as on the wire */
static volatile ULONG lastCmd, lastVal;
static volatile UWORD sentID[64];
static volatile ULONG sentCmd[64];
static volatile int holdPort, modeCount, upSeen;
static volatile int sendBlockIntact;
#define CMD_SWEEP       1
#define CMD_LATE        2
#define CMD_SHUTDOWN    3
#define CMD_QUIT        4
#define CMD_PICK        5       /* take what waits on the port now */
#define CMD_REVERSE     6       /* answer the two held requests, newest first */
static volatile int helperCmd;

static void fake_sendpkt(UBYTE *pkt, ULONG length, struct SDIO *sdio)
{
    /* the BCDC header follows the SDPCM header, and the glom header when
       glomming is on -- bring-up switches it on halfway through */
    UBYTE *c = pkt + 12 + (sdio->s_GlomEnabled ? 8 : 0);
    (void)length;
    lastCmd = *(ULONG *)(c + 0);                    /* raw LE, compared raw */
    lastID = *(UWORD *)(c + 10);
    lastVal = *(ULONG *)(c + 16);
    if (lastCmd == LE32(2) && lastVal == LE32(1))
        upSeen = 1;
    sentID[sends & 63] = lastID;
    sentCmd[sends & 63] = lastCmd;
    sends++;
    if (sendBlockTicks)
    {
        UWORD len = *(UWORD *)pkt, chk = *(UWORD *)(pkt + 2);
        Delay(sendBlockTicks);
        /* the caller timed out meanwhile and has refilled freed memory with
           0xEE: an intact header means the block was not freed under us */
        sendBlockIntact = (*(UWORD *)pkt == len && *(UWORD *)(pkt + 2) == chk);
        sendBlockTicks = 0;
    }
}

static UBYTE replyFrame[128];

static void replyTo(struct SDIO *sdio, UWORD id, ULONG cmd, UWORD flags, ULONG status, ULONG dataLen, ULONG pktLen);
static void reply(struct SDIO *sdio, UWORD flags, ULONG status, ULONG dataLen, ULONG pktLen)
{
    replyTo(sdio, lastID, lastCmd, flags, status, dataLen, pktLen);
}

static void replyTo(struct SDIO *sdio, UWORD id, ULONG cmd, UWORD flags, ULONG status, ULONG dataLen, ULONG pktLen)
{
    UBYTE *c = replyFrame + 12;
    int i;
    for (i = 0; i < (int)sizeof(replyFrame); i++) replyFrame[i] = 0;
    replyFrame[7] = 12;                              /* c_DataOffset */
    *(ULONG *)(c + 0) = cmd;
    *(ULONG *)(c + 4) = LE32(dataLen);
    *(UWORD *)(c + 8) = LE16(flags);
    *(UWORD *)(c + 10) = id;
    *(ULONG *)(c + 12) = LE32(status);
    c[16] = 0x44; c[17] = 0x33; c[18] = 0x22; c[19] = 0x11;   /* LE 0x11223344 */
    c[20] = 0x55; c[21] = 0x66; c[22] = 0x77; c[23] = 0x88;
    PacketCtrlComplete(sdio, (struct Packet *)replyFrame, pktLen);
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
            else if (c == CMD_LATE) reply(sdio, 0, 0, 4, 12 + 16 + 4);
            else if (c == CMD_SHUTDOWN) PacketCtrlShutdown(sdio, port);
            else if (c == CMD_REVERSE)
            {
                int n = sends;
                replyTo(sdio, sentID[(n - 1) & 63], sentCmd[(n - 1) & 63], 0, 0, 4, 12 + 16 + 4);
                replyTo(sdio, sentID[(n - 2) & 63], sentCmd[(n - 2) & 63], 0, 0, 4, 12 + 16 + 4);
            }
            if (c == CMD_PICK) holdPort = 0;
            Signal(mainTask, SIGBREAKF_CTRL_E);
            if (c == CMD_QUIT) break;
        }
        while (!holdPort && fsdio.s_ReceiverPort != NULL && (m = GetMsg(port)) != NULL)
        {
            PacketCtrlQueue(sdio, m);
            modeCount++;
            switch (mode)
            {
                case M_SHORTN:   reply(sdio, 0, 0, shortN, 12 + 16 + shortN); break;
                case M_WRONGCMD: replyTo(sdio, lastID, lastCmd ^ LE32(1), 0, 0, 4, 12 + 16 + 4); break;
                case M_MACONLY:  if (modeCount <= 2) reply(sdio, 0, 0, 8, 12 + 16 + 8); break;
                case M_UPDEAD:   if (!(lastCmd == LE32(2) && lastVal == LE32(1))) reply(sdio, 0, 0, 8, 12 + 16 + 8); break;
                case M_SUCCESS: case M_ECHO: reply(sdio, 0, 0, 4, 12 + 16 + 4); break;
                case M_FWERR:   reply(sdio, 1 /* BCDC_DCMD_ERROR */, (ULONG)-23, 0, 12 + 16); break;
                case M_SHORT:   reply(sdio, 0, 0, 2, 12 + 16 + 2); break;
                case M_TRUNC:   reply(sdio, 0, 0, 4, 12 + 8); break;
                case M_DELAY:   Delay(delayTicks); reply(sdio, 0, 0, 4, 12 + 16 + 4); break;
                default: break;                      /* M_NOREPLY, M_LATE, M_SENDBLOCK */
            }
        }
    }
    DeleteMsgPort(port);
    Forbid();
    helperTask = NULL;
    Signal(mainTask, SIGBREAKF_CTRL_E);
}

static void helper_cmd(int c)
{
    helperCmd = c;
    Signal((struct Task *)helperTask, SIGBREAKF_CTRL_F);
    Wait(SIGBREAKF_CTRL_E);
}

static int listEmpty(void)
{
    return waitList.mlh_TailPred == (struct MinNode *)&waitList;
}

static struct Chip fchip;

/* two more callers, for two live requests at once */
static volatile ULONG resA, valA, resB, valB;
static void callerA(void) { ULONG v = 0; resA = PacketCmdIntGet(&fsdio, 201, &v); valA = v; Signal(mainTask, SIGBREAKF_CTRL_D); }
static void callerB(void) { ULONG v = 0; resB = PacketCmdIntGet(&fsdio, 202, &v); valB = v; Signal(mainTask, SIGBREAKF_CTRL_C); }

/* the second caller */
static volatile ULONG secondResult, secondValue;
static void second(void)
{
    ULONG v = 0;
    secondResult = PacketCmdIntGet(&fsdio, 98, &v);
    secondValue = v;
    Signal(mainTask, SIGBREAKF_CTRL_D);
}

int main(void)
{
    static Frame f, rd;
    struct IOSana2Req *io, *read_io;
    ULONG low0, v, err, t0, t1, k;
    int i, ok, ntimeout, nsuccess;
    struct DateStamp ds;
    const UWORD FULL = sizeof(struct IOSana2Req);

    mainTask = FindTask(NULL);
    fbase.w_SysBase = SysBase;
    fbase.w_Unit = &funit;
    fbase.w_SDIO = &fsdio;
    fbase.w_UtilityBase = OpenLibrary((CONST_STRPTR)"utility.library", 37);
    fbase.w_MemPool = CreatePool(MEMF_ANY | MEMF_CLEAR, 16384, 8192);
    funit.wu_Base = &fbase;
    funit.wu_Flags = IFF_STARTED | IFF_UP | IFF_ONLINE | IFF_CONFIGURED;
    InitSemaphore(&funit.wu_Lock);
    funit.wu_CmdQueue = CreateMsgPort();
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
    fsdio.s_Chip = &fchip;              /* no CLM: bring-up skips the upload */

    PutStr("wifipi.device control requests\n");
    SetSignal(0, SIGBREAKF_CTRL_E | SIGBREAKF_CTRL_D);
    if (CreateNewProcTags(NP_Entry, (ULONG)helper, NP_Name, (ULONG)"ctrl-receiver", NP_Priority, 5, TAG_DONE) == NULL)
    {
        PutStr("RESULT FAIL no helper\n");
        return 20;
    }
    Wait(SIGBREAKF_CTRL_E);
    fsdio.s_ReceiverPort = (struct MsgPort *)ctrlPort;
    low0 = lowsum();

#define NOW() (DateStamp(&ds), (ULONG)(ds.ds_Minute * 3000 + ds.ds_Tick))   /* ticks */

    PutStr("step 1 success\n");
    mode = M_SUCCESS; v = 0;
    err = PacketCmdIntGet(&fsdio, 1, &v);
    expect_eq(err, 0, "success returns 0");
    expect_eq(v, 0x11223344, "value converted from the reply");
    expect(listEmpty(), "nothing left waiting");

    PutStr("step 2 firmware error\n");
    mode = M_FWERR; v = 0x5a5a5a5a;
    err = PacketCmdIntGet(&fsdio, 2, &v);
    expect_eq((LONG)err, -23, "firmware status returned");
    expect_eq(v, 0x5a5a5a5a, "value untouched on error");

    PutStr("step 3 no reply\n");
    mode = M_NOREPLY; v = 0x5a5a5a5a;
    t0 = NOW();
    err = PacketCmdIntGet(&fsdio, 3, &v);
    t1 = NOW();
    expect_eq(err, PACKET_CTRL_TIMEOUT, "no reply times out");
    expect(t1 - t0 >= 120 && t1 - t0 <= 150, "after about 2.5 s");
    expect_eq(v, 0x5a5a5a5a, "value untouched on timeout");
    expect(!listEmpty(), "the abandoned block is still the receiver's");
    helper_cmd(CMD_SWEEP);
    expect(listEmpty(), "the sweep frees it");

    PutStr("step 4 late reply\n");
    mode = M_LATE;
    {
        static ULONG canary[3];
        canary[0] = canary[1] = canary[2] = 0xa5a5a5a5;
        err = PacketCmdIntGet(&fsdio, 4, &canary[1]);
        expect_eq(err, PACKET_CTRL_TIMEOUT, "late: times out first");
        helper_cmd(CMD_LATE);           /* the reply comes in now */
        expect_eq(canary[1], 0xa5a5a5a5, "late reply not copied into the caller's buffer");
        expect(canary[0] == 0xa5a5a5a5 && canary[2] == 0xa5a5a5a5, "nor around it");
        expect(listEmpty(), "late reply frees the abandoned block");
    }

    PutStr("step 5 quarantine\n");
    {
        UWORD abandoned = LE16(lastID);
        mode = M_ECHO;
        fsdio.s_CmdID = abandoned - 1;  /* the next ID would be the abandoned one */
        err = PacketCmdIntGet(&fsdio, 5, &v);
        expect_eq(err, 0, "request after quarantine succeeds");
        expect(LE16(lastID) != abandoned, "the abandoned c_ID is not issued again");
    }

    PutStr("step 6 short reply and truncated frame\n");
    mode = M_SHORT; v = 0x5a5a5a5a;
    err = PacketCmdIntGet(&fsdio, 6, &v);
    expect_eq(err, PACKET_CTRL_SHORT, "2 of 4 bytes: short");
    expect_eq(v, 0x5a5a5a5a, "short IntGet leaves the caller's value whole, not half-written");
    for (k = 1; k <= 3; k++)
    {
        mode = M_SHORTN; shortN = k; v = 0x5a5a5a5a;
        err = PacketCmdIntGet(&fsdio, 6, &v);
        expect(err == PACKET_CTRL_SHORT && v == 0x5a5a5a5a, "1, 2 and 3-byte IntGet replies: SHORT, value whole");
    }
    mode = M_SHORT;                     /* 2 bytes again for the GetVar checks */
    {
        static UBYTE buf[8];
        for (i = 0; i < 8; i++) buf[i] = 0xa5;
        err = PacketGetVar(&fsdio, "x", buf, 8);
        expect_eq(err, 0, "GetVar: a shorter well-formed reply is success (capacity)");
        expect(buf[0] == 0x44 && buf[1] == 0x33, "the bytes that came are copied");
        ok = 1; for (i = 2; i < 8; i++) if (buf[i] != 0) ok = 0;
        expect(ok, "the rest is zeroed, not stale");
        for (i = 0; i < 8; i++) buf[i] = 0xa5;
        err = PacketGetVarMin(&fsdio, "x", buf, 8, 6);
        expect_eq(err, PACKET_CTRL_SHORT, "GetVarMin: below the required size is short");
        ok = 1; for (i = 2; i < 8; i++) if (buf[i] != 0) ok = 0;
        expect(ok, "and still zeroed, not stale");
    }
    mode = M_TRUNC; v = 0x5a5a5a5a;
    err = PacketCmdIntGet(&fsdio, 7, &v);
    expect_eq(err, PACKET_CTRL_TIMEOUT, "frame shorter than its header is dropped");
    expect_eq(v, 0x5a5a5a5a, "and copies nothing");
    helper_cmd(CMD_SWEEP);

    PutStr("step 7 around the deadline\n");
    ntimeout = nsuccess = 0;
    for (k = 0; k < 5; k++)
    {
        static const int ticks[5] = { 115, 123, 125, 127, 135 };   /* 2.30 .. 2.70 s */
        mode = M_DELAY; delayTicks = ticks[k]; v = 0x5a5a5a5a;
        err = PacketCmdIntGet(&fsdio, 8, &v);
        if (err == 0 && v == 0x11223344) nsuccess++;
        else if (err == PACKET_CTRL_TIMEOUT && v == 0x5a5a5a5a) ntimeout++;
        else expect(0, "boundary: neither a clean success nor a clean timeout");
        helper_cmd(CMD_SWEEP);
    }
    expect_eq(nsuccess + ntimeout, 5, "every boundary call ends cleanly");
    expect(nsuccess >= 1 && ntimeout >= 1, "both sides of the deadline seen");
    expect(listEmpty(), "nothing left after the boundary runs");

    PutStr("step 8 timer cannot open\n");
    wifipi_test_fail_timer = 1;
    k = sends;
    err = PacketCmdIntGet(&fsdio, 9, &v);
    wifipi_test_fail_timer = 0;
    expect_eq(err, PACKET_CTRL_NORES, "no timer: NORES");
    expect_eq(sends, k, "and nothing was sent");
    expect(listEmpty(), "or queued");
    wifipi_test_fail_timer = 2;         /* the port is there, timer.device refuses */
    err = PacketCmdIntGet(&fsdio, 9, &v);
    wifipi_test_fail_timer = 0;
    expect_eq(err, PACKET_CTRL_NORES, "timer.device refusing: NORES");
    expect_eq(sends, k, "still nothing sent");

    PutStr("step 9 timeout while the receiver is sending\n");
    mode = M_SENDBLOCK; sendBlockTicks = 175;   /* 3.5 s inside SendPKT */
    err = PacketCmdIntGet(&fsdio, 10, &v);
    expect_eq(err, PACKET_CTRL_TIMEOUT, "times out while being sent");
    {
        /* hand freed memory of that size back to someone and scribble on it */
        /* one probe of each size a control block can have, so a block freed
           too early is handed out again and scribbled on */
        static UBYTE *probes[40];
        for (k = 0; k < 40; k++)
        {
            probes[k] = AllocMem(40 + 4 * k, MEMF_PUBLIC);
            if (probes[k]) for (i = 0; i < (int)(40 + 4 * k); i++) probes[k][i] = 0xee;
        }
        Delay(75);                              /* SendPKT returns meanwhile */
        for (k = 0; k < 40; k++) if (probes[k]) FreeMem(probes[k], 40 + 4 * k);
    }
    expect(sendBlockIntact, "the block stayed valid until the receiver was done with it");
    helper_cmd(CMD_SWEEP);
    expect(listEmpty(), "and the receiver freed it after");

    PutStr("step 10 two callers\n");
    mode = M_ECHO;
    if (CreateNewProcTags(NP_Entry, (ULONG)second, NP_Name, (ULONG)"ctrl-caller2", NP_Priority, 0, TAG_DONE) != NULL)
    {
        err = PacketCmdIntGet(&fsdio, 97, &v);
        Wait(SIGBREAKF_CTRL_D);
        expect_eq(err, 0, "first caller answered");
        expect_eq(secondResult, 0, "second caller answered");
        expect(v == 0x11223344 && secondValue == 0x11223344, "both got their value");
    }
    else
        expect(0, "second caller started");

    PutStr("step 10b two live requests, answered out of order\n");
    mode = M_HOLD;
    SetSignal(0, SIGBREAKF_CTRL_D | SIGBREAKF_CTRL_C);
    if (CreateNewProcTags(NP_Entry, (ULONG)callerA, NP_Name, (ULONG)"ctrl-A", NP_Priority, 0, TAG_DONE) != NULL &&
        CreateNewProcTags(NP_Entry, (ULONG)callerB, NP_Name, (ULONG)"ctrl-B", NP_Priority, 0, TAG_DONE) != NULL)
    {
        Delay(10);                              /* both are on the list now */
        helper_cmd(CMD_REVERSE);
        Wait(SIGBREAKF_CTRL_D);
        Wait(SIGBREAKF_CTRL_C);
        expect(resA == 0 && valA == 0x11223344, "request A got its own reply");
        expect(resB == 0 && valB == 0x11223344, "request B got its own reply");
        expect(listEmpty(), "both off the list");
    }
    else
        expect(0, "callers A and B started");

    PutStr("step 10c same c_ID, other command: not a match\n");
    mode = M_WRONGCMD; v = 0x5a5a5a5a;
    err = PacketCmdIntGet(&fsdio, 12, &v);
    expect_eq(err, PACKET_CTRL_TIMEOUT, "a reply for another command is not taken");
    expect_eq(v, 0x5a5a5a5a, "and copies nothing");
    helper_cmd(CMD_SWEEP);
    expect(listEmpty(), "swept");

    PutStr("step 10d timeout while still queued on the receiver's port\n");
    mode = M_NOREPLY; holdPort = 1;
    k = sends;
    err = PacketCmdIntGet(&fsdio, 13, &v);
    expect_eq(err, PACKET_CTRL_TIMEOUT, "times out before the receiver took it");
    expect_eq(sends, k, "not sent yet");
    helper_cmd(CMD_PICK);
    helper_cmd(CMD_SWEEP);                  /* wakes the loop, which picks it up */
    expect_eq(sends, k + 1, "sent anyway: its TX seq is spent");
    expect(listEmpty(), "and freed, not left waiting");

    PutStr("step 11 GETSIGNALQUALITY timeout, then a read gets through\n");
    io = frame(&f, FULL);
    WiFi_Open(io, 0, 0);
    expect_eq(io->ios2_Req.io_Error, 0, "full Open");
    {
        static struct Sana2SignalQuality q;
        mode = M_NOREPLY;
        io->ios2_Req.io_Command = S2_GETSIGNALQUALITY;
        io->ios2_Req.io_Flags = IOF_QUICK;
        io->ios2_StatData = &q;
        funit.wu_Flags |= IFF_CONNECTED;
        WiFi_BeginIO(io);
        expect_eq(io->ios2_Req.io_Error, S2ERR_OUTOFSERVICE, "signal quality reports the lost reply");
        helper_cmd(CMD_SWEEP);
    }
    {
        struct MsgPort *rp = CreateMsgPort();
        read_io = frame(&rd, FULL);
        read_io->ios2_Req.io_Unit = &funit.wu_Unit;
        read_io->ios2_Req.io_Message.mn_ReplyPort = rp;
        read_io->ios2_BufferManagement = io->ios2_BufferManagement;
        read_io->ios2_Req.io_Command = CMD_READ;
        read_io->ios2_Req.io_Flags = IOF_QUICK;
        t0 = NOW();
        WiFi_BeginIO(read_io);
        t1 = NOW();
        expect((read_io->ios2_Req.io_Flags & IOF_QUICK) == 0, "CMD_READ queued: the unit lock was free");
        expect(t1 - t0 < 10, "at once");
        /* take it back: the fake base has no AbortIO vector, and on this
           base CMD_FLUSH does not return ordinary reads */
        Forbid();
        Remove(&read_io->ios2_Req.io_Message.mn_Node);
        Permit();
        DeleteMsgPort(rp);
    }
    WiFi_Close(io);

    PutStr("step 13 CONFIGINTERFACE: a 4-byte cur_etheraddr fails the command\n");
    {
        static Frame g;
        struct IOSana2Req *cio = frame(&g, FULL);
        UBYTE mac0[6];
        WiFi_Open(cio, 0, 0);
        expect_eq(cio->ios2_Req.io_Error, 0, "open for CONFIGINTERFACE");
        funit.wu_Flags &= ~(IFF_CONFIGURED | IFF_UP | IFF_ONLINE);
        for (i = 0; i < 6; i++) mac0[i] = funit.wu_EtherAddr[i];
        mode = M_ECHO;                  /* the get is answered with 4 bytes, not 6 */
        cio->ios2_Req.io_Command = S2_CONFIGINTERFACE;
        cio->ios2_Req.io_Flags = IOF_QUICK;
        WiFi_BeginIO(cio);
        expect_eq(cio->ios2_Req.io_Error, S2ERR_OUTOFSERVICE, "short cur_etheraddr fails CONFIGINTERFACE");
        expect((funit.wu_Flags & (IFF_CONFIGURED | IFF_UP | IFF_ONLINE)) == 0, "and the unit is not taken up");
        ok = 1; for (i = 4; i < 6; i++) if (funit.wu_EtherAddr[i] != 0) ok = 0;
        expect(ok, "the address bytes that did not come are zeroed, not stale");
        (void)mac0;
        funit.wu_Flags |= IFF_UP | IFF_ONLINE | IFF_CONFIGURED;
        WiFi_Close(cio);
    }

    PutStr("step 13b CONFIGINTERFACE: firmware silent after the address step\n");
    {
        static Frame g;
        struct IOSana2Req *cio = frame(&g, FULL);
        WiFi_Open(cio, 0, 0);
        funit.wu_Flags &= ~(IFF_CONFIGURED | IFF_UP | IFF_ONLINE);
        mode = M_MACONLY; modeCount = 0;
        cio->ios2_Req.io_Command = S2_CONFIGINTERFACE;
        cio->ios2_Req.io_Flags = IOF_QUICK;
        t0 = NOW();
        WiFi_BeginIO(cio);
        t1 = NOW();
        expect_eq(cio->ios2_Req.io_Error, S2ERR_OUTOFSERVICE, "silent firmware fails CONFIGINTERFACE");
        expect((funit.wu_Flags & (IFF_CONFIGURED | IFF_UP | IFF_ONLINE)) == 0, "unit not taken up");
        expect(t1 - t0 <= 150, "after one wait, not one per remaining step");
        helper_cmd(CMD_SWEEP);

        PutStr("step 13c CONFIGINTERFACE: only the final UP goes unanswered\n");
        mode = M_UPDEAD; upSeen = 0;
        cio->ios2_Req.io_Command = S2_CONFIGINTERFACE;
        cio->ios2_Req.io_Flags = IOF_QUICK;
        WiFi_BeginIO(cio);
        expect(upSeen, "bring-up got as far as the final UP");
        expect_eq(cio->ios2_Req.io_Error, S2ERR_OUTOFSERVICE, "a lost final UP fails CONFIGINTERFACE");
        expect((funit.wu_Flags & (IFF_CONFIGURED | IFF_UP | IFF_ONLINE)) == 0, "not reported up or online");
        helper_cmd(CMD_SWEEP);

        funit.wu_Flags |= IFF_UP | IFF_ONLINE | IFF_CONFIGURED;
        WiFi_Close(cio);
    }

    PutStr("step 13d StartUnit: the address is taken whole or not at all\n");
    {
        static Frame g;
        struct IOSana2Req *sio;
        for (i = 0; i < 6; i++) funit.wu_OrigEtherAddr[i] = 0xa5;
        funit.wu_Flags &= ~IFF_STARTED;
        mode = M_NOREPLY;
        sio = frame(&g, FULL);
        WiFi_Open(sio, 0, 0);
        expect((funit.wu_Flags & IFF_STARTED) == 0, "lost address: unit not marked started");
        ok = 1; for (i = 0; i < 6; i++) if (funit.wu_OrigEtherAddr[i] != 0xa5) ok = 0;
        expect(ok, "and the permanent address not overwritten");
        WiFi_Close(sio);
        helper_cmd(CMD_SWEEP);
        mode = M_SHORTN; shortN = 4;
        sio = frame(&g, FULL);
        WiFi_Open(sio, 0, 0);
        expect((funit.wu_Flags & IFF_STARTED) == 0, "4 of 6 address bytes: not started either");
        WiFi_Close(sio);
        mode = M_UPDEAD;                    /* 8-byte answers: the whole address */
        sio = frame(&g, FULL);
        WiFi_Open(sio, 0, 0);
        expect((funit.wu_Flags & IFF_STARTED) != 0, "whole address: started on the next open");
        expect(funit.wu_OrigEtherAddr[0] == 0x44 && funit.wu_OrigEtherAddr[5] == 0x66, "with the firmware's address");
        WiFi_Close(sio);
    }

    PutStr("step 12 receiver shutdown with a caller waiting\n");
    mode = M_NOREPLY;
    err = PacketCmdIntGet(&fsdio, 14, &v);  /* leaves an abandoned entry, unswept */
    expect(err == PACKET_CTRL_TIMEOUT && !listEmpty(), "an abandoned entry waits for the shutdown");
    {
        /* the second task waits; the receiver shuts down under it */
        secondResult = 0xffffffff;
        if (CreateNewProcTags(NP_Entry, (ULONG)second, NP_Name, (ULONG)"ctrl-caller3", NP_Priority, 0, TAG_DONE) != NULL)
        {
            Delay(25);
            t0 = NOW();
            helper_cmd(CMD_SHUTDOWN);
            Wait(SIGBREAKF_CTRL_D);
            t1 = NOW();
            expect_eq(secondResult, PACKET_CTRL_TIMEOUT, "waiting caller gets an error reply");
            expect(t1 - t0 < 25, "at once, not at its deadline");
        }
        expect(fsdio.s_ReceiverPort == NULL && fsdio.s_CtrlWaitList == NULL, "receiver pointers cleared");
        expect(listEmpty(), "abandoned and live entries all gone");
        err = PacketCmdIntGet(&fsdio, 11, &v);
        expect_eq(err, PACKET_CTRL_NORES, "after shutdown a request fails closed");
    }
    helper_cmd(CMD_QUIT);

    expect(lowsum() == low0, "low memory [0, 0x400) unchanged across the run");
    PutStr(failures ? "RESULT FAIL " : "RESULT PASS "); num(checks); PutStr(" checks, "); num(failures); PutStr(" failures\n");
    return failures ? 20 : 0;
}

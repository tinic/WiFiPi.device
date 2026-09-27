/*
 * wifipi.device against the requests WirelessManager 1.3 and 1.5 really
 * make, run under an emulator: no Pi hardware.  The driver's own
 * WiFi_Open/WiFi_BeginIO are linked in and called against a fake
 * WiFiBase/WiFiUnit.
 *
 * The rows are tests/callers/wirelessmanager-1.3.tsv and -1.5.tsv, which
 * check-corpus.py ties to the two binaries.  Replayed here are the ones that
 * need no firmware, each built exactly as the binary builds it:
 *
 *   row 1   NSCMD_DEVICEQUERY on the freshly opened 88-byte request
 *           (CreateIORequest = MEMF_CLEAR), io_Command and io_Data only,
 *           io_Data -> a 16-byte {0, 16, 0, 0} buffer on the caller's stack
 *   row 2   S2_GETSTATIONADDRESS on the same request, io_Command only
 *   row 24  (1.5 only) S2_SETOPTIONS whose tag list holds S2INFO_OperState
 *           and nothing else: accepted, and no join is sent
 *
 * The 16-byte buffer sits between canaries, so a write past it fails the
 * run, as does any frame sent to the card.
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

#ifndef S2INFO_OperState
#define S2INFO_OperState (TAG_USER + 20)
#endif

void  WiFi_Open(REGARG(struct IOSana2Req *io, "a1"), REGARG(LONG unitNumber, "d0"), REGARG(ULONG flags, "d1"));
ULONG WiFi_Close(REGARG(struct IOSana2Req *io, "a1"));
void  WiFi_BeginIO(REGARG(struct IOSana2Req *io, "a1"));

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

static volatile int sends;
static void fake_sendpkt(UBYTE *pkt, ULONG length, struct SDIO *sdio)
{
    (void)pkt; (void)length; (void)sdio;
    sends++;
}

#define CANARY 0xC3
/* the caller's stack frame around device_info: 16 bytes of canary each side */
static struct { UBYTE before[16]; struct NSDeviceQueryResult info; UBYTE after[16]; } frame;

static int canaries_intact(void)
{
    int i;
    for (i = 0; i < 16; i++)
        if (frame.before[i] != CANARY || frame.after[i] != CANARY) return 0;
    return 1;
}

static const UBYTE mac[6] = { 0x02, 0x5f, 0x01, 0x21, 0xfc, 0xbe };

static void do_io(struct IOSana2Req *io)
{
    /* DoIO: quick, then wait if it went to the unit task */
    io->ios2_Req.io_Flags = IOF_QUICK;
    WiFi_BeginIO(io);
    if (!(io->ios2_Req.io_Flags & IOF_QUICK))
        WaitIO((struct IORequest *)io);
}

static void replay(const char *version, int operstate)
{
    struct MsgPort *port = CreateMsgPort();
    struct IOSana2Req *io = (struct IOSana2Req *)CreateIORequest(port, sizeof(struct IOSana2Req));
    struct IOStdReq *std = (struct IOStdReq *)io;
    int getnetworks = 0, i;

    PutStr("WirelessManager "); PutStr(version); PutStr("\n");
    if (port == NULL || io == NULL)
    {
        expect(0, "request allocated");
        return;
    }

    io->ios2_Req.io_Device = (struct Device *)&fbase;
    io->ios2_BufferManagement = NULL;               /* WM passes its buffer tags; none needed here */
    WiFi_Open(io, 0, 0);
    expect_eq(io->ios2_Req.io_Error, 0, "OpenDevice");
    expect_eq(std->io_Length, 0, "io_Length still 0 after Open");
    expect(std->io_Data == NULL, "io_Data still NULL after Open");
    expect(io->ios2_Data == NULL, "ios2_Data still NULL after Open");

    /* row 1: movea.l 12(a3),a2; move.w #$4000,28(a2); lea -16(a5),a0;
       move.l a0,40(a2); movea.l a2,a1; jsr DoIO */
    memset(&frame, CANARY, sizeof(frame));
    frame.info.nsdqr_DevQueryFormat = 0;
    frame.info.nsdqr_SizeAvailable = 16;
    frame.info.nsdqr_DeviceType = 0;
    frame.info.nsdqr_DeviceSubType = 0;
    frame.info.nsdqr_SupportedCommands = NULL;
    std->io_Command = NSCMD_DEVICEQUERY;
    std->io_Data = &frame.info;
    do_io(io);
    expect_eq(std->io_Error, 0, "row 1 NSCMD_DEVICEQUERY answered");
    expect_eq(frame.info.nsdqr_DeviceType, NSDEVTYPE_SANA2, "row 1 DeviceType SANA-II");
    expect(frame.info.nsdqr_SupportedCommands != NULL, "row 1 command list present");
    {
        const UWORD *cmds = (const UWORD *)frame.info.nsdqr_SupportedCommands;
        for (i = 0; cmds != NULL && cmds[i] != 0; i++)
            if (cmds[i] == S2_GETNETWORKS) getnetworks = 1;
    }
    expect(getnetworks, "row 1 S2_GETNETWORKS listed (hard_mac)");
    expect(canaries_intact(), "row 1 nothing written outside the 16-byte buffer");
    expect(io->ios2_Data == NULL, "row 1 ios2_Data untouched");

    /* row 2 */
    io->ios2_Req.io_Command = S2_GETSTATIONADDRESS;
    do_io(io);
    expect_eq(io->ios2_Req.io_Error, 0, "row 2 S2_GETSTATIONADDRESS");
    expect(memcmp(io->ios2_DstAddr, mac, 6) == 0, "row 2 DstAddr = the station address");

    /* row 24, 1.5 only: a tag list with S2INFO_OperState alone */
    if (operstate)
    {
        struct TagItem tags[2];
        int before = sends;
        tags[0].ti_Tag = S2INFO_OperState;
        tags[0].ti_Data = 6;                    /* IF_OPER_UP */
        tags[1].ti_Tag = TAG_DONE;
        tags[1].ti_Data = 0;
        io->ios2_Req.io_Command = S2_SETOPTIONS;
        io->ios2_Data = tags;
        do_io(io);
        expect_eq(io->ios2_Req.io_Error, 0, "row 24 S2_SETOPTIONS OperState accepted");
        expect_eq(sends - before, 0, "row 24 no join sent to the card");
        io->ios2_Data = NULL;
    }

    WiFi_Close(io);
    DeleteIORequest((struct IORequest *)io);
    DeleteMsgPort(port);
}

int main(void)
{
    static struct timerequest tr;

    fbase.w_SysBase = SysBase;
    fbase.w_Unit = &funit;
    fbase.w_SDIO = &fsdio;
    fbase.w_UtilityBase = OpenLibrary((CONST_STRPTR)"utility.library", 37);
    funit.wu_Base = &fbase;
    funit.wu_Flags = IFF_STARTED;               /* no StartUnit(): no hardware */
    memcpy(funit.wu_EtherAddr, mac, 6);
    memcpy(funit.wu_OrigEtherAddr, mac, 6);
    InitSemaphore(&funit.wu_Lock);
    funit.wu_CmdQueue = CreateMsgPort();
    funit.wu_ScanQueue = CreateMsgPort();
    fsdio.s_SysBase = SysBase;
    fsdio.s_WiFiBase = &fbase;
    fsdio.SendPKT = fake_sendpkt;
    fsdio.s_SenderPort = CreateMsgPort();
    if (OpenDevice((CONST_STRPTR)TIMERNAME, UNIT_MICROHZ, (struct IORequest *)&tr, 0) == 0)
        funit.wu_TimerBase = (struct TimerBase *)tr.tr_node.io_Device;
    funit.wu_Openers.mlh_Head = (struct MinNode *)&funit.wu_Openers.mlh_Tail;
    funit.wu_Openers.mlh_Tail = NULL;
    funit.wu_Openers.mlh_TailPred = (struct MinNode *)&funit.wu_Openers.mlh_Head;

    PutStr("wifipi.device and the WirelessManager request corpus\n");
    if (fbase.w_UtilityBase == NULL || funit.wu_CmdQueue == NULL || funit.wu_ScanQueue == NULL ||
        fsdio.s_SenderPort == NULL || funit.wu_TimerBase == NULL)
    {
        PutStr("RESULT FAIL setup\n");
        return 20;
    }

    replay("1.3 (sha256 9d2e45a8)", 0);
    replay("1.5 (sha256 4f6227d1)", 1);

    PutStr(failures ? "RESULT FAIL " : "RESULT PASS "); num(checks); PutStr(" checks, "); num(failures); PutStr(" failures\n");
    return failures ? 20 : 0;
}

/*
 * NSCMD_DEVICEQUERY forms, run under an emulator: no Pi hardware.  The
 * driver's own WiFi_Open/WiFi_BeginIO/WiFi_Close and HandleRequest are linked
 * in and called against a fake WiFiBase/WiFiUnit.
 *
 * WirelessManager 1.3/1.5 (tests/callers corpus, row 1): CreateIORequest(88)
 * (MEMF_CLEAR), OpenDevice, then NSCMD_DEVICEQUERY as the first command with
 * io_Data = a 16-byte {0,16} buffer, io_Length and ios2_Data 0.  In a full
 * request io_Data is ios2_SrcAddr[0..3], which the driver itself writes, so a
 * reused request's io_Data can be a stale MAC.  Covered:
 *
 *   a  WM sequence answered; S2_GETSTATIONADDRESS afterwards
 *   b  same request closed and reopened with a stale io_Data: refused
 *   c  legacy query after another command on the request: refused
 *   d  CopyMem clone of the opened request: refused, and the opener's own
 *      first query still answered
 *   e  SANA-II form (ios2_Data, DataLength 16): answered into ios2_Data only
 *   f  short IOStdReq (limited open): answered into io_Data
 *   g  NULL io_Data, odd io_Data, ios2_Data with DataLength < 16: refused
 *   h  a second legacy query after an answered one: refused
 *   i  a rejected first legacy query, then a corrected one: refused
 *   j  the queued (unit-task) path: first query answered, second refused
 *   k  wu_FreshOpenReqs: +1 per Open, -1 at the first command, -1 at Close
 *      only if unused; two openers closed in both orders
 *
 * Every buffer and every request sits between 16-byte canaries; the stale
 * io_Data is made to point at a guarded decoy, so a write through it is seen.
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

#define CANARY 0xC3
#define FILL   0x5A

/* a result buffer: canaries each side, the 16 bytes preset as WM does */
typedef struct { UBYTE before[16]; struct NSDeviceQueryResult info; UBYTE after[16]; } Buf;
/* a request: canaries each side; bytes past mn_Length are canary too */
typedef struct { UBYTE before[16]; UBYTE req[sizeof(struct IOSana2Req)]; UBYTE after[16]; } Req;

static void buf_init(Buf *b)
{
    memset(b, CANARY, sizeof(*b));
    b->info.nsdqr_DevQueryFormat = 0;
    b->info.nsdqr_SizeAvailable = 16;
    b->info.nsdqr_DeviceType = 0;
    b->info.nsdqr_DeviceSubType = 0;
    b->info.nsdqr_SupportedCommands = NULL;
}
static int buf_guards(const Buf *b)
{
    int i;
    for (i = 0; i < 16; i++)
        if (b->before[i] != CANARY || b->after[i] != CANARY) return 0;
    return 1;
}
/* nothing written at all: guards intact and the preset unchanged */
static int buf_untouched(const Buf *b)
{
    return buf_guards(b) && b->info.nsdqr_DevQueryFormat == 0 &&
           b->info.nsdqr_SizeAvailable == 16 && b->info.nsdqr_DeviceType == 0 &&
           b->info.nsdqr_DeviceSubType == 0 && b->info.nsdqr_SupportedCommands == NULL;
}
static int buf_answered(const Buf *b)
{
    const UWORD *cmds = (const UWORD *)b->info.nsdqr_SupportedCommands;
    int i, getnetworks = 0;
    for (i = 0; cmds != NULL && cmds[i] != 0; i++)
        if (cmds[i] == S2_GETNETWORKS) getnetworks = 1;
    return buf_guards(b) && b->info.nsdqr_DevQueryFormat == 0 &&
           b->info.nsdqr_SizeAvailable == 16 &&
           b->info.nsdqr_DeviceType == NSDEVTYPE_SANA2 &&
           b->info.nsdqr_DeviceSubType == 0 && getnetworks;
}

static struct WiFiBase fbase;
static struct WiFiUnit funit;
static struct SDIO fsdio;
static struct MsgPort *reply;

static const UBYTE mac[6] = { 0x02, 0x5f, 0x01, 0x21, 0xfc, 0xbe };

static struct IOSana2Req *req_init(Req *r, UWORD mn_length)
{
    struct IOSana2Req *io = (struct IOSana2Req *)r->req;
    memset(r, CANARY, sizeof(*r));
    memset(r->req, 0, mn_length);           /* CreateIORequest: MEMF_CLEAR */
    io->ios2_Req.io_Message.mn_Node.ln_Type = NT_REPLYMSG;
    io->ios2_Req.io_Message.mn_ReplyPort = reply;
    io->ios2_Req.io_Message.mn_Length = mn_length;
    io->ios2_Req.io_Device = (struct Device *)&fbase;
    return io;
}
static int req_guards(const Req *r, UWORD mn_length)
{
    ULONG i;
    for (i = 0; i < 16; i++)
        if (r->before[i] != CANARY || r->after[i] != CANARY) return 0;
    for (i = mn_length; i < sizeof(r->req); i++)
        if (r->req[i] != CANARY) return 0;
    return 1;
}

static void do_io(struct IOSana2Req *io)
{
    io->ios2_Req.io_Flags = IOF_QUICK;
    WiFi_BeginIO(io);
    if (!(io->ios2_Req.io_Flags & IOF_QUICK))
        WaitIO((struct IORequest *)io);
}

/* full open of a fresh request, io_Data as the caller left it */
static struct IOSana2Req *open_full(Req *r, APTR io_data)
{
    struct IOSana2Req *io = req_init(r, sizeof(struct IOSana2Req));
    ((struct IOStdReq *)io)->io_Data = io_data;
    WiFi_Open(io, 0, 0);
    return io;
}

static void query(struct IOSana2Req *io, APTR io_data)
{
    io->ios2_Req.io_Command = NSCMD_DEVICEQUERY;
    ((struct IOStdReq *)io)->io_Data = io_data;
    do_io(io);
}

static void set_station(ULONG first4)
{
    funit.wu_EtherAddr[0] = first4 >> 24;
    funit.wu_EtherAddr[1] = first4 >> 16;
    funit.wu_EtherAddr[2] = first4 >> 8;
    funit.wu_EtherAddr[3] = first4;
    funit.wu_EtherAddr[4] = 0xfc;
    funit.wu_EtherAddr[5] = 0xbe;
}

static void getstation(struct IOSana2Req *io)
{
    io->ios2_Req.io_Command = S2_GETSTATIONADDRESS;
    do_io(io);
}

int main(void)
{
    static Req r, r2, rc, r3;
    static Buf buf, buf2, decoy;
    static struct timerequest tr;
    struct IOSana2Req *io, *clone;
    struct IOStdReq *std;
    ULONG low0, lib0, unit0;
    const UWORD FULL = sizeof(struct IOSana2Req);
    const UWORD SHORT = sizeof(struct IOStdReq);

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
    fsdio.s_SenderPort = CreateMsgPort();
    reply = CreateMsgPort();
    if (OpenDevice((CONST_STRPTR)TIMERNAME, UNIT_MICROHZ, (struct IORequest *)&tr, 0) == 0)
        funit.wu_TimerBase = (struct TimerBase *)tr.tr_node.io_Device;
    funit.wu_Openers.mlh_Head = (struct MinNode *)&funit.wu_Openers.mlh_Tail;
    funit.wu_Openers.mlh_Tail = NULL;
    funit.wu_Openers.mlh_TailPred = (struct MinNode *)&funit.wu_Openers.mlh_Head;

    PutStr("wifipi.device NSCMD_DEVICEQUERY forms\n");
    if (fbase.w_UtilityBase == NULL || funit.wu_CmdQueue == NULL || funit.wu_ScanQueue == NULL ||
        fsdio.s_SenderPort == NULL || reply == NULL || funit.wu_TimerBase == NULL)
    {
        PutStr("RESULT FAIL setup\n");
        return 20;
    }
    low0 = lowsum();
    lib0 = fbase.w_Device.dd_Library.lib_OpenCnt;
    unit0 = funit.wu_Unit.unit_OpenCnt;
    /* the stale-MAC decoy: S2_GETSTATIONADDRESS makes io_Data point at it */
    buf_init(&decoy);

    PutStr("a WirelessManager 1.3/1.5 sequence\n");
    io = open_full(&r, NULL);
    std = (struct IOStdReq *)io;
    expect_eq(io->ios2_Req.io_Error, 0, "a Open");
    expect_eq(std->io_Length, 0, "a io_Length 0 after Open");
    expect(io->ios2_Data == NULL, "a ios2_Data NULL after Open");
    buf_init(&buf);
    query(io, &buf.info);
    expect_eq(std->io_Error, 0, "a query answered");
    expect(buf_answered(&buf), "a 16-byte result, guards intact");
    expect_eq(std->io_Actual, 16, "a io_Actual 16");
    expect(io->ios2_Data == NULL, "a ios2_Data untouched");

    PutStr("h second legacy query on the same request\n");
    buf_init(&buf2);
    query(io, &buf2.info);
    expect_eq(std->io_Error, IOERR_BADLENGTH, "h refused");
    expect(buf_untouched(&buf2), "h buffer untouched");

    getstation(io);
    expect_eq(io->ios2_Req.io_Error, 0, "a S2_GETSTATIONADDRESS");
    expect(memcmp(io->ios2_DstAddr, mac, 6) == 0, "a DstAddr = station address");
    expect(req_guards(&r, FULL), "a request guards intact");
    WiFi_Close(io);

    PutStr("b stale request closed and reopened\n");
    io = open_full(&r, NULL);
    std = (struct IOStdReq *)io;
    set_station((ULONG)&decoy.info);
    getstation(io);                             /* SrcAddr[0..3] = &decoy.info */
    memcpy(funit.wu_EtherAddr, mac, 6);
    expect(std->io_Data == (APTR)&decoy.info, "b io_Data now the stale MAC");
    expect_eq(std->io_Length, 0, "b PacketType 0");
    WiFi_Close(io);
    io->ios2_BufferManagement = NULL;           /* no buffer tags on reopen */
    WiFi_Open(io, 0, 0);
    expect_eq(io->ios2_Req.io_Error, 0, "b reopen");
    io->ios2_Req.io_Command = NSCMD_DEVICEQUERY; /* io_Data left as it is */
    do_io(io);
    expect_eq(std->io_Error, IOERR_BADLENGTH, "b stale legacy query refused");
    expect(buf_untouched(&decoy), "b decoy untouched");
    expect(req_guards(&r, FULL), "b request guards intact");
    WiFi_Close(io);

    PutStr("c legacy query after another command\n");
    buf_init(&decoy);
    io = open_full(&r, NULL);
    std = (struct IOStdReq *)io;
    set_station((ULONG)&decoy.info);
    getstation(io);
    memcpy(funit.wu_EtherAddr, mac, 6);
    buf_init(&buf);
    query(io, &buf.info);
    expect_eq(std->io_Error, IOERR_BADLENGTH, "c refused after S2_GETSTATIONADDRESS");
    expect(buf_untouched(&buf), "c buffer untouched");
    expect(buf_untouched(&decoy), "c decoy untouched");

    PutStr("e SANA-II form on a used request\n");
    buf_init(&buf);
    buf_init(&decoy);
    io->ios2_Req.io_Command = NSCMD_DEVICEQUERY;
    std->io_Data = &decoy.info;
    io->ios2_Data = &buf.info;
    io->ios2_DataLength = 16;
    do_io(io);
    expect_eq(std->io_Error, 0, "e answered");
    expect(buf_answered(&buf), "e result in ios2_Data");
    expect_eq(io->ios2_DataLength, 16, "e ios2_DataLength 16");
    expect_eq(io->ios2_WireError, 0, "e WireError 0");
    expect(buf_untouched(&decoy), "e io_Data target untouched");
    expect(req_guards(&r, FULL), "e request guards intact");
    io->ios2_Data = NULL;
    io->ios2_DataLength = 0;
    WiFi_Close(io);

    PutStr("d CopyMem clone\n");
    io = open_full(&r, NULL);
    std = (struct IOStdReq *)io;
    req_init(&rc, FULL);
    CopyMem(io, rc.req, FULL);
    clone = (struct IOSana2Req *)rc.req;
    buf_init(&buf);
    query(clone, &buf.info);
    expect_eq(clone->ios2_Req.io_Error, IOERR_BADLENGTH, "d clone refused");
    expect(buf_untouched(&buf), "d buffer untouched");
    expect(req_guards(&rc, FULL), "d clone guards intact");
    buf_init(&buf);
    query(io, &buf.info);
    expect_eq(std->io_Error, 0, "d the opener's own first query still answered");
    expect(buf_answered(&buf), "d its result");
    WiFi_Close(io);

    PutStr("g refused forms\n");
    buf_init(&buf);
    io = open_full(&r, &buf2.info);             /* non-NULL at Open */
    std = (struct IOStdReq *)io;
    query(io, NULL);
    expect_eq(std->io_Error, IOERR_BADLENGTH, "g NULL io_Data refused");
    WiFi_Close(io);

    io = open_full(&r, NULL);
    std = (struct IOStdReq *)io;
    buf_init(&buf);
    query(io, (APTR)((ULONG)&buf.info + 1));
    expect_eq(std->io_Error, IOERR_BADLENGTH, "g odd io_Data refused");
    expect(buf_untouched(&buf), "g odd: buffer untouched");

    PutStr("i corrected query after a rejected first one\n");
    buf_init(&buf);
    query(io, &buf.info);
    expect_eq(std->io_Error, IOERR_BADLENGTH, "i refused");
    expect(buf_untouched(&buf), "i buffer untouched");
    WiFi_Close(io);

    io = open_full(&r, NULL);
    std = (struct IOStdReq *)io;
    buf_init(&buf);
    buf_init(&buf2);
    io->ios2_Data = &buf.info;
    io->ios2_DataLength = 15;
    query(io, &buf2.info);
    expect_eq(std->io_Error, IOERR_BADLENGTH, "g ios2_DataLength 15 refused");
    expect(buf_untouched(&buf), "g short ios2_Data untouched");
    expect(buf_untouched(&buf2), "g io_Data untouched");
    expect(req_guards(&r, FULL), "g request guards intact");
    io->ios2_Data = NULL;
    io->ios2_DataLength = 0;
    WiFi_Close(io);

    PutStr("j queued path\n");
    io = open_full(&r, NULL);
    std = (struct IOStdReq *)io;
    /* the unit lock held by some other task: BeginIO queues */
    funit.wu_Lock.ss_Owner = (struct Task *)&fbase;
    funit.wu_Lock.ss_NestCount = 1;
    funit.wu_Lock.ss_QueueCount = 0;
    buf_init(&buf);
    io->ios2_Req.io_Command = NSCMD_DEVICEQUERY;
    std->io_Data = &buf.info;
    io->ios2_Req.io_Flags = IOF_QUICK;
    WiFi_BeginIO(io);
    expect((io->ios2_Req.io_Flags & IOF_QUICK) == 0, "j query queued");
    expect(GetMsg(funit.wu_CmdQueue) == (struct Message *)io, "j on the command queue");
    HandleRequest(io);                          /* as the unit task does */
    WaitIO((struct IORequest *)io);
    expect_eq(std->io_Error, 0, "j queued query answered");
    expect(buf_answered(&buf), "j its result");
    buf_init(&buf2);
    io->ios2_Req.io_Command = NSCMD_DEVICEQUERY;
    std->io_Data = &buf2.info;
    io->ios2_Req.io_Flags = IOF_QUICK;
    WiFi_BeginIO(io);
    expect(GetMsg(funit.wu_CmdQueue) == (struct Message *)io, "j second on the command queue");
    HandleRequest(io);
    WaitIO((struct IORequest *)io);
    expect_eq(std->io_Error, IOERR_BADLENGTH, "j queued second query refused");
    expect(buf_untouched(&buf2), "j buffer untouched");
    InitSemaphore(&funit.wu_Lock);
    WiFi_Close(io);

    PutStr("k fresh open-request accounting\n");
    {
        UWORD n0 = funit.wu_FreshOpenReqs;
        struct IOSana2Req *io2;

        /* every earlier case closed what it opened: an underflow shows here */
        expect_eq(n0, 0, "k0 no fresh open requests before k");

        io = open_full(&r, NULL);
        expect_eq(funit.wu_FreshOpenReqs, n0 + 1, "k1 Open: +1");
        WiFi_Close(io);
        expect_eq(funit.wu_FreshOpenReqs, n0, "k1 Close unused: back");

        io = open_full(&r, NULL);
        buf_init(&buf);
        query(io, &buf.info);
        expect_eq(((struct IOStdReq *)io)->io_Error, 0, "k2 WM query answered");
        expect_eq(funit.wu_FreshOpenReqs, n0, "k2 first command (query): -1");
        getstation(io);
        expect_eq(funit.wu_FreshOpenReqs, n0, "k2 second command: no change");
        WiFi_Close(io);
        expect_eq(funit.wu_FreshOpenReqs, n0, "k2 Close used (query): no change");

        io = open_full(&r, NULL);
        getstation(io);
        expect_eq(funit.wu_FreshOpenReqs, n0, "k2 first command (S2_GETSTATIONADDRESS): -1");
        WiFi_Close(io);
        expect_eq(funit.wu_FreshOpenReqs, n0, "k2 Close used (getstation): no change");

        /* two openers, one used; closed used first, then unused first */
        io = open_full(&r, NULL);
        io2 = open_full(&r3, NULL);
        expect_eq(funit.wu_FreshOpenReqs, n0 + 2, "k3 two Opens: +2");
        getstation(io);
        expect_eq(funit.wu_FreshOpenReqs, n0 + 1, "k3 one used: +1");
        WiFi_Close(io);
        expect_eq(funit.wu_FreshOpenReqs, n0 + 1, "k3 Close used first: +1");
        WiFi_Close(io2);
        expect_eq(funit.wu_FreshOpenReqs, n0, "k3 then Close unused: back");

        io = open_full(&r, NULL);
        io2 = open_full(&r3, NULL);
        getstation(io);
        expect_eq(funit.wu_FreshOpenReqs, n0 + 1, "k3' one used: +1");
        WiFi_Close(io2);
        expect_eq(funit.wu_FreshOpenReqs, n0, "k3' Close unused first: back");
        WiFi_Close(io);
        expect_eq(funit.wu_FreshOpenReqs, n0, "k3' then Close used: no change");
        expect(req_guards(&r, FULL) && req_guards(&r3, FULL), "k request guards intact");
    }

    PutStr("l short first command on the opening request\n");
    {
        UWORD n0 = funit.wu_FreshOpenReqs;
        static const UWORD first_cmd[2] = { NSCMD_DEVICEQUERY, S2_GETSTATIONADDRESS };
        int i;

        for (i = 0; i < 2; i++)
        {
            io = open_full(&r, NULL);
            std = (struct IOStdReq *)io;
            io->ios2_Req.io_Message.mn_Length = SHORT;
            buf_init(&buf);
            if (first_cmd[i] == NSCMD_DEVICEQUERY)
            {
                std->io_Length = 16;
                query(io, &buf.info);
                expect_eq(std->io_Error, 0, "l short query answered");
            }
            else
            {
                getstation(io);
                expect_eq(std->io_Error, IOERR_BADLENGTH, "l short S2 command refused");
            }
            expect_eq(funit.wu_FreshOpenReqs, n0, "l short first command consumes");
            io->ios2_Req.io_Message.mn_Length = FULL;
            buf_init(&decoy);
            query(io, &decoy.info);
            expect_eq(std->io_Error, IOERR_BADLENGTH, "l later full legacy query refused");
            expect(buf_untouched(&decoy), "l decoy untouched");
            WiFi_Close(io);
            expect_eq(funit.wu_FreshOpenReqs, n0, "l Close used: no change");
            expect(req_guards(&r, FULL), "l request guards intact");
        }
    }

    PutStr("f short IOStdReq\n");
    io = req_init(&r2, SHORT);
    std = (struct IOStdReq *)io;
    WiFi_Open(io, 0, 0);
    expect_eq(std->io_Error, 0, "f limited Open");
    expect(std->io_Unit == &funit.wu_Unit, "f limited Open sets io_Unit");
    buf_init(&buf);
    std->io_Length = 16;
    query(io, &buf.info);
    expect_eq(std->io_Error, 0, "f answered");
    expect(buf_answered(&buf), "f result in io_Data");
    expect_eq(std->io_Actual, 16, "f io_Actual 16");
    query(io, NULL);
    expect_eq(std->io_Error, IOERR_BADLENGTH, "f NULL io_Data refused");
    expect(req_guards(&r2, SHORT), "f nothing past the 48-byte request");
    WiFi_Close(io);
    expect(req_guards(&r2, SHORT), "f Close reads/writes nothing past it");

    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, lib0, "device count balanced");
    expect_eq(funit.wu_Unit.unit_OpenCnt, unit0, "unit count balanced");
    expect_eq(funit.wu_FreshOpenReqs, 0, "no fresh open requests left");
    expect(lowsum() == low0, "low memory [0, 0x400) unchanged");

    PutStr(failures ? "RESULT FAIL " : "RESULT PASS "); num(checks); PutStr(" checks, "); num(failures); PutStr(" failures\n");
    return failures ? 20 : 0;
}

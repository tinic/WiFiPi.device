/*
 * wifipi.device request lifecycle, run under an emulator: no Pi hardware is
 * touched on these paths.  The driver's own WiFi_Open/WiFi_BeginIO/WiFi_Close
 * are linked in and called against a fake WiFiBase/WiFiUnit.
 *
 * Only full IOSana2Req opens are used: a short (limited-mode) open on this
 * base still takes no unit, and is not what these checks are about.
 *
 * WirelessManager 1.3 (driver_sana2.c) opens with an 88-byte request from
 * CreateIORequest(sizeof(struct IOSana2Req)) and asks NSCMD_DEVICEQUERY with
 * only io_Data set -- io_Length and ios2_Data stay 0.  That query must be
 * answered, or WirelessManager stops with "Failed to initialize driver
 * interface".
 *
 * #91: CMD_FLUSH and S2_OFFLINE hand back ordinary queued reads, an offline
 * unit refuses a new read, and S2_ONLINE takes reads again.
 *
 * Every request sits at the head of a block whose tail is a canary, and low
 * memory [0, 0x400) is checksummed around the whole run.
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
static int beyond_intact(const Frame *f, UWORD mn_length)
{
    ULONG i;
    for (i = mn_length; i < sizeof(f->req); i++) if (f->req[i] != 0xA5) return 0;
    for (i = 0; i < TAIL; i++) if (f->tail[i] != 0xA5) return 0;
    return 1;
}

static struct IOSana2Req *read_on(Frame *f, struct Opener *opener, struct MsgPort *reply)
{
    struct IOSana2Req *io = frame(f, sizeof(struct IOSana2Req));
    io->ios2_Req.io_Unit = &funit.wu_Unit;
    io->ios2_Req.io_Message.mn_ReplyPort = reply;
    io->ios2_BufferManagement = opener;
    io->ios2_Req.io_Command = CMD_READ;
    io->ios2_Req.io_Flags = IOF_QUICK;
    WiFi_BeginIO(io);
    return io;
}

static void control(Frame *f, UWORD command)
{
    struct IOSana2Req *io = frame(f, sizeof(struct IOSana2Req));
    io->ios2_Req.io_Unit = &funit.wu_Unit;
    io->ios2_Req.io_Command = command;
    io->ios2_Req.io_Flags = IOF_QUICK;
    WiFi_BeginIO(io);
}

int main(void)
{
    static Frame f, read_frame, ctl_frame;
    struct IOSana2Req *io, *read_io;
    struct IOStdReq *std;
    struct Opener *opener;
    struct MsgPort *read_reply;
    ULONG low0, lib0, unit0, i;
    int getnetworks;
    const UWORD FULL = sizeof(struct IOSana2Req);

    fbase.w_SysBase = SysBase;
    fbase.w_Unit = &funit;
    fbase.w_SDIO = &fsdio;
    fbase.w_UtilityBase = OpenLibrary((CONST_STRPTR)"utility.library", 37);
    funit.wu_Base = &fbase;
    funit.wu_Flags = IFF_STARTED;               /* no StartUnit(): no hardware */
    InitSemaphore(&funit.wu_Lock);
    funit.wu_CmdQueue = CreateMsgPort();
    funit.wu_ScanQueue = CreateMsgPort();
    fsdio.s_SenderPort = CreateMsgPort();
    read_reply = CreateMsgPort();
    {
        /* S2_ONLINE stamps LastStart with GetSysTime(): the unit's timer base,
           set by StartUnit() on hardware, is opened here. */
        static struct timerequest tr;
        if (OpenDevice((CONST_STRPTR)TIMERNAME, UNIT_MICROHZ, (struct IORequest *)&tr, 0) == 0)
            funit.wu_TimerBase = (struct TimerBase *)tr.tr_node.io_Device;
    }
    funit.wu_Openers.mlh_Head = (struct MinNode *)&funit.wu_Openers.mlh_Tail;
    funit.wu_Openers.mlh_Tail = NULL;
    funit.wu_Openers.mlh_TailPred = (struct MinNode *)&funit.wu_Openers.mlh_Head;

    PutStr("wifipi.device request lifecycle\n");
    if (funit.wu_CmdQueue == NULL || funit.wu_ScanQueue == NULL ||
        fsdio.s_SenderPort == NULL || read_reply == NULL || funit.wu_TimerBase == NULL)
    {
        PutStr("RESULT FAIL no ports or timer\n");
        return 20;
    }
    low0 = lowsum();
    lib0 = fbase.w_Device.dd_Library.lib_OpenCnt;
    unit0 = funit.wu_Unit.unit_OpenCnt;

    PutStr("step 1 full Open\n");
    io = frame(&f, FULL);
    WiFi_Open(io, 0, 0);
    expect_eq(io->ios2_Req.io_Error, 0, "full Open succeeds");
    expect(io->ios2_Req.io_Unit == &funit.wu_Unit, "full Open sets io_Unit");
    opener = io->ios2_BufferManagement;
    expect(opener != NULL, "full Open makes an opener");

    PutStr("step 2 WirelessManager query form\n");
    {
        /* driver_sana2.c: device_info = {0, sizeof(struct NSDeviceQueryResult)} */
        static struct NSDeviceQueryResult info;
        info.nsdqr_DevQueryFormat = 0;
        info.nsdqr_SizeAvailable = sizeof(info);
        info.nsdqr_DeviceType = 0x5A5A;
        info.nsdqr_SupportedCommands = NULL;
        std = (struct IOStdReq *)io;
        std->io_Command = NSCMD_DEVICEQUERY;
        std->io_Data = &info;
        std->io_Flags = IOF_QUICK;
        expect_eq(std->io_Length, 0, "WM form: io_Length left 0");
        expect(io->ios2_Data == NULL, "WM form: ios2_Data left NULL");
        WiFi_BeginIO(io);
        expect_eq(std->io_Error, 0, "WM form query answered");
        expect_eq(info.nsdqr_DeviceType, NSDEVTYPE_SANA2, "WM form DeviceType SANA-II");
        expect(info.nsdqr_SupportedCommands != NULL, "WM form command list present");
        getnetworks = 0;
        {
            const UWORD *cmds = (const UWORD *)info.nsdqr_SupportedCommands;
            for (i = 0; cmds != NULL && cmds[i] != 0; i++)
                if (cmds[i] == S2_GETNETWORKS)
                    getnetworks = 1;
        }
        expect(getnetworks, "WM finds S2_GETNETWORKS (hard-MAC device)");
        expect(beyond_intact(&f, FULL), "query writes nothing past the request");
    }

    PutStr("step 3 CMD_FLUSH returns a queued read\n");
    funit.wu_Flags |= IFF_UP | IFF_ONLINE;
    read_io = read_on(&read_frame, opener, read_reply);
    expect((read_io->ios2_Req.io_Flags & IOF_QUICK) == 0, "queued CMD_READ becomes asynchronous");
    control(&ctl_frame, CMD_FLUSH);
    expect((struct IOSana2Req *)GetMsg(read_reply) == read_io, "CMD_FLUSH returns an ordinary queued read");
    expect_eq(read_io->ios2_Req.io_Error, IOERR_ABORTED, "flushed read reports aborted");
    control(&ctl_frame, CMD_FLUSH);
    expect((struct IOSana2Req *)GetMsg(read_reply) == NULL, "a second CMD_FLUSH returns it no second time");

    PutStr("step 4 S2_OFFLINE returns a queued read\n");
    read_io = read_on(&read_frame, opener, read_reply);
    control(&ctl_frame, S2_OFFLINE);
    expect((funit.wu_Flags & IFF_ONLINE) == 0, "S2_OFFLINE clears IFF_ONLINE");
    expect((struct IOSana2Req *)GetMsg(read_reply) == read_io, "S2_OFFLINE returns an ordinary queued read");
    expect_eq(read_io->ios2_Req.io_Error, S2ERR_OUTOFSERVICE, "offline read reports out of service");
    expect_eq(read_io->ios2_WireError, S2WERR_UNIT_OFFLINE, "offline read reports unit offline");
    control(&ctl_frame, S2_OFFLINE);
    expect((struct IOSana2Req *)GetMsg(read_reply) == NULL, "a second S2_OFFLINE returns it no second time");

    PutStr("step 5 offline unit refuses a new read\n");
    read_io = read_on(&read_frame, opener, read_reply);
    expect_eq(read_io->ios2_Req.io_Error, S2ERR_OUTOFSERVICE, "offline unit rejects a new read synchronously");
    expect((struct IOSana2Req *)GetMsg(read_reply) == NULL, "and queues nothing");

    PutStr("step 6 S2_ONLINE takes reads again\n");
    control(&ctl_frame, S2_ONLINE);
    expect((funit.wu_Flags & IFF_ONLINE) != 0, "S2_ONLINE sets IFF_ONLINE");
    read_io = read_on(&read_frame, opener, read_reply);
    expect((read_io->ios2_Req.io_Flags & IOF_QUICK) == 0, "online unit queues a read again");
    control(&ctl_frame, CMD_FLUSH);
    expect((struct IOSana2Req *)GetMsg(read_reply) == read_io, "and CMD_FLUSH returns it");
    expect((struct IOSana2Req *)GetMsg(read_reply) == NULL, "exactly once");

    PutStr("step 7 full Close\n");
    WiFi_Close(io);
    expect_eq(fbase.w_Device.dd_Library.lib_OpenCnt, lib0, "full Close balances the device count");
    expect_eq(funit.wu_Unit.unit_OpenCnt, unit0, "full Close balances the unit count");

    DeleteMsgPort(read_reply);
    DeleteMsgPort(fsdio.s_SenderPort);
    DeleteMsgPort(funit.wu_ScanQueue);

    expect(lowsum() == low0, "low memory [0, 0x400) unchanged across the run");

    PutStr(failures ? "RESULT FAIL " : "RESULT PASS "); num(checks); PutStr(" checks, "); num(failures); PutStr(" failures\n");
    return failures ? 20 : 0;
}

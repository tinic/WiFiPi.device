/*
 * S2_GETNETWORKS from the request to the reply, run under an emulator: no Pi
 * hardware.  The driver's ProcessEvent, UpdateNetwork, ReplyScan,
 * ScanWatchdog, ScanParams and WiFi_BeginIO/WiFi_AbortIO are linked in
 * against a fake WiFiBase/WiFiUnit/SDIO; the firmware's escan events are
 * built here as a d11ac chip (the Pi 4's 43455) sends them.
 *
 *   params     the escan parameters name no channel (all the firmware
 *              allows, both bands); a directed scan carries its SSID
 *   wm         WirelessManager's scan (tests/callers row 11: ios2_Data =
 *              pool, ios2_StatData = an S2INFO_SSID tag list) is queued
 *   mixed      2.4 and 5 GHz networks at 20/40/80 MHz, every sideband,
 *              d11ac and d11n chanspecs: S2INFO_Channel is the primary
 *              channel, S2INFO_Band B or A; a duplicate is dropped, the
 *              same BSSID on another channel kept; replied once
 *   empty      a scan that finds nothing: io_Error 0, no list
 *   abort      AbortIO between 5 GHz results: replied once at completion,
 *              aborted and empty; later results are not written into it
 *   watchdog   a scan with no completion ends after 10 s (fake CLO), with
 *              what it found, or aborted and empty; not before
 *
 * Built like test_devquery (tests/README).
 */
#include <exec/exec.h>
#include <exec/io.h>
#include <exec/errors.h>
#include <devices/sana2.h>
#include <devices/sana2wireless.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/utility.h>
#include <string.h>

#include "../src/wifipi.h"
#include "../src/packet.h"

void  WiFi_Open(REGARG(struct IOSana2Req *io, "a1"), REGARG(LONG unitNumber, "d0"), REGARG(ULONG flags, "d1"));
ULONG WiFi_Close(REGARG(struct IOSana2Req *io, "a1"));
void  WiFi_BeginIO(REGARG(struct IOSana2Req *io, "a1"));
LONG  WiFi_AbortIO(REGARG(struct IOSana2Req *io, "a1"));

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
static ULONG fclock[2];                 /* the Pi's system timer: CLO at +4 */
static struct MsgPort *reply;

static void set_clock(ULONG us) { fclock[1] = __builtin_bswap32(us); }

/* d11ac chanspecs: band 2G 0x0000 / 5G 0xc000, BW 20 0x1000 / 40 0x1800 /
   80 0x2000, sideband LL(L) 0x0000, the centre channel in the low byte */
#define CS_2G_6_20      0x1006          /* primary 6 */
#define CS_5G_42_80_LL  0xe02a          /* 36..48, primary 36 */
#define CS_5G_46_40_L   0xd82e          /* 44+48, primary 44 */
#define CS_5G_149_20    0xd095          /* primary 149 */
#define CS_5G_46_40_U   0xd92e          /* 44+48, primary 48 */
#define CS_5G_42_80_LU  0xe12a          /* 36..48, primary 40 */
#define CS_5G_42_80_UL  0xe22a          /* 36..48, primary 44 */
#define CS_5G_42_80_UU  0xe32a          /* 36..48, primary 48 */
#define CS_2G_3_40_U    0x1903          /* 1..5, primary 5 */
#define CS_2G_11_20     0x100b          /* primary 11 */
/* d11n (43430): 2G 0x2000 / 5G 0x1000, BW 20 0x0800 / 40 0x0c00, SB L 0x0100 / none 0x0300 */
#define CSN_2G_1_20     0x2b01          /* primary 1 */
#define CSN_5G_38_40_L  0x1d26          /* 36+40, primary 36 */

struct Net { const char *ssid; UBYTE id; UWORD chanspec; WORD rssi; };

/* One BRCMF_E_ESCAN_RESULT event as the receiver hands it to ProcessEvent */
static void escan(const struct Net *nets, int count)
{
    static UBYTE buf[sizeof(struct PacketEvent) + sizeof(struct EScanResult) + 8 * sizeof(struct BSSInfo)];
    struct PacketEvent *pe = (struct PacketEvent *)buf;
    struct EScanResult *esr = (struct EScanResult *)(buf + sizeof(struct PacketEvent));

    memset(buf, 0, sizeof(buf));
    pe->e_EventType = BRCMF_E_ESCAN_RESULT;     /* network order = native */
    esr->esr_BSSCount = __builtin_bswap16(count);
    for (int i = 0; i < count; i++)
    {
        struct BSSInfo *b = &esr->esr_BSSInfo[i];
        int len = strlen(nets[i].ssid);
        b->bssi_ID[0] = 0x02; b->bssi_ID[5] = nets[i].id;
        b->bssi_SSIDLength = len;
        memcpy(b->bssi_SSID, nets[i].ssid, len);
        b->bssi_ChanSpec = __builtin_bswap16(nets[i].chanspec);
        b->bssi_RSSI = __builtin_bswap16((UWORD)nets[i].rssi);
        b->bssi_BeaconPeriod = __builtin_bswap16(100);
    }
    ProcessEvent(&fsdio, pe);
}
static void complete(void) { escan(NULL, 0); }

static struct TagItem *find(struct IOSana2Req *io, const char *ssid)
{
    struct Library *UtilityBase = fbase.w_UtilityBase;
    struct TagItem **list = io->ios2_StatData;
    for (ULONG i = 0; list != NULL && i < io->ios2_DataLength; i++)
    {
        const char *s = (const char *)GetTagData(S2INFO_SSID, 0, list[i]);
        if (s != NULL && strcmp(s, ssid) == 0)
            return list[i];
    }
    return NULL;
}

static void check_net(struct IOSana2Req *io, const char *ssid, LONG channel, LONG band, LONG rssi)
{
    struct Library *UtilityBase = fbase.w_UtilityBase;
    struct TagItem *t = find(io, ssid);
    expect(t != NULL, ssid);
    if (t == NULL) return;
    expect_eq(GetTagData(S2INFO_Channel, 0, t), channel, "S2INFO_Channel (primary)");
    expect_eq(GetTagData(S2INFO_Band, 99, t), band, "S2INFO_Band");
    expect_eq((LONG)GetTagData(S2INFO_Signal, 0, t), rssi, "S2INFO_Signal");
    expect(GetTagData(S2INFO_BSSID, 0, t) != 0, "S2INFO_BSSID");
}

/* What the receiver does on taking a scan off the queue (StartNetworkScan
   without the two control frames to the firmware) */
static void start(struct IOSana2Req *io, ULONG now)
{
    set_clock(now);
    io->ios2_DataLength = 0;
    io->ios2_StatData = NULL;
    io->ios2_Req.io_Error = 0;
    funit.wu_ScanStart = now;
    funit.wu_ScanRequest = io;
}

static struct IOSana2Req *open_req(APTR pool)
{
    struct IOSana2Req *io = AllocVec(sizeof(*io), MEMF_PUBLIC | MEMF_CLEAR);
    io->ios2_Req.io_Message.mn_Length = sizeof(*io);
    io->ios2_Req.io_Message.mn_ReplyPort = reply;
    io->ios2_Req.io_Device = (struct Device *)&fbase;
    WiFi_Open(io, 0, 0);
    expect_eq(io->ios2_Req.io_Error, 0, "Open");
    io->ios2_Req.io_Command = S2_GETNETWORKS;
    io->ios2_Data = pool;
    return io;
}

static int replies(struct IOSana2Req *io)
{
    int n = 0;
    struct Message *m;
    while ((m = GetMsg(reply)) != NULL)
    {
        expect(m == (struct Message *)io, "the scan request replied");
        n++;
    }
    return n;
}

int main(void)
{
    static const struct Net mixed[] = {
        { "Two4",   1, CS_2G_6_20,     -40 },
        { "Five80", 2, CS_5G_42_80_LL, -55 },
        { "Five40", 3, CS_5G_46_40_L,  -66 },
    };
    static const struct Net more[] = {
        { "Five20", 4, CS_5G_149_20,   -77 },
        { "Two4",   1, CS_2G_6_20,     -41 },      /* duplicate: dropped */
    };
    static const struct Net sidebands[] = {
        { "U40",    5, CS_5G_46_40_U,  -50 },
        { "LU80",   6, CS_5G_42_80_LU, -51 },
        { "UL80",   7, CS_5G_42_80_UL, -52 },
        { "UU80",   8, CS_5G_42_80_UU, -53 },
        { "Two4U",  9, CS_2G_3_40_U,   -54 },
        { "Two4",   1, CS_2G_11_20,    -42 },      /* same BSSID, other channel: kept */
    };
    static const struct Net d11n[] = {
        { "N20",   10, CSN_2G_1_20,    -60 },
        { "N40",   11, CSN_5G_38_40_L, -61 },
    };
    struct Library *UtilityBase;
    UBYTE buf[SCAN_PARAMS_SIZE];
    const UBYTE *p;
    APTR pool;
    struct IOSana2Req *io;

    UtilityBase = OpenLibrary((CONST_STRPTR)"utility.library", 37);
    reply = CreateMsgPort();
    pool = CreatePool(MEMF_PUBLIC | MEMF_CLEAR, 4096, 4096);
    fbase.w_SysBase = SysBase;
    fbase.w_UtilityBase = UtilityBase;
    fbase.w_Unit = &funit;
    fbase.w_SDIO = &fsdio;
    fbase.w_SysTimer = fclock;
    fsdio.s_WiFiBase = &fbase;
    fsdio.s_SysBase = SysBase;
    fsdio.s_Chip = &fchip;
    fchip.c_D11Type = 2;                        /* BRCMU_D11AC_IOTYPE */
    funit.wu_Base = &fbase;
    funit.wu_Flags = IFF_STARTED | IFF_CONFIGURED | IFF_UP | IFF_ONLINE;
    InitSemaphore(&funit.wu_Lock);
    funit.wu_Openers.mlh_Head = (struct MinNode *)&funit.wu_Openers.mlh_Tail;
    funit.wu_Openers.mlh_TailPred = (struct MinNode *)&funit.wu_Openers.mlh_Head;
    funit.wu_ScanQueue = CreateMsgPort();

    PutStr("wifipi.device S2_GETNETWORKS: params, both bands, abort, watchdog\n");
    if (UtilityBase == NULL || reply == NULL || pool == NULL || funit.wu_ScanQueue == NULL)
    {
        PutStr("RESULT FAIL setup\n");
        return 20;
    }

    PutStr("params\n");
    p = ScanParams(buf, NULL);
    expect_eq(p[0] | p[1] << 8, 1, "escan version 1");
    expect_eq(p[4] | p[5] << 8, 1, "action start");
    expect_eq(p[SCAN_PARAMS_NCHAN] | p[SCAN_PARAMS_NCHAN + 1] << 8, 0, "no channel named: all, both bands");
    expect_eq(p[SCAN_PARAMS_NCHAN + 2] | p[SCAN_PARAMS_NCHAN + 3] << 8, 0, "no SSID");
    expect_eq(p[8], 0, "broadcast scan: SSID length 0");
    p = ScanParams(buf, (const UBYTE *)"Hidden");
    expect(p == buf, "directed scan in the caller's buffer");
    expect_eq(p[8], 6, "directed scan: SSID length");
    expect(memcmp(p + 12, "Hidden", 6) == 0, "directed scan: SSID");
    expect_eq(p[SCAN_PARAMS_NCHAN] | p[SCAN_PARAMS_NCHAN + 1] << 8, 0, "directed scan: all channels");

    PutStr("wm row 11\n");
    {
        struct TagItem tags[] = { { S2INFO_SSID, (ULONG)"Five80" }, { TAG_DONE, 0 } };
        io = open_req(pool);
        io->ios2_StatData = tags;
        WiFi_BeginIO(io);
        expect(GetMsg(reply) == NULL, "queued, not replied");
        expect(GetMsg(funit.wu_ScanQueue) == (struct Message *)io, "on the scan queue");
        p = ScanParams(buf, (const UBYTE *)GetTagData(S2INFO_SSID, 0, tags));
        expect(memcmp(p + 12, "Five80", 6) == 0, "WM's SSID is the probe");
    }

    PutStr("mixed\n");
    start(io, 1000);
    escan(mixed, 3);
    escan(more, 2);
    expect_eq(replies(io), 0, "not replied before completion");
    complete();
    expect_eq(replies(io), 1, "replied once at completion");
    expect(funit.wu_ScanRequest == NULL, "unit released it");
    expect_eq(io->ios2_Req.io_Error, 0, "io_Error 0");
    expect_eq(io->ios2_DataLength, 4, "four networks, duplicate dropped");
    check_net(io, "Two4",   6,   S2BAND_B, -40);
    check_net(io, "Five80", 36,  S2BAND_A, -55);
    check_net(io, "Five40", 44,  S2BAND_A, -66);
    check_net(io, "Five20", 149, S2BAND_A, -77);
    complete();
    expect_eq(replies(io), 0, "a second completion replies nothing");

    PutStr("sidebands\n");
    start(io, 1500);
    escan(sidebands, 6);
    complete();
    expect_eq(replies(io), 1, "sidebands: replied once");
    expect_eq(io->ios2_DataLength, 6, "sidebands: six networks");
    check_net(io, "U40",   48, S2BAND_A, -50);
    check_net(io, "LU80",  40, S2BAND_A, -51);
    check_net(io, "UL80",  44, S2BAND_A, -52);
    check_net(io, "UU80",  48, S2BAND_A, -53);
    check_net(io, "Two4U",  5, S2BAND_B, -54);
    check_net(io, "Two4",  11, S2BAND_B, -42);

    PutStr("d11n\n");
    fchip.c_D11Type = 1;                        /* BRCMU_D11N_IOTYPE */
    start(io, 1700);
    escan(d11n, 2);
    complete();
    expect_eq(replies(io), 1, "d11n: replied once");
    check_net(io, "N20",  1, S2BAND_B, -60);
    check_net(io, "N40", 36, S2BAND_A, -61);
    fchip.c_D11Type = 2;

    PutStr("empty\n");
    start(io, 2000);
    complete();
    expect_eq(replies(io), 1, "empty: replied once");
    expect_eq(io->ios2_Req.io_Error, 0, "empty: io_Error 0");
    expect_eq(io->ios2_DataLength, 0, "empty: no networks");
    expect(io->ios2_StatData == NULL, "empty: no list");

    PutStr("abort\n");
    start(io, 3000);
    escan(mixed + 1, 1);
    WiFi_AbortIO(io);
    expect_eq(replies(io), 0, "abort: not replied by AbortIO");
    escan(more, 1);
    expect_eq(io->ios2_DataLength, 1, "abort: later results not written");
    complete();
    expect_eq(replies(io), 1, "abort: replied once at completion");
    expect_eq(io->ios2_Req.io_Error, IOERR_ABORTED, "abort: IOERR_ABORTED");
    expect_eq(io->ios2_DataLength, 0, "abort: no networks");
    expect(io->ios2_StatData == NULL, "abort: no list");

    PutStr("watchdog\n");
    start(io, 0xfffff000);                      /* across the CLO wrap */
    escan(mixed, 2);
    set_clock(0xfffff000 + 9000000);
    ScanWatchdog(&fbase);
    expect_eq(replies(io), 0, "watchdog: 9 s, still running");
    set_clock(0xfffff000 + 10000001);
    ScanWatchdog(&fbase);
    expect_eq(replies(io), 1, "watchdog: past 10 s, replied");
    expect(funit.wu_ScanRequest == NULL, "watchdog: unit released it");
    expect_eq(io->ios2_Req.io_Error, 0, "watchdog: io_Error 0");
    expect_eq(io->ios2_DataLength, 2, "watchdog: the networks found so far");
    ScanWatchdog(&fbase);
    complete();
    expect_eq(replies(io), 0, "watchdog: late completion replies nothing");

    start(io, 5000);
    escan(mixed, 1);
    WiFi_AbortIO(io);
    set_clock(5000 + 10000001);
    ScanWatchdog(&fbase);
    expect_eq(replies(io), 1, "watchdog after abort: replied once");
    expect_eq(io->ios2_Req.io_Error, IOERR_ABORTED, "watchdog after abort: IOERR_ABORTED");
    expect_eq(io->ios2_DataLength, 0, "watchdog after abort: empty");

    WiFi_Close(io);
    FreeVec(io);
    DeletePool(pool);

    PutStr(failures ? "RESULT FAIL " : "RESULT PASS "); num(checks); PutStr(" checks, "); num(failures); PutStr(" failures\n");
    return failures ? 20 : 0;
}

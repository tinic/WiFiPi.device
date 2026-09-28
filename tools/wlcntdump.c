/*
 * wlcntdump: write the firmware's 'counters' (AmiNetXDuo #89) to a file.
 * Only a driver built with -DWIFIPI_WLCNT answers the command.
 *
 *   wlcntdump FILE/A,DEVICE/K,UNIT/K/N
 *
 * One line out, key=value; RC 0 written and the firmware answered, 5 written
 * but the firmware refused or did not answer (error= says which), 10 the
 * driver refused, 20 failed.  The file is the dump as the driver made it:
 * struct WcDumpHeader (big-endian), then wd_Asked bytes of the firmware's
 * answer as it came (little-endian).  Take one before and one after a leg;
 * tools/wlcnt.py diffs them.
 */
#include <exec/types.h>
#include <exec/memory.h>
#include <exec/io.h>
#include <dos/dos.h>
#include <devices/sana2.h>
#include <proto/exec.h>
#include <proto/dos.h>

#include "../src/wlcnt.h"

#define TEMPLATE "FILE/A,DEVICE/K,UNIT/K/N"
#define SIZE     (sizeof(struct WcDumpHeader) + WC_GET_SIZE)

static const char ver[] __attribute__((used)) = "$VER: wlcntdump 1.0 (28.9.2026)";

int main(void)
{
    LONG args[3] = { 0, 0, 0 };
    struct RDArgs *rd = ReadArgs((CONST_STRPTR)TEMPLATE, args, NULL);
    CONST_STRPTR dev = (CONST_STRPTR)"anxwifipi.device";
    ULONG unit = 0;
    struct MsgPort *port = NULL;
    struct IOSana2Req *io = NULL;
    UBYTE *buf = NULL;
    struct WcDumpHeader *h;
    BPTR fh;
    int rc = RETURN_FAIL;
    BOOL open = FALSE;

    if (rd == NULL)
    {
        PutStr((CONST_STRPTR)"wlcntdump=fail reason=args\n");
        return RETURN_FAIL;
    }
    if (args[1])
        dev = (CONST_STRPTR)args[1];
    if (args[2])
        unit = *(ULONG *)args[2];

    port = CreateMsgPort();
    if (port)
        io = (struct IOSana2Req *)CreateIORequest(port, sizeof(struct IOSana2Req));
    buf = AllocMem(SIZE, MEMF_ANY | MEMF_CLEAR);
    if (io == NULL || buf == NULL)
    {
        PutStr((CONST_STRPTR)"wlcntdump=fail reason=memory\n");
        goto out;
    }
    io->ios2_BufferManagement = NULL;
    if (OpenDevice(dev, unit, (struct IORequest *)io, 0) != 0)
    {
        Printf((CONST_STRPTR)"wlcntdump=fail reason=open error=%ld\n", (LONG)io->ios2_Req.io_Error);
        goto out;
    }
    open = TRUE;

    h = (struct WcDumpHeader *)buf;
    io->ios2_Req.io_Command = WIFIPI_CMD_WLCNT;
    io->ios2_Data = buf;
    io->ios2_DataLength = SIZE;
    if (DoIO((struct IORequest *)io) != 0 || h->wd_Magic != WC_DUMP_MAGIC)
    {
        Printf((CONST_STRPTR)"wlcntdump=refused error=%ld\n", (LONG)io->ios2_Req.io_Error);
        rc = RETURN_ERROR;
        goto out;
    }

    fh = Open((CONST_STRPTR)args[0], MODE_NEWFILE);
    if (fh == 0)
    {
        Printf((CONST_STRPTR)"wlcntdump=fail reason=file ioerr=%ld\n", IoErr());
        goto out;
    }
    if (Write(fh, buf, io->ios2_DataLength) != (LONG)io->ios2_DataLength)
    {
        Printf((CONST_STRPTR)"wlcntdump=fail reason=write ioerr=%ld\n", IoErr());
        Close(fh);
        goto out;
    }
    Close(fh);

    {
        UBYTE *d = buf + sizeof(*h);
        Printf((CONST_STRPTR)"wlcntdump=%s bytes=%lu error=%ld copied=%lu version=%lu length=%lu "
               "clo_before=%lu clo_after=%lu flags=0x%08lx\n",
               h->wd_Error ? "fwerror" : "ok", io->ios2_DataLength, (LONG)h->wd_Error, h->wd_Copied,
               (ULONG)(d[0] | (d[1] << 8)), (ULONG)(d[2] | (d[3] << 8)),
               h->wd_CloBefore, h->wd_CloAfter, h->wd_UnitFlags);
    }
    rc = h->wd_Error ? RETURN_WARN : RETURN_OK;

out:
    if (open)
        CloseDevice((struct IORequest *)io);
    if (buf)
        FreeMem(buf, SIZE);
    if (io)
        DeleteIORequest((struct IORequest *)io);
    if (port)
        DeleteMsgPort(port);
    FreeArgs(rd);
    return rc;
}

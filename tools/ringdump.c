/*
 * ringdump: write a debug driver's event ring (AmiNetXDuo #89) to a file.
 * Only a driver built with -DWIFIPI_RINGTRACE answers the command.
 *
 *   ringdump FILE/A,DEVICE/K,UNIT/K/N
 *
 * One line out, key=value; RC 0 written, 10 the driver refused, 20 failed.
 * The file is the dump as the driver made it: struct RtDumpHeader, then
 * rd_Count records oldest first, all big-endian.  tools/ringtrace.py reads it.
 */
#include <exec/types.h>
#include <exec/memory.h>
#include <exec/io.h>
#include <dos/dos.h>
#include <devices/sana2.h>
#include <proto/exec.h>
#include <proto/dos.h>

#include "../src/ringtrace.h"

#define TEMPLATE "FILE/A,DEVICE/K,UNIT/K/N"
#define MARGIN   262144UL       /* records that may land between probe and dump */

static const char ver[] __attribute__((used)) = "$VER: ringdump 1.0 (28.9.2026)";

int main(void)
{
    LONG args[3] = { 0, 0, 0 };
    struct RDArgs *rd = ReadArgs((CONST_STRPTR)TEMPLATE, args, NULL);
    CONST_STRPTR dev = (CONST_STRPTR)"anxwifipi.device";
    ULONG unit = 0;
    struct MsgPort *port = NULL;
    struct IOSana2Req *io = NULL;
    struct RtDumpHeader probe;
    UBYTE *buf = NULL;
    ULONG size = 0, held, want;
    BPTR fh;
    int rc = RETURN_FAIL;
    BOOL open = FALSE;

    if (rd == NULL)
    {
        PutStr((CONST_STRPTR)"ringdump=fail reason=args\n");
        return RETURN_FAIL;
    }
    if (args[1])
        dev = (CONST_STRPTR)args[1];
    if (args[2])
        unit = *(ULONG *)args[2];

    port = CreateMsgPort();
    if (port)
        io = (struct IOSana2Req *)CreateIORequest(port, sizeof(struct IOSana2Req));
    if (io == NULL)
    {
        PutStr((CONST_STRPTR)"ringdump=fail reason=memory\n");
        goto out;
    }
    io->ios2_BufferManagement = NULL;
    if (OpenDevice(dev, unit, (struct IORequest *)io, 0) != 0)
    {
        Printf((CONST_STRPTR)"ringdump=fail reason=open error=%ld\n", (LONG)io->ios2_Req.io_Error);
        goto out;
    }
    open = TRUE;

    /* header only: the ring's size and fill */
    io->ios2_Req.io_Command = WIFIPI_CMD_RINGDUMP;
    io->ios2_Data = &probe;
    io->ios2_DataLength = sizeof(probe);
    if (DoIO((struct IORequest *)io) != 0 || probe.rd_Magic != RT_DUMP_MAGIC)
    {
        Printf((CONST_STRPTR)"ringdump=refused error=%ld\n", (LONG)io->ios2_Req.io_Error);
        rc = RETURN_ERROR;
        goto out;
    }

    held = probe.rd_Seq < probe.rd_Capacity ? probe.rd_Seq : probe.rd_Capacity;
    want = held + MARGIN < probe.rd_Capacity ? held + MARGIN : probe.rd_Capacity;
    while (buf == NULL && want > 0)
    {
        size = sizeof(struct RtDumpHeader) + want * sizeof(struct RtRec);
        buf = AllocMem(size, MEMF_ANY);
        if (buf == NULL)
            want /= 2;
    }
    if (buf == NULL)
    {
        PutStr((CONST_STRPTR)"ringdump=fail reason=memory\n");
        goto out;
    }

    io->ios2_Req.io_Command = WIFIPI_CMD_RINGDUMP;
    io->ios2_Data = buf;
    io->ios2_DataLength = size;
    if (DoIO((struct IORequest *)io) != 0)
    {
        Printf((CONST_STRPTR)"ringdump=refused error=%ld\n", (LONG)io->ios2_Req.io_Error);
        rc = RETURN_ERROR;
        goto out;
    }

    fh = Open((CONST_STRPTR)args[0], MODE_NEWFILE);
    if (fh == 0)
    {
        Printf((CONST_STRPTR)"ringdump=fail reason=file ioerr=%ld\n", IoErr());
        goto out;
    }
    if (Write(fh, buf, io->ios2_DataLength) != (LONG)io->ios2_DataLength)
    {
        Printf((CONST_STRPTR)"ringdump=fail reason=write ioerr=%ld\n", IoErr());
        Close(fh);
        goto out;
    }
    Close(fh);

    {
        struct RtDumpHeader *h = (struct RtDumpHeader *)buf;
        Printf((CONST_STRPTR)"ringdump=ok bytes=%lu capacity=%lu seq=%lu first=%lu count=%lu lost=%lu clo=%lu\n",
               io->ios2_DataLength, h->rd_Capacity, h->rd_Seq, h->rd_First, h->rd_Count,
               h->rd_Lost, h->rd_Clo);
    }
    rc = RETURN_OK;

out:
    if (buf)
        FreeMem(buf, size);
    if (open)
        CloseDevice((struct IORequest *)io);
    if (io)
        DeleteIORequest((struct IORequest *)io);
    if (port)
        DeleteMsgPort(port);
    FreeArgs(rd);
    return rc;
}

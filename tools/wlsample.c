/*
 * wlsample: switch a debug driver's in-leg counter sampler on or off
 * (AmiNetXDuo #89).  Only a driver built with -DWIFIPI_WLSAMPLE (and so
 * -DWIFIPI_RINGTRACE) answers.  ENABLE works once per driver instance;
 * DISABLE is for good.  The samples are in the event ring: ringdump, then
 * tools/wlsample.py.
 *
 *   wlsample ENABLE/S,DISABLE/S,DEVICE/K,UNIT/K/N
 *
 * One line out, key=value; RC 0 done, 10 the driver refused, 20 failed.
 */
#include <exec/types.h>
#include <exec/io.h>
#include <dos/dos.h>
#include <devices/sana2.h>
#include <proto/exec.h>
#include <proto/dos.h>

#define WIFIPI_CMD_WLSAMPLE_ENABLE  0xF08B      /* src/wlsample.h */
#define WIFIPI_CMD_WLSAMPLE_DISABLE 0xF08C

#define TEMPLATE "ENABLE/S,DISABLE/S,DEVICE/K,UNIT/K/N"

static const char ver[] __attribute__((used)) = "$VER: wlsample 1.0 (28.9.2026)";

int main(void)
{
    LONG args[4] = { 0, 0, 0, 0 };
    struct RDArgs *rd = ReadArgs((CONST_STRPTR)TEMPLATE, args, NULL);
    CONST_STRPTR dev = (CONST_STRPTR)"anxwifipi.device";
    ULONG unit = 0;
    struct MsgPort *port = NULL;
    struct IOSana2Req *io = NULL;
    int rc = RETURN_FAIL;
    BOOL open = FALSE;

    if (rd == NULL || (args[0] != 0) == (args[1] != 0))
    {
        PutStr((CONST_STRPTR)"wlsample=fail reason=args\n");
        if (rd)
            FreeArgs(rd);
        return RETURN_FAIL;
    }
    if (args[2])
        dev = (CONST_STRPTR)args[2];
    if (args[3])
        unit = *(ULONG *)args[3];

    port = CreateMsgPort();
    if (port)
        io = (struct IOSana2Req *)CreateIORequest(port, sizeof(struct IOSana2Req));
    if (io == NULL)
    {
        PutStr((CONST_STRPTR)"wlsample=fail reason=memory\n");
        goto out;
    }
    io->ios2_BufferManagement = NULL;
    if (OpenDevice(dev, unit, (struct IORequest *)io, 0) != 0)
    {
        Printf((CONST_STRPTR)"wlsample=fail reason=open error=%ld\n", (LONG)io->ios2_Req.io_Error);
        goto out;
    }
    open = TRUE;

    io->ios2_Req.io_Command = args[0] ? WIFIPI_CMD_WLSAMPLE_ENABLE : WIFIPI_CMD_WLSAMPLE_DISABLE;
    if (DoIO((struct IORequest *)io) != 0)
    {
        Printf((CONST_STRPTR)"wlsample=refused op=%s error=%ld wire=%ld\n", args[0] ? "enable" : "disable",
               (LONG)io->ios2_Req.io_Error, (LONG)io->ios2_WireError);
        rc = RETURN_ERROR;
        goto out;
    }
    Printf((CONST_STRPTR)"wlsample=ok op=%s\n", args[0] ? "enable" : "disable");
    rc = RETURN_OK;

out:
    if (open)
        CloseDevice((struct IORequest *)io);
    if (io)
        DeleteIORequest((struct IORequest *)io);
    if (port)
        DeleteMsgPort(port);
    FreeArgs(rd);
    return rc;
}

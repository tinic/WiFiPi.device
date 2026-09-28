/*
 * btcmode: read the firmware's BT-coexistence state, or set btc_mode
 * (AmiNetXDuo #89, hw34).  Only a driver built with -DWIFIPI_BTC answers.
 *
 *   btcmode GET NAME          NAME: btc_mode, btc_flags, btc_dos_status, ant_dt, ext_gpio
 *   btcmode SET btc_mode N
 *
 * One line out, key=value.  RC 0 ok, 5 the firmware refused (fwerror=),
 * 10 the driver refused, 20 failed (no reply, no device, bad arguments).
 */
#include <exec/types.h>
#include <exec/io.h>
#include <dos/dos.h>
#include <devices/sana2.h>
#include <proto/exec.h>
#include <proto/dos.h>

#include "../src/btc.h"

#define TEMPLATE "OP/A,NAME/A,VALUE/N,DEVICE/K,UNIT/K/N"

static const char ver[] __attribute__((used)) = "$VER: btcmode 1.0 (28.9.2026)";

static int same(CONST_STRPTR a, const char *b)
{
    while (*a && (*a | 0x20) == (*b | 0x20))
        a++, b++;
    return *a == 0 && *b == 0;
}

int main(void)
{
    LONG args[5] = { 0, 0, 0, 0, 0 };
    struct RDArgs *rd = ReadArgs((CONST_STRPTR)TEMPLATE, args, NULL);
    CONST_STRPTR dev = (CONST_STRPTR)"anxwifipi.device";
    ULONG unit = 0, i;
    struct MsgPort *port = NULL;
    struct IOSana2Req *io = NULL;
    struct BtcReq req;
    const char *op;
    int rc = RETURN_FAIL;
    BOOL open = FALSE;

    if (rd == NULL)
    {
        PutStr((CONST_STRPTR)"btc=fail reason=args\n");
        return RETURN_FAIL;
    }
    for (i = 0; i < sizeof(req); i++)
        ((UBYTE *)&req)[i] = 0;
    if (same((CONST_STRPTR)args[0], "get"))
        req.br_Op = BTC_OP_GET, op = "get";
    else if (same((CONST_STRPTR)args[0], "set") && args[2])
        req.br_Op = BTC_OP_SET, op = "set", req.br_Value = *(ULONG *)args[2];
    else
    {
        PutStr((CONST_STRPTR)"btc=fail reason=args\n");
        goto out;
    }
    for (i = 0; i < BTC_NAME_MAX - 1 && ((CONST_STRPTR)args[1])[i]; i++)
        req.br_Name[i] = ((CONST_STRPTR)args[1])[i];
    if (((CONST_STRPTR)args[1])[i])
    {
        PutStr((CONST_STRPTR)"btc=fail reason=name_too_long\n");
        goto out;
    }
    if (args[3])
        dev = (CONST_STRPTR)args[3];
    if (args[4])
        unit = *(ULONG *)args[4];

    port = CreateMsgPort();
    if (port)
        io = (struct IOSana2Req *)CreateIORequest(port, sizeof(struct IOSana2Req));
    if (io == NULL)
    {
        PutStr((CONST_STRPTR)"btc=fail reason=memory\n");
        goto out;
    }
    io->ios2_BufferManagement = NULL;
    if (OpenDevice(dev, unit, (struct IORequest *)io, 0) != 0)
    {
        Printf((CONST_STRPTR)"btc=fail reason=open error=%ld\n", (LONG)io->ios2_Req.io_Error);
        goto out;
    }
    open = TRUE;

    io->ios2_Req.io_Command = WIFIPI_CMD_BTC;
    io->ios2_Data = &req;
    io->ios2_DataLength = sizeof(req);
    if (DoIO((struct IORequest *)io) != 0)
    {
        Printf((CONST_STRPTR)"btc=refused op=%s name=%s error=%ld\n", op, req.br_Name, (LONG)io->ios2_Req.io_Error);
        rc = RETURN_ERROR;
    }
    else if (req.br_Rc == 0)
    {
        Printf((CONST_STRPTR)"btc=ok op=%s name=%s value=%lu\n", op, req.br_Name, req.br_Value);
        rc = RETURN_OK;
    }
    else if ((ULONG)req.br_Rc >= 0x7fff0001UL && (ULONG)req.br_Rc <= 0x7fff0004UL)
    {
        /* PACKET_CTRL_TIMEOUT / NORES / SHORT / TOOBIG: no firmware answer */
        Printf((CONST_STRPTR)"btc=fail reason=ctrl op=%s name=%s rc=0x%08lx\n", op, req.br_Name, (ULONG)req.br_Rc);
        rc = RETURN_FAIL;
    }
    else
    {
        Printf((CONST_STRPTR)"btc=fwerror op=%s name=%s rc=%ld\n", op, req.br_Name, req.br_Rc);
        rc = RETURN_WARN;
    }

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

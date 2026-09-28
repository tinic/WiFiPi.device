/*
 * fwinfo: the boot-time firmware record of a debug driver (AmiNetXDuo #89):
 * directory, firmware size and CRC-32, clmload chunks and clmload_status,
 * 'ver'.  Only a driver built with -DWIFIPI_FWINFO answers.
 *
 *   fwinfo DEVICE/K,UNIT/K/N
 *
 * key=value lines; RC 0 read, 10 the driver refused, 20 failed.
 */
#include <exec/types.h>
#include <exec/io.h>
#include <dos/dos.h>
#include <devices/sana2.h>
#include <proto/exec.h>
#include <proto/dos.h>

#include "../src/fwinfo.h"

#define TEMPLATE "DEVICE/K,UNIT/K/N"

static const char ver[] __attribute__((used)) = "$VER: fwinfo 1.0 (28.9.2026)";

static const char *clm_meaning(const struct FwInfo *fi)
{
    if (!(fi->fi_Flags & FWI_F_CLMSTATUS))
        return "not_asked";
    if (fi->fi_ClmStatusRc != 0)
        return "get_failed";
    if (fi->fi_ClmStatus == 0)
        return "zero";
    if (fi->fi_ClmStatus == FWI_CHIPID_MISMATCH)
        return "chipid_mismatch";
    return "undocumented";
}

int main(void)
{
    LONG args[2] = { 0, 0 };
    struct RDArgs *rd = ReadArgs((CONST_STRPTR)TEMPLATE, args, NULL);
    CONST_STRPTR dev = (CONST_STRPTR)"anxwifipi.device";
    ULONG unit = 0, i;
    struct MsgPort *port = NULL;
    struct IOSana2Req *io = NULL;
    static struct FwInfo fi;
    int rc = RETURN_FAIL;
    BOOL open = FALSE;

    if (rd == NULL)
    {
        PutStr((CONST_STRPTR)"fwinfo=fail reason=args\n");
        return RETURN_FAIL;
    }
    if (args[0])
        dev = (CONST_STRPTR)args[0];
    if (args[1])
        unit = *(ULONG *)args[1];

    port = CreateMsgPort();
    if (port)
        io = (struct IOSana2Req *)CreateIORequest(port, sizeof(struct IOSana2Req));
    if (io == NULL)
    {
        PutStr((CONST_STRPTR)"fwinfo=fail reason=memory\n");
        goto out;
    }
    io->ios2_BufferManagement = NULL;
    if (OpenDevice(dev, unit, (struct IORequest *)io, 0) != 0)
    {
        Printf((CONST_STRPTR)"fwinfo=fail reason=open error=%ld\n", (LONG)io->ios2_Req.io_Error);
        goto out;
    }
    open = TRUE;

    for (i = 0; i < sizeof(fi); i++)
        ((UBYTE *)&fi)[i] = 0;
    io->ios2_Req.io_Command = WIFIPI_CMD_FWINFO;
    io->ios2_Data = &fi;
    io->ios2_DataLength = sizeof(fi);
    if (DoIO((struct IORequest *)io) != 0)
    {
        Printf((CONST_STRPTR)"fwinfo=refused error=%ld\n", (LONG)io->ios2_Req.io_Error);
        rc = RETURN_ERROR;
        goto out;
    }
    if (fi.fi_Magic != FWI_MAGIC || fi.fi_Version != FWI_VERSION || fi.fi_Size != sizeof(fi))
    {
        Printf((CONST_STRPTR)"fwinfo=fail reason=layout magic=0x%08lx version=%lu size=%lu\n",
               fi.fi_Magic, (ULONG)fi.fi_Version, (ULONG)fi.fi_Size);
        goto out;
    }
    fi.fi_Dir[FWI_DIR_MAX - 1] = 0;
    fi.fi_Ver[FWI_VER_MAX - 1] = 0;
    Printf((CONST_STRPTR)"fwinfo=ok flags=0x%02lx dir=%s altdir=%ld loaded=%ld\n", fi.fi_Flags, fi.fi_Dir,
           (LONG)((fi.fi_Flags & FWI_F_ALTDIR) != 0), (LONG)((fi.fi_Flags & FWI_F_LOADED) != 0));
    Printf((CONST_STRPTR)"fw_size=%lu fw_crc32=0x%08lx\n", fi.fi_FwSize, fi.fi_FwCrc32);
    Printf((CONST_STRPTR)"clm_size=%lu clm_uploads=%lu clm_chunks=%lu clm_first_err=%ld clm_first_err_chunk=%ld\n",
           fi.fi_ClmSize, fi.fi_ClmUploads, fi.fi_ClmChunks, (LONG)fi.fi_ClmFirstErr,
           fi.fi_ClmFirstErrChunk == FWI_NO_CHUNK ? -1L : (LONG)fi.fi_ClmFirstErrChunk);
    Printf((CONST_STRPTR)"clm_status=%lu clm_status_rc=%ld clm_status_meaning=%s\n", fi.fi_ClmStatus,
           fi.fi_ClmStatusRc, clm_meaning(&fi));
    Printf((CONST_STRPTR)"ver_rc=%ld ver=%s\n", fi.fi_VerRc, fi.fi_Ver);
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

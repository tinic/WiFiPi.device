#include <exec/resident.h>
#include <exec/nodes.h>
#include <exec/devices.h>
#include <exec/errors.h>

#include <utility/tagitem.h>

#include <devices/timer.h>
#include <devices/sana2.h>
#include <devices/sana2specialstats.h>
#include <devices/newstyle.h>

#include <common/compiler.h>

#if defined(__INTELLISENSE__)
#include <clib/exec_protos.h>
#include <clib/utility_protos.h>
#else
#include <proto/exec.h>
#include <proto/utility.h>
#endif

#include <stdint.h>

#include "wifipi.h"
#include <aminetxduo/anxs2ext.h>

#define D(x) x

extern const char deviceEnd;
/*
 * The first bytes of the first code hunk: "moveq #-1,d0 / rts", so that a
 * device file typed at a Shell returns instead of running whatever function
 * the compiler placed first.  A C function is not enough under -flto -- the
 * link-time compiler orders functions as it likes and put putch() here; a
 * top-level asm from the first object on the link line stays put.  The link
 * names __start as the entry (-Wl,-e,__start) and tools/check-image.sh reads
 * the bytes.
 */
asm("    .text                   \n"
    "    .globl __start          \n"
    "__start:                    \n"
    "    moveq  #-1,%d0          \n"
    "    rts                     \n");

extern const char deviceName[];
extern const char deviceIdString[];
extern const uint32_t InitTable[];

const struct Resident RomTag __attribute__((used)) = {
    RTC_MATCHWORD,
    (struct Resident *)&RomTag,
    (APTR)&deviceEnd,
    RTF_AUTOINIT | RTF_AFTERDOS,
    WIFIPI_VERSION,
    NT_DEVICE,
    WIFIPI_PRIORITY,
    (APTR)deviceName,
    (APTR)deviceIdString,
    (APTR)InitTable,
};

/*
 * The name and the version string come from the build: WIFIPI_DEVICE_NAME
 * defaults to wifipi.device; a tree that carries this driver under another
 * name (AmiNetXDuo's anxwifipi.device) defines it, and may hand over its own
 * version header -- WIFIPI_VERSION_HEADER, whose TOOL_VERSTAG(name) makes the
 * $VER string -- instead of VERSION_STRING.
 */
#ifdef WIFIPI_VERSION_HEADER
#include WIFIPI_VERSION_HEADER
#define WIFIPI_VERSTRING TOOL_VERSTAG(WIFIPI_DEVICE_NAME)
#else
#define WIFIPI_VERSTRING VERSION_STRING
#endif
const char deviceName[] = WIFIPI_DEVICE_NAME;
const char deviceIdString[] = WIFIPI_VERSTRING;

static uint32_t WiFi_ExtFunc()
{
    return 0;
}

void _NewList(APTR listPTR)
{
    struct List *lh = listPTR;
    lh->lh_Head = (struct Node *)&(lh->lh_Tail);
    lh->lh_Tail = NULL;
    lh->lh_TailPred = (struct Node *)&(lh->lh_Head);
}

static BPTR WiFi_Expunge(REGARG(struct WiFiBase * WiFiBase, "a6"))
{
    struct ExecBase *SysBase = WiFiBase->w_SysBase;
    BPTR segList = 0;

    D(bug("[WiFi] WiFi_Expunge()\n"));

    /* If device's open count is 0, remove it from list and free memory */
    if (WiFiBase->w_Device.dd_Library.lib_OpenCnt == 0)
    {
        struct MsgPort *port = CreateMsgPort();
        struct timerequest *tr = CreateIORequest(port, sizeof(struct timerequest));

        UWORD negSize = WiFiBase->w_Device.dd_Library.lib_NegSize;
        UWORD posSize = WiFiBase->w_Device.dd_Library.lib_PosSize;

        if (tr != NULL && port != NULL)
        {
            OpenDevice((CONST_STRPTR)"timer.device", UNIT_VBLANK, (struct IORequest *)tr, 0);
        }

        /* Stop tasks */
        D(bug("[WiFi] Killing receiver task\n"));
        Signal(WiFiBase->w_SDIO->s_ReceiverTask, SIGBREAKF_CTRL_C);
        D(bug("[WiFi] Killing unit task\n"));
        Signal(WiFiBase->w_Unit->wu_Task, SIGBREAKF_CTRL_C);

        /* Wait for unit and receiver tasks to finish */
        do {
            if (tr) {
                tr->tr_time.tv_micro = 250000;
                tr->tr_time.tv_secs = 0;
                tr->tr_node.io_Command = TR_ADDREQUEST;
                DoIO(&tr->tr_node);
            }
            D(bug("[WiFi] Receiver: %08lx, Unit: %08lx\n", (ULONG)WiFiBase->w_SDIO->s_ReceiverTask, (ULONG)WiFiBase->w_Unit->wu_Task));
        } while(WiFiBase->w_SDIO->s_ReceiverTask != 0 || WiFiBase->w_Unit->wu_Task != 0);

        CloseDevice(&tr->tr_node);
        DeleteIORequest(tr);
        DeleteMsgPort(port);

        D(bug("[WiFi] Both tasks finished\n"));

        if (WiFiBase->w_UtilityBase != NULL)
        {
            CloseLibrary(WiFiBase->w_UtilityBase);
        }
        if (WiFiBase->w_DosBase != NULL)
        {
            CloseLibrary(WiFiBase->w_DosBase);
        }

        /* Return SegList so that DOS can unload the binary */
        segList = WiFiBase->w_SegList;

        Disable();
        /* Remove device node */
        Remove(&WiFiBase->w_Device.dd_Library.lib_Node);
        Enable();

        /* Free memory */
        DeletePool(WiFiBase->w_MemPool);
        FreeMem((APTR)((ULONG)WiFiBase - negSize), negSize + posSize);
    }
    else
    {
        WiFiBase->w_Device.dd_Library.lib_Flags |= LIBF_DELEXP;
    }

    D(bug("[WiFi] WiFi_Expunge() returns %08lx\n", segList));

    return segList;
}

void WiFi_Open(REGARG(struct IOSana2Req * io, "a1"), REGARG(LONG unitNumber, "d0"), REGARG(ULONG flags, "d1"))
{
    struct WiFiBase *WiFiBase = (struct WiFiBase *)io->ios2_Req.io_Device;
    struct ExecBase *SysBase = WiFiBase->w_SysBase;
    struct Library *UtilityBase = WiFiBase->w_UtilityBase;

    struct TagItem *tags;
    struct WiFiUnit *unit = WiFiBase->w_Unit;
    struct Opener *opener;
    BYTE error=0;

    D(bug("[WiFi] WiFi_Open(%08lx, %ld, %lx)\n", (ULONG)io, unitNumber, flags));

    if (unitNumber != 0)
    {
        error = IOERR_OPENFAIL;
    }
    
    if (io->ios2_Req.io_Message.mn_Length < sizeof(struct IOSana2Req))
    {
        D(bug("[WiFi] Opening device with ordinary IORequest. Allowing limited mode only\n"));
        if (io->ios2_Req.io_Message.mn_Length < sizeof(struct IOStdReq))
        {
            /* Message smaller than regular IORequest? Too bad, break now. */
            error = IOERR_OPENFAIL;
        }
        else
        {
            /* Small IOReqest, only NSCMD command will be allowed. Check sharing now */
            if (unit->wu_Unit.unit_OpenCnt != 0 && 
            ((unit->wu_Flags & IFF_SHARED) == 0 || (flags & SANA2OPF_MINE) != 0))
            {
                error = IOERR_UNITBUSY;
            }
            else
            {
                WiFiBase->w_Device.dd_Library.lib_Flags &= ~LIBF_DELEXP;
                WiFiBase->w_Device.dd_Library.lib_OpenCnt++;
                unit->wu_Unit.unit_OpenCnt++;
                io->ios2_Req.io_Error = 0;
                return;
            }
        }
    }

    io->ios2_Req.io_Unit = NULL;
    tags = io->ios2_BufferManagement;
    io->ios2_BufferManagement = NULL;

    /* Device sharing */
    if (error == 0)
    {
        if (unit->wu_Unit.unit_OpenCnt != 0 && 
            ((unit->wu_Flags & IFF_SHARED) == 0 || (flags & SANA2OPF_MINE) != 0))
        {
            error = IOERR_UNITBUSY;
        }
    }    

    /* Set flags, alloc opener */
    if (error == 0)
    {
        opener = AllocMem(sizeof(struct Opener), MEMF_PUBLIC | MEMF_CLEAR);
        io->ios2_BufferManagement = opener;

        if (opener != NULL)
        {
            if ((flags & SANA2OPF_MINE) == 0)
                unit->wu_Flags |= IFF_SHARED;
            if ((flags & SANA2OPB_PROM) != 0)
                unit->wu_Flags |= IFF_PROMISC;
        }
        else
        {
            error = IOERR_OPENFAIL;
        }
    }

    /* No errors so far, increase open counters, handle buffer management etc */
    if (error == 0)
    {
        WiFiBase->w_Device.dd_Library.lib_Flags &= ~LIBF_DELEXP;
        WiFiBase->w_Device.dd_Library.lib_OpenCnt++;
        unit->wu_Unit.unit_OpenCnt++;

        io->ios2_Req.io_Unit = &unit->wu_Unit;

        _NewList(&opener->o_ReadPort.mp_MsgList);
        opener->o_ReadPort.mp_Flags = PA_IGNORE;

        _NewList(&opener->o_OrphanListeners.mp_MsgList);
        opener->o_OrphanListeners.mp_Flags = PA_IGNORE;

        _NewList(&opener->o_EventListeners.mp_MsgList);
        opener->o_EventListeners.mp_Flags = PA_IGNORE;

        opener->o_RXFunc = (APTR)GetTagData(S2_CopyToBuff, (ULONG)opener->o_RXFunc, tags);
        opener->o_TXFunc = (APTR)GetTagData(S2_CopyFromBuff, (ULONG)opener->o_TXFunc, tags);
/*
        opener->o_TXFuncDMA = (APTR)GetTagData(S2_DMACopyFromBuff32, 0, tags);
        opener->o_RXFuncDMA = (APTR)GetTagData(S2_DMACopyToBuff32, 0, tags);
*/
        opener->o_FilterHook = (APTR)GetTagData(S2_PacketFilter, 0, tags);

        /*
         * AmiNetXDuo's private receive tags.  The direct pair is taken as
         * offered; RX_LINK_HDR and RX_FLAGS point at a BOOL and a UBYTE the
         * opener reads back to learn what was agreed: LINK_HDR set TRUE,
         * FLAGS replaced by the intersection with what this device does
         * (SUMMED always, VERIFIED on request, never CONTINUES).  TX_CSUM is
         * left alone -- the frame is pulled by S2_CopyFromBuff, there is no
         * pass to sum it in -- and the opener reads ASKED back.
         */
        opener->o_RxDirect = (APTR)GetTagData(ANXD_S2_RX_DIRECT, 0, tags);
        opener->o_RxFilled = (APTR)GetTagData(ANXD_S2_RX_FILLED, 0, tags);
        if (opener->o_RxDirect != NULL && opener->o_RxFilled != NULL)
        {
            BOOL *linkHdr = (BOOL *)GetTagData(ANXD_S2_RX_LINK_HDR, 0, tags);
            UBYTE *flags = (UBYTE *)GetTagData(ANXD_S2_RX_FLAGS, 0, tags);

            if (linkHdr != NULL)
            {
                *linkHdr = TRUE;
                opener->o_RxLinkHdr = TRUE;
            }
            if (flags != NULL)
            {
                UBYTE want = *flags ? *flags : (UBYTE)(ANXD_S2_RXF_SUMMED | ANXD_S2_RXF_VERIFIED);
                opener->o_RxFlags = (UBYTE)(want & ANXD_S2_RXF_VERIFIED);
                *flags = (UBYTE)(ANXD_S2_RXF_SUMMED | opener->o_RxFlags);
            }
        }
        else
        {
            opener->o_RxDirect = opener->o_RxFilled = NULL;
        }
        
        Disable();
        AddTail((APTR)&unit->wu_Openers, (APTR)opener);
        Enable();

        /* Start unit here? */
        if (!(unit->wu_Flags & IFF_STARTED))
        {
            StartUnit(unit);
        }
    }

    D(bug("[WiFi] WiFi_Open ends with status %ld\n", error));

    io->ios2_Req.io_Error = error;
}

ULONG WiFi_Close(REGARG(struct IOSana2Req * io, "a1"))
{
    struct WiFiBase *WiFiBase = (struct WiFiBase *)io->ios2_Req.io_Device;
    struct ExecBase *SysBase = WiFiBase->w_SysBase;
    struct WiFiUnit *u = (struct WiFiUnit *)io->ios2_Req.io_Unit;
    struct Opener *opener = io->ios2_BufferManagement;

    D(bug("[WiFi] WiFi_Close(%08lx)\n", (ULONG)io));

    /* DO most of things **only** if request is larger than IORequest */
    if (io->ios2_Req.io_Message.mn_Length >= sizeof(struct IOSana2Req))
    {
        /* Stop unit? */

        // ...

        if (opener)
        {
            Disable();
            Remove((struct Node *)opener);
            Enable();

            FreeMem(opener, sizeof(struct Opener));
        }
    }

    u->wu_Unit.unit_OpenCnt--;
    WiFiBase->w_Device.dd_Library.lib_OpenCnt--;

    if (WiFiBase->w_Device.dd_Library.lib_OpenCnt == 0)
    {
        if (WiFiBase->w_Device.dd_Library.lib_Flags & LIBF_DELEXP)
        {
            return WiFi_Expunge(WiFiBase);
        }
    }
    
    return 0;
}

void WiFi_BeginIO(REGARG(struct IOSana2Req * io, "a1"))
{
    struct WiFiBase *WiFiBase = (struct WiFiBase *)io->ios2_Req.io_Device;
    struct ExecBase *SysBase = WiFiBase->w_SysBase;
    struct WiFiUnit *unit = (struct WiFiUnit *)io->ios2_Req.io_Unit;

    // Try to do the request directly by obtaining the lock, otherwise put in unit's CMD queue
    if (AttemptSemaphore(&unit->wu_Lock))
    {
        HandleRequest(io);
        ReleaseSemaphore(&unit->wu_Lock);
    }
    else
    {
        /* Unit was busy, remove QUICK flag so that Exec will wait for completion properly */
        io->ios2_Req.io_Error = 0;
        io->ios2_Req.io_Flags &= ~IOF_QUICK;
        PutMsg(unit->wu_CmdQueue, (struct Message *)io);
    }
}

LONG WiFi_AbortIO(REGARG(struct IOSana2Req *io, "a1"))
{
    struct WiFiBase *WiFiBase = (struct WiFiBase *)io->ios2_Req.io_Device;
    struct ExecBase *SysBase = WiFiBase->w_SysBase;

    /* AbortIO is a *wish* call. Someone would like to abort current IORequest */
    if (io->ios2_Req.io_Unit != NULL)
    {
        Forbid();
        /* If the IO was not quick and is of type message (not handled yet or in process), abord it and remove from queue */
        if ((io->ios2_Req.io_Flags & IOF_QUICK) == 0 && io->ios2_Req.io_Message.mn_Node.ln_Type == NT_MESSAGE)
        {
            Remove(&io->ios2_Req.io_Message.mn_Node);
            io->ios2_Req.io_Error = IOERR_ABORTED;
            io->ios2_WireError = S2WERR_GENERIC_ERROR;
            ReplyMsg(&io->ios2_Req.io_Message);
        }
        Permit();
    }

    return 0;
}

static const uint32_t wifipi_functions[] = {
    (uint32_t)WiFi_Open,
    (uint32_t)WiFi_Close,
    (uint32_t)WiFi_Expunge,
    (uint32_t)WiFi_ExtFunc,
    (uint32_t)WiFi_BeginIO,
    (uint32_t)WiFi_AbortIO,
    -1
};

const uint32_t InitTable[4] = {
    sizeof(struct WiFiBase), 
    (uint32_t)wifipi_functions, 
    0, 
    (uint32_t)WiFi_Init
};

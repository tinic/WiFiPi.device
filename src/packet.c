#include <exec/types.h>
#include <exec/memory.h>
#include <exec/ports.h>
#include <exec/io.h>
#include <exec/alerts.h>
#include <devices/timer.h>
#include <devices/sana2wireless.h>

#if defined(__INTELLISENSE__)
#include <clib/exec_protos.h>
#include <clib/utility_protos.h>
#else
#include <proto/exec.h>
#include <proto/utility.h>
#endif

#include "d11.h"
#include "sdio.h"
#include "brcm.h"
#include "wifipi.h"
#include "packet.h"
#include "brcm_wifi.h"
#include <aminetxduo/anxs2ext.h>

#ifndef	PAD
#define	_PADLINE(line)	pad ## line
#define	_XSTR(line)	_PADLINE(line)
#define	PAD		_XSTR(__LINE__)
#endif

/*
 * brcmfmac sdio bus specific header
 * This is the lowest layer header wrapped on the packets transmitted between
 * host and WiFi dongle which contains information needed for SDIO core and
 * firmware
 *
 * It consists of 3 parts: hardware header, hardware extension header and
 * software header
 * hardware header (frame tag) - 4 bytes
 * Byte 0~1: Frame length
 * Byte 2~3: Checksum, bit-wise inverse of frame length
 * hardware extension header - 8 bytes
 * Tx glom mode only, N/A for Rx or normal Tx
 * Byte 0~1: Packet length excluding hw frame tag
 * Byte 2: Reserved
 * Byte 3: Frame flags, bit 0: last frame indication
 * Byte 4~5: Reserved
 * Byte 6~7: Tail padding length
 * software header - 8 bytes
 * Byte 0: Rx/Tx sequence number
 * Byte 1: 4 MSB Channel number, 4 LSB arbitrary flag
 * Byte 2: Length of next data frame, reserved for Tx
 * Byte 3: Data offset
 * Byte 4: Flow control bits, reserved for Tx
 * Byte 5: Maximum Sequence number allowed by firmware for Tx, N/A for Rx packet
 * Byte 6~7: Reserved
 */
#define SDPCM_HWHDR_LEN			4
#define SDPCM_HWEXT_LEN			8
#define SDPCM_SWHDR_LEN			8
#define SDPCM_HDRLEN			(SDPCM_HWHDR_LEN + SDPCM_SWHDR_LEN)
/* software header */
#define SDPCM_SEQ_MASK			0x000000ff
#define SDPCM_SEQ_WRAP			256
#define SDPCM_CHANNEL_MASK		0x00000f00
#define SDPCM_CHANNEL_SHIFT		8
#define SDPCM_CONTROL_CHANNEL	0	/* Control */
#define SDPCM_EVENT_CHANNEL		1	/* Asyc Event Indication */
#define SDPCM_DATA_CHANNEL		2	/* Data Xmit/Recv */
#define SDPCM_GLOM_CHANNEL		3	/* Coalesced packets */
#define SDPCM_TEST_CHANNEL		15	/* Test/debug packets */
#define SDPCM_GLOMDESC(p)		(((u8 *)p)[1] & 0x80)
#define SDPCM_NEXTLEN_MASK		0x00ff0000
#define SDPCM_NEXTLEN_SHIFT		16
#define SDPCM_DOFFSET_MASK		0xff000000
#define SDPCM_DOFFSET_SHIFT		24
#define SDPCM_FCMASK_MASK		0x000000ff
#define SDPCM_WINDOW_MASK		0x0000ff00
#define SDPCM_WINDOW_SHIFT		8

struct PacketHeaderHW {
    UWORD ph_Length;
    UWORD ph_ChkSum;
} __attribute__((packed));

struct GlomHeader {
    UWORD gh_Length;
    UBYTE gh_ReservedB;
    UBYTE gh_LastItem;
    UWORD gh_ReservedW;
    UWORD gh_TailPad;
} __attribute__((packed));

struct PacketHeaderSW {
    UBYTE c_Seq;
    UBYTE c_ChannelFlag;
    UBYTE c_NextLength;
    UBYTE c_DataOffset;
    UBYTE c_FlowControl;
    UBYTE c_MaxSeq;
    UBYTE c_Reserved[2];
} __attribute__((packed));

struct Packet {
    // Hardware header
    UWORD p_Length;
    UWORD c_ChkSum;
    // Software header
    UBYTE c_Seq;
    UBYTE c_ChannelFlag;
    UBYTE c_NextLength;
    UBYTE c_DataOffset;
    UBYTE c_FlowControl;
    UBYTE c_MaxSeq;
    UBYTE c_Reserved[2];
} __attribute__((packed));

#define BCDC_DCMD_ERROR		0x01		/* 1=cmd failed */
#define BCDC_DCMD_SET		0x02		/* 0=get, 1=set cmd */

struct PacketCmd {
    ULONG c_Command;
    ULONG c_Length;
    UWORD c_Flags;
    UWORD c_ID;
    ULONG c_Status;
} __attribute__((packed));

struct EtherHeader {
    UBYTE eh_Dest[6];
    UBYTE eh_Src[6];
    UWORD eh_Type;
} __attribute__((packed));

#define ETHERHDR_TYPE_LINK_CTL  0x886c

struct BCMEtherHeader {
    UWORD beh_Subtype;
    UWORD beh_Length;
    UBYTE beh_Version;
    UBYTE beh_OUI[3];
    UWORD beh_UsrSubtype;
} __attribute__((packed));

#define BCMETHHDR_OUI   "\0x00\0x10\0x18"
#define BCMETHHDR_SUBTYPE_EVENT 1

struct EtherAddr {
    UBYTE ea_Addr[6];
} __attribute__((packed));

struct PacketEvent {
    struct EtherHeader      e_EthHeader;
    struct BCMEtherHeader   e_Header;
    UWORD                   e_Version;
    UWORD                   e_Flags;
    ULONG                   e_EventType;
    ULONG                   e_Status;
    ULONG                   e_Reason;
    ULONG                   e_AuthType;
    ULONG                   e_DataLen;
    struct EtherAddr        e_Address;
    char                    e_IFName[16];
    UBYTE                   e_IFIdx;
    UBYTE                   e_BSSCFgIdx;
} __attribute__((packed));

struct BSSInfo {
    ULONG   bssi_Version;
    ULONG   bssi_Length;
    UBYTE   bssi_ID[6];
    UWORD   bssi_BeaconPeriod;
    UWORD   bssi_Capability;
    UBYTE   bssi_SSIDLength;
    UBYTE   bssi_SSID[32];
    UBYTE   PAD;
    ULONG   bssi_NRates;
    UBYTE   bssi_Rates[16];
    UWORD   bssi_ChanSpec;      // 72
    UWORD   bssi_ATimWindow;
    UBYTE   bssi_DTimPeriod;
    UBYTE   PAD;
    UWORD   bssi_RSSI;
    UBYTE   bssi_PHYNoise;
    UBYTE   bssi_NCap;
    UWORD   PAD;
    ULONG   bssi_NBSSCap;
    UBYTE   bssi_CtlCh;
    UBYTE   PAD[3];
    ULONG   bssi_Reserved32[1];
    UBYTE   bssi_Flags;
    UBYTE   bssi_Reserved[3];
    UBYTE   bssi_BasicMCS[16];
    UWORD   bssi_IEOffset;
    UWORD   PAD;
    ULONG   bssi_IELength;
    UWORD   bssi_SNR;
} __attribute__((packed));

struct EScanResult {
    ULONG   esr_Length;
    ULONG   esr_Version;
    UWORD   esr_SyncID;
    UWORD   esr_BSSCount;
    struct BSSInfo esr_BSSInfo[];
} __attribute__((packed));

struct PacketMessage {
    struct Message  pm_Message;
    APTR            pm_RecvBuffer;
    ULONG           pm_RecvSize;
    APTR            pm_PacketData;
    ULONG           pm_AllocSize;   // the whole block, for whoever frees it
    ULONG           pm_Copied;      // bytes of the reply copied to pm_RecvBuffer
    UBYTE           pm_Abandoned;   // the caller gave up: the receiver frees the block (#93)
    UBYTE           pm_SeqOff;      // c_Seq's offset in the packet: 4, or 12 when built glommed (#96)
    UBYTE           pm_Pad[2];
    struct Packet   pm_PacketHeader[];
};


#define D(x) x

#define VENDOR_SPECIFIC_IE  221
#define WLAN_EID_RSN 48



/*
static const UBYTE WPA_OUI_TYPE[] = {0x00, 0x50, 0xf2, 1};
static const UBYTE WPA_CIPHER_SUITE_NONE[] = {0x00, 0x50, 0xf2, 0};
static const UBYTE WPA_CIPHER_SUITE_WEP40[] = {0x00, 0x50, 0xf2, 1};
static const UBYTE WPA_CIPHER_SUITE_TKIP[] = {0x00, 0x50, 0xf2, 2};
static const UBYTE WPA_CIPHER_SUITE_CCMP[] = {0x00, 0x50, 0xf2, 4};
static const UBYTE WPA_CIPHER_SUITE_WEP104[] = {0x00, 0x50, 0xf2, 5};

static const UBYTE RSN_CIPHER_SUITE_NONE[] = {0x00, 0x0f, 0xac, 0};
static const UBYTE RSN_CIPHER_SUITE_WEP40[] = {0x00, 0x0f, 0xac, 1};
static const UBYTE RSN_CIPHER_SUITE_TKIP[] = {0x00, 0x0f, 0xac, 2};
static const UBYTE RSN_CIPHER_SUITE_CCMP[] = {0x00, 0x0f, 0xac, 4};
static const UBYTE RSN_CIPHER_SUITE_WEP104[] = {0x00, 0x0f, 0xac, 5};
*/



/* Traverse a string of 1-byte tag/1-byte length/variable-length value
 * triples, returning a pointer to the substring whose first element
 * matches tag
 */
struct TLV * brcmf_parse_tlvs(void *buf, ULONG buflen, UBYTE key)
{
    struct TLV *elt = buf;
    ULONG totlen = buflen;

    /* find tagged parameter */
    while (totlen >= TLV_HDR_LEN) {
        ULONG len = elt->len;

        /* validate remaining totlen */
        if ((elt->id == key) && (totlen >= (len + TLV_HDR_LEN)))
            return elt;

        elt = (struct TLV*)((UBYTE *)elt + (len + TLV_HDR_LEN));
        totlen -= (len + TLV_HDR_LEN);
    }

    return NULL;
}

int my_memcmp(const UBYTE *s1, const UBYTE *s2, ULONG len)
{
    for (ULONG i=0; i < len; i++)
    {
        if (s1[i] > s2[i]) return 1;
        else if (s1[i] < s2[i]) return -1;
    }
    return 0;
}

static int brcmf_tlv_has_ie(UBYTE *ie, UBYTE **tlvs, ULONG *tlvs_len,
		 const UBYTE *oui, ULONG oui_len, UBYTE type)
{
    /* If the contents match the OUI and the type */
    if (ie[TLV_LEN_OFF] >= oui_len + 1 &&
        !my_memcmp(&ie[TLV_BODY_OFF], oui, oui_len) &&
        type == ie[TLV_BODY_OFF + oui_len]) {
        return TRUE;
    }

    if (tlvs == NULL)
        return FALSE;

    /* point to the next ie */
    ie += ie[TLV_LEN_OFF] + TLV_HDR_LEN;
    /* calculate the length of the rest of the buffer */
    *tlvs_len -= (int)(ie - *tlvs);
    /* update the pointer to the start of the buffer */
    *tlvs = ie;

    return FALSE;
}

struct VsTLV * FindWPAIE(UBYTE *data, ULONG len)
{
    const struct TLV *ie;

    while ((ie = brcmf_parse_tlvs(data, len, VENDOR_SPECIFIC_IE)))
    {
        if (brcmf_tlv_has_ie((UBYTE *)ie, &data, &len,
                        WPA_OUI, TLV_OUI_LEN, WPA_OUI_TYPE))
            return (struct VsTLV *)ie;
    }
    return NULL;
}

#define WPA_VERSION_1   1
#define WPA_VERSION_2   2
#define WPA_VERSION_3   4

int SetWPAVersion(struct SDIO *sdio, struct WiFiNetwork *network, ULONG wpa_versions)
{
    ULONG val = 0;
    (void)network;
    (void)wpa_versions;

    if (wpa_versions & WPA_VERSION_1)
        val = WPA_AUTH_PSK | WPA_AUTH_UNSPECIFIED;
    else if (wpa_versions & WPA_VERSION_2)
        val = WPA2_AUTH_PSK | WPA2_AUTH_UNSPECIFIED;
    else if (wpa_versions & WPA_VERSION_3)
        val = WPA3_AUTH_SAE_PSK;
    else
        val = WPA_AUTH_DISABLED;

    return PacketSetVarInt(sdio, "wpa_auth", val);
}

#define SCANNER_STACKSIZE       (16384 / sizeof(ULONG))
#define SCANNER_PRIORITY         0


#define PACKET_RECV_STACKSIZE   (65536 / sizeof(ULONG))
#define PACKET_RECV_PRIORITY    5

/* The poller: lowest priority, a small stack, and how long it keeps looking
   after the last frame before it goes back to sleep */
#define POLL_STACKSIZE          (8192 / sizeof(ULONG))
#define POLL_PRIORITY           -128
#define POLL_GRACE_US           10000
/* A write queued while the poller watches goes out this long after it was
   queued -- long enough for the stack's burst of writes to become one glom,
   not the up-to-a-tick a lone reply used to wait */
#define POLL_WRITE_US           200

#define PACKET_WAIT_DELAY_MIN   2000
/*
 * The idle back-off used to reach 100 ms, and the first frame after a quiet
 * second waited for it: ping at 1 s intervals averaged 51 ms (max 169) against
 * 6.9 ms at 20 ms intervals, A1200 + PiStorm32 Lite, 2026-09-18.  A look costs
 * ~45 us (a 16-byte header read and the timer interrupt); 2 ms is 500 looks a
 * second when idle, 2% of the CPU, and at most 2 ms on the first frame.
 */
#define PACKET_WAIT_DELAY_MAX   10000
/*
 * A tick is not 45 us on Emu68.  Measured on an A1200 + PiStorm32 Lite,
 * sampled at 1 kHz (2026-09-19): 155-220 us a tick WHICHEVER timer.device
 * unit fires it -- about 40% inside timer.device, 22% in Exec's wake and
 * dispatch, 20% the driver's own look (a 16-byte header read), the rest
 * whatever interrupt server runs meanwhile.  Every Disable/Enable and every
 * interrupt entry is a trap into Emu68 at some 5 us, and a tick is a dozen
 * of them; the CIA is not the cost, the round trip is.  So the count is
 * what is spent: 500 ticks a second was 9.8% of the machine with nothing
 * on the air, and the 2 s of fast ticks after every exchange still showed
 * as 6% blips.
 *
 * Three ticks.  A frame in or out, or a write waiting for TX credit, is
 * followed by PACKET_WAIT_DELAY_MIN ticks (2 ms, five of them: TX credits
 * ride the header of the next frame read, and a 10 ms tick between reads
 * halved TX); while an exchange is recent (PACKET_QUIET_US) a MICROHZ tick
 * of PACKET_WAIT_DELAY_MAX, 100 a second, ~2% for that second and up to
 * 10 ms on the first frame after the poller's 10 ms watch; after that a
 * VBLANK tick of PACKET_WAIT_DELAY_IDLE, which rides the vertical-blank
 * interrupt the machine takes anyway, up to 20 ms on the first frame of
 * the next exchange, 0.7% of the machine.  Broadcast and multicast from
 * the rest of the LAN (ARP, mDNS, a frame or two a second here) is not an
 * exchange, or an idle LAN would never let the tick rest.
 */
#define PACKET_WAIT_DELAY_IDLE  20000
#define PACKET_QUIET_US         1000000

#define PACKET_INITIAL_FETCH_SIZE   16

void PacketDump(struct SDIO *sdio, APTR data, char *src);

struct TagItem * FindNetwork(struct WiFiUnit *unit, struct BSSInfo *info)
{
    struct WiFiBase *WiFiBase = unit->wu_Base;
    struct SDIO *sdio = WiFiBase->w_SDIO;
    struct Library *UtilityBase = WiFiBase->w_UtilityBase;
    struct IOSana2Req *io = unit->wu_ScanRequest;
    struct TagItem *found = NULL;
    struct TagItem **list = (struct TagItem **)io->ios2_StatData;
    
    if (list != NULL)
    {
        for (ULONG i=0; i < io->ios2_DataLength; i++)
        {
            struct TagItem *tags = list[i];
            UBYTE *bssid;
            UBYTE *ssid;
            /*
                Two networks are considered the same if:
                - SSID is same
                - BSSID is same
                - Channel and band are the same
            */

            /* Check SSID */
            ssid = (UBYTE*)GetTagData(S2INFO_SSID, 0, tags);
            
            /* Must not be null! */
            if (ssid == NULL)
                continue;

            /* SSID length must match */
            if (_strlen(ssid) != info->bssi_SSIDLength)
                continue;

            /* SSID must match */
            if (_strncmp(ssid, info->bssi_SSID, info->bssi_SSIDLength) != 0)
                continue;

            /* Check BSSID */
            bssid = (UBYTE*)GetTagData(S2INFO_BSSID, 0, tags);

            /* Must not be null */
            if (bssid == NULL)
                continue;
            
            /* Must be the same */
            if (bssid[0] != info->bssi_ID[0] ||
                bssid[1] != info->bssi_ID[1] ||
                bssid[2] != info->bssi_ID[2] ||
                bssid[3] != info->bssi_ID[3] ||
                bssid[4] != info->bssi_ID[4] ||
                bssid[5] != info->bssi_ID[5])
                continue;
            
            /* Finally, check channel */
            struct ChannelInfo ci;
            ci.ci_CHSpec = LE16(info->bssi_ChanSpec);
            DecodeChanSpec(&ci, sdio->s_Chip->c_D11Type);

            ULONG band = GetTagData(S2INFO_Band, -1, tags);
            if ((ci.ci_Band == BRCMU_CHAN_BAND_2G && band != S2BAND_B) ||
                (ci.ci_Band != BRCMU_CHAN_BAND_2G && band != S2BAND_A))
                continue;

            ULONG channel = GetTagData(S2INFO_Channel, 0, tags);
            if (channel != ci.ci_CHNum)
                continue;

            found = tags;
            break;
        }
    }

    return found;
}

void UpdateNetwork(struct WiFiUnit *unit, struct BSSInfo *info)
{
    struct WiFiBase *WiFiBase = unit->wu_Base;
    struct SDIO *sdio = WiFiBase->w_SDIO;
    struct ExecBase *SysBase = WiFiBase->w_SysBase;
    struct IOSana2Req *io = unit->wu_ScanRequest;
    struct TagItem *net;

    /* Ignore event if no scan request is active */
    if (io == NULL)
    {
        return;
    }

    /* Ignore network duplicates, later maybe update them */
    if ((net = FindNetwork(unit, info)))
    {
        return;
    }

    /* Ignore networks with empty ssid */
    if (info->bssi_SSIDLength == 0)
        return;

    APTR memPool = io->ios2_Data;
    struct TagItem **networks = NULL;
    struct TagItem *tags;

    /* Increase tag list counter */
    io->ios2_DataLength++;

    /* Get memory for tag list's list */
    networks = AllocVecPooled(memPool, 4 * io->ios2_DataLength);
    if (networks == NULL)
    {
        io->ios2_WireError = S2WERR_BUFF_ERROR;
        io->ios2_Req.io_Error = S2ERR_NO_RESOURCES;
        unit->wu_ScanRequest = NULL;
        ReplyMsg((struct Message *)io);
        return;
    }

    /* 
        If StatData is not null, copy it now and free. After copy networks[1..] will contain
        previous data, current network can be stored at networks[0]
    */
    if (io->ios2_StatData != NULL)
    {
        struct TagItem **src = io->ios2_StatData;
        for (ULONG i=0; i < io->ios2_DataLength - 1; i++)
        {
            networks[i+1] = src[i];
        }
        /* Get rid of old taglist */
        FreeVecPooled(memPool, src);
    }

    io->ios2_StatData = networks;
    
    /* Get memory for TagList, maximal number is number of S2INFO_TAGS plus one */
    tags = AllocPooled(memPool, sizeof(struct TagItem) * 16);
    
    if (tags == NULL)
    {
        io->ios2_WireError = S2WERR_BUFF_ERROR;
        io->ios2_Req.io_Error = S2ERR_NO_RESOURCES;
        unit->wu_ScanRequest = NULL;
        ReplyMsg((struct Message *)io);
        return;
    }

    /* Ignore all tags for now */
    for (int i=0; i < 15; i++) tags[i].ti_Tag = TAG_IGNORE;
    
    /* Finish with DONE tag*/
    tags[15].ti_Tag = TAG_DONE;
    tags[15].ti_Data = 0;

    /* Put the taglist in place */
    networks[0] = tags;

    /* All is prepared to fill the necessary info */
    tags->ti_Tag = S2INFO_SSID;
    tags->ti_Data = (ULONG)AllocPooledClear(memPool, info->bssi_SSIDLength + 1);
    if (tags->ti_Data == 0)
    {
        io->ios2_WireError = S2WERR_BUFF_ERROR;
        io->ios2_Req.io_Error = S2ERR_NO_RESOURCES;
        unit->wu_ScanRequest = NULL;
        ReplyMsg((struct Message *)io);
        return;
    }
    CopyMem(info->bssi_SSID, (APTR)tags->ti_Data, info->bssi_SSIDLength);
    tags++;

    tags->ti_Tag = S2INFO_BSSID;
    tags->ti_Data = (ULONG)AllocPooled(memPool, 6);
    if (tags->ti_Data == 0)
    {
        io->ios2_WireError = S2WERR_BUFF_ERROR;
        io->ios2_Req.io_Error = S2ERR_NO_RESOURCES;
        unit->wu_ScanRequest = NULL;
        ReplyMsg((struct Message *)io);
        return;
    }
    CopyMem(info->bssi_ID, (APTR)tags->ti_Data, 6);
    tags++;

    tags->ti_Tag = S2INFO_BeaconInterval;
    tags->ti_Data = LE16(info->bssi_BeaconPeriod);
    tags++;

    tags->ti_Tag = S2INFO_Signal;
    tags->ti_Data = (WORD)LE16(info->bssi_RSSI);
    tags++;

    if (info->bssi_PHYNoise != 0)
    {
        tags->ti_Tag = S2INFO_Noise;
        tags->ti_Data = (BYTE)info->bssi_PHYNoise;
        tags++;
    }

    if (info->bssi_IELength)
    {
        UWORD length = LE32(info->bssi_IELength);
        UWORD *data = AllocPooled(memPool, length + 2);
        if (data == NULL)
        {
            io->ios2_WireError = S2WERR_BUFF_ERROR;
            io->ios2_Req.io_Error = S2ERR_NO_RESOURCES;
            unit->wu_ScanRequest = NULL;
            ReplyMsg((struct Message *)io);
            return;
        }

        *data = length;
        CopyMem(&((UBYTE*)info)[LE16(info->bssi_IEOffset)], data + 1, length);
        
        tags->ti_Tag = S2INFO_InfoElements;
        tags->ti_Data = (ULONG)data;
        tags++;
    }

    tags->ti_Tag = S2INFO_Capabilities;
    tags->ti_Data = LE16(info->bssi_Capability);
    tags++;

    struct ChannelInfo ci;
    ci.ci_CHSpec = LE16(info->bssi_ChanSpec);
    DecodeChanSpec(&ci, sdio->s_Chip->c_D11Type);

    tags->ti_Tag = S2INFO_Channel;
    tags->ti_Data = ci.ci_CHNum;
    tags++;

    tags->ti_Tag = S2INFO_Band;
    tags->ti_Data = ci.ci_Band == BRCMU_CHAN_BAND_2G ? S2BAND_B : S2BAND_A;
    tags++;
}

void ProcessEvent(struct SDIO *sdio, struct PacketEvent *pe)
{
    struct WiFiBase *base = sdio->s_WiFiBase;
    struct WiFiUnit *unit = base->w_Unit;
    struct ExecBase *SysBase = base->w_SysBase;

    // pe is in network (BigEndian) order!
    // BUT! pe data is native (LittleEndian) order!
    switch (pe->e_EventType)
    {
        case BRCMF_E_ESCAN_RESULT:
        {
            struct EScanResult *escan = (APTR)((ULONG)pe + sizeof(struct PacketEvent));
            //D(bug("[WiFi] EScan result. Length %ld, BSS count %ld\n", LE32(escan->esr_Length), LE16(escan->esr_BSSCount)));
            
            if (escan->esr_BSSCount == LE16(0))
            {
                // Scan complete
                if (unit->wu_ScanRequest)
                {
                    ReplyMsg((struct Message *)unit->wu_ScanRequest);
                    unit->wu_ScanRequest = NULL;
                }
                //D(bug("[WiFi] EScan complete\n"));
            }

            for (int i=0; i < LE16(escan->esr_BSSCount); i++)
            {
                UpdateNetwork(unit, &escan->esr_BSSInfo[i]);
            }
            break;
        }

        case BRCMF_E_ASSOC:
            D(bug("[WiFi] E_ASSOC\n"));
            /* AllocVec, not w_MemPool: this is the receiver, outside wu_Lock (#94) */
            if (unit->wu_AssocIE) FreeVec(unit->wu_AssocIE);
            unit->wu_AssocIE = NULL;
            unit->wu_AssocIELength = pe->e_DataLen;
            if (unit->wu_AssocIELength)
            {
                unit->wu_AssocIE = AllocVec(pe->e_DataLen, MEMF_ANY);
                if (unit->wu_AssocIE != NULL)
                {
                    CopyMem(((UBYTE*)pe) + sizeof(struct PacketEvent), unit->wu_AssocIE, pe->e_DataLen);
                }
                else
                {
                    unit->wu_AssocIELength = 0;
                }
            }
            CopyMem(&pe->e_Address, unit->wu_JoinParams.ej_Assoc.ap_BSSID, 6);
            break;
        
        case BRCMF_E_AUTH:
            D(bug("[WiFi] E_AUTH "));
            if (pe->e_Status == 0) {
                D(bug("OK\n"));
            }
            else
            {
                D(bug("Failed with reason %08lx\n", pe->e_Reason));
            }
            break;

        case BRCMF_E_DISASSOC:
            D(bug("[WiFi] E_DISASSOC\n"));
            {
                UBYTE *p = (APTR)pe;
                for (ULONG i=0; i < sizeof(struct PacketEvent) + pe->e_DataLen; i++)
                {
                    if (i % 16 == 0)
                    bug("[WiFI]  ");
                    bug(" %02lx", p[i]);
                    if (i % 16 == 15)
                        bug("\n");
                }
                if ((sizeof(struct PacketEvent) + pe->e_DataLen) % 16)
                    bug("\n");
            }
            break;
        
        case BRCMF_E_REASSOC:
            D(bug("[WiFi] E_REASSOC\n"));
            {
                UBYTE *p = (APTR)pe;
                for (ULONG i=0; i < sizeof(struct PacketEvent) + pe->e_DataLen; i++)
                {
                    if (i % 16 == 0)
                    bug("[WiFI]  ");
                    bug(" %02lx", p[i]);
                    if (i % 16 == 15)
                        bug("\n");
                }
                if ((sizeof(struct PacketEvent) + pe->e_DataLen) % 16)
                    bug("\n");
            }
            break;

        case BRCMF_E_LINK:
            if (pe->e_Reason)
            {
                D(bug("[WiFi] E_LINK down\n"));
                unit->wu_Flags &= ~IFF_CONNECTED;
                ReportEvents(unit, S2EVENT_DISCONNECT);
            }
            else
            {
                D(bug("[WiFi] E_LINK up\n"));
                unit->wu_Flags |= IFF_CONNECTED;
                ReportEvents(unit, S2EVENT_CONNECT);
            }
            break;

        default:
            D(bug("[WiFi] Unhandled event type %ld, status %08lx, reason %08lx\n", pe->e_EventType, pe->e_Status, pe->e_Reason));
            UBYTE *p = (APTR)pe;
            for (ULONG i=0; i < sizeof(struct PacketEvent) + pe->e_DataLen; i++)
            {
                if (i % 16 == 0)
                bug("[WiFI]  ");
                bug(" %02lx", p[i]);
                if (i % 16 == 15)
                    bug("\n");
            }
            if ((sizeof(struct PacketEvent) + pe->e_DataLen) % 16)
                bug("\n");
            break;
    }
}

ULONG ProcessPacket(struct SDIO *sdio, struct Packet *pkt)
{
    UBYTE *buffer = (UBYTE*)pkt;

    UWORD pktLen = LE16(pkt->p_Length);
    UWORD pktChk = LE16(pkt->c_ChkSum);

    /* Both null size - empty packet */
    if (pktLen == 0 && pktChk == 0) return 0;

    /* Length and checksum not matching - error */
    if (pktLen != (~pktChk & 0xffff)) return 0xffffffff;

    /* Update max sequence number at transfer */
    sdio->s_MaxTXSeq = pkt->c_MaxSeq;

    switch(pkt->c_ChannelFlag)
    {
        case SDPCM_CONTROL_CHANNEL:
            /* A reply to one of our control requests (#93): matched, bounded
               and handed over in PacketCtrlComplete(). */
            PacketCtrlComplete(sdio, pkt, pktLen);
            break;

        case SDPCM_EVENT_CHANNEL:
        {
            struct PacketEvent *pe = (APTR)&buffer[pkt->c_DataOffset + 4];

            if ((ULONG)(pkt->p_Length - pkt->c_DataOffset) >= sizeof(struct PacketEvent))
            {
                if (pe->e_EthHeader.eh_Type == ETHERHDR_TYPE_LINK_CTL && 
                    pe->e_Header.beh_OUI[0] == 0x00 && 
                    pe->e_Header.beh_OUI[1] == 0x10 && 
                    pe->e_Header.beh_OUI[2] == 0x18)
                {
                    if (pe->e_Header.beh_UsrSubtype == BCMETHHDR_SUBTYPE_EVENT)
                    {
                        ProcessEvent(sdio, pe);
                    }
                }
            }
            break;
        }
        
        case SDPCM_DATA_CHANNEL:
        {
            UBYTE *frame = (APTR)&buffer[pkt->c_DataOffset + 4];
            ULONG frameLength = pktLen - pkt->c_DataOffset - 4;

            ProcessDataPacket(sdio, frame, frameLength);

            break;
        }
    }

    return pktLen;
}

int SendGlomDataPacket(struct SDIO *sdio, struct IOSana2Req **ioList, UBYTE count);

/*
 * THE POLLER.  On Emu68 every interrupt costs ~20 us of exception entry
 * and the WLAN host's line is not to be had anyway (it is the SD card's,
 * see sdio_int_attach); a timer tick sees a frame up to a millisecond late.
 * This task runs at the lowest priority -- it only ever gets the CPU when
 * nothing else wants it -- and looks at the card's line in the host's
 * status register, a 20 ns read.  The moment the line is up it signals the
 * receiver and waits; the receiver drains the card and signals it back, and
 * it looks again.  After POLL_GRACE_US without a frame it sleeps until the
 * receiver has seen traffic (a tick that found a frame or sent one).  The
 * timer tick stays: it is what wakes everything when the machine was idle.
 */
static inline ULONG PollClock(struct WiFiBase *WiFiBase)
{
    return rd32(WiFiBase->w_SysTimer, 4);       /* CLO, 1 MHz */
}

/*
 * TX credit (#99): how many frames the firmware's window still admits.  The
 * window end s_MaxTXSeq and the next number s_TXSeq are modulo 256; only a
 * forward distance of 1..127 is credit (brcmf_sdio data_ok: nonzero, high
 * bit clear).  0 is a closed window, and 128..255 means the next number is
 * already past the window's end -- a closed window too, not 128..255 frames
 * of credit.
 */
UBYTE PacketTxCredit(struct SDIO *sdio)
{
    UBYTE d = (UBYTE)(sdio->s_MaxTXSeq - sdio->s_TXSeq);
    return (d & 0x80) ? 0 : d;
}

static void PacketPoller(struct SDIO *sdio)
{
    struct ExecBase *SysBase = sdio->s_SysBase;
    struct WiFiBase *WiFiBase = sdio->s_WiFiBase;
    BYTE sig = AllocSignal(-1);
    ULONG got;

    if (sig < 0 || WiFiBase->w_SysTimer == NULL)
    {
        sdio->s_PollTask = NULL;
        if (sig >= 0)
            FreeSignal(sig);
        return;
    }
    sdio->s_PollWake = 1UL << sig;

    for (;;)
    {
        sdio->s_PollAsleep = TRUE;
        got = Wait(SIGBREAKF_CTRL_C | sdio->s_PollWake);
        sdio->s_PollAsleep = FALSE;
        if (got & SIGBREAKF_CTRL_C)
            break;

        ULONG since = PollClock(WiFiBase);
        ULONG queued = 0;       /* when the first waiting write was seen, 0 = none */
        for (;;)
        {
            BOOL send = FALSE;

            if (!IsMsgPortEmpty(sdio->s_SenderPort) && PacketTxCredit(sdio) != 0)
            {
                ULONG now = PollClock(WiFiBase);

                if (queued == 0)
                    queued = now ? now : 1;
                else if ((ULONG)(now - queued) >= POLL_WRITE_US)
                    send = TRUE;
            }
            else
                queued = 0;

            if (sdio_card_asserting(sdio) || send)
            {
                if (send)
                    sdio->s_StatPollSends++;
                queued = 0;
                sdio->s_StatPollHits++;
                /* asleep BEFORE the Signal: the receiver outranks this task
                   and may run to its PokePoller before the next line here */
                sdio->s_PollAsleep = TRUE;
                Signal(sdio->s_ReceiverTask, 1UL << sdio->s_PollSignal);
                got = Wait(SIGBREAKF_CTRL_C | sdio->s_PollWake);
                sdio->s_PollAsleep = FALSE;
                if (got & SIGBREAKF_CTRL_C)
                    goto out;
                since = PollClock(WiFiBase);
                continue;
            }
            if ((ULONG)(PollClock(WiFiBase) - since) > POLL_GRACE_US)
            {
                sdio->s_StatPollSleeps++;
                break;
            }
        }
    }
out:
    sdio->s_PollWake = 0;
    sdio->s_PollTask = NULL;
    /* the receiver waits for this before it frees the signal and goes */
    Signal(sdio->s_ReceiverTask, 1UL << sdio->s_PollSignal);
    FreeSignal(sig);
}

static void StartPoller(struct SDIO *sdio)
{
    struct ExecBase *SysBase = sdio->s_SysBase;
    struct Task *task = AllocMem(sizeof(struct Task), MEMF_PUBLIC | MEMF_CLEAR);
    struct MemList *ml = AllocMem(sizeof(struct MemList) + sizeof(struct MemEntry), MEMF_PUBLIC | MEMF_CLEAR);
    ULONG *stack = AllocMem(POLL_STACKSIZE * sizeof(ULONG), MEMF_PUBLIC | MEMF_CLEAR);
    static const char task_name[] = WIFIPI_TASK_POLLER;

    if (task == NULL || ml == NULL || stack == NULL)
    {
        if (task) FreeMem(task, sizeof(struct Task));
        if (ml) FreeMem(ml, sizeof(struct MemList) + sizeof(struct MemEntry));
        if (stack) FreeMem(stack, POLL_STACKSIZE * sizeof(ULONG));
        return;
    }

    ml->ml_NumEntries = 2;
    ml->ml_ME[0].me_Un.meu_Addr = task;
    ml->ml_ME[0].me_Length = sizeof(struct Task);
    ml->ml_ME[1].me_Un.meu_Addr = &stack[0];
    ml->ml_ME[1].me_Length = POLL_STACKSIZE * sizeof(ULONG);

    task->tc_UserData = sdio;
    task->tc_SPLower = &stack[0];
    task->tc_SPUpper = &stack[POLL_STACKSIZE];
    stack = (ULONG *)task->tc_SPUpper;
    *--stack = (ULONG)sdio;
    task->tc_SPReg = stack;
    task->tc_Node.ln_Name = (char *)task_name;
    task->tc_Node.ln_Type = NT_TASK;
    task->tc_Node.ln_Pri = POLL_PRIORITY;
    _NewList((struct MinList *)&task->tc_MemEntry);
    AddHead(&task->tc_MemEntry, &ml->ml_Node);

    sdio->s_PollTask = task;
    AddTask(task, (APTR)PacketPoller, NULL);
}

/* Wake the poller if it sleeps: one Signal() (an 11 us trap on Emu68) per
   burst, not per frame */
static inline void PokePoller(struct SDIO *sdio)
{
    struct ExecBase *SysBase = sdio->s_SysBase;

    if (sdio->s_PollTask != NULL && sdio->s_PollAsleep && sdio->s_PollWake != 0)
        Signal(sdio->s_PollTask, sdio->s_PollWake);
}

void PacketReceiver(struct SDIO *sdio, struct Task *caller)
{
    struct ExecBase *SysBase = sdio->s_SysBase;
    ULONG waitDelay = PACKET_WAIT_DELAY_MAX;
    struct MsgPort *ctrl = CreateMsgPort();
    struct MsgPort *sender = CreateMsgPort();
    struct WiFiBase *WiFiBase = sdio->s_WiFiBase;

    struct MinList ctrlWaitList;
    ULONG waitDelayTimeout = PACKET_WAIT_DELAY_MAX / waitDelay;

    _NewList(&ctrlWaitList);

    /*
     * Sender port is signal-free: writes wait for the next wake-up, and the
     * wake-up sends everything queued as one glom.  Measured 2026-09-18 on
     * an A1200 + PiStorm32 Lite, 5 GHz: waking on every write cost TX a
     * third (57 -> 39 Mbit/s, twice) and gave RX and ping nothing.
     */
    FreeSignal(sender->mp_SigBit);
    sender->mp_Flags = PA_IGNORE;

    D(bug("[WiFi.RECV] Packet receiver task\n"));
    D(bug("[WiFi.RECV] SDIO=%08lx, Caller task=%08lx\n", (ULONG)sdio, (ULONG)caller));

    if (ctrl == NULL)
    {
        D(bug("[WiFi.RECV] Failed to create command port\n"));
        return;
    }

    // Create MessagePort and timer.device IORequest
    struct MsgPort *port = CreateMsgPort();
    struct timerequest *tr = (struct timerequest *)CreateIORequest(port, sizeof(struct timerequest));

    if (port == NULL || tr == NULL)
    {
        D(bug("[WiFi.RECV] Failed to create IO Request\n"));
        if (port != NULL) DeleteMsgPort(port);
        Signal(caller, SIGBREAKF_CTRL_C);
        return;
    }

    if (OpenDevice((CONST_STRPTR)"timer.device", UNIT_MICROHZ, &tr->tr_node, 0))
    {
        D(bug("[WiFi.RECV] Failed to open timer.device\n"));
        DeleteIORequest(&tr->tr_node);
        DeleteMsgPort(port);
        Signal(caller, SIGBREAKF_CTRL_C);
        return;
    }

    /* The idle tick's request: the VBLANK unit, same port.  One of the two
       is outstanding at any time, `cur` says which. */
    struct timerequest *trv = (struct timerequest *)CreateIORequest(port, sizeof(struct timerequest));
    if (trv == NULL || OpenDevice((CONST_STRPTR)"timer.device", UNIT_VBLANK, &trv->tr_node, 0))
    {
        D(bug("[WiFi.RECV] Failed to open timer.device VBLANK\n"));
        if (trv != NULL) DeleteIORequest(&trv->tr_node);
        CloseDevice(&tr->tr_node);
        DeleteIORequest(&tr->tr_node);
        DeleteMsgPort(port);
        Signal(caller, SIGBREAKF_CTRL_C);
        return;
    }
    struct timerequest *cur = tr;

    // Set up receiver task pointer in SDIO
    sdio->s_ReceiverTask = FindTask(NULL);

    // Create message port used by receiver
    sdio->s_ReceiverPort = ctrl;
    sdio->s_SenderPort = sender;
    sdio->s_CtrlWaitList = &ctrlWaitList;

    /*
     * The card's interrupt line, when the tree names one and gic400.library
     * is there: a frame or a TX credit wakes this task at once instead of at
     * the next timer tick.  The tick stays as it was, as the fallback.
     */
    ULONG irqMask = 0;
    ULONG irqEmpty = 0;         // consecutive card interrupts that found no frame
    ULONG irqStorms = 0;        // consecutive ticks that found the line parked
    BOOL  irqParked = FALSE;    // line left masked until the next tick (storm breaker)
    ULONG pollMask = 0;
    ULONG pollEmpty = 0;        // consecutive poller wake-ups that found no frame
    BOOL  pollDead = FALSE;     // a line that stays up with nothing behind it: poller retired
    sdio_card_int_expose(sdio);
    sdio->s_IRQSignal = AllocSignal(-1);
    if (sdio->s_IRQSignal >= 0)
    {
        if (sdio_int_attach(sdio))
            irqMask = 1UL << sdio->s_IRQSignal;
        else
        {
            FreeSignal(sdio->s_IRQSignal);
            sdio->s_IRQSignal = -1;
        }
    }
    sdio->s_PollSignal = AllocSignal(-1);
    if (sdio->s_PollSignal >= 0)
    {
        pollMask = 1UL << sdio->s_PollSignal;
        StartPoller(sdio);
    }

    // Signal caller that we are done with setup
    Signal(caller, SIGBREAKF_CTRL_C);

    cur = (waitDelay >= PACKET_WAIT_DELAY_IDLE) ? trv : tr;
    cur->tr_node.io_Command = TR_ADDREQUEST;
    cur->tr_time.tv_sec = waitDelay / 1000000;
    cur->tr_time.tv_micro = waitDelay % 1000000;
    SendIO(&cur->tr_node);

    // Clear PACKET_INITIAL_FETCH_SIZE bytes of RX buffer
    UBYTE *buffer = sdio->s_RXBuffer;
    struct Packet *pkt = sdio->s_RXBuffer;

    for (int i=0; i < PACKET_INITIAL_FETCH_SIZE; i++) buffer[i] = 0;

    /* when this station last sent or was sent to; the tick slows after PACKET_QUIET_US */
    ULONG lastTraffic = WiFiBase->w_SysTimer ? PollClock(WiFiBase) : 0;

    // Loop forever
    while(1)
    {
        UBYTE gotTransfer = 0;
        UBYTE sendTransfer = 0;
        sdio->s_RxUnicast = 0;

        ULONG sigSet = Wait(SIGBREAKF_CTRL_C | 
                            (1 << port->mp_SigBit) |
                            (1 << ctrl->mp_SigBit) |
                            irqMask | pollMask);

        /* control requests whose callers gave up (#93) */
        PacketCtrlSweep(sdio);
       
        // Signal from control message port?
        if (sigSet & (1 << ctrl->mp_SigBit))
        {
            struct PacketMessage *msg;

            // Repeat until we run out of the messages
            while((msg = (struct PacketMessage *)GetMsg(ctrl)) != NULL)
            {
                // Onto the control wait list and out, unless its caller gave up
                PacketCtrlQueue(sdio, &msg->pm_Message);
                /* its answer is wanted at the fast tick, not the idle one */
                sendTransfer = TRUE;
            }
        }

        // Always check if there are data packets for sending
        if (TRUE)
        {
            struct IOSana2Req *ioList[32];
            struct IOSana2Req *msg;
            ULONG ioCount = 0;
            UBYTE maxCount;

            maxCount = PacketTxCredit(sdio);
            
            /* Make sure we have place in TX */
            if (maxCount == 0)
            {
                if (!IsMsgPortEmpty(sender))
                    sdio->s_StatTXStalls++;
            }
            else
            {
                // Drain outgoing packet requests
                while ((msg = (struct IOSana2Req *)GetMsg(sender)) != NULL)
                {
                    sendTransfer = TRUE;

                    // Put the packet into an array. It will be used later to construct Glom frame
                    ioList[ioCount++] = msg;
                    sdio->s_StatTXFrames++;

                    if (--maxCount == 0)
                    {
                        //D(bug("[WiFi] No more place in TX\n"));
                        break;
                    }

                    // Glom full? Push out large frame
                    // But not yet, for now just send them all out, one after another
                    if (ioCount == 32)
                    {
                        //D(bug("[WiFi] Glom frame would do, there are %ld entries in queue\n", ioCount));
                        /*
                        for (ULONG i=0; i < ioCount; i++)
                        {
                            SendDataPacket(sdio, ioList[i]);
                            ReplyMsg((struct Message *)ioList[i]);
                        }
                        */
                        SendGlomDataPacket(sdio, ioList, ioCount);
                        ioCount = 0;
                    }
                }

                // Any write requests left? Push them out now
                // One item only? Send it as one packet.
                #if 0
                 if (ioCount == 1)
                {
                    SendDataPacket(sdio, ioList[0]);
                    ReplyMsg((struct Message *)ioList[0]);
                }
                else 
                #endif
                if (ioCount)
                {
                    //D(bug("[WiFi] Glom frame would do, there are %ld entries in queue\n", ioCount));
                    // More items? Construct glom frame
                    SendGlomDataPacket(sdio, ioList, ioCount);
                    /*
                    for (ULONG i=0; i < ioCount; i++)
                    {
                        SendDataPacket(sdio, ioList[i]);
                        ReplyMsg((struct Message *)ioList[i]);
                    }
                    */
                }
            }
        }

        /* If no scan request is in progress start another one (if needed) */
        if (WiFiBase->w_Unit && WiFiBase->w_Unit->wu_ScanRequest == NULL)
        {
            struct IOSana2Req *io = (struct IOSana2Req *)GetMsg(WiFiBase->w_Unit->wu_ScanQueue);
            if (io)
            {
                StartNetworkScan(io);
            }
        }

        // Signal from timer.device, from the control message port or from the card?
        // All are great occasions to test if some data is pending
        if (sigSet & ((1 << port->mp_SigBit) | (1 << ctrl->mp_SigBit) | irqMask | pollMask))
        {
            BOOL timerEvent = (sigSet & (1 << port->mp_SigBit)) ? TRUE : FALSE;
            BOOL timerReady = FALSE;

            if (sigSet & (1 << ctrl->mp_SigBit))
            {
                /* A control request wants its answer looked for now, so take
                   the timer back first.  This wake need not also carry the
                   timer signal: in that ordinary case the old code aborted
                   the only fallback poll and never submitted another one.
                   A board without a usable interrupt/poller then stopped
                   receiving after its first firmware command. */
                if (!timerEvent)
                {
                    AbortIO(&cur->tr_node);
                    WaitIO(&cur->tr_node);
                    timerReady = TRUE;
                }
            }

            /*
             * The card's interrupt status is sticky and, once its interrupts
             * are enabled, the firmware expects it serviced -- with the line
             * up and nobody clearing it TX credits came back late and TX
             * halved (57 -> 25 Mbit/s, 2026-09-18).  Clear it whenever the
             * line is up, whatever woke us, and BEFORE the frames are read,
             * so a frame that lands after the last read sets it again.
             */
            if (sdio_card_asserting(sdio))
                sdio_service_card(sdio);

            sdio->RecvPKT(buffer, PACKET_INITIAL_FETCH_SIZE, sdio);

            /* Update gotTransfer flag if it wasn't set already */
            gotTransfer = LE16(pkt->p_Length) != 0;
            sdio->s_StatWakes++;
            if (!gotTransfer)
                sdio->s_StatEmpty++;

            if (timerEvent)
            {
                // Check if IO really completed. If yes, remove it from the queue
                if (CheckIO(&cur->tr_node))
                {
                    WaitIO(&cur->tr_node);
                    timerReady = TRUE;
                }
            }

            /* A completed tick and a timer deliberately aborted for a
               control request both need a successor.  Only a stale port
               signal with the request still active leaves timerReady false. */
            if (timerReady)
            {
                /* A frame in or out, or a write still waiting for TX credit:
                   the 2 ms tick for the next few ticks -- credits come back in
                   the header of the next frame read, and a 10 ms tick between
                   reads halved TX (61 -> 29 Mbit/s, 2026-09-19). */
                if (gotTransfer || sendTransfer || !IsMsgPortEmpty(sender))
                {
                    waitDelay = PACKET_WAIT_DELAY_MIN;
                    waitDelayTimeout = PACKET_WAIT_DELAY_MAX / PACKET_WAIT_DELAY_MIN;
                }
                else if (WiFiBase->w_SysTimer != NULL &&
                         (ULONG)(PollClock(WiFiBase) - lastTraffic) > PACKET_QUIET_US)
                {
                    waitDelay = PACKET_WAIT_DELAY_IDLE;
                    waitDelayTimeout = 1;
                }
                else if (waitDelay > PACKET_WAIT_DELAY_MAX)
                {
                    /* traffic came back under the poller: the fast tick again */
                    waitDelay = PACKET_WAIT_DELAY_MAX;
                    waitDelayTimeout = 1;
                }
                else
                {
                    if (waitDelayTimeout)
                    {
                        waitDelayTimeout--;
                    } 
                    else if (waitDelay < PACKET_WAIT_DELAY_MAX)
                    {
                        waitDelay <<= 2;
                        if (waitDelay > PACKET_WAIT_DELAY_MAX) waitDelay = PACKET_WAIT_DELAY_MAX;
                        waitDelayTimeout = PACKET_WAIT_DELAY_MAX / waitDelay;
                    }
                }

                // Fire new IORequest: the VBLANK one for the idle tick
                cur = (waitDelay >= PACKET_WAIT_DELAY_IDLE) ? trv : tr;
                cur->tr_node.io_Command = TR_ADDREQUEST;
                cur->tr_time.tv_sec = waitDelay / 1000000;
                cur->tr_time.tv_micro = waitDelay % 1000000;
                SendIO(&cur->tr_node);
            }

            if (gotTransfer)
            {
                /*
                 * Drain.  One SDPCM frame per timer tick was the rule; the
                 * chip queues more than that as soon as traffic flows (on an
                 * A1200 + PiStorm32 Lite at 27 Mbit/s in, a third of the ticks
                 * that found a frame found several, up to 29, 2026-09-18) and
                 * every extra frame waited for another tick.  Ask again until
                 * the header read comes back empty; bounded so a flood cannot
                 * starve the control port.
                 */
                ULONG burst = 0;

                for (;;)
                {
                    UWORD pktLen = LE16(pkt->p_Length);
                    UWORD pktChk = LE16(pkt->c_ChkSum);
                
                    if ((pktChk | pktLen) == 0xffff)
                    {
                        // Until now we have fetched PACKET_INITIAL_FETCH_SIZE bytes only. If packet length is larger, fetch 
                        // the rest now
                        if (pktLen > PACKET_INITIAL_FETCH_SIZE)
                        {
                            sdio->RecvPKT(&buffer[PACKET_INITIAL_FETCH_SIZE], pktLen - PACKET_INITIAL_FETCH_SIZE, sdio);
                        }

                        if ((pkt->c_ChannelFlag & 15) == SDPCM_GLOM_CHANNEL)
                        {
                            if (pkt->c_ChannelFlag & 0x80)
                            {
                                // Announcment of large frame
                            }
                            else
                            {
                                ULONG pos = pkt->c_DataOffset;

                                while(pos < pktLen)
                                {
                                    struct Packet *epkt = (APTR)&buffer[pos];

                                    ULONG processed = ProcessPacket(sdio, epkt);

                                    if (processed == 0)
                                    {
                                        D(bug("[WiFi] Last glom element\n"));
                                        break;
                                    }
                                    else if (processed == 0xffffffff)
                                    {
                                        D(bug("[WiFi] Frame error\n"));
                                        break;
                                    }
                                    else
                                    {
                                        pos += processed;
                                        pos = (pos + 3) & ~3;
                                    }
                                }
                            }
                        }
                        else
                        {
                            ProcessPacket(sdio, pkt);
                        }

                        // Mark that we have the transfer, we will wait for next one a bit shorter
                        gotTransfer = 1;
                    }
                    else
                    {
                        D(bug("[WiFi.RECV] Garbage received. Data:\n"));
                        for (int i=0; i < 256; i++)
                        {
                            if (i % 16 == 0)
                                bug("[WiFi]  ");
                            bug(" %02lx", buffer[i]);
                            if (i % 16 == 15)
                                bug("\n");
                        }
                    }

                    if (++burst >= 64)
                        break;
                    sdio->RecvPKT(buffer, PACKET_INITIAL_FETCH_SIZE, sdio);
                    if (LE16(pkt->p_Length) == 0)
                        break;
                }
                sdio->s_StatRXFrames += burst;
                if (burst > 1)
                    sdio->s_StatBursts++;
                if (burst > sdio->s_StatMaxBurst)
                    sdio->s_StatMaxBurst = burst;
            }

            /*
             * Traffic: the poller watches the line for the next POLL_GRACE_US.
             * The line is up for credits and mailbox events too, not only for
             * frames, so an empty poll wake-up is normal; a line that is STILL
             * up after the clear, sixteen wake-ups running with nothing read,
             * is a status the clear does not reach and would have the two
             * tasks chase each other at full speed -- the poller is retired
             * and the tick carries on alone.
             */
            if (sigSet & pollMask)
                pollEmpty = (!gotTransfer && sdio_card_asserting(sdio)) ? pollEmpty + 1 : 0;
            if (pollEmpty >= 16)
                pollDead = TRUE;
            /* a frame for this station or one sent is traffic; a broadcast
               the LAN made is not, and does not start the poller either */
            if (sdio->s_RxUnicast || sendTransfer)
            {
                if (WiFiBase->w_SysTimer != NULL)
                    lastTraffic = PollClock(WiFiBase);
            }
            if (!pollDead && (sdio->s_RxUnicast || sendTransfer || (sigSet & pollMask)))
                PokePoller(sdio);

            /*
             * Drained: let the host raise the card's line again.  A line that
             * keeps asserting with nothing to read (a status the clear did
             * not reach) would otherwise spin this task; after four such
             * interrupts in a row the line stays masked until the next
             * timer tick re-arms it, so a storm costs at most four
             * interrupts per tick.
             */
            if (sigSet & irqMask)
            {
                if (gotTransfer)
                    irqEmpty = irqStorms = 0;
                else
                    irqEmpty++;
                if (irqEmpty >= 4)
                    irqParked = TRUE;
                else
                    sdio_int_rearm(sdio);
            }
            if (irqParked && (sigSet & (1 << port->mp_SigBit)))
            {
                irqParked = FALSE;
                irqEmpty = 0;
                if (++irqStorms >= 250)
                {
                    /* A line that asserts with nothing behind it for a quarter
                       of a second of ticks is not one to listen to: polling only. */
                    sdio_int_detach(sdio);
                    irqMask = 0;
                }
                else
                    sdio_int_rearm(sdio);
            }
        }

        // Shutdown signal?
        if (sigSet & SIGBREAKF_CTRL_C)
        {
            D(bug("[WiFi.RECV] Quiting receiver loop\n"));
            // Abort timer IO
            AbortIO(&cur->tr_node);
            WaitIO(&cur->tr_node);
            break;
        }
    }

    D(bug("[WiFi.RECV] Packet receiver is closing now\n"));
    PacketCtrlShutdown(sdio, ctrl);
    if (sdio->s_PollTask != NULL)
    {
        /* it runs at -128: wait for its goodbye so it gets the CPU to leave */
        Signal(sdio->s_PollTask, SIGBREAKF_CTRL_C);
        Wait(pollMask);
    }
    if (sdio->s_PollSignal >= 0)
    {
        FreeSignal(sdio->s_PollSignal);
        sdio->s_PollSignal = -1;
    }
    sdio_int_detach(sdio);
    if (sdio->s_IRQSignal >= 0)
    {
        FreeSignal(sdio->s_IRQSignal);
        sdio->s_IRQSignal = -1;
    }
    CloseDevice(&trv->tr_node);
    DeleteIORequest(&trv->tr_node);
    CloseDevice(&tr->tr_node);
    DeleteIORequest(&tr->tr_node);
    DeleteMsgPort(port);
    DeleteMsgPort(ctrl);
    sdio->s_ReceiverTask = NULL;
}

/*
 * The two halves of AmiNetXDuo's single-copy receive (aminetxduo/anxs2ext.h).
 *
 * CopySumLongwords: copy `length` bytes and return the ones-complement sum of
 * the longwords copied, carries folded end-around, the tail zero-padded --
 * the contract of the stack's n68k_copy_sum_longwords().  Longword loads
 * from word-aligned addresses: this device runs on a 68040-class core or the
 * JIT, never on a 68000.
 *
 * VerifyIPv4: what that sum is worth once the headers are in cache -- the
 * IPv4 header checksum and the TCP or UDP checksum, both answered from the
 * sum and some forty adds, so the opener can skip its own walk.  Refused, so
 * VERIFIED is never set on a frame it does not describe: anything but IPv4
 * with a twenty-byte header, a fragment, a total length that is not the whole
 * payload (Ethernet padding is summed and is not the datagram's), a protocol
 * other than TCP or UDP, a UDP checksum of zero.  The same rules as the
 * stack's own netdev_rx_verify4().
 */
static ULONG CopySumLongwords(UBYTE *to, const UBYTE *from, ULONG length)
{
    ULONG acc = 0;
    ULONG longs = length >> 2;
    ULONG tail = length & 3;
    const ULONG *s = (const ULONG *)from;
    ULONG *d = (ULONG *)to;

    while (longs--)
    {
        ULONG w = *s++;
        *d++ = w;
        acc += w;
        if (acc < w) acc++;
    }
    if (tail)
    {
        const UBYTE *sb = (const UBYTE *)s;
        UBYTE *db = (UBYTE *)d;
        ULONG w = 0;
        for (ULONG i = 0; i < tail; i++)
        {
            db[i] = sb[i];
            w |= (ULONG)sb[i] << (24 - 8 * i);
        }
        acc += w;
        if (acc < w) acc++;
    }
    return acc;
}

static inline UWORD Be16(const UBYTE *p) { return *(const UWORD *)p; }

static inline UWORD Fold16(ULONG acc)
{
    acc = (acc & 0xffffUL) + (acc >> 16);
    acc = (acc & 0xffffUL) + (acc >> 16);
    return (UWORD)acc;
}

static BOOL VerifyIPv4(const UBYTE *ip, ULONG plen, ULONG sum)
{
    UWORD total, tlen;
    UBYTE proto;
    ULONG acc = 0;

    if (ip[0] != 0x45)
        return FALSE;                       /* not IPv4, or options */
    total = Be16(ip + 2);
    if (total != plen || total < 20)
        return FALSE;                       /* padded, truncated, or short */
    if ((ip[6] & 0x3f) != 0 || ip[7] != 0)
        return FALSE;                       /* MF, or a fragment offset */
    proto = ip[9];
    if (proto != 6 && proto != 17)
        return FALSE;
    for (int i = 0; i < 20; i += 2)
        acc += Be16(ip + i);
    if (Fold16(acc) != 0xffffu)
        return FALSE;
    tlen = (UWORD)(total - 20);
    if (proto == 17)
    {
        if (tlen < 8 || Be16(ip + 24) != tlen)
            return FALSE;
        if (Be16(ip + 26) == 0)             /* IPv4 UDP checksum absent */
            return FALSE;
    }
    else if (tlen < 20)
        return FALSE;
    acc  = Fold16(sum);
    acc += Be16(ip + 12);
    acc += Be16(ip + 14);
    acc += Be16(ip + 16);
    acc += Be16(ip + 18);
    acc += proto;
    acc += tlen;
    return Fold16(acc) == 0xffffu;
}

void CopyPacket(struct IOSana2Req *io, UBYTE *packet, ULONG packetLength)
{
    struct WiFiUnit *unit = (struct WiFiUnit *)io->ios2_Req.io_Unit;
    struct WiFiBase *WiFiBase = unit->wu_Base;
    struct ExecBase *SysBase = WiFiBase->w_SysBase;
    struct Opener *opener = io->ios2_BufferManagement;
    struct Library *UtilityBase = WiFiBase->w_UtilityBase;
    UBYTE packetFiltered = FALSE;

    UBYTE *copyData;
    ULONG copyLength;

    UWORD type = *(UWORD*)&packet[12];

    /* Clear broadcast and multicast flags */
    io->ios2_Req.io_Flags &= ~(SANA2IOF_BCAST | SANA2IOF_MCAST);

    /* Copy source and dest addresses */
    for (int i=0; i < 6; i++) io->ios2_DstAddr[i] = packet[i];
    for (int i=0; i < 6; i++) io->ios2_SrcAddr[i] = packet[6 + i];

    //CopyMem(packet, io->ios2_DstAddr, 6);
    //CopyMem(&packet[6], io->ios2_SrcAddr, 6);
    io->ios2_PacketType = type;

    /* If dest address is FF:FF:FF:FF:FF:FF then it is a broadcast */
    if (*(ULONG*)packet == 0xffffffff && *(UWORD*)(packet+4) == 0xffff)
    {
        io->ios2_Req.io_Flags |= SANA2IOF_BCAST;
    }
    /* If dest address has lowest bit of first addr byte set, then it is a multicast */
    else if (*packet & 0x01)
    {
        io->ios2_Req.io_Flags |= SANA2IOF_MCAST;
    }

    /* 
        If RAW packet is requested, copy everything, otherwise copy only contents of 
        the frame without ethernet header
    */
    if (io->ios2_Req.io_Flags & SANA2IOF_RAW)
    {
        copyData = packet;
        copyLength = packetLength;
    }
    else
    {
        copyData = packet + 14;
        copyLength = packetLength - 14;
    }

    /* Filter packet if CMD_READ and filter hook is set */
    if (io->ios2_Req.io_Command == CMD_READ && opener->o_FilterHook)
    {
        if (!CallHookPkt(opener->o_FilterHook, io, copyData))
        {
            packetFiltered = TRUE;
        }
    }

    /*
     * AmiNetXDuo's single-copy receive: a cooked CMD_READ of an opener that
     * offered the pair, no filter hook (it would have to see the frame
     * first).  The opener says where the payload goes, the copy from the
     * SDIO buffer sums it on the way, the header is written in front when
     * asked for, and the checksums are checked from that sum before the
     * read is replied.  A NULL answer is the opener declining this frame.
     */
    if (!packetFiltered && copyLength != 0 && io->ios2_Req.io_Command == CMD_READ &&
        opener->o_RxDirect != NULL && opener->o_FilterHook == NULL &&
        (io->ios2_Req.io_Flags & SANA2IOF_RAW) == 0)
    {
        UBYTE *dst = ((AnxdS2RxDirect)opener->o_RxDirect)(io->ios2_Data, copyLength);

        if (dst != NULL)
        {
            ULONG sum = CopySumLongwords(dst, copyData, copyLength);
            UBYTE flags = ANXD_S2_RXF_SUMMED;

            if (opener->o_RxLinkHdr)
                for (int i = 0; i < 14; i++) dst[i - 14] = packet[i];
            if ((opener->o_RxFlags & ANXD_S2_RXF_VERIFIED) && VerifyIPv4(dst, copyLength, sum))
                flags |= ANXD_S2_RXF_VERIFIED;

            io->ios2_DataLength = copyLength;
            ((AnxdS2RxFilled)opener->o_RxFilled)(io->ios2_Data, copyLength, sum, flags);

            Disable();
            Remove((struct Node *)io);
            Enable();
            ReplyMsg((struct Message *)io);
            return;
        }
    }

    /* Packet not filtered. Send it now and reply request. */
    if (!packetFiltered)
    {
        if (copyLength != 0)
        {
            if (opener->o_RXFunc(io->ios2_Data, copyData, copyLength) == 0)
            {
                io->ios2_WireError = S2WERR_BUFF_ERROR;
                io->ios2_Req.io_Error = S2ERR_NO_RESOURCES;

                /* Report error event */
            }
        }
        else
        {
            D(bug("[WiFi] Received frame without data\n"));
        }

        /* Set number of bytes received */
        io->ios2_DataLength = copyLength;

        Disable();
        Remove((struct Node *)io);
        Enable();
        ReplyMsg((struct Message *)io);
    }
}

void ProcessDataPacket(struct SDIO *sdio, UBYTE *packet, ULONG packetLength)
{
    struct WiFiBase *WiFiBase = sdio->s_WiFiBase;
    struct ExecBase *SysBase = WiFiBase->w_SysBase;
    struct WiFiUnit *unit = WiFiBase->w_Unit;
    int accept = TRUE;
    UWORD packetType = *(UWORD*)&packet[12];

    // Get destination address and check if it is a multicast
    uint64_t destAddr = ((uint64_t)*(UWORD*)&packet[0] << 32) |
                        *(ULONG*)&packet[2];

    /* the receiver's tick and poller run fast for frames addressed to us */
    if ((packet[0] & 0x01) == 0)
        sdio->s_RxUnicast = 1;
#if 1
    if (packetType == 0x888e)
    {
        struct ExecBase *SysBase = WiFiBase->w_SysBase;
        bug("[DATA.IN] Packet in:\n");
        for (ULONG i=0; i < packetLength; i++)
        {
            if (i % 16 == 0)
                bug("[DATA.IN] %04lx: ", i);
            bug(" %02lx", packet[i]);
            if (i % 16 == 15)
                bug("\n");
        }
        if (packetLength % 16 != 0) bug("\n");
    }
#endif

    if (destAddr != 0xffffffffffffULL && (destAddr & 0x010000000000ULL))
    {
        struct MulticastRange *range;
        accept = FALSE;

        ForeachNode(&unit->wu_MulticastRanges, range)
        {
            if (destAddr >= range->mr_LowerBound && destAddr <= range->mr_UpperBound)
            {
                accept = TRUE;
                break;
            }
        }
    }

    if (accept)
    {
        UBYTE orphan = TRUE;
        struct Opener *opener;

        unit->wu_Stats.PacketsReceived++;

        Disable();
        /* Go through all openers */
        ForeachNode(&unit->wu_Openers, opener)
        {
            struct IOSana2Req *io;
            
            /* Go through all IO read requests pending*/
            ForeachNode(&opener->o_ReadPort.mp_MsgList, io)
            {
                // EthernetII has packet type larger than 1500 (MTU),
                // 802.3 has no packet type but just length
                if (io->ios2_PacketType == packetType ||
                    (packetType <= 1500 && io->ios2_PacketType <= 1500))
                {
                    /* Match, copy packet, break loop for this opener */
                    CopyPacket(io, packet, packetLength);
                    
                    /* The packet is sent at least to one opener, not an orphan anymore */
                    orphan = FALSE;
                    break;
                }
            }
        }
        Enable();

        /* No receiver for this packet found? It's an orphan then */
        if (orphan)
        {
            unit->wu_Stats.UnknownTypesReceived++;

            Disable();
            /* Go through all openers and offer orphan packet to anyone asking */
            ForeachNode(&unit->wu_Openers, opener)
            {
                struct IOSana2Req *io = (APTR)opener->o_OrphanListeners.mp_MsgList.lh_Head;
                /* 
                    If this is a real node, ln_Succ will be not NULL, otherwise it is just 
                    protector node of empty list
                */
                if (io->ios2_Req.io_Message.mn_Node.ln_Succ)
                {
                    CopyPacket(io, packet, packetLength);
                }
            }
            Enable();
        }
    }
}

/*
 * brcmfmac sdio bus specific header
 * This is the lowest layer header wrapped on the packets transmitted between
 * host and WiFi dongle which contains information needed for SDIO core and
 * firmware
 *
 * It consists of 3 parts: hardware header, hardware extension header and
 * software header
 * hardware header (frame tag) - 4 bytes
 * Byte 0~1: Frame length
 * Byte 2~3: Checksum, bit-wise inverse of frame length
 * hardware extension header - 8 bytes
 * Tx glom mode only, N/A for Rx or normal Tx
 * Byte 0~1: Packet length excluding hw frame tag
 * Byte 2: Reserved
 * Byte 3: Frame flags, bit 0: last frame indication
 * Byte 4~5: Reserved
 * Byte 6~7: Tail padding length
 * software header - 8 bytes
 * Byte 0: Rx/Tx sequence number
 * Byte 1: 4 MSB Channel number, 4 LSB arbitrary flag
 * Byte 2: Length of next data frame, reserved for Tx
 * Byte 3: Data offset
 * Byte 4: Flow control bits, reserved for Tx
 * Byte 5: Maximum Sequence number allowed by firmware for Tx, N/A for Rx packet
 * Byte 6~7: Reserved
 */

int SendGlomDataPacket(struct SDIO *sdio, struct IOSana2Req **ioList, UBYTE count)
{
    struct WiFiBase *WiFiBase = sdio->s_WiFiBase;
    struct ExecBase *SysBase = sdio->s_SysBase;
    struct WiFiUnit *unit = WiFiBase->w_Unit;
    ULONG totalLength = 0;

    struct PacketHeaderHW *pktBase = sdio->s_TXBuffer;
    UBYTE *byteBuffer = sdio->s_TXBuffer;
    struct GlomHeader *lastGh = NULL;

    for (UBYTE i = 0; i < count; i++)
    {
        struct IOSana2Req *io = ioList[i];
        struct Opener *opener = io->ios2_BufferManagement;
        struct PacketHeaderHW *hw = (APTR)(byteBuffer + totalLength);
        struct GlomHeader *gh = (APTR)((UBYTE*)hw + sizeof(struct PacketHeaderHW));
        struct PacketHeaderSW *hdr = (APTR)((UBYTE*)gh + sizeof(struct GlomHeader));
        
        UWORD packetLength = io->ios2_DataLength + sizeof(struct Packet) + sizeof(struct GlomHeader) + 4;

        if ((io->ios2_Req.io_Flags & SANA2IOF_RAW) == 0)
        {
            packetLength += 14;
        }

        /* Fill HW header */
        hw->ph_Length = LE16(packetLength);
        hw->ph_ChkSum = ~hw->ph_Length;

        /* Fill out glom header */
        gh->gh_Length = LE16(packetLength - 4);
        gh->gh_ReservedB = 0;
        gh->gh_ReservedW = 0;
        if (i == count - 1) gh->gh_LastItem = 1;
        else gh->gh_LastItem = 0;
        gh->gh_TailPad = LE16((-packetLength) & 3);
        lastGh = gh;

        /* Following glom header there is PacketSW header */
        hdr->c_ChannelFlag = SDPCM_DATA_CHANNEL;
        hdr->c_DataOffset = sizeof(struct Packet) + sizeof(struct GlomHeader);
        hdr->c_FlowControl = 0;
        hdr->c_Seq = sdio->s_TXSeq++;
        hdr->c_NextLength = 0;
        hdr->c_MaxSeq = 0;
        hdr->c_Reserved[0] = 0;
        hdr->c_Reserved[1] = 0;

        /* Finally packet data */
        UBYTE *ptr = (UBYTE *)hdr + sizeof(struct PacketHeaderSW);

        /* BDC Header */
        *ptr++ = 0x20;
        *ptr++ = 0;
        *ptr++ = 0;
        *ptr++ = 0;

        if ((io->ios2_Req.io_Flags & SANA2IOF_RAW) == 0)
        {
            // Copy destination
            for (int i=0; i < 6; i++) ptr[i] = io->ios2_DstAddr[i];

            // Copy source
            for (int i=0; i < 6; i++) ptr[6 + i] = unit->wu_EtherAddr[i];

            // Copy packet type
            *(UWORD*)&ptr[12] = io->ios2_PacketType;
            ptr+=14;
        }

        if (io->ios2_DataLength != 0)
        {
            // Copy packet contents
            opener->o_TXFunc(ptr, io->ios2_Data, io->ios2_DataLength);
        }
        else
        {
            D(bug("[WiFi] Sending Frame without data, packet type %04lx\n", io->ios2_PacketType));
        }

#if 1
        if (io->ios2_PacketType == 0x888e)
        {
            UBYTE *ptr = (UBYTE *)hdr + sizeof(struct PacketHeaderSW) + 4;
            ULONG length = packetLength - sizeof(struct Packet) - sizeof(struct GlomHeader) - 4;

            bug("[DATA.OUT] Packet out:\n");
            for (ULONG i=0; i < length; i++)
            {
                if (i % 16 == 0)
                    bug("[DATA.OUT] %04lx: ", i);
                bug(" %02lx", ptr[i]);
                if (i % 16 == 15)
                    bug("\n");
            }
            if (packetLength % 16 != 0) bug("\n");
        }
#endif
        // Increase total length by packet length (aligned)
        totalLength += (packetLength + 3) & ~3;
    }

    /* A chain of more than one frame goes out as whole F2 blocks: the last
       frame's tail pad takes the chain up to the next 512 bytes, and the
       first frame's length covers it, as brcmf_sdio_txpkt_prep_sg does.
       One frame is sent as it is (#89). */
    if (count > 1)
    {
        ULONG chainPad = (512 - (totalLength % 512)) % 512;

        for (ULONG i = 0; i < chainPad; i++)
            byteBuffer[totalLength + i] = 0;
        lastGh->gh_TailPad = LE16(LE16(lastGh->gh_TailPad) + chainPad);
        totalLength += chainPad;
    }

    pktBase->ph_Length = LE16(totalLength);
    pktBase->ph_ChkSum = ~pktBase->ph_Length;
#if 0
    UBYTE *bdata = (UBYTE*)pktBase;
    for (ULONG i=0; i < totalLength; i++)
    {
        if (i % 16 == 0)
            bug("[GLOM] %04lx:", i);
        bug(" %02lx", bdata[i]);
        if (i % 16 == 15)
            bug("\n");
    }
    if (totalLength % 16 != 0) bug("\n");
#endif
#if 0
    while(1);
#endif
    sdio->SendPKT((UBYTE *)pktBase, totalLength, sdio);

    for (UBYTE i = 0; i < count; i++) {
        ReplyMsg(&ioList[i]->ios2_Req.io_Message);
        unit->wu_Stats.PacketsSent++;
    }

    return 1;
}

int SendDataPacket(struct SDIO *sdio, struct IOSana2Req *io)
{
    struct WiFiBase *WiFiBase = sdio->s_WiFiBase;
    struct ExecBase *SysBase = sdio->s_SysBase;
    struct WiFiUnit *unit = WiFiBase->w_Unit;
    struct Opener *opener = io->ios2_BufferManagement;

    UWORD totLen = sizeof(struct Packet) + io->ios2_DataLength + 4;
    
    // Raw packet has all data in it, non-raw need to reserve 14 bytes extra
    if ((io->ios2_Req.io_Flags & SANA2IOF_RAW) == 0)
    {
        totLen += 14;
    }
    
    struct Packet *p = sdio->s_TXBuffer;
    ULONG *clr = (ULONG*)p;

    *clr++ = 0;
    *clr++ = 0;
    *clr++ = 0;

    p->p_Length = LE16(totLen);
    p->c_ChkSum = ~p->p_Length;
    p->c_ChannelFlag = SDPCM_DATA_CHANNEL;
    p->c_DataOffset = sizeof(struct Packet);
    p->c_FlowControl = 0;
    p->c_Seq = sdio->s_TXSeq++;

    UBYTE *ptr = (UBYTE *)p + p->c_DataOffset;

    // BDC Header
    *ptr++ = 0x20;
    *ptr++ = 0;
    *ptr++ = 0;
    *ptr++ = 0;

    if ((io->ios2_Req.io_Flags & SANA2IOF_RAW) == 0)
    {
        // Copy destination
        for (int i=0; i < 6; i++) ptr[i] = io->ios2_DstAddr[i];
        
        // Copy source
        for (int i=0; i < 6; i++) ptr[6 + i] = io->ios2_SrcAddr[i];

        // Copy packet type
        *(UWORD*)&ptr[12] = io->ios2_PacketType;
        ptr+=14;
    }

    if (io->ios2_DataLength != 0)
    {
        // Copy packet contents
        opener->o_TXFunc(ptr, io->ios2_Data, io->ios2_DataLength);
    }
    else
    {
        D(bug("[WiFi] Sending non-glom Frame without data, packet type %04lx\n", io->ios2_PacketType));
    }
    //PacketDump(sdio, p, "WiFi.OUT");

    sdio->SendPKT((UBYTE*)p, totLen, sdio);
    unit->wu_Stats.PacketsSent++;

    return 1;
}
#if 0
void NetworkScanner(struct SDIO *sdio)
{
    struct ExecBase *SysBase = sdio->s_SysBase;
    struct WiFiBase *WiFiBase = sdio->s_WiFiBase;

    // Create MessagePort and timer.device IORequest
    struct MsgPort *port = CreateMsgPort();
    struct timerequest *tr = (struct timerequest *)CreateIORequest(port, sizeof(struct timerequest));
    ULONG sigSet;
    ULONG scanDelay = 10;

    if (port == NULL || tr == NULL)
    {
        D(bug("[WiFi.SCAN] Failed to create IO Request\n"));
        if (port != NULL) DeleteMsgPort(port);
        return;
    }

    if (OpenDevice("timer.device", UNIT_VBLANK, &tr->tr_node, 0))
    {
        D(bug("[WiFi.SCAN] Failed to open timer.device\n"));
        DeleteIORequest(&tr->tr_node);
        DeleteMsgPort(port);
        return;
    }

    tr->tr_node.io_Command = TR_ADDREQUEST;
    tr->tr_time.tv_sec = 1;
    tr->tr_time.tv_micro = 0;
    SendIO(&tr->tr_node);

    do {
        sigSet = Wait(SIGBREAKF_CTRL_C | (1 << port->mp_SigBit));
        
        if (sigSet & (1 << port->mp_SigBit))
        {
            if (CheckIO(&tr->tr_node))
            {
                WaitIO(&tr->tr_node);
            }

            // No network is in progress, decrease delay and start scanner
            if (!sdio->s_WiFiBase->w_NetworkScanInProgress)
            {
                if (scanDelay == 10)
                {
                    struct WiFiNetwork *network, *next;
                    ObtainSemaphore(&sdio->s_WiFiBase->w_NetworkListLock);
                    D(bug("[WiFI] Network list from scanner:\n"));
                    ForeachNodeSafe(&sdio->s_WiFiBase->w_NetworkList, network, next)
                    {
                        // If network wasn't available for more than 60 seconds after scan, remove it
                        if (network->wn_LastUpdated++ > 6) {
                            Remove((struct Node*)network);
                            if (network->wn_IE)
                                FreePooled(WiFiBase->w_MemPool, network->wn_IE, network->wn_IELength);
                            FreePooled(WiFiBase->w_MemPool, network, sizeof(struct WiFiNetwork));
                        }
                        else
                        {
                            D(bug("[WiFi]   SSID: '%-32s', BSID: %02lx:%02lx:%02lx:%02lx:%02lx:%02lx, Type: %s, Channel %ld, Spec:%04lx, RSSI: %ld\n",
                                (ULONG)network->wn_SSID, network->wn_BSID[0], network->wn_BSID[1], network->wn_BSID[2],
                                network->wn_BSID[3], network->wn_BSID[4], network->wn_BSID[5], 
                                network->wn_ChannelInfo.ci_Band == BRCMU_CHAN_BAND_2G ? (ULONG)"2.4GHz" : (ULONG)"5GHz",
                                network->wn_ChannelInfo.ci_CHNum, network->wn_ChannelInfo.ci_CHSpec,
                                network->wn_RSSI
                            ));
                        }
                    }
                    ReleaseSemaphore(&sdio->s_WiFiBase->w_NetworkListLock);
                }

                if (scanDelay) scanDelay--;

                if (scanDelay == 0)
                {
                    StartNetworkScan(sdio);
                }
            }
            else
            {
                scanDelay = 10;
            }

            tr->tr_node.io_Command = TR_ADDREQUEST;
            tr->tr_time.tv_sec = 1;
            tr->tr_time.tv_micro = 0;
            SendIO(&tr->tr_node);
        }

    } while(!(sigSet & SIGBREAKF_CTRL_C));

    CloseDevice(&tr->tr_node);
    DeleteIORequest(&tr->tr_node);
    DeleteMsgPort(port);
}
#endif
static const char * const brcmf_fil_errstr[] = {
    "BCME_OK",
    "BCME_ERROR",
    "BCME_BADARG",
    "BCME_BADOPTION",
    "BCME_NOTUP",
    "BCME_NOTDOWN",
    "BCME_NOTAP",
    "BCME_NOTSTA",
    "BCME_BADKEYIDX",
    "BCME_RADIOOFF",
    "BCME_NOTBANDLOCKED",
    "BCME_NOCLK",
    "BCME_BADRATESET",
    "BCME_BADBAND",
    "BCME_BUFTOOSHORT",
    "BCME_BUFTOOLONG",
    "BCME_BUSY",
    "BCME_NOTASSOCIATED",
    "BCME_BADSSIDLEN",
    "BCME_OUTOFRANGECHAN",
    "BCME_BADCHAN",
    "BCME_BADADDR",
    "BCME_NORESOURCE",
    "BCME_UNSUPPORTED",
    "BCME_BADLEN",
    "BCME_NOTREADY",
    "BCME_EPERM",
    "BCME_NOMEM",
    "BCME_ASSOCIATED",
    "BCME_RANGE",
    "BCME_NOTFOUND",
    "BCME_WME_NOT_ENABLED",
    "BCME_TSPEC_NOTFOUND",
    "BCME_ACM_NOTSUPPORTED",
    "BCME_NOT_WME_ASSOCIATION",
    "BCME_SDIO_ERROR",
    "BCME_DONGLE_DOWN",
    "BCME_VERSION",
    "BCME_TXFAIL",
    "BCME_RXFAIL",
    "BCME_NODEVICE",
    "BCME_NMODE_DISABLED",
    "BCME_NONRESIDENT",
    "BCME_SCANREJECT",
    "BCME_USAGE_ERROR",
    "BCME_IOCTL_ERROR",
    "BCME_SERIAL_PORT_ERR",
    "BCME_DISABLED",
    "BCME_DECERR",
    "BCME_ENCERR",
    "BCME_MICERR",
    "BCME_REPLAY",
    "BCME_IE_NOTFOUND",
};

void PacketDump(struct SDIO *sdio, APTR data, char *src)
{
    struct ExecBase *SysBase = sdio->s_SysBase;
    struct Packet *pkt = data;
    ULONG dataLength = LE16(pkt->p_Length);// - sizeof(struct Packet);

    D(bug("[%s] Packet dump: \n", (ULONG)src));
    D(bug("[%s]   Len=%04lx, ChkSum=%04lx\n", (ULONG)src, LE16(pkt->p_Length), LE16(pkt->c_ChkSum)));
    D(bug("[%s]   SEQ=%03ld, CHAN=%ld, NEXT=%ld, DATA=%ld, FLOW=%ld, MAX_SEQ=%ld\n", (ULONG)src, 
                        pkt->c_Seq, pkt->c_ChannelFlag, pkt->c_NextLength, pkt->c_DataOffset, pkt->c_FlowControl, pkt->c_MaxSeq));
    
    data = (APTR)((ULONG)data + pkt->c_DataOffset);

    if (pkt->c_ChannelFlag == 0)
    {
        struct PacketCmd *c = data;
        D(bug("[%s]   CMD=%08lx, FLAGS=%04lx, ID=%04lx, STAT=%08lx\n", (ULONG)src, LE32(c->c_Command), LE16(c->c_Flags),
            LE16(c->c_ID), LE32(c->c_Status)));
    
        if (LE16(c->c_Flags) & BCDC_DCMD_ERROR)
        {
            LONG errCode = LE32(c->c_Status);
            D(bug("[%s]   Command ended with error: %s\n", (ULONG)src, (ULONG)brcmf_fil_errstr[-errCode]));
        }

        data = (APTR)((ULONG)data + sizeof(struct PacketCmd));
        //dataLength -= sizeof(struct PacketCmd);
    }
    
    UBYTE *bdata = (UBYTE*)pkt;

    if (pkt->c_ChannelFlag != 3)
        if (dataLength > 64) dataLength = 64;

    for (ULONG i=0; i < dataLength; i++)
    {
        if (i % 16 == 0)
            bug("[%s]  ", (ULONG)src);
        bug(" %02lx", bdata[i]);
        if (i % 16 == 15)
            bug("\n");
    }
    if (dataLength % 16 != 0) bug("\n");
}

static int int_strlen(const char *c)
{
    int len = 0;
    if (!c) return 0;

    while(*c++) len++;

    return len;
}

/*
 * Synchronous control requests (#93).  A caller builds the request, hands it
 * to the receiver task and waits for the firmware's reply -- used to wait
 * forever, in the caller's task under wu_Lock, so one lost reply stopped all
 * of the unit's traffic.  Now the wait has a deadline, and ownership is:
 *
 *   queued on the receiver's port, on ctrlWaitList, being sent:
 *       the receiver owns the block; the caller owns its reply port.
 *   completed (taken off the list and replied, under Forbid):
 *       the caller owns block and port and frees both.
 *   abandoned (pm_Abandoned set under Forbid, no reply yet):
 *       the caller deletes only its own port (its signal bit is its own);
 *       the receiver frees the block -- when it takes it from its port, when
 *       a reply walk or a sweep finds it -- never while sending it, and never
 *       copies into pm_RecvBuffer (cleared) or replies it.
 *
 * The caller's give-up and the receiver's check-copy-reply both run under
 * Forbid, so each sees the other's result whole.  The blocks come from
 * AllocMem(), not w_MemPool: an exec pool has no locking of its own on 3.x,
 * and these are freed by whichever task ends up owning them.  No allocation
 * or free is made under Forbid.
 *
 * Replies match on c_ID and c_Command.  The protocol echoes no generation, so
 * an ID given up on is quarantined (the last 32) and not issued again while
 * there: a reply delayed past 65,504 later requests, for the same command,
 * could still be taken for a new one.  Nothing stronger is claimed.
 */
#ifdef WIFIPI_TEST_SEAMS
int wifipi_test_fail_timer;
#endif

static UWORD NextCmdID(struct SDIO *sdio)
{
    struct ExecBase *SysBase = sdio->s_SysBase;
    UWORD id;
    ULONG i;
    BOOL used;

    Forbid();
    do
    {
        id = ++(sdio->s_CmdID);
        used = (id == 0);
        for (i = 0; i < 32 && !used; i++)
            if (sdio->s_CtrlQuarantine[i] == id)
                used = TRUE;
    } while (used);
    Permit();
    return id;
}

_Static_assert(sizeof(struct PacketMessage) % 4 == 0,
               "the packet after the message header starts 4-aligned (#97)");

struct CtrlTimer {
    struct MsgPort *        ct_Port;
    struct timerequest *    ct_Req;
};

static BOOL CtrlTimerOpen(struct SDIO *sdio, struct CtrlTimer *t)
{
    struct ExecBase *SysBase = sdio->s_SysBase;

    t->ct_Req = NULL;
    t->ct_Port = CreateMsgPort();
#ifdef WIFIPI_TEST_SEAMS
    /* 1: no port; 2: timer.device refuses the open */
    if (wifipi_test_fail_timer == 1 && t->ct_Port != NULL)
    {
        DeleteMsgPort(t->ct_Port);
        t->ct_Port = NULL;
    }
#endif
    if (t->ct_Port == NULL)
        return FALSE;
    t->ct_Req = (struct timerequest *)CreateIORequest(t->ct_Port, sizeof(struct timerequest));
    if (t->ct_Req != NULL &&
#ifdef WIFIPI_TEST_SEAMS
        wifipi_test_fail_timer != 2 &&
#endif
        OpenDevice((CONST_STRPTR)TIMERNAME, UNIT_MICROHZ, (struct IORequest *)t->ct_Req, 0) == 0)
        return TRUE;
    if (t->ct_Req != NULL)
        DeleteIORequest((struct IORequest *)t->ct_Req);
    DeleteMsgPort(t->ct_Port);
    t->ct_Req = NULL;
    t->ct_Port = NULL;
    return FALSE;
}

static void CtrlTimerClose(struct SDIO *sdio, struct CtrlTimer *t)
{
    struct ExecBase *SysBase = sdio->s_SysBase;

    CloseDevice((struct IORequest *)t->ct_Req);
    DeleteIORequest((struct IORequest *)t->ct_Req);
    DeleteMsgPort(t->ct_Port);
}

/* Everything a synchronous request needs before it may be queued: a timer,
   a reply port and the block.  All or nothing: on failure nothing is left
   allocated and nothing is queued. */
static struct PacketMessage *CtrlBegin(struct SDIO *sdio, struct CtrlTimer *t, struct MsgPort **port, ULONG totalLen)
{
    struct ExecBase *SysBase = sdio->s_SysBase;
    struct PacketMessage *mpkt;

    if (!CtrlTimerOpen(sdio, t))
        return NULL;
    *port = CreateMsgPort();
    if (*port == NULL)
    {
        CtrlTimerClose(sdio, t);
        return NULL;
    }
    /* sdio_sendpkt() sends the packet rounded up to 4 bytes: the block covers
       that, zeroed, so the padding comes from our own memory (#97).  The
       message header is a multiple of 4, so rounding the whole rounds the
       packet part. */
    totalLen = (totalLen + 3) & ~3;
    mpkt = AllocMem(totalLen, MEMF_PUBLIC | MEMF_CLEAR);
    if (mpkt == NULL)
    {
        DeleteMsgPort(*port);
        CtrlTimerClose(sdio, t);
        return NULL;
    }
    mpkt->pm_Message.mn_ReplyPort = *port;
    mpkt->pm_Message.mn_Length = totalLen;
    mpkt->pm_AllocSize = totalLen;
    return mpkt;
}

/* Queue the request, wait for its reply or the deadline, and settle who owns
   what.  Returns the firmware status (0 = done), or PACKET_CTRL_TIMEOUT. */
static ULONG CtrlTransact(struct SDIO *sdio, struct PacketMessage *mpkt, struct MsgPort *port, struct CtrlTimer *t, ULONG *copied)
{
    struct ExecBase *SysBase = sdio->s_SysBase;
    struct PacketCmd *c = mpkt->pm_PacketData;
    BOOL replied = FALSE;
    BOOL queued = FALSE;
    ULONG error_code;

    if (copied != NULL)
        *copied = 0;

    /* No receiver (it has shut down): nothing is queued, all is still ours */
    Forbid();
    if (sdio->s_ReceiverPort != NULL)
    {
        PutMsg(sdio->s_ReceiverPort, &mpkt->pm_Message);
        queued = TRUE;
    }
    Permit();
    if (!queued)
    {
        FreeMem(mpkt, mpkt->pm_AllocSize);
        CtrlTimerClose(sdio, t);
        DeleteMsgPort(port);
        return PACKET_CTRL_NORES;
    }

    t->ct_Req->tr_node.io_Command = TR_ADDREQUEST;
    t->ct_Req->tr_time.tv_secs = PACKET_CTRL_TIMEOUT_MS / 1000;
    t->ct_Req->tr_time.tv_micro = (PACKET_CTRL_TIMEOUT_MS % 1000) * 1000;
    SendIO((struct IORequest *)t->ct_Req);

    for (;;)
    {
        if (GetMsg(port) != NULL)
        {
            replied = TRUE;
            break;
        }
        if (CheckIO((struct IORequest *)t->ct_Req))
            break;
        Wait((1UL << port->mp_SigBit) | (1UL << t->ct_Port->mp_SigBit));
    }

    if (!replied)
    {
        /* The receiver completes a request under Forbid too: either its reply
           is already on the port, or it will find the flag and not touch the
           caller's buffer or port. */
        Forbid();
        if (GetMsg(port) != NULL)
            replied = TRUE;
        else
        {
            mpkt->pm_Abandoned = 1;
            mpkt->pm_RecvBuffer = NULL;
            mpkt->pm_RecvSize = 0;
            sdio->s_CtrlQuarantine[sdio->s_CtrlQuarantineNext++ & 31] = LE16(c->c_ID);
        }
        Permit();
    }

    if (!CheckIO((struct IORequest *)t->ct_Req))
        AbortIO((struct IORequest *)t->ct_Req);
    WaitIO((struct IORequest *)t->ct_Req);
    CtrlTimerClose(sdio, t);

    if (replied)
    {
        error_code = (c->c_Flags & LE16(BCDC_DCMD_ERROR)) ? LE32(c->c_Status) : 0;
        if (copied != NULL)
            *copied = mpkt->pm_Copied;
        FreeMem(mpkt, mpkt->pm_AllocSize);
    }
    else
        error_code = PACKET_CTRL_TIMEOUT;   /* the block is the receiver's now */

    DeleteMsgPort(port);
    return error_code;
}

/* Receiver side.  These run only in the receiver task (and the tests' stand-in
   for it); ctrlWaitList is touched nowhere else. */

static void CtrlFreeChain(struct SDIO *sdio, struct PacketMessage *chain)
{
    struct ExecBase *SysBase = sdio->s_SysBase;

    while (chain != NULL)
    {
        struct PacketMessage *next = (struct PacketMessage *)chain->pm_Message.mn_Node.ln_Succ;
        FreeMem(chain, chain->pm_AllocSize);
        chain = next;
    }
}

/* A request taken from the receiver's port: queue it for its reply and send
   it, unless its caller has already given up. */
void PacketCtrlQueue(struct SDIO *sdio, struct Message *msg)
{
    struct ExecBase *SysBase = sdio->s_SysBase;
    struct PacketMessage *m = (struct PacketMessage *)msg;
    BOOL abandoned;

    Forbid();
    abandoned = m->pm_Abandoned;
    if (!abandoned)
        AddTail((struct List *)sdio->s_CtrlWaitList, &m->pm_Message.mn_Node);
    Permit();

    /* Given up on before it was sent: it has no sequence number yet, so it
       is simply dropped (#96). */
    if (abandoned)
    {
        FreeMem(m, m->pm_AllocSize);
        return;
    }

    /* Numbered here, as it goes out, by the only task that numbers frames:
       data gloms and the scan requests are numbered by this task at send
       too, so the numbers leave in order (brcmf_sdio_tx_ctrlframe). */
    ((UBYTE *)&m->pm_PacketHeader[0])[m->pm_SeqOff] = sdio->s_TXSeq++;
    sdio->SendPKT((APTR)&m->pm_PacketHeader[0], LE16(m->pm_PacketHeader[0].p_Length), sdio);
}

/* A control reply from the firmware.  Abandoned requests met on the way are
   taken off and freed; only a live request with the same c_ID and c_Command
   gets the reply, and never more of it than arrived. */
void PacketCtrlComplete(struct SDIO *sdio, struct Packet *pkt, ULONG pktLen)
{
    struct ExecBase *SysBase = sdio->s_SysBase;
    UBYTE *buffer = (UBYTE *)pkt;
    struct PacketCmd *cmd;
    struct PacketMessage *m, *next, *chain = NULL;
    ULONG avail;

    if (pkt->c_DataOffset < sizeof(struct Packet) ||
        pktLen < (ULONG)pkt->c_DataOffset + sizeof(struct PacketCmd))
        return;
    cmd = (APTR)&buffer[pkt->c_DataOffset];
    avail = pktLen - pkt->c_DataOffset - sizeof(struct PacketCmd);

    Forbid();
    for (m = (APTR)sdio->s_CtrlWaitList->mlh_Head; (next = (APTR)m->pm_Message.mn_Node.ln_Succ) != NULL; m = next)
    {
        struct PacketCmd *c = (APTR)m->pm_PacketData;

        if (m->pm_Abandoned)
        {
            Remove(&m->pm_Message.mn_Node);
            m->pm_Message.mn_Node.ln_Succ = (APTR)chain;
            chain = m;
            continue;
        }
        if (c->c_ID == cmd->c_ID && c->c_Command == cmd->c_Command)
        {
            Remove(&m->pm_Message.mn_Node);
            CopyMem(cmd, c, sizeof(struct PacketCmd));
            if (!(c->c_Flags & LE16(BCDC_DCMD_SET)) && !(c->c_Flags & LE16(BCDC_DCMD_ERROR)) &&
                m->pm_RecvBuffer != NULL && m->pm_RecvSize != 0)
            {
                ULONG n = m->pm_RecvSize;
                if (n > avail)
                    n = avail;
                if (n > LE32(c->c_Length))
                    n = LE32(c->c_Length);
                CopyMem((UBYTE *)cmd + sizeof(struct PacketCmd), m->pm_RecvBuffer, n);
                m->pm_Copied = n;
            }
            ReplyMsg(&m->pm_Message);
            break;
        }
    }
    Permit();
    CtrlFreeChain(sdio, chain);
}

/* Every receiver wake-up: free the requests whose callers gave up. */
void PacketCtrlSweep(struct SDIO *sdio)
{
    struct ExecBase *SysBase = sdio->s_SysBase;
    struct PacketMessage *m, *next, *chain = NULL;

    Forbid();
    for (m = (APTR)sdio->s_CtrlWaitList->mlh_Head; (next = (APTR)m->pm_Message.mn_Node.ln_Succ) != NULL; m = next)
    {
        if (m->pm_Abandoned)
        {
            Remove(&m->pm_Message.mn_Node);
            m->pm_Message.mn_Node.ln_Succ = (APTR)chain;
            chain = m;
        }
    }
    Permit();
    CtrlFreeChain(sdio, chain);
}

/* The receiver is leaving: waiting callers get an error reply now, abandoned
   requests are freed. */
void PacketCtrlShutdown(struct SDIO *sdio, struct MsgPort *ctrl)
{
    struct ExecBase *SysBase = sdio->s_SysBase;
    struct PacketMessage *m, *chain = NULL;

    Forbid();
    sdio->s_ReceiverPort = NULL;            /* new requests fail closed from here */
    while ((m = (APTR)GetMsg(ctrl)) != NULL)
        AddTail((struct List *)sdio->s_CtrlWaitList, &m->pm_Message.mn_Node);
    while ((m = (APTR)RemHead((struct List *)sdio->s_CtrlWaitList)) != NULL)
    {
        if (m->pm_Abandoned)
        {
            m->pm_Message.mn_Node.ln_Succ = (APTR)chain;
            chain = m;
        }
        else
        {
            struct PacketCmd *c = (APTR)m->pm_PacketData;
            c->c_Flags |= LE16(BCDC_DCMD_ERROR);
            c->c_Status = LE32((ULONG)PACKET_CTRL_TIMEOUT);
            ReplyMsg(&m->pm_Message);
        }
    }
    /* the list lives on the receiver's stack, which is about to go */
    sdio->s_CtrlWaitList = NULL;
    Permit();
    CtrlFreeChain(sdio, chain);
}

int PacketSetVar(struct SDIO *sdio, char *varName, const void *setBuffer, int setSize)
{
    /* read once: another task's S2_CONFIGINTERFACE may switch glomming on
       while this frame is being built, and every field must agree (#96) */
    BOOL glom = sdio->s_GlomEnabled;
    struct ExecBase *SysBase = sdio->s_SysBase;
    UBYTE *pkt;
    struct MsgPort *port;
    struct CtrlTimer timer;
    struct PacketMessage *mpkt;
    ULONG totalLen = sizeof(struct Packet) + sizeof(struct PacketCmd) + sizeof(struct PacketMessage) + setSize;
    ULONG error_code = 0;

    if (glom)
        totalLen += 8;

    int varSize = int_strlen(varName) + 1;

    totalLen += varSize;

    mpkt = CtrlBegin(sdio, &timer, &port, totalLen);
    if (mpkt == NULL)
        return PACKET_CTRL_NORES;
    pkt = (APTR)&mpkt->pm_PacketHeader[0];


    struct PacketHeaderHW *hw = (APTR)&pkt[0];
    struct GlomHeader *gl = (APTR)&pkt[4];
    struct PacketHeaderSW *sw = glom ? (APTR)&pkt[12] : (APTR)&pkt[4];
    struct PacketCmd *c = glom ? (APTR)&pkt[20] : (APTR)&pkt[12];
    
    mpkt->pm_PacketData = c;
    UWORD totLen = sizeof(struct Packet) + sizeof(struct PacketCmd) + varSize + setSize;
    
    if (glom)
    {
        totLen += 8;
        gl->gh_Length = LE16(totLen - sizeof(struct PacketHeaderHW));
        gl->gh_ReservedB = 0;
        gl->gh_LastItem = 1;
        gl->gh_ReservedW = 0;
        gl->gh_TailPad = LE16((-totLen) & 3);
    }

    hw->ph_Length = LE16(totLen);
    hw->ph_ChkSum = ~hw->ph_Length;
    sw->c_DataOffset = sizeof(struct Packet);
    if (glom) sw->c_DataOffset += sizeof(struct GlomHeader);
    sw->c_FlowControl = 0;
    /* the receiver numbers it when it sends it (#96) */
    mpkt->pm_SeqOff = glom ? 12 : 4;

    c->c_Command = LE32(BRCMF_C_SET_VAR); 
    c->c_Length = LE32(varSize + setSize);
    c->c_Flags = LE16(BCDC_DCMD_SET);
    c->c_ID = LE16(NextCmdID(sdio));
    c->c_Status = 0;

    UBYTE *param = (UBYTE*)c + sizeof(struct PacketCmd);
    
    CopyMem(varName, &param[0], varSize);
    CopyMem((APTR)setBuffer, &param[varSize], setSize);

    error_code = CtrlTransact(sdio, mpkt, port, &timer, NULL);
    D(bug("[WiFi] PacketSetVar ended with %08lx\n", error_code));

    return error_code;
}

void PacketSetVarAsync(struct SDIO *sdio, char *varName, const void *setBuffer, int setSize)
{
    /* read once: another task's S2_CONFIGINTERFACE may switch glomming on
       while this frame is being built, and every field must agree (#96) */
    BOOL glom = sdio->s_GlomEnabled;
    struct ExecBase *SysBase = sdio->s_SysBase;
    UBYTE *pkt;
    ULONG totalLen = sizeof(struct Packet) + sizeof(struct PacketCmd) + setSize;

    if (glom)
        totalLen += 8;

    int varSize = int_strlen(varName) + 1;

    totalLen += varSize;

    /* the frame is sent rounded up to 4 bytes: allocate (zeroed) that far (#97);
       AllocMem, not w_MemPool: the receiver sends these, outside wu_Lock (#94) */
    ULONG allocLen = (totalLen + 3) & ~3;
    pkt = AllocMem(allocLen, MEMF_PUBLIC | MEMF_CLEAR);
    if (pkt == NULL)
        return;

    struct PacketHeaderHW *hw = (APTR)&pkt[0];
    struct GlomHeader *gl = (APTR)&pkt[4];
    struct PacketHeaderSW *sw = glom ? (APTR)&pkt[12] : (APTR)&pkt[4];
    struct PacketCmd *c = glom ? (APTR)&pkt[20] : (APTR)&pkt[12];

    if (glom)
    {
        gl->gh_Length = LE16(totalLen - sizeof(struct PacketHeaderHW));
        gl->gh_ReservedB = 0;
        gl->gh_LastItem = 1;
        gl->gh_ReservedW = 0;
        gl->gh_TailPad = LE16((-totalLen) & 3);
    }

    hw->ph_Length = LE16(totalLen);
    hw->ph_ChkSum = ~hw->ph_Length;
    sw->c_DataOffset = sizeof(struct Packet);
    if (glom) sw->c_DataOffset += sizeof(struct GlomHeader);
    sw->c_FlowControl = 0;
    sw->c_Seq = sdio->s_TXSeq++;

    c->c_Command = LE32(263);
    c->c_Length = LE32(varSize + setSize);
    c->c_Flags = LE16(BCDC_DCMD_SET);
    c->c_ID = LE16(NextCmdID(sdio));
    c->c_Status = 0;

    UBYTE *param = (UBYTE*)c + sizeof(struct PacketCmd);
    
    CopyMem(varName, &param[0], varSize);
    CopyMem((APTR)setBuffer, &param[varSize], setSize);

    // Async - fire the packet and forget
    sdio->SendPKT(pkt, totalLen, sdio);

    FreeMem(pkt, allocLen);
}

int PacketSetVarInt(struct SDIO *sdio, char *varName, ULONG varValue)
{
    ULONG val = LE32(varValue);
    return PacketSetVar(sdio, varName, &val, 4);
}

void PacketSetVarIntAsync(struct SDIO *sdio, char *varName, ULONG varValue)
{
    ULONG val = LE32(varValue);
    PacketSetVarAsync(sdio, varName, &val, 4);
}

int PacketCmdInt(struct SDIO *sdio, ULONG cmd, ULONG cmdValue)
{
    /* read once: another task's S2_CONFIGINTERFACE may switch glomming on
       while this frame is being built, and every field must agree (#96) */
    BOOL glom = sdio->s_GlomEnabled;
    struct ExecBase *SysBase = sdio->s_SysBase;
    UBYTE *pkt;
    struct MsgPort *port;
    struct CtrlTimer timer;
    struct PacketMessage *mpkt;
    ULONG totalLen = sizeof(struct Packet) + sizeof(struct PacketCmd) + sizeof(struct PacketMessage) + 4;
    ULONG error_code = 0;

    if (glom)
        totalLen += 8;

    mpkt = CtrlBegin(sdio, &timer, &port, totalLen);
    if (mpkt == NULL)
        return PACKET_CTRL_NORES;
    pkt = (APTR)&mpkt->pm_PacketHeader[0];

    
    struct PacketHeaderHW *hw = (APTR)&pkt[0];
    struct GlomHeader *gl = (APTR)&pkt[4];
    struct PacketHeaderSW *sw = glom ? (APTR)&pkt[12] : (APTR)&pkt[4];
    struct PacketCmd *c = glom ? (APTR)&pkt[20] : (APTR)&pkt[12];

    mpkt->pm_PacketData = c;

    UWORD totLen = sizeof(struct Packet) + sizeof(struct PacketCmd) + 4;
    
    if (glom)
    {
        totLen += 8;
        gl->gh_Length = LE16(totLen - sizeof(struct PacketHeaderHW));
        gl->gh_ReservedB = 0;
        gl->gh_LastItem = 1;
        gl->gh_ReservedW = 0;
        gl->gh_TailPad = LE16((-totLen) & 3);
    }

    hw->ph_Length = LE16(totLen);
    hw->ph_ChkSum = ~hw->ph_Length;
    sw->c_DataOffset = sizeof(struct Packet);
    if (glom) sw->c_DataOffset += sizeof(struct GlomHeader);
    sw->c_FlowControl = 0;
    /* the receiver numbers it when it sends it (#96) */
    mpkt->pm_SeqOff = glom ? 12 : 4;

    c->c_Command = LE32(cmd);
    c->c_Length = LE32(4);
    c->c_Flags = LE16(BCDC_DCMD_SET);
    c->c_ID = LE16(NextCmdID(sdio));
    c->c_Status = 0;

    ULONG *param = (APTR)((UBYTE*)c + sizeof(struct PacketCmd));

    *param = LE32(cmdValue);

    error_code = CtrlTransact(sdio, mpkt, port, &timer, NULL);
    D(bug("[WiFi] PacketCmdInt ended with %08lx\n", error_code));

    return error_code;
}

void PacketCmdIntAsync(struct SDIO *sdio, ULONG cmd, ULONG cmdValue)
{
    /* read once: another task's S2_CONFIGINTERFACE may switch glomming on
       while this frame is being built, and every field must agree (#96) */
    BOOL glom = sdio->s_GlomEnabled;
    struct ExecBase *SysBase = sdio->s_SysBase;
    UBYTE *pkt;
    ULONG totalLen = sizeof(struct Packet) + sizeof(struct PacketCmd) + 4;

    if (glom)
        totalLen += 8;

    /* the frame is sent rounded up to 4 bytes: allocate (zeroed) that far (#97);
       AllocMem, not w_MemPool: the receiver sends these, outside wu_Lock (#94) */
    ULONG allocLen = (totalLen + 3) & ~3;
    pkt = AllocMem(allocLen, MEMF_PUBLIC | MEMF_CLEAR);
    if (pkt == NULL)
        return;
    
    struct PacketHeaderHW *hw = (APTR)&pkt[0];
    struct GlomHeader *gl = (APTR)&pkt[4];
    struct PacketHeaderSW *sw = glom ? (APTR)&pkt[12] : (APTR)&pkt[4];
    struct PacketCmd *c = glom ? (APTR)&pkt[20] : (APTR)&pkt[12];

    if (glom)
    {
        gl->gh_Length = LE16(totalLen - sizeof(struct PacketHeaderHW));
        gl->gh_ReservedB = 0;
        gl->gh_LastItem = 1;
        gl->gh_ReservedW = 0;
        gl->gh_TailPad = LE16((-totalLen) & 3);
    }

    hw->ph_Length = LE16(totalLen);
    hw->ph_ChkSum = ~hw->ph_Length;
    sw->c_DataOffset = sizeof(struct Packet);
    if (glom) sw->c_DataOffset += sizeof(struct GlomHeader);
    sw->c_FlowControl = 0;
    sw->c_Seq = sdio->s_TXSeq++;

    c->c_Command = LE32(cmd);
    c->c_Length = LE32(4);
    c->c_Flags = LE16(BCDC_DCMD_SET);
    c->c_ID = LE16(NextCmdID(sdio));
    c->c_Status = 0;

    ULONG *param = (APTR)((UBYTE*)c + sizeof(struct PacketCmd));

    // Put command argument into packet
    *param = LE32(cmdValue);

    // Fire packet and forget it
    sdio->SendPKT(pkt, totalLen, sdio);

    FreeMem(pkt, allocLen);
}

int PacketCmdIntGet(struct SDIO *sdio, ULONG cmd, ULONG *cmdValue)
{
    /* read once: another task's S2_CONFIGINTERFACE may switch glomming on
       while this frame is being built, and every field must agree (#96) */
    BOOL glom = sdio->s_GlomEnabled;
    ULONG error_code = 2;

    if (cmdValue != NULL)
    {
        ULONG scratch = 0;
        struct ExecBase *SysBase = sdio->s_SysBase;
        UBYTE *pkt;
        struct MsgPort *port;
    struct CtrlTimer timer;
        struct PacketMessage *mpkt;
        ULONG totalLen = sizeof(struct Packet) + sizeof(struct PacketCmd) + sizeof(struct PacketMessage) + 4;
        error_code = 0;

        if (glom)
            totalLen += 8;

        mpkt = CtrlBegin(sdio, &timer, &port, totalLen);
        if (mpkt == NULL)
            return PACKET_CTRL_NORES;
        pkt = (APTR)&mpkt->pm_PacketHeader[0];

        /* The reply lands in scratch, and reaches *cmdValue only whole: a
           short reply must not leave a half-written value behind.  On the
           stack is safe -- a request given up on has pm_RecvBuffer cleared
           under Forbid before this function returns. */
        mpkt->pm_RecvBuffer = &scratch;
        mpkt->pm_RecvSize = 4;
        
        struct PacketHeaderHW *hw = (APTR)&pkt[0];
        struct GlomHeader *gl = (APTR)&pkt[4];
        struct PacketHeaderSW *sw = glom ? (APTR)&pkt[12] : (APTR)&pkt[4];
        struct PacketCmd *c = glom ? (APTR)&pkt[20] : (APTR)&pkt[12];

        mpkt->pm_PacketData = c;

        UWORD totLen = sizeof(struct Packet) + sizeof(struct PacketCmd) + 4;
        
        if (glom)
        {
            totLen += 8;
            gl->gh_Length = LE16(totLen - sizeof(struct PacketHeaderHW));
            gl->gh_ReservedB = 0;
            gl->gh_LastItem = 1;
            gl->gh_ReservedW = 0;
            gl->gh_TailPad = LE16((-totLen) & 3);
        }

        hw->ph_Length = LE16(totLen);
        hw->ph_ChkSum = ~hw->ph_Length;
        sw->c_DataOffset = sizeof(struct Packet);
        if (glom) sw->c_DataOffset += sizeof(struct GlomHeader);
        sw->c_FlowControl = 0;
        /* the receiver numbers it when it sends it (#96) */
        mpkt->pm_SeqOff = glom ? 12 : 4;

        c->c_Command = LE32(cmd);
        c->c_Length = LE32(4);
        c->c_Flags = LE16(0);
        c->c_ID = LE16(NextCmdID(sdio));
        c->c_Status = 0;

        //PacketDump(sdio, p, "WiFi");

        ULONG copied;

        error_code = CtrlTransact(sdio, mpkt, port, &timer, &copied);
        /* The value is the firmware's only if all four bytes of it arrived */
        if (error_code == 0 && copied < 4)
            error_code = PACKET_CTRL_SHORT;
        if (error_code == 0)
            *cmdValue = LE32(scratch);
        D(bug("[WiFi] PacketCmdIntGet ended with %08lx\n", error_code));
    }

    return error_code;
}

/* getSize is the buffer's capacity: a well-formed reply may be shorter ('ver',
   'counters'), is copied as far as it goes and the rest zeroed -- success, as
   brcmf_proto_bcdc_query_dcmd() does.  A caller that needs an exact size
   (cur_etheraddr: 6) says so in minSize and gets PACKET_CTRL_SHORT below it. */
int PacketGetVarMin(struct SDIO *sdio, char *varName, void *getBuffer, int getSize, int minSize)
{
    /* read once: another task's S2_CONFIGINTERFACE may switch glomming on
       while this frame is being built, and every field must agree (#96) */
    BOOL glom = sdio->s_GlomEnabled;
    struct ExecBase *SysBase = sdio->s_SysBase;
    UBYTE *pkt;
    struct MsgPort *port;
    struct CtrlTimer timer;
    struct PacketMessage *mpkt;
    ULONG totalLen = sizeof(struct Packet) + sizeof(struct PacketCmd) + sizeof(struct PacketMessage);
    ULONG error_code = 0;

    if (glom)
        totalLen += 8;

    int varSize = int_strlen(varName) + 1;

    if (varSize > getSize)
        totalLen += varSize;
    else
        totalLen += getSize;

    mpkt = CtrlBegin(sdio, &timer, &port, totalLen);
    if (mpkt == NULL)
        return PACKET_CTRL_NORES;
    pkt = (APTR)&mpkt->pm_PacketHeader[0];

    mpkt->pm_RecvBuffer = getBuffer;
    mpkt->pm_RecvSize = getSize;

    struct PacketHeaderHW *hw = (APTR)&pkt[0];
    struct GlomHeader *gl = (APTR)&pkt[4];
    struct PacketHeaderSW *sw = glom ? (APTR)&pkt[12] : (APTR)&pkt[4];
    struct PacketCmd *c = glom ? (APTR)&pkt[20] : (APTR)&pkt[12];

    mpkt->pm_PacketData = c;

    UWORD max = varSize;
    if (getSize > max) max = getSize;

    UWORD totLen = sizeof(struct Packet) + sizeof(struct PacketCmd) + max;
    
    if (glom)
    {
        totLen += 8;
        gl->gh_Length = LE16(totLen - sizeof(struct PacketHeaderHW));
        gl->gh_ReservedB = 0;
        gl->gh_LastItem = 1;
        gl->gh_ReservedW = 0;
        gl->gh_TailPad = LE16((-totLen) & 3);
    }

    hw->ph_Length = LE16(totLen);
    hw->ph_ChkSum = ~hw->ph_Length;
    sw->c_DataOffset = sizeof(struct Packet);
    if (glom) sw->c_DataOffset += sizeof(struct GlomHeader);
    sw->c_FlowControl = 0;
    /* the receiver numbers it when it sends it (#96) */
    mpkt->pm_SeqOff = glom ? 12 : 4;

    c->c_Command = LE32(262);
    c->c_Length = LE32(max);
    c->c_Flags = LE16(0);
    c->c_ID = LE16(NextCmdID(sdio));
    c->c_Status = 0;

    UBYTE *param = (UBYTE*)c + sizeof(struct PacketCmd);
    
    CopyMem(varName, &param[0], varSize);

    ULONG copied;

    error_code = CtrlTransact(sdio, mpkt, port, &timer, &copied);
    /* No stale bytes behind a shorter answer: the rest is zeroed */
    if (error_code == 0 && copied < (ULONG)getSize)
    {
        UBYTE *out = getBuffer;
        ULONG i;
        for (i = copied; i < (ULONG)getSize; i++)
            out[i] = 0;
        if (copied < (ULONG)minSize)
            error_code = PACKET_CTRL_SHORT;
    }
    D(bug("[WiFi] PacketGetVar ended with %08lx\n", error_code));

    return error_code;
}

int PacketGetVar(struct SDIO *sdio, char *varName, void *getBuffer, int getSize)
{
    return PacketGetVarMin(sdio, varName, getBuffer, getSize, 0);
}

#define MAX_CHUNK_LEN			1400

#define DLOAD_HANDLER_VER		1	/* Downloader version */
#define DLOAD_FLAG_VER_MASK		0xf000	/* Downloader version mask */
#define DLOAD_FLAG_VER_SHIFT		12	/* Downloader version shift */

#define DL_BEGIN			0x0002
#define DL_END				0x0004

#define DL_TYPE_CLM			2

int PacketUploadCLM(struct SDIO *sdio)
{
    struct ExecBase *SysBase = sdio->s_SysBase;
    struct WiFiBase *WiFiBase = sdio->s_WiFiBase;

    // Check if there is CLM to be uploaded
    if (sdio->s_Chip->c_CLMBase && sdio->s_Chip->c_CLMSize)
    {
        LONG dataLen = sdio->s_Chip->c_CLMSize;
        UBYTE *data = sdio->s_Chip->c_CLMBase;
        UWORD flag = DL_BEGIN | (DLOAD_HANDLER_VER << DLOAD_FLAG_VER_SHIFT);

        struct UploadHeader {
            UWORD flag;
            UWORD dload_type;
            ULONG len;
            ULONG crc;
            UBYTE data[];
        };

        struct UploadHeader *upload = AllocPooled(WiFiBase->w_MemPool, sizeof(struct UploadHeader) + MAX_CHUNK_LEN);
        ULONG err = 0;

        if (upload)
        {
            // Upload CLM in chunks of size MAX_CHUNK_LEN
            do {
                ULONG transferLen; 

                if (dataLen > MAX_CHUNK_LEN) {
                    transferLen = MAX_CHUNK_LEN;
                }
                else {
                    transferLen = dataLen;
                    flag |= DL_END;
                }

                CopyMem(data, &upload->data[0], transferLen);

                upload->flag = LE16(flag);
                upload->dload_type = LE16(DL_TYPE_CLM);
                upload->len = LE32(transferLen);
                upload->crc = 0;

                err = PacketSetVar(sdio, "clmload", upload, sizeof(struct UploadHeader) + transferLen);
                /* a firmware that stopped answering is not asked again, chunk
                   after chunk, 2.5 s each (#93); its refusals are ignored as before */
                if (PACKET_CTRL_DEAD(err))
                    break;

                dataLen -= transferLen;
                data += transferLen;

                flag &= ~DL_BEGIN;
            } while (dataLen > 0);

            FreePooled(WiFiBase->w_MemPool, upload, sizeof(struct UploadHeader) + MAX_CHUNK_LEN);
            if (PACKET_CTRL_DEAD(err))
                return err;
        }

        //D(bug("[WiFi] CLM upload complete. Getting status\n"));
        //PacketGetVar(sdio, "clmload_status", NULL, 32);
    }
    else
    {
        D(bug("[WiFi] No CLM to upload\n"));
    }

    return 1;
}

void StartNetworkScan(struct IOSana2Req *io)
{
    struct WiFiUnit *unit = (APTR)io->ios2_Req.io_Unit;
    struct WiFiBase *base = unit->wu_Base;
    struct ExecBase *SysBase = base->w_SysBase;
    struct Library *UtilityBase = base->w_UtilityBase;
    struct SDIO *sdio = base->w_SDIO;
    UBYTE *networkName = NULL;
    struct TagItem *tags = io->ios2_StatData;

    /* THis needs to be gone! The paramsv2 layout is known... */
    static const UBYTE params[4+2+2+4+32+6+1+1+4*4+2+2+14*2+32+4] = {
        1,0,0,0,
        1,0,
        0x34,0x12,
        0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0xff,0xff,0xff,0xff,0xff,0xff,
        2,
        0,
        0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,
        14,0,
        0,0,
        0x01,0x2b,0x02,0x2b,0x03,0x2b,0x04,0x2b,0x05,0x2e,0x06,0x2e,0x07,0x2e,
        0x08,0x2b,0x09,0x2b,0x0a,0x2b,0x0b,0x2b,0x0c,0x2b,0x0d,0x2b,0x0e,0x2b,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    };
    UBYTE buf[sizeof(params)];      /* the receiver's stack, not w_MemPool (#94) */
    UBYTE *data = (UBYTE*)params;
    
    D(bug("[WiFi] StartNetworkScan("));

    /* If tags were passed check if S2INFO_SSID was set */
    if (tags != NULL) {
        networkName = (UBYTE*)GetTagData(S2INFO_SSID, 0, tags);
    }

    if (networkName) D(bug(networkName));
    
    D(bug(")\n"));

    if (networkName)
    {
        ULONG len = _strlen(networkName);
        data = buf;

        if (len > 32) len = 32;

        CopyMem((const APTR)params, data, sizeof(params));
        
        data[8] = len;
        for (int i=0; i < data[8]; i++)
            data[12 + i] = networkName[i];
    }

    io->ios2_DataLength = 0;
    io->ios2_StatData = NULL;

    unit->wu_ScanRequest = io;

    PacketCmdIntAsync(sdio, BRCMF_C_SET_PASSIVE_SCAN, 0);
    PacketSetVarAsync(sdio, "escan", data, sizeof(params));
}

#if 0
static void StartScannerTask(struct SDIO *sdio)
{
    struct WiFiBase *WiFiBase = sdio->s_WiFiBase;
    struct ExecBase *SysBase = sdio->s_SysBase;
    APTR entry = (APTR)NetworkScanner;
    struct Task *task;
    struct MemList *ml;
    ULONG *stack;

    static const char task_name[] = WIFIPI_TASK_SCANNER;
    D(bug("[WiFi] Starting network scanner\n"));

    // Get all memory we need for the receiver task
    task = AllocMem(sizeof(struct Task), MEMF_PUBLIC | MEMF_CLEAR);
    ml = AllocMem(sizeof(struct MemList) + sizeof(struct MemEntry), MEMF_PUBLIC | MEMF_CLEAR);
    stack = AllocMem(SCANNER_STACKSIZE * sizeof(ULONG), MEMF_PUBLIC | MEMF_CLEAR);

    // Prepare mem list, put task and its stack there
    ml->ml_NumEntries = 2;
    ml->ml_ME[0].me_Un.meu_Addr = task;
    ml->ml_ME[0].me_Length = sizeof(struct Task);

    ml->ml_ME[1].me_Un.meu_Addr = &stack[0];
    ml->ml_ME[1].me_Length = SCANNER_STACKSIZE * sizeof(ULONG);

    // Task's UserData will contain pointer to SDIO
    task->tc_UserData = sdio;

    // Set up stack
    task->tc_SPLower = &stack[0];
    task->tc_SPUpper = &stack[SCANNER_STACKSIZE];

    // Push ThisTask and SDIO on the stack
    stack = (ULONG *)task->tc_SPUpper;
    *--stack = (ULONG)sdio;
    task->tc_SPReg = stack;

    task->tc_Node.ln_Name = (char *)task_name;
    task->tc_Node.ln_Type = NT_TASK;
    task->tc_Node.ln_Pri = SCANNER_PRIORITY;

    NewMinList((struct MinList *)&task->tc_MemEntry);
    AddHead(&task->tc_MemEntry, &ml->ml_Node);

    D(bug("[WiFi] Bringing scanner to life\n"));

    sdio->s_ScannerTask = AddTask(task, entry, NULL);
}
#endif
void StartPacketReceiver(struct SDIO *sdio)
{
    struct ExecBase *SysBase = sdio->s_SysBase;
    APTR entry = (APTR)PacketReceiver;
    struct Task *task;
    struct MemList *ml;
    ULONG *stack;
    static const char task_name[] = WIFIPI_TASK_RECEIVER;

    D(bug("[WiFi] Starting packet receiver task\n"));

    // Get all memory we need for the receiver task
    task = AllocMem(sizeof(struct Task), MEMF_PUBLIC | MEMF_CLEAR);
    ml = AllocMem(sizeof(struct MemList) + sizeof(struct MemEntry), MEMF_PUBLIC | MEMF_CLEAR);
    stack = AllocMem(PACKET_RECV_STACKSIZE * sizeof(ULONG), MEMF_PUBLIC | MEMF_CLEAR);

    // Prepare mem list, put task and its stack there
    ml->ml_NumEntries = 2;
    ml->ml_ME[0].me_Un.meu_Addr = task;
    ml->ml_ME[0].me_Length = sizeof(struct Task);

    ml->ml_ME[1].me_Un.meu_Addr = &stack[0];
    ml->ml_ME[1].me_Length = PACKET_RECV_STACKSIZE * sizeof(ULONG);

    // Task's UserData will contain pointer to SDIO
    task->tc_UserData = sdio;

    // Set up stack
    task->tc_SPLower = &stack[0];
    task->tc_SPUpper = &stack[PACKET_RECV_STACKSIZE];

    // Push ThisTask and SDIO on the stack
    stack = (ULONG *)task->tc_SPUpper;
    *--stack = (ULONG)FindTask(NULL);
    *--stack = (ULONG)sdio;
    task->tc_SPReg = stack;

    task->tc_Node.ln_Name = (char*)task_name;
    task->tc_Node.ln_Type = NT_TASK;
    task->tc_Node.ln_Pri = PACKET_RECV_PRIORITY;

    _NewList((struct MinList *)&task->tc_MemEntry);
    AddHead(&task->tc_MemEntry, &ml->ml_Node);

    D(bug("[WiFi] Bringing packet receiver to life\n"));

    AddTask(task, entry, NULL);
    Wait(SIGBREAKF_CTRL_C);

    //StartScannerTask(sdio);

    if (sdio->s_ReceiverTask)
        D(bug("[WiFi] Packet receiver up and running\n"));
    else
        D(bug("[WiFi] Packet receiver not started!\n"));

#if 0
    UBYTE s_HWAddr[6];
    PacketGetVar(sdio, "cur_etheraddr", s_HWAddr, 6);

    D(bug("[WiFi] Ethernet addr: %02lx:%02lx:%02lx:%02lx:%02lx:%02lx\n",
        s_HWAddr[0], s_HWAddr[1], s_HWAddr[2],
        s_HWAddr[3], s_HWAddr[4], s_HWAddr[5]));

    ULONG d11Type = 0;
    static const char * const types[]= { "UNKNOWN", "N", "AC" };
    if (0 == PacketCmdIntGet(sdio, BRCMF_C_GET_VERSION, &d11Type))
    {
        D(bug("[WiFi] D11 Version: %s\n", (ULONG)types[d11Type]));
        sdio->s_Chip->c_D11Type = d11Type;
    }

    PacketUploadCLM(sdio);

    PacketSetVarInt(sdio, "assoc_listen", 10);

    if (sdio->s_Chip->c_ChipID == BRCM_CC_43430_CHIP_ID || sdio->s_Chip->c_ChipID == BRCM_CC_4345_CHIP_ID)
    {
        PacketCmdInt(sdio, 0x56, 0);
    }
    else
    {
        PacketCmdInt(sdio, 0x56, 2);
    }

    PacketSetVarInt(sdio, "bus:txglom", 0);
    PacketSetVarInt(sdio, "bcn_timeout", 10);
    PacketSetVarInt(sdio, "assoc_retry_max", 3);

    /* Pepare event mask. Allow only events which are really needed */
    UBYTE ev_mask[(BRCMF_E_LAST + 7) / 8];
    for (int i=0; i < (BRCMF_E_LAST + 7) / 8; i++) ev_mask[i] = 0;

#define EVENT_BIT(mask, i) (mask)[(i) / 8] |= 1 << ((i) % 8)
#define EVENT_BIT_CLEAR(mask, i) (mask)[(i) / 8] &= ~(1 << ((i) % 8))
    EVENT_BIT(ev_mask, BRCMF_E_IF);
    EVENT_BIT(ev_mask, BRCMF_E_LINK);
    EVENT_BIT(ev_mask, BRCMF_E_AUTH);
    EVENT_BIT(ev_mask, BRCMF_E_ASSOC);
    EVENT_BIT(ev_mask, BRCMF_E_DEAUTH);
    EVENT_BIT(ev_mask, BRCMF_E_DISASSOC);
    EVENT_BIT(ev_mask, BRCMF_E_ESCAN_RESULT);
    EVENT_BIT_CLEAR(ev_mask, 124);
#undef EVENT_BIT

    PacketSetVar(sdio, "event_msgs", ev_mask, (BRCMF_E_LAST + 7) / 8);

    PacketCmdInt(sdio, BRCMF_C_SET_SCAN_CHANNEL_TIME, 40);
    PacketCmdInt(sdio, BRCMF_C_SET_SCAN_UNASSOC_TIME, 40);
    PacketCmdInt(sdio, BRCMF_C_SET_SCAN_PASSIVE_TIME, 120);

    PacketCmdInt(sdio, BRCMF_C_UP, 0);

    char ver[128];
    for (int i=0; i < 128; i++) ver[i] = 0;
    PacketGetVar(sdio, "ver", ver, 128);

    // Remove \r and \n from version string. Replace first found with 0
    for (int i=0; i < 128; i++) { if (ver[i] == 13 || ver[i] == 10) { ver[i] = 0; break; } }
    D(bug("[WiFi] Firmware version: %s\n", (ULONG)ver));

    PacketSetVarInt(sdio, "roam_off", 1);

    PacketCmdInt(sdio, BRCMF_C_SET_INFRA, 1);
    PacketCmdInt(sdio, BRCMF_C_SET_PROMISC, 0);
    PacketCmdInt(sdio, BRCMF_C_UP, 1);

    StartNetworkScan(sdio);

void delay_us(ULONG us, struct WiFiBase *WiFiBase)
{
    (void)WiFiBase;
    ULONG timer = LE32(*(volatile ULONG*)0xf2003004);
    ULONG end = timer + us;

    if (end < timer) {
        while (end < LE32(*(volatile ULONG*)0xf2003004)) asm volatile("nop");
    }
    while (end > LE32(*(volatile ULONG*)0xf2003004)) asm volatile("nop");
}
delay_us(5000000, sdio->s_WiFiBase);

    ObtainSemaphore(&sdio->s_WiFiBase->w_NetworkListLock);
    struct WiFiNetwork *network;
    UBYTE found = 0;
    ForeachNode(&sdio->s_WiFiBase->w_NetworkList, network)
    {
        if (_strncmp("pistorm", network->wn_SSID, 32) == 0)
        {
            found = 1;
            Connect(sdio, network);
        }
    }
    ReleaseSemaphore(&sdio->s_WiFiBase->w_NetworkListLock);

    if (!found)
    {
        Connect(sdio, NULL);
    }
#endif
#if 0

delay_us(5000000, sdio->s_WiFiBase);
    PacketCmdInt(sdio, 49, 0);
    PacketSetVar(sdio, "escan", params, sizeof(params));


delay_us(5000000, sdio->s_WiFiBase);
    PacketCmdInt(sdio, 49, 0);
    PacketSetVar(sdio, "escan", params, sizeof(params));
#endif

#if 0

    UBYTE pkt[256];
    for (int i=0; i < 256; i++) pkt[i] = 0;
    struct Packet *p = (struct Packet *)&pkt[0];
    struct PacketCmd *c = (struct PacketCmd *)&pkt[12];
    char cmd[] = "cur_etheraddr";
    

    p->p_Length = LE16(12 + 16 + 32); //sizeof(cmd));
    p->c_ChkSum = ~p->p_Length;
    p->c_DataOffset = sizeof(struct Packet);
    p->c_FlowControl = 0;
    p->c_Seq = 0;
    c->c_Command = LE32(262);   // GetVar
    c->c_Length = LE32(32); //sizeof(cmd));     // Length
    c->c_Flags = 0;
    c->c_ID = LE16(1);
    c->c_Status = 0;
    
    CopyMem(cmd, &pkt[sizeof(struct Packet) + sizeof(struct PacketCmd)], sizeof(cmd));
    D(bug("[WiFi] Packet: \n"));
    for (int i=0; i < LE16(p->p_Length); i++)
    {
        if (i % 16 == 0)
            bug("[WiFi]  ");
        bug(" %02lx", pkt[i]);
        if (i % 16 == 15)
            bug("\n");
    }
    if (LE16(p->p_Length) % 16 != 0) bug("\n");

    sdio->SendPKT(pkt, LE16(p->p_Length), sdio);

#endif

#if 0

    for (int i=0; i < 256; i++) pkt[i] = 0;
    p->p_Length = LE16(12 + 16 + 4);
    p->c_ChkSum = ~p->p_Length;
    p->c_DataOffset = sizeof(struct Packet);
    p->c_FlowControl = 0;
    p->c_Seq = 1;
    c->c_Command = LE32(49);   // GetVar
    c->c_Length = LE32(4);     // Length
    c->c_Flags = LE16(2);
    c->c_ID = LE16(2);
    c->c_Status = 0;

    pkt[sizeof(struct Packet) + sizeof(struct PacketCmd)] = 0;
    pkt[sizeof(struct Packet) + sizeof(struct PacketCmd)+1] = 0;
    pkt[sizeof(struct Packet) + sizeof(struct PacketCmd)+2] = 0;
    pkt[sizeof(struct Packet) + sizeof(struct PacketCmd)+3] = 0;

    D(bug("[WiFi] Packet: \n"));
    for (int i=0; i < LE16(p->p_Length); i++)
    {
        if (i % 16 == 0)
            bug("[WiFi]  ");
        bug(" %02lx", pkt[i]);
        if (i % 16 == 15)
            bug("\n");
    }
    if (LE16(p->p_Length) % 16 != 0) bug("\n");

    sdio->SendPKT(pkt, LE16(p->p_Length), sdio);

    for (int i=0; i < 256; i++) pkt[i] = 0;

    p->p_Length = LE16(12 + 16 + sizeof(cmd2) + sizeof(params));
    p->c_ChkSum = ~p->p_Length;
    p->c_DataOffset = sizeof(struct Packet);
    p->c_FlowControl = 0;
    p->c_Seq = 2;
    c->c_Command = LE32(263);   // SetVar
    c->c_Length = LE32(sizeof(cmd2) + sizeof(params));     // Length
    c->c_Flags = LE16(2);
    c->c_ID = LE16(3);
    c->c_Status = 0;
    
    CopyMem(cmd2, &pkt[sizeof(struct Packet) + sizeof(struct PacketCmd)], sizeof(cmd2));
    CopyMem(params, &pkt[sizeof(struct Packet) + sizeof(struct PacketCmd) + sizeof(cmd2)], sizeof(params));
    
    D(bug("[WiFi] Packet: \n"));
    for (int i=0; i < LE16(p->p_Length); i++)
    {
        if (i % 16 == 0)
            bug("[WiFi]  ");
        bug(" %02lx", pkt[i]);
        if (i % 16 == 15)
            bug("\n");
    }
    if (LE16(p->p_Length) % 16 != 0) bug("\n");

    sdio->SendPKT(pkt, LE16(p->p_Length), sdio);

    #endif
}

/*
 * Debug-only boot-time firmware record (AmiNetXDuo #89).  Compiled in only
 * with -DWIFIPI_FWINFO, which needs -DWIFIPI_RINGTRACE.
 *
 * What was loaded and how it went, kept in struct Chip for the driver's
 * life and returned whole by private command 0xF08E (tools/fwinfo.c):
 *   - the firmware directory used: DEVS:Firmware, or ENV:WiFiPi/FirmwareDir
 *     when that variable exists.  The directory is chosen once, before the
 *     first file, and all three files (bin, clm_blob, txt) come from it; a
 *     file missing there fails the load, never a fall back to DEVS:.  A
 *     variable that is not an absolute path (no ':') or does not fit fails
 *     the load too.
 *   - the loaded firmware's size and CRC-32 (IEEE, as zlib crc32()).
 *   - every 'clmload' chunk: how many were sent, the first non-zero result
 *     and its chunk index; then 'clmload_status' (value and rc), asked for
 *     after the last chunk.  Linux brcmfmac (common.c brcmf_c_download_blob)
 *     and bcmdhd (dhd_common.c) read clmload_status only after a failed
 *     clmload and only print it; bcmdhd names one value, 8 CHIPID_MISMATCH.
 *     No source defines the others: 0 is reported as ok-by-implication and
 *     anything else as undocumented.
 *   - the firmware's 'ver' string, CR/LF cut, at most 127 characters.
 * An RT_FWINFO ring record is written when the version has been read.
 *
 * The pure part below makes no Exec or DOS calls; a host test links it as
 * is.  Types come from the includer.
 */
#ifndef WIFIPI_FWINFO_H
#define WIFIPI_FWINFO_H

#if defined(WIFIPI_FWINFO) && !defined(WIFIPI_RINGTRACE)
#error "WIFIPI_FWINFO needs WIFIPI_RINGTRACE"
#endif

#define WIFIPI_CMD_FWINFO   0xF08E
#define RT_FWINFO           30      /* clo; a flags, b clmload_status (low 16), c firmware bytes, d CRC-32 */
#define FWI_MAGIC           0x46574931UL    /* 'FWI1' */
#define FWI_VERSION         1
#define FWI_DEFAULT_DIR     "DEVS:Firmware"
#define FWI_ENV_NAME        "WiFiPi/FirmwareDir"
#define FWI_DIR_MAX         64
#define FWI_ENV_BUF         128     /* GetVar() buffer; a value filling it was cut off */
#define FWI_VER_MAX         128
#define FWI_NO_CHUNK        0xffffffffUL
#define FWI_CHIPID_MISMATCH 8           /* bcmdhd dhd_common.c CHIPID_MISMATCH */

/* fi_Flags */
#define FWI_F_ALTDIR        0x01    /* ENV:WiFiPi/FirmwareDir used */
#define FWI_F_DIRBAD        0x02    /* the variable was there but unusable: load failed */
#define FWI_F_LOADED        0x04    /* all three files read */
#define FWI_F_CLMSENT       0x08    /* clmload chunks sent */
#define FWI_F_CLMSTATUS     0x10    /* clmload_status asked */
#define FWI_F_VER           0x20    /* ver asked */

struct FwInfo {
    ULONG   fi_Magic;
    UWORD   fi_Version;
    UWORD   fi_Size;                /* sizeof(struct FwInfo) */
    ULONG   fi_Flags;
    ULONG   fi_FwSize;              /* firmware bytes loaded */
    ULONG   fi_FwCrc32;
    ULONG   fi_ClmSize;
    ULONG   fi_ClmChunks;           /* clmload SETs made (last upload) */
    ULONG   fi_ClmFirstErr;         /* first non-zero clmload result, 0 none */
    ULONG   fi_ClmFirstErrChunk;    /* its chunk index, FWI_NO_CHUNK none */
    ULONG   fi_ClmStatus;           /* clmload_status value */
    LONG    fi_ClmStatusRc;         /* the GET's result */
    LONG    fi_VerRc;               /* the 'ver' GET's result */
    ULONG   fi_ClmUploads;          /* CLM uploads made (each init path counts) */
    ULONG   fi_Reserved[3];
    char    fi_Dir[FWI_DIR_MAX];    /* NUL-terminated */
    char    fi_Ver[FWI_VER_MAX];    /* NUL-terminated */
};

_Static_assert(sizeof(struct FwInfo) == 256, "struct FwInfo is 256 bytes");

static inline void fwi_init(struct FwInfo *fi)
{
    ULONG i;
    UBYTE *p = (UBYTE *)fi;

    for (i = 0; i < sizeof(*fi); i++)
        p[i] = 0;
    fi->fi_Magic = FWI_MAGIC;
    fi->fi_Version = FWI_VERSION;
    fi->fi_Size = sizeof(*fi);
    fi->fi_ClmFirstErrChunk = FWI_NO_CHUNK;
}

/* CRC-32, IEEE 802.3, reflected, as zlib crc32(crc, buf, len); start with 0 */
static inline ULONG fwi_crc32(ULONG crc, const UBYTE *p, ULONG len)
{
    ULONG i;
    int k;

    crc = ~crc;
    for (i = 0; i < len; i++)
    {
        crc ^= p[i];
        for (k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320UL & (0UL - (crc & 1)));
    }
    return ~crc;
}

enum { FWI_DIR_DEFAULT = 0, FWI_DIR_ALT = 1, FWI_DIR_BAD = -1 };

/* The directory to load from.  env/envLen: GetVar()'s buffer and result
   (-1: no such variable; FWI_ENV_BUF or more: cut off, refused unread).
   dir gets FWI_DIR_MAX bytes, always terminated. */
static inline int fwi_resolve(const char *env, LONG envLen, char *dir)
{
    static const char def[] = FWI_DEFAULT_DIR;
    LONG n = envLen, i;
    int colon = 0;

    if (envLen < 0)
    {
        for (i = 0; i < (LONG)sizeof(def); i++)
            dir[i] = def[i];
        return FWI_DIR_DEFAULT;
    }
    dir[0] = 0;
    if (envLen >= FWI_ENV_BUF)
        return FWI_DIR_BAD;
    while (n > 0 && (env[n - 1] == '\n' || env[n - 1] == '\r' || env[n - 1] == ' ' || env[n - 1] == '\t'))
        n--;
    dir[0] = 0;
    if (n <= 0 || n >= FWI_DIR_MAX)
        return FWI_DIR_BAD;
    for (i = 0; i < n; i++)
    {
        if (env[i] == 0)
            return FWI_DIR_BAD;
        if (env[i] == ':')
            colon = 1;
    }
    if (!colon)
        return FWI_DIR_BAD;         /* relative: would be taken from wherever */
    for (i = 0; i < n; i++)
        dir[i] = env[i];
    dir[n] = 0;
    return FWI_DIR_ALT;
}

/* dir + file, as AddPart() joins them ("A:" + f -> "A:f", "A:b" + f ->
   "A:b/f", "A:b/" + f -> "A:b/f").  0 when it does not fit in size. */
static inline int fwi_join(const char *dir, const char *file, char *out, ULONG size)
{
    ULONG n = 0, i;

    for (i = 0; dir[i]; i++)
    {
        if (n + 1 >= size)
            return 0;
        out[n++] = dir[i];
    }
    if (n > 0 && out[n - 1] != ':' && out[n - 1] != '/')
    {
        if (n + 1 >= size)
            return 0;
        out[n++] = '/';
    }
    for (i = 0; file[i]; i++)
    {
        if (n + 1 >= size)
            return 0;
        out[n++] = file[i];
    }
    out[n] = 0;
    return 1;
}

/* One clmload chunk's result */
static inline void fwi_clm_chunk(struct FwInfo *fi, ULONG index, ULONG err)
{
    fi->fi_Flags |= FWI_F_CLMSENT;
    fi->fi_ClmChunks = index + 1;
    if (err != 0 && fi->fi_ClmFirstErrChunk == FWI_NO_CHUNK)
    {
        fi->fi_ClmFirstErr = err;
        fi->fi_ClmFirstErrChunk = index;
    }
}

/* A new CLM upload begins: the chunk record is the last upload's */
static inline void fwi_clm_begin(struct FwInfo *fi, ULONG clmSize)
{
    fi->fi_ClmUploads++;
    fi->fi_ClmSize = clmSize;
    fi->fi_ClmChunks = 0;
    fi->fi_ClmFirstErr = 0;
    fi->fi_ClmFirstErrChunk = FWI_NO_CHUNK;
}

static inline void fwi_clm_status(struct FwInfo *fi, ULONG value, LONG rc)
{
    fi->fi_Flags |= FWI_F_CLMSTATUS;
    fi->fi_ClmStatus = value;
    fi->fi_ClmStatusRc = rc;
}

/* The 'ver' answer: up to the first CR or LF, at most FWI_VER_MAX - 1 */
static inline void fwi_ver(struct FwInfo *fi, const char *ver, ULONG len, LONG rc)
{
    ULONG i;

    fi->fi_Flags |= FWI_F_VER;
    fi->fi_VerRc = rc;
    for (i = 0; i < len && i < FWI_VER_MAX - 1 && ver[i] && ver[i] != '\r' && ver[i] != '\n'; i++)
        fi->fi_Ver[i] = ver[i];
    for (; i < FWI_VER_MAX; i++)
        fi->fi_Ver[i] = 0;
}

#endif /* WIFIPI_FWINFO_H */

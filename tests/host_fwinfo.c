/*
 * Host test for the boot-time firmware record (src/fwinfo.h, #89): plain
 * cc.  Packing of struct FwInfo, CRC-32, the firmware directory choice
 * (ENV:WiFiPi/FirmwareDir or DEVS:Firmware, and a missing file in the
 * chosen one failing the load), path joining, clmload tracking, 'ver'.
 *
 *   cc -std=c11 -O1 -g -fsanitize=address,undefined -Wall -Wextra -Werror \
 *      -DWIFIPI_RINGTRACE -o host_fwinfo tests/host_fwinfo.c
 *   ./host_fwinfo [FILE]   -> "RESULT host_fwinfo checks=N failures=0"
 *   (FILE: also print its CRC-32 as fwinfo computes it)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

typedef uint8_t UBYTE;
typedef uint16_t UWORD;
typedef uint32_t ULONG;
typedef int32_t LONG;

#include "../src/fwinfo.h"

static int checks, failures;
#define EXPECT(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

static int resolve(const char *env, char *dir)
{
    return fwi_resolve(env, env ? (LONG)strlen(env) : -1, dir);
}

/* LoadFirmware's order: bin, clm_blob, txt, each from the one directory;
   the first that cannot be opened fails the load.  Returns the files read,
   -1 on failure; *tried gets the last path tried. */
static const char *present[8];
static int exists(const char *path)
{
    for (int i = 0; present[i]; i++)
        if (strcmp(present[i], path) == 0) return 1;
    return 0;
}

static int load(const char *env, char *tried)
{
    static const char *files[3] = { "cyfmac43455-sdio.bin", "cyfmac43455-sdio.clm_blob", "brcmfmac43455-sdio.txt" };
    char dir[FWI_DIR_MAX], path[256];
    if (fwi_resolve(env, env ? (LONG)strlen(env) : -1, dir) == FWI_DIR_BAD)
        return -1;
    for (int i = 0; i < 3; i++)
    {
        if (!fwi_join(dir, files[i], path, 255))
            return -1;
        strcpy(tried, path);
        if (!exists(path))
            return -1;
    }
    return 3;
}

int main(int argc, char **argv)
{
    struct FwInfo fi;
    char dir[FWI_DIR_MAX], out[256], tried[256];

    /* packing: the tool and the driver share it */
    EXPECT(sizeof(struct FwInfo) == 256);
    EXPECT(offsetof(struct FwInfo, fi_Flags) == 8 && offsetof(struct FwInfo, fi_FwCrc32) == 16);
    EXPECT(offsetof(struct FwInfo, fi_ClmStatus) == 36 && offsetof(struct FwInfo, fi_ClmUploads) == 48);
    EXPECT(offsetof(struct FwInfo, fi_Dir) == 64 && offsetof(struct FwInfo, fi_Ver) == 128);
    fwi_init(&fi);
    EXPECT(fi.fi_Magic == 0x46574931u && fi.fi_Version == 1 && fi.fi_Size == 256 && fi.fi_Flags == 0);
    EXPECT(fi.fi_ClmFirstErrChunk == FWI_NO_CHUNK && fi.fi_Dir[0] == 0 && fi.fi_Ver[0] == 0);

    /* CRC-32: the check value, and in pieces */
    EXPECT(fwi_crc32(0, (const UBYTE *)"123456789", 9) == 0xCBF43926u);
    EXPECT(fwi_crc32(0, (const UBYTE *)"", 0) == 0);
    EXPECT(fwi_crc32(fwi_crc32(0, (const UBYTE *)"1234", 4), (const UBYTE *)"56789", 5) == 0xCBF43926u);
    EXPECT(fwi_crc32(0, (const UBYTE *)"The quick brown fox jumps over the lazy dog", 43) == 0x414FA339u);

    /* directory choice */
    EXPECT(resolve(NULL, dir) == FWI_DIR_DEFAULT && strcmp(dir, "DEVS:Firmware") == 0);
    EXPECT(resolve("RAM:fw286", dir) == FWI_DIR_ALT && strcmp(dir, "RAM:fw286") == 0);
    EXPECT(resolve("DH0:Firmware/7.45.286\n", dir) == FWI_DIR_ALT && strcmp(dir, "DH0:Firmware/7.45.286") == 0);
    EXPECT(resolve("RAM:  \r\n", dir) == FWI_DIR_ALT && strcmp(dir, "RAM:") == 0);
    EXPECT(resolve("fw286", dir) == FWI_DIR_BAD && dir[0] == 0);        /* relative */
    EXPECT(resolve("", dir) == FWI_DIR_BAD);
    EXPECT(resolve(" \n", dir) == FWI_DIR_BAD);
    {
        char longv[FWI_ENV_BUF];
        memset(longv, 'a', sizeof(longv));
        memcpy(longv, "DH0:", 4);
        longv[63] = 0;
        EXPECT(resolve(longv, dir) == FWI_DIR_ALT && strlen(dir) == 63);
        longv[63] = 'a'; longv[64] = 0;
        EXPECT(resolve(longv, dir) == FWI_DIR_BAD);                     /* 64: does not fit */
        EXPECT(fwi_resolve("RAM:x\0y", 7, dir) == FWI_DIR_BAD);         /* a NUL inside */
        memset(longv, 'a', sizeof(longv));
        memcpy(longv, "DH0:", 4);
        EXPECT(fwi_resolve(longv, FWI_ENV_BUF, dir) == FWI_DIR_BAD && dir[0] == 0);   /* GetVar cut it off */
    }

    /* joining, as AddPart */
    EXPECT(fwi_join("DEVS:Firmware", "a.bin", out, 255) && strcmp(out, "DEVS:Firmware/a.bin") == 0);
    EXPECT(fwi_join("RAM:", "a.bin", out, 255) && strcmp(out, "RAM:a.bin") == 0);
    EXPECT(fwi_join("RAM:fw/", "a.bin", out, 255) && strcmp(out, "RAM:fw/a.bin") == 0);
    EXPECT(!fwi_join("RAM:fw", "a.bin", out, 8) && fwi_join("RAM:fw", "a.bin", out, 13) && strcmp(out, "RAM:fw/a.bin") == 0);

    /* loading: the stock directory, the alternate, and a missing file there
       failing the load with no second try in DEVS: */
    present[0] = "DEVS:Firmware/cyfmac43455-sdio.bin";
    present[1] = "DEVS:Firmware/cyfmac43455-sdio.clm_blob";
    present[2] = "DEVS:Firmware/brcmfmac43455-sdio.txt";
    present[3] = "RAM:fw286/cyfmac43455-sdio.bin";
    present[4] = "RAM:fw286/brcmfmac43455-sdio.txt";                 /* no clm_blob in RAM:fw286 */
    present[5] = NULL;
    EXPECT(load(NULL, tried) == 3 && strcmp(tried, "DEVS:Firmware/brcmfmac43455-sdio.txt") == 0);
    EXPECT(load("RAM:fw286", tried) == -1 && strcmp(tried, "RAM:fw286/cyfmac43455-sdio.clm_blob") == 0);
    present[5] = "RAM:fw286/cyfmac43455-sdio.clm_blob";
    present[6] = NULL;
    EXPECT(load("RAM:fw286", tried) == 3 && strcmp(tried, "RAM:fw286/brcmfmac43455-sdio.txt") == 0);
    EXPECT(load("fw286", tried) == -1);                               /* relative: refused, no DEVS: */
    EXPECT(load("RAM:empty", tried) == -1 && strcmp(tried, "RAM:empty/cyfmac43455-sdio.bin") == 0);

    /* clmload tracking */
    fwi_init(&fi);
    fwi_clm_begin(&fi, 7000);
    {
        static const ULONG errs[5] = { 0, 0, 0xffffffe9u, 0xffffffffu, 0 };
        for (ULONG i = 0; i < 5; i++)
            fwi_clm_chunk(&fi, i, errs[i]);
    }
    EXPECT(fi.fi_ClmChunks == 5 && fi.fi_ClmFirstErr == 0xffffffe9u && fi.fi_ClmFirstErrChunk == 2);
    EXPECT(fi.fi_ClmSize == 7000 && fi.fi_ClmUploads == 1 && (fi.fi_Flags & FWI_F_CLMSENT));
    fwi_clm_status(&fi, 8, 0);
    EXPECT(fi.fi_ClmStatus == 8 && fi.fi_ClmStatusRc == 0 && (fi.fi_Flags & FWI_F_CLMSTATUS));
    fwi_clm_begin(&fi, 7000);                       /* a second init path: the last upload's record */
    fwi_clm_chunk(&fi, 0, 0);
    fwi_clm_chunk(&fi, 1, 0);
    EXPECT(fi.fi_ClmUploads == 2 && fi.fi_ClmChunks == 2 && fi.fi_ClmFirstErr == 0 && fi.fi_ClmFirstErrChunk == FWI_NO_CHUNK);

    /* ver: cut at CR/LF, at most 127 characters, always terminated */
    fwi_ver(&fi, "wl0: Oct 19 2023 7.45.286 (r1001) FWID 01-a9c7d9f7\r\nmore", 128, 0);
    EXPECT(strcmp(fi.fi_Ver, "wl0: Oct 19 2023 7.45.286 (r1001) FWID 01-a9c7d9f7") == 0 && fi.fi_VerRc == 0);
    {
        char big[200];
        memset(big, 'v', sizeof(big));
        fwi_ver(&fi, big, 128, -1);
        EXPECT(strlen(fi.fi_Ver) == 127 && fi.fi_VerRc == -1 && (fi.fi_Flags & FWI_F_VER));
    }

    if (argc > 1)
    {
        FILE *f = fopen(argv[1], "rb");
        if (f)
        {
            fseek(f, 0, SEEK_END);
            long n = ftell(f);
            fseek(f, 0, SEEK_SET);
            UBYTE *b = malloc(n);
            if (fread(b, 1, n, f) == (size_t)n)
                printf("CRC32 %s size=%ld crc32=0x%08x\n", argv[1], n, (unsigned)fwi_crc32(0, b, n));
            free(b);
            fclose(f);
        }
    }
    printf("RESULT host_fwinfo checks=%d failures=%d\n", checks, failures);
    return failures != 0;
}

/*
 * Firmware upload plan: the image goes to the chip in
 * 64-byte backplane writes, each rounded up to 4 bytes.  The image buffer
 * is allocated at the file's exact size, so a last chunk whose length is
 * not a multiple of 4 must not be written from it: it is copied into a
 * zeroed buffer first, and the chip gets the file's bytes and 1-3 zeros.
 * Every other chunk is written from the image as before, at the same
 * offsets and lengths.
 *
 * Pure: no Exec calls, so a host test runs it as is.  Types come from the
 * includer.
 */
#ifndef WIFIPI_FWUPLOAD_H
#define WIFIPI_FWUPLOAD_H

#define FW_CHUNK 64

struct FwChunk {
    ULONG   fc_Off;     /* offset in the image and on the chip */
    ULONG   fc_Raw;     /* image bytes in this chunk */
    ULONG   fc_Len;     /* bytes written: fc_Raw rounded up to 4 */
    int     fc_Tail;    /* fc_Raw is not a multiple of 4: write from a copy */
};

/* The chunk that starts at pos, 0 when the image ends before it */
static inline int fw_chunk(ULONG size, ULONG pos, struct FwChunk *c)
{
    ULONG raw;

    if (pos >= size)
        return 0;
    raw = size - pos;
    if (raw > FW_CHUNK)
        raw = FW_CHUNK;
    c->fc_Off = pos;
    c->fc_Raw = raw;
    c->fc_Len = (raw + 3) & ~3UL;
    c->fc_Tail = (raw & 3) != 0;
    return 1;
}

typedef void (*fw_write_fn)(void *ctx, ULONG off, const UBYTE *src, ULONG len);

/* Write the whole image; returns the bytes written (size rounded up to 4) */
static inline ULONG fw_upload(const UBYTE *bin, ULONG size, fw_write_fn write, void *ctx)
{
    ULONG tail[FW_CHUNK / 4];       /* longword-aligned, as the image is */
    struct FwChunk c;
    ULONG pos = 0, i;

    while (fw_chunk(size, pos, &c))
    {
        const UBYTE *src = &bin[c.fc_Off];

        if (c.fc_Tail)
        {
            UBYTE *t = (UBYTE *)tail;
            for (i = 0; i < c.fc_Len; i++)
                t[i] = i < c.fc_Raw ? src[i] : 0;
            src = t;
        }
        write(ctx, c.fc_Off, src, c.fc_Len);
        pos += c.fc_Len;
    }
    return pos;
}

#endif /* WIFIPI_FWUPLOAD_H */

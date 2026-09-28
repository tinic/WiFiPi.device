/*
 * Host test for the firmware upload plan (src/fwupload.h, AmiNetXDuo #89):
 * plain cc, meant for -fsanitize=address,undefined.  Each image is an
 * exact-size malloc, as the driver's AllocPooled of the file size; the fake
 * write reads every byte it is given, so a read past the image is an ASan
 * report and a failed run.
 *
 *   cc -std=c11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
 *      -Wall -Wextra -Werror -o test_fwupload tests/test_fwupload.c
 *   ./test_fwupload      -> "RESULT test_fwupload checks=N failures=0"
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t UBYTE;
typedef uint32_t ULONG;

#include "../src/fwupload.h"

static int checks, failures;
#define EXPECT(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

static UBYTE *out;          /* what the chip got, at its offsets */
static ULONG outSize, nWrites, lens[20000], offs[20000];

static void fake_write(void *ctx, ULONG off, const UBYTE *src, ULONG len)
{
    volatile ULONG sum = 0;
    ULONG i;
    (void)ctx;
    for (i = 0; i < len; i++)
    {
        sum += src[i];                  /* the read ASan checks */
        if (off + i < outSize)
            out[off + i] = src[i];
    }
    if (nWrites < 20000)
    {
        offs[nWrites] = off;
        lens[nWrites] = len;
    }
    nWrites++;
}

/* The loop the driver had, lengths only (no reads) */
static ULONG old_lengths(ULONG size, ULONG *ol, ULONG *oo)
{
    ULONG remaining = size, pos, n = 0;
    for (pos = 0; pos < size; )
    {
        ULONG sz = remaining > 64 ? 64 : remaining;
        sz = (sz + 3) & ~3UL;
        oo[n] = pos;
        ol[n++] = sz;
        pos += sz;
        remaining -= sz;
    }
    return n;
}

static ULONG oldLens[20000], oldOffs[20000];

static void run(ULONG size)
{
    UBYTE *img = malloc(size ? size : 1);
    ULONG i, n, wrote, padded = (size + 3) & ~3UL;
    int same = 1, content = 1;

    for (i = 0; i < size; i++)
        img[i] = (UBYTE)(i * 7 + 13);
    outSize = padded + 64;
    out = malloc(outSize);
    memset(out, 0xa5, outSize);
    nWrites = 0;
    wrote = fw_upload(img, size, fake_write, NULL);
    n = old_lengths(size, oldLens, oldOffs);

    EXPECT(wrote == padded);
    EXPECT(nWrites == n);
    for (i = 0; i < n && i < 20000; i++)
        if (lens[i] != oldLens[i] || offs[i] != oldOffs[i])
            same = 0;
    EXPECT(same);                                       /* lengths and offsets as the old loop */
    for (i = 0; i < size; i++)
        if (out[i] != img[i]) content = 0;
    for (; i < padded; i++)
        if (out[i] != 0) content = 0;                   /* the pad is zeros */
    for (; i < outSize; i++)
        if (out[i] != 0xa5) content = 0;                /* nothing past the rounded end */
    EXPECT(content);
    free(img);
    free(out);
}

int main(void)
{
    static const ULONG sizes[] = { 643651, 616233, 643652, 616236, 1, 2, 3, 4, 5, 7, 8, 60, 61, 62, 63, 64,
                                   65, 66, 67, 68, 127, 128, 129, 130, 131, 132, 256, 1021, 1022, 1023, 1024 };
    ULONG k;
    struct FwChunk c;

    for (k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++)
        run(sizes[k]);
    for (k = 0; k <= 200; k++)                          /* every size up to 200, 0 included */
        run(k);

    /* the plan itself: only a last chunk not a multiple of 4 is a tail */
    EXPECT(!fw_chunk(0, 0, &c));
    EXPECT(fw_chunk(643651, 643648, &c) && c.fc_Raw == 3 && c.fc_Len == 4 && c.fc_Tail);
    EXPECT(fw_chunk(616233, 616192, &c) && c.fc_Raw == 41 && c.fc_Len == 44 && c.fc_Tail);
    EXPECT(fw_chunk(643651, 0, &c) && c.fc_Raw == 64 && c.fc_Len == 64 && !c.fc_Tail);
    EXPECT(fw_chunk(643652, 643648, &c) && c.fc_Raw == 4 && !c.fc_Tail);
    EXPECT(!fw_chunk(643651, 643652, &c));

    printf("RESULT test_fwupload checks=%d failures=%d\n", checks, failures);
    return failures != 0;
}

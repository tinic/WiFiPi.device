/*
 * Host test for the BT-coexistence command's validation and record
 * (src/btc.h, #89 hw34): plain cc, no Amiga headers.
 *
 *   cc -std=c11 -O2 -Wall -Wextra -Werror -DWIFIPI_RINGTRACE -o host_btc tests/host_btc.c
 *   ./host_btc          -> "RESULT host_btc checks=N failures=0"
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

typedef uint8_t UBYTE;
typedef uint16_t UWORD;
typedef uint32_t ULONG;
typedef int32_t LONG;

#include "../src/btc.h"

static int checks, failures;
#define EXPECT(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

static ULONG chk(ULONG op, const char *name)
{
    char buf[BTC_NAME_MAX];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, name, strlen(name) < sizeof(buf) ? strlen(name) : sizeof(buf));
    return btc_check(op, buf);
}

int main(void)
{
    /* allowed */
    EXPECT(chk(BTC_OP_GET, "btc_mode") == BTC_NAME_MODE);
    EXPECT(chk(BTC_OP_GET, "btc_flags") == BTC_NAME_FLAGS);
    EXPECT(chk(BTC_OP_GET, "btc_dos_status") == BTC_NAME_DOS_STATUS);
    EXPECT(chk(BTC_OP_SET, "btc_mode") == BTC_NAME_MODE);
    /* SET on anything but btc_mode */
    EXPECT(chk(BTC_OP_SET, "btc_flags") == 0);
    EXPECT(chk(BTC_OP_SET, "btc_dos_status") == 0);
    EXPECT(chk(BTC_OP_SET, "btc_params") == 0);
    EXPECT(chk(BTC_OP_SET, "btc_params_ext") == 0);
    /* names outside the three, for either op */
    static const char *bad[] = { "btc_params", "btc_params_ext", "btc_mode2", "btc_mod", "BTC_MODE",
                                 "btc_mode ", " btc_mode", "", "counters", "btc_flags\x01", "mpc" };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        EXPECT(chk(BTC_OP_GET, bad[i]) == 0);
        EXPECT(chk(BTC_OP_SET, bad[i]) == 0);
    }
    /* bad ops */
    EXPECT(chk(0, "btc_mode") == 0 && chk(3, "btc_mode") == 0 && chk(0xffffffffu, "btc_mode") == 0);
    /* no NUL inside the 20 bytes: refused, never read past */
    {
        char full[BTC_NAME_MAX];
        memset(full, 'b', sizeof(full));
        memcpy(full, "btc_mode", 8);
        EXPECT(btc_check(BTC_OP_GET, full) == 0);
        memcpy(full, "btc_dos_status", 14);
        EXPECT(btc_check(BTC_OP_GET, full) == 0);
    }
    /* names by id */
    EXPECT(strcmp(btc_name(1), "btc_mode") == 0 && strcmp(btc_name(2), "btc_flags") == 0 &&
           strcmp(btc_name(3), "btc_dos_status") == 0 && btc_name(0) == 0 && btc_name(4) == 0);
    /* the request block the tool and the driver share */
    EXPECT(sizeof(struct BtcReq) == 32 && offsetof(struct BtcReq, br_Name) == 12);
    /* record packing */
    {
        ULONG log2 = 4, size = sizeof(struct RtRing) + (sizeof(struct RtRec) << log2);
        struct RtRing *r = malloc(size);
        rt_init(r, log2, size);
        btc_log(r, 123456, BTC_OP_SET, BTC_NAME_MODE, 1, 0);
        btc_log(r, 123460, BTC_OP_GET, BTC_NAME_DOS_STATUS, 0, 0xffffffe9u);
        btc_log(r, 123470, BTC_OP_SET, 0, 0, BTC_RC_REFUSED);
        const struct RtRec *e = r->rt_Rec;
        EXPECT(r->rt_Seq == 3);
        EXPECT(e[0].r_Clo == 123456 && e[0].r_Kind == RT_BTC && e[0].r_A == 2 && e[0].r_B == 1 &&
               e[0].r_C == 1 && e[0].r_D == 0);
        EXPECT(e[1].r_Kind == 29 && e[1].r_A == 1 && e[1].r_B == 3 && e[1].r_D == 0xffffffe9u);
        EXPECT(e[2].r_B == 0 && e[2].r_D == 0x7fff0100u);
        btc_log(NULL, 0, 1, 1, 1, 1);           /* no ring: nothing, no crash */
        free(r);
    }
    printf("RESULT host_btc checks=%d failures=%d\n", checks, failures);
    return failures != 0;
}

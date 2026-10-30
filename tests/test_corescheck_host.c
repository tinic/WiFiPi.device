/* brcm_chip_cores_check() on fake core lists.  A chip without the SDIO device
 * core, or a CM3/CA7 chip without a D11 core, is refused: SetActive,
 * SetPassive and chip_init() use those cores without a check. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t UBYTE;
typedef uint16_t UWORD;
typedef uint32_t ULONG;
typedef int BOOL;
#define TRUE 1
#define FALSE 0
#define D(x) ((void)0)
#include "corescheck-constants.inc"

struct MinNode { struct MinNode *mln_Succ, *mln_Pred; };
struct MinList { struct MinNode *mlh_Head, *mlh_Tail, *mlh_TailPred; };
struct ExecBase { int unused; };
struct WiFiBase { struct ExecBase *w_SysBase; };
struct Core {
    struct MinNode c_Node;
    UWORD c_CoreID, c_CoreREV;
    ULONG c_BaseAddress, c_WrapBase;
};
struct SDIO { struct Core *s_SDIOC; };
struct Chip {
    struct WiFiBase *c_WiFiBase;
    struct SDIO *c_SDIO;
    struct MinList c_Cores;
    BOOL (*SetActive)(struct Chip *, ULONG);
    void (*SetPassive)(struct Chip *);
};
#define ForeachNode(list, node) \
    for ((node) = (void *)(list)->mlh_Head; \
         ((struct MinNode *)(node))->mln_Succ; \
         (node) = (void *)((struct MinNode *)(node))->mln_Succ)

static BOOL brcm_chip_cm3_set_active(struct Chip *c, ULONG v) { (void)c; (void)v; return TRUE; }
static void brcm_chip_cm3_set_passive(struct Chip *c) { (void)c; }
static BOOL brcm_chip_cr4_set_active(struct Chip *c, ULONG v) { (void)c; (void)v; return TRUE; }
static void brcm_chip_cr4_set_passive(struct Chip *c) { (void)c; }
static BOOL brcm_chip_ca7_set_active(struct Chip *c, ULONG v) { (void)c; (void)v; return TRUE; }
static void brcm_chip_ca7_set_passive(struct Chip *c) { (void)c; }

#include "corescheck-under-test.inc"

static int checks, failures;
#define CHECK(cond, what) do { checks++; if (!(cond)) { failures++; \
    printf("  FAIL %s\n", (what)); } } while (0)

static struct ExecBase h_exec;
static struct WiFiBase h_base = { &h_exec };
static struct SDIO h_sdio;
static struct Core h_cores[8];

/* A chip whose cores are ids[0..n-1], in that order. */
static int h_check(const UWORD *ids, unsigned n, struct Chip *chip)
{
    unsigned i;

    memset(chip, 0, sizeof(*chip));
    memset(h_cores, 0, sizeof(h_cores));
    chip->c_WiFiBase = &h_base;
    chip->c_SDIO = &h_sdio;
    h_sdio.s_SDIOC = (struct Core *)&h_sdio;    /* stale from a last probe */
    chip->c_Cores.mlh_Head = (struct MinNode *)&chip->c_Cores.mlh_Tail;
    chip->c_Cores.mlh_TailPred = (struct MinNode *)&chip->c_Cores.mlh_Head;
    for (i = 0; i < n; i++)
    {
        struct MinNode *tail = chip->c_Cores.mlh_TailPred;

        h_cores[i].c_CoreID = ids[i];
        h_cores[i].c_Node.mln_Succ = (struct MinNode *)&chip->c_Cores.mlh_Tail;
        h_cores[i].c_Node.mln_Pred = tail;
        tail->mln_Succ = &h_cores[i].c_Node;
        chip->c_Cores.mlh_TailPred = &h_cores[i].c_Node;
    }
    return brcm_chip_cores_check(chip);
}

int main(void)
{
    struct Chip chip;
    static const UWORD cm3[] = { BCMA_CORE_CHIPCOMMON, BCMA_CORE_SDIO_DEV,
                                 BCMA_CORE_ARM_CM3, BCMA_CORE_80211,
                                 BCMA_CORE_INTERNAL_MEM };
    static const UWORD cr4[] = { BCMA_CORE_CHIPCOMMON, BCMA_CORE_SDIO_DEV,
                                 BCMA_CORE_ARM_CR4, BCMA_CORE_80211 };
    static const UWORD cr4_no_sdio[] = { BCMA_CORE_CHIPCOMMON,
                                         BCMA_CORE_ARM_CR4, BCMA_CORE_80211 };
    static const UWORD cm3_no_sdio[] = { BCMA_CORE_CHIPCOMMON, BCMA_CORE_ARM_CM3,
                                         BCMA_CORE_80211, BCMA_CORE_INTERNAL_MEM };
    static const UWORD cm3_no_d11[] = { BCMA_CORE_CHIPCOMMON, BCMA_CORE_SDIO_DEV,
                                        BCMA_CORE_ARM_CM3, BCMA_CORE_INTERNAL_MEM };
    static const UWORD ca7_no_d11[] = { BCMA_CORE_CHIPCOMMON, BCMA_CORE_SDIO_DEV,
                                        BCMA_CORE_ARM_CA7 };
    static const UWORD cr4_no_d11[] = { BCMA_CORE_CHIPCOMMON, BCMA_CORE_SDIO_DEV,
                                        BCMA_CORE_ARM_CR4 };

    CHECK(h_check(cm3, 5, &chip) && h_sdio.s_SDIOC == &h_cores[1] &&
          chip.SetActive == brcm_chip_cm3_set_active,
          "43430 (CM3) accepted, SDIO core recorded");
    CHECK(h_check(cr4, 4, &chip) && h_sdio.s_SDIOC == &h_cores[1] &&
          chip.SetActive == brcm_chip_cr4_set_active,
          "43455 (CR4) accepted, SDIO core recorded");
    CHECK(!h_check(cr4_no_sdio, 3, &chip) && h_sdio.s_SDIOC == NULL,
          "CR4 chip without SDIO core refused, nothing recorded");
    CHECK(!h_check(cm3_no_sdio, 4, &chip) && h_sdio.s_SDIOC == NULL,
          "CM3 chip without SDIO core refused, nothing recorded");
    CHECK(!h_check(cm3_no_d11, 4, &chip), "CM3 chip without D11 core refused");
    CHECK(!h_check(ca7_no_d11, 3, &chip), "CA7 chip without D11 core refused");
    CHECK(h_check(cr4_no_d11, 3, &chip),
          "CR4 chip without D11 core accepted (its SetPassive iterates)");

    printf("corescheck: %d checks, %d failures\n", checks, failures);
    return failures != 0;
}

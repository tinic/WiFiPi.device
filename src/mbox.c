/*
    Copyright © 2021 Michal Schulz <michal.schulz@gmx.de>
    https://github.com/michalsc

    This Source Code Form is subject to the terms of the
    Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
    with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/


#include <exec/types.h>
#include <exec/execbase.h>
#include <exec/io.h>
#include <exec/errors.h>

#if defined(__INTELLISENSE__)
#include <clib/exec_protos.h>
#else
#include <proto/exec.h>
#endif

#include <libraries/configregs.h>
#include <libraries/configvars.h>

#include <stdint.h>

#include "wifipi.h"

/* status register flags */

#define MBOX_TX_FULL (1UL << 31)
#define MBOX_RX_EMPTY (1UL << 30)
#define MBOX_CHANMASK 0xF

/* VideoCore tags used. */

#define VCTAG_GET_ARM_MEMORY     0x00010005
#define VCTAG_GET_CLOCK_RATE     0x00030002

static uint32_t mbox_recv(uint32_t channel, struct WiFiBase * WiFiBase)
{
	volatile uint32_t *mbox_read = (uint32_t*)(WiFiBase->w_MailBox);
	volatile uint32_t *mbox_status = (uint32_t*)((uintptr_t)WiFiBase->w_MailBox + 0x18);
	uint32_t response, status;

	do
	{
		do
		{
			status = LE32(*mbox_status);
			asm volatile("nop");
		}
		while (status & MBOX_RX_EMPTY);

		asm volatile("nop");
		response = LE32(*mbox_read);
		asm volatile("nop");
	}
	while ((response & MBOX_CHANMASK) != channel);

	return (response & ~MBOX_CHANMASK);
}

static void mbox_send(uint32_t channel, uint32_t data, struct WiFiBase * WiFiBase)
{
	volatile uint32_t *mbox_write = (uint32_t*)((uintptr_t)WiFiBase->w_MailBox + 0x20);
	volatile uint32_t *mbox_status = (uint32_t*)((uintptr_t)WiFiBase->w_MailBox + 0x18);
	uint32_t status;

	data &= ~MBOX_CHANMASK;
	data |= channel & MBOX_CHANMASK;

	do
	{
		status = LE32(*mbox_status);
		asm volatile("nop");
	}
	while (status & MBOX_TX_FULL);

	asm volatile("nop");
	*mbox_write = LE32(data);
}

/*
 * mailbox.resource (in Emu68 1.1+ ROMs) serialises every mailbox user and
 * copies the request into its own aligned buffer, swapping it to the VC's
 * little-endian order.  MB_RawCommand(command) (A0), LVO -6: the request goes
 * in and comes back in the 68k's byte order, command[0] = 0xffffffff on a
 * failure.  Without the resource (Emu68 < 1.1) the registers are driven here.
 */
static inline void MB_RawCommand(APTR MailboxBase, ULONG *command)
{
    register APTR _a6 asm("a6") = MailboxBase;
    register ULONG *_a0 asm("a0") = command;

    asm volatile("jsr %%a6@(-6)"
        : "+r"(_a0)
        : "r"(_a6)
        : "d0", "d1", "a1", "cc", "memory");
}

/* Run one property request; cmd[] is in the 68k's byte order. */
static uint32_t mbox_property(ULONG *cmd, struct WiFiBase * WiFiBase)
{
    struct ExecBase *SysBase = WiFiBase->w_SysBase;

    if (WiFiBase->w_MailboxBase)
    {
        MB_RawCommand(WiFiBase->w_MailboxBase, cmd);
        return cmd[6];
    }

    ULONG *FBReq = WiFiBase->w_Request;
    ULONG len = cmd[0];

    for (ULONG i = 0; i < len / 4; i++)
        FBReq[i] = LE32(cmd[i]);

    CachePreDMA(FBReq, &len, 0);
    mbox_send(8, (ULONG)FBReq, WiFiBase);
    mbox_recv(8, WiFiBase);
    CachePostDMA(FBReq, &len, 0);

    return LE32(FBReq[6]);
}

/* One tag with a value buffer of 8 or 12 bytes: two argument words */
static uint32_t mbox_tag(ULONG tag, ULONG size, ULONG arg0, ULONG arg1, struct WiFiBase * WiFiBase)
{
    ULONG cmd[9];

    cmd[0] = size == 12 ? 4*9 : 4*8;    // Length
    cmd[1] = 0;                         // Request
    cmd[2] = tag;
    cmd[3] = size;
    cmd[4] = 0;
    cmd[5] = arg0;
    cmd[6] = arg1;
    cmd[7] = 0;
    cmd[8] = 0;

    return mbox_property(cmd, WiFiBase);
}

uint32_t get_clock_rate(uint32_t clock_id, struct WiFiBase * WiFiBase)
{
    return mbox_tag(0x00030047, 8, clock_id, 0, WiFiBase);     // GetClockRate
}

uint32_t set_clock_rate(uint32_t clock_id, uint32_t speed, struct WiFiBase * WiFiBase)
{
    return mbox_tag(0x00038002, 12, clock_id, speed, WiFiBase); // SetClockRate
}

uint32_t get_clock_state(uint32_t id, struct WiFiBase * WiFiBase)
{
    return mbox_tag(0x00030001, 8, id, 0, WiFiBase);           // GetClockState
}

uint32_t set_clock_state(uint32_t id, uint32_t state, struct WiFiBase * WiFiBase)
{
    return mbox_tag(0x00038001, 8, id, state, WiFiBase);       // SetClockState
}

uint32_t get_power_state(uint32_t id, struct WiFiBase * WiFiBase)
{
    return mbox_tag(0x00020001, 8, id, 0, WiFiBase);           // GetPowerState
}

uint32_t set_power_state(uint32_t id, uint32_t state, struct WiFiBase * WiFiBase)
{
    return mbox_tag(0x00028001, 12, id, state, WiFiBase);      // SetPowerState
}

uint32_t get_extgpio_state(uint32_t id, struct WiFiBase * WiFiBase)
{
    return mbox_tag(0x00030041, 8, 128 + id, 0, WiFiBase);     // GET_GPIO_STATE
}

uint32_t set_extgpio_state(uint32_t id, uint32_t state, struct WiFiBase * WiFiBase)
{
    return mbox_tag(0x00038041, 8, 128 + id, state, WiFiBase); // SET_GPIO_STATE
}

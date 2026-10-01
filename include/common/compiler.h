/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef COMMON_COMPILER_H
#define COMMON_COMPILER_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__INTELLISENSE__)
#define REGARG(arg, reg) arg
#else
#define REGARG(arg, reg) arg asm(reg)
#endif

/*
 * Arguments on the stack whatever -mregparm says.  For a function that is
 * entered by something other than a C call: a task entry whose arguments
 * were pushed onto its initial stack, or a callback another binary calls.
 * AmiNetXDuo builds this driver with -mregparm=3, under which an unmarked
 * function reads its first arguments from a0/a1/d0 instead.  Goes before the
 * declarator: GCC rejects a trailing attribute on a definition.
 */
#if defined(__GNUC__) && defined(__stdargs) && !defined(__INTELLISENSE__)
#define STACKARGS __stdargs
#else
#define STACKARGS
#endif

#ifdef __cplusplus
}
#endif

#endif // COMMON_COMPILER_H

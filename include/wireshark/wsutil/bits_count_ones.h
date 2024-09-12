/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSUTIL_BITS_COUNT_ONES_H__
#define __WSUTIL_BITS_COUNT_ONES_H__

#include <inttypes.h>

/*
 * The variable-precision SWAR algorithm is an interesting way to count
 * the number of bits set in an integer:
 *
 *     https://www.playingwithpointers.com/blog/swar.html
 *
 * See
 *
 *     https://gcc.gnu.org/bugzilla/show_bug.cgi?id=36041
 *     https://danluu.com/assembly-intrinsics/
 *
 * for discussions of various forms of population-counting code on x86.
 *
 * See
 *
 *     https://docs.microsoft.com/en-us/cpp/intrinsics/popcnt16-popcnt-popcnt64
 *
 * for MSVC's population count intrinsics.
 *
 * Note that not all x86 processors support the POPCOUNT instruction.
 *
 * Other CPUs may have population count instructions as well.
 */

static inline int
ws_count_ones(const uint64_t x)
{
	uint64_t bits = x;

	bits = bits - ((bits >> 1) & UINT64_C(0x5555555555555555));
	bits = (bits & UINT64_C(0x3333333333333333)) + ((bits >> 2) & UINT64_C(0x3333333333333333));
	bits = (bits + (bits >> 4)) & UINT64_C(0x0F0F0F0F0F0F0F0F);

	return (int)((bits * UINT64_C(0x0101010101010101)) >> 56);
}

#endif /* __WSUTIL_BITS_COUNT_ONES_H__ */

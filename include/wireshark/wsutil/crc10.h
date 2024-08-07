/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CRC10_H__
#define __CRC10_H__

#include <include/wireshark.h>

/* Update the data block's CRC-10 remainder one byte at a time */
WS_DLL_PUBLIC uint16_t update_crc10_by_bytes(uint16_t crc10, const uint8_t *data_blk_ptr, int data_blk_size);

#endif /* __CRC10_H__ */

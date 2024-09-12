/* packet-tr.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_TR_H__
#define __PACKET_TR_H__

#include "include/ws_symbol_export.h"

typedef struct _tr_hdr {
	uint8_t ac;
	uint8_t fc;
	address dst;
	address src;
} tr_hdr;

#endif

/* packet-ieee802a.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_IEEE802A_H__
#define __PACKET_IEEE802A_H__

#include "include/ws_symbol_export.h"

/*
 * Add an entry for a new OUI.
 */
WS_DLL_PUBLIC
void ieee802a_add_oui(uint32_t, const char *, const char *, hf_register_info *, const int);

#endif

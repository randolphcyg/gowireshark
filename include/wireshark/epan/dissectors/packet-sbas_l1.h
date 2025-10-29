/* packet-sbas_l1.h
 * SBAS L1 protocol dissection.
 *
 * By Timo Warns <timo.warns@gmail.com>
 * Copyright 2024 Timo Warns
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_SBAS_L1_h
#define PACKET_SBAS_L1_h

#include <stdint.h>

// UDREI_i mapping
// see ICAO Annex 10, Vol I, 8th edition, Table B-67
extern const value_string UDREI_EVALUATION[];

extern uint32_t sbas_crc24q(const uint8_t *data);

extern const char *EMS_L1_SVC_FLAG;

#endif

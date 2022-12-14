/* packet-rtcp.h
 *
 * Routines for RTCP dissection
 * RTCP = Real-time Transport Control Protocol
 *
 * Copyright 2000, Philips Electronics N.V.
 * Written by Andreas Sikkema <andreas.sikkema@philips.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "include/ws_symbol_export.h"

/* Info to save in RTCP conversation / packet-info.
   Note that this structure applies to the destination end of
   an RTP session */
#define MAX_RTCP_SETUP_METHOD_SIZE 10
struct _rtcp_conversation_info
{
    /* Setup info is relevant to traffic whose dest is the conversation address */
    guchar  setup_method_set;
    gchar   setup_method[MAX_RTCP_SETUP_METHOD_SIZE + 1];
    guint32 setup_frame_number;

    /* Info used for roundtrip calculations */
    guchar   last_received_set;
    guint32  last_received_frame_number;
    nstime_t last_received_timestamp;
    guint32  last_received_ts;

    /* Stored result of calculation */
    guchar  lsr_matched;
    guint32 calculated_delay_used_frame;
    gint    calculated_delay_report_gap;
    gint32  calculated_delay;

    /* SRTCP context */
    struct srtp_info *srtcp_info;
};


/* Add an RTCP conversation with the given details */
WS_DLL_PUBLIC
void rtcp_add_address(packet_info *pinfo,
                      address *addr, int port,
                      int other_port,
                      const gchar *setup_method, guint32 setup_frame_number);

/* Add an SRTP conversation with the given details */
WS_DLL_PUBLIC
void srtcp_add_address(packet_info *pinfo,
                      address *addr, int port,
                      int other_port,
                      const gchar *setup_method, guint32 setup_frame_number,
                      struct srtp_info *srtcp_info);

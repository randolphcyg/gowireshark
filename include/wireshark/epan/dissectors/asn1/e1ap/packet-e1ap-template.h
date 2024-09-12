/* packet-e1ap.h
 * Routines for E-UTRAN E1 Application Protocol (E1AP) packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_E1AP_H
#define PACKET_E1AP_H

typedef struct {
    uint32_t message_type;
    uint32_t ProcedureCode;
    uint32_t ProtocolIE_ID;
    uint32_t ProtocolExtensionID;
} e1ap_ctx_t;


#include "packet-e1ap-exp.h"

#endif  /* PACKET_E1AP_H */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */

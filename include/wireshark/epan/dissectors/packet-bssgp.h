/* packet-bssgp.h
 * Routines for Base Station Subsystem GPRS Protocol dissection
 * Copyright 2006, Anders Broman <anders.broman [at] ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* 3GPP TS 48.018 V 6.5.0 (2004-07) Release 6 */
#ifndef __PACKET_BSSGP_H__
#define __PACKET_BSSGP_H__

#include "include/ws_symbol_export.h"

WS_DLL_PUBLIC value_string_ext bssgp_cause_vals_ext;

void bssgp_suspend_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len);
uint16_t de_bssgp_cell_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_bssgp_rnc_identifier(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len _U_, char *add_string, int string_len);
uint16_t de_bssgp_enb_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_bssgp_source_BSS_to_target_BSS_transp_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_bssgp_target_BSS_to_source_BSS_transp_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string, int string_len);
uint16_t de_bssgp_list_of_setup_pfcs(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_);

#endif /* __PACKET_BSSGP_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

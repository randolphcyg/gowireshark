/* packet-opa-fe.c
 * Routines for Omni-Path FE header dissection
 * Copyright (c) 2016, Intel Corporation.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-tls.h"
#include "packet-tcp.h"

void proto_reg_handoff_opa_fe(void);
void proto_register_opa_fe(void);

#define OPA_FE_TCP_RANGE "3245-3248" /* Not IANA registered */
#define OPA_FE_SSL_RANGE "3249-3252"

#define OPA_FE_HEADER_LEN 24

/* Wireshark ID */
static int proto_opa_fe;

/* Variables to hold expansion values between packets */
static int ett_fe;

/* SnC Fields */
static int hf_opa_fe_magicnumber;
static int hf_opa_fe_length_oob;
static int hf_opa_fe_headerversion;
static int hf_opa_fe_length;
static int hf_opa_fe_Reserved64;

/* Dissector Declarations */
static dissector_handle_t opa_fe_handle;
static dissector_handle_t opa_mad_handle;

static range_t *global_fe_ssl_range;

static range_t *fe_ssl_range;

static unsigned get_opa_fe_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return tvb_get_ntohl(tvb, offset + 4);
}
static int dissect_opa_fe_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;    /* Current Offset */
    proto_item *FE_item;
    proto_tree *FE_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Omni-Path");
    col_clear(pinfo->cinfo, COL_INFO);

    tree = proto_tree_get_root(tree);

    FE_item = proto_tree_add_item(tree, proto_opa_fe, tvb, offset, OPA_FE_HEADER_LEN, ENC_NA);
    FE_tree = proto_item_add_subtree(FE_item, ett_fe);

    proto_tree_add_item(FE_tree, hf_opa_fe_magicnumber, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(FE_tree, hf_opa_fe_length_oob, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(FE_tree, hf_opa_fe_headerversion, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(FE_tree, hf_opa_fe_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(FE_tree, hf_opa_fe_Reserved64, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* Pass to OPA MAD dissector */
    call_dissector(opa_mad_handle, tvb_new_subset_remaining(tvb, offset), pinfo, FE_tree);
    return tvb_captured_length(tvb);
}

static int dissect_opa_fe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    tcp_dissect_pdus(tvb, pinfo, tree, true, OPA_FE_HEADER_LEN,
        get_opa_fe_message_len, dissect_opa_fe_message, data);

    return tvb_reported_length(tvb);
}

static void range_delete_fe_ssl_callback(uint32_t port, void *ptr _U_)
{
    ssl_dissector_delete(port, opa_fe_handle);
}

static void range_add_fe_ssl_callback(uint32_t port, void *ptr _U_)
{
    ssl_dissector_add(port, opa_fe_handle);
}

void proto_register_opa_fe(void)
{
    module_t *opa_fe_module;

    static hf_register_info hf[] = {
        { &hf_opa_fe_magicnumber, {
                "Magic Number", "opa.fe.magicnumber",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_fe_length_oob, {
                "Length OOB", "opa.fe.lengthoob",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_fe_headerversion, {
                "Header Version", "opa.fe.headerversion",
                FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_fe_length, {
                "Length", "opa.fe.length",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_opa_fe_Reserved64, {
                "Reserved (64 bits)", "opa.fe.reserved64",
                FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_fe
    };

    proto_opa_fe = proto_register_protocol("Intel Omni-Path FE Header - Omni-Path Fabric Executive Header", "OPA FE", "opa.fe");
    opa_fe_handle = register_dissector("opa.fe", dissect_opa_fe, proto_opa_fe);

    proto_register_field_array(proto_opa_fe, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    opa_fe_module = prefs_register_protocol(proto_opa_fe, proto_reg_handoff_opa_fe);
    range_convert_str(wmem_epan_scope(), &global_fe_ssl_range, OPA_FE_SSL_RANGE, 65535);
    prefs_register_range_preference(opa_fe_module, "tls.port", "SSL/TLS Ports",
        "SSL/TLS Ports range",
        &global_fe_ssl_range, 65535);
    prefs_register_obsolete_preference(opa_fe_module, "ssl.port");
}

void proto_reg_handoff_opa_fe(void)
{
    static bool initialized = false;

    if (!initialized)
    {
        opa_mad_handle = find_dissector("opa.mad");
        dissector_add_uint_range_with_preference("tcp.port", OPA_FE_TCP_RANGE, opa_fe_handle);
        initialized = true;
    }

    range_foreach(fe_ssl_range, range_delete_fe_ssl_callback, NULL);
    wmem_free(wmem_epan_scope(), fe_ssl_range);
    fe_ssl_range = range_copy(wmem_epan_scope(), global_fe_ssl_range);
    range_foreach(fe_ssl_range, range_add_fe_ssl_callback, NULL);

}

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

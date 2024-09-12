/* packet-etag.c
 *
 * 802.1BR E-Tag dissector
 * Inspired by packet-vntag.c
 *
 * Copyright 2016 APCON, Inc.
 * Kim Kempf <kim.kempf@apcon.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/prefs.h>

void proto_register_etag(void);
void proto_reg_handoff_etag(void);

static dissector_handle_t etag_handle;
static dissector_handle_t ethertype_handle;

static int proto_etag;

static bool etag_summary_in_tree = true;

static int hf_etag_etype;
static int hf_etag_pcp;
static int hf_etag_dei;
static int hf_etag_res;
static int hf_etag_grp;
static int hf_etag_iecid_base;
static int hf_etag_iecid_ext;
static int hf_etag_ecid_base;
static int hf_etag_ecid_ext;

static int hf_etag_trailer;

static int ett_etag;

#define IEEE8021BR_LEN 8    /* length including ethertype */

/* From Table G-2 of IEEE standard 802.1D-2004 */
static const value_string pri_vals[] = {
    { 1, "Background"                        },
    { 2, "Spare"                             },
    { 0, "Best Effort (default)"             },
    { 3, "Excellent Effort"                  },
    { 4, "Controlled Load"                   },
    { 5, "Video, < 100ms latency and jitter" },
    { 6, "Voice, < 10ms latency and jitter"  },
    { 7, "Network Control"                   },
    { 0, NULL                                }
};


static const value_string grp_vals[] = {
    { 0, "Point-to-point"                    },
    { 1, "Point-to-multipoint"               },
    { 2, "Point-to-multipoint"               },
    { 3, "Point-to-multipoint"               },
    { 0, NULL                                }
};

/*
    From 801.2BR 7.5 E-TAG Control Information
    0                   1
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                               |
    |                               |
    |      E-Tag EtherType          |
    |          0x893F               |
    |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     |E|                       |
    |     |-|                       |
    |E-PCP|D|  Ingress_E-CID_base   |
    |     |E|                       |
    |     |I|                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   |   |                       |
    | R | G |                       |
    | E | R |  E-CID_base           |
    | S | P |                       |
    | V |   |                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |               |               |
    |               |               |
    |Ingress_E-CID_ |  E_CID_ext    |
    |     ext       |               |
    |               |               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

static int
dissect_etag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    uint16_t    encap_proto;
    proto_tree *etag_tree = NULL;
    ethertype_data_t ethertype_data;

    uint64_t tci;

    /* Decoding per IEEE802.1BR-2012 */
    static int * const fields1[] = {
        &hf_etag_pcp,
        &hf_etag_dei,
        &hf_etag_iecid_base,
        NULL
    };

    static int * const fields2[] = {
        &hf_etag_res,
        &hf_etag_grp,
        &hf_etag_ecid_base,
        NULL
    };

    tci = tvb_get_ntoh48( tvb, 0);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETAG");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        uint32_t e_cid, ing_e_cid;

        proto_item *ti = proto_tree_add_item(tree, proto_etag, tvb, 0, IEEE8021BR_LEN - 2, ENC_NA);

        e_cid =     (uint32_t)((((tci >> 16) & 0xFFF) |  (tci << 12))            & 0xFFFFF);    /* E-CID_base | E-CID_ext */
        ing_e_cid = (uint32_t)((((tci >> 32) & 0xFFF) | ((tci <<  4) & 0xFF000)) & 0xFFFFF);    /* Ingress_E-CID_base | Ingress_E-CID ext */

        if (etag_summary_in_tree) {
            proto_item_append_text(ti, ", TCI: 0x%" PRIx64 " Ingress_E-CID: %u E-CID: %u", tci, ing_e_cid, e_cid);
        }
        etag_tree = proto_item_add_subtree(ti, ett_etag);

        proto_tree_add_bitmask_list(etag_tree, tvb, 0, 2, fields1, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask_list(etag_tree, tvb, 2, 2, fields2, ENC_BIG_ENDIAN);

        proto_tree_add_item(etag_tree, hf_etag_iecid_ext, tvb, 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(etag_tree, hf_etag_ecid_ext, tvb, 5, 1, ENC_BIG_ENDIAN);
    }

    encap_proto = tvb_get_ntohs(tvb, IEEE8021BR_LEN - 2);
    proto_tree_add_uint(etag_tree, hf_etag_etype, tvb, IEEE8021BR_LEN - 2, 2, encap_proto);

    ethertype_data.etype = encap_proto;
    ethertype_data.payload_offset = IEEE8021BR_LEN;
    ethertype_data.fh_tree = etag_tree;
    ethertype_data.trailer_id = hf_etag_trailer;
    ethertype_data.fcs_len = 0;

    call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);

    return tvb_captured_length(tvb);
}

void
proto_register_etag(void)
{
    static hf_register_info hf[] = {
        { &hf_etag_pcp,
            { "E-PCP", "etag.pcp", FT_UINT16, BASE_DEC, VALS(pri_vals), 0xE000,
                "Descriptions are recommendations from IEEE standard 802.1D-2004", HFILL }
        },
        { &hf_etag_dei,
            { "E-DEI", "etag.dei", FT_UINT16, BASE_DEC, NULL, 0x1000, NULL, HFILL }
        },
        { &hf_etag_iecid_base,
            { "Ingress_E-CID_base", "etag.iecid_base", FT_UINT16, BASE_HEX, NULL, 0x0FFF, NULL, HFILL }
        },
        { &hf_etag_res,
            { "Reserved", "etag.resv", FT_UINT16, BASE_DEC, NULL, 0xC000, NULL, HFILL }
        },
        { &hf_etag_grp,
            { "GRP", "etag.group", FT_UINT16, BASE_DEC, VALS(grp_vals), 0x3000, NULL, HFILL }
        },
        { &hf_etag_ecid_base,
            { "E-CID_base", "etag.ecid_base", FT_UINT16, BASE_HEX, NULL, 0x0FFF, NULL, HFILL }
        },
        { &hf_etag_iecid_ext,
            { "Ingress_E-CID_ext", "etag.iecid_ext", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_etag_ecid_ext,
            { "E-CID_ext", "etag.ecid_ext", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_etag_etype,
            { "Type", "etag.etype", FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0, NULL, HFILL }
        },
        { &hf_etag_trailer,
            { "Trailer", "etag.trailer", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_etag
    };

    module_t *etag_module;

    proto_etag = proto_register_protocol("802.1BR E-Tag", "ETAG", "etag");
    etag_handle = register_dissector("etag", dissect_etag, proto_etag);
    proto_register_field_array(proto_etag, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    etag_module = prefs_register_protocol(proto_etag, NULL);
    prefs_register_bool_preference(etag_module, "summary_in_tree",
        "Show E-Tag summary in protocol tree",
        "Whether the E-Tag summary line should be shown in the protocol tree",
        &etag_summary_in_tree);
}

void
proto_reg_handoff_etag(void)
{
    dissector_add_uint("ethertype", ETHERTYPE_IEEE_802_1BR, etag_handle);

    ethertype_handle = find_dissector_add_dependency("ethertype", proto_etag);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */

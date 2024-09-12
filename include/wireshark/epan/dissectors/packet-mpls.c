/* packet-mpls.c
 * Routines for MPLS data packet disassembly
 * RFC 3032
 *
 * (c) Copyright Ashok Narayanan <ashokn@cisco.com>
 *
 * (c) Copyright 2006, _FF_ Francesco Fondelli <francesco.fondelli@gmail.com>
 *     - added MPLS OAM support, ITU-T Y.1711
 *     - PW Associated Channel Header dissection as per RFC 4385
 *     - PW MPLS Control Word dissection as per RFC 4385
 *     - mpls subdissector table indexed by label value
 *     - enhanced "what's past last mpls label?" heuristic
 *
 * (c) Copyright 2011, Shobhank Sharma <ssharma5@ncsu.edu>
 *     - Removed some mpls preferences which are no longer relevant/needed like
 *       decode PWAC payloads as PPP traffic and assume all channel types except
 *       0x21 are raw BFD.
 *     - MPLS extension from PW-ACH to MPLS Generic Associated Channel as per RFC 5586
 *     - Updated Pseudowire Associated Channel Types as per http://www.iana.org/assignments/pwe3-parameters
 *
 * (c) Copyright 2011, Jaihari Kalijanakiraman <jaiharik@ipinfusion.com>
 *                     Krishnamurthy Mayya <krishnamurthy.mayya@ipinfusion.com>
 *                     Nikitha Malgi       <malgi.nikitha@ipinfusion.com>
 *     - Identification of BFD CC, BFD CV and ON-Demand CV ACH types as per RFC 6428, RFC 6426
 *       respectively and the corresponding decoding of messages
 *     - Decoding support for MPLS-TP Lock Instruct as per RFC 6435
 *     - Decoding support for MPLS-TP Fault-Management as per RFC 6427
 *
 * (c) Copyright 2012, Aditya Ambadkar and Diana Chris <arambadk,dvchris@ncsu.edu>
 *   -  Added preference to select BOS label as flowlabel as per RFC 6391
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#include <epan/ppptypes.h>
#include <epan/etypes.h>
#include <epan/prefs.h>
#include <epan/ipproto.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>

#include "packet-ppp.h"
#include "packet-mpls.h"
#include "packet-pw-common.h"
#include "packet-bfd.h"
#include "packet-juniper.h"
#include "packet-sflow.h"
#include "packet-l2tp.h"
#include "packet-vxlan.h"
#include "packet-nsh.h"

void proto_register_mpls(void);
void proto_reg_handoff_mpls(void);

static int proto_mpls;
static int proto_pw_ach;
static int proto_pw_ach_mcc;
static int proto_pw_mcw;

static int ett_mpls;
static int ett_mpls_pw_ach;
static int ett_mpls_pw_ach_mcc;
static int ett_mpls_pw_mcw;
static char PW_ACH[50] = "PW Associated Channel Header";

const value_string special_labels[] = {
    {MPLS_LABEL_IP4_EXPLICIT_NULL,   "IPv4 Explicit-Null"},
    {MPLS_LABEL_ROUTER_ALERT,        "Router Alert"},
    {MPLS_LABEL_IP6_EXPLICIT_NULL,   "IPv6 Explicit-Null"},
    {MPLS_LABEL_IMPLICIT_NULL,       "Implicit-Null"},
    {MPLS_LABEL_OAM_ALERT,           "OAM Alert"},
    {MPLS_LABEL_GACH,                "Generic Associated Channel Label (GAL)"},
    {MPLS_LABEL_ELI,                 "Entropy Label Indicator (ELI)"},
    {0, NULL }
};

static dissector_table_t   pw_ach_subdissector_table;
static dissector_table_t   pw_ach_mcc_subdissector_table;

static dissector_handle_t dissector_ipv6;
static dissector_handle_t dissector_ip;
static dissector_handle_t dissector_pw_ach;
static dissector_handle_t dissector_pw_eth_heuristic;
static dissector_handle_t mpls_handle;
static dissector_handle_t mpls_pwcw_handle;
static dissector_handle_t mpls_mcc_handle;

/*
 * RFC 8469 deprecated Ethernet without CW, so default this to false.
 * https://datatracker.ietf.org/doc/html/rfc8469
 */
static bool mpls_try_heuristic_first;
/* For RFC6391 - Flow aware transport of pseudowire over a mpls PSN*/
static bool mpls_bos_flowlabel;

static int hf_mpls_label;
static int hf_mpls_label_special;
static int hf_mpls_exp;
static int hf_mpls_bos;
static int hf_mpls_ttl;

static int hf_mpls_pw_ach_ver;
static int hf_mpls_pw_ach_res;
static int hf_mpls_pw_ach_channel_type;

static int hf_mpls_pw_ach_mcc_proto;

static int hf_mpls_pw_mcw_flags;
static int hf_mpls_pw_mcw_length;
static int hf_mpls_pw_mcw_sequence_number;

static expert_field ei_mpls_pw_ach_error_processing_message;
static expert_field ei_mpls_pw_ach_res;
static expert_field ei_mpls_pw_mcw_error_processing_message;
static expert_field ei_mpls_invalid_label;

#if 0 /*not used yet*/
/*
 * MPLS PW types
 * http://www.iana.org/assignments/pwe3-parameters
 */
static const value_string mpls_pw_types[] = {
    { 0x0001, "Frame Relay DLCI ( Martini Mode )"              },
    { 0x0002, "ATM AAL5 SDU VCC transport"                     },
    { 0x0003, "ATM transparent cell transport"                 },
    { 0x0004, "Ethernet Tagged Mode"                           },
    { 0x0005, "Ethernet"                                       },
    { 0x0006, "HDLC"                                           },
    { 0x0007, "PPP"                                            },
    { 0x0008, "SONET/SDH Circuit Emulation Service Over MPLS"  },
    { 0x0009, "ATM n-to-one VCC cell transport"                },
    { 0x000A, "ATM n-to-one VPC cell transport"                },
    { 0x000B, "IP Layer2 Transport"                            },
    { 0x000C, "ATM one-to-one VCC Cell Mode"                   },
    { 0x000D, "ATM one-to-one VPC Cell Mode"                   },
    { 0x000E, "ATM AAL5 PDU VCC transport"                     },
    { 0x000F, "Frame-Relay Port mode"                          },
    { 0x0010, "SONET/SDH Circuit Emulation over Packet"        },
    { 0x0011, "Structure-agnostic E1 over Packet"              },
    { 0x0012, "Structure-agnostic T1 (DS1) over Packet"        },
    { 0x0013, "Structure-agnostic E3 over Packet"              },
    { 0x0014, "Structure-agnostic T3 (DS3) over Packet"        },
    { 0x0015, "CESoPSN basic mode"                             },
    { 0x0016, "TDMoIP AAL1 Mode"                               },
    { 0x0017, "CESoPSN TDM with CAS"                           },
    { 0x0018, "TDMoIP AAL2 Mode"                               },
    { 0x0019, "Frame Relay DLCI"                               },
    { 0x001A, "ROHC Transport Header-compressed Packets"       },/*[RFC4995][RFC4901]*/
    { 0x001B, "ECRTP Transport Header-compressed Packets"      },/*[RFC3545][RFC4901]*/
    { 0x001C, "IPHC Transport Header-compressed Packets"       },/*[RFC2507][RFC4901]*/
    { 0x001D, "cRTP Transport Header-compressed Packets"       },/*[RFC2508][RFC4901]*/
    { 0x001E, "ATM VP Virtual Trunk"                           },/*[MFA9]*/
    { 0x001F, "Reserved"                                       },/*[Bryant]  2008-04-17*/
    { 0, NULL }
};
static value_string_ext mpls_pw_types_ext = VALUE_STRING_EXT_INIT(mpls_pw_types);
#endif

/*
 * MPLS PW Associated Channel Types
 * as per http://www.iana.org/assignments/pwe3-parameters
 * and https://tools.ietf.org/html/draft-ietf-pwe3-vccv-bfd-05 clause 3.2
 */
static const value_string mpls_pwac_types[] = {
    { 0x0000, "Reserved"},
    { 0x0001, "Management Communication Channel (MCC)"},
    { 0x0002, "Signaling Communication Channel (SCC)"},
    { 0x0007, "BFD Control, PW-ACH-encapsulated (BFD Without IP/UDP Headers)" },
    { 0x000A, "MPLS Direct Loss Measurement (DLM)"},
    { 0x000B, "MPLS Inferred Loss Measurement (ILM)"},
    { 0x000C, "MPLS Delay Measurement (DM)"},
    { 0x000D, "MPLS Direct Loss and Delay Measurement (DLM+DM)"},
    { 0x000E, "MPLS Inferred Loss and Delay Measurement (ILM+DM)"},
    { 0x0021, "IPv4 packet" },
    { 0x0022, "MPLS-TP CC message"},
    { 0x0023, "MPLS-TP CV message"},
    { 0x0024, "Protection State Coordination Protocol (PSC)"},
    { 0x0025, "On-Demand CV"},
    { 0x0026, "LI"},
    { 0x0027, "Pseudo-Wire OAM"},
    { 0x0028, "MAC Withdraw OAM Msg"},
    { 0x0057, "IPv6 packet" },
    { 0x0058, "Fault OAM"},
    { 0x7FF8, "Reserved for Experimental Use"},
    { 0x7FF9, "Reserved for Experimental Use"},
    { 0x7FFA, "Reserved for Experimental Use"},
    { 0x7FFB, "Reserved for Experimental Use"},
    { 0x7FFC, "Reserved for Experimental Use"},
    { 0x7FFD, "Reserved for Experimental Use"},
    { 0x7FFE, "Reserved for Experimental Use"},
    { 0x7FFF, "Reserved for Experimental Use"},
    { 0x8902, "MPLS-TP OAM"},
    { 0, NULL }
};
static value_string_ext mpls_pwac_types_ext = VALUE_STRING_EXT_INIT(mpls_pwac_types);

static dissector_table_t mpls_subdissector_table;
/*
 * Post-stack First Nibble
 * https://datatracker.ietf.org/doc/html/draft-ietf-mpls-1stnibble-06
 */
static dissector_table_t mpls_pfn_subdissector_table;
static heur_dissector_list_t mpls_heur_subdissector_list;

static void mpls_prompt(packet_info *pinfo, char* result)
{
    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Data after label %u as",
        GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_mpls, 0)));
}

static void *mpls_value(packet_info *pinfo)
{
    return p_get_proto_data(pinfo->pool, pinfo, proto_mpls, 0);
}

static void mpls_pfn_prompt(packet_info *pinfo, char* result)
{
    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Data after post-stack first nibble %u as",
        GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_mpls, 1)));
}

static void *mpls_pfn_value(packet_info *pinfo)
{
    return p_get_proto_data(pinfo->pool, pinfo, proto_mpls, 1);
}

static void pw_ach_prompt(packet_info *pinfo, char* result)
{
    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Channel type 0x%x as",
        GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_pw_ach, 0)));
}

static void *pw_ach_value(packet_info *pinfo)
{
    return p_get_proto_data(pinfo->pool, pinfo, proto_pw_ach, 0);
}

/*
 * Given a 4-byte MPLS label starting at offset "offset", in tvbuff "tvb",
 * decode it.
 * Return the label in "label", EXP bits in "exp",
 * bottom_of_stack in "bos", and TTL in "ttl"
 */
void
decode_mpls_label(tvbuff_t *tvb, int offset,
                       uint32_t *label, uint8_t *exp,
                       uint8_t  *bos, uint8_t *ttl)
{
    uint8_t octet0 = tvb_get_uint8(tvb, offset+0);
    uint8_t octet1 = tvb_get_uint8(tvb, offset+1);
    uint8_t octet2 = tvb_get_uint8(tvb, offset+2);

    *label = (octet0 << 12) + (octet1 << 4) + ((octet2 >> 4) & 0xff);
    *exp = (octet2 >> 1) & 0x7;
    *bos = (octet2 & 0x1);
    *ttl = tvb_get_uint8(tvb, offset+3);
}

/*
 * PW Associated Channel Header Management Communication
 * Network (MCN) dissection as per RFC 5718.
 */
static int
dissect_pw_ach_mcc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbuff_t   *next_tvb;
    proto_tree *mpls_pw_ach_mcc_tree;
    proto_item *ti;
    uint32_t    pid;

    ti = proto_tree_add_item(tree, proto_pw_ach_mcc, tvb, 0,2, ENC_NA);
    mpls_pw_ach_mcc_tree = proto_item_add_subtree(ti, ett_mpls_pw_ach_mcc);
    proto_tree_add_item_ret_uint(mpls_pw_ach_mcc_tree, hf_mpls_pw_ach_mcc_proto,tvb, 0, 2, ENC_BIG_ENDIAN, &pid);

    next_tvb = tvb_new_subset_remaining(tvb, 2);

    if (!dissector_try_uint(pw_ach_mcc_subdissector_table, pid, next_tvb, pinfo, tree))
    {
        call_data_dissector(next_tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

/*
 * FF: PW Associated Channel Header dissection as per RFC 4385.
 */
static int
dissect_pw_ach(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbuff_t   *next_tvb;
    unsigned    channel_type;

    if (tvb_reported_length_remaining(tvb, 0) < 4) {
        proto_tree_add_expert(tree, pinfo, &ei_mpls_pw_ach_error_processing_message, tvb, 0, -1);
        return tvb_captured_length(tvb);
    }

    channel_type = tvb_get_ntohs(tvb, 2);
    p_add_proto_data(pinfo->pool, pinfo, proto_pw_ach, 0, GUINT_TO_POINTER(channel_type));

    if (tree) {
        proto_tree *mpls_pw_ach_tree;
        proto_item *ti;
        uint16_t    res;

        ti = proto_tree_add_item(tree, proto_pw_ach, tvb, 0, 4, ENC_NA);
        mpls_pw_ach_tree = proto_item_add_subtree(ti, ett_mpls_pw_ach);

        proto_tree_add_item(mpls_pw_ach_tree, hf_mpls_pw_ach_ver,
                            tvb, 0, 1, ENC_BIG_ENDIAN);

        res = tvb_get_uint8(tvb, 1);
        ti = proto_tree_add_uint(mpls_pw_ach_tree, hf_mpls_pw_ach_res,
                                        tvb, 1, 1, res);
        if (res != 0)
            expert_add_info(pinfo, ti, &ei_mpls_pw_ach_res);

        proto_tree_add_item(mpls_pw_ach_tree, hf_mpls_pw_ach_channel_type,
                            tvb, 2, 2, ENC_BIG_ENDIAN);

    } /* if (tree) */

    next_tvb     = tvb_new_subset_remaining(tvb, 4);

    if (!dissector_try_uint(pw_ach_subdissector_table, channel_type, next_tvb, pinfo, tree))
    {
        call_data_dissector(next_tvb, pinfo, tree);
    }

    if (channel_type == PW_ACH_TYPE_BFD_CV)
    {
        /* The BFD dissector has already been called, this is called in addition
           XXX - Perhaps a new dissector function that combines both is preferred.*/
        dissect_bfd_mep(next_tvb, tree, 0);
    }
    return tvb_captured_length(tvb);
}

bool
dissect_try_cw_first_nibble( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
    uint8_t nibble;

    nibble = (tvb_get_uint8(tvb, 0 ) >> 4) & 0x0F;
    switch ( nibble )
    {
        case 6:
            /*
             * XXX - this could be from an pseudo-wire without a control
             * word, with the packet's first nibble being 6.
             */
            call_dissector(dissector_ipv6, tvb, pinfo, tree);
            return true;
        case 4:
            /*
             * XXX - this could be from an pseudo-wire without a control
             * word, with the packet's first nibble being 4.
             */
            call_dissector(dissector_ip, tvb, pinfo, tree);
            return true;
        case 1:
            /*
             * XXX - this could be from an pseudo-wire without a control
             * word, with the packet's first nibble being 1.
             */
            call_dissector(dissector_pw_ach, tvb, pinfo, tree );
            return true;
        default:
            break;
    }
    return false;
}

/*
 * FF: Generic/Preferred PW MPLS Control Word dissection as per RFC 4385.
 */
static int
dissect_pw_mcw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbuff_t *next_tvb;

    if (tvb_reported_length_remaining(tvb, 0) < 4) {
        proto_tree_add_expert(tree, pinfo, &ei_mpls_pw_mcw_error_processing_message, tvb, 0, -1);
        return tvb_captured_length(tvb);
    }

    if ( dissect_try_cw_first_nibble( tvb, pinfo, tree ))
        return tvb_captured_length(tvb);

    if (tree) {
        proto_tree  *mpls_pw_mcw_tree;
        proto_item  *ti;

        ti = proto_tree_add_item(tree, proto_pw_mcw, tvb, 0, 4, ENC_NA);
        mpls_pw_mcw_tree = proto_item_add_subtree(ti, ett_mpls_pw_mcw);

        proto_tree_add_item(mpls_pw_mcw_tree, hf_mpls_pw_mcw_flags,
                            tvb, 0, 2, ENC_BIG_ENDIAN);
        /* bits 4 to 7 and FRG bits are displayed together */
        proto_tree_add_item(mpls_pw_mcw_tree, hf_mpls_pw_mcw_length,
                            tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(mpls_pw_mcw_tree, hf_mpls_pw_mcw_sequence_number,
                            tvb, 2, 2, ENC_BIG_ENDIAN);
    }
    next_tvb = tvb_new_subset_remaining(tvb, 4);
    call_data_dissector(next_tvb, pinfo, tree);
    return tvb_captured_length(tvb);
}

static int
dissect_mpls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int       offset = 0;
    uint32_t  label  = MPLS_LABEL_INVALID;
    uint8_t   exp;
    uint8_t   bos;
    uint8_t   ttl;
    tvbuff_t *next_tvb;
    int       found;
    uint8_t   first_nibble;
    struct mplsinfo mplsinfo;
    heur_dtbl_entry_t *hdtbl_entry;
    dissector_handle_t payload_handle;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPLS");
    col_set_str(pinfo->cinfo, COL_INFO, "MPLS Label Switched Packet");

    /* Ensure structure is initialized */
    memset(&mplsinfo, 0, sizeof(struct mplsinfo));

    /* Start Decoding Here. */
    while (tvb_reported_length_remaining(tvb, offset) > 0) {

        decode_mpls_label(tvb, offset, &label, &exp, &bos, &ttl);

        /*
         * FF: export (last shim in stack) info to subdissectors and
         * update pinfo
         */
        mplsinfo.label = label;
        p_add_proto_data(pinfo->pool, pinfo, proto_mpls, 0, GUINT_TO_POINTER(label));
        mplsinfo.exp   = exp;
        mplsinfo.bos   = bos;
        mplsinfo.ttl   = ttl;

        if (tree) {
            proto_item *ti;
            proto_tree *mpls_tree;

            ti = proto_tree_add_item(tree, proto_mpls, tvb, offset, 4, ENC_NA);
            mpls_tree = proto_item_add_subtree(ti, ett_mpls);

            if (mpls_bos_flowlabel && bos) {
                proto_item_append_text(ti, ", Label: %u (Flow Label)", label);
            } else {
                proto_item_append_text(ti, ", Label: %u", label);
            }
            if (label <= MPLS_LABEL_MAX_RESERVED){
                proto_tree_add_item(mpls_tree, hf_mpls_label_special, tvb,
                                    offset, 4, ENC_BIG_ENDIAN);
                proto_item_append_text(ti, " (%s)",
                                       val_to_str_const(label, special_labels, "Reserved - Unknown"));
            } else {
                proto_tree_add_item(mpls_tree, hf_mpls_label, tvb, offset, 4,
                                    ENC_BIG_ENDIAN);
            }

            proto_tree_add_item(mpls_tree, hf_mpls_exp, tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            proto_item_append_text(ti, ", Exp: %u", exp);

            proto_tree_add_item(mpls_tree, hf_mpls_bos , tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            proto_item_append_text(ti, ", S: %u", bos);

            proto_tree_add_item(mpls_tree, hf_mpls_ttl, tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            proto_item_append_text(ti, ", TTL: %u", ttl);
        }

        offset += 4;

        if ((label == MPLS_LABEL_GACH) && !bos) {
            proto_tree_add_expert(tree, pinfo, &ei_mpls_invalid_label, tvb, 0, -1);
        }

        if ((label == MPLS_LABEL_GACH) && bos) {
            (void) g_strlcpy(PW_ACH, "Generic Associated Channel Header",50);
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            call_dissector(dissector_pw_ach, next_tvb, pinfo, tree );
            return tvb_captured_length(tvb);
        }
        else
            (void) g_strlcpy(PW_ACH, "PW Associated Channel Header",50);

        if (bos)
            break;
    }

    first_nibble = (tvb_get_uint8(tvb, offset) >> 4) & 0x0F;
    p_add_proto_data(pinfo->pool, pinfo, proto_mpls, 1, GUINT_TO_POINTER(first_nibble));

    next_tvb = tvb_new_subset_remaining(tvb, offset);

    /*
     * Is there an explicit label-to-dissector binding?
     * If so, use it.
     */
    found = dissector_try_uint_new(mpls_subdissector_table, label,
                               next_tvb, pinfo, tree, false, &mplsinfo);
    if (found) {
        /* Yes, there is. */
        return tvb_captured_length(tvb);
    }

    /*
     * Do we try heuristic dissectors first? This is necessary for, e.g.,
     * Ethernet without CW where the address begins with a 4 or 6 nibble.
     */
    if (mpls_try_heuristic_first) {
        if (dissector_try_heuristic(mpls_heur_subdissector_list, next_tvb, pinfo,
                                    tree, &hdtbl_entry, NULL)) {
            return tvb_captured_length(tvb);
        }
    }

    /*
     * Use the 1st nibble logic (see BCP 128 (RFC 4928), RFC 4385 and 5586).
     * https://datatracker.ietf.org/doc/html/draft-ietf-mpls-1stnibble-06
     */
    if (dissector_try_uint_new(mpls_pfn_subdissector_table, first_nibble,
        next_tvb, pinfo, tree, false, &mplsinfo)) {

        payload_handle = dissector_get_uint_handle(mpls_pfn_subdissector_table, first_nibble);
        if (payload_handle == dissector_ip || payload_handle == dissector_ipv6) {
            /* IPv4 and IPv6 dissectors may reduce the length of the tvb.
               We need to do the same, so that any Ethernet trailer is detected.
             */
            set_actual_length(tvb, offset+tvb_reported_length(next_tvb));
        }
        return tvb_captured_length(tvb);
    }

    if (!mpls_try_heuristic_first) {
        if (dissector_try_heuristic(mpls_heur_subdissector_list, next_tvb, pinfo,
                                    tree, &hdtbl_entry, NULL)) {
            return tvb_captured_length(tvb);
        }
    }

    call_data_dissector(next_tvb, pinfo, tree);
    return tvb_captured_length(tvb);
}

void
proto_register_mpls(void)
{
    static hf_register_info mplsf_info[] = {

        /* MPLS header fields */
        {&hf_mpls_label,
         {"MPLS Label", "mpls.label",
          FT_UINT32, BASE_DEC_HEX, NULL, 0xFFFFF000,
          NULL, HFILL }
        },

        {&hf_mpls_label_special,
         {"MPLS Label", "mpls.label",
          FT_UINT32, BASE_DEC_HEX, VALS(special_labels), 0xFFFFF000,
          NULL, HFILL }
        },

        {&hf_mpls_exp,
         {"MPLS Experimental Bits", "mpls.exp",
          FT_UINT32, BASE_DEC, NULL, 0x00000E00,
          NULL, HFILL }
        },

        {&hf_mpls_bos,
         {"MPLS Bottom Of Label Stack", "mpls.bottom",
          FT_UINT32, BASE_DEC, NULL, 0x00000100,
          NULL, HFILL }
        },

        {&hf_mpls_ttl,
         {"MPLS TTL", "mpls.ttl",
          FT_UINT32, BASE_DEC, NULL, 0x000000FF,
          NULL, HFILL }
        },

        /* PW Associated Channel Header fields */
        {&hf_mpls_pw_ach_ver,
         {"Channel Version", "pwach.ver",
          FT_UINT8, BASE_DEC, NULL, 0x0F,
          "PW Associated Channel Version", HFILL }
        },

        {&hf_mpls_pw_ach_res,
         {"Reserved", "pwach.res",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
        },

        {&hf_mpls_pw_ach_channel_type,
         {"Channel Type", "pwach.channel_type",
          FT_UINT16, BASE_HEX|BASE_EXT_STRING, &mpls_pwac_types_ext, 0x0,
          "PW Associated Channel Type", HFILL }
        },

        /* Generic/Preferred PW MPLS MCC Control Word fields */
        {&hf_mpls_pw_ach_mcc_proto,
         {"Protocol Id", "mcc.proto",
          FT_UINT16, BASE_HEX|BASE_EXT_STRING, &mpls_pwac_types_ext, 0x0,
          "MCC Protocol", HFILL }
        },

        /* Generic/Preferred PW MPLS Control Word fields */
        {&hf_mpls_pw_mcw_flags,
         {"Flags", "pwmcw.flags",
          FT_UINT16, BASE_HEX, NULL, 0x0FC0,
          "Generic/Preferred PW MPLS Control Word Flags", HFILL }
        },

        {&hf_mpls_pw_mcw_length,
         {"Length", "pwmcw.length",
          FT_UINT8, BASE_DEC, NULL, 0x3F,
          "Generic/Preferred PW MPLS Control Word Length", HFILL }
        },

        {&hf_mpls_pw_mcw_sequence_number,
         {"Sequence Number", "pwmcw.sequence_number",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "Generic/Preferred PW MPLS Control Word Sequence Number", HFILL }
        },
    };

    static int *ett[] = {
        &ett_mpls,
        &ett_mpls_pw_ach,
        &ett_mpls_pw_ach_mcc,
        &ett_mpls_pw_mcw,
    };

    static ei_register_info ei[] = {
        { &ei_mpls_pw_ach_error_processing_message, { "pwach.error_processing_message", PI_MALFORMED, PI_ERROR, "Error processing Message", EXPFILL }},
        { &ei_mpls_pw_ach_res, { "pwach.res.not_zero", PI_PROTOCOL, PI_WARN, "Error: this byte is reserved and must be 0", EXPFILL }},
        { &ei_mpls_pw_mcw_error_processing_message, { "pwmcw.error_processing_message", PI_MALFORMED, PI_ERROR, "Error processing Message", EXPFILL }},
        { &ei_mpls_invalid_label, { "mpls.invalid_label", PI_PROTOCOL, PI_WARN, "Invalid Label", EXPFILL }},
    };

    /* Decode As handling */
    static build_valid_func mpls_da_build_value[1] = {mpls_value};
    static decode_as_value_t mpls_da_values = {mpls_prompt, 1, mpls_da_build_value};
    static decode_as_t mpls_da = {"mpls", "mpls.label", 1, 0, &mpls_da_values, NULL, NULL,
                                  decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    static build_valid_func mpls_pfn_da_build_value[1] = {mpls_pfn_value};
    static decode_as_value_t mpls_pfn_da_values = {mpls_pfn_prompt, 1, mpls_pfn_da_build_value};
    static decode_as_t mpls_pfn_da = {"mpls", "mpls.pfn", 1, 0, &mpls_pfn_da_values, NULL, NULL,
                                  decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    static build_valid_func pw_ach_da_build_value[1] = {pw_ach_value};
    static decode_as_value_t pw_ach_da_values = {pw_ach_prompt, 1, pw_ach_da_build_value};
    static decode_as_t pw_ach_da = {"pwach", "pwach.channel_type", 1, 0, &pw_ach_da_values, NULL, NULL,
                                  decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    expert_module_t* expert_mpls;
    module_t * module_mpls;

    proto_mpls = proto_register_protocol("MultiProtocol Label Switching Header", "MPLS", "mpls");
    proto_pw_ach = proto_register_protocol(PW_ACH, "PW Associated Channel", "pwach");
    proto_pw_mcw = proto_register_protocol("PW MPLS Control Word (generic/preferred)", "Generic PW (with CW)", "pwmcw");
    proto_pw_ach_mcc = proto_register_protocol("Management Communication Channel (MCC)", "PW Associated Management Communication Channel", "mcc");

    proto_register_field_array(proto_mpls, mplsf_info, array_length(mplsf_info));
    proto_register_subtree_array(ett, array_length(ett));
    expert_mpls = expert_register_protocol(proto_mpls);
    expert_register_field_array(expert_mpls, ei, array_length(ei));

    mpls_handle = register_dissector("mpls", dissect_mpls, proto_mpls);
    mpls_mcc_handle = register_dissector("mplsmcc", dissect_pw_ach_mcc, proto_pw_ach_mcc);
    mpls_pwcw_handle = register_dissector("mplspwcw", dissect_pw_mcw, proto_pw_mcw);
    dissector_pw_ach = register_dissector("mplspwach", dissect_pw_ach, proto_pw_ach );

    /* FF: mpls subdissector table is indexed by label */
    mpls_subdissector_table = register_dissector_table("mpls.label",
                                                       "MPLS label",
                                                       proto_mpls, FT_UINT32, BASE_DEC);

    mpls_pfn_subdissector_table = register_dissector_table("mpls.pfn",
                                                           "MPLS post-stack first nibble",
                                                           proto_mpls, FT_UINT8, BASE_HEX);

    mpls_heur_subdissector_list = register_heur_dissector_list_with_description("mpls", "MPLS payload", proto_mpls);

    pw_ach_subdissector_table  = register_dissector_table("pwach.channel_type", "PW Associated Channel Type", proto_pw_ach, FT_UINT16, BASE_HEX);

    pw_ach_mcc_subdissector_table  = register_dissector_table("mcc.proto", "PW Associated Management Communication Channel Protocol", proto_pw_ach_mcc, FT_UINT16, BASE_HEX);

    module_mpls = prefs_register_protocol( proto_mpls, NULL );

    prefs_register_obsolete_preference(module_mpls, "mplspref.payload");

    prefs_register_bool_preference(module_mpls, "try_heuristic_first",
                                "Try heuristic sub-dissectors first",
                                "Try to decode a packet heuristically, e.g. as "
                                "Ethernet without control word, before trying "
                                "sub-dissectors based upon the first nibble.",
                                &mpls_try_heuristic_first);

    /* RFC6391: Flow aware transport of pseudowire*/
    prefs_register_bool_preference(module_mpls,
                                    "flowlabel_in_mpls_header",
                                    "Assume bottom of stack label as Flow label",
                                    "Lowest label is used to segregate flows inside a pseudowire",
                                    &mpls_bos_flowlabel);

    register_decode_as(&mpls_da);
    register_decode_as(&mpls_pfn_da);
    register_decode_as(&pw_ach_da);
}

void
proto_reg_handoff_mpls(void)
{
    dissector_add_uint("ethertype", ETHERTYPE_MPLS, mpls_handle);
    dissector_add_uint("ethertype", ETHERTYPE_MPLS_MULTI, mpls_handle);
    dissector_add_uint("ppp.protocol", PPP_MPLS_UNI, mpls_handle);
    dissector_add_uint("ppp.protocol", PPP_MPLS_MULTI, mpls_handle);
    dissector_add_uint("chdlc.protocol", ETHERTYPE_MPLS, mpls_handle);
    dissector_add_uint("chdlc.protocol", ETHERTYPE_MPLS_MULTI, mpls_handle);
    dissector_add_uint("gre.proto", ETHERTYPE_MPLS, mpls_handle);
    dissector_add_uint("gre.proto", ETHERTYPE_MPLS_MULTI, mpls_handle);
    dissector_add_uint("ip.proto", IP_PROTO_MPLS_IN_IP, mpls_handle);
    dissector_add_uint("juniper.proto", JUNIPER_PROTO_MPLS, mpls_handle);
    dissector_add_uint("juniper.proto", JUNIPER_PROTO_IP_MPLS, mpls_handle);
    dissector_add_uint("juniper.proto", JUNIPER_PROTO_IP6_MPLS, mpls_handle);
    dissector_add_uint("juniper.proto", JUNIPER_PROTO_CLNP_MPLS, mpls_handle);
    dissector_add_for_decode_as("pwach.channel_type", mpls_handle);
    dissector_add_uint("sflow_245.header_protocol", SFLOW_245_HEADER_MPLS, mpls_handle);
    dissector_add_for_decode_as("l2tp.pw_type", mpls_handle);
    dissector_add_uint_with_preference("udp.port", UDP_PORT_MPLS_OVER_UDP, mpls_handle);
    dissector_add_uint("vxlan.next_proto", VXLAN_MPLS, mpls_handle);
    dissector_add_uint("nsh.next_proto", NSH_MPLS, mpls_handle);

    dissector_add_uint( "mpls.label", MPLS_LABEL_INVALID, mpls_pwcw_handle);

    dissector_add_uint("pwach.channel_type", PW_ACH_TYPE_MCC, mpls_mcc_handle);

    dissector_ipv6                  = find_dissector_add_dependency("ipv6", proto_pw_mcw );
    dissector_ip                    = find_dissector_add_dependency("ip", proto_pw_mcw );
    dissector_pw_eth_heuristic      = find_dissector_add_dependency("pw_eth_heuristic", proto_pw_mcw);

    /*
     * Our previous default behavior has been to try the Eth CW heuristic
     * on first nibble 0. Continue doing that. For other first nibbles
     * registered to dissectors, "try heuristic first" can be enabled.
     */
    dissector_add_for_decode_as("mpls.pfn", mpls_pwcw_handle);
    dissector_add_uint("mpls.pfn", 0, dissector_pw_eth_heuristic);
    dissector_add_uint("mpls.pfn", 1, dissector_pw_ach);
    dissector_add_uint("mpls.pfn", 4, dissector_ip);
    dissector_add_uint("mpls.pfn", 6, dissector_ipv6);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

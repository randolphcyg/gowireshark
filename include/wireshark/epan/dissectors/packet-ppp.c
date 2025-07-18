/* packet-ppp.c
 * Routines for ppp packet disassembly
 * RFC 1661, RFC 1662
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * This file created and by Mike Hall <mlh@io.com>
 * Copyright 1998
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/tfs.h>
#include <epan/capture_dissectors.h>
#include <epan/unit_strings.h>
#include <wsutil/pint.h>
#include <wsutil/str_util.h>
#include <epan/prefs.h>
#include "packet-ppp.h"
#include <epan/ppptypes.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include "packet-chdlc.h"
#include "packet-ip.h"
#include <epan/nlpid.h>
#include <epan/crc16-tvb.h>
#include <epan/crc32-tvb.h>
#include <epan/ipproto.h>
#include <epan/addr_resolv.h>
#include <epan/reassemble.h>
#include "packet-sll.h"
#include "packet-juniper.h"
#include "packet-sflow.h"
#include "packet-l2tp.h"

void proto_register_ppp_raw_hdlc(void);
void proto_reg_handoff_ppp_raw_hdlc(void);
void proto_register_ppp(void);
void proto_reg_handoff_ppp(void);
void proto_register_mp(void);
void proto_reg_handoff_mp(void);
void proto_register_lcp(void);
void proto_reg_handoff_lcp(void);
void proto_register_vsncp(void);
void proto_reg_handoff_vsncp(void);
void proto_register_vsnp(void);
void proto_reg_handoff_vsnp(void);
void proto_register_ipcp(void);
void proto_reg_handoff_ipcp(void);
void proto_register_bcp_bpdu(void);
void proto_reg_handoff_bcp_bpdu(void);
void proto_register_bcp_ncp(void);
void proto_reg_handoff_bcp_ncp(void);
void proto_register_osinlcp(void);
void proto_reg_handoff_bcp(void);
void proto_reg_handoff_osinlcp(void);
void proto_register_ccp(void);
void proto_reg_handoff_ccp(void);
void proto_register_cbcp(void);
void proto_reg_handoff_cbcp(void);
void proto_register_bacp(void);
void proto_reg_handoff_bacp(void);
void proto_register_bap(void);
void proto_reg_handoff_bap(void);
void proto_register_comp_data(void);
void proto_reg_handoff_comp_data(void);
void proto_register_pap(void);
void proto_reg_handoff_pap(void);
void proto_register_chap(void);
void proto_reg_handoff_chap(void);
void proto_register_pppmuxcp(void);
void proto_reg_handoff_pppmuxcp(void);
void proto_register_pppmux(void);
void proto_reg_handoff_pppmux(void);
void proto_register_mplscp(void);
void proto_reg_handoff_mplscp(void);
void proto_register_cdpcp(void);
void proto_reg_handoff_cdpcp(void);
void proto_register_ipv6cp(void);
void proto_reg_handoff_ipv6cp(void);
void proto_register_iphc_crtp(void);
void proto_reg_handoff_iphc_crtp(void);

static int proto_ppp;
static int hf_ppp_direction;
static int hf_ppp_address;
static int hf_ppp_control;
static int hf_ppp_protocol;
static int hf_ppp_code;
static int hf_ppp_identifier;
static int hf_ppp_length;
static int hf_ppp_magic_number;
static int hf_ppp_oui;
static int hf_ppp_kind;
static int hf_ppp_data;
static int hf_ppp_fcs_16;
static int hf_ppp_fcs_32;
static int hf_ppp_fcs_status;

static int ett_ppp;
static int ett_ppp_opt_type;
static int ett_ppp_unknown_opt;

static expert_field ei_ppp_opt_len_invalid;
static expert_field ei_ppp_fcs;

static int proto_ppp_hdlc;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_ppp_hdlc_data;
static int hf_ppp_hdlc_fragment;

static int ett_ppp_hdlc_data;

static int proto_lcp;
static int proto_lcp_option_vendor;
static int proto_lcp_option_mru;
static int proto_lcp_option_async_map;
static int proto_lcp_option_authprot;
static int proto_lcp_option_qualprot;
static int proto_lcp_option_magicnumber;
static int proto_lcp_option_linkqualmon;
static int proto_lcp_option_field_compress;
static int proto_lcp_option_addr_field_compress;
static int proto_lcp_option_fcs_alternatives;
static int proto_lcp_option_self_desc_pad;
static int proto_lcp_option_numbered_mode;
static int proto_lcp_option_callback;
static int proto_lcp_option_compound_frames;
static int proto_lcp_option_nomdataencap;
static int proto_lcp_option_multilink_mrru;
static int proto_lcp_option_multilink_ssnh;
static int proto_lcp_option_multilink_ep_disc;
static int proto_lcp_option_dce_identifier;
static int proto_lcp_option_multilink_pp;
static int proto_lcp_option_link_discrim;
static int proto_lcp_option_auth;
static int proto_lcp_option_cobs;
static int proto_lcp_option_prefix_elision;
static int proto_lcp_option_multilink_hdr_fmt;
static int proto_lcp_option_internationalization;
static int proto_lcp_option_sonet_sdh;

static int ett_lcp;
static int ett_lcp_options;
static int ett_lcp_vendor_opt;
static int ett_lcp_mru_opt;
static int ett_lcp_asyncmap_opt;
static int ett_lcp_authprot_opt;
static int ett_lcp_qualprot_opt;
static int ett_lcp_magicnumber_opt;
static int ett_lcp_linkqualmon_opt;
static int ett_lcp_pcomp_opt;
static int ett_lcp_acccomp_opt;
static int ett_lcp_fcs_alternatives_opt;
static int ett_lcp_self_desc_pad_opt;
static int ett_lcp_numbered_mode_opt;
static int ett_lcp_callback_opt;
static int ett_lcp_compound_frames_opt;
static int ett_lcp_nomdataencap_opt;
static int ett_lcp_multilink_mrru_opt;
static int ett_lcp_multilink_ssnh_opt;
static int ett_lcp_multilink_ep_disc_opt;
static int ett_lcp_magic_block;
static int ett_lcp_dce_identifier_opt;
static int ett_lcp_multilink_pp_opt;
static int ett_lcp_bacp_link_discrim_opt;
static int ett_lcp_auth_opt;
static int ett_lcp_cobs_opt;
static int ett_lcp_prefix_elision_opt;
static int ett_multilink_hdr_fmt_opt;
static int ett_lcp_internationalization_opt;
static int ett_lcp_sonet_sdh_opt;

static dissector_table_t lcp_option_table;

static int proto_ipcp;
static int proto_ipcp_option_addrs;
static int proto_ipcp_option_compress;
static int proto_ipcp_option_addr;
static int proto_ipcp_option_mobileipv4;
static int proto_ipcp_option_pri_dns;
static int proto_ipcp_option_pri_nbns;
static int proto_ipcp_option_sec_dns;
static int proto_ipcp_option_sec_nbns;
static int proto_ipcp_rohc_option_profiles;
static int proto_ipcp_iphc_option_rtp_compress;
static int proto_ipcp_iphc_option_enhanced_rtp_compress;
static int proto_ipcp_iphc_option_neghdrcomp;

static int ett_ipcp;
static int ett_ipcp_options;
static int ett_ipcp_ipaddrs_opt;
static int ett_ipcp_compress_opt;
static int ett_ipcp_ipaddr_opt;
static int ett_ipcp_mobileipv4_opt;
static int ett_ipcp_pridns_opt;
static int ett_ipcp_secdns_opt;
static int ett_ipcp_prinbns_opt;
static int ett_ipcp_secnbns_opt;

static int ett_ipcp_iphc_rtp_compress_opt;
static int ett_ipcp_iphc_enhanced_rtp_compress_opt;
static int ett_ipcp_iphc_neghdrcomp_opt;
static int ett_ipcp_rohc_profiles_opt;

static dissector_table_t ipcp_option_table;
static dissector_table_t ipcp_rohc_suboption_table;
static dissector_table_t ipcp_iphc_suboption_table;

static int proto_vsncp;
static int proto_vsncp_option_pdnid;
static int proto_vsncp_option_apname;
static int proto_vsncp_option_pdntype;
static int proto_vsncp_option_pdnaddress;
static int proto_vsncp_option_pco;
static int proto_vsncp_option_errorcode;
static int proto_vsncp_option_attachtype;
static int proto_vsncp_option_ipv4address;
static int proto_vsncp_option_addressalloc;
static int proto_vsncp_option_apn_ambr;
static int proto_vsncp_option_ipv6_hsgw_lla_iid;

static int hf_vsncp_opt_type;
static int hf_vsncp_opt_length;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_vsncp_protocol_configuration_length;
static int hf_vsncp_error_code;
static int hf_vsncp_identifier;
static int hf_vsncp_attach_type;
static int hf_vsncp_protocol_configuration_data;
static int hf_vsncp_default_router_address;
static int hf_vsncp_pdn_identifier;
static int hf_vsncp_address_allocation_cause;
static int hf_vsncp_length;
static int hf_vsncp_code;
static int hf_vsncp_protocol;
static int hf_vsncp_pdn_type;
static int hf_vsncp_ipv6_interface_identifier;
static int hf_vsncp_pdn_ipv4;
static int hf_vsncp_access_point_name;
static int hf_vsncp_ambr_data;
static int hf_vsncp_pdn_ipv6;

static int ett_vsncp;
static int ett_vsncp_options;
static int ett_vsncp_pdnid_opt;
static int ett_vsncp_apname_opt;
static int ett_vsncp_pdntype_opt;
static int ett_vsncp_pdnaddress_opt;
static int ett_vsncp_pco_opt;
static int ett_vsncp_errorcode_opt;
static int ett_vsncp_attachtype_opt;
static int ett_vsncp_ipv4address_opt;
static int ett_vsncp_addressalloc_opt;
static int ett_vsncp_apn_ambr_opt;
static int ett_vsncp_ipv6_hsgw_lla_iid_opt;

static dissector_table_t vsncp_option_table;

/*
* VSNP (RFC3772) has no defined packet structure.
* The following organisations have defined their own VSNPs,
* any VSNCPs containing one of the below OUIs will result in the VSNP being parsed accordingly.
*/
#define OUI_BBF 0x00256D    /* Broadband Forum TR 456 */
#define OUI_3GPP 0xCF0002   /* 3GPP X.S0057-0 */

static uint32_t vsnp_oui = -1;
static int proto_vsnp;

/* 3GPP Variables */
static int hf_vsnp_3gpp_pdnid;

/* BBF Variables */
/* TO DO */

static int ett_vsnp;

static int proto_osinlcp;
static int proto_osinlcp_option_align_npdu;

static int ett_osinlcp;
static int ett_osinlcp_options;
static int ett_osinlcp_align_npdu_opt;

static dissector_table_t osinlcp_option_table;

static int proto_bcp_bpdu;
static int hf_bcp_bpdu_flags;
static int hf_bcp_bpdu_fcs_present;
static int hf_bcp_bpdu_zeropad;
static int hf_bcp_bpdu_bcontrol;
static int hf_bcp_bpdu_pads;
static int hf_bcp_bpdu_mac_type;
static int hf_bcp_bpdu_pad;

static int ett_bcp_bpdu;
static int ett_bcp_bpdu_flags;

static int proto_bcp_ncp;
static int proto_bcp_ncp_option_bridge_id;
static int proto_bcp_ncp_option_line_id;
static int proto_bcp_ncp_option_mac_sup;
static int proto_bcp_ncp_option_tinygram_comp;
static int proto_bcp_ncp_option_lan_id;
static int proto_bcp_ncp_option_mac_addr;
static int proto_bcp_ncp_option_stp;
static int proto_bcp_ncp_option_ieee_802_tagged_frame;
static int proto_bcp_ncp_option_management_inline;
static int proto_bcp_ncp_option_bcp_ind;

static int hf_bcp_ncp_opt_type;
static int hf_bcp_ncp_opt_length;
static int hf_bcp_ncp_lan_seg_no;
static int hf_bcp_ncp_bridge_no;
static int hf_bcp_ncp_tinygram_comp;
static int hf_bcp_ncp_mac;
static int hf_bcp_ncp_mac_l;
static int hf_bcp_ncp_mac_m;
static int hf_bcp_ncp_stp_prot;
static int hf_bcp_ncp_ieee_802_tagged_frame;

static int ett_bcp_ncp;
static int ett_bcp_ncp_options;
static int ett_bcp_ncp_ieee_802_tagged_frame_opt;
static int ett_bcp_ncp_management_inline_opt;
static int ett_bcp_ncp_bcp_ind_opt;
static int ett_bcp_ncp_bridge_id_opt;
static int ett_bcp_ncp_line_id_opt;
static int ett_bcp_ncp_mac_sup_opt;
static int ett_bcp_ncp_tinygram_comp_opt;
static int ett_bcp_ncp_lan_id_opt;
static int ett_bcp_ncp_mac_addr_opt;
static int ett_bcp_ncp_stp_opt;

static dissector_table_t bcp_ncp_option_table;

static int proto_ccp;
static int proto_ccp_option_oui;
static int proto_ccp_option_predict1;
static int proto_ccp_option_predict2;
static int proto_ccp_option_puddle;
static int proto_ccp_option_hpppc;
static int proto_ccp_option_stac;
static int proto_ccp_option_stac_ascend;
static int proto_ccp_option_mppe;
static int proto_ccp_option_gfza;
static int proto_ccp_option_v42bis;
static int proto_ccp_option_bsdcomp;
static int proto_ccp_option_lzsdcp;
static int proto_ccp_option_mvrca;
static int proto_ccp_option_dce;
static int proto_ccp_option_deflate;
static int proto_ccp_option_v44lzjh;

static int ett_ccp;
static int ett_ccp_options;
static int ett_ccp_oui_opt;
static int ett_ccp_predict1_opt;
static int ett_ccp_predict2_opt;
static int ett_ccp_puddle_opt;
static int ett_ccp_hpppc_opt;
static int ett_ccp_stac_opt;
static int ett_ccp_stac_opt_check_mode;
static int ett_ccp_mppe_opt;
static int ett_ccp_mppe_opt_supp_bits;
static int ett_ccp_gfza_opt;
static int ett_ccp_v42bis_opt;
static int ett_ccp_bsdcomp_opt;
static int ett_ccp_lzsdcp_opt;
static int ett_ccp_mvrca_opt;
static int ett_ccp_dce_opt;
static int ett_ccp_deflate_opt;
static int ett_ccp_v44lzjh_opt;

static dissector_table_t ccp_option_table;

static int proto_cbcp;
static int proto_cbcp_option_no_callback;
static int proto_cbcp_option_callback_user;
static int proto_cbcp_option_callback_admin;
static int proto_cbcp_option_callback_list;

static int hf_cbcp_opt_type;
static int hf_cbcp_opt_length;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_cbcp_address_type;
static int hf_cbcp_address;
static int hf_cbcp_callback_delay;
static int hf_cbcp_no_callback;

static int ett_cbcp;
static int ett_cbcp_options;
static int ett_cbcp_callback_opt;
static int ett_cbcp_callback_opt_addr;
static int ett_cbcp_no_callback;
static int ett_cbcp_callback_user;
static int ett_cbcp_callback_admin;
static int ett_cbcp_callback_list;

static expert_field ei_cbcp_address;

static dissector_table_t cbcp_option_table;

static int proto_bacp;
static int proto_bacp_option_favored_peer;

static int hf_bacp_opt_type;
static int hf_bacp_opt_length;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_bacp_link_speed;
static int hf_bacp_magic_number;
static int hf_bacp_link_type;

static int ett_bacp;
static int ett_bacp_options;
static int ett_bacp_favored_peer_opt;

static dissector_table_t bacp_option_table;

static int proto_bap;
static int proto_bap_option_link_type;
static int proto_bap_option_phone_delta;
static int proto_bap_option_no_phone;
static int proto_bap_option_reason;
static int proto_bap_option_link_disc;
static int proto_bap_option_call_status;

static int hf_bap_opt_type;
static int hf_bap_opt_length;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_bap_sub_option_length;
static int hf_bap_call_status;
static int hf_bap_unknown_option_data;
static int hf_bap_sub_option_type;
static int hf_bap_reason;
static int hf_bap_link_discriminator;
static int hf_bap_unique_digit;
static int hf_bap_type;
static int hf_bap_identifier;
static int hf_bap_subscriber_number;
static int hf_bap_phone_number_sub_address;
static int hf_bap_response_code;
static int hf_bap_call_action;
static int hf_bap_length;

static int ett_bap;
static int ett_bap_options;
static int ett_bap_link_type_opt;
static int ett_bap_phone_delta_opt;
static int ett_bap_phone_delta_subopt;
static int ett_bap_call_status_opt;
static int ett_bap_no_phone_opt;
static int ett_bap_reason_opt;
static int ett_bap_link_disc_opt;

static expert_field ei_bap_sub_option_length;

static dissector_table_t bap_option_table;

static dissector_handle_t ppp_hdlc_handle, ppp_handle;
static dissector_handle_t ppp_raw_hdlc_handle;
static dissector_handle_t mp_handle;
static dissector_handle_t lcp_handle;
static dissector_handle_t vsncp_handle;
static dissector_handle_t vsnp_handle;
static dissector_handle_t ipcp_handle;
static dissector_handle_t bcp_bpdu_handle;
static dissector_handle_t bcp_ncp_handle;
static dissector_handle_t osinlcp_handle;
static dissector_handle_t ccp_handle;
static dissector_handle_t cbcp_handle;
static dissector_handle_t bacp_handle;
static dissector_handle_t bap_handle;
static dissector_handle_t comp_data_handle;
static dissector_handle_t pap_handle;
static dissector_handle_t chap_handle;
static dissector_handle_t muxcp_handle;
static dissector_handle_t pppmux_handle;
static dissector_handle_t mplscp_handle;
static dissector_handle_t cdpcp_handle;
static dissector_handle_t ipv6cp_handle;
static dissector_handle_t fh_handle;
static dissector_handle_t cudp16_handle;
static dissector_handle_t cudp8_handle;
static dissector_handle_t cs_handle;
static dissector_handle_t cntcp_handle;


static int proto_comp_data;

#if 0  /* see dissect_comp_data() */
static int ett_comp_data;
#endif
static int proto_pppmuxcp;
static int proto_pppmuxcp_option_def_pid;

static int hf_pppmux_flags_pid;
static int hf_pppmux_flags_field_length;
static int hf_pppmuxcp_opt_type;
static int hf_pppmuxcp_opt_length;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_pppmux_sub_frame_length;
static int hf_pppmux_flags;
static int hf_pppmux_def_prot_id;

static int ett_pppmuxcp;
static int ett_pppmuxcp_options;
static int ett_pppmuxcp_def_pid_opt;

static dissector_table_t pppmuxcp_option_table;

static int proto_pppmux;
static int hf_pppmux_protocol;

static int ett_pppmux;
static int ett_pppmux_subframe;
static int ett_pppmux_subframe_hdr;
static int ett_pppmux_subframe_flags;
static int ett_pppmux_subframe_info;

static reassembly_table mp_reassembly_table;

static int proto_mp;
static int hf_mp_frag;
static int hf_mp_frag_short;
static int hf_mp_frag_first;
static int hf_mp_frag_last;
static int hf_mp_sequence_num;
static int hf_mp_sequence_num_cls;
static int hf_mp_sequence_num_reserved;
static int hf_mp_short_sequence_num;
static int hf_mp_short_sequence_num_cls;
static int hf_mp_payload;
static int hf_mp_fragments;
static int hf_mp_fragment;
static int hf_mp_fragment_overlap;
static int hf_mp_fragment_overlap_conflicts;
static int hf_mp_fragment_multiple_tails;
static int hf_mp_fragment_too_long_fragment;
static int hf_mp_fragment_error;
static int hf_mp_fragment_count;
static int hf_mp_reassembled_in;
static int hf_mp_reassembled_length;

static int ett_mp;
static int ett_mp_flags;
static int ett_mp_fragment;
static int ett_mp_fragments;

static const fragment_items mp_frag_items = {
    /* Fragment subtrees */
    &ett_mp_fragment,
    &ett_mp_fragments,
    /* Fragment fields */
    &hf_mp_fragments,
    &hf_mp_fragment,
    &hf_mp_fragment_overlap,
    &hf_mp_fragment_overlap_conflicts,
    &hf_mp_fragment_multiple_tails,
    &hf_mp_fragment_too_long_fragment,
    &hf_mp_fragment_error,
    &hf_mp_fragment_count,
    /* Reassembled in field */
    &hf_mp_reassembled_in,
    /* Reassembled length field */
    &hf_mp_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "Message fragments"
};

static int proto_mplscp;
static int ett_mplscp;
static int ett_mplscp_options;

static int proto_cdpcp;
static int ett_cdpcp;
static int ett_cdpcp_options;

static int proto_pap;           /* PAP vars */
static int ett_pap;
static int ett_pap_data;

static int hf_pap_code;
static int hf_pap_identifier;
static int hf_pap_length;
static int hf_pap_data;
static int hf_pap_peer_id;
static int hf_pap_peer_id_length;
static int hf_pap_password;
static int hf_pap_password_length;
static int hf_pap_message;
static int hf_pap_message_length;
static int hf_pap_stuff;

static int proto_chap;           /* CHAP vars */
static int ett_chap;
static int ett_chap_data;


static int hf_chap_code;
static int hf_chap_identifier;
static int hf_chap_length;
static int hf_chap_data;
static int hf_chap_value_size;
static int hf_chap_value;
static int hf_chap_name;
static int hf_chap_message;
static int hf_chap_stuff;

static int proto_ipv6cp;  /* IPv6CP vars */
static int proto_ipv6cp_option_if_id;
static int proto_ipv6cp_option_compress;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_ipv6cp_opt_type;
static int hf_ipv6cp_opt_length;
static int hf_ipv6cp_interface_identifier;

static int ett_ipv6cp;
static int ett_ipv6cp_options;
static int ett_ipv6cp_if_id_opt;
static int ett_ipv6cp_compress_opt;

static dissector_table_t ipv6cp_option_table;

static int proto_iphc_crtp;            /* CRTP vars */
static int proto_iphc_crtp_cudp16;
static int proto_iphc_crtp_cudp8;
static int proto_iphc_crtp_cs;
static int proto_iphc_crtp_cntcp;

static int hf_iphc_crtp_cid8;
static int hf_iphc_crtp_cid16;
static int hf_iphc_crtp_gen;
static int hf_iphc_crtp_seq;
static int hf_iphc_crtp_fh_flags;
static int hf_iphc_crtp_fh_cidlenflag;
static int hf_iphc_crtp_fh_dataflag;
static int hf_iphc_crtp_cs_flags;
static int hf_iphc_crtp_cs_cnt;
static int hf_iphc_crtp_cs_invalid;
static int hf_iphc_crtp_ip_id;
static int hf_iphc_crtp_data;

static int ett_iphc_crtp;
static int ett_iphc_crtp_hdr;
static int ett_iphc_crtp_info;
static int ett_iphc_crtp_fh_flags;

static expert_field ei_iphc_crtp_ip_version;
static expert_field ei_iphc_crtp_next_protocol;
static expert_field ei_iphc_crtp_seq_nonzero;

static dissector_table_t ppp_subdissector_table;
static dissector_handle_t chdlc_handle;
static dissector_handle_t eth_withfcs_handle;
static dissector_handle_t eth_withoutfcs_handle;

static capture_dissector_handle_t chdlc_cap_handle;

static const value_string ppp_direction_vals[] = {
    {P2P_DIR_RECV, "DCE->DTE"},
    {P2P_DIR_SENT, "DTE->DCE"},
    {0,            NULL}
};

/* options */
static int ppp_fcs_decode; /* 0 = No FCS, 1 = 16 bit FCS, 2 = 32 bit FCS */
#define NO_FCS 0
#define FCS_16 1
#define FCS_32 2

const enum_val_t fcs_options[] = {
    {"none",   "None",   NO_FCS},
    {"16-bit", "16-Bit", FCS_16},
    {"32-bit", "32-Bit", FCS_32},
    {NULL,     NULL,     -1}
};

/*
 * For Default Protocol ID negotiated with PPPMuxCP. We need to
 * this ID so that if the first subframe doesn't have protocol
 * ID, we can use it
 */

static unsigned pppmux_def_prot_id;

/* PPP definitions */

/*
 * Used by the GTP dissector as well.
 * www.iana.org/assignments/ppp-numbers
 */
static const value_string ppp_vals[] = {
    {PPP_PADDING,     "Padding Protocol"},
    {PPP_ROHC_SCID,   "ROHC small-CID"},
    {PPP_ROHC_LCID,   "ROHC large-CID"},
    {PPP_IP,          "Internet Protocol version 4"},
    {PPP_OSI,         "OSI Network Layer"},
    {PPP_XNSIDP,      "Xerox NS IDP"},
    {PPP_DEC4,        "DECnet Phase IV"},
    {PPP_AT,          "Appletalk"},
    {PPP_IPX,         "Novell IPX"},
    {PPP_VJC_COMP,    "Van Jacobson Compressed TCP/IP"},
    {PPP_VJC_UNCOMP,  "Van Jacobson Uncompressed TCP/IP"},
    {PPP_BCP_BPDU,    "Bridging PDU"},
    {PPP_ST,          "Stream Protocol (ST-II)"},
    {PPP_VINES,       "Banyan Vines"},
    {PPP_AT_EDDP,     "AppleTalk EDDP"},
    {PPP_AT_SB,       "AppleTalk SmartBuffered"},
    {PPP_MP,          "Multi-Link"},
    {PPP_NB,          "NETBIOS Framing"},
    {PPP_CISCO,       "Cisco Systems"},
    {PPP_ASCOM,       "Ascom Timeplex"},
    {PPP_LBLB,        "Fujitsu Link Backup and Load Balancing (LBLB)"},
    {PPP_RL,          "DCA Remote Lan"},
    {PPP_SDTP,        "Serial Data Transport Protocol (PPP-SDTP)"},
    {PPP_LLC,         "SNA over 802.2"},
    {PPP_SNA,         "SNA"},
    {PPP_IPV6HC,      "IPv6 Header Compression "},
    {PPP_KNX,         "KNX Bridging Data"},
    {PPP_ENCRYPT,     "Encryption"},
    {PPP_ILE,         "Individual Link Encryption"},
    {PPP_IPV6,        "Internet Protocol version 6"},
    {PPP_MUX,         "PPP Muxing"},
    {PPP_VSNP,        "Vendor-Specific Network Protocol (VSNP)"},
    {PPP_TNP,         "TRILL Network Protocol (TNP)"},
    {PPP_RTP_FH,      "RTP IPHC Full Header"},
    {PPP_RTP_CTCP,    "RTP IPHC Compressed TCP"},
    {PPP_RTP_CNTCP,   "RTP IPHC Compressed Non TCP"},
    {PPP_RTP_CUDP8,   "RTP IPHC Compressed UDP 8"},
    {PPP_RTP_CRTP8,   "RTP IPHC Compressed RTP 8"},
    {PPP_STAMPEDE,    "Stampede Bridging"},
    {PPP_MPPLUS,      "MP+ Protocol"},
    {PPP_NTCITS_IPI,  "NTCITS IPI"},
    {PPP_ML_SLCOMP,   "Single link compression in multilink"},
    {PPP_COMP,        "Compressed datagram"},
    {PPP_STP_HELLO,   "802.1d Hello Packets"},
    {PPP_IBM_SR,      "IBM Source Routing BPDU"},
    {PPP_DEC_LB,      "DEC LANBridge100 Spanning Tree"},
    {PPP_CDP,         "Cisco Discovery Protocol"},
    {PPP_NETCS,       "Netcs Twin Routing"},
    {PPP_STP,         "STP - Scheduled Transfer Protocol"},
    {PPP_EDP,         "EDP - Extreme Discovery Protocol"},
    {PPP_OSCP,        "Optical Supervisory Channel Protocol (OSCP)"},
    {PPP_OSCP2,       "Optical Supervisory Channel Protocol (OSCP)"},
    {PPP_LUXCOM,      "Luxcom"},
    {PPP_SIGMA,       "Sigma Network Systems"},
    {PPP_ACSP,        "Apple Client Server Protocol"},
    {PPP_MPLS_UNI,    "MPLS Unicast"},
    {PPP_MPLS_MULTI,  "MPLS Multicast"},
    {PPP_P12844,      "IEEE p1284.4 standard - data packets"},
    {PPP_TETRA,       "ETSI TETRA Network Protocol Type 1"},
    {PPP_MFTP,        "Multichannel Flow Treatment Protocol"},
    {PPP_RTP_CTCPND,  "RTP IPHC Compressed TCP No Delta"},
    {PPP_RTP_CS,      "RTP IPHC Context State"},
    {PPP_RTP_CUDP16,  "RTP IPHC Compressed UDP 16"},
    {PPP_RTP_CRDP16,  "RTP IPHC Compressed RTP 16"},
    {PPP_CCCP,        "Cray Communications Control Protocol"},
    {PPP_CDPD_MNRP,   "CDPD Mobile Network Registration Protocol"},
    {PPP_EXPANDAP,    "Expand accelerator protocol"},
    {PPP_ODSICP,      "ODSICP NCP"},
    {PPP_DOCSIS,      "DOCSIS DLL"},
    {PPP_CETACEANNDP, "Cetacean Network Detection Protocol"},
    {PPP_LZS,         "Stacker LZS"},
    {PPP_REFTEK,      "RefTek Protocol"},
    {PPP_FC,          "Fibre Channel"},
    {PPP_EMIT,        "EMIT Protocols"},
    {PPP_VSP,         "Vendor-Specific Protocol (VSP)"},
    {PPP_TLSP,        "TRILL Link State Protocol (TLSP)"},
    {PPP_IPCP,        "Internet Protocol Control Protocol"},
    {PPP_OSINLCP,     "OSI Network Layer Control Protocol"},
    {PPP_XNSIDPCP,    "Xerox NS IDP Control Protocol"},
    {PPP_DECNETCP,    "DECnet Phase IV Control Protocol"},
    {PPP_ATCP,        "AppleTalk Control Protocol"},
    {PPP_IPXCP,       "Novell IPX Control Protocol"},
    {PPP_BCP_NCP,     "Bridging NCP"},
    {PPP_SPCP,        "Stream Protocol Control Protocol"},
    {PPP_BVCP,        "Banyan Vines Control Protocol"},
    {PPP_MLCP,        "Multi-Link Control Protocol"},
    {PPP_NBCP,        "NETBIOS Framing Control Protocol"},
    {PPP_CISCOCP,     "Cisco Systems Control Protocol"},
    {PPP_ASCOMCP,     "Ascom Timeplex"},
    {PPP_LBLBCP,      "Fujitsu LBLB Control Protocol"},
    {PPP_RLNCP,       "DCA Remote Lan Network Control Protocol (RLNCP)"},
    {PPP_SDCP,        "Serial Data Control Protocol (PPP-SDCP)"},
    {PPP_LLCCP,       "SNA over 802.2 Control Protocol"},
    {PPP_SNACP,       "SNA Control Protocol"},
    {PPP_IP6HCCP,     "IP6 Header Compression Control Protocol"},
    {PPP_KNXCP,       "KNX Bridging Control Protocol"},
    {PPP_ECP,         "Encryption Control Protocol"},
    {PPP_ILECP,       "Individual Link Encryption Control Protocol"},
    {PPP_IPV6CP,      "IPv6 Control Protocol"},
    {PPP_MUXCP,       "PPP Muxing Control Protocol"},
    {PPP_VSNCP,       "Vendor-Specific Network Control Protocol (VSNCP)"},
    {PPP_TNCP,        "TRILL Network Control Protocol"},
    {PPP_STAMPEDECP,  "Stampede Bridging Control Protocol"},
    {PPP_MPPCP,       "MP+ Control Protocol"},
    {PPP_IPICP,       "NTCITS IPI Control Protocol"},
    {PPP_SLCC,        "Single link compression in multilink control"},
    {PPP_CCP,         "Compression Control Protocol"},
    {PPP_CDPCP,       "Cisco Discovery Protocol Control Protocol"},
    {PPP_NETCSCP,     "Netcs Twin Routing"},
    {PPP_STPCP,       "STP - Control Protocol"},
    {PPP_EDPCP,       "EDPCP - Extreme Discovery Protocol Control Protocol"},
    {PPP_ACSPC,       "Apple Client Server Protocol Control"},
    {PPP_MPLSCP,      "MPLS Control Protocol"},
    {PPP_P12844CP,    "IEEE p1284.4 standard - Protocol Control"},
    {PPP_TETRACP,     "ETSI TETRA TNP1 Control Protocol"},
    {PPP_MFTPCP,      "Multichannel Flow Treatment Protocol"},
    {PPP_LCP,         "Link Control Protocol"},
    {PPP_PAP,         "Password Authentication Protocol"},
    {PPP_LQR,         "Link Quality Report"},
    {PPP_SPAP,        "Shiva Password Authentication Protocol"},
    {PPP_CBCP,        "Callback Control Protocol (CBCP)"},
    {PPP_BACP,        "BACP Bandwidth Allocation Control Protocol"},
    {PPP_BAP,         "BAP Bandwidth Allocation Protocol"},
    {PPP_VSAP,        "Vendor-Specific Authentication Protocol (VSAP)"},
    {PPP_CONTCP,      "Container Control Protocol"},
    {PPP_CHAP,        "Challenge Handshake Authentication Protocol"},
    {PPP_RSAAP,       "RSA Authentication Protocol"},
    {PPP_EAP,         "Extensible Authentication Protocol"},
    {PPP_SIEP,        "Mitsubishi Security Information Exchange Protocol (SIEP)"},
    {PPP_SBAP,        "Stampede Bridging Authorization Protocol"},
    {PPP_PRPAP,       "Proprietary Authentication Protocol"},
    {PPP_PRPAP2,      "Proprietary Authentication Protocol"},
    {PPP_PRPNIAP,     "Proprietary Node ID Authentication Protocol"},
    {0,               NULL}
};
value_string_ext ppp_vals_ext = VALUE_STRING_EXT_INIT(ppp_vals);

/* CP (LCP, CCP, IPCP, etc.) codes.
 * from pppd fsm.h
 */
#define VNDRSPCFC  0  /* Vendor Specific: RFC 2153 */
#define CONFREQ    1  /* Configuration Request */
#define CONFACK    2  /* Configuration Ack */
#define CONFNAK    3  /* Configuration Nak */
#define CONFREJ    4  /* Configuration Reject */
#define TERMREQ    5  /* Termination Request */
#define TERMACK    6  /* Termination Ack */
#define CODEREJ    7  /* Code Reject */

static const value_string cp_vals[] = {
    {VNDRSPCFC, "Vendor Specific"},
    {CONFREQ,   "Configuration Request"},
    {CONFACK,   "Configuration Ack"},
    {CONFNAK,   "Configuration Nak"},
    {CONFREJ,   "Configuration Reject"},
    {TERMREQ,   "Termination Request"},
    {TERMACK,   "Termination Ack"},
    {CODEREJ,   "Code Reject"},
    {0,         NULL}
};

/*
 * LCP-specific packet types.
 */
#define PROTREJ    8  /* Protocol Reject */
#define ECHOREQ    9  /* Echo Request */
#define ECHOREP    10 /* Echo Reply */
#define DISCREQ    11 /* Discard Request */
#define IDENT      12 /* Identification */
#define TIMEREMAIN 13 /* Time remaining */

/*
 * CCP-specific packet types.
 */
#define RESETREQ   14  /* Reset Request */
#define RESETACK   15  /* Reset Ack */

/*
 * CBCP-specific packet types.
 */
#define CBREQ      1  /* Callback Request */
#define CBRES      2  /* Callback Response */
#define CBACK      3  /* Callback Ack */

#define CBCP_OPT  6 /* Use callback control protocol */

/*
 * BAP-specific packet types.
 */
#define BAP_CREQ   1  /* Call Request */
#define BAP_CRES   2  /* Call Response */
#define BAP_CBREQ  3  /* Callback Request */
#define BAP_CBRES  4  /* Callback Response */
#define BAP_LDQREQ 5  /* Link Drop Query Request */
#define BAP_LDQRES 6  /* Link Drop Query Response */
#define BAP_CSI    7  /* Call Status Indication */
#define BAP_CSRES  8  /* Call Status Response */

static const value_string lcp_vals[] = {
    {VNDRSPCFC,  "Vendor Specific"},
    {CONFREQ,    "Configuration Request"},
    {CONFACK,    "Configuration Ack"},
    {CONFNAK,    "Configuration Nak"},
    {CONFREJ,    "Configuration Reject"},
    {TERMREQ,    "Termination Request"},
    {TERMACK,    "Termination Ack"},
    {CODEREJ,    "Code Reject"},
    {PROTREJ,    "Protocol Reject"},
    {ECHOREQ,    "Echo Request"},
    {ECHOREP,    "Echo Reply"},
    {DISCREQ,    "Discard Request"},
    {IDENT,      "Identification"},
    {TIMEREMAIN, "Time Remaining"},
    {0,          NULL}
};

static const value_string ccp_vals[] = {
    {VNDRSPCFC, "Vendor Specific"},
    {CONFREQ,   "Configuration Request"},
    {CONFACK,   "Configuration Ack"},
    {CONFNAK,   "Configuration Nak"},
    {CONFREJ,   "Configuration Reject"},
    {TERMREQ,   "Termination Request"},
    {TERMACK,   "Termination Ack"},
    {CODEREJ,   "Code Reject"},
    {RESETREQ,  "Reset Request"},
    {RESETACK,  "Reset Ack"},
    {0,         NULL}
};

static const value_string cbcp_vals[] = {
    {CBREQ, "Callback Request"},
    {CBRES, "Callback Response"},
    {CBACK, "Callback Ack"},
    {0,     NULL}
};

static const value_string bap_vals[] = {
    {BAP_CREQ,   "Call Request"},
    {BAP_CRES,   "Call Response"},
    {BAP_CBREQ,  "Callback Request"},
    {BAP_CBRES,  "Callback Response"},
    {BAP_LDQREQ, "Link Drop Query Request"},
    {BAP_LDQRES, "Link Drop Query Response"},
    {BAP_CSI,    "Call Status Indication"},
    {BAP_CSRES,  "Call Status Response"},
    {0,          NULL}
};

#define BAP_RESP_CODE_REQACK     0x00
#define BAP_RESP_CODE_REQNAK     0x01
#define BAP_RESP_CODE_REQREJ     0x02
#define BAP_RESP_CODE_REQFULLNAK 0x03
static const value_string bap_resp_code_vals[] = {
    {BAP_RESP_CODE_REQACK,     "Request Ack"},
    {BAP_RESP_CODE_REQNAK,     "Request Nak"},
    {BAP_RESP_CODE_REQREJ,     "Request Rej"},
    {BAP_RESP_CODE_REQFULLNAK, "Request Full Nak"},
    {0,                        NULL}
};

#define BAP_LINK_TYPE_ISDN      0       /* ISDN */
#define BAP_LINK_TYPE_X25       1       /* X.25 */
#define BAP_LINK_TYPE_ANALOG    2       /* Analog */
#define BAP_LINK_TYPE_SD        3       /* Switched Digital (non-ISDN) */
#define BAP_LINK_TYPE_ISDNOV    4       /* ISDN data over voice */
#define BAP_LINK_TYPE_RESV5     5       /* Reserved */
#define BAP_LINK_TYPE_RESV6     6       /* Reserved */
#define BAP_LINK_TYPE_RESV7     7       /* Reserved */
static const value_string bap_link_type_vals[] = {
    {BAP_LINK_TYPE_ISDN,   "ISDN"},
    {BAP_LINK_TYPE_X25,    "X.25"},
    {BAP_LINK_TYPE_ANALOG, "Analog"},
    {BAP_LINK_TYPE_SD,     "Switched Digital (non-ISDN)"},
    {BAP_LINK_TYPE_ISDNOV, "ISDN data over voice"},
    {BAP_LINK_TYPE_RESV5,  "Reserved"},
    {BAP_LINK_TYPE_RESV6,  "Reserved"},
    {BAP_LINK_TYPE_RESV7,  "Reserved"},
    {0,                    NULL}
};

#define BAP_PHONE_DELTA_SUBOPT_UNIQ_DIGIT       1 /* Unique Digit */
#define BAP_PHONE_DELTA_SUBOPT_SUBSC_NUM        2 /* Subscriber Number */
#define BAP_PHONE_DELTA_SUBOPT_PHONENUM_SUBADDR 3 /* Phone Number Sub Address */
static const value_string bap_phone_delta_subopt_vals[] = {
    {BAP_PHONE_DELTA_SUBOPT_UNIQ_DIGIT,       "Unique Digit"},
    {BAP_PHONE_DELTA_SUBOPT_SUBSC_NUM,        "Subscriber Number"},
    {BAP_PHONE_DELTA_SUBOPT_PHONENUM_SUBADDR, "Phone Number Sub Address"},
    {0,                                       NULL}
};

/*
 * Cause codes for Cause.
 *
 * The following code table is taken from packet-q931.c but is slightly
 * adapted to BAP protocol.
 */
static const value_string q931_cause_code_vals[] = {
    {0x00, "Call successful"},
    {0x01, "Unallocated (unassigned) number"},
    {0x02, "No route to specified transit network"},
    {0x03, "No route to destination"},
    {0x04, "Send special information tone"},
    {0x05, "Misdialled trunk prefix"},
    {0x06, "Channel unacceptable"},
    {0x07, "Call awarded and being delivered in an established channel"},
    {0x08, "Prefix 0 dialed but not allowed"},
    {0x09, "Prefix 1 dialed but not allowed"},
    {0x0A, "Prefix 1 dialed but not required"},
    {0x0B, "More digits received than allowed, call is proceeding"},
    {0x10, "Normal call clearing"},
    {0x11, "User busy"},
    {0x12, "No user responding"},
    {0x13, "No answer from user (user alerted)"},
    {0x14, "Subscriber absent"},
    {0x15, "Call rejected"},
    {0x16, "Number changed"},
    {0x17, "Reverse charging rejected"},
    {0x18, "Call suspended"},
    {0x19, "Call resumed"},
    {0x1A, "Non-selected user clearing"},
    {0x1B, "Destination out of order"},
    {0x1C, "Invalid number format (incomplete number)"},
    {0x1D, "Facility rejected"},
    {0x1E, "Response to STATUS ENQUIRY"},
    {0x1F, "Normal unspecified"},
    {0x21, "Circuit out of order"},
    {0x22, "No circuit/channel available"},
    {0x23, "Destination unattainable"},
    {0x25, "Degraded service"},
    {0x26, "Network out of order"},
    {0x27, "Transit delay range cannot be achieved"},
    {0x28, "Throughput range cannot be achieved"},
    {0x29, "Temporary failure"},
    {0x2A, "Switching equipment congestion"},
    {0x2B, "Access information discarded"},
    {0x2C, "Requested circuit/channel not available"},
    {0x2D, "Pre-empted"},
    {0x2E, "Precedence call blocked"},
    {0x2F, "Resources unavailable, unspecified"},
    {0x31, "Quality of service unavailable"},
    {0x32, "Requested facility not subscribed"},
    {0x33, "Reverse charging not allowed"},
    {0x34, "Outgoing calls barred"},
    {0x35, "Outgoing calls barred within CUG"},
    {0x36, "Incoming calls barred"},
    {0x37, "Incoming calls barred within CUG"},
    {0x38, "Call waiting not subscribed"},
    {0x39, "Bearer capability not authorized"},
    {0x3A, "Bearer capability not presently available"},
    {0x3E, "Inconsistency in designated outgoing access information and subscriber class"},
    {0x3F, "Service or option not available, unspecified"},
    {0x41, "Bearer capability not implemented"},
    {0x42, "Channel type not implemented"},
    {0x43, "Transit network selection not implemented"},
    {0x44, "Message not implemented"},
    {0x45, "Requested facility not implemented"},
    {0x46, "Only restricted digital information bearer capability is available"},
    {0x4F, "Service or option not implemented, unspecified"},
    {0x51, "Invalid call reference value"},
    {0x52, "Identified channel does not exist"},
    {0x53, "Call identity does not exist for suspended call"},
    {0x54, "Call identity in use"},
    {0x55, "No call suspended"},
    {0x56, "Call having the requested call identity has been cleared"},
    {0x57, "Called user not member of CUG"},
    {0x58, "Incompatible destination"},
    {0x59, "Non-existent abbreviated address entry"},
    {0x5A, "Destination address missing, and direct call not subscribed"},
    {0x5B, "Invalid transit network selection (national use)"},
    {0x5C, "Invalid facility parameter"},
    {0x5D, "Mandatory information element is missing"},
    {0x5F, "Invalid message, unspecified"},
    {0x60, "Mandatory information element is missing"},
    {0x61, "Message type non-existent or not implemented"},
    {0x62, "Message not compatible with call state or message type non-existent or not implemented"},
    {0x63, "Information element non-existent or not implemented"},
    {0x64, "Invalid information element contents"},
    {0x65, "Message not compatible with call state"},
    {0x66, "Recovery on timer expiry"},
    {0x67, "Parameter non-existent or not implemented - passed on"},
    {0x6E, "Message with unrecognized parameter discarded"},
    {0x6F, "Protocol error, unspecified"},
    {0x7F, "Internetworking, unspecified"},
    {0xFF, "Non-specific failure"},
    {0,    NULL}
};
static value_string_ext q931_cause_code_vals_ext = VALUE_STRING_EXT_INIT(q931_cause_code_vals);

static const value_string bap_call_status_opt_action_vals[] = {
    {0, "No retry"},
    {1, "Retry"},
    {0, NULL}
};

#define STAC_CM_NONE            0
#define STAC_CM_LCB             1
#define STAC_CM_CRC             2
#define STAC_CM_SN              3
#define STAC_CM_EXTMODE         4
static const value_string stac_checkmode_vals[] = {
    {STAC_CM_NONE,    "None"},
    {STAC_CM_LCB,     "LCB"},
    {STAC_CM_CRC,     "CRC"},
    {STAC_CM_SN,      "Sequence Number"},
    {STAC_CM_EXTMODE, "Extended Mode"},
    {0,               NULL}
};

#define LZSDCP_CM_NONE          0
#define LZSDCP_CM_LCB           1
#define LZSDCP_CM_SN            2
#define LZSDCP_CM_SN_LCB        3
static const value_string lzsdcp_checkmode_vals[] = {
    {LZSDCP_CM_NONE,   "None"},
    {LZSDCP_CM_LCB,    "LCB"},
    {LZSDCP_CM_SN,     "Sequence Number"},
    {LZSDCP_CM_SN_LCB, "Sequence Number + LCB (default)"},
    {0,                NULL}
};

#define LZSDCP_PM_NONE          0
#define LZSDCP_PM_PROC_UNCOMP   1
static const value_string lzsdcp_processmode_vals[] = {
    {LZSDCP_PM_NONE,        "None (default)"},
    {LZSDCP_PM_PROC_UNCOMP, "Process-Uncompressed"},
    {0,                     NULL}
};

#define DCE_MODE_1  1
#define DCE_MODE_2  2
static const value_string dce_mode_vals[] = {
    {DCE_MODE_1, "No Additional Negotiation"},
    {DCE_MODE_2, "Full PPP Negotiation and State Machine"},
    {0,          NULL}
};

/*
 * Options.  (LCP)
 */
#define CI_VENDORSPECIFIC       0   /* Vendor Specific [RFC2153] */
#define CI_MRU                  1   /* Maximum Receive Unit [RFC1661] */
#define CI_ASYNCMAP             2   /* Async Control Character Map */
#define CI_AUTHPROT             3   /* Authentication Protocol [RFC1661] */
#define CI_QUALITY              4   /* Quality Protocol [RFC1661] */
#define CI_MAGICNUMBER          5   /* Magic Number [RFC1661] */
#define CI_LINKQUALMON          6   /* DEPRECATED (Quality Protocol) [RFC1172] */
#define CI_PCOMPRESSION         7   /* Protocol Field Compression [RFC1661] */
#define CI_ACCOMPRESSION        8   /* Address/Control Field Compression
                                       [RFC1661] */
#define CI_FCS_ALTERNATIVES     9   /* FCS Alternatives [RFC1570] */
#define CI_SELF_DESCRIBING_PAD  10  /* Self-Describing Pad [RFC1570] */
#define CI_NUMBERED_MODE        11  /* Numbered Mode [RFC1663] */
#define CI_MULTILINK_PROC       12  /* DEPRECATED (Multi-Link Procedure) */
#define CI_CALLBACK             13  /* Callback [RFC1570] */
#define CI_CONNECTTIME          14  /* DEPRECATED (Connect Time) */
#define CI_COMPOUND_FRAMES      15  /* DEPRECATED (Compound Frames) [RFC1570] */
#define CI_NOMDATAENCAP         16  /* DEPRECATED (Nominal Data Encapsulation) */
/* NOTE: IANA lists CI_NOMDATAENCAP as 16, but it is listed as 14 in
 *       https://tools.ietf.org/html/draft-ietf-pppext-dataencap-03.
 *       Which is correct is anyone's guess. */
#define CI_MULTILINK_MRRU       17  /* Multilink MRRU [RFC1990] */
#define CI_MULTILINK_SSNH       18  /* Multilink Short Sequence Number Header
                                       [RFC1990] */
#define CI_MULTILINK_EP_DISC    19  /* Multilink Endpoint Discriminator
                                       [RFC1990] */
#define CI_PROP_KEN             20  /* Proprietary [Ken Culbert] ken@funk.com */
#define CI_DCE_IDENTIFIER       21  /* DCE Identifier [RFC1976]: Warning:
                                       Option type 25 in the RFC is incorrect */
#define CI_MULTILINK_PLUS_PROC  22  /* Multilink Plus Procedure [RFC1934] */
#define CI_LINK_DISC_FOR_BACP   23  /* Link Discriminator for BACP [RFC2125] */
#define CI_LCP_AUTHENTICATION   24  /* LCP Authentication Option [Culbert] */
#define CI_COBS                 25  /* Consistent Overhead Byte Stuffing (COBS)
                                       [Carlson] */
#define CI_PREFIX_ELISION       26  /* Prefix elision [RFC2686][RFC2687] */
#define CI_MULTILINK_HDR_FMT    27  /* Multilink header format
                                       [RFC2686][RFC2687] */
#define CI_INTERNATIONALIZATION 28  /* Internationalization [RFC2484] */
#define CI_SDL_ON_SONET_SDH     29  /* Simple Data Link on SONET/SDH
                                      [RFC2823] */
#define CI_UNASSIGNED           30  /* Unassigned ... but so are 31-255, so
                                       why do they bother specifically
                                       mentioning this one, I wonder? */

static int hf_lcp_magic_number;
static int hf_lcp_data;
static int hf_lcp_message;
static int hf_lcp_secs_remaining;
static int hf_lcp_rej_proto;
static int hf_lcp_opt_type;
static int hf_lcp_opt_length;
static int hf_lcp_opt_oui;
static int hf_lcp_opt_kind;
static int hf_lcp_opt_data;
static int hf_lcp_opt_mru;
static int hf_lcp_opt_asyncmap;
static int hf_lcp_opt_asyncmap_nul;
static int hf_lcp_opt_asyncmap_soh;
static int hf_lcp_opt_asyncmap_stx;
static int hf_lcp_opt_asyncmap_etx;
static int hf_lcp_opt_asyncmap_eot;
static int hf_lcp_opt_asyncmap_enq;
static int hf_lcp_opt_asyncmap_ack;
static int hf_lcp_opt_asyncmap_bel;
static int hf_lcp_opt_asyncmap_bs;
static int hf_lcp_opt_asyncmap_ht;
static int hf_lcp_opt_asyncmap_lf;
static int hf_lcp_opt_asyncmap_vt;
static int hf_lcp_opt_asyncmap_ff;
static int hf_lcp_opt_asyncmap_cr;
static int hf_lcp_opt_asyncmap_so;
static int hf_lcp_opt_asyncmap_si;
static int hf_lcp_opt_asyncmap_dle;
static int hf_lcp_opt_asyncmap_dc1;
static int hf_lcp_opt_asyncmap_dc2;
static int hf_lcp_opt_asyncmap_dc3;
static int hf_lcp_opt_asyncmap_dc4;
static int hf_lcp_opt_asyncmap_nak;
static int hf_lcp_opt_asyncmap_syn;
static int hf_lcp_opt_asyncmap_etb;
static int hf_lcp_opt_asyncmap_can;
static int hf_lcp_opt_asyncmap_em;
static int hf_lcp_opt_asyncmap_sub;
static int hf_lcp_opt_asyncmap_esc;
static int hf_lcp_opt_asyncmap_fs;
static int hf_lcp_opt_asyncmap_gs;
static int hf_lcp_opt_asyncmap_rs;
static int hf_lcp_opt_asyncmap_us;
static int hf_lcp_opt_auth_protocol;
static int hf_lcp_opt_algorithm;
static int hf_lcp_opt_quality_protocol;
static int hf_lcp_opt_magic_number;
static int hf_lcp_opt_reportingperiod;
static int hf_lcp_opt_fcs_alternatives;
static int hf_lcp_opt_fcs_alternatives_null;
static int hf_lcp_opt_fcs_alternatives_ccitt16;
static int hf_lcp_opt_fcs_alternatives_ccitt32;
static int hf_lcp_opt_maximum;
static int hf_lcp_opt_window;
static int hf_lcp_opt_hdlc_address;
static int hf_lcp_opt_operation;
static int hf_lcp_opt_message;
static int hf_lcp_opt_mrru;
static int hf_lcp_opt_ep_disc_class;
static int hf_lcp_opt_ip_address;
static int hf_lcp_opt_802_1_address;
static int hf_lcp_opt_magic_block;
static int hf_lcp_opt_psndn;
static int hf_lcp_opt_mode;
static int hf_lcp_opt_unused;
static int hf_lcp_opt_link_discrim;
static int hf_lcp_opt_id;
static int hf_lcp_opt_cobs_flags;
static int hf_lcp_opt_cobs_flags_res;
static int hf_lcp_opt_cobs_flags_pre;
static int hf_lcp_opt_cobs_flags_zxe;
static int hf_lcp_opt_class;
static int hf_lcp_opt_prefix;
static int hf_lcp_opt_code;
static int hf_lcp_opt_max_susp_classes;
static int hf_lcp_opt_MIBenum;
static int hf_lcp_opt_language_tag;

static bool
ppp_option_len_check(proto_tree* tree, packet_info *pinfo, tvbuff_t *tvb, int proto, unsigned len, unsigned optlen)
{
    if (len != optlen) {
        /* Bogus - option length isn't what it's supposed to be for this option. */
        proto_tree_add_expert_format(tree, pinfo, &ei_ppp_opt_len_invalid, tvb, 0, len,
                            "%s (with option length = %u byte%s; should be %u)",
                            proto_get_protocol_short_name(find_protocol_by_id(proto)),
                            len, plurality(len, "", "s"), optlen);
        return false;
    }

    return true;
}

 /* Started as a copy of dissect_ip_tcp_options(), but was changed to support
    options as a dissector table */
static void
ppp_dissect_options(tvbuff_t *tvb, int offset, unsigned length, dissector_table_t const option_dissectors,
                       packet_info *pinfo, proto_tree *opt_tree)
{
    unsigned char     opt;
    unsigned          optlen;
    const char       *name;
    dissector_handle_t option_dissector = NULL;
    tvbuff_t         *next_tvb;

    while (length > 0) {
        opt = tvb_get_uint8(tvb, offset);
        --length;      /* account for type byte */
        if (option_dissectors != NULL) {
            option_dissector = dissector_get_uint_handle(option_dissectors, opt);
            if (option_dissector == NULL) {
                name = wmem_strdup_printf(pinfo->pool, "Unknown (0x%02x)", opt);
            } else {
                name = dissector_handle_get_protocol_short_name(option_dissector);
            }
        } else {
            name = wmem_strdup_printf(pinfo->pool, "Unknown (0x%02x)", opt);
        }

        /* Option has a length. Is it in the packet? */
        if (length == 0) {
            /* Bogus - packet must at least include option code byte and
                length byte! */
            proto_tree_add_expert_format(opt_tree, pinfo, &ei_ppp_opt_len_invalid, tvb, offset, 1,
                                            "%s (length byte past end of options)", name);
            return;
        }

        optlen = tvb_get_uint8(tvb, offset + 1);  /* total including type, len */
        --length;    /* account for length byte */

        if (optlen < 2) {
            /* Bogus - option length is too short to include option code and
                option length. */
            proto_tree_add_expert_format(opt_tree, pinfo, &ei_ppp_opt_len_invalid, tvb, offset, 2,
                                "%s (with too-short option length = %u byte%s)",
                                name, optlen, plurality(optlen, "", "s"));
            return;
        } else if (optlen - 2 > length) {
            /* Bogus - option goes past the end of the header. */
            proto_tree_add_expert_format(opt_tree, pinfo, &ei_ppp_opt_len_invalid, tvb, offset, length,
                                "%s (option length = %u byte%s says option goes past end of options)",
                                name, optlen, plurality(optlen, "", "s"));
            return;
        }

        if (option_dissector == NULL) {
            proto_tree_add_subtree_format(opt_tree, tvb, offset, optlen, ett_ppp_unknown_opt, NULL, "%s (%u byte%s)",
                                            name, optlen, plurality(optlen, "", "s"));
        } else {
            next_tvb = tvb_new_subset_length(tvb, offset, optlen);
            call_dissector(option_dissector, next_tvb, pinfo, opt_tree);
            proto_item_append_text(proto_tree_get_parent(opt_tree), ", %s", name);
        }
        offset += optlen;
        length -= (optlen-2); //already accounted for type and len bytes
    }
}

static void
dissect_lcp_opt_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    uint8_t type;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_lcp_opt_type, tvb, offset, 1,
        type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_lcp_opt_length, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
}

static bool
dissect_lcp_fixed_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             int proto, int ett, int expected_length,
                             proto_tree** ret_tree, proto_item** ret_item)
{
    if (!ppp_option_len_check(tree, pinfo, tvb, proto, tvb_reported_length(tvb), expected_length))
        return false;

    *ret_item = proto_tree_add_item(tree, proto, tvb, 0, expected_length, ENC_NA);
    *ret_tree = proto_item_add_subtree(*ret_item, ett);

    dissect_lcp_opt_type_len(tvb, 0, *ret_tree, proto_registrar_get_name(proto));
    return true;
}

static bool
dissect_lcp_var_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             int proto, int ett, int expected_length,
                             proto_tree** ret_tree, proto_item** ret_item)
{
    int len = tvb_reported_length(tvb);

    if (len < expected_length) {
        /* Bogus - option length isn't what it's supposed to be for this option. */
        proto_tree_add_expert_format(tree, pinfo, &ei_ppp_opt_len_invalid, tvb, 0, len,
                            "%s (with option length = %u byte%s; should be at least %u)",
                            proto_get_protocol_short_name(find_protocol_by_id(proto_lcp_option_vendor)),
                            len, plurality(len, "", "s"), 6);
        return false;
    }

    *ret_item = proto_tree_add_item(tree, proto, tvb, 0, -1, ENC_NA);
    *ret_tree = proto_item_add_subtree(*ret_item, ett);

    dissect_lcp_opt_type_len(tvb, 0, *ret_tree, proto_registrar_get_name(proto));
    return true;
}

/* Used for:
 *  Protocol Field Compression
 *  Address and Control Field Compression
 *  Compound Frames (Deprecated)
 *  Nominal Data Encapsulation (Deprecated)
 *  Multilink Short Sequence Number Header
 *  Simple Data Link on SONET/SDH
 */
static int
dissect_lcp_simple_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int proto, int ett)
{
    proto_tree *field_tree;
    proto_item *ti;

    dissect_lcp_fixed_opt(tvb, pinfo, tree, proto, ett, 2, &field_tree, &ti);
    return tvb_captured_length(tvb);
}

/* 3GPP2 X.S0057-B v1.0
 * 9.1.4.1 3GPP2 VSNCP Configuration Options
 * Options.  (VSNCP)
 */

#define CI_PDN_IDENTIFIER       1
#define CI_ACCESS_POINT_NM      2
#define CI_PDN_TYPE             3
#define CI_PDN_ADDRESS          4
#define CI_PROTOCOL_CONFIG      5
#define CI_ERROR_CODE           6
#define CI_ATTACH_TYPE          7
#define CI_IPv4DEFAULT_ROUTER   8
#define CI_ADDRESS_ALLOC        9
#define CI_APN_AMBR             10
#define CI_IPv6_HSGW_LLA_IID    11

/*
 * CHAP Algorithms
 */
/* 0-4: Reserved */
#define CHAP_ALG_MD5      5       /* CHAP with MD5 */
#define CHAP_AGL_SHA1     6       /* CHAP with SHA-1 [Black] */
#define CHAP_AGL_SHA256   7       /* CHAP with SHA-256 */
#define CHAP_AGL_SHA3_256 8       /* CHAP with SHA3-256 */
/* 9-127: Unassigned */
#define CHAP_ALG_MSV1   128     /* MS-CHAP */
#define CHAP_ALG_MSV2   129     /* MS-CHAP-2 */

static const range_string chap_alg_rvals[] = {
    {0,                 4,                 "Reserved"},
    {CHAP_ALG_MD5,      CHAP_ALG_MD5,      "CHAP with MD5"},
    {CHAP_AGL_SHA1,     CHAP_AGL_SHA1,     "CHAP with SHA-1"},
    {CHAP_AGL_SHA256,   CHAP_AGL_SHA256,   "CHAP with SHA-256"},
    {CHAP_AGL_SHA3_256, CHAP_AGL_SHA3_256, "CHAP with SHA3-256"},
    {CHAP_ALG_MSV1,     CHAP_ALG_MSV1,     "MS-CHAP"},
    {CHAP_ALG_MSV2,     CHAP_ALG_MSV2,     "MS-CHAP-2"},
    {0,                 0,                 NULL}
};


/*
 * Options.  (IPCP)
 * https://tools.ietf.org/html/rfc1172
 * https://tools.ietf.org/html/rfc1332
 * https://tools.ietf.org/html/rfc1877
 * https://tools.ietf.org/html/rfc2290
 * https://tools.ietf.org/html/rfc3241
 * https://tools.ietf.org/html/rfc3545
 */
#define CI_ADDRS            1       /* IP Addresses (deprecated) (RFC 1172) */
#define CI_COMPRESS_PROTO   2       /* Compression Protocol (RFC 1332) */
#define CI_ADDR             3       /* IP Address (RFC 1332) */
#define CI_MOBILE_IPv4      4       /* Mobile IPv4 (RFC 2290) */
#define CI_PRI_DNS          129     /* Primary DNS value (RFC 1877) */
#define CI_PRI_NBNS         130     /* Primary NBNS value (RFC 1877) */
#define CI_SEC_DNS          131     /* Secondary DNS value (RFC 1877) */
#define CI_SEC_NBNS         132     /* Secondary NBNS value (RFC 1877) */

static int hf_ipcp_opt_type;
static int hf_ipcp_opt_length;
static int hf_ipcp_opt_src_address;
static int hf_ipcp_opt_dst_address;
static int hf_ipcp_opt_compress_proto;
static int hf_ipcp_opt_max_cid;
static int hf_ipcp_opt_mrru;
static int hf_ipcp_opt_max_slot_id;
static int hf_ipcp_opt_comp_slot_id;
static int hf_ipcp_opt_tcp_space;
static int hf_ipcp_opt_non_tcp_space;
static int hf_ipcp_opt_f_max_period;
static int hf_ipcp_opt_f_max_time;
static int hf_ipcp_opt_max_header;
static int hf_ipcp_data;
static int hf_ipcp_opt_ip_address;
static int hf_ipcp_opt_mobilenodehomeaddr;
static int hf_ipcp_opt_pri_dns_address;
static int hf_ipcp_opt_pri_nbns_address;
static int hf_ipcp_opt_sec_dns_address;
static int hf_ipcp_opt_sec_nbns_address;

static int hf_ipcp_opt_rohc_type;
static int hf_ipcp_opt_rohc_length;
static int hf_ipcp_opt_rohc_profile;
static int hf_ipcp_opt_iphc_type;
static int hf_ipcp_opt_iphc_length;
static int hf_ipcp_opt_iphc_param;

/*
 * IP Compression options
 */
#define IPCP_ROHC               0x0003  /* RFC3241 */
#define IPCP_COMPRESS_VJ_1172   0x0037  /* value defined in RFC1172 (typo) */
#define IPCP_COMPRESS_VJ        0x002d  /* value defined in RFC1332 (correct) */
#define IPCP_COMPRESS_IPHC      0x0061  /* RFC3544 (and RFC2509) */

static const value_string ipcp_compress_proto_vals[] = {
    {IPCP_ROHC,             "Robust Header Compression (ROHC)"},
    {IPCP_COMPRESS_VJ,      "VJ compression"},
    {IPCP_COMPRESS_VJ_1172, "VJ compression (RFC1172-typo)"},
    {IPCP_COMPRESS_IPHC,    "IPHC compression"},
    {0,                     NULL}
};

/* IPHC suboptions (RFC2508, 3544) */
#define IPCP_IPHC_CRTP          1
#define IPCP_IPHC_ECRTP         2
#define IPCP_IPHC_NEGHC         3

static const value_string ipcp_iphc_parameter_vals[] = {
    {1, "The number of contexts for TCP Space is 0"},
    {2, "The number of contexts for Non TCP Space is 0"},
    {0, NULL}
};


/* ROHC suboptions */
#define IPCP_ROHC_PROFILES      1

/* From https://tools.ietf.org/html/rfc3095 */
static const value_string ipcp_rohc_profile_vals[] = {
    {0x0000, "ROHC uncompressed -- no compression"},
    {0x0002, "ROHC UDP -- non-RTP UDP/IP compression"},
    {0x0003, "ROHC ESP -- ESP/IP compression"},
    {0,      NULL}
};

/*
* Options.  (bcp_ncp)
1       Bridge-Identification
2       Line-Identification
3       MAC-Support
4       Tinygram-Compression
5       LAN-Identification (obsoleted)
6       MAC-Address
7       Spanning-Tree-Protocol (old formatted)
8       IEEE 802 Tagged Frame
9       Management Inline
10       Bridge Control Packet Indicator

*/
#define CI_BCPNCP_BRIDGE_ID 1
#define CI_BCPNCP_LINE_ID 2
#define CI_BCPNCP_MAC_SUPPORT 3
#define CI_BCPNCP_TINYGRAM_COMP 4
#define CI_BCPNCP_LAN_ID 5
#define CI_BCPNCP_MAC_ADDRESS 6
#define CI_BCPNCP_STP 7
#define CI_BCPNCP_IEEE_802_TAGGED_FRAME 8
#define CI_BCPNCP_MANAGEMENT_INLINE 9
#define CI_BCPNCP_BCP_IND 10

/*
 * Options.  (OSINLCP)
 */
#define CI_OSINLCP_ALIGN_NPDU    1  /* Alignment of the OSI NPDU (RFC 1377) */

static int hf_osinlcp_opt_type;
static int hf_osinlcp_opt_length;
static int hf_osinlcp_opt_alignment;

/*
 * Options.  (CCP)
 */
#define CI_CCP_OUI      0       /* OUI (RFC1962) */
#define CI_CCP_PREDICT1 1       /* Predictor type 1 (RFC1962) */
#define CI_CCP_PREDICT2 2       /* Predictor type 2 (RFC1962) */
#define CI_CCP_PUDDLE   3       /* Puddle Jumper (RFC1962) */
#define CI_CCP_HPPPC    16      /* Hewlett-Packard PPC (RFC1962) */
#define CI_CCP_STAC     17      /* stac Electronics LZS (RFC1974) */
#define CI_CCP_MPPE     18      /* Microsoft PPE/C (RFC2118/3078) */
#define CI_CCP_GFZA     19      /* Gandalf FZA (RFC1962) */
#define CI_CCP_V42BIS   20      /* V.42bis compression */
#define CI_CCP_BSDLZW   21      /* BSD LZW Compress (RFC1977) */
#define CI_CCP_LZSDCP   23      /* LZS-DCP (RFC1967) */
#define CI_CCP_MVRCA    24      /* MVRCA (Magnalink) (RFC1975) */
#define CI_CCP_DCE      25      /* DCE (RFC1976) */
#define CI_CCP_DEFLATE  26      /* Deflate (RFC1979) */
#define CI_CCP_V44LZJH  27      /* V.44/LZJH (https://tools.ietf.org/html/draft-heath-ppp-v44-01) */
#define CI_CCP_RESERVED 255     /* Reserved (RFC1962) */

static int hf_ccp_opt_type;
static int hf_ccp_opt_length;
static int hf_ccp_opt_oui;
static int hf_ccp_opt_subtype;
static int hf_ccp_opt_data;
static int hf_ccp_opt_history_count;
static int hf_ccp_opt_cm;
static int hf_ccp_opt_cm_reserved;
static int hf_ccp_opt_cm_check_mode;
static int hf_ccp_opt_supported_bits;
static int hf_ccp_opt_supported_bits_h;
static int hf_ccp_opt_supported_bits_m;
static int hf_ccp_opt_supported_bits_s;
static int hf_ccp_opt_supported_bits_l;
static int hf_ccp_opt_supported_bits_d;
static int hf_ccp_opt_supported_bits_c;
static int hf_ccp_opt_history;
static int hf_ccp_opt_version;
static int hf_ccp_opt_vd;
static int hf_ccp_opt_vd_vers;
static int hf_ccp_opt_vd_dict;
static int hf_ccp_opt_check_mode;
static int hf_ccp_opt_process_mode;
static int hf_ccp_opt_fe;
static int hf_ccp_opt_p;
static int hf_ccp_opt_History; /* Different than hf_ccp_opt_history */
static int hf_ccp_opt_contexts;
static int hf_ccp_opt_mode;
static int hf_ccp_opt_window;
static int hf_ccp_opt_method;
static int hf_ccp_opt_mbz;
static int hf_ccp_opt_chk;
static int hf_ccp_opt_mode_dictcount;
static int hf_ccp_opt_dict_size;
static int hf_ccp_opt_history_length;

/*
 * Options.  (CBCP)
 */
#define CI_CBCP_NO_CALLBACK     1  /* No callback */
#define CI_CBCP_CB_USER         2  /* Callback to a user-specified number */
#define CI_CBCP_CB_PRE          3  /* Callback to a pre-specified or
                                      administrator specified number */
#define CI_CBCP_CB_ANY          4  /* Callback to any of a list of numbers */

/*
 * Options.  (BACP)
 */
#define CI_BACP_FAVORED_PEER    1  /* Favored-Peer */

/*
 * Options.  (BAP)
 */
#define CI_BAP_LINK_TYPE           1  /* Link Type */
#define CI_BAP_PHONE_DELTA         2  /* Phone-Delta */
#define CI_BAP_NO_PHONE_NUM_NEEDED 3  /* No Phone Number Needed */
#define CI_BAP_REASON              4  /* Reason */
#define CI_BAP_LINK_DISC           5  /* Link Discriminator */
#define CI_BAP_CALL_STATUS         6  /* Call Status */

static int dissect_ppp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);

static const value_string pap_vals[] = {
    {CONFREQ, "Authenticate-Request"},
    {CONFACK, "Authenticate-Ack"},
    {CONFNAK, "Authenticate-Nak"},
    {0,       NULL}
};

#define CHAP_CHAL  1  /* CHAP Challenge */
#define CHAP_RESP  2  /* CHAP Response */
#define CHAP_SUCC  3  /* CHAP Success */
#define CHAP_FAIL  4  /* CHAP Failure */

static const value_string chap_vals[] = {
    {CHAP_CHAL, "Challenge"},
    {CHAP_RESP, "Response"},
    {CHAP_SUCC, "Success"},
    {CHAP_FAIL, "Failure"},
    {0,         NULL}
};

static const value_string pppmuxcp_vals[] = {
    {CONFREQ, "Configuration Request"},
    {CONFACK, "Configuration Ack"},
    {0,       NULL}
};

/*
 * PPPMuxCP options
 */

#define CI_DEFAULT_PID   1

static const true_false_string tfs_pppmux_length_field = { "2 bytes", "1 byte" };

/*
 * Options.  (IPv6CP)
 */
#define CI_IPV6CP_IF_ID         1       /* Interface Identifier (RFC 2472) */
#define CI_IPV6CP_COMPRESSTYPE  2       /* Compression Type (RFC 2472) */

/*
*******************************************************************************
* DETAILS : Calculate a new FCS-16 given the current FCS-16 and the new data.
*******************************************************************************
*/
static uint16_t
fcs16(tvbuff_t *tvbuff)
{
    unsigned len = tvb_reported_length(tvbuff) - 2;

    /* Check for Invalid Length */
    if (len == 0)
        return (0x0000);
    return crc16_ccitt_tvb(tvbuff, len);
}

/*
*******************************************************************************
* DETAILS : Calculate a new FCS-32 given the current FCS-32 and the new data.
*******************************************************************************
*/
static uint32_t
fcs32(tvbuff_t *tvbuff)
{
    unsigned len = tvb_reported_length(tvbuff) - 4;

    /* Check for invalid Length */
    if (len == 0)
        return (0x00000000);
    return crc32_ccitt_tvb(tvbuff, len);
}

tvbuff_t *
decode_fcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *fh_tree, int fcs_decode, int proto_offset)
{
    tvbuff_t *next_tvb;
    int       len, reported_len;

    /*
     * Remove the FCS, if any, from the packet data.
     */
    switch (fcs_decode) {

    case NO_FCS:
        next_tvb = tvb_new_subset_remaining(tvb, proto_offset);
        break;

    case FCS_16:
        /*
         * Do we have the entire packet, and does it include a 2-byte FCS?
         */
        len = tvb_captured_length_remaining(tvb, proto_offset);
        reported_len = tvb_reported_length_remaining(tvb, proto_offset);
        if (reported_len < 2 || len < 0) {
            /*
             * The packet is claimed not to even have enough data for a 2-byte
             * FCS, or we're already past the end of the captured data.
             * Don't slice anything off.
             */
            next_tvb = tvb_new_subset_remaining(tvb, proto_offset);
        } else if (len < reported_len) {
            /*
             * The packet is claimed to have enough data for a 2-byte FCS, but
             * we didn't capture all of the packet.
             * Slice off the 2-byte FCS from the reported length, and trim the
             * captured length so it's no more than the reported length; that
             * will slice off what of the FCS, if any, is in the captured
             * length.
             */
            reported_len -= 2;
            if (len > reported_len)
                len = reported_len;
            next_tvb = tvb_new_subset_length_caplen(tvb, proto_offset, len, reported_len);
        } else {
            /*
             * We have the entire packet, and it includes a 2-byte FCS.
             * Slice it off.
             */
            len -= 2;
            reported_len -= 2;
            next_tvb = tvb_new_subset_length_caplen(tvb, proto_offset, len, reported_len);

            /*
             * Compute the FCS and put it into the tree.
             */
            proto_tree_add_checksum(fh_tree, tvb, proto_offset + len, hf_ppp_fcs_16, hf_ppp_fcs_status, &ei_ppp_fcs, pinfo, fcs16(tvb),
                            ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
        }
        break;

    case FCS_32:
        /*
         * Do we have the entire packet, and does it include a 4-byte FCS?
         */
        len = tvb_captured_length_remaining(tvb, proto_offset);
        reported_len = tvb_reported_length_remaining(tvb, proto_offset);
        if (reported_len < 4) {
            /*
             * The packet is claimed not to even have enough data for a 4-byte
             * FCS.  Just pass on the tvbuff as is.
             */
            next_tvb = tvb_new_subset_remaining(tvb, proto_offset);
        } else if (len < reported_len) {
            /*
             * The packet is claimed to have enough data for a 4-byte FCS, but
             * we didn't capture all of the packet.
             * Slice off the 4-byte FCS from the reported length, and trim the
             * captured length so it's no more than the reported length; that
             * will slice off what of the FCS, if any, is in the captured
             * length.
             */
            reported_len -= 4;
            if (len > reported_len)
                len = reported_len;
            next_tvb = tvb_new_subset_length_caplen(tvb, proto_offset, len, reported_len);
        } else {
            /*
             * We have the entire packet, and it includes a 4-byte FCS.
             * Slice it off.
             */
            len -= 4;
            reported_len -= 4;
            next_tvb = tvb_new_subset_length_caplen(tvb, proto_offset, len, reported_len);

            /*
             * Compute the FCS and put it into the tree.
             */
            proto_tree_add_checksum(fh_tree, tvb, proto_offset + len, hf_ppp_fcs_32, hf_ppp_fcs_status, &ei_ppp_fcs, pinfo, fcs32(tvb),
                            ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
        }
        break;

    default:
        DISSECTOR_ASSERT_NOT_REACHED();
        next_tvb = NULL;
        break;
    }

    return next_tvb;
}

static bool
capture_ppp_hdlc(const unsigned char *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
    if (!BYTES_ARE_IN_FRAME(offset, len, 2))
        return false;

    if (pd[0] == CHDLC_ADDR_UNICAST || pd[0] == CHDLC_ADDR_MULTICAST)
        return call_capture_dissector(chdlc_cap_handle, pd, offset, len, cpinfo, pseudo_header);

    if (!BYTES_ARE_IN_FRAME(offset, len, 4))
        return false;

    return try_capture_dissector("ppp_hdlc", pntoh16(&pd[offset + 2]), pd, offset + 4, len, cpinfo, pseudo_header);
}

static int
dissect_lcp_vendor_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *ti;
    int offset = 0;
    int len = tvb_reported_length(tvb);

    if (!dissect_lcp_var_opt(tvb, pinfo, tree, proto_lcp_option_vendor, ett_lcp_vendor_opt, 6,
                             &field_tree, &ti))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_lcp_opt_oui, tvb, offset + 2, 3, ENC_BIG_ENDIAN);

    proto_tree_add_item(field_tree, hf_lcp_opt_kind, tvb, offset + 5, 1,
        ENC_BIG_ENDIAN);
    if (len > 6) {
        proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset + 6,
            len - 6, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_lcp_mru_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *ti;
    uint32_t mru;
    int offset = 0;

    if (!dissect_lcp_fixed_opt(tvb, pinfo, tree,
                             proto_lcp_option_mru, ett_lcp_mru_opt, 4,
                             &field_tree, &ti))
        return tvb_captured_length(tvb);

    proto_tree_add_item_ret_uint(field_tree, hf_lcp_opt_mru, tvb, offset + 2, 2,
        ENC_BIG_ENDIAN, &mru);
    proto_item_append_text(ti, ": %u", mru);
    return tvb_captured_length(tvb);
}

static int
dissect_lcp_async_map_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf, *ti;
    int offset = 0;
    static int * const asyncmap_fields[] = {
        &hf_lcp_opt_asyncmap_us,  &hf_lcp_opt_asyncmap_rs,
        &hf_lcp_opt_asyncmap_gs,  &hf_lcp_opt_asyncmap_fs,
        &hf_lcp_opt_asyncmap_esc, &hf_lcp_opt_asyncmap_sub,
        &hf_lcp_opt_asyncmap_em,  &hf_lcp_opt_asyncmap_can,
        &hf_lcp_opt_asyncmap_etb, &hf_lcp_opt_asyncmap_syn,
        &hf_lcp_opt_asyncmap_nak, &hf_lcp_opt_asyncmap_dc4,
        &hf_lcp_opt_asyncmap_dc3, &hf_lcp_opt_asyncmap_dc2,
        &hf_lcp_opt_asyncmap_dc1, &hf_lcp_opt_asyncmap_dle,
        &hf_lcp_opt_asyncmap_si,  &hf_lcp_opt_asyncmap_so,
        &hf_lcp_opt_asyncmap_cr,  &hf_lcp_opt_asyncmap_ff,
        &hf_lcp_opt_asyncmap_vt,  &hf_lcp_opt_asyncmap_lf,
        &hf_lcp_opt_asyncmap_ht,  &hf_lcp_opt_asyncmap_bs,
        &hf_lcp_opt_asyncmap_bel, &hf_lcp_opt_asyncmap_ack,
        &hf_lcp_opt_asyncmap_enq, &hf_lcp_opt_asyncmap_eot,
        &hf_lcp_opt_asyncmap_etx, &hf_lcp_opt_asyncmap_stx,
        &hf_lcp_opt_asyncmap_soh, &hf_lcp_opt_asyncmap_nul,
        NULL
    };

    static const char *ctrlchars[32] = {
        "NUL", "SOH",       "STX", "ETX",        "EOT", "ENQ", "ACK", "BEL",
        "BS",  "HT",        "LF",  "VT",         "FF",  "CR",  "SO",  "SI",
        "DLE", "DC1 (XON)", "DC2", "DC3 (XOFF)", "DC4", "NAK", "SYN", "ETB",
        "CAN", "EM",        "SUB", "ESC",        "FS",  "GS",  "RS",  "US"
    };

    uint32_t map;
    bool anyctrlchars;
    int i;

    if (!dissect_lcp_fixed_opt(tvb, pinfo, tree,
                             proto_lcp_option_async_map, ett_lcp_asyncmap_opt, 6,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    map = tvb_get_ntohl(tvb, offset + 2);
    proto_item_append_text(tf, ": 0x%08x", map);

    ti = proto_tree_add_bitmask(field_tree, tvb, offset + 2,
        hf_lcp_opt_asyncmap, ett_lcp_asyncmap_opt, asyncmap_fields,
        ENC_BIG_ENDIAN);

    if (map == 0x00000000) {
        proto_item_append_text(tf, " (None)");
        proto_item_append_text(ti, " (None)");
    } else if (map == 0xffffffff) {
        proto_item_append_text(tf, " (All)");
        proto_item_append_text(ti, " (All)");
    } else {
        for (anyctrlchars = false, i = 31; i >= 0; i--) {
            if (map & (1 << i)) {
                if (anyctrlchars)
                    proto_item_append_text(tf, ", %s", ctrlchars[i]);
                else {
                    anyctrlchars = true;
                    proto_item_append_text(tf, "%s", ctrlchars[i]);
                }
            }
        }
        proto_item_append_text(tf, ")");
    }

    return tvb_captured_length(tvb);
}

static int
dissect_lcp_authprot_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *ti;
    uint32_t protocol;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    if (!dissect_lcp_var_opt(tvb, pinfo, tree, proto_lcp_option_authprot, ett_lcp_authprot_opt, 4,
                             &field_tree, &ti))
        return tvb_captured_length(tvb);

    proto_tree_add_item_ret_uint(field_tree, hf_lcp_opt_auth_protocol, tvb, offset + 2,
        2, ENC_BIG_ENDIAN, &protocol);
    proto_item_append_text(ti, ": %s (0x%02x)", val_to_str_ext_const(protocol, &ppp_vals_ext, "Unknown"),
        protocol);

    if (length > 4) {
        offset += 4;
        length -= 4;
        if (protocol == PPP_CHAP) {
            proto_tree_add_item(field_tree, hf_lcp_opt_algorithm, tvb, offset,
                1, ENC_BIG_ENDIAN);
            if (length > 1) {
                proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb,
                    offset + 1, length - 1, ENC_NA);
            }
        } else {
            proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset,
                length, ENC_NA);
        }
    }

    return tvb_captured_length(tvb);
}

static int
dissect_lcp_qualprot_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *ti;
    uint32_t protocol;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    if (!dissect_lcp_var_opt(tvb, pinfo, tree, proto_lcp_option_qualprot, ett_lcp_qualprot_opt, 4,
                             &field_tree, &ti))
        return tvb_captured_length(tvb);

    proto_tree_add_item_ret_uint(field_tree, hf_lcp_opt_quality_protocol, tvb, offset + 2,
        2, ENC_BIG_ENDIAN, &protocol);
    proto_item_append_text(ti, ": %s (0x%02x)", val_to_str_ext_const(protocol, &ppp_vals_ext, "Unknown"),
        protocol);

    if (length > 4) {
        proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset + 4,
            length + 4, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_lcp_magicnumber_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *ti;
    uint32_t magic_number;
    int offset = 0;

    if (!dissect_lcp_fixed_opt(tvb, pinfo, tree,
                             proto_lcp_option_magicnumber, ett_lcp_magicnumber_opt, 6,
                             &field_tree, &ti))
        return tvb_captured_length(tvb);

    proto_tree_add_item_ret_uint(field_tree, hf_lcp_opt_magic_number, tvb, offset + 2,
        4, ENC_BIG_ENDIAN, &magic_number);
    proto_item_append_text(ti, ": 0x%08x", magic_number);

    return tvb_captured_length(tvb);
}

static int
dissect_lcp_linkqualmon_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *ti, *tf;
    uint32_t reportingperiod;
    int offset = 0;

    if (!dissect_lcp_fixed_opt(tvb, pinfo, tree,
                             proto_lcp_option_linkqualmon, ett_lcp_linkqualmon_opt, 6,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    ti = proto_tree_add_item_ret_uint(field_tree, hf_lcp_opt_reportingperiod,
        tvb, offset + 2, 4, ENC_BIG_ENDIAN, &reportingperiod);
    proto_item_append_text(tf, ": %u microsecond%s", reportingperiod, plurality(reportingperiod, "", "s"));
    if (reportingperiod == 0)
    {
        proto_item_append_text(ti, " [illegal]");
        proto_item_append_text(tf, " [illegal]");
    }

    return tvb_captured_length(tvb);
}

static int
dissect_lcp_field_compress(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_lcp_simple_opt(tvb, pinfo, tree, proto_lcp_option_field_compress, ett_lcp_pcomp_opt);
}

static int
dissect_lcp_addr_field_compress(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_lcp_simple_opt(tvb, pinfo, tree, proto_lcp_option_addr_field_compress, ett_lcp_acccomp_opt);
}

static int
dissect_lcp_fcs_alternatives_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    static int * const fcs_alternatives_fields[] = {
        &hf_lcp_opt_fcs_alternatives_ccitt32,
        &hf_lcp_opt_fcs_alternatives_ccitt16,
        &hf_lcp_opt_fcs_alternatives_null,
        NULL
    };

    if (!dissect_lcp_fixed_opt(tvb, pinfo, tree,
                             proto_lcp_option_fcs_alternatives, ett_lcp_fcs_alternatives_opt, 3,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_bitmask(field_tree, tvb, offset + 2,
        hf_lcp_opt_fcs_alternatives, ett_lcp_fcs_alternatives_opt,
        fcs_alternatives_fields, ENC_NA);
    proto_item_append_text(tf, ": 0x%02x", tvb_get_uint8(tvb, offset + 2));
    return tvb_captured_length(tvb);
}

static int
dissect_lcp_self_describing_pad_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf, *ti;
    uint32_t maximum;
    int offset = 0;

    if (!dissect_lcp_fixed_opt(tvb, pinfo, tree,
                             proto_lcp_option_self_desc_pad, ett_lcp_self_desc_pad_opt, 3,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    ti = proto_tree_add_item_ret_uint(field_tree, hf_lcp_opt_maximum, tvb,
        offset + 2, 1, ENC_BIG_ENDIAN, &maximum);
    proto_item_append_text(tf, ": %u octet%s", maximum, plurality(maximum, "", "s"));
    if (maximum == 0)
    {
        proto_item_append_text(ti, " [invalid]");
        proto_item_append_text(tf, " [invalid]");
    }

    return tvb_captured_length(tvb);
}

static int
dissect_lcp_numbered_mode_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf, *ti;
    uint32_t window;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    if (!dissect_lcp_var_opt(tvb, pinfo, tree, proto_lcp_option_numbered_mode, ett_lcp_numbered_mode_opt, 3,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    ti = proto_tree_add_item_ret_uint(field_tree, hf_lcp_opt_window, tvb,
        offset + 2, 1, ENC_BIG_ENDIAN, &window);
    proto_item_append_text(tf, ": %u frame%s", window, plurality(window, "", "s"));
    if (window == 0 || window > 127)
    {
        proto_item_append_text(ti, " [invalid]");
        proto_item_append_text(tf, " [invalid]");
    }
    if (length > 3) {
        proto_tree_add_item(field_tree, hf_lcp_opt_hdlc_address, tvb,
            offset + 3, length - 3, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

/* https://tools.ietf.org/html/rfc1570#section-2.3 only lists 0-4, but
 * https://tools.ietf.org/html/draft-ietf-pppext-callback-ds-02 lists 5 as
 * "E.165 number", rather than "unassigned", and
 * https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cbcp/efee6372-3251-471e-a141-71d1e7fef21f
 * does indicate 6 as below.  Since 5 is only mentioned in the draft, leave it
 * as "unassigned"?
 */
static const value_string callback_op_vals[] = {
    {0, "Location is determined by user authentication"},
    {1, "Message is dialing string"},
    {2, "Message is location identifier"},
    {3, "Message is E.164"},
    {4, "Message is distinguished name"},
    {5, "unassigned"}, /* "Message is E.165"? */
    {6, "Location is determined during CBCP negotiation"},
    {0, NULL}
};

static int
dissect_lcp_callback_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    uint32_t operation;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    if (!dissect_lcp_var_opt(tvb, pinfo, tree, proto_lcp_option_callback, ett_lcp_callback_opt, 3,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item_ret_uint(field_tree, hf_lcp_opt_operation, tvb, offset + 2, 1,
        ENC_BIG_ENDIAN, &operation);
    proto_item_append_text(tf, ": %s", val_to_str_const(operation, callback_op_vals, "Unknown"));

    if (length > 3) {
        proto_tree_add_item(field_tree, hf_lcp_opt_message, tvb, offset + 3,
            length - 3, ENC_NA);
    }
    return tvb_captured_length(tvb);
}

static int
dissect_lcp_compound_frames_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_lcp_simple_opt(tvb, pinfo, tree, proto_lcp_option_compound_frames, ett_lcp_compound_frames_opt);
}

static int
dissect_lcp_nomdataencap_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_lcp_simple_opt(tvb, pinfo, tree, proto_lcp_option_nomdataencap, ett_lcp_nomdataencap_opt);
}

/* https://tools.ietf.org/html/rfc1990#section-5.1.1 */
static int
dissect_lcp_multilink_mrru_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    uint32_t mrru;
    int offset = 0;

    if (!dissect_lcp_fixed_opt(tvb, pinfo, tree,
                             proto_lcp_option_multilink_mrru, ett_lcp_multilink_mrru_opt, 4,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item_ret_uint(field_tree, hf_lcp_opt_mrru, tvb, offset + 2, 2,
        ENC_BIG_ENDIAN, &mrru);
    proto_item_append_text(tf, ": %u", mrru);
    return tvb_captured_length(tvb);
}

static int
dissect_lcp_multilink_ssnh_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_lcp_simple_opt(tvb, pinfo, tree, proto_lcp_option_multilink_ssnh, ett_lcp_multilink_ssnh_opt);
}

#define CLASS_NULL                      0
#define CLASS_LOCAL                     1
#define CLASS_IP                        2
#define CLASS_IEEE_802_1                3
#define CLASS_PPP_MAGIC_NUMBER          4
#define CLASS_PSDN_DIRECTORY_NUMBER     5

static const value_string multilink_ep_disc_class_vals[] = {
    {CLASS_NULL,                  "Null"},
    {CLASS_LOCAL,                 "Locally assigned address"},
    {CLASS_IP,                    "Internet Protocol (IP) address"},
    {CLASS_IEEE_802_1,            "IEEE 802.1 globally assigned MAC address"},
    {CLASS_PPP_MAGIC_NUMBER,      "PPP magic-number block"},
    {CLASS_PSDN_DIRECTORY_NUMBER, "Public switched network directory number"},
    {0,                           NULL}
};

static int
dissect_lcp_multilink_ep_disc_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree, *magic_tree;
    proto_item *tf, *tm;
    uint32_t ep_disc_class;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    if (!dissect_lcp_var_opt(tvb, pinfo, tree, proto_lcp_option_multilink_ep_disc, ett_lcp_multilink_ep_disc_opt, 3,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item_ret_uint(field_tree, hf_lcp_opt_ep_disc_class, tvb, offset + 2,
        1, ENC_BIG_ENDIAN, &ep_disc_class);
    proto_item_append_text(tf, ": Class: %s", val_to_str_const(ep_disc_class, multilink_ep_disc_class_vals, "Unknown"));

    if (length <= 3)
        return tvb_captured_length(tvb);

    length -= 3;
    offset += 3;
    switch (ep_disc_class) {
    case CLASS_NULL:
        break;

    case CLASS_LOCAL:
        proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset,
            length <= 20 ? length : 20, ENC_NA);
        break;

    case CLASS_IP:
        if (length >= 4) {
            proto_tree_add_item(field_tree, hf_lcp_opt_ip_address, tvb, offset,
                4, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset,
                length, ENC_NA);
        }
        break;

    case CLASS_IEEE_802_1:
        if (length >= 6) {
            proto_tree_add_item(field_tree, hf_lcp_opt_802_1_address, tvb,
                offset, 6, ENC_NA);
        } else {
            proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset,
                length, ENC_NA);
        }
        break;

    case CLASS_PPP_MAGIC_NUMBER:
        if (length % 4) {
            proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset,
                length, ENC_NA);
        } else {
            tm = proto_tree_add_item(field_tree, hf_lcp_opt_magic_block, tvb,
                offset, length <= 20 ? length : 20, ENC_NA);
            magic_tree = proto_item_add_subtree(tm, ett_lcp_magic_block);
            for ( ; length >= 4; length -= 4, offset += 4) {
                proto_tree_add_item(magic_tree, hf_lcp_opt_magic_number, tvb,
                    offset, 4, ENC_BIG_ENDIAN);
            }
        }
        break;

    case CLASS_PSDN_DIRECTORY_NUMBER:
        proto_tree_add_item(field_tree, hf_lcp_opt_psndn, tvb, offset,
            length > 15 ? 15 : length, ENC_NA);
        break;

    default:
        proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset, length,
            ENC_NA);
        break;
    }
    return tvb_captured_length(tvb);
}

static const value_string dce_id_mode_vals[] = {
    {1, "Mode-1 (No Additional Negotiation)"},
    {2, "Mode-2 (Full PPP Negotiation and State Machine)"},
    {0, NULL}
};

static int
dissect_lcp_dce_identifier_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    uint32_t mode;

    if (!dissect_lcp_fixed_opt(tvb, pinfo, tree,
                             proto_lcp_option_dce_identifier, ett_lcp_dce_identifier_opt, 3,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item_ret_uint(field_tree, hf_lcp_opt_mode, tvb, offset + 2, 1,
        ENC_BIG_ENDIAN, &mode);
    proto_item_append_text(tf, ": %s", val_to_str_const(mode, dce_id_mode_vals, "Unknown"));

    return tvb_captured_length(tvb);
}

static int
dissect_lcp_multilink_pp_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_lcp_fixed_opt(tvb, pinfo, tree,
                             proto_lcp_option_multilink_pp, ett_lcp_multilink_pp_opt, 4,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_lcp_opt_unused, tvb, offset + 2, 2, ENC_NA);
    return tvb_captured_length(tvb);
}

static int
dissect_lcp_bacp_link_discriminator_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    uint32_t link_discrim;

    if (!dissect_lcp_fixed_opt(tvb, pinfo, tree,
                             proto_lcp_option_link_discrim, ett_lcp_bacp_link_discrim_opt, 4,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item_ret_uint(field_tree, hf_lcp_opt_link_discrim, tvb, offset + 2,
        2, ENC_BIG_ENDIAN, &link_discrim);
    proto_item_append_text(tf, ": %u (0x%04x)", link_discrim, link_discrim);
    return tvb_captured_length(tvb);
}

/* Assuming it's this one:
 * https://tools.ietf.org/html/draft-ietf-pppext-link-negot-00
 */
static int
dissect_lcp_auth_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    uint32_t id_len;
    int offset = 0;
    int length;

    if (!dissect_lcp_var_opt(tvb, pinfo, tree, proto_lcp_option_auth, ett_lcp_auth_opt, 3,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    offset += 2;
    proto_tree_add_item_ret_length(field_tree, hf_lcp_opt_id, tvb, offset, 1, ENC_BIG_ENDIAN, &id_len);

    length = tvb_reported_length_remaining(tvb, offset);
    if ((int)id_len < length) {
        length -= id_len;
        offset += id_len;
        proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset,
            length, ENC_NA);
    }
    return tvb_captured_length(tvb);
}

/* Assuming it's this one:
 * https://tools.ietf.org/html/draft-ietf-pppext-cobs-00
 */
static int
dissect_lcp_cobs_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    static int * const cobs_flags_fields[] = {
        &hf_lcp_opt_cobs_flags_res,
        &hf_lcp_opt_cobs_flags_pre,
        &hf_lcp_opt_cobs_flags_zxe,
        NULL
    };

    if (!dissect_lcp_fixed_opt(tvb, pinfo, tree,
                             proto_lcp_option_cobs, ett_lcp_cobs_opt, 3,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_bitmask(field_tree, tvb, offset + 2, hf_lcp_opt_cobs_flags,
        ett_lcp_cobs_opt, cobs_flags_fields, ENC_NA);
    return tvb_captured_length(tvb);
}

static int
dissect_lcp_prefix_elision_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    uint8_t pre_len;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    if (!dissect_lcp_var_opt(tvb, pinfo, tree, proto_lcp_option_prefix_elision, ett_lcp_prefix_elision_opt, 2,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    if (length > 2) {
        length -= 2;
        offset += 2;
        while (length >= 2) {
            proto_tree_add_item(field_tree, hf_lcp_opt_class, tvb, offset, 1,
                ENC_BIG_ENDIAN);
            pre_len = tvb_get_uint8(tvb, offset + 1);
            if (pre_len + 2 <= length) {
                proto_tree_add_item(field_tree, hf_lcp_opt_prefix, tvb,
                    offset + 2, 1, ENC_NA);
                length -= (2 + pre_len);
            } else {
                /* Prefix length doesn't make sense, so bail out */
                length = 0;
            }
        }
    }

    return tvb_captured_length(tvb);
}

static const value_string ml_hdr_fmt_code_vals[] = {
    {2, "Long sequence number fragment format with classes"},
    {6, "Short sequence number fragment format with classes"},
    {0, NULL}
};

static int
dissect_lcp_multilink_hdr_fmt_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_lcp_fixed_opt(tvb, pinfo, tree,
                             proto_lcp_option_multilink_hdr_fmt, ett_multilink_hdr_fmt_opt, 4,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_lcp_opt_code, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_lcp_opt_max_susp_classes, tvb,
        offset + 3, 1, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}


/* Character sets from https://www.iana.org/assignments/character-sets. */
static const value_string charset_vals[] = {
    {3,    "ANSI_X3.4-1968"},
    {4,    "ISO_8859-1:1987"},
    {5,    "ISO_8859-2:1987"},
    {6,    "ISO_8859-3:1988"},
    {7,    "ISO_8859-4:1988"},
    {8,    "ISO_8859-5:1988"},
    {9,    "ISO_8859-6:1987"},
    {10,   "ISO_8859-7:1987"},
    {11,   "ISO_8859-8:1988"},
    {12,   "ISO_8859-9:1989"},
    {13,   "ISO-8859-10"},
    {14,   "ISO_6937-2-add"},
    {15,   "JIS_X0201"},
    {16,   "JIS_Encoding"},
    {17,   "Shift_JIS"},
    {18,   "Extended_UNIX_Code_Packed_Format_for_Japanese"},
    {19,   "Extended_UNIX_Code_Fixed_Width_for_Japanese"},
    {20,   "BS_4730"},
    {21,   "SEN_850200_C"},
    {22,   "IT"},
    {23,   "ES"},
    {24,   "DIN_66003"},
    {25,   "NS_4551-1"},
    {26,   "NF_Z_62-010"},
    {27,   "ISO-10646-UTF-1"},
    {28,   "ISO_646.basic:1983"},
    {29,   "INVARIANT"},
    {30,   "ISO_646.irv:1983"},
    {31,   "NATS-SEFI"},
    {32,   "NATS-SEFI-ADD"},
    {33,   "NATS-DANO"},
    {34,   "NATS-DANO-ADD"},
    {35,   "SEN_850200_B"},
    {36,   "KS_C_5601-1987"},
    {37,   "ISO-2022-KR"},
    {38,   "EUC-KR"},
    {39,   "ISO-2022-JP"},
    {40,   "ISO-2022-JP-2"},
    {41,   "JIS_C6220-1969-jp"},
    {42,   "JIS_C6220-1969-ro"},
    {43,   "PT"},
    {44,   "greek7-old"},
    {45,   "latin-greek"},
    {46,   "NF_Z_62-010_(1973)"},
    {47,   "Latin-greek-1"},
    {48,   "ISO_5427"},
    {49,   "JIS_C6226-1978"},
    {50,   "BS_viewdata"},
    {51,   "INIS"},
    {52,   "INIS-8"},
    {53,   "INIS-cyrillic"},
    {54,   "ISO_5427:1981"},
    {55,   "ISO_5428:1980"},
    {56,   "GB_1988-80"},
    {57,   "GB_2312-80"},
    {58,   "NS_4551-2"},
    {59,   "videotex-suppl"},
    {60,   "PT2"},
    {61,   "ES2"},
    {62,   "MSZ_7795.3"},
    {63,   "JIS_C6226-1983"},
    {64,   "greek7"},
    {65,   "ASMO_449"},
    {66,   "iso-ir-90"},
    {67,   "JIS_C6229-1984-a"},
    {68,   "JIS_C6229-1984-b"},
    {69,   "JIS_C6229-1984-b-add"},
    {70,   "JIS_C6229-1984-hand"},
    {71,   "JIS_C6229-1984-hand-add"},
    {72,   "JIS_C6229-1984-kana"},
    {73,   "ISO_2033-1983"},
    {74,   "ANSI_X3.110-1983"},
    {75,   "T.61-7bit"},
    {76,   "T.61-8bit"},
    {77,   "ECMA-cyrillic"},
    {78,   "CSA_Z243.4-1985-1"},
    {79,   "CSA_Z243.4-1985-2"},
    {80,   "CSA_Z243.4-1985-gr"},
    {81,   "ISO_8859-6-E"},
    {82,   "ISO_8859-6-I"},
    {83,   "T.101-G2"},
    {84,   "ISO_8859-8-E"},
    {85,   "ISO_8859-8-I"},
    {86,   "CSN_369103"},
    {87,   "JUS_I.B1.002"},
    {88,   "IEC_P27-1"},
    {89,   "JUS_I.B1.003-serb"},
    {90,   "JUS_I.B1.003-mac"},
    {91,   "greek-ccitt"},
    {92,   "NC_NC00-10:81"},
    {93,   "ISO_6937-2-25"},
    {94,   "GOST_19768-74"},
    {95,   "ISO_8859-supp"},
    {96,   "ISO_10367-box"},
    {97,   "latin-lap"},
    {98,   "JIS_X0212-1990"},
    {99,   "DS_2089"},
    {100,  "us-dk"},
    {101,  "dk-us"},
    {102,  "KSC5636"},
    {103,  "UNICODE-1-1-UTF-7"},
    {104,  "ISO-2022-CN"},
    {105,  "ISO-2022-CN-EXT"},
    {106,  "UTF-8"},
    {109,  "ISO-8859-13"},
    {110,  "ISO-8859-14"},
    {111,  "ISO-8859-15"},
    {112,  "ISO-8859-16"},
    {113,  "GBK"},
    {114,  "GB18030"},
    {115,  "OSD_EBCDIC_DF04_15"},
    {116,  "OSD_EBCDIC_DF03_IRV"},
    {117,  "OSD_EBCDIC_DF04_1"},
    {118,  "ISO-11548-1"},
    {119,  "KZ-1048"},
    {1000, "ISO-10646-UCS-2"},
    {1001, "ISO-10646-UCS-4"},
    {1002, "ISO-10646-UCS-Basic"},
    {1003, "ISO-10646-Unicode-Latin1"},
    {1004, "ISO-10646-J-1"},
    {1005, "ISO-Unicode-IBM-1261"},
    {1006, "ISO-Unicode-IBM-1268"},
    {1007, "ISO-Unicode-IBM-1276"},
    {1008, "ISO-Unicode-IBM-1264"},
    {1009, "ISO-Unicode-IBM-1265"},
    {1010, "UNICODE-1-1"},
    {1011, "SCSU"},
    {1012, "UTF-7"},
    {1013, "UTF-16BE"},
    {1014, "UTF-16LE"},
    {1015, "UTF-16"},
    {1016, "CESU-8"},
    {1017, "UTF-32"},
    {1018, "UTF-32BE"},
    {1019, "UTF-32LE"},
    {1020, "BOCU-1"},
    {2000, "ISO-8859-1-Windows-3.0-Latin-1"},
    {2001, "ISO-8859-1-Windows-3.1-Latin-1"},
    {2002, "ISO-8859-2-Windows-Latin-2"},
    {2003, "ISO-8859-9-Windows-Latin-5"},
    {2004, "hp-roman8"},
    {2005, "Adobe-Standard-Encoding"},
    {2006, "Ventura-US"},
    {2007, "Ventura-International"},
    {2008, "DEC-MCS"},
    {2009, "IBM850"},
    {2010, "IBM852"},
    {2011, "IBM437"},
    {2012, "PC8-Danish-Norwegian"},
    {2013, "IBM862"},
    {2014, "PC8-Turkish"},
    {2015, "IBM-Symbols"},
    {2016, "IBM-Thai"},
    {2017, "HP-Legal"},
    {2018, "HP-Pi-font"},
    {2019, "HP-Math8"},
    {2020, "Adobe-Symbol-Encoding"},
    {2021, "HP-DeskTop"},
    {2022, "Ventura-Math"},
    {2023, "Microsoft-Publishing"},
    {2024, "Windows-31J"},
    {2025, "GB2312"},
    {2026, "Big5"},
    {2027, "macintosh"},
    {2028, "IBM037"},
    {2029, "IBM038"},
    {2030, "IBM273"},
    {2031, "IBM274"},
    {2032, "IBM275"},
    {2033, "IBM277"},
    {2034, "IBM278"},
    {2035, "IBM280"},
    {2036, "IBM281"},
    {2037, "IBM284"},
    {2038, "IBM285"},
    {2039, "IBM290"},
    {2040, "IBM297"},
    {2041, "IBM420"},
    {2042, "IBM423"},
    {2043, "IBM424"},
    {2044, "IBM500"},
    {2045, "IBM851"},
    {2046, "IBM855"},
    {2047, "IBM857"},
    {2048, "IBM860"},
    {2049, "IBM861"},
    {2050, "IBM863"},
    {2051, "IBM864"},
    {2052, "IBM865"},
    {2053, "IBM868"},
    {2054, "IBM869"},
    {2055, "IBM870"},
    {2056, "IBM871"},
    {2057, "IBM880"},
    {2058, "IBM891"},
    {2059, "IBM903"},
    {2060, "IBM904"},
    {2061, "IBM905"},
    {2062, "IBM918"},
    {2063, "IBM1026"},
    {2064, "EBCDIC-AT-DE"},
    {2065, "EBCDIC-AT-DE-A"},
    {2066, "EBCDIC-CA-FR"},
    {2067, "EBCDIC-DK-NO"},
    {2068, "EBCDIC-DK-NO-A"},
    {2069, "EBCDIC-FI-SE"},
    {2070, "EBCDIC-FI-SE-A"},
    {2071, "EBCDIC-FR"},
    {2072, "EBCDIC-IT"},
    {2073, "EBCDIC-PT"},
    {2074, "EBCDIC-ES"},
    {2075, "EBCDIC-ES-A"},
    {2076, "EBCDIC-ES-S"},
    {2077, "EBCDIC-UK"},
    {2078, "EBCDIC-US"},
    {2079, "UNKNOWN-8BIT"},
    {2080, "MNEMONIC"},
    {2081, "MNEM"},
    {2082, "VISCII"},
    {2083, "VIQR"},
    {2084, "KOI8-R"},
    {2085, "HZ-GB-2312"},
    {2086, "IBM866"},
    {2087, "IBM775"},
    {2088, "KOI8-U"},
    {2089, "IBM00858"},
    {2090, "IBM00924"},
    {2091, "IBM01140"},
    {2092, "IBM01141"},
    {2093, "IBM01142"},
    {2094, "IBM01143"},
    {2095, "IBM01144"},
    {2096, "IBM01145"},
    {2097, "IBM01146"},
    {2098, "IBM01147"},
    {2099, "IBM01148"},
    {2100, "IBM01149"},
    {2101, "Big5-HKSCS"},
    {2102, "IBM1047"},
    {2103, "PTCP154"},
    {2104, "Amiga-1251"},
    {2105, "KOI7-switched"},
    {2106, "BRF"},
    {2107, "TSCII"},
    {2108, "CP51932"},
    {2109, "windows-874"},
    {2250, "windows-1250"},
    {2251, "windows-1251"},
    {2252, "windows-1252"},
    {2253, "windows-1253"},
    {2254, "windows-1254"},
    {2255, "windows-1255"},
    {2256, "windows-1256"},
    {2257, "windows-1257"},
    {2258, "windows-1258"},
    {2259, "TIS-620"},
    {2260, "CP50220"},
    {0,    NULL}
};
static value_string_ext charset_vals_ext = VALUE_STRING_EXT_INIT(charset_vals);

static int
dissect_lcp_internationalization_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    if (!dissect_lcp_var_opt(tvb, pinfo, tree, proto_lcp_option_internationalization, ett_lcp_internationalization_opt, 7,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_lcp_opt_MIBenum, tvb, offset + 2, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_lcp_opt_language_tag, tvb, offset + 6,
        length - 6, ENC_ASCII);

    return tvb_captured_length(tvb);
}

static int
dissect_lcp_sonet_sdh_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_lcp_simple_opt(tvb, pinfo, tree, proto_lcp_option_sonet_sdh, ett_lcp_sonet_sdh_opt);
}

static void
dissect_ipcp_opt_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    uint8_t type;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_ipcp_opt_type, tvb, offset, 1,
        type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_ipcp_opt_length, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
}

static bool
dissect_ipcp_fixed_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             int proto, int ett, int expected_length,
                             proto_tree** ret_tree, proto_item** ret_item)
{
    if (!ppp_option_len_check(tree, pinfo, tvb, proto, tvb_reported_length(tvb), expected_length))
        return false;

    *ret_item = proto_tree_add_item(tree, proto, tvb, 0, expected_length, ENC_NA);
    *ret_tree = proto_item_add_subtree(*ret_item, ett);

    dissect_ipcp_opt_type_len(tvb, 0, *ret_tree, proto_registrar_get_name(proto));
    return true;
}

/* https://tools.ietf.org/html/rfc1172#section-5.1 */
static int
dissect_ipcp_addrs_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_ipcp_fixed_opt(tvb, pinfo, tree, proto_ipcp_option_addrs , ett_ipcp_ipaddrs_opt, 10,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_ipcp_opt_src_address, tvb, offset + 2,
        4, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_ipcp_opt_dst_address, tvb, offset + 6,
        4, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static const true_false_string tfs_comp_slot_id = {
    "The slot identifier may be compressed",
    "The slot identifier must not be compressed"
};

/* https://tools.ietf.org/html/rfc1332#section-3.2 */
static int
dissect_ipcp_compress_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    int length = tvb_reported_length(tvb);
    uint16_t    us;

    tf = proto_tree_add_item(tree, proto_ipcp_option_compress, tvb, 0, length, ENC_NA);
    field_tree = proto_item_add_subtree(tf, ett_ipcp_compress_opt);

    dissect_ipcp_opt_type_len(tvb, 0, field_tree, proto_registrar_get_name(proto_ipcp_option_compress));
    proto_tree_add_item(field_tree, hf_ipcp_opt_compress_proto, tvb,
        offset + 2, 2, ENC_BIG_ENDIAN);
    us = tvb_get_ntohs(tvb, offset + 2);
    switch (us) {
    case IPCP_ROHC:
        proto_tree_add_item(field_tree, hf_ipcp_opt_max_cid, tvb, offset + 4,
            2, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree, hf_ipcp_opt_mrru, tvb, offset + 6, 2,
            ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree, hf_ipcp_opt_max_header, tvb,
            offset + 8, 2, ENC_BIG_ENDIAN);

        if (length > 10) {
            proto_tree *subopt_tree;

            /* suboptions */
            offset += 10;
            length -= 10;
            subopt_tree = proto_tree_add_subtree_format(field_tree, tvb, offset, length,
                ett_ipcp_compress_opt, NULL, "Suboptions: (%u byte%s)", length, plurality(length, "", "s"));

            ppp_dissect_options(tvb, offset, length, ipcp_rohc_suboption_table, pinfo, subopt_tree);
        }
        break;

    case IPCP_COMPRESS_VJ_1172:
    case IPCP_COMPRESS_VJ:
        proto_tree_add_item(field_tree, hf_ipcp_opt_max_slot_id, tvb,
            offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree, hf_ipcp_opt_comp_slot_id, tvb,
            offset + 5, 1, ENC_NA);
      break;

    case IPCP_COMPRESS_IPHC:
        proto_tree_add_item(field_tree, hf_ipcp_opt_tcp_space, tvb, offset + 4,
            2, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree, hf_ipcp_opt_non_tcp_space, tvb,
            offset + 6, 2, ENC_BIG_ENDIAN);
        us = tvb_get_ntohs(tvb, offset + 8);
        proto_tree_add_uint_format_value(field_tree, hf_ipcp_opt_f_max_period,
            tvb, offset + 8, 2, us, "%u%s", us,
            (us == 0) ? " (infinity)" : "");
        us = tvb_get_ntohs(tvb, offset + 10);
        proto_tree_add_uint_format_value(field_tree, hf_ipcp_opt_f_max_time,
            tvb, offset + 10, 2, us, "%u%s", us,
            (us == 0) ? " (infinity)" : "");
        proto_tree_add_item(field_tree, hf_ipcp_opt_max_header, tvb,
            offset + 12, 2, ENC_BIG_ENDIAN);

        if ( length > 14 ) {
            proto_tree *subopt_tree;

            /* suboptions */
            offset += 14;
            length -= 14;
            subopt_tree = proto_tree_add_subtree_format(field_tree, tvb, offset, length,
                ett_ipcp_compress_opt, NULL, "Suboptions: (%u byte%s)", length, plurality(length, "", "s"));
            ppp_dissect_options(tvb, offset, length, ipcp_iphc_suboption_table, pinfo, subopt_tree);
        }
        break;

    default:
        if (length > 4) {
            proto_tree_add_item(field_tree, hf_ipcp_data, tvb, offset + 4,
                length - 4, ENC_NA);
        }
        break;
    }

    return tvb_captured_length(tvb);
}

static void
dissect_ipcp_opt_rohc_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    uint8_t type;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_ipcp_opt_rohc_type, tvb, offset,
        1, type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_ipcp_opt_rohc_length, tvb, offset + 1, 1,
        ENC_BIG_ENDIAN);
}

static int
dissect_ipcp_rohc_profiles_opt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int length = tvb_reported_length(tvb);
    int offset = 0;

    tf = proto_tree_add_item(tree, proto_ipcp_rohc_option_profiles, tvb, offset, length, ENC_NA);
    field_tree = proto_item_add_subtree(tf, ett_ipcp_rohc_profiles_opt);

    dissect_ipcp_opt_rohc_type_len(tvb, offset, field_tree, proto_registrar_get_name(proto_ipcp_rohc_option_profiles));
    if (length <= 2)
        return tvb_captured_length(tvb);

    for (offset += 2, length -= 2; length >= 2; length -= 2, offset += 2) {
        proto_tree_add_item(field_tree, hf_ipcp_opt_rohc_profile, tvb,
            offset, 2, ENC_BIG_ENDIAN);
    }
    return tvb_captured_length(tvb);
}

static void
dissect_ipcp_opt_iphc_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    uint8_t type;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_ipcp_opt_iphc_type, tvb, offset,
        1, type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_ipcp_opt_iphc_length, tvb, offset + 1, 1,
        ENC_BIG_ENDIAN);
}

static bool
dissect_ipcp_iphc_fixed_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             int proto, int ett, int expected_length,
                             proto_tree** ret_tree, proto_item** ret_item)
{
    if (!ppp_option_len_check(tree, pinfo, tvb, proto, tvb_reported_length(tvb), expected_length))
        return false;

    *ret_item = proto_tree_add_item(tree, proto, tvb, 0, expected_length, ENC_NA);
    *ret_tree = proto_item_add_subtree(*ret_item, ett);

    dissect_ipcp_opt_iphc_type_len(tvb, 0, *ret_tree, proto_registrar_get_name(proto));
    return true;
}

static int
dissect_ipcp_iphc_rtp_compress(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;

    dissect_ipcp_iphc_fixed_opt(tvb, pinfo, tree, proto_ipcp_iphc_option_rtp_compress, ett_ipcp_iphc_rtp_compress_opt, 2,
                                  &field_tree, &tf);
    return tvb_captured_length(tvb);
}

static int
dissect_ipcp_iphc_enhanced_rtp_compress(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;

    dissect_ipcp_iphc_fixed_opt(tvb, pinfo, tree, proto_ipcp_iphc_option_enhanced_rtp_compress, ett_ipcp_iphc_enhanced_rtp_compress_opt, 2,
                                  &field_tree, &tf);
    return tvb_captured_length(tvb);
}

static int
dissect_ipcp_iphc_neghdrcomp_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_ipcp_iphc_fixed_opt(tvb, pinfo, tree, proto_ipcp_iphc_option_neghdrcomp, ett_ipcp_iphc_neghdrcomp_opt, 3,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_ipcp_opt_iphc_param, tvb, offset + 2, 1,
        ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static int
dissect_ipcp_addr_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_ipcp_fixed_opt(tvb, pinfo, tree, proto_ipcp_option_addr, ett_ipcp_ipaddr_opt, 6,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_ipcp_opt_ip_address, tvb, offset + 2, 4, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static int
dissect_ipcp_mobileipv4_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_ipcp_fixed_opt(tvb, pinfo, tree, proto_ipcp_option_mobileipv4, ett_ipcp_mobileipv4_opt, 6,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_ipcp_opt_mobilenodehomeaddr, tvb,
        offset + 2, 4, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static int
dissect_ipcp_pri_dns_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_ipcp_fixed_opt(tvb, pinfo, tree, proto_ipcp_option_pri_dns, ett_ipcp_pridns_opt, 6,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_ipcp_opt_pri_dns_address, tvb,
        offset + 2, 4, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static int
dissect_ipcp_pri_nbns_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_ipcp_fixed_opt(tvb, pinfo, tree, proto_ipcp_option_pri_nbns, ett_ipcp_prinbns_opt, 6,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_ipcp_opt_pri_nbns_address, tvb,
        offset + 2, 4, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static int
dissect_ipcp_sec_dns_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_ipcp_fixed_opt(tvb, pinfo, tree, proto_ipcp_option_sec_dns, ett_ipcp_secdns_opt, 6,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_ipcp_opt_sec_dns_address, tvb,
        offset + 2, 4, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static int
dissect_ipcp_sec_nbns_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_ipcp_fixed_opt(tvb, pinfo, tree, proto_ipcp_option_sec_nbns, ett_ipcp_secnbns_opt, 6,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_ipcp_opt_sec_nbns_address, tvb,
        offset + 2, 4, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static void
dissect_bcp_ncp_opt_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    uint8_t type;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_bcp_ncp_opt_type, tvb, offset, 1,
        type, "%s (%u)", name, type);
    offset++;
    proto_tree_add_item(tree, hf_bcp_ncp_opt_length, tvb, offset, 1,
        ENC_BIG_ENDIAN);
}

static bool
dissect_bcp_ncp_fixed_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             int proto, int ett, int expected_length,
                             proto_tree** ret_tree, proto_item** ret_item)
{
    if (!ppp_option_len_check(tree, pinfo, tvb, proto, tvb_reported_length(tvb), expected_length))
        return false;

    *ret_item = proto_tree_add_item(tree, proto, tvb, 0, expected_length, ENC_NA);
    *ret_tree = proto_item_add_subtree(*ret_item, ett);

    dissect_bcp_ncp_opt_type_len(tvb, 0, *ret_tree, proto_registrar_get_name(proto));
    return true;
}

/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |    Length     | LAN Segment Number    |Bridge#|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static int
dissect_bcp_ncp_bridge_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;
    int offset = 0;

    if (!dissect_bcp_ncp_fixed_opt(tvb, pinfo, tree, proto_bcp_ncp_option_bridge_id, ett_bcp_ncp_bridge_id_opt, 4,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_bcp_ncp_lan_seg_no, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_bcp_ncp_bridge_no, tvb, offset+2, 2, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |    Length     | LAN Segment Number    |Bridge#|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static int
dissect_bcp_ncp_line_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;
    int offset = 0;

    if (!dissect_bcp_ncp_fixed_opt(tvb, pinfo, tree, proto_bcp_ncp_option_line_id, ett_bcp_ncp_line_id_opt, 4,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_bcp_ncp_lan_seg_no, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_bcp_ncp_bridge_no, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

/*
0                   1                   2
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |    Length     |    MAC Type   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

MAC Type
0: reserved
1: IEEE 802.3/Ethernet  with canonical addresses
2: IEEE 802.4           with canonical addresses
3: IEEE 802.5           with non-canonical addresses
4: FDDI                 with non-canonical addresses
5-10: reserved
11: IEEE 802.5           with canonical addresses
12: FDDI                 with canonical addresses

*/
static int
dissect_bcp_ncp_mac_sup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;
    int offset = 0;

    if (!dissect_bcp_ncp_fixed_opt(tvb, pinfo, tree, proto_bcp_ncp_option_mac_sup, ett_bcp_ncp_mac_sup_opt, 3,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_bcp_bpdu_mac_type, tvb, offset+2, 1, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

/*
0                   1                   2
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |    Length     | Enable/Disable|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static int
dissect_bcp_ncp_tinygram_comp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;
    int offset = 0;

    if (!dissect_bcp_ncp_fixed_opt(tvb, pinfo, tree, proto_bcp_ncp_option_tinygram_comp, ett_bcp_ncp_tinygram_comp_opt, 3,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_bcp_ncp_tinygram_comp, tvb, offset+2, 1, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static int
dissect_bcp_ncp_lan_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;

    dissect_bcp_ncp_fixed_opt(tvb, pinfo, tree, proto_bcp_ncp_option_lan_id, ett_bcp_ncp_lan_id_opt, 3,
                                  &field_tree, &tf);
    /* XXX - missing a field? */
    return tvb_captured_length(tvb);
}

/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |    Length     |MAC byte 1 |L|M|  MAC byte 2   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  MAC byte 3   |  MAC byte 4   |  MAC byte 5   |  MAC byte 6   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static int
dissect_bcp_ncp_mac_addr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;
    int offset = 0;

    if (!dissect_bcp_ncp_fixed_opt(tvb, pinfo, tree, proto_bcp_ncp_option_mac_addr, ett_bcp_ncp_mac_addr_opt, 8,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_bcp_ncp_mac, tvb, offset+2, 6, ENC_NA);
    proto_tree_add_item(field_tree, hf_bcp_ncp_mac_l, tvb, offset+2, 6, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_bcp_ncp_mac_m, tvb, offset+2, 6, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|     Type      |    Length     |  Protocol 1   |  Protocol 2   | ..
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

*/

static const value_string bcp_ncp_stp_prot_vals[] = {
    { 0, "Null (no Spanning Tree protocol supported)" },
    { 1, "IEEE 802.1D spanning tree" },
    { 2, "IEEE 802.1G extended spanning tree protocol" },
    { 3, "IBM Source Route Spanning tree protocol" },
    { 4, "DEC LANbridge 100 Spanning tree protocol" },
    { 0,            NULL }
};

static int
dissect_bcp_ncp_stp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    tf = proto_tree_add_item(tree, proto_bcp_ncp_option_stp, tvb, offset, length, ENC_NA);
    field_tree = proto_item_add_subtree(tf, ett_bcp_ncp_stp_opt);

    dissect_bcp_ncp_opt_type_len(tvb, offset, field_tree, proto_registrar_get_name(proto_bcp_ncp_option_stp));
    offset += 2;
    length -= 2;

    while (length != 0) {
        proto_tree_add_item(field_tree, hf_bcp_ncp_stp_prot, tvb, offset, 1, ENC_BIG_ENDIAN);
        length--;
        offset++;
    }
    return tvb_captured_length(tvb);
}

/*
0                   1                   2
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |    Length     | Enable/Disable|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static int
dissect_bcp_ncp_ieee_802_tagged_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;
    int offset = 0;

    if (!dissect_bcp_ncp_fixed_opt(tvb, pinfo, tree, proto_bcp_ncp_option_ieee_802_tagged_frame,
                                  ett_bcp_ncp_ieee_802_tagged_frame_opt, 3, &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_bcp_ncp_ieee_802_tagged_frame, tvb, offset+2, 1, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

/*
0                   1
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |    Length     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static int
dissect_bcp_ncp_management_inline(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;

    dissect_bcp_ncp_fixed_opt(tvb, pinfo, tree, proto_bcp_ncp_option_management_inline, ett_bcp_ncp_management_inline_opt, 3,
                                  &field_tree, &tf);
    return tvb_captured_length(tvb);
}

/*
0                   1
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |    Length     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
static int
dissect_bcp_ncp_bcp_ncp_bcp_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;

    dissect_bcp_ncp_fixed_opt(tvb, pinfo, tree, proto_bcp_ncp_option_bcp_ind, ett_bcp_ncp_bcp_ind_opt, 3,
                                  &field_tree, &tf);
    return tvb_captured_length(tvb);
}


static void
dissect_osinlcp_opt_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    uint8_t type;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_osinlcp_opt_type, tvb, offset, 1,
        type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_osinlcp_opt_length, tvb, offset + 1, 1,
        ENC_BIG_ENDIAN);
}

static bool
dissect_osinlcp_fixed_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             int proto, int ett, int expected_length,
                             proto_tree** ret_tree, proto_item** ret_item)
{
    if (!ppp_option_len_check(tree, pinfo, tvb, proto, tvb_reported_length(tvb), expected_length))
        return false;

    *ret_item = proto_tree_add_item(tree, proto, tvb, 0, expected_length, ENC_NA);
    *ret_tree = proto_item_add_subtree(*ret_item, ett);

    dissect_osinlcp_opt_type_len(tvb, 0, *ret_tree, proto_registrar_get_name(proto));
    return true;
}

static int
dissect_osinlcp_align_npdu_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_osinlcp_fixed_opt(tvb, pinfo, tree, proto_osinlcp_option_align_npdu, ett_osinlcp_align_npdu_opt, 3,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_osinlcp_opt_alignment, tvb, offset + 2,
        1, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static void
dissect_pppmuxcp_opt_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    uint8_t type;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_pppmuxcp_opt_type, tvb, offset, 1,
        type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_pppmuxcp_opt_length, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
}

static bool
dissect_pppmuxcp_fixed_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             int proto, int ett, int expected_length,
                             proto_tree** ret_tree, proto_item** ret_item)
{
    if (!ppp_option_len_check(tree, pinfo, tvb, proto, tvb_reported_length(tvb), expected_length))
        return false;

    *ret_item = proto_tree_add_item(tree, proto, tvb, 0, expected_length, ENC_NA);
    *ret_tree = proto_item_add_subtree(*ret_item, ett);

    dissect_pppmuxcp_opt_type_len(tvb, 0, *ret_tree, proto_registrar_get_name(proto));
    return true;
}

static int
dissect_pppmuxcp_def_pid_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;
    int offset = 0;

    if (!dissect_pppmuxcp_fixed_opt(tvb, pinfo, tree, proto_pppmuxcp_option_def_pid, ett_pppmuxcp_def_pid_opt, 4,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item_ret_uint(tree, hf_pppmux_def_prot_id, tvb, offset + 2, 2, ENC_BIG_ENDIAN, &pppmux_def_prot_id);
    return tvb_captured_length(tvb);
}


static void
dissect_ccp_opt_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    uint8_t type;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_ccp_opt_type, tvb, offset, 1,
        type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_ccp_opt_length, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
}

static bool
dissect_ccp_fixed_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             int proto, int ett, int expected_length,
                             proto_tree** ret_tree, proto_item** ret_item)
{
    if (!ppp_option_len_check(tree, pinfo, tvb, proto, tvb_reported_length(tvb), expected_length))
        return false;

    *ret_item = proto_tree_add_item(tree, proto, tvb, 0, expected_length, ENC_NA);
    *ret_tree = proto_item_add_subtree(*ret_item, ett);

    dissect_ccp_opt_type_len(tvb, 0, *ret_tree, proto_registrar_get_name(proto));
    return true;
}

static bool
dissect_ccp_var_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             int proto, int ett, int expected_length,
                             proto_tree** ret_tree, proto_item** ret_item)
{
    int len = tvb_reported_length(tvb);

    if (len < expected_length) {
        /* Bogus - option length isn't what it's supposed to be for this option. */
        proto_tree_add_expert_format(tree, pinfo, &ei_ppp_opt_len_invalid, tvb, 0, len,
                            "%s (with option length = %u byte%s; should be at least %u)",
                            proto_get_protocol_short_name(find_protocol_by_id(proto)),
                            len, plurality(len, "", "s"), expected_length);
        return false;
    }

    *ret_item = proto_tree_add_item(tree, proto, tvb, 0, -1, ENC_NA);
    *ret_tree = proto_item_add_subtree(*ret_item, ett);

    dissect_ccp_opt_type_len(tvb, 0, *ret_tree, proto_registrar_get_name(proto));
    return true;
}


/* https://tools.ietf.org/html/rfc1962 */
static int dissect_ccp_oui_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    if (!dissect_ccp_var_opt(tvb, pinfo, tree, proto_ccp_option_oui, ett_ccp_oui_opt, 6,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_ccp_opt_oui, tvb, offset + 2, 3, ENC_BIG_ENDIAN);

    proto_tree_add_item(field_tree, hf_ccp_opt_subtype, tvb, offset + 5, 1,
        ENC_BIG_ENDIAN);
    if (length > 6) {
        proto_tree_add_item(field_tree, hf_ccp_opt_data, tvb, offset + 6,
            length - 6, ENC_NA);
    }
    return tvb_captured_length(tvb);
}

/* The following configuration option types are mentioned at
 * https://www.iana.org/assignments/ppp-numbers/ppp-numbers.xhtml as referencing RFC1962; however,
 * RFC1962 only mentions Proprietary Compression OUI in section 4.1.  These
 * others are therefore being treated as section 4.2 "Other Compression Types",
 * in terms of how they are dissected:
 *      1)  Predictor type 1
 *      2)  Predictor type 2
 *      3)  Puddle Jumper
 *      16) Hewlett-Packard PPC
 *      20) V.42bis compression
 */
static int dissect_ccp_other_opt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int proto, int ett)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    tf = proto_tree_add_item(tree, proto, tvb, 0, length, ENC_NA);
    field_tree = proto_item_add_subtree(tf, ett);

    dissect_ccp_opt_type_len(tvb, offset, field_tree, proto_registrar_get_name(proto));

    if (length > 2) {
        proto_tree_add_item(field_tree, hf_ccp_opt_data, tvb, offset + 2,
            length - 2, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

static int dissect_ccp_predict1_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_ccp_other_opt(tvb, pinfo, tree, proto_ccp_option_predict1, ett_ccp_predict1_opt);
}

static int dissect_ccp_predict2_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_ccp_other_opt(tvb, pinfo, tree, proto_ccp_option_predict2, ett_ccp_predict2_opt);
}

static int dissect_ccp_puddle_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_ccp_other_opt(tvb, pinfo, tree, proto_ccp_option_puddle, ett_ccp_puddle_opt);
}

static int dissect_ccp_hpppc_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_ccp_other_opt(tvb, pinfo, tree, proto_ccp_option_hpppc, ett_ccp_hpppc_opt);
}

/* https://tools.ietf.org/html/rfc1974 */
static int
dissect_ccp_stac_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    int length = tvb_reported_length(tvb);
    static int * const check_mode_fields[] = {
        &hf_ccp_opt_cm_reserved,
        &hf_ccp_opt_cm_check_mode,
        NULL
    };

    /* In RFC 1974, this is a fixed-length field of size 5, but in
     * Ascend Proprietary STAC compression this field is 6 octets. */

    if (!dissect_ccp_var_opt(tvb, pinfo, tree,
                                  (length == 6) ? proto_ccp_option_stac_ascend : proto_ccp_option_stac,
                                  ett_ccp_stac_opt, 5, &field_tree, &tf))
        return tvb_captured_length(tvb);


    if (length == 6) {
        /* We don't know how to decode the following 4 octets, since
           there are no public documents that describe their usage. */
        proto_tree_add_item(field_tree, hf_ccp_opt_data, tvb, offset + 2,
            length - 2, ENC_NA);
    } else {
        proto_tree_add_item(field_tree, hf_ccp_opt_history_count, tvb,
            offset + 2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(field_tree, tvb, offset + 4, hf_ccp_opt_cm,
            ett_ccp_stac_opt_check_mode, check_mode_fields, ENC_NA);
    }
    return tvb_captured_length(tvb);
}

/*
 * Microsoft Point-To-Point Compression (MPPC) and Encryption (MPPE)
 * supported bits.
 */
#define MPPC_SUPPORTED_BITS_C   0x00000001      /* MPPC negotiation */
#define MPPE_SUPPORTED_BITS_D   0x00000010      /* Obsolete */
#define MPPE_SUPPORTED_BITS_L   0x00000020      /* 40-bit encryption */
#define MPPE_SUPPORTED_BITS_S   0x00000040      /* 128-bit encryption */
#define MPPE_SUPPORTED_BITS_M   0x00000080      /* 56-bit encryption */
#define MPPE_SUPPORTED_BITS_H   0x01000000      /* stateless mode */

static const true_false_string ccp_mppe_h_tfs = {
    "Stateless mode ON",
    "Stateless mode OFF"
};
static const true_false_string ccp_mppe_m_tfs = {
    "56-bit encryption ON",
    "56-bit encryption OFF"
};
static const true_false_string ccp_mppe_s_tfs = {
    "128-bit encryption ON",
    "128-bit encryption OFF"
};
static const true_false_string ccp_mppe_l_tfs = {
    "40-bit encryption ON",
    "40-bit encryption OFF"
};
static const true_false_string ccp_mppe_d_tfs = {
    "Obsolete (should NOT be 1)",
    "Obsolete (should ALWAYS be 0)"
};
static const true_false_string ccp_mppe_c_tfs = {
    "Desire to negotiate MPPC",
    "No desire to negotiate MPPC"
};

/* https://tools.ietf.org/html/rfc2118,
 * https://tools.ietf.org/html/rfc3078 */
static int
dissect_ccp_mppe_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    static int * const supported_bits_fields[] = {
        &hf_ccp_opt_supported_bits_h,
        &hf_ccp_opt_supported_bits_m,
        &hf_ccp_opt_supported_bits_s,
        &hf_ccp_opt_supported_bits_l,
        &hf_ccp_opt_supported_bits_d,
        &hf_ccp_opt_supported_bits_c,
        NULL
    };

    if (!dissect_ccp_fixed_opt(tvb, pinfo, tree, proto_ccp_option_mppe, ett_ccp_mppe_opt, 6,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_bitmask(field_tree, tvb, offset + 2,
        hf_ccp_opt_supported_bits, ett_ccp_mppe_opt_supp_bits,
        supported_bits_fields, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

/* https://tools.ietf.org/html/rfc1993 */
static int dissect_ccp_gfza_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    if (!dissect_ccp_var_opt(tvb, pinfo, tree, proto_ccp_option_gfza, ett_ccp_gfza_opt, 3,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_ccp_opt_history, tvb, offset + 2, 1,
        ENC_BIG_ENDIAN);

    if (length > 3) {
        proto_tree_add_item(field_tree, hf_ccp_opt_version, tvb, offset + 3,
            length - 3, ENC_NA);
    }
    return tvb_captured_length(tvb);
}

static int dissect_ccp_v42bis_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    return dissect_ccp_other_opt(tvb, pinfo, tree, proto_ccp_option_v42bis, ett_ccp_v42bis_opt);
}

/* https://tools.ietf.org/html/rfc1977 */
static int
dissect_ccp_bsdcomp_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    static int * const vd_fields[] = {
        &hf_ccp_opt_vd_vers,
        &hf_ccp_opt_vd_dict,
        NULL
    };

    if (!dissect_ccp_fixed_opt(tvb, pinfo, tree, proto_ccp_option_bsdcomp, ett_ccp_bsdcomp_opt, 3,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_bitmask(field_tree, tvb, offset + 2, hf_ccp_opt_vd,
        ett_ccp_bsdcomp_opt, vd_fields, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

/* https://tools.ietf.org/html/rfc1967 */
static int
dissect_ccp_lzsdcp_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_ccp_fixed_opt(tvb, pinfo, tree, proto_ccp_option_lzsdcp, ett_ccp_lzsdcp_opt, 6,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_ccp_opt_history_count, tvb,
        offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_ccp_opt_check_mode, tvb, offset + 4, 1,
        ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_ccp_opt_process_mode, tvb, offset + 5,
        1, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

/* https://tools.ietf.org/html/rfc1975 */
static int
dissect_ccp_mvrca_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_ccp_fixed_opt(tvb, pinfo, tree, proto_ccp_option_mvrca, ett_ccp_mvrca_opt, 4,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_ccp_opt_fe, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_ccp_opt_p, tvb, offset + 2, 1, ENC_NA);
    proto_tree_add_item(field_tree, hf_ccp_opt_History, tvb, offset + 2, 1,
        ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_ccp_opt_contexts, tvb, offset + 3, 1,
        ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

/* https://tools.ietf.org/html/rfc1976 */
static int
dissect_ccp_dce_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_ccp_fixed_opt(tvb, pinfo, tree, proto_ccp_option_dce, ett_ccp_dce_opt, 3,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_ccp_opt_mode, tvb, offset + 2, 1,
        ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static const value_string deflate_method_vals[] = {
    {8, "zlib compression"},
    {0, NULL}
};

static const value_string deflate_chk_vals[] = {
    {0, "sequence number check method"},
    {0, NULL}
};

/* https://tools.ietf.org/html/rfc1979 */
static int
dissect_ccp_deflate_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    uint8_t window;

    /* RFC1979 says the length is 3 but it's actually 4. */
    if (!dissect_ccp_fixed_opt(tvb, pinfo, tree, proto_ccp_option_deflate, ett_ccp_deflate_opt, 4,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    window = tvb_get_uint8(tvb, offset + 2);
    proto_tree_add_uint_format_value(field_tree, hf_ccp_opt_window, tvb,
        offset + 2, 1, window, "%u", 1 << (hi_nibble(window) + 8));
    proto_tree_add_item(field_tree, hf_ccp_opt_method, tvb, offset + 2, 1,
        ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_ccp_opt_mbz, tvb, offset + 3, 1,
        ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_ccp_opt_chk, tvb, offset + 3, 1,
        ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static const range_string v44lzjh_mode_dict_rvals[] = {
    {0, 0, "Datagram Mode (one dictionary and no history)"},
    {1, 1, "Multi-Datagram Mode (one dictionary with history)"},
    {2, UINT16_MAX, "Individual Link Mode" /* "(and proposed number of
                                                 dictionaries each with a
                                                 corresponding history" */},
    {0, 0, NULL}
};

/* https://tools.ietf.org/html/draft-heath-ppp-v44-01 */
static int dissect_ccp_v44lzjh_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    if (!dissect_ccp_var_opt(tvb, pinfo, tree, proto_ccp_option_v44lzjh, ett_ccp_v44lzjh_opt, 4,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_ccp_opt_mode_dictcount, tvb, offset + 2,
        2, ENC_BIG_ENDIAN);

    if (length > 4) {
        proto_tree_add_item(field_tree, hf_ccp_opt_dict_size, tvb, offset + 4,
            2, ENC_BIG_ENDIAN);
        if (length > 6) {
            proto_tree_add_item(field_tree, hf_ccp_opt_history_length, tvb,
                offset + 6, 2, ENC_BIG_ENDIAN);
        }
    }
    return tvb_captured_length(tvb);
}

static int
dissect_cbcp_callback_opt_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int length)
{
    proto_tree *addr_tree;
    proto_item *ti;
    uint8_t     addr_type;
    unsigned    addr_len;

    proto_tree_add_item(tree, hf_cbcp_callback_delay, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
    offset += 3;
    length -= 3;

    while (length > 0) {
        addr_tree = proto_tree_add_subtree(tree, tvb, offset, length,
            ett_cbcp_callback_opt_addr, NULL, "Callback Address");
        addr_type = tvb_get_uint8(tvb, offset);
        ti = proto_tree_add_uint_format_value(addr_tree, hf_cbcp_address_type, tvb, offset, 1, addr_type,
             "%s (%u)", ((addr_type == 1) ? "PSTN/ISDN" : "Other"), addr_type);
        offset++;
        length--;
        addr_len = tvb_strsize(tvb, offset);
        if (addr_len > (unsigned)length) {
            expert_add_info(pinfo, ti, &ei_cbcp_address);
            break;
        }
        proto_tree_add_item(addr_tree, hf_cbcp_address, tvb, offset, addr_len, ENC_NA|ENC_ASCII);
        offset += addr_len;
        length -= addr_len;
    }

    return tvb_captured_length(tvb);
}

static void
dissect_cbcp_opt_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    uint8_t type;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_cbcp_opt_type, tvb, offset, 1,
        type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_cbcp_opt_length, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
}

static int
dissect_cbcp_no_callback_opt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    tf = proto_tree_add_item(tree, proto_cbcp_option_no_callback, tvb, offset, length, ENC_NA);
    field_tree = proto_item_add_subtree(tf, ett_cbcp_no_callback);

    dissect_cbcp_opt_type_len(tvb, offset, field_tree, proto_registrar_get_name(proto_cbcp_option_no_callback));
    proto_tree_add_item(field_tree, hf_cbcp_no_callback, tvb, offset+2, length-2, ENC_NA);

    return tvb_captured_length(tvb);
}

static int
dissect_cbcp_callback_user_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    if (length < 4) {
        /* Bogus - option length isn't what it's supposed to be for this option. */
        proto_tree_add_expert_format(tree, pinfo, &ei_ppp_opt_len_invalid, tvb, 0, length,
                            "%s (with option length = %u byte%s; should be at least %u)",
                            proto_get_protocol_short_name(find_protocol_by_id(proto_cbcp_option_callback_user)),
                            length, plurality(length, "", "s"), 4);
        return tvb_captured_length(tvb);
    }

    tf = proto_tree_add_item(tree, proto_cbcp_option_callback_user, tvb, offset, length, ENC_NA);
    field_tree = proto_item_add_subtree(tf, ett_cbcp_callback_user);

    dissect_cbcp_opt_type_len(tvb, offset, field_tree, proto_registrar_get_name(proto_cbcp_option_callback_user));

    return dissect_cbcp_callback_opt_common(tvb, pinfo, tree, 0, tvb_reported_length(tvb));
}

static int
dissect_cbcp_callback_admin_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;
    int offset = 0;

    if (!ppp_option_len_check(tree, pinfo, tvb, proto_cbcp_option_callback_admin, tvb_reported_length(tvb), 4))
        return tvb_captured_length(tvb);

    tf = proto_tree_add_item(tree, proto_cbcp_option_callback_admin, tvb, offset, -1, ENC_NA);
    field_tree = proto_item_add_subtree(tf, ett_cbcp_callback_admin);

    dissect_cbcp_opt_type_len(tvb, offset, field_tree, proto_registrar_get_name(proto_cbcp_option_callback_admin));

    return dissect_cbcp_callback_opt_common(tvb, pinfo, tree, 0, tvb_reported_length(tvb));
}

static int
dissect_cbcp_callback_list_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    if (length < 4) {
        /* Bogus - option length isn't what it's supposed to be for this option. */
        proto_tree_add_expert_format(tree, pinfo, &ei_ppp_opt_len_invalid, tvb, 0, length,
                            "%s (with option length = %u byte%s; should be at least %u)",
                            proto_get_protocol_short_name(find_protocol_by_id(proto_cbcp_option_callback_list)),
                            length, plurality(length, "", "s"), 4);
        return tvb_captured_length(tvb);
    }

    tf = proto_tree_add_item(tree, proto_cbcp_option_callback_list, tvb, offset, length, ENC_NA);
    field_tree = proto_item_add_subtree(tf, ett_cbcp_callback_list);

    dissect_cbcp_opt_type_len(tvb, offset, field_tree, proto_registrar_get_name(proto_cbcp_option_callback_list));

    return dissect_cbcp_callback_opt_common(tvb, pinfo, tree, 0, tvb_reported_length(tvb));
}

static void
dissect_bacp_opt_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    uint8_t type;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_bacp_opt_type, tvb, offset, 1,
        type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_bacp_opt_length, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
}

static bool
dissect_bacp_fixed_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             int proto, int ett, int expected_length,
                             proto_tree** ret_tree, proto_item** ret_item)
{
    if (!ppp_option_len_check(tree, pinfo, tvb, proto, tvb_reported_length(tvb), expected_length))
        return false;

    *ret_item = proto_tree_add_item(tree, proto, tvb, 0, expected_length, ENC_NA);
    *ret_tree = proto_item_add_subtree(*ret_item, ett);

    dissect_bacp_opt_type_len(tvb, 0, *ret_tree, proto_registrar_get_name(proto));
    return true;
}

static int
dissect_bacp_favored_peer_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;
    int offset = 0;

    if (!dissect_bacp_fixed_opt(tvb, pinfo, tree, proto_bacp_option_favored_peer, ett_bacp_favored_peer_opt, 6,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_bacp_magic_number, tvb, offset + 2, 4, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static void
dissect_bap_opt_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    uint8_t type;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_bap_opt_type, tvb, offset, 1,
        type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_bap_opt_length, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
}

static bool
dissect_bap_fixed_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             int proto, int ett, int expected_length,
                             proto_tree** ret_tree, proto_item** ret_item)
{
    if (!ppp_option_len_check(tree, pinfo, tvb, proto, tvb_reported_length(tvb), expected_length))
        return false;

    *ret_item = proto_tree_add_item(tree, proto, tvb, 0, expected_length, ENC_NA);
    *ret_tree = proto_item_add_subtree(*ret_item, ett);

    dissect_bap_opt_type_len(tvb, 0, *ret_tree, proto_registrar_get_name(proto));
    return true;
}

static bool
dissect_bap_var_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             int proto, int ett, int expected_length,
                             proto_tree** ret_tree, proto_item** ret_item)
{
    int len = tvb_reported_length(tvb);

    if (len < expected_length) {
        /* Bogus - option length isn't what it's supposed to be for this option. */
        proto_tree_add_expert_format(tree, pinfo, &ei_ppp_opt_len_invalid, tvb, 0, len,
                            "%s (with option length = %u byte%s; should be at least %u)",
                            proto_get_protocol_short_name(find_protocol_by_id(proto)),
                            len, plurality(len, "", "s"), expected_length);
        return false;
    }

    *ret_item = proto_tree_add_item(tree, proto, tvb, 0, -1, ENC_NA);
    *ret_tree = proto_item_add_subtree(*ret_item, ett);

    dissect_bap_opt_type_len(tvb, 0, *ret_tree, proto_registrar_get_name(proto));
    return true;
}

static int
dissect_bap_link_type_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;
    int offset = 0;

    if (!dissect_bap_fixed_opt(tvb, pinfo, tree, proto_bap_option_link_type, ett_bap_link_type_opt, 5,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_bacp_link_speed, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_bacp_link_type, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static int
dissect_bap_phone_delta_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_tree *suboption_tree;
    proto_item *tf, *ti;
    int offset = 0;
    int length = tvb_reported_length(tvb);
    uint8_t     subopt_type;
    uint8_t     subopt_len;

    if (!dissect_bap_var_opt(tvb, pinfo, tree, proto_bap_option_phone_delta, ett_bap_phone_delta_opt, 4,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    offset += 2;
    length -= 2;

    while (length > 0) {
        subopt_type = tvb_get_uint8(tvb, offset);
        subopt_len = tvb_get_uint8(tvb, offset + 1);
        suboption_tree = proto_tree_add_subtree_format(field_tree, tvb, offset, subopt_len,
            ett_bap_phone_delta_subopt, NULL, "Sub-Option (%u byte%s)", subopt_len,
            plurality(subopt_len, "", "s"));

        proto_tree_add_item(suboption_tree, hf_bap_sub_option_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(suboption_tree, hf_bap_sub_option_length, tvb, offset + 1, 1, ENC_BIG_ENDIAN);

        if (subopt_len < 2) {
            expert_add_info_format(pinfo, ti, &ei_bap_sub_option_length,
                "Sub-Option Length invalid, must be >= 2");
            break;
        }
        if (subopt_len > length) {
            expert_add_info_format(pinfo, ti, &ei_bap_sub_option_length,
                "Sub-Option Length invalid, must be <= length remaining in option %u)", length);
            break;
        }

        switch (subopt_type) {
        case BAP_PHONE_DELTA_SUBOPT_UNIQ_DIGIT:
            if (subopt_len == 3) {
                proto_tree_add_item(suboption_tree, hf_bap_unique_digit, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
            } else {
                expert_add_info_format(pinfo, ti, &ei_bap_sub_option_length,
                    "Invalid suboption length: %u (must be == 3)", subopt_len);
            }
            break;
        case BAP_PHONE_DELTA_SUBOPT_SUBSC_NUM:
            if (subopt_len > 2) {
                proto_tree_add_item(suboption_tree, hf_bap_subscriber_number, tvb, offset + 2, subopt_len - 2, ENC_NA|ENC_ASCII);
            } else {
                expert_add_info_format(pinfo, ti, &ei_bap_sub_option_length,
                    "Invalid suboption length: %u (must be > 2)", subopt_len);
            }
            break;
        case BAP_PHONE_DELTA_SUBOPT_PHONENUM_SUBADDR:
            if (subopt_len > 2) {
                proto_tree_add_item(suboption_tree, hf_bap_phone_number_sub_address, tvb, offset + 2, subopt_len - 2, ENC_NA|ENC_ASCII);
            } else {
                expert_add_info_format(pinfo, ti, &ei_bap_sub_option_length,
                    "Invalid suboption length: %u (must be > 2)", subopt_len);
            }
            break;
        default:
            if (subopt_len > 2) {
                proto_tree_add_item(suboption_tree, hf_bap_unknown_option_data, tvb, offset + 2, subopt_len - 2, ENC_NA);
            } else {
                expert_add_info_format(pinfo, ti, &ei_bap_sub_option_length,
                    "Invalid suboption length: %u (must be > 2)", subopt_len);
            }
            break;
        }
        offset += subopt_len;
        length -= subopt_len;
    }
    return tvb_captured_length(tvb);
}

static int
dissect_bap_no_phone_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;

    dissect_bap_fixed_opt(tvb, pinfo, tree, proto_bap_option_no_phone, ett_bap_no_phone_opt, 2,
                                  &field_tree, &tf);
    return tvb_captured_length(tvb);
}

static int
dissect_bap_reason_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    if (!dissect_bap_var_opt(tvb, pinfo, tree, proto_bap_option_reason, ett_bap_reason_opt, 2,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_bap_reason, tvb, offset+2, length-2, ENC_NA|ENC_ASCII);
    return tvb_captured_length(tvb);
}

static int
dissect_bap_link_disc_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;
    int offset = 0;

    if (!dissect_bap_fixed_opt(tvb, pinfo, tree, proto_bap_option_link_disc, ett_bap_link_disc_opt, 4,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_bap_link_discriminator, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static int
dissect_bap_call_status_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;
    int offset = 0;

    if (!dissect_bap_fixed_opt(tvb, pinfo, tree, proto_bap_option_call_status, ett_bap_call_status_opt, 4,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_bap_call_status, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_bap_call_action, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static void
dissect_vsncp_opt_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    uint8_t type;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_vsncp_opt_type, tvb, offset, 1,
        type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_vsncp_opt_length, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
}

static bool
dissect_vsncp_fixed_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             int proto, int ett, int expected_length,
                             proto_tree** ret_tree, proto_item** ret_item)
{
    if (!ppp_option_len_check(tree, pinfo, tvb, proto, tvb_reported_length(tvb), expected_length))
        return false;

    *ret_item = proto_tree_add_item(tree, proto, tvb, 0, expected_length, ENC_NA);
    *ret_tree = proto_item_add_subtree(*ret_item, ett);

    dissect_vsncp_opt_type_len(tvb, 0, *ret_tree, proto_registrar_get_name(proto));
    return true;
}

static int
dissect_vsncp_pdnid_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_vsncp_fixed_opt(tvb, pinfo, tree,
                             proto_vsncp_option_pdnid, ett_vsncp_pdnid_opt, 3,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_vsncp_pdn_identifier, tvb, offset+2, 1, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static const value_string vsncp_attach_vals[] = {
    {1, "Initial Attach"},
    {3, "Handover Attach"},
    {0, NULL}
};

static int
dissect_vsncp_attachtype_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_vsncp_fixed_opt(tvb, pinfo, tree,
                             proto_vsncp_option_attachtype, ett_vsncp_attachtype_opt, 3,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_vsncp_attach_type, tvb, offset+2, 1, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static const value_string vsncp_pdntype_vals[] = {
    {0, "Initial Request by UE"},
    {1, "IPv4"},
    {2, "IPv6"},
    {3, "IPv6/IPv4"},
    {0, NULL}
};

static int
dissect_vsncp_pdntype_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_vsncp_fixed_opt(tvb, pinfo, tree,
                             proto_vsncp_option_pdntype, ett_vsncp_pdntype_opt, 3,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_vsncp_pdn_type, tvb, offset+2, 1, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static const value_string vsncp_errorcode_vals[] = {
    {0,  "General Error"},
    {1,  "Unauthorized APN"},
    {2,  "PDN Limit Exceeded"},
    {3,  "NO PG-W Available"},
    {4,  "P-GW Unreachable"},
    {5,  "P-GW Reject"},
    {6,  "Insufficient Parameters"},
    {7,  "Resource Unavailable"},
    {8,  "Admin Prohibited"},
    {9,  "PDN-ID Already in Use"},
    {10, "Subscription Limitation"},
    {11, "PDN connection already exists for APN"},
    {12, "Emergency services not supported"},
    {13, "Reconnect to this APN not allowed"},
    {14, "APN congested"},
    {0,  NULL}
};

static int
dissect_vsncp_errorcode_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    if (length < 3) {
        /* Bogus - option length isn't what it's supposed to be for this option. */
        proto_tree_add_expert_format(tree, pinfo, &ei_ppp_opt_len_invalid, tvb, 0, length,
                            "%s (with option length = %u byte%s; should be at least %u)",
                            proto_get_protocol_short_name(find_protocol_by_id(proto_vsncp_option_errorcode )),
                            length, plurality(length, "", "s"), 3);
        return tvb_captured_length(tvb);
    }

    tf = proto_tree_add_item(tree, proto_vsncp_option_errorcode, tvb, 0, length, ENC_NA);
    field_tree = proto_item_add_subtree(tf, ett_vsncp_errorcode_opt);

    dissect_vsncp_opt_type_len(tvb, 0, field_tree, proto_registrar_get_name(proto_vsncp_option_pdnaddress));

    proto_tree_add_item(field_tree, hf_vsncp_error_code, tvb, offset+2, 1, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static int
dissect_vsncp_pdnaddress_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    int length = tvb_reported_length(tvb);
    uint32_t pdnaddtype;

    if (length < 3) {
        /* Bogus - option length isn't what it's supposed to be for this option. */
        proto_tree_add_expert_format(tree, pinfo, &ei_ppp_opt_len_invalid, tvb, 0, length,
                            "%s (with option length = %u byte%s; should be at least %u)",
                            proto_get_protocol_short_name(find_protocol_by_id(proto_vsncp_option_pdnaddress )),
                            length, plurality(length, "", "s"), 3);
        return tvb_captured_length(tvb);
    }

    tf = proto_tree_add_item(tree, proto_vsncp_option_pdnaddress, tvb, 0, length, ENC_NA);
    field_tree = proto_item_add_subtree(tf, ett_vsncp_pdnaddress_opt);

    dissect_vsncp_opt_type_len(tvb, 0, field_tree, proto_registrar_get_name(proto_vsncp_option_pdnaddress));

    proto_tree_add_item_ret_uint(field_tree, hf_vsncp_pdn_type, tvb, offset + 2, 1, ENC_BIG_ENDIAN, &pdnaddtype);

    switch (pdnaddtype) {
    case 1:
        proto_tree_add_ipv4_format(field_tree, hf_vsncp_pdn_ipv4, tvb, offset + 3, 4,
            tvb_get_ntohl(tvb, offset + 3), "%s: %s",
            val_to_str_const(pdnaddtype, vsncp_pdntype_vals, "Unknown"),
            tvb_ip_to_str(pinfo->pool, tvb, offset + 3));
        break;

    case 2:
    {
        ws_in6_addr *ad = wmem_new0(pinfo->pool,ws_in6_addr);
        address addr;

        tvb_memcpy(tvb, &ad->bytes[8], offset + 3, 8);
        set_address(&addr, AT_IPv6, 16, ad->bytes);
        proto_tree_add_ipv6_format(field_tree, hf_vsncp_pdn_ipv6, tvb, offset + 3, length - 3, ad,
            "%s: %s", val_to_str_const(pdnaddtype, vsncp_pdntype_vals, "Unknown"),
            address_to_str(pinfo->pool, &addr));
        break;
    }

    case 3:
    {
        ws_in6_addr *ad = wmem_new0(pinfo->pool, ws_in6_addr);
        address addr;

        tvb_memcpy(tvb, &ad->bytes[8], offset + 3, 8);
        set_address(&addr, AT_IPv6, 16, ad->bytes);
        proto_tree_add_ipv6_format(field_tree, hf_vsncp_pdn_ipv6, tvb, offset + 3, length - 3, ad,
            "%s: %s", val_to_str_const(pdnaddtype, vsncp_pdntype_vals, "Unknown"),
            address_to_str(pinfo->pool, &addr));
        proto_tree_add_ipv4_format(field_tree, hf_vsncp_pdn_ipv4, tvb, offset + 11, length - 11,
            tvb_get_ntohl(tvb, offset + 11), "%s: %s", val_to_str_const(pdnaddtype, vsncp_pdntype_vals, "Unknown"),
            tvb_ip_to_str(pinfo->pool, tvb, offset + 11));
        break;
    }

    default:
        break;
    }

    return tvb_captured_length(tvb);
}

static int
dissect_vsncp_ipv4address_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_vsncp_fixed_opt(tvb, pinfo, tree,
                             proto_vsncp_option_ipv4address, ett_vsncp_ipv4address_opt, 6,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_vsncp_default_router_address, tvb, offset+2, 4, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static int
dissect_vsncp_apname_opt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    tf = proto_tree_add_item(tree, proto_vsncp_option_apname, tvb, 0, length, ENC_NA);
    field_tree = proto_item_add_subtree(tf, ett_vsncp_apname_opt);

    dissect_vsncp_opt_type_len(tvb, 0, field_tree, proto_registrar_get_name(proto_vsncp_option_apname));

    if (length > 2) {
        uint8_t i = 0;
        uint8_t j = 1;
        uint8_t lengthofapn;
        int off = offset + 2;

        while (i < (length - 2)) {
            lengthofapn = tvb_get_uint8(tvb, off++);
            proto_tree_add_string_format(field_tree, hf_vsncp_access_point_name, tvb, off, lengthofapn,
                tvb_get_string_enc(pinfo->pool, tvb, off, lengthofapn, ENC_ASCII),
                "Label%d (%d byte%s): %s", j++, lengthofapn,
                plurality(lengthofapn, "", "s"),
                tvb_format_text(pinfo->pool, tvb, off, lengthofapn));
            off += lengthofapn;
            i += lengthofapn + 1;
        }
    }
    return tvb_captured_length(tvb);
}

static const value_string vsncp_alloc_vals[] = {
    {0,   "Null Value (Attach or Handover)"},
    {18,  "New PDN type due to network preference"},
    {255, "Success"},
    {0,   NULL}
};

static int
dissect_vsncp_addressalloc_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_vsncp_fixed_opt(tvb, pinfo, tree,
                             proto_vsncp_option_addressalloc, ett_vsncp_addressalloc_opt, 3,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_vsncp_address_allocation_cause, tvb, offset+2, 1, ENC_BIG_ENDIAN);
    return tvb_captured_length(tvb);
}

static int
dissect_vsncp_apn_ambr_opt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;
    int length = tvb_reported_length(tvb);

    tf = proto_tree_add_item(tree, proto_vsncp_option_apn_ambr, tvb, 0, length, ENC_NA);
    field_tree = proto_item_add_subtree(tf, ett_vsncp_apn_ambr_opt);

    dissect_vsncp_opt_type_len(tvb, 0, field_tree, proto_registrar_get_name(proto_vsncp_option_apn_ambr ));
    proto_tree_add_item(field_tree, hf_vsncp_ambr_data, tvb, offset+2, length-2, ENC_NA);

    return tvb_captured_length(tvb);
}

static int
dissect_vsncp_ipv6_hsgw_lla_iid_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    int offset = 0;

    if (!dissect_vsncp_fixed_opt(tvb, pinfo, tree,
                             proto_vsncp_option_ipv6_hsgw_lla_iid, ett_vsncp_ipv6_hsgw_lla_iid_opt, 10,
                             &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_vsncp_ipv6_interface_identifier, tvb, offset+2, 8, ENC_NA);
    return tvb_captured_length(tvb);
}

/* Ch 10.5.6.3 3GPP TS 24.008 version 11.5.0 Release 11 */
static const value_string vsncp_pco_vals[] = {
    {0x8021, "IPCP (DNS Address Request)"},
    {0x0001, "P-CSCF Address Request (IPv6)"},
    {0x0005, "MS Support of Network Requested Bearer Control indicator"},
    {0x0003, "DNS Server Address (IPv6)"},
    {0x000A, "IP address allocation via NAS signalling"},
    {0x000B, "IPv4 address allocation via DHCPv4"},
    {0x000D, "DNS Server IPv4 Address Request"},
    {0,      NULL}
};

static int
dissect_vsncp_pco_opt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    uint8_t len;
    proto_tree *field_tree;
    proto_item *tf;
    int length = tvb_reported_length(tvb);
    int offset = 3;
    uint8_t i = 0;

    tf = proto_tree_add_item(tree, proto_vsncp_option_pco, tvb, 0, length, ENC_NA);
    field_tree = proto_item_add_subtree(tf, ett_vsncp_pco_opt);

    dissect_vsncp_opt_type_len(tvb, 0, field_tree, proto_registrar_get_name(proto_vsncp_option_pco));

    while (i < (length - 3)) {
        len = tvb_get_uint8(tvb, (offset + 2));
        proto_tree_add_item(field_tree, hf_vsncp_protocol, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree, hf_vsncp_protocol_configuration_length, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
        if (len > 0) {
            proto_tree_add_item(field_tree, hf_vsncp_protocol_configuration_data, tvb, offset + 3, len, ENC_NA);
        }

        offset += 3 + len;
        i += 3 + len;
    }

    return tvb_captured_length(tvb);
}

static void
dissect_cp(tvbuff_t *tvb, int proto_id, int proto_subtree_index,
    const value_string *proto_vals, int options_subtree_index,
    dissector_table_t option_table, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *fh_tree;
    uint8_t code;
    int length, offset;
    uint32_t oui;
    const char *manuf;
    uint32_t secs_remaining;

    code   = tvb_get_uint8(tvb, 0);
    length = tvb_get_ntohs(tvb, 2);

    col_set_str(pinfo->cinfo, COL_PROTOCOL,
        proto_get_protocol_short_name(find_protocol_by_id(proto_id)));
    col_set_str(pinfo->cinfo, COL_INFO,
        val_to_str_const(code, proto_vals, "Unknown"));

    ti = proto_tree_add_item(tree, proto_id, tvb, 0, length, ENC_NA);
    fh_tree = proto_item_add_subtree(ti, proto_subtree_index);
    proto_tree_add_uint_format_value(fh_tree, hf_ppp_code, tvb, 0, 1, code,
            "%s (%u)", val_to_str_const(code, proto_vals, "Unknown"), code);
    proto_tree_add_item(fh_tree, hf_ppp_identifier, tvb, 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(fh_tree, hf_ppp_length, tvb, 2, 2, ENC_BIG_ENDIAN);

    offset = 4;
    length -= 4;

    switch (code) {
    case VNDRSPCFC:
        proto_tree_add_item(fh_tree, hf_ppp_magic_number, tvb, offset, 4,
                ENC_BIG_ENDIAN);
        oui = tvb_get_ntoh24(tvb, offset + 4);
        ti = proto_tree_add_uint_format_value(fh_tree, hf_ppp_oui, tvb,
                offset + 4, 3, oui, "%02x:%02x:%02x", (oui >> 16) & 0xff,
                (oui >> 8) & 0xff, oui & 0xff);
        manuf = uint_get_manuf_name_if_known(oui);
        if (manuf){
            proto_item_append_text(ti, "(%s)", manuf);
        }
        proto_tree_add_item(fh_tree, hf_ppp_kind, tvb, offset + 7, 1,
                ENC_BIG_ENDIAN);
        if (length > 8) {
            proto_tree_add_item(fh_tree, hf_ppp_data, tvb, offset + 8,
                    length - 8, ENC_NA);
        }
        break;

    case CONFREQ:
    case CONFACK:
    case CONFNAK:
    case CONFREJ:
        if (length > 0) {
            proto_tree *field_tree;

            field_tree = proto_tree_add_subtree_format(fh_tree, tvb, offset, length,
                options_subtree_index, NULL, "Options: (%d byte%s)", length, plurality(length, "", "s"));
            ppp_dissect_options(tvb, offset, length, option_table, pinfo, field_tree);
        }
        break;

    case CODEREJ:
        if (length > 0) {
            /* TODO: Decode the rejected packet here ... but wait until we have
             * a valid capture file with a CODEREJ, since the only capture file
             * with CODEREJ packets in it that I know of is pppoe.dump.gz from
             * the menagerie, and that file appears to have malformed CODEREJ
             * packets as they don't include the Code, Identifier or Length
             * fields so it's impossible to do the decode. */
            proto_tree_add_bytes_format(fh_tree, hf_ppp_data, tvb, offset,
                length, NULL, "Rejected Packet (%d byte%s): %s", length,
                plurality(length, "", "s"),
                tvb_bytes_to_str(pinfo->pool, tvb, offset, length));
        }
        break;

    case PROTREJ:       /* LCP only: RFC 1661 */
        proto_tree_add_item(fh_tree, hf_lcp_rej_proto, tvb, offset, 2,
                ENC_BIG_ENDIAN);
        if (length > 2) {
            bool save_in_error_pkt;
            tvbuff_t *next_tvb;
            uint16_t protocol;

            protocol = tvb_get_ntohs(tvb, offset);
            offset += 2;
            length -= 2;

            /*
             * Save the current value of the "we're inside an error packet"
             * flag, and set that flag; subdissectors may treat packets that
             * are the payload of error packets differently from "real"
             * packets.
             */
            save_in_error_pkt = pinfo->flags.in_error_pkt;
            pinfo->flags.in_error_pkt = true;

            /* Decode the rejected packet. */
            next_tvb = tvb_new_subset_length(tvb, offset, length);
            if (!dissector_try_uint(ppp_subdissector_table, protocol, next_tvb,
                pinfo, fh_tree)) {
                call_data_dissector(next_tvb, pinfo, fh_tree);
            }

            /* Restore the "we're inside an error packet" flag. */
            pinfo->flags.in_error_pkt = save_in_error_pkt;
        }
        break;

    case ECHOREQ: /* All 3 are LCP only: RFC 1661 */
    case ECHOREP:
    case DISCREQ:
        proto_tree_add_item(fh_tree, hf_lcp_magic_number, tvb, offset, 4,
                ENC_BIG_ENDIAN);
        if (length > 4) {
            proto_tree_add_item(fh_tree, hf_lcp_data, tvb, offset + 4,
                    length - 4, ENC_NA);
        }
        break;

    case IDENT:         /* LCP only: RFC 1570 */
        proto_tree_add_item(fh_tree, hf_lcp_magic_number, tvb, offset, 4,
                ENC_BIG_ENDIAN);
        if (length > 4) {
            proto_tree_add_item(fh_tree, hf_lcp_message, tvb, offset + 4,
                    length - 4, ENC_ASCII);
        }
        break;

    case TIMEREMAIN:    /* LCP only: RFC 1570 */
        proto_tree_add_item(fh_tree, hf_lcp_magic_number, tvb, offset, 4,
                ENC_BIG_ENDIAN);
        secs_remaining = tvb_get_ntohl(tvb, offset + 4);
        proto_tree_add_uint_format_value(fh_tree, hf_lcp_secs_remaining,
                tvb, offset + 4, 4, secs_remaining, "%u %s", secs_remaining,
                (secs_remaining == 0xffffffff) ? "(forever)" : "seconds");
        if (length > 8) {
            proto_tree_add_item(fh_tree, hf_lcp_message, tvb, offset + 8,
                    length - 8, ENC_ASCII);
        }
        break;

    case TERMREQ:
    case TERMACK:
    case RESETREQ:  /* RESETREQ and RESETACK are CCP only: RFC 1962 */
    case RESETACK:
    default:
        if (length > 0) {
            proto_tree_add_item(fh_tree, hf_ppp_data, tvb, offset, length,
                ENC_NA);
        }
        break;
    }
}

/* Protocol field compression */
#define PFC_BIT 0x01

static void
dissect_ppp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    proto_tree *fh_tree, proto_item *ti, int proto_offset)
{
    uint16_t  ppp_prot;
    int       proto_len;
    tvbuff_t *next_tvb;

    /* Make direction information filterable */
    if (pinfo->p2p_dir == P2P_DIR_RECV || pinfo->p2p_dir == P2P_DIR_SENT) {
        proto_item *direction_ti = proto_tree_add_uint(fh_tree, hf_ppp_direction,
            tvb, 0, 0, pinfo->p2p_dir);
        proto_item_set_generated(direction_ti);
    }

    ppp_prot = tvb_get_uint8(tvb, 0);
    if (ppp_prot & PFC_BIT) {
        /* Compressed protocol field - just the byte we fetched. */
        proto_len = 1;
    } else {
        /* Uncompressed protocol field - fetch all of it. */
        ppp_prot = tvb_get_ntohs(tvb, 0);
        proto_len = 2;
    }

    /* If "ti" is not null, it refers to the top-level "proto_ppp" item
       for PPP, and proto_offset is the length of any stuff in the header
       preceding the protocol type, e.g. an HDLC header; add the length
       of the protocol type field to it, and set the length of that item
       to the result. */
    proto_item_set_len(ti, proto_offset + proto_len);

    proto_tree_add_uint(fh_tree, hf_ppp_protocol, tvb, 0, proto_len,
            ppp_prot);

    next_tvb = tvb_new_subset_remaining(tvb, proto_len);

    /* do lookup with the subdissector table */
    if (!dissector_try_uint(ppp_subdissector_table, ppp_prot, next_tvb, pinfo,
        tree)) {
        col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "0x%04x", ppp_prot);
        col_add_fstr(pinfo->cinfo, COL_INFO, "PPP %s (0x%04x)",
            val_to_str_ext_const(ppp_prot, &ppp_vals_ext, "Unknown"),
            ppp_prot);
        call_data_dissector(next_tvb, pinfo, tree);
    }
}

static int
dissect_lcp_options(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    ppp_dissect_options(tvb, 0, tvb_reported_length(tvb), lcp_option_table, pinfo, tree);
    return tvb_captured_length(tvb);
}

/*
 * RFC's 1661, 2153 and 1570.
 */
static int
dissect_lcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_cp(tvb, proto_lcp, ett_lcp, lcp_vals, ett_lcp_options, lcp_option_table, pinfo, tree);
    return tvb_captured_length(tvb);
}

static int
dissect_vsncp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *fh_tree;
    proto_tree *field_tree;
    uint8_t code;
    int length, offset;

    code = tvb_get_uint8(tvb, 0);
    length = tvb_get_ntohs(tvb, 2);
    vsnp_oui = tvb_get_uint24(tvb, 4, ENC_NA);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VSNCP");
    col_set_str(pinfo->cinfo, COL_INFO,
        val_to_str_const(code, cp_vals, "Unknown"));

    ti = proto_tree_add_item(tree, proto_vsncp, tvb, 0, length, ENC_NA);
    fh_tree = proto_item_add_subtree(ti, ett_vsncp);
    proto_tree_add_item(fh_tree, hf_vsncp_code, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(fh_tree, hf_vsncp_identifier, tvb, 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(fh_tree, hf_vsncp_length, tvb, 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(fh_tree, hf_ppp_oui, tvb, 4, 3, ENC_BIG_ENDIAN);

    offset = 7;
    length -= 7;

    switch (code) {
    case CONFREQ:
    case CONFACK:
    case CONFNAK:
    case CONFREJ:
    case TERMREQ:
    case TERMACK:
        if (length > 0) {
            field_tree = proto_tree_add_subtree_format(fh_tree, tvb, offset, length,
                                     ett_vsncp_options, NULL, "Options: (%d byte%s)", length,
                                     plurality(length, "", "s"));
            ppp_dissect_options(tvb, offset, length, vsncp_option_table, pinfo, field_tree);
        }
        break;

    default:
        /* TODO? */
        break;
    }
    return tvb_captured_length(tvb);
}

static int
dissect_vsnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *vsnp_item;
    proto_tree *vsnp_tree;

    int offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VSNP");
    col_clear(pinfo->cinfo, COL_INFO);

    vsnp_item = proto_tree_add_item(tree, proto_vsnp, tvb, 0, -1, ENC_NA);
    vsnp_tree = proto_item_add_subtree(vsnp_item, ett_vsnp);

    switch (vsnp_oui) {
        case OUI_BBF:
            col_set_str(pinfo->cinfo, COL_INFO, "Broadband Forum Session Data");
            /* TO DO: Add support for Broadband Forum's VSNP */
            break;
        case OUI_3GPP:
            col_set_str(pinfo->cinfo, COL_INFO, "3GPP Session Data");
            tvbuff_t *next_tvb;

            /* dissect 3GPP packet */
            proto_tree_add_item(vsnp_tree, hf_vsnp_3gpp_pdnid, tvb, offset, 1, ENC_BIG_ENDIAN);
            next_tvb = tvb_new_subset_remaining(tvb, 1);
            if (!dissector_try_uint(ppp_subdissector_table, PPP_IP, next_tvb, pinfo, tree)) {
                col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "0x%04x", PPP_IP);
                col_add_fstr(pinfo->cinfo, COL_INFO, "PPP %s (0x%04x)",
                val_to_str_ext_const(PPP_IP, &ppp_vals_ext, "Unknown"), PPP_IP);
                call_data_dissector(next_tvb, pinfo, tree);
            }
            break;
        default:
            break;
    }
    return tvb_captured_length(tvb);
}

/*
 * RFC 1332.
 */
static int
dissect_ipcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_cp(tvb, proto_ipcp, ett_ipcp, cp_vals, ett_ipcp_options, ipcp_option_table,
                pinfo, tree);
    return tvb_captured_length(tvb);
}

/*
 * RFC 3518
 */
#define BCP_FCS_PRESENT         0x80
#define BCP_ZEROPAD             0x20
#define BCP_IS_BCONTROL         0x10
#define BCP_PADS_MASK           0x0f

#define BCP_MACT_ETHERNET       1
#define BCP_MACT_802_4          2
#define BCP_MACT_802_5_NONCANON 3
#define BCP_MACT_FDDI_NONCANON  4
#define BCP_MACT_802_5_CANON    11
#define BCP_MACT_FDDI_CANON     12

static const value_string bcp_bpdu_mac_type_vals[] = {
    {BCP_MACT_ETHERNET,       "IEEE 802.3/Ethernet"},
    {BCP_MACT_802_4,          "IEEE 802.4"},
    {BCP_MACT_802_5_NONCANON, "IEEE 802.5, non-canonical addresses"},
    {BCP_MACT_FDDI_NONCANON,  "FDDI, non-canonical addresses"},
    {BCP_MACT_802_5_CANON,    "IEEE 802.5, canonical addresses"},
    {BCP_MACT_FDDI_CANON,     "FDDI, canonical addresses"},
    {0,                       NULL}
};

static int
dissect_bcp_bpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *bcp_bpdu_tree;
    int offset = 0;
    uint8_t flags;
    uint8_t mac_type;
    int captured_length, reported_length, pad_length;
    tvbuff_t *next_tvb;
    static int * const bcp_bpdu_flags[] = {
        &hf_bcp_bpdu_fcs_present,
        &hf_bcp_bpdu_zeropad,
        &hf_bcp_bpdu_bcontrol,
        &hf_bcp_bpdu_pads,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP BCP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_bcp_bpdu, tvb, 0, -1, ENC_NA);
    bcp_bpdu_tree = proto_item_add_subtree(ti, ett_bcp_bpdu);

    flags = tvb_get_uint8(tvb, offset);
    if (flags & BCP_IS_BCONTROL) {
        col_set_str(pinfo->cinfo, COL_INFO, "Bridge control");
    }

    proto_tree_add_bitmask(bcp_bpdu_tree, tvb, offset, hf_bcp_bpdu_flags, ett_bcp_bpdu_flags, bcp_bpdu_flags, ENC_NA);
    offset++;

    mac_type = tvb_get_uint8(tvb, offset);
    if (!(flags & BCP_IS_BCONTROL)) {
        col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str(mac_type, bcp_bpdu_mac_type_vals,
                "Unknown MAC type %u"));
    }
    proto_tree_add_uint(bcp_bpdu_tree, hf_bcp_bpdu_mac_type, tvb, offset, 1, mac_type);
    offset++;

    switch (mac_type) {

    case BCP_MACT_802_4:
    case BCP_MACT_802_5_NONCANON:
    case BCP_MACT_FDDI_NONCANON:
    case BCP_MACT_802_5_CANON:
    case BCP_MACT_FDDI_CANON:
        proto_tree_add_item(bcp_bpdu_tree, hf_bcp_bpdu_pad, tvb, offset, 1, ENC_NA);
        offset++;
        break;

    default:
        /* TODO? */
        break;
    }

    proto_item_set_len(ti, offset);

    if (!(flags & BCP_IS_BCONTROL)) {
        captured_length = tvb_captured_length_remaining(tvb, offset);
        reported_length = tvb_reported_length_remaining(tvb, offset);
        pad_length = flags & BCP_PADS_MASK;
        if (reported_length >= pad_length) {
            reported_length -= pad_length;
            if (captured_length > reported_length)
                captured_length = reported_length;
            next_tvb = tvb_new_subset_length_caplen(tvb, offset, captured_length,
                reported_length);
            switch (mac_type) {

            case BCP_MACT_ETHERNET:
                if (flags & BCP_FCS_PRESENT) {
                    call_dissector(eth_withfcs_handle, next_tvb, pinfo, tree);
                } else {
                    call_dissector(eth_withoutfcs_handle, next_tvb, pinfo,
                        tree);
                }
                break;

            case BCP_MACT_802_4:
            case BCP_MACT_802_5_NONCANON:
            case BCP_MACT_FDDI_NONCANON:
            case BCP_MACT_802_5_CANON:
            case BCP_MACT_FDDI_CANON:
                break;

            default:
                call_data_dissector(next_tvb, pinfo, tree);
                break;
            }
        }
    }
    return tvb_captured_length(tvb);
}

/* RFC 3518
 * 4.  A PPP Network Control Protocol for Bridging
 * :
 * The Bridging Control Protocol is exactly the same as the Link Control
 * Protocol [6] with the following exceptions...
 * :
 * ---the PPP Protocol field indicates type hex 8031 (BCP).
 */
static int
dissect_bcp_ncp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_cp(tvb, proto_bcp_ncp, ett_bcp_ncp, lcp_vals, ett_bcp_ncp_options,
        bcp_ncp_option_table, pinfo, tree);
    return tvb_captured_length(tvb);
}

/*
 * RFC 1377.
 */
static int
dissect_osinlcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_cp(tvb, proto_osinlcp, ett_osinlcp, cp_vals, ett_osinlcp_options, osinlcp_option_table,
        pinfo, tree);
    return tvb_captured_length(tvb);
}

/*
 * RFC 1962.
 */
static int
dissect_ccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_cp(tvb, proto_ccp, ett_ccp, ccp_vals, ett_ccp_options, ccp_option_table, pinfo, tree);
    return tvb_captured_length(tvb);
}

/*
 * Callback Control Protocol - see
 *
 * https://tools.ietf.org/html/draft-gidwani-ppp-callback-cp-00
 */
static int
dissect_cbcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_cp(tvb, proto_cbcp, ett_cbcp, cbcp_vals, ett_cbcp_options,
        cbcp_option_table, pinfo, tree);
    return tvb_captured_length(tvb);
}

/*
 * RFC 2125 (BACP and BAP).
 */
static int
dissect_bacp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_cp(tvb, proto_bacp, ett_bacp, cp_vals, ett_bacp_options, bacp_option_table,
                pinfo, tree);
    return tvb_captured_length(tvb);
}

static int
dissect_bap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *fh_tree;
    proto_tree *field_tree;
    uint8_t type;
    int length, offset;

    type = tvb_get_uint8(tvb, 0);
    length = tvb_get_ntohs(tvb, 2);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP BAP");
    col_set_str(pinfo->cinfo, COL_INFO,
        val_to_str_const(type, bap_vals, "Unknown"));

    ti = proto_tree_add_item(tree, proto_bap, tvb, 0, length, ENC_NA);
    fh_tree = proto_item_add_subtree(ti, ett_bap_options);
    proto_tree_add_item(fh_tree, hf_bap_type, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(fh_tree, hf_bap_identifier, tvb, 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(fh_tree, hf_bap_length, tvb, 2, 2, ENC_BIG_ENDIAN);

    offset = 4;
    length -= 4;

    if (type == BAP_CRES || type == BAP_CBRES ||
        type == BAP_LDQRES || type == BAP_CSRES) {
        proto_tree_add_item(fh_tree, hf_bap_response_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        length--;
    }

    if (length > 0) {
        field_tree = proto_tree_add_subtree_format(fh_tree, tvb, offset, length,
                                 ett_bap_options, NULL, "Data (%d byte%s)", length, plurality(length, "", "s"));
        ppp_dissect_options(tvb, offset, length, bap_option_table, pinfo, field_tree);
    }
    return tvb_captured_length(tvb);
}

#if 0 /* TODO? */
static int
dissect_comp_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *comp_data_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP Comp");
    col_set_str(pinfo->cinfo, COL_INFO, "Compressed data");

    ti = proto_tree_add_item(tree, proto_comp_data, tvb, 0, -1, ENC_NA);
    comp_data_tree = proto_item_add_subtree(ti, ett_comp_data);

    return tvb_captured_length(tvb);
}
#else
static int
dissect_comp_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP Comp");
    col_set_str(pinfo->cinfo, COL_INFO, "Compressed data");

    proto_tree_add_item(tree, proto_comp_data, tvb, 0, -1, ENC_NA);
    return tvb_captured_length(tvb);
}
#endif

/*
 * RFC 3153 (both PPPMuxCP and PPPMux).
 */
static int
dissect_pppmuxcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_cp(tvb, proto_pppmuxcp, ett_pppmuxcp, pppmuxcp_vals,
        ett_pppmuxcp_options, pppmuxcp_option_table, pinfo, tree);
    return tvb_captured_length(tvb);
}

#define PPPMUX_FLAGS_MASK          0xc0
#define PPPMUX_PFF_BIT_SET         0x80
#define PPPMUX_LXT_BIT_SET         0x40

static int
dissect_pppmux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree     *mux_tree, *hdr_tree, *sub_tree;
    proto_tree     *info_tree;
    proto_item     *ti           = NULL;
    uint8_t         flags, byte;
    uint16_t        length;
    static uint16_t pid;
    tvbuff_t       *next_tvb;
    int             offset       = 0, length_remaining;
    int             length_field, pid_field, hdr_length;
    static int * const subframe_flags[] = {
        &hf_pppmux_flags_pid,
        &hf_pppmux_flags_field_length,
        NULL
    };

    col_set_str(pinfo->cinfo,COL_PROTOCOL, "PPP PPPMux");
    col_set_str(pinfo->cinfo, COL_INFO, "PPP Multiplexing");

    length_remaining = tvb_reported_length(tvb);

    ti = proto_tree_add_item(tree, proto_pppmux, tvb, 0, -1, ENC_NA);
    mux_tree = proto_item_add_subtree(ti, ett_pppmux);

    while (length_remaining > 0) {
        flags = tvb_get_uint8(tvb,offset) & PPPMUX_FLAGS_MASK;

        if (flags & PPPMUX_LXT_BIT_SET) {
            length = tvb_get_ntohs(tvb,offset) & 0x3fff;
            length_field = 2;
        } else {
            length = tvb_get_uint8(tvb,offset) & 0x3f;
            length_field = 1;
        }

        if (flags & PPPMUX_PFF_BIT_SET) {
            byte = tvb_get_uint8(tvb,offset + length_field);
            if (byte & PFC_BIT) {             /* Compressed PID field */
                pid = byte;
                pid_field = 1;
            } else {                  /* PID field is 2 bytes */
                pid = tvb_get_ntohs(tvb,offset + length_field);
                pid_field = 2;
            }
        } else {
            pid_field = 0;   /* PID field is 0 bytes */
            if (!pid) {       /* No Last PID, hence use the default */
                if (pppmux_def_prot_id)
                    pid = pppmux_def_prot_id;
            }
        }

        hdr_length = length_field + pid_field;

        sub_tree = proto_tree_add_subtree(mux_tree, tvb, offset, length + length_field,
            ett_pppmux_subframe, NULL, "PPPMux Sub-frame");
        hdr_tree = proto_tree_add_subtree(sub_tree, tvb, offset, hdr_length,
            ett_pppmux_subframe_hdr, NULL, "Header field");

        proto_tree_add_bitmask(tree, tvb, offset, hf_pppmux_flags, ett_pppmux_subframe_flags, subframe_flags, ENC_BIG_ENDIAN);
        proto_tree_add_uint(hdr_tree, hf_pppmux_sub_frame_length, tvb,offset, length_field, length);

        ti = proto_tree_add_uint(hdr_tree, hf_pppmux_protocol, tvb,
            offset + length_field, pid_field, pid);

        /* if protocol is not present in the sub-frame */
        if (!(flags & PPPMUX_PFF_BIT_SET)) {
            /* mark this item as generated */
            proto_item_set_generated(ti);
        }

        offset += hdr_length;
        length_remaining -= hdr_length;
        length -= pid_field;

        tvb_ensure_bytes_exist (tvb, offset, length);
        info_tree = proto_tree_add_subtree(sub_tree, tvb,offset, length,
            ett_pppmux_subframe_info, NULL, "Information Field");
        next_tvb = tvb_new_subset_length(tvb, offset, length);

        if (!dissector_try_uint(ppp_subdissector_table, pid, next_tvb, pinfo,
            info_tree)) {
            call_data_dissector(next_tvb, pinfo, info_tree);
        }
        offset += length;
        length_remaining -= length;
    }
    return tvb_captured_length(tvb);
}

/*
 * RFC 2507 / RFC 2508 Internet Protocol Header Compression
 */
#define IPHC_CRTP_FH_FLAG_MASK   0xc0
#define IPHC_CRTP_FH_CIDLEN_FLAG 0x80
#define IPHC_CRTP_FH_DATA_FLAG   0x40

#define IPHC_CRTP_CS_CID8        1
#define IPHC_CRTP_CS_CID16       2

static int * const iphc_crtp_fh_flags_fields[] = {
    &hf_iphc_crtp_fh_cidlenflag,
    &hf_iphc_crtp_fh_dataflag,
    NULL
};

static const true_false_string iphc_crtp_fh_cidlenflag = {
    "16-bit",
    "8-bit"
};

static const value_string iphc_crtp_cs_flags[] = {
    {IPHC_CRTP_CS_CID8,  "8-bit Context Id"},
    {IPHC_CRTP_CS_CID16, "16-bit Context Id"},
    {0,                  NULL}
};

static const crumb_spec_t iphc_crtp_cntcp_cid16_crumbs[] = {
    {0, 8},
    {16, 8},
    {0, 0}
};

/*
 * 0x61 Packets: Full IP/UDP Header
 */
static int
dissect_iphc_crtp_fh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *fh_tree, *info_tree;
    proto_item *ti;
    unsigned  ip_hdr_len, flags, seq;
    unsigned  length;
    unsigned  hdr_len;
    tvbuff_t *next_tvb;
    int       offset_seq;
    int       offset_cid;
    uint8_t   ip_version;
    uint8_t   next_protocol;
    unsigned char   *ip_packet;

    length = tvb_reported_length(tvb);

    col_set_str(pinfo->cinfo,COL_PROTOCOL, "CRTP");
    col_set_str(pinfo->cinfo, COL_INFO, "Full Header");

    /* only dissect IPv4 and UDP */
    ip_version = tvb_get_uint8(tvb, 0) >> 4;
    flags = (tvb_get_uint8(tvb, 2) & IPHC_CRTP_FH_FLAG_MASK);
    next_protocol = tvb_get_uint8(tvb, 9);

    ti = proto_tree_add_protocol_format(tree, proto_iphc_crtp, tvb, 0, -1,
            "%s", val_to_str_ext_const(PPP_RTP_FH, &ppp_vals_ext, "Unknown"));
    fh_tree = proto_item_add_subtree(ti, ett_iphc_crtp);

    proto_tree_add_bitmask_with_flags(fh_tree, tvb, 2, hf_iphc_crtp_fh_flags,
            ett_iphc_crtp_fh_flags, iphc_crtp_fh_flags_fields, ENC_BIG_ENDIAN,
            BMT_NO_FLAGS);
    proto_tree_add_item(fh_tree, hf_iphc_crtp_gen, tvb, 2, 1,
            ENC_BIG_ENDIAN);

    /* calculate length of IP header, assume IPv4 */
    ip_hdr_len = (tvb_get_uint8(tvb, 0) & 0x0f) * 4;

    /* calculate total hdr length, assume UDP */
    hdr_len = ip_hdr_len + 8;

    if (ip_version != 4) {
        proto_tree_add_expert_format(fh_tree, pinfo, &ei_iphc_crtp_ip_version, tvb, 3, -1,
                            "IP version is %u: the only supported version is 4",
                            ip_version);
        return 1;
    }

    if (next_protocol != IP_PROTO_UDP) {
        proto_tree_add_expert_format(fh_tree, pinfo, &ei_iphc_crtp_next_protocol, tvb, 3, -1,
                            "Next protocol is %s (%u): the only supported protocol is UDP",
                            ipprotostr(next_protocol), next_protocol);
        return 1;
    }

    /* context id and sequence fields */
    if (flags & IPHC_CRTP_FH_CIDLEN_FLAG) {
        offset_seq = 3;
        offset_cid = ip_hdr_len + 4;
        if (flags & IPHC_CRTP_FH_DATA_FLAG) {
            proto_tree_add_item(fh_tree, hf_iphc_crtp_seq, tvb, offset_seq, 1,
                    ENC_BIG_ENDIAN);
        } else {
            seq = tvb_get_uint8(tvb, offset_seq);
            if (seq != 0) {
                ti = proto_tree_add_item(fh_tree, hf_iphc_crtp_seq, tvb, offset_seq,
                        1, ENC_BIG_ENDIAN);
                expert_add_info(pinfo, ti, &ei_iphc_crtp_seq_nonzero);
            }
        }
        proto_tree_add_item(fh_tree, hf_iphc_crtp_cid16, tvb, offset_cid,
                            2, ENC_BIG_ENDIAN);
    } else {
        offset_cid = 3;
        offset_seq = ip_hdr_len + 5;
        proto_tree_add_item(fh_tree, hf_iphc_crtp_cid8, tvb, offset_cid, 1,
                            ENC_BIG_ENDIAN);
        if (flags & IPHC_CRTP_FH_DATA_FLAG) {
            proto_tree_add_item(fh_tree, hf_iphc_crtp_seq, tvb, offset_seq, 1,
                    ENC_BIG_ENDIAN);
        } else {
            seq = tvb_get_uint8(tvb, offset_seq);
            if (seq != 0) {
                ti = proto_tree_add_item(fh_tree, hf_iphc_crtp_seq, tvb, offset_seq,
                        1, ENC_BIG_ENDIAN);
                expert_add_info(pinfo, ti, &ei_iphc_crtp_seq_nonzero);
            }
        }
    }

    /* information field */
    info_tree = proto_tree_add_subtree(fh_tree, tvb, 0, length, ett_iphc_crtp_info, NULL, "Information Field");

    /* XXX: 1: May trap above; 2: really only need to check for ip_hdr_len+6 ?? */
    tvb_ensure_bytes_exist (tvb, 0, hdr_len);  /* ip_hdr_len + 8 */

    /* allocate a copy of the IP packet */
    ip_packet = (unsigned char *)tvb_memdup(pinfo->pool, tvb, 0, length);

    /* restore the proper values to the IP and UDP length fields */
    ip_packet[2] = length >> 8;
    ip_packet[3] = length;

    ip_packet[ip_hdr_len + 4] = (length - ip_hdr_len) >> 8;
    ip_packet[ip_hdr_len + 5] = (length - ip_hdr_len);

    next_tvb = tvb_new_child_real_data(tvb, ip_packet, length, length);
    add_new_data_source(pinfo, next_tvb, "Decompressed Data");

    if (!dissector_try_uint(ppp_subdissector_table, PPP_IP, next_tvb, pinfo,
        info_tree)) {
        call_data_dissector(next_tvb, pinfo, info_tree);
    }
    return tvb_captured_length(tvb);
}

/*
 * 0x2067 Packets:  Compressed UDP with 16-bit Context Identifier
 */
static int
dissect_iphc_crtp_cudp16(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *cudp_tree;
    proto_item *ti;
    unsigned    length;
    unsigned    hdr_length;
    int         offset = 0;

    col_set_str(pinfo->cinfo,COL_PROTOCOL, "CRTP");
    col_set_str(pinfo->cinfo, COL_INFO, "Compressed UDP 16");

    length = tvb_reported_length(tvb);

    ti = proto_tree_add_protocol_format(tree, proto_iphc_crtp, tvb, 0, -1,
            "%s",
            val_to_str_ext_const(PPP_RTP_CUDP16, &ppp_vals_ext, "Unknown"));
    cudp_tree = proto_item_add_subtree(ti, ett_iphc_crtp);

    hdr_length = 3;

    proto_tree_add_item(cudp_tree, hf_iphc_crtp_cid16, tvb, 0, 2,
            ENC_BIG_ENDIAN);
    proto_tree_add_item(cudp_tree, hf_iphc_crtp_seq, tvb, 2, 1,
            ENC_BIG_ENDIAN);

    offset += hdr_length;
    length -= hdr_length;

    proto_tree_add_item(cudp_tree, hf_iphc_crtp_data, tvb, offset, length, ENC_NA);

    return tvb_captured_length(tvb);
}

/*
 * 0x67 Packets:  Compressed UDP with 8-bit Context Identifier
 */
static int
dissect_iphc_crtp_cudp8(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *cudp_tree;
    proto_item *ti;
    unsigned    length;
    unsigned    hdr_length;
    int         offset = 0;

    col_set_str(pinfo->cinfo,COL_PROTOCOL, "CRTP");
    col_set_str(pinfo->cinfo, COL_INFO, "Compressed UDP 8");

    length = tvb_reported_length(tvb);

    ti = proto_tree_add_protocol_format(tree, proto_iphc_crtp, tvb, 0, -1,
            "%s",
            val_to_str_ext_const(PPP_RTP_CUDP8, &ppp_vals_ext, "Unknown"));
    cudp_tree = proto_item_add_subtree(ti, ett_iphc_crtp);

    hdr_length = 2;

    proto_tree_add_item(cudp_tree, hf_iphc_crtp_cid8, tvb, 0, 1,
            ENC_BIG_ENDIAN);
    proto_tree_add_item(cudp_tree, hf_iphc_crtp_seq, tvb, 1, 1,
            ENC_BIG_ENDIAN);

    offset += hdr_length;
    length -= hdr_length;

    proto_tree_add_item(cudp_tree, hf_iphc_crtp_data, tvb, offset, length, ENC_NA);

    return tvb_captured_length(tvb);
}


/*
 * 0x2065 Packets:  Context State
 */
static int
dissect_iphc_crtp_cs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *cs_tree;
    proto_item *ti     = NULL;
    uint8_t     flags, cnt;
    unsigned    length, cid_size;
    unsigned    offset = 2, hf;

    col_set_str(pinfo->cinfo,COL_PROTOCOL, "CRTP");
    col_set_str(pinfo->cinfo, COL_INFO, "Context State");

    ti = proto_tree_add_protocol_format(tree, proto_iphc_crtp, tvb, 0, -1,
            "%s", val_to_str_ext_const(PPP_RTP_CS, &ppp_vals_ext, "Unknown"));

    cs_tree = proto_item_add_subtree(ti, ett_iphc_crtp);

    proto_tree_add_item(cs_tree, hf_iphc_crtp_cs_flags, tvb, 0, 1,
            ENC_BIG_ENDIAN);
    proto_tree_add_item(cs_tree, hf_iphc_crtp_cs_cnt, tvb, 1, 1,
            ENC_BIG_ENDIAN);

    /* calculate required length */
    flags = tvb_get_uint8(tvb, 0);
    cnt = tvb_get_uint8(tvb, 1);

    if (flags == IPHC_CRTP_CS_CID8) {
        hf = hf_iphc_crtp_cid8;
        cid_size = 1;
        length = 3 * cnt;
    } else {
        hf = hf_iphc_crtp_cid16;
        cid_size = 2;
        length = 4 * cnt;
    }

    while (offset < length) {
        proto_tree_add_item(cs_tree, hf, tvb, offset, cid_size,
                ENC_BIG_ENDIAN);
        offset += cid_size;
        proto_tree_add_item(cs_tree, hf_iphc_crtp_cs_invalid, tvb, offset,
                1, ENC_BIG_ENDIAN);
        proto_tree_add_item(cs_tree, hf_iphc_crtp_seq, tvb, offset, 1,
                ENC_BIG_ENDIAN);
        ++offset;
        proto_tree_add_item(cs_tree, hf_iphc_crtp_gen, tvb, offset, 1,
                ENC_BIG_ENDIAN);
        ++offset;
    }

    return tvb_captured_length(tvb);
}

/*
 * 0x65 Packets:  Compressed Non TCP
 */
static int
dissect_iphc_crtp_cntcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *cntcp_tree;
    proto_item *ti;
    unsigned    length, flags;
    unsigned    hdr_length;
    int         offset = 0;

    col_set_str(pinfo->cinfo,COL_PROTOCOL, "CRTP");
    col_set_str(pinfo->cinfo, COL_INFO, "Compressed Non TCP");

    length = tvb_reported_length(tvb);

    flags = (tvb_get_uint8(tvb, 1) & IPHC_CRTP_FH_FLAG_MASK);

    ti = proto_tree_add_protocol_format(tree, proto_iphc_crtp, tvb, 0, -1,
            "%s",
            val_to_str_ext_const(PPP_RTP_CNTCP, &ppp_vals_ext, "Unknown"));
    cntcp_tree = proto_item_add_subtree(ti, ett_iphc_crtp);

    if (flags & IPHC_CRTP_FH_CIDLEN_FLAG) {
        /* RFC 2507 6. Compressed Header Formats
         * d) Compressed non-TCP header, 16 bit CID:
         *      0             7
         *     +-+-+-+-+-+-+-+-+
         *     |  msb of CID   |
         *     +-+-+-+-+-+-+-+-+
         *     |1|D| Generation|
         *     +-+-+-+-+-+-+-+-+
         *     |  lsb of CID   |
         *     +-+-+-+-+-+-+-+-+
         *     |      data     |                      (if D=1)
         *      - - - - - - - -
         *     | RANDOM fields, if any (section 7)    (implied)
         */
        hdr_length = 3;
        proto_tree_add_split_bits_item_ret_val(cntcp_tree, hf_iphc_crtp_cid16, tvb, 0,
                iphc_crtp_cntcp_cid16_crumbs, NULL);
    } else {
        /* c) Compressed non-TCP header, 8 bit CID:
         *      0             7
         *     +-+-+-+-+-+-+-+-+
         *     |      CID      |
         *     +-+-+-+-+-+-+-+-+
         *     |0|D| Generation|
         *     +-+-+-+-+-+-+-+-+
         *     |      data     |                      (if D=1)
         *      - - - - - - - -
         *     | RANDOM fields, if any (section 7)    (implied)
         *      - - - - - - - -
         */
        hdr_length = 2;
        proto_tree_add_item(cntcp_tree, hf_iphc_crtp_cid8, tvb, 0, 1,
                ENC_BIG_ENDIAN);
    }
    proto_tree_add_bitmask_with_flags(cntcp_tree, tvb, 1, hf_iphc_crtp_fh_flags,
            ett_iphc_crtp_fh_flags, iphc_crtp_fh_flags_fields, ENC_BIG_ENDIAN,
            BMT_NO_FLAGS);
    proto_tree_add_item(cntcp_tree, hf_iphc_crtp_gen, tvb, 1, 1,
            ENC_BIG_ENDIAN);

    if (flags & IPHC_CRTP_FH_DATA_FLAG) {
        proto_tree_add_item(cntcp_tree, hf_iphc_crtp_seq, tvb, hdr_length++,
                1, ENC_BIG_ENDIAN);
    }

    offset += hdr_length;
    length -= hdr_length;

    /* The IPv4 Identification Field is RANDOM and thus included in a
     * compressed Non TCP packet (RFC 2507 6a, 7.13a). Only IPv4 is
     * supported in this dissector, so we don't worry about the IPv6
     * case, which is different (RFC 2507 7.1)."
     */
    proto_tree_add_item(cntcp_tree, hf_iphc_crtp_ip_id, tvb, offset,
            2, ENC_BIG_ENDIAN);
    offset += 2;
    length -= 2;

    proto_tree_add_item(cntcp_tree, hf_iphc_crtp_data, tvb, offset, length, ENC_NA);

    return tvb_captured_length(tvb);
}

/*
 * RFC 3032.
 */
static int
dissect_mplscp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_cp(tvb, proto_mplscp, ett_mplscp, cp_vals, ett_mplscp_options,
        NULL, pinfo, tree);
    return tvb_captured_length(tvb);
}

/*
 * Cisco Discovery Protocol Control Protocol.
 * XXX - where is this documented?
 */
static int
dissect_cdpcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_cp(tvb, proto_cdpcp, ett_cdpcp, cp_vals, ett_cdpcp_options, NULL,
        pinfo, tree);
    return tvb_captured_length(tvb);
}

/* PPP Multilink Protcol (RFC 1990) and
 * the Multiclass Extension to Multi-Link PPP (RFC 2686)
 */
static bool mp_short_seqno; /* Default to long sequence numbers */
static unsigned mp_max_fragments = 6;
/* Maximum fragments to try to reassemble. This affects performance and
 * memory use significantly. */
static unsigned mp_fragment_aging = 4000; /* Short sequence numbers only 12 bit */

#define MP_FRAG_MASK           0xFF
#define MP_FRAG_MASK_SHORT     0xF0
#define MP_FRAG_FIRST          0x80
#define MP_FRAG_LAST           0x40
#define MP_FRAG_CLS            0x3C
#define MP_FRAG_RESERVED       0x03
#define MP_FRAG_CLS_SHORT      0x30

/* According to RFC 1990, the length the MP header isn't indicated anywhere
   in the header itself.  It starts out at four bytes and can be
   negotiated down to two using LCP.  We currently have a preference
   to select short headers.  - gcc & gh
*/

static int
dissect_mp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree  *mp_tree;
    proto_item  *ti;
    bool save_fragmented;
    uint8_t     flags;
    uint32_t    cls; /* 32 bit since we shift it left and XOR with seqnum */
    uint32_t    seqnum;
    int         hdrlen;
    fragment_head *frag_mp;
    tvbuff_t    *next_tvb;
    static int * const mp_flags[] = {
        &hf_mp_frag_first,
        &hf_mp_frag_last,
        &hf_mp_sequence_num_cls,
        &hf_mp_sequence_num_reserved,
        NULL
    };
    static int * const mp_short_flags[] = {
        &hf_mp_frag_first,
        &hf_mp_frag_last,
        &hf_mp_short_sequence_num_cls,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP MP");
    col_set_str(pinfo->cinfo, COL_INFO, "PPP Multilink");

    save_fragmented = pinfo->fragmented;
    flags = tvb_get_uint8(tvb, 0);

    ti = proto_tree_add_item(tree, proto_mp, tvb, 0,
            mp_short_seqno ? 2 : 4, ENC_NA);
    mp_tree = proto_item_add_subtree(ti, ett_mp);

    if (mp_short_seqno) {
        proto_tree_add_bitmask(mp_tree, tvb, 0, hf_mp_frag_short, ett_mp_flags, mp_short_flags, ENC_NA);
        proto_tree_add_item_ret_uint(mp_tree, hf_mp_short_sequence_num, tvb,  0, 2, ENC_BIG_ENDIAN, &seqnum);
    } else {
        proto_tree_add_bitmask(mp_tree, tvb, 0, hf_mp_frag, ett_mp_flags, mp_flags, ENC_NA);
        proto_tree_add_item_ret_uint(mp_tree, hf_mp_sequence_num, tvb,  1, 3, ENC_BIG_ENDIAN, &seqnum);
    }

    hdrlen = mp_short_seqno ? 2 : 4;
    if (mp_short_seqno) {
        cls = (flags & MP_FRAG_CLS_SHORT) >> 4;
    } else {
        cls = (flags & MP_FRAG_CLS) >> 2;
    }
    if (tvb_reported_length_remaining(tvb, hdrlen) > 0) {
        pinfo->fragmented = true;
        frag_mp = NULL;
        if (!pinfo->fd->visited) {
            frag_mp = fragment_add_seq_single_aging(&mp_reassembly_table,
                tvb, hdrlen, pinfo, seqnum ^ (cls << 24), NULL,
                tvb_captured_length_remaining(tvb, hdrlen),
                flags & MP_FRAG_FIRST, flags & MP_FRAG_LAST,
                mp_max_fragments, mp_fragment_aging);
        } else {
            frag_mp = fragment_get_reassembled_id(&mp_reassembly_table, pinfo, seqnum ^ (cls << 24));
        }
        next_tvb = process_reassembled_data(tvb, hdrlen, pinfo,
            "Reassembled PPP MP payload", frag_mp, &mp_frag_items,
            NULL, mp_tree);

        if (frag_mp) {
            if (next_tvb) {
                dissect_ppp(next_tvb, pinfo, tree, NULL);
            } else {
                col_append_fstr(pinfo->cinfo, COL_INFO,
                    " (PPP MP reassembled in packet %u)",
                    frag_mp->reassembled_in);
                proto_tree_add_item(mp_tree, hf_mp_payload, tvb, hdrlen, -1, ENC_NA);
            }
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO,
                " (PPP MP Unreassembled fragment %u)",
                seqnum);
            proto_tree_add_item(mp_tree, hf_mp_payload, tvb, hdrlen, -1, ENC_NA);
        }
    }

    pinfo->fragmented = save_fragmented;
    return tvb_captured_length(tvb);
}

/*
 * Handles PPP without HDLC framing, just a protocol field (RFC 1661).
 */
static int
dissect_ppp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *fh_tree;

    ti = proto_tree_add_item(tree, proto_ppp, tvb, 0, -1, ENC_NA);
    fh_tree = proto_item_add_subtree(ti, ett_ppp);

    dissect_ppp_common(tvb, pinfo, tree, fh_tree, ti, 0);
    return tvb_captured_length(tvb);
}

static void
dissect_ppp_hdlc_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *fh_tree;
    uint8_t     byte0;
    int         proto_offset;
    tvbuff_t   *next_tvb;

    byte0 = tvb_get_uint8(tvb, 0);

    /* PPP HDLC encapsulation */
    if (byte0 == 0xff)
        proto_offset = 2;
    else {
        /* address and control are compressed (NULL) */
        proto_offset = 0;
    }

    /* load the top pane info. This should be overwritten by
       the next protocol in the stack */
    ti = proto_tree_add_item(tree, proto_ppp, tvb, 0, -1, ENC_NA);
    fh_tree = proto_item_add_subtree(ti, ett_ppp);
    if (byte0 == 0xff) {
        proto_tree_add_item(fh_tree, hf_ppp_address, tvb, 0, 1,
                ENC_BIG_ENDIAN);
        proto_tree_add_item(fh_tree, hf_ppp_control, tvb, 1, 1,
                ENC_BIG_ENDIAN);
    }

    next_tvb = decode_fcs(tvb, pinfo, fh_tree, ppp_fcs_decode, proto_offset);
    dissect_ppp_common(next_tvb, pinfo, tree, fh_tree, ti, proto_offset);
}

/*
 * Handles link-layer encapsulations where the frame might be
 * a PPP in HDLC-like Framing frame (RFC 1662) or a Cisco HDLC frame.
 */
static int
dissect_ppp_hdlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    uint8_t    byte0;

    byte0 = tvb_get_uint8(tvb, 0);
    if (byte0 == CHDLC_ADDR_UNICAST || byte0 == CHDLC_ADDR_MULTICAST) {
        /* Cisco HDLC encapsulation */
        return call_dissector(chdlc_handle, tvb, pinfo, tree);
    }

    /*
     * XXX - should we have an exported dissector that always dissects
     * PPP-in-HDLC-like-framing, without checking for Cisco HDLC, for
     * use when we know the packets are PPP, not Cisco HDLC?
     */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP");
    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DTE");
        col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DCE");
        break;

    case P2P_DIR_RECV:
        col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DCE");
        col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DTE");
        break;

    default:
        col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "N/A");
        col_set_str(pinfo->cinfo, COL_RES_DL_DST, "N/A");
        break;
    }

    dissect_ppp_hdlc_common(tvb, pinfo, tree);
    return tvb_captured_length(tvb);
}

static tvbuff_t*
remove_escape_chars(tvbuff_t *tvb, packet_info *pinfo, int offset, int length)
{
    uint8_t   *buff;
    int        i;
    int        scanned_len = 0;
    uint8_t    octet;
    tvbuff_t  *next_tvb;

    buff = (uint8_t *)wmem_alloc(pinfo->pool, length);
    i = 0;
    while (scanned_len < length) {
        octet = tvb_get_uint8(tvb, offset);
        if (octet == 0x7d) {
            offset++;
            scanned_len++;
            if (scanned_len >= length)
                break;
            octet = tvb_get_uint8(tvb, offset);
            buff[i] = octet ^ 0x20;
        } else {
            buff[i] = octet;
        }
        offset++;
        scanned_len++;
        i++;
    }
    if (i == 0) {
        return NULL;
    }
    next_tvb = tvb_new_child_real_data(tvb, buff, i, i);

    return next_tvb;
}

/*
 * Handles link-layer encapsulations where we have a raw RFC 1662
 * HDLC-like asynchronous framing byte stream, and have to
 * break the byte stream into frames and remove escapes.
 */
static int
dissect_ppp_raw_hdlc( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_ )
{
    proto_item *ti;
    proto_tree *bs_tree;
    int         offset, end_offset, data_offset;
    int         length, data_length;
    tvbuff_t   *ppp_tvb;
    bool        first   = true;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP");

    ti = proto_tree_add_item(tree, proto_ppp_hdlc, tvb, 0, -1, ENC_NA);
    bs_tree = proto_item_add_subtree(ti, ett_ppp_hdlc_data);

    /*
     * XXX - this needs to handle a PPP frame split over multiple higher-level
     * packets.
     */

    /*
     * Look for a frame delimiter.
     */
    offset = tvb_find_uint8(tvb, 0, -1, 0x7e);
    if (offset == -1) {
        /*
         * None found - this is presumably continued from an earlier
         * packet and continued in a later packet.
         */
        col_set_str(pinfo->cinfo, COL_INFO, "PPP Fragment");
        proto_tree_add_item(bs_tree, hf_ppp_hdlc_fragment, tvb, offset, -1, ENC_NA);
        offset++;
        length = tvb_captured_length_remaining(tvb,offset);
        ppp_tvb = remove_escape_chars(tvb, pinfo, offset,length);
        if (ppp_tvb != NULL) {
            add_new_data_source(pinfo, ppp_tvb, "PPP Fragment");
            call_data_dissector(ppp_tvb, pinfo, tree);
        }
        return tvb_captured_length(tvb);
    }
    if (offset != 0) {
        /*
         * We have some data preceding the first PPP packet;
         * mark it as a PPP fragment.
         */
        col_set_str(pinfo->cinfo, COL_INFO, "PPP Fragment");
        length = offset;
        proto_tree_add_item(bs_tree, hf_ppp_hdlc_fragment, tvb, 0, length, ENC_NA);
        ppp_tvb = remove_escape_chars(tvb, pinfo, 0, length - 1);
        if (ppp_tvb != NULL) {
            add_new_data_source(pinfo, ppp_tvb, "PPP Fragment");
            call_data_dissector(ppp_tvb, pinfo, tree);
        }
    }

    /* These frames within the byte stream need to be treated like independent
     * frames / PDUs, not encapsulated in each other, which means that much of
     * the various information stored in the packet_info struct should be reset
     * with each frame.
     * In particular, the "most recent conservation" elements should be reset
     * at the start of a new frame, if that frame is dissected, and possibly
     * for fragments that are put on a reassembly table (if the reassembly
     * functions use elements from the pinfo struct for matching). (#18278)
     * On the other hand, we do want to keep the last set information for use
     * in displaying the address of the packet, conversation filtering, etc.
     */
    bool save_use_conv_addr_port_endpoints;
    struct conversation_addr_port_endpoints *save_conv_addr_port_endpoints;
    struct conversation_element *save_conv_elements;

    save_use_conv_addr_port_endpoints = pinfo->use_conv_addr_port_endpoints;
    save_conv_addr_port_endpoints = pinfo->conv_addr_port_endpoints;
    save_conv_elements = pinfo->conv_elements;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {

        /*
         * Look for the next frame delimiter.
         */
        end_offset = tvb_find_uint8(tvb, offset + 1, -1, 0x7e);
        if (end_offset == -1) {
            /*
             * We didn't find one.  This is probably continued in a later
             * packet.
             */
            if (first)
                col_set_str(pinfo->cinfo, COL_INFO, "PPP Fragment");
            proto_tree_add_item(bs_tree, hf_ppp_hdlc_fragment, tvb, offset, -1, ENC_NA);
            offset++;
            length = tvb_captured_length_remaining(tvb, offset);
            ppp_tvb = remove_escape_chars(tvb, pinfo, offset, length);
            if (ppp_tvb != NULL) {
                add_new_data_source(pinfo, ppp_tvb, "PPP Fragment");
                call_data_dissector(ppp_tvb, pinfo, tree);
            }
            return tvb_captured_length(tvb);
        }

        data_offset = offset + 1;     /* skip starting frame delimiter */
        data_length = end_offset - data_offset;

        /*
         * Is that frame delimiter immediately followed by another one?
         * Some PPP implementations put a frame delimiter at the
         * beginning and the end of each frame, although RFC 1662
         * appears only to require that there be one frame delimiter
         * between adjacent frames:
         *
         *  Each frame begins and ends with a Flag Sequence, which is the
         *  binary sequence 01111110 (hexadecimal 0x7e).  All implementations
         *  continuously check for this flag, which is used for frame
         *  synchronization.
         *
         *  Only one Flag Sequence is required between two frames.  Two
         *  consecutive Flag Sequences constitute an empty frame, which is
         *  silently discarded, and not counted as a FCS error.
         *
         * If the delimiter at the end of this frame is followed by
         * another delimiter, we consider the first delimiter part
         * of this frame.
         */
        if (tvb_offset_exists(tvb, end_offset + 1) &&
            tvb_get_uint8(tvb, end_offset+1) == 0x7e) {
            end_offset++;
        }
        length = end_offset - offset;
        proto_tree_add_item(bs_tree, hf_ppp_hdlc_data, tvb, offset, length, ENC_NA);
        if (length > 1) {
            ppp_tvb = remove_escape_chars(tvb, pinfo, data_offset, data_length);
            if (ppp_tvb != NULL) {
                pinfo->use_conv_addr_port_endpoints = save_use_conv_addr_port_endpoints;
                pinfo->conv_addr_port_endpoints = save_conv_addr_port_endpoints;
                pinfo->conv_elements = save_conv_elements;
                add_new_data_source(pinfo, ppp_tvb, "PPP Message");
                dissect_ppp_hdlc_common(ppp_tvb, pinfo, tree);
                first = false;
            }
        }
        offset = end_offset;
    }
    return tvb_captured_length(tvb);
}

/*
 * At least for the PPP/USB captures I've seen, the data either starts with
 * 0x7eff03 or 0x7eff7d23 or 0xff03, so this function performs that heuristic
 * matching first before calling dissect_ppp_raw_hdlc().  Otherwise, if we call
 * it directly for USB captures, some captures like the following will not be
 * dissected correctly:
 * https://gitlab.com/wireshark/wireshark/-/wikis/SampleCaptures#head-886e340c31ca977f321c921f81cbec4c21bb7738
 */
static bool
dissect_ppp_usb( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
    /*
     * In some cases, the 0x03 normally in byte 3 is escaped so we must look
     * for the 2 byte sequence of 0x7d23 instead of 0x03.  The 0x23 is
     * generated by 0x20^0x03 per section 4.2 of:
     * https://tools.ietf.org/html/rfc1662.html.
     */
    static const unsigned char buf1[3] = {0x7e, 0xff, 0x03};
    static const unsigned char buf2[4] = {0x7e, 0xff, 0x7d, 0x23};
    tvbuff_t *next_tvb;

    if ((tvb_memeql(tvb, 0, buf2, sizeof(buf2)) == 0) ||
        (tvb_memeql(tvb, 0, buf1, sizeof(buf1)) == 0)) {
        dissect_ppp_raw_hdlc(tvb, pinfo, tree, data);
    } else if ((tvb_memeql(tvb, 0, &buf1[1], sizeof(buf1) - 1) == 0) ||
        (tvb_memeql(tvb, 0, &buf2[1], sizeof(buf2) - 1) == 0)) {
        /* It's missing the 0x7e framing character.  What TODO?
         * Should we try faking it by sticking 0x7e in front?  Or try telling
         * dissect_ppp_raw_hdlc() NOT to look for the 0x7e frame deliminator?
         * Or is this a bug in libpcap (used 1.1.0)?
         * Or a bug in the Linux kernel (tested with 2.6.24.4)  Or a bug in
         * usbmon?  Or is the data we're looking at really just part of the
         * payload and not control data?  Well, at least in my case it's
         * definitely not, but not sure if this is always the case. Is this
         * issue applicable only to PPP/USB or PPP/XYZ, in which case a more
         * general solution should be found?
         */
        /* For now, just try skipping the framing I guess??? */
        if (tvb_get_uint8(tvb, 1) == 0x03)
            next_tvb = tvb_new_subset_remaining(tvb, 2);
        else
            next_tvb = tvb_new_subset_remaining(tvb, 3);
        dissect_ppp(next_tvb, pinfo, tree, data);
    } else if (tvb_get_uint8(tvb, 0) == 0x7e) {
        /* Well, let's guess that since the 1st byte is 0x7e that it really is
         * a PPP frame, and the address and control bytes are compressed (NULL)
         * per https://tools.ietf.org/html/rfc1662, section 3.2, which means
         * that they're omitted from the packet. */
        next_tvb = tvb_new_subset_remaining(tvb, 1);
        dissect_ppp_hdlc_common(next_tvb, pinfo, tree);
    } else
        return false;
    return true;
}

void
proto_register_ppp_raw_hdlc(void)
{
    static hf_register_info hf[] = {
      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_ppp_hdlc_fragment, { "PPP Fragment", "ppp_hdlc.fragment", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ppp_hdlc_data, { "PPP Data", "ppp_hdlc.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_ppp_hdlc_data
    };

    proto_ppp_hdlc = proto_register_protocol("PPP In HDLC-Like Framing", "PPP-HDLC", "ppp_hdlc");
    ppp_raw_hdlc_handle = register_dissector("ppp_raw_hdlc", dissect_ppp_raw_hdlc, proto_ppp_hdlc);
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_ppp_hdlc, hf, array_length(hf));

    register_capture_dissector_table("ppp_hdlc", "PPP-HDLC");
    register_capture_dissector("ppp_hdlc", capture_ppp_hdlc, proto_ppp_hdlc);
}

void
proto_reg_handoff_ppp_raw_hdlc(void)
{
    capture_dissector_handle_t ppp_hdlc_cap_handle;

    dissector_add_uint("gre.proto", ETHERTYPE_CDMA2000_A10_UBS, ppp_raw_hdlc_handle);
    dissector_add_uint("gre.proto", ETHERTYPE_3GPP2, ppp_raw_hdlc_handle);

    /*
     * The heuristic checks are rather weak. Each payload starting with
     * 0x7e is accepted as a PPP over USB frame, this creates a lot of
     * false positives. We disable the heuristic subdissector by
     * default.
     */
    heur_dissector_add("usb.bulk", dissect_ppp_usb,
            "PPP USB bulk endpoint", "ppp_usb_bulk", proto_ppp, HEURISTIC_DISABLE);

    ppp_hdlc_cap_handle = find_capture_dissector("ppp_hdlc");
    capture_dissector_add_uint("wtap_encap", WTAP_ENCAP_PPP, ppp_hdlc_cap_handle);
    capture_dissector_add_uint("sll.ltype", LINUX_SLL_P_PPPHDLC, ppp_hdlc_cap_handle);
    capture_dissector_add_uint("fr.nlpid", NLPID_PPP, ppp_hdlc_cap_handle);

    chdlc_cap_handle = find_capture_dissector("chdlc");
}

/*
 * Handles PAP just as a protocol field
 */
static int
dissect_pap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti, *data_ti;
    proto_tree *fh_tree, *data_tree = NULL;
    uint8_t     code;
    char       *peer_id, *password, *message;
    uint8_t     peer_id_length, password_length, message_length;
    int         offset              = 0;

    code = tvb_get_uint8(tvb, 0);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP PAP");
    col_set_str(pinfo->cinfo, COL_INFO,
                val_to_str_const(code, pap_vals, "Unknown"));

    ti = proto_tree_add_item(tree, proto_pap, tvb, 0, -1, ENC_NA);
    fh_tree = proto_item_add_subtree(ti, ett_pap);

    proto_tree_add_item(fh_tree, hf_pap_code, tvb, offset, 1,
                        ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(fh_tree, hf_pap_identifier, tvb, offset, 1,
                        ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(fh_tree, hf_pap_length, tvb, offset, 2,
                        ENC_BIG_ENDIAN);
    offset += 2;

    data_ti = proto_tree_add_item(fh_tree, hf_pap_data, tvb, offset, -1,
                                  ENC_NA);
    data_tree = proto_item_add_subtree(data_ti, ett_pap_data);

    switch (code) {
    case CONFREQ:
        proto_tree_add_item(data_tree, hf_pap_peer_id_length, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        peer_id_length = tvb_get_uint8(tvb, offset);
        offset++;

        proto_tree_add_item(data_tree, hf_pap_peer_id, tvb, offset,
                            peer_id_length, ENC_ASCII);
        peer_id = tvb_format_text(pinfo->pool, tvb, offset, peer_id_length);
        offset += peer_id_length;

        proto_tree_add_item(data_tree, hf_pap_password_length, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        password_length = tvb_get_uint8(tvb, offset);
        offset++;

        proto_tree_add_item(data_tree, hf_pap_password, tvb, offset,
                            password_length, ENC_ASCII);
        password = tvb_format_text(pinfo->pool, tvb, offset, password_length);

        col_append_fstr(pinfo->cinfo, COL_INFO,
                        " (Peer-ID='%s', Password='%s')", peer_id, password);
        break;

    case CONFACK:
    case CONFNAK:
        proto_tree_add_item(data_tree, hf_pap_message_length, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        message_length = tvb_get_uint8(tvb, offset);
        offset +=1;

        proto_tree_add_item(data_tree, hf_pap_message, tvb, offset,
                            message_length, ENC_ASCII);
        message = tvb_format_text(pinfo->pool, tvb, offset, message_length);

        col_append_fstr(pinfo->cinfo, COL_INFO, " (Message='%s')",
                        message);
        break;

    default:
        proto_tree_add_item(data_tree, hf_pap_stuff, tvb, offset, -1,
                            ENC_NA);
        break;
    }
    return tvb_captured_length(tvb);
}

/*
 * RFC 1994
 * Handles CHAP just as a protocol field
 */
static int
dissect_chap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *fh_tree;
    proto_item *tf;
    proto_tree *field_tree;
    uint8_t     code, value_size;
    uint32_t    length;
    int         offset;

    code = tvb_get_uint8(tvb, 0);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP CHAP");
    col_set_str(pinfo->cinfo, COL_INFO,
        val_to_str_const(code, chap_vals, "Unknown"));


    /* Create CHAP protocol tree */
    ti = proto_tree_add_item(tree, proto_chap, tvb, 0, -1, ENC_NA);
    fh_tree = proto_item_add_subtree(ti, ett_chap);

    proto_tree_add_item(fh_tree, hf_chap_code, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(fh_tree, hf_chap_identifier, tvb, 1, 1,
            ENC_BIG_ENDIAN);

    /* Length - make sure it's valid */
    length = tvb_get_ntohs(tvb, 2);
    if (length < 4) {
        proto_tree_add_uint_format_value(fh_tree, hf_chap_length, tvb, 2, 2,
                length, "%u (invalid, must be >= 4)", length);
        return 4;
    }
    proto_item_set_len(ti, length);
    proto_tree_add_item(fh_tree, hf_chap_length, tvb, 2, 2,
            ENC_BIG_ENDIAN);

    offset = 4;     /* Offset moved to after length field */
    length -= 4;    /* Length includes previous 4 bytes, subtract */

    switch (code) {
    /* Challenge or Response data */
    case CHAP_CHAL:
    case CHAP_RESP:
        if (length > 0) {
            unsigned value_offset = 0;
            unsigned name_offset  = 0, name_size = 0;

            /* Create data subtree */
            tf = proto_tree_add_item(fh_tree, hf_chap_data, tvb, offset,
                                     length, ENC_NA);
            field_tree = proto_item_add_subtree(tf, ett_chap_data);
            length--;

            /* Value size */
            value_size = tvb_get_uint8(tvb, offset);
            if (value_size > length) {
                proto_tree_add_uint_format_value(field_tree, hf_chap_value_size, tvb, offset, 1,
                                    value_size, "%d byte%s (invalid, must be <= %u)",
                                    value_size, plurality(value_size, "", "s"), length);
                return offset;
            }
            proto_tree_add_item(field_tree, hf_chap_value_size, tvb,
                                offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* Value */
            if (length > 0) {
                value_offset = offset;
                proto_tree_add_item(field_tree, hf_chap_value, tvb, offset,
                                    value_size, ENC_NA);

                /* Move along value_size bytes */
                offset += value_size;
                length -= value_size;

                /* Find name in remaining bytes */
                if (length > 0) {
                    proto_tree_add_item(field_tree, hf_chap_name, tvb,
                                        offset, length, ENC_ASCII);
                    name_offset = offset;
                    name_size = length;
                }

                /* Show name and value in info column */
                col_append_fstr(pinfo->cinfo, COL_INFO,
                                " (NAME='%s%s', VALUE=0x%s)",
                                tvb_format_text(pinfo->pool, tvb, name_offset,
                                                (name_size > 20) ? 20 : name_size),
                                (name_size > 20) ? "..." : "",
                                (value_size > 0) ? tvb_bytes_to_str(pinfo->pool, tvb, value_offset, value_size) : "");
            }
        }
        break;

    /* Success or Failure data */
    case CHAP_SUCC:
    case CHAP_FAIL:
        if (length > 0) {
            proto_tree_add_item(fh_tree, hf_chap_message, tvb, offset,
                    length, ENC_ASCII);
        }

        /* Show message in info column */
        col_append_fstr(pinfo->cinfo, COL_INFO, " (MESSAGE='%s')",
            tvb_format_text(pinfo->pool, tvb, offset, length));
        break;

    /* Code from unknown code type... */
    default:
        if (length > 0)
            proto_tree_add_item(fh_tree, hf_chap_stuff, tvb, offset, length, ENC_NA);
        break;
    }
    return tvb_captured_length(tvb);
}

/*
 * RFC 2472.
 */
static int
dissect_ipv6cp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_cp(tvb, proto_ipv6cp, ett_ipv6cp, cp_vals, ett_ipv6cp_options, ipv6cp_option_table, pinfo, tree);
    return tvb_captured_length(tvb);
}

static void
dissect_ipv6cp_opt_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    uint8_t type;

    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_ipv6cp_opt_type, tvb, offset, 1,
        type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_ipv6cp_opt_length, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
}

static bool
dissect_ipv6cp_fixed_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             int proto, int ett, int expected_length,
                             proto_tree** ret_tree, proto_item** ret_item)
{
    if (!ppp_option_len_check(tree, pinfo, tvb, proto, tvb_reported_length(tvb), expected_length))
        return false;

    *ret_item = proto_tree_add_item(tree, proto, tvb, 0, expected_length, ENC_NA);
    *ret_tree = proto_item_add_subtree(*ret_item, ett);

    dissect_ipv6cp_opt_type_len(tvb, 0, *ret_tree, proto_registrar_get_name(proto));
    return true;
}

static int
dissect_ipv6cp_if_id_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree* field_tree;
    proto_item* tf;
    int offset = 0;

    if (!dissect_ipv6cp_fixed_opt(tvb, pinfo, tree, proto_ipv6cp_option_if_id, ett_ipv6cp_if_id_opt, 10,
                                  &field_tree, &tf))
        return tvb_captured_length(tvb);

    proto_tree_add_item(field_tree, hf_ipv6cp_interface_identifier, tvb, offset+2, 8, ENC_NA);
    return tvb_captured_length(tvb);
}

void
proto_register_ppp(void)
{
    static hf_register_info hf[] = {
        { &hf_ppp_direction,
            { "Direction", "ppp.direction", FT_UINT8, BASE_DEC,
                VALS(ppp_direction_vals), 0x0, "PPP direction", HFILL }},
        { &hf_ppp_address,
            { "Address", "ppp.address", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_control,
            { "Control", "ppp.control", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_protocol,
            { "Protocol", "ppp.protocol", FT_UINT16, BASE_HEX|BASE_EXT_STRING,
                &ppp_vals_ext, 0x0, NULL, HFILL }},
        { &hf_ppp_code,
            { "Code", "ppp.code", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_identifier,
            { "Identifier", "ppp.identifier", FT_UINT8, BASE_DEC_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_length,
            { "Length", "ppp.length", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_magic_number,
            { "Magic Number", "ppp.magic_number", FT_UINT32, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_oui,
            { "OUI", "ppp.oui", FT_UINT24, BASE_OUI,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_kind,
            { "Kind", "ppp.kind", FT_UINT8, BASE_DEC_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_data,
            { "Data", "ppp.data", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_fcs_16,
            { "FCS 16", "ppp.fcs_16", FT_UINT16, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_fcs_32,
            { "FCS 32", "ppp.fcs_32", FT_UINT32, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_fcs_status,
            { "FCS Status", "ppp.fcs.status", FT_UINT8, BASE_NONE,
                VALS(proto_checksum_vals), 0x0, NULL, HFILL }},
    };
    static int *ett[] = {
        &ett_ppp,
        &ett_ppp_opt_type,
        &ett_ppp_unknown_opt
    };
    static ei_register_info ei[] = {
        { &ei_ppp_opt_len_invalid, { "ppp.opt.len.invalid", PI_PROTOCOL, PI_WARN, "Invalid length for option", EXPFILL }},
        { &ei_ppp_fcs, { "ppp.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
    };

    module_t *ppp_module;
    expert_module_t* expert_ppp;

    proto_ppp = proto_register_protocol("Point-to-Point Protocol", "PPP", "ppp");
    proto_register_field_array(proto_ppp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ppp = expert_register_protocol(proto_ppp);
    expert_register_field_array(expert_ppp, ei, array_length(ei));

    /* subdissector code */
    ppp_subdissector_table = register_dissector_table("ppp.protocol",
        "PPP protocol", proto_ppp, FT_UINT16, BASE_HEX);

    ppp_hdlc_handle = register_dissector("ppp_hdlc", dissect_ppp_hdlc, proto_ppp);
    register_dissector("ppp_lcp_options", dissect_lcp_options, proto_ppp);
    ppp_handle = register_dissector("ppp", dissect_ppp, proto_ppp);

    /* Register the preferences for the ppp protocol */
    ppp_module = prefs_register_protocol(proto_ppp, NULL);

    prefs_register_enum_preference(ppp_module, "fcs_type",
        "PPP Frame Checksum Type",
        "The type of PPP frame checksum (none, 16-bit, 32-bit)",
        &ppp_fcs_decode, fcs_options, false);
    prefs_register_obsolete_preference(ppp_module, "decompress_vj");
    prefs_register_uint_preference(ppp_module, "default_proto_id",
        "PPPMuxCP Default PID (in hex)",
        "Default Protocol ID to be used for PPPMuxCP",
        16, &pppmux_def_prot_id);
}

void
proto_reg_handoff_ppp(void)
{
    /*
     * Get a handle for the CHDLC dissector.
     */
    chdlc_handle = find_dissector_add_dependency("chdlc", proto_ppp);

    dissector_add_uint("fr.nlpid", NLPID_PPP, ppp_handle);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_PPP, ppp_hdlc_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_PPP_WITH_PHDR,
        ppp_hdlc_handle);
    dissector_add_uint("sll.ltype", LINUX_SLL_P_PPPHDLC, ppp_hdlc_handle);
    dissector_add_uint("osinl.excl", NLPID_PPP, ppp_handle);
    dissector_add_uint("gre.proto", ETHERTYPE_PPP, ppp_hdlc_handle);
    dissector_add_uint("juniper.proto", JUNIPER_PROTO_PPP, ppp_handle);
    dissector_add_uint("sflow_245.header_protocol", SFLOW_245_HEADER_PPP, ppp_hdlc_handle);
    dissector_add_uint("l2tp.pw_type", L2TPv3_PW_PPP, ppp_hdlc_handle);
}

void
proto_register_mp(void)
{
    static hf_register_info hf[] = {
        { &hf_mp_frag,
            { "Fragment", "mp.frag", FT_UINT8, BASE_HEX,
                NULL, MP_FRAG_MASK, NULL, HFILL }},
        { &hf_mp_frag_short,
            { "Fragment", "mp.frag", FT_UINT8, BASE_HEX,
                NULL, MP_FRAG_MASK_SHORT, NULL, HFILL }},
        { &hf_mp_frag_first,
            { "First fragment", "mp.first", FT_BOOLEAN, 8,
                TFS(&tfs_yes_no), MP_FRAG_FIRST, NULL, HFILL }},
        { &hf_mp_frag_last,
            { "Last fragment", "mp.last", FT_BOOLEAN, 8,
                TFS(&tfs_yes_no), MP_FRAG_LAST, NULL, HFILL }},
        { &hf_mp_sequence_num,
            { "Sequence number", "mp.seq", FT_UINT24, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_mp_sequence_num_cls,
            { "Class", "mp.sequence_num_cls", FT_UINT8, BASE_DEC,
                NULL, MP_FRAG_CLS, NULL, HFILL }},
        { &hf_mp_sequence_num_reserved,
            { "Reserved", "mp.sequence_num_reserved", FT_BOOLEAN, 8,
                NULL, MP_FRAG_RESERVED, NULL, HFILL }},
        { &hf_mp_short_sequence_num,
            { "Short Sequence number", "mp.sseq", FT_UINT16, BASE_DEC,
                NULL, 0x0FFF, NULL, HFILL }},
        { &hf_mp_short_sequence_num_cls,
            { "Class", "mp.short_sequence_num_cls", FT_UINT8, BASE_DEC,
                NULL, MP_FRAG_CLS_SHORT, NULL, HFILL }},
        { &hf_mp_payload,
            {"Payload", "mp.payload", FT_BYTES, BASE_NONE,
                NULL, 0x00, NULL, HFILL }},
        { &hf_mp_fragments,
            {"Message fragments", "mp.fragments", FT_NONE, BASE_NONE,
                NULL, 0x00, NULL, HFILL }},
        { &hf_mp_fragment,
          {"Message fragment", "mp.fragment", FT_FRAMENUM, BASE_NONE,
                NULL, 0x00, NULL, HFILL }},
        { &hf_mp_fragment_overlap,
          {"Message fragment overlap", "mp.fragment.overlap",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x00, NULL, HFILL }},
        { &hf_mp_fragment_overlap_conflicts,
          {"Message fragment overlapping with conflicting data", "mp.fragment.overlap.conflicts",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x00, NULL, HFILL }},
        { &hf_mp_fragment_multiple_tails,
          {"Message has multiple tail fragments", "mp.fragment.multiple_tails",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x00, NULL, HFILL }},
        { &hf_mp_fragment_too_long_fragment,
          {"Message fragment too long", "mp.fragment.too_long_fragment",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x00, NULL, HFILL }},
        { &hf_mp_fragment_error,
          {"Message defragmentation error", "mp.fragment.error",
                FT_FRAMENUM, BASE_NONE,
                NULL, 0x00, NULL, HFILL }},
        { &hf_mp_fragment_count,
          {"Message fragment count", "mp.fragment.count", FT_UINT32, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},
        { &hf_mp_reassembled_in,
          {"Reassembled in", "mp.reassembled.in", FT_FRAMENUM, BASE_NONE,
                NULL, 0x00, NULL, HFILL }},
        { &hf_mp_reassembled_length,
          {"Reassembled length", "mp.reassembled.length", FT_UINT32, BASE_DEC,
                NULL, 0x00, NULL, HFILL }}
    };
    static int *ett[] = {
        &ett_mp,
        &ett_mp_flags,
        &ett_mp_fragment,
        &ett_mp_fragments
    };

    module_t *mp_module;

    proto_mp = proto_register_protocol("PPP Multilink Protocol", "PPP MP", "mp");
    mp_handle = register_dissector("mp", dissect_mp, proto_mp);
    proto_register_field_array(proto_mp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    reassembly_table_register(&mp_reassembly_table,
                          &addresses_reassembly_table_functions);

    /* Register the preferences for the PPP multilink protocol */
    mp_module = prefs_register_protocol(proto_mp, NULL);

    prefs_register_bool_preference(mp_module, "short_seqno",
        "Short sequence numbers",
        "Whether PPP Multilink frames use 12-bit sequence numbers",
        &mp_short_seqno);
    prefs_register_uint_preference(mp_module, "max_fragments",
        "Maximum fragments",
        "Maximum number of PPP Multilink fragments to try to reassemble into one frame",
        10, &mp_max_fragments);
    prefs_register_uint_preference(mp_module, "fragment_aging",
        "Max unreassembled fragment age",
        "Age off unreassembled fragments after this many packets",
        10, &mp_fragment_aging);
}

void
proto_reg_handoff_mp(void)
{
    dissector_add_uint("ppp.protocol", PPP_MP, mp_handle);
}

void
proto_register_lcp(void)
{
    static hf_register_info hf[] = {
        { &hf_lcp_magic_number,
            { "Magic Number", "lcp.magic_number", FT_UINT32, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_data,
            { "Data", "lcp.data", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_message,
            { "Message", "lcp.message", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_secs_remaining,
            { "Seconds Remaining", "lcp.secs_remaining", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_rej_proto,
            { "Rejected Protocol", "lcp.rej_proto", FT_UINT16,
                BASE_HEX | BASE_EXT_STRING, &ppp_vals_ext, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_type,
            { "Type", "lcp.opt.type", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_length,
            { "Length", "lcp.opt.length", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_oui,
            { "OUI", "lcp.opt.oui", FT_UINT24, BASE_OUI,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_kind,
            { "Kind", "lcp.opt.kind", FT_UINT8, BASE_DEC_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_data,
            { "Data", "lcp.opt.data", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_mru,
            { "Maximum Receive Unit", "lcp.opt.mru", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap,
            { "Async Control Character Map", "lcp.opt.asyncmap", FT_UINT32,
                BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_nul,
            { "NUL", "lcp.opt.asyncmap.nul", FT_BOOLEAN, 32,
                NULL, 0x00000001, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_soh,
            { "SOH", "lcp.opt.asyncmap.soh", FT_BOOLEAN, 32,
                NULL, 0x00000002, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_stx,
            { "STX", "lcp.opt.asyncmap.stx", FT_BOOLEAN, 32,
                NULL, 0x00000004, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_etx,
            { "ETX", "lcp.opt.asyncmap.etx", FT_BOOLEAN, 32,
                NULL, 0x00000008, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_eot,
            { "EOT", "lcp.opt.asyncmap.eot", FT_BOOLEAN, 32,
                NULL, 0x00000010, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_enq,
            { "ENQ", "lcp.opt.asyncmap.enq", FT_BOOLEAN, 32,
                NULL, 0x00000020, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_ack,
            { "ACK", "lcp.opt.asyncmap.ack", FT_BOOLEAN, 32,
                NULL, 0x00000040, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_bel,
            { "BEL", "lcp.opt.asyncmap.bel", FT_BOOLEAN, 32,
                NULL, 0x00000080, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_bs,
            { "BS", "lcp.opt.asyncmap.bs", FT_BOOLEAN, 32,
                NULL, 0x00000100, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_ht,
            { "HT", "lcp.opt.asyncmap.ht", FT_BOOLEAN, 32,
                NULL, 0x00000200, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_lf,
            { "LF", "lcp.opt.asyncmap.lf", FT_BOOLEAN, 32,
                NULL, 0x00000400, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_vt,
            { "VT", "lcp.opt.asyncmap.vt", FT_BOOLEAN, 32,
                NULL, 0x00000800, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_ff,
            { "FF", "lcp.opt.asyncmap.ff", FT_BOOLEAN, 32,
                NULL, 0x00001000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_cr,
            { "CR", "lcp.opt.asyncmap.cr", FT_BOOLEAN, 32,
                NULL, 0x00002000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_so,
            { "SO", "lcp.opt.asyncmap.so", FT_BOOLEAN, 32,
                NULL, 0x00004000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_si,
            { "SI", "lcp.opt.asyncmap.si", FT_BOOLEAN, 32,
                NULL, 0x00008000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_dle,
            { "DLE", "lcp.opt.asyncmap.dle", FT_BOOLEAN, 32,
                NULL, 0x00010000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_dc1,
            { "DC1 (XON)", "lcp.opt.asyncmap.dc1", FT_BOOLEAN, 32,
                NULL, 0x00020000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_dc2,
            { "DC2", "lcp.opt.asyncmap.dc2", FT_BOOLEAN, 32,
                NULL, 0x00040000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_dc3,
            { "DC3 (XOFF)", "lcp.opt.asyncmap.dc3", FT_BOOLEAN, 32,
                NULL, 0x00080000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_dc4,
            { "DC4", "lcp.opt.asyncmap.dc4", FT_BOOLEAN, 32,
                NULL, 0x00100000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_nak,
            { "NAK", "lcp.opt.asyncmap.nak", FT_BOOLEAN, 32,
                NULL, 0x00200000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_syn,
            { "SYN", "lcp.opt.asyncmap.syn", FT_BOOLEAN, 32,
                NULL, 0x00400000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_etb,
            { "ETB", "lcp.opt.asyncmap.etb", FT_BOOLEAN, 32,
                NULL, 0x00800000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_can,
            { "CAN", "lcp.opt.asyncmap.can", FT_BOOLEAN, 32,
                NULL, 0x01000000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_em,
            { "EM", "lcp.opt.asyncmap.em", FT_BOOLEAN, 32,
                NULL, 0x02000000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_sub,
            { "SUB", "lcp.opt.asyncmap.sub", FT_BOOLEAN, 32,
                NULL, 0x04000000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_esc,
            { "ESC", "lcp.opt.asyncmap.esc", FT_BOOLEAN, 32,
                NULL, 0x08000000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_fs,
            { "FS", "lcp.opt.asyncmap.fs", FT_BOOLEAN, 32,
                NULL, 0x10000000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_gs,
            { "GS", "lcp.opt.asyncmap.gs", FT_BOOLEAN, 32,
                NULL, 0x20000000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_rs,
            { "RS", "lcp.opt.asyncmap.rs", FT_BOOLEAN, 32,
                NULL, 0x40000000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_us,
            { "US", "lcp.opt.asyncmap.us", FT_BOOLEAN, 32,
                NULL, 0x80000000, NULL, HFILL }},
        { &hf_lcp_opt_auth_protocol,
            { "Authentication Protocol", "lcp.opt.auth_protocol", FT_UINT16,
                BASE_HEX | BASE_EXT_STRING, &ppp_vals_ext, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_algorithm,
            { "Algorithm", "lcp.opt.algorithm", FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING, &chap_alg_rvals,
                0x0, NULL, HFILL }},
        { &hf_lcp_opt_quality_protocol,
            { "Quality Protocol", "lcp.opt.quality_protocol", FT_UINT16,
                BASE_HEX | BASE_EXT_STRING, &ppp_vals_ext, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_magic_number,
            { "Magic Number", "lcp.opt.magic_number", FT_UINT32, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_reportingperiod,
            { "Reporting Period", "lcp.opt.reporting_period", FT_UINT32,
                BASE_DEC|BASE_UNIT_STRING, UNS(&units_microsecond_microseconds), 0x0,
                "Maximum time in micro-seconds that the remote end should "
                "wait between transmission of LCP Link-Quality-Report packets",
                HFILL }},
        { &hf_lcp_opt_fcs_alternatives,
            { "FCS Alternatives", "lcp.opt.fcs_alternatives", FT_UINT8,
                BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_fcs_alternatives_null,
            { "NULL FCS", "lcp.opt.fcs_alternatives.null", FT_BOOLEAN, 8,
                NULL, 0x01, NULL, HFILL }},
        { &hf_lcp_opt_fcs_alternatives_ccitt16,
            { "CCITT 16-bit", "lcp.opt.fcs_alternatives.ccitt16", FT_BOOLEAN,
                8, NULL, 0x02, NULL, HFILL }},
        { &hf_lcp_opt_fcs_alternatives_ccitt32,
            { "CCITT 32-bit", "lcp.opt.fcs_alternatives.ccitt32", FT_BOOLEAN,
                8, NULL, 0x04, NULL, HFILL }},
        { &hf_lcp_opt_maximum,
            { "Maximum", "lcp.opt.maximum", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_octet_octets), 0x0,
                "The largest number of padding octets which may be added "
                "to the frame.", HFILL }},
        { &hf_lcp_opt_window,
            { "Window", "lcp.opt.window", FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_frame_frames), 0x0,
                "The number of frames the receiver will buffer.", HFILL }},
        { &hf_lcp_opt_hdlc_address,
            { "Address", "lcp.opt.hdlc_address", FT_BYTES, BASE_NONE, NULL,
                0x0, "An HDLC Address as specified in ISO 3309.", HFILL }},
        { &hf_lcp_opt_operation,
            { "Operation", "lcp.opt.operation", FT_UINT8, BASE_DEC,
                VALS(callback_op_vals), 0x0, NULL, HFILL }},
        { &hf_lcp_opt_message,
            { "Message", "lcp.opt.message", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_mrru,
            { "MRRU", "lcp.opt.mrru", FT_UINT16, BASE_DEC, NULL, 0x0,
                "Maximum Receive Reconstructed Unit", HFILL }},
        { &hf_lcp_opt_ep_disc_class,
            { "Class", "lcp.opt.ep_disc_class", FT_UINT8, BASE_DEC,
                VALS(multilink_ep_disc_class_vals), 0x0, NULL, HFILL }},
        { &hf_lcp_opt_ip_address,
            { "IP Address", "lcp.opt.ip_address", FT_IPv4, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_802_1_address,
            { "IEEE 802.1 Address", "lcp.opt.802_1_address", FT_ETHER,
                BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_magic_block,
            { "PPP Magic-Number Block", "lcp.opt.magic_block", FT_BYTES,
                BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_psndn,
            { "Public Switched Network Directory Number", "lcp.opt.psndn",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_mode,
            { "Mode", "lcp.opt.mode", FT_UINT8, BASE_DEC,
                VALS(dce_id_mode_vals), 0x0, NULL, HFILL }},
        { &hf_lcp_opt_unused,
            { "Unused", "lcp.opt.unused", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_link_discrim,
            { "Link Discriminator", "lcp.opt.link_discrim", FT_UINT16,
                BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_id,
            { "Identification", "lcp.opt.id", FT_UINT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_cobs_flags,
            { "Flags", "lcp.opt.flags", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_cobs_flags_res,
            { "Reserved", "lcp.opt.flags.reserved", FT_UINT8, BASE_HEX,
                NULL, 0xFC, NULL, HFILL }},
        { &hf_lcp_opt_cobs_flags_pre,
            { "PRE", "lcp.opt.flags.pre", FT_BOOLEAN, 8,
                NULL, 0x02, "Preemption", HFILL }},
        { &hf_lcp_opt_cobs_flags_zxe,
            { "ZXE", "lcp.opt.flags.zxe", FT_BOOLEAN, 8,
                NULL, 0x01, "Zero pair/run elimination", HFILL }},
        { &hf_lcp_opt_class,
            { "Class", "lcp.opt.class", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_prefix,
            { "Prefix", "lcp.opt.prefix", FT_UINT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_code,
            { "Code", "lcp.opt.code", FT_UINT8, BASE_DEC,
                VALS(ml_hdr_fmt_code_vals), 0x0, NULL, HFILL }},
        { &hf_lcp_opt_max_susp_classes,
            { "Max suspendable classes", "lcp.opt.max_susp_classes",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_MIBenum,
            { "MIBenum", "lcp.opt.MIBenum", FT_UINT32,
                BASE_DEC | BASE_EXT_STRING, &charset_vals_ext, 0x0,
                "A unique integer value identifying a charset", HFILL }},
        { &hf_lcp_opt_language_tag,
            { "Language-Tag", "lcp.opt.language_tag", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }}
    };

    static int *ett[] = {
        &ett_lcp,
        &ett_lcp_options,
        &ett_lcp_vendor_opt,
        &ett_lcp_mru_opt,
        &ett_lcp_asyncmap_opt,
        &ett_lcp_authprot_opt,
        &ett_lcp_qualprot_opt,
        &ett_lcp_magicnumber_opt,
        &ett_lcp_linkqualmon_opt,
        &ett_lcp_pcomp_opt,
        &ett_lcp_acccomp_opt,
        &ett_lcp_fcs_alternatives_opt,
        &ett_lcp_self_desc_pad_opt,
        &ett_lcp_numbered_mode_opt,
        &ett_lcp_callback_opt,
        &ett_lcp_compound_frames_opt,
        &ett_lcp_nomdataencap_opt,
        &ett_lcp_multilink_mrru_opt,
        &ett_lcp_multilink_ssnh_opt,
        &ett_lcp_multilink_ep_disc_opt,
        &ett_lcp_magic_block,
        &ett_lcp_dce_identifier_opt,
        &ett_lcp_multilink_pp_opt,
        &ett_lcp_bacp_link_discrim_opt,
        &ett_lcp_auth_opt,
        &ett_lcp_cobs_opt,
        &ett_lcp_prefix_elision_opt,
        &ett_multilink_hdr_fmt_opt,
        &ett_lcp_internationalization_opt,
        &ett_lcp_sonet_sdh_opt
    };

    proto_lcp = proto_register_protocol("PPP Link Control Protocol", "PPP LCP", "lcp");
    lcp_handle = register_dissector("lcp", dissect_lcp, proto_lcp);
    proto_register_field_array(proto_lcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    lcp_option_table = register_dissector_table("lcp.option", "PPP LCP Options", proto_lcp, FT_UINT8, BASE_DEC);

    /* Register LCP options as their own protocols so we can get the name of the option */
    proto_lcp_option_vendor = proto_register_protocol_in_name_only("Vendor Specific", "Vendor Specific", "lcp.opt.vendor", proto_lcp, FT_BYTES);
    proto_lcp_option_mru = proto_register_protocol_in_name_only("Maximum Receive Unit", "Maximum Receive Unit", "lcp.opt.mtu_bytes", proto_lcp, FT_BYTES);
    proto_lcp_option_async_map = proto_register_protocol_in_name_only("Async Control Character Map", "Async Control Character Map", "lcp.opt.asyncmap_bytes", proto_lcp, FT_BYTES);
    proto_lcp_option_authprot = proto_register_protocol_in_name_only("Authentication Protocol", "Authentication Protocol", "lcp.opt.auth_protocol_bytes", proto_lcp, FT_BYTES);
    proto_lcp_option_qualprot = proto_register_protocol_in_name_only("Quality Protocol", "Quality Protocol", "lcp.opt.quality_protocol_bytes", proto_lcp, FT_BYTES);
    proto_lcp_option_magicnumber = proto_register_protocol_in_name_only("Magic Number", "Magic Number", "lcp.opt.magic_number_bytes", proto_lcp, FT_BYTES);
    proto_lcp_option_linkqualmon = proto_register_protocol_in_name_only("Link Quality Monitoring", "Link Quality Monitoring", "lcp.opt.linkqualmon", proto_lcp, FT_BYTES);
    proto_lcp_option_field_compress = proto_register_protocol_in_name_only("Protocol Field Compression", "Protocol Field Compression", "lcp.opt.field_compress", proto_lcp, FT_BYTES);
    proto_lcp_option_addr_field_compress = proto_register_protocol_in_name_only("Address and Control Field Compression", "Address and Control Field Compression", "lcp.opt.addr_field_compress", proto_lcp, FT_BYTES);
    proto_lcp_option_fcs_alternatives = proto_register_protocol_in_name_only("FCS Alternatives", "FCS Alternatives", "lcp.opt.fcs_alternatives_bytes", proto_lcp, FT_BYTES);
    proto_lcp_option_self_desc_pad = proto_register_protocol_in_name_only("Self Describing Pad", "Self Describing Pad", "lcp.opt.self_desc_pad", proto_lcp, FT_BYTES);
    proto_lcp_option_numbered_mode = proto_register_protocol_in_name_only("Numbered Mode", "Numbered Mode", "lcp.opt.numbered_mode", proto_lcp, FT_BYTES);
    /* TODO? CI_MULTILINK_PROC */
    proto_lcp_option_callback = proto_register_protocol_in_name_only("Callback", "Callback", "lcp.opt.callback", proto_lcp, FT_BYTES);
    /* TODO? CI_CONNECTTIME */
    proto_lcp_option_compound_frames = proto_register_protocol_in_name_only("Compound Frames (Deprecated)", "Compound Frames (Deprecated)", "lcp.opt.compound_frames", proto_lcp, FT_BYTES);
    proto_lcp_option_nomdataencap = proto_register_protocol_in_name_only("Nominal Data Encapsulation (Deprecated)", "Nominal Data Encapsulation (Deprecated)", "lcp.opt.nomdataencap", proto_lcp, FT_BYTES);
    proto_lcp_option_multilink_mrru = proto_register_protocol_in_name_only("Multilink MRRU", "Multilink MRRU", "lcp.opt.multilink_mrru", proto_lcp, FT_BYTES);
    proto_lcp_option_multilink_ssnh = proto_register_protocol_in_name_only("Multilink Short Sequence Number Header", "Multilink Short Sequence Number Header", "lcp.opt.multilink_ssnh", proto_lcp, FT_BYTES);
    proto_lcp_option_multilink_ep_disc = proto_register_protocol_in_name_only("Multilink Endpoint Discriminator", "Multilink Endpoint Discriminator", "lcp.opt.multilink_ep_disc", proto_lcp, FT_BYTES);
    /* TODO? CI_PROP_KEN: ken@funk.com: www.funk.com => www.juniper.net */
    proto_lcp_option_dce_identifier = proto_register_protocol_in_name_only("DCE Identifier", "DCE Identifier", "lcp.opt.dce_identifier", proto_lcp, FT_BYTES);
    proto_lcp_option_multilink_pp = proto_register_protocol_in_name_only("Multi Link Plus Procedure", "Multi Link Plus Procedure", "lcp.opt.multilink_pp", proto_lcp, FT_BYTES);
    proto_lcp_option_link_discrim = proto_register_protocol_in_name_only("Link Discriminator for BACP", "Link Discriminator for BACP", "lcp.opt.link_discrim_bytes", proto_lcp, FT_BYTES);
    proto_lcp_option_auth = proto_register_protocol_in_name_only("Authentication Option", "Authentication Option", "lcp.opt.auth", proto_lcp, FT_BYTES);
    proto_lcp_option_cobs = proto_register_protocol_in_name_only("Consistent Overhead Byte Stuffing (COBS)", "Consistent Overhead Byte Stuffing (COBS)", "lcp.opt.cobs", proto_lcp, FT_BYTES);
    proto_lcp_option_prefix_elision = proto_register_protocol_in_name_only("Prefix Elision", "Prefix Elision", "lcp.opt.prefix_elision", proto_lcp, FT_BYTES);
    proto_lcp_option_multilink_hdr_fmt = proto_register_protocol_in_name_only("Multilink header format", "Multilink header format", "lcp.opt.multilink_hdr_fmt", proto_lcp, FT_BYTES);
    proto_lcp_option_internationalization = proto_register_protocol_in_name_only("Internationalization", "Internationalization", "lcp.opt.internationalization", proto_lcp, FT_BYTES);
    proto_lcp_option_sonet_sdh = proto_register_protocol_in_name_only("Simple Data Link on SONET/SDH", "Simple Data Link on SONET/SDH", "lcp.opt.sonet_sdh", proto_lcp, FT_BYTES);
}

void
proto_reg_handoff_lcp(void)
{
    dissector_add_uint("ppp.protocol", PPP_LCP, lcp_handle);

    /*
     * NDISWAN on Windows translates Ethernet frames from higher-level
     * protocols into PPP frames to hand to the PPP driver, and translates
     * PPP frames from the PPP driver to hand to the higher-level protocols.
     *
     * Apparently the PPP driver, on at least some versions of Windows,
     * passes frames for internal-to-PPP protocols up through NDISWAN;
     * the protocol type field appears to be passed through unchanged
     * (unlike what's done with, for example, the protocol type field
     * for IP, which is mapped from its PPP value to its Ethernet value).
     *
     * This means that we may see, on Ethernet captures, frames for
     * protocols internal to PPP, so we register PPP_LCP with the
     * "ethertype" dissector table as well as the PPP protocol dissector
     * table.
     */
    dissector_add_uint("ethertype", PPP_LCP, lcp_handle);

    /*
     * for GSM-A / MobileL3 / GPRS SM / PCO
     */
    dissector_add_uint("sm_pco.protocol", PPP_LCP, lcp_handle);

    /* Create dissection function handles for all LCP options */
    dissector_add_uint("lcp.option", CI_VENDORSPECIFIC, create_dissector_handle( dissect_lcp_vendor_opt, proto_lcp_option_vendor ));
    dissector_add_uint("lcp.option", CI_MRU, create_dissector_handle( dissect_lcp_mru_opt, proto_lcp_option_mru ));
    dissector_add_uint("lcp.option", CI_ASYNCMAP, create_dissector_handle( dissect_lcp_async_map_opt, proto_lcp_option_async_map ));
    dissector_add_uint("lcp.option", CI_AUTHPROT, create_dissector_handle( dissect_lcp_authprot_opt, proto_lcp_option_authprot ));
    dissector_add_uint("lcp.option", CI_QUALITY, create_dissector_handle( dissect_lcp_qualprot_opt, proto_lcp_option_qualprot ));
    dissector_add_uint("lcp.option", CI_MAGICNUMBER, create_dissector_handle( dissect_lcp_magicnumber_opt, proto_lcp_option_magicnumber ));
    dissector_add_uint("lcp.option", CI_LINKQUALMON, create_dissector_handle( dissect_lcp_linkqualmon_opt, proto_lcp_option_linkqualmon ));
    dissector_add_uint("lcp.option", CI_PCOMPRESSION, create_dissector_handle( dissect_lcp_field_compress, proto_lcp_option_field_compress ));
    dissector_add_uint("lcp.option", CI_ACCOMPRESSION, create_dissector_handle( dissect_lcp_addr_field_compress, proto_lcp_option_addr_field_compress ));
    dissector_add_uint("lcp.option", CI_FCS_ALTERNATIVES, create_dissector_handle( dissect_lcp_fcs_alternatives_opt, proto_lcp_option_fcs_alternatives ));
    dissector_add_uint("lcp.option", CI_SELF_DESCRIBING_PAD, create_dissector_handle( dissect_lcp_self_describing_pad_opt, proto_lcp_option_self_desc_pad ));
    dissector_add_uint("lcp.option", CI_NUMBERED_MODE, create_dissector_handle( dissect_lcp_numbered_mode_opt, proto_lcp_option_numbered_mode ));
    /* TODO? CI_MULTILINK_PROC */
    dissector_add_uint("lcp.option", CI_CALLBACK, create_dissector_handle( dissect_lcp_callback_opt, proto_lcp_option_callback ));
    /* TODO? CI_CONNECTTIME */
    dissector_add_uint("lcp.option", CI_COMPOUND_FRAMES, create_dissector_handle( dissect_lcp_compound_frames_opt, proto_lcp_option_compound_frames ));
    dissector_add_uint("lcp.option", CI_NOMDATAENCAP, create_dissector_handle( dissect_lcp_nomdataencap_opt, proto_lcp_option_nomdataencap ));
    dissector_add_uint("lcp.option", CI_MULTILINK_MRRU, create_dissector_handle( dissect_lcp_multilink_mrru_opt, proto_lcp_option_multilink_mrru ));
    dissector_add_uint("lcp.option", CI_MULTILINK_SSNH, create_dissector_handle( dissect_lcp_multilink_ssnh_opt, proto_lcp_option_multilink_ssnh ));
    dissector_add_uint("lcp.option", CI_MULTILINK_EP_DISC, create_dissector_handle( dissect_lcp_multilink_ep_disc_opt, proto_lcp_option_multilink_ep_disc ));
    /* TODO? CI_PROP_KEN: ken@funk.com: www.funk.com => www.juniper.net */
    dissector_add_uint("lcp.option", CI_DCE_IDENTIFIER, create_dissector_handle( dissect_lcp_dce_identifier_opt, proto_lcp_option_dce_identifier ));
    dissector_add_uint("lcp.option", CI_MULTILINK_PLUS_PROC, create_dissector_handle( dissect_lcp_multilink_pp_opt, proto_lcp_option_multilink_pp ));
    dissector_add_uint("lcp.option", CI_LINK_DISC_FOR_BACP, create_dissector_handle( dissect_lcp_bacp_link_discriminator_opt, proto_lcp_option_link_discrim ));
    dissector_add_uint("lcp.option", CI_LCP_AUTHENTICATION, create_dissector_handle( dissect_lcp_auth_opt, proto_lcp_option_auth ));
    dissector_add_uint("lcp.option", CI_COBS, create_dissector_handle( dissect_lcp_cobs_opt, proto_lcp_option_cobs ));
    dissector_add_uint("lcp.option", CI_PREFIX_ELISION, create_dissector_handle( dissect_lcp_prefix_elision_opt, proto_lcp_option_prefix_elision ));
    dissector_add_uint("lcp.option", CI_MULTILINK_HDR_FMT, create_dissector_handle( dissect_lcp_multilink_hdr_fmt_opt, proto_lcp_option_multilink_hdr_fmt ));
    dissector_add_uint("lcp.option", CI_INTERNATIONALIZATION, create_dissector_handle( dissect_lcp_internationalization_opt, proto_lcp_option_internationalization ));
    dissector_add_uint("lcp.option", CI_SDL_ON_SONET_SDH, create_dissector_handle( dissect_lcp_sonet_sdh_opt, proto_lcp_option_sonet_sdh ));
}

void
proto_register_vsncp(void)
{
    static hf_register_info hf[] = {
      { &hf_vsncp_opt_type, { "Type", "vsncp.opt.type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_vsncp_opt_length, { "Length", "vsncp.opt.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_vsncp_pdn_identifier, { "PDN Identifier", "vsncp.pdn_identifier", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_vsncp_attach_type, { "Attach Type", "vsncp.attach_type", FT_UINT8, BASE_HEX, VALS(vsncp_attach_vals), 0x0, NULL, HFILL }},
      { &hf_vsncp_pdn_type, { "PDN Type", "vsncp.pdn_type", FT_UINT8, BASE_HEX, VALS(vsncp_pdntype_vals), 0x0, NULL, HFILL }},
      { &hf_vsncp_error_code, { "Error Code", "vsncp.error_code", FT_UINT8, BASE_HEX, VALS(vsncp_errorcode_vals), 0x0, NULL, HFILL }},
      { &hf_vsncp_pdn_ipv4, { "PDN IPv4", "vsncp.pdn_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_vsncp_pdn_ipv6, { "PDN IPv6", "vsncp.pdn_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_vsncp_default_router_address, { "IPv4 Default Router Address", "vsncp.default_router_address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_vsncp_access_point_name, { "Access Point Name Label", "vsncp.access_point_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_vsncp_address_allocation_cause, { "Address Allocation Cause", "vsncp.address_allocation_cause", FT_UINT8, BASE_HEX, VALS(vsncp_alloc_vals), 0x0, NULL, HFILL }},
      { &hf_vsncp_ambr_data, { "AMBR Data", "vsncp.ambr_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_vsncp_ipv6_interface_identifier, { "IPv6 interface identifier", "vsncp.ipv6_interface_identifier", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_vsncp_protocol, { "Protocol", "vsncp.protocol", FT_UINT16, BASE_HEX, VALS(vsncp_pco_vals), 0x0, NULL, HFILL }},
      { &hf_vsncp_protocol_configuration_length, { "Length", "vsncp.protocol_configuration_length", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_vsncp_protocol_configuration_data, { "Data", "vsncp.protocol_configuration_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_vsncp_code, { "Code", "vsncp.code", FT_UINT8, BASE_HEX, VALS(cp_vals), 0x0, NULL, HFILL }},
      { &hf_vsncp_identifier, { "Identifier", "vsncp.identifier", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_vsncp_length, { "Length", "vsncp.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_vsncp,
        &ett_vsncp_options,
        &ett_vsncp_pdnid_opt,
        &ett_vsncp_apname_opt,
        &ett_vsncp_pdntype_opt,
        &ett_vsncp_pdnaddress_opt,
        &ett_vsncp_pco_opt,
        &ett_vsncp_errorcode_opt,
        &ett_vsncp_attachtype_opt,
        &ett_vsncp_ipv4address_opt,
        &ett_vsncp_addressalloc_opt,
        &ett_vsncp_apn_ambr_opt,
        &ett_vsncp_ipv6_hsgw_lla_iid_opt,
    };

    proto_vsncp = proto_register_protocol("Vendor Specific Control Protocol", "VSNCP", "vsncp");
    vsncp_handle = register_dissector("vsncp", dissect_vsncp, proto_vsncp);
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_vsncp, hf, array_length(hf));

    vsncp_option_table = register_dissector_table("vsncp.option", "PPP VSNCP Options", proto_vsncp, FT_UINT8, BASE_DEC);

    /* Register VSNCP options as their own protocols so we can get the name of the option */
    proto_vsncp_option_pdnid = proto_register_protocol_in_name_only("PDN Identifier", "PDN Identifier", "vsncp.opt.pdnid", proto_vsncp, FT_BYTES);
    proto_vsncp_option_apname = proto_register_protocol_in_name_only("Access Point Name", "Access Point Name", "vsncp.opt.apname", proto_vsncp, FT_BYTES);
    proto_vsncp_option_pdntype = proto_register_protocol_in_name_only("PDN Type", "PDN Type", "vsncp.opt.pdntype", proto_vsncp, FT_BYTES);
    proto_vsncp_option_pdnaddress = proto_register_protocol_in_name_only("PDN Address", "PDN Address", "vsncp.opt.pdnaddress", proto_vsncp, FT_BYTES);
    proto_vsncp_option_pco = proto_register_protocol_in_name_only("Protocol Configuration Options", "Protocol Configuration Options", "vsncp.opt.pco", proto_vsncp, FT_BYTES);
    proto_vsncp_option_errorcode = proto_register_protocol_in_name_only("Error Code", "Error Code", "vsncp.opt.errorcode", proto_vsncp, FT_BYTES);
    proto_vsncp_option_attachtype = proto_register_protocol_in_name_only("Attach Type", "Attach Type", "vsncp.opt.attachtype", proto_vsncp, FT_BYTES);
    proto_vsncp_option_ipv4address = proto_register_protocol_in_name_only("IPv4 Default Router Address", "IPv4 Default Router Address", "vsncp.opt.ipv4address", proto_vsncp, FT_BYTES);
    proto_vsncp_option_addressalloc = proto_register_protocol_in_name_only("Address Allocation Cause", "Address Allocation Cause", "vsncp.opt.addressalloc", proto_vsncp, FT_BYTES);
    proto_vsncp_option_apn_ambr = proto_register_protocol_in_name_only("APN Aggregate Maximum Bit Rate(APN-AMBR)", "APN Aggregate Maximum Bit Rate(APN-AMBR)", "vsncp.opt.apn_ambr", proto_vsncp, FT_BYTES);
    proto_vsncp_option_ipv6_hsgw_lla_iid = proto_register_protocol_in_name_only("IPv6 HSGW Link Local Address IID", "IPv6 HSGW Link Local Address IID", "vsncp.opt.ipv6_hsgw_lla_iid", proto_vsncp, FT_BYTES);
}

void
proto_reg_handoff_vsncp(void)
{
    dissector_add_uint("ppp.protocol", PPP_VSNCP, vsncp_handle);

    dissector_add_uint("vsncp.option", CI_PDN_IDENTIFIER, create_dissector_handle( dissect_vsncp_pdnid_opt, proto_vsncp_option_pdnid ));
    dissector_add_uint("vsncp.option", CI_ACCESS_POINT_NM, create_dissector_handle( dissect_vsncp_apname_opt, proto_vsncp_option_apname ));
    dissector_add_uint("vsncp.option", CI_PDN_TYPE, create_dissector_handle( dissect_vsncp_pdntype_opt, proto_vsncp_option_pdntype ));
    dissector_add_uint("vsncp.option", CI_PDN_ADDRESS, create_dissector_handle( dissect_vsncp_pdnaddress_opt, proto_vsncp_option_pdnaddress ));
    dissector_add_uint("vsncp.option", CI_PROTOCOL_CONFIG, create_dissector_handle( dissect_vsncp_pco_opt, proto_vsncp_option_pco ));
    dissector_add_uint("vsncp.option", CI_ERROR_CODE, create_dissector_handle( dissect_vsncp_errorcode_opt, proto_vsncp_option_errorcode ));
    dissector_add_uint("vsncp.option", CI_ATTACH_TYPE, create_dissector_handle( dissect_vsncp_attachtype_opt, proto_vsncp_option_attachtype ));
    dissector_add_uint("vsncp.option", CI_IPv4DEFAULT_ROUTER, create_dissector_handle( dissect_vsncp_ipv4address_opt, proto_vsncp_option_ipv4address ));
    dissector_add_uint("vsncp.option", CI_ADDRESS_ALLOC, create_dissector_handle( dissect_vsncp_addressalloc_opt, proto_vsncp_option_addressalloc ));
    dissector_add_uint("vsncp.option", CI_APN_AMBR, create_dissector_handle( dissect_vsncp_apn_ambr_opt, proto_vsncp_option_apn_ambr ));
    dissector_add_uint("vsncp.option", CI_IPv6_HSGW_LLA_IID, create_dissector_handle( dissect_vsncp_ipv6_hsgw_lla_iid_opt, proto_vsncp_option_ipv6_hsgw_lla_iid ));
}

void
proto_register_vsnp(void)
{
    static int *ett[] = {
        &ett_vsnp
    };

    static hf_register_info hf[] = {
        { &hf_vsnp_3gpp_pdnid,
            { "PDN ID", "vsnp.3gpp.pdnid", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }}
    };

    proto_vsnp = proto_register_protocol("Vendor Specific Network Protocol",
        "PPP VSNP", "vsnp");
    vsnp_handle = register_dissector("vsnp", dissect_vsnp, proto_vsnp);
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_vsnp, hf, array_length(hf));
}

void
proto_reg_handoff_vsnp(void)
{
    dissector_add_uint("ppp.protocol", PPP_VSNP, vsnp_handle);
}

void
proto_register_ipcp(void)
{
    static hf_register_info hf[] = {
        { &hf_ipcp_opt_type,
            { "Type", "ipcp.opt.type", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_length,
            { "Length", "ipcp.opt.length", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_src_address,
            { "Source IP Address", "ipcp.opt.src_address", FT_IPv4, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_dst_address,
            { "Destination IP Address", "ipcp.opt.dst_address", FT_IPv4,
                BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_compress_proto,
            { "IP Compression Protocol", "ipcp.opt.compress_proto", FT_UINT16,
                BASE_HEX, VALS(ipcp_compress_proto_vals), 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_max_cid,
            { "Max CID", "ipcp.opt.max_cid", FT_UINT16, BASE_DEC,
                NULL, 0x0, "Maximum value of a context identifier", HFILL }},
        { &hf_ipcp_opt_mrru,
            { "MRRU", "ipcp.opt.mrru", FT_UINT16, BASE_DEC,
                NULL, 0x0, "Maximum Reconstructed Reception Unit", HFILL }},
        { &hf_ipcp_opt_max_slot_id,
            { "Max Slot ID", "ipcp.opt.max_slot_id", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_comp_slot_id,
            { "Comp Slot ID", "ipcp.opt.comp_slot_id", FT_BOOLEAN, 8,
                TFS(&tfs_comp_slot_id), 0x01, NULL, HFILL }},
        { &hf_ipcp_opt_tcp_space,
            { "TCP Space", "ipcp.opt.tcp_space", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_non_tcp_space,
            { "Non TCP Space", "ipcp.opt.non_tcp_space", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_f_max_period,
            { "F Max Period", "ipcp.opt.f_max_period", FT_UINT16, BASE_DEC,
                NULL, 0x0, "Maximum interval between full headers", HFILL }},
        { &hf_ipcp_opt_f_max_time,
            { "F Max Time", "ipcp.opt.f_max_time", FT_UINT16, BASE_DEC, NULL,
                0x0, "Maximum time interval between full headers", HFILL }},
        { &hf_ipcp_opt_max_header,
            { "Max Header", "ipcp.opt.max_header", FT_UINT16, BASE_DEC, NULL,
                0x0,
                "The largest header size in octets that may be compressed",
                HFILL }},
        { &hf_ipcp_data,
            { "Data", "ipcp.data", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_ip_address,
            { "IP Address", "ipcp.opt.ip_address", FT_IPv4, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_mobilenodehomeaddr,
            { "Mobile Node's Home Address", "ipcp.opt.mobilenodehomeaddress",
                FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_pri_dns_address,
            { "Primary DNS Address", "ipcp.opt.pri_dns_address",
                FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_pri_nbns_address,
            { "Primary NBNS Address", "ipcp.opt.pri_nbns_address",
                FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_sec_dns_address,
            { "Secondary DNS Address", "ipcp.opt.sec_dns_address",
                FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_sec_nbns_address,
            { "Secondary NBNS Address", "ipcp.opt.sec_nbns_address",
                FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_rohc_type,
            { "Type", "ipcp.opt.rohc.type", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_rohc_length,
            { "Length", "ipcp.opt.rohc.length", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_rohc_profile,
            { "Profile", "ipcp.opt.rohc.profile", FT_UINT16, BASE_HEX,
                VALS(ipcp_rohc_profile_vals), 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_iphc_type,
            { "Type", "ipcp.opt.iphc.type", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_iphc_length,
            { "Length", "ipcp.opt.iphc.length", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_iphc_param,
            { "Parameter", "ipcp.opt.iphc.param", FT_UINT8, BASE_DEC,
                VALS(ipcp_iphc_parameter_vals), 0x0, NULL, HFILL }}
    };

    static int *ett[] = {
        &ett_ipcp,
        &ett_ipcp_options,
        &ett_ipcp_ipaddrs_opt,
        &ett_ipcp_compress_opt,
        &ett_ipcp_ipaddr_opt,
        &ett_ipcp_mobileipv4_opt,
        &ett_ipcp_pridns_opt,
        &ett_ipcp_secdns_opt,
        &ett_ipcp_prinbns_opt,
        &ett_ipcp_secnbns_opt,
        &ett_ipcp_iphc_rtp_compress_opt,
        &ett_ipcp_iphc_enhanced_rtp_compress_opt,
        &ett_ipcp_iphc_neghdrcomp_opt,
        &ett_ipcp_rohc_profiles_opt
    };

    proto_ipcp = proto_register_protocol("PPP IP Control Protocol", "PPP IPCP", "ipcp");
    ipcp_handle = register_dissector("ipcp", dissect_ipcp, proto_ipcp);
    proto_register_field_array(proto_ipcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    ipcp_option_table = register_dissector_table("ipcp.option", "PPP IPCP Options", proto_ipcp, FT_UINT8, BASE_DEC);
    ipcp_rohc_suboption_table = register_dissector_table("ipcp.rohc.option", "PPP IPCP ROHC Options", proto_ipcp, FT_UINT8, BASE_DEC);
    ipcp_iphc_suboption_table = register_dissector_table("ipcp.iphc.option", "PPP IPCP IPHC Options", proto_ipcp, FT_UINT8, BASE_DEC);

    /* Register IPCP options as their own protocols so we can get the name of the option */
    proto_ipcp_option_addrs = proto_register_protocol_in_name_only("IP Addresses (deprecated)", "IP Addresses (deprecated)", "ipcp.opt.addrs", proto_ipcp, FT_BYTES);
    proto_ipcp_option_compress = proto_register_protocol_in_name_only("IP Compression Protocol", "IP Compression Protocol", "ipcp.opt.compress", proto_ipcp, FT_BYTES);
    proto_ipcp_option_addr = proto_register_protocol_in_name_only("IP Address", "IP Address", "ipcp.opt.addr", proto_ipcp, FT_BYTES);
    proto_ipcp_option_mobileipv4 = proto_register_protocol_in_name_only("Mobile Node's Home IP Address", "Mobile Node's Home IP Address", "ipcp.opt.mobileipv4", proto_ipcp, FT_BYTES);
    proto_ipcp_option_pri_dns = proto_register_protocol_in_name_only("Primary DNS Server IP Address", "Primary DNS Server IP Address", "ipcp.opt.pri_dns", proto_ipcp, FT_BYTES);
    proto_ipcp_option_pri_nbns = proto_register_protocol_in_name_only("Primary NBNS Server IP Address", "Primary NBNS Server IP Address", "ipcp.opt.pri_nbns", proto_ipcp, FT_BYTES);
    proto_ipcp_option_sec_dns = proto_register_protocol_in_name_only("Secondary DNS Server IP Address", "Secondary DNS Server IP Address", "ipcp.opt.sec_dns", proto_ipcp, FT_BYTES);
    proto_ipcp_option_sec_nbns = proto_register_protocol_in_name_only("Secondary NBNS Server IP Address", "Secondary NBNS Server IP Address", "ipcp.opt.sec_nbns", proto_ipcp, FT_BYTES);

    proto_ipcp_rohc_option_profiles = proto_register_protocol_in_name_only("Profiles (RFC3241)", "Profiles (RFC3241)", "ipcp.opt.rohc.profile_bytes", proto_ipcp, FT_BYTES);

    proto_ipcp_iphc_option_rtp_compress = proto_register_protocol_in_name_only("RTP compression (RFC2508)", "RTP compression (RFC2508)", "ipcp.opt.iphc.rtp_compress", proto_ipcp, FT_BYTES);
    proto_ipcp_iphc_option_enhanced_rtp_compress = proto_register_protocol_in_name_only("Enhanced RTP compression (RFC3545)", "Enhanced RTP compression (RFC3545)", "ipcp.opt.iphc.enhanced_rtp_compress", proto_ipcp, FT_BYTES);
    proto_ipcp_iphc_option_neghdrcomp = proto_register_protocol_in_name_only("Negotiating header compression (RFC3545)", "Negotiating header compression (RFC3545)", "ipcp.opt.iphc.neghdrcomp", proto_ipcp, FT_BYTES);
}

void
proto_reg_handoff_ipcp(void)
{
    dissector_add_uint("ppp.protocol", PPP_IPCP, ipcp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_IPCP, ipcp_handle);

    /*
     * for GSM-A / MobileL3 / GPRS SM / PCO
     */
    dissector_add_uint("sm_pco.protocol", PPP_IPCP, ipcp_handle);

    dissector_add_uint("ipcp.option", CI_ADDRS, create_dissector_handle( dissect_ipcp_addrs_opt, proto_ipcp_option_addrs ));
    dissector_add_uint("ipcp.option", CI_COMPRESS_PROTO, create_dissector_handle( dissect_ipcp_compress_opt, proto_ipcp_option_compress ));
    dissector_add_uint("ipcp.option", CI_ADDR, create_dissector_handle( dissect_ipcp_addr_opt, proto_ipcp_option_addr ));
    dissector_add_uint("ipcp.option", CI_MOBILE_IPv4, create_dissector_handle( dissect_ipcp_mobileipv4_opt, proto_ipcp_option_mobileipv4 ));
    dissector_add_uint("ipcp.option", CI_PRI_DNS, create_dissector_handle( dissect_ipcp_pri_dns_opt, proto_ipcp_option_pri_dns ));
    dissector_add_uint("ipcp.option", CI_PRI_NBNS, create_dissector_handle( dissect_ipcp_pri_nbns_opt, proto_ipcp_option_pri_nbns ));
    dissector_add_uint("ipcp.option", CI_SEC_DNS, create_dissector_handle( dissect_ipcp_sec_dns_opt, proto_ipcp_option_sec_dns ));
    dissector_add_uint("ipcp.option", CI_SEC_NBNS, create_dissector_handle( dissect_ipcp_sec_nbns_opt, proto_ipcp_option_sec_nbns ));

    dissector_add_uint("ipcp.rohc.option", IPCP_ROHC_PROFILES, create_dissector_handle( dissect_ipcp_rohc_profiles_opt, proto_ipcp_rohc_option_profiles ));

    dissector_add_uint("ipcp.iphc.option", IPCP_IPHC_CRTP, create_dissector_handle( dissect_ipcp_iphc_rtp_compress, proto_ipcp_iphc_option_rtp_compress ));
    dissector_add_uint("ipcp.iphc.option", IPCP_IPHC_ECRTP, create_dissector_handle( dissect_ipcp_iphc_enhanced_rtp_compress, proto_ipcp_iphc_option_enhanced_rtp_compress ));
    dissector_add_uint("ipcp.iphc.option", IPCP_IPHC_NEGHC, create_dissector_handle( dissect_ipcp_iphc_neghdrcomp_opt, proto_ipcp_iphc_option_neghdrcomp ));
}

void
proto_register_bcp_bpdu(void)
{
    static hf_register_info hf[] = {
        { &hf_bcp_bpdu_flags,
            { "Flags", "bcp_bpdu.flags", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_bcp_bpdu_fcs_present,
            { "LAN FCS present", "bcp_bpdu.flags.fcs_present", FT_BOOLEAN, 8,
                TFS(&tfs_yes_no), BCP_FCS_PRESENT, NULL, HFILL }},
        { &hf_bcp_bpdu_zeropad,
            { "802.3 pad zero-filled", "bcp_bpdu.flags.zeropad", FT_BOOLEAN, 8,
                TFS(&tfs_yes_no), BCP_ZEROPAD, NULL, HFILL }},
        { &hf_bcp_bpdu_bcontrol,
            { "Bridge control", "bcp_bpdu.flags.bcontrol", FT_BOOLEAN, 8,
                TFS(&tfs_yes_no), BCP_IS_BCONTROL, NULL, HFILL }},
        { &hf_bcp_bpdu_pads,
            { "Pads", "bcp_bpdu.pads", FT_UINT8, BASE_DEC,
                NULL, BCP_PADS_MASK, NULL, HFILL }},
        { &hf_bcp_bpdu_mac_type,
            { "MAC Type", "bcp_bpdu.mac_type", FT_UINT8, BASE_DEC,
                VALS(bcp_bpdu_mac_type_vals), 0x0, NULL, HFILL }},
        { &hf_bcp_bpdu_pad,
            { "Pad", "bcp_bpdu.pad", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_bcp_bpdu,
        &ett_bcp_bpdu_flags,
    };

    proto_bcp_bpdu = proto_register_protocol("PPP Bridging Control Protocol Bridged PDU",
        "PPP BCP BPDU", "bcp_bpdu");
    bcp_bpdu_handle = register_dissector("bcp_bpdu", dissect_bcp_bpdu, proto_bcp_bpdu);
    proto_register_field_array(proto_bcp_bpdu, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_bcp_bpdu(void)
{
    eth_withfcs_handle    = find_dissector_add_dependency("eth_withfcs", proto_bcp_bpdu);
    eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_bcp_bpdu);

    dissector_add_uint("ppp.protocol", PPP_BCP_BPDU, bcp_bpdu_handle);
}

void
proto_register_bcp_ncp(void)
{
    static hf_register_info hf[] = {
        { &hf_bcp_ncp_opt_type,
            { "Type", "bcp_ncp.lcp.opt.type", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL } },
        { &hf_bcp_ncp_opt_length,
            { "Length", "bcp_ncp.lcp.opt.length", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL } },
        { &hf_bcp_ncp_lan_seg_no,
            { "LAN Segment Number", "bcp_ncp.lcp.lan_seg_no", FT_UINT16, BASE_DEC,
                NULL, 0xfff0, NULL, HFILL } },
        { &hf_bcp_ncp_bridge_no,
            { "Bridge Number", "bcp_ncp.lcp.bridge_no", FT_UINT16, BASE_DEC,
                NULL, 0x000f, NULL, HFILL } },
       { &hf_bcp_ncp_tinygram_comp,
            { "Tinygram-Compression", "bcp_ncp.lcp.tinygram_comp", FT_BOOLEAN, BASE_NONE,
                TFS(&tfs_enabled_disabled), 0x0, NULL, HFILL } },
       { &hf_bcp_ncp_mac,
            { "MAC Address", "bcp_ncp.lcp.mac_address", FT_ETHER, BASE_NONE,
                NULL, 0x0, NULL, HFILL } },
       { &hf_bcp_ncp_mac_l,
            { "L bit", "bcp_ncp.lcp.mac_l", FT_UINT48, BASE_HEX,
                NULL, UINT64_C(0x0200000000), NULL, HFILL } },
       { &hf_bcp_ncp_mac_m,
           { "M bit", "bcp_ncp.lcp.mac_m", FT_UINT48, BASE_HEX,
                NULL, UINT64_C(0x0100000000), NULL, HFILL } },
       { &hf_bcp_ncp_stp_prot,
           { "Protocol", "bcp_ncp.lcp.stp_protocol", FT_UINT8, BASE_DEC,
                VALS(bcp_ncp_stp_prot_vals), 0x0, NULL, HFILL } },
       { &hf_bcp_ncp_ieee_802_tagged_frame,
           { "IEEE-802-Tagged-Frame", "bcp_ncp.ieee_802_tagged_frame", FT_BOOLEAN, BASE_NONE,
                TFS(&tfs_enabled_disabled), 0x0, NULL, HFILL } },

    };

    static int *ett[] = {
        &ett_bcp_ncp,
        &ett_bcp_ncp_options,
        &ett_bcp_ncp_ieee_802_tagged_frame_opt,
        &ett_bcp_ncp_management_inline_opt,
        &ett_bcp_ncp_bcp_ind_opt,
        &ett_bcp_ncp_bridge_id_opt,
        &ett_bcp_ncp_line_id_opt,
        &ett_bcp_ncp_mac_sup_opt,
        &ett_bcp_ncp_tinygram_comp_opt,
        &ett_bcp_ncp_lan_id_opt,
        &ett_bcp_ncp_mac_addr_opt,
        &ett_bcp_ncp_stp_opt
    };

    proto_bcp_ncp = proto_register_protocol("PPP Bridging Control Protocol Network Control Protocol", "PPP BCP NCP", "bcp_ncp");
    bcp_ncp_handle = register_dissector("bcp_ncp", dissect_bcp_ncp, proto_bcp_ncp);
    proto_register_field_array(proto_bcp_ncp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    bcp_ncp_option_table = register_dissector_table("bcp_ncp.option", "PPP BCP NCP Options", proto_bcp_ncp, FT_UINT8, BASE_DEC);

    /* Register BCP NCP options as their own protocols so we can get the name of the option */
    proto_bcp_ncp_option_bridge_id = proto_register_protocol_in_name_only("Bridge-Identification", "Bridge-Identification", "bcp_ncp.opt.bridge_id", proto_bcp_ncp, FT_BYTES);
    proto_bcp_ncp_option_line_id = proto_register_protocol_in_name_only("Line-Identification", "Line-Identification", "bcp_ncp.opt.line_id", proto_bcp_ncp, FT_BYTES);
    proto_bcp_ncp_option_mac_sup = proto_register_protocol_in_name_only("MAC-Support", "MAC-Support", "bcp_ncp.opt.mac_sup", proto_bcp_ncp, FT_BYTES);
    proto_bcp_ncp_option_tinygram_comp = proto_register_protocol_in_name_only("Tinygram-Compression", "Tinygram-Compression", "bcp_ncp.opt.tinygram_comp", proto_bcp_ncp, FT_BYTES);
    proto_bcp_ncp_option_lan_id = proto_register_protocol_in_name_only("LAN-Identification (obsoleted)", "LAN-Identification (obsoleted)", "bcp_ncp.opt.lan_id", proto_bcp_ncp, FT_BYTES);
    proto_bcp_ncp_option_mac_addr = proto_register_protocol_in_name_only("MAC-Address", "MAC-Address", "bcp_ncp.opt.mac_addr", proto_bcp_ncp, FT_BYTES);
    proto_bcp_ncp_option_stp = proto_register_protocol_in_name_only("Spanning-Tree-Protocol (old formatted)", "Spanning-Tree-Protocol (old formatted)", "bcp_ncp.opt.stp", proto_bcp_ncp, FT_BYTES);
    proto_bcp_ncp_option_ieee_802_tagged_frame = proto_register_protocol_in_name_only("IEEE 802 Tagged Frame", "IEEE 802 Tagged Frame", "bcp_ncp.opt.ieee_802_tagged_frame", proto_bcp_ncp, FT_BYTES);
    proto_bcp_ncp_option_management_inline = proto_register_protocol_in_name_only("Management Inline", "Management Inline", "bcp_ncp.opt.management_inline", proto_bcp_ncp, FT_BYTES);
    proto_bcp_ncp_option_bcp_ind = proto_register_protocol_in_name_only("Bridge Control Packet Indicator", "Bridge Control Packet Indicator", "bcp_ncp.opt.bcp_ind", proto_bcp_ncp, FT_BYTES);
}

void
proto_reg_handoff_bcp_ncp(void)
{
    dissector_add_uint("ppp.protocol", PPP_BCP_NCP, bcp_ncp_handle);

    dissector_add_uint("bcp_ncp.option", CI_BCPNCP_BRIDGE_ID, create_dissector_handle( dissect_bcp_ncp_bridge_id, proto_bcp_ncp_option_bridge_id ));
    dissector_add_uint("bcp_ncp.option", CI_BCPNCP_LINE_ID, create_dissector_handle( dissect_bcp_ncp_line_id, proto_bcp_ncp_option_line_id ));
    dissector_add_uint("bcp_ncp.option", CI_BCPNCP_MAC_SUPPORT, create_dissector_handle( dissect_bcp_ncp_mac_sup, proto_bcp_ncp_option_mac_sup ));
    dissector_add_uint("bcp_ncp.option", CI_BCPNCP_TINYGRAM_COMP, create_dissector_handle( dissect_bcp_ncp_tinygram_comp, proto_bcp_ncp_option_tinygram_comp ));
    dissector_add_uint("bcp_ncp.option", CI_BCPNCP_LAN_ID, create_dissector_handle( dissect_bcp_ncp_lan_id, proto_bcp_ncp_option_lan_id ));
    dissector_add_uint("bcp_ncp.option", CI_BCPNCP_MAC_ADDRESS, create_dissector_handle( dissect_bcp_ncp_mac_addr, proto_bcp_ncp_option_mac_addr ));
    dissector_add_uint("bcp_ncp.option", CI_BCPNCP_STP, create_dissector_handle( dissect_bcp_ncp_stp, proto_bcp_ncp_option_stp ));
    dissector_add_uint("bcp_ncp.option", CI_BCPNCP_IEEE_802_TAGGED_FRAME, create_dissector_handle( dissect_bcp_ncp_ieee_802_tagged_frame, proto_bcp_ncp_option_ieee_802_tagged_frame ));
    dissector_add_uint("bcp_ncp.option", CI_BCPNCP_MANAGEMENT_INLINE, create_dissector_handle( dissect_bcp_ncp_management_inline, proto_bcp_ncp_option_management_inline ));
    dissector_add_uint("bcp_ncp.option", CI_BCPNCP_BCP_IND, create_dissector_handle( dissect_bcp_ncp_bcp_ncp_bcp_ind, proto_bcp_ncp_option_bcp_ind ));
}

void
proto_register_osinlcp(void)
{
    static hf_register_info hf[] = {
        { &hf_osinlcp_opt_type,
        { "Type", "osinlcp.opt.type", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
        { &hf_osinlcp_opt_length,
        { "Length", "osinlcp.opt.length", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL } },
        { &hf_osinlcp_opt_alignment,
        { "Alignment", "osinlcp.opt.alignment", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL } }
    };

    static int *ett[] = {
        &ett_osinlcp,
        &ett_osinlcp_options,
        &ett_osinlcp_align_npdu_opt
    };

    proto_osinlcp = proto_register_protocol("PPP OSI Network Layer Control Protocol", "PPP OSINLCP", "osinlcp");
    osinlcp_handle = register_dissector("osinlcp", dissect_osinlcp, proto_osinlcp);
    proto_register_field_array(proto_osinlcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    osinlcp_option_table = register_dissector_table("osinlcp.option", "PPP OSINLCP Options", proto_osinlcp, FT_UINT8, BASE_DEC);

    /* Register OSINLCP options as their own protocols so we can get the name of the option */
    proto_osinlcp_option_align_npdu = proto_register_protocol_in_name_only("Align-NPDU", "Align-NPDU", "osinlcp.opt.def_pid", proto_osinlcp, FT_BYTES);
}


void
proto_reg_handoff_osinlcp(void)
{
    dissector_add_uint("ppp.protocol", PPP_OSINLCP, osinlcp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_OSINLCP, osinlcp_handle);

    dissector_add_uint("osinlcp.option", CI_OSINLCP_ALIGN_NPDU, create_dissector_handle( dissect_osinlcp_align_npdu_opt, proto_osinlcp_option_align_npdu ));
}

void
proto_register_ccp(void)
{
    static hf_register_info hf[] = {
        { &hf_ccp_opt_type,
            { "Type", "ccp.opt.type", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_length,
            { "Length", "ccp.opt.length", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_oui,
            { "OUI", "ccp.opt.oui", FT_UINT24, BASE_OUI,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_subtype,
            { "Subtype", "ccp.opt.subtype", FT_UINT8, BASE_DEC_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_history_count,
            { "History Count", "ccp.opt.history_count", FT_UINT16, BASE_DEC,
                NULL, 0x0, "The maximum number of compression histories",
                HFILL }},
        { &hf_ccp_opt_cm,
            { "Check Mode Field", "ccp.opt.cm", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_cm_reserved,
            { "Reserved", "ccp.opt.cm.reserved", FT_UINT8, BASE_DEC,
                NULL, 0xF8, NULL, HFILL }},
        { &hf_ccp_opt_cm_check_mode,
            { "Check Mode", "ccp.opt.cm.check_mode", FT_UINT8, BASE_DEC,
                VALS(stac_checkmode_vals), 0x07, NULL, HFILL }},
        { &hf_ccp_opt_supported_bits,
            { "Supported Bits", "ccp.opt.supported_bits", FT_UINT32, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_supported_bits_h,
            { "H", "ccp.opt.supported_bits.h", FT_BOOLEAN, 32,
                TFS(&ccp_mppe_h_tfs), MPPE_SUPPORTED_BITS_H, NULL, HFILL }},
        { &hf_ccp_opt_supported_bits_m,
            { "M", "ccp.opt.supported_bits.m", FT_BOOLEAN, 32,
                TFS(&ccp_mppe_m_tfs), MPPE_SUPPORTED_BITS_M, NULL, HFILL }},
        { &hf_ccp_opt_supported_bits_s,
            { "S", "ccp.opt.supported_bits.s", FT_BOOLEAN, 32,
                TFS(&ccp_mppe_s_tfs), MPPE_SUPPORTED_BITS_S, NULL, HFILL }},
        { &hf_ccp_opt_supported_bits_l,
            { "L", "ccp.opt.supported_bits.l", FT_BOOLEAN, 32,
                TFS(&ccp_mppe_l_tfs), MPPE_SUPPORTED_BITS_L, NULL, HFILL }},
        { &hf_ccp_opt_supported_bits_d,
            { "D", "ccp.opt.supported_bits.d", FT_BOOLEAN, 32,
                TFS(&ccp_mppe_d_tfs), MPPE_SUPPORTED_BITS_D, NULL, HFILL }},
        { &hf_ccp_opt_supported_bits_c,
            { "C", "ccp.opt.supported_bits.c", FT_BOOLEAN, 32,
                TFS(&ccp_mppe_c_tfs), MPPC_SUPPORTED_BITS_C, NULL, HFILL }},
        { &hf_ccp_opt_history,
            { "History", "ccp.opt.history", FT_UINT8, BASE_DEC, NULL, 0x0,
                "Maximum size of the compression history in powers of 2",
                HFILL }},
        { &hf_ccp_opt_version,
            { "Version", "ccp.opt.version", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_vd,
            { "Vers/Dict", "ccp.opt.vd", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_vd_vers,
            { "Vers", "ccp.opt.vd.vers", FT_UINT8, BASE_DEC,
                NULL, 0xE0, NULL, HFILL }},
        { &hf_ccp_opt_vd_dict,
            { "Dict", "ccp.opt.vd.dict", FT_UINT8, BASE_DEC, NULL,
                0x1F, "The size in bits of the largest code used", HFILL }},
        { &hf_ccp_opt_check_mode,
            { "Check Mode", "ccp.opt.check_mode", FT_UINT8, BASE_DEC,
                VALS(lzsdcp_checkmode_vals), 0x0, NULL, HFILL }},
        { &hf_ccp_opt_process_mode,
            { "Process Mode", "ccp.opt.process_mode", FT_UINT8, BASE_DEC,
                VALS(lzsdcp_processmode_vals), 0x0, NULL, HFILL }},
        { &hf_ccp_opt_fe,
            { "Features", "ccp.opt.fe", FT_UINT8, BASE_DEC,
                NULL, 0xC0, NULL, HFILL }},
        { &hf_ccp_opt_p,
            { "Packet by Packet flag", "ccp.opt.p", FT_BOOLEAN, 8,
                TFS(&tfs_enabled_disabled), 0x20, NULL, HFILL }},
        { &hf_ccp_opt_History,
            { "History", "ccp.opt.History", FT_UINT8, BASE_DEC,
                NULL, 0x1F, NULL, HFILL }},
        { &hf_ccp_opt_contexts,
            { "# Contexts", "ccp.opt.contexts", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_mode,
            { "Mode", "ccp.opt.mode", FT_UINT8, BASE_DEC,
                VALS(dce_mode_vals), 0x0, NULL, HFILL }},
        { &hf_ccp_opt_window,
            { "Window", "ccp.opt.window", FT_UINT8, BASE_DEC,
                NULL, 0xF0, NULL, HFILL }},
        { &hf_ccp_opt_method,
            { "Method", "ccp.opt.method", FT_UINT8, BASE_DEC,
                VALS(deflate_method_vals), 0x0F, NULL, HFILL }},
        { &hf_ccp_opt_mbz,
            { "MBZ", "ccp.opt.mbz", FT_UINT8, BASE_DEC,
                NULL, 0xFC, NULL, HFILL }},
        { &hf_ccp_opt_chk,
            { "Chk", "ccp.opt.chk", FT_UINT8, BASE_DEC,
                VALS(deflate_chk_vals), 0x03, NULL, HFILL }},
        { &hf_ccp_opt_mode_dictcount,
            { "Mode/Dictionary Count", "ccp.opt.mode_dictcount", FT_UINT16,
                BASE_DEC | BASE_RANGE_STRING, RVALS(v44lzjh_mode_dict_rvals),
                0x0, NULL, HFILL }},
        { &hf_ccp_opt_dict_size,
            { "Dictionary Size", "ccp.opt.dict_size", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_history_length,
            { "History Length", "ccp.opt.history_length", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_data,
            { "Data", "ccp.opt.data", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
    };
    static int *ett[] = {
        &ett_ccp,
        &ett_ccp_options,
        &ett_ccp_oui_opt,
        &ett_ccp_predict1_opt,
        &ett_ccp_predict2_opt,
        &ett_ccp_puddle_opt,
        &ett_ccp_hpppc_opt,
        &ett_ccp_stac_opt,
        &ett_ccp_stac_opt_check_mode,
        &ett_ccp_mppe_opt,
        &ett_ccp_mppe_opt_supp_bits,
        &ett_ccp_gfza_opt,
        &ett_ccp_v42bis_opt,
        &ett_ccp_bsdcomp_opt,
        &ett_ccp_lzsdcp_opt,
        &ett_ccp_mvrca_opt,
        &ett_ccp_dce_opt,
        &ett_ccp_deflate_opt,
        &ett_ccp_v44lzjh_opt
    };

    proto_ccp = proto_register_protocol("PPP Compression Control Protocol", "PPP CCP", "ccp");
    ccp_handle = register_dissector("ccp", dissect_ccp, proto_ccp);
    proto_register_field_array(proto_ccp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    ccp_option_table = register_dissector_table("ccp.option", "PPP CCP Options", proto_ccp, FT_UINT8, BASE_DEC);

    /* Register CCP options as their own protocols so we can get the name of the option */
    proto_ccp_option_oui = proto_register_protocol_in_name_only("OUI", "OUI", "ccp.opt_oui", proto_ccp, FT_BYTES);
    proto_ccp_option_predict1 = proto_register_protocol_in_name_only("Predictor type 1", "Predictor type 1", "ccp.opt.predict1", proto_ccp, FT_BYTES);
    proto_ccp_option_predict2 = proto_register_protocol_in_name_only("Predictor type 2", "Predictor type 2", "ccp.opt.predict2", proto_ccp, FT_BYTES);
    proto_ccp_option_puddle = proto_register_protocol_in_name_only("Puddle Jumper", "Puddle Jumper", "ccp.opt.puddle", proto_ccp, FT_BYTES);
    proto_ccp_option_hpppc = proto_register_protocol_in_name_only("Hewlett-Packard PPC", "Hewlett-Packard PPC", "ccp.opt.hpppc", proto_ccp, FT_BYTES);
    proto_ccp_option_stac = proto_register_protocol_in_name_only("Stac Electronics LZS", "Stac Electronics LZS", "ccp.opt.stac", proto_ccp, FT_BYTES);
    proto_ccp_option_stac_ascend = proto_register_protocol_in_name_only("Stac Electronics LZS (Ascend Proprietary version)", "Stac Electronics LZS (Ascend Proprietary version)", "ccp.opt.stac_ascend", proto_ccp, FT_BYTES);
    proto_ccp_option_mppe = proto_register_protocol_in_name_only("Microsoft PPE/PPC", "Microsoft PPE/PPC", "ccp.opt.mppe", proto_ccp, FT_BYTES);
    proto_ccp_option_gfza = proto_register_protocol_in_name_only("Gandalf FZA", "Gandalf FZA", "ccp.opt.gfza", proto_ccp, FT_BYTES);
    proto_ccp_option_v42bis = proto_register_protocol_in_name_only("V.42bis compression", "V.42bis compression", "ccp.opt.v42bis", proto_ccp, FT_BYTES);
    proto_ccp_option_bsdcomp = proto_register_protocol_in_name_only("BSD LZW Compress", "BSD LZW Compress", "ccp.opt.bsdcomp", proto_ccp, FT_BYTES);
    proto_ccp_option_lzsdcp = proto_register_protocol_in_name_only("LZS-DCP", "LZS-DCP", "ccp.opt.lzsdcp", proto_ccp, FT_BYTES);
    proto_ccp_option_mvrca = proto_register_protocol_in_name_only("MVRCA (Magnalink)", "MVRCA (Magnalink)", "ccp.opt.mvrca", proto_ccp, FT_BYTES);
    proto_ccp_option_dce = proto_register_protocol_in_name_only("PPP for Data Compression in Data Circuit-Terminating Equipment (DCE)", "PPP for Data Compression in Data Circuit-Terminating Equipment (DCE)", "ccp.opt.dce", proto_ccp, FT_BYTES);
    proto_ccp_option_deflate = proto_register_protocol_in_name_only("Deflate", "Deflate", "ccp.opt.deflate", proto_ccp, FT_BYTES);
    proto_ccp_option_v44lzjh = proto_register_protocol_in_name_only("V.44/LZJH compression", "V.44/LZJH compression", "ccp.opt.v44lzjh", proto_ccp, FT_BYTES);
}

void
proto_reg_handoff_ccp(void)
{
    dissector_add_uint("ppp.protocol", PPP_CCP, ccp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_CCP, ccp_handle);

    dissector_add_uint("ccp.option", CI_CCP_OUI, create_dissector_handle( dissect_ccp_oui_opt, proto_ccp_option_oui ));
    dissector_add_uint("ccp.option", CI_CCP_PREDICT1, create_dissector_handle( dissect_ccp_predict1_opt, proto_ccp_option_predict1 ));
    dissector_add_uint("ccp.option", CI_CCP_PREDICT2, create_dissector_handle( dissect_ccp_predict2_opt, proto_ccp_option_predict2 ));
    dissector_add_uint("ccp.option", CI_CCP_PUDDLE, create_dissector_handle( dissect_ccp_puddle_opt, proto_ccp_option_puddle ));
    dissector_add_uint("ccp.option", CI_CCP_HPPPC, create_dissector_handle( dissect_ccp_hpppc_opt, proto_ccp_option_hpppc ));
    dissector_add_uint("ccp.option", CI_CCP_STAC, create_dissector_handle( dissect_ccp_stac_opt, proto_ccp_option_stac ));
    dissector_add_uint("ccp.option", CI_CCP_MPPE, create_dissector_handle( dissect_ccp_mppe_opt, proto_ccp_option_mppe ));
    dissector_add_uint("ccp.option", CI_CCP_GFZA, create_dissector_handle( dissect_ccp_gfza_opt, proto_ccp_option_gfza ));
    dissector_add_uint("ccp.option", CI_CCP_V42BIS, create_dissector_handle( dissect_ccp_v42bis_opt, proto_ccp_option_v42bis ));
    dissector_add_uint("ccp.option", CI_CCP_BSDLZW, create_dissector_handle( dissect_ccp_bsdcomp_opt, proto_ccp_option_bsdcomp ));
    dissector_add_uint("ccp.option", CI_CCP_LZSDCP, create_dissector_handle( dissect_ccp_lzsdcp_opt, proto_ccp_option_lzsdcp ));
    dissector_add_uint("ccp.option", CI_CCP_MVRCA, create_dissector_handle( dissect_ccp_mvrca_opt, proto_ccp_option_mvrca ));
    dissector_add_uint("ccp.option", CI_CCP_DCE, create_dissector_handle( dissect_ccp_dce_opt, proto_ccp_option_dce ));
    dissector_add_uint("ccp.option", CI_CCP_DEFLATE, create_dissector_handle( dissect_ccp_deflate_opt, proto_ccp_option_deflate ));
    dissector_add_uint("ccp.option", CI_CCP_V44LZJH, create_dissector_handle( dissect_ccp_v44lzjh_opt, proto_ccp_option_v44lzjh ));
}

void
proto_register_cbcp(void)
{
    static hf_register_info hf[] = {
      { &hf_cbcp_opt_type, { "Type", "cbcp.opt.type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cbcp_opt_length, { "Length", "cbcp.opt.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_cbcp_callback_delay, { "Callback delay", "cbcp.callback_delay", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cbcp_address_type, { "Address Type", "cbcp.address_type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cbcp_address, { "Address", "cbcp.address", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cbcp_no_callback, { "No callback", "cbcp.no_callback", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_cbcp,
        &ett_cbcp_options,
        &ett_cbcp_callback_opt,
        &ett_cbcp_callback_opt_addr,
        &ett_cbcp_no_callback,
        &ett_cbcp_callback_user,
        &ett_cbcp_callback_admin,
        &ett_cbcp_callback_list,
    };

    static ei_register_info ei[] = {
        { &ei_cbcp_address, { "cbcp.address.malformed", PI_MALFORMED, PI_ERROR, "Address runs past end of option", EXPFILL }},
    };

    expert_module_t* expert_cbcp;

    proto_cbcp = proto_register_protocol("PPP Callback Control Protocol", "PPP CBCP", "cbcp");
    cbcp_handle = register_dissector("cbcp", dissect_cbcp, proto_cbcp);
    proto_register_field_array(proto_cbcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_cbcp = expert_register_protocol(proto_cbcp);
    expert_register_field_array(expert_cbcp, ei, array_length(ei));

    cbcp_option_table = register_dissector_table("cbcp.option", "PPP CBCP Options", proto_cbcp, FT_UINT8, BASE_DEC);

    /* Register CBCP options as their own protocols so we can get the name of the option */
    proto_cbcp_option_no_callback = proto_register_protocol_in_name_only("No callback", "No callback", "cbcp.opt.no_callback", proto_cbcp, FT_BYTES);
    proto_cbcp_option_callback_user = proto_register_protocol_in_name_only("Callback to a user-specified number", "Callback to a user-specified number", "cbcp.opt.callback_user", proto_cbcp, FT_BYTES);
    proto_cbcp_option_callback_admin = proto_register_protocol_in_name_only("Callback to a pre-specified or admin-specified number", "Callback to a pre-specified or admin-specified number", "cbcp.opt.callback_admin", proto_cbcp, FT_BYTES);
    proto_cbcp_option_callback_list = proto_register_protocol_in_name_only("Callback to any of a list of numbers", "Callback to any of a list of numbers", "cbcp.opt.callback_list", proto_cbcp, FT_BYTES);
}

void
proto_reg_handoff_cbcp(void)
{
    dissector_add_uint("ppp.protocol", PPP_CBCP, cbcp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_CBCP, cbcp_handle);

    dissector_add_uint("cbcp.option", CI_CBCP_NO_CALLBACK, create_dissector_handle( dissect_cbcp_no_callback_opt, proto_cbcp_option_no_callback ));
    dissector_add_uint("cbcp.option", CI_CBCP_CB_USER, create_dissector_handle( dissect_cbcp_callback_user_opt, proto_cbcp_option_callback_user ));
    dissector_add_uint("cbcp.option", CI_CBCP_CB_PRE, create_dissector_handle( dissect_cbcp_callback_admin_opt, proto_cbcp_option_callback_admin ));
    dissector_add_uint("cbcp.option", CI_CBCP_CB_ANY, create_dissector_handle( dissect_cbcp_callback_list_opt, proto_cbcp_option_callback_list ));
}

void
proto_register_bacp(void)
{
    static hf_register_info hf[] = {
      { &hf_bacp_opt_type, { "Type", "bacp.opt.type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bacp_opt_length, { "Length", "bacp.opt.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_bacp_magic_number, { "Magic number", "bacp.magic_number", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_bacp_link_speed, { "Link Speed", "bacp.link_speed", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_kbps), 0x0, NULL, HFILL }},
      { &hf_bacp_link_type, { "Link Type", "bacp.link_type", FT_UINT8, BASE_DEC, VALS(bap_link_type_vals), 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_bacp,
        &ett_bacp_options,
        &ett_bacp_favored_peer_opt
    };

    proto_bacp = proto_register_protocol("PPP Bandwidth Allocation Control Protocol", "PPP BACP", "bacp");
    bacp_handle = register_dissector("bacp", dissect_bacp, proto_bacp);
    proto_register_field_array(proto_bacp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    bacp_option_table = register_dissector_table("bacp.option", "PPP BACP Options", proto_bacp, FT_UINT8, BASE_DEC);

    /* Register BACP options as their own protocols so we can get the name of the option */
    proto_bacp_option_favored_peer = proto_register_protocol_in_name_only("Favored-Peer", "Favored-Peer", "bacp.opt.favored_peer", proto_bacp, FT_BYTES);
}

void
proto_reg_handoff_bacp(void)
{
    dissector_add_uint("ppp.protocol", PPP_BACP, bacp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_BACP, bacp_handle);

    dissector_add_uint("bacp.option", CI_BACP_FAVORED_PEER, create_dissector_handle( dissect_bacp_favored_peer_opt, proto_bacp_option_favored_peer ));
}

void
proto_register_bap(void)
{
    static hf_register_info hf[] = {
      { &hf_bap_opt_type, { "Type", "bap.opt.type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bap_opt_length, { "Length", "bap.opt.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_bap_sub_option_type, { "Sub-Option Type", "bap.sub_option_type", FT_UINT8, BASE_DEC, VALS(bap_phone_delta_subopt_vals), 0x0, NULL, HFILL }},
      { &hf_bap_sub_option_length, { "Sub-Option Length", "bap.sub_option_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bap_unique_digit, { "Unique Digit", "bap.unique_digit", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bap_subscriber_number, { "Subscriber Number", "bap.subscriber_number", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bap_phone_number_sub_address, { "Phone Number Sub Address", "bap.phone_number_sub_address", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bap_unknown_option_data, { "Unknown", "bap.unknown_option_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bap_reason, { "Reason", "bap.reason", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bap_link_discriminator, { "Link Discriminator", "bap.link_discriminator", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_bap_call_status, { "Status", "bap.call_status", FT_UINT8, BASE_HEX|BASE_EXT_STRING, &q931_cause_code_vals_ext, 0x0, NULL, HFILL }},
      { &hf_bap_call_action, { "Action", "bap.call_action", FT_UINT8, BASE_HEX, VALS(bap_call_status_opt_action_vals), 0x0, NULL, HFILL }},
      { &hf_bap_type, { "Type", "bap.type", FT_UINT8, BASE_HEX, VALS(bap_vals), 0x0, NULL, HFILL }},
      { &hf_bap_identifier, { "Identifier", "bap.identifier", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_bap_length, { "Length", "bap.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bap_response_code, { "Response Code", "bap.response_code", FT_UINT8, BASE_HEX, VALS(bap_resp_code_vals), 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_bap,
        &ett_bap_options,
        &ett_bap_link_type_opt,
        &ett_bap_phone_delta_opt,
        &ett_bap_phone_delta_subopt,
        &ett_bap_call_status_opt,
        &ett_bap_no_phone_opt,
        &ett_bap_reason_opt,
        &ett_bap_link_disc_opt,
    };

    static ei_register_info ei[] = {
        { &ei_bap_sub_option_length, { "bap.sub_option_length.invalid", PI_PROTOCOL, PI_WARN, "Invalid length", EXPFILL }},
    };

    expert_module_t* expert_bap;

    proto_bap = proto_register_protocol("PPP Bandwidth Allocation Protocol", "PPP BAP", "bap");
    bap_handle = register_dissector("bap", dissect_bap, proto_bap);
    proto_register_field_array(proto_bap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_bap = expert_register_protocol(proto_bap);
    expert_register_field_array(expert_bap, ei, array_length(ei));

    bap_option_table = register_dissector_table("bap.option", "PPP BAP Options", proto_bap, FT_UINT8, BASE_DEC);

    /* Register BAP options as their own protocols so we can get the name of the option */
    proto_bap_option_link_type = proto_register_protocol_in_name_only("Link Type", "Link Type", "bap.opt.link_type", proto_bap, FT_BYTES);
    proto_bap_option_phone_delta = proto_register_protocol_in_name_only("Phone Delta", "Phone Delta", "bap.opt.phone_delta", proto_bap, FT_BYTES);
    proto_bap_option_no_phone = proto_register_protocol_in_name_only("No Phone Number Needed", "No Phone Number Needed", "bap.opt.no_phone", proto_bap, FT_BYTES);
    proto_bap_option_reason = proto_register_protocol_in_name_only("Reason", "Reason", "bap.opt.reason", proto_bap, FT_BYTES);
    proto_bap_option_link_disc = proto_register_protocol_in_name_only("Link Discriminator", "Link Discriminator", "bap.opt.link_disc", proto_bap, FT_BYTES);
    proto_bap_option_call_status = proto_register_protocol_in_name_only("Call Status", "Call Status", "bap.opt.call_status", proto_bap, FT_BYTES);
}

void
proto_reg_handoff_bap(void)
{
    dissector_add_uint("ppp.protocol", PPP_BAP, bap_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_BAP, bap_handle);

    dissector_add_uint("bap.option", CI_BAP_LINK_TYPE, create_dissector_handle( dissect_bap_link_type_opt, proto_bap_option_link_type ));
    dissector_add_uint("bap.option", CI_BAP_PHONE_DELTA, create_dissector_handle( dissect_bap_phone_delta_opt, proto_bap_option_phone_delta ));
    dissector_add_uint("bap.option", CI_BAP_NO_PHONE_NUM_NEEDED, create_dissector_handle( dissect_bap_no_phone_opt, proto_bap_option_no_phone ));
    dissector_add_uint("bap.option", CI_BAP_REASON, create_dissector_handle( dissect_bap_reason_opt, proto_bap_option_reason ));
    dissector_add_uint("bap.option", CI_BAP_LINK_DISC, create_dissector_handle( dissect_bap_link_disc_opt, proto_bap_option_link_disc ));
    dissector_add_uint("bap.option", CI_BAP_CALL_STATUS, create_dissector_handle( dissect_bap_call_status_opt, proto_bap_option_call_status ));
}

void
proto_register_comp_data(void)
{
#if 0 /* See dissect_comp_data() */
    static int *ett[] = {
        &ett_comp_data
    };
#endif

    proto_comp_data = proto_register_protocol("PPP Compressed Datagram",
        "PPP Comp", "comp_data");
    comp_data_handle = register_dissector("ppp_comp", dissect_comp_data,
        proto_comp_data);
#if 0
    proto_register_subtree_array(ett, array_length(ett));
#endif
}

void
proto_reg_handoff_comp_data(void)
{
    dissector_add_uint("ppp.protocol", PPP_COMP, comp_data_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_COMP, comp_data_handle);
}

void
proto_register_pap(void)
{
    static int *ett[] = {
        &ett_pap,
        &ett_pap_data
    };

    static hf_register_info hf[] = {
        { &hf_pap_code,
            { "Code", "pap.code", FT_UINT8, BASE_DEC, VALS(pap_vals), 0x0,
                "The Code field is one octet and identifies the type of PAP "
                "packet", HFILL }},
        { &hf_pap_identifier,
            { "Identifier", "pap.identifier", FT_UINT8, BASE_DEC, NULL, 0x0,
                "The Identifier field is one octet and aids in matching "
                "requests and replies.", HFILL }},
        { &hf_pap_length,
            { "Length", "pap.length", FT_UINT16, BASE_DEC, NULL, 0x0,
                "The Length field is two octets and indicates the length of "
                "the PAP packet", HFILL }},
        { &hf_pap_data,
            { "Data", "pap.data", FT_NONE, BASE_NONE, NULL, 0x0,
                "The format of the Data field is determined by the Code field",
                HFILL }},
        { &hf_pap_peer_id_length,
            { "Peer-ID-Length", "pap.peer_id.length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "The Peer-ID-Length field is one octet and indicates the "
                "length of the Peer-ID field", HFILL }},
        { &hf_pap_peer_id,
            { "Peer-ID", "pap.peer_id", FT_STRING, BASE_NONE, NULL, 0x0,
                "The Peer-ID field is zero or more octets and indicates the "
                "name of the peer to be authenticated", HFILL }},
        { &hf_pap_password_length,
            { "Password-Length", "pap.password.length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "The Password-Length field is one octet and indicates the "
                "length of the Password field", HFILL }},
        { &hf_pap_password,
            { "Password", "pap.password", FT_STRING, BASE_NONE, NULL, 0x0,
                "The Password field is zero or more octets and indicates the "
                "password to be used for authentication", HFILL }},
        { &hf_pap_message_length,
            { "Message-Length", "pap.message.length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "The Message-Length field is one octet and indicates the "
                "length of the Message field", HFILL }},
        { &hf_pap_message,
            { "Message", "pap.message", FT_STRING, BASE_NONE, NULL, 0x0,
                "The Message field is zero or more octets, and its contents "
                "are implementation dependent.", HFILL }},
        { &hf_pap_stuff,
            { "stuff", "pap.stuff", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }}
    };

    proto_pap = proto_register_protocol("PPP Password Authentication Protocol",
        "PPP PAP", "pap");
    pap_handle = register_dissector("pap", dissect_pap, proto_pap);
    proto_register_field_array(proto_pap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pap(void)
{
    dissector_add_uint("ppp.protocol", PPP_PAP, pap_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_PAP, pap_handle);

    /*
     * for GSM-A / MobileL3 / GPRS SM / PCO
     */
    dissector_add_uint("sm_pco.protocol", PPP_PAP, pap_handle);
}

void
proto_register_chap(void)
{
    static int *ett[] = {
        &ett_chap,
        &ett_chap_data
    };

    static hf_register_info hf[] = {
        { &hf_chap_code,
            { "Code", "chap.code", FT_UINT8, BASE_DEC, VALS(chap_vals), 0x0,
                "CHAP code", HFILL }},
        { &hf_chap_identifier,
            { "Identifier", "chap.identifier", FT_UINT8, BASE_DEC, NULL, 0x0,
                "CHAP identifier", HFILL }},
        { &hf_chap_length,
            { "Length", "chap.length", FT_UINT16, BASE_DEC, NULL, 0x0,
                "CHAP length", HFILL  }},
        { &hf_chap_data,
            { "Data", "chap.data", FT_NONE, BASE_NONE, NULL, 0x0,
                "CHAP Data", HFILL }},
         { &hf_chap_value_size,
            { "Value Size", "chap.value_size", FT_UINT8, BASE_DEC, NULL, 0x0,
                "CHAP value size", HFILL }},
        { &hf_chap_value,
            { "Value", "chap.value", FT_BYTES, BASE_NONE, NULL, 0x0,
                "CHAP value data", HFILL }},
        { &hf_chap_name,
            { "Name", "chap.name", FT_STRING, BASE_NONE, NULL, 0x0,
                "CHAP name", HFILL }},
        { &hf_chap_message,
            { "Message", "chap.message", FT_STRING, BASE_NONE, NULL, 0x0,
                "CHAP message", HFILL }},
        { &hf_chap_stuff,
            { "Stuff", "chap.stuff", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        };

    proto_chap = proto_register_protocol("PPP Challenge Handshake Authentication Protocol", "PPP CHAP", "chap");
    chap_handle = register_dissector("chap", dissect_chap,
        proto_chap);
    proto_register_field_array(proto_chap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_chap(void)
{
    dissector_add_uint("ppp.protocol", PPP_CHAP, chap_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_CHAP, chap_handle);

    /*
     * for GSM-A / MobileL3 / GPRS SM / PCO
     */
    dissector_add_uint("sm_pco.protocol", PPP_CHAP, chap_handle);
}

void
proto_register_pppmuxcp(void)
{
    static hf_register_info hf[] = {
        { &hf_pppmux_flags_pid,
            { "PID", "pppmuxcp.flags.pid", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x80,
                NULL, HFILL }},
        { &hf_pppmux_flags_field_length,
            { "Length field", "pppmuxcp.flags.field_length", FT_BOOLEAN, 8, TFS(&tfs_pppmux_length_field), 0x40,
                NULL, HFILL }},
        { &hf_pppmuxcp_opt_type,
            { "Type", "pppmuxcp.opt.type", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
        { &hf_pppmuxcp_opt_length,
            { "Length", "pppmuxcp.opt.length", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        /* Generated from convert_proto_tree_add_text.pl */
        { &hf_pppmux_flags, { "PFF/LXT", "pppmuxcp.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_pppmux_sub_frame_length, { "Sub-frame Length", "pppmuxcp.sub_frame_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_pppmux_def_prot_id, { "Default Protocol ID", "pppmuxcp.def_prot_id", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &ppp_vals_ext, 0x0, NULL, HFILL }},
        };

    static int *ett[] = {
        &ett_pppmuxcp,
        &ett_pppmuxcp_options,
        &ett_pppmuxcp_def_pid_opt
    };

    proto_pppmuxcp = proto_register_protocol("PPPMux Control Protocol", "PPP PPPMuxCP", "pppmuxcp");
    muxcp_handle = register_dissector("pppmuxcp", dissect_pppmuxcp, proto_pppmuxcp);
    proto_register_field_array(proto_pppmuxcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    pppmuxcp_option_table = register_dissector_table("pppmuxcp.option", "PPP PPPMuxCP Options", proto_pppmuxcp, FT_UINT8, BASE_DEC);

    /* Register PPPMuxCP options as their own protocols so we can get the name of the option */
    proto_pppmuxcp_option_def_pid = proto_register_protocol_in_name_only("Default Protocol ID", "Default Protocol ID", "pppmuxcp.opt.def_pid", proto_pppmuxcp, FT_BYTES);
}


void
proto_reg_handoff_pppmuxcp(void)
{
    dissector_add_uint("ppp.protocol", PPP_MUXCP, muxcp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_MUXCP, muxcp_handle);

    dissector_add_uint("pppmuxcp.option", CI_DEFAULT_PID, create_dissector_handle( dissect_pppmuxcp_def_pid_opt, proto_pppmuxcp_option_def_pid ));
}


void
proto_register_pppmux(void)
{
    static hf_register_info hf[] = {
        { &hf_pppmux_protocol,
            { "Protocol", "pppmux.protocol", FT_UINT16,
                BASE_HEX|BASE_EXT_STRING, &ppp_vals_ext, 0x0,
                "The protocol of the sub-frame.", HFILL }}
    };

    static int *ett[] = {
        &ett_pppmux,
        &ett_pppmux_subframe,
        &ett_pppmux_subframe_hdr,
        &ett_pppmux_subframe_flags,
        &ett_pppmux_subframe_info
    };

    proto_pppmux = proto_register_protocol("PPP Multiplexing", "PPP PPPMux",
        "pppmux");
    pppmux_handle = register_dissector("pppmux", dissect_pppmux, proto_pppmux);
    proto_register_field_array(proto_pppmux, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pppmux(void)
{
    dissector_add_uint("ppp.protocol", PPP_MUX, pppmux_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_MUX, pppmux_handle);
}

void
proto_register_mplscp(void)
{
    static int *ett[] = {
        &ett_mplscp,
        &ett_mplscp_options
    };

    proto_mplscp = proto_register_protocol("PPP MPLS Control Protocol",
        "PPP MPLSCP", "mplscp");
    mplscp_handle = register_dissector("mplscp", dissect_mplscp, proto_mplscp);
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mplscp(void)
{
    dissector_add_uint("ppp.protocol", PPP_MPLSCP, mplscp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_MPLSCP, mplscp_handle);
}

void
proto_register_cdpcp(void)
{
    static int *ett[] = {
        &ett_cdpcp,
        &ett_cdpcp_options
    };

    proto_cdpcp = proto_register_protocol("PPP CDP Control Protocol",
        "PPP CDPCP", "cdpcp");
    cdpcp_handle = register_dissector("cdpcp", dissect_cdpcp, proto_cdpcp);
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_cdpcp(void)
{
    dissector_add_uint("ppp.protocol", PPP_CDPCP, cdpcp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_CDPCP, cdpcp_handle);
}

void
proto_register_ipv6cp(void)
{
    static hf_register_info hf[] = {
      { &hf_ipv6cp_opt_type, { "Type", "ipv6cp.opt.type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ipv6cp_opt_length, { "Length", "ipv6cp.opt.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_ipv6cp_interface_identifier, { "Interface Identifier", "ipv6cp.interface_identifier", FT_BYTES, SEP_COLON, NULL, 0x0, NULL, HFILL }},
    };
    static int *ett[] = {
        &ett_ipv6cp,
        &ett_ipv6cp_options,
        &ett_ipv6cp_if_id_opt,
        &ett_ipv6cp_compress_opt
    };

    proto_ipv6cp = proto_register_protocol("PPP IPv6 Control Protocol", "PPP IPV6CP", "ipv6cp");
    ipv6cp_handle = register_dissector("ipv6cp", dissect_ipv6cp, proto_ipv6cp);
    proto_register_field_array(proto_ipv6cp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    ipv6cp_option_table = register_dissector_table("ipv6cp.option", "PPP IPV6CP Options", proto_ipv6cp, FT_UINT8, BASE_DEC);

    /* Register IPV6CP options as their own protocols so we can get the name of the option */
    proto_ipv6cp_option_if_id = proto_register_protocol_in_name_only("Interface Identifier", "Interface Identifier", "ipv6cp.opt.interface_identifier", proto_ipv6cp, FT_BYTES);
    proto_ipv6cp_option_compress = proto_register_protocol_in_name_only("IPv6 compression", "IPv6 compression", "ipv6cp.opt.compress", proto_ipv6cp, FT_BYTES);
}

void
proto_reg_handoff_ipv6cp(void)
{
    dissector_add_uint("ppp.protocol", PPP_IPV6CP, ipv6cp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_IPV6CP, ipv6cp_handle);

    /*
     * for GSM-A / MobileL3 / GPRS SM / PCO
     */
    dissector_add_uint("sm_pco.protocol", PPP_IPV6CP, ipv6cp_handle);

    dissector_add_uint("ipv6cp.option", CI_IPV6CP_IF_ID, create_dissector_handle( dissect_ipv6cp_if_id_opt, proto_ipv6cp_option_if_id ));
    dissector_add_uint("ipv6cp.option", CI_COMPRESS_PROTO, create_dissector_handle( dissect_ipcp_compress_opt, proto_ipv6cp_option_compress ));
}

void
proto_register_iphc_crtp(void)
{
    static hf_register_info hf[] = {
        { &hf_iphc_crtp_cid16,
            { "Context Id", "crtp.cid", FT_UINT16, BASE_DEC, NULL, 0x0,
                "The context identifier of the compressed packet.", HFILL }},
        { &hf_iphc_crtp_cid8,
            { "Context Id", "crtp.cid", FT_UINT8, BASE_DEC, NULL, 0x0,
                "The context identifier of the compressed packet.", HFILL }},
        { &hf_iphc_crtp_gen,
            { "Generation", "crtp.gen", FT_UINT8, BASE_DEC, NULL, 0x3f,
                "The generation of the compressed packet.", HFILL }},
        { &hf_iphc_crtp_seq,
            { "Sequence (Data)", "crtp.seq", FT_UINT8, BASE_DEC, NULL, 0x0f,
                "The sequence of the compressed packet.", HFILL }},
        { &hf_iphc_crtp_fh_flags,
            { "Flags", "crtp.fh_flags", FT_UINT8, BASE_HEX, NULL,
                IPHC_CRTP_FH_FLAG_MASK,
                "The flags of the full header packet.", HFILL }},
        { &hf_iphc_crtp_fh_cidlenflag,
            { "CID Length", "crtp.fh_flags.cidlen", FT_BOOLEAN, 8, TFS(&iphc_crtp_fh_cidlenflag),
                IPHC_CRTP_FH_CIDLEN_FLAG, "A flag which is not set for 8-bit Context Ids and set for 16-bit Context Ids.", HFILL }},
        { &hf_iphc_crtp_fh_dataflag,
            { "Sequence (Data)", "crtp.fh_flags.data", FT_BOOLEAN, 8,
                TFS(&tfs_present_absent), IPHC_CRTP_FH_DATA_FLAG,
                "This indicates the presence of a nonzero data field, usually meaning the low nibble is a sequence number.", HFILL }},
        { &hf_iphc_crtp_cs_flags,
            { "Flags", "crtp.cs_flags", FT_UINT8, BASE_DEC, VALS(iphc_crtp_cs_flags),
                0x0, "The flags of the context state packet.", HFILL }},
        { &hf_iphc_crtp_cs_cnt,
            { "Count", "crtp.cnt", FT_UINT8, BASE_DEC, NULL, 0x0,
                "The count of the context state packet.", HFILL }},
        { &hf_iphc_crtp_cs_invalid,
            { "Invalid", "crtp.invalid", FT_BOOLEAN, 8, NULL, 0x80,
                "The invalid bit of the context state packet.", HFILL }},
        { &hf_iphc_crtp_ip_id,
            { "IP-ID", "crtp.ip-id", FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
                "The IPv4 Identification Field is RANDOM and thus included in a compressed Non TCP packet (RFC 2507 6a, 7.13a). Only IPv4 is supported in this dissector.", HFILL }},
        { &hf_iphc_crtp_data,
            { "Data", "crtp.data", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},
        };

    static int *ett[] = {
        &ett_iphc_crtp,
        &ett_iphc_crtp_hdr,
        &ett_iphc_crtp_info,
        &ett_iphc_crtp_fh_flags
    };

    static ei_register_info ei[] = {
        { &ei_iphc_crtp_ip_version, { "crtp.ip_version_unsupported", PI_PROTOCOL, PI_WARN, "IP version is unsupported", EXPFILL }},
        { &ei_iphc_crtp_next_protocol, { "crtp.next_protocol_unsupported", PI_PROTOCOL, PI_WARN, "Next protocol is unsupported", EXPFILL }},
        { &ei_iphc_crtp_seq_nonzero, { "crtp.seq_nonzero", PI_PROTOCOL, PI_WARN, "Sequence (Data) field is nonzero despite D bit not set", EXPFILL }}
    };

    expert_module_t* expert_iphc_crtp;

    proto_iphc_crtp = proto_register_protocol("CRTP", "CRTP", "crtp");
    fh_handle = register_dissector("crtp", dissect_iphc_crtp_fh, proto_iphc_crtp);
    /* Created to remove Decode As confusion */
    proto_iphc_crtp_cudp16 = proto_register_protocol_in_name_only("CRTP (CUDP 16)", "CRTP (CUDP 16)", "crtp_cudp16", proto_iphc_crtp, FT_PROTOCOL);
    cudp16_handle = register_dissector("crtp_cudp16", dissect_iphc_crtp_cudp16, proto_iphc_crtp_cudp16);
    proto_iphc_crtp_cudp8 = proto_register_protocol_in_name_only("CRTP (CUDP 8)", "CRTP (CUDP 8)", "crtp_cudp8", proto_iphc_crtp, FT_PROTOCOL);
    cudp8_handle = register_dissector("crtp_cudp8", dissect_iphc_crtp_cudp8, proto_iphc_crtp_cudp8);
    proto_iphc_crtp_cs = proto_register_protocol_in_name_only("CRTP (CS)", "CRTP (CS)", "crtp_cs", proto_iphc_crtp, FT_PROTOCOL);
    cs_handle = register_dissector("crtp_cs", dissect_iphc_crtp_cs, proto_iphc_crtp_cs);
    proto_iphc_crtp_cntcp = proto_register_protocol_in_name_only("CRTP (CNTCP)", "CRTP (CNTCP)", "crtp_cntcp", proto_iphc_crtp, FT_PROTOCOL);
    cntcp_handle = register_dissector("crtp_cntcp", dissect_iphc_crtp_cntcp, proto_iphc_crtp_cntcp);

    proto_register_field_array(proto_iphc_crtp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_iphc_crtp = expert_register_protocol(proto_iphc_crtp);
    expert_register_field_array(expert_iphc_crtp, ei, array_length(ei));
}

void
proto_reg_handoff_iphc_crtp(void)
{
    dissector_add_uint("ppp.protocol", PPP_RTP_FH, fh_handle);
    dissector_add_uint("ppp.protocol", PPP_RTP_CUDP16, cudp16_handle);
    dissector_add_uint("ppp.protocol", PPP_RTP_CUDP8, cudp8_handle);
    dissector_add_uint("ppp.protocol", PPP_RTP_CS, cs_handle);
    dissector_add_uint("ppp.protocol", PPP_RTP_CNTCP, cntcp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_RTP_FH, fh_handle);
    dissector_add_uint("ethertype", PPP_RTP_CUDP16, cudp16_handle);
    dissector_add_uint("ethertype", PPP_RTP_CUDP8, cudp8_handle);
    dissector_add_uint("ethertype", PPP_RTP_CS, cs_handle);
    dissector_add_uint("ethertype", PPP_RTP_CNTCP, cntcp_handle);
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

/* packet-erf.c
 * Routines for ERF encapsulation dissection
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
#include <epan/prefs.h>
#include <epan/ipproto.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <wsutil/str_util.h>
#include <wiretap/wtap.h>
#include <wiretap/erf_record.h>

#include "packet-erf.h"
#include "packet-ptp.h"

/*
*/

void proto_register_erf(void);
void proto_reg_handoff_erf(void);

#define DECHAN_MAX_LINE_RATE 5
#define DECHAN_MAX_VC_SIZE 5
#define DECHAN_MAX_AUG_INDEX 4

typedef struct sdh_g707_format_s
{
  uint8_t m_sdh_line_rate;
  uint8_t m_vc_size ;
  int8_t m_vc_index_array[DECHAN_MAX_AUG_INDEX];
        /* i = 3 --> ITU-T letter #D - index of AUG-16
         * i = 2 --> ITU-T letter #C - index of AUG-4,
         * i = 1 --> ITU-T letter #B - index of AUG-1
         * i = 0 --> ITU-T letter #A - index of AU3*/
} sdh_g707_format_t;

static dissector_handle_t erf_handle;
static dissector_table_t erf_dissector_table;

/* Initialize the protocol and registered fields */
static int proto_erf;

static int hf_erf_ts;
static int hf_erf_rectype;
static int hf_erf_type;
static int hf_erf_ehdr;
static int hf_erf_ehdr_t;
static int hf_erf_flags;
static int hf_erf_flags_cap;
static int hf_erf_flags_if_raw;
static int hf_erf_flags_vlen;
static int hf_erf_flags_trunc;
static int hf_erf_flags_rxe;
static int hf_erf_flags_dse;
static int hf_erf_flags_res;

static int hf_erf_rlen;
static int hf_erf_lctr;
static int hf_erf_color;
static int hf_erf_wlen;

/* Classification extension header */

/* InterceptID extension header */
static int hf_erf_ehdr_int_res1;
static int hf_erf_ehdr_int_id;
static int hf_erf_ehdr_int_res2;

/* Raw Link extension header */
static int hf_erf_ehdr_raw_link_res;
static int hf_erf_ehdr_raw_link_seqnum;
static int hf_erf_ehdr_raw_link_rate;
static int hf_erf_ehdr_raw_link_type;

/* Classification extension header */
static int hf_erf_ehdr_class_flags;
static int hf_erf_ehdr_class_flags_sh;
static int hf_erf_ehdr_class_flags_shm;
static int hf_erf_ehdr_class_flags_res1;
static int hf_erf_ehdr_class_flags_user;
static int hf_erf_ehdr_class_flags_res2;
static int hf_erf_ehdr_class_flags_drop;
static int hf_erf_ehdr_class_flags_str;
static int hf_erf_ehdr_class_seqnum;

/* BFS extension header */
static int hf_erf_ehdr_bfs_hash;
static int hf_erf_ehdr_bfs_color;
static int hf_erf_ehdr_bfs_raw_hash;

/* Channelised extension header */
static int hf_erf_ehdr_chan_morebits;
static int hf_erf_ehdr_chan_morefrag;
static int hf_erf_ehdr_chan_seqnum;
static int hf_erf_ehdr_chan_res;
static int hf_erf_ehdr_chan_virt_container_id;
static int hf_erf_ehdr_chan_assoc_virt_container_size;
static int hf_erf_ehdr_chan_rate;
static int hf_erf_ehdr_chan_type;

/* Filter Hash extension header */
static int hf_erf_ehdr_signature_payload_hash;
static int hf_erf_ehdr_signature_color;
static int hf_erf_ehdr_signature_flow_hash;

/* Flow ID extension header */
static int hf_erf_ehdr_flow_id_source_id;
static int hf_erf_ehdr_flow_id_hash_type;
static int hf_erf_ehdr_flow_id_hash_type_type;
static int hf_erf_ehdr_flow_id_hash_type_inner;
static int hf_erf_ehdr_flow_id_stack_type;
static int hf_erf_ehdr_flow_id_flow_hash;

/* Host ID extension header */
static int hf_erf_ehdr_host_id_sourceid;
static int hf_erf_ehdr_host_id_hostid;

/* Anchor ID extension header */
static int hf_erf_ehdr_anchor_id_definition;
static int hf_erf_ehdr_anchor_id_reserved;
static int hf_erf_ehdr_anchor_id_anchorid;
static int hf_erf_ehdr_anchor_id_flags;

static int hf_erf_anchor_linked;
static int hf_erf_anchor_anchorid;
static int hf_erf_anchor_hostid;

/* Generated Host ID/Source ID */
static int hf_erf_sourceid;
static int hf_erf_hostid;
static int hf_erf_source_current;
static int hf_erf_source_next;
static int hf_erf_source_prev;

/* Entropy extension header */
static int hf_erf_ehdr_entropy_entropy;
static int hf_erf_ehdr_entropy_entropy_raw;
static int hf_erf_ehdr_entropy_reserved;

/* Unknown extension header */
static int hf_erf_ehdr_unk;

/* MC HDLC Header */
static int hf_erf_mc_hdlc;
static int hf_erf_mc_hdlc_cn;
static int hf_erf_mc_hdlc_res1;
static int hf_erf_mc_hdlc_res2;
static int hf_erf_mc_hdlc_fcse;
static int hf_erf_mc_hdlc_sre;
static int hf_erf_mc_hdlc_lre;
static int hf_erf_mc_hdlc_afe;
static int hf_erf_mc_hdlc_oe;
static int hf_erf_mc_hdlc_lbe;
static int hf_erf_mc_hdlc_first;
static int hf_erf_mc_hdlc_res3;

/* MC RAW Header */
static int hf_erf_mc_raw;
static int hf_erf_mc_raw_int;
static int hf_erf_mc_raw_res1;
static int hf_erf_mc_raw_sre;
static int hf_erf_mc_raw_lre;
static int hf_erf_mc_raw_res2;
static int hf_erf_mc_raw_lbe;
static int hf_erf_mc_raw_first;
static int hf_erf_mc_raw_res3;

/* MC ATM Header */
static int hf_erf_mc_atm;
static int hf_erf_mc_atm_cn;
static int hf_erf_mc_atm_res1;
static int hf_erf_mc_atm_mul;
static int hf_erf_mc_atm_port;
static int hf_erf_mc_atm_res2;
static int hf_erf_mc_atm_lbe;
static int hf_erf_mc_atm_hec;
static int hf_erf_mc_atm_crc10;
static int hf_erf_mc_atm_oamcell;
static int hf_erf_mc_atm_first;
static int hf_erf_mc_atm_res3;

/* MC Raw link Header */
static int hf_erf_mc_rawl;
static int hf_erf_mc_rawl_cn;
static int hf_erf_mc_rawl_res1;
static int hf_erf_mc_rawl_lbe;
static int hf_erf_mc_rawl_first;
static int hf_erf_mc_rawl_res2;

/* MC AAL5 Header */
static int hf_erf_mc_aal5;
static int hf_erf_mc_aal5_cn;
static int hf_erf_mc_aal5_res1;
static int hf_erf_mc_aal5_port;
static int hf_erf_mc_aal5_crcck;
static int hf_erf_mc_aal5_crce;
static int hf_erf_mc_aal5_lenck;
static int hf_erf_mc_aal5_lene;
static int hf_erf_mc_aal5_res2;
static int hf_erf_mc_aal5_first;
static int hf_erf_mc_aal5_res3;

/* MC AAL2 Header */
static int hf_erf_mc_aal2;
static int hf_erf_mc_aal2_cn;
static int hf_erf_mc_aal2_res1;
static int hf_erf_mc_aal2_res2;
static int hf_erf_mc_aal2_port;
static int hf_erf_mc_aal2_res3;
static int hf_erf_mc_aal2_first;
static int hf_erf_mc_aal2_maale;
static int hf_erf_mc_aal2_lene;
static int hf_erf_mc_aal2_cid;

/* AAL2 Header */
static int hf_erf_aal2;
static int hf_erf_aal2_cid;
static int hf_erf_aal2_maale;
static int hf_erf_aal2_maalei;
static int hf_erf_aal2_first;
static int hf_erf_aal2_res1;

/* ERF Ethernet header/pad */
static int hf_erf_eth;
static int hf_erf_eth_off;
static int hf_erf_eth_pad;

/* ERF Meta record tag */
static int hf_erf_meta_tag_type;
static int hf_erf_meta_tag_len;
static int hf_erf_meta_tag_unknown;

/* Initialize the subtree pointers */
static int ett_erf;
static int ett_erf_pseudo_hdr;
static int ett_erf_rectype;
static int ett_erf_hash_type;
static int ett_erf_flags;
static int ett_erf_mc_hdlc;
static int ett_erf_mc_raw;
static int ett_erf_mc_atm;
static int ett_erf_mc_rawlink;
static int ett_erf_mc_aal5;
static int ett_erf_mc_aal2;
static int ett_erf_aal2;
static int ett_erf_eth;
static int ett_erf_meta;
static int ett_erf_meta_tag;
static int ett_erf_source;
static int ett_erf_anchor;
static int ett_erf_anchor_flags;
static int ett_erf_entropy_value;

static expert_field ei_erf_extension_headers_not_shown;
static expert_field ei_erf_packet_loss;
static expert_field ei_erf_mc_hdlc_checksum_error;
static expert_field ei_erf_mc_hdlc_short_error;
static expert_field ei_erf_mc_hdlc_long_error;
static expert_field ei_erf_mc_hdlc_abort_error;
static expert_field ei_erf_mc_hdlc_octet_error;
static expert_field ei_erf_mc_hdlc_lost_byte_error;
static expert_field ei_erf_rx_error;
static expert_field ei_erf_ds_error;
static expert_field ei_erf_truncation_error;
static expert_field ei_erf_meta_section_len_error;
static expert_field ei_erf_meta_truncated_record;
static expert_field ei_erf_meta_truncated_tag;
static expert_field ei_erf_meta_zero_len_tag;
static expert_field ei_erf_meta_reset;

typedef enum {
  ERF_HDLC_CHDLC  = 0,
  ERF_HDLC_PPP    = 1,
  ERF_HDLC_FRELAY = 2,
  ERF_HDLC_MTP2   = 3,
  ERF_HDLC_GUESS  = 4,
  ERF_HDLC_MAX    = 5
} erf_hdlc_type_vals;

static int erf_hdlc_type = ERF_HDLC_GUESS;
static dissector_handle_t chdlc_handle, ppp_handle, frelay_handle, mtp2_handle;

static bool erf_rawcell_first;

typedef enum {
  ERF_AAL5_GUESS  = 0,
  ERF_AAL5_LLC    = 1,
  ERF_AAL5_UNSPEC = 2
} erf_aal5_type_val;

static int erf_aal5_type = ERF_AAL5_GUESS;
static dissector_handle_t atm_untruncated_handle;

static dissector_handle_t sdh_handle;

/* ERF Extension Header */
#define ERF_EHDR_FLOW_ID_HASH_TYPE_TYPE_MASK 0x7f
#define ERF_EHDR_FLOW_ID_HASH_TYPE_INNER_MASK 0x80

/* Classification */
#define EHDR_CLASS_FLAGS_MASK 0x00ffffff
#define EHDR_CLASS_SH_MASK    0x00800000
#define EHDR_CLASS_SHM_MASK   0x00400000
#define EHDR_CLASS_RES1_MASK  0x00300000
#define EHDR_CLASS_USER_MASK  0x000FFFF0
#define EHDR_CLASS_RES2_MASK  0x00000008
#define EHDR_CLASS_DROP_MASK  0x00000004
#define EHDR_CLASS_STER_MASK  0x00000003

/* Header for ATM traffic identification */
#define ATM_HDR_LENGTH 4

/* Multi Channel HDLC */
#define MC_HDLC_CN_MASK    0x000003ff
#define MC_HDLC_RES1_MASK  0x0000fc00
#define MC_HDLC_RES2_MASK  0x00ff0000
#define MC_HDLC_FCSE_MASK  0x01000000
#define MC_HDLC_SRE_MASK   0x02000000
#define MC_HDLC_LRE_MASK   0x04000000
#define MC_HDLC_AFE_MASK   0x08000000
#define MC_HDLC_OE_MASK    0x10000000
#define MC_HDLC_LBE_MASK   0x20000000
#define MC_HDLC_FIRST_MASK 0x40000000
#define MC_HDLC_RES3_MASK  0x80000000

/* Multi Channel RAW */
#define MC_RAW_INT_MASK   0x0000000f
#define MC_RAW_RES1_MASK  0x01fffff0
#define MC_RAW_SRE_MASK   0x02000000
#define MC_RAW_LRE_MASK   0x04000000
#define MC_RAW_RES2_MASK  0x18000000
#define MC_RAW_LBE_MASK   0x20000000
#define MC_RAW_FIRST_MASK 0x40000000
#define MC_RAW_RES3_MASK  0x80000000

/* Multi Channel ATM */
#define MC_ATM_CN_MASK      0x000003ff
#define MC_ATM_RES1_MASK    0x00007c00
#define MC_ATM_MUL_MASK     0x00008000
#define MC_ATM_PORT_MASK    0x000f0000
#define MC_ATM_RES2_MASK    0x00f00000
#define MC_ATM_LBE_MASK     0x01000000
#define MC_ATM_HEC_MASK     0x02000000
#define MC_ATM_CRC10_MASK   0x04000000
#define MC_ATM_OAMCELL_MASK 0x08000000
#define MC_ATM_FIRST_MASK   0x10000000
#define MC_ATM_RES3_MASK    0xe0000000

/* Multi Channel RAW Link */
#define MC_RAWL_CN_MASK    0x000003ff
#define MC_RAWL_RES1_MASK  0x1ffffc00
#define MC_RAWL_LBE_MASK   0x20000000
#define MC_RAWL_FIRST_MASK 0x40000000
#define MC_RAWL_RES2_MASK  0x80000000

/* Multi Channel AAL5 */
#define MC_AAL5_CN_MASK    0x000003ff
#define MC_AAL5_RES1_MASK  0x0000fc00
#define MC_AAL5_PORT_MASK  0x000f0000
#define MC_AAL5_CRCCK_MASK 0x00100000
#define MC_AAL5_CRCE_MASK  0x00200000
#define MC_AAL5_LENCK_MASK 0x00400000
#define MC_AAL5_LENE_MASK  0x00800000
#define MC_AAL5_RES2_MASK  0x0f000000
#define MC_AAL5_FIRST_MASK 0x10000000
#define MC_AAL5_RES3_MASK  0xe0000000

/* Multi Channel AAL2 */
#define MC_AAL2_CN_MASK    0x000003ff
#define MC_AAL2_RES1_MASK  0x00001c00
#define MC_AAL2_RES2_MASK  0x0000e000
#define MC_AAL2_PORT_MASK  0x000f0000
#define MC_AAL2_RES3_MASK  0x00100000
#define MC_AAL2_FIRST_MASK 0x00200000
#define MC_AAL2_MAALE_MASK 0x00400000
#define MC_AAL2_LENE_MASK  0x00800000
#define MC_AAL2_CID_MASK   0xff000000
#define MC_AAL2_CID_SHIFT  24

/* AAL2 */
#define AAL2_CID_MASK    0x000000ff
#define AAL2_CID_SHIFT   0
#define AAL2_MAALE_MASK  0x0000ff00
#define AAL2_MAALEI_MASK 0x00010000
#define AAL2_FIRST_MASK  0x00020000
#define AAL2_RES1_MASK   0xfffc0000

/* ETH */
#define ETH_OFF_MASK  0x00
#define ETH_RES1_MASK 0x00

/* Invalid Provenance sections used for special lookup */
#define ERF_META_SECTION_NONE 0
#define ERF_META_SECTION_UNKNOWN 1

#define NS_PER_S 1000000000

/* Record type defines */
static const value_string erf_type_vals[] = {
  { ERF_TYPE_LEGACY             ,"LEGACY"},
  { ERF_TYPE_HDLC_POS           ,"HDLC_POS"},
  { ERF_TYPE_ETH                ,"ETH"},
  { ERF_TYPE_ATM                ,"ATM"},
  { ERF_TYPE_AAL5               ,"AAL5"},
  { ERF_TYPE_MC_HDLC            ,"MC_HDLC"},
  { ERF_TYPE_MC_RAW             ,"MC_RAW"},
  { ERF_TYPE_MC_ATM             ,"MC_ATM"},
  { ERF_TYPE_MC_RAW_CHANNEL     ,"MC_RAW_CHANNEL"},
  { ERF_TYPE_MC_AAL5            ,"MC_AAL5"},
  { ERF_TYPE_COLOR_HDLC_POS     ,"COLOR_HDLC_POS"},
  { ERF_TYPE_COLOR_ETH          ,"COLOR_ETH"},
  { ERF_TYPE_COLOR_HASH_POS     ,"COLOR_HASH_POS"},
  { ERF_TYPE_COLOR_HASH_ETH     ,"COLOR_HASH_ETH"},
  { ERF_TYPE_MC_AAL2            ,"MC_AAL2 "},
  { ERF_TYPE_IP_COUNTER         ,"IP_COUNTER"},
  { ERF_TYPE_TCP_FLOW_COUNTER   ,"TCP_FLOW_COUNTER"},
  { ERF_TYPE_DSM_COLOR_HDLC_POS ,"DSM_COLOR_HDLC_POS"},
  { ERF_TYPE_DSM_COLOR_ETH      ,"DSM_COLOR_ETH "},
  { ERF_TYPE_COLOR_MC_HDLC_POS  ,"COLOR_MC_HDLC_POS"},
  { ERF_TYPE_AAL2               ,"AAL2"},
  { ERF_TYPE_PAD                ,"PAD"},
  { ERF_TYPE_INFINIBAND         , "INFINIBAND"},
  { ERF_TYPE_IPV4               , "IPV4"},
  { ERF_TYPE_IPV6               , "IPV6"},
  { ERF_TYPE_RAW_LINK           , "RAW_LINK"},
  { ERF_TYPE_INFINIBAND_LINK    , "INFINIBAND_LINK"},
  { ERF_TYPE_META               , "META"},
  { ERF_TYPE_OPA_SNC            , "OMNI-PATH_SNC"},
  { ERF_TYPE_OPA_9B             , "OMNI-PATH"},
  {0, NULL}
};

/* Extended headers type defines */
static const value_string ehdr_type_vals[] = {
  { ERF_EXT_HDR_TYPE_CLASSIFICATION , "Classification"},
  { ERF_EXT_HDR_TYPE_INTERCEPTID    , "InterceptID"},
  { ERF_EXT_HDR_TYPE_RAW_LINK       , "Raw Link"},
  { ERF_EXT_HDR_TYPE_BFS            , "BFS Filter/Hash"},
  { ERF_EXT_HDR_TYPE_CHANNELISED    , "Channelised"},
  { ERF_EXT_HDR_TYPE_SIGNATURE      , "Signature"},
  { ERF_EXT_HDR_TYPE_PKT_ID         , "Packet ID"},
  { ERF_EXT_HDR_TYPE_FLOW_ID        , "Flow ID"},
  { ERF_EXT_HDR_TYPE_HOST_ID        , "Host ID"},
  { ERF_EXT_HDR_TYPE_ANCHOR_ID      , "Anchor ID"},
  { ERF_EXT_HDR_TYPE_ENTROPY        , "Entropy"},
  { 0, NULL }
};

/* Used for Provenance ext_hdrs_added/removed, should match the field abbreviation */
static const value_string ehdr_type_vals_short[] = {
  { ERF_EXT_HDR_TYPE_CLASSIFICATION , "class"},
  { ERF_EXT_HDR_TYPE_INTERCEPTID    , "int"},
  { ERF_EXT_HDR_TYPE_RAW_LINK       , "raw"},
  { ERF_EXT_HDR_TYPE_BFS            , "bfs"},
  { ERF_EXT_HDR_TYPE_CHANNELISED    , "chan"},
  { ERF_EXT_HDR_TYPE_SIGNATURE      , "signature"},
  { ERF_EXT_HDR_TYPE_PKT_ID         , "packetid"},
  { ERF_EXT_HDR_TYPE_FLOW_ID        , "flowid"},
  { ERF_EXT_HDR_TYPE_HOST_ID        , "hostid"},
  { ERF_EXT_HDR_TYPE_ANCHOR_ID      , "anchorid"},
  { ERF_EXT_HDR_TYPE_ENTROPY        , "entropy"},
  { 0, NULL }
};

/* XXX: Must be at least array_length(ehdr_type_vals). */
#define ERF_HF_VALUES_PER_TAG 32

static const value_string raw_link_types[] = {
  { 0x00, "raw SONET"},
  { 0x01, "raw SDH"},
  { 0x02, "SONET spe"},
  { 0x03, "SDH spe"},
  { 0x04, "ds3"},
  { 0x05, "SONET spe w/o POH"},
  { 0x06, "SDH spe w/o POH"},
  { 0x07, "SONET line mode 2"},
  { 0x08, "SHD line mode 2"},
  { 0x09, "raw bit-level"},
  { 0x0A, "raw 10Gbe 66b"},
  { 0, NULL },
};

static const value_string raw_link_rates[] = {
  { 0x00, "reserved"},
  { 0x01, "oc3/stm1"},
  { 0x02, "oc12/stm4"},
  { 0x03, "oc48/stm16"},
  { 0x04, "oc192/stm64"},
  { 0, NULL },
};

static const value_string channelised_assoc_virt_container_size[] = {
  { 0x00, "unused field"},
  { 0x01, "VC-3 / STS-1"},
  { 0x02, "VC-4 / STS-3"},
  { 0x03, "VC-4-4c / STS-12"},
  { 0x04, "VC-4-16c / STS-48"},
  { 0x05, "VC-4-64c / STS-192"},
  { 0, NULL }
};

static const value_string channelised_rate[] = {
  { 0x00, "Reserved"},
  { 0x01, "STM-0 / STS-1"},
  { 0x02, "STM-1 / STS-3"},
  { 0x03, "STM-4 / STS-12"},
  { 0x04, "STM-16 / STS-48"},
  { 0x05, "STM-64 / STS-192"},
  { 0, NULL}
};

static const value_string channelised_type[] = {
  { 0x00, "SOH / TOH"},
  { 0x01, "POH"},
  { 0x02, "Container"},
  { 0x03, "POS Packet"},
  { 0x04, "ATM Cell"},
  { 0x05, "Positive justification bytes"},
  { 0x06, "Raw demultiplexed channel"},
  { 0, NULL}
};

static const value_string erf_hash_type[] = {
  { 0x00, "Not set"},
  { 0x01, "Non-IP (Src/Dst MACs, EtherType)"},
  { 0x02, "2-tuple (Src/Dst IPs)"},
  { 0x03, "3-tuple (Src/Dst IPs, IP Protocol)"},
  { 0x04, "4-tuple (Src/Dst IPs, IP Protocol, Interface ID)"},
  { 0x05, "5-tuple (Src/Dst IPs, IP Protocol, Src/Dst L4 Ports)"},
  { 0x06, "6-tuple (Src/Dst IPs, IP Protocol, Src/Dst L4 Ports, Interface ID)"},
  { 0, NULL}
};

static const value_string erf_hash_mode[] = {
  { 0x00, "Reserved"},
  { 0x01, "Reserved"},
  { 0x02, "2-tuple (Src/Dst IPs)"},
  { 0x03, "3-tuple (Src/Dst IPs, IP Protocol)"},
  { 0x04, "4-tuple (Src/Dst IPs, IP Protocol, Interface ID)"},
  { 0x05, "5-tuple (Src/Dst IPs, IP Protocol, Src/Dst L4 Ports)"},
  { 0x06, "6-tuple (Src/Dst IPs, IP Protocol, Src/Dst L4 Ports, Interface ID)"},
  { 0x07, "2-tuple (Inner Src/Dst IPs)"},
  { 0x08, "4-tuple (Inner Src/Dst IPs, Outer Src/Dst IPs)"},
  { 0x09, "4-tuple (Inner Src/Dst IPs, Inner Src/Dst L4 Ports)"},
  { 0x0A, "6-tuple (Inner Src/Dst IPs, Outer Src/Dst IPs, Inner Src/Dst L4 Ports)"},
  { 0, NULL}
};

static const value_string erf_stack_type[] = {
  { 0x00, "Not set"},
  { 0x01, "Non-IP"},
  { 0x02, "No VLAN, IPv4"},
  { 0x03, "No VLAN, IPv6"},
  { 0x04, "One VLAN, IPv4"},
  { 0x05, "One VLAN, IPv6"},
  { 0x06, "Two VLANs, IPv4"},
  { 0x07, "Two VLANs, IPv6"},
  { 0, NULL}
};
static const value_string erf_port_type[] = {
  { 0x00, "Reserved"},
  { 0x01, "Capture Port"},
  { 0x02, "Timing Port"},
  { 0, NULL}
};

static const value_string erf_clk_source[] = {
  { 0x00, "Invalid"},
  { 0x01, "None" },
  { 0x02, "External"},
  { 0x03, "Host"},
  { 0x04, "Link Cable"},
  { 0x05, "PTP"},
  { 0x06, "Internal"},
  { 0, NULL}
};

static const value_string erf_clk_state[] = {
  { 0x00, "Invalid" },
  { 0x01, "Unsynchronized"},
  { 0x02, "Synchronized"},
  { 0, NULL}
};

static const value_string erf_clk_link_mode[] = {
  { 0x00, "Invalid"},
  { 0x01, "Not Connected"},
  { 0x02, "Master"},
  { 0x03, "Disabled Master"},
  { 0x04, "Slave"},
  { 0, NULL}
};

static const value_string erf_clk_port_proto[] = {
  { 0x00, "Invalid" },
  { 0x01, "None" },
  { 0x02, "1PPS" },
  { 0x03, "IRIG-B" },
  { 0x04, "Ethernet" },
  { 0, NULL }
};

static const value_string erf_tap_mode[] = {
  { 0x00, "Invalid" },
  { 0x01, "Off" },
  { 0x02, "Active" },
  { 0x03, "Monitor" },
  { 0x04, "Bypass" },
  { 0x05, "Blocking" },
  { 0, NULL }
};

static const value_string erf_tap_fail_mode[] = {
  { 0x00, "Invalid" },
  { 0x01, "Off" },
  { 0x02, "Open" },
  { 0x03, "Closed" },
  { 0, NULL }
};

static const value_string erf_dpi_state[] = {
  { 0x00, "Terminated"},
  { 0x01, "Inspecting"},
  { 0x02, "Monitoring"},
  { 0x03, "Classified"},
  { 0, NULL}
};

static const value_string erf_flow_state[] = {
  { 0x00, "Active"},
  { 0x01, "Terminated"},
  { 0x02, "Expired"},
  { 0, NULL}
};

/* Used as templates for ERF_META_TAG_tunneling_mode */
static const header_field_info erf_tunneling_modes[] = {
  { "IP-in-IP", "ip_in_ip", FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL },
  /* 0x02 is currently unused and reserved */
  { "VXLAN", "vxlan", FT_BOOLEAN, 32, NULL, 0x4, NULL, HFILL },
  { "GRE", "gre", FT_BOOLEAN, 32, NULL, 0x8, NULL, HFILL },
  { "GTP", "gtp", FT_BOOLEAN, 32, NULL, 0x10, NULL, HFILL },
  { "MPLS over VLAN", "mpls_vlan", FT_BOOLEAN, 32, NULL, 0x20, NULL, HFILL }
};


/* Used as templates for ERF_META_TAG_if_link_status */
static const header_field_info erf_link_status[] = {
  { "Link", "link", FT_BOOLEAN, 32, TFS(&tfs_up_down), 0x1, NULL, HFILL }
};

/* Used as templates for ERF_META_TAG_ptp_time_properties */
static const header_field_info erf_ptp_time_properties_flags[] = {
  { "Leap61", "leap61", FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL },
  { "Leap59", "leap59", FT_BOOLEAN, 32, NULL, 0x2, NULL, HFILL },
  { "Current UTC Offset Valid", "currentUtcOffsetValid", FT_BOOLEAN, 32, NULL, 0x4, NULL, HFILL },
  { "PTP Timescale", "ptpTimescale", FT_BOOLEAN, 32, NULL, 0x8, NULL, HFILL },
  { "Time Traceable", "timeTraceable", FT_BOOLEAN, 32, NULL, 0x10, NULL, HFILL },
  { "Frequency Traceable", "frequencyTraceable", FT_BOOLEAN, 32, NULL, 0x20, NULL, HFILL }
};

/* Used as templates for ERF_META_TAG_ptp_gm_clock_quality */
static const header_field_info erf_ptp_clock_quality[] = {
  { "Clock Class", "clockClass", FT_UINT32, BASE_DEC, NULL, 0xFF000000, NULL, HFILL },
  { "Clock Accuracy", "clockAccuracy", FT_UINT32, BASE_DEC | BASE_EXT_STRING, &ptp_v2_clockAccuracy_vals_ext, 0x00FF0000, NULL, HFILL },
  { "Offset Scaled Log Variance","offsetScaledLogVariance", FT_UINT32, BASE_DEC, NULL, 0x0000FFFF, NULL, HFILL },
};

/* Used as templates for ERF_META_TAG_parent_section */
static const header_field_info erf_parent_section[] = {
  { "Section Type", "section_type", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
  { "Section ID", "section_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
};

/* Used as templates for ERF_META_TAG_stream_flags */
static const header_field_info erf_stream_flags[] = {
  { "Relative Snapping", "relative_snap", FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL },
  { "Entropy Snapping", "entropy_snap", FT_BOOLEAN, 32, NULL, 0x2, NULL, HFILL }
};

/* Used as templates for ERF_META_TAG_ext_hdrs_added/removed subtrees */
static const header_field_info erf_ext_hdr_items[] = {
  { "Extension Headers 0 to 31", "0_31", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
  { "Extension Headers 32 to 63", "32_63", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
  { "Extension Headers 64 to 95", "64_95", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
  { "Extension Headers 96 to 127", "96_127", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
};

/* Used as templates for ERF_META_TAG_smart_trunc_default */
static const header_field_info erf_smart_trunc_default_flags[] = {
  { "Truncation Candidate", "trunc_candidate", FT_BOOLEAN, 32, &tfs_yes_no, 0x1, NULL, HFILL }
};

typedef struct {
  uint16_t code;
  header_field_info hfinfo;
} erf_meta_hf_template_t;

typedef struct {
  int ett_value;
  /*
   * XXX: Must be at least array_length(ehdr_type_vals). Should change to
   * dynamic (possibly using new proto tree API) if many more fields defined.
   * Non-trivial as bitmask functions take an array of pointers not values.
   * Either that or add a value-string-like automatic bitmask flags proto_item.
   *
   * Note that this struct is only added for tags that need it.
   */
  int hf_values[ERF_HF_VALUES_PER_TAG];
} erf_meta_tag_info_ex_t;

typedef struct {
  uint16_t code;
  uint16_t section;
  const erf_meta_hf_template_t* tag_template;
  const erf_meta_hf_template_t* section_template;

  int ett;
  int hf_value;
  erf_meta_tag_info_ex_t *extra;
  /* TODO: could add a type_value and callback here for greater flexibility */
} erf_meta_tag_info_t;

typedef struct {
  wmem_map_t* tag_table;
  wmem_array_t* hfri;
  wmem_array_t* ett;
  wmem_array_t* vs_list;
  wmem_array_t* vs_abbrev_list;
  erf_meta_tag_info_t* unknown_section_info;
} erf_meta_index_t;

typedef struct {
  wmem_map_t* source_map;
  wmem_map_t* host_anchor_map;
  uint64_t implicit_host_id;
} erf_state_t;

typedef struct {
  wmem_tree_t* meta_tree;
  wmem_list_t* meta_list;
} erf_source_info_t;

typedef struct {
  unsigned frame_num;
} erf_anchored_info_t;

typedef struct {
  wmem_tree_t* anchored_tree;
  wmem_list_t* anchored_list;
} erf_host_anchor_info_t;

typedef struct {
  uint64_t host_id;
  uint64_t anchor_id;
} erf_anchor_key_t;

#define ERF_SOURCE_KEY(host_id, source_id) (((uint64_t) host_id << 16) | source_id)
#define ERF_TAG_INFO_KEY(tag_info) (((uint32_t) (tag_info)->section << 16) | (tag_info)->code)

static erf_meta_index_t erf_meta_index;
static erf_state_t erf_state;

/*
 * XXX: These header_field_info are used as templates for dynamically building
 * per-section fields for each tag, as well as appropriate value_string arrays.
 * We abuse the abbrev field to store the short name of the tags.
 */
static const erf_meta_hf_template_t erf_meta_tags[] = {
  { ERF_META_TAG_padding,           { "Padding",                            "padding",           FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_comment,           { "Comment",                            "comment",           FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_gen_time,          { "Metadata Generation Time",           "gen_time",          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_parent_section,    { "Parent Section",                     "parent_section",    FT_BYTES,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_reset,             { "Metadata Reset",                     "reset",             FT_BYTES,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_event_time,        { "Event Time",                         "event_time",        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_host_id,           { "Host ID",                            "host_id",           FT_UINT64,        BASE_HEX,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_attribute,         { "Attribute",                          "attribute",         FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_fcs_len,           { "FCS Length (bits)",                  "fcs_len",           FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_mask_ipv4,         { "Subnet Mask (IPv4)",                 "mask_ipv4",         FT_IPv4,          BASE_NETMASK,      NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_mask_cidr,         { "Subnet Mask (CIDR)",                 "mask_cidr",         FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },

  { ERF_META_TAG_org_name,          { "Organisation",                       "org_name",          FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_name,              { "Name",                               "name",              FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_descr,             { "Description",                        "descr",             FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_config,            { "Configuration",                      "config",            FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_datapipe,          { "Datapipe Name",                      "datapipe",          FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_app_name,          { "Application Name",                   "app_name",          FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_os,                { "Operating System",                   "os",                FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_hostname,          { "Hostname",                           "hostname",          FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_user,              { "User",                               "user",              FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_model,             { "Model",                              "model",             FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_fw_version,        { "Firmware Version",                   "fw_version",        FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_serial_no,         { "Serial Number",                      "serial_no",         FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ts_offset,         { "Timestamp Offset",                   "ts_offset",         FT_RELATIVE_TIME, BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ts_clock_freq,     { "Timestamp Clock Frequency (Hz)",     "ts_clock_freq",     FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_tzone,             { "Timezone Offset",                    "tzone",             FT_INT32,         BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_tzone_name,        { "Timezone Name",                      "tzone_name",        FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_loc_lat,           { "Location Latitude",                  "loc_lat",           FT_INT32,         BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_loc_long,          { "Location Longitude",                 "loc_long",          FT_INT32,         BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_snaplen,           { "Snap Length",                        "snaplen",           FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_card_num,          { "Card Number",                        "card_num",          FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_module_num,        { "Module Number",                      "module_num",        FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_access_num,        { "Access Number",                      "access_num",        FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stream_num,        { "Stream Number",                      "stream_num",        FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_loc_name,          { "Location Name",                      "loc_name",          FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_parent_file,       { "Parent Filename",                    "parent_file",       FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_filter,            { "Filter",                             "filter",            FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_flow_hash_mode,    { "Flow Hash Mode",                     "flow_hash_mode",    FT_UINT32,        BASE_DEC,          VALS(erf_hash_mode), 0x0, NULL, HFILL } },
  { ERF_META_TAG_tunneling_mode,    { "Tunneling Mode",                     "tunneling_mode",    FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_npb_format,        { "NPB Format",                         "npb_format",        FT_BYTES,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_mem,               { "Memory",                             "mem",               FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_datamine_id,       { "Datamine ID",                        "datamine_id",       FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_rotfile_id,        { "Rotfile ID",                         "rotfile_id",        FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_rotfile_name,      { "Rotfile Name",                       "rotfile_name",      FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_dev_name,          { "Device Name",                        "dev_name",          FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_dev_path,          { "Device Canonical Path",              "dev_path",          FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_loc_descr,         { "Location Description",               "loc_descr",         FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_app_version,       { "Application Version",                "app_version",       FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_cpu_affinity,      { "CPU Affinity Mask",                  "cpu_affinity",      FT_BYTES,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_cpu,               { "CPU Model",                          "cpu",               FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_cpu_phys_cores,    { "CPU Physical Cores",                 "cpu_phys_cores",    FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_cpu_numa_nodes,    { "CPU NUMA Nodes",                     "cpu_numa_nodes",    FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_dag_attribute,     { "DAG Attribute",                      "dag_attribute",     FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_dag_version,       { "DAG Software Version",               "dag_version",       FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stream_flags,      { "Stream Flags",                       "stream_flags",      FT_UINT32,        BASE_HEX,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_entropy_threshold, { "Entropy Threshold",                  "entropy_threshold", FT_FLOAT,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_smart_trunc_default, { "Smart Truncation Default",         "smart_trunc_default",FT_UINT32,       BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ext_hdrs_added,    { "Extension Headers Added",            "ext_hdrs_added",    FT_BYTES,         BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ext_hdrs_removed,  { "Extension Headers Removed",          "ext_hdrs_removed",  FT_BYTES,         BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_relative_snaplen,  { "Relative Snap Length",               "relative_snaplen",  FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_temperature,       { "Temperature",                        "temperature",       FT_FLOAT,         BASE_NONE|BASE_UNIT_STRING, UNS(&units_degree_celsius), 0x0, NULL, HFILL } },
  { ERF_META_TAG_power,             { "Power Consumption",                  "power",             FT_FLOAT,         BASE_NONE|BASE_UNIT_STRING, UNS(&units_watt), 0x0, NULL, HFILL } },
  { ERF_META_TAG_vendor,            { "Vendor",                             "vendor",            FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_cpu_threads,       { "CPU Threads",                        "cpu_threads",       FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },

  { ERF_META_TAG_if_num,            { "Interface Number",                   "if_num",            FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_vc,             { "Interface Virtual Circuit",          "if_vc",             FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_speed,          { "Interface Line Rate",                "if_speed",          FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_ipv4,           { "Interface IPv4 address",             "if_ipv4",           FT_IPv4,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_ipv6,           { "Interface IPv6 address",             "if_ipv6",           FT_IPv6,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_mac,            { "Interface MAC address",              "if_mac",            FT_ETHER,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_eui,            { "Interface EUI-64 address",           "if_eui",            FT_EUI64,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_ib_gid,         { "Interface InfiniBand GID",           "if_ib_gid",         FT_IPv6,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_ib_lid,         { "Interface InfiniBand LID",           "if_ib_lid",         FT_UINT16,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_wwn,            { "Interface WWN",                      "if_wwn",            FT_BYTES,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_fc_id,          { "Interface FCID address",             "if_fc_id",          FT_BYTES,         SEP_DOT,           NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_tx_speed,       { "Interface TX Line Rate",             "if_tx_speed",       FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_erf_type,       { "Interface ERF type",                 "if_erf_type",       FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_link_type,      { "Interface link type",                "if_link_type",      FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_sfp_type,       { "Interface Transceiver type",         "if_sfp_type",       FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_rx_power,       { "Interface RX Optical Power",         "if_rx_power",       FT_INT32,         BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_tx_power,       { "Interface TX Optical Power",         "if_tx_power",       FT_INT32,         BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_link_status,    { "Interface Link Status",              "if_link_status",    FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_phy_mode,       { "Interface Endace PHY Mode",          "if_phy_mode",       FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_port_type,      { "Interface Port Type",                "if_port_type",      FT_UINT32,        BASE_DEC,          VALS(erf_port_type), 0x0, NULL, HFILL } },
  { ERF_META_TAG_if_rx_latency,     { "Interface Uncorrected RX Latency",   "if_rx_latency",     FT_RELATIVE_TIME, BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_tap_mode,          { "Tap Mode",                           "tap_mode",          FT_UINT32,        BASE_DEC,          VALS(erf_tap_mode), 0x0, NULL, HFILL } },
  { ERF_META_TAG_tap_fail_mode,     { "Tap Failover Mode",                  "tap_fail_mode",     FT_UINT32,        BASE_DEC,          VALS(erf_tap_fail_mode), 0x0, NULL, HFILL } },
  { ERF_META_TAG_watchdog_expired,  { "Watchdog Expired",                   "watchdog_expired",  FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_watchdog_interval, { "Watchdog Interval (ms)",             "watchdog_interval", FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },

  { ERF_META_TAG_src_ipv4,          { "Source IPv4 address",                "src_ipv4",          FT_IPv4,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_dest_ipv4,         { "Destination IPv4 address",           "dest_ipv4",         FT_IPv4,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_src_ipv6,          { "Source IPv6 address",                "src_ipv6",          FT_IPv6,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_dest_ipv6,         { "Destination IPv6 address",           "dest_ipv6",         FT_IPv6,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_src_mac,           { "Source MAC address",                 "src_mac",           FT_ETHER,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_dest_mac,          { "Destination MAC address",            "dest_mac",          FT_ETHER,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_src_eui,           { "Source EUI-64 address",              "src_eui",           FT_EUI64,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_dest_eui,          { "Destination EUI-64 address",         "dest_eui",          FT_EUI64,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_src_ib_gid,        { "Source InfiniBand GID address",      "src_ib_gid",        FT_IPv6,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_dest_ib_gid,       { "Destination InfiniBand GID address", "dest_ib_gid",       FT_IPv6,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_src_ib_lid,        { "Source InfiniBand LID address",      "src_ib_lid",        FT_UINT16,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_dest_ib_lid,       { "Destination InfiniBand LID address", "dest_ib_lid",       FT_UINT16,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_src_wwn,           { "Source WWN address",                 "src_wwn",           FT_BYTES,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_dest_wwn,          { "Destination WWN address",            "dest_wwn",          FT_BYTES,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_src_fc_id,         { "Source FCID address",                "src_fc_id",         FT_BYTES,         SEP_DOT,           NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_dest_fc_id,        { "Destination FCID address",           "dest_fc_id",        FT_BYTES,         SEP_DOT,           NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_src_port,          { "Source Port",                        "src_port",          FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_dest_port,         { "Destination Port",                   "dest_port",         FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ip_proto,          { "IP Protocol",                        "ip_proto",          FT_UINT32,        BASE_DEC|BASE_EXT_STRING, &ipproto_val_ext, 0x0, NULL, HFILL } },
  { ERF_META_TAG_flow_hash,         { "Flow Hash",                          "flow_hash",         FT_UINT32,        BASE_HEX,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_filter_match,      { "Filter Match",                       "filter_match",      FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_filter_match_name, { "Filter Match Name",                  "filter_match_name", FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_error_flags,       { "Error Flags",                        "error_flags",       FT_BYTES,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_initiator_pkts,    { "Initiator Packets",                  "initiator_pkts",    FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_responder_pkts,    { "Responder Packets",                  "responder_pkts",    FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_initiator_bytes,   { "Initiator Bytes",                    "initiator_bytes",   FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_responder_bytes,   { "Responder Bytes",                    "responder_bytes",   FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_initiator_min_entropy, { "Initiator Minimum Entropy",      "initiator_min_entropy", FT_FLOAT,     BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_responder_min_entropy, { "Responder Minimum Entropy",      "responder_min_entropy", FT_FLOAT,     BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_initiator_avg_entropy, { "Initiator Average Entropy",      "initiator_avg_entropy", FT_FLOAT,     BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_responder_avg_entropy, { "Responder Average Entropy",      "responder_avg_entropy", FT_FLOAT,     BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_initiator_max_entropy, { "Initiator Maximum Entropy",      "initiator_max_entropy", FT_FLOAT,     BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_responder_max_entropy, { "Responder Maximum Entropy",      "responder_max_entropy", FT_FLOAT,     BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_dpi_application,       { "DPI Application",                "dpi_application",   FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_dpi_confidence,        { "DPI Confidence",                 "dpi_confidence",    FT_STRING,        BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_dpi_state,             { "DPI State",                      "dpi_state",         FT_UINT32,        BASE_NONE,         VALS(erf_dpi_state), 0x0, NULL, HFILL } },
  { ERF_META_TAG_dpi_protocol_stack,    { "DPI Protocol Stack",             "dpi_protocol_stack", FT_STRING,       BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_flow_state,            { "Flow State",                     "flow_state",        FT_UINT32,        BASE_NONE,         VALS(erf_flow_state), 0x0, NULL, HFILL } },
  { ERF_META_TAG_vlan_id,           { "VLAN ID",                            "vlan_id",           FT_INT32,         BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_mpls_label,        { "MPLS Label",                         "mpls_label",        FT_INT32,         BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_vlan_pcp,          { "VLAN PCP",                           "vlan_pcp",          FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_mpls_tc,           { "MPLS_TC",                            "mpls_tc",           FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_dscp,              { "DSCP",                               "dscp",              FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_initiator_mpls_label, { "Initiator MPLS Label",            "initiator_mpls_label", FT_INT32,      BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_responder_mpls_label, { "Responder MPLS Label",            "responder_mpls_label", FT_INT32,      BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_initiator_mpls_tc, { "Initiator MPLS TC",                  "initiator_mpls_tc", FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_responder_mpls_tc, { "Responder MPLS TC",                  "responder_mpls_tc", FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_initiator_ipv4,    { "Initiator IPv4",                     "initiator_ipv4",    FT_IPv4,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_responder_ipv4,    { "Responder IPv4",                     "responder_ipv4",    FT_IPv4,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_initiator_ipv6,    { "Initiator IPv6",                     "initiator_ipv6",    FT_IPv6,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_responder_ipv6,    { "Responder IPv6",                     "responder_ipv6",    FT_IPv6,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_initiator_mac,     { "Initiator MAC Address",              "initiator_mac",     FT_ETHER,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_responder_mac,     { "Responder MAC Address",              "responder_mac",     FT_ETHER,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_initiator_port,    { "Initiator Port",                     "initiator_port",    FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_responder_port,    { "Responder Port",                     "responder_port",    FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_initiator_retx,    { "Initiator Retransmissions",          "initiator_retx",    FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_responder_retx,    { "Responder Retransmissions",          "responder_retx",    FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_initiator_zwin,    { "Initiator Zero Window Count",        "initiator_zwin",    FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_responder_zwin,    { "Responder Zero Window Count",        "responder_zwin",    FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_initiator_tcp_flags, { "Initiator TCP Flags",              "initiator_flags",   FT_BYTES,         BASE_NONE,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_responder_tcp_flags, { "Responder TCP Flags",              "responder_flags",   FT_BYTES,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_tcp_irtt,          { "TCP Initial Round Trip Time",        "tcp_irtt",          FT_RELATIVE_TIME, BASE_NONE,         NULL, 0x0, NULL, HFILL } },

  { ERF_META_TAG_start_time,        { "Start Time",                         "start_time",        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_end_time,          { "End Time",                           "end_time",          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_if_drop,      { "Interface Drop",                     "stat_if_drop",      FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_frames,       { "Packets Received",                   "stat_frames",       FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_bytes,        { "Bytes Received",                     "stat_bytes",        FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_cap,          { "Packets Captured",                   "stat_cap",          FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_cap_bytes,    { "Bytes Captured",                     "stat_cap_bytes",    FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_os_drop,      { "OS Drop",                            "stat_os_drop",      FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_ds_lctr,      { "Internal Error Drop",                "stat_ds_lctr",      FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_filter_match, { "Filter Match",                       "stat_filter_match", FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_filter_drop,  { "Filter Drop",                        "stat_filter_drop",  FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_too_short,    { "Packets Too Short",                  "stat_too_short",    FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_too_long,     { "Packets Too Long",                   "stat_too_long",     FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_rx_error,     { "Packets RX Error",                   "stat_rx_error",     FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_fcs_error,    { "Packets FCS Error",                  "stat_fcs_error",    FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_aborted,      { "Packets Aborted",                    "stat_aborted",      FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_proto_error,  { "Packets Protocol Error",             "stat_proto_error",  FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_b1_error,     { "SDH B1 Errors",                      "stat_b1_error",     FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_b2_error,     { "SDH B2 Errors",                      "stat_b2_error",     FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_b3_error,     { "SDH B3 Errors",                      "stat_b3_error",     FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_rei_error,    { "SDH REI Errors",                     "stat_rei_error",    FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_drop,         { "Packets Dropped",                    "stat_drop",         FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stat_buf_drop,     { "Buffer Drop",                        "stat_buf_drop",     FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stream_drop,       { "Stream Drop",                        "stream_drop",       FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_stream_buf_drop,   { "Stream Buffer Drop",                 "stream_buf_drop",   FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_pkt_drop,          { "Packet Drop",                        "packet_drop",       FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_record_drop,       { "Record Drop",                        "record_drop",       FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_bandwidth,         { "Bandwidth",                          "bandwidth",         FT_UINT64,        BASE_DEC|BASE_UNIT_STRING, UNS(&units_bit_sec), 0x0, NULL, HFILL } },
  { ERF_META_TAG_duration,          { "Duration",                           "duration",          FT_RELATIVE_TIME, BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_top_index,         { "Top N Index",                        "top_index",         FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_concurrent_flows,  { "Concurrent Flows",                   "concurrent_flows",  FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_active_flows,      { "Active Flows",                       "active_flows",      FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_created_flows,     { "Created Flows",                      "created_flows",     FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_deleted_flows,     { "Deleted Flows",                      "deleted_flows",     FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_active_endpoints,  { "Active Endpoints",                   "active_endpoints",  FT_UINT32,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_tx_pkts,           { "Transmitted Packets",                "tx_packets",        FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_tx_bytes,          { "Transmitted Bytes",                  "tx_bytes",          FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_rx_bandwidth,      { "Receive Bandwidth",                  "rx_bandwidth",      FT_UINT64,        BASE_DEC|BASE_UNIT_STRING, UNS(&units_bit_sec), 0x0, NULL, HFILL } },
  { ERF_META_TAG_tx_bandwidth,      { "Transmit Bandwidth",                 "tx_bandwidth",      FT_UINT64,        BASE_DEC|BASE_UNIT_STRING, UNS(&units_bit_sec), 0x0, NULL, HFILL } },
  { ERF_META_TAG_records,           { "Records",                            "records",           FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_record_bytes,      { "Record Bytes",                       "record_bytes",      FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_pkt_drop_bytes,    { "Packet Drop Bytes",                  "packet_drop_bytes", FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_record_drop_bytes, { "Record Drop Bytes",                  "record_drop_bytes", FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_drop_bandwidth,    { "Drop Bandwidth",                     "drop_bandwidth",    FT_UINT64,        BASE_DEC|BASE_UNIT_STRING, UNS(&units_bit_sec), 0x0, NULL, HFILL } },
  { ERF_META_TAG_retx_pkts,         { "Retransmitted Packets",              "retx_packets",      FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_zwin_pkts,         { "Zero-Window Packets",                "zwin_packets",      FT_UINT64,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },

  { ERF_META_TAG_ns_host_ipv4,      { "IPv4 Name",                          "ns_host_ipv4",      FT_IPv4,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ns_host_ipv6,      { "IPv6 Name",                          "ns_host_ipv6",      FT_IPv6,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ns_host_mac,       { "MAC Name",                           "ns_host_mac",       FT_ETHER,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ns_host_eui,       { "EUI Name",                           "ns_host_eui",       FT_EUI64,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ns_host_ib_gid,    { "InfiniBand GID Name",                "ns_host_ib_gid",    FT_IPv6,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ns_host_ib_lid,    { "InfiniBand LID Name",                "ns_host_ib_lid",    FT_UINT16,        BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ns_host_wwn,       { "WWN Name",                           "ns_host_wwn",       FT_BYTES,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ns_host_fc_id,     { "FCID Name",                          "ns_host_fc_id",     FT_BYTES,         SEP_DOT,           NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ns_dns_ipv4,       { "Nameserver IPv4 address",            "ns_dns_ipv4",       FT_IPv4,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ns_dns_ipv6,       { "Nameserver IPv6 address",            "ns_dns_ipv6",       FT_IPv6,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },

  { ERF_META_TAG_exthdr,            { "ERF Extension Header",               "exthdr",            FT_BYTES,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_pcap_ng_block,     { "Pcapng Block",                       "pcap_ng_block",     FT_BYTES,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_asn1,              { "ASN.1",                              "asn1",              FT_BYTES,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_section_ref,       { "Section Reference",                  "section_ref",       FT_BYTES,         BASE_NONE,         NULL, 0x0, NULL, HFILL } },

  { ERF_META_TAG_clk_source,             { "Clock Source",                  "clk_source",             FT_UINT32,   BASE_DEC,          VALS(erf_clk_source), 0x0, NULL, HFILL } },
  { ERF_META_TAG_clk_state,              { "Clock State",                   "clk_state",              FT_UINT32,   BASE_DEC,          VALS(erf_clk_state), 0x0, NULL, HFILL } },
  { ERF_META_TAG_clk_threshold,          { "Clock Threshold",               "clk_threshold",          FT_RELATIVE_TIME, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_clk_correction,         { "Clock Correction",              "clk_correction",         FT_RELATIVE_TIME, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_clk_failures,           { "Clock Failures",                "clk_failures",           FT_UINT32,   BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_clk_resyncs,            { "Clock Resyncs",                 "clk_resyncs",            FT_UINT32,   BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_clk_phase_error,        { "Clock Phase Error",             "clk_phase_error",        FT_RELATIVE_TIME, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_clk_input_pulses,       { "Clock Input Pulses",            "clk_input_pulses",       FT_UINT32,   BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_clk_rejected_pulses,    { "Clock Rejected Pulses",         "clk_rejected_pulses",    FT_UINT32,   BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_clk_phc_index,          { "Clock PHC Index",               "clk_phc_index",          FT_UINT32,   BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_clk_phc_offset,         { "Clock PHC Offset",              "clk_phc_offset",         FT_RELATIVE_TIME, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_clk_timebase,           { "Clock Timebase",                "clk_timebase",           FT_STRING,   BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_clk_descr,              { "Clock Description",             "clk_descr",              FT_STRING,   BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_clk_out_source,         { "Clock Output Source",           "clk_out_source",         FT_UINT32,   BASE_DEC,          VALS(erf_clk_source), 0x0, NULL, HFILL } },
  { ERF_META_TAG_clk_link_mode,          { "Clock Link Cable Mode",         "clk_link_mode",          FT_UINT32,   BASE_DEC,          VALS(erf_clk_link_mode), 0x0, NULL, HFILL } },

  /*
   * PTP tags use the native PTPv2 format to preserve precision
   * (except expanding integers to 32-bit).
   */
  { ERF_META_TAG_ptp_domain_num,         { "PTP Domain Number",             "ptp_domain_num",         FT_UINT32,   BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ptp_steps_removed,      { "PTP Steps Removed",             "ptp_steps_removed",      FT_UINT32,   BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  /* PTP TimeInterval scaled nanoseconds, using FT_RELATIVE_TIME so can compare with clk_threshold */
  { ERF_META_TAG_ptp_offset_from_master, { "PTP Offset From Master",        "ptp_offset_from_master", FT_RELATIVE_TIME, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ptp_mean_path_delay,    { "PTP Mean Path Delay",           "ptp_mean_path_delay",    FT_RELATIVE_TIME, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ptp_parent_identity,    { "PTP Parent Clock Identity",     "ptp_parent_identity",    FT_EUI64,    BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ptp_parent_port_num,    { "PTP Parent Port Number",        "ptp_parent_port_num",    FT_UINT32,   BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ptp_gm_identity,        { "PTP Grandmaster Identity",      "ptp_gm_identity",        FT_EUI64,    BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  /* PTP ClockQuality combined field, see erf_ptp_clock_quality */
  { ERF_META_TAG_ptp_gm_clock_quality,   { "PTP Grandmaster Clock Quality", "ptp_gm_clock_quality",   FT_UINT32,   BASE_HEX,          NULL, 0x0, NULL, HFILL } },
  /* Integer seconds, using FT_RELATIVE_TIME so can compare with clk_phc_offset */
  { ERF_META_TAG_ptp_current_utc_offset, { "PTP Current UTC Offset",        "ptp_current_utc_offset", FT_RELATIVE_TIME, BASE_NONE,    NULL, 0x0, NULL, HFILL } },
  /* PTP TIME_PROPERTIES_DATA_SET flags, see erf_ptp_time_properties_flags */
  { ERF_META_TAG_ptp_time_properties,    { "PTP Time Properties",           "ptp_time_properties",    FT_UINT32,   BASE_HEX,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ptp_time_source,        { "PTP Time Source",               "ptp_time_source",        FT_UINT32,   BASE_DEC | BASE_EXT_STRING, &ptp_v2_timeSource_vals_ext, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ptp_clock_identity,     { "PTP Clock Identity",            "ptp_clock_identity",     FT_EUI64,    BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ptp_port_num,           { "PTP Port Number",               "ptp_port_num",           FT_UINT32,   BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ptp_port_state,         { "PTP Port State",                "ptp_port_state",         FT_UINT32,   BASE_DEC | BASE_EXT_STRING, &ptp_v2_portState_vals_ext, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ptp_delay_mechanism,    { "PTP Delay Mechanism",           "ptp_delay_mechanism",    FT_UINT32,   BASE_DEC, VALS(ptp_v2_delayMechanism_vals), 0x0, NULL, HFILL } },

  { ERF_META_TAG_clk_port_proto,         { "Clock Input Port Protocol",     "clk_port_proto",         FT_UINT32,   BASE_DEC, VALS(erf_clk_port_proto), 0x0, NULL, HFILL } },

  { ERF_META_TAG_ntp_status,             { "NTP Status",                    "ntp_status",             FT_UINT32,   BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ntp_stratum,            { "NTP Stratum",                   "ntp_stratum",            FT_UINT32,   BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ntp_rootdelay,          { "NTP Root Delay",                "ntp_root_delay",         FT_INT32,    BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ntp_rootdisp,           { "NTP Root Dispersion",           "ntp_root_dispersion",    FT_UINT32,   BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ntp_offset,             { "NTP Offset",                    "ntp_offset",             FT_INT32,    BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ntp_frequency,          { "NTP Frequency",                 "ntp_frequency",          FT_INT32,    BASE_DEC|BASE_UNIT_STRING, UNS(&units_hz), 0x0, NULL, HFILL } },
  { ERF_META_TAG_ntp_sys_jitter,         { "NTP System Jitter",             "ntp_sys_jitter",         FT_UINT32,   BASE_DEC,          NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ntp_peer_remote,        { "NTP Peer Remote",               "ntp_peer_remote",        FT_STRING,   BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_TAG_ntp_peer_refid,         { "NTP Peer Refid",                "ntp_peer_refid",         FT_STRING,   BASE_NONE,         NULL, 0x0, NULL, HFILL } }
};

/* Sections are also tags, but enumerate them separately to make logic simpler */
static const erf_meta_hf_template_t erf_meta_sections[] = {
  /*
   * Some tags (such as generation time) can appear before the first section,
   * we group these together into a fake section for consistency.
   */
  { ERF_META_SECTION_NONE,          { "No Section",                         "section_none",      FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_SECTION_UNKNOWN,       { "Unknown Section",                    "section_unknown",   FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },

  { ERF_META_SECTION_CAPTURE,       { "Capture Section",                    "section_capture",   FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_SECTION_HOST,          { "Host Section",                       "section_host",      FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_SECTION_MODULE,        { "Module Section",                     "section_module",    FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_SECTION_INTERFACE,     { "Interface Section",                  "section_interface", FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_SECTION_FLOW,          { "Flow Section",                       "section_flow",      FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_SECTION_STATS,         { "Statistics Section",                 "section_stats",     FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_SECTION_INFO,          { "Information Section",                "section_info",      FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_SECTION_CONTEXT,       { "Context Section",                    "section_context",   FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_SECTION_STREAM,        { "Stream Section",                     "section_stream",    FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_SECTION_TRANSFORM,     { "Transform Section",                  "section_transform", FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_SECTION_DNS,           { "DNS Section",                        "section_dns",       FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_SECTION_SOURCE,        { "Source Section",                     "section_source",    FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_SECTION_NETWORK,       { "Network Section",                    "section_network",   FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_SECTION_ENDPOINT,      { "Endpoint Section",                   "section_endpoint",  FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_SECTION_INPUT,         { "Input Section",                      "section_input",     FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } },
  { ERF_META_SECTION_OUTPUT,        { "Output Section",                     "section_output",    FT_NONE,          BASE_NONE,         NULL, 0x0, NULL, HFILL } }
};

static int erf_type_has_color(unsigned int type) {
  switch (type & ERF_HDR_TYPE_MASK) {
  case ERF_TYPE_COLOR_HDLC_POS:
  case ERF_TYPE_COLOR_ETH:
  case ERF_TYPE_COLOR_HASH_POS:
  case ERF_TYPE_COLOR_HASH_ETH:
  case ERF_TYPE_DSM_COLOR_HDLC_POS:
  case ERF_TYPE_DSM_COLOR_ETH:
  case ERF_TYPE_COLOR_MC_HDLC_POS:
    return 1;
  }
  return 0;
}

static erf_meta_tag_info_ex_t* erf_meta_tag_info_ex_new(wmem_allocator_t *allocator) {
  size_t i = 0;
  erf_meta_tag_info_ex_t *extra = wmem_new0(allocator, erf_meta_tag_info_ex_t);

  extra->ett_value = -1;
  for (i = 0; i < array_length(extra->hf_values); i++) {
    extra->hf_values[i] = -1;
  }

  return extra;
}

static erf_meta_tag_info_t* erf_meta_tag_info_new(wmem_allocator_t *allocator, const erf_meta_hf_template_t *section, const erf_meta_hf_template_t *tag) {
  erf_meta_tag_info_t *tag_info = wmem_new0(allocator, erf_meta_tag_info_t);

  tag_info->code = tag->code;
  tag_info->section = section->code;
  tag_info->ett = -1;
  tag_info->hf_value = -1;
  tag_info->tag_template = tag;
  tag_info->section_template = section;
  tag_info->extra = NULL;

  return tag_info;
}

static erf_meta_tag_info_t*
init_section_fields(wmem_array_t *hfri_table, wmem_array_t *ett_table, const erf_meta_hf_template_t *section)
{
  erf_meta_tag_info_t *section_info;
  int                 *ett_tmp; /* wmem_array_append needs actual memory to copy from */
  hf_register_info     hfri_tmp[] = {
    { NULL, { "Section ID", NULL, FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }}, /* Section ID */
    { NULL, { "Section Length", NULL, FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},  /* Section Length */
    { NULL, { "Reserved", NULL, FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }} /* Reserved extra bytes */
  };

  section_info = erf_meta_tag_info_new(wmem_epan_scope(), section, section /*Needed for lookup commonality*/);
  section_info->extra = erf_meta_tag_info_ex_new(wmem_epan_scope());

  /*Can't use the generic functions here because directly at section level*/
  hfri_tmp[0].hfinfo.abbrev = wmem_strconcat(wmem_epan_scope(), "erf.meta.", section->hfinfo.abbrev, ".section_id", NULL);
  hfri_tmp[0].p_id = &section_info->hf_value;
  hfri_tmp[1].hfinfo.abbrev = wmem_strconcat(wmem_epan_scope(), "erf.meta.", section->hfinfo.abbrev, ".section_len", NULL);
  hfri_tmp[1].p_id = &section_info->extra->hf_values[0];
  hfri_tmp[2].hfinfo.abbrev = wmem_strconcat(wmem_epan_scope(), "erf.meta.", section->hfinfo.abbrev, ".section_hdr_rsvd", NULL);
  hfri_tmp[2].p_id = &section_info->extra->hf_values[1];

  /* Add hf_register_info, ett entries */
  wmem_array_append(hfri_table, hfri_tmp, array_length(hfri_tmp));
  ett_tmp = &section_info->ett;
  wmem_array_append(ett_table, &ett_tmp, 1);
  ett_tmp = &section_info->extra->ett_value;
  wmem_array_append(ett_table, &ett_tmp, 1);

  return section_info;
}

static erf_meta_tag_info_t*
init_tag_value_field(wmem_array_t *hfri_table, erf_meta_tag_info_t *tag_info)
{
  hf_register_info     hfri_tmp = { NULL, { NULL, NULL, FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }}; /* Value, will be filled from template */

  /* Add value field */
  hfri_tmp.p_id = &tag_info->hf_value;
  hfri_tmp.hfinfo = tag_info->tag_template->hfinfo;
  hfri_tmp.hfinfo.abbrev = wmem_strconcat(wmem_epan_scope(), "erf.meta.", tag_info->section_template->hfinfo.abbrev, ".", tag_info->tag_template->hfinfo.abbrev, NULL);
  wmem_array_append_one(hfri_table, hfri_tmp);

  return tag_info;
}

static erf_meta_tag_info_t*
init_tag_value_subfields(wmem_array_t *hfri_table, erf_meta_tag_info_t *tag_info, const header_field_info *extra_fields, int extra_fields_len)
{
  int                  i = 0;
  hf_register_info     hfri_tmp = { NULL, { NULL, NULL, FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }}; /* Value, will be filled from template */

  if (extra_fields) {
    tag_info->extra = erf_meta_tag_info_ex_new(wmem_epan_scope());
    for (i = 0; i < extra_fields_len; i++) {
      /* Add value subfield */
      hfri_tmp.p_id = &tag_info->extra->hf_values[i];
      hfri_tmp.hfinfo = extra_fields[i];
      hfri_tmp.hfinfo.abbrev = wmem_strconcat(wmem_epan_scope(), "erf.meta.", tag_info->section_template->hfinfo.abbrev, ".", tag_info->tag_template->hfinfo.abbrev, ".", extra_fields[i].abbrev, NULL);
      wmem_array_append_one(hfri_table, hfri_tmp);
    }
  }

  return tag_info;
}

static erf_meta_tag_info_t*
init_ext_hdrs_tag_value_subfields(wmem_array_t *hfri_table, erf_meta_tag_info_t *tag_info)
{
  size_t               i = 0;
  size_t               num_known_ext_hdrs = array_length(ehdr_type_vals) -1 /*null terminated*/;
  hf_register_info     hfri_tmp = { NULL, { NULL, NULL, FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL } }; /* Value, will be filled from template */

  DISSECTOR_ASSERT(array_length(ehdr_type_vals_short) > num_known_ext_hdrs);
  /* XXX: this currently supports only up to 27 known extension headers */
  DISSECTOR_ASSERT(ERF_HF_VALUES_PER_TAG > num_known_ext_hdrs - 4); /* -1 sentinel terminated */
  /* Use the first 4 hf_values for 32-bit subtree */
  init_tag_value_subfields(hfri_table, tag_info, erf_ext_hdr_items, array_length(erf_ext_hdr_items));
  DISSECTOR_ASSERT(tag_info->extra);

  /*Fill in the rest of the remaining 27 entries with any known tag entries values */
  for (i = 0; i < num_known_ext_hdrs; i++) {
    /* Add value subfield */
    hfri_tmp.p_id = &tag_info->extra->hf_values[4+i];
    hfri_tmp.hfinfo.bitmask = (uint64_t)1 << ehdr_type_vals[i].value;
    hfri_tmp.hfinfo.name = ehdr_type_vals[i].strptr;
    hfri_tmp.hfinfo.abbrev = wmem_strconcat(wmem_epan_scope(),
      "erf.meta.", tag_info->section_template->hfinfo.abbrev, ".", tag_info->tag_template->hfinfo.abbrev, ".", ehdr_type_vals_short[i].strptr, NULL);
    wmem_array_append_one(hfri_table, hfri_tmp);
  }

  return tag_info;
}

static erf_meta_tag_info_t*
init_ns_addr_tag_value_fields(wmem_array_t *hfri_table, erf_meta_tag_info_t *tag_info)
{
  header_field_info ns_addr_extra_fields[] = {
    { NULL, NULL, FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }, /* Address value, will be filled from template */
    { "Name", "name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }  /* Name value */
  };

  tag_info->extra = erf_meta_tag_info_ex_new(wmem_epan_scope());

  /* Set address subfield type, etc. from template based on address type */
  ns_addr_extra_fields[0] = tag_info->tag_template->hfinfo;
  ns_addr_extra_fields[0].name = "Address";
  ns_addr_extra_fields[0].abbrev = "addr";
  /* Don't need a main value as we just use a text subtree */
  /* Init subfields */
  init_tag_value_subfields(hfri_table, tag_info, ns_addr_extra_fields, array_length(ns_addr_extra_fields));

  return tag_info;
}

static erf_meta_tag_info_t*
init_tag_fields(wmem_array_t *hfri_table, wmem_array_t *ett_table, const erf_meta_hf_template_t *section, const erf_meta_hf_template_t *tag)
{
  erf_meta_tag_info_t *tag_info;
  int                 *ett_tmp; /* wmem_array_append needs actual memory to copy from */

  tag_info = erf_meta_tag_info_new(wmem_epan_scope(), section, tag);

  /*Tags with subfields (only)*/
  /*XXX: Can't currently easily be described in the template because
   * there is curently no dissect bitfield equivalent that supports arbitrary
   * types/offsets*/
  switch (tag->code) {
  /*Special case: parent_section*/
  case ERF_META_TAG_parent_section:
    /*Don't need a main value*/
    /*Init subfields*/
    init_tag_value_subfields(hfri_table, tag_info, erf_parent_section, array_length(erf_parent_section));
    break;

  /* Special case: name entry */
  case ERF_META_TAG_ns_dns_ipv4:
  case ERF_META_TAG_ns_dns_ipv6:
  case ERF_META_TAG_ns_host_ipv4:
  case ERF_META_TAG_ns_host_ipv6:
  case ERF_META_TAG_ns_host_mac:
  case ERF_META_TAG_ns_host_eui:
  case ERF_META_TAG_ns_host_wwn:
  case ERF_META_TAG_ns_host_ib_gid:
  case ERF_META_TAG_ns_host_ib_lid:
  case ERF_META_TAG_ns_host_fc_id:
    init_ns_addr_tag_value_fields(hfri_table, tag_info);
    break;

  /* Usual case: init single field template */
  default:
    init_tag_value_field(hfri_table, tag_info);
    break;
  }

  /*Tags that need additional subfields*/
  switch (tag->code) {
  /*Special case: bitfields*/
  /*TODO: Maybe put extra_fields in template with dissect callback?*/
  case ERF_META_TAG_tunneling_mode:
    init_tag_value_subfields(hfri_table, tag_info, erf_tunneling_modes, array_length(erf_tunneling_modes));
    break;
  case ERF_META_TAG_if_link_status:
    init_tag_value_subfields(hfri_table, tag_info, erf_link_status, array_length(erf_link_status));
    break;
  case ERF_META_TAG_ptp_time_properties:
    init_tag_value_subfields(hfri_table, tag_info, erf_ptp_time_properties_flags, array_length(erf_ptp_time_properties_flags));
    break;
  case ERF_META_TAG_ptp_gm_clock_quality:
    init_tag_value_subfields(hfri_table, tag_info, erf_ptp_clock_quality, array_length(erf_ptp_clock_quality));
    break;
    case ERF_META_TAG_stream_flags:
    init_tag_value_subfields(hfri_table, tag_info, erf_stream_flags, array_length(erf_stream_flags));
    break;
  case ERF_META_TAG_smart_trunc_default:
    init_tag_value_subfields(hfri_table, tag_info, erf_smart_trunc_default_flags, array_length(erf_smart_trunc_default_flags));
    break;
  case ERF_META_TAG_ext_hdrs_added:
  case ERF_META_TAG_ext_hdrs_removed:
    init_ext_hdrs_tag_value_subfields(hfri_table, tag_info);
    break;
  }

  /* Add ett entries */
  ett_tmp = &tag_info->ett;
  wmem_array_append_one(ett_table, ett_tmp);

  return tag_info;
}

static void
init_meta_tags(void)
{
  unsigned int                  i, j    = 0;
  const erf_meta_hf_template_t *section = NULL;
  const erf_meta_hf_template_t *tag     = NULL;
  erf_meta_tag_info_t          *tag_info;
  value_string                  vs_tmp  = {0, NULL};

  erf_meta_index.tag_table      = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
  erf_meta_index.vs_list        = wmem_array_new(wmem_epan_scope(), sizeof(value_string));
  erf_meta_index.vs_abbrev_list = wmem_array_new(wmem_epan_scope(), sizeof(value_string));
  erf_meta_index.hfri           = wmem_array_new(wmem_epan_scope(), sizeof(hf_register_info));
  erf_meta_index.ett            = wmem_array_new(wmem_epan_scope(), sizeof(int*));

  /* Generate tag fields */
  for (j = 0; j < array_length(erf_meta_tags); j++) {
    tag = &erf_meta_tags[j];

    /* Generate copy of the tag for each section */
    for (i = 0; i < array_length(erf_meta_sections); i++) {
      section = &erf_meta_sections[i];
      tag_info = init_tag_fields(erf_meta_index.hfri, erf_meta_index.ett, section, tag);
      /* Add to hash table */
      wmem_map_insert(erf_meta_index.tag_table, GUINT_TO_POINTER(ERF_TAG_INFO_KEY(tag_info)), tag_info);
    }

    /* Add value string entries */
    vs_tmp.value = tag->code;
    vs_tmp.strptr = tag->hfinfo.name;
    wmem_array_append_one(erf_meta_index.vs_list, vs_tmp);
    vs_tmp.value = tag->code;
    vs_tmp.strptr = tag->hfinfo.abbrev;
    wmem_array_append_one(erf_meta_index.vs_abbrev_list, vs_tmp);
  }

  /* Generate section fields (skipping section_none and parts of section_unknown) */
  for (i = 1; i < array_length(erf_meta_sections); i++) {
    section = &erf_meta_sections[i];
    tag_info = init_section_fields(erf_meta_index.hfri, erf_meta_index.ett, section);

    if (i != 1) { /* don't add value string for unknown section as it doesn't correspond to one section type code */
      /* Add to hash table */
      wmem_map_insert(erf_meta_index.tag_table, GUINT_TO_POINTER(ERF_TAG_INFO_KEY(tag_info)), tag_info);
      /* Add value string entries */
      vs_tmp.value = section->code;
      vs_tmp.strptr = section->hfinfo.name;
      wmem_array_append_one(erf_meta_index.vs_list, vs_tmp);
      vs_tmp.value = section->code;
      vs_tmp.strptr = section->hfinfo.abbrev;
      wmem_array_append_one(erf_meta_index.vs_abbrev_list, vs_tmp);
    } else {
      /* Store section_unknown separately to simplify logic later */
      erf_meta_index.unknown_section_info = tag_info;
    }
  }

  /* Terminate value string lists with {0, NULL} */
  vs_tmp.value = 0;
  vs_tmp.strptr = NULL;
  wmem_array_append_one(erf_meta_index.vs_list, vs_tmp);
  wmem_array_append_one(erf_meta_index.vs_abbrev_list, vs_tmp);
  /* TODO: try value_string_ext, requires sorting first */
}

static inline value_string *erf_to_value_string(wmem_array_t *array) {
  return (value_string *)wmem_array_get_raw(array);
}

static unsigned erf_anchor_key_hash(const void *key) {
  const erf_anchor_key_t *anchor_key = (const erf_anchor_key_t*) key;

  return ((uint32_t)anchor_key->host_id ^ (uint32_t)anchor_key->anchor_id);

}

static gboolean erf_anchor_key_equal(const void *a, const void *b) {
  const erf_anchor_key_t *anchor_key_a = (const erf_anchor_key_t*) a ;
  const erf_anchor_key_t *anchor_key_b = (const erf_anchor_key_t*) b ;

  return (anchor_key_a->host_id) == (anchor_key_b->host_id) &&
    (anchor_key_a->anchor_id & ERF_EXT_HDR_TYPE_ANCHOR_ID) == (anchor_key_b->anchor_id & ERF_EXT_HDR_TYPE_ANCHOR_ID);
}

static void erf_host_anchor_info_insert(packet_info *pinfo, uint64_t host_id, uint64_t anchor_id, uint8_t flags _U_) {
  erf_host_anchor_info_t *anchor_info;
  erf_anchor_key_t key = {host_id, anchor_id};
  erf_anchored_info_t *anchored_info;

  anchor_info = (erf_host_anchor_info_t*)wmem_map_lookup(erf_state.host_anchor_map, &key);

  if(!anchor_info) {
    erf_anchor_key_t *key_ptr = wmem_new(wmem_file_scope(), erf_anchor_key_t);
    *key_ptr = key;

    anchor_info = (erf_host_anchor_info_t*) wmem_new(wmem_file_scope(), erf_host_anchor_info_t);
    anchor_info->anchored_tree = wmem_tree_new(wmem_file_scope());
    anchor_info->anchored_list = wmem_list_new(wmem_file_scope());

    wmem_map_insert(erf_state.host_anchor_map, key_ptr, anchor_info);
  }

  /* Information about this frame associated with the Anchor ID */
  anchored_info = (erf_anchored_info_t*)wmem_tree_lookup32(anchor_info->anchored_tree, pinfo->num);
  if(!anchored_info) {
    /* anchored_info not found */
    anchored_info = (erf_anchored_info_t*)wmem_new(wmem_file_scope(), erf_anchored_info_t);
    anchored_info->frame_num = pinfo->num;

    wmem_list_append(anchor_info->anchored_list, anchored_info);
    wmem_tree_insert32(anchor_info->anchored_tree, pinfo->num, anchored_info);
  }
  else {
    return;
  }
}


static int
erf_source_append(uint64_t host_id, uint8_t source_id, uint32_t num)
{
  erf_source_info_t *source_info;
  uint64_t           source_key = ERF_SOURCE_KEY(host_id, source_id);

  source_info = (erf_source_info_t*) wmem_map_lookup(erf_state.source_map, &source_key);

  if (!source_info) {
    uint64_t *source_key_ptr = wmem_new(wmem_file_scope(), uint64_t);
    *source_key_ptr = source_key;

    source_info = (erf_source_info_t*) wmem_new(wmem_file_scope(), erf_source_info_t);
    source_info->meta_tree = wmem_tree_new(wmem_file_scope());
    source_info->meta_list = wmem_list_new(wmem_file_scope());

    wmem_map_insert(erf_state.source_map, source_key_ptr, source_info);
  }

  /* Add the frame to the list for that source */
  wmem_list_append(source_info->meta_list, GUINT_TO_POINTER(num));
  /*
   * XXX: This assumes we are inserting fd_num in order, which we are as we use
   * PINFO_FD_VISITED in caller.
   */
  wmem_tree_insert32(source_info->meta_tree, num, wmem_list_tail(source_info->meta_list));

  return 0;
}

static uint32_t
erf_source_find_closest(uint64_t host_id, uint8_t source_id, uint32_t fnum, uint32_t *fnum_next_ptr) {
  wmem_list_frame_t  *list_frame      = NULL;
  wmem_list_frame_t  *list_frame_prev = NULL;
  erf_source_info_t  *source_info     = NULL;
  uint64_t            source_key      = ERF_SOURCE_KEY(host_id, source_id);
  uint32_t            fnum_prev       = UINT32_MAX;
  uint32_t            fnum_next       = UINT32_MAX;

  source_info = (erf_source_info_t*) wmem_map_lookup(erf_state.source_map, &source_key);

  if (source_info) {
    list_frame = (wmem_list_frame_t*) wmem_tree_lookup32_le(source_info->meta_tree, fnum);

    if (list_frame) {
      fnum_prev = GPOINTER_TO_UINT(wmem_list_frame_data(list_frame));
      /* If looking at a metadata record, get the real previous meta frame */
      if (fnum_prev == fnum) {
        list_frame_prev = wmem_list_frame_prev(list_frame);
        fnum_prev = list_frame_prev ? GPOINTER_TO_UINT(wmem_list_frame_data(list_frame_prev)) : UINT32_MAX;
      }

      list_frame = wmem_list_frame_next(list_frame);
      fnum_next = list_frame ? GPOINTER_TO_UINT(wmem_list_frame_data(list_frame)) : UINT32_MAX;
    } else {
      /*
       * XXX: Edge case: still need the first meta record to find the next one at the
       * beginning of the file.
       */
      list_frame = wmem_list_head(source_info->meta_list);
      fnum_next = list_frame ? GPOINTER_TO_UINT(wmem_list_frame_data(list_frame)) : UINT32_MAX;
      fnum_prev = UINT32_MAX;
    }
  }

  if (fnum_next_ptr)
    *fnum_next_ptr = fnum_next;

  return fnum_prev;
}

/* Copy of atm_guess_traffic_type from atm.c in /wiretap */
static void
erf_atm_guess_lane_type(tvbuff_t *tvb, int offset, unsigned len,
    struct atm_phdr *atm_info)
{
  if (len >= 2) {
    if (tvb_get_ntohs(tvb, offset) == 0xFF00) {
      /*
       * Looks like LE Control traffic.
       */
      atm_info->subtype = TRAF_ST_LANE_LE_CTRL;
    } else {
      /*
       * XXX - Ethernet, or Token Ring?
       * Assume Ethernet for now; if we see earlier
       * LANE traffic, we may be able to figure out
       * the traffic type from that, but there may
       * still be situations where the user has to
       * tell us.
       */
      atm_info->subtype = TRAF_ST_LANE_802_3;
    }
  }
}

static void
erf_atm_guess_traffic_type(tvbuff_t *tvb, int offset, unsigned len,
    struct atm_phdr *atm_info)
{
  /*
   * Start out assuming nothing other than that it's AAL5.
   */
  atm_info->aal     = AAL_5;
  atm_info->type    = TRAF_UNKNOWN;
  atm_info->subtype = TRAF_ST_UNKNOWN;

  if (atm_info->vpi == 0) {
    /*
     * Traffic on some PVCs with a VPI of 0 and certain
     * VCIs is of particular types.
     */
    switch (atm_info->vci) {

    case 5:
      /*
       * Signalling AAL.
       */
      atm_info->aal = AAL_SIGNALLING;
      return;

    case 16:
      /*
       * ILMI.
       */
      atm_info->type = TRAF_ILMI;
      return;
    }
  }

  /*
   * OK, we can't tell what it is based on the VPI/VCI; try
   * guessing based on the contents, if we have enough data
   * to guess.
   */

  if (len >= 3) {
    uint8_t mtp3b;
    if (tvb_get_ntoh24(tvb, offset) == 0xAAAA03) {
      /*
       * Looks like a SNAP header; assume it's LLC
       * multiplexed RFC 1483 traffic.
       */
      atm_info->type = TRAF_LLCMX;
    } else if ((atm_info->aal5t_len &&
                atm_info->aal5t_len < 16) || len<16) {
      /*
       * As this cannot be a LANE Ethernet frame (less
       * than 2 bytes of LANE header + 14 bytes of
       * Ethernet header) we can try it as a SSCOP frame.
       */
      atm_info->aal = AAL_SIGNALLING;
    } else if (((mtp3b = tvb_get_uint8(tvb, offset)) == 0x83) || (mtp3b == 0x81)) {
      /*
       * MTP3b headers often encapsulate
       * a SCCP or MTN in the 3G network.
       * This should cause 0x83 or 0x81
       * in the first byte.
       */
      atm_info->aal = AAL_SIGNALLING;
    } else {
      /*
       * Assume it's LANE.
       */
      atm_info->type = TRAF_LANE;
      erf_atm_guess_lane_type(tvb, offset, len, atm_info);
    }
  } else {
    /*
     * Not only VCI 5 is used for signaling. It might be
     * one of these VCIs.
     */
    atm_info->aal = AAL_SIGNALLING;
  }
}

static void
dissect_classification_ex_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree, int idx)
{
  proto_item *flags_item;
  proto_tree *flags_tree;
  uint64_t    hdr   = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;
  uint32_t    value = ((uint32_t)(hdr >> 32)) & EHDR_CLASS_FLAGS_MASK;

  flags_item = proto_tree_add_uint(tree, hf_erf_ehdr_class_flags, tvb, 0, 0, value);
  flags_tree = proto_item_add_subtree(flags_item, ett_erf_flags);

  proto_tree_add_uint(flags_tree, hf_erf_ehdr_class_flags_sh,   tvb, 0, 0, value);
  proto_tree_add_uint(flags_tree, hf_erf_ehdr_class_flags_shm,  tvb, 0, 0, value);
  proto_tree_add_uint(flags_tree, hf_erf_ehdr_class_flags_res1, tvb, 0, 0, value);
  proto_tree_add_uint(flags_tree, hf_erf_ehdr_class_flags_user, tvb, 0, 0, value);
  proto_tree_add_uint(flags_tree, hf_erf_ehdr_class_flags_res2, tvb, 0, 0, value);
  proto_tree_add_uint(flags_tree, hf_erf_ehdr_class_flags_drop, tvb, 0, 0, value);
  proto_tree_add_uint(flags_tree, hf_erf_ehdr_class_flags_str,  tvb, 0, 0, value);

  proto_tree_add_uint(tree, hf_erf_ehdr_class_seqnum, tvb, 0, 0, (uint32_t)hdr);
}

static void
dissect_intercept_ex_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree, int idx)
{
  uint64_t    hdr = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;

  proto_tree_add_uint(tree, hf_erf_ehdr_int_res1, tvb, 0, 0, (uint8_t)((hdr >> 48) & 0xFF));
  proto_tree_add_uint(tree, hf_erf_ehdr_int_id, tvb, 0, 0, (uint16_t)((hdr >> 32 ) & 0xFFFF));
  proto_tree_add_uint(tree, hf_erf_ehdr_int_res2, tvb, 0, 0, (uint32_t)hdr);
}

static void
dissect_raw_link_ex_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree, int idx)
{
  uint64_t    hdr = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;

  proto_tree_add_uint(tree, hf_erf_ehdr_raw_link_res ,    tvb, 0, 0, (uint32_t)((hdr >> 32) & 0xFFFFFF));
  proto_tree_add_uint(tree, hf_erf_ehdr_raw_link_seqnum , tvb, 0, 0, (uint32_t)((hdr >> 16) & 0xffff));
  proto_tree_add_uint(tree, hf_erf_ehdr_raw_link_rate,    tvb, 0, 0, (uint32_t)((hdr >> 8) & 0x00ff));
  proto_tree_add_uint(tree, hf_erf_ehdr_raw_link_type,    tvb, 0, 0, (uint32_t)(hdr & 0x00ff));
}

static void
dissect_bfs_ex_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree, int idx)
{
  uint64_t    hdr = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;

  proto_tree_add_uint(tree, hf_erf_ehdr_bfs_hash, tvb, 0, 0, (uint32_t)((hdr >> 48) & 0xFF));
  proto_tree_add_uint(tree, hf_erf_ehdr_bfs_color, tvb, 0, 0, (uint32_t)((hdr >> 32) & 0xFFFF));
  proto_tree_add_uint(tree, hf_erf_ehdr_bfs_raw_hash, tvb, 0, 0, (uint32_t)(hdr & 0xFFFFFFFF));
}

static int
channelised_fill_sdh_g707_format(sdh_g707_format_t* in_fmt, uint16_t bit_flds, uint8_t vc_size, uint8_t rate)
{
  int i = 0; /* i = 3 --> ITU-T letter #D - index of AUG-16
              * i = 2 --> ITU-T letter #C - index of AUG-4,
              * i = 1 --> ITU-T letter #B - index of AUG-1
              * i = 0 --> ITU-T letter #A - index of AU3*/

  if ( (0 == vc_size) || (vc_size > DECHAN_MAX_VC_SIZE) || (rate > DECHAN_MAX_LINE_RATE) )
  {
    /* unknown / unused / invalid container size or invalid line rate */
    in_fmt->m_vc_size = 0;
    in_fmt->m_sdh_line_rate = 0;
    memset(&(in_fmt->m_vc_index_array[0]), 0x00, DECHAN_MAX_AUG_INDEX);
    return -1;
  }

  in_fmt->m_vc_size = vc_size;
  in_fmt->m_sdh_line_rate = rate;
  memset(&(in_fmt->m_vc_index_array[0]), 0xff, DECHAN_MAX_AUG_INDEX);

  /* for STM64 traffic,from #D and so on .. */
    for (i = (rate - 2); i >= 0; i--)
  {
    uint8_t aug_n_index = 0;

    /*if AUG-n is bigger than vc-size*/
    if ( i >= (vc_size - 1))
    {
      /* check the value in bit flds */
      aug_n_index = ((bit_flds >> (2 *i))& 0x3) +1;
    }
    else
    {
      aug_n_index = 0;
    }
    in_fmt->m_vc_index_array[i] = aug_n_index;
  }
  return 0;
}

static void
channelised_fill_vc_id_string(wmem_strbuf_t* out_string, sdh_g707_format_t* in_fmt)
{
  int      i;
  bool is_printed  = false;

  static const char* g_vc_size_strings[] = {
    "unknown",  /*0x0*/
    "VC3",      /*0x1*/
    "VC4",      /*0x2*/
    "VC4-4c",   /*0x3*/
    "VC4-16c",  /*0x4*/
    "VC4-64c",  /*0x5*/};

  wmem_strbuf_truncate(out_string, 0);

  if ( (in_fmt->m_vc_size > DECHAN_MAX_VC_SIZE) || (in_fmt->m_sdh_line_rate > DECHAN_MAX_LINE_RATE) )
  {
    wmem_strbuf_append_printf(out_string, "Malformed");
    return;
  }

  wmem_strbuf_append_printf(out_string, "%s(",
                            (in_fmt->m_vc_size < array_length(g_vc_size_strings)) ?
                            g_vc_size_strings[in_fmt->m_vc_size] : g_vc_size_strings[0] );

  if (in_fmt->m_sdh_line_rate <= 0 )
  {
    /* line rate is not given */
    for (i = (DECHAN_MAX_AUG_INDEX -1); i >= 0; i--)
    {
      if ((in_fmt->m_vc_index_array[i] > 0) || (is_printed) )
      {
        wmem_strbuf_append_printf(out_string, "%s%d",
                                  ((is_printed)?", ":""),
                                  in_fmt->m_vc_index_array[i]);
        is_printed = true;
      }
    }

  }
  else
  {
    for (i = in_fmt->m_sdh_line_rate - 2; i >= 0; i--)
    {
      wmem_strbuf_append_printf(out_string, "%s%d",
                                ((is_printed)?", ":""),
                                in_fmt->m_vc_index_array[i]);
      is_printed = true;
    }
  }
  if ( ! is_printed )
  {
    /* Not printed . possibly it's a ocXc packet with (0,0,0...) */
    for ( i =0; i < in_fmt->m_vc_size - 2; i++)
    {
      wmem_strbuf_append_printf(out_string, "%s0",
                                ((is_printed)?", ":""));
      is_printed = true;
    }
  }
  wmem_strbuf_append_c(out_string, ')');
  return;
}

static void
dissect_channelised_ex_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree, int idx)
{
  uint64_t           hdr              = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;
  uint8_t            vc_id            = (uint8_t)((hdr >> 24) & 0xFF);
  uint8_t            vc_size          = (uint8_t)((hdr >> 16) & 0xFF);
  uint8_t            line_rate        = (uint8_t)((hdr >> 8) & 0xFF);
  sdh_g707_format_t  g707_format;
  wmem_strbuf_t     *vc_id_string = wmem_strbuf_create(pinfo->pool);

  channelised_fill_sdh_g707_format(&g707_format, vc_id, vc_size, line_rate);
  channelised_fill_vc_id_string(vc_id_string, &g707_format);

  proto_tree_add_boolean(tree, hf_erf_ehdr_chan_morebits, tvb, 0, 0, (uint8_t)((hdr >> 63) & 0x1));
  proto_tree_add_boolean(tree, hf_erf_ehdr_chan_morefrag, tvb, 0, 0, (uint8_t)((hdr >> 55) & 0x1));
  proto_tree_add_uint(tree, hf_erf_ehdr_chan_seqnum, tvb, 0, 0, (uint16_t)((hdr >> 40) & 0x7FFF));
  proto_tree_add_uint(tree, hf_erf_ehdr_chan_res, tvb, 0, 0, (uint8_t)((hdr >> 32) & 0xFF));
  proto_tree_add_uint_format_value(tree, hf_erf_ehdr_chan_virt_container_id, tvb, 0, 0, vc_id,
                                   "0x%.2x (g.707: %s)", vc_id, wmem_strbuf_get_str(vc_id_string));
  proto_tree_add_uint(tree, hf_erf_ehdr_chan_assoc_virt_container_size, tvb, 0, 0, vc_size);
  proto_tree_add_uint(tree, hf_erf_ehdr_chan_rate, tvb, 0, 0, line_rate);
  proto_tree_add_uint(tree, hf_erf_ehdr_chan_type, tvb, 0, 0, (uint8_t)((hdr >> 0) & 0xFF));
}

static void
dissect_signature_ex_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int idx)
{
  uint64_t    hdr = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;

  proto_tree_add_uint(tree, hf_erf_ehdr_signature_payload_hash, tvb, 0, 0, (uint32_t)((hdr >> 32) & 0xFFFFFF));
  proto_tree_add_uint(tree, hf_erf_ehdr_signature_color,        tvb, 0, 0, (uint8_t)((hdr >> 24) & 0xFF));
  proto_tree_add_uint(tree, hf_erf_ehdr_signature_flow_hash,    tvb, 0, 0, (uint32_t)(hdr & 0xFFFFFF));
}

static void
dissect_host_id_ex_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int idx)
{
  uint64_t    hdr = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;

  proto_tree_add_uint(tree, hf_erf_ehdr_host_id_sourceid, tvb, 0, 0, (uint8_t)((hdr >> 48) & 0xFF));
  proto_tree_add_uint64(tree, hf_erf_ehdr_host_id_hostid, tvb, 0, 0, (hdr & ERF_EHDR_HOST_ID_MASK));
}

static void
dissect_anchor_id_ex_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int idx)
{
  static int * const anchor_flags[] =
  {
    &hf_erf_ehdr_anchor_id_definition,
    &hf_erf_ehdr_anchor_id_reserved,
    NULL
  };

  uint64_t    hdr = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;

  proto_tree_add_bitmask_value(tree, tvb, 0, hf_erf_ehdr_anchor_id_flags, ett_erf_anchor_flags, anchor_flags, (uint8_t)(hdr >> 48) & 0xff);
  proto_tree_add_uint64(tree, hf_erf_ehdr_anchor_id_anchorid, tvb, 0, 0, (hdr & ERF_EHDR_ANCHOR_ID_MASK));
}


static void
dissect_flow_id_ex_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int idx)
{
  uint64_t    hdr = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;
  uint8_t     hash_type = (uint8_t)((hdr >> 40) & 0xFF);
  proto_item *hash_type_item;
  proto_tree *hash_type_tree;

  proto_tree_add_uint(tree, hf_erf_ehdr_flow_id_source_id,  tvb, 0, 0, (uint8_t)((hdr >> 48) & 0xFF));

  hash_type_item = proto_tree_add_uint_format_value(tree, hf_erf_ehdr_flow_id_hash_type, tvb, 0, 0, hash_type,
                                                  "0x%02x (%s%s)",
                                                  hash_type,
                                                  (hash_type & ERF_EHDR_FLOW_ID_HASH_TYPE_INNER_MASK) ? "Inner " : "",
                                                  val_to_str_const(
                                                    (hash_type & ERF_EHDR_FLOW_ID_HASH_TYPE_TYPE_MASK),
                                                    erf_hash_type,
                                                    "Unknown Type"));

  hash_type_tree = proto_item_add_subtree(hash_type_item, ett_erf_hash_type);
  proto_tree_add_uint(hash_type_tree, hf_erf_ehdr_flow_id_hash_type_type,  tvb, 0, 0, hash_type);
  proto_tree_add_uint(hash_type_tree, hf_erf_ehdr_flow_id_hash_type_inner, tvb, 0, 0, hash_type);

  proto_tree_add_uint(tree, hf_erf_ehdr_flow_id_stack_type, tvb, 0, 0, (uint8_t)((hdr >> 32) & 0xFF));
  proto_tree_add_uint(tree, hf_erf_ehdr_flow_id_flow_hash,  tvb, 0, 0, (uint32_t)(hdr & 0xFFFFFFFF));
}

static float
entropy_from_entropy_header_value(uint8_t entropy_hdr_value)
{
  /* mapping 1-255 to 0.0-8.0 */
  /*  255 is 8.0 */
  /* 1 represent any value less than 2/32 */
  /* 0 represents not calculated */
  return (float)((entropy_hdr_value == 0)?0.0f: (((float)entropy_hdr_value+1) / 32.0f));
}

static void
dissect_entropy_ex_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int idx)
{
  uint64_t    hdr = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;
  uint8_t     entropy_hdr_value = (uint8_t)((hdr >> 48) & 0xFF);
  float      entropy;
  proto_item *pi;
  proto_tree *entropy_value_tree;

  entropy = entropy_from_entropy_header_value(entropy_hdr_value);

  pi = proto_tree_add_float_format_value(tree, hf_erf_ehdr_entropy_entropy, tvb, 0, 0, entropy,
    "%.2f %s", (double) entropy, entropy == 0.0f ? "(not calculated)":"bits");
  entropy_value_tree = proto_item_add_subtree(pi, ett_erf_entropy_value);
  proto_tree_add_uint(entropy_value_tree, hf_erf_ehdr_entropy_entropy_raw, tvb, 0, 0, entropy_hdr_value);

  proto_tree_add_uint64(tree, hf_erf_ehdr_entropy_reserved, tvb, 0, 0, (hdr & 0xFFFFFFFFFFFF));
}

static uint64_t
find_host_id(packet_info *pinfo, bool *has_anchor_definition) {
  uint64_t    hdr;
  uint8_t     type;
  uint8_t     has_more = pinfo->pseudo_header->erf.phdr.type & 0x80;
  int         i = 0;
  uint64_t    host_id = ERF_META_HOST_ID_IMPLICIT;
  bool        anchor_definition = false;

  while(has_more && (i < MAX_ERF_EHDR)) {
    hdr = pinfo->pseudo_header->erf.ehdr_list[i].ehdr;
    type = (uint8_t) (hdr >> 56);

    switch (type & 0x7f) {
      case ERF_EXT_HDR_TYPE_HOST_ID:
        if (host_id == ERF_META_HOST_ID_IMPLICIT)
          host_id = hdr & ERF_EHDR_HOST_ID_MASK;
        break;
      case ERF_EXT_HDR_TYPE_ANCHOR_ID:
        if ((hdr & ERF_EHDR_ANCHOR_ID_DEFINITION_MASK))
          anchor_definition = true;
        break;
    }
    has_more = type & 0x80;
    i += 1;
  }

  if (has_anchor_definition)
    *has_anchor_definition = anchor_definition;

  return host_id;
}

static void dissect_host_anchor_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint64_t host_id, uint64_t anchor_id, uint8_t anchor _U_) {

  erf_anchor_key_t key = {host_id, anchor_id};
  erf_host_anchor_info_t *anchor_info;
  erf_anchored_info_t *anchored_info;
  wmem_list_frame_t *frame;
  wmem_list_t *frame_list;
  proto_item *pi = NULL;
  proto_tree *subtree;

  /* TODO: top level linking to most recent frame like we have for Host ID? */
  subtree = proto_tree_add_subtree_format(tree, tvb, 0, 0, ett_erf_anchor, &pi, "Host ID: 0x%012" PRIx64 ", Anchor ID: 0x%012" PRIx64, host_id & ERF_EHDR_HOST_ID_MASK, anchor_id & ERF_EHDR_ANCHOR_ID_MASK);
  proto_item_set_generated(pi);

  pi = proto_tree_add_uint64(subtree, hf_erf_anchor_hostid, tvb, 0, 0, host_id & ERF_EHDR_HOST_ID_MASK);
  proto_item_set_generated(pi);
  pi = proto_tree_add_uint64(subtree, hf_erf_anchor_anchorid, tvb, 0, 0, anchor_id & ERF_EHDR_ANCHOR_ID_MASK);
  proto_item_set_generated(pi);

  anchor_info = (erf_host_anchor_info_t*)wmem_map_lookup(erf_state.host_anchor_map, &key);

  if(!anchor_info) {
    return;
  }

  frame_list = anchor_info->anchored_list;

  /* Try to link frames */
  frame = wmem_list_head(frame_list);
  while(frame != NULL) {
    anchored_info = (erf_anchored_info_t*)wmem_list_frame_data(frame);
    if(pinfo->num != anchored_info->frame_num) {
      /* Don't list the frame itself */
      pi = proto_tree_add_uint(subtree, hf_erf_anchor_linked, tvb, 0, 0, anchored_info->frame_num);
      proto_item_set_generated(pi);
      /* XXX: Need to do this each time because pinfo is discarded. Filtering does not reset visited as it does not do a full redissect.
      We also might not catch all frames in the first pass (e.g. comment after record). */
      mark_frame_as_depended_upon(pinfo->fd, anchored_info->frame_num);
    }
    frame = wmem_list_frame_next(frame);
  }
}

static void
dissect_host_id_source_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint64_t host_id, uint8_t source_id)
{
  proto_tree *hostid_tree;
  proto_item *pi           = NULL;
  uint32_t    fnum_current = UINT32_MAX;
  uint32_t    fnum         = UINT32_MAX;
  uint32_t    fnum_next    = UINT32_MAX;

  fnum = erf_source_find_closest(host_id, source_id, pinfo->num, &fnum_next);

  if (fnum != UINT32_MAX) {
    fnum_current = fnum;
  } else {
    /* XXX: Possibly undesirable side effect: first metadata record links to next */
    fnum_current = fnum_next;
  }

  if (fnum_current != UINT32_MAX) {
    pi = proto_tree_add_uint_format(tree, hf_erf_source_current, tvb, 0, 0, fnum_current,
        "Host ID: 0x%012" PRIx64 ", Source ID: %u", host_id, source_id&0xFF);
    hostid_tree = proto_item_add_subtree(pi, ett_erf_source);
  } else {
    /* If we have no frame number to link against, just add a static subtree */
    hostid_tree = proto_tree_add_subtree_format(tree, tvb, 0, 0, ett_erf_source, &pi,
        "Host ID: 0x%012" PRIx64 ", Source ID: %u", host_id, source_id&0xFF);
  }
  proto_item_set_generated(pi);

  pi = proto_tree_add_uint64(hostid_tree, hf_erf_hostid, tvb, 0, 0, host_id);
  proto_item_set_generated(pi);
  pi = proto_tree_add_uint(hostid_tree, hf_erf_sourceid, tvb, 0, 0, source_id);
  proto_item_set_generated(pi);

  if (fnum_next != UINT32_MAX) {
    pi = proto_tree_add_uint(hostid_tree, hf_erf_source_next, tvb, 0, 0, fnum_next);
    proto_item_set_generated(pi);
    /* XXX: Save the surrounding nearest periodic records when we do a filtered save so we keep native ERF metadata */
    mark_frame_as_depended_upon(pinfo->fd, fnum_next);
  }
  if (fnum != UINT32_MAX) {
    pi = proto_tree_add_uint(hostid_tree, hf_erf_source_prev, tvb, 0, 0, fnum);
    proto_item_set_generated(pi);
    mark_frame_as_depended_upon(pinfo->fd, fnum);
  }
}

static void
dissect_unknown_ex_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree, int idx)
{
  uint64_t    hdr = pinfo->pseudo_header->erf.ehdr_list[idx].ehdr;

  proto_tree_add_uint64(tree, hf_erf_ehdr_unk, tvb, 0, 0, hdr);
}

static void
dissect_mc_hdlc_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree)
{
  proto_item *mc_hdlc_item;
  proto_tree *mc_hdlc_tree;
  uint32_t    mc_hdlc;
  proto_item *pi;

  /* Multi Channel HDLC Header */
  mc_hdlc_item = proto_tree_add_uint(tree, hf_erf_mc_hdlc, tvb, 0, 0, pinfo->pseudo_header->erf.subhdr.mc_hdr);
  mc_hdlc_tree = proto_item_add_subtree(mc_hdlc_item, ett_erf_mc_hdlc);
  mc_hdlc = pinfo->pseudo_header->erf.subhdr.mc_hdr;

  proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_cn, tvb, 0, 0,  mc_hdlc);
  proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_res1, tvb, 0, 0,  mc_hdlc);
  proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_res2, tvb, 0, 0,  mc_hdlc);
  pi=proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_fcse, tvb, 0, 0,  mc_hdlc);
  if (mc_hdlc & MC_HDLC_FCSE_MASK)
    expert_add_info(pinfo, pi, &ei_erf_mc_hdlc_checksum_error);

  pi=proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_sre,  tvb, 0, 0,  mc_hdlc);
  if (mc_hdlc & MC_HDLC_SRE_MASK)
    expert_add_info(pinfo, pi, &ei_erf_mc_hdlc_short_error);

  pi=proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_lre,  tvb, 0, 0,  mc_hdlc);
  if (mc_hdlc & MC_HDLC_LRE_MASK)
    expert_add_info(pinfo, pi, &ei_erf_mc_hdlc_long_error);

  pi=proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_afe,  tvb, 0, 0,  mc_hdlc);
  if (mc_hdlc & MC_HDLC_AFE_MASK)
    expert_add_info(pinfo, pi, &ei_erf_mc_hdlc_abort_error);

  pi=proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_oe,   tvb, 0, 0,  mc_hdlc);
  if (mc_hdlc & MC_HDLC_OE_MASK)
    expert_add_info(pinfo, pi, &ei_erf_mc_hdlc_octet_error);

  pi=proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_lbe,  tvb, 0, 0,  mc_hdlc);
  if (mc_hdlc & MC_HDLC_LBE_MASK)
    expert_add_info(pinfo, pi, &ei_erf_mc_hdlc_lost_byte_error);

  proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_first, tvb, 0, 0,  mc_hdlc);
  proto_tree_add_uint(mc_hdlc_tree, hf_erf_mc_hdlc_res3,  tvb, 0, 0,  mc_hdlc);
}

static void
dissect_mc_raw_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree)
{
  proto_item *mc_raw_item;
  proto_tree *mc_raw_tree;
  uint32_t    mc_raw;

  /* Multi Channel RAW Header */
  mc_raw_item = proto_tree_add_uint(tree, hf_erf_mc_raw, tvb, 0, 0, pinfo->pseudo_header->erf.subhdr.mc_hdr);
  mc_raw_tree = proto_item_add_subtree(mc_raw_item, ett_erf_mc_raw);
  mc_raw = pinfo->pseudo_header->erf.subhdr.mc_hdr;

  proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_int,   tvb, 0, 0, mc_raw);
  proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_res1,  tvb, 0, 0, mc_raw);
  proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_sre,   tvb, 0, 0, mc_raw);
  proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_lre,   tvb, 0, 0, mc_raw);
  proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_res2,  tvb, 0, 0, mc_raw);
  proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_lbe,   tvb, 0, 0, mc_raw);
  proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_first, tvb, 0, 0, mc_raw);
  proto_tree_add_uint(mc_raw_tree, hf_erf_mc_raw_res3,  tvb, 0, 0, mc_raw);
}

static void
dissect_mc_atm_header(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree)
{
  proto_item *mc_atm_item;
  proto_tree *mc_atm_tree;
  uint32_t    mc_atm;

  /*"Multi Channel ATM Header"*/
  mc_atm_item = proto_tree_add_uint(tree, hf_erf_mc_atm, tvb, 0, 0, pinfo->pseudo_header->erf.subhdr.mc_hdr);
  mc_atm_tree = proto_item_add_subtree(mc_atm_item, ett_erf_mc_atm);
  mc_atm = pinfo->pseudo_header->erf.subhdr.mc_hdr;

  proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_cn,      tvb, 0, 0, mc_atm);
  proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_res1,    tvb, 0, 0, mc_atm);
  proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_mul,     tvb, 0, 0, mc_atm);

  proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_port,    tvb, 0, 0, mc_atm);
  proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_res2,    tvb, 0, 0, mc_atm);

  proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_lbe,     tvb, 0, 0, mc_atm);
  proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_hec,     tvb, 0, 0, mc_atm);
  proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_crc10,   tvb, 0, 0, mc_atm);
  proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_oamcell, tvb, 0, 0, mc_atm);
  proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_first,   tvb, 0, 0, mc_atm);
  proto_tree_add_uint(mc_atm_tree, hf_erf_mc_atm_res3,    tvb, 0, 0, mc_atm);
}

static void
dissect_mc_rawlink_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *mc_rawl_item;
  proto_tree *mc_rawl_tree;
  uint32_t    mc_rawl;

  /* Multi Channel RAW Link Header */
  mc_rawl_item = proto_tree_add_uint(tree, hf_erf_mc_rawl, tvb, 0, 0, pinfo->pseudo_header->erf.subhdr.mc_hdr);
  mc_rawl_tree = proto_item_add_subtree(mc_rawl_item, ett_erf_mc_rawlink);
  mc_rawl = pinfo->pseudo_header->erf.subhdr.mc_hdr;

  proto_tree_add_uint(mc_rawl_tree, hf_erf_mc_rawl_cn,    tvb, 0, 0, mc_rawl);
  proto_tree_add_uint(mc_rawl_tree, hf_erf_mc_rawl_res1,  tvb, 0, 0, mc_rawl);
  proto_tree_add_uint(mc_rawl_tree, hf_erf_mc_rawl_lbe,   tvb, 0, 0, mc_rawl);
  proto_tree_add_uint(mc_rawl_tree, hf_erf_mc_rawl_first, tvb, 0, 0, mc_rawl);
  proto_tree_add_uint(mc_rawl_tree, hf_erf_mc_rawl_res2,  tvb, 0, 0, mc_rawl);
}

static void
dissect_mc_aal5_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *mc_aal5_item;
  proto_tree *mc_aal5_tree;
  uint32_t    mc_aal5;

  /* Multi Channel AAL5 Header */
  mc_aal5_item = proto_tree_add_uint(tree, hf_erf_mc_aal5, tvb, 0, 0, pinfo->pseudo_header->erf.subhdr.mc_hdr);
  mc_aal5_tree = proto_item_add_subtree(mc_aal5_item, ett_erf_mc_aal5);
  mc_aal5 = pinfo->pseudo_header->erf.subhdr.mc_hdr;

  proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_cn,    tvb, 0, 0, mc_aal5);
  proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_res1,  tvb, 0, 0, mc_aal5);

  proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_port,  tvb, 0, 0, mc_aal5);
  proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_crcck, tvb, 0, 0, mc_aal5);
  proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_crce,  tvb, 0, 0, mc_aal5);
  proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_lenck, tvb, 0, 0, mc_aal5);
  proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_lene,  tvb, 0, 0, mc_aal5);

  proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_res2,  tvb, 0, 0, mc_aal5);
  proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_first, tvb, 0, 0, mc_aal5);
  proto_tree_add_uint(mc_aal5_tree, hf_erf_mc_aal5_res3,  tvb, 0, 0, mc_aal5);
}

static void
dissect_mc_aal2_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *mc_aal2_item;
  proto_tree *mc_aal2_tree;
  uint32_t    mc_aal2;

  /* Multi Channel AAL2 Header */
  mc_aal2_item = proto_tree_add_uint(tree, hf_erf_mc_aal2, tvb, 0, 0, pinfo->pseudo_header->erf.subhdr.mc_hdr);
  mc_aal2_tree = proto_item_add_subtree(mc_aal2_item, ett_erf_mc_aal2);
  mc_aal2 = pinfo->pseudo_header->erf.subhdr.mc_hdr;

  proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_cn,    tvb, 0, 0, mc_aal2);
  proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_res1,  tvb, 0, 0, mc_aal2);
  proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_res2,  tvb, 0, 0, mc_aal2);

  proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_port,  tvb, 0, 0, mc_aal2);
  proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_res3,  tvb, 0, 0, mc_aal2);
  proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_first, tvb, 0, 0, mc_aal2);
  proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_maale, tvb, 0, 0, mc_aal2);
  proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_lene,  tvb, 0, 0, mc_aal2);

  proto_tree_add_uint(mc_aal2_tree, hf_erf_mc_aal2_cid,   tvb, 0, 0, mc_aal2);
}

static void
dissect_aal2_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *aal2_item;
  proto_tree *aal2_tree;
  uint32_t    aal2;

  /* AAL2 Header */
  aal2_item = proto_tree_add_uint(tree, hf_erf_aal2, tvb, 0, 0, pinfo->pseudo_header->erf.subhdr.mc_hdr);
  aal2_tree = proto_item_add_subtree(aal2_item, ett_erf_aal2);
  aal2 = pinfo->pseudo_header->erf.subhdr.aal2_hdr;

  proto_tree_add_uint(aal2_tree, hf_erf_aal2_cid,    tvb, 0, 0, aal2);

  proto_tree_add_uint(aal2_tree, hf_erf_aal2_maale,  tvb, 0, 0, aal2);

  proto_tree_add_uint(aal2_tree, hf_erf_aal2_maalei, tvb, 0, 0, aal2);
  proto_tree_add_uint(aal2_tree, hf_erf_aal2_first,  tvb, 0, 0, aal2);
  proto_tree_add_uint(aal2_tree, hf_erf_aal2_res1,   tvb, 0, 0, aal2);
}

static void
dissect_eth_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item          *eth_item;
  proto_tree          *eth_tree;
  uint8_t              eth_offset, eth_pad;

  eth_item = proto_tree_add_item(tree, hf_erf_eth, tvb, 0, 0, ENC_NA);

  eth_tree = proto_item_add_subtree(eth_item, ett_erf_eth);
  eth_offset = pinfo->pseudo_header->erf.subhdr.eth_hdr.offset;
  eth_pad = pinfo->pseudo_header->erf.subhdr.eth_hdr.pad;

  proto_tree_add_uint(eth_tree, hf_erf_eth_off, tvb, 0, 0, eth_offset);
  proto_tree_add_uint(eth_tree, hf_erf_eth_pad, tvb, 0, 0, eth_pad);
}

static void
dissect_erf_pseudo_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *pi;
  proto_item *flags_item, *rectype_item;
  proto_tree *flags_tree, *rectype_tree;
  bool has_flags = false;

  proto_tree_add_uint64(tree, hf_erf_ts, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.ts);

  rectype_item = proto_tree_add_uint_format_value(tree, hf_erf_rectype, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.type,
                                                  "0x%02x (Type %d: %s)",
                                                  pinfo->pseudo_header->erf.phdr.type,
                                                  pinfo->pseudo_header->erf.phdr.type & ERF_HDR_TYPE_MASK,
                                                  val_to_str_const(
                                                    pinfo->pseudo_header->erf.phdr.type & ERF_HDR_TYPE_MASK,
                                                    erf_type_vals,
                                                    "Unknown Type"));

  rectype_tree = proto_item_add_subtree(rectype_item, ett_erf_rectype);
  proto_tree_add_uint(rectype_tree, hf_erf_type, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.type);
  proto_tree_add_uint(rectype_tree, hf_erf_ehdr, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.type);

  flags_item=proto_tree_add_uint(tree, hf_erf_flags, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.flags);
  flags_tree = proto_item_add_subtree(flags_item, ett_erf_flags);

  proto_tree_add_uint(flags_tree, hf_erf_flags_if_raw, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.flags);

  proto_tree_add_uint(flags_tree, hf_erf_flags_vlen, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.flags);
  pi=proto_tree_add_uint(flags_tree, hf_erf_flags_trunc, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.flags);
  if (pinfo->pseudo_header->erf.phdr.flags & ERF_HDR_TRUNC_MASK) {
    proto_item_append_text(flags_item, "(ERF Truncation Error");
    expert_add_info(pinfo, pi, &ei_erf_truncation_error);
    has_flags = true;
  }

  pi=proto_tree_add_uint(flags_tree, hf_erf_flags_rxe, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.flags);
  if (pinfo->pseudo_header->erf.phdr.flags & ERF_HDR_RXE_MASK) {
    proto_item_append_text(flags_item, "%sERF Rx Error", has_flags ? "; " : "(");
    expert_add_info(pinfo, pi, &ei_erf_rx_error);
    has_flags = true;
  }

  pi=proto_tree_add_uint(flags_tree, hf_erf_flags_dse, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.flags);
  if (pinfo->pseudo_header->erf.phdr.flags & ERF_HDR_DSE_MASK) {
    proto_item_append_text(flags_item, "%sERF DS Error", has_flags ? "; " : "(");
    expert_add_info(pinfo, pi, &ei_erf_ds_error);
    has_flags = true;
  }
  if (has_flags) {
    proto_item_append_text(flags_item, ")");
  }

  proto_tree_add_uint(flags_tree, hf_erf_flags_res, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.flags);

  proto_tree_add_uint(tree, hf_erf_flags_cap, tvb, 0, 0, erf_interface_id_from_flags(pinfo->pseudo_header->erf.phdr.flags));

  proto_tree_add_uint(tree, hf_erf_rlen, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.rlen);

  if (erf_type_has_color(pinfo->pseudo_header->erf.phdr.type)) {
    proto_tree_add_uint(tree, hf_erf_color, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.lctr);
  } else {
    pi=proto_tree_add_uint(tree, hf_erf_lctr, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.lctr);
    if (pinfo->pseudo_header->erf.phdr.lctr > 0)
      expert_add_info(pinfo, pi, &ei_erf_packet_loss);
  }

  proto_tree_add_uint(tree, hf_erf_wlen, tvb, 0, 0, pinfo->pseudo_header->erf.phdr.wlen);
}

static void
dissect_erf_pseudo_extension_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *pi;
  proto_item *ehdr_tree;
  uint64_t    hdr;
  uint8_t     type;
  uint8_t     has_more = pinfo->pseudo_header->erf.phdr.type & 0x80;
  int         i        = 0;
  int         max      = array_length(pinfo->pseudo_header->erf.ehdr_list);

  uint64_t    host_id        = ERF_META_HOST_ID_IMPLICIT;
  uint8_t     source_id      = 0;
  bool        found_host_id  = false;
  bool        has_anchor_definition = false;

  /*
   * Get the first Host ID of the record (which may not be the first extension
   * header).
   */
  host_id = find_host_id(pinfo, &has_anchor_definition);
  if (host_id == ERF_META_HOST_ID_IMPLICIT) {
    /*
     * XXX: We are relying here on the Wireshark doing a second parse any
     * time it does anything with tree items (including filtering) to associate
     * the records before the first ERF_TYPE_META record. This does not work
     * with TShark in one-pass mode, in which case the first few records get
     * Host ID 0 (unset).
     */
    host_id = erf_state.implicit_host_id;
    found_host_id = false;
  } else {
    found_host_id = true;
  }

  while(has_more && (i < max)) {
    hdr = pinfo->pseudo_header->erf.ehdr_list[i].ehdr;
    type = (uint8_t) (hdr >> 56);

    pi = proto_tree_add_uint(tree, hf_erf_ehdr_t, tvb, 0, 0, (type & 0x7f));
    ehdr_tree = proto_item_add_subtree(pi, ett_erf_pseudo_hdr);

    switch (type & 0x7f) {
    case ERF_EXT_HDR_TYPE_CLASSIFICATION:
      dissect_classification_ex_header(tvb, pinfo, ehdr_tree, i);
      break;
    case ERF_EXT_HDR_TYPE_INTERCEPTID:
      dissect_intercept_ex_header(tvb, pinfo, ehdr_tree, i);
      break;
    case ERF_EXT_HDR_TYPE_RAW_LINK:
      dissect_raw_link_ex_header(tvb, pinfo, ehdr_tree, i);
      break;
    case ERF_EXT_HDR_TYPE_BFS:
      dissect_bfs_ex_header(tvb, pinfo, ehdr_tree, i);
      break;
    case ERF_EXT_HDR_TYPE_CHANNELISED:
      dissect_channelised_ex_header(tvb, pinfo, ehdr_tree, i);
      break;
    case ERF_EXT_HDR_TYPE_SIGNATURE:
      dissect_signature_ex_header(tvb, pinfo, ehdr_tree, i);
      break;
    case ERF_EXT_HDR_TYPE_FLOW_ID:
      if (source_id == 0) {
        source_id = (uint8_t)((hdr >> 48) & 0xFF);
      }
      dissect_flow_id_ex_header(tvb, pinfo, ehdr_tree, i);
      break;
    case ERF_EXT_HDR_TYPE_HOST_ID:
      host_id = hdr & ERF_EHDR_HOST_ID_MASK;
      source_id = (uint8_t)((hdr >> 48) & 0xFF);
      dissect_host_id_ex_header(tvb, pinfo, ehdr_tree, i);

      /* Track and dissect combined Host ID and Source ID(s) */
      if (!PINFO_FD_VISITED(pinfo)) {
        if ((pinfo->pseudo_header->erf.phdr.type & 0x7f) == ERF_TYPE_META) {
          /* Update the implicit Host ID when ERF_TYPE_META */
          /* XXX: We currently assume there is only one in the whole file */
          if (erf_state.implicit_host_id == 0 && source_id > 0) {
            erf_state.implicit_host_id = host_id;
          }

          /* Add to the sequence of ERF_TYPE_META records if periodic record */
          /*
           * Adding metadata from comment records makes for unhelpful linking
           * and means we miss out on the correct frame when marking surrounding
           * metadata as depended upon (e.g. could end up with a comment from
           * another frame). We mark the anchor linked records separately.
           */
          if (!has_anchor_definition) {
            /* XXX: this is a heuristic, technically we could have non-local sections
              in the metadata even as an anchor definition record. */
            erf_source_append(host_id, source_id, pinfo->num);
          }
        }
      }
      dissect_host_id_source_id(tvb, pinfo, tree, host_id, source_id);
      break;
    case ERF_EXT_HDR_TYPE_ANCHOR_ID:
      dissect_anchor_id_ex_header(tvb, pinfo, ehdr_tree, i);
      if (!PINFO_FD_VISITED(pinfo)) {
        erf_host_anchor_info_insert(pinfo, host_id, hdr & ERF_EHDR_ANCHOR_ID_MASK, (uint8_t)(hdr >> 48));
      }
      dissect_host_anchor_id(tvb, pinfo, tree, host_id, hdr & ERF_EHDR_ANCHOR_ID_MASK, (uint8_t)(hdr >> 48));
      break;
    case ERF_EXT_HDR_TYPE_ENTROPY:
      dissect_entropy_ex_header(tvb, pinfo, ehdr_tree, i);
      break;
    default:
      dissect_unknown_ex_header(tvb, pinfo, ehdr_tree, i);
      break;
    }

    has_more = type & 0x80;
    i += 1;
  }
  if (has_more) {
    proto_tree_add_expert(tree, pinfo, &ei_erf_extension_headers_not_shown, tvb, 0, 0);
  }

  /* If we have no explicit Host ID association, associate with the first Source ID (or 0) and implicit Host ID */
  /* XXX: We are allowed to assume there is only one Source ID unless we have
   * a Host ID extension header */
  if (!found_host_id) {
    /*
     * TODO: Do we also want to track Host ID 0 Source ID 0 records?
     * Don't for now to preserve feel of legacy files.
     */
    if (host_id != 0 || source_id != 0) {
      if (!PINFO_FD_VISITED(pinfo)) {
        if ((pinfo->pseudo_header->erf.phdr.type & 0x7f) == ERF_TYPE_META) {
          /* Add to the sequence of ERF_TYPE_META records */
          erf_source_append(host_id, source_id, pinfo->num);
        }
      }
      dissect_host_id_source_id(tvb, pinfo, tree, host_id, source_id);
    }
  }
}

uint64_t* erf_get_ehdr(packet_info *pinfo, uint8_t hdrtype, int* afterindex) {
  uint8_t     type;
  uint8_t     has_more;
  int         max;
  int         i        = afterindex ? *afterindex + 1 : 0; /*allow specifying instance to start after for use in loop*/

  if (!pinfo) /*XXX: how to determine if erf pseudo_header is valid?*/
      return NULL;

  has_more = pinfo->pseudo_header->erf.phdr.type & 0x80;
  max      = array_length(pinfo->pseudo_header->erf.ehdr_list);


  while(has_more && (i < max)) {
    type = (uint8_t) (pinfo->pseudo_header->erf.ehdr_list[i].ehdr >> 56);

    if ((type & 0x7f) == (hdrtype & 0x7f)) {
         if (afterindex)
             *afterindex = i;
         return &pinfo->pseudo_header->erf.ehdr_list[i].ehdr;
    }

    has_more = type & 0x80;
    i += 1;
  }

  return NULL;
}

static void
check_section_length(packet_info *pinfo, proto_item *sectionlen_pi, int offset, int sectionoffset, int sectionlen) {
  if (sectionlen_pi) {
    if (offset - sectionoffset == sectionlen) {
      proto_item_append_text(sectionlen_pi, " [correct]");
    } else if (sectionlen != 0) {
      proto_item_append_text(sectionlen_pi, " [incorrect, should be %u]", offset - sectionoffset);
      expert_add_info(pinfo, sectionlen_pi, &ei_erf_meta_section_len_error);
    }
  }
}

static proto_item*
dissect_meta_tag_bitfield(proto_item *section_tree, tvbuff_t *tvb, int offset, erf_meta_tag_info_t *tag_info, proto_item **out_tag_tree)
{
  proto_item *tag_pi        = NULL;
  int* hf_flags[ERF_HF_VALUES_PER_TAG];
  int i;

  DISSECTOR_ASSERT(tag_info->extra);

  for (i = 0; tag_info->extra->hf_values[i] != -1; i++) {
    hf_flags[i] = &tag_info->extra->hf_values[i];
  }
  hf_flags[i] = NULL;

  /* use flags variant so we print integers without value_strings */
  tag_pi = proto_tree_add_bitmask_with_flags(section_tree, tvb, offset + 4, tag_info->hf_value, tag_info->ett, hf_flags, ENC_BIG_ENDIAN, BMT_NO_FLAGS);
  if (out_tag_tree) {
    *out_tag_tree = proto_item_get_subtree(tag_pi);
  }

  return tag_pi;
}

static proto_item*
dissect_meta_tag_ext_hdrs(proto_item *section_tree, tvbuff_t *tvb, int offset, int taglength, erf_meta_tag_info_t *tag_info, proto_item **out_tag_tree, expert_field **out_truncated_expert)
{
  proto_item *tag_pi        = NULL;
  proto_tree *subtree       = NULL;
  proto_item *subtree_pi    = NULL;
  int i;
  uint32_t ext_hdrs[4] = {0, 0, 0, 0};
  int int_offset      = 0;
  int int_avail       = MIN(taglength / 4, 4);
  int bit_offset      = 0;
  int ext_hdr_num     = 0;
  bool first      = true;
  bool all_set    = true;

  DISSECTOR_ASSERT(tag_info->extra);

  tag_pi = proto_tree_add_item(section_tree, tag_info->hf_value, tvb, offset + 4, taglength, ENC_BIG_ENDIAN);
  *out_tag_tree = proto_item_add_subtree(tag_pi, tag_info->ett);

  for (int_offset = 0; int_offset < int_avail; int_offset++) {
    ext_hdrs[int_offset] = tvb_get_uint32(tvb, offset + 4 + int_offset*4, ENC_BIG_ENDIAN);
    if (ext_hdrs[int_offset] != UINT32_MAX)
      all_set = false;
  }

  /* Special case: all specified bits are 1 means all extension headers */
  if (all_set)
    proto_item_append_text(tag_pi, ": <All>");

  /* Add 4 subtrees, one for each uint32 representing 32 extension header numbers */
  for (int_offset = 0; int_offset < int_avail; int_offset++) {
    /* TODO: Put subtree hf values somewhere better than first 4 hf_values */
    subtree_pi = proto_tree_add_item(*out_tag_tree, tag_info->extra->hf_values[int_offset], tvb, offset + 4 + int_offset*4, 4, ENC_BIG_ENDIAN);

    /* Add the individual bit dissections */
    /* XXX: This currently assumes we only know up to the first 32 */
    if (int_offset == 0) {
      subtree = proto_item_add_subtree(subtree_pi, tag_info->ett);
      for (i = 4; tag_info->extra->hf_values[i] != -1; i++) {
        proto_tree_add_boolean(subtree, tag_info->extra->hf_values[i], tvb, offset + 4 + int_offset*4, 4, ext_hdrs[int_offset]);
      }
    }

    /* Add all set bits to the header, including the ones we don't understand */
    for (bit_offset = 0; bit_offset < 32; bit_offset++) {
      if (ext_hdrs[int_offset] & (1U << bit_offset)) {
        proto_item_append_text(subtree_pi, ", %s", val_to_str(ext_hdr_num, ehdr_type_vals, "%d"));

        /* Also add to the top level */
        if (!all_set)
          proto_item_append_text(tag_pi, "%s %s", first ? ":" : ",", val_to_str(ext_hdr_num, ehdr_type_vals, "%d"));

        first = false;
      }

      ext_hdr_num++;
    }
  }

  if (first)
    proto_item_append_text(tag_pi, ": <None>");

  /* Check for truncated tag (i.e. last uint32 is partial) */
  if (int_avail < 4 && taglength % 4 != 0) {
    *out_truncated_expert = &ei_erf_meta_truncated_tag;
  }

  return tag_pi;
}

static void erf_ts_to_nstime(uint64_t timestamp, nstime_t* t, bool is_relative) {
  uint64_t ts = timestamp;

  /* relative ERF timestamps are signed, convert as if unsigned then flip back */
  if (is_relative) {
    ts = (uint64_t) ABS((int64_t)timestamp);
  }


  t->secs = (long) (ts >> 32);
  ts  = ((ts & 0xffffffff) * 1000 * 1000 * 1000);
  ts += (ts & 0x80000000) << 1; /* rounding */
  t->nsecs = ((int) (ts >> 32));
  if (t->nsecs >= NS_PER_S) {
    t->nsecs -= NS_PER_S;
    t->secs += 1;
  }

  if (is_relative && (int64_t)timestamp < 0) {
    /*
     * Set both signs to negative for consistency with other nstime code
     * and so -0.123 works.
     */
    t->secs = -(t->secs);
    t->nsecs = -(t->nsecs);
  }
}

/* TODO: Would be nice if default FT_RELATIVE_TIME formatter was prettier */
static proto_item *dissect_relative_time(proto_tree *tree, const int hfindex, tvbuff_t *tvb, int offset, int length, nstime_t* t) {
  proto_item *pi = NULL;

  DISSECTOR_ASSERT(t);

  /*Print in nanoseconds if <1ms for small values*/
  if (t->secs == 0 && t->nsecs < 1000000 && t->nsecs > -1000000) {
    pi = proto_tree_add_time_format_value(tree, hfindex, tvb, offset, length, t, "%d nanoseconds", t->nsecs);
  } else {
    pi = proto_tree_add_time(tree, hfindex, tvb, offset, length, t);
  }

  return pi;
}

static proto_item *dissect_ptp_timeinterval(proto_tree *tree, const int hfindex, tvbuff_t *tvb, int offset, int length, int64_t timeinterval) {
  nstime_t t;
  uint64_t ti, ti_ns;

  ti = (uint64_t) ABS(timeinterval);

  ti += (ti & 0x8000) << 1; /* rounding */
  ti_ns = ti >> 16;
  t.secs = (time_t) (ti_ns / NS_PER_S);
  t.nsecs = (uint32_t)(ti_ns % NS_PER_S);
  if (t.nsecs >= NS_PER_S) {
    t.nsecs -= NS_PER_S;
    t.secs += 1;
  }

  if (timeinterval < 0) {
    /*
     * Set both signs to negative for consistency with other nstime code
     * and so -0.123 works.
     */
    t.secs = -(t.secs);
    t.nsecs = -(t.nsecs);
  }

  return dissect_relative_time(tree, hfindex, tvb, offset, length, &t);
}

static int
meta_tag_expected_length(erf_meta_tag_info_t *tag_info) {
  ftenum_t ftype = tag_info->tag_template->hfinfo.type;
  int expected_length = 0;

  switch (ftype) {
    case FT_ABSOLUTE_TIME:
    case FT_RELATIVE_TIME:
      /* Timestamps are in ERF timestamp except as below */
      expected_length = 8;
      break;

    default:
      expected_length = ftype_wire_size(ftype); /* Returns 0 if unknown */
      break;
  }

  /* Special case overrides */
  switch (tag_info->code) {
    case ERF_META_TAG_ptp_current_utc_offset:
      /*
       * PTP tags are in native PTP format, but only current_utc_offset is
       * a different length to the ERF timestamp.
       */
      expected_length = 4;
      break;

    case ERF_META_TAG_if_wwn:
    case ERF_META_TAG_src_wwn:
    case ERF_META_TAG_dest_wwn:
    case ERF_META_TAG_ns_host_wwn:
      /* 16-byte WWNs */
      expected_length = 16;
      break;

    case ERF_META_TAG_ext_hdrs_added:
    case ERF_META_TAG_ext_hdrs_removed:
      /* 1 to 4 uint32 fields */
      expected_length = 4;
      break;
  }

  return expected_length;
}

static void
dissect_meta_record_tags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  proto_item *pi            = NULL;
  proto_item *tag_pi        = NULL;
  proto_item *tag_tree;
  proto_item *section_pi    = NULL;
  proto_item *section_tree  = tree;
  proto_item *sectionlen_pi = NULL;

  uint16_t               sectiontype  = ERF_META_SECTION_NONE;
  uint16_t               tagtype      = 0;
  uint16_t               taglength    = 0;
  const char            *tagvalstring = NULL;
  erf_meta_tag_info_t   *tag_info;
  int                    expected_length = 0;
  expert_field          *truncated_expert = NULL;
  bool                   skip_truncated = false;

  /* Used for search entry and unknown tags */
  erf_meta_hf_template_t tag_template_unknown = { 0, { "Unknown", "unknown",
    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } };
  erf_meta_tag_info_t    tag_info_local       = { 0, 0, &tag_template_unknown, &tag_template_unknown,
    ett_erf_meta_tag, hf_erf_meta_tag_unknown, NULL };

  int     offset        = 0;
  int     sectionoffset = 0;
  uint16_t sectionid     = 0;
  uint16_t sectionlen    = 0;
  int     remaining_len = 0;

  int captured_length = (int) tvb_captured_length(tvb);

  /* Set column heading title*/
  col_set_str(pinfo->cinfo, COL_INFO, "Provenance Metadata");

  /* Go through the sections and their tags */
  /* Not using tvb_captured_length because want to check for overrun */
  while ((remaining_len = captured_length - offset) >= 4) {
    tagtype = tvb_get_ntohs(tvb, offset);
    taglength = tvb_get_ntohs(tvb, offset + 2);
    tag_tree = NULL;
    tag_pi = NULL;
    truncated_expert = NULL;
    skip_truncated = false;

    if (ERF_META_IS_SECTION(tagtype))
      sectiontype = tagtype;

    /* Look up per-section tag hf */
    tag_info_local.code = tagtype;
    tag_info_local.section = sectiontype;
    tag_info = (erf_meta_tag_info_t*) wmem_map_lookup(erf_meta_index.tag_table, GUINT_TO_POINTER(ERF_TAG_INFO_KEY(&tag_info_local)));

    /* Fall back to unknown tag */
    if (tag_info == NULL)
      tag_info = &tag_info_local;

    /* Get expected length (minimum length in the case of ns_host_*) */
    expected_length = meta_tag_expected_length(tag_info);

    if (remaining_len < (int32_t)taglength + 4 || taglength < expected_length) {
      /*
       * Malformed tag, just dissect type and length. Top level tag
       * dissection means can't add the subtree and type/length first.
       *
       * Allow too-long tags for now (and proto_tree generally generates
       * a warning for these anyway).
       */
      skip_truncated = true;
      truncated_expert = &ei_erf_meta_truncated_tag;
    }

    if (taglength == 0) {
      /*
       * We highlight zero length differently as a special case to indicate
       * a deliberately invalid tag.
       */
      if (!ERF_META_IS_SECTION(tagtype) && tagtype != ERF_META_TAG_padding) {
        truncated_expert = &ei_erf_meta_zero_len_tag;
        /* XXX: Still dissect normally too if string/unknown or section header */
        if (expected_length != 0) {
          skip_truncated = true;
        }
      }
    }

    /* Dissect value, length and type */
    if (ERF_META_IS_SECTION(tagtype)) { /* Section header tag */
      if (section_pi) {
        /* Update section item length of last section */
        proto_item_set_len(section_pi, offset - sectionoffset);
        if (sectionlen_pi) {
          check_section_length(pinfo, sectionlen_pi, offset, sectionoffset, sectionlen);
        }
      }

      sectionoffset = offset;
      if (tag_info->tag_template == &tag_template_unknown) {
        /* Unknown section */
        sectiontype = ERF_META_SECTION_UNKNOWN;
        tag_info = erf_meta_index.unknown_section_info;
      }
      DISSECTOR_ASSERT(tag_info->extra);

      tagvalstring = val_to_str(tagtype, erf_to_value_string(erf_meta_index.vs_list), "Unknown Section (0x%x)");
      col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", tagvalstring);
      section_tree = proto_tree_add_subtree(tree, tvb, offset, 0, tag_info->extra->ett_value, &section_pi, tagvalstring);
      tag_tree = proto_tree_add_subtree_format(section_tree, tvb, offset, MIN(taglength + 4, remaining_len), tag_info->ett, &tag_pi, "Provenance %s Header", tagvalstring);

      /* XXX: Value may have been truncated (avoiding exception so get custom expertinfos) */
      if (taglength >= 4 && !skip_truncated) {
        sectionid = tvb_get_ntohs(tvb, offset + 4);
        sectionlen = tvb_get_ntohs(tvb, offset + 6);

        /* Add section_id */
        proto_tree_add_uint(tag_tree, tag_info->hf_value, tvb, offset + 4, 2, sectionid);
        if (sectionid != 0) {
          if(sectionid & 0x8000U) {
            /* Local section */
            proto_item_append_text(section_pi, " (Local) %u", sectionid & 0x7FFFU);
          }
          else {
            proto_item_append_text(section_pi, " %u", sectionid);
          }
        }

        /* Add section_len */
        sectionlen_pi = proto_tree_add_uint(tag_tree, tag_info->extra->hf_values[0], tvb, offset + 6, 2, sectionlen);

        /* Reserved extra section header information */
        if (taglength > 4) {
          proto_tree_add_item(tag_tree, tag_info->extra->hf_values[1], tvb, offset + 8, taglength - 4, ENC_NA);
        }
      } else if (taglength != 0) {
        /* Section Header value is too short */
        truncated_expert = &ei_erf_meta_truncated_tag;
      }
    } else if (!skip_truncated) { /* Not section header tag (and not truncated) */
      enum ftenum tag_ft;
      char        pi_label[ITEM_LABEL_LENGTH+1];
      bool        dissected = true;
      uint32_t    value32;
      uint64_t    value64;
      float       float_value;
      char       *tmp = NULL;

      tag_ft = tag_info->tag_template->hfinfo.type;
      pi_label[0] = '\0';

      /* Group tags before first section header into a fake section */
      if (offset == 0) {
        section_tree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_erf_meta, &section_pi, "No Section");
      }

      /* Handle special cases */
      /* TODO: might want to do this dynamically via tag_info callback */
      switch (tagtype) {
      /* TODO: use get_tcp_port in epan/addr_resolv.h etc */
      case ERF_META_TAG_if_speed:
      case ERF_META_TAG_if_tx_speed:
        value64 = tvb_get_ntoh64(tvb, offset + 4);
        tmp = format_size((int64_t)value64, FORMAT_SIZE_UNIT_BITS_S, FORMAT_SIZE_PREFIX_SI);
        tag_pi = proto_tree_add_uint64_format_value(section_tree, tag_info->hf_value, tvb, offset + 4, taglength, value64, "%s (%" PRIu64 " bps)", tmp, value64);
        g_free(tmp);
        break;

      case ERF_META_TAG_if_rx_power:
      case ERF_META_TAG_if_tx_power:
        value32 = tvb_get_ntohl(tvb, offset + 4);
        tag_pi = proto_tree_add_int_format_value(section_tree, tag_info->hf_value, tvb, offset + 4, taglength, (int32_t) value32, "%.2fdBm", (double)((int32_t) value32)/100.0);
        break;

      case ERF_META_TAG_temperature:
      case ERF_META_TAG_power:
        value32 = tvb_get_ntohl(tvb, offset + 4);
        float_value = (float)((int32_t) value32)/1000.0f;
        tag_pi = proto_tree_add_float(section_tree, tag_info->hf_value, tvb, offset + 4, taglength, float_value);
        break;

      case ERF_META_TAG_loc_lat:
      case ERF_META_TAG_loc_long:
        value32 = tvb_get_ntohl(tvb, offset + 4);
        tag_pi = proto_tree_add_int_format_value(section_tree, tag_info->hf_value, tvb, offset + 4, taglength, (int32_t) value32, "%.2f", (double)((int32_t) value32)*1000000.0);
        break;

      case ERF_META_TAG_mask_cidr:
        value32 = tvb_get_ntohl(tvb, offset + 4);
        tag_pi = proto_tree_add_uint_format_value(section_tree, tag_info->hf_value, tvb, offset + 4, taglength, value32, "/%u", value32);
        break;

      case ERF_META_TAG_mem:
        value64 = tvb_get_ntoh64(tvb, offset + 4);
        tmp = format_size((int64_t)value64, FORMAT_SIZE_UNIT_BYTES, FORMAT_SIZE_PREFIX_IEC);
        tag_pi = proto_tree_add_uint64_format_value(section_tree, tag_info->hf_value, tvb, offset + 4, taglength, value64, "%s (%" PRIu64" bytes)", tmp, value64);
        g_free(tmp);
        break;

      case ERF_META_TAG_parent_section:
        DISSECTOR_ASSERT(tag_info->extra);
        value32 = tvb_get_ntohs(tvb, offset + 4);
        /*
         * XXX: Formatting value manually because don't have erf_meta_vs_list
         * populated at registration time.
         */
        tag_tree = proto_tree_add_subtree_format(section_tree, tvb, offset + 4, taglength, tag_info->ett, &tag_pi, "%s: %s %u", tag_info->tag_template->hfinfo.name,
            val_to_str(value32, erf_to_value_string(erf_meta_index.vs_list), "Unknown Section (%u)"), tvb_get_ntohs(tvb, offset + 4 + 2));

        proto_tree_add_uint_format_value(tag_tree, tag_info->extra->hf_values[0], tvb, offset + 4, MIN(2, taglength), value32, "%s (%u)",
            val_to_str_const(value32, erf_to_value_string(erf_meta_index.vs_abbrev_list), "Unknown"), value32);
        proto_tree_add_item(tag_tree, tag_info->extra->hf_values[1], tvb, offset + 6, MIN(2, taglength - 2), ENC_BIG_ENDIAN);
        break;

      case ERF_META_TAG_reset:
        tag_pi = proto_tree_add_item(section_tree, tag_info->hf_value, tvb, offset + 4, taglength, ENC_NA);
        expert_add_info(pinfo, tag_pi, &ei_erf_meta_reset);
        break;

      case ERF_META_TAG_if_link_status:
      case ERF_META_TAG_tunneling_mode:
      case ERF_META_TAG_ptp_time_properties:
      case ERF_META_TAG_ptp_gm_clock_quality:
      case ERF_META_TAG_stream_flags:
      case ERF_META_TAG_smart_trunc_default:
        tag_pi = dissect_meta_tag_bitfield(section_tree, tvb, offset, tag_info, &tag_tree);
        break;


      case ERF_META_TAG_ns_dns_ipv4:
      case ERF_META_TAG_ns_dns_ipv6:
      case ERF_META_TAG_ns_host_ipv4:
      case ERF_META_TAG_ns_host_ipv6:
      case ERF_META_TAG_ns_host_mac:
      case ERF_META_TAG_ns_host_eui:
      case ERF_META_TAG_ns_host_wwn:
      case ERF_META_TAG_ns_host_ib_gid:
      case ERF_META_TAG_ns_host_ib_lid:
      case ERF_META_TAG_ns_host_fc_id:
      {
        int addr_len = ftype_wire_size(tag_ft);

        DISSECTOR_ASSERT(tag_info->extra);

        tag_tree = proto_tree_add_subtree(section_tree, tvb, offset + 4, taglength, tag_info->ett, &tag_pi, tag_info->tag_template->hfinfo.name);
        /* Address */
        pi = proto_tree_add_item(tag_tree, tag_info->extra->hf_values[0], tvb, offset + 4, MIN(addr_len, taglength), ENC_BIG_ENDIAN);
        /* Name */
        proto_tree_add_item(tag_tree, tag_info->extra->hf_values[1], tvb, offset + 4 + addr_len, taglength - addr_len, ENC_UTF_8);
        if (pi) {
          proto_item_fill_label(PITEM_FINFO(pi), pi_label);
          /* Set top level label e.g IPv4 Name: hostname Address: 1.2.3.4 */
          /* TODO: Name is unescaped here but escaped in actual field */
          proto_item_append_text(tag_pi, ": %s, %s",
              tvb_get_stringzpad(pinfo->pool, tvb, offset + 4 + addr_len, taglength - addr_len, ENC_UTF_8), pi_label /* Includes ": " */);
        }

        break;
      }

      case ERF_META_TAG_ptp_offset_from_master:
      case ERF_META_TAG_ptp_mean_path_delay:
        value64 = tvb_get_ntoh64(tvb, offset + 4);
        tag_pi = dissect_ptp_timeinterval(section_tree, tag_info->hf_value, tvb, offset + 4, taglength, (int64_t) value64);
        break;

      case ERF_META_TAG_ptp_current_utc_offset:
      {
        nstime_t t;

        value32 = tvb_get_ntohl(tvb, offset + 4);
        /* PTP value is signed */
        t.secs = (int32_t) value32;
        t.nsecs = 0;

        tag_pi = dissect_relative_time(section_tree, tag_info->hf_value, tvb, offset + 4, taglength, &t);
        break;
      }

      case ERF_META_TAG_entropy_threshold:
      case ERF_META_TAG_initiator_min_entropy:
      case ERF_META_TAG_responder_min_entropy:
      case ERF_META_TAG_initiator_avg_entropy:
      case ERF_META_TAG_responder_avg_entropy:
      case ERF_META_TAG_initiator_max_entropy:
      case ERF_META_TAG_responder_max_entropy:
      {
        float entropy;
        value32 = tvb_get_ntohl(tvb, offset + 4);
        entropy = entropy_from_entropy_header_value((uint8_t) value32);

        tag_pi = proto_tree_add_float_format_value(section_tree, tag_info->hf_value, tvb, 0, 0, entropy,
          "%.2f %s", (double) entropy, entropy == 0.0f ? "(not calculated)":"bits");
        break;
      }

      case ERF_META_TAG_ext_hdrs_added:
      case ERF_META_TAG_ext_hdrs_removed:
        tag_pi = dissect_meta_tag_ext_hdrs(section_tree, tvb, offset, taglength, tag_info, &tag_tree, &truncated_expert);
        break;

      default:
        dissected = false;
        break;
      }

      /* If not special case, dissect generically from template */
      if (!dissected) {
        if (FT_IS_INT(tag_ft) || FT_IS_UINT(tag_ft)) {
          tag_pi = proto_tree_add_item(section_tree, tag_info->hf_value, tvb, offset + 4, taglength, ENC_BIG_ENDIAN);
        } else if (FT_IS_STRING(tag_ft)) {
          tag_pi = proto_tree_add_item(section_tree, tag_info->hf_value, tvb, offset + 4, taglength, ENC_UTF_8);
        } else if (FT_IS_TIME(tag_ft)) {
          /*
           * ERF timestamps are conveniently the same as NTP/PTP timestamps but
           * little endian.
           */
          /*
           * FIXME: ENC_TIME_NTP | ENC_LITTLE_ENDIAN only swaps the
           * upper and lower 32 bits. Is that a bug or by design? Should add
           * a 'PTP" variant that doesn't round to microseconds and use that
           * here. For now do by hand.
           */
          nstime_t t;
          uint64_t ts;

          ts = tvb_get_letoh64(tvb, offset + 4);
          erf_ts_to_nstime(ts, &t, tag_ft == FT_RELATIVE_TIME);

          tag_pi = dissect_relative_time(section_tree, tag_info->hf_value, tvb, offset + 4, taglength, &t);
        } else {
          tag_pi = proto_tree_add_item(section_tree, tag_info->hf_value, tvb, offset + 4, taglength, ENC_NA);
        }
      }
    }

    /* Create subtree for tag if we haven't already */
    if (!tag_tree) {
      /* Make sure we actually put the subtree in the right place */
      if (tag_pi || !tree) {
        tag_tree = proto_item_add_subtree(tag_pi, tag_info->ett);
      } else {
        /* Truncated or error (avoiding exception so get custom expertinfos) */
        tag_tree = proto_tree_add_subtree_format(section_tree, tvb, offset, MIN(taglength + 4, remaining_len), tag_info->ett, &tag_pi, "%s: [Invalid]", tag_info->tag_template->hfinfo.name);
      }
    }

    /* Add tag type field to subtree */
    /*
     * XXX: Formatting value manually because don't have erf_meta_vs_list
     * populated at registration time.
     */
    proto_tree_add_uint_format_value(tag_tree, hf_erf_meta_tag_type, tvb, offset, 2, tagtype, "%s (%u)", val_to_str_const(tagtype, erf_to_value_string(erf_meta_index.vs_abbrev_list), "Unknown"), tagtype);
    proto_tree_add_uint(tag_tree, hf_erf_meta_tag_len, tvb, offset + 2, 2, taglength);

    /* Add truncated expertinfo if needed */
    if (truncated_expert) {
      expert_add_info(pinfo, tag_pi, truncated_expert);
    }

    offset += (((uint32_t)taglength + 4) + 0x3U) & ~0x3U;
  }

  if (remaining_len != 0) {
    /* Record itself is truncated */
    expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_erf_meta_truncated_record);
    /* Continue to setting sectionlen error */
  }

  /* Check final section length */
  proto_item_set_len(section_pi, offset - sectionoffset);
  check_section_length(pinfo, sectionlen_pi, offset, sectionoffset, sectionlen);
}

static int
dissect_erf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  uint8_t             flags;
  uint8_t             erf_type;
  uint32_t            atm_hdr  = 0;
  proto_tree         *erf_tree;
  proto_item         *erf_item;
  erf_hdlc_type_vals  hdlc_type;
  uint8_t             first_byte;
  tvbuff_t           *new_tvb;
  uint8_t             aal2_cid;
  struct atm_phdr     atm_info;

  erf_type=pinfo->pseudo_header->erf.phdr.type & 0x7F;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ERF");

  col_add_str(pinfo->cinfo, COL_INFO,
       val_to_str(erf_type, erf_type_vals, "Unknown type %u"));

  erf_item = proto_tree_add_item(tree, proto_erf, tvb, 0, -1, ENC_NA);
  erf_tree = proto_item_add_subtree(erf_item, ett_erf);

  dissect_erf_pseudo_header(tvb, pinfo, erf_tree);
  if (pinfo->pseudo_header->erf.phdr.type & 0x80) {
    dissect_erf_pseudo_extension_header(tvb, pinfo, erf_tree);
    }

  flags = pinfo->pseudo_header->erf.phdr.flags;
  /*
   * Set if frame is Received or Sent.
   * XXX - this is really testing the low-order bit of the capture
   * interface number, so interface 0 is assumed to be capturing
   * in one direction on a bi-directional link, interface 1 is
   * assumed to be capturing in the other direction on that link,
   * and interfaces 2 and 3 are assumed to be capturing in two
   * different directions on another link.  We don't distinguish
   * between the two links.
   */
  pinfo->p2p_dir = ( (flags & 0x01) ? P2P_DIR_RECV : P2P_DIR_SENT);

  switch (erf_type) {

  case ERF_TYPE_RAW_LINK:
    if(sdh_handle) {
      call_dissector(sdh_handle, tvb, pinfo, tree);
    }
    else{
      call_data_dissector(tvb, pinfo, tree);
    }
    break;

  case ERF_TYPE_ETH:
  case ERF_TYPE_COLOR_ETH:
  case ERF_TYPE_DSM_COLOR_ETH:
  case ERF_TYPE_COLOR_HASH_ETH:
    dissect_eth_header(tvb, pinfo, erf_tree);
    /* fall through */
  case ERF_TYPE_IPV4:
  case ERF_TYPE_IPV6:
  case ERF_TYPE_INFINIBAND:
  case ERF_TYPE_INFINIBAND_LINK:
  case ERF_TYPE_OPA_SNC:
  case ERF_TYPE_OPA_9B:
    if (!dissector_try_uint(erf_dissector_table, erf_type, tvb, pinfo, tree)) {
      call_data_dissector(tvb, pinfo, tree);
    }
    break;

  case ERF_TYPE_LEGACY:
  case ERF_TYPE_IP_COUNTER:
  case ERF_TYPE_TCP_FLOW_COUNTER:
    /* undefined */
    break;

  case ERF_TYPE_PAD:
    /* Nothing to do */
    break;

  case ERF_TYPE_MC_RAW:
    dissect_mc_raw_header(tvb, pinfo, erf_tree);
    call_data_dissector(tvb, pinfo, tree);
    break;

  case ERF_TYPE_MC_RAW_CHANNEL:
    dissect_mc_rawlink_header(tvb, pinfo, erf_tree);
    call_data_dissector(tvb, pinfo, tree);
    break;

  case ERF_TYPE_MC_ATM:
    dissect_mc_atm_header(tvb, pinfo, erf_tree);
    /* continue with type ATM */
    /* FALL THROUGH */

  case ERF_TYPE_ATM:
    memset(&atm_info, 0, sizeof(atm_info));
    atm_hdr = tvb_get_ntohl(tvb, 0);
    atm_info.vpi = ((atm_hdr & 0x0ff00000) >> 20);
    atm_info.vci = ((atm_hdr & 0x000ffff0) >>  4);
    atm_info.channel = (flags & 0x03);

    /* Work around to have decoding working */
    if (erf_rawcell_first) {
      new_tvb = tvb_new_subset_remaining(tvb, ATM_HDR_LENGTH);
      /* Treat this as a (short) ATM AAL5 PDU */
      atm_info.aal = AAL_5;
      switch (erf_aal5_type) {

      case ERF_AAL5_GUESS:
        atm_info.type = TRAF_UNKNOWN;
        atm_info.subtype = TRAF_ST_UNKNOWN;
        /* Try to guess the type according to the first bytes */
        erf_atm_guess_traffic_type(new_tvb, 0, tvb_captured_length(new_tvb), &atm_info);
        break;

      case ERF_AAL5_LLC:
        atm_info.type = TRAF_LLCMX;
        atm_info.subtype = TRAF_ST_UNKNOWN;
        break;

      case ERF_AAL5_UNSPEC:
        atm_info.aal = AAL_5;
        atm_info.type = TRAF_UNKNOWN;
        atm_info.subtype = TRAF_ST_UNKNOWN;
        break;
      }

      call_dissector_with_data(atm_untruncated_handle, new_tvb, pinfo, tree,
                               &atm_info);
    } else {
      /* Treat this as a raw cell */
      atm_info.flags |= ATM_RAW_CELL;
      atm_info.flags |= ATM_NO_HEC;
      atm_info.aal = AAL_UNKNOWN;
      /* can call atm_untruncated because we set ATM_RAW_CELL flag */
      call_dissector_with_data(atm_untruncated_handle, tvb, pinfo, tree,
                               &atm_info);
    }
    break;

  case ERF_TYPE_MC_AAL5:
    dissect_mc_aal5_header(tvb, pinfo, erf_tree);
    /* continue with type AAL5 */
    /* FALL THROUGH */

  case ERF_TYPE_AAL5:
    atm_hdr = tvb_get_ntohl(tvb, 0);
    memset(&atm_info, 0, sizeof(atm_info));
    atm_info.vpi = ((atm_hdr & 0x0ff00000) >> 20);
    atm_info.vci = ((atm_hdr & 0x000ffff0) >>  4);
    atm_info.channel = (flags & 0x03);

    new_tvb = tvb_new_subset_remaining(tvb, ATM_HDR_LENGTH);
    /* Work around to have decoding working */
    atm_info.aal = AAL_5;
    switch (erf_aal5_type) {

    case ERF_AAL5_GUESS:
      atm_info.type = TRAF_UNKNOWN;
      atm_info.subtype = TRAF_ST_UNKNOWN;
      /* Try to guess the type according to the first bytes */
      erf_atm_guess_traffic_type(new_tvb, 0, tvb_captured_length(new_tvb), &atm_info);
      break;

    case ERF_AAL5_LLC:
      atm_info.type = TRAF_LLCMX;
      atm_info.subtype = TRAF_ST_UNKNOWN;
      break;

    case ERF_AAL5_UNSPEC:
      atm_info.aal = AAL_5;
      atm_info.type = TRAF_UNKNOWN;
      atm_info.subtype = TRAF_ST_UNKNOWN;
      break;
    }

    call_dissector_with_data(atm_untruncated_handle, new_tvb, pinfo, tree,
                             &atm_info);
    break;

  case ERF_TYPE_MC_AAL2:
    dissect_mc_aal2_header(tvb, pinfo, erf_tree);

    /*
     * Most of the information is in the ATM header; fetch it.
     */
    atm_hdr = tvb_get_ntohl(tvb, 0);

    /*
     * The channel identification number is in the MC header, so it's
     * in the pseudo-header, not in the packet data.
     */
    aal2_cid = (pinfo->pseudo_header->erf.subhdr.mc_hdr & MC_AAL2_CID_MASK) >> MC_AAL2_CID_SHIFT;

    /* Zero out and fill in the ATM pseudo-header. */
    memset(&atm_info, 0, sizeof(atm_info));
    atm_info.aal = AAL_2;
    atm_info.flags |= ATM_AAL2_NOPHDR;
    atm_info.vpi = ((atm_hdr & 0x0ff00000) >> 20);
    atm_info.vci = ((atm_hdr & 0x000ffff0) >>  4);
    atm_info.channel = (flags & 0x03);
    atm_info.aal2_cid = aal2_cid;
    atm_info.type = TRAF_UNKNOWN;
    atm_info.subtype = TRAF_ST_UNKNOWN;

    /* remove ATM cell header from tvb */
    new_tvb = tvb_new_subset_remaining(tvb, ATM_HDR_LENGTH);
    call_dissector_with_data(atm_untruncated_handle, new_tvb, pinfo, tree,
                             &atm_info);
    break;

  case ERF_TYPE_AAL2:
    dissect_aal2_header(tvb, pinfo, erf_tree);

    /*
     * Most of the information is in the ATM header; fetch it.
     */
    atm_hdr = tvb_get_ntohl(tvb, 0);

    /*
     * The channel identification number is in the AAL2 header, so it's
     * in the pseudo-header, not in the packet data.
     */
    aal2_cid = (pinfo->pseudo_header->erf.subhdr.aal2_hdr & AAL2_CID_MASK) >> AAL2_CID_SHIFT;

    /* Zero out and fill in the ATM pseudo-header. */
    memset(&atm_info, 0, sizeof(atm_info));
    atm_info.aal = AAL_2;
    atm_info.flags |= ATM_AAL2_NOPHDR;
    atm_info.vpi = ((atm_hdr & 0x0ff00000) >> 20);
    atm_info.vci = ((atm_hdr & 0x000ffff0) >>  4);
    atm_info.channel = (flags & 0x03);
    atm_info.aal2_cid = aal2_cid;
    atm_info.type = TRAF_UNKNOWN;
    atm_info.subtype = TRAF_ST_UNKNOWN;

    /* remove ATM cell header from tvb */
    new_tvb = tvb_new_subset_remaining(tvb, ATM_HDR_LENGTH);
    call_dissector_with_data(atm_untruncated_handle, new_tvb, pinfo, tree,
                             &atm_info);
    break;

  case ERF_TYPE_MC_HDLC:
    dissect_mc_hdlc_header(tvb, pinfo, erf_tree);
    /* continue with type HDLC */
    /* FALL THROUGH */

  case ERF_TYPE_HDLC_POS:
  case ERF_TYPE_COLOR_HDLC_POS:
  case ERF_TYPE_DSM_COLOR_HDLC_POS:
  case ERF_TYPE_COLOR_MC_HDLC_POS:
  case ERF_TYPE_COLOR_HASH_POS:
    hdlc_type = (erf_hdlc_type_vals)erf_hdlc_type;

    if (hdlc_type == ERF_HDLC_GUESS) {
      /* Try to guess the type. */
      first_byte = tvb_get_uint8(tvb, 0);
      if (first_byte == 0x0f || first_byte == 0x8f)
        hdlc_type = ERF_HDLC_CHDLC;
      else {
        /* Anything to check for to recognize Frame Relay or MTP2?
           Should we require PPP packets to begin with FF 03? */
        hdlc_type = ERF_HDLC_PPP;
      }
    }
    /* Clean the pseudo header (if used in subdissector) and call the
       appropriate subdissector. */
    switch (hdlc_type) {
    case ERF_HDLC_CHDLC:
      call_dissector(chdlc_handle, tvb, pinfo, tree);
      break;
    case ERF_HDLC_PPP:
      call_dissector(ppp_handle, tvb, pinfo, tree);
      break;
    case ERF_HDLC_FRELAY:
      memset(&pinfo->pseudo_header->dte_dce, 0, sizeof(pinfo->pseudo_header->dte_dce));
      call_dissector(frelay_handle, tvb, pinfo, tree);
      break;
    case ERF_HDLC_MTP2:
      /* not used, but .. */
      memset(&pinfo->pseudo_header->mtp2, 0, sizeof(pinfo->pseudo_header->mtp2));
      call_dissector(mtp2_handle, tvb, pinfo, tree);
      break;
    default:
      break;
    }
    break;

  case ERF_TYPE_META:
    dissect_meta_record_tags(tvb, pinfo, erf_tree);
    break;

  default:
    call_data_dissector(tvb, pinfo, tree);
    break;
  } /* erf type */
  return tvb_captured_length(tvb);
}

static void erf_init_dissection(void)
{
  erf_state.implicit_host_id = 0;
  erf_state.source_map = wmem_map_new(wmem_file_scope(), wmem_int64_hash, g_int64_equal);
  erf_state.host_anchor_map = wmem_map_new(wmem_file_scope(), erf_anchor_key_hash, erf_anchor_key_equal);
  /* Old map is freed automatically */
}

void
proto_register_erf(void)
{

  static hf_register_info hf[] = {
    /* ERF Header */
    { &hf_erf_ts,
      { "Timestamp", "erf.ts",
        FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_rectype,
      { "Record type", "erf.types",
        FT_UINT8, BASE_HEX,  NULL, 0x0, NULL, HFILL } },
    { &hf_erf_type,
      { "Type", "erf.types.type",
        FT_UINT8, BASE_DEC,  VALS(erf_type_vals), ERF_HDR_TYPE_MASK, NULL, HFILL } },
    { &hf_erf_ehdr,
      { "Extension header present", "erf.types.ext_header",
        FT_UINT8, BASE_DEC,  NULL, ERF_HDR_EHDR_MASK, NULL, HFILL } },
    { &hf_erf_flags,
      { "Flags", "erf.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_flags_cap,
      { "Capture interface", "erf.flags.cap",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_flags_if_raw,
      { "Raw interface", "erf.flags.if_raw",
        FT_UINT8, BASE_HEX, NULL, ERF_HDR_CAP_MASK, NULL, HFILL } },
    { &hf_erf_flags_vlen,
      { "Varying record length", "erf.flags.vlen",
        FT_UINT8, BASE_DEC, NULL, ERF_HDR_VLEN_MASK, NULL, HFILL } },
    { &hf_erf_flags_trunc,
      { "Truncated", "erf.flags.trunc",
        FT_UINT8, BASE_DEC, NULL, ERF_HDR_TRUNC_MASK, NULL, HFILL } },
    { &hf_erf_flags_rxe,
      { "RX error", "erf.flags.rxe",
        FT_UINT8, BASE_DEC, NULL, ERF_HDR_RXE_MASK, NULL, HFILL } },
    { &hf_erf_flags_dse,
      { "DS error", "erf.flags.dse",
        FT_UINT8, BASE_DEC, NULL, ERF_HDR_DSE_MASK, NULL, HFILL } },
    { &hf_erf_flags_res,
       { "Reserved", "erf.flags.res",
         FT_UINT8, BASE_DEC, NULL, ERF_HDR_RES_MASK, NULL, HFILL } },
     { &hf_erf_rlen,
       { "Record length", "erf.rlen",
         FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
     { &hf_erf_lctr,
       { "Loss counter", "erf.lctr",
         FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
     { &hf_erf_color,
       { "Color", "erf.color",
         FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
     { &hf_erf_wlen,
       { "Wire length", "erf.wlen",
         FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_ehdr_t,
      { "Extension Header", "erf.ehdr.types",
        FT_UINT8, BASE_DEC, VALS(ehdr_type_vals), 0x0, NULL, HFILL } },

    /* Intercept ID Extension Header */
    { &hf_erf_ehdr_int_res1,
      { "Reserved", "erf.ehdr.int.res1",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_ehdr_int_id,
      { "Intercept ID", "erf.ehdr.int.intid",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_ehdr_int_res2,
      { "Reserved", "erf.ehdr.int.res2",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    /* Raw Link Extension Header */
    { &hf_erf_ehdr_raw_link_res,
      { "Reserved", "erf.ehdr.raw.res",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_ehdr_raw_link_seqnum,
      { "Sequence number", "erf.ehdr.raw.seqnum",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_ehdr_raw_link_rate,
      { "Rate", "erf.ehdr.raw.rate",
        FT_UINT8, BASE_DEC, VALS(raw_link_rates), 0x0, NULL, HFILL } },
    { &hf_erf_ehdr_raw_link_type,
      { "Link Type", "erf.ehdr.raw.link_type",
        FT_UINT8, BASE_DEC, VALS(raw_link_types), 0x0, NULL, HFILL } },

    /* Classification Extension Header */
    { &hf_erf_ehdr_class_flags,
      { "Flags", "erf.ehdr.class.flags",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_ehdr_class_flags_sh,
      { "Search hit", "erf.ehdr.class.flags.sh",
        FT_UINT32, BASE_DEC, NULL, EHDR_CLASS_SH_MASK, NULL, HFILL } },
    { &hf_erf_ehdr_class_flags_shm,
      { "Multiple search hits", "erf.ehdr.class.flags.shm",
        FT_UINT32, BASE_DEC, NULL, EHDR_CLASS_SHM_MASK, NULL, HFILL } },
    { &hf_erf_ehdr_class_flags_res1,
      { "Reserved", "erf.ehdr.class.flags.res1",
        FT_UINT32, BASE_HEX, NULL, EHDR_CLASS_RES1_MASK, NULL, HFILL } },
    { &hf_erf_ehdr_class_flags_user,
      { "User classification", "erf.ehdr.class.flags.user",
        FT_UINT32, BASE_DEC, NULL, EHDR_CLASS_USER_MASK, NULL, HFILL } },
    { &hf_erf_ehdr_class_flags_res2,
      { "Reserved", "erf.ehdr.class.flags.res2",
        FT_UINT32, BASE_HEX, NULL, EHDR_CLASS_RES2_MASK, NULL, HFILL } },
    { &hf_erf_ehdr_class_flags_drop,
      { "Drop Steering Bit", "erf.ehdr.class.flags.drop",
        FT_UINT32, BASE_DEC, NULL, EHDR_CLASS_DROP_MASK, NULL, HFILL } },
    { &hf_erf_ehdr_class_flags_str,
      { "Stream Steering Bits", "erf.ehdr.class.flags.str",
        FT_UINT32, BASE_DEC, NULL, EHDR_CLASS_STER_MASK, NULL, HFILL } },
    { &hf_erf_ehdr_class_seqnum,
      { "Sequence number", "erf.ehdr.class.seqnum",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    /* BFS Extension Header */
    { &hf_erf_ehdr_bfs_hash,
      { "Hash", "erf.ehdr.bfs.hash",
        FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_bfs_color,
      { "Filter Color", "erf.ehdr.bfs.color",
        FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_bfs_raw_hash,
      { "Raw Hash", "erf.ehdr.bfs.rawhash",
        FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },

    /* Channelised Extension Header */
    { &hf_erf_ehdr_chan_morebits,
      { "More Bits", "erf.ehdr.chan.morebits",
        FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_chan_morefrag,
      { "More Fragments", "erf.ehdr.chan.morefrag",
        FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_chan_seqnum,
      { "Sequence Number", "erf.ehdr.chan.seqnum",
        FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_chan_res,
      { "Reserved", "erf.ehdr.chan.res",
        FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_chan_virt_container_id,
      { "Virtual Container ID", "erf.ehdr.chan.vcid",
        FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_chan_assoc_virt_container_size,
      { "Associated Virtual Container Size", "erf.ehdr.chan.vcsize",
        FT_UINT8, BASE_HEX, VALS(channelised_assoc_virt_container_size), 0, NULL, HFILL } },
    { &hf_erf_ehdr_chan_rate,
      { "Origin Line Type/Rate", "erf.ehdr.chan.rate",
        FT_UINT8, BASE_HEX, VALS(channelised_rate), 0, NULL, HFILL } },
    { &hf_erf_ehdr_chan_type,
      { "Frame Part Type", "erf.ehdr.chan.type",
        FT_UINT8, BASE_HEX, VALS(channelised_type), 0, NULL, HFILL } },

    /* Signature Extension Header */
    { &hf_erf_ehdr_signature_payload_hash,
      { "Payload Hash", "erf.ehdr.signature.payloadhash",
        FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_signature_color,
      { "Filter Color", "erf.ehdr.signature.color",
        FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_signature_flow_hash,
      { "Flow Hash", "erf.ehdr.signature.flowhash",
        FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL } },

    /* Flow ID Extension Header */
    { &hf_erf_ehdr_flow_id_source_id,
      { "Source ID", "erf.ehdr.flowid.sourceid",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_flow_id_hash_type,
      { "Hash Type", "erf.ehdr.flowid.hashtype",
        FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_flow_id_hash_type_type,
      { "Type", "erf.ehdr.flowid.hashtype.type",
        FT_UINT8, BASE_DEC, VALS(erf_hash_type), ERF_EHDR_FLOW_ID_HASH_TYPE_TYPE_MASK, NULL, HFILL } },
    { &hf_erf_ehdr_flow_id_hash_type_inner,
      { "Hash is for Tunnel Inner", "erf.ehdr.flowid.hashtype.inner",
        FT_UINT8, BASE_DEC, NULL, ERF_EHDR_FLOW_ID_HASH_TYPE_INNER_MASK, NULL, HFILL } },
    { &hf_erf_ehdr_flow_id_stack_type,
      { "Stack Type", "erf.ehdr.flowid.stacktype",
        FT_UINT8, BASE_HEX, VALS(erf_stack_type), 0, NULL, HFILL } },
    { &hf_erf_ehdr_flow_id_flow_hash,
      { "Flow Hash", "erf.ehdr.flowid.flowhash",
        FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },

    /* Host ID Extension Header */
    { &hf_erf_ehdr_host_id_sourceid,
      { "Source ID", "erf.ehdr.hostid.sourceid",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_erf_ehdr_host_id_hostid,
      { "Host ID", "erf.ehdr.hostid.hostid",
        FT_UINT48, BASE_HEX, NULL, 0, NULL, HFILL } },

    /* Anchor ID Extension Header */
    { &hf_erf_ehdr_anchor_id_flags,
     { "Flags", "erf.ehdr.anchorid.flags",
        FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL} },
    { &hf_erf_ehdr_anchor_id_definition,
     { "Anchor Definition", "erf.ehdr.anchorid.flags.definition",
        FT_BOOLEAN, 8 /*bits in bitfield*/, NULL, 0x80, NULL, HFILL} },
    { &hf_erf_ehdr_anchor_id_reserved,
     { "Reserved", "erf.ehdr.anchorid.flags.rsvd",
        FT_UINT8, BASE_HEX, NULL, 0x7f, NULL, HFILL} },
    { &hf_erf_ehdr_anchor_id_anchorid,
     { "Anchor ID", "erf.ehdr.anchorid.anchorid",
        FT_UINT48, BASE_HEX, NULL, 0, NULL, HFILL} },

    /* Generated fields for navigating Host ID/Anchor ID */
    { &hf_erf_anchor_linked,
      {"Linked Frame", "erf.anchor.frame",
        FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL} },
    { &hf_erf_anchor_anchorid,
      { "Anchor ID", "erf.anchor.anchorid",
        FT_UINT48, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_erf_anchor_hostid,
      { "Host ID", "erf.anchor.hostid",
        FT_UINT48, BASE_HEX, NULL, 0, NULL, HFILL } },

    /* Generated fields for navigating Host ID/Source ID */
    { &hf_erf_sourceid,
      { "Source ID", "erf.sourceid",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_erf_hostid,
      { "Host ID", "erf.hostid",
        FT_UINT48, BASE_HEX, NULL, 0, NULL, HFILL } },
    { &hf_erf_source_current,
      { "Next Metadata in Source", "erf.source_meta_frame_current",
        FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_erf_source_next,
      { "Next Metadata in Source", "erf.source_meta_frame_next",
        FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_erf_source_prev,
      { "Previous Metadata in Source", "erf.source_meta_frame_prev",
        FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL } },

    /* Entropy Extension Header */
    { &hf_erf_ehdr_entropy_entropy,
     { "Entropy", "erf.ehdr.entropy.entropy",
        FT_FLOAT, BASE_NONE, NULL, 0, NULL, HFILL} },
    { &hf_erf_ehdr_entropy_entropy_raw,
     { "Raw Entropy", "erf.ehdr.entropy.entropy.raw",
        FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL} },
    { &hf_erf_ehdr_entropy_reserved,
     { "Reserved", "erf.ehdr.entropy.rsvd",
        FT_UINT48, BASE_HEX, NULL, 0, NULL, HFILL} },

    /* Unknown Extension Header */
    { &hf_erf_ehdr_unk,
      { "Data", "erf.ehdr.unknown.data",
        FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    /* MC HDLC Header */
    { &hf_erf_mc_hdlc,
      { "Multi Channel HDLC Header", "erf.mchdlc",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_mc_hdlc_cn,
      { "Connection number", "erf.mchdlc.cn",
        FT_UINT32, BASE_DEC, NULL, MC_HDLC_CN_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_res1,
      { "Reserved", "erf.mchdlc.res1",
        FT_UINT32, BASE_HEX, NULL, MC_HDLC_RES1_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_res2,
      { "Reserved", "erf.mchdlc.res2",
        FT_UINT32, BASE_HEX, NULL, MC_HDLC_RES2_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_fcse,
      { "FCS error", "erf.mchdlc.fcse",
        FT_UINT32, BASE_DEC, NULL, MC_HDLC_FCSE_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_sre,
      { "Short record error", "erf.mchdlc.sre",
        FT_UINT32, BASE_DEC, NULL, MC_HDLC_SRE_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_lre,
      { "Long record error", "erf.mchdlc.lre",
        FT_UINT32, BASE_DEC, NULL, MC_HDLC_LRE_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_afe,
      { "Aborted frame error", "erf.mchdlc.afe",
        FT_UINT32, BASE_DEC, NULL, MC_HDLC_AFE_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_oe,
      { "Octet error", "erf.mchdlc.oe",
        FT_UINT32, BASE_DEC, NULL, MC_HDLC_OE_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_lbe,
      { "Lost byte error", "erf.mchdlc.lbe",
        FT_UINT32, BASE_DEC, NULL, MC_HDLC_LBE_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_first,
      { "First record", "erf.mchdlc.first",
        FT_UINT32, BASE_DEC, NULL, MC_HDLC_FIRST_MASK, NULL, HFILL } },
    { &hf_erf_mc_hdlc_res3,
      { "Reserved", "erf.mchdlc.res3",
        FT_UINT32, BASE_HEX, NULL, MC_HDLC_RES3_MASK, NULL, HFILL } },

    /* MC RAW Header */
    { &hf_erf_mc_raw,
      { "Multi Channel RAW Header", "erf.mcraw",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_mc_raw_int,
      { "Physical interface", "erf.mcraw.int",
        FT_UINT32, BASE_DEC, NULL, MC_RAW_INT_MASK, NULL, HFILL } },
    { &hf_erf_mc_raw_res1,
      { "Reserved", "erf.mcraw.res1",
        FT_UINT32, BASE_HEX, NULL, MC_RAW_RES1_MASK, NULL, HFILL } },
    { &hf_erf_mc_raw_sre,
      { "Short record error", "erf.mcraw.sre",
        FT_UINT32, BASE_DEC, NULL, MC_RAW_SRE_MASK, NULL, HFILL } },
    { &hf_erf_mc_raw_lre,
      { "Long record error", "erf.mcraw.lre",
        FT_UINT32, BASE_DEC, NULL, MC_RAW_LRE_MASK, NULL, HFILL } },
    { &hf_erf_mc_raw_res2,
      { "Reserved", "erf.mcraw.res2",
        FT_UINT32, BASE_HEX, NULL, MC_RAW_RES2_MASK, NULL, HFILL } },
    { &hf_erf_mc_raw_lbe,
      { "Lost byte error", "erf.mcraw.lbe",
        FT_UINT32, BASE_DEC, NULL, MC_RAW_LBE_MASK, NULL, HFILL } },
    { &hf_erf_mc_raw_first,
      { "First record", "erf.mcraw.first",
        FT_UINT32, BASE_DEC, NULL, MC_RAW_FIRST_MASK, NULL, HFILL } },
    { &hf_erf_mc_raw_res3,
      { "Reserved", "erf.mcraw.res3",
        FT_UINT32, BASE_HEX, NULL, MC_RAW_RES3_MASK, NULL, HFILL } },

    /* MC ATM Header */
    { &hf_erf_mc_atm,
      { "Multi Channel ATM Header", "erf.mcatm",
        FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL } },
    { &hf_erf_mc_atm_cn,
      { "Connection number", "erf.mcatm.cn",
        FT_UINT32, BASE_DEC, NULL, MC_ATM_CN_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_res1,
      { "Reserved", "erf.mcatm.res1",
        FT_UINT32, BASE_HEX, NULL, MC_ATM_RES1_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_mul,
      { "Multiplexed", "erf.mcatm.mul",
        FT_UINT32, BASE_DEC, NULL, MC_ATM_MUL_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_port,
      { "Physical port", "erf.mcatm.port",
        FT_UINT32, BASE_DEC, NULL, MC_ATM_PORT_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_res2,
      { "Reserved", "erf.mcatm.res2",
        FT_UINT32, BASE_HEX, NULL, MC_ATM_RES2_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_lbe,
      { "Lost Byte Error", "erf.mcatm.lbe",
        FT_UINT32, BASE_DEC, NULL, MC_ATM_LBE_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_hec,
      { "HEC corrected", "erf.mcatm.hec",
        FT_UINT32, BASE_DEC, NULL, MC_ATM_HEC_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_crc10,
      { "OAM Cell CRC10 Error (not implemented)", "erf.mcatm.crc10",
        FT_UINT32, BASE_DEC, NULL, MC_ATM_CRC10_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_oamcell,
      { "OAM Cell", "erf.mcatm.oamcell",
        FT_UINT32, BASE_DEC, NULL, MC_ATM_OAMCELL_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_first,
      { "First record", "erf.mcatm.first",
        FT_UINT32, BASE_DEC, NULL, MC_ATM_FIRST_MASK, NULL, HFILL } },
    { &hf_erf_mc_atm_res3,
      { "Reserved", "erf.mcatm.res3",
        FT_UINT32, BASE_HEX, NULL, MC_ATM_RES3_MASK, NULL, HFILL } },

    /* MC RAW Link Header */
    { &hf_erf_mc_rawl,
      { "Multi Channel RAW Link Header", "erf.mcrawl",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_mc_rawl_cn,
      { "Connection number", "erf.mcrawl.cn",
        FT_UINT32, BASE_DEC, NULL, MC_RAWL_CN_MASK, NULL, HFILL } },
    { &hf_erf_mc_rawl_res1,
      { "Reserved", "erf.mcrawl.res1",
        FT_UINT32, BASE_HEX, NULL, MC_RAWL_RES2_MASK, NULL, HFILL } },
    { &hf_erf_mc_rawl_lbe,
      { "Lost byte error", "erf.mcrawl.lbe",
        FT_UINT32, BASE_DEC, NULL, MC_RAWL_LBE_MASK, NULL, HFILL } },
    { &hf_erf_mc_rawl_first,
      { "First record", "erf.mcrawl.first",
        FT_UINT32, BASE_DEC, NULL, MC_RAWL_FIRST_MASK, NULL, HFILL } },
    { &hf_erf_mc_rawl_res2,
      { "Reserved", "erf.mcrawl.res2",
        FT_UINT32, BASE_HEX, NULL, MC_RAWL_RES2_MASK, NULL, HFILL } },

    /* MC AAL5 Header */
    { &hf_erf_mc_aal5,
      { "Multi Channel AAL5 Header", "erf.mcaal5",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_mc_aal5_cn,
      { "Connection number", "erf.mcaal5.cn",
        FT_UINT32, BASE_DEC, NULL, MC_AAL5_CN_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_res1,
      { "Reserved", "erf.mcaal5.res1",
        FT_UINT32, BASE_HEX, NULL, MC_AAL5_RES1_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_port,
      { "Physical port", "erf.mcaal5.port",
        FT_UINT32, BASE_DEC, NULL, MC_AAL5_PORT_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_crcck,
      { "CRC checked", "erf.mcaal5.crcck",
        FT_UINT32, BASE_DEC, NULL, MC_AAL5_CRCCK_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_crce,
      { "CRC error", "erf.mcaal5.crce",
        FT_UINT32, BASE_DEC, NULL, MC_AAL5_CRCE_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_lenck,
      { "Length checked", "erf.mcaal5.lenck",
        FT_UINT32, BASE_DEC, NULL, MC_AAL5_LENCK_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_lene,
      { "Length error", "erf.mcaal5.lene",
        FT_UINT32, BASE_DEC, NULL, MC_AAL5_LENE_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_res2,
      { "Reserved", "erf.mcaal5.res2",
        FT_UINT32, BASE_HEX, NULL, MC_AAL5_RES2_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_first,
      { "First record", "erf.mcaal5.first",
        FT_UINT32, BASE_DEC, NULL, MC_AAL5_FIRST_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal5_res3,
      { "Reserved", "erf.mcaal5.res3",
        FT_UINT32, BASE_HEX, NULL, MC_AAL5_RES3_MASK, NULL, HFILL } },

    /* MC AAL2 Header */
    { &hf_erf_mc_aal2,
      { "Multi Channel AAL2 Header", "erf.mcaal2",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_mc_aal2_cn,
      { "Connection number", "erf.mcaal2.cn",
        FT_UINT32, BASE_DEC, NULL, MC_AAL2_CN_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal2_res1,
      { "Reserved for extra connection", "erf.mcaal2.res1",
        FT_UINT32, BASE_HEX, NULL, MC_AAL2_RES1_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal2_res2,
      { "Reserved for type", "erf.mcaal2.mul",
        FT_UINT32, BASE_HEX, NULL, MC_AAL2_RES2_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal2_port,
      { "Physical port", "erf.mcaal2.port",
        FT_UINT32, BASE_DEC, NULL, MC_AAL2_PORT_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal2_res3,
      { "Reserved", "erf.mcaal2.res2",
        FT_UINT32, BASE_HEX, NULL, MC_AAL2_RES3_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal2_first,
      { "First cell received", "erf.mcaal2.lbe",
        FT_UINT32, BASE_DEC, NULL, MC_AAL2_FIRST_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal2_maale,
      { "MAAL error", "erf.mcaal2.hec",
        FT_UINT32, BASE_DEC, NULL, MC_AAL2_MAALE_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal2_lene,
      { "Length error", "erf.mcaal2.crc10",
        FT_UINT32, BASE_DEC, NULL, MC_AAL2_LENE_MASK, NULL, HFILL } },
    { &hf_erf_mc_aal2_cid,
      { "Channel Identification Number", "erf.mcaal2.cid",
        FT_UINT32, BASE_DEC, NULL, MC_AAL2_CID_MASK, NULL, HFILL } },

    /* AAL2 Header */
    { &hf_erf_aal2,
      { "AAL2 Header", "erf.aal2",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_aal2_cid,
      { "Channel Identification Number", "erf.aal2.cid",
        FT_UINT32, BASE_DEC, NULL, AAL2_CID_MASK, NULL, HFILL } },
    { &hf_erf_aal2_maale,
      { "MAAL error number", "erf.aal2.maale",
        FT_UINT32, BASE_DEC, NULL, AAL2_MAALE_MASK, NULL, HFILL } },
    { &hf_erf_aal2_maalei,
      { "MAAL error", "erf.aal2.hec",
        FT_UINT32, BASE_DEC, NULL, AAL2_MAALEI_MASK, NULL, HFILL } },
    { &hf_erf_aal2_first,
      { "First cell received", "erf.aal2.lbe",
        FT_UINT32, BASE_DEC, NULL, AAL2_FIRST_MASK, NULL, HFILL } },
    { &hf_erf_aal2_res1,
      { "Reserved", "erf.aal2.res1",
        FT_UINT32, BASE_HEX, NULL, AAL2_RES1_MASK, NULL, HFILL } },

    /* ETH Header */
    { &hf_erf_eth,
      { "Ethernet pad", "erf.eth",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_eth_off,
      { "Offset", "erf.eth.off",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_eth_pad,
      { "Padding", "erf.eth.pad",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },

    /* Provenance record unknown tags */
    { &hf_erf_meta_tag_type,
      { "Tag Type", "erf.meta.tag.type",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_meta_tag_len,
      { "Tag Length", "erf.meta.tag.len",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_erf_meta_tag_unknown,
      { "Unknown Tag", "erf.meta.unknown",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } }
  };

  static int *ett[] = {
    &ett_erf,
    &ett_erf_pseudo_hdr,
    &ett_erf_rectype,
    &ett_erf_hash_type,
    &ett_erf_flags,
    &ett_erf_mc_hdlc,
    &ett_erf_mc_raw,
    &ett_erf_mc_atm,
    &ett_erf_mc_rawlink,
    &ett_erf_mc_aal5,
    &ett_erf_mc_aal2,
    &ett_erf_aal2,
    &ett_erf_eth,
    &ett_erf_meta,
    &ett_erf_meta_tag,
    &ett_erf_source,
    &ett_erf_anchor,
    &ett_erf_anchor_flags,
    &ett_erf_entropy_value
  };

  static const enum_val_t erf_hdlc_options[] = {
    { "chdlc",  "Cisco HDLC",       ERF_HDLC_CHDLC },
    { "ppp",    "PPP serial",       ERF_HDLC_PPP },
    { "frelay", "Frame Relay",      ERF_HDLC_FRELAY },
    { "mtp2",   "SS7 MTP2",         ERF_HDLC_MTP2 },
    { "guess",  "Attempt to guess", ERF_HDLC_GUESS },
    { NULL, NULL, 0 }
  };

  static const enum_val_t erf_aal5_options[] = {
    { "guess", "Attempt to guess", ERF_AAL5_GUESS },
    { "llc",   "LLC multiplexed",  ERF_AAL5_LLC },
    { "unspec", "Unspecified", ERF_AAL5_UNSPEC },
    { NULL, NULL, 0 }
  };

  static ei_register_info ei[] = {
      { &ei_erf_mc_hdlc_checksum_error, { "erf.mchdlc.checksum.error", PI_CHECKSUM, PI_ERROR, "ERF MC HDLC FCS Error", EXPFILL }},
      { &ei_erf_mc_hdlc_short_error, { "erf.mchdlc.short.error", PI_RECEIVE, PI_ERROR, "ERF MC HDLC Short Record Error, <5 bytes", EXPFILL }},
      { &ei_erf_mc_hdlc_long_error, { "erf.mchdlc.long.error", PI_RECEIVE, PI_ERROR, "ERF MC HDLC Long Record Error, >2047 bytes", EXPFILL }},
      { &ei_erf_mc_hdlc_abort_error, { "erf.mchdlc.abort.error", PI_RECEIVE, PI_ERROR, "ERF MC HDLC Aborted Frame Error", EXPFILL }},
      { &ei_erf_mc_hdlc_octet_error, { "erf.mchdlc.octet.error", PI_RECEIVE, PI_ERROR, "ERF MC HDLC Octet Error, the closing flag was not octet aligned after bit unstuffing", EXPFILL }},
      { &ei_erf_mc_hdlc_lost_byte_error, { "erf.mchdlc.lost_byte.error", PI_RECEIVE, PI_ERROR, "ERF MC HDLC Lost Byte Error", EXPFILL }},
      { &ei_erf_rx_error, { "erf.rx.error", PI_INTERFACE, PI_ERROR, "ERF RX Error", EXPFILL }},
      { &ei_erf_ds_error, { "erf.ds.error", PI_INTERFACE, PI_ERROR, "ERF DS Error", EXPFILL }},
      { &ei_erf_truncation_error, { "erf.truncation.error", PI_INTERFACE, PI_ERROR, "ERF Truncation Error", EXPFILL }},
      { &ei_erf_packet_loss, { "erf.packet_loss", PI_INTERFACE, PI_WARN, "Packet loss occurred between previous and current packet", EXPFILL }},
      { &ei_erf_extension_headers_not_shown, { "erf.ehdr.more_not_shown", PI_INTERFACE, PI_WARN, "More extension headers were present, not shown", EXPFILL }},
      { &ei_erf_meta_section_len_error, { "erf.meta.section_len.error", PI_PROTOCOL, PI_ERROR, "Provenance Section Length incorrect", EXPFILL }},
      { &ei_erf_meta_truncated_record, { "erf.meta.truncated_record", PI_MALFORMED, PI_ERROR, "Provenance truncated record", EXPFILL }},
      { &ei_erf_meta_truncated_tag, { "erf.meta.truncated_tag", PI_PROTOCOL, PI_ERROR, "Provenance truncated tag", EXPFILL }},
      { &ei_erf_meta_zero_len_tag, { "erf.meta.zero_len_tag", PI_PROTOCOL, PI_NOTE, "Provenance zero length tag", EXPFILL }},
      { &ei_erf_meta_reset, { "erf.meta.metadata_reset", PI_PROTOCOL, PI_WARN, "Provenance metadata reset", EXPFILL }}
  };

  module_t *erf_module;
  expert_module_t* expert_erf;

  proto_erf = proto_register_protocol("Extensible Record Format", "ERF", "erf");
  erf_handle = register_dissector("erf", dissect_erf, proto_erf);

  init_meta_tags();

  proto_register_field_array(proto_erf, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_erf = expert_register_protocol(proto_erf);
  expert_register_field_array(expert_erf, ei, array_length(ei));

  /* Register per-section Provenance fields */
  proto_register_field_array(proto_erf, (hf_register_info*) wmem_array_get_raw(erf_meta_index.hfri), (int) wmem_array_get_count(erf_meta_index.hfri));
  proto_register_subtree_array((int**) wmem_array_get_raw(erf_meta_index.ett), (int) wmem_array_get_count(erf_meta_index.ett));

  erf_module = prefs_register_protocol(proto_erf, NULL);

  prefs_register_enum_preference(erf_module, "hdlc_type", "ERF_HDLC Layer 2",
                                 "Protocol encapsulated in HDLC records",
                                 &erf_hdlc_type, erf_hdlc_options, false);

  prefs_register_bool_preference(erf_module, "rawcell_first",
                                 "Raw ATM cells are first cell of AAL5 PDU",
                                 "Whether raw ATM cells should be treated as "
                                 "the first cell of an AAL5 PDU",
                                 &erf_rawcell_first);

  prefs_register_enum_preference(erf_module, "aal5_type",
                                 "ATM AAL5 packet type",
                                 "Protocol encapsulated in ATM AAL5 packets",
                                 &erf_aal5_type, erf_aal5_options, false);

  /*
   * We just use eth_maybefcs now and respect the Ethernet preference.
   * ERF records usually have FCS.
   */
  prefs_register_obsolete_preference(erf_module, "ethfcs");

  erf_dissector_table = register_dissector_table("erf.types.type", "ERF Type", proto_erf, FT_UINT8, BASE_DEC);

  register_init_routine(erf_init_dissection);
  /* No extra cleanup needed */
}

void
proto_reg_handoff_erf(void)
{
  int file_type_subtype_erf;

  dissector_add_uint("wtap_encap", WTAP_ENCAP_ERF, erf_handle);
  /* Also register dissector for Provenance non-packet records */
  file_type_subtype_erf = wtap_name_to_file_type_subtype("erf");
  if (file_type_subtype_erf != -1)
    dissector_add_uint("wtap_fts_rec", file_type_subtype_erf, erf_handle);

  /* Get handles for serial line protocols */
  chdlc_handle  = find_dissector_add_dependency("chdlc", proto_erf);
  ppp_handle    = find_dissector_add_dependency("ppp_hdlc", proto_erf);
  frelay_handle = find_dissector_add_dependency("fr", proto_erf);
  mtp2_handle   = find_dissector_add_dependency("mtp2_with_crc", proto_erf);

  /* Get handle for ATM dissector */
  atm_untruncated_handle = find_dissector_add_dependency("atm_untruncated", proto_erf);

  sdh_handle = find_dissector_add_dependency("sdh", proto_erf);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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

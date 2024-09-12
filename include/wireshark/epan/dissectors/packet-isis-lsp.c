/* packet-isis-lsp.c
 * Routines for decoding isis lsp packets and their CLVs
 *
 * Stuart Stanley <stuarts@mxmail.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
/*
 * Copyright 2011, Malgi Nikitha Vivekananda <malgi.nikitha@ipinfusion.com>
 *                 Krishnamurthy Mayya <krishnamurthy.mayya@ipinfusion.com>
 *                    - Decoding for Router Capability TLV and associated subTLVs as per RFC 6326
 *                    - Decoding for Group Address TLV and associated subTLVs as per RFC 6326
 *
 * Copyright 2019, Rohan Saini <rohan.saini@nokia.com>
 *     - Support for dissecting BIER Info Sub-TLV (RFC 8401)
 */

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>

#include "packet-osi.h"
#include "packet-isis.h"
#include "packet-isis-clv.h"
#include <epan/addr_resolv.h>

/*
 * Declarations for L1/L2 LSP base header.
 */

/* P | ATT | HIPPITY | DS FIELD description */
#define ISIS_LSP_PARTITION_MASK     0x80
#define ISIS_LSP_PARTITION_SHIFT    7
#define ISIS_LSP_PARTITION(info)    (((info) & ISIS_LSP_PARTITION_MASK) >> ISIS_LSP_PARTITION_SHIFT)

#define ISIS_LSP_ATT_MASK           0x78
#define ISIS_LSP_ATT_SHIFT          3
#define ISIS_LSP_ATT(info)          (((info) & ISIS_LSP_ATT_MASK) >> ISIS_LSP_ATT_SHIFT)

#define ISIS_LSP_ATT_ERROR(info)    ((info) >> 3)
#define ISIS_LSP_ATT_EXPENSE(info)  (((info) >> 2) & 1)
#define ISIS_LSP_ATT_DELAY(info)    (((info) >> 1) & 1)
#define ISIS_LSP_ATT_DEFAULT(info)  ((info) & 1)

#define ISIS_LSP_HIPPITY_MASK       0x04
#define ISIS_LSP_HIPPITY_SHIFT      2
#define ISIS_LSP_HIPPITY(info)      (((info) & ISIS_LSP_HIPPITY_MASK) >> ISIS_LSP_HIPPITY_SHIFT)

#define ISIS_LSP_IS_TYPE_MASK       0x03
#define ISIS_LSP_IS_TYPE(info)      ((info) & ISIS_LSP_IS_TYPE_MASK)

#define ISIS_LSP_MT_MSHIP_RES_MASK  0xF000
#define ISIS_LSP_MT_MSHIP_ID_MASK   0x0FFF


#define ISIS_LSP_TYPE_UNUSED0       0
#define ISIS_LSP_TYPE_LEVEL_1       1
#define ISIS_LSP_TYPE_UNUSED2       2
#define ISIS_LSP_TYPE_LEVEL_2       3

#define ISIS_LSP_ATTACHED_NONE      0
#define ISIS_LSP_ATTACHED_DEFAULT   1
#define ISIS_LSP_ATTACHED_DELAY     2
#define ISIS_LSP_ATTACHED_EXPENSE   4
#define ISIS_LSP_ATTACHED_ERROR     8

/*
 * The "supported" bit in a metric is actually the "not supported" bit;
 * if it's *clear*, the metric is supported, and if it's *set*, the
 * metric is not supported.
 */
#define ISIS_LSP_CLV_METRIC_SUPPORTED(x)    (!((x)&0x80))
#define ISIS_LSP_CLV_METRIC_IE(x)           ((x)&0x40)
#define ISIS_LSP_CLV_METRIC_RESERVED(x)     ((x)&0x40)
#define ISIS_LSP_CLV_METRIC_UPDOWN(x)       ((x)&0x80)
#define ISIS_LSP_CLV_METRIC_VALUE(x)        ((x)&0x3f)

/* Sub-TLVs under Router Capability and MT Capability TLVs
   As per RFC 7176 section 2.3
   http://www.iana.org/assignments/isis-tlv-codepoints/isis-tlv-codepoints.xhtml#isis-tlv-codepoints-242
 */
#define ISIS_TE_NODE_CAP_DESC     1
#define SEGMENT_ROUTING_CAP       2            /* draft-ietf-isis-segment-routing-extensions-03 */
#define NICKNAME                  6
#define TREES                     7
#define TREE_IDENTIFIER           8
#define TREES_USED_IDENTIFIER     9
#define INTERESTED_VLANS         10
#define IPV6_TE_ROUTER_ID        12
#define TRILL_VERSION            13
#define VLAN_GROUP               14
#define SEGMENT_ROUTING_ALG      19
#define SEGMENT_ROUTING_LB       22
#define NODE_MSD                 23            /* rfc8491 */
#define SRV6_CAP                 25            /* rfc9352 */
#define FLEX_ALGO_DEF            26            /* draft-ietf-lsr-flex-algo-16 */


/*Sub-TLVs under Group Address TLV*/
#define GRP_MAC_ADDRESS 1
#define GRP_IPV4_ADDRESS 2
#define GRP_IPV6_ADDRESS 3

/* sub-TLV's under SID/Label binding TLV */
#define ISIS_LSP_SL_SUB_SID_LABEL   1
#define ISIS_LSP_SL_SUB_PREFIX_SID  3
#define ISIS_LSP_SL_SUB_ADJ_SID     31
#define ISIS_LSP_SL_SUB_LAN_ADJ_SID 32

/* Segment Routing Sub-TLV */
#define ISIS_SR_SID_LABEL           1

/*
    From: https://www.iana.org/assignments/igp-parameters/igp-parameters.xhtml
    IGP Algorithm Types
*/
#define ISIS_ALG_SPF  0
#define ISIS_ALG_SSPF 1

/* IGP MSD Type (rfc8491/rfc9352) */
#define IGP_MSD_TYPE_RESERVED       0
#define IGP_MSD_TYPE_MPLS           1
#define IGP_MSD_TYPE_SEGMENT_LEFT   41
#define IGP_MSD_TYPE_END_POP        42
#define IGP_MSD_TYPE_H_ENCAP        44
#define IGP_MSD_TYPE_END_D          45

/* Flex Algo Definition Sub-TLV (draft-ietf-lsr-flex-algo-16) */
#define FAD_EXCLUDE_AG              1
#define FAD_INCLUDE_ANY_AG          2
#define FAD_INCLUDE_ALL_AG          3
#define FAD_DEF_FLAGS               4
#define FAD_EXCLUDE_SRLG            5

/* Prefix Attribute Flags Sub-TLV (rfc7794)*/
#define ISIS_LSP_PFX_ATTR_FLAG_X    0x80
#define ISIS_LSP_PFX_ATTR_FLAG_R    0x40
#define ISIS_LSP_PFX_ATTR_FLAG_N    0x20

const range_string mtid_strings[] = {
  {    0,    0, "Standard topology" },
  {    1,    1, "IPv4 In-Band Management" },
  {    2,    2, "IPv6 routing topology" },
  {    3,    3, "IPv4 multicast routing topology" },
  {    4,    4, "IPv6 multicast routing topology" },
  {    5,    5, "IPv6 in-band management" },
  {    6, 3995, "Reserved for IETF Consensus" },
  { 3996, 4095, "Development, Experimental and Proprietary features" },
  {    0,    0, NULL }
} ;

void proto_register_isis_lsp(void);
void proto_reg_handoff_isis_lsp(void);

static int proto_isis_lsp;

/* lsp packets */
static int hf_isis_lsp_pdu_length;
static int hf_isis_lsp_remaining_life;
static int hf_isis_lsp_sequence_number;
static int hf_isis_lsp_lsp_id;
static int hf_isis_lsp_hostname;
static int hf_isis_lsp_srlg_system_id;
static int hf_isis_lsp_srlg_pseudo_num;
static int hf_isis_lsp_srlg_flags_numbered;
static int hf_isis_lsp_srlg_ipv4_local;
static int hf_isis_lsp_srlg_ipv4_remote;
static int hf_isis_lsp_srlg_value;
static int hf_isis_lsp_checksum;
static int hf_isis_lsp_checksum_status;
static int hf_isis_lsp_clv_ipv4_int_addr;
static int hf_isis_lsp_clv_ipv6_int_addr;
static int hf_isis_lsp_clv_te_router_id;
static int hf_isis_lsp_clv_mt;
static int hf_isis_lsp_p;
static int hf_isis_lsp_att;
static int hf_isis_lsp_hippity;
static int hf_isis_lsp_is_type;
static int hf_isis_lsp_clv_type;
static int hf_isis_lsp_clv_length;
static int hf_isis_lsp_root_id;
static int hf_isis_lsp_bw_ct_model;
static int hf_isis_lsp_bw_ct_reserved;
static int hf_isis_lsp_bw_ct0;
static int hf_isis_lsp_bw_ct1;
static int hf_isis_lsp_bw_ct2;
static int hf_isis_lsp_bw_ct3;
static int hf_isis_lsp_bw_ct4;
static int hf_isis_lsp_bw_ct5;
static int hf_isis_lsp_bw_ct6;
static int hf_isis_lsp_bw_ct7;
static int hf_isis_lsp_spb_link_metric;
static int hf_isis_lsp_spb_port_count;
static int hf_isis_lsp_spb_port_id;
static int hf_isis_lsp_adj_sid_flags;
static int hf_isis_lsp_adj_sid_family_flag;
static int hf_isis_lsp_adj_sid_backup_flag;
static int hf_isis_lsp_adj_sid_value_flag;
static int hf_isis_lsp_adj_sid_local_flag;
static int hf_isis_lsp_adj_sid_set_flag;
static int hf_isis_lsp_adj_sid_weight;
static int hf_isis_lsp_adj_sid_system_id;
static int hf_isis_lsp_sid_sli_label;
static int hf_isis_lsp_sid_sli_index;
static int hf_isis_lsp_sid_sli_ipv6;
static int hf_isis_lsp_spb_reserved;
static int hf_isis_lsp_spb_sr_bit;
static int hf_isis_lsp_spb_spvid;
static int hf_isis_lsp_spb_short_mac_address_t;
static int hf_isis_lsp_spb_short_mac_address_r;
static int hf_isis_lsp_spb_short_mac_address_reserved;
static int hf_isis_lsp_spb_short_mac_address;
/* TLV 149 items draft-previdi-isis-segment-routing-extensions */
static int hf_isis_lsp_sl_binding_flags;
static int hf_isis_lsp_sl_binding_flags_f;
static int hf_isis_lsp_sl_binding_flags_m;
static int hf_isis_lsp_sl_binding_flags_s;
static int hf_isis_lsp_sl_binding_flags_d;
static int hf_isis_lsp_sl_binding_flags_a;
static int hf_isis_lsp_sl_binding_flags_rsv;
static int hf_isis_lsp_sl_binding_weight;
static int hf_isis_lsp_sl_binding_range;
static int hf_isis_lsp_sl_binding_prefix_length;
static int hf_isis_lsp_sl_binding_fec_prefix_ipv4;
static int hf_isis_lsp_sl_binding_fec_prefix_ipv6;
static int hf_isis_lsp_sl_sub_tlv;
static int hf_isis_lsp_sl_sub_tlv_type;
static int hf_isis_lsp_sl_sub_tlv_length;
static int hf_isis_lsp_sl_sub_tlv_label_20;
static int hf_isis_lsp_sl_sub_tlv_label_32;
static int hf_isis_lsp_sl_sub_tlv_flags;
static int hf_isis_lsp_sl_sub_tlv_flags_r;
static int hf_isis_lsp_sl_sub_tlv_flags_n;
static int hf_isis_lsp_sl_sub_tlv_flags_p;
static int hf_isis_lsp_sl_sub_tlv_flags_e;
static int hf_isis_lsp_sl_sub_tlv_flags_v;
static int hf_isis_lsp_sl_sub_tlv_flags_l;
static int hf_isis_lsp_sl_sub_tlv_flags_rsv;
static int hf_isis_lsp_sl_sub_tlv_algorithm;
static int hf_isis_lsp_mt_cap_spb_instance_v;
static int hf_isis_lsp_mt_cap_spb_instance_cist_external_root_path_cost;
static int hf_isis_lsp_rt_capable_tree_used_id_starting_tree_no;
static int hf_isis_lsp_mt_cap_spb_instance_bridge_priority;
static int hf_isis_lsp_mt_cap_spbm_service_identifier_base_vid;
static int hf_isis_lsp_mt_cap_spbm_service_identifier_t;
static int hf_isis_lsp_mt_cap_spbm_service_identifier_r;
static int hf_isis_lsp_mt_cap_spbm_service_identifier_reserved;
static int hf_isis_lsp_mt_cap_spbm_service_identifier_i_sid;
static int hf_isis_lsp_64_bit_administrative_tag;
static int hf_isis_lsp_grp_type;
static int hf_isis_lsp_grp_macaddr_length;
static int hf_isis_lsp_grp_ipv4addr_length;
static int hf_isis_lsp_grp_ipv6addr_length;
static int hf_isis_lsp_grp_unknown_length;
static int hf_isis_lsp_grp_macaddr_number_of_sources;
static int hf_isis_lsp_grp_ipv4addr_number_of_sources;
static int hf_isis_lsp_grp_ipv6addr_number_of_sources;
static int hf_isis_lsp_ext_is_reachability_traffic_engineering_default_metric;
static int hf_isis_lsp_grp_macaddr_group_address;
static int hf_isis_lsp_grp_ipv4addr_group_address;
static int hf_isis_lsp_grp_ipv6addr_group_address;
static int hf_isis_lsp_rt_capable_tree_root_id_nickname;
static int hf_isis_lsp_ext_is_reachability_ipv4_interface_address;
static int hf_isis_lsp_ext_ip_reachability_metric;
static int hf_isis_lsp_ext_ip_reachability_ipv4_prefix;
static int hf_isis_lsp_eis_neighbors_es_neighbor_id;
static int hf_isis_lsp_expense_metric;
static int hf_isis_lsp_ext_is_reachability_link_remote_identifier;
static int hf_isis_lsp_rt_capable_vlan_group_secondary_vlan_id;
static int hf_isis_lsp_grp_macaddr_vlan_id;
static int hf_isis_lsp_grp_ipv4addr_vlan_id;
static int hf_isis_lsp_grp_ipv6addr_vlan_id;
static int hf_isis_lsp_rt_capable_trill_affinity_tlv;
static int hf_isis_lsp_rt_capable_trill_fgl_safe;
static int hf_isis_lsp_rt_capable_trill_caps;
static int hf_isis_lsp_rt_capable_trill_flags;
static int hf_isis_lsp_rt_capable_tree_root_id_starting_tree_no;
static int hf_isis_lsp_rt_capable_interested_vlans_nickname;
static int hf_isis_lsp_ip_reachability_ipv4_prefix;
static int hf_isis_lsp_grp_macaddr_topology_id;
static int hf_isis_lsp_grp_ipv4addr_topology_id;
static int hf_isis_lsp_grp_ipv6addr_topology_id;
static int hf_isis_lsp_ext_is_reachability_ipv4_neighbor_address;
static int hf_isis_lsp_ipv6_reachability_reserved_bits;
static int hf_isis_lsp_eis_neighbors_default_metric;
static int hf_isis_lsp_mt_cap_spb_instance_cist_root_identifier;
static int hf_isis_lsp_rt_capable_tree_used_id_nickname;
static int hf_isis_lsp_grp_macaddr_source_address;
static int hf_isis_lsp_grp_ipv4addr_source_address;
static int hf_isis_lsp_grp_ipv6addr_source_address;
static int hf_isis_lsp_delay_metric;
static int hf_isis_lsp_ext_is_reachability_link_local_identifier;
static int hf_isis_lsp_mt_cap_mtid;
static int hf_isis_lsp_32_bit_administrative_tag;
static int hf_isis_lsp_ext_is_reachability_is_neighbor_id;
static int hf_isis_lsp_reservable_link_bandwidth;
static int hf_isis_lsp_rt_capable_vlan_group_primary_vlan_id;
static int hf_isis_lsp_rt_capable_interested_vlans_multicast_ipv4;
static int hf_isis_lsp_rt_capable_interested_vlans_multicast_ipv6;
static int hf_isis_lsp_mt_cap_spb_instance_number_of_trees;
static int hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_u;
static int hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_m;
static int hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_a;
static int hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_reserved;
static int hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_ect;
static int hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_base_vid;
static int hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_spvid;
static int hf_isis_lsp_mt_cap_spb_opaque_algorithm;
static int hf_isis_lsp_mt_cap_spb_opaque_information;
static int hf_isis_lsp_mt_cap_spbm_service_identifier_b_mac;
static int hf_isis_lsp_ipv6_reachability_subclvs_len;
static int hf_isis_lsp_ipv6_reachability_distribution;
static int hf_isis_lsp_ipv6_reachability_distribution_internal;
static int hf_isis_lsp_ipv6_reachability_subtlv;
static int hf_isis_lsp_ipv6_reachability_metric;
static int hf_isis_lsp_ipv6_reachability_prefix_length;
static int hf_isis_lsp_prefix_attr_flags;
static int hf_isis_lsp_prefix_attr_flags_x;
static int hf_isis_lsp_prefix_attr_flags_r;
static int hf_isis_lsp_prefix_attr_flags_n;
static int hf_isis_lsp_rt_capable_trees_maximum_nof_trees_to_compute;
static int hf_isis_lsp_rt_capable_interested_vlans_vlan_start_id;
static int hf_isis_lsp_rt_capable_nickname_nickname_priority;
static int hf_isis_lsp_ext_is_reachability_metric;
static int hf_isis_lsp_ext_is_reachability_subclvs_len;
static int hf_isis_lsp_ext_is_reachability_code;
static int hf_isis_lsp_ext_is_reachability_len;
static int hf_isis_lsp_ext_is_reachability_value;
static int hf_isis_lsp_default_metric;
static int hf_isis_lsp_ext_is_reachability_unidir_link_flags;
static int hf_isis_lsp_ext_is_reachability_unidir_link_flags_a;
static int hf_isis_lsp_ext_is_reachability_unidir_link_reserved;
static int hf_isis_lsp_ext_is_reachability_unidir_link_delay;
static int hf_isis_lsp_ext_is_reachability_unidir_link_delay_min;
static int hf_isis_lsp_ext_is_reachability_unidir_link_delay_max;
static int hf_isis_lsp_ext_is_reachability_unidir_delay_variation;
static int hf_isis_lsp_ext_is_reachability_unidir_link_loss;
static int hf_isis_lsp_ext_is_reachability_unidir_residual_bandwidth;
static int hf_isis_lsp_ext_is_reachability_unidir_available_bandwidth;
static int hf_isis_lsp_ext_is_reachability_unidir_utilized_bandwidth;
static int hf_isis_lsp_ext_ip_reachability_distribution;
static int hf_isis_lsp_ext_ip_reachability_subtlv;
static int hf_isis_lsp_ext_ip_reachability_prefix_length;
static int hf_isis_lsp_ext_ip_reachability_subclvs_len;
static int hf_isis_lsp_ext_ip_reachability_code;
static int hf_isis_lsp_ext_ip_reachability_len;
static int hf_isis_lsp_ext_ip_reachability_prefix_flags;
static int hf_isis_lsp_ext_ip_reachability_prefix_re_adv_flag;
static int hf_isis_lsp_ext_ip_reachability_prefix_node_sid_flag;
static int hf_isis_lsp_ext_ip_reachability_prefix_nophp_flag;
static int hf_isis_lsp_ext_ip_reachability_prefix_expl_null_flag;
static int hf_isis_lsp_ext_ip_reachability_prefix_value_flag;
static int hf_isis_lsp_ext_ip_reachability_prefix_local_flag;
static int hf_isis_lsp_maximum_link_bandwidth;
static int hf_isis_lsp_rt_capable_nickname_tree_root_priority;
static int hf_isis_lsp_eis_neighbors_delay_metric;
static int hf_isis_lsp_rt_capable_trill_maximum_version;
static int hf_isis_lsp_rt_capable_interested_vlans_afs_lost_counter;
static int hf_isis_lsp_ipv6_reachability_ipv6_prefix;
static int hf_isis_lsp_eis_neighbors_error_metric;
static int hf_isis_lsp_rt_capable_interested_vlans_vlan_end_id;
static int hf_isis_lsp_error_metric;
static int hf_isis_lsp_grp_macaddr_number_of_records;
static int hf_isis_lsp_grp_ipv4addr_number_of_records;
static int hf_isis_lsp_grp_ipv6addr_number_of_records;
static int hf_isis_lsp_rt_capable_nickname_nickname;
static int hf_isis_lsp_mt_id_reserved;
static int hf_isis_lsp_eis_neighbors_is_neighbor_id;
static int hf_isis_lsp_mt_id;
static int hf_isis_lsp_eis_neighbors_reserved;
static int hf_isis_lsp_ip_reachability_error_metric;
static int hf_isis_lsp_ip_reachability_delay_metric;
static int hf_isis_lsp_ip_reachability_expense_metric;
static int hf_isis_lsp_rt_capable_trees_nof_trees_to_use;
static int hf_isis_lsp_ip_reachability_default_metric;
static int hf_isis_lsp_rt_capable_trees_nof_trees_to_compute;
static int hf_isis_lsp_eis_neighbors_expense_metric;
static int hf_isis_lsp_partition_designated_l2_is;
static int hf_isis_lsp_originating_lsp_buffer_size;
static int hf_isis_lsp_ip_reachability_default_metric_ie;
static int hf_isis_lsp_eis_neighbors_default_metric_ie;
static int hf_isis_lsp_eis_neighbors_error_metric_supported;
static int hf_isis_lsp_unrsv_bw_priority_level;
static int hf_isis_lsp_ip_reachability_expense_metric_support;
static int hf_isis_lsp_mt_cap_overload;
static int hf_isis_lsp_eis_neighbors_expense_metric_supported;
static int hf_isis_lsp_ip_reachability_delay_metric_support;
static int hf_isis_lsp_ip_reachability_error_metric_support;
static int hf_isis_lsp_mt_cap_spsourceid;
static int hf_isis_lsp_eis_neighbors_delay_metric_supported;
static int hf_isis_lsp_eis_neighbors_error_metric_ie;
static int hf_isis_lsp_eis_neighbors_expense_metric_ie;
static int hf_isis_lsp_eis_neighbors_delay_metric_ie;
static int hf_isis_lsp_ip_reachability_delay_metric_ie;
static int hf_isis_lsp_ip_reachability_distribution;
static int hf_isis_lsp_ip_reachability_error_metric_ie;
static int hf_isis_lsp_ip_reachability_expense_metric_ie;
static int hf_isis_lsp_rt_capable_router_id;
static int hf_isis_lsp_rt_capable_flag_s;
static int hf_isis_lsp_rt_capable_flag_d;
static int hf_isis_lsp_clv_te_node_cap_b_bit;
static int hf_isis_lsp_clv_te_node_cap_e_bit;
static int hf_isis_lsp_clv_te_node_cap_m_bit;
static int hf_isis_lsp_clv_te_node_cap_g_bit;
static int hf_isis_lsp_clv_te_node_cap_p_bit;
static int hf_isis_lsp_clv_sr_cap_i_flag;
static int hf_isis_lsp_clv_sr_cap_v_flag;
static int hf_isis_lsp_clv_sr_cap_range;
static int hf_isis_lsp_clv_sr_cap_sid;
static int hf_isis_lsp_clv_sr_cap_label;
static int hf_isis_lsp_clv_sr_alg;
static int hf_isis_lsp_clv_sr_lb_flags;
static int hf_isis_lsp_clv_srv6_cap_flags;
static int hf_isis_lsp_clv_srv6_cap_flags_o;
static int hf_isis_lsp_clv_srv6_cap_flags_reserved;
static int hf_isis_lsp_clv_igp_msd_type;
static int hf_isis_lsp_clv_igp_msd_value;
static int hf_isis_lsp_clv_ext_admin_group;
static int hf_isis_lsp_clv_app_sabm_legacy;
static int hf_isis_lsp_clv_app_sabm_length;
static int hf_isis_lsp_clv_app_sabm_bits;
static int hf_isis_lsp_clv_app_sabm_bits_r;
static int hf_isis_lsp_clv_app_sabm_bits_s;
static int hf_isis_lsp_clv_app_sabm_bits_f;
static int hf_isis_lsp_clv_app_sabm_bits_x;
static int hf_isis_lsp_clv_app_udabm_reserved;
static int hf_isis_lsp_clv_app_udabm_length;
static int hf_isis_lsp_clv_app_udabm_bits;
static int hf_isis_lsp_clv_flex_algo_algorithm;
static int hf_isis_lsp_clv_flex_algo_metric_type;
static int hf_isis_lsp_clv_flex_algo_calc_type;
static int hf_isis_lsp_clv_flex_algo_priority;
static int hf_isis_lsp_clv_srv6_endx_sid_system_id;
static int hf_isis_lsp_clv_srv6_endx_sid_flags;
static int hf_isis_lsp_clv_srv6_endx_sid_flags_b;
static int hf_isis_lsp_clv_srv6_endx_sid_flags_s;
static int hf_isis_lsp_clv_srv6_endx_sid_flags_p;
static int hf_isis_lsp_clv_srv6_endx_sid_flags_reserved;
static int hf_isis_lsp_clv_srv6_endx_sid_alg;
static int hf_isis_lsp_clv_srv6_endx_sid_weight;
static int hf_isis_lsp_clv_srv6_endx_sid_endpoint_behavior;
static int hf_isis_lsp_clv_srv6_endx_sid_sid;
static int hf_isis_lsp_clv_srv6_endx_sid_subsubclvs_len;
static int hf_isis_lsp_area_address;
static int hf_isis_lsp_instance_identifier;
static int hf_isis_lsp_supported_itid;
static int hf_isis_lsp_clv_nlpid_nlpid;
static int hf_isis_lsp_ip_authentication;
static int hf_isis_lsp_authentication;
static int hf_isis_lsp_area_address_str;
static int hf_isis_lsp_is_virtual;
static int hf_isis_lsp_group;
static int hf_isis_lsp_default;
static int hf_isis_lsp_default_support;
static int hf_isis_lsp_delay;
static int hf_isis_lsp_delay_support;
static int hf_isis_lsp_expense;
static int hf_isis_lsp_expense_support;
static int hf_isis_lsp_error;
static int hf_isis_lsp_error_support;
static int hf_isis_lsp_clv_ipv6_te_router_id;
static int hf_isis_lsp_ext_is_reachability_ipv6_interface_address;
static int hf_isis_lsp_ext_is_reachability_ipv6_neighbor_address;
static int hf_isis_lsp_clv_bier_alg;
static int hf_isis_lsp_clv_bier_igp_alg;
static int hf_isis_lsp_clv_bier_subdomain;
static int hf_isis_lsp_clv_bier_bfrid;
static int hf_isis_lsp_clv_bier_subsub_type;
static int hf_isis_lsp_clv_bier_subsub_len;
static int hf_isis_lsp_clv_bier_subsub_mplsencap_maxsi;
static int hf_isis_lsp_clv_bier_subsub_mplsencap_bslen;
static int hf_isis_lsp_clv_bier_subsub_mplsencap_label;
static int hf_isis_lsp_srv6_loc_metric;
static int hf_isis_lsp_srv6_loc_flags;
static int hf_isis_lsp_srv6_loc_flags_d;
static int hf_isis_lsp_srv6_loc_flags_reserved;
static int hf_isis_lsp_srv6_loc_alg;
static int hf_isis_lsp_srv6_loc_size;
static int hf_isis_lsp_srv6_loc_locator;
static int hf_isis_lsp_srv6_loc_subclvs_len;
static int hf_isis_lsp_srv6_loc_sub_tlv_type;
static int hf_isis_lsp_srv6_loc_sub_tlv_length;
static int hf_isis_lsp_clv_srv6_end_sid_flags;
static int hf_isis_lsp_clv_srv6_end_sid_endpoint_behavior;
static int hf_isis_lsp_clv_srv6_end_sid_sid;
static int hf_isis_lsp_clv_srv6_end_sid_subsubclvs_len;
static int hf_isis_lsp_clv_srv6_sid_struct_lb_len;
static int hf_isis_lsp_clv_srv6_sid_struct_ln_len;
static int hf_isis_lsp_clv_srv6_sid_struct_fun_len;
static int hf_isis_lsp_clv_srv6_sid_struct_arg_len;
static int hf_isis_lsp_purge_orig_id_num;
static int hf_isis_lsp_purge_orig_id_system_id;
/* rfc 6165: MAC Reachability */
static int hf_isis_lsp_mac_reachability_topoid_nick;
static int hf_isis_lsp_mac_reachability_confidence;
static int hf_isis_lsp_mac_reachability_reserved;
static int hf_isis_lsp_mac_reachability_vlan;
static int hf_isis_lsp_mac_reachability_mac;
static int hf_isis_lsp_mac_reachability_chassismac;
static int hf_isis_lsp_mac_reachability_fanmcast;
/* Avaya proprietary */
static int hf_isis_lsp_avaya_ipvpn_unknown;
static int hf_isis_lsp_avaya_ipvpn_system_id;
static int hf_isis_lsp_avaya_ipvpn_vrfsid;
static int hf_isis_lsp_avaya_ipvpn_subtlvbytes;
static int hf_isis_lsp_avaya_ipvpn_subtlvtype;
static int hf_isis_lsp_avaya_ipvpn_subtlvlength;
static int hf_isis_lsp_avaya_ipvpn_unknown_sub;
static int hf_isis_lsp_avaya_ipvpn_ipv4_metric;
static int hf_isis_lsp_avaya_ipvpn_ipv4_metrictype;
static int hf_isis_lsp_avaya_ipvpn_ipv4_addr;
static int hf_isis_lsp_avaya_ipvpn_ipv4_mask;
static int hf_isis_lsp_avaya_ipvpn_ipv6_metric;
static int hf_isis_lsp_avaya_ipvpn_ipv6_prefixlen;
static int hf_isis_lsp_avaya_ipvpn_ipv6_prefix;
static int hf_isis_lsp_avaya_185_unknown;
static int hf_isis_lsp_avaya_186_unknown;

static int ett_isis_lsp;
static int ett_isis_lsp_info;
static int ett_isis_lsp_att;
static int ett_isis_lsp_cksum;
static int ett_isis_lsp_clv_area_addr;
static int ett_isis_lsp_clv_is_neighbors;
static int ett_isis_lsp_clv_instance_identifier;
static int ett_isis_lsp_clv_ext_is_reachability; /* CLV 22 */
static int ett_isis_lsp_part_of_clv_ext_is_reachability;
static int ett_isis_lsp_part_of_clv_ext_is_reachability_subtlv;
static int ett_isis_lsp_subclv_admin_group;
static int ett_isis_lsp_subclv_unrsv_bw;
static int ett_isis_lsp_subclv_bw_ct;
static int ett_isis_lsp_subclv_spb_link_metric;
static int ett_isis_lsp_adj_sid_flags;
static int ett_isis_lsp_clv_unknown;
static int ett_isis_lsp_clv_partition_dis;
static int ett_isis_lsp_clv_prefix_neighbors;
static int ett_isis_lsp_clv_nlpid_nlpid;
static int ett_isis_lsp_clv_hostname;
static int ett_isis_lsp_clv_srlg;
static int ett_isis_lsp_clv_te_router_id;
static int ett_isis_lsp_clv_authentication;
static int ett_isis_lsp_clv_ip_authentication;
static int ett_isis_lsp_clv_ipv4_int_addr;
static int ett_isis_lsp_clv_ipv6_int_addr; /* CLV 232 */
static int ett_isis_lsp_clv_mt_cap;
static int ett_isis_lsp_clv_mt_cap_spb_instance;
static int ett_isis_lsp_clv_mt_cap_spbm_service_identifier;
static int ett_isis_lsp_clv_mt_cap_spbv_mac_address;
static int ett_isis_lsp_clv_sid_label_binding;
static int ett_isis_lsp_clv_ip_reachability;
static int ett_isis_lsp_clv_ip_reach_subclv;
static int ett_isis_lsp_clv_ext_ip_reachability; /* CLV 135 */
static int ett_isis_lsp_part_of_clv_ext_ip_reachability;
static int ett_isis_lsp_clv_ipv6_reachability; /* CLV 236 */
static int ett_isis_lsp_part_of_clv_ipv6_reachability;
static int ett_isis_lsp_prefix_sid_flags;
static int ett_isis_lsp_prefix_attr_flags;
static int ett_isis_lsp_clv_mt;
static int ett_isis_lsp_clv_mt_is;
static int ett_isis_lsp_part_of_clv_mt_is;
static int ett_isis_lsp_clv_mt_reachable_IPv4_prefx;  /* CLV 235 */
static int ett_isis_lsp_clv_mt_reachable_IPv6_prefx;  /* CLV 237 */
static int ett_isis_lsp_clv_rt_capable;   /* CLV 242 */
static int ett_isis_lsp_clv_te_node_cap_desc;
static int ett_isis_lsp_clv_sr_cap;
static int ett_isis_lsp_clv_sr_sid_label;
static int ett_isis_lsp_clv_sr_alg;
static int ett_isis_lsp_clv_sr_lb;
static int ett_isis_lsp_clv_node_msd;
static int ett_isis_lsp_clv_srv6_cap;
static int ett_isis_lsp_clv_srv6_cap_flags;
static int ett_isis_lsp_clv_flex_algo_def;
static int ett_isis_lsp_clv_flex_algo_def_sub_tlv;
static int ett_isis_lsp_clv_app_sabm_bits;
static int ett_isis_lsp_clv_ipv6_te_rtrid;
static int ett_isis_lsp_clv_trill_version;
static int ett_isis_lsp_clv_trees;
static int ett_isis_lsp_clv_root_id;
static int ett_isis_lsp_clv_nickname;
static int ett_isis_lsp_clv_interested_vlans;
static int ett_isis_lsp_clv_tree_used;
static int ett_isis_lsp_clv_vlan_group;
static int ett_isis_lsp_clv_grp_address;  /* CLV 142 */
static int ett_isis_lsp_clv_grp_macaddr;
static int ett_isis_lsp_clv_grp_ipv4addr;
static int ett_isis_lsp_clv_grp_ipv6addr;
static int ett_isis_lsp_clv_grp_unknown;
static int ett_isis_lsp_clv_purge_orig_id; /* CLV 13 */
static int ett_isis_lsp_clv_originating_buff_size; /* CLV 14 */
static int ett_isis_lsp_sl_flags;
static int ett_isis_lsp_sl_sub_tlv;
static int ett_isis_lsp_sl_sub_tlv_flags;
static int ett_isis_lsp_clv_ipv6_te_router_id;
static int ett_isis_lsp_clv_bier_subsub_tlv;
static int ett_isis_lsp_clv_srv6_locator;
static int ett_isis_lsp_clv_srv6_loc_entry;
static int ett_isis_lsp_clv_srv6_loc_flags;
static int ett_isis_lsp_clv_srv6_loc_sub_tlv;
static int ett_isis_lsp_clv_srv6_loc_end_sid_sub_sub_tlv;
static int ett_isis_lsp_clv_srv6_endx_sid_flags;
static int ett_isis_lsp_clv_srv6_endx_sid_sub_sub_tlv;
static int ett_isis_lsp_clv_unidir_link_flags;
static int ett_isis_lsp_clv_mac_reachability;
static int ett_isis_lsp_clv_avaya_ipvpn;
static int ett_isis_lsp_clv_avaya_ipvpn_subtlv;
static int ett_isis_lsp_clv_avaya_ipvpn_mc;
static int ett_isis_lsp_clv_avaya_ip_grt_mc;


static expert_field ei_isis_lsp_short_pdu;
static expert_field ei_isis_lsp_long_pdu;
static expert_field ei_isis_lsp_bad_checksum;
static expert_field ei_isis_lsp_subtlv;
static expert_field ei_isis_lsp_authentication;
static expert_field ei_isis_lsp_short_clv;
static expert_field ei_isis_lsp_long_clv;
static expert_field ei_isis_lsp_length_clv;
static expert_field ei_isis_lsp_clv_mt;
static expert_field ei_isis_lsp_clv_unknown;
static expert_field ei_isis_lsp_malformed_subtlv;
static expert_field ei_isis_lsp_unknown_subtlv;
static expert_field ei_isis_lsp_reserved_not_zero;
static expert_field ei_isis_lsp_length_invalid;

static const value_string isis_lsp_istype_vals[] = {
    { ISIS_LSP_TYPE_UNUSED0,    "Unused 0x0 (invalid)"},
    { ISIS_LSP_TYPE_LEVEL_1,    "Level 1"},
    { ISIS_LSP_TYPE_UNUSED2,    "Unused 0x2 (invalid)"},
    { ISIS_LSP_TYPE_LEVEL_2,    "Level 2"},
    { 0, NULL } };

static const value_string isis_lsp_sl_sub_tlv_vals[] = {
    { ISIS_LSP_SL_SUB_SID_LABEL,  "SID/Label"},
    { ISIS_LSP_SL_SUB_PREFIX_SID, "Prefix SID"},
    { ISIS_LSP_SL_SUB_ADJ_SID,    "Adjacency SID"},
    { ISIS_LSP_SL_SUB_LAN_ADJ_SID,"LAN-Adjacency SID"},
    { 0, NULL } };

/* rfc8986 */
/* draft-filsfils-spring-net-pgm-extension-srv6-usid-15 */
static const value_string srv6_endpoint_type_vals[] = {
    { 1,     "End" },
    { 2,     "End (PSP)" },
    { 3,     "End (USP)" },
    { 4,     "End (PSP/USP)" },
    { 5,     "End.X" },
    { 6,     "End.X (PSP)" },
    { 7,     "End.X (USP)" },
    { 8,     "End.X (PSP/USP)" },
    { 9,     "End.T" },
    { 10,    "End.T (PSP)" },
    { 11,    "End.T (USP)" },
    { 12,    "End.T (PSP/USP)" },
    { 13,    "Unassigned" },
    { 14,    "End.B6.Encaps" },
    { 15,    "End.BM" },
    { 16,    "End.DX6" },
    { 17,    "End.DX4" },
    { 18,    "End.DT6" },
    { 19,    "End.DT4" },
    { 20,    "End.DT46" },
    { 21,    "End.DX2" },
    { 22,    "End.DX2V" },
    { 23,    "End.DT2U" },
    { 24,    "End.DT2M" },
    { 25,    "Reserved" },
    { 26,    "Unassigned" },
    { 27,    "End.B6.Encaps.Red" },
    { 28,    "End (USD)" },
    { 29,    "End (PSP/USD)" },
    { 30,    "End (USP/USD)" },
    { 31,    "End (PSP/USP/USD)" },
    { 32,    "End.X (USD)" },
    { 33,    "End.X (PSP/USD)" },
    { 34,    "End.X (USP/USD)" },
    { 35,    "End.X (PSP/USP/USD)" },
    { 36,    "End.T (USD)" },
    { 37,    "End.T (PSP/USD)" },
    { 38,    "End.T (USP/USD)" },
    { 39,    "End.T (PSP/USP/USD)" },
    { 42,    "End (NEXT-ONLY-CSID)" },
    { 43,    "End (NEXT-CSID)" },
    { 44,    "End (NEXT-CSID/PSP)" },
    { 45,    "End (NEXT-CSID/USP)" },
    { 46,    "End (NEXT-CSID/PSP/USP)" },
    { 47,    "End (NEXT-CSID/USD)" },
    { 48,    "End (NEXT-CSID/PSP/USD)" },
    { 49,    "End (NEXT-CSID/USP/USD)" },
    { 50,    "End (NEXT-CSID/PSP/USP/USD)" },
    { 51,    "End.X (NEXT-ONLY-CSID)" },
    { 52,    "End.X (NEXT-CSID)" },
    { 53,    "End.X (NEXT-CSID/PSP)" },
    { 54,    "End.X (NEXT-CSID/USP)" },
    { 55,    "End.X (NEXT-CSID/PSP/USP)" },
    { 56,    "End.X (NEXT-CSID/USD)" },
    { 57,    "End.X (NEXT-CSID/PSP/USD)" },
    { 58,    "End.X (NEXT-CSID/USP/USD)" },
    { 59,    "End.X (NEXT-CSID/PSP/USP/USD)" },
    { 60,    "End.DX6 (NEXT-CSID)" },
    { 61,    "End.DX4 (NEXT-CSID)" },
    { 62,    "End.DT6 (NEXT-CSID)" },
    { 63,    "End.DT4 (NEXT-CSID)" },
    { 64,    "End.DT46 (NEXT-CSID)" },
    { 65,    "End.DX2 (NEXT-CSID)" },
    { 66,    "End.DX2V (NEXT-CSID)" },
    { 67,    "End.DT2U (NEXT-CSID)" },
    { 68,    "End.DT2M (NEXT-CSID)" },
    { 0, NULL }
};

static const value_string isis_lsp_srv6_loc_sub_tlv_vals[] = {
    { 4,  "Prefix Attribute Flags"},
    { 5,  "SRv6 End SID"},
    { 0, NULL } };

static const value_string isis_lsp_srv6_loc_end_sid_sub_sub_tlv_vals[] = {
    { 1,  "SRv6 SID Structure"},
    { 0, NULL } };

static int * const adj_sid_flags[] = {
    &hf_isis_lsp_adj_sid_family_flag,
    &hf_isis_lsp_adj_sid_backup_flag,
    &hf_isis_lsp_adj_sid_value_flag,
    &hf_isis_lsp_adj_sid_local_flag,
    &hf_isis_lsp_adj_sid_set_flag,
    NULL,
};

static int * const srv6_cap_flags[] = {
    &hf_isis_lsp_clv_srv6_cap_flags_o,
    &hf_isis_lsp_clv_srv6_cap_flags_reserved,
    NULL,
};

static int * const srv6_locator_flags[] = {
    &hf_isis_lsp_srv6_loc_flags_d,
    &hf_isis_lsp_srv6_loc_flags_reserved,
    NULL,
};

static int * const srv6_endx_sid_flags[] = {
    &hf_isis_lsp_clv_srv6_endx_sid_flags_b,
    &hf_isis_lsp_clv_srv6_endx_sid_flags_s,
    &hf_isis_lsp_clv_srv6_endx_sid_flags_p,
    &hf_isis_lsp_clv_srv6_endx_sid_flags_reserved,
    NULL,
};

static int * const prefix_sid_flags[] = {
    &hf_isis_lsp_ext_ip_reachability_prefix_re_adv_flag,
    &hf_isis_lsp_ext_ip_reachability_prefix_node_sid_flag,
    &hf_isis_lsp_ext_ip_reachability_prefix_nophp_flag,
    &hf_isis_lsp_ext_ip_reachability_prefix_expl_null_flag,
    &hf_isis_lsp_ext_ip_reachability_prefix_value_flag,
    &hf_isis_lsp_ext_ip_reachability_prefix_local_flag,
    NULL,
};

static int * const prefix_attr_flags[] = {
    &hf_isis_lsp_prefix_attr_flags_x,
    &hf_isis_lsp_prefix_attr_flags_r,
    &hf_isis_lsp_prefix_attr_flags_n,
    NULL,
};

static const true_false_string tfs_ipv6_ipv4 = { "IPv6", "IPv4" };

static const value_string isis_igp_alg_vals[] = {
    { ISIS_ALG_SPF,  "Shortest Path First (SPF)" },
    { ISIS_ALG_SSPF, "Strict Shortest Path First (SPF)" },
    { 0, NULL }
};

static const value_string isis_lsp_igp_msd_types[] = {
    { IGP_MSD_TYPE_RESERVED,        "Reserved" },
    { IGP_MSD_TYPE_MPLS,            "Base MPLS Imposition" },
    { IGP_MSD_TYPE_SEGMENT_LEFT,    "Maximum Segments Left" },
    { IGP_MSD_TYPE_END_POP,         "Maximum End Pop" },
    { IGP_MSD_TYPE_H_ENCAP,         "Maximum H.Encaps" },
    { IGP_MSD_TYPE_END_D,           "Maximum End D" },
    { 0, NULL }
};

static const value_string isis_lsp_flex_algo_metric_type_vals[] = {
    { 0, "IGP Metric"},
    { 1, "Min Unidirectional Link Delay"},
    { 2, "TE Metric"},
    { 0, NULL }
};

static const value_string isis_lsp_flex_algo_sub_tlv_vals[] = {
    { FAD_EXCLUDE_AG,       "Flexible Algorithm Exclude Admin Group"},
    { FAD_INCLUDE_ANY_AG,   "Flexible Algorithm Include-Any Admin Group"},
    { FAD_INCLUDE_ALL_AG,   "Flexible Algorithm Include-All Admin Group"},
    { FAD_DEF_FLAGS,        "Flexible Algorithm Definition Flags"},
    { FAD_EXCLUDE_SRLG,     "Flexible Algorithm Exclude SRLG"},
    { 0, NULL } };

static int * const isis_lsp_app_sabm_bits[] = {
    &hf_isis_lsp_clv_app_sabm_bits_r,
    &hf_isis_lsp_clv_app_sabm_bits_s,
    &hf_isis_lsp_clv_app_sabm_bits_f,
    &hf_isis_lsp_clv_app_sabm_bits_x,
    NULL,
};

static const value_string isis_lsp_grp_types[] = {
    { GRP_MAC_ADDRESS,  "MAC address" },
    { GRP_IPV4_ADDRESS, "IPv4 address" },
    { GRP_IPV6_ADDRESS, "IPv6 address" },
    { 0, NULL }
};

static int * const unidir_link_flags[] = {
    &hf_isis_lsp_ext_is_reachability_unidir_link_flags_a,
    NULL,
};

/*
http://www.iana.org/assignments/isis-tlv-codepoints/isis-tlv-codepoints.xhtml#isis-tlv-codepoints-22-23-141-222-223
https://tools.ietf.org/html/rfc8667
*/
static const value_string isis_lsp_ext_is_reachability_code_vals[] = {
    { 3, "Administrative group (color)" },
    { 4, "Link Local/Remote Identifiers" },
    { 6, "IPv4 interface address" },
    { 8, "IPv4 neighbor address" },
    { 9, "Maximum link bandwidth" },
    { 10, "Maximum reservable link bandwidth" },
    { 11, "Unreserved bandwidth" },
    { 12, "IPv6 Interface Address" },
    { 13, "IPv6 Neighbor Address" },
    { 14, "Extended Administrative Group" },
    { 15, "Link Maximum SID Depth" },
    { 16, "Application-Specific Link Attributes" },
    { 18, "TE Default metric" },
    { 19, "Link-attributes" },
    { 20, "Link Protection Type" },
    { 21, "Interface Switching Capability Descriptor" },
    { 22, "Bandwidth Constraints" },
    { 23, "Unconstrained TE LSP Count (sub-)TLV" },
    { 24, "Remote AS number" },
    { 25, "IPv4 remote ASBR Identifier" },
    { 26, "IPv6 remote ASBR Identifier" },
    { 27, "Interface Adjustment Capability Descriptor (IACD)" },
    { 28, "MTU" },
    { 29, "SPB-Metric" },
    { 30, "SPB-A-OALG" },
    { 31, "Adj-SID" },
    { 32, "LAN-Adj-SID" },
    { 33, "Unidirectional Link Delay"},
    { 34, "Min/Max Unidirectional Link Delay"},
    { 35, "Unidirectional Delay Variation"},
    { 36, "Unidirectional Link Loss"},
    { 37, "Unidirectional Residual Bandwidth"},
    { 38, "Unidirectional Available Bandwidth"},
    { 39, "Unidirectional Utilized Bandwidth"},
    { 43, "SRv6 End.X SID" },       /* Suggested Value */
    { 44, "SRv6 LAN End.X SID" },   /* Suggested Value */
    { 250, "Reserved for Cisco-specific extensions" },
    { 251, "Reserved for Cisco-specific extensions" },
    { 252, "Reserved for Cisco-specific extensions" },
    { 253, "Reserved for Cisco-specific extensions" },
    { 254, "Reserved for Cisco-specific extensions" },
    { 0, NULL }
};

/*
    From: https://www.iana.org/assignments/isis-tlv-codepoints/isis-tlv-codepoints.xhtml
    Sub-TLVs for TLVs 135, 235, 236, and 237
*/
#define IP_REACH_SUBTLV_32BIT_ADMIN_TAG 1
#define IP_REACH_SUBTLV_64BIT_ADMIN_TAG 2
#define IP_REACH_SUBTLV_PFX_SID         3
#define IP_REACH_SUBTLV_PFX_ATTRIB_FLAG 4
#define IP_REACH_SUBTLV_BIER_INFO       32

static const value_string isis_lsp_ext_ip_reachability_code_vals[] = {
    { IP_REACH_SUBTLV_32BIT_ADMIN_TAG, "32-bit Administrative Tag" },
    { IP_REACH_SUBTLV_64BIT_ADMIN_TAG, "64-bit Administrative Tag" },
    { IP_REACH_SUBTLV_PFX_SID,         "Prefix-SID" },
    { IP_REACH_SUBTLV_PFX_ATTRIB_FLAG, "Prefix Attribute Flags" },
    { IP_REACH_SUBTLV_BIER_INFO,       "BIER Info" },
    { 0, NULL }
};

/*
    From: https://www.iana.org/assignments/bier/bier.xhtml
    BIER Algorithm
*/
static const range_string isis_lsp_bier_alg_vals[] = {
    {   0,   0, "No BIER specific algorithm is used" },
    { 240, 255, "Experimental Use" },
    {   0,   0, NULL }
};

/*
    From: https://www.iana.org/assignments/isis-tlv-codepoints/isis-tlv-codepoints.xhtml
    sub-sub-TLVs for BIER Info sub-TLV
*/
static const value_string isis_lsp_bier_subsubtlv_type_vals[] = {
    { 1, "BIER MPLS Encapsulation" },
    { 0, NULL }
};

/* Avaya specific sub-TLV types */
static const value_string isis_lsp_avaya_ipvpn_subtlv_code_vals[] = {
    { 1,   "IPv4 Metric Type" },
    { 135, "IPv4 Reachability" },
    { 236, "IPv6 Reachability" },
    { 0, NULL }
};

/*
 * Name: dissect_lsp_mt_id()
 *
 * Description:
 *    dissect and display the multi-topology ID value
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  CAN'T BE NULL
 *    int : offset into packet data where we are.
 *
 * Output:
 *    void, but we will add to proto tree.
 */
static void
dissect_lsp_mt_id(tvbuff_t *tvb, proto_tree *tree, int offset)
{

    proto_tree_add_item(tree, hf_isis_lsp_mt_id_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_isis_lsp_mt_id, tvb, offset, 2, ENC_BIG_ENDIAN);

}

/*
 * Name: dissect_metric()
 *
 * Description:
 *    Display a metric prefix portion.  ISIS has the concept of multiple
 *    metric per prefix (default, delay, expense, and error).  This
 *    routine assists other dissectors by adding a single one of
 *    these to the display tree..
 *
 *    The 8th(msbit) bit in the metric octet is the "supported" bit.  The
 *        "default" support is required, so we support a "force_supported"
 *        flag that tells us that it MUST be zero (zero==supported,
 *        so it really should be a "not supported" in the boolean sense)
 *        and to display a protocol failure accordingly.  Notably,
 *        Cisco IOS 12(6) blows this!
 *    The 7th bit must be zero (reserved).
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  May be NULL
 *    int : offset into packet data where we are.
 *    int : hf of the metric.
 *    int : hf_support of the metric.
 *    int : force supported.  True is the supported bit MUST be zero.
 *
 * Output:
 *    void, but we will add to proto tree if !NULL.
 */
static void
dissect_metric(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    int hf, int hf_support, int force_supported )
{
    uint8_t metric;
    proto_item *item, *support_item;

    metric = tvb_get_uint8(tvb, offset);
    support_item = proto_tree_add_boolean(tree, hf_support, tvb, offset, 1, metric);
    item = proto_tree_add_uint(tree, hf, tvb, offset, 1, metric);

    if (!ISIS_LSP_CLV_METRIC_SUPPORTED(metric) && force_supported)
        proto_item_append_text(support_item, " (but is required to be)");

    if (ISIS_LSP_CLV_METRIC_RESERVED(metric))
        expert_add_info(pinfo, item, &ei_isis_lsp_reserved_not_zero);
}

/*
 * Name: dissect_lsp_ip_reachability_clv()
 *
 * Description:
 *    Decode an IP reachability CLV.  This can be either internal or
 *    external (the clv format does not change and which type we are
 *    displaying is put there by the dispatcher).  All of these
 *    are a metric block followed by an IP addr and mask.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_lsp_ip_reachability_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    proto_item     *ti;
    proto_tree    *ntree = NULL;
    uint32_t       src, mask, bitmask;
    int        prefix_len;
    bool        found_mask = false;

    while ( length > 0 ) {
        if (length<12) {
            proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                "short IP reachability (%d vs 12)", length );
            return;
        }
        /*
         * Gotta build a sub-tree for all our pieces
         */
        if ( tree ) {
            src = tvb_get_ipv4(tvb, offset+4);
            mask = tvb_get_ntohl(tvb, offset+8);

            /* find out if the mask matches one of 33 possible prefix lengths */
            bitmask = 0xffffffff;
            for(prefix_len = 32; prefix_len >= 0; prefix_len--) {
                if (bitmask==mask) {
                    found_mask = true;
                    break;
                }
                bitmask = bitmask << 1;
            }

            /* If we have a discontiguous netmask, dump the mask, otherwise print the prefix_len */
            /* XXX - We should probably have some sort of netmask_to_str() routine in to_str.c that does this. */

            if(found_mask) {
              ti = proto_tree_add_ipv4_format_value( tree, hf_isis_lsp_ip_reachability_ipv4_prefix, tvb, offset, 12,
                src, "%s/%d", tvb_ip_to_str(pinfo->pool, tvb, offset+4), prefix_len );
            } else {
              ti = proto_tree_add_ipv4_format_value( tree, hf_isis_lsp_ip_reachability_ipv4_prefix, tvb, offset, 12,
                src, "%s mask %s", tvb_ip_to_str(pinfo->pool, tvb, offset+4), tvb_ip_to_str(pinfo->pool, tvb, offset+8));
            };

            ntree = proto_item_add_subtree(ti, ett_isis_lsp_clv_ip_reachability);

            proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_default_metric, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_default_metric_ie, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_distribution, tvb, offset, 1, ENC_NA);

            proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_delay_metric, tvb, offset+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_delay_metric_support, tvb, offset+1, 1, ENC_NA);
            proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_delay_metric_ie, tvb, offset+1, 1, ENC_NA);

            proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_expense_metric, tvb, offset+2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_expense_metric_support, tvb, offset+2, 1, ENC_NA);
            proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_expense_metric_ie, tvb, offset+2, 1, ENC_NA);

            proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_error_metric, tvb, offset+3, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_error_metric_support, tvb, offset+3, 1, ENC_NA);
            proto_tree_add_item(ntree, hf_isis_lsp_ip_reachability_error_metric_ie, tvb, offset+3, 1, ENC_NA);
        }
        offset += 12;
        length -= 12;
    }
}


/*
 * Name: dissect_bierinfo_subsubtlv()
 *
 * Description:
 *    Decodes a BIER Info sub-sub-TLV (RFC 8401)
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_bierinfo_subsubtlv (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                            int offset, int tlv_type, int tlv_len)
{
    switch (tlv_type) {
    case 1:
        if (tlv_len != 4) {
            proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv,
                    tvb, offset, tlv_len, "TLV length (%d) != 4 bytes", tlv_len);
            return;
        }
        proto_tree_add_item(tree, hf_isis_lsp_clv_bier_subsub_mplsencap_maxsi, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_isis_lsp_clv_bier_subsub_mplsencap_bslen, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_isis_lsp_clv_bier_subsub_mplsencap_label, tvb, offset+1, 3, ENC_BIG_ENDIAN);
        break;
    default:
        break;
    }

    return;
}


/*
 * Name: dissect_bierinfo_subtlv()
 *
 * Description:
 *    Decodes a BIER Info sub-TLV (RFC 8401)
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_bierinfo_subtlv (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                         int offset, int tlv_len)
{
    int min_tlv_len = 5;
    int len = tlv_len;
    unsigned subsub_type, subsub_len;
    proto_tree *subsub_tree = NULL;
    proto_item *ti_subsub = NULL;

    if (tlv_len < min_tlv_len) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv,
                tvb, offset-2, tlv_len+2,
                "Invalid length (%d) bytes for BIER Info sub-TLV: Minimum length (%d) bytes",
                tlv_len+2, min_tlv_len+2);
        return;
    }
    proto_tree_add_item(tree, hf_isis_lsp_clv_bier_alg, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_isis_lsp_clv_bier_igp_alg, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_isis_lsp_clv_bier_subdomain, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_isis_lsp_clv_bier_bfrid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    len -= 5;

    /* Dissect sub-sub-TLVs if present */
    min_tlv_len = 2;
    while (len > 0) {
        if (len < min_tlv_len) {
            proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv,
                    tvb, offset, len,
                    "Invalid data length (%d) bytes for BIER Info sub-sub-TLV: Minimum length (%d) bytes",
                    len, min_tlv_len);
            return;
        }
        subsub_type = tvb_get_uint8(tvb, offset);
        subsub_len  = tvb_get_uint8(tvb, offset+1);
        subsub_tree = proto_tree_add_subtree(tree, tvb, offset, subsub_len+2,
                                             ett_isis_lsp_clv_bier_subsub_tlv,
                                             &ti_subsub, "sub-subTLV");
        proto_tree_add_item(subsub_tree, hf_isis_lsp_clv_bier_subsub_type,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(subsub_tree, hf_isis_lsp_clv_bier_subsub_len,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        len -= 2;
        proto_item_append_text(ti_subsub, ": %s (t=%u, l=%u)",
                val_to_str_const(subsub_type, isis_lsp_bier_subsubtlv_type_vals, "Unknown"),
                subsub_type, subsub_len);
        dissect_bierinfo_subsubtlv(tvb, pinfo, subsub_tree, offset, subsub_type, subsub_len);
        offset += subsub_len;
        len -= subsub_len;
    }

    return;
}

/*
 * Name: dissect_prefix_attr_flags_subclv()
 *
 * Description:
 *    Decodes a Prefix Attribute Flags sub-TLV (RFC 7794)
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   packet_info * : expert error misuse reporting
 *   proto_tree * : proto tree to build on
 *   tree_item * : proto tree item to build on (may be null)
 *   int : current offset into packet data
 *   int : type of this clv
 *   int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_prefix_attr_flags_subclv(tvbuff_t *tvb, packet_info *pinfo,
                                 proto_tree *tree, proto_item *tree_item,
                                 int offset, int clv_code _U_, int clv_len)
{
    uint8_t flags;

    if (clv_len != 1) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv,
                                     tvb, offset-2, 2,
                                     "Invalid Sub-TLV Length %d (should be 1)", clv_len);
        return;
    }
    flags = tvb_get_uint8(tvb, offset);
    proto_tree_add_bitmask(tree, tvb, offset, hf_isis_lsp_prefix_attr_flags,
                           ett_isis_lsp_prefix_attr_flags, prefix_attr_flags, ENC_BIG_ENDIAN);
    if (tree_item) {
        proto_item_append_text(tree_item, ": Flags:%c%c%c",
                               ((flags & ISIS_LSP_PFX_ATTR_FLAG_X) != 0) ? 'X' : '-',
                               ((flags & ISIS_LSP_PFX_ATTR_FLAG_R) != 0) ? 'R' : '-',
                               ((flags & ISIS_LSP_PFX_ATTR_FLAG_N) != 0) ? 'N' : '-');
    }
}


/*
 * Name: dissect_ipreach_subclv ()
 *
 * Description: parses IP reach subTLVs
 *              Called by various IP Reachability dissectors.
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.
 *   int : offset into packet data where we are (beginning of the sub_clv value).
 *
 * Output:
 *   void
 */
static void
dissect_ipreach_subclv(tvbuff_t *tvb, packet_info *pinfo,  proto_tree *tree, proto_item *tree_item, int offset, int clv_code, int clv_len)
{
    uint8_t flags;

    switch (clv_code) {
    case IP_REACH_SUBTLV_32BIT_ADMIN_TAG:
        while (clv_len >= 4) {
            proto_tree_add_item(tree, hf_isis_lsp_32_bit_administrative_tag, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            clv_len-=4;
        }
        break;
    case IP_REACH_SUBTLV_64BIT_ADMIN_TAG:
        while (clv_len >= 8) {
            proto_tree_add_item(tree, hf_isis_lsp_64_bit_administrative_tag, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset+=8;
            clv_len-=8;
        }
        break;
    case IP_REACH_SUBTLV_PFX_SID:
        flags = tvb_get_uint8(tvb, offset);
        proto_tree_add_bitmask(tree, tvb, offset, hf_isis_lsp_ext_ip_reachability_prefix_flags,
                                   ett_isis_lsp_prefix_sid_flags, prefix_sid_flags, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(tree, hf_isis_lsp_clv_sr_alg, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        if (clv_len == 5) {
            if (!((flags & 0x0C) == 0x0C))
                proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb,
                                offset-2, clv_len, "V & L flags must be set");
            proto_tree_add_item(tree, hf_isis_lsp_sid_sli_label, tvb, offset, 3, ENC_BIG_ENDIAN);
        } else if (clv_len == 6) {
            if (flags & 0x0C)
                proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb,
                                offset-2, clv_len, "V & L flags must be unset");
            proto_tree_add_item(tree, hf_isis_lsp_sid_sli_index, tvb, offset, 4, ENC_BIG_ENDIAN);
        } else {
                proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb,
                                offset-2, clv_len, "Unknown SID/Index/Label format");
        }
        break;
    case IP_REACH_SUBTLV_PFX_ATTRIB_FLAG:
        /* Prefix Attribute Flags */
        dissect_prefix_attr_flags_subclv(tvb, pinfo, tree, tree_item, offset, clv_code, clv_len);
        break;
    case IP_REACH_SUBTLV_BIER_INFO:
        dissect_bierinfo_subtlv(tvb, pinfo, tree, offset, clv_len);
        break;
    default :
        break;
    }
}


/*
 * Name: dissect_lsp_ext_ip_reachability_clv()
 *
 * Description: Decode an Extended IP Reachability CLV - code 135.
 *
 *   The extended IP reachability TLV is an extended version
 *   of the IP reachability TLVs (codes 128 and 130). It encodes
 *   the metric as a 32-bit unsigned interger and allows to add
 *   sub-CLV(s).
 *
 *   CALLED BY TLV 235 DISSECTOR
 *
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : proto tree to build on (may be null)
 *   int : current offset into packet data
 *   int : length of IDs in packet.
 *   int : length of this clv
 *
 * Output:
 *   void, will modify proto_tree if not null.
 */
static void
dissect_lsp_ext_ip_reachability_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree,
    int offset, isis_data_t *isis _U_, int length)
{
    proto_tree  *subtree = NULL;
    proto_tree  *subclv_tree = NULL;
    proto_item  *ti_subtree = NULL;
    proto_item  *ti_subclvs = NULL;
    uint8_t     ctrl_info;
    unsigned    bit_length;
    int         byte_length;
    ws_in4_addr prefix;
    address     prefix_addr;
    unsigned    len,i;
    unsigned    subclvs_len;
    unsigned    clv_code, clv_len;
    int         clv_offset;
    char        *prefix_str;

    while (length > 0) {
        ctrl_info = tvb_get_uint8(tvb, offset+4);
        bit_length = ctrl_info & 0x3f;
        byte_length = tvb_get_ipv4_addr_with_prefix_len(tvb, offset+5, &prefix, bit_length);
        if (byte_length == -1) {
            proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                 "IPv4 prefix has an invalid length: %d bits", bit_length );
                return;
            }
        subclvs_len = 0;
        if ((ctrl_info & 0x40) != 0)
            subclvs_len = 1+tvb_get_uint8(tvb, offset+5+byte_length);

        /* open up a new tree per prefix */
        subtree = proto_tree_add_subtree(tree, tvb, offset, 5+byte_length+subclvs_len,
                            ett_isis_lsp_part_of_clv_ext_ip_reachability, &ti_subtree, "Ext. IP Reachability");

        set_address(&prefix_addr, AT_IPv4, 4, &prefix);
        prefix_str = address_to_str(pinfo->pool, &prefix_addr);
        proto_item_append_text(ti_subtree, ": %s/%u", prefix_str, bit_length);

        proto_tree_add_item(subtree, hf_isis_lsp_ext_ip_reachability_metric, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_isis_lsp_ext_ip_reachability_distribution, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_isis_lsp_ext_ip_reachability_subtlv, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_isis_lsp_ext_ip_reachability_prefix_length, tvb, offset+4, 1, ENC_NA);

        proto_tree_add_ipv4(subtree, hf_isis_lsp_ext_ip_reachability_ipv4_prefix, tvb, offset + 5, byte_length, prefix);

        len = 5 + byte_length;
        if ((ctrl_info & 0x40) != 0) {
            subclvs_len = tvb_get_uint8(tvb, offset+len);
            proto_tree_add_item(subtree, hf_isis_lsp_ext_ip_reachability_subclvs_len, tvb, offset+len, 1, ENC_BIG_ENDIAN);
            i =0;
            while (i < subclvs_len) {
                clv_offset = offset + len + 1 + i; /* skip the total subtlv len indicator */
                clv_code = tvb_get_uint8(tvb, clv_offset);
                clv_len  = tvb_get_uint8(tvb, clv_offset+1);
                subclv_tree = proto_tree_add_subtree(subtree, tvb, clv_offset, clv_len + 2,
                                                 ett_isis_lsp_clv_ip_reach_subclv,
                                                 &ti_subclvs, "subTLV");
                proto_tree_add_item(subclv_tree, hf_isis_lsp_ext_ip_reachability_code,
                                    tvb, clv_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subclv_tree, hf_isis_lsp_ext_ip_reachability_len, tvb, clv_offset+1, 1, ENC_BIG_ENDIAN);
                proto_item_append_text(ti_subclvs, ": %s (c=%u, l=%u)", val_to_str_const(clv_code, isis_lsp_ext_ip_reachability_code_vals, "Unknown"), clv_code, clv_len);

                /*
                 * we pass on now the raw data to the ipreach_subtlv dissector
                 * therefore we need to skip 3 bytes
                 * (total subtlv len, subtlv type, subtlv len)
                 */
                dissect_ipreach_subclv(tvb, pinfo, subclv_tree, ti_subclvs, clv_offset+2, clv_code, clv_len);
                i += clv_len + 2;
            }
            len += 1 + subclvs_len;
        } else {
            proto_tree_add_uint_format(subtree, hf_isis_lsp_ext_ip_reachability_subclvs_len, tvb, offset+len, 0, 0, "no sub-TLVs present");
        }

        offset += len;
        length -= len;
    }
}

/*
 * Name: dissect_isis_grp_address_clv()
 *
 * Description: Decode GROUP ADDRESS subTLVs
 *              The  Group Address  TLV is composed of 1 octet for the type,
 *              1 octet that specifies the number of bytes in the value field, and a
 *              Variable length value field that can have any or all of the subTLVs that are listed in the
 *              - below section
 *
 *Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : proto tree to build on (may be null)
 *   int : current offset into packet data
 *   int : length of IDs in packet.
 *   int : length of this clv
 *
 * Output:
 *   void, will modify proto_tree if not null.
 */

static void
dissect_isis_grp_address_clv(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    int source_num;
    uint8_t subtlv_type;
    int subtlv_len;

    proto_tree *rt_tree=NULL;

    while (length>0) {
        subtlv_type = tvb_get_uint8(tvb, offset);
        subtlv_len = tvb_get_uint8(tvb, offset+1);
        switch(subtlv_type) {


            case GRP_MAC_ADDRESS:
                rt_tree = proto_tree_add_subtree(tree, tvb, offset, subtlv_len+2,
                    ett_isis_lsp_clv_grp_macaddr, NULL, "Group MAC Address Sub-TLV");

                proto_tree_add_uint(rt_tree, hf_isis_lsp_grp_type, tvb, offset, 1, subtlv_type);

                length--;
                offset++;

                proto_tree_add_uint(rt_tree, hf_isis_lsp_grp_macaddr_length, tvb, offset, 1, subtlv_len);

                if(subtlv_len < 5) {
                    length -= subtlv_len;
                    offset += subtlv_len;
                    break;
                }

                length--;
                offset++;

                proto_tree_add_item(rt_tree, hf_isis_lsp_grp_macaddr_topology_id, tvb, offset, 2, ENC_BIG_ENDIAN);

                length -= 2;
                offset += 2;
                subtlv_len -= 2;

                proto_tree_add_item(rt_tree, hf_isis_lsp_grp_macaddr_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);

                length -= 2;
                offset += 2;
                subtlv_len -= 2;

                proto_tree_add_item(rt_tree, hf_isis_lsp_grp_macaddr_number_of_records, tvb, offset, 1, ENC_BIG_ENDIAN);

                length--;
                offset++;
                subtlv_len--;

                while(subtlv_len > 0) {

                    source_num=tvb_get_uint8(tvb, offset);
                    proto_tree_add_item(rt_tree, hf_isis_lsp_grp_macaddr_number_of_sources, tvb, offset, 1, ENC_BIG_ENDIAN);

                    length--;
                    offset++;
                    subtlv_len--;

                    proto_tree_add_item(rt_tree, hf_isis_lsp_grp_macaddr_group_address, tvb, offset, 6, ENC_NA);

                    length -= 6;
                    offset += 6;
                    subtlv_len -= 6;


                    while((subtlv_len > 0) && (source_num > 0)) {
                        proto_tree_add_item(rt_tree, hf_isis_lsp_grp_macaddr_source_address, tvb, offset, 6, ENC_NA);

                        length -= 6;
                        offset += 6;
                        subtlv_len -= 6;
                        source_num--;
                    }
                }

                break;

            case GRP_IPV4_ADDRESS:
                rt_tree = proto_tree_add_subtree(tree, tvb, offset, subtlv_len+2,
                    ett_isis_lsp_clv_grp_ipv4addr, NULL, "Group IPv4 Address Sub-TLV");

                proto_tree_add_uint(rt_tree, hf_isis_lsp_grp_type, tvb, offset, 1, subtlv_type);

                length--;
                offset++;

                proto_tree_add_uint(rt_tree, hf_isis_lsp_grp_ipv4addr_length, tvb, offset, 1, subtlv_len);

                if(subtlv_len < 5) {
                    length -= subtlv_len;
                    offset += subtlv_len;
                    break;
                }

                length--;
                offset++;

                proto_tree_add_item(rt_tree, hf_isis_lsp_grp_ipv4addr_topology_id, tvb, offset, 2, ENC_BIG_ENDIAN);

                length -= 2;
                offset += 2;
                subtlv_len -= 2;

                proto_tree_add_item(rt_tree, hf_isis_lsp_grp_ipv4addr_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);

                length -= 2;
                offset += 2;
                subtlv_len -= 2;

                proto_tree_add_item(rt_tree, hf_isis_lsp_grp_ipv4addr_number_of_records, tvb, offset, 1, ENC_BIG_ENDIAN);

                length--;
                offset++;
                subtlv_len--;

                while(subtlv_len > 0) {

                    source_num=tvb_get_uint8(tvb, offset);
                    proto_tree_add_item(rt_tree, hf_isis_lsp_grp_ipv4addr_number_of_sources, tvb, offset, 1, ENC_BIG_ENDIAN);

                    length--;
                    offset++;
                    subtlv_len--;

                    proto_tree_add_item(rt_tree, hf_isis_lsp_grp_ipv4addr_group_address, tvb, offset, 4, ENC_BIG_ENDIAN);

                    length -= 4;
                    offset += 4;
                    subtlv_len -= 4;


                    while((subtlv_len > 0) && (source_num > 0)) {
                        proto_tree_add_item(rt_tree, hf_isis_lsp_grp_ipv4addr_source_address, tvb, offset, 4, ENC_BIG_ENDIAN);

                        length -= 4;
                        offset += 4;
                        subtlv_len -= 4;
                        source_num--;
                    }
                }

                break;

            case GRP_IPV6_ADDRESS:
                rt_tree = proto_tree_add_subtree(tree, tvb, offset, subtlv_len+2,
                    ett_isis_lsp_clv_grp_ipv6addr, NULL, "Group IPv6 Address Sub-TLV");

                proto_tree_add_uint(rt_tree, hf_isis_lsp_grp_type, tvb, offset, 1, subtlv_type);

                length--;
                offset++;

                proto_tree_add_uint(rt_tree, hf_isis_lsp_grp_ipv6addr_length, tvb, offset, 1, subtlv_len);

                if(subtlv_len < 5) {
                    length -= subtlv_len;
                    offset += subtlv_len;
                    break;
                }

                length--;
                offset++;

                proto_tree_add_item(rt_tree, hf_isis_lsp_grp_ipv6addr_topology_id, tvb, offset, 2, ENC_BIG_ENDIAN);

                length -= 2;
                offset += 2;
                subtlv_len -= 2;

                proto_tree_add_item(rt_tree, hf_isis_lsp_grp_ipv6addr_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);

                length -= 2;
                offset += 2;
                subtlv_len -= 2;

                proto_tree_add_item(rt_tree, hf_isis_lsp_grp_ipv6addr_number_of_records, tvb, offset, 1, ENC_BIG_ENDIAN);

                length--;
                offset++;
                subtlv_len--;

                while(subtlv_len > 0) {

                    source_num=tvb_get_uint8(tvb, offset);
                    proto_tree_add_item(rt_tree, hf_isis_lsp_grp_ipv6addr_number_of_sources, tvb, offset, 1, ENC_BIG_ENDIAN);

                    length--;
                    offset++;
                    subtlv_len--;

                    proto_tree_add_item(rt_tree, hf_isis_lsp_grp_ipv6addr_group_address, tvb, offset, 16, ENC_NA);

                    length -= 16;
                    offset += 16;
                    subtlv_len -= 16;


                    while((subtlv_len > 0) && (source_num > 0)) {
                        proto_tree_add_item(rt_tree, hf_isis_lsp_grp_ipv6addr_source_address, tvb, offset, 16, ENC_NA);

                        length -= 16;
                        offset += 16;
                        subtlv_len -= 16;
                        source_num--;
                    }
                }

                break;

            default:
                rt_tree = proto_tree_add_subtree(tree, tvb, offset, subtlv_len+2,
                    ett_isis_lsp_clv_grp_unknown, NULL, "Unknown Sub-TLV");

                proto_tree_add_uint(rt_tree, hf_isis_lsp_grp_type, tvb, offset, 1, subtlv_type);

                length--;
                offset++;

                proto_tree_add_uint(rt_tree, hf_isis_lsp_grp_unknown_length, tvb, offset, 1, subtlv_len);

                length--;
                offset++;

                length -= subtlv_len;
                offset += subtlv_len;
                break;
        }
    }
}

/**
 * Decode the Segment Routing "SID/Label" Sub-TLV
 *
 * This Sub-TLV is used in the Segment Routing Capability TLV (2)
 * It's called by the TLV 242 dissector (dissect_isis_trill_clv)
 *
 * @param tvb the buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item
 * @param offset the offset in the tvb
 * @param tlv_len the length of tlv
 */
static void
dissect_lsp_sr_sid_label_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
                             proto_tree *tree, int offset, uint8_t tlv_len)
{
    proto_tree *subtree;

    subtree = proto_tree_add_subtree_format(tree, tvb, offset-2, tlv_len+2, ett_isis_lsp_clv_sr_sid_label,
                                         NULL, "SID/Label (t=1, l=%u)", tlv_len);

    switch (tlv_len) { /* The length determines the type of info */
    case 4:     /* Then it's a SID */
            proto_tree_add_item(subtree, hf_isis_lsp_clv_sr_cap_sid, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
            break;
        case 3: /* Then it's a Label */
            proto_tree_add_item(subtree, hf_isis_lsp_clv_sr_cap_label, tvb, offset, tlv_len, ENC_BIG_ENDIAN);
            break;
    default:
            proto_tree_add_expert_format(subtree, pinfo, &ei_isis_lsp_subtlv, tvb, offset, tlv_len,
                                         "SID/Label SubTlv - Bad length: Type: %d, Length: %d", ISIS_SR_SID_LABEL, tlv_len);
            break;
    }
}

static void dissect_subclv_ext_admin_group(tvbuff_t *tvb, proto_tree *tree,
                                           int offset, int subtype _U_, int sublen);

static int
dissect_isis_trill_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
        proto_tree *tree, int offset, int subtype, int sublen)
{
    uint16_t rt_block;
    proto_tree *rt_tree, *cap_tree, *subtree;
    uint16_t root_id;
    uint8_t tlv_type, tlv_len;
    int i;
    int local_offset;

    switch (subtype) {

    case ISIS_TE_NODE_CAP_DESC:
        /* 1 TE Node Capability Descriptor [RFC5073] */
        cap_tree = proto_tree_add_subtree(tree, tvb, offset-2, sublen+2,
            ett_isis_lsp_clv_te_node_cap_desc, NULL, "TE Node Capability Descriptor");
        /*
         *    0        B bit: P2MP Branch LSR capability       [RFC5073]
         *    1        E bit: P2MP Bud LSR capability          [RFC5073]
         *    2        M bit: MPLS-TE support                  [RFC5073]
         *    3        G bit: GMPLS support                    [RFC5073]
         *    4        P bit: P2MP RSVP-TE support             [RFC5073]
         *    5-7      Unassigned                              [RFC5073]
         */

        proto_tree_add_item(cap_tree, hf_isis_lsp_clv_te_node_cap_b_bit, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(cap_tree, hf_isis_lsp_clv_te_node_cap_e_bit, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(cap_tree, hf_isis_lsp_clv_te_node_cap_m_bit, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(cap_tree, hf_isis_lsp_clv_te_node_cap_g_bit, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(cap_tree, hf_isis_lsp_clv_te_node_cap_p_bit, tvb, offset, 1, ENC_NA);
        return 0;

    case SEGMENT_ROUTING_CAP:
        rt_tree = proto_tree_add_subtree_format(tree, tvb, offset-2, sublen+2, ett_isis_lsp_clv_sr_cap,
                                                NULL, "Segment Routing - Capability (t=%u, l=%u)", subtype, sublen);

        /*
         *    0        I-Flag: IPv4 flag                [draft-ietf-isis-segment-routing-extensions]
         *    1        V-Flag: IPv6 flag                [draft-ietf-isis-segment-routing-extensions]
         *    2-7      Unassigned
         */

        proto_tree_add_item(rt_tree, hf_isis_lsp_clv_sr_cap_i_flag, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(rt_tree, hf_isis_lsp_clv_sr_cap_v_flag, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(rt_tree, hf_isis_lsp_clv_sr_cap_range, tvb, offset+1, 3, ENC_BIG_ENDIAN);

        tlv_type = tvb_get_uint8(tvb, offset+4);
        tlv_len = tvb_get_uint8(tvb, offset+5);
        if (tlv_type == ISIS_SR_SID_LABEL) {
            dissect_lsp_sr_sid_label_clv(tvb, pinfo, rt_tree, offset+6, tlv_len);
        } else
            proto_tree_add_expert_format(rt_tree, pinfo, &ei_isis_lsp_subtlv, tvb, offset+4, tlv_len+2,
                                         "Unknown SubTlv: Type: %d, Length: %d", tlv_type, tlv_len);

        return 0;

    case IPV6_TE_ROUTER_ID:
        /* 12: IPv6 TE Router ID (rfc5316) */
        rt_tree = proto_tree_add_subtree_format(tree, tvb, offset-2, sublen+2,
                                                ett_isis_lsp_clv_ipv6_te_rtrid,
                                                NULL, "IPv6 TE Router ID (t=%u, l=%u)",
                                                subtype, sublen);
        proto_tree_add_item(rt_tree, hf_isis_lsp_clv_ipv6_te_router_id, tvb, offset, 16, ENC_NA);
        return 0;

    case TRILL_VERSION:
        rt_tree = proto_tree_add_subtree_format(tree, tvb, offset-2, sublen+2,
                    ett_isis_lsp_clv_trill_version, NULL, "TRILL version (t=%u, l=%u)", subtype, sublen);

        proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_trill_maximum_version, tvb, offset, 1, ENC_BIG_ENDIAN);

        if ( sublen == 5 ) {
            offset++;
            proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_trill_affinity_tlv, tvb, offset, 4, ENC_NA);
            proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_trill_fgl_safe, tvb, offset, 4, ENC_NA);
            proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_trill_caps, tvb, offset, 4, ENC_NA);
            proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_trill_flags, tvb, offset, 4, ENC_NA);
        }

        return 0;

    case TREES:
        rt_tree = proto_tree_add_subtree_format(tree, tvb, offset-2, sublen+2,
                            ett_isis_lsp_clv_trees, NULL, "Trees (t=%u, l=%u)", subtype, sublen);

        proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_trees_nof_trees_to_compute, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_trees_maximum_nof_trees_to_compute, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_trees_nof_trees_to_use, tvb, offset+4, 2, ENC_BIG_ENDIAN);

        return 0;

    case TREE_IDENTIFIER:
        rt_tree = proto_tree_add_subtree_format(tree, tvb, offset-2, sublen+2,
                            ett_isis_lsp_clv_root_id, NULL, "Tree root identifiers (t=%u, l=%u)", subtype, sublen);

        root_id = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_tree_root_id_starting_tree_no, tvb, offset, 2, ENC_BIG_ENDIAN);

        sublen -= 2;
        offset += 2;

        while (sublen>=2) {
            rt_block = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format(rt_tree, hf_isis_lsp_rt_capable_tree_root_id_nickname, tvb, offset, 2,
                                       rt_block, "Nickname(%dth root): 0x%04x (%d)", root_id, rt_block, rt_block);
            root_id++;
            sublen -= 2;
            offset += 2;
        }

        return 0;

    case NICKNAME:
        rt_tree = proto_tree_add_subtree_format(tree, tvb, offset-2, sublen+2,
                            ett_isis_lsp_clv_nickname, NULL, "Nickname (t=%u, l=%u)", subtype, sublen);

        while (sublen>=5) {
            proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_nickname_nickname_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_nickname_tree_root_priority, tvb, offset+1, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_nickname_nickname, tvb, offset+3, 2, ENC_BIG_ENDIAN);
            sublen -= 5;
            offset += 5;
        }

        return 0;

    case INTERESTED_VLANS:
        rt_tree = proto_tree_add_subtree_format(tree, tvb, offset-2, sublen+2,
                        ett_isis_lsp_clv_interested_vlans, NULL, "Interested VLANs and spanning tree roots (t=%u, l=%u)", subtype, sublen);

        proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_interested_vlans_nickname, tvb, offset, 2, ENC_BIG_ENDIAN);
        sublen -= 2;
        offset += 2;

        proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_interested_vlans_multicast_ipv4, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_interested_vlans_multicast_ipv6, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_interested_vlans_vlan_start_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        sublen -= 2;
        offset += 2;

        proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_interested_vlans_vlan_end_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        sublen -= 2;
        offset += 2;

        proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_interested_vlans_afs_lost_counter, tvb, offset, 4, ENC_BIG_ENDIAN);
        sublen -= 4;
        offset += 4;

        while (sublen>=6) {
            proto_tree_add_item(rt_tree, hf_isis_lsp_root_id, tvb, offset, 6, ENC_NA);
            sublen -= 6;
            offset += 6;
        }

        return 0;

    case TREES_USED_IDENTIFIER:
        rt_tree = proto_tree_add_subtree_format(tree, tvb, offset-2, sublen+2,
                    ett_isis_lsp_clv_tree_used, NULL, "Trees used identifiers (t=%u, l=%u)", subtype, sublen);

        root_id = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_tree_used_id_starting_tree_no, tvb, offset, 2, ENC_BIG_ENDIAN);

        sublen -= 2;
        offset += 2;

        while (sublen>=2) {
            rt_block = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint_format(rt_tree, hf_isis_lsp_rt_capable_tree_used_id_nickname, tvb, offset,2,
                                       rt_block, "Nickname(%dth root): 0x%04x (%d)", root_id, rt_block, rt_block);
            root_id++;
            offset += 2;
            sublen -= 2;
        }

        return 0;

    case VLAN_GROUP:
        rt_tree = proto_tree_add_subtree_format(tree, tvb, offset-2, sublen+2,
                        ett_isis_lsp_clv_vlan_group, NULL, "VLAN group (t=%u, l=%u)", subtype, sublen);

        proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_vlan_group_primary_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);

        offset += 2;
        sublen -= 2;

        while (sublen>=2) {

            proto_tree_add_item(rt_tree, hf_isis_lsp_rt_capable_vlan_group_secondary_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            sublen -= 2;
            offset += 2;
        }

        return 0;

    case SEGMENT_ROUTING_ALG:
        rt_tree = proto_tree_add_subtree_format(tree, tvb, offset-2, sublen+2,
                                         ett_isis_lsp_clv_sr_alg, NULL, "Segment Routing - Algorithms (t=%u, l=%u)",
                                         subtype, sublen);
        i = 0;
        while (i < sublen) {
            proto_tree_add_item(rt_tree, hf_isis_lsp_clv_sr_alg, tvb, offset+i, 1, ENC_NA);
            i++;
        }
        return 0;

    case SEGMENT_ROUTING_LB:
        rt_tree = proto_tree_add_subtree_format(tree, tvb, offset-2, sublen+2,
                                         ett_isis_lsp_clv_sr_lb, NULL, "Segment Routing - Local Block (t=%u, l=%u)",
                                         subtype, sublen);
        proto_tree_add_item(rt_tree, hf_isis_lsp_clv_sr_lb_flags, tvb, offset, 1, ENC_NA);
        offset += 1;
        sublen -= 1;
        i = 0;
        while (i < sublen) {
            local_offset = offset + i;
            proto_tree_add_item(rt_tree, hf_isis_lsp_clv_sr_cap_range, tvb, local_offset, 3, ENC_NA);
            tlv_type = tvb_get_uint8(tvb, local_offset+3);
            tlv_len = tvb_get_uint8(tvb, local_offset+4);
            if (tlv_type == ISIS_SR_SID_LABEL) {
                dissect_lsp_sr_sid_label_clv(tvb, pinfo, rt_tree, local_offset+5, tlv_len);
            } else {
                proto_tree_add_expert_format(rt_tree, pinfo, &ei_isis_lsp_subtlv, tvb, local_offset+3, tlv_len+2,
                                             "Unknown Sub-TLV: Type: %d, Length: %d", tlv_type, tlv_len);
            }
            i += (5 + tlv_len);
        }
        return 0;

    case SRV6_CAP:
        rt_tree = proto_tree_add_subtree_format(tree, tvb, offset-2, sublen+2,
                                                ett_isis_lsp_clv_srv6_cap,
                                                NULL, "SRv6 Capability (t=%u, l=%u)",
                                                subtype, sublen);
        proto_tree_add_bitmask(rt_tree, tvb, offset, hf_isis_lsp_clv_srv6_cap_flags,
                               ett_isis_lsp_clv_srv6_cap_flags, srv6_cap_flags, ENC_NA);
        return 0;

    case NODE_MSD:
        rt_tree = proto_tree_add_subtree_format(tree, tvb, offset-2, sublen+2,
                                                ett_isis_lsp_clv_node_msd,
                                                NULL, "Node Maximum SID Depth (t=%u, l=%u)",
                                                subtype, sublen);
        while (sublen >= 2) {
            proto_tree_add_item(rt_tree, hf_isis_lsp_clv_igp_msd_type, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(rt_tree, hf_isis_lsp_clv_igp_msd_value, tvb, offset+1, 1, ENC_NA);
            sublen -= 2;
            offset += 2;
        }
        return 0;

    case FLEX_ALGO_DEF:
        rt_tree = proto_tree_add_subtree_format(tree, tvb, offset-2, sublen+2,
                                                ett_isis_lsp_clv_flex_algo_def,
                                                NULL, "Flexible Algorithm Definition (t=%u, l=%u)",
                                                subtype, sublen);
        proto_tree_add_item(rt_tree, hf_isis_lsp_clv_flex_algo_algorithm, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(rt_tree, hf_isis_lsp_clv_flex_algo_metric_type, tvb, offset+1, 1, ENC_NA);
        proto_tree_add_item(rt_tree, hf_isis_lsp_clv_flex_algo_calc_type, tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(rt_tree, hf_isis_lsp_clv_flex_algo_priority, tvb, offset+3, 1, ENC_NA);
        sublen -= 4;
        offset += 4;
        while (sublen >= 2) {
            tlv_type = tvb_get_uint8(tvb, offset);
            tlv_len = tvb_get_uint8(tvb, offset+1);
            sublen -= 2;
            offset += 2;
            subtree = proto_tree_add_subtree_format(rt_tree, tvb, offset-2, tlv_len+2,
                                                    ett_isis_lsp_clv_flex_algo_def_sub_tlv,
                                                    NULL, "%s (t=%u, l=%u)",
                                                    val_to_str_const(tlv_type, isis_lsp_flex_algo_sub_tlv_vals, "Unknown"),
                                                    tlv_type, tlv_len);
            switch (tlv_type) {
            case FAD_EXCLUDE_AG:
            case FAD_INCLUDE_ANY_AG:
            case FAD_INCLUDE_ALL_AG:
                dissect_subclv_ext_admin_group(tvb, subtree, offset, tlv_type, tlv_len);
                break;
            default:
                break;
            }
            sublen -= tlv_len;
            offset += tlv_len;
        }
        return 0;

    default:
        return -1;
    }
}

/*
 * Name: dissect_isis_rt_capable_clv()
 *
 * Description: Decode RouterCapability subTLVs
 *
 *   The Router Capability TLV is composed of 1 octet for the type,
 *   1 octet that specifies the number of bytes in the value field, and a
 *   variable length value field that can have any or all of the subTLVs
 *   that are listed in the below section
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : proto tree to build on (may be null)
 *   int : current offset into packet data
 *   int : length of IDs in packet.
 *   int : length of this clv
 *   len : local variable described to handle the length of the subTLV
 *
 * Output:
 *   void, will modify proto_tree if not null.
 */

/* As per RFC 7176 section 2.3 */
static void
dissect_isis_rt_capable_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
        proto_tree *tree, int offset, isis_data_t *isis _U_, int length)
{
    uint8_t subtype, subtlvlen;

    proto_tree_add_item(tree, hf_isis_lsp_rt_capable_router_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    length -= 4;
    proto_tree_add_item(tree, hf_isis_lsp_rt_capable_flag_s, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_isis_lsp_rt_capable_flag_d, tvb, offset, 1, ENC_BIG_ENDIAN);
    length -= 1;
    offset += 1;

    while (length>=2) {
        subtype   = tvb_get_uint8(tvb, offset);
        subtlvlen = tvb_get_uint8(tvb, offset+1);
        length -= 2;
        offset += 2;

        if (subtlvlen > length) {
            proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset-2, -1,
                                  "Short type %d TLV (%d vs %d)", subtype, subtlvlen, length);
            return;
        }

        if (dissect_isis_trill_clv(tvb, pinfo, tree, offset, subtype, subtlvlen)==-1) {

            proto_tree_add_expert_format( tree, pinfo, &ei_isis_lsp_subtlv, tvb, offset-2, subtlvlen+2,
                                      "Unknown SubTlv: Type: %d, Length: %d", subtype, subtlvlen);
        }
        length -= subtlvlen;
        offset += subtlvlen;
    }
}

/*
 * Name: dissect_lsp_ipv6_reachability_clv()
 *
 * Description: Decode an IPv6 reachability CLV - code 236.
 *
 *   CALLED BY TLV 237 DISSECTOR
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : proto tree to build on (may be null)
 *   int : current offset into packet data
 *   int : length of IDs in packet.
 *   int : length of this clv
 *
 * Output:
 *   void, will modify proto_tree if not null.
 */
static void
dissect_lsp_ipv6_reachability_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    proto_tree        *subtree = NULL;
    proto_tree        *subtree2 = NULL;
    proto_item        *ti_subtree = NULL;
    proto_item        *ti_subclvs = NULL;
    uint8_t           ctrl_info;
    unsigned          bit_length;
    int               byte_length;
    ws_in6_addr prefix;
    address           prefix_addr;
    unsigned          len,i;
    unsigned          subclvs_len;
    unsigned          clv_code, clv_len;
    int               clv_offset;
    char              *prefix_str;

    if (!tree) return;

    while (length > 0) {
        ctrl_info = tvb_get_uint8(tvb, offset+4);
        bit_length = tvb_get_uint8(tvb, offset+5);
        byte_length = tvb_get_ipv6_addr_with_prefix_len(tvb, offset+6, &prefix, bit_length);
        if (byte_length == -1) {
            proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                "IPv6 prefix has an invalid length: %d bits", bit_length );
                return;
            }
        subclvs_len = 0;
        if ((ctrl_info & 0x20) != 0)
            subclvs_len = 1+tvb_get_uint8(tvb, offset+6+byte_length);

        subtree = proto_tree_add_subtree(tree, tvb, offset, 6+byte_length+subclvs_len,
            ett_isis_lsp_part_of_clv_ipv6_reachability, &ti_subtree, "IPv6 Reachability");

        set_address(&prefix_addr, AT_IPv6, 16, prefix.bytes);
        prefix_str = address_to_str(pinfo->pool, &prefix_addr);
        proto_item_append_text(ti_subtree, ": %s/%u", prefix_str, bit_length);

        proto_tree_add_item(subtree, hf_isis_lsp_ipv6_reachability_metric, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_isis_lsp_ipv6_reachability_distribution, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_isis_lsp_ipv6_reachability_distribution_internal, tvb, offset+4, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_isis_lsp_ipv6_reachability_subtlv, tvb, offset+4, 1, ENC_NA);

        if ((ctrl_info & 0x1f) != 0) {
            proto_tree_add_item(subtree, hf_isis_lsp_ipv6_reachability_reserved_bits, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(subtree, hf_isis_lsp_ipv6_reachability_prefix_length, tvb, offset+5, 1, ENC_NA);
        proto_tree_add_ipv6_format_value(subtree, hf_isis_lsp_ipv6_reachability_ipv6_prefix, tvb, offset+6, byte_length,
                            &prefix, "%s", prefix_str);

        len = 6 + byte_length;
        if ((ctrl_info & 0x20) != 0) {
            subclvs_len = tvb_get_uint8(tvb, offset+len);
            proto_tree_add_item(subtree, hf_isis_lsp_ipv6_reachability_subclvs_len, tvb, offset+len, 1, ENC_BIG_ENDIAN);

            i =0;
            while (i < subclvs_len) {
                clv_offset = offset + len + 1 + i; /* skip the total subtlv len indicator */
                clv_code = tvb_get_uint8(tvb, clv_offset);
                clv_len  = tvb_get_uint8(tvb, clv_offset+ 1);
                subtree2 = proto_tree_add_subtree_format(subtree, tvb, clv_offset, clv_len + 2,
                                                         ett_isis_lsp_clv_ip_reach_subclv,
                                                         &ti_subclvs, "subTLV");
                proto_tree_add_item(subtree2, hf_isis_lsp_ext_ip_reachability_code,
                                    tvb, clv_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree2, hf_isis_lsp_ext_ip_reachability_len,
                                    tvb, clv_offset+1, 1, ENC_BIG_ENDIAN);
                proto_item_append_text(ti_subclvs, ": %s (c=%u, l=%u)",
                                       val_to_str_const(clv_code, isis_lsp_ext_ip_reachability_code_vals, "Unknown"),
                                       clv_code, clv_len);

                dissect_ipreach_subclv(tvb, pinfo, subtree2, ti_subclvs, clv_offset+2, clv_code, clv_len);
                i += clv_len + 2;
            }
            len += 1 + subclvs_len;
        } else {
            proto_tree_add_uint_format(subtree, hf_isis_lsp_ext_ip_reachability_subclvs_len, tvb, offset, len, 0, "no sub-TLVs present");
        }
        offset += len;
        length -= len;
    }
}

/*
 * Name: dissect_lsp_nlpid_clv()
 *
 * Description:
 *    Decode for a lsp packets NLPID clv.  Calls into the
 *    clv common one.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_lsp_nlpid_clv(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    isis_dissect_nlpid_clv(tvb, tree, ett_isis_lsp_clv_nlpid_nlpid, hf_isis_lsp_clv_nlpid_nlpid, offset, length);
}

/*
 * Name: dissect_lsp_mt_clv()
 *
 * Description: - code 229
 *    Decode for a lsp packets Multi Topology clv.  Calls into the
 *    clv common one.
 *
 * Input:
 *      tvbuff_t * : tvbuffer for packet data
 *      proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    unsigned : length of this clv
 *    int : length of IDs in packet.
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_lsp_mt_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    isis_dissect_mt_clv(tvb, pinfo, tree, offset, length, hf_isis_lsp_clv_mt, &ei_isis_lsp_clv_mt );
}

/*
 * Name: dissect_lsp_hostname_clv()
 *
 * Description:
 *      Decode for a lsp packets hostname clv.  Calls into the
 *      clv common one.
 *
 * Input:
 *      tvbuff_t * : tvbuffer for packet data
 *      proto_tree * : proto tree to build on (may be null)
 *      int : current offset into packet data
 *      int : length of IDs in packet.
 *      int : length of this clv
 *
 * Output:
 *      void, will modify proto_tree if not null.
 */
static void
dissect_lsp_hostname_clv(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    isis_dissect_hostname_clv(tvb, tree, offset, length,
        hf_isis_lsp_hostname);
}

/*
 * Name: dissect_lsp_srlg_clv()
 *
 * Description:
 *      Decode for a lsp packets Shared Risk Link Group (SRLG) clv (138).  Calls into the
 *      clv common one.
 *
 * Input:
 *      tvbuff_t * : tvbuffer for packet data
 *      proto_tree * : proto tree to build on (may be null)
 *      int : current offset into packet data
 *      int : length of IDs in packet.
 *      int : length of this clv
 *
 * Output:
 *      void, will modify proto_tree if not null.
 */
static void
dissect_lsp_srlg_clv(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{

    proto_tree_add_item(tree, hf_isis_lsp_srlg_system_id, tvb, offset, 6, ENC_BIG_ENDIAN);
    offset += 6;

    proto_tree_add_item(tree, hf_isis_lsp_srlg_pseudo_num, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_isis_lsp_srlg_flags_numbered, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_isis_lsp_srlg_ipv4_local, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_isis_lsp_srlg_ipv4_remote, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    length -= 16;
    while(length){
        proto_tree_add_item(tree, hf_isis_lsp_srlg_value, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        length -= 4;
    }
}


/*
 * Name: dissect_lsp_te_router_id_clv()
 *
 * Description:
 *      Decode for a lsp packets Traffic Engineering ID clv.  Calls into the
 *      clv common one.
 *
 * Input:
 *      tvbuff_t * : tvbuffer for packet data
 *      proto_tree * : proto tree to build on (may be null)
 *      int : current offset into packet data
 *      int : length of IDs in packet.
 *      int : length of this clv
 *
 * Output:
 *      void, will modify proto_tree if not null.
 */
static void
dissect_lsp_te_router_id_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    isis_dissect_te_router_id_clv(tree, pinfo, tvb, &ei_isis_lsp_short_clv, offset, length,
        hf_isis_lsp_clv_te_router_id );
}


/*
 * Name: dissect_lsp_ip_int_addr_clv()
 *
 * Description:
 *    Decode for a lsp packets ip interface addr clv.  Calls into the
 *    clv common one.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_lsp_ip_int_addr_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    isis_dissect_ip_int_clv(tree, pinfo, tvb, &ei_isis_lsp_short_clv, offset, length,
        hf_isis_lsp_clv_ipv4_int_addr );
}

/*
 * Name: dissect_lsp_ipv6_int_addr_clv()
 *
 * Description: Decode an IPv6 interface addr CLV - code 232.
 *
 *   Calls into the clv common one.
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : proto tree to build on (may be null)
 *   int : current offset into packet data
 *   int : length of IDs in packet.
 *   int : length of this clv
 *
 * Output:
 *   void, will modify proto_tree if not null.
 */
static void
dissect_lsp_ipv6_int_addr_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    isis_dissect_ipv6_int_clv(tree, pinfo, tvb, &ei_isis_lsp_short_clv, offset, length,
        hf_isis_lsp_clv_ipv6_int_addr );
}

static void
dissect_isis_lsp_clv_mt_cap_spb_instance(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, int offset, int subtype, int sublen)
{
    const int CIST_ROOT_ID_LEN            = 8; /* CIST Root Identifier */
    const int CIST_EXT_ROOT_PATH_COST_LEN = 4; /* CIST External Root Path Cost */
    const int BRIDGE_PRI_LEN              = 2; /* Bridge Priority */
    const int V_SPSOURCEID_LEN            = 4; /* v | SPSourceID */
    const int NUM_TREES_LEN               = 1; /* num of trees */

    const int CIST_ROOT_ID_OFFSET = 0;
    const int CIST_EXT_ROOT_PATH_COST_OFFSET = CIST_ROOT_ID_OFFSET            + CIST_ROOT_ID_LEN;
    const int BRIDGE_PRI_OFFSET              = CIST_EXT_ROOT_PATH_COST_OFFSET + CIST_EXT_ROOT_PATH_COST_LEN;
    const int V_SPSOURCEID_OFFSET            = BRIDGE_PRI_OFFSET              + BRIDGE_PRI_LEN;
    const int NUM_TREES_OFFSET               = V_SPSOURCEID_OFFSET            + V_SPSOURCEID_LEN;
    const int FIXED_LEN                      = NUM_TREES_OFFSET               + NUM_TREES_LEN;
    const int VLAN_ID_TUPLE_LEN = 8;

    static int * const lsp_cap_spb_instance_vlanid_tuple[] = {
        &hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_u,
        &hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_m,
        &hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_a,
        &hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_reserved,
        NULL
    };

    if (sublen < FIXED_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                              "Short SPB Digest subTLV (%d vs %d)", sublen, FIXED_LEN);
        return;
    }
    else {
        proto_tree *subtree, *ti;
        int subofs = offset;
        uint8_t       num_trees            = tvb_get_uint8(tvb, subofs + NUM_TREES_OFFSET);

        /*************************/
        subtree = proto_tree_add_subtree_format( tree, tvb, offset-2, sublen+2, ett_isis_lsp_clv_mt_cap_spb_instance, NULL,
                                  "SPB Instance: Type: 0x%02x, Length: %d", subtype, sublen);

        /*************************/
        proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spb_instance_cist_root_identifier, tvb, subofs + CIST_ROOT_ID_OFFSET, CIST_ROOT_ID_LEN, ENC_NA);
        proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spb_instance_cist_external_root_path_cost, tvb, subofs + CIST_EXT_ROOT_PATH_COST_OFFSET, CIST_EXT_ROOT_PATH_COST_LEN, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spb_instance_bridge_priority, tvb, subofs + BRIDGE_PRI_OFFSET, BRIDGE_PRI_LEN, ENC_BIG_ENDIAN);

        proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spb_instance_v, tvb, subofs + V_SPSOURCEID_OFFSET, V_SPSOURCEID_LEN, ENC_BIG_ENDIAN);

        proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spsourceid, tvb, subofs + V_SPSOURCEID_OFFSET, V_SPSOURCEID_LEN, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spb_instance_number_of_trees, tvb, subofs + NUM_TREES_OFFSET, NUM_TREES_LEN, ENC_BIG_ENDIAN);
        if (num_trees == 0)
            proto_item_append_text(ti, " Invalid subTLV: zero trees");

        subofs += FIXED_LEN;
        sublen -= FIXED_LEN;

        /*************************/
        if (sublen != (num_trees * VLAN_ID_TUPLE_LEN)) {
            proto_tree_add_expert_format( subtree, pinfo, &ei_isis_lsp_short_clv, tvb, subofs, 0, "SubTLV length doesn't match number of trees");
            return;
        }
        while (sublen > 0 && num_trees > 0) {
            if (sublen < VLAN_ID_TUPLE_LEN) {
                proto_tree_add_expert_format(subtree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                                      "Short VLAN_ID entry (%d vs %d)", sublen, VLAN_ID_TUPLE_LEN);
                return;
            }
            else {
                proto_tree_add_bitmask_list(subtree, tvb, subofs, 1, lsp_cap_spb_instance_vlanid_tuple, ENC_BIG_ENDIAN);
                subofs += 1;

                proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_ect, tvb, subofs, 4, ENC_BIG_ENDIAN);
                subofs += 4;
                proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_base_vid, tvb, subofs, 3, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_spvid, tvb, subofs, 3, ENC_BIG_ENDIAN);
                subofs += 3;

                sublen -= VLAN_ID_TUPLE_LEN;
                --num_trees;
            }
        }
        if (num_trees) {
            proto_tree_add_expert_format(subtree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                                  "Short subTLV (%d vs %d)", sublen, num_trees * VLAN_ID_TUPLE_LEN);
            return;
        }
    }
}
static void
dissect_isis_lsp_clv_mt_cap_spb_oalg(tvbuff_t   *tvb,
    proto_tree *tree, int offset, int subtype _U_, int sublen _U_)
{

    proto_tree_add_item(tree, hf_isis_lsp_mt_cap_spb_opaque_algorithm, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_isis_lsp_mt_cap_spb_opaque_information, tvb, offset, -1, ENC_NA);

}
static void
dissect_isis_lsp_clv_mt_cap_spbm_service_identifier(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, int offset, int subtype, int sublen)
{
    const int BMAC_LEN = 6; /* B-MAC Address */
    const int BVID_LEN = 2; /* Base-VID */

    const int BMAC_OFFSET = 0;
    const int BVID_OFFSET = BMAC_OFFSET + BMAC_LEN;
    const int FIXED_LEN   = BVID_OFFSET + BVID_LEN;

    const int ISID_LEN = 4;

    static int * const lsp_cap_spbm_service_identifier[] = {
        &hf_isis_lsp_mt_cap_spbm_service_identifier_t,
        &hf_isis_lsp_mt_cap_spbm_service_identifier_r,
        &hf_isis_lsp_mt_cap_spbm_service_identifier_reserved,
        NULL
    };

    if (sublen < FIXED_LEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                              "Short SPBM Service Identifier and Unicast Address subTLV (%d vs %d)", sublen, FIXED_LEN);
        return;
    }
    else {
        proto_tree *subtree;
        int subofs = offset;

        /*************************/
        subtree = proto_tree_add_subtree_format( tree, tvb, offset-2, sublen+2, ett_isis_lsp_clv_mt_cap_spbm_service_identifier, NULL,
                                  "SPB Service ID and Unicast Address: Type: 0x%02x, Length: %d", subtype, sublen);

        /*************************/
        proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spbm_service_identifier_b_mac, tvb, subofs + BMAC_OFFSET, BMAC_LEN, ENC_NA);
        proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spbm_service_identifier_base_vid, tvb, subofs + BVID_OFFSET, BVID_LEN, ENC_BIG_ENDIAN);

        subofs += FIXED_LEN;
        sublen -= FIXED_LEN;

        /*************************/
        while (sublen > 0) {
            if (sublen < ISID_LEN) {
                proto_tree_add_expert_format(subtree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                                      "Short ISID entry (%d vs %d)", sublen, 4);
                return;
            }
            else {
                proto_tree_add_bitmask_list(subtree, tvb, subofs, 1, lsp_cap_spbm_service_identifier, ENC_BIG_ENDIAN);
                subofs += 1;
                sublen -= 1;

                proto_tree_add_item(subtree, hf_isis_lsp_mt_cap_spbm_service_identifier_i_sid, tvb, subofs, 3, ENC_BIG_ENDIAN);
                subofs += 3;
                sublen -= 3;
            }
        }
    }
}
static void
dissect_isis_lsp_clv_mt_cap_spbv_mac_address(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, int offset, int subtype, int sublen)
{

    static int * const lsp_spb_short_mac_address[] = {
        &hf_isis_lsp_spb_short_mac_address_t,
        &hf_isis_lsp_spb_short_mac_address_r,
        &hf_isis_lsp_spb_short_mac_address_reserved,
        NULL
    };


    if (sublen < 2) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                              "Short SPBV Mac Address subTLV (%d vs %d)", sublen, 2);
        return;
    }
    else {
        proto_tree *subtree;
        int subofs = offset;

        /*************************/
        subtree = proto_tree_add_subtree_format( tree, tvb, offset-2, sublen+2, ett_isis_lsp_clv_mt_cap_spbv_mac_address, NULL,
                                  "SPBV Mac Address: Type: 0x%02x, Length: %d", subtype, sublen);

        /*************************/
        proto_tree_add_item(subtree, hf_isis_lsp_spb_reserved, tvb, subofs, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_isis_lsp_spb_sr_bit, tvb, subofs, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_isis_lsp_spb_spvid, tvb, subofs, 2, ENC_BIG_ENDIAN);

        subofs += 2;
        sublen -= 2;

        /*************************/
        while (sublen > 0) {
            if (sublen < 7) {
                proto_tree_add_expert_format(subtree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                                      "Short MAC Address entry (%d vs %d)", sublen, 7);
                return;
            }
            else {
                proto_tree_add_bitmask_list(subtree, tvb, subofs, 1, lsp_spb_short_mac_address, ENC_BIG_ENDIAN);
                subofs += 1;
                sublen -= 1;

                proto_tree_add_item(subtree, hf_isis_lsp_spb_short_mac_address, tvb, subofs, 6, ENC_NA);

                subofs += 6;
                sublen -= 6;
            }
        }
    }
}




/*
 * Name: dissect_lsp_clv_mt_cap()
 *
 * Description: Decode an ISIS MT-CAP CLV - code 144.
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : proto tree to build on (may be null)
 *   int : current offset into packet data
 *   int : length of IDs in packet.
 *   int : length of this clv
 *
 * Output:
 *   void, will modify proto_tree if not null.
 */
static void
dissect_isis_lsp_clv_mt_cap(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
                            isis_data_t *isis _U_, int length)
{
    if (length >= 2) {
        /* mtid */
        proto_tree_add_item( tree, hf_isis_lsp_mt_cap_mtid, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_isis_lsp_mt_cap_overload, tvb, offset, 2, ENC_BIG_ENDIAN);
        length -= 2;
        offset += 2;
        while (length >= 2) {
            uint8_t subtype   = tvb_get_uint8(tvb, offset);
            uint8_t subtlvlen = tvb_get_uint8(tvb, offset+1);
            length -= 2;
            offset += 2;
            if (subtlvlen > length) {
                proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset-2, -1,
                                      "Short type %d TLV (%d vs %d)", subtype, subtlvlen, length);
                return;
            }
            if (subtype == 0x01) { /* SPB Instance */
                dissect_isis_lsp_clv_mt_cap_spb_instance(tvb, pinfo, tree, offset, subtype, subtlvlen);
            }
            else if (subtype == 0x02) { /* OALG */
                dissect_isis_lsp_clv_mt_cap_spb_oalg(tvb, tree, offset, subtype, subtlvlen);
            }
            else if (subtype == 0x03) { /* SPBM Service Identifier */
                dissect_isis_lsp_clv_mt_cap_spbm_service_identifier(tvb, pinfo, tree, offset, subtype, subtlvlen);
            }
            else if (subtype == 0x04) { /* SPBV Mac Address */
                dissect_isis_lsp_clv_mt_cap_spbv_mac_address(tvb, pinfo, tree, offset, subtype, subtlvlen);
            }
            else if (dissect_isis_trill_clv(tvb, pinfo, tree, offset, subtype, subtlvlen)==-1) {
                proto_tree_add_expert_format( tree, pinfo, &ei_isis_lsp_subtlv, tvb, offset-2, subtlvlen+2,
                                      "Unknown SubTlv: Type: %d, Length: %d", subtype, subtlvlen);
            }
            length -= subtlvlen;
            offset += subtlvlen;
        }

    }
}


/*
 * Name: dissect_isis_lsp_clv_sid_label_binding()
 *
 * Description: Decode an ISIS SID/LABEL binding - code 149.
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : proto tree to build on (may be null)
 *   int : current offset into packet data
 *   int : length of IDs in packet.
 *   int : length of this clv
 *
 * Output:
 *   void, will modify proto_tree if not null.
 */
static void
dissect_isis_lsp_clv_sid_label_binding(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
                                       isis_data_t *isis _U_, int length)
{
    proto_item *ti_subclvs = NULL;
    proto_tree *subtree = NULL;
    int tlv_offset = 0;
    int sub_tlv_len = 0;
    int i = 0;
    uint8_t clv_pref_l = 0;
    unsigned   clv_code;
    unsigned   clv_len;

    static int * const lsp_sl_flags[] = {
        &hf_isis_lsp_sl_binding_flags_f,
        &hf_isis_lsp_sl_binding_flags_m,
        &hf_isis_lsp_sl_binding_flags_s,
        &hf_isis_lsp_sl_binding_flags_d,
        &hf_isis_lsp_sl_binding_flags_a,
        &hf_isis_lsp_sl_binding_flags_rsv,
        NULL
    };

    static int * const lsp_sl_sub_tlv_flags[] = {
        &hf_isis_lsp_sl_sub_tlv_flags_r,
        &hf_isis_lsp_sl_sub_tlv_flags_n,
        &hf_isis_lsp_sl_sub_tlv_flags_p,
        &hf_isis_lsp_sl_sub_tlv_flags_e,
        &hf_isis_lsp_sl_sub_tlv_flags_v,
        &hf_isis_lsp_sl_sub_tlv_flags_l,
        &hf_isis_lsp_sl_sub_tlv_flags_rsv,
        NULL
    };

    if ( length <= 0 ) {
        return;
    }


    tlv_offset  = offset;

    proto_tree_add_bitmask(tree, tvb, tlv_offset,
                           hf_isis_lsp_sl_binding_flags, ett_isis_lsp_sl_flags, lsp_sl_flags, ENC_NA);
    tlv_offset++;
    proto_tree_add_item(tree, hf_isis_lsp_sl_binding_weight, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
    tlv_offset++;
    proto_tree_add_item(tree, hf_isis_lsp_sl_binding_range, tvb, tlv_offset, 2, ENC_BIG_ENDIAN);
    tlv_offset = tlv_offset+2;
    proto_tree_add_item(tree, hf_isis_lsp_sl_binding_prefix_length, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
    clv_pref_l = tvb_get_uint8(tvb, tlv_offset);
    tlv_offset++;
    if (clv_pref_l == 32) {
        proto_tree_add_item(tree, hf_isis_lsp_sl_binding_fec_prefix_ipv4, tvb, tlv_offset, clv_pref_l/8, ENC_NA);
    }
    else if (clv_pref_l == 128) {
        proto_tree_add_item(tree, hf_isis_lsp_sl_binding_fec_prefix_ipv6, tvb, tlv_offset, clv_pref_l/8, ENC_NA);
    }
    else {
      proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb, tlv_offset, -1,
                                      "Prefix address format unknown length : %d",clv_pref_l);
    }
    tlv_offset = tlv_offset+(clv_pref_l/8);
    sub_tlv_len = length - (5+clv_pref_l/8);
    while (i < sub_tlv_len) {
        clv_code = tvb_get_uint8(tvb, i+tlv_offset);
        clv_len  = tvb_get_uint8(tvb, i+1+tlv_offset);
        ti_subclvs = proto_tree_add_item(tree, hf_isis_lsp_sl_sub_tlv, tvb, tlv_offset, clv_len+2, ENC_NA);
        proto_item_append_text(ti_subclvs, " %s",
                               val_to_str_const(clv_code, isis_lsp_sl_sub_tlv_vals, "Unknown capability sub-tlv type"));
        subtree = proto_item_add_subtree(ti_subclvs, ett_isis_lsp_sl_sub_tlv);
        proto_tree_add_item(subtree, hf_isis_lsp_sl_sub_tlv_type, tvb, i+tlv_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_isis_lsp_sl_sub_tlv_length, tvb, i+1+tlv_offset, 1, ENC_BIG_ENDIAN);
        switch (clv_code) {
            case ISIS_LSP_SL_SUB_SID_LABEL:
                switch (clv_len) {
                    case 3 :
                        proto_tree_add_item(subtree, hf_isis_lsp_sl_sub_tlv_label_20,
                                            tvb, i+2+tlv_offset, clv_len, ENC_BIG_ENDIAN);
                        break;
                    case 4 :
                        proto_tree_add_item(subtree, hf_isis_lsp_sl_sub_tlv_label_32,
                                            tvb, i+2+tlv_offset, clv_len, ENC_BIG_ENDIAN);
                        break;
                    default :
                        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb, i+2+tlv_offset, -1,
                                                "Label badly formatted");
                    break;
                }
                break;
            case ISIS_LSP_SL_SUB_PREFIX_SID: {
                proto_tree_add_bitmask(subtree, tvb, i+2+tlv_offset, hf_isis_lsp_sl_sub_tlv_flags,
                                       ett_isis_lsp_sl_sub_tlv_flags, lsp_sl_sub_tlv_flags, ENC_NA);
                proto_tree_add_item(subtree, hf_isis_lsp_sl_sub_tlv_algorithm,
                                    tvb, i+2+tlv_offset+1, 1, ENC_BIG_ENDIAN);
                switch (clv_len-2) {
                    case 3 :
                        proto_tree_add_item(subtree, hf_isis_lsp_sl_sub_tlv_label_20,
                                            tvb, i+2+tlv_offset+2, clv_len-2, ENC_BIG_ENDIAN);
                        break;
                    case 4 :
                        proto_tree_add_item(subtree, hf_isis_lsp_sl_sub_tlv_label_32,
                                            tvb, i+2+tlv_offset+2, clv_len-2, ENC_BIG_ENDIAN);
                        break;
                    default :
                        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb, i+2+tlv_offset+2, -1,
                                                "Label badly formatted");
                        break;
                    }
                }
                break;
            default:
                proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb, i+2+tlv_offset, -1,
                                            "Sub TLV badly formatted, type unknown %d", clv_code);
                break;
        }
        i += clv_len + 2;
    }
}

/*
 * Name: dissect_lsp_authentication_clv()
 *
 * Description:
 *    Decode for a lsp packets authentication clv.  Calls into the
 *    clv common one.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_lsp_authentication_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    isis_dissect_authentication_clv(tree, pinfo, tvb, hf_isis_lsp_authentication, hf_isis_clv_key_id, &ei_isis_lsp_authentication, offset, length);
}

/*
 * Name: dissect_lsp_ip_authentication_clv()
 *
 * Description:
 *    Decode for a lsp packets authentication clv.  Calls into the
 *    clv common one.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_lsp_ip_authentication_clv(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    if ( length != 0 ) {
       proto_tree_add_item(tree, hf_isis_lsp_ip_authentication, tvb, offset, length, ENC_ASCII);
    }
}

/*
 * Name: dissect_lsp_area_address_clv()
 *
 * Description:
 *    Decode for a lsp packet's area address clv.  Call into clv common
 *    one.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  May be NULL
 *    int : offset into packet data where we are.
 *    int : length of IDs in packet.
 *    int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_area_address_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    isis_dissect_area_address_clv(tree, pinfo, tvb, &ei_isis_lsp_short_clv, hf_isis_lsp_area_address, offset, length);
}

/*
 * Name: dissect_lsp_eis_neighbors_clv_inner()
 *
 * Description:
 *    Real work horse for showing neighbors.  This means we decode the
 *    first octet as either virtual/!virtual (if show_virtual param is
 *    set), or as a must == 0 reserved value.
 *
 *    Once past that, we decode n neighbor elements.  Each neighbor
 *    is comprised of a metric block (is dissect_metric) and the
 *    addresses.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  May be NULL
 *    int : offset into packet data where we are.
 *    int : length of IDs in packet.
 *    int : length of clv we are decoding
 *    int : set to decode first octet as virtual vs reserved == 0
 *    int : set to indicate EIS instead of IS (6 octet per addr instead of 7)
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_eis_neighbors_clv_inner(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, int length, unsigned id_length, int show_virtual, int is_eis)
{
    proto_item     *ti;
    proto_tree    *ntree = NULL;
    int        tlen;

    if (!is_eis) {
        id_length++;    /* IDs are one octet longer in IS neighbours */
        if ( tree ) {
            if ( show_virtual ) {
                /* virtual path flag */
                proto_tree_add_item( tree, hf_isis_lsp_is_virtual, tvb, offset, 1, ENC_NA);
            } else {
                proto_tree_add_item(tree, hf_isis_lsp_eis_neighbors_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            }
        }
        offset++;
        length--;
    }
    tlen = 4 + id_length;

    while ( length > 0 ) {
        if (length<tlen) {
            proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                "short E/IS reachability (%d vs %d)", length, tlen );
            return;
        }
        /*
         * Gotta build a sub-tree for all our pieces
         */
        if ( tree ) {
            if ( is_eis ) {
                ntree = proto_tree_add_subtree(tree, tvb, offset, tlen, ett_isis_lsp_clv_is_neighbors, &ti, "ES Neighbor");
            } else {
                ntree = proto_tree_add_subtree(tree, tvb, offset, tlen, ett_isis_lsp_clv_is_neighbors, &ti, "IS Neighbor");
            }

            proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_default_metric, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_default_metric_ie, tvb, offset, 1, ENC_NA);

            proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_delay_metric, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_delay_metric_supported, tvb, offset, 1, ENC_NA);

            proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_delay_metric_ie, tvb, offset+1, 1, ENC_NA);

            proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_expense_metric, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_expense_metric_supported, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_expense_metric_ie, tvb, offset+2, 1, ENC_NA);

            proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_error_metric, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_error_metric_supported, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(ntree, hf_isis_lsp_eis_neighbors_error_metric_ie, tvb, offset+3, 1, ENC_NA);
            proto_tree_add_item(ntree, is_eis ? hf_isis_lsp_eis_neighbors_es_neighbor_id : hf_isis_lsp_eis_neighbors_is_neighbor_id,
                                    tvb, offset+4, id_length, ENC_NA);
            proto_item_append_text(ti, ": %s", tvb_print_system_id(pinfo->pool, tvb, offset+4, id_length));
        }
        offset += tlen;
        length -= tlen;
    }
}

/*
 * Name: dissect_lsp_l1_is_neighbors_clv()
 *
 * Description:
 *    Dispatch a l1 intermediate system neighbor by calling
 *    the inner function with show virtual set to true and is es set to false.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  May be NULL
 *    int : offset into packet data where we are.
 *    int : length of IDs in packet.
 *    int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_l1_is_neighbors_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis, int length)
{
    dissect_lsp_eis_neighbors_clv_inner(tvb, pinfo, tree, offset,
        length, isis->system_id_len, true, false);
}

/*
 * Name: dissect_lsp_l1_es_neighbors_clv()
 *
 * Description:
 *    Dispatch a l1 end or intermediate system neighbor by calling
 *    the inner function with show virtual set to true and es set to true.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  May be NULL
 *    int : offset into packet data where we are.
 *    int : length of IDs in packet.
 *    int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_l1_es_neighbors_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis, int length)
{
    dissect_lsp_eis_neighbors_clv_inner(tvb, pinfo, tree, offset,
        length, isis->system_id_len, true, true);
}

/*
 * Name: dissect_lsp_l2_is_neighbors_clv()
 *
 * Description:
 *    Dispatch a l2 intermediate system neighbor by calling
 *    the inner function with show virtual set to false, and is es set
 *    to false
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  May be NULL
 *    int : offset into packet data where we are.
 *    int : length of IDs in packet.
 *    int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_l2_is_neighbors_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis, int length)
{
    dissect_lsp_eis_neighbors_clv_inner(tvb, pinfo, tree, offset,
        length, isis->system_id_len, false, false);
}

/*
 * Name: dissect_lsp_instance_identifier_clv()
 *
 * Description:
 *    Decode for a lsp packets Instance Identifier clv.
 *      Calls into the CLV common one.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_lsp_instance_identifier_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
    proto_tree *tree, int offset, isis_data_t *isis _U_, int length)
{
    isis_dissect_instance_identifier_clv(tree, pinfo, tvb, &ei_isis_lsp_short_clv, hf_isis_lsp_instance_identifier, hf_isis_lsp_supported_itid, offset, length);
}

/*
 * Name: dissect_subclv_admin_group ()
 *
 * Description: Called by function dissect_lsp_ext_is_reachability_clv().
 *
 *   This function is called by dissect_lsp_ext_is_reachability_clv()
 *   for dissect the administrative group sub-CLV (code 3).
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.
 *   int : offset into packet data where we are (beginning of the sub_clv value).
 *
 * Output:
 *   void
 */
static void
dissect_subclv_admin_group (tvbuff_t *tvb, proto_tree *tree, int offset) {
    proto_tree *ntree;
    uint32_t   clv_value;
    uint32_t   mask;
    int        i;

    ntree = proto_tree_add_subtree(tree, tvb, offset-2, 6,
                ett_isis_lsp_subclv_admin_group, NULL, "Administrative group(s):");

    clv_value = tvb_get_ntohl(tvb, offset);
    mask = 1;
    for (i = 0 ; i < 32 ; i++) {
        if ( (clv_value & mask) != 0 ) {
            proto_tree_add_uint_format(ntree, hf_isis_lsp_group, tvb, offset, 4, clv_value & mask, "group %d", i);
        }
        mask <<= 1;
    }
}

/*
 * Name: dissect_subclv_max_bw ()
 *
 * Description: Called by function dissect_lsp_ext_is_reachability_clv().
 *
 *   This function is called by dissect_lsp_ext_is_reachability_clv()
 *   for dissect the maximum link bandwidth sub-CLV (code 9).
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.
 *   int : offset into packet data where we are (beginning of the sub_clv value).
 *
 * Output:
 *   void
 */
static void
dissect_subclv_max_bw(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    float   bw;

    bw = tvb_get_ntohieee_float(tvb, offset)*8/1000000;
    proto_tree_add_float_format_value(tree, hf_isis_lsp_maximum_link_bandwidth, tvb, offset-2, 6,
        bw, "%.2f Mbps", bw);
}

/*
 * Name: dissect_subclv_rsv_bw ()
 *
 * Description: Called by function dissect_lsp_ext_is_reachability_clv().
 *
 *   This function is called by dissect_lsp_ext_is_reachability_clv()
 *   for dissect the reservable link bandwidth sub-CLV (code 10).
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.
 *   int : offset into packet data where we are (beginning of the sub_clv value).
 *
 * Output:
 *   void
 */
static void
dissect_subclv_rsv_bw(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    float   bw;

    bw = tvb_get_ntohieee_float(tvb, offset)*8/1000000;
    proto_tree_add_float_format_value (tree, hf_isis_lsp_reservable_link_bandwidth, tvb, offset-2, 6,
        bw, "%.2f Mbps", bw );
}

/*
 * Name: dissect_subclv_unrsv_bw ()
 *
 * Description: Called by function dissect_lsp_ext_is_reachability_clv().
 *
 *   This function is called by dissect_lsp_ext_is_reachability_clv()
 *   for dissect the unreserved bandwidth sub-CLV (code 11).
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.
 *   int : offset into packet data where we are (beginning of the sub_clv value).
 *
 * Output:
 *   void
 */
static void
dissect_subclv_unrsv_bw(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    proto_tree *ntree;
    float      bw;
    int        i;

    ntree = proto_tree_add_subtree(tree, tvb, offset-2, 34,
                    ett_isis_lsp_subclv_unrsv_bw, NULL, "Unreserved bandwidth:");

    for (i = 0 ; i < 8 ; i++) {
        bw = tvb_get_ntohieee_float(tvb, offset+4*i)*8/1000000;
        proto_tree_add_float_format(ntree, hf_isis_lsp_unrsv_bw_priority_level, tvb, offset+4*i, 4,
            bw, "priority level %d: %.2f Mbps", i, bw );
    }
}

/*
 * Name: dissect_subclv_bw_ct ()
 *
 * Description: Called by function dissect_lsp_ext_is_reachability_clv().
 *
 *   This function is called by dissect_lsp_ext_is_reachability_clv()
 *   for dissect the Bandwidth Constraints sub-CLV (code 22).
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.
 *   int : offset into packet data where we are (beginning of the sub_clv value).
 *
 * Output:
 *   void
 */
static void
dissect_subclv_bw_ct(tvbuff_t *tvb, proto_tree *tree, int offset, int sublen)
{
    proto_tree *ntree;
    int offset_end = offset + sublen;
    float   bw;

    ntree = proto_tree_add_subtree(tree, tvb, offset-2, sublen,
                    ett_isis_lsp_subclv_bw_ct, NULL, "Bandwidth Constraints:");

    proto_tree_add_item(ntree, hf_isis_lsp_bw_ct_model, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset +=1;

    proto_tree_add_item(ntree, hf_isis_lsp_bw_ct_reserved, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset +=3;

    if(offset < offset_end){
        bw = tvb_get_ntohieee_float(tvb, offset)*8/1000000;
        proto_tree_add_float_format_value(ntree, hf_isis_lsp_bw_ct0, tvb, offset, 4,
            bw, "%.2f Mbps", bw);
        offset += 4;
    }

    if(offset < offset_end){
        bw = tvb_get_ntohieee_float(tvb, offset)*8/1000000;
        proto_tree_add_float_format_value(ntree, hf_isis_lsp_bw_ct1, tvb, offset, 4,
            bw, "%.2f Mbps", bw);
        offset += 4;
    }

    if(offset < offset_end){
        bw = tvb_get_ntohieee_float(tvb, offset)*8/1000000;
        proto_tree_add_float_format_value(ntree, hf_isis_lsp_bw_ct2, tvb, offset, 4,
            bw, "%.2f Mbps", bw);
        offset += 4;
    }

    if(offset < offset_end){
        bw = tvb_get_ntohieee_float(tvb, offset)*8/1000000;
        proto_tree_add_float_format_value(ntree, hf_isis_lsp_bw_ct3, tvb, offset, 4,
            bw, "%.2f Mbps", bw);
        offset += 4;
    }

    if(offset < offset_end){
        bw = tvb_get_ntohieee_float(tvb, offset)*8/1000000;
        proto_tree_add_float_format_value(ntree, hf_isis_lsp_bw_ct4, tvb, offset, 4,
            bw, "%.2f Mbps", bw);
        offset += 4;
    }

    if(offset < offset_end){
        bw = tvb_get_ntohieee_float(tvb, offset)*8/1000000;
        proto_tree_add_float_format_value(ntree, hf_isis_lsp_bw_ct5, tvb, offset, 4,
            bw, "%.2f Mbps", bw);
        offset += 4;
    }

    if(offset < offset_end){
        bw = tvb_get_ntohieee_float(tvb, offset)*8/1000000;
        proto_tree_add_float_format_value(ntree, hf_isis_lsp_bw_ct6, tvb, offset, 4,
            bw, "%.2f Mbps", bw);
        offset += 4;
    }

    if(offset < offset_end){
        bw = tvb_get_ntohieee_float(tvb, offset)*8/1000000;
        proto_tree_add_float_format_value(ntree, hf_isis_lsp_bw_ct7, tvb, offset, 4,
            bw, "%.2f Mbps", bw);
        /*offset += 4;*/
    }
}

/*
 * Name: dissect_subclv_spb_link_metric ()
 *
 * Description: Called by function dissect_lsp_ext_is_reachability_clv().
 *
 *   This function is called by dissect_lsp_ext_is_reachability_clv()
 *   for dissect the SPB link metric sub-CLV (code 29).
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.
 *   int : offset into packet data where we are (beginning of the sub_clv value).
 *   int : subtlv type
 *   int : subtlv length
 *
 * Output:
 *   void
 */

static void
dissect_subclv_spb_link_metric(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, int offset, int subtype, int sublen)
{
    const int SUBLEN     = 6;

    if (sublen != SUBLEN) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                              "Short SPB Link Metric sub-TLV (%d vs %d)", sublen, SUBLEN);
        return;
    }
    else {
        proto_tree *subtree;
        subtree = proto_tree_add_subtree_format( tree, tvb, offset-2, sublen+2, ett_isis_lsp_subclv_spb_link_metric, NULL,
                                  "SPB Link Metric: Type: 0x%02x (%d), Length: %d", subtype, subtype, sublen);

        proto_tree_add_item(subtree, hf_isis_lsp_spb_link_metric,
                            tvb, offset, 3, ENC_BIG_ENDIAN);

        proto_tree_add_item(subtree, hf_isis_lsp_spb_port_count,
                            tvb, offset+3, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(subtree, hf_isis_lsp_spb_port_id,
                            tvb, offset+4, 2, ENC_BIG_ENDIAN);
    }
}

/*
 * Name : dissect_subclv_ext_admin_group()
 *
 * Description : called by function dissect_sub_clv_tlv_22_22_23_141_222_223()
 *
 *   Dissects Extended Administrative Groups subclv
 *
 * Input :
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.
 *   int : offset into packet data where we are (beginning of the sub_clv value).
 *   int : subtlv type
 *   int : subtlv length
 *
 * Output:
 *   void
 */
static void
dissect_subclv_ext_admin_group(tvbuff_t *tvb, proto_tree *tree,
                               int offset, int subtype _U_, int sublen)
{
    int i;
    uint32_t admin_group;

    /* Number of Extended Admin Groups */
    for (i = 0; i < (sublen / 4); i++) {
        admin_group = tvb_get_uint32(tvb, offset + (i * 4), ENC_BIG_ENDIAN);
        proto_tree_add_uint_format(tree, hf_isis_lsp_clv_ext_admin_group,
                                   tvb, offset + (i * 4), 4, admin_group,
                                   "Extended Admin Group[%d]: 0x%08x",
                                   i, admin_group);
    }
}

/*
 * Name : dissect_subclv_adj_sid()
 *
 * Description : called by function dissect_sub_clv_tlv_22_22_23_141_222_223()
 *
 *   Dissects LAN-Adj-SID & Adj-SID subclv
 *
 * Input :
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.
 *   int : offset into packet data where we are (beginning of the sub_clv value).
 *   int : subtlv type
 *   int : subtlv length
 *
 * Output:
 *   void
 */

static void
dissect_subclv_adj_sid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        int local_offset, int subtype, int sublen)
{
    int offset = local_offset;
    proto_item *ti;
    int sli_len;
    uint8_t flags;

    flags = tvb_get_uint8(tvb, offset);
    proto_tree_add_bitmask(tree, tvb, offset, hf_isis_lsp_adj_sid_flags,
                               ett_isis_lsp_adj_sid_flags, adj_sid_flags, ENC_BIG_ENDIAN);

    offset++;

    proto_tree_add_item(tree, hf_isis_lsp_adj_sid_weight, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Only present in LAN-Adj-SID, not Adj-SID */
    if (subtype == 32) {
        proto_tree_add_item(tree, hf_isis_lsp_adj_sid_system_id, tvb, offset, 6, ENC_NA);
        offset += 6;
    }

    sli_len = local_offset + sublen - offset;
    switch(sli_len) {
        case 3:
            if (!((flags & 0x30) == 0x30))
                proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb,
                                local_offset, sublen, "V & L flags must be set");
            proto_tree_add_item(tree, hf_isis_lsp_sid_sli_label, tvb, offset, sli_len, ENC_BIG_ENDIAN);
            break;
        case 4:
            if (flags & 0x30)
                proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb,
                                local_offset, sublen, "V & L flags must be unset");
            proto_tree_add_item(tree, hf_isis_lsp_sid_sli_index, tvb, offset, sli_len, ENC_BIG_ENDIAN);
            break;
        case 16:
            if (!(flags & 0x20))
                proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb,
                                local_offset, sublen, "V flag must be set");
            ti = proto_tree_add_item(tree, hf_isis_lsp_sid_sli_ipv6, tvb, offset, sli_len, ENC_NA);
            /* L flag set */
            if (flags & 0x10)
                proto_item_append_text(ti, "Globally unique");
            break;
        default:
            break;
    }
    /*offset += sli_len;*/
}

/*
 * Name: dissect_srv6_sid_struct_subsubclv()
 *
 * Description:
 *    Decodes a SRv6 SID Structure sub-sub-TLV (RFC 9352)
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   packet_info * : expert error misuse reporting
 *   proto_tree * : proto tree to build on
 *   tree_item * : proto tree item to build on (may be null)
 *   int : current offset into packet data
 *   int : type of this clv
 *   int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_srv6_sid_struct_subsubclv(tvbuff_t *tvb, packet_info* pinfo,
                                  proto_tree *tree, proto_item *tree_item _U_,
                                  int offset, int clv_code _U_, int clv_len)
{
    if (clv_len != 4) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv,
                                     tvb, offset-2, 2,
                                     "Invalid Sub-Sub-TLV Length %d (should be 4)", clv_len);
        return;
    }
    proto_tree_add_item(tree, hf_isis_lsp_clv_srv6_sid_struct_lb_len, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_isis_lsp_clv_srv6_sid_struct_ln_len, tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(tree, hf_isis_lsp_clv_srv6_sid_struct_fun_len, tvb, offset+2, 1, ENC_NA);
    proto_tree_add_item(tree, hf_isis_lsp_clv_srv6_sid_struct_arg_len, tvb, offset+3, 1, ENC_NA);
}

/*
 * Name: dissect_sub_clv_tlv_22_22_23_141_222_223
 *
 * Description: Decode a sub tlv's for all those tlv
 *
 *   CALLED BY TLV 22,23,141,222,223 DISSECTOR
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   packet_info * : expert error misuse reporting
 *   proto_tree * : protocol display tree to fill out.  May be NULL
 *   int : offset into packet data where we are.
 *   int : sub-tlv length
 *   int : length of clv we are decoding
 *
 * Output:
 *   void
 */

static void
// NOLINTNEXTLINE(misc-no-recursion)
dissect_sub_clv_tlv_22_22_23_141_222_223(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree,
    int offset, int subclvs_len)
{
    proto_item *ti_subclvs = NULL;
    proto_tree *subtree = NULL;
    int sub_tlv_offset = 0;
    int i = 0;
    unsigned  clv_code, clv_len;
    int local_offset, local_len;
    proto_item *ti;
    float percentage;
    uint8_t sabm_length = 0, udabm_length = 0;
    int subsubclvs_len;
    int ssclv_code, ssclv_len;
    proto_tree *subsubtree = NULL;
    proto_item *ti_subsubtree = NULL;

    increment_dissection_depth(pinfo);

    while (i < subclvs_len) {
        /* offset for each sub-TLV */
        sub_tlv_offset = offset + i;

        subtree = proto_tree_add_subtree(tree, tvb, sub_tlv_offset, 0,
                                         ett_isis_lsp_part_of_clv_ext_is_reachability_subtlv,
                                         &ti_subclvs, "subTLV");
        proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_code,
                            tvb, sub_tlv_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_len, tvb, sub_tlv_offset+1, 1, ENC_BIG_ENDIAN);
        clv_code = tvb_get_uint8(tvb, sub_tlv_offset);
        clv_len  = tvb_get_uint8(tvb, sub_tlv_offset+1);
        proto_item_append_text(ti_subclvs, ": %s (c=%u, l=%u)",
                               val_to_str_const(clv_code, isis_lsp_ext_is_reachability_code_vals, "Unknown"),
                               clv_code, clv_len);
        proto_item_set_len(ti_subclvs, clv_len+2);

        sub_tlv_offset += 2;

        switch (clv_code) {
            case 3 :
                dissect_subclv_admin_group(tvb, subtree, sub_tlv_offset);
            break;
            case 4 :
                proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_link_local_identifier,
                                    tvb, sub_tlv_offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_link_remote_identifier,
                                    tvb, sub_tlv_offset + 4, 4, ENC_BIG_ENDIAN);
            break;
            case 6 :
                proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_ipv4_interface_address, tvb, sub_tlv_offset, 4, ENC_BIG_ENDIAN);
            break;
            case 8 :
                proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_ipv4_neighbor_address, tvb, sub_tlv_offset, 4, ENC_BIG_ENDIAN);
            break;
            case 9 :
                dissect_subclv_max_bw(tvb, subtree, sub_tlv_offset);
            break;
            case 10:
                dissect_subclv_rsv_bw(tvb, subtree, sub_tlv_offset);
            break;
            case 11:
                dissect_subclv_unrsv_bw(tvb, subtree, sub_tlv_offset);
            break;
            case 12:
                proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_ipv6_interface_address, tvb, sub_tlv_offset, 16, ENC_NA);
            break;
            case 13:
                proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_ipv6_neighbor_address, tvb, sub_tlv_offset, 16, ENC_NA);
            break;
            case 14:
                /* Extended Administrative Groups (rfc7308) */
                dissect_subclv_ext_admin_group(tvb, subtree, sub_tlv_offset, clv_code, clv_len);
                break;
            case 15:
                /* Link MSD */
                local_offset = sub_tlv_offset;
                local_len = clv_len;
                while (local_len >= 2) {
                    proto_tree_add_item(subtree, hf_isis_lsp_clv_igp_msd_type, tvb, local_offset, 1, ENC_NA);
                    proto_tree_add_item(subtree, hf_isis_lsp_clv_igp_msd_value, tvb, local_offset+1, 1, ENC_NA);
                    local_len -= 2;
                    local_offset += 2;
                }
            break;
            case 16:
                /* Application-Specific Link Attributes (rfc8919) */
                local_offset = sub_tlv_offset;
                local_len = clv_len;
                proto_tree_add_item(subtree, hf_isis_lsp_clv_app_sabm_legacy, tvb, local_offset, 1, ENC_NA);
                sabm_length = tvb_get_uint8(tvb, local_offset) & 0x7f;
                proto_tree_add_uint(subtree, hf_isis_lsp_clv_app_sabm_length, tvb, local_offset, 1, sabm_length);
                proto_tree_add_item(subtree, hf_isis_lsp_clv_app_udabm_reserved, tvb, local_offset + 1, 1, ENC_NA);
                udabm_length = tvb_get_uint8(tvb, local_offset + 1) & 0x7f;
                proto_tree_add_uint(subtree, hf_isis_lsp_clv_app_udabm_length, tvb, local_offset + 1, 1, udabm_length);
                local_offset += 2;
                local_len -= 2;
                if (sabm_length > 0) {
                    proto_tree_add_bitmask(subtree, tvb, local_offset,
                                           hf_isis_lsp_clv_app_sabm_bits,
                                           ett_isis_lsp_clv_app_sabm_bits,
                                           isis_lsp_app_sabm_bits, ENC_NA);
                    local_offset += sabm_length;
                    local_len -= sabm_length;
                }
                if (udabm_length > 0) {
                    proto_tree_add_item(subtree, hf_isis_lsp_clv_app_udabm_bits,
                                        tvb, local_offset, udabm_length, ENC_NA);
                    local_offset += udabm_length;
                    local_len -= udabm_length;
                }
                if (local_len > 2) {
                    /* Dissect Link Attribute sub-sub-TLVs */
                    dissect_sub_clv_tlv_22_22_23_141_222_223(tvb, pinfo, subtree, local_offset, local_len);
                }
                break;
            case 18:
                proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_traffic_engineering_default_metric,
                                    tvb, sub_tlv_offset, 3, ENC_BIG_ENDIAN);
            break;
            case 22:
                dissect_subclv_bw_ct(tvb, subtree, sub_tlv_offset, clv_len);
            break;
            case 29:
                dissect_subclv_spb_link_metric(tvb, pinfo, subtree,
                                               sub_tlv_offset, clv_code, clv_len);
            break;
            case 31:
            case 32:
                dissect_subclv_adj_sid(tvb, pinfo, subtree, sub_tlv_offset, clv_code, clv_len);
            break;
            case 33:
                /* Unidirectional Link Delay (rfc8570) */
                proto_tree_add_bitmask(subtree, tvb, sub_tlv_offset,
                                       hf_isis_lsp_ext_is_reachability_unidir_link_flags,
                                       ett_isis_lsp_clv_unidir_link_flags,
                                       unidir_link_flags, ENC_NA);
                proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_unidir_link_delay, tvb, sub_tlv_offset+1, 3, ENC_BIG_ENDIAN);
            break;
            case 34:
                /* Min/Max Unidirectional Link Delay (rfc8570) */
                proto_tree_add_bitmask(subtree, tvb, sub_tlv_offset,
                                       hf_isis_lsp_ext_is_reachability_unidir_link_flags,
                                       ett_isis_lsp_clv_unidir_link_flags,
                                       unidir_link_flags, ENC_NA);
                proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_unidir_link_delay_min, tvb, sub_tlv_offset+1, 3, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_unidir_link_reserved, tvb, sub_tlv_offset+4, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_unidir_link_delay_max, tvb, sub_tlv_offset+5, 3, ENC_BIG_ENDIAN);
            break;
            case 35:
                /* Unidirectional Delay Variation (rfc8570) */
                proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_unidir_link_reserved, tvb, sub_tlv_offset, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_unidir_delay_variation, tvb, sub_tlv_offset+1, 3, ENC_BIG_ENDIAN);
            break;
            case 36:
                /* Unidirectional Link Loss (rfc8570) */
                proto_tree_add_bitmask(subtree, tvb, sub_tlv_offset,
                                       hf_isis_lsp_ext_is_reachability_unidir_link_flags,
                                       ett_isis_lsp_clv_unidir_link_flags,
                                       unidir_link_flags, ENC_NA);
                ti = proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_unidir_link_loss, tvb, sub_tlv_offset+1, 3, ENC_BIG_ENDIAN);
                if (ti) {
                    percentage = (float)tvb_get_uint24(tvb, sub_tlv_offset+1, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti, " (%f %%)", percentage * 0.000003);
                }
            break;
            case 37:
                /* 37: Unidirectional Residual Bandwidth (rfc8570) */
                proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_unidir_residual_bandwidth, tvb, sub_tlv_offset, 4, ENC_BIG_ENDIAN);
                break;
            case 38:
                /* 38: Unidirectional Available Bandwidth (rfc8570) */
                proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_unidir_available_bandwidth, tvb, sub_tlv_offset, 4, ENC_BIG_ENDIAN);
                break;
            case 39:
                /* 39: Unidirectional Utilized Bandwidth (rfc8570) */
                proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_unidir_utilized_bandwidth, tvb, sub_tlv_offset, 4, ENC_BIG_ENDIAN);
            break;
            case 43:
                /* SRv6 End.X SID */
                proto_tree_add_bitmask(subtree, tvb, sub_tlv_offset,
                                       hf_isis_lsp_clv_srv6_endx_sid_flags,
                                       ett_isis_lsp_clv_srv6_endx_sid_flags,
                                       srv6_endx_sid_flags, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_isis_lsp_clv_srv6_endx_sid_alg, tvb, sub_tlv_offset+1, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_isis_lsp_clv_srv6_endx_sid_weight, tvb, sub_tlv_offset+2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_isis_lsp_clv_srv6_endx_sid_endpoint_behavior, tvb, sub_tlv_offset+3, 2, ENC_NA);
                proto_tree_add_item(subtree, hf_isis_lsp_clv_srv6_endx_sid_sid, tvb, sub_tlv_offset+5, 16, ENC_NA);
                proto_tree_add_item(subtree, hf_isis_lsp_clv_srv6_endx_sid_subsubclvs_len, tvb, sub_tlv_offset+21, 1, ENC_NA);
                subsubclvs_len = tvb_get_uint8(tvb, sub_tlv_offset+21);
                local_offset = sub_tlv_offset + 22;
                while (subsubclvs_len >= 2) {
                    ssclv_code = tvb_get_uint8(tvb, local_offset);
                    ssclv_len  = tvb_get_uint8(tvb, local_offset+1);
                    subsubtree = proto_tree_add_subtree_format(subtree, tvb, local_offset, ssclv_len+2,
                                                               ett_isis_lsp_clv_srv6_endx_sid_sub_sub_tlv,
                                                               &ti_subsubtree, "subsubTLV: %s (c=%u, l=%u)",
                                                               val_to_str_const(ssclv_code, isis_lsp_srv6_loc_end_sid_sub_sub_tlv_vals, "Unknown"),
                                                               ssclv_code, ssclv_len);
                    subsubclvs_len -= 2;
                    local_offset += 2;
                    if (ssclv_len > subsubclvs_len) {
                        proto_tree_add_expert_format(subtree, pinfo,
                                                     &ei_isis_lsp_short_clv,
                                                     tvb, local_offset-2, 2,
                                                     "Too short Sub-Sub-TLV length %u (%d bytes left)",
                                                     ssclv_len, subsubclvs_len);
                        break;
                    }
                    switch (ssclv_code) {
                    case 1:
                        /* SRv6 SID Structure (rfc9352) */
                        dissect_srv6_sid_struct_subsubclv(tvb, pinfo, subsubtree, ti_subsubtree,
                                                          local_offset, ssclv_code, ssclv_len);
                        break;
                    default:
                        proto_tree_add_expert_format(subsubtree, pinfo, &ei_isis_lsp_subtlv, tvb,
                                                     local_offset, ssclv_len,
                                                     "Unknown Sub-Sub-TLV: Type: %u, Length: %u",
                                                     ssclv_code, ssclv_len);
                        break;
                    }
                    subsubclvs_len -= ssclv_len;
                    local_offset += ssclv_len;
                }
                break;
            case 44:
                /* SRv6 LAN End.X SID */
                proto_tree_add_item(subtree, hf_isis_lsp_clv_srv6_endx_sid_system_id, tvb, sub_tlv_offset, 6, ENC_NA);
                proto_tree_add_bitmask(subtree, tvb, sub_tlv_offset+6,
                                       hf_isis_lsp_clv_srv6_endx_sid_flags,
                                       ett_isis_lsp_clv_srv6_endx_sid_flags,
                                       srv6_endx_sid_flags, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_isis_lsp_clv_srv6_endx_sid_alg, tvb, sub_tlv_offset+7, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_isis_lsp_clv_srv6_endx_sid_weight, tvb, sub_tlv_offset+8, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_isis_lsp_clv_srv6_endx_sid_endpoint_behavior, tvb, sub_tlv_offset+9, 2, ENC_NA);
                proto_tree_add_item(subtree, hf_isis_lsp_clv_srv6_endx_sid_sid, tvb, sub_tlv_offset+11, 16, ENC_NA);
                proto_tree_add_item(subtree, hf_isis_lsp_clv_srv6_endx_sid_subsubclvs_len, tvb, sub_tlv_offset+27, 1, ENC_NA);
                subsubclvs_len = tvb_get_uint8(tvb, sub_tlv_offset+27);
                local_offset = sub_tlv_offset+28;
                while (subsubclvs_len >= 2) {
                    ssclv_code = tvb_get_uint8(tvb, local_offset);
                    ssclv_len  = tvb_get_uint8(tvb, local_offset+1);
                    subsubtree = proto_tree_add_subtree_format(subtree, tvb, local_offset, ssclv_len+2,
                                                               ett_isis_lsp_clv_srv6_endx_sid_sub_sub_tlv,
                                                               &ti_subsubtree, "subsubTLV: %s (c=%u, l=%u)",
                                                               val_to_str_const(ssclv_code, isis_lsp_srv6_loc_end_sid_sub_sub_tlv_vals, "Unknown"),
                                                               ssclv_code, ssclv_len);
                    subsubclvs_len -= 2;
                    local_offset += 2;
                    if (ssclv_len > subsubclvs_len) {
                        proto_tree_add_expert_format(subtree, pinfo,
                                                     &ei_isis_lsp_short_clv,
                                                     tvb, local_offset-2, 2,
                                                     "Too short Sub-Sub-TLV length %u (%d bytes left)",
                                                     ssclv_len, subsubclvs_len);
                        break;
                    }
                    switch (ssclv_code) {
                    case 1:
                        /* SRv6 SID Structure (rfc9352) */
                        dissect_srv6_sid_struct_subsubclv(tvb, pinfo, subsubtree, ti_subsubtree,
                                                          local_offset, ssclv_code, ssclv_len);
                        break;
                    default:
                        proto_tree_add_expert_format(subsubtree, pinfo, &ei_isis_lsp_subtlv, tvb,
                                                     local_offset, ssclv_len,
                                                     "Unknown Sub-Sub-TLV: Type: %u, Length: %u",
                                                     ssclv_code, ssclv_len);
                        break;
                    }
                    subsubclvs_len -= ssclv_len;
                    local_offset += ssclv_len;
                }
                break;
            default:
                proto_tree_add_item(subtree, hf_isis_lsp_ext_is_reachability_value, tvb, sub_tlv_offset, clv_len, ENC_NA);
            break;
        }
        i += clv_len + 2;
    }
    decrement_dissection_depth(pinfo);
}


/*
 * Name: dissect_lsp_ext_is_reachability_clv()
 *
 * Description: Decode a Extended IS Reachability CLV - code 22
 * RFC 3784
 *
 *   The extended IS reachability TLV is an extended version
 *   of the IS reachability TLV (code 2). It encodes the metric
 *   as a 24-bit unsigned integer and allows to add sub-CLV(s).
 *
 *   CALLED BY TLV 222 DISSECTOR
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.  May be NULL
 *   int : offset into packet data where we are.
 *   int : length of IDs in packet.
 *   int : length of clv we are decoding
 *
 * Output:
 *   void, but we will add to proto tree if !NULL.
 */

static void
dissect_lsp_ext_is_reachability_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree,
    int offset, isis_data_t *isis _U_, int length)
{
    proto_item *ti, *ti_subclvs_len;
    proto_tree *ntree = NULL;
    unsigned   subclvs_len;
    unsigned   len;

    while (length > 0) {
        ntree = proto_tree_add_subtree(tree, tvb, offset, -1,
                ett_isis_lsp_part_of_clv_ext_is_reachability, &ti, "IS Neighbor");

        proto_tree_add_item(ntree, hf_isis_lsp_ext_is_reachability_is_neighbor_id, tvb, offset, 7, ENC_NA);
        proto_item_append_text(ti, ": %s", tvb_print_system_id(pinfo->pool, tvb, offset, 7));

        proto_tree_add_item(ntree, hf_isis_lsp_ext_is_reachability_metric, tvb, offset+7, 3, ENC_BIG_ENDIAN);

        ti_subclvs_len = proto_tree_add_item(ntree, hf_isis_lsp_ext_is_reachability_subclvs_len, tvb, offset+10, 1, ENC_BIG_ENDIAN);

        subclvs_len = tvb_get_uint8(tvb, offset+10);
        if (subclvs_len == 0) {
            proto_item_append_text(ti_subclvs_len, " (no sub-TLVs present)");
        }
        else {
            dissect_sub_clv_tlv_22_22_23_141_222_223(tvb, pinfo, ntree,
                                                    offset + 11, subclvs_len);
        }

        len = 11 + subclvs_len;
        proto_item_set_len (ti, len);
        offset += len;
        length -= len;
    }
}

/*
 * Name: dissect_lsp_mt_reachable_IPv4_prefx_clv()
 *
 * Description: Decode Multi-Topology IPv4 Prefixes - code 235
 *
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.  May be NULL
 *   int : offset into packet data where we are.
 *   int : length of IDs in packet.
 *   int : length of clv we are decoding
 *
 * Output:
 *   void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_mt_reachable_IPv4_prefx_clv(tvbuff_t *tvb, packet_info* pinfo,
        proto_tree *tree, int offset, isis_data_t *isis _U_, int length)
{
    if (length < 2) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                "short lsp multi-topology reachable IPv4 prefixes(%d vs %d)", length, 2 );
        return;
    }
    dissect_lsp_mt_id(tvb, tree, offset);
    dissect_lsp_ext_ip_reachability_clv(tvb, pinfo, tree, offset+2, 0, length-2);
}

/*
 * Name: dissect_lsp_mt_reachable_IPv6_prefx_clv()
 *
 * Description: Decode Multi-Topology IPv6 Prefixes - code 237
 *
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.  May be NULL
 *   int : offset into packet data where we are.
 *   int : length of IDs in packet.
 *   int : length of clv we are decoding
 *
 * Output:
 *   void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_mt_reachable_IPv6_prefx_clv(tvbuff_t *tvb, packet_info* pinfo,
        proto_tree *tree, int offset, isis_data_t *isis _U_, int length)
{
    if (length < 2) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                "short lsp multi-topology reachable IPv6 prefixes(%d vs %d)", length, 2 );
        return;
    }
    dissect_lsp_mt_id(tvb, tree, offset);
    dissect_lsp_ipv6_reachability_clv(tvb, pinfo, tree, offset+2, 0, length-2);
}


/*
 * Name: dissect_lsp_mt_is_reachability_clv()
 *
 * Description: Decode Multi-Topology Intermediate Systems - code 222
 *
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : protocol display tree to fill out.  May be NULL
 *   int : offset into packet data where we are.
 *   int : unused
 *   int : length of clv we are decoding
 *
 * Output:
 *   void, but we will add to proto tree if !NULL.
 */

static void
dissect_lsp_mt_is_reachability_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    if (length < 2) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                "short lsp reachability(%d vs %d)", length, 2 );
        return;
    }

    /*
     * the MT ID value dissection is used in other LSPs so we push it
     * in a function
     */
    dissect_lsp_mt_id(tvb, tree, offset);
    /*
     * fix here. No need to parse TLV 22 (with bugs) while it is
     * already done correctly!!
     */
    dissect_lsp_ext_is_reachability_clv(tvb, pinfo, tree, offset+2, 0, length-2);
}


/*
 * Name: dissect_lsp_ori_buffersize_clv()
 *
 * Description:
 *    This CLV is used give neighbor buffer size
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  May be NULL
 *    int : offset into packet data where we are.
 *    int : length of IDs in packet.
 *    int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_ori_buffersize_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis, int length)
{
    if ( length != 2 ) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                "short lsp partition DIS(%d vs %d)", length, isis->system_id_len );
        return;
    }
    /*
     * Gotta build a sub-tree for all our pieces
     */
    proto_tree_add_item(tree, hf_isis_lsp_originating_lsp_buffer_size, tvb, offset, length, ENC_BIG_ENDIAN);
}


/*
 * Name: dissect_lsp_partition_dis_clv()
 *
 * Description:
 *    This CLV is used to indicate which system is the designated
 *    IS for partition repair.  This means just putting out the
 *    "isis->system_id_len"-octet IS.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  May be NULL
 *    int : offset into packet data where we are.
 *    int : length of IDs in packet.
 *    int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_partition_dis_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis, int length)
{
    if ( length < isis->system_id_len ) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                "short lsp partition DIS(%d vs %d)", length, isis->system_id_len );
        return;
    }
    /*
     * Gotta build a sub-tree for all our pieces
     */
    proto_tree_add_item( tree, hf_isis_lsp_partition_designated_l2_is, tvb, offset, isis->system_id_len, ENC_NA);

    length -= isis->system_id_len;
    offset += isis->system_id_len;
    if ( length > 0 ) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_long_clv, tvb, offset, -1,
                "Long lsp partition DIS, %d left over", length );
        return;
    }
}

/*
 * Name: dissect_lsp_prefix_neighbors_clv()
 *
 * Description:
 *    The prefix CLV describes what other (OSI) networks we can reach
 *    and what their cost is.  It is built from a metric block
 *    (see dissect_metric) followed by n addresses.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to fill out.  May be NULL
 *    int : offset into packet data where we are.
 *    int : length of IDs in packet.
 *    int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_prefix_neighbors_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    char *sbuf;
    int mylen;

    if ( length < 4 ) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
            "Short lsp prefix neighbors (%d vs 4)", length );
        return;
    }
    if ( tree ) {
        dissect_metric (tvb, pinfo, tree, offset,
            hf_isis_lsp_default, hf_isis_lsp_default_support, true );
        dissect_metric (tvb, pinfo, tree, offset+1,
            hf_isis_lsp_delay, hf_isis_lsp_delay_support, false );
        dissect_metric (tvb, pinfo, tree, offset+2,
            hf_isis_lsp_expense, hf_isis_lsp_expense_support, false );
        dissect_metric (tvb, pinfo, tree, offset+3,
            hf_isis_lsp_error, hf_isis_lsp_error_support, false );
    }
    offset += 4;
    length -= 4;
    while ( length > 0 ) {
        /*
         * This is a length in "semi-octets", i.e., in nibbles.
         */
        mylen = tvb_get_uint8(tvb, offset);
        length--;
        if (length<=0) {
            proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, -1,
                "Zero payload space after length in prefix neighbor" );
            return;
        }
        if ( mylen > length*2) {
            proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_long_clv, tvb, offset, -1,
                "Integral length of prefix neighbor too long (%d vs %d)", mylen, length*2 );
            return;
        }

        /*
         * Lets turn the area address into "standard" 0000.0000.etc
         * format string.
         */
        sbuf =  print_address_prefix( pinfo->pool, tvb, offset+1, mylen );
        /* and spit it out */
        proto_tree_add_string( tree, hf_isis_lsp_area_address_str, tvb, offset, (mylen+1)/2 + 1, sbuf);

        offset += mylen + 1;
        length -= mylen;    /* length already adjusted for len fld*/
    }
}

/*
 * Name: dissect_lsp_ipv6_te_router_id()
 *
 * Description: Decode an IPv6 TE Router ID CLV - code 140.
 *
 *   Calls into the clv common one.
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   proto_tree * : proto tree to build on (may be null)
 *   int : current offset into packet data
 *   int : length of IDs in packet.
 *   int : length of this clv
 *
 * Output:
 *   void, will modify proto_tree if not null.
 */
static void
dissect_lsp_ipv6_te_router_id_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    isis_dissect_ipv6_int_clv(tree, pinfo, tvb, &ei_isis_lsp_short_clv, offset, length,
        hf_isis_lsp_clv_ipv6_te_router_id );
}

/*
 * Name: dissect_lsp_srv6_locator_subclv ()
 *
 * Description: parses IP reach subTLVs
 *              Called by various IP Reachability dissectors.
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   packet_info * : expert error misuse reporting
 *   proto_tree * : protocol display tree to fill out.
 *   int : offset into packet data where we are (beginning of the sub_clv value).
 *
 * Output:
 *   void
 */
static void
dissect_lsp_srv6_locator_subclv(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *subtree, proto_item *subtree_item,
                                int offset, int length, int clv_code, int clv_len)
{
    int subsubclvs_len;
    int ssclv_code, ssclv_len;
    proto_tree *subsubtree;
    proto_item *ti_subsubtree = NULL;

    switch (clv_code) {
    case 4:
        /* Prefix Attribute Flags */
        dissect_prefix_attr_flags_subclv(tvb, pinfo, subtree, subtree_item, offset, clv_code, clv_len);
        break;
    case 5:
        /* SRv6 End SID */
        if (clv_len < 20) {
            proto_tree_add_expert_format(subtree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb, offset-2, clv_len+2,
                                         "Invalid SubSub-TLV Length (%d vs min 20)", clv_len);
            break;
        }
        proto_tree_add_item(subtree, hf_isis_lsp_clv_srv6_end_sid_flags, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_isis_lsp_clv_srv6_end_sid_endpoint_behavior, tvb, offset+1, 2, ENC_NA);
        proto_tree_add_item(subtree, hf_isis_lsp_clv_srv6_end_sid_sid, tvb, offset+3, 16, ENC_NA);
        proto_tree_add_item(subtree, hf_isis_lsp_clv_srv6_end_sid_subsubclvs_len, tvb, offset+19, 1, ENC_NA);
        subsubclvs_len = tvb_get_uint8(tvb, offset + 19);
        offset += 20;
        length -= 20;
        if (subsubclvs_len > length) {
            proto_tree_add_expert_format(subtree, pinfo, &ei_isis_lsp_short_clv, tvb, offset-1, 1,
                                         "Too short SRv6 End SID Sub-Sub-TLV length %u (%d bytes left)",
                                         subsubclvs_len, length);
            break;
        }
        while (subsubclvs_len >= 2) {
            ssclv_code = tvb_get_uint8(tvb, offset);
            ssclv_len  = tvb_get_uint8(tvb, offset + 1);
            subsubtree = proto_tree_add_subtree_format(subtree, tvb, offset, ssclv_len+2,
                                                       ett_isis_lsp_clv_srv6_loc_end_sid_sub_sub_tlv,
                                                       &ti_subsubtree,
                                                       "subsubTLV: %s (c=%u, l=%u)",
                                                       val_to_str_const(ssclv_code, isis_lsp_srv6_loc_end_sid_sub_sub_tlv_vals, "Unknown"),
                                                       ssclv_code, ssclv_len);
            offset += 2;
            subsubclvs_len -= 2;
            if (ssclv_len > subsubclvs_len) {
                proto_tree_add_expert_format(subtree, pinfo, &ei_isis_lsp_short_clv, tvb, offset-2, 2,
                                             "Invalid Sub-Sub-TLV length (%u vs %d bytes left)",
                                             ssclv_len, subsubclvs_len);
                break;
            }
            switch (ssclv_code) {
            case 1:
                /* SRv6 SID Structure (rfc9352) */
                dissect_srv6_sid_struct_subsubclv(tvb, pinfo, subsubtree, ti_subsubtree,
                                                  offset, ssclv_code, ssclv_len);
                break;
            default:
                proto_tree_add_expert_format(subsubtree, pinfo, &ei_isis_lsp_subtlv, tvb,
                                             offset, ssclv_len,
                                             "Unknown Sub-Sub-TLV: Type: %u, Length: %u",
                                             ssclv_code, ssclv_len);
                break;
            }
            offset += ssclv_len;
            subsubclvs_len -= ssclv_len;
        }
        break;
    default:
        proto_tree_add_expert_format(subtree, pinfo, &ei_isis_lsp_subtlv, tvb,
                                     offset, clv_len,
                                     "Unknown Sub-TLV: Type: %u, Length: %u", clv_code, clv_len);
        break;
    }
}

/*
 * Name: dissect_lsp_srv6_locator_entry()
 *
 * Description: Decode each SRv6 locator entry in SRv6 Locator TLV
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   packet_info * : expert error misuse reporting
 *   proto_tree * : proto tree to build on (may be null)
 *   int : current offset into packet data
 *   isis_data_t : data given to subdissectors
 *   int : length of clv we are decoding
 *
 * Output:
 *   int : Length of each SRv6 locator entry (-1 when it cannot dissect)
 */
static int
dissect_lsp_srv6_locator_entry(tvbuff_t *tvb, packet_info* pinfo,
                               proto_tree *tree, int offset,
                               isis_data_t *isis _U_, int length)
{
    int locator_length;
    proto_tree *loctree = NULL;
    proto_item *ti_loctree = NULL;
    uint32_t bit_length;
    int byte_length;
    ws_in6_addr prefix;
    address prefix_addr;
    char *prefix_str;
    uint8_t algorithm;
    int subtlv_length;
    int clv_code, clv_len;
    proto_item *ti_subtree = NULL;
    proto_tree *subtree = NULL;

    if (length < 9) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, length,
                                     "Too short SRv6 locator entry (%d vs min 9)",
                                     length);
        return (-1);
    }

    /* (1) Determine the length of each SRv6 locator entry, first */
    /* Loc Size */
    bit_length = tvb_get_uint8(tvb, offset+6);
    if (bit_length <= 0 || bit_length > 128) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb, offset+6, 1,
                                     "Invalid SRv6 locator size %u (should be 1-128)",
                                     bit_length);
        return (-1);
    }
    byte_length = (bit_length + 7) / 8;
    if (length < 7 + byte_length + 1) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, length,
                                     "Too short SRv6 locator entry (%d vs min %d)",
                                     length, 7+byte_length+1);
        return (-1);
    }

    /* Sub-TLV Length */
    subtlv_length = tvb_get_uint8(tvb, offset+7+byte_length);

    /* Length of each SRv6 locator */
    locator_length = (7 + byte_length + 1) + subtlv_length;
    if (length < locator_length) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb, offset, length,
                                     "Too short SRv6 locator entry (%d vs %d bytes left)",
                                     locator_length, length);
        return (-1);
    }

    /* (2) Dissect each SRv6 locator entry */
    loctree = proto_tree_add_subtree_format(tree, tvb, offset, locator_length,
                                            ett_isis_lsp_clv_srv6_loc_entry,
                                            &ti_loctree, "SRv6 Locator");
    /* Metric */
    proto_tree_add_item(loctree, hf_isis_lsp_srv6_loc_metric, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    length -= 4;

    /* Flags */
    proto_tree_add_bitmask(loctree, tvb, offset, hf_isis_lsp_srv6_loc_flags,
                           ett_isis_lsp_clv_srv6_loc_flags, srv6_locator_flags, ENC_NA);
    offset++;
    length--;

    /* Algorithm */
    algorithm = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(loctree, hf_isis_lsp_srv6_loc_alg, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    length--;

    /* Locator Size */
    proto_tree_add_item(loctree, hf_isis_lsp_srv6_loc_size, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    length--;

    /* Locator */
    (void)tvb_get_ipv6_addr_with_prefix_len(tvb, offset, &prefix, bit_length);
    proto_tree_add_ipv6(loctree, hf_isis_lsp_srv6_loc_locator, tvb, offset, byte_length, &prefix);
    offset += byte_length;
    length -= byte_length;

    /* Sub-TLV Length */
    subtlv_length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(loctree, hf_isis_lsp_srv6_loc_subclvs_len, tvb, offset, 1, ENC_NA);
    offset++;
    length--;

    set_address(&prefix_addr, AT_IPv6, 16, prefix.bytes);
    prefix_str = address_to_str(pinfo->pool, &prefix_addr);
    proto_item_append_text(ti_loctree, ": %s/%u (Algorithm: %u)", prefix_str, bit_length, algorithm);

    while (subtlv_length >= 2) {
        clv_code = tvb_get_uint8(tvb, offset);
        clv_len  = tvb_get_uint8(tvb, offset+1);
        subtree = proto_tree_add_subtree_format(loctree, tvb, offset, clv_len + 2,
                                                ett_isis_lsp_clv_srv6_loc_sub_tlv,
                                                &ti_subtree, "subTLV: %s (c=%u, l=%u)",
                                                val_to_str_const(clv_code, isis_lsp_srv6_loc_sub_tlv_vals, "Unknown"),
                                                clv_code, clv_len);
        proto_tree_add_item(subtree, hf_isis_lsp_srv6_loc_sub_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_isis_lsp_srv6_loc_sub_tlv_length, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        offset += 2;
        subtlv_length -= 2;
        if (clv_len > subtlv_length) {
            proto_tree_add_expert_format(subtree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb, offset-1, 1,
                                         "Invalid Sub-TLV length %u (%d bytes left)",
                                         clv_len, subtlv_length);
            return (-1);
        }
        dissect_lsp_srv6_locator_subclv(tvb, pinfo, subtree, ti_subtree, offset, subtlv_length, clv_code, clv_len);
        offset += clv_len;
        subtlv_length -= clv_len;
    }

    /* Return the length of each SRv6 locator entry */
    return locator_length;
}

/*
 * Name: dissect_lsp_srv6_locator_clv()
 *
 * Description: Decode an SRv6 Locator CLV - code 27.
 *
 *   CALLED BY TLV 27 DISSECTOR
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   packet_info * : expert error misuse reporting
 *   proto_tree * : proto tree to build on (may be null)
 *   int : current offset into packet data
 *   int : length of IDs in packet.
 *   int : length of this clv
 *
 * Output:
 *   void, will modify proto_tree if not null.
 */
static void
dissect_lsp_srv6_locator_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
                             isis_data_t *isis, int length)
{
    int locator_length;

    if (length < 11) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, length,
                                     "Too short LSP SRv6 locator TLV (%d vs min 11)", length);
        return;
    }

    /* MTID */
    dissect_lsp_mt_id(tvb, tree, offset);
    offset += 2;
    length -= 2;

    /* Dissect each SRv6 Locator */
    while (length > 0) {
        locator_length = dissect_lsp_srv6_locator_entry(tvb, pinfo, tree, offset, isis, length);
        if (locator_length < 0) {
            break;
        }
        offset += locator_length;
        length -= locator_length;
    }
}

/*
 * Name: dissect_lsp_purge_orig_id_clv()
 *
 * Description: Decode a Purge Originator ID CLV - code 13.
 *
 *   CALLED BY TLV 13 DISSECTOR
 *
 * Input:
 *   tvbuff_t * : tvbuffer for packet data
 *   packet_info * : expert error misuse reporting
 *   proto_tree * : proto tree to build on (may be null)
 *   int : current offset into packet data
 *   isis_data_t : data given to subdissectors
 *   int : length of clv we are decoding
 *
 * Output:
 *   void, will modify proto_tree if not null.
 */
static void
dissect_lsp_purge_orig_id_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
                              isis_data_t *isis _U_, int length)
{
    int min_tlv_len = 7;
    uint8_t num_of_system_ids;
    int i;

    if (length < min_tlv_len) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, length,
                                     "Too short LSP Purge Originator ID (%d vs %d)",
                                     length, min_tlv_len);
        return;
    }

    /* Number of System IDs */
    num_of_system_ids = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_isis_lsp_purge_orig_id_num, tvb, offset, 1, ENC_NA);
    offset++;
    length--;

    if (num_of_system_ids != 1 && num_of_system_ids != 2) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb, offset, length,
                                     "Invalid number of System IDs: %u (should be 1 or 2)",
                                     num_of_system_ids);
        return;
    }
    if (length < num_of_system_ids * 6) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb, offset, length,
                                     "Invalid Purge Originator ID TLV length: %u ",
                                     length+1);
        return;
    }
    for (i = 0; i < num_of_system_ids; i++) {
        proto_tree_add_item(tree, hf_isis_lsp_purge_orig_id_system_id, tvb, offset, 6, ENC_NA);
        offset += 6;
        length -= 6;
    }
}

/* rfc6165: MAC Reachability */
static void
dissect_lsp_mac_reachability(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, int offset,
                              isis_data_t *isis _U_, int length)
{
    int num_macs;
    int count;
    bool is_avaya = true; // JMayer: FIXME Add preference or determine from other parts of packet

    if ((length - 5) % 6) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_length_clv, tvb, offset, length,
                                     "Unexpected length of MAC Reachability TLV (%d vs 5 + N*6)",
                                     length);
        return;
    }
    num_macs = (length -5) / 6;

    proto_tree_add_item(tree, hf_isis_lsp_mac_reachability_topoid_nick, tvb, offset, 2, ENC_NA);
    offset += 2;
    proto_tree_add_item(tree, hf_isis_lsp_mac_reachability_confidence, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_isis_lsp_mac_reachability_reserved, tvb, offset, 2, ENC_NA);
    proto_tree_add_item(tree, hf_isis_lsp_mac_reachability_vlan, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    for (count = 1; count <= num_macs; count++) {
        if (is_avaya && count == 1 )
            proto_tree_add_item(tree, hf_isis_lsp_mac_reachability_chassismac, tvb, offset, 6, ENC_NA);
        else if (is_avaya && count == 2)
            proto_tree_add_item(tree, hf_isis_lsp_mac_reachability_fanmcast, tvb, offset, 6, ENC_NA);
        else
            proto_tree_add_item(tree, hf_isis_lsp_mac_reachability_mac, tvb, offset + 5, 6, ENC_NA);
        offset += 6;
    }
}

static void
dissect_lsp_avaya_ipvpn(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, int offset,
                              isis_data_t *isis _U_, int length)
{
    unsigned subtlvbytes;
    proto_item *ti;
    proto_item *ti_pfxlen, *ti_prefix;
    proto_tree *subtlvtree;
    unsigned subtype;
    unsigned sublength;

    if (length < 15) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_short_clv, tvb, offset, length,
                                     "Too short LSP Avaya IPVPN (%d vs min 15)",
                                     length);
        return;
    }
    proto_tree_add_item(tree, hf_isis_lsp_avaya_ipvpn_unknown, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item(tree, hf_isis_lsp_avaya_ipvpn_system_id, tvb, offset, 7, ENC_NA);
    offset += 7;
    proto_tree_add_item(tree, hf_isis_lsp_avaya_ipvpn_vrfsid, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item_ret_uint(tree, hf_isis_lsp_avaya_ipvpn_subtlvbytes, tvb, offset, 1, ENC_NA, &subtlvbytes);
    offset += 1;

    if ((unsigned)length != 15+subtlvbytes) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_length_clv, tvb, offset, length,
                                     "Inconsistent length of LSP Avaya IPVPN with subtlvs (%d vs min %d)",
                                     length, 15 + subtlvbytes);
        return;
    }
    while (subtlvbytes > 0) {
        if (subtlvbytes == 1) {
            proto_tree_add_expert_format(tree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb, offset, length,
                                         "Too few bytes remaining for Sub-TLV header (1 vs 2)");
            return;
        }
	subtype = tvb_get_uint8(tvb, offset);
	sublength = tvb_get_uint8(tvb, offset + 1);
        subtlvtree = proto_tree_add_subtree_format(tree, tvb, offset, sublength + 2, ett_isis_lsp_clv_avaya_ipvpn_subtlv, &ti, "%s",
                                    val_to_str_const(subtype, isis_lsp_avaya_ipvpn_subtlv_code_vals, "Unknown"));
        proto_tree_add_item(subtlvtree, hf_isis_lsp_avaya_ipvpn_subtlvtype, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(subtlvtree, hf_isis_lsp_avaya_ipvpn_subtlvlength, tvb, offset + 1, 1, ENC_NA);
        offset += 2;
        switch (subtype) {
        case 1:   /* Metric Type */
            if (sublength != 4) {
                proto_tree_add_expert_format(subtlvtree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb, offset, sublength,
                                         "Unexpected Metric Type sub-TLV length (%d vs 4)", sublength);
                offset += sublength;
            } else {
                proto_tree_add_item(subtlvtree, hf_isis_lsp_avaya_ipvpn_ipv4_metrictype, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }
            break;
        case 135: /* IPv4 */
            if (sublength != 12) {
                proto_tree_add_expert_format(subtlvtree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb, offset, sublength,
                                         "Unexpected IPv4 Reachability sub-TLV length (%d vs 12)", sublength);
                offset += sublength;
            } else {
                proto_tree_add_item(subtlvtree, hf_isis_lsp_avaya_ipvpn_ipv4_metric, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                ti_prefix = proto_tree_add_item(subtlvtree, hf_isis_lsp_avaya_ipvpn_ipv4_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                ti_pfxlen = proto_tree_add_item(subtlvtree, hf_isis_lsp_avaya_ipvpn_ipv4_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_item_append_text(ti, ": %s/%s", proto_item_get_display_repr(pinfo->pool, ti_prefix),
                                                  proto_item_get_display_repr(pinfo->pool, ti_pfxlen));
            }
            break;
        case 236: /* IPv6 */
            if (sublength != 22) {
                proto_tree_add_expert_format(subtlvtree, pinfo, &ei_isis_lsp_malformed_subtlv, tvb, offset, sublength,
                                         "Unexpected IPv6 Reachability sub-TLV length (%d vs 22)", sublength);
                offset += sublength;
            } else {
                proto_tree_add_item(subtlvtree, hf_isis_lsp_avaya_ipvpn_ipv6_metric, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                ti_pfxlen = proto_tree_add_item(subtlvtree, hf_isis_lsp_avaya_ipvpn_ipv6_prefixlen, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                ti_prefix = proto_tree_add_item(subtlvtree, hf_isis_lsp_avaya_ipvpn_ipv6_prefix, tvb, offset, 16, ENC_NA);
                offset += 16;
                proto_item_append_text(ti, ": %s/%s", proto_item_get_display_repr(pinfo->pool, ti_prefix),
                                                  proto_item_get_display_repr(pinfo->pool, ti_pfxlen));
            }
            break;
        default:
            proto_tree_add_item(subtlvtree, hf_isis_lsp_avaya_ipvpn_unknown_sub, tvb, offset, sublength, ENC_NA);
            proto_tree_add_expert_format(subtlvtree, pinfo, &ei_isis_lsp_unknown_subtlv, tvb, offset, sublength,
                                         "Unknown Avaya IPVPN subTLV (%d): Please report to Wireshark developers.", subtype);
            offset += sublength;
        }
        subtlvbytes -= (2 + sublength);
    }
}

static void
dissect_lsp_avaya_ipvpn_mc(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, int offset,
                              isis_data_t *isis _U_, int length)
{
    proto_tree_add_item(tree, hf_isis_lsp_avaya_185_unknown, tvb, offset, length, ENC_NA);
}

static void
dissect_lsp_avaya_ip_grt_mc(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, int offset,
                              isis_data_t *isis _U_, int length)
{
    proto_tree_add_item(tree, hf_isis_lsp_avaya_186_unknown, tvb, offset, length, ENC_NA);
}

static const isis_clv_handle_t clv_l1_lsp_opts[] = {
    {
        ISIS_CLV_AREA_ADDRESS,
        "Area address(es)",
        &ett_isis_lsp_clv_area_addr,
        dissect_lsp_area_address_clv
    },
    {
        ISIS_CLV_IS_REACH,
        "IS Reachability",
        &ett_isis_lsp_clv_is_neighbors,
        dissect_lsp_l1_is_neighbors_clv
    },
    {
        ISIS_CLV_ES_NEIGHBORS,
        "ES Neighbor(s)",
        &ett_isis_lsp_clv_is_neighbors,
        dissect_lsp_l1_es_neighbors_clv
    },
    {
        ISIS_CLV_INSTANCE_IDENTIFIER,
        "Instance Identifier",
        &ett_isis_lsp_clv_instance_identifier,
        dissect_lsp_instance_identifier_clv
    },
    {
        ISIS_CLV_LSP_BUFFERSIZE,
        "Originating neighbor buffer size",
        &ett_isis_lsp_clv_originating_buff_size,
        dissect_lsp_ori_buffersize_clv
    },
    {
        ISIS_CLV_EXTD_IS_REACH,
        "Extended IS reachability",
        &ett_isis_lsp_clv_ext_is_reachability,
        dissect_lsp_ext_is_reachability_clv
    },
    {
        ISIS_CLV_INT_IP_REACH,
        "IP Internal reachability",
        &ett_isis_lsp_clv_ip_reachability,
        dissect_lsp_ip_reachability_clv
    },
    {
        ISIS_CLV_EXT_IP_REACH,
        "IP External reachability",
        &ett_isis_lsp_clv_ip_reachability,
        dissect_lsp_ip_reachability_clv
    },
    {
        ISIS_CLV_EXTD_IP_REACH,
        "Extended IP Reachability",
        &ett_isis_lsp_clv_ext_ip_reachability,
        dissect_lsp_ext_ip_reachability_clv
    },
    {
        ISIS_CLV_IP6_REACH,
        "IPv6 reachability",
        &ett_isis_lsp_clv_ipv6_reachability,
        dissect_lsp_ipv6_reachability_clv
    },
    {
        ISIS_CLV_PROTOCOLS_SUPPORTED,
        "Protocols supported",
        &ett_isis_lsp_clv_nlpid_nlpid,
        dissect_lsp_nlpid_clv
    },
    {
        ISIS_CLV_HOSTNAME,
        "Hostname",
        &ett_isis_lsp_clv_hostname,
        dissect_lsp_hostname_clv
    },
    {
        ISIS_CLV_SHARED_RISK_GROUP,
        "Shared Risk Link Group",
        &ett_isis_lsp_clv_srlg,
        dissect_lsp_srlg_clv
    },
    {
        ISIS_CLV_TE_ROUTER_ID,
        "Traffic Engineering Router ID",
        &ett_isis_lsp_clv_te_router_id,
        dissect_lsp_te_router_id_clv
    },
    {
        ISIS_CLV_IP_ADDR,
        "IP Interface address(es)",
        &ett_isis_lsp_clv_ipv4_int_addr,
        dissect_lsp_ip_int_addr_clv
    },
    {
        ISIS_CLV_IP6_ADDR,
        "IPv6 Interface address(es)",
        &ett_isis_lsp_clv_ipv6_int_addr,
        dissect_lsp_ipv6_int_addr_clv
    },
    {
        ISIS_CLV_MT_CAP,
        "MT-Capability",
        &ett_isis_lsp_clv_mt_cap,
        dissect_isis_lsp_clv_mt_cap
    },
    {
        ISIS_CLV_SID_LABEL_BINDING,
        "SID/Label Binding TLV",
        &ett_isis_lsp_clv_sid_label_binding,
        dissect_isis_lsp_clv_sid_label_binding
    },
    {
        ISIS_CLV_AUTHENTICATION,
        "Authentication",
        &ett_isis_lsp_clv_authentication,
        dissect_lsp_authentication_clv
    },
    {
        ISIS_CLV_IP_AUTHENTICATION,
        "IP Authentication",
        &ett_isis_lsp_clv_ip_authentication,
        dissect_lsp_ip_authentication_clv
    },
    {
        ISIS_CLV_MT_SUPPORTED,
        "Multi Topology supported",
        &ett_isis_lsp_clv_mt,
        dissect_lsp_mt_clv
    },
    {
        ISIS_CLV_MT_IS_REACH,
        "Multi Topology IS Reachability",
        &ett_isis_lsp_clv_mt_is,
        dissect_lsp_mt_is_reachability_clv
    },
    {
        ISIS_CLV_MT_IP_REACH,
        "Multi Topology Reachable IPv4 Prefixes",
        &ett_isis_lsp_clv_mt_reachable_IPv4_prefx,
        dissect_lsp_mt_reachable_IPv4_prefx_clv
    },
    {
        ISIS_CLV_MT_IP6_REACH,
        "Multi Topology Reachable IPv6 Prefixes",
        &ett_isis_lsp_clv_mt_reachable_IPv6_prefx,
        dissect_lsp_mt_reachable_IPv6_prefx_clv
    },
    {
        ISIS_CLV_RT_CAPABLE,
        "Router Capability",
        &ett_isis_lsp_clv_rt_capable,
        dissect_isis_rt_capable_clv
    },
    {
        ISIS_GRP_ADDR,
        "Group Address",
        &ett_isis_lsp_clv_grp_address,
        dissect_isis_grp_address_clv
    },
    {
        ISIS_CLV_IPV6_TE_ROUTER_ID,
        "IPv6 TE Router ID",
        &ett_isis_lsp_clv_ipv6_te_router_id,
        dissect_lsp_ipv6_te_router_id_clv
    },
    {
        ISIS_CLV_SRV6_LOCATOR,
        "SRv6 Locator",
        &ett_isis_lsp_clv_srv6_locator,
        dissect_lsp_srv6_locator_clv
    },
    {
        ISIS_CLV_PURGE_ORIG_ID,
        "Purge Originator ID",
        &ett_isis_lsp_clv_purge_orig_id,
        dissect_lsp_purge_orig_id_clv
    },
    {
        ISIS_CLV_MAC_RI,
        "MAC Reachability",
        &ett_isis_lsp_clv_mac_reachability,
        dissect_lsp_mac_reachability
    },
    {
        ISIS_CLV_AVAYA_IPVPN,
        "Avaya IPVPN",
        &ett_isis_lsp_clv_avaya_ipvpn,
        dissect_lsp_avaya_ipvpn
    },
    {
        ISIS_CLV_AVAYA_IPVPN_MC,
        "Avaya IPVPN MCast",
        &ett_isis_lsp_clv_avaya_ipvpn_mc,
        dissect_lsp_avaya_ipvpn_mc
    },
    {
        ISIS_CLV_AVAYA_IP_GRT_MC,
        "Avaya IP GRT MCast",
        &ett_isis_lsp_clv_avaya_ip_grt_mc,
        dissect_lsp_avaya_ip_grt_mc
    },
    {
        0,
        "",
        NULL,
        NULL
    }
};

static const isis_clv_handle_t clv_l2_lsp_opts[] = {
    {
        ISIS_CLV_AREA_ADDRESS,
        "Area address(es)",
        &ett_isis_lsp_clv_area_addr,
        dissect_lsp_area_address_clv
    },
    {
        ISIS_CLV_IS_REACH,
        "IS Reachability",
        &ett_isis_lsp_clv_is_neighbors,
        dissect_lsp_l2_is_neighbors_clv
    },
    {
        ISIS_CLV_EXTD_IS_REACH,
        "Extended IS reachability",
        &ett_isis_lsp_clv_ext_is_reachability,
        dissect_lsp_ext_is_reachability_clv
    },
    {
        ISIS_CLV_PARTITION_DIS,
        "Partition Designated Level 2 IS",
        &ett_isis_lsp_clv_partition_dis,
        dissect_lsp_partition_dis_clv
    },
    {
        ISIS_CLV_PREFIX_NEIGHBORS,
        "Prefix neighbors",
        &ett_isis_lsp_clv_prefix_neighbors,
        dissect_lsp_prefix_neighbors_clv
    },
    {
        ISIS_CLV_INSTANCE_IDENTIFIER,
        "Instance Identifier",
        &ett_isis_lsp_clv_instance_identifier,
        dissect_lsp_instance_identifier_clv
    },
    {
        ISIS_CLV_LSP_BUFFERSIZE,
        "Originating neighbor buffer size",
        &ett_isis_lsp_clv_originating_buff_size,
        dissect_lsp_ori_buffersize_clv
    },
    {
        ISIS_CLV_INT_IP_REACH,
        "IP Internal reachability",
        &ett_isis_lsp_clv_ip_reachability,
        dissect_lsp_ip_reachability_clv
    },
    {
        ISIS_CLV_EXT_IP_REACH,
        "IP External reachability",
        &ett_isis_lsp_clv_ip_reachability,
        dissect_lsp_ip_reachability_clv
    },
    {
        ISIS_CLV_PROTOCOLS_SUPPORTED,
        "Protocols supported",
        &ett_isis_lsp_clv_nlpid_nlpid,
        dissect_lsp_nlpid_clv
    },
    {
        ISIS_CLV_HOSTNAME,
        "Hostname",
        &ett_isis_lsp_clv_hostname,
        dissect_lsp_hostname_clv
    },
    {
        ISIS_CLV_SHARED_RISK_GROUP,
        "Shared Risk Link Group",
        &ett_isis_lsp_clv_srlg,
        dissect_lsp_srlg_clv
    },
    {
        ISIS_CLV_TE_ROUTER_ID,
        "Traffic Engineering Router ID",
        &ett_isis_lsp_clv_te_router_id,
        dissect_lsp_te_router_id_clv
    },
    {
        ISIS_CLV_EXTD_IP_REACH,
        "Extended IP Reachability",
        &ett_isis_lsp_clv_ext_ip_reachability,
        dissect_lsp_ext_ip_reachability_clv
    },
    {
        ISIS_CLV_IP6_REACH,
        "IPv6 reachability",
        &ett_isis_lsp_clv_ipv6_reachability,
        dissect_lsp_ipv6_reachability_clv
    },
    {
        ISIS_CLV_IP_ADDR,
        "IP Interface address(es)",
        &ett_isis_lsp_clv_ipv4_int_addr,
        dissect_lsp_ip_int_addr_clv
    },
    {
        ISIS_CLV_IP6_ADDR,
        "IPv6 Interface address(es)",
        &ett_isis_lsp_clv_ipv6_int_addr,
        dissect_lsp_ipv6_int_addr_clv
    },
    {
        ISIS_CLV_MT_CAP,
        "MT-Capability",
        &ett_isis_lsp_clv_mt_cap,
        dissect_isis_lsp_clv_mt_cap
    },
    {
        ISIS_CLV_SID_LABEL_BINDING,
        "SID/Label Binding TLV",
        &ett_isis_lsp_clv_sid_label_binding,
        dissect_isis_lsp_clv_sid_label_binding
    },
    {
        ISIS_CLV_AUTHENTICATION,
        "Authentication",
        &ett_isis_lsp_clv_authentication,
        dissect_lsp_authentication_clv
    },
    {
        ISIS_CLV_IP_AUTHENTICATION,
        "IP Authentication",
        &ett_isis_lsp_clv_ip_authentication,
        dissect_lsp_ip_authentication_clv
    },
    {
        ISIS_CLV_MT_SUPPORTED,
        "Multi Topology",
        &ett_isis_lsp_clv_mt,
        dissect_lsp_mt_clv
    },
    {
        ISIS_CLV_MT_IS_REACH,
        "Multi Topology IS Reachability",
        &ett_isis_lsp_clv_mt_is,
        dissect_lsp_mt_is_reachability_clv
    },
    {
        ISIS_CLV_MT_IP_REACH,
        "Multi Topology Reachable IPv4 Prefixes",
        &ett_isis_lsp_clv_mt_reachable_IPv4_prefx,
        dissect_lsp_mt_reachable_IPv4_prefx_clv
    },
    {
        ISIS_CLV_MT_IP6_REACH,
        "Multi Topology Reachable IPv6 Prefixes",
        &ett_isis_lsp_clv_mt_reachable_IPv6_prefx,
        dissect_lsp_mt_reachable_IPv6_prefx_clv
    },
    {
        ISIS_CLV_RT_CAPABLE,
        "Router Capability",
        &ett_isis_lsp_clv_rt_capable,
        dissect_isis_rt_capable_clv
    },
    {
        ISIS_CLV_IPV6_TE_ROUTER_ID,
        "IPv6 TE Router ID",
        &ett_isis_lsp_clv_ipv6_te_router_id,
        dissect_lsp_ipv6_te_router_id_clv
    },
    {
        ISIS_CLV_SRV6_LOCATOR,
        "SRv6 Locator",
        &ett_isis_lsp_clv_srv6_locator,
        dissect_lsp_srv6_locator_clv
    },
    {
        ISIS_CLV_PURGE_ORIG_ID,
        "Purge Originator ID",
        &ett_isis_lsp_clv_purge_orig_id,
        dissect_lsp_purge_orig_id_clv
    },
    {
        0,
        "",
        NULL,
        NULL
    }
};

/*
 * Name: isis_dissect_isis_lsp()
 *
 * Description:
 *    Print out the LSP part of the main header and then call the CLV
 *    de-mangler with the right list of valid CLVs.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : protocol display tree to add to.  May be NULL.
 *    int offset : our offset into packet data.
 *    int : LSP type, a la packet-isis.h ISIS_TYPE_* values
 *    int : header length of packet.
 *    int : length of IDs in packet.
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_isis_lsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
    const isis_clv_handle_t *opts, isis_data_t *isis)
{
    proto_item    *ti;
    proto_tree    *lsp_tree, *info_tree;
    uint16_t       pdu_length, lifetime, checksum, cacl_checksum=0;
    bool           pdu_length_too_short = false;
    bool           pdu_length_too_long = false;
    uint8_t        lsp_info;
    int            offset_checksum;
    char          *system_id;

    /*
     * We are passed a tvbuff for the entire ISIS PDU, because some ISIS
     * PDUs may contain a checksum CLV, and that's a checksum covering
     * the entire PDU.  Skip the part of the header that's already been
     * dissected.
     */
    offset += 8;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISIS LSP");

    ti = proto_tree_add_item(tree, proto_isis_lsp, tvb, offset, -1, ENC_NA);
    lsp_tree = proto_item_add_subtree(ti, ett_isis_lsp);

    if (isis->header_length < 8 + 2) {
        /* Not large enough to include the part of the header that
           we dissect here. */
        expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
        return;
    }
    pdu_length = tvb_get_ntohs(tvb, offset);
    ti = proto_tree_add_uint(lsp_tree, hf_isis_lsp_pdu_length, tvb,
            offset, 2, pdu_length);
    if (pdu_length < isis->header_length) {
        expert_add_info(pinfo, ti, &ei_isis_lsp_short_pdu);
        pdu_length_too_short = true;
    } else if (pdu_length > tvb_reported_length(tvb) + isis->header_length) {
        expert_add_info(pinfo, ti, &ei_isis_lsp_long_pdu);
        pdu_length_too_long = true;
    }
    offset += 2;

    if (isis->header_length < 8 + 2 + 2) {
        /* Not large enough to include the part of the header that
           we dissect here. */
        expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
        return;
    }
    proto_tree_add_item(lsp_tree, hf_isis_lsp_remaining_life,
            tvb, offset, 2, ENC_BIG_ENDIAN);
    lifetime = tvb_get_ntohs(tvb, offset);
    offset += 2;

    /* Checksumming starts with the LSP ID */
    offset_checksum = offset;

    if (isis->header_length < 8 + 2 + 2 + isis->system_id_len + 2) {
        /* Not large enough to include the part of the header that
           we dissect here. */
        expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
        return;
    }
    proto_tree_add_item(lsp_tree, hf_isis_lsp_lsp_id, tvb, offset, isis->system_id_len + 2, ENC_NA);
    system_id = tvb_print_system_id( pinfo->pool, tvb, offset, isis->system_id_len+2 );
    col_append_fstr(pinfo->cinfo, COL_INFO, ", LSP-ID: %s", system_id);
    offset += (isis->system_id_len + 2);

    if (isis->header_length < 8 + 2 + 2 + isis->system_id_len + 2 + 4) {
        /* Not large enough to include the part of the header that
           we dissect here. */
        expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
        return;
    }
    proto_tree_add_item(lsp_tree, hf_isis_lsp_sequence_number,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Sequence: 0x%08x, Lifetime: %5us",
            tvb_get_ntohl(tvb, offset),
            tvb_get_ntohs(tvb, offset - (isis->system_id_len+2+2)));
    offset += 4;

    if (isis->header_length < 8 + 2 + 2 + isis->system_id_len + 2 + 4 + 2) {
        /* Not large enough to include the part of the header that
           we dissect here. */
        expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
        return;
    }
    checksum = lifetime ? tvb_get_ntohs(tvb, offset) : 0;
    if (checksum == 0) {
        /* No checksum present */
        proto_tree_add_checksum(lsp_tree, tvb, offset, hf_isis_lsp_checksum, hf_isis_lsp_checksum_status, &ei_isis_lsp_bad_checksum, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NOT_PRESENT);
    } else if (pdu_length_too_short || pdu_length_too_long) {
        /* Length bogus, so we can't check the checksum */
        proto_tree_add_checksum(lsp_tree, tvb, offset, hf_isis_lsp_checksum, hf_isis_lsp_checksum_status, &ei_isis_lsp_bad_checksum, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
    } else {
        if (osi_check_and_get_checksum(tvb, offset_checksum, pdu_length-12, offset, &cacl_checksum)) {
            /* Successfully processed checksum, verify it */
            proto_tree_add_checksum(lsp_tree, tvb, offset, hf_isis_lsp_checksum, hf_isis_lsp_checksum_status, &ei_isis_lsp_bad_checksum, pinfo, cacl_checksum, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
            if (cacl_checksum != checksum) {
                col_append_str(pinfo->cinfo, COL_INFO, " [ISIS CHECKSUM INCORRECT]");
            }
        } else {
            /* We didn't capture the entire packet, so we can't verify it */
            proto_tree_add_checksum(lsp_tree, tvb, offset, hf_isis_lsp_checksum, hf_isis_lsp_checksum_status, &ei_isis_lsp_bad_checksum, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
        }
    }
    offset += 2;

    if (isis->header_length < 8 + 2 + 2 + isis->system_id_len + 2 + 4 + 2 + 1) {
        /* Not large enough to include the part of the header that
           we dissect here. */
        expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
        return;
    }
    if (tree) {
        static int * const attach_flags[] = {
            &hf_isis_lsp_error_metric,
            &hf_isis_lsp_expense_metric,
            &hf_isis_lsp_delay_metric,
            &hf_isis_lsp_default_metric,
            NULL
        };

        /*
         * P | ATT | HIPPITY | IS TYPE description.
         */
        lsp_info = tvb_get_uint8(tvb, offset);
        info_tree = proto_tree_add_subtree_format(lsp_tree, tvb, offset, 1, ett_isis_lsp_info, NULL,
            "Type block(0x%02x): Partition Repair:%d, Attached bits:%d, Overload bit:%d, IS type:%d",
            lsp_info,
            ISIS_LSP_PARTITION(lsp_info),
            ISIS_LSP_ATT(lsp_info),
            ISIS_LSP_HIPPITY(lsp_info),
            ISIS_LSP_IS_TYPE(lsp_info)
            );

        proto_tree_add_boolean(info_tree, hf_isis_lsp_p, tvb, offset, 1, lsp_info);
        proto_tree_add_bitmask_with_flags(info_tree, tvb, offset, hf_isis_lsp_att,
                           ett_isis_lsp_att, attach_flags, ENC_NA, BMT_NO_APPEND);
        proto_tree_add_boolean(info_tree, hf_isis_lsp_hippity, tvb, offset, 1, lsp_info);
        proto_tree_add_uint(info_tree, hf_isis_lsp_is_type, tvb, offset, 1, lsp_info);
    }
    offset += 1;

    if (pdu_length_too_short) {
        return;
    }
    /*
     * Now, we need to decode our CLVs.  We need to pass in
     * our list of valid ones!
     */
    isis->pdu_length = pdu_length;
    isis_dissect_clvs(tvb, pinfo, lsp_tree, offset,
            opts, &ei_isis_lsp_short_clv, isis, ett_isis_lsp_clv_unknown,
            hf_isis_lsp_clv_type, hf_isis_lsp_clv_length,
            &ei_isis_lsp_clv_unknown);
}

static int
dissect_isis_l1_lsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    isis_data_t* isis = (isis_data_t*)data;
    dissect_isis_lsp(tvb, pinfo, tree, 0, clv_l1_lsp_opts, isis);
    return tvb_reported_length(tvb);
}

static int
dissect_isis_l2_lsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    isis_data_t* isis = (isis_data_t*)data;
    dissect_isis_lsp(tvb, pinfo, tree, 0, clv_l2_lsp_opts, isis);
    return tvb_reported_length(tvb);
}

/*
 * The "supported" bit in a metric is actually the "not supported" bit;
 * if it's *clear*, the metric is supported, and if it's *set*, the
 * metric is not supported.
 */

void
proto_register_isis_lsp(void)
{
    static hf_register_info hf[] = {
        { &hf_isis_lsp_pdu_length,
            { "PDU length", "isis.lsp.pdu_length",
              FT_UINT16, BASE_DEC,
              NULL, 0x0, NULL, HFILL }
        },

        { &hf_isis_lsp_remaining_life,
            { "Remaining lifetime", "isis.lsp.remaining_life",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_lsp_id,
            { "LSP-ID", "isis.lsp.lsp_id",
              FT_SYSTEM_ID, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_hostname,
            { "Hostname", "isis.lsp.hostname",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_srlg_system_id,
            { "System ID", "isis.lsp.srlg.system_id",
              FT_SYSTEM_ID, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_srlg_pseudo_num,
            { "Pseudonode num", "isis.lsp.srlg.pseudo_num",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_srlg_flags_numbered,
            { "Numbered", "isis.lsp.srlg.flags_numbered",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
              NULL, HFILL }
        },

        { &hf_isis_lsp_srlg_ipv4_local,
            { "IPv4 interface address/Link Local Identifier", "isis.lsp.srlg.ipv4_local",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_srlg_ipv4_remote,
            { "IPv4 neighbor address/Link remote Identifier", "isis.lsp.srlg.ipv4_remote",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_srlg_value,
            { "Shared Risk Link Group Value", "isis.lsp.srlg.value",
              FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_sequence_number,
            { "Sequence number", "isis.lsp.sequence_number",
              FT_UINT32, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_checksum,
            { "Checksum", "isis.lsp.checksum",
              FT_UINT16, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_checksum_status,
            { "Checksum Status", "isis.lsp.checksum.status",
              FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_clv_ipv4_int_addr,
            { "IPv4 interface address", "isis.lsp.clv_ipv4_int_addr",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_clv_ipv6_int_addr,
            { "IPv6 interface address", "isis.lsp.clv_ipv6_int_addr",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_clv_te_router_id,
            { "Traffic Engineering Router ID", "isis.lsp.clv_te_router_id",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_clv_mt,
            { "MT-ID", "isis.lsp.clv_mt",
              FT_UINT16, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_p,
            { "Partition Repair", "isis.lsp.partition_repair",
              FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), ISIS_LSP_PARTITION_MASK,
              "If set, this router supports the optional Partition Repair function", HFILL }
        },

        { &hf_isis_lsp_att,
            { "Attachment", "isis.lsp.att",
              FT_UINT8, BASE_DEC, NULL, ISIS_LSP_ATT_MASK,
              NULL, HFILL }
        },

        { &hf_isis_lsp_hippity,
            { "Overload bit", "isis.lsp.overload",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), ISIS_LSP_HIPPITY_MASK,
              "If set, this router will not be used by any decision process to calculate routes", HFILL }
        },

        { &hf_isis_lsp_root_id,
            { "Root Bridge ID", "isis.lsp.root.id",
              FT_SYSTEM_ID, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_is_type,
            { "Type of Intermediate System", "isis.lsp.is_type",
              FT_UINT8, BASE_DEC, VALS(isis_lsp_istype_vals), ISIS_LSP_IS_TYPE_MASK,
              NULL, HFILL }
        },

        { &hf_isis_lsp_clv_type,
            { "Type", "isis.lsp.clv.type",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_clv_length,
            { "Length", "isis.lsp.clv.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_bw_ct_model,
            { "Bandwidth Constraints Model Id", "isis.lsp.bw_ct.model",
              FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_bw_ct_reserved,
            { "Reserved", "isis.lsp.bw_ct.rsv",
              FT_UINT24, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_bw_ct0,
            { "Bandwidth Constraints 0", "isis.lsp.bw_ct.0",
              FT_FLOAT, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_bw_ct1,
            { "Bandwidth Constraints 1", "isis.lsp.bw_ct.1",
              FT_FLOAT, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_bw_ct2,
            { "Bandwidth Constraints 2", "isis.lsp.bw_ct.2",
              FT_FLOAT, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_bw_ct3,
            { "Bandwidth Constraints 3", "isis.lsp.bw_ct.3",
              FT_FLOAT, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_bw_ct4,
            { "Bandwidth Constraints 4", "isis.lsp.bw_ct.4",
              FT_FLOAT, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_bw_ct5,
            { "Bandwidth Constraints 5", "isis.lsp.bw_ct.5",
              FT_FLOAT, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_bw_ct6,
            { "Bandwidth Constraints 6", "isis.lsp.bw_ct.6",
              FT_FLOAT, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_bw_ct7,
            { "Bandwidth Constraints 7", "isis.lsp.bw_ct.7",
              FT_FLOAT, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_spb_link_metric,
            { "SPB Link Metric", "isis.lsp.spb.link_metric",
              FT_UINT24, BASE_HEX_DEC, NULL, 0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_spb_port_count,
            { "Number of Ports", "isis.lsp.spb.port_count",
              FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_spb_port_id,
            { "Port Id", "isis.lsp.spb.port_id",
              FT_UINT16, BASE_HEX_DEC, NULL, 0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_adj_sid_flags,
            { "Flags", "isis.lsp.adj_sid.flags",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_adj_sid_family_flag,
            { "Outgoing Encapsulation", "isis.lsp.adj_sid.flags.f",
              FT_BOOLEAN, 8, TFS(&tfs_ipv6_ipv4), 0x80,
              NULL, HFILL }
        },

        { &hf_isis_lsp_adj_sid_backup_flag,
            { "Backup", "isis.lsp.adj_sid.flags.b",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
              NULL, HFILL }
        },

        { &hf_isis_lsp_adj_sid_value_flag,
            { "Value", "isis.lsp.adj_sid.flags.v",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
              NULL, HFILL }
        },

        { &hf_isis_lsp_adj_sid_local_flag,
            { "Local Significance", "isis.lsp.adj_sid.flags.l",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
              NULL, HFILL }
        },

        { &hf_isis_lsp_adj_sid_set_flag,
            { "Set", "isis.lsp.adj_sid.flags.s",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x8,
              NULL, HFILL }
        },

        { &hf_isis_lsp_adj_sid_weight,
            { "Weight", "isis.lsp.adj_sid.weight",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_adj_sid_system_id,
            { "System-ID", "isis.lsp.adj_sid.system_id",
              FT_SYSTEM_ID, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_sid_sli_label,
            { "SID/Label/Index", "isis.lsp.sid.sli_label",
              FT_UINT24, BASE_DEC, NULL, 0x0FFFFF,
              NULL, HFILL }
        },

        { &hf_isis_lsp_sid_sli_index,
            { "SID/Label/Index", "isis.lsp.sid.sli_index",
              FT_UINT32, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_sid_sli_ipv6,
            { "SID/Label/Index", "isis.lsp.sid.sli_ipv6",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_spb_reserved,
            { "SR Bit", "isis.lsp.spb.reserved",
              FT_UINT16, BASE_DEC, NULL, 0xC000,
              NULL, HFILL }
        },

        { &hf_isis_lsp_spb_sr_bit,
            { "SR Bit", "isis.lsp.spb.sr_bit",
              FT_UINT16, BASE_DEC, NULL, 0x3000,
              NULL, HFILL }
        },

        { &hf_isis_lsp_spb_spvid,
            { "SPVID", "isis.lsp.spb.spvid",
              FT_UINT16, BASE_HEX_DEC, NULL, 0x0FFF,
              NULL, HFILL }
        },
        { &hf_isis_lsp_spb_short_mac_address_t,
            { "T", "isis.lsp.spb.mac_address.t",
              FT_BOOLEAN, 8, NULL, 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_spb_short_mac_address_r,
            { "R", "isis.lsp.spb.mac_address.r",
              FT_BOOLEAN, 8, NULL, 0x40,
              NULL, HFILL }
        },
        { &hf_isis_lsp_spb_short_mac_address_reserved,
            { "Reserved", "isis.lsp.spb.mac_address.reserved",
              FT_UINT8, BASE_DEC, NULL, 0x3F,
              NULL, HFILL }
        },
        { &hf_isis_lsp_spb_short_mac_address,
            { "MAC Address", "isis.lsp.spb.mac_address",
              FT_ETHER, BASE_NONE, NULL, 0x00,
              NULL, HFILL }
        },
      /* TLV 149 draft-previdi-isis-segmentrouting-extensions */
        { &hf_isis_lsp_sl_binding_flags,
            { "TLV Flags", "isis.lsp.sl_binding.flags",
              FT_UINT8, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_sl_binding_flags_f,
            { "Flag F: Address Family", "isis.lsp.sl_binding.flags_f",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_binding_flags_m,
            { "Flag M: Mirror Context", "isis.lsp.sl_binding.flags_m",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_binding_flags_s,
            { "Flag S", "isis.lsp.sl_binding.flags_s",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
              "If set, the SID/Label Binding TLV SHOULD be flooded across the entire routing domain", HFILL}
        },
        { &hf_isis_lsp_sl_binding_flags_d,
            { "Flag D", "isis.lsp.sl_binding.flags_d",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
              "when the SID/Label Binding TLV is leaked from level-2 to level-1", HFILL}
        },
        { &hf_isis_lsp_sl_binding_flags_a,
            { "Flag A: Attached", "isis.lsp.sl_binding.flags_a",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_binding_flags_rsv,
            { "Flag reserved", "isis.lsp.sl_binding.flags_rsv",
              FT_UINT8, BASE_HEX, NULL, 0x07,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_binding_weight,
            { "Weight", "isis.lsp.sl_binding.weight",
              FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_binding_range,
            { "Range", "isis.lsp.sl_binding.range",
              FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_binding_prefix_length,
            { "Prefix length", "isis.lsp.sl_binding.prefix_len",
              FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_binding_fec_prefix_ipv4,
            { "Prefix", "isis.lsp.sl_binding.prefix_ipv4",
              FT_IPv4, BASE_NONE, NULL, 0,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_binding_fec_prefix_ipv6,
            { "Prefix", "isis.lsp.sl_binding.prefix_ipv6",
              FT_IPv6, BASE_NONE, NULL, 0,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_sub_tlv,
            { "SID/Label sub-TLV :", "isis.lsp.sl_binding.subtlv",
              FT_NONE, BASE_NONE, NULL, 0,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_sub_tlv_type,
            { "SID/label sub-TLV type", "isis.lsp.sl_sub_tlv_type",
              FT_UINT8, BASE_DEC, VALS(isis_lsp_sl_sub_tlv_vals), 0,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_sub_tlv_length,
            { "Sub-TLV length", "isis.lsp.sl_binding.sub_tlv_len",
              FT_UINT8, BASE_DEC, NULL, 0,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_sub_tlv_label_20,
            { "SID/Label", "isis.lsp.sl_sub_tlv.label20",
              FT_UINT24, BASE_DEC, NULL, 0x0FFFFF,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_sub_tlv_label_32,
            { "SID/Label", "isis.lsp.sl_sub_tlv.label32",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_sub_tlv_flags,
            { "sub-TLV Flags", "isis.lsp.sl_sub_tlv.flags",
              FT_UINT8, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_sl_sub_tlv_flags_r,
            { "Flag R: Re-advertisement", "isis.lsp.sl_sub_tlv.flags_r",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_sub_tlv_flags_n,
            { "Flag N: Node-SID", "isis.lsp.sl_sub_tlv.flags_n",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_sub_tlv_flags_p,
            { "Flag P: no-PHP", "isis.lsp.sl_sub_tlv.flags_p",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_sub_tlv_flags_e,
            { "Flag E: Explicit-Null", "isis.lsp.sl_sub_tlv.flags_e",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_sub_tlv_flags_v,
            { "Flag V: Value", "isis.lsp.sl_sub_tlv.flags_v",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_sub_tlv_flags_l,
            { "Flag L: Local", "isis.lsp.sl_sub_tlv.flags_l",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_sub_tlv_flags_rsv,
            { "Flag reserved", "isis.lsp.sl_sub_tlv.flags_rsv",
              FT_UINT8, BASE_HEX, NULL, 0x03,
              NULL, HFILL}
        },
        { &hf_isis_lsp_sl_sub_tlv_algorithm,
            { "Algorithm", "isis.lsp.sl_sub_tlv.algorithm",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL}
        },

        /* Generated from convert_proto_tree_add_text.pl */
        { &hf_isis_lsp_mt_id_reserved,
            { "Reserved", "isis.lsp.reserved",
              FT_UINT16, BASE_HEX, NULL, ISIS_LSP_MT_MSHIP_RES_MASK,
            NULL, HFILL}
        },
        { &hf_isis_lsp_mt_id,
            { "Topology ID", "isis.lsp.mtid",
              FT_UINT16, BASE_DEC|BASE_RANGE_STRING, RVALS(mtid_strings), 0x0fff,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ip_reachability_ipv4_prefix,
            { "IPv4 prefix", "isis.lsp.ip_reachability.ipv4_prefix",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ip_reachability_default_metric,
            { "Default Metric", "isis.lsp.ip_reachability.default_metric",
              FT_UINT8, BASE_DEC, NULL, 0x3F,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ip_reachability_delay_metric,
            { "Delay Metric", "isis.lsp.ip_reachability.delay_metric",
              FT_UINT8, BASE_DEC, NULL, 0x3F,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ip_reachability_expense_metric,
            { "Expense Metric", "isis.lsp.ip_reachability.expense_metric",
              FT_UINT8, BASE_DEC, NULL, 0x3F,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ip_reachability_error_metric,
            { "Error Metric", "isis.lsp.ip_reachability.error_metric",
              FT_UINT8, BASE_DEC, NULL, 0x3F,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_ip_reachability_subclvs_len,
            { "SubCLV Length", "isis.lsp.ext_ip_reachability.subclvs_length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_ip_reachability_code,
            { "Code", "isis.lsp.ext_ip_reachability.code",
              FT_UINT8, BASE_DEC, VALS(isis_lsp_ext_ip_reachability_code_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_ip_reachability_len,
            { "Length", "isis.lsp.ext_ip_reachability.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_ip_reachability_prefix_flags,
            { "Flags", "isis.lsp.ext_ip_reachability.prefix_sid.flags",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_ip_reachability_prefix_re_adv_flag,
            { "Re-advertisement", "isis.lsp.ext_ip_reachability.prefix_sid.flags.r",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_ip_reachability_prefix_node_sid_flag,
            { "Node-SID", "isis.lsp.ext_ip_reachability.prefix_sid.flags.n",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_ip_reachability_prefix_nophp_flag,
            { "no-PHP", "isis.lsp.ext_ip_reachability.prefix_sid.flags.p",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_ip_reachability_prefix_expl_null_flag,
            { "Explicit-Null", "isis.lsp.ext_ip_reachability.prefix_sid.flags.e",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_ip_reachability_prefix_value_flag,
            { "Value", "isis.lsp.ext_ip_reachability.prefix_sid.flags.v",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x8,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_ip_reachability_prefix_local_flag,
            { "Local", "isis.lsp.ext_ip_reachability.prefix_sid.flags.l",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x4,
              NULL, HFILL }
        },
        { &hf_isis_lsp_32_bit_administrative_tag,
            { "32-Bit Administrative tag", "isis.lsp.32_bit_administrative_tag",
              FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_64_bit_administrative_tag,
            { "64-Bit Administrative tag", "isis.lsp.64_bit_administrative_tag",
              FT_UINT64, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_ip_reachability_ipv4_prefix,
            { "IPv4 prefix", "isis.lsp.ext_ip_reachability.ipv4_prefix",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_ip_reachability_metric,
            { "Metric", "isis.lsp.ext_ip_reachability.metric",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_ip_reachability_distribution,
            { "Distribution", "isis.lsp.ext_ip_reachability.distribution",
              FT_BOOLEAN, 8, TFS(&tfs_down_up), 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_ip_reachability_subtlv,
            { "Sub-TLV", "isis.lsp.ext_ip_reachability.subtlv",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_ip_reachability_prefix_length,
            { "Prefix Length", "isis.lsp.ext_ip_reachability.prefix_length",
              FT_UINT8, BASE_DEC, NULL, 0x3F,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_type,
            { "Type", "isis.lsp.grp.type",
              FT_UINT8, BASE_DEC, VALS(isis_lsp_grp_types), 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_macaddr_length,
            { "Length", "isis.lsp.grp_macaddr.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_macaddr_topology_id,
            { "Topology ID", "isis.lsp.grp_macaddr.mtid",
              FT_UINT16, BASE_DEC|BASE_RANGE_STRING, RVALS(mtid_strings), 0x0fff,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_macaddr_vlan_id,
            { "VLAN ID", "isis.lsp.grp_macaddr.vlan_id",
              FT_UINT16, BASE_DEC, NULL, 0x0fff,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_macaddr_number_of_records,
            { "Number of records", "isis.lsp.grp_macaddr.number_of_records",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_macaddr_number_of_sources,
            { "Number of sources", "isis.lsp.grp_macaddr.number_of_sources",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_macaddr_group_address,
            { "Group Address", "isis.lsp.grp_macaddr.group_address",
              FT_SYSTEM_ID, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_macaddr_source_address,
            { "Source Address", "isis.lsp.grp_macaddr.source_address",
              FT_SYSTEM_ID, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_ipv4addr_length,
            { "Length", "isis.lsp.grp_ipv4addr.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_ipv4addr_topology_id,
            { "Topology ID", "isis.lsp.grp_ipv4addr.mtid",
              FT_UINT16, BASE_DEC|BASE_RANGE_STRING, RVALS(mtid_strings), 0x0fff,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_ipv4addr_vlan_id,
            { "VLAN ID", "isis.lsp.grp_ipv4addr.vlan_id",
              FT_UINT16, BASE_DEC, NULL, 0x0fff,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_ipv4addr_number_of_records,
            { "Number of records", "isis.lsp.grp_ipv4addr.number_of_records",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_ipv4addr_number_of_sources,
            { "Number of sources", "isis.lsp.grp_ipv4addr.number_of_sources",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_ipv4addr_group_address,
            { "Group Address", "isis.lsp.grp_ipv4addr.group_address",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_ipv4addr_source_address,
            { "Source Address", "isis.lsp.grp_ipv4addr.source_address",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_ipv6addr_length,
            { "Length", "isis.lsp.grp_ipv6addr.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_ipv6addr_topology_id,
            { "Topology ID", "isis.lsp.grp_ipv6addr.mtid",
              FT_UINT16, BASE_DEC|BASE_RANGE_STRING, RVALS(mtid_strings), 0x0fff,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_ipv6addr_vlan_id,
            { "VLAN ID", "isis.lsp.grp_ipv6addr.vlan_id",
              FT_UINT16, BASE_DEC, NULL, 0x0fff,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_ipv6addr_number_of_records,
            { "Number of records", "isis.lsp.grp_ipv6addr.number_of_records",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_ipv6addr_number_of_sources,
            { "Number of sources", "isis.lsp.grp_ipv6addr.number_of_sources",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_ipv6addr_group_address,
            { "Group Address", "isis.lsp.grp_ipv6addr.group_address",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_ipv6addr_source_address,
            { "Source Address", "isis.lsp.grp_ipv6addr.source_address",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_grp_unknown_length,
            { "Length", "isis.lsp.grp_unknown.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_trill_affinity_tlv,
            { "Affinity Sub-TLV", "isis.lsp.rt_capable.trill.affinity_tlv",
              FT_BOOLEAN, 32 , TFS(&tfs_supported_not_supported), 0x80000000,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_trill_fgl_safe,
            { "FGL-safe", "isis.lsp.rt_capable.trill.fgl_safe",
              FT_BOOLEAN, 32 , TFS(&tfs_yes_no), 0x40000000,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_trill_caps,
            { "Other Capabilities", "isis.lsp.rt_capable.trill.caps",
              FT_BOOLEAN, 32 , TFS(&tfs_supported_not_supported), 0x3ffc0000,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_trill_flags,
            { "Extended Header Flags", "isis.lsp.rt_capable.trill.flags",
              FT_BOOLEAN, 32 , TFS(&tfs_supported_not_supported), 0x0003ffff,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_trill_maximum_version,
            { "Maximum version", "isis.lsp.rt_capable.trill.maximum_version",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_trees_nof_trees_to_compute,
            { "Nof. trees to compute", "isis.lsp.rt_capable.trees.nof_trees_to_compute",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_trees_maximum_nof_trees_to_compute,
            { "Maximum nof. trees to compute", "isis.lsp.rt_capable.trees.maximum_nof_trees_to_compute",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_trees_nof_trees_to_use,
            { "Nof. trees to use", "isis.lsp.rt_capable.trees.nof_trees_to_use",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_tree_root_id_starting_tree_no,
            { "Starting tree no", "isis.lsp.rt_capable.tree_root_id.starting_tree_no",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_tree_root_id_nickname,
            { "Nickname", "isis.lsp.rt_capable.tree_root_id.nickname",
              FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_nickname_nickname_priority,
            { "Nickname priority", "isis.lsp.rt_capable.nickname.nickname_priority",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_nickname_tree_root_priority,
            { "Tree root priority", "isis.lsp.rt_capable.nickname.tree_root_priority",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_nickname_nickname,
            { "Nickname", "isis.lsp.rt_capable.nickname.nickname",
              FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_interested_vlans_nickname,
            { "Nickname", "isis.lsp.rt_capable.interested_vlans.nickname",
              FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_interested_vlans_multicast_ipv4,
            { "IPv4 multicast router", "isis.lsp.rt_capable.interested_vlans.multicast_ipv4",
              FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x8000,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_interested_vlans_multicast_ipv6,
            { "IPv6 multicast router", "isis.lsp.rt_capable.interested_vlans.multicast_ipv6",
              FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x4000,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_interested_vlans_vlan_start_id,
            { "Vlan start id", "isis.lsp.rt_capable.interested_vlans.vlan_start_id",
              FT_UINT16, BASE_DEC, NULL, 0x0fff,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_interested_vlans_vlan_end_id,
            { "Vlan end id", "isis.lsp.rt_capable.interested_vlans.vlan_end_id",
              FT_UINT16, BASE_DEC, NULL, 0x0fff,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_interested_vlans_afs_lost_counter,
            { "Appointed forward state lost counter", "isis.lsp.rt_capable.interested_vlans.afs_lost_counter",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_tree_used_id_starting_tree_no,
            { "Starting tree no", "isis.lsp.rt_capable.tree_used_id.starting_tree_no",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_tree_used_id_nickname,
            { "Nickname", "isis.lsp.rt_capable.tree_used_id.nickname",
              FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_vlan_group_primary_vlan_id,
            { "Primary vlan id", "isis.lsp.rt_capable.vlan_group.primary_vlan_id",
              FT_UINT16, BASE_DEC, NULL, 0x0fff,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_vlan_group_secondary_vlan_id,
            { "Secondary vlan id", "isis.lsp.rt_capable.vlan_group.secondary_vlan_id",
              FT_UINT16, BASE_DEC, NULL, 0x0fff,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ipv6_reachability_subclvs_len,
            { "SubCLV Length", "isis.lsp.ipv6_reachability.subclvs_length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ipv6_reachability_ipv6_prefix,
            { "IPv6 prefix", "isis.lsp.ipv6_reachability.ipv6_prefix",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ipv6_reachability_metric,
            { "Metric", "isis.lsp.ipv6_reachability.metric",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ipv6_reachability_distribution,
            { "Distribution", "isis.lsp.ipv6_reachability.distribution",
              FT_BOOLEAN, 8, TFS(&tfs_down_up), 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ipv6_reachability_distribution_internal,
            { "Distribution", "isis.lsp.ipv6_reachability.distribution_internal",
              FT_BOOLEAN, 8, TFS(&tfs_external_internal), 0x40,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ipv6_reachability_subtlv,
            { "Sub-TLV", "isis.lsp.ipv6_reachability.subtlv",
              FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ipv6_reachability_reserved_bits,
            { "Reserved bits", "isis.lsp.ipv6_reachability.reserved_bits",
              FT_UINT8, BASE_HEX, NULL, 0x1F,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ipv6_reachability_prefix_length,
            { "Prefix Length", "isis.lsp.ipv6_reachability.prefix_length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        /* rfc7794 */
        { &hf_isis_lsp_prefix_attr_flags,
            { "Flags", "isis.lsp.prefix_attribute.flags",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_prefix_attr_flags_x,
            { "External Prefix", "isis.lsp.prefix_attribute.flags.x",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), ISIS_LSP_PFX_ATTR_FLAG_X,
              NULL, HFILL }
        },
        { &hf_isis_lsp_prefix_attr_flags_r,
            { "Re-advertisement", "isis.lsp.prefix_attribute.flags.r",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), ISIS_LSP_PFX_ATTR_FLAG_R,
              NULL, HFILL }
        },
        { &hf_isis_lsp_prefix_attr_flags_n,
            { "Node", "isis.lsp.prefix_attribute.flags.n",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), ISIS_LSP_PFX_ATTR_FLAG_N,
              NULL, HFILL }
        },

        { &hf_isis_lsp_mt_cap_spb_instance_cist_root_identifier,
            { "CIST Root Identifier", "isis.lsp.mt_cap_spb_instance.cist_root_identifier",
              FT_BYTES, SEP_DASH, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_spb_instance_cist_external_root_path_cost,
            { "CIST External Root Path Cost", "isis.lsp.mt_cap_spb_instance.cist_external_root_path_cost",
              FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_spb_instance_bridge_priority,
            { "Bridge Priority", "isis.lsp.mt_cap_spb_instance.bridge_priority",
              FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_spb_instance_v,
            { "V", "isis.lsp.mt_cap_spb_instance.v",
              FT_BOOLEAN, 32, NULL, 0x00100000,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_spb_instance_number_of_trees,
            { "Number of Trees", "isis.lsp.mt_cap_spb_instance.number_of_trees",
              FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_u,
            { "U", "isis.lsp.mt_cap_spb_instance.vlanid_tuple.u",
              FT_BOOLEAN, 8, NULL, 0x80,
              "Set if this bridge is currently using this ECT-ALGORITHM for I-SIDs it sources or sinks", HFILL }
        },
        { &hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_m,
            { "M", "isis.lsp.mt_cap_spb_instance.vlanid_tuple.m",
              FT_BOOLEAN, 8, NULL, 0x40,
              "indicates if this is SPBM or SPBV mode", HFILL }
        },
        { &hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_a,
            { "A", "isis.lsp.mt_cap_spb_instance.vlanid_tuple.a",
              FT_BOOLEAN, 8, NULL, 0x20,
              "When set, declares this is an SPVID with auto-allocation", HFILL }
        },
        { &hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_reserved,
            { "Reserved", "isis.lsp.mt_cap_spb_instance.vlanid_tuple.reserved",
              FT_UINT8, BASE_HEX, NULL, 0x1F,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_ect,
            { "ECT-ALGORITHM", "isis.lsp.mt_cap_spb_instance.vlanid_tuple.ect",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_base_vid,
            { "Base VID", "isis.lsp.mt_cap_spb_instance.vlanid_tuple.basevid",
              FT_UINT24, BASE_DEC, NULL, 0xFFF000,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_spb_instance_vlanid_tuple_spvid,
            { "SPVID", "isis.lsp.mt_cap_spb_instance.vlanid_tuple.spvid",
              FT_UINT24, BASE_DEC, NULL, 0x000FFF,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_spb_opaque_algorithm,
            { "Algorithm", "isis.lsp.mt_cap_spb_opaque.algorithm",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_spb_opaque_information,
            { "information", "isis.lsp.mt_cap_spb_opaque.information",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_spbm_service_identifier_b_mac,
            { "B-MAC", "isis.lsp.mt_cap_spbm_service_identifier.b_mac",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_spbm_service_identifier_base_vid,
            { "Base-VID", "isis.lsp.mt_cap_spbm_service_identifier.base_vid",
              FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_spbm_service_identifier_t,
            { "T", "isis.lsp.mt_cap_spbm_service_identifier.t",
              FT_BOOLEAN, 8, NULL, 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_spbm_service_identifier_r,
            { "R", "isis.lsp.mt_cap_spbm_service_identifier.r",
              FT_BOOLEAN, 8, NULL, 0x40,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_spbm_service_identifier_reserved,
            { "Reserved", "isis.lsp.mt_cap_spbm_service_identifier.reserved",
              FT_UINT8, BASE_HEX, NULL, 0x3F,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_spbm_service_identifier_i_sid,
            { "I-SID", "isis.lsp.mt_cap_spbm_service_identifier.i_sid",
              FT_UINT24, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_mtid,
            { "Topology ID", "isis.lsp.mt_cap.mtid",
              FT_UINT16, BASE_DEC|BASE_RANGE_STRING, RVALS(mtid_strings), 0x0fff,
              NULL, HFILL }
        },
        { &hf_isis_lsp_eis_neighbors_reserved,
            { "Reserved", "isis.lsp.eis_neighbors_clv_inner.reserved",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_eis_neighbors_es_neighbor_id,
            { "ES Neighbor ID", "isis.lsp.eis_neighbors.es_neighbor_id",
              FT_SYSTEM_ID, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_eis_neighbors_is_neighbor_id,
            { "IS Neighbor", "isis.lsp.eis_neighbors.is_neighbor",
              FT_SYSTEM_ID, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_eis_neighbors_default_metric,
            { "Default Metric", "isis.lsp.eis_neighbors.default_metric",
              FT_UINT8, BASE_DEC, NULL, 0x3F,
              NULL, HFILL }
        },
        { &hf_isis_lsp_eis_neighbors_delay_metric,
            { "Delay Metric", "isis.lsp.eis_neighbors.delay_metric",
              FT_UINT8, BASE_DEC, NULL, 0x3F,
              NULL, HFILL }
        },
        { &hf_isis_lsp_eis_neighbors_expense_metric,
            { "Expense Metric", "isis.lsp.eis_neighbors.expense_metric",
              FT_UINT8, BASE_DEC, NULL, 0x3F,
              NULL, HFILL }
        },
        { &hf_isis_lsp_eis_neighbors_error_metric,
            { "Error Metric", "isis.lsp.eis_neighbors.error_metric",
              FT_UINT8, BASE_DEC, NULL, 0x3F,
              NULL, HFILL }
        },
        { &hf_isis_lsp_maximum_link_bandwidth,
            { "Maximum link bandwidth", "isis.lsp.maximum_link_bandwidth",
              FT_FLOAT, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_reservable_link_bandwidth,
            { "Reservable link bandwidth", "isis.lsp.reservable_link_bandwidth",
              FT_FLOAT, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_is_neighbor_id,
            { "IS neighbor ID", "isis.lsp.ext_is_reachability.is_neighbor_id",
              FT_SYSTEM_ID, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_metric,
            { "Metric", "isis.lsp.ext_is_reachability.metric",
              FT_UINT24, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_subclvs_len,
            { "SubCLV Length", "isis.lsp.ext_is_reachability.subclvs_length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_code,
            { "Code", "isis.lsp.ext_is_reachability.code",
              FT_UINT8, BASE_DEC, VALS(isis_lsp_ext_is_reachability_code_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_len,
            { "Length", "isis.lsp.ext_is_reachability.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_value,
            { "Value", "isis.lsp.ext_is_reachability.value",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_link_local_identifier,
            { "Link Local Identifier", "isis.lsp.ext_is_reachability.link_local_identifier",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_link_remote_identifier,
            { "Link Remote Identifier", "isis.lsp.ext_is_reachability.link_remote_identifier",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_ipv4_interface_address,
            { "IPv4 interface address", "isis.lsp.ext_is_reachability.ipv4_interface_address",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_ipv4_neighbor_address,
            { "IPv4 neighbor address", "isis.lsp.ext_is_reachability.ipv4_neighbor_address",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_traffic_engineering_default_metric,
            { "Traffic engineering default metric", "isis.lsp.ext_is_reachability.traffic_engineering_default_metric",
              FT_UINT24, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        /* rfc8570 */
        { &hf_isis_lsp_ext_is_reachability_unidir_link_flags,
            { "Flags", "isis.lsp.ext_is_reachability.unidirectional_link_flags",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_unidir_link_flags_a,
            { "Anomalous bit", "isis.lsp.ext_is_reachability.unidirectional_link_flags.a",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_unidir_link_reserved,
            { "Reserved", "isis.lsp.ext_is_reachability.unidirectional_link_reserved",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_unidir_link_delay,
            { "Delay", "isis.lsp.ext_is_reachability.unidirectional_link_delay",
              FT_UINT24, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_unidir_link_delay_min,
            { "Min Delay", "isis.lsp.ext_is_reachability.unidirectional_link_delay_min",
              FT_UINT24, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_unidir_link_delay_max,
            { "Max Delay", "isis.lsp.ext_is_reachability.unidirectional_link_delay_max",
              FT_UINT24, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_unidir_delay_variation,
            { "Delay Variation", "isis.lsp.ext_is_reachability.unidirectional_delay_variation",
              FT_UINT24, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_unidir_link_loss,
            { "Link Loss", "isis.lsp.ext_is_reachability.unidirectional_link_loss",
              FT_UINT24, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_unidir_residual_bandwidth,
            { "Residual Bandwidth", "isis.lsp.ext_is_reachability.unidirectional_residual_bandwidth",
              FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_unidir_available_bandwidth,
            { "Available Bandwidth", "isis.lsp.ext_is_reachability.unidirectional_available_bandwidth",
              FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_unidir_utilized_bandwidth,
            { "Utilized Bandwidth", "isis.lsp.ext_is_reachability.unidirectional_utilized_bandwidth",
              FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_partition_designated_l2_is,
            { "Partition designated L2 IS", "isis.lsp.partition_designated_l2_is",
              FT_SYSTEM_ID, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_originating_lsp_buffer_size,
            { "Neighbor originating buffer size", "isis.lsp.originating_lsp_buffer_size",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_error_metric,
            { "Error metric", "isis.lsp.error_metric",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
              NULL, HFILL }
        },
        { &hf_isis_lsp_expense_metric,
            { "Expense metric", "isis.lsp.expense_metric",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
              NULL, HFILL }
        },
        { &hf_isis_lsp_delay_metric,
            { "Delay metric", "isis.lsp.delay_metric",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
              NULL, HFILL }
        },
        { &hf_isis_lsp_default_metric,
            { "Default metric", "isis.lsp.default_metric",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ip_reachability_default_metric_ie,
            { "Default Metric IE", "isis.lsp.ip_reachability.default_metric_ie",
              FT_BOOLEAN, 8, TFS(&tfs_external_internal), 0x40,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ip_reachability_delay_metric_support,
            { "Delay Metric", "isis.lsp.ip_reachability.delay_metric_support",
              FT_BOOLEAN, 8, TFS(&tfs_not_supported_supported), 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ip_reachability_expense_metric_support,
            { "Expense Metric", "isis.lsp.ip_reachability.expense_metric_support",
              FT_BOOLEAN, 8, TFS(&tfs_not_supported_supported), 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ip_reachability_error_metric_support,
            { "Error Metric", "isis.lsp.ip_reachability.error_metric_support",
              FT_BOOLEAN, 8, TFS(&tfs_not_supported_supported), 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_spsourceid,
            { "SPSourceId", "isis.lsp.mt_cap.spsourceid",
              FT_UINT32, BASE_HEX_DEC, NULL, 0x000fffff,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mt_cap_overload,
            { "Overload", "isis.lsp.overload",
              FT_BOOLEAN, 16, NULL, 0x8000,
              NULL, HFILL }
        },
        { &hf_isis_lsp_eis_neighbors_default_metric_ie,
            { "Default Metric", "isis.lsp.eis_neighbors.default_metric_ie",
              FT_BOOLEAN, 8, TFS(&tfs_external_internal), 0x40,
              NULL, HFILL }
        },
        { &hf_isis_lsp_eis_neighbors_delay_metric_supported,
            { "Delay Metric", "isis.lsp.eis_neighbors_delay_metric.supported",
              FT_BOOLEAN, 8, TFS(&tfs_not_supported_supported), 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_eis_neighbors_expense_metric_supported,
            { "Expense Metric", "isis.lsp.eis_neighbors.expense_metric_supported",
              FT_BOOLEAN, 8, TFS(&tfs_not_supported_supported), 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_eis_neighbors_error_metric_supported,
            { "Error Metric", "isis.lsp.eis_neighbors.error_metric_supported",
              FT_BOOLEAN, 8, TFS(&tfs_not_supported_supported), 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_unrsv_bw_priority_level,
            { "priority level", "isis.lsp.unrsv_bw.priority_level",
              FT_FLOAT, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ip_reachability_distribution,
            { "Distribution", "isis.lsp.ip_reachability.distribution",
              FT_BOOLEAN, 8, TFS(&tfs_down_up), 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ip_reachability_delay_metric_ie,
            { "Delay Metric", "isis.lsp.ip_reachability.delay_metric_ie",
              FT_BOOLEAN, 8, TFS(&tfs_external_internal), 0x40,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ip_reachability_expense_metric_ie,
            { "Expense Metric", "isis.lsp.ip_reachability.expense_metric_ie",
              FT_BOOLEAN, 8, TFS(&tfs_external_internal), 0x40,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ip_reachability_error_metric_ie,
            { "Error Metric", "isis.lsp.ip_reachability.error_metric_ie",
              FT_BOOLEAN, 8, TFS(&tfs_external_internal), 0x40,
              NULL, HFILL }
        },
        { &hf_isis_lsp_eis_neighbors_delay_metric_ie,
            { "Delay Metric", "isis.lsp.eis_neighbors.delay_metric_ie",
              FT_BOOLEAN, 8, TFS(&tfs_external_internal), 0x40,
              NULL, HFILL }
        },
        { &hf_isis_lsp_eis_neighbors_expense_metric_ie,
            { "Expense Metric", "isis.lsp.eis_neighbors.expense_metric_ie",
              FT_BOOLEAN, 8, TFS(&tfs_external_internal), 0x40,
              NULL, HFILL }
        },
        { &hf_isis_lsp_eis_neighbors_error_metric_ie,
            { "Error Metric", "isis.lsp.eis_neighbors.error_metric_ie",
              FT_BOOLEAN, 8, TFS(&tfs_external_internal), 0x40,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_router_id,
            { "Router ID", "isis.lsp.rt_capable.router_id",
              FT_UINT32, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_flag_s,
            { "S bit", "isis.lsp.rt_capable.flag_s",
              FT_BOOLEAN, 8, NULL, 0x01,
              NULL, HFILL }
        },
        { &hf_isis_lsp_rt_capable_flag_d,
            { "D bit", "isis.lsp.rt_capable.flag_d",
              FT_BOOLEAN, 8, NULL, 0x02,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_te_node_cap_b_bit,
            { "B bit: P2MP Branch LSR capability", "isis.lsp.te_node_cap.b_bit",
              FT_BOOLEAN, 8, NULL, 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_te_node_cap_e_bit,
            { "E bit: P2MP Bud LSR capability", "isis.lsp.te_node_cap.e_bit",
              FT_BOOLEAN, 8, NULL, 0x40,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_te_node_cap_m_bit,
            { "M bit: MPLS-TE support", "isis.lsp.te_node_cap.m_bit",
              FT_BOOLEAN, 8, NULL, 0x20,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_te_node_cap_g_bit,
            { "G bit: GMPLS support", "isis.lsp.te_node_cap.g_bit",
              FT_BOOLEAN, 8, NULL, 0x10,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_te_node_cap_p_bit,
            { "P bit: P2MP RSVP-TE support", "isis.lsp.te_node_cap.p_bit",
              FT_BOOLEAN, 8, NULL, 0x08,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_sr_cap_i_flag,
            { "I flag: IPv4 support", "isis.lsp.sr_cap.i_flag",
              FT_BOOLEAN, 8, NULL, 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_sr_cap_v_flag,
          { "V flag: IPv6 support", "isis.lsp.sr_cap.v_flag",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_isis_lsp_clv_sr_cap_range,
          { "Range", "isis.lsp.sr_cap.range",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isis_lsp_clv_sr_cap_sid,
          { "SID", "isis.lsp.sr_cap.sid",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isis_lsp_clv_sr_cap_label,
          { "Label", "isis.lsp.sr_cap.label",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isis_lsp_clv_sr_alg,
          { "Algorithm", "isis.lsp.sr_alg",
            FT_UINT8, BASE_DEC, VALS(isis_igp_alg_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_isis_lsp_clv_sr_lb_flags,
          { "Flags", "isis.lsp.sr_local_block.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_cap_flags,
            { "Flags", "isis.lsp.srv6_cap.flags",
              FT_UINT16, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_cap_flags_o,
            { "OAM flag", "isis.lsp.srv6_cap.flags.o",
              FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x4000,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_cap_flags_reserved,
            { "Reserved", "isis.lsp.srv6_cap.flags.reserved",
              FT_UINT16, BASE_HEX, NULL, 0x3fff,
              NULL, HFILL }
        },

        { &hf_isis_lsp_srv6_loc_metric,
            { "Metric", "isis.lsp.srv6_locator.metric",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_srv6_loc_flags,
            { "Flags", "isis.lsp.srv6_locator.flags",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_srv6_loc_flags_d,
            { "Down flag", "isis.lsp.srv6_locator.flags.d",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_srv6_loc_flags_reserved,
            { "Reserved", "isis.lsp.srv6_locator.flags.reserved",
              FT_UINT8, BASE_HEX, NULL, 0x7f,
              NULL, HFILL }
        },
        { &hf_isis_lsp_srv6_loc_alg,
            { "Algorithm", "isis.lsp.srv6_locator.algorithm",
              FT_UINT8, BASE_DEC, VALS(isis_igp_alg_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_srv6_loc_size,
            { "Locator Size", "isis.lsp.srv6_locator.locator_size",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_srv6_loc_locator,
            { "Locator", "isis.lsp.srv6_locator.locator",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_srv6_loc_subclvs_len,
            { "SubCLV Length", "isis.lsp.srv6_locator.subclvs_length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_srv6_loc_sub_tlv_type,
            { "Code", "isis.lsp.srv6_locator.sub_tlv_type",
              FT_UINT8, BASE_DEC, VALS(isis_lsp_srv6_loc_sub_tlv_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_srv6_loc_sub_tlv_length,
            { "Length", "isis.lsp.srv6_locator.sub_tlv_length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_clv_srv6_end_sid_flags,
            { "Flags", "isis.lsp.srv6_end_sid.flags",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_end_sid_endpoint_behavior,
            { "Endpoint Behavior", "isis.lsp.srv6_end_sid.endpoint_behavior",
              FT_UINT16, BASE_DEC, VALS(srv6_endpoint_type_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_end_sid_sid,
            { "SID", "isis.lsp.srv6_end_sid.sid",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_end_sid_subsubclvs_len,
            { "SubSubCLV Length", "isis.lsp.srv6_end_sid.subsubclvs_length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_clv_srv6_endx_sid_system_id,
            { "System-ID", "isis.lsp.srv6_endx_sid.system_id",
              FT_SYSTEM_ID, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_endx_sid_flags,
            { "Flags", "isis.lsp.srv6_endx_sid.flags",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_endx_sid_flags_b,
            { "Backup flag", "isis.lsp.srv6_endx_sid.flags.b",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_endx_sid_flags_s,
            { "Set flag", "isis.lsp.srv6_endx_sid.flags.s",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_endx_sid_flags_p,
            { "Persistent flag", "isis.lsp.srv6_endx_sid.flags.p",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_endx_sid_flags_reserved,
            { "Reserved", "isis.lsp.srv6_endx_sid.flags.reserved",
              FT_UINT8, BASE_HEX, NULL, 0x1f,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_endx_sid_alg,
          { "Algorithm", "isis.lsp.srv6_endx_sid.algorithm",
            FT_UINT8, BASE_DEC, VALS(isis_igp_alg_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_endx_sid_weight,
            { "Weight", "isis.lsp.srv6_endx_sid.weight",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_endx_sid_endpoint_behavior,
            { "Endpoint Behavior", "isis.lsp.srv6_endx_sid.endpoint_behavior",
              FT_UINT16, BASE_DEC, VALS(srv6_endpoint_type_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_endx_sid_sid,
            { "SID", "isis.lsp.srv6_endx_sid.sid",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_endx_sid_subsubclvs_len,
            { "SubSubCLV Length", "isis.lsp.srv6_endx_sid.subsubclvs_length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        /* rfc9352 */
        { &hf_isis_lsp_clv_srv6_sid_struct_lb_len,
            { "Locator Block Length", "isis.lsp.srv6_sid_struct.lb_length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_sid_struct_ln_len,
            { "Locator Node Length", "isis.lsp.srv6_sid_struct.ln_length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_sid_struct_fun_len,
            { "Function Length", "isis.lsp.srv6_sid_struct.fun_length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_srv6_sid_struct_arg_len,
            { "Arguments Length", "isis.lsp.srv6_sid_struct.arg_length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        /* rfc8491 */
        { &hf_isis_lsp_clv_igp_msd_type,
          { "MSD Type", "isis.lsp.igp_msd_type",
            FT_UINT8, BASE_DEC, VALS(isis_lsp_igp_msd_types), 0x0,
            NULL, HFILL }
        },
        { &hf_isis_lsp_clv_igp_msd_value,
          { "MSD Value", "isis.lsp.igp_msd_value",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        /* rfc7308 */
        { &hf_isis_lsp_clv_ext_admin_group,
            { "Extended Admin Group", "isis.lsp.extended_admin_group",
              FT_UINT32, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },

        /* rfc8919 */
        { &hf_isis_lsp_clv_app_sabm_legacy,
          { "Legacy flag (L)", "isis.lsp.application.sabm.legacy",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
            NULL, HFILL }
        },
        { &hf_isis_lsp_clv_app_sabm_length,
          { "SABM Length", "isis.lsp.application.sabm.length",
            FT_UINT8, BASE_DEC, NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_isis_lsp_clv_app_udabm_reserved,
          { "Reserved (R)", "isis.lsp.application.udabm.reserved",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
            NULL, HFILL }
        },
        { &hf_isis_lsp_clv_app_udabm_length,
          { "UDABM Length", "isis.lsp.application.udabm.length",
            FT_UINT8, BASE_DEC, NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_isis_lsp_clv_app_sabm_bits,
            { "Standard Application Identifier Bit Mask", "isis.lsp.application.sabm.bits",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_app_sabm_bits_r,
            { "RSVP-TE bit (R)", "isis.lsp.application.sabm.bits.r",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_app_sabm_bits_s,
            { "Segment Routing Policy bit (S)", "isis.lsp.application.sabm.bits.s",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_app_sabm_bits_f,
            { "Loop-Free Alternate (LFA) bit (F)", "isis.lsp.application.sabm.bits.f",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_app_sabm_bits_x,
            { "Flexible Algorithm bit (X)", "isis.lsp.application.sabm.bits.x",
              FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_app_udabm_bits,
          { "User-Defined Application Identifier Bit Mask", "isis.lsp.application.udabm.bits",
            FT_BYTES, SEP_SPACE, NULL, 0x0,
            NULL, HFILL }
        },

        /* draft-ietf-lsr-flex-algo-16 */
        { &hf_isis_lsp_clv_flex_algo_algorithm,
          { "Flex-Algorithm", "isis.lsp.flex_algorithm.algorithm",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isis_lsp_clv_flex_algo_metric_type,
          { "Metric-Type", "isis.lsp.flex_algorithm.metric_type",
            FT_UINT8, BASE_DEC, VALS(isis_lsp_flex_algo_metric_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_isis_lsp_clv_flex_algo_calc_type,
          { "Calculation-Type", "isis.lsp.flex_algorithm.calculation_type",
            FT_UINT8, BASE_DEC, VALS(isis_igp_alg_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_isis_lsp_clv_flex_algo_priority,
          { "Priority", "isis.lsp.flex_algorithm.priority",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        /* rfc6232 */
        { &hf_isis_lsp_purge_orig_id_num,
            { "Number of System IDs", "isis.lsp.purge_originator_id.num",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_purge_orig_id_system_id,
            { "System ID", "isis.lsp.purge_originator_id.system_id",
              FT_SYSTEM_ID, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        { &hf_isis_lsp_area_address,
            { "Area address", "isis.lsp.area_address",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_instance_identifier,
            { "Instance Identifier", "isis.lsp.iid",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_isis_lsp_supported_itid,
            { "Supported ITID", "isis.lsp.supported_itid",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_nlpid_nlpid,
            { "NLPID", "isis.lsp.clv_nlpid.nlpid",
              FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ip_authentication,
            { "IP Authentication", "isis.lsp.ip_authentication",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_authentication,
            { "Authentication", "isis.lsp.authentication",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_area_address_str,
            { "Area address", "isis.lsp.area_address_str",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_is_virtual,
            { "IsVirtual", "isis.lsp.is_virtual",
              FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_group,
          { "Group", "isis.lsp.group",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isis_lsp_default,
          { "Default metric", "isis.lsp.default",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_isis_lsp_default_support,
          { "Default metric supported", "isis.lsp.default_support",
            FT_BOOLEAN, 8, TFS(&tfs_no_yes), 0x80,
            NULL, HFILL }
        },
        { &hf_isis_lsp_delay,
          { "Delay metric", "isis.lsp.delay",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_isis_lsp_delay_support,
          { "Delay metric supported", "isis.lsp.delay_support",
            FT_BOOLEAN, 8, TFS(&tfs_no_yes), 0x80,
            NULL, HFILL }
        },
        { &hf_isis_lsp_expense,
          { "Expense metric", "isis.lsp.expense",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_isis_lsp_expense_support,
          { "Expense metric supported", "isis.lsp.expense_support",
            FT_BOOLEAN, 8, TFS(&tfs_no_yes), 0x80,
            NULL, HFILL }
        },
        { &hf_isis_lsp_error,
          { "Error metric", "isis.lsp.error",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_isis_lsp_error_support,
          { "Error metric supported", "isis.lsp.error_support",
            FT_BOOLEAN, 8, TFS(&tfs_no_yes), 0x80,
            NULL, HFILL }
        },

        /* rfc6119 */
        { &hf_isis_lsp_clv_ipv6_te_router_id,
            { "IPv6 TE Router ID", "isis.lsp.clv_ipv6_te_router_id",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              "IPv6 Traffic Engineering Router ID", HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_ipv6_interface_address,
            { "IPv6 interface address", "isis.lsp.ext_is_reachability.ipv6_interface_address",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_ext_is_reachability_ipv6_neighbor_address,
            { "IPv6 neighbor address", "isis.lsp.ext_is_reachability.ipv6_neighbor_address",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_bier_alg,
          { "BIER Algorithm", "isis.lsp.bier_alg",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(isis_lsp_bier_alg_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_isis_lsp_clv_bier_igp_alg,
          { "IGP Algorithm", "isis.lsp.bier_igp_alg",
            FT_UINT8, BASE_DEC, VALS(isis_igp_alg_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_isis_lsp_clv_bier_subdomain,
            { "BIER sub-domain", "isis.lsp.bier_subdomain",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_bier_bfrid,
            { "BFR-id", "isis.lsp.bier_bfrid",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_bier_subsub_type,
            { "Type", "isis.lsp.bier.subsub.type",
              FT_UINT8, BASE_DEC, VALS(isis_lsp_bier_subsubtlv_type_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_bier_subsub_len,
            { "Length", "isis.lsp.bier.subsub.length",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_bier_subsub_mplsencap_maxsi,
            { "Maximum Set Identifier", "isis.lsp.bier.subsub.mplsencap.maxsi",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_bier_subsub_mplsencap_bslen,
            { "BitString Length", "isis.lsp.bier.subsub.mplsencap.bslen",
              FT_UINT8, BASE_DEC, NULL, 0xF0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_clv_bier_subsub_mplsencap_label,
            { "Label", "isis.lsp.bier.subsub.mplsencap.label",
              FT_UINT24, BASE_DEC, NULL, 0x0FFFFF,
              NULL, HFILL }
        },
        /* rfc 6165 */
        { &hf_isis_lsp_mac_reachability_topoid_nick,
            { "Topology-id/Nickname", "isis.lsp.mac_reachability.topoid_nick",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mac_reachability_confidence,
            { "Confidence", "isis.lsp.mac_reachability.confidence",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mac_reachability_reserved,
            { "Reserved", "isis.lsp.mac_reachability.reserved",
              FT_UINT16, BASE_DEC, NULL, 0xf000,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mac_reachability_vlan,
            { "VLAN-ID", "isis.lsp.mac_reachability.vlan",
              FT_UINT16, BASE_DEC, NULL, 0x0fff,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mac_reachability_mac,
            { "MAC Address", "isis.lsp.mac_reachability.mac",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mac_reachability_chassismac,
            { "Chassis MAC", "isis.lsp.mac_reachability.chassismac",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_mac_reachability_fanmcast,
            { "FAN Mcast", "isis.lsp.mac_reachability.fanmcast",
              FT_ETHER, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
	/* Avaya proprietary */
        { &hf_isis_lsp_avaya_ipvpn_unknown,
            { "Unknown", "isis.lsp.avaya.ipvpn.unknown",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_avaya_ipvpn_system_id,
            { "System-ID", "isis.lsp.avaya.ipvpn.system_id",
              FT_SYSTEM_ID, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_avaya_ipvpn_vrfsid,
            { "Vrf I-SID", "isis.lsp.avaya.ipvpn.vrfsid",
              FT_UINT24, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_avaya_ipvpn_subtlvbytes,
            { "SubTLV Bytes", "isis.lsp.avaya.ipvpn.subtlvbytes",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_avaya_ipvpn_subtlvtype,
            { "SubTLV Type", "isis.lsp.avaya.ipvpn.subtlvtype",
              FT_UINT8, BASE_DEC, VALS(isis_lsp_avaya_ipvpn_subtlv_code_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_avaya_ipvpn_subtlvlength,
            { "SubTLV Length", "isis.lsp.avaya.ipvpn.subtlvlength",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_avaya_ipvpn_unknown_sub,
            { "Unknown", "isis.lsp.avaya.ipvpn.sub.unknown",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_avaya_ipvpn_ipv4_metric,
            { "Metric", "isis.lsp.avaya.ipvpn.ipv4.metric",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_avaya_ipvpn_ipv4_metrictype,
            { "Metric Type", "isis.lsp.avaya.ipvpn.ipv4.metrictype",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_avaya_ipvpn_ipv4_addr,
            { "IPv4 Address", "isis.lsp.avaya.ipvpn.ipv4.address",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_avaya_ipvpn_ipv4_mask,
            { "IPv4 Mask", "isis.lsp.avaya.ipvpn.ipv4.mask",
              FT_IPv4, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_avaya_ipvpn_ipv6_metric,
            { "Metric", "isis.lsp.avaya.ipvpn.ipv6.metric",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_avaya_ipvpn_ipv6_prefixlen,
            { "Prefix length", "isis.lsp.avaya.ipvpn.ipv6.prefixlen",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_avaya_ipvpn_ipv6_prefix,
            { "Prefix", "isis.lsp.avaya.ipvpn.ipv6.prefix",
              FT_IPv6, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_avaya_185_unknown,
            { "Unknown", "isis.lsp.avaya.185.unknown",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_isis_lsp_avaya_186_unknown,
            { "Unknown", "isis.lsp.avaya.186.unknown",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
    };
    static int *ett[] = {
        &ett_isis_lsp,
        &ett_isis_lsp_info,
        &ett_isis_lsp_att,
        &ett_isis_lsp_cksum,
        &ett_isis_lsp_clv_area_addr,
        &ett_isis_lsp_clv_is_neighbors,
        &ett_isis_lsp_clv_instance_identifier,
        &ett_isis_lsp_clv_ext_is_reachability, /* CLV 22 */
        &ett_isis_lsp_part_of_clv_ext_is_reachability,
        &ett_isis_lsp_part_of_clv_ext_is_reachability_subtlv,
        &ett_isis_lsp_subclv_admin_group,
        &ett_isis_lsp_subclv_unrsv_bw,
        &ett_isis_lsp_subclv_bw_ct,
        &ett_isis_lsp_subclv_spb_link_metric,
        &ett_isis_lsp_adj_sid_flags,
        &ett_isis_lsp_clv_unknown,
        &ett_isis_lsp_clv_partition_dis,
        &ett_isis_lsp_clv_prefix_neighbors,
        &ett_isis_lsp_clv_authentication,
        &ett_isis_lsp_clv_ip_authentication,
        &ett_isis_lsp_clv_nlpid_nlpid,
        &ett_isis_lsp_clv_hostname,
        &ett_isis_lsp_clv_srlg,
        &ett_isis_lsp_clv_ipv4_int_addr,
        &ett_isis_lsp_clv_ipv6_int_addr, /* CLV 232 */
        &ett_isis_lsp_clv_mt_cap,
        &ett_isis_lsp_clv_mt_cap_spb_instance,
        &ett_isis_lsp_clv_mt_cap_spbm_service_identifier,
        &ett_isis_lsp_clv_mt_cap_spbv_mac_address,
        &ett_isis_lsp_clv_sid_label_binding,
        &ett_isis_lsp_clv_te_router_id,
        &ett_isis_lsp_clv_ip_reachability,
        &ett_isis_lsp_clv_ip_reach_subclv,
        &ett_isis_lsp_clv_ext_ip_reachability, /* CLV 135 */
        &ett_isis_lsp_part_of_clv_ext_ip_reachability,
        &ett_isis_lsp_prefix_sid_flags,
        &ett_isis_lsp_prefix_attr_flags,
        &ett_isis_lsp_clv_ipv6_reachability, /* CLV 236 */
        &ett_isis_lsp_part_of_clv_ipv6_reachability,
        &ett_isis_lsp_clv_mt,
        &ett_isis_lsp_clv_mt_is,
        &ett_isis_lsp_part_of_clv_mt_is,
        &ett_isis_lsp_clv_rt_capable, /*CLV 242*/
        &ett_isis_lsp_clv_te_node_cap_desc,
        &ett_isis_lsp_clv_trill_version,
        &ett_isis_lsp_clv_trees,
        &ett_isis_lsp_clv_root_id,
        &ett_isis_lsp_clv_nickname,
        &ett_isis_lsp_clv_interested_vlans,
        &ett_isis_lsp_clv_tree_used,
        &ett_isis_lsp_clv_vlan_group,
        &ett_isis_lsp_clv_grp_address, /*CLV 142*/
        &ett_isis_lsp_clv_grp_macaddr,
        &ett_isis_lsp_clv_grp_ipv4addr,
        &ett_isis_lsp_clv_grp_ipv6addr,
        &ett_isis_lsp_clv_grp_unknown,
        &ett_isis_lsp_clv_mt_reachable_IPv4_prefx,
        &ett_isis_lsp_clv_mt_reachable_IPv6_prefx,
        &ett_isis_lsp_clv_purge_orig_id, /* CLV 13 */
        &ett_isis_lsp_clv_originating_buff_size, /* CLV 14 */
        &ett_isis_lsp_clv_sr_cap,
        &ett_isis_lsp_clv_sr_sid_label,
        &ett_isis_lsp_clv_sr_alg,
        &ett_isis_lsp_clv_sr_lb,
        &ett_isis_lsp_clv_bier_subsub_tlv,
        &ett_isis_lsp_clv_node_msd,
        &ett_isis_lsp_clv_srv6_cap,
        &ett_isis_lsp_clv_srv6_cap_flags,
        &ett_isis_lsp_clv_ipv6_te_rtrid,
        &ett_isis_lsp_clv_srv6_endx_sid_flags,
        &ett_isis_lsp_clv_srv6_endx_sid_sub_sub_tlv,
        &ett_isis_lsp_clv_srv6_locator,
        &ett_isis_lsp_clv_srv6_loc_entry,
        &ett_isis_lsp_clv_srv6_loc_flags,
        &ett_isis_lsp_clv_srv6_loc_sub_tlv,
        &ett_isis_lsp_clv_srv6_loc_end_sid_sub_sub_tlv,
        &ett_isis_lsp_clv_flex_algo_def,
        &ett_isis_lsp_clv_flex_algo_def_sub_tlv,
        &ett_isis_lsp_clv_app_sabm_bits,
        &ett_isis_lsp_sl_flags,
        &ett_isis_lsp_sl_sub_tlv,
        &ett_isis_lsp_sl_sub_tlv_flags,
        &ett_isis_lsp_clv_ipv6_te_router_id, /* CLV 140, rfc6119 */
        &ett_isis_lsp_clv_mac_reachability,  /* CLV 147, rfc6165 */
        &ett_isis_lsp_clv_avaya_ipvpn,
        &ett_isis_lsp_clv_avaya_ipvpn_subtlv,
        &ett_isis_lsp_clv_avaya_ipvpn_mc,
        &ett_isis_lsp_clv_avaya_ip_grt_mc,
        &ett_isis_lsp_clv_unidir_link_flags,
    };

    static ei_register_info ei[] = {
        { &ei_isis_lsp_short_pdu, { "isis.lsp.short_pdu", PI_MALFORMED, PI_ERROR, "PDU length less than header length", EXPFILL }},
        { &ei_isis_lsp_long_pdu, { "isis.lsp.long_pdu", PI_MALFORMED, PI_ERROR, "PDU length greater than packet length", EXPFILL }},
        { &ei_isis_lsp_bad_checksum, { "isis.lsp.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
        { &ei_isis_lsp_subtlv, { "isis.lsp.subtlv.unknown", PI_PROTOCOL, PI_WARN, "Unknown SubTLV", EXPFILL }},
        { &ei_isis_lsp_authentication, { "isis.lsp.authentication.unknown", PI_PROTOCOL, PI_WARN, "Unknown authentication type", EXPFILL }},
        { &ei_isis_lsp_short_clv, { "isis.lsp.short_clv", PI_MALFORMED, PI_ERROR, "Short CLV", EXPFILL }},
        { &ei_isis_lsp_long_clv, { "isis.lsp.long_clv", PI_MALFORMED, PI_ERROR, "Long CLV", EXPFILL }},
        { &ei_isis_lsp_length_clv, { "isis.lsp.length_clv", PI_MALFORMED, PI_ERROR, "Wrong length CLV", EXPFILL }},
        { &ei_isis_lsp_clv_mt, { "isis.lsp.clv_mt.malformed", PI_MALFORMED, PI_ERROR, "malformed MT-ID", EXPFILL }},
        { &ei_isis_lsp_clv_unknown, { "isis.lsp.clv.unknown", PI_UNDECODED, PI_NOTE, "Unknown option", EXPFILL }},
        { &ei_isis_lsp_malformed_subtlv, { "isis.lsp.subtlv.malformed", PI_MALFORMED, PI_ERROR, "malformed SubTLV", EXPFILL }},
        { &ei_isis_lsp_unknown_subtlv, { "isis.lsp.subtlv.unknown", PI_UNDECODED, PI_NOTE, "Unknown SubTLV", EXPFILL }},
        { &ei_isis_lsp_reserved_not_zero, { "isis.lsp.reserved_not_zero", PI_PROTOCOL, PI_WARN, "Reserve bit not 0", EXPFILL }},
        { &ei_isis_lsp_length_invalid, { "isis.lsp.length.invalid", PI_PROTOCOL, PI_WARN, "Invalid length", EXPFILL }},
    };

    expert_module_t* expert_isis_lsp;

    /* Register the protocol name and description */
    proto_isis_lsp = proto_register_protocol(PROTO_STRING_LSP, "ISIS LSP", "isis.lsp");

    proto_register_field_array(proto_isis_lsp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_isis_lsp = expert_register_protocol(proto_isis_lsp);
    expert_register_field_array(expert_isis_lsp, ei, array_length(ei));
}

void
proto_reg_handoff_isis_lsp(void)
{
    dissector_add_uint("isis.type", ISIS_TYPE_L1_LSP, create_dissector_handle(dissect_isis_l1_lsp, proto_isis_lsp));
    dissector_add_uint("isis.type", ISIS_TYPE_L2_LSP, create_dissector_handle(dissect_isis_l2_lsp, proto_isis_lsp));
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

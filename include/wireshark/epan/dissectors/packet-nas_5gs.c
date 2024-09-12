/* packet-nas_5gs.c
 * Routines for Non-Access-Stratum (NAS) protocol for 5G System (5GS) dissection
 *
 * Copyright 2018-2022, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: 3GPP TS 24.501 18.7.0
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/ipproto.h>
#include <epan/etypes.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/to_str.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>

#include <wsutil/array.h>
#include <wsutil/pow2.h>
#include <wsutil/pint.h>
#include <wsutil/wsjson.h>

#include "packet-gsm_a_common.h"
#include "packet-media-type.h"
#include "packet-tcp.h"

void proto_register_nas_5gs(void);
void proto_reg_handoff_nas_5gs(void);

static bool g_nas_5gs_null_decipher;
enum {
    DECODE_USER_DATA_AS_NONE,
    DECODE_USER_DATA_AS_IP,
    DECODE_USER_DATA_AS_NON_IP,
    DECODE_USER_DATA_AS_ETHERNET
};
static const enum_val_t nas_5gs_user_data_container_as_vals[] = {
    {"none", "None", DECODE_USER_DATA_AS_NONE},
    {"ip", "IP", DECODE_USER_DATA_AS_IP},
    {"non_ip","Non IP", DECODE_USER_DATA_AS_NON_IP},
    {"ethernet","Ethernet", DECODE_USER_DATA_AS_ETHERNET},
    {NULL, NULL, -1}
};
static int g_nas_5gs_decode_user_data_container_as = DECODE_USER_DATA_AS_NONE;
static const char *g_nas_5gs_non_ip_data_dissector = "";


static int dissect_nas_5gs_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, void* data);
static int dissect_nas_5gs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);
static uint16_t de_nas_5gs_mm_pdu_ses_id_2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_);
static uint16_t de_nas_5gs_cmn_add_inf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_);
static void nas_5gs_mm_5gmm_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len);
static uint16_t de_nas_5gs_mm_req_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_);

static dissector_handle_t nas_5gs_handle;
static dissector_handle_t eap_handle;
static dissector_handle_t nas_eps_handle;
static dissector_handle_t lpp_handle;
static dissector_handle_t gsm_a_dtap_handle;
static dissector_handle_t ipv4_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t non_ip_data_handle;
static dissector_handle_t ethernet_handle;

#define PNAME  "Non-Access-Stratum 5GS (NAS)PDU"
#define PSNAME "NAS-5GS"
#define PFNAME "nas-5gs"

static int proto_json;

static int proto_nas_5gs;

int hf_nas_5gs_common_elem_id;
int hf_nas_5gs_mm_elem_id;
int hf_nas_5gs_sm_elem_id;
int hf_nas_5gs_updp_elem_id;

static int hf_nas_5gs_epd;
static int hf_nas_5gs_spare_bits;
static int hf_nas_5gs_spare_b7;
static int hf_nas_5gs_spare_b6;
static int hf_nas_5gs_spare_b5;
static int hf_nas_5gs_spare_b4;
static int hf_nas_5gs_spare_b3;
static int hf_nas_5gs_spare_b2;
static int hf_nas_5gs_spare_b1;
static int hf_nas_5gs_spare_b0;
static int hf_nas_5gs_rfu_b2;
static int hf_nas_5gs_rfu_b1;
static int hf_nas_5gs_rfu_b0;
static int hf_nas_5gs_security_header_type;
static int hf_nas_5gs_msg_auth_code;
static int hf_nas_5gs_seq_no;
static int hf_nas_5gs_mm_msg_type;
static int hf_nas_5gs_sm_msg_type;
static int hf_nas_5gs_updp_msg_type;
static int hf_nas_5gs_proc_trans_id;
static int hf_nas_5gs_spare_half_octet;
static int hf_nas_5gs_spare_octet;
static int hf_nas_5gs_pdu_session_id;
static int hf_nas_5gs_msg_elems;
static int hf_nas_5gs_mm_for;
static int hf_nas_5gs_cmn_add_info;
static int hf_nas_5gs_cmn_acc_type;
static int hf_nas_5gs_cmn_dnn;
static int hf_nas_5gs_cmn_service_level_aa_param_type;
static int hf_nas_5gs_cmn_service_level_aa_param_len;
static int hf_nas_5gs_cmn_service_level_aa_param_device_id;
static int hf_nas_5gs_cmn_service_level_aa_param_addr_type;
static int hf_nas_5gs_cmn_service_level_aa_param_addr_ipv4;
static int hf_nas_5gs_cmn_service_level_aa_param_addr_ipv6;
static int hf_nas_5gs_cmn_service_level_aa_param_addr_fqdn;
static int hf_nas_5gs_cmn_service_level_aa_param_resp_c2ar;
static int hf_nas_5gs_cmn_service_level_aa_param_resp_slar;
static int hf_nas_5gs_cmn_service_level_aa_param_payload_type;
static int hf_nas_5gs_cmn_service_level_aa_param_payload;
static int hf_nas_5gs_cmn_service_level_aa_param_pending_ind_slapi;
static int hf_nas_5gs_cmn_service_level_aa_param_service_status_ind_uas;
static int hf_nas_5gs_cmn_service_level_aa_param_unknown;
static int hf_nas_5gs_mm_sms_requested;
static int hf_nas_5gs_mm_ng_ran_rcu;
static int hf_nas_5gs_mm_5gs_pnb_ciot;
static int hf_nas_5gs_mm_eps_pnb_ciot;
static int hf_nas_5gs_mm_5gs_reg_type;
static int hf_nas_5gs_mm_tsc;
static int hf_nas_5gs_mm_nas_key_set_id;
static int hf_nas_5gs_mm_tsc_h1;
static int hf_nas_5gs_mm_nas_key_set_id_h1;
static int hf_nas_5gs_mm_5gmm_cause;
static int hf_nas_5gs_mm_pld_cont_type;
static int hf_nas_5gs_mm_sst;
static int hf_nas_5gs_mm_sd;
static int hf_nas_5gs_mm_mapped_hplmn_sst;
static int hf_nas_5gs_mm_mapped_hplmn_ssd;
static int hf_nas_5gs_mm_switch_off;
static int hf_nas_5gs_mm_re_reg_req;
static int hf_nas_5gs_mm_acc_type;
static int hf_nas_5gs_mm_raai_b0;
static int hf_nas_5gs_mm_sprti_b1;
static int hf_nas_5gs_mm_ma_pdu_session_info_value;
static int hf_nas_5gs_mm_len_of_mapped_s_nssai;
static int hf_nas_5gs_mm_conf_upd_ind_ack_b0;
static int hf_nas_5gs_mm_conf_upd_ind_red_b1;
static int hf_nas_5gs_mm_cag_info_entry_len;
static int hf_nas_5gs_mm_cag_info_entry_cag_only;
static int hf_nas_5gs_mm_cag_info_entry_lci;
static int hf_nas_5gs_mm_cag_info_entry_caili;
static int hf_nas_5gs_mm_cag_info_entry_cag_without_add_info_list_len;
static int hf_nas_5gs_mm_cag_info_entry_cag_with_add_info_list_len;
static int hf_nas_5gs_mm_cag_info_entry_cag_with_add_info_len;
static int hf_nas_5gs_mm_cag_info_entry_cag_id;
static int hf_nas_5gs_mm_cag_info_entry_svii;
static int hf_nas_5gs_mm_cag_info_entry_tvii;
static int hf_nas_5gs_mm_cag_info_entry_nb_time_periods;
static int hf_nas_5gs_mm_cag_info_entry_time_period;
static int hf_nas_5gs_mm_ciot_small_data_cont_data_type;
static int hf_nas_5gs_mm_ciot_small_data_cont_ddx;
static int hf_nas_5gs_mm_ciot_small_data_cont_pdu_session_id;
static int hf_nas_5gs_mm_ciot_small_data_cont_add_info_len;
static int hf_nas_5gs_mm_ciot_small_data_cont_add_info;
static int hf_nas_5gs_mm_ciot_small_data_cont_data_contents;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_1;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_2;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_3;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_4;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_5;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_6;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_7;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_8;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_1;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_2;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_3;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_4;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_5;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_6;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_7;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_8;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_9;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_10;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_11;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_12;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_13;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_14;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_15;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_16;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_17;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_18;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_19;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_20;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_21;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_22;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_23;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_24;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_25;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_3_1;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_4_1;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_5_1;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_9;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_10;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_1;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_2;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_3;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_4;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_5;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_6;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_7;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_8;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_1;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_2;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_3;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_4;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_5;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_6;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_7;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_8;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_9;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_10;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_11;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_12;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_13;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_14;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_15;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_16;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_17;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_18;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_19;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_20;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_21;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_22;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_23;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_3_1;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_4_1;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_5_1;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_1;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_2;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_3;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_4;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_5;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_6;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_9;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_10;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_24;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_25;
static int hf_nas_5gs_mm_ciph_key_data_ciphering_set_id;
static int hf_nas_5gs_mm_ciph_key_data_ciphering_key;
static int hf_nas_5gs_mm_ciph_key_data_c0_len;
static int hf_nas_5gs_mm_ciph_key_data_c0;
static int hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_len;
static int hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_len;
static int hf_nas_5gs_mm_ciph_key_data_validity_start_time;
static int hf_nas_5gs_mm_ciph_key_data_validity_duration;
static int hf_nas_5gs_mm_ciph_key_data_tais_list_len;
static int hf_nas_5gs_mm_ctrl_plane_serv_type;
static int hf_nas_5gs_mm_nas_sec_algo_enc;
static int hf_nas_5gs_mm_nas_sec_algo_ip;
static int hf_nas_5gs_mm_s1_mode_b0;
static int hf_nas_5gs_mm_ho_attach_b1;
static int hf_nas_5gs_mm_lpp_cap_b2;
static int hf_nas_5gs_mm_restrict_ec_b3;
static int hf_nas_5gs_mm_5g_cp_ciot_b4;
static int hf_nas_5gs_mm_n3_data_b5;
static int hf_nas_5gs_mm_5g_iphc_cp_ciot_b6;
static int hf_nas_5gs_mm_sgc_b7;
static int hf_nas_5gs_mm_5g_srvcc_b0;
static int hf_nas_5gs_mm_5g_up_ciot_b1;
static int hf_nas_5gs_mm_v2x_b2;
static int hf_nas_5gs_mm_v2xcepc5_b3;
static int hf_nas_5gs_mm_v2xcnpc5_b4;
static int hf_nas_5gs_mm_5g_lcs_b5;
static int hf_nas_5gs_mm_nssaa_b6;
static int hf_nas_5gs_mm_racs_b7;
static int hf_nas_5gs_mm_cag_b0;
static int hf_nas_5gs_mm_wsusa_b1;
static int hf_nas_5gs_mm_multiple_up_b2;
static int hf_nas_5gs_mm_5g_ehc_cp_ciot_b3;
static int hf_nas_5gs_mm_er_nssai_b4;
static int hf_nas_5gs_mm_5g_prose_dd_b5;
static int hf_nas_5gs_mm_5g_prose_dc_b6;
static int hf_nas_5gs_mm_5g_prose_l2relay_b7;
static int hf_nas_5gs_mm_5g_prose_l3relay_b0;
static int hf_nas_5gs_mm_5g_prose_l2rmt_b1;
static int hf_nas_5gs_mm_5g_prose_l3rmt_b2;
static int hf_nas_5gs_mm_nr_pssi_b3;
static int hf_nas_5gs_mm_ncr_b4;
static int hf_nas_5gs_mm_piv_b5;
static int hf_nas_5gs_mm_rpr_b6;
static int hf_nas_5gs_mm_pr_b7;
static int hf_nas_5gs_mm_nssrg_b0;
static int hf_nas_5gs_mm_mint_b1;
static int hf_nas_5gs_mm_event_notif_b2;
static int hf_nas_5gs_mm_ssnpnsi_b3;
static int hf_nas_5gs_mm_ex_cag_b4;
static int hf_nas_5gs_mm_nsag_b5;
static int hf_nas_5gs_mm_uas_b6;
static int hf_nas_5gs_mm_mpsiu_b7;
static int hf_nas_5gs_mm_rcmap_b0;
static int hf_nas_5gs_mm_rcman_b1;
static int hf_nas_5gs_mm_esi_b2;
static int hf_nas_5gs_mm_eci_b3;
static int hf_nas_5gs_mm_rantiming_b4;
static int hf_nas_5gs_mm_ladn_ds_b5;
static int hf_nas_5gs_mm_nsr_b6;
static int hf_nas_5gs_mm_sbts_b7;
static int hf_nas_5gs_mm_a2xepc5_b0;
static int hf_nas_5gs_mm_a2xnpc5_b1;
static int hf_nas_5gs_mm_un_per_b2;
static int hf_nas_5gs_mm_sbns_b3;
static int hf_nas_5gs_mm_rslps_b4;
static int hf_nas_5gs_mm_5g_prose_l2u2u_relay_b5;
static int hf_nas_5gs_mm_5g_prose_l3u2u_relay_b6;
static int hf_nas_5gs_mm_5g_prose_l2end_b7;
static int hf_nas_5gs_mm_5g_prose_l3end_b0;
static int hf_nas_5gs_mm_rslp_b1;
static int hf_nas_5gs_mm_pns_b2;
static int hf_nas_5gs_mm_lcs_upp_b3;
static int hf_nas_5gs_mm_supl_b4;
static int hf_nas_5gs_mm_tempns_b5;
static int hf_nas_5gs_mm_slvi_b6;
static int hf_nas_5gs_mm_a2x_uu_b7;
static int hf_nas_5gs_mm_mcsiu_b0;
static int hf_nas_5gs_mm_nvl_satnr_b1;
static int hf_nas_5gs_rslpl_b2;
static int hf_nas_5gs_nsuc_b3;
static int hf_nas_5gs_mm_type_id;
static int hf_nas_5gs_mm_odd_even;
static int hf_nas_5gs_mm_length;
static int hf_nas_5gs_mm_pld_cont;
static int hf_nas_5gs_mm_pld_cont_event_notif_ind_nb;
static int hf_nas_5gs_mm_pld_cont_event_notif_ind_type;
static int hf_nas_5gs_mm_pld_cont_event_notif_ind_len;
static int hf_nas_5gs_mm_pld_cont_event_notif_ind_val;
static int hf_nas_5gs_mm_pld_cont_nb_entries;
static int hf_nas_5gs_mm_pld_cont_pld_cont_len;
static int hf_nas_5gs_mm_pld_cont_nb_opt_ies;
static int hf_nas_5gs_mm_pld_cont_pld_cont_type;
static int hf_nas_5gs_mm_pld_cont_opt_ie_type;
static int hf_nas_5gs_mm_pld_cont_opt_ie_len;
static int hf_nas_5gs_mm_pld_cont_opt_ie_val;
static int hf_nas_5gs_mm_req_type;
static int hf_nas_5gs_mm_serv_type;
static int hf_nas_5gs_mm_5g_ea0;
static int hf_nas_5gs_mm_128_5g_ea1;
static int hf_nas_5gs_mm_128_5g_ea2;
static int hf_nas_5gs_mm_128_5g_ea3;
static int hf_nas_5gs_mm_5g_ea4;
static int hf_nas_5gs_mm_5g_ea5;
static int hf_nas_5gs_mm_5g_ea6;
static int hf_nas_5gs_mm_5g_ea7;
static int hf_nas_5gs_mm_5g_ia0;
static int hf_nas_5gs_mm_5g_128_ia1;
static int hf_nas_5gs_mm_5g_128_ia2;
static int hf_nas_5gs_mm_5g_128_ia3;
static int hf_nas_5gs_mm_5g_ia4;
static int hf_nas_5gs_mm_5g_ia5;
static int hf_nas_5gs_mm_5g_ia6;
static int hf_nas_5gs_mm_5g_ia7;
static int hf_nas_5gs_mm_eea0;
static int hf_nas_5gs_mm_128eea1;
static int hf_nas_5gs_mm_128eea2;
static int hf_nas_5gs_mm_eea3;
static int hf_nas_5gs_mm_eea4;
static int hf_nas_5gs_mm_eea5;
static int hf_nas_5gs_mm_eea6;
static int hf_nas_5gs_mm_eea7;
static int hf_nas_5gs_mm_eia0;
static int hf_nas_5gs_mm_128eia1;
static int hf_nas_5gs_mm_128eia2;
static int hf_nas_5gs_mm_eia3;
static int hf_nas_5gs_mm_eia4;
static int hf_nas_5gs_mm_eia5;
static int hf_nas_5gs_mm_eia6;
static int hf_nas_5gs_mm_eia7;
static int hf_nas_5gs_mm_n1_mode_reg_b1;
static int hf_nas_5gs_mm_s1_mode_reg_b0;

static int hf_nas_5gs_mm_sal_al_t;
static int hf_nas_5gs_mm_sal_t_li;
static int hf_nas_5gs_mm_sal_num_e;

static int hf_nas_5gs_pdu_ses_sts_psi_7_b7;
static int hf_nas_5gs_pdu_ses_sts_psi_6_b6;
static int hf_nas_5gs_pdu_ses_sts_psi_5_b5;
static int hf_nas_5gs_pdu_ses_sts_psi_4_b4;
static int hf_nas_5gs_pdu_ses_sts_psi_3_b3;
static int hf_nas_5gs_pdu_ses_sts_psi_2_b2;
static int hf_nas_5gs_pdu_ses_sts_psi_1_b1;
static int hf_nas_5gs_pdu_ses_sts_psi_0_b0;

static int hf_nas_5gs_pdu_ses_sts_psi_15_b7;
static int hf_nas_5gs_pdu_ses_sts_psi_14_b6;
static int hf_nas_5gs_pdu_ses_sts_psi_13_b5;
static int hf_nas_5gs_pdu_ses_sts_psi_12_b4;
static int hf_nas_5gs_pdu_ses_sts_psi_11_b3;
static int hf_nas_5gs_pdu_ses_sts_psi_10_b2;
static int hf_nas_5gs_pdu_ses_sts_psi_9_b1;
static int hf_nas_5gs_pdu_ses_sts_psi_8_b0;

static int hf_nas_5gs_pdu_ses_rect_res_psi_7_b7;
static int hf_nas_5gs_pdu_ses_rect_res_psi_6_b6;
static int hf_nas_5gs_pdu_ses_rect_res_psi_5_b5;
static int hf_nas_5gs_pdu_ses_rect_res_psi_4_b4;
static int hf_nas_5gs_pdu_ses_rect_res_psi_3_b3;
static int hf_nas_5gs_pdu_ses_rect_res_psi_2_b2;
static int hf_nas_5gs_pdu_ses_rect_res_psi_1_b1;
static int hf_nas_5gs_pdu_ses_rect_res_psi_0_b0;

static int hf_nas_5gs_pdu_ses_rect_res_psi_15_b7;
static int hf_nas_5gs_pdu_ses_rect_res_psi_14_b6;
static int hf_nas_5gs_pdu_ses_rect_res_psi_13_b5;
static int hf_nas_5gs_pdu_ses_rect_res_psi_12_b4;
static int hf_nas_5gs_pdu_ses_rect_res_psi_11_b3;
static int hf_nas_5gs_pdu_ses_rect_res_psi_10_b2;
static int hf_nas_5gs_pdu_ses_rect_res_psi_9_b1;
static int hf_nas_5gs_pdu_ses_rect_res_psi_8_b0;

static int hf_nas_5gs_ul_data_sts_psi_7_b7;
static int hf_nas_5gs_ul_data_sts_psi_6_b6;
static int hf_nas_5gs_ul_data_sts_psi_5_b5;
static int hf_nas_5gs_ul_data_sts_psi_4_b4;
static int hf_nas_5gs_ul_data_sts_psi_3_b3;
static int hf_nas_5gs_ul_data_sts_psi_2_b2;
static int hf_nas_5gs_ul_data_sts_psi_1_b1;
static int hf_nas_5gs_ul_data_sts_psi_0_b0;

static int hf_nas_5gs_ul_data_sts_psi_15_b7;
static int hf_nas_5gs_ul_data_sts_psi_14_b6;
static int hf_nas_5gs_ul_data_sts_psi_13_b5;
static int hf_nas_5gs_ul_data_sts_psi_12_b4;
static int hf_nas_5gs_ul_data_sts_psi_11_b3;
static int hf_nas_5gs_ul_data_sts_psi_10_b2;
static int hf_nas_5gs_ul_data_sts_psi_9_b1;
static int hf_nas_5gs_ul_data_sts_psi_8_b0;

static int hf_nas_5gs_allow_pdu_ses_sts_psi_7_b7;
static int hf_nas_5gs_allow_pdu_ses_sts_psi_6_b6;
static int hf_nas_5gs_allow_pdu_ses_sts_psi_5_b5;
static int hf_nas_5gs_allow_pdu_ses_sts_psi_4_b4;
static int hf_nas_5gs_allow_pdu_ses_sts_psi_3_b3;
static int hf_nas_5gs_allow_pdu_ses_sts_psi_2_b2;
static int hf_nas_5gs_allow_pdu_ses_sts_psi_1_b1;
static int hf_nas_5gs_allow_pdu_ses_sts_psi_0_b0;

static int hf_nas_5gs_allow_pdu_ses_sts_psi_15_b7;
static int hf_nas_5gs_allow_pdu_ses_sts_psi_14_b6;
static int hf_nas_5gs_allow_pdu_ses_sts_psi_13_b5;
static int hf_nas_5gs_allow_pdu_ses_sts_psi_12_b4;
static int hf_nas_5gs_allow_pdu_ses_sts_psi_11_b3;
static int hf_nas_5gs_allow_pdu_ses_sts_psi_10_b2;
static int hf_nas_5gs_allow_pdu_ses_sts_psi_9_b1;
static int hf_nas_5gs_allow_pdu_ses_sts_psi_8_b0;

static int hf_nas_5gs_sm_pdu_session_type;
static int hf_nas_5gs_sm_sc_mode;
static int hf_nas_5gs_sm_eplmnc;
static int hf_nas_5gs_sm_ratc;
static int hf_nas_5gs_sm_naps;
static int hf_nas_5gs_sm_ept_s1;
static int hf_nas_5gs_sm_catbo;
static int hf_nas_5gs_sm_abo;
static int hf_nas_5gs_sm_atsss_cont;
static int hf_nas_5gs_sm_cpoi;
static int hf_nas_5gs_sm_ip_hdr_comp_config_p0104;
static int hf_nas_5gs_sm_ip_hdr_comp_config_p0103;
static int hf_nas_5gs_sm_ip_hdr_comp_config_p0102;
static int hf_nas_5gs_sm_ip_hdr_comp_config_p0006;
static int hf_nas_5gs_sm_ip_hdr_comp_config_p0004;
static int hf_nas_5gs_sm_ip_hdr_comp_config_p0003;
static int hf_nas_5gs_sm_ip_hdr_comp_config_p0002;
static int hf_nas_5gs_sm_ip_hdr_comp_config_max_cid;
static int hf_nas_5gs_sm_ip_hdr_comp_config_add_ip_hdr_compr_cxt_setup_params_type;
static int hf_nas_5gs_sm_ip_hdr_comp_config_add_ip_hdr_compr_cxt_setup_params_cont;
static int hf_nas_5gs_sm_ds_tt_eth_port_mac_addr;
static int hf_nas_5gs_sm_ue_ds_tt_residence_time;
static int hf_nas_5gs_sm_port_mgmt_info_cont;
static int hf_nas_5gs_sm_eth_hdr_comp_config_cid_len;
static int hf_nas_5gs_sm_pdu_session_pair_id;
static int hf_nas_5gs_sm_pdu_session_rsn;
static int hf_nas_5gs_sm_sel_sc_mode;
static int hf_nas_5gs_sm_tpmic_b7;
static int hf_nas_5gs_sm_atsss_st_b3_b6;
static int hf_nas_5gs_sm_ept_s1_b2;
static int hf_nas_5gs_sm_mh6_pdu_b1;
static int hf_nas_5gs_sm_rqos_b0;
static int hf_nas_5gs_sm_sdnaepc_b1;
static int hf_nas_5gs_sm_apmqf_b0;
static int hf_nas_5gs_sm_5gsm_cause;
static int hf_nas_5gs_sm_apsi;
static int hf_nas_5gs_sm_apsr;
static int hf_nas_5gs_sm_int_prot_max_data_rate_ul;
static int hf_nas_5gs_sm_int_prot_max_data_rate_dl;
static int hf_nas_5gs_sm_si6lla;
static int hf_nas_5gs_sm_pdu_ses_type;
static int hf_nas_5gs_sm_pdu_addr_inf_ipv4;
static int hf_nas_5gs_sm_pdu_addr_inf_ipv6;
static int hf_nas_5gs_sm_smf_ipv6_lla;
static int hf_nas_5gs_sm_qos_rule_id;
static int hf_nas_5gs_sm_length;
static int hf_nas_5gs_sm_rop;
static int hf_nas_5gs_sm_dqr;
static int hf_nas_5gs_sm_nof_pkt_filters;
static int hf_nas_5gs_sm_pkt_flt_id;
static int hf_nas_5gs_sm_pkt_flt_dir;
static int hf_nas_5gs_sm_pf_len;
static int hf_nas_5gs_sm_pf_type;
static int hf_nas_5gs_sm_e;
static int hf_nas_5gs_sm_nof_params;
static int hf_nas_5gs_sm_param_id;
static int hf_nas_5gs_sm_param_len;
static int hf_nas_5gs_sm_qos_rule_precedence;
static int hf_nas_5gs_sm_segregation;
static int hf_nas_5gs_sm_param_cont;
static int hf_nas_5gs_sm_5qi;
static int hf_nas_5gs_sm_unit_for_gfbr_ul;
static int hf_nas_5gs_sm_gfbr_ul;
static int hf_nas_5gs_sm_unit_for_gfbr_dl;
static int hf_nas_5gs_sm_gfbr_dl;
static int hf_nas_5gs_sm_unit_for_mfbr_ul;
static int hf_nas_5gs_sm_mfbr_ul;
static int hf_nas_5gs_sm_unit_for_mfbr_dl;
static int hf_nas_5gs_sm_mfbr_dl;
static int hf_nas_5gs_sm_averaging_window;
static int hf_nas_5gs_sm_eps_bearer_id;
static int hf_nas_5gs_sm_qfi;
static int hf_nas_5gs_sm_mapd_eps_b_cont_id;
static int hf_nas_5gs_sm_mapd_eps_b_cont_opt_code;
static int hf_nas_5gs_sm_qos_des_flow_opt_code;
static int hf_nas_5gs_sm_mapd_eps_b_cont_E;
static int hf_nas_5gs_sm_mapd_eps_b_cont_num_eps_parms;
static int hf_nas_5gs_sm_mapd_eps_b_cont_E_mod;
static int hf_nas_5gs_sm_mapd_eps_b_cont_param_id;

static int hf_nas_5gs_sm_unit_for_session_ambr_dl;
static int hf_nas_5gs_sm_session_ambr_dl;
static int hf_nas_5gs_sm_unit_for_session_ambr_ul;
static int hf_nas_5gs_sm_session_ambr_ul;
static int hf_nas_5gs_sm_dm_spec_id;
static int hf_nas_5gs_sm_all_ssc_mode_b0;
static int hf_nas_5gs_sm_all_ssc_mode_b1;
static int hf_nas_5gs_sm_all_ssc_mode_b2;
static int hf_nas_5gs_addr_mask_ipv4;
static int hf_nas_5gs_ipv6;
static int hf_nas_5gs_ipv6_prefix_len;
static int hf_nas_5gs_protocol_identifier_or_next_hd;
static int hf_nas_5gs_mm_rinmr;
static int hf_nas_5gs_mm_hdp;
static int hf_nas_5gs_mm_cipher_key;
static int hf_nas_5gs_mm_dcni;
static int hf_nas_5gs_mm_nssci;
static int hf_nas_5gs_mm_nssai_inc_mode;
static int hf_nas_5gs_mm_ue_usage_setting;
static int hf_nas_5gs_mm_5gs_drx_param;
static int hf_nas_5gs_sup_andsp;
static int hf_nas_5gs_nssui;

static int ett_nas_5gs;
static int ett_nas_5gs_mm_nssai;
static int ett_nas_5gs_mm_pdu_ses_id;
static int ett_nas_5gs_sm_qos_rules;
static int ett_nas_5gs_sm_qos_params;
static int ett_nas_5gs_plain;
static int ett_nas_5gs_sec;
static int ett_nas_5gs_mm_part_sal;
static int ett_nas_5gs_mm_part_tal;
static int ett_nas_5gs_sm_mapd_eps_b_cont;
static int ett_nas_5gs_sm_mapd_eps_b_cont_params_list;
static int ett_nas_5gs_enc;
static int ett_nas_5gs_mm_ladn_indic;
static int ett_nas_5gs_mm_sor;
static int ett_nas_5gs_sm_pkt_filter_components;
static int ett_nas_5gs_updp_ue_policy_section_mgm_lst;
static int ett_nas_5gs_updp_ue_policy_section_mgm_sublst;
static int ett_nas_5gs_ue_policies_ursp;
static int ett_nas_5gs_ursp_traff_desc;
static int ett_nas_5gs_usrp_r_sel_list;
static int ett_nas_5gs_usrp_r_sel;
static int ett_nas_5gs_ursp_r_sel_desc_cont;
static int ett_nas_5gs_updp_upsi_list;
static int ett_nas_5gs_mm_rej_nssai;
static int ett_nas_5gs_mm_scheme_output;
static int ett_nas_5gs_mm_pld_cont_pld_entry;
static int ett_nas_5gs_mm_pld_cont_opt_ie;
static int ett_nas_5gs_mm_cag_info_entry;
static int ett_nas_5gs_ciot_small_data_cont_data_contents;
static int ett_nas_5gs_user_data_cont;
static int ett_nas_5gs_ciph_data_set;
static int ett_nas_5gs_mm_mapped_nssai;
static int ett_nas_5gs_mm_partial_extended_rejected_nssai_list;
static int ett_nas_5gs_mm_ext_rej_nssai_back_off_timer;
static int ett_nas_5gs_mm_ext_rej_nssai;
static int ett_nas_5gs_mm_op_def_acc_cat_def;
static int ett_nas_5gs_mm_op_def_acc_cat_criteria_component;
static int ett_nas_5gs_mm_op_def_acc_cat_criteria;
static int ett_nas_5gs_cmn_service_level_aa_cont_param;
static int ett_nas_5gs_mm_pld_cont_event_notif_ind;
static int ett_nas_5gs_mm_peips_assist_info;
static int ett_nas_5gs_mm_nssrg_info;
static int ett_nas_5gs_mm_plmns_list_disaster_cond;
static int ett_nas_5gs_mm_reg_wait_range;
static int ett_nas_5gs_mm_nsag_info;
static int ett_nas_5gs_mm_snpn_list;
static int ett_nas_5gs_mm_ext_ladn_info;
static int ett_nas_5gs_mm_alt_nssai;
static int ett_nas_5gs_mm_alt_nssai_replaced;
static int ett_nas_5gs_mm_alt_nssai_alternative;
static int ett_nas_5gs_mm_s_nssai_loc_valid_info;
static int ett_nas_5gs_mm_s_nssai_time_valid_info;
static int ett_nas_5gs_mm_on_demand_nssai;

static int hf_nas_5gs_mm_abba;
static int hf_nas_5gs_mm_supi_fmt;
static int hf_nas_5gs_mm_routing_indicator;
static int hf_nas_5gs_mm_prot_scheme_id;
static int hf_nas_5gs_mm_pki;
static int hf_nas_5gs_mm_suci_msin;
static int hf_nas_5gs_mm_scheme_output;
static int hf_nas_5gs_mm_scheme_output_ecc_public_key;
static int hf_nas_5gs_mm_scheme_output_ciphertext;
static int hf_nas_5gs_mm_scheme_output_mac_tag;
static int hf_nas_5gs_mm_suci_nai;
static int hf_nas_5gs_mm_imei;
static int hf_nas_5gs_mm_imeisv;
static int hf_nas_5gs_mm_mauri;
static int hf_nas_5gs_mm_mac_addr;
static int hf_nas_5gs_mm_eui_64;
static int hf_nas_5gs_mm_reg_res_res;
static int hf_nas_5gs_mm_reg_res_sms_allowed;
static int hf_nas_5gs_mm_reg_res_nssaa_perf;
static int hf_nas_5gs_mm_reg_res_emergency_reg;
static int hf_nas_5gs_mm_reg_res_disaster_roaming_reg_res;
static int hf_nas_5gs_amf_region_id;
static int hf_nas_5gs_amf_set_id;
static int hf_nas_5gs_amf_pointer;
static int hf_nas_5gs_5g_tmsi;
static int hf_nas_5gs_mm_op_def_access_cat_len;
static int hf_nas_5gs_mm_op_def_access_cat_precedence;
static int hf_nas_5gs_mm_op_def_access_cat_psac;
static int hf_nas_5gs_mm_op_def_access_cat_number;
static int hf_nas_5gs_mm_op_def_access_cat_criteria_length;
static int hf_nas_5gs_mm_op_def_access_cat_criteria_type;
static int hf_nas_5gs_mm_op_def_access_cat_criteria_dnn_count;
static int hf_nas_5gs_mm_op_def_access_cat_criteria_dnn_len;
static int hf_nas_5gs_mm_op_def_access_cat_criteria_os_id_os_app_id_count;
static int hf_nas_5gs_mm_op_def_access_cat_criteria_os_id;
static int hf_nas_5gs_mm_op_def_access_cat_criteria_os_app_id_len;
static int hf_nas_5gs_mm_op_def_access_cat_criteria_os_app_id;
static int hf_nas_5gs_mm_op_def_access_cat_criteria_s_nssai_count;
static int hf_nas_5gs_mm_op_def_access_cat_criteria_s_nssai_len;
static int hf_nas_5gs_mm_op_def_access_cat_standardized_number;
static int hf_nas_5gs_mm_sms_indic_sai;

static int hf_nas_5gs_nw_feat_sup_mpsi_b7;
static int hf_nas_5gs_nw_feat_sup_ims_iwk_n26_b6;
static int hf_nas_5gs_nw_feat_sup_ims_emf_b5b4;
static int hf_nas_5gs_nw_feat_sup_ims_emc_b3b2;
static int hf_nas_5gs_nw_feat_sup_ims_vops_3gpp;
static int hf_nas_5gs_nw_feat_sup_ims_vops_n3gpp;
static int hf_nas_5gs_nw_feat_sup_emcn3;
static int hf_nas_5gs_nw_feat_sup_mcsi;
static int hf_nas_5gs_nw_feat_sup_restrict_ec;
static int hf_nas_5gs_nw_feat_sup_5g_cp_ciot;
static int hf_nas_5gs_nw_feat_sup_n3_data;
static int hf_nas_5gs_nw_feat_sup_5g_iphc_cp_ciot;
static int hf_nas_5gs_nw_feat_sup_5g_ciot_up;
static int hf_nas_5gs_nw_feat_sup_5g_lcs;
static int hf_nas_5gs_nw_feat_sup_ats_ind;
static int hf_nas_5gs_nw_feat_sup_5g_ehc_cp_ciot;
static int hf_nas_5gs_nw_feat_sup_ncr;
static int hf_nas_5gs_nw_feat_sup_piv;
static int hf_nas_5gs_nw_feat_sup_rpr;
static int hf_nas_5gs_nw_feat_sup_pr;
static int hf_nas_5gs_nw_feat_sup_un_per;
static int hf_nas_5gs_nw_feat_sup_naps;
static int hf_nas_5gs_nw_feat_sup_lcs_upp;
static int hf_nas_5gs_nw_feat_sup_supl;
static int hf_nas_5gs_nw_feat_sup_rslp;

static int hf_nas_5gs_tac;

static int hf_nas_5gs_mm_tal_t_li;
static int hf_nas_5gs_mm_tal_num_e;
static int hf_nas_5gs_sm_mapd_eps_b_cont_eps_param_cont;

static int hf_nas_5gs_sm_max_nb_sup_pkt_flt_nb;
static int hf_nas_5gs_sm_max_nb_sup_pkt_flt_spare;

static int hf_nas_5gs_kacf;
static int hf_nas_5gs_ncc;

static int hf_nas_5gs_sor_hdr0_ap;
static int hf_nas_5gs_sor_hdr0_ack;
static int hf_nas_5gs_sor_hdr0_list_type;
static int hf_nas_5gs_sor_hdr0_list_ind;
static int hf_nas_5gs_sor_hdr0_sor_data_type;
static int hf_nas_5gs_sor_mssi;
static int hf_nas_5gs_sor_mssnpnsi;
static int hf_nas_5gs_sor_msssnpnsils;
static int hf_nas_5gs_sor_mac_iue;
static int hf_nas_5gs_sor_mac_iausf;
static int hf_nas_5gs_counter_sor;
static int hf_nas_5gs_sor_sec_pkt;
static int hf_nas_5gs_sor_sssli;
static int hf_nas_5gs_sor_sssi;
static int hf_nas_5gs_sor_sscmi;
static int hf_nas_5gs_sor_si;
static int hf_nas_5gs_sor_plmn_id_act_len;
static int hf_nas_5gs_sor_cmci_len;
static int hf_nas_5gs_sor_cmci_payload;
static int hf_nas_5gs_sor_snpn_si_len;
static int hf_nas_5gs_sor_snpn_si_payload;
static int hf_nas_5gs_sor_snpn_si_ls_len;
static int hf_nas_5gs_sor_snpn_si_ls_payload;

static int hf_nas_5gs_access_tech_o1_b7;
static int hf_nas_5gs_access_tech_o1_b6;
static int hf_nas_5gs_access_tech_o1_b5;
static int hf_nas_5gs_access_tech_o1_b4;
static int hf_nas_5gs_access_tech_o1_b3;
static int hf_nas_5gs_access_tech_o2_b7;
static int hf_nas_5gs_access_tech_o2_b6;
static int hf_nas_5gs_access_tech_o2_b5;
static int hf_nas_5gs_access_tech_o2_b4;
static int hf_nas_5gs_access_tech_o2_b3;
static int hf_nas_5gs_access_tech_o2_b2;
static int hf_nas_5gs_single_port_type;
static int hf_nas_5gs_port_range_type_low;
static int hf_nas_5gs_port_range_type_high;
static int hf_nas_5gs_sec_param_idx;
static int hf_nas_5gs_tos_tc_val;
static int hf_nas_5gs_tos_tc_mask;
static int hf_nas_5gs_flow_label;
static int hf_nas_5gs_mac_addr;
static int hf_nas_5gs_vlan_tag_vid;
static int hf_nas_5gs_vlan_tag_pcp;
static int hf_nas_5gs_vlan_tag_dei;
static int hf_nas_5gs_ethertype;
static int hf_nas_5gs_mac_addr_low;
static int hf_nas_5gs_mac_addr_high;
static int hf_nas_5gs_updp_ue_pol_sect_sublst_len;
static int hf_nas_5gs_updp_ue_pol_sect_subresult_len;
static int hf_nas_5gs_updp_instr_len;
static int hf_nas_5gs_updp_upsc;
static int hf_nas_5gs_updp_failed_instruction_order;
static int hf_nas_5gs_updp_policy_len;
static int hf_nas_5gs_updp_ue_policy_part_type;
static int hf_nas_5gs_updp_ue_policy_part_cont;
static int hf_nas_5gs_ursp_rule_len;
static int hf_nas_5gs_ursp_rule_prec;
static int hf_nas_5gs_ursp_traff_desc_lst_len;
static int hf_nas_5gs_ursp_traff_desc;
static int hf_nas_5gs_ursp_r_sel_desc_lst_len;
static int hf_nas_5gs_ursp_r_sel_desc_lst;
static int hf_nas_5gs_ursp_traff_desc_ipv4;
static int hf_nas_5gs_ursp_traff_desc_ipv4_mask;
static int hf_nas_5gs_ursp_traff_desc_ipv6;
static int hf_nas_5gs_ursp_traff_desc_ipv6_prefix_len;
static int hf_nas_5gs_ursp_traff_desc_next_hdr;
static int hf_nas_5gs_ursp_traff_desc_single_remote_port;
static int hf_nas_5gs_ursp_traff_desc_remote_port_range_low;
static int hf_nas_5gs_ursp_traff_desc_remote_port_range_high;
static int hf_nas_5gs_ursp_traff_desc_sec_param_index;
static int hf_nas_5gs_ursp_traff_desc_tos_tc;
static int hf_nas_5gs_ursp_traff_desc_tos_tc_mask;
static int hf_nas_5gs_ursp_traff_desc_flow_label;
static int hf_nas_5gs_ursp_traff_desc_dest_mac_addr;
static int hf_nas_5gs_ursp_traff_desc_ctag_vid;
static int hf_nas_5gs_ursp_traff_desc_stag_vid;
static int hf_nas_5gs_ursp_traff_desc_ctag_pcp;
static int hf_nas_5gs_ursp_traff_desc_ctag_dei;
static int hf_nas_5gs_ursp_traff_desc_stag_pcp;
static int hf_nas_5gs_ursp_traff_desc_stag_dei;
static int hf_nas_5gs_ursp_traff_desc_ethertype;
static int hf_nas_5gs_ursp_traff_desc_conn_cap_len;
static int hf_nas_5gs_ursp_traff_desc_conn_cap;
static int hf_nas_5gs_ursp_traff_desc_dest_fqdn_len;
static int hf_nas_5gs_ursp_traff_desc_dest_fqdn;
static int hf_nas_5gs_ursp_traff_desc_dest_mac_addr_range_low;
static int hf_nas_5gs_ursp_traff_desc_dest_mac_addr_range_high;
static int hf_nas_5gs_ursp_traff_desc_len;
static int hf_nas_5gs_ursp_r_sel_des_prec;
static int hf_nas_5gs_ursp_r_sel_des_cont_len;
static int hf_nas_5gs_ursp_ursp_r_sel_desc_comp_type;
static int hf_nas_5gs_dnn_len;
static int hf_nas_5gs_upsi_sublist_len;
static int hf_nas_5gs_upsc;
static int hf_nas_5gs_os_id;
static int hf_nas_5gs_upds_cause;
static int hf_nas_5gs_v2xuui;
static int hf_nas_5gs_v2xpc5i;
static int hf_nas_5gs_os_app_id_len;
static int hf_nas_5gs_os_app_id;
static int hf_nas_5gs_mm_len_of_rej_s_nssai;
static int hf_nas_5gs_mm_rej_s_nssai_cause;
static int hf_nas_5gs_mm_ue_radio_cap_id;
static int hf_nas_5gs_mm_ue_radio_cap_id_del_req;
static int hf_nas_5gs_mm_trunc_amf_set_id;
static int hf_nas_5gs_mm_trunc_amf_pointer;
static int hf_nas_5gs_mm_n5gcreg_b0;
static int hf_nas_5gs_mm_nb_n1_drx_value;
static int hf_nas_5gs_mm_scmr;
static int hf_nas_5gs_mm_extended_rejected_nssai_number_of_element;
static int hf_nas_5gs_mm_extended_rejected_nssai_type_of_list;
static int hf_nas_5gs_mm_extended_rejected_nssai_spare;
static int hf_nas_5gs_mm_extended_rejected_nssai_back_off_timer;
static int hf_nas_5gs_mm_len_of_rejected_s_nssai;
static int hf_nas_5gs_mm_rejected_s_nssai_cause_value;
static int hf_nas_5gs_mm_paging_restriction_type;
static int hf_nas_5gs_mm_paging_restriction_psi_7;
static int hf_nas_5gs_mm_paging_restriction_psi_6;
static int hf_nas_5gs_mm_paging_restriction_psi_5;
static int hf_nas_5gs_mm_paging_restriction_psi_4;
static int hf_nas_5gs_mm_paging_restriction_psi_3;
static int hf_nas_5gs_mm_paging_restriction_psi_2;
static int hf_nas_5gs_mm_paging_restriction_psi_1;
static int hf_nas_5gs_mm_paging_restriction_psi_0;
static int hf_nas_5gs_mm_paging_restriction_psi_15;
static int hf_nas_5gs_mm_paging_restriction_psi_14;
static int hf_nas_5gs_mm_paging_restriction_psi_13;
static int hf_nas_5gs_mm_paging_restriction_psi_12;
static int hf_nas_5gs_mm_paging_restriction_psi_11;
static int hf_nas_5gs_mm_paging_restriction_psi_10;
static int hf_nas_5gs_mm_paging_restriction_psi_9;
static int hf_nas_5gs_mm_paging_restriction_psi_8;
static int hf_nas_5gs_mm_nid_assign_mode;
static int hf_nas_5gs_mm_nid_value;
static int hf_nas_5gs_mm_peips_assist_info_type;
static int hf_nas_5gs_mm_peips_assist_info_paging_subgroup_id;
static int hf_nas_5gs_mm_peips_assist_info_ue_paging_probability_info;
static int hf_nas_5gs_mm_add_req_res_prd;
static int hf_nas_5gs_mm_nssrg_info_len;
static int hf_nas_5gs_mm_nssrg_info_s_nssai_len;
static int hf_nas_5gs_mm_nssrg_info_nssrg;
static int hf_nas_5gs_mm_nsag_info_len;
static int hf_nas_5gs_mm_nsag_id;
static int hf_nas_5gs_mm_nsag_info_s_nssai_len;
static int hf_nas_5gs_mm_nsag_prio;
static int hf_nas_5gs_mm_nsag_tais_list_len;
static int hf_nas_5gs_mm_prose_relay_trans_id;
static int hf_nas_5gs_mm_relay_key_req_params_relay_service_code;
static int hf_nas_5gs_mm_relay_key_req_params_nonce_1;
static int hf_nas_5gs_mm_relay_key_req_params_uit;
static int hf_nas_5gs_mm_relay_key_req_params_ue_id;
static int hf_nas_5gs_mm_relay_key_resp_params_key_knr_prose;
static int hf_nas_5gs_mm_relay_key_resp_params_nonce_2;
static int hf_nas_5gs_mm_relay_key_resp_params_cp_pruk_id;
static int hf_nas_5gs_mm_prio_ind_mcsi;
static int hf_nas_5gs_mm_prio_ind_mpsi;
static int hf_nas_5gs_mm_n3iwf_id_type;
static int hf_nas_5gs_mm_n3iwf_id_ipv4;
static int hf_nas_5gs_mm_n3iwf_id_ipv6;
static int hf_nas_5gs_mm_n3iwf_id_fqdn;
static int hf_nas_5gs_mm_tnan_info_ssid_ind;
static int hf_nas_5gs_mm_tnan_info_tngf_id_ind;
static int hf_nas_5gs_mm_tnan_info_tngf_id_len;
static int hf_nas_5gs_mm_tnan_info_tngf_id;
static int hf_nas_5gs_mm_tnan_info_ssid_len;
static int hf_nas_5gs_mm_tnan_info_ssid;
static int hf_nas_5gs_mm_ran_timing_sync_recreq;
static int hf_nas_5gs_mm_n3gpp_acc_path_switch_ind_naps;
static int hf_nas_5gs_mm_s_nssai_loc_valid_info_per_s_nssai_len;
static int hf_nas_5gs_mm_s_nssai_loc_valid_info_per_s_nssai_nb_nr_cgi;
static int hf_nas_5gs_mm_s_nssai_loc_valid_info_per_s_nssai_nr_cell_id;
static int hf_nas_5gs_mm_s_nssai_time_valid_info_per_s_nssai_len;
static int hf_nas_5gs_mm_s_nssai_time_valid_info_time_window_len;
static int hf_nas_5gs_mm_s_nssai_time_valid_info_time_window_start_time;
static int hf_nas_5gs_mm_s_nssai_time_valid_info_time_window_stop_time;
static int hf_nas_5gs_mm_s_nssai_time_valid_info_time_window_recurrence_pattern;
static int hf_nas_5gs_mm_s_nssai_time_valid_info_time_window_recurrence_end_time;
static int hf_nas_5gs_mm_n3gpp_path_switch_info_nsonr;
static int hf_nas_5gs_mm_au3n_ind_aun3reg;
static int hf_nas_5gs_mm_feat_auth_ind_mbsrai;
static int hf_nas_5gs_mm_payload_cont_info_pru;
static int hf_nas_5gs_mm_aun3_device_sec_key_askt;
static int hf_nas_5gs_mm_aun3_device_sec_key_key_len;
static int hf_nas_5gs_mm_aun3_device_sec_key_key;
static int hf_nas_5gs_mm_on_demand_nssai_len;
static int hf_nas_5gs_mm_on_demand_nssai_slice_dereg_inactiv_timer;
static int hf_nas_5gs_mm_ext_5gmm_cause_sat_nr;
static int hf_nas_5gs_ue_os_id;

static expert_field ei_nas_5gs_extraneous_data;
static expert_field ei_nas_5gs_unknown_pd;
static expert_field ei_nas_5gs_mm_unknown_msg_type;
static expert_field ei_nas_5gs_sm_unknown_msg_type;
static expert_field ei_nas_5gs_updp_unknown_msg_type;
static expert_field ei_nas_5gs_msg_not_dis;
static expert_field ei_nas_5gs_ie_not_dis;
static expert_field ei_nas_5gs_missing_mandatory_element;
static expert_field ei_nas_5gs_dnn_too_long;
static expert_field ei_nas_5gs_unknown_value;
static expert_field ei_nas_5gs_num_pkt_flt;
static expert_field ei_nas_5gs_not_diss;

#define NAS_5GS_PLAIN_NAS_MSG          0
#define NAS_5GS_INTEG_NAS_MSG          1
#define NAS_5GS_INTEG_CIPH_NAS_MSG     2
#define NAS_5GS_INTEG_NEW_NAS_MSG      3
#define NAS_5GS_INTEG_CIPH_NEW_NAS_MSG 4

static const value_string nas_5gs_security_header_type_vals[] = {
    { NAS_5GS_PLAIN_NAS_MSG,          "Plain NAS message, not security protected"},
    { NAS_5GS_INTEG_NAS_MSG,          "Integrity protected"},
    { NAS_5GS_INTEG_CIPH_NAS_MSG,     "Integrity protected and ciphered"},
    { NAS_5GS_INTEG_NEW_NAS_MSG,      "Integrity protected with new 5GS security context"},
    { NAS_5GS_INTEG_CIPH_NEW_NAS_MSG, "Integrity protected and ciphered with new 5GS security context"},
    { 0,    NULL }
};

#define N1_SMINFO_FROM_UE "n1SmInfoFromUe"
#define N1_SMINFO_TO_UE   "n1SmInfoToUe"
#define UNKNOWN_N1_SMINFO "unknownN1SmInfo"

#define TGPP_PD_5GMM 0x7e
#define TGPP_PD_5GSM 0x2e

static const value_string nas_5gs_epd_vals[] = {
    { 0x00,              "Group call control" },
    { 0x01,              "Broadcast call control" },
    { 0x02,              "EPS session management messages" },
    { 0x03,              "Call Control; call related SS messages" },
    { 0x04,              "GPRS Transparent Transport Protocol (GTTP)" },
    { 0x05,              "Mobility Management messages" },
    { 0x06,              "Radio Resources Management messages" },
    { 0x07,              "EPS mobility management messages" },
    { 0x08,              "GPRS mobility management messages" },
    { 0x09,              "SMS messages" },
    { 0x0a,              "GPRS session management messages" },
    { 0x0b,              "Non call related SS messages" },
    { 0x0c,              "Location services specified in 3GPP TS 44.071" },
    { 0x0d,              "Unknown" },
    /*{0x0e,            "Reserved for extension of the PD to one octet length "},*/
    { 0x0f,              "Tests procedures described in 3GPP TS 44.014, 3GPP TS 34.109 and 3GPP TS 36.509" },
    { TGPP_PD_5GSM,      "5G session management messages" },
    { TGPP_PD_5GMM,      "5G mobility management messages" },
    { 0,    NULL }
};

struct nas5gs_private_data {
    uint8_t sec_hdr_type;
    uint32_t payload_container_type;
};

static struct nas5gs_private_data*
nas5gs_get_private_data(packet_info *pinfo)
{
    struct nas5gs_private_data *nas5gs_data = (struct nas5gs_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_nas_5gs, pinfo->curr_layer_num);
    if (!nas5gs_data) {
        nas5gs_data = wmem_new0(pinfo->pool, struct nas5gs_private_data);
        p_add_proto_data(pinfo->pool, pinfo, proto_nas_5gs, pinfo->curr_layer_num, nas5gs_data);
    }
    return nas5gs_data;
}

static uint32_t
get_ext_ambr_unit(uint32_t unit, const char **unit_str)
{
    uint32_t mult;

    if (unit == 0) {
        mult = 1;
        *unit_str = "Unit value 0, Illegal";
        return mult;
    }

    if (unit <= 0x05) {
        mult = pow4(uint32_t, unit - 0x01);
        *unit_str = "Kbps";
    } else if (unit <= 0x0a) {
        mult = pow4(uint32_t, unit - 0x06);
        *unit_str = "Mbps";
    } else if (unit <= 0x0f) {
        mult = pow4(uint32_t, unit - 0x0b);
        *unit_str = "Gbps";
    } else if (unit <= 0x14) {
        mult = pow4(uint32_t, unit - 0x10);
        *unit_str = "Tbps";
    } else if (unit <= 0x19) {
        mult = pow4(uint32_t, unit - 0x15);
        *unit_str = "Pbps";
    } else {
        mult = 256;
        *unit_str = "Pbps";
    }
    return mult;
}

/*
 * 9.11.3 5GS mobility management (5GMM) information elements
 */

 /*
  * 9.11.3.1 5GMM capability
  */
static uint16_t
de_nas_5gs_mm_5gmm_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    uint32_t    curr_offset;

    static int * const flags1[] = {
        &hf_nas_5gs_mm_sgc_b7,
        &hf_nas_5gs_mm_5g_iphc_cp_ciot_b6,
        &hf_nas_5gs_mm_n3_data_b5,
        &hf_nas_5gs_mm_5g_cp_ciot_b4,
        &hf_nas_5gs_mm_restrict_ec_b3,
        &hf_nas_5gs_mm_lpp_cap_b2,
        &hf_nas_5gs_mm_ho_attach_b1,
        &hf_nas_5gs_mm_s1_mode_b0,
        NULL
    };

    static int * const flags2[] = {
        &hf_nas_5gs_mm_racs_b7,
        &hf_nas_5gs_mm_nssaa_b6,
        &hf_nas_5gs_mm_5g_lcs_b5,
        &hf_nas_5gs_mm_v2xcnpc5_b4,
        &hf_nas_5gs_mm_v2xcepc5_b3,
        &hf_nas_5gs_mm_v2x_b2,
        &hf_nas_5gs_mm_5g_up_ciot_b1,
        &hf_nas_5gs_mm_5g_srvcc_b0,
        NULL
    };

    static int * const flags3[] = {
        &hf_nas_5gs_mm_5g_prose_l2relay_b7,
        &hf_nas_5gs_mm_5g_prose_dc_b6,
        &hf_nas_5gs_mm_5g_prose_dd_b5,
        &hf_nas_5gs_mm_er_nssai_b4,
        &hf_nas_5gs_mm_5g_ehc_cp_ciot_b3,
        &hf_nas_5gs_mm_multiple_up_b2,
        &hf_nas_5gs_mm_wsusa_b1,
        &hf_nas_5gs_mm_cag_b0,
        NULL
    };

    static int * const flags4[] = {
        &hf_nas_5gs_mm_pr_b7,
        &hf_nas_5gs_mm_rpr_b6,
        &hf_nas_5gs_mm_piv_b5,
        &hf_nas_5gs_mm_ncr_b4,
        &hf_nas_5gs_mm_nr_pssi_b3,
        &hf_nas_5gs_mm_5g_prose_l3rmt_b2,
        &hf_nas_5gs_mm_5g_prose_l2rmt_b1,
        &hf_nas_5gs_mm_5g_prose_l3relay_b0,
        NULL
    };

    static int * const flags5[] = {
        &hf_nas_5gs_mm_mpsiu_b7,
        &hf_nas_5gs_mm_uas_b6,
        &hf_nas_5gs_mm_nsag_b5,
        &hf_nas_5gs_mm_ex_cag_b4,
        &hf_nas_5gs_mm_ssnpnsi_b3,
        &hf_nas_5gs_mm_event_notif_b2,
        &hf_nas_5gs_mm_mint_b1,
        &hf_nas_5gs_mm_nssrg_b0,
        NULL
    };

    static int * const flags6[] = {
        &hf_nas_5gs_mm_sbts_b7,
        &hf_nas_5gs_mm_nsr_b6,
        &hf_nas_5gs_mm_ladn_ds_b5,
        &hf_nas_5gs_mm_rantiming_b4,
        &hf_nas_5gs_mm_eci_b3,
        &hf_nas_5gs_mm_esi_b2,
        &hf_nas_5gs_mm_rcman_b1,
        &hf_nas_5gs_mm_rcmap_b0,
        NULL
    };

    static int * const flags7[] = {
        &hf_nas_5gs_mm_5g_prose_l2end_b7,
        &hf_nas_5gs_mm_5g_prose_l3u2u_relay_b6,
        &hf_nas_5gs_mm_5g_prose_l2u2u_relay_b5,
        &hf_nas_5gs_mm_rslps_b4,
        &hf_nas_5gs_mm_sbns_b3,
        &hf_nas_5gs_mm_un_per_b2,
        &hf_nas_5gs_mm_a2xnpc5_b1,
        &hf_nas_5gs_mm_a2xepc5_b0,
        NULL
    };

    static int * const flags8[] = {
        &hf_nas_5gs_mm_a2x_uu_b7,
        &hf_nas_5gs_mm_slvi_b6,
        &hf_nas_5gs_mm_tempns_b5,
        &hf_nas_5gs_mm_supl_b4,
        &hf_nas_5gs_mm_lcs_upp_b3,
        &hf_nas_5gs_mm_pns_b2,
        &hf_nas_5gs_mm_rslp_b1,
        &hf_nas_5gs_mm_5g_prose_l3end_b0,
        NULL
    };

    static int * const flags9[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_nsuc_b3,
        &hf_nas_5gs_rslpl_b2,
        &hf_nas_5gs_mm_nvl_satnr_b1,
        &hf_nas_5gs_mm_mcsiu_b0,
        NULL
    };

    curr_offset = offset;

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags1, ENC_BIG_ENDIAN);
    curr_offset++;

    if ((curr_offset - offset) >= len)
        return (len);

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags2, ENC_BIG_ENDIAN);
    curr_offset++;

    if ((curr_offset - offset) >= len)
        return (len);

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags3, ENC_BIG_ENDIAN);
    curr_offset++;

    if ((curr_offset - offset) >= len)
        return (len);

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags4, ENC_BIG_ENDIAN);
    curr_offset++;

    if ((curr_offset - offset) >= len)
        return (len);

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags5, ENC_BIG_ENDIAN);
    curr_offset++;

    if ((curr_offset - offset) >= len)
        return (len);

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags6, ENC_BIG_ENDIAN);
    curr_offset++;

    if ((curr_offset - offset) >= len)
        return (len);

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags7, ENC_BIG_ENDIAN);
    curr_offset++;

    if ((curr_offset - offset) >= len)
        return (len);

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags8, ENC_BIG_ENDIAN);
    curr_offset++;

    if ((curr_offset - offset) >= len)
        return (len);

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags9, ENC_BIG_ENDIAN);
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_5gs_extraneous_data);

    return (curr_offset - offset);
}

/*
 * 9.11.3.2 5GMM cause
 */

static const value_string nas_5gs_mm_cause_vals[] = {
    { 0x03, "Illegal UE" },
    { 0x05, "PEI not accepted" },
    { 0x06, "Illegal ME" },
    { 0x07, "5GS services not allowed" },
    { 0x09, "UE identity cannot be derived by the network" },
    { 0x0a, "Implicitly deregistered" },
    { 0x0b, "PLMN not allowed" },
    { 0x0c, "Tracking area not allowed" },
    { 0x0d, "Roaming not allowed in this tracking area" },
    { 0x0f, "No suitable cells in tracking area" },
    { 0x14, "MAC failure" },
    { 0x15, "Synch failure" },
    { 0x16, "Congestion" },
    { 0x17, "UE security capabilities mismatch" },
    { 0x18, "Security mode rejected, unspecified" },
    { 0x1a, "Non-5G authentication unacceptable" },
    { 0x1b, "N1 mode not allowed" },
    { 0x1c, "Restricted service area" },
    { 0x1f, "Redirection to EPC required" },
    { 0x24, "IAB-node operation not authorized" },
    { 0x2b, "LADN not available" },
    { 0x3e, "No network slices available" },
    { 0x41, "Maximum number of PDU sessions reached" },
    { 0x43, "Insufficient resources for specific slice and DNN" },
    { 0x45, "Insufficient resources for specific slice" },
    { 0x47, "ngKSI already in use" },
    { 0x48, "Non-3GPP access to 5GCN not allowed" },
    { 0x49, "Serving network not authorized" },
    { 0x4a, "Temporarily not authorized for this SNPN" },
    { 0x4b, "Permanently not authorized for this SNPN" },
    { 0x4c, "Not authorized for this CAG or authorized for CAG cells only" },
    { 0x4d, "Wireline access area not allowed" },
    { 0x4e, "PLMN not allowed to operate at the present UE location" },
    { 0x4f, "UAS services not allowed" },
    { 0x50, "Disaster roaming for the determined PLMN with disaster condition not allowed" },
    { 0x51, "Selected N3IWF is not compatible with the allowed NSSAI" },
    { 0x52, "Selected TNGF is not compatible with the allowed NSSAI" },
    { 0x5a, "Payload was not forwarded" },
    { 0x5b, "DNN not supported or not subscribed in the slice" },
    { 0x5c, "Insufficient user-plane resources for the PDU session" },
    { 0x5d, "Onboarding services terminated" },
    { 0x5e, "User plane positioning not authorized" },
    { 0x5f, "Semantically incorrect message" },
    { 0x60, "Invalid mandatory information" },
    { 0x61, "Message type non-existent or not implemented" },
    { 0x62, "Message type not compatible with the protocol state" },
    { 0x63, "Information element non-existent or not implemented" },
    { 0x64, "Conditional IE error" },
    { 0x65, "Message not compatible with the protocol state" },
    { 0x6f, "Protocol error, unspecified" },
    { 0,    NULL }
};

static uint16_t
de_nas_5gs_mm_5gmm_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{
    uint32_t cause;

    proto_tree_add_item_ret_uint(tree, hf_nas_5gs_mm_5gmm_cause, tvb, offset, 1, ENC_BIG_ENDIAN, &cause);

    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
        val_to_str_const(cause, nas_5gs_mm_cause_vals, "Unknown"));


    return 1;
}


static const value_string nas_5gs_mm_drx_vals[] = {
    { 0x0, "DRX value not specified" },
    { 0x1, "DRX cycle parameter T = 32" },
    { 0x2, "DRX cycle parameter T = 64" },
    { 0x3, "DRX cycle parameter T = 128" },
    { 0x4, "DRX cycle parameter T = 256" },
    { 0, NULL }
};


/* 9.11.3.2A    5GS DRX parameters*/
static uint16_t
de_nas_5gs_mm_5gs_drx_param(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{

    proto_tree_add_item(tree, hf_nas_5gs_mm_5gs_drx_param, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.11.3.3 5GS identity type
 */
static uint16_t
de_nas_5gs_mm_5gs_identity_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{

    proto_tree_add_item(tree, hf_nas_5gs_mm_type_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.11.3.4    5GS mobile identity
 */
static const value_string nas_5gs_mm_type_id_vals[] = {
    { 0x0, "No identity" },
    { 0x1, "SUCI" },
    { 0x2, "5G-GUTI" },
    { 0x3, "IMEI" },
    { 0x4, "5G-S-TMSI" },
    { 0x5, "IMEISV" },
    { 0x6, "MAC address" },
    { 0x7, "EUI-64" },
    { 0, NULL }
 };

static true_false_string nas_5gs_odd_even_tfs = {
    "Odd number of identity digits",
    "Even number of identity digits"
};

static const value_string nas_5gs_mm_supi_fmt_vals[] = {
    { 0x0, "IMSI" },
    { 0x1, "Network Specific Identifier" },
    { 0x2, "GCI" },
    { 0x3, "GLI" },
    { 0, NULL }
};

static const value_string nas_5gs_mm_prot_scheme_id_vals[] = {
    { 0x0, "NULL scheme" },
    { 0x1, "ECIES scheme profile A" },
    { 0x2, "ECIES scheme profile B" },
    { 0, NULL }
};

static true_false_string nas_5gs_mauri_tfs = {
    "MAC address is not usable as an equipment identifier",
    "No restrictions"
};

static uint16_t
de_nas_5gs_mm_5gs_mobile_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    uint8_t oct, type_id, supi_fmt;
    uint32_t scheme_id, fiveg_tmsi;
    tvbuff_t * new_tvb;
    const char *route_id_str;
    proto_item* ti;

    static int * const flags_spare_tid[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_mm_type_id,
        NULL
    };

    static int * const flags_supi_fmt_tid[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_mm_supi_fmt,
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_mm_type_id,
        NULL
    };

    static int * const flags_odd_even_tid[] = {
        &hf_nas_5gs_mm_odd_even,
        &hf_nas_5gs_mm_type_id,
        NULL
    };

    static int * const flags_mauri_tid[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_mm_mauri,
        &hf_nas_5gs_mm_type_id,
        NULL
    };

    oct = tvb_get_uint8(tvb, offset);
    type_id = oct & 0x07;

    switch (type_id) {
    case 0:
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_spare_tid, ENC_BIG_ENDIAN);
        break;
    case 1:
        /* SUCI */
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_supi_fmt_tid, ENC_BIG_ENDIAN);
        offset++;

        supi_fmt = (oct & 0x70) >> 4;
        if (supi_fmt == 0) {
            /* IMSI */

            /* MCC digit 2    MCC digit 1
             * MNC digit 3    MCC digit 3
             * MNC digit 2    MNC digit 1
             */
            offset = dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, E212_NONE, true);
            /* Routing indicator octet 8-9 */
            new_tvb = tvb_new_subset_length(tvb, offset, 2);
            route_id_str = tvb_bcd_dig_to_str(pinfo->pool, new_tvb, 0, (tvb_get_uint8(new_tvb, 1) == 0xff) ? 1 : 2, NULL, false);
            proto_tree_add_string(tree, hf_nas_5gs_mm_routing_indicator, new_tvb, 0, -1, route_id_str);
            offset += 2;
            /* Protection scheme id octet 10 */
            proto_tree_add_item_ret_uint(tree, hf_nas_5gs_mm_prot_scheme_id, tvb, offset, 1, ENC_BIG_ENDIAN, &scheme_id);
            offset += 1;
            /* Home network public key identifier octet 11 */
            proto_tree_add_item(tree, hf_nas_5gs_mm_pki, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            /* Scheme output octet 12-x */
            if (scheme_id == 0) {
                new_tvb = tvb_new_subset_length(tvb, offset, len - 8);
                proto_tree_add_item(tree, hf_nas_5gs_mm_suci_msin, new_tvb, 0, -1, ENC_BCD_DIGITS_0_9|ENC_LITTLE_ENDIAN);
            } else {
                proto_item *pi = proto_tree_add_item(tree, hf_nas_5gs_mm_scheme_output, tvb, offset, len - 8, ENC_NA);
                if ((scheme_id == 1 && len >= 49) || (scheme_id == 2 && len >= 50)) {
                    uint32_t public_key_len;
                    proto_tree *subtree = proto_item_add_subtree(pi, ett_nas_5gs_mm_scheme_output);
                    if (scheme_id == 1) {
                        public_key_len = 32;
                    } else {
                        public_key_len = 33;
                    }
                    proto_tree_add_item(subtree, hf_nas_5gs_mm_scheme_output_ecc_public_key, tvb, offset, public_key_len, ENC_NA);
                    offset += public_key_len;
                    proto_tree_add_item(subtree, hf_nas_5gs_mm_scheme_output_ciphertext, tvb, offset, len - public_key_len - 16, ENC_NA);
                    offset += len - public_key_len - 16;
                    proto_tree_add_item(subtree, hf_nas_5gs_mm_scheme_output_mac_tag, tvb, offset, 8, ENC_BIG_ENDIAN);
                }
            }
        } else if (supi_fmt == 1 ||supi_fmt == 2 ||supi_fmt == 3) {
            /* NAI */
            proto_tree_add_item(tree, hf_nas_5gs_mm_suci_nai, tvb, offset, len - 1, ENC_UTF_8 | ENC_NA);
        } else {
            proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_unknown_value, tvb, offset, len - 1);
        }
        break;
    case 2:
        /* 5G-GUTI*/
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_spare_tid, ENC_BIG_ENDIAN);
        offset++;
        /* MCC digit 2    MCC digit 1
         * MNC digit 3    MCC digit 3
         * MNC digit 2    MNC digit 1
         */
        offset = dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, E212_GUAMI, true);
        /* AMF Region ID octet 7 */
        proto_tree_add_item(tree, hf_nas_5gs_amf_region_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* AMF Set ID octet 8 */
        proto_tree_add_item(tree, hf_nas_5gs_amf_set_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset++;
        /* AMF AMF Pointer AMF Set ID (continued) */
        proto_tree_add_item(tree, hf_nas_5gs_amf_pointer, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item_ret_uint(tree, hf_nas_5gs_5g_tmsi, tvb, offset, 4, ENC_BIG_ENDIAN, &fiveg_tmsi);
        ti = proto_tree_add_uint(tree, hf_3gpp_tmsi, tvb, offset, 4, fiveg_tmsi);
        proto_item_set_hidden(ti);
        break;
    case 3:
        /* IMEI */
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_odd_even_tid, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_nas_5gs_mm_imei, tvb, offset, len, ENC_BCD_DIGITS_0_9 | ENC_LITTLE_ENDIAN | ENC_BCD_SKIP_FIRST);
        break;
    case 4:
        /*5G-S-TMSI*/
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_odd_even_tid, ENC_BIG_ENDIAN);
        offset++;
        /* AMF Set ID */
        proto_tree_add_item(tree, hf_nas_5gs_amf_set_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset++;
        /* AMF Pointer AMF Set ID (continued) */
        proto_tree_add_item(tree, hf_nas_5gs_amf_pointer, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item_ret_uint(tree, hf_nas_5gs_5g_tmsi, tvb, offset, 4, ENC_BIG_ENDIAN, &fiveg_tmsi);
        ti = proto_tree_add_uint(tree, hf_3gpp_tmsi, tvb, offset, 4, fiveg_tmsi);
        proto_item_set_hidden(ti);
        break;
    case 5:
        /* IMEISV */
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_odd_even_tid, ENC_BIG_ENDIAN);
        /* XXXX Do we need the odd/even bit?*/
        proto_tree_add_item(tree, hf_nas_5gs_mm_imeisv, tvb, offset, len, ENC_BCD_DIGITS_0_9 | ENC_LITTLE_ENDIAN | ENC_BCD_SKIP_FIRST);
        break;
    case 6:
        /* MAC address */
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_mauri_tid, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(tree, hf_nas_5gs_mm_mac_addr, tvb, offset, 6, ENC_NA);
        break;
    case 7:
        /* EUI-64 */
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_spare_tid, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(tree, hf_nas_5gs_mm_eui_64, tvb, offset, 8, ENC_NA);
        break;

    default:
        proto_tree_add_item(tree, hf_nas_5gs_mm_type_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_unknown_value, tvb, offset, len);
        break;
    }

    return len;
}

/*
 * 9.11.3.5    5GS network feature support
 */

static const value_string nas_5gs_nw_feat_sup_emc_values[] = {
    { 0x0, "Emergency services not supported" },
    { 0x1, "Emergency services supported in NR connected to 5GCN only" },
    { 0x2, "Emergency services supported in E-UTRA connected to 5GCN only" },
    { 0x3, "Emergency services supported in NR connected to 5GCN and E-UTRA connected to 5GCN" },
    { 0, NULL }
};

static const value_string nas_5gs_nw_feat_sup_emf_values[] = {
    { 0x0, "Emergency services fallback not supported" },
    { 0x1, "Emergency services fallback supported in NR connected to 5GCN only" },
    { 0x2, "Emergency services fallback supported in E-UTRA connected to 5GCN only" },
    { 0x3, "Emergency services fallback supported in NR connected to 5GCN and E-UTRA connected to 5GCN" },
    { 0, NULL }
};

static const true_false_string tfs_nas_5gs_nw_feat_sup_mpsi = {
    "Access identity 1 valid in RPLMN or equivalent PLMN",
    "Access identity 1 not valid in RPLMN or equivalent PLMN"
};

static const true_false_string tfs_nas_5gs_nw_feat_sup_mcsi = {
    "Access identity 2 valid",
    "Access identity 2 not valid"
};

static const value_string nas_5gs_nw_feat_sup_restrict_ec_values[] = {
    { 0x0, "WB-N1: Both CE mode A and CE mode B are not restricted / NB-N1: Use of enhanced coverage is not restricted" },
    { 0x1, "WB-N1: Both CE mode A and CE mode B are restricted / NB-N1: Use of enhanced coverage is restricted" },
    { 0x2, "WB-N1: CE mode B is restricted / NB-N1: Restricted" },
    { 0x3, "Restricted" },
    { 0, NULL }
};

static uint16_t
de_nas_5gs_mm_5gs_nw_feat_sup(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset;

    static int * const flags_oct3[] = {
        &hf_nas_5gs_nw_feat_sup_mpsi_b7,
        &hf_nas_5gs_nw_feat_sup_ims_iwk_n26_b6,
        &hf_nas_5gs_nw_feat_sup_ims_emf_b5b4,
        &hf_nas_5gs_nw_feat_sup_ims_emc_b3b2,
        &hf_nas_5gs_nw_feat_sup_ims_vops_n3gpp,
        &hf_nas_5gs_nw_feat_sup_ims_vops_3gpp,
        NULL
    };

    static int * const flags_oct4[] = {
        &hf_nas_5gs_nw_feat_sup_5g_ciot_up,
        &hf_nas_5gs_nw_feat_sup_5g_iphc_cp_ciot,
        &hf_nas_5gs_nw_feat_sup_n3_data,
        &hf_nas_5gs_nw_feat_sup_5g_cp_ciot,
        &hf_nas_5gs_nw_feat_sup_restrict_ec,
        &hf_nas_5gs_nw_feat_sup_mcsi,
        &hf_nas_5gs_nw_feat_sup_emcn3,
        NULL
    };

    static int * const flags_oct5[] = {
        &hf_nas_5gs_nw_feat_sup_un_per,
        &hf_nas_5gs_nw_feat_sup_pr,
        &hf_nas_5gs_nw_feat_sup_rpr,
        &hf_nas_5gs_nw_feat_sup_piv,
        &hf_nas_5gs_nw_feat_sup_ncr,
        &hf_nas_5gs_nw_feat_sup_5g_ehc_cp_ciot,
        &hf_nas_5gs_nw_feat_sup_ats_ind,
        &hf_nas_5gs_nw_feat_sup_5g_lcs,
        NULL
    };

    static int * const flags_oct6[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_nw_feat_sup_rslp,
        &hf_nas_5gs_nw_feat_sup_supl,
        &hf_nas_5gs_nw_feat_sup_lcs_upp,
        &hf_nas_5gs_nw_feat_sup_naps,
        NULL
    };

    /* MPSI    IWK N26    EMF    EMC    IMS VoPS    octet 3*/
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags_oct3, ENC_BIG_ENDIAN);
    curr_offset++;

    if (len == 1) {
        return len;
    }

    /* 5G-UP CIoT 5G-IPHC-CP CIoT N3 data 5G-CP CIoT RestrictEC MCSI EMCN3 octet 4*/
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags_oct4, ENC_BIG_ENDIAN);
    curr_offset++;

    if (len == 2) {
        return len;
    }

    /* UN-PER PR RPR PIV NCR 5G-EHC-CP CIoT ATS-IND 5G-LCS octet 5*/
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags_oct5, ENC_BIG_ENDIAN);
    curr_offset++;

    if (len == 3) {
        return len;
    }

    /* spare spare spare spare RSLP SUPL LCS-UPP NAPS octet 6*/
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags_oct6, ENC_BIG_ENDIAN);
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_5gs_extraneous_data);

    return len;
}

/*
 * 9.11.3.6    5GS registration result
 */

static const value_string nas_5gs_mm_reg_res_values[] = {
    { 0x1, "3GPP access" },
    { 0x2, "Non-3GPP access" },
    { 0x3, "3GPP access and non-3GPP access" },
{ 0, NULL }
};

static true_false_string tfs_nas_5gs_mm_reg_res_nssaa_perf = {
    "Network slice-specific authentication and authorization is to be performed",
    "Network slice-specific authentication and authorization is not to be performed"
};

static true_false_string tfs_nas_5gs_mm_reg_res_emergency_reg = {
    "Registered for emergency services",
    "Not registered for emergency services"
};

static true_false_string tfs_nas_5gs_mm_reg_res_disaster_roaming_reg_res = {
    "Request for registration for disaster roaming services accepted as registration not for disaster roaming services",
    "No additional information"
};

static uint16_t
de_nas_5gs_mm_5gs_reg_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{

    static int* const flags[] = {
        &hf_nas_5gs_mm_reg_res_disaster_roaming_reg_res,
        &hf_nas_5gs_mm_reg_res_emergency_reg,
        &hf_nas_5gs_mm_reg_res_nssaa_perf,
        &hf_nas_5gs_mm_reg_res_sms_allowed,
        &hf_nas_5gs_mm_reg_res_res,
        NULL
    };

    /* 0 Spare 0 Spare 0 Spare NSSAA Performed SMS allowed 5GS registration result value */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.11.3.7    5GS registration type
 */

static const value_string nas_5gs_registration_type_values[] = {
    { 0x1, "initial registration" },
    { 0x2, "mobility registration updating" },
    { 0x3, "periodic registration updating" },
    { 0x4, "emergency registration" },
    { 0x5, "SNPN onboarding registration" },
    { 0x6, "disaster roaming mobility registration updating" },
    { 0x7, "disaster roaming initial registration" },
    { 0, NULL }
 };

static true_false_string nas_5gs_for_tfs = {
    "Follow-on request pending",
    "No follow-on request pending"
};

static int * const nas_5gs_registration_type_flags[] = {
    &hf_nas_5gs_mm_for,
    &hf_nas_5gs_mm_5gs_reg_type,
    NULL
};

static uint16_t
de_nas_5gs_mm_5gs_reg_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{



    /* FOR    SMS requested    5GS registration type value    octet 3*/
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, nas_5gs_registration_type_flags, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.11.3.8     5GS tracking area identity
 */
static uint16_t
de_nas_5gs_mm_5gs_ta_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{
    /* MCC digit 2    MCC digit 1 Octet 2*/
    /* MNC digit 3    MCC digit 3 Octet 3*/
    /* MNC digit 2    MNC digit 1 Octet 4*/
    /* TAC Octet 5 - 7 */
    uint32_t curr_offset;

    curr_offset = offset;

    curr_offset = dissect_e212_mcc_mnc(tvb, pinfo, tree, curr_offset, E212_5GSTAI, true);
    proto_tree_add_item(tree, hf_nas_5gs_tac, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
    curr_offset += 3;

    return curr_offset - offset;
}

/*
 * 9.11.3.9     5GS tracking area identity list
 */
static const value_string nas_5gs_mm_tal_t_li_values[] = {
    { 0x00, "list of TACs belonging to one PLMN or SNPN, with non-consecutive TAC values" },
    { 0x01, "list of TACs belonging to one PLMN or SNPN, with consecutive TAC values" },
    { 0x02, "list of TAIs belonging to different PLMNs" },
    { 0, NULL } };

static const value_string nas_5gs_mm_tal_num_e[] = {
    { 0x00, "1 element" },
    { 0x01, "2 elements" },
    { 0x02, "3 elements" },
    { 0x03, "4 elements" },
    { 0x04, "5 elements" },
    { 0x05, "6 elements" },
    { 0x06, "7 elements" },
    { 0x07, "8 elements" },
    { 0x08, "9 elements" },
    { 0x09, "10 elements" },
    { 0x0a, "11 elements" },
    { 0x0b, "12 elements" },
    { 0x0c, "13 elements" },
    { 0x0d, "14 elements" },
    { 0x0e, "15 elements" },
    { 0x0f, "16 elements" },
    { 0, NULL }
};

static uint16_t
de_nas_5gs_mm_5gs_ta_id_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    proto_tree *sub_tree;
    proto_item *item;

    static int * const flags[] = {
        &hf_nas_5gs_mm_tal_t_li,
        &hf_nas_5gs_mm_tal_num_e,
        NULL
    };

    unsigned num_par_tal = 1;
    uint32_t curr_offset = offset;
    uint32_t start_offset;
    uint8_t tal_head, tal_t_li, tal_num_e;

    /*Partial tracking area list*/
    while ((curr_offset - offset) < len) {
        start_offset = curr_offset;
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_part_tal, &item, "Partial tracking area list  %u", num_par_tal);
        /*Head of Partial tracking area list*/
        /* Type of list    Number of elements    octet 1 */
        tal_head = tvb_get_uint8(tvb, curr_offset);
        tal_t_li = (tal_head & 0x60) >> 5;
        tal_num_e = (tal_head & 0x1f) + 1;
        proto_tree_add_bitmask_list(sub_tree, tvb, curr_offset, 1, flags, ENC_BIG_ENDIAN);
        curr_offset++;
        switch (tal_t_li) {
        case 0:
            /*octet 2  MCC digit2  MCC digit1*/
            /*octet 3  MNC digit3  MCC digit3*/
            /*octet 4  MNC digit2  MNC digit1*/
            dissect_e212_mcc_mnc(tvb, pinfo, sub_tree, curr_offset, E212_5GSTAI, true);
            curr_offset += 3;
            while (tal_num_e > 0) {
                proto_tree_add_item(sub_tree, hf_nas_5gs_tac, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
                curr_offset += 3;
                tal_num_e--;
            }
            break;
        case 1:
            /*octet 2  MCC digit2  MCC digit1*/
            /*octet 3  MNC digit3  MCC digit3*/
            /*octet 4  MNC digit2  MNC digit1*/
            dissect_e212_mcc_mnc(tvb, pinfo, sub_tree, curr_offset, E212_5GSTAI, true);
            curr_offset += 3;

            /*octet 5  TAC 1*/
            proto_tree_add_item(sub_tree, hf_nas_5gs_tac, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
            curr_offset+=3;
            break;
        case 2:
            while (tal_num_e > 0) {
                /*octet 2  MCC digit2  MCC digit1*/
                /*octet 3  MNC digit3  MCC digit3*/
                /*octet 4  MNC digit2  MNC digit1*/
                dissect_e212_mcc_mnc(tvb, pinfo, sub_tree, curr_offset, E212_5GSTAI, true);
                curr_offset += 3;

                /*octet 5  TAC 1*/
                proto_tree_add_item(sub_tree, hf_nas_5gs_tac, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
                curr_offset += 3;

                tal_num_e--;
            }
            break;
        case 3:
            dissect_e212_mcc_mnc(tvb, pinfo, sub_tree, curr_offset, E212_5GSTAI, true);
            curr_offset += 3;
            break;
        default:
            proto_tree_add_expert(sub_tree, pinfo, &ei_nas_5gs_unknown_value, tvb, curr_offset, len - 1);
        }

        /*calculate the length of IE?*/
        proto_item_set_len(item, curr_offset - start_offset);
        /*calculate the number of Partial tracking area list*/
        num_par_tal++;
    }

    return len;
}

/*
 * 9.11.3.9A    5GS update type
 */
static const value_string nas_5gs_mm_5gs_pnb_ciot_values[] = {
    { 0x0, "no additional information" },
    { 0x1, "control plane CIoT 5GS optimization" },
    { 0x2, "user plane CIoT 5GS optimization" },
    { 0x3, "reserved" },
    { 0, NULL }
};

static const value_string nas_5gs_mm_eps_pnb_ciot_values[] = {
    { 0x0, "no additional information" },
    { 0x1, "control plane CIoT EPS optimization" },
    { 0x2, "user plane CIoT EPS optimization" },
    { 0x3, "reserved" },
    { 0, NULL }
};

static uint16_t
de_nas_5gs_mm_update_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{
    static int * const flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_mm_eps_pnb_ciot,
        &hf_nas_5gs_mm_5gs_pnb_ciot,
        &hf_nas_5gs_mm_ng_ran_rcu,
        &hf_nas_5gs_mm_sms_requested,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;

}

/*
 * 9.11.3.10    ABBA
 */
static uint16_t
de_nas_5gs_mm_abba(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_mm_abba, tvb, offset, len, ENC_NA);

    return len;
}

/*
 * 9.11.3.11    Void
 */

/*
 * 9.11.3.12    Additional 5G security information
 */
static uint16_t
de_nas_5gs_mm_add_5g_sec_inf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{
    static int * const flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_mm_rinmr,
        &hf_nas_5gs_mm_hdp,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.11.3.12A   Additional information requested
 */
static uint16_t
de_nas_5gs_mm_add_inf_req(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char* add_string _U_, int string_len _U_)
{
    static int* const flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_spare_b1,
        &hf_nas_5gs_mm_cipher_key,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}

/*
 *  9.11.3.13    Allowed PDU session status
 */
static true_false_string tfs_nas_5gs_allow_pdu_ses_sts_psi = {
    "user-plane resources of corresponding PDU session can be re-established over 3GPP access",
    "user-plane resources of corresponding PDU session is not allowed to be re-established over 3GPP access"
};

static uint16_t
de_nas_5gs_mm_allow_pdu_ses_sts(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)

{
    int curr_offset;

    static int * const psi_0_7_flags[] = {
        &hf_nas_5gs_allow_pdu_ses_sts_psi_7_b7,
        &hf_nas_5gs_allow_pdu_ses_sts_psi_6_b6,
        &hf_nas_5gs_allow_pdu_ses_sts_psi_5_b5,
        &hf_nas_5gs_allow_pdu_ses_sts_psi_4_b4,
        &hf_nas_5gs_allow_pdu_ses_sts_psi_3_b3,
        &hf_nas_5gs_allow_pdu_ses_sts_psi_2_b2,
        &hf_nas_5gs_allow_pdu_ses_sts_psi_1_b1,
        &hf_nas_5gs_allow_pdu_ses_sts_psi_0_b0,
        NULL
    };

    static int * const psi_8_15_flags[] = {
        &hf_nas_5gs_allow_pdu_ses_sts_psi_15_b7,
        &hf_nas_5gs_allow_pdu_ses_sts_psi_14_b6,
        &hf_nas_5gs_allow_pdu_ses_sts_psi_13_b5,
        &hf_nas_5gs_allow_pdu_ses_sts_psi_12_b4,
        &hf_nas_5gs_allow_pdu_ses_sts_psi_11_b3,
        &hf_nas_5gs_allow_pdu_ses_sts_psi_10_b2,
        &hf_nas_5gs_allow_pdu_ses_sts_psi_9_b1,
        &hf_nas_5gs_allow_pdu_ses_sts_psi_8_b0,
        NULL
    };

    curr_offset = offset;
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, psi_0_7_flags, ENC_BIG_ENDIAN);
    curr_offset++;

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, psi_8_15_flags, ENC_BIG_ENDIAN);
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_5gs_extraneous_data);

    return (curr_offset - offset);
}

/*
 * 9.11.3.14    Authentication failure parameter
 */
/* See subclause 10.5.3.2.2 in 3GPP TS 24.008 */

/*
 *  9.11.3.15    Authentication parameter AUTN
 */
/* See subclause 10.5.3.1 in 3GPP TS 24.008 */

/*
 *   9.11.3.16    Authentication parameter RAND
 */

/* See subclause 10.5.3.1 in 3GPP TS 24.008 */

/*
 * 9.11.3.17    Authentication response parameter
 */
/* See subclause 9.9.3.4 in 3GPP TS 24.301 */

/*
 *   9.11.3.18    Configuration update indication
 */
static uint16_t
de_nas_5gs_mm_conf_upd_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{

    static int * const flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_mm_conf_upd_ind_red_b1,
        &hf_nas_5gs_mm_conf_upd_ind_ack_b0,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.11.3.18A   CAG information list
 */
static true_false_string tfs_5gs_mm_cag_info_entry_cag_only = {
    "the UE is not allowed to access 5GS via non-CAG cells",
    "the UE is allowed to access 5GS via non-CAG cells"
};

static uint16_t
dissect_nas_5gs_mm_cag_information_list(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len, bool is_ext)
{
    proto_tree *sub_tree;
    proto_item *item;
    unsigned num_entry = 1;
    uint32_t curr_offset = offset;
    uint32_t start_offset, entry_len;
    bool caili, lci;

    while ((curr_offset - offset) < len) {
        start_offset = curr_offset;
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_cag_info_entry,
                                                 &item, "%sCAG information entry %u",
                                                 is_ext ? "Extended " : "", num_entry);
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_mm_cag_info_entry_len, tvb, curr_offset, is_ext ? 2 : 1, ENC_BIG_ENDIAN, &entry_len);
        curr_offset += is_ext ? 2 : 1;
        dissect_e212_mcc_mnc(tvb, pinfo, sub_tree, curr_offset, E212_NONE, true);
        curr_offset += 3;
        if (is_ext) {
            proto_tree_add_bits_item(sub_tree, hf_nas_5gs_spare_bits, tvb, (curr_offset << 3), 5, ENC_BIG_ENDIAN);
            proto_tree_add_item_ret_boolean(sub_tree, hf_nas_5gs_mm_cag_info_entry_caili, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &caili);
            proto_tree_add_item_ret_boolean(sub_tree, hf_nas_5gs_mm_cag_info_entry_lci, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &lci);
        } else {
            proto_tree_add_bits_item(sub_tree, hf_nas_5gs_spare_bits, tvb, (curr_offset << 3), 7, ENC_BIG_ENDIAN);
            caili = false;
            lci = false;
        }
        proto_tree_add_item(sub_tree, hf_nas_5gs_mm_cag_info_entry_cag_only, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
        if (lci) {
            proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_mm_cag_info_entry_cag_without_add_info_list_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &entry_len);
            curr_offset += 2;
        }
        while ((curr_offset - start_offset) < entry_len) {
            proto_tree_add_item(sub_tree, hf_nas_5gs_mm_cag_info_entry_cag_id, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
            curr_offset += 4;
        }
        if (caili) {
            uint32_t caili_start_offset = curr_offset;
            unsigned num_entry2 = 1;

            proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_mm_cag_info_entry_cag_with_add_info_list_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &entry_len);
            curr_offset += 2;
            while ((curr_offset - caili_start_offset) < entry_len) {
                proto_tree *sub_tree2;
                proto_item *item2;
                bool tvii;
                uint32_t start_offset2 = curr_offset;

                sub_tree2 = proto_tree_add_subtree_format(sub_tree, tvb, curr_offset, -1, ett_nas_5gs_mm_cag_info_entry,
                                                          &item2, "CAG-ID with additional information entry %u", num_entry2);
                proto_tree_add_item(sub_tree2, hf_nas_5gs_mm_cag_info_entry_cag_with_add_info_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                curr_offset += 2;
                proto_tree_add_item(sub_tree2, hf_nas_5gs_mm_cag_info_entry_cag_id, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
                curr_offset += 4;
                proto_tree_add_bits_item(sub_tree2, hf_nas_5gs_spare_bits, tvb, (curr_offset << 3), 1, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(sub_tree2, hf_nas_5gs_mm_cag_info_entry_svii, tvb, (curr_offset << 3) + 1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(sub_tree2, hf_nas_5gs_mm_cag_info_entry_svii, tvb, (curr_offset << 3) + 2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(sub_tree2, hf_nas_5gs_mm_cag_info_entry_svii, tvb, (curr_offset << 3) + 3, 1, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(sub_tree2, hf_nas_5gs_mm_cag_info_entry_svii, tvb, (curr_offset << 3) + 4, 1, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(sub_tree2, hf_nas_5gs_mm_cag_info_entry_svii, tvb, (curr_offset << 3) + 5, 1, ENC_BIG_ENDIAN);
                proto_tree_add_bits_item(sub_tree2, hf_nas_5gs_mm_cag_info_entry_svii, tvb, (curr_offset << 3) + 6, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item_ret_boolean(sub_tree2, hf_nas_5gs_mm_cag_info_entry_tvii, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &tvii);
                curr_offset++;
                if (tvii) {
                    uint32_t time_periods, i;

                    proto_tree_add_item_ret_uint(sub_tree2, hf_nas_5gs_mm_cag_info_entry_nb_time_periods, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &time_periods);
                    curr_offset++;
                    for (i = 0; i < time_periods; i++) {
                        proto_tree_add_item(sub_tree2, hf_nas_5gs_mm_cag_info_entry_time_period, tvb, curr_offset, 16, ENC_NA);
                        curr_offset += 16;
                    }
                }
                proto_item_set_len(item2, curr_offset - start_offset2);
                num_entry2++;
            }
        }
        proto_item_set_len(item, curr_offset - start_offset);
        num_entry++;
    }

    return len;
}

static uint16_t
de_nas_5gs_mm_cag_information_list(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    return dissect_nas_5gs_mm_cag_information_list(tvb, tree, pinfo, offset, len, false);
}

/*
 * 9.11.3.18B CIoT small data container
 */
static void
nas_5gs_decode_user_data_cont(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
                              uint32_t offset, unsigned len, int hfindex)
{
    proto_item *item;

    item = proto_tree_add_item(tree, hfindex, tvb, offset, len, ENC_NA);
    if (g_nas_5gs_decode_user_data_container_as != DECODE_USER_DATA_AS_NONE) {
        tvbuff_t *user_data_cont_tvb;
        volatile dissector_handle_t handle;

        user_data_cont_tvb = tvb_new_subset_length(tvb, offset, len);
        if (g_nas_5gs_decode_user_data_container_as == DECODE_USER_DATA_AS_IP) {
            uint8_t first_byte = tvb_get_uint8(user_data_cont_tvb, 0);
            if (first_byte >= 0x45 && first_byte <= 0x4f && len > 20)
                handle = ipv4_handle;
            else if ((first_byte & 0xf0) == 0x60 && len > 40)
                handle = ipv6_handle;
            else
                handle = NULL;
        } else if (g_nas_5gs_decode_user_data_container_as == DECODE_USER_DATA_AS_NON_IP) {
            handle = non_ip_data_handle;
        } else {
            handle = ethernet_handle;
        }
        if (handle) {
            col_append_str(pinfo->cinfo, COL_PROTOCOL, "/");
            col_set_fence(pinfo->cinfo, COL_PROTOCOL);
            col_append_str(pinfo->cinfo, COL_INFO, ", ");
            col_set_fence(pinfo->cinfo, COL_INFO);
            TRY {
                proto_tree *toptree = proto_tree_get_root(tree);
                call_dissector_only(handle, user_data_cont_tvb, pinfo, toptree, NULL);
            } CATCH_BOUNDS_ERRORS {
                /* Dissection exception: message was probably non IP and heuristic was too weak */
                proto_tree *subtree = proto_item_add_subtree(item, ett_nas_5gs_user_data_cont);
                show_exception(user_data_cont_tvb, pinfo, subtree, EXCEPT_CODE, GET_MESSAGE);
            } ENDTRY
        }
    }
}

static const value_string nas_5gs_mm_ciot_small_data_cont_data_type_values[] = {
    { 0x00, "Control plane user data" },
    { 0x01, "SMS" },
    { 0x02, "Location services message container" },
    { 0, NULL }
};

static const value_string nas_5gs_mm_ciot_small_data_cont_ddx_values[] = {
    { 0x00, "No information available" },
    { 0x01, "No further uplink and no further downlink data transmission subsequent to the uplink data transmission is expected" },
    { 0x02, "Only a single downlink data transmission and no further uplink data transmission subsequent to the uplink data transmission is expected" },
    { 0x03, "Reserved" },
    { 0, NULL }
};

static uint16_t
de_nas_5gs_mm_ciot_small_data_cont(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset;
    uint32_t data_type, add_info_len;
    proto_tree *sub_tree;
    proto_item *item;

    proto_tree_add_item_ret_uint(tree, hf_nas_5gs_mm_ciot_small_data_cont_data_type,
                                 tvb, curr_offset, 1, ENC_BIG_ENDIAN, &data_type);
    switch (data_type) {
    case 0:
        proto_tree_add_item(tree, hf_nas_5gs_mm_ciot_small_data_cont_ddx,
                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_nas_5gs_mm_ciot_small_data_cont_pdu_session_id,
                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
        nas_5gs_decode_user_data_cont(tvb, tree, pinfo, curr_offset, len - curr_offset,
                                      hf_nas_5gs_mm_ciot_small_data_cont_data_contents);
        break;
    case 1:
        proto_tree_add_bits_item(tree, hf_nas_5gs_spare_bits, tvb,
                                 (curr_offset << 3) + 3, 5, ENC_BIG_ENDIAN);
        curr_offset++;
        item = proto_tree_add_item(tree, hf_nas_5gs_mm_ciot_small_data_cont_data_contents,
                                   tvb, curr_offset, len - curr_offset, ENC_NA);
        if (gsm_a_dtap_handle) {
            sub_tree = proto_item_add_subtree(item, ett_nas_5gs_ciot_small_data_cont_data_contents);
            call_dissector(gsm_a_dtap_handle, tvb_new_subset_length(tvb, curr_offset, curr_offset - len), pinfo, sub_tree);
        }
        break;
    case 2:
        proto_tree_add_item(tree, hf_nas_5gs_mm_ciot_small_data_cont_ddx,
                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(tree, hf_nas_5gs_spare_bits, tvb,
                                 (curr_offset << 3) + 5, 3, ENC_BIG_ENDIAN);
        curr_offset++;
        proto_tree_add_item_ret_uint(tree, hf_nas_5gs_mm_ciot_small_data_cont_add_info_len,
                                     tvb, curr_offset, 1, ENC_BIG_ENDIAN, &add_info_len);
        curr_offset++;
        if (add_info_len > 0) {
            proto_tree_add_item(tree, hf_nas_5gs_mm_ciot_small_data_cont_add_info,
                                tvb, curr_offset, add_info_len, ENC_NA);
            curr_offset += add_info_len;
        }
        proto_tree_add_item(tree, hf_nas_5gs_mm_ciot_small_data_cont_data_contents,
                            tvb, curr_offset, len - curr_offset, ENC_NA);
        break;
    default:
        proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_unknown_value, tvb, curr_offset, len);
        break;
    }

    return len;
}

/*
 * 9.11.3.18C   Ciphering key data
 */

static uint16_t
de_nas_5gs_mm_ciphering_key_data(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t saved_offset, curr_offset = offset, c0_len, pos_sib_len, tai_len, i = 1;
    uint8_t oct;
    struct tm tm;
    nstime_t tv;
    proto_item *pi;
    proto_tree *sub_tree;

    while ((curr_offset - offset) < len) {
        static int * const eutra_flags1[] = {
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_1,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_2,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_3,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_4,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_5,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_6,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_7,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_8,
            NULL
        };
        static int * const eutra_flags2[] = {
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_1,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_2,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_3,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_4,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_5,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_6,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_7,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_8,
            NULL
        };
        static int * const eutra_flags3[] = {
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_9,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_10,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_11,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_12,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_13,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_14,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_15,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_16,
            NULL
        };
        static int * const eutra_flags4[] = {
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_17,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_18,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_19,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_20,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_21,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_22,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_23,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_24,
            NULL
        };
        static int * const eutra_flags5[] = {
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_25,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_3_1,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_4_1,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_5_1,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_9,
            &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_10,
            &hf_nas_5gs_spare_b1,
            &hf_nas_5gs_spare_b0,
            NULL
        };
        static int * const nr_flags1[] = {
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_1,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_2,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_3,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_4,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_5,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_6,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_7,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_8,
            NULL
        };
        static int * const nr_flags2[] = {
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_1,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_2,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_3,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_4,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_5,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_6,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_7,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_8,
            NULL
        };
        static int * const nr_flags3[] = {
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_9,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_10,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_11,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_12,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_13,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_14,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_15,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_16,
            NULL
        };
        static int * const nr_flags4[] = {
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_17,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_18,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_19,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_20,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_21,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_22,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_23,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_3_1,
            NULL
        };
        static int * const nr_flags5[] = {
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_4_1,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_5_1,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_1,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_2,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_3,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_4,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_5,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_6,
            NULL
        };
        static int * const nr_flags6[] = {
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_9,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_10,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_24,
            &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_25,
            &hf_nas_5gs_spare_b3,
            &hf_nas_5gs_spare_b2,
            &hf_nas_5gs_spare_b1,
            &hf_nas_5gs_spare_b0,
            NULL
        };

        saved_offset = curr_offset;
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_ciph_data_set,
                                                 &pi, "Ciphering data set #%u", i++);
        proto_tree_add_item(sub_tree, hf_nas_5gs_mm_ciph_key_data_ciphering_set_id, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
        curr_offset += 2;
        proto_tree_add_item(sub_tree, hf_nas_5gs_mm_ciph_key_data_ciphering_key, tvb, curr_offset, 16, ENC_NA);
        curr_offset += 16;
        proto_tree_add_bits_item(sub_tree, hf_nas_5gs_spare_bits, tvb, offset<<3, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_mm_ciph_key_data_c0_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &c0_len);
        curr_offset++;
        if (c0_len) {
            proto_tree_add_item(sub_tree, hf_nas_5gs_mm_ciph_key_data_c0, tvb, curr_offset, c0_len, ENC_NA);
            curr_offset += c0_len;
        }
        proto_tree_add_bits_item(sub_tree, hf_nas_5gs_spare_bits, tvb, offset<<3, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &pos_sib_len);
        curr_offset++;
        if (pos_sib_len > 0) {
            proto_tree_add_bitmask_list(sub_tree, tvb, curr_offset, 1, eutra_flags1, ENC_NA);
            if (pos_sib_len >= 2)
                proto_tree_add_bitmask_list(sub_tree, tvb, curr_offset + 1, 1, eutra_flags2, ENC_NA);
            if (pos_sib_len >= 3)
                proto_tree_add_bitmask_list(sub_tree, tvb, curr_offset + 2, 1, eutra_flags3, ENC_NA);
            if (pos_sib_len >= 4)
                proto_tree_add_bitmask_list(sub_tree, tvb, curr_offset + 3, 1, eutra_flags4, ENC_NA);
            if (pos_sib_len >= 5)
                proto_tree_add_bitmask_list(sub_tree, tvb, curr_offset + 4, 1, eutra_flags5, ENC_NA);
            curr_offset += pos_sib_len;
        }
        proto_tree_add_bits_item(sub_tree, hf_nas_5gs_spare_bits, tvb, offset<<3, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &pos_sib_len);
        curr_offset++;
        if (pos_sib_len > 0) {
            proto_tree_add_bitmask_list(sub_tree, tvb, curr_offset, 1, nr_flags1, ENC_NA);
            if (pos_sib_len >= 2)
                proto_tree_add_bitmask_list(sub_tree, tvb, curr_offset + 1, 1, nr_flags2, ENC_NA);
            if (pos_sib_len >= 3)
                proto_tree_add_bitmask_list(sub_tree, tvb, curr_offset + 2, 1, nr_flags3, ENC_NA);
            if (pos_sib_len >= 4)
                proto_tree_add_bitmask_list(sub_tree, tvb, curr_offset + 3, 1, nr_flags4, ENC_NA);
            if (pos_sib_len >= 5)
                proto_tree_add_bitmask_list(sub_tree, tvb, curr_offset + 4, 1, nr_flags5, ENC_NA);
            if (pos_sib_len >= 6)
                proto_tree_add_bitmask_list(sub_tree, tvb, curr_offset + 5, 1, nr_flags6, ENC_NA);
            curr_offset += pos_sib_len;
        }
        tm.tm_wday = 0;
        tm.tm_yday = 0;
        tm.tm_isdst = -1;
        oct = tvb_get_uint8(tvb, curr_offset);
        tm.tm_year = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4) + 100;
        oct = tvb_get_uint8(tvb, curr_offset+1);
        tm.tm_mon = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4) - 1;
        oct = tvb_get_uint8(tvb, curr_offset+2);
        tm.tm_mday = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4);
        oct = tvb_get_uint8(tvb, curr_offset+3);
        tm.tm_hour = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4);
        oct = tvb_get_uint8(tvb, curr_offset+4);
        tm.tm_min = (oct & 0x0f)*10 + ((oct & 0xf0) >> 4);
        tm.tm_sec = 0;
        tv.secs = mktime(&tm);
        tv.nsecs = 0;
        proto_tree_add_time_format_value(sub_tree, hf_nas_5gs_mm_ciph_key_data_validity_start_time, tvb, curr_offset, 5, &tv,
                                         "%s", abs_time_to_str(pinfo->pool, &tv, ABSOLUTE_TIME_LOCAL, false));
        curr_offset += 5;
        proto_tree_add_item(sub_tree, hf_nas_5gs_mm_ciph_key_data_validity_duration, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
        curr_offset += 2;
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_mm_ciph_key_data_tais_list_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &tai_len);
        curr_offset++;
        if (tai_len) {
            de_nas_5gs_mm_5gs_ta_id_list(tvb, sub_tree, pinfo, curr_offset, tai_len, NULL, 0);
            curr_offset += tai_len;
        }
        proto_item_set_len(pi, curr_offset - saved_offset);
    }

    return len;
}

/*
 * 9.11.3.18D   Control plane service type
 */
static const value_string nas_5gs_mm_ctrl_plane_serv_type_values[] = {
    { 0x00, "mobile originating request" },
    { 0x01, "mobile terminating request" },
    { 0x02, "emergency services" },
    { 0x03, "emergency services fallback" },
    { 0, NULL }
};

static uint16_t
de_nas_5gs_mm_ctrl_plane_service_type(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    static int * const flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_mm_ctrl_plane_serv_type,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_NA);

    return len;
}

/*
 *   9.11.3.19    Daylight saving time
 */
/* See subclause 10.5.3.12 in 3GPP TS 24.008 */

/*
 *   9.11.3.20    De-registration type
 */
static const true_false_string nas_5gs_mm_switch_off_tfs = {
    "Switch off",
    "Normal de-registration"
};

static const true_false_string nas_5gs_mm_re_reg_req_tfs = {
    "re-registration required",
    "re-registration not required"
};

static const value_string nas_5gs_mm_acc_type_vals[] = {
    { 0x1, "3GPP access"},
    { 0x2, "Non-3GPP access"},
    { 0x3, "3GPP access and non-3GPP access"},
    {   0, NULL }
};

static uint16_t
de_nas_5gs_mm_de_reg_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{
    /* Switch off   Re-registration required    Access type */
    proto_tree_add_item(tree, hf_nas_5gs_mm_switch_off, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_re_reg_req, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_acc_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}

/* 9.11.3.21    Void*/
/* 9.11.3.22    Void*/

/*
 * 9.11.3.23    Emergency number list
 */
/* See subclause 10.5.3.13 in 3GPP TS 24.008 */

/*
 *   9.11.3.24    EPS NAS message container
 */
static uint16_t
de_nas_5gs_mm_eps_nas_msg_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    /* an EPS NAS message as specified in 3GPP TS 24.301 */
    if (nas_eps_handle) {
        col_append_str(pinfo->cinfo, COL_PROTOCOL, "/");
        col_set_fence(pinfo->cinfo, COL_PROTOCOL);
        call_dissector(nas_eps_handle, tvb_new_subset_length(tvb, offset, len), pinfo, tree);
    }

    return len;
}

/*
 * 9.11.3.25    EPS NAS security algorithms
 */
/* See subclause 9.9.3.23 in 3GPP TS 24.301 */

/*
 * 9.11.3.26    Extended emergency number list
 */
/* See subclause 9.9.3.37A in 3GPP TS 24.301 */

/*
 * 9.11.3.26A    Extended DRX parameters
 */
/* See subclause 10.5.5.32 in 3GPP TS 24.008 */

/* 9.11.3.27    Void*/

/*
 *   9.11.3.28    IMEISV request
 */
/* See subclause 10.5.5.10 in 3GPP TS 24.008 */

/*
 *   9.11.3.29    LADN indication
 */

static uint16_t
de_nas_5gs_mm_ladn_indic(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    proto_tree *sub_tree;
    proto_item *item;
    int i = 1;
    uint32_t length;
    uint32_t curr_offset;

    curr_offset = offset;

    while ((curr_offset - offset) < len) {
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, 2, ett_nas_5gs_mm_ladn_indic, &item, "LADN DNN value %u", i);
        /*LADN DNN value is coded as the length and value part of DNN information element as specified in subclause 9.11.2.1B starting with the second octet*/
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_mm_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &length);
        curr_offset++;
        curr_offset += de_nas_5gs_cmn_dnn(tvb, sub_tree, pinfo, curr_offset, length, NULL, 0);
        proto_item_set_len(item, length + 1);

        i++;

    }

    return len;
}

/*
 *   9.11.3.30    LADN information
 */

static uint16_t
de_nas_5gs_mm_ladn_inf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    proto_tree *sub_tree;
    proto_item *item;
    int i = 1;
    uint32_t length;
    uint32_t curr_offset;

    curr_offset = offset;

    while ((curr_offset - offset) < len) {
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, 2, ett_nas_5gs_mm_ladn_indic, &item, "LADN %u", i);
        /* DNN value (octet 5 to octet m):
         * LADN DNN value is coded as the length and value part of DNN information element as specified in
         * subclause 9.11.2.1B starting with the second octet
         */
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_mm_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &length);
        curr_offset++;
        curr_offset += de_nas_5gs_cmn_dnn(tvb, sub_tree, pinfo, curr_offset, length, NULL, 0);
        /* 5GS tracking area identity list (octet m+1 to octet a):
         * 5GS tracking area identity list field is coded as the length and the value part of the
         * 5GS Tracking area identity list information element as specified in subclause 9.11.3.9
         * starting with the second octet
         */
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_mm_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &length);
        curr_offset++;
        curr_offset += de_nas_5gs_mm_5gs_ta_id_list(tvb, sub_tree, pinfo, curr_offset, length, NULL, 0);

        proto_item_set_len(item, curr_offset - offset);

        i++;

    }

    return len;
}

/*
 *   9.11.3.31    MICO indication
 */
static const true_false_string tfs_nas_5gs_raai = {
    "all PLMN registration area allocated",
    "all PLMN registration area not allocated"
};

static uint16_t
de_nas_5gs_mm_mico_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{
    static int * const flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_mm_sprti_b1,
        &hf_nas_5gs_mm_raai_b0,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.11.3.31A   MA PDU session information
 */
static const value_string nas_5gs_mm_ma_pdu_session_info_vals[] = {
    { 0x0, "No additional information"},
    { 0x1, "MA PDU session network upgrade is allowed"},
    {   0, NULL }
};

static uint16_t
de_nas_5gs_mm_ma_pdu_ses_inf(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_mm_ma_pdu_session_info_value, tvb, offset, 1, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.11.3.31B   Mapped NSSAI
 */
static const value_string nas_5gs_mm_sst_vals[] = {
    { 0x1, "eMBB"},
    { 0x2, "URLLC"},
    { 0x3, "MIoT"},
    { 0x4, "V2X"},
    {   0, NULL }
};

static uint16_t
de_nas_5gs_mm_mapped_nssai(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree* sub_tree;
    proto_item* item;
    unsigned num_items = 1;
    uint32_t curr_offset = offset;
    uint32_t start_offset, nssai_len;

    /* Rejected NSSAI */
    while ((curr_offset - offset) < len) {
        start_offset = curr_offset;
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_mapped_nssai,
                                                 &item, "Mapped S-NSSAI content %u", num_items++);

        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_mm_len_of_mapped_s_nssai, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &nssai_len);
        curr_offset++;
        proto_tree_add_item(sub_tree, hf_nas_5gs_mm_sst, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
        if (nssai_len > 1) {
            proto_tree_add_item(sub_tree, hf_nas_5gs_mm_sd, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
            curr_offset += 3;
        }
        proto_item_set_len(item, curr_offset - start_offset);
    }

    return len;
}

/*
 * 9.11.3.31C    Mobile station classmark 2
 */
/* See subclause 10.5.1.6 in 3GPP TS 24.008 */

/*
 *   9.11.3.32    NAS key set identifier
 */
static const true_false_string nas_5gs_mm_tsc_tfs = {
    "Mapped security context (for KSIASME)",
    "Native security context (for KSIAMF)"
};

static uint16_t
de_nas_5gs_mm_nas_key_set_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{
    static int * const flags[] = {
        &hf_nas_5gs_mm_tsc,
        &hf_nas_5gs_mm_nas_key_set_id,
        NULL
    };

    /* NAS key set identifier IEI   TSC     NAS key set identifier */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}

/* High nibble version (LEFT_NIBBLE) */
static uint16_t
de_nas_5gs_mm_nas_key_set_id_h1(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char* add_string _U_, int string_len _U_)
{
    static int* const flags[] = {
        &hf_nas_5gs_mm_tsc_h1,
        &hf_nas_5gs_mm_nas_key_set_id_h1,
        NULL
    };

    /* NAS key set identifier IEI   TSC     NAS key set identifier */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}


/*
 *   9.11.3.33    NAS message container
 */
static uint16_t
de_nas_5gs_mm_nas_msg_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    /* The purpose of the NAS message container IE is to encapsulate a plain 5GS NAS message. */
    /* a NAS message without NAS security header */
    struct nas5gs_private_data *nas5gs_data = nas5gs_get_private_data(pinfo);

    if (nas5gs_data->sec_hdr_type == NAS_5GS_PLAIN_NAS_MSG || g_nas_5gs_null_decipher) {
        dissect_nas_5gs(tvb_new_subset_length(tvb, offset, len), pinfo, tree, NULL);
    } else {
        proto_tree_add_subtree(tree, tvb, offset, len, ett_nas_5gs_enc, NULL, "Encrypted data");
    }

    return len;
}

/*
 *   9.11.3.34    NAS security algorithms
 */

static const value_string nas_5gs_mm_type_of_ip_algo_vals[] = {
    { 0x0, "5G-IA0 (null integrity protection algorithm)"},
    { 0x1, "128-5G-IA1"},
    { 0x2, "128-5G-IA2"},
    { 0x3, "128-5G-IA3"},
    { 0x4, "5G-IA4"},
    { 0x5, "5G-IA5"},
    { 0x6, "5G-IA6"},
    { 0x7, "5G-IA7"},
    {   0, NULL }
};

static const value_string nas_5gs_mm_type_of_enc_algo_vals[] = {
    { 0x0, "5G-EA0 (null ciphering algorithm)"},
    { 0x1, "128-5G-EA1"},
    { 0x2, "128-5G-EA2"},
    { 0x3, "128-5G-EA3"},
    { 0x4, "5G-EA4"},
    { 0x5, "5G-EA5"},
    { 0x6, "5G-EA6"},
    { 0x7, "5G-EA7"},
    {   0, NULL }
};

static uint16_t
de_nas_5gs_mm_nas_sec_algo(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{

    static int * const flags[] = {
        &hf_nas_5gs_mm_nas_sec_algo_enc,
        &hf_nas_5gs_mm_nas_sec_algo_ip,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}


/*
 *   9.11.3.35    Network name
 */
/* See subclause 10.5.3.5a in 3GPP TS 24.008 */


/*
 *   9.11.3.36    Network slicing indication
 */

static const true_false_string nas_5gs_mm_dcni_tfs = {
    "Requested NSSAI created from default configured NSSAI",
    "Requested NSSAI not created from default configured NSSAI"
};

static uint16_t
de_nas_5gs_mm_nw_slicing_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    static int * const flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_mm_dcni,
        &hf_nas_5gs_mm_nssci,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return len;
}

/*
 *   9.11.3.37    NSSAI
 */
static uint16_t
de_nas_5gs_mm_nssai(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    proto_tree *sub_tree;
    proto_item *item;
    int i = 1;
    uint32_t length;
    uint32_t curr_offset;

    curr_offset = offset;

    while ((curr_offset - offset) < len) {
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, 2, ett_nas_5gs_mm_nssai, &item, "S-NSSAI %u", i);

        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_mm_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &length);
        curr_offset++;
        curr_offset += de_nas_5gs_cmn_s_nssai(tvb, sub_tree, pinfo, curr_offset, length, NULL, 0);
        proto_item_set_len(item, length + 1);
        i++;

    }

    return len;
}

/*
 *   9.11.3.37A    NSSAI inclusion mode
 */


static const value_string nas_5gs_mm_nssai_inc_mode_vals[] = {
    { 0x00, "A" },
    { 0x01, "B" },
    { 0x02, "C" },
    { 0x03, "D" },
    {    0, NULL } };

static uint16_t
de_nas_5gs_mm_nssai_inc_mode(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    static int * const flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_mm_nssai_inc_mode,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return len;
}

/*
 *   9.11.3.38    Operator-defined access category definitions
 */

static void
nas_5gs_mm_access_cat_number(char *s, uint32_t val)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%u (%u)", 32+val, val);
}

static void
nas_5gs_mm_access_standardized_cat_number(char *s, uint32_t val)
{
    if (val <= 7)
        snprintf(s, ITEM_LABEL_LENGTH, "%u", val);
    else
        snprintf(s, ITEM_LABEL_LENGTH, "Reserved (%u)", val);
}

static const value_string nas_5gs_mm_op_def_access_cat_criteria_type_vals[] = {
    { 0, "DNN" },
    { 1, "OS Id + OS App Id" },
    { 2, "S-NSSAI" },
    { 0, NULL }
};

static uint16_t
de_nas_5gs_mm_op_def_acc_cat_def(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    proto_tree *sub_tree, *sub_tree2, *sub_tree3;
    proto_item *item, *item2, *item3;
    uint32_t i = 1, j, k;
    uint32_t length, criteria_length, criteria_type, criteria_count;
    uint32_t curr_offset, saved_offset, saved_offset2, saved_offset3, criteria_offset;
    bool psac;

    curr_offset = offset;

    while ((curr_offset - offset) < len) {
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, 4, ett_nas_5gs_mm_op_def_acc_cat_def,
                                                 &item, "Operator-defined access category definition %u", i);

        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_mm_op_def_access_cat_len, tvb,
                                     curr_offset, 1, ENC_BIG_ENDIAN, &length);
        curr_offset++;
        saved_offset = curr_offset;
        /* Precedence value */
        proto_tree_add_item(sub_tree, hf_nas_5gs_mm_op_def_access_cat_precedence,
                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
        /* PSAC    0 Spare    0 Spare    Operator-defined access category number */
        proto_tree_add_item_ret_boolean(sub_tree, hf_nas_5gs_mm_op_def_access_cat_psac,
                                        tvb, curr_offset, 1, ENC_BIG_ENDIAN, &psac);
        proto_tree_add_bits_item(sub_tree, hf_nas_5gs_spare_bits, tvb,
                                 (curr_offset << 3)+1, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_nas_5gs_mm_op_def_access_cat_number,
                            tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
        /* Length of criteria */
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_mm_op_def_access_cat_criteria_length,
                                     tvb, curr_offset, 1, ENC_BIG_ENDIAN, &criteria_length);
        curr_offset++;
        criteria_offset = curr_offset;
        j = 1;
        while ((curr_offset - criteria_offset) < criteria_length) {
            saved_offset2 = curr_offset;
            sub_tree2 = proto_tree_add_subtree_format(sub_tree, tvb, curr_offset, 1, ett_nas_5gs_mm_op_def_acc_cat_criteria_component,
                                                      &item2, "Criteria component %u", j++);
            /* Criteria */
            proto_tree_add_item_ret_uint(sub_tree2, hf_nas_5gs_mm_op_def_access_cat_criteria_type,
                                         tvb, curr_offset, 1, ENC_BIG_ENDIAN, &criteria_type);
            curr_offset++;
            switch (criteria_type) {
            case 0:
                proto_tree_add_item_ret_uint(sub_tree2, hf_nas_5gs_mm_op_def_access_cat_criteria_dnn_count,
                                             tvb, curr_offset, 1, ENC_BIG_ENDIAN, &criteria_count);
                curr_offset++;
                for (k = 1; k <= criteria_count; k++) {
                    uint32_t dnn_len;
                    saved_offset3 = curr_offset;
                    sub_tree3 = proto_tree_add_subtree_format(sub_tree2, tvb, curr_offset, -1,
                                                              ett_nas_5gs_mm_op_def_acc_cat_criteria, &item3, "DNN %u", k);
                    proto_tree_add_item_ret_uint(sub_tree3, hf_nas_5gs_mm_op_def_access_cat_criteria_dnn_len,
                                                 tvb, curr_offset, 1, ENC_BIG_ENDIAN, &dnn_len);
                    curr_offset++;
                    de_nas_5gs_cmn_dnn(tvb, sub_tree3, pinfo, curr_offset, dnn_len, NULL, 0);
                    curr_offset += dnn_len;
                    proto_item_set_len(item3, curr_offset - saved_offset3);
                }
                break;
            case 1:
                proto_tree_add_item_ret_uint(sub_tree2, hf_nas_5gs_mm_op_def_access_cat_criteria_os_id_os_app_id_count,
                                             tvb, curr_offset, 1, ENC_BIG_ENDIAN, &criteria_count);
                curr_offset++;
                for (k = 1; k <= criteria_count; k++) {
                    uint32_t os_app_id_len;
                    saved_offset3 = curr_offset;
                    sub_tree3 = proto_tree_add_subtree_format(sub_tree2, tvb, curr_offset, -1, ett_nas_5gs_mm_op_def_acc_cat_criteria,
                                                              &item3, "OS Id + Os App Id %u", k);
                    proto_tree_add_item(sub_tree3, hf_nas_5gs_mm_op_def_access_cat_criteria_os_id,
                                        tvb, curr_offset, 16, ENC_NA);
                    curr_offset += 16;
                    proto_tree_add_item_ret_uint(sub_tree3, hf_nas_5gs_mm_op_def_access_cat_criteria_os_app_id_len,
                                                 tvb, curr_offset, 1, ENC_BIG_ENDIAN, &os_app_id_len);
                    curr_offset++;
                    proto_tree_add_item(sub_tree3, hf_nas_5gs_mm_op_def_access_cat_criteria_os_app_id,
                                        tvb, curr_offset, os_app_id_len, ENC_NA);
                    curr_offset += os_app_id_len;
                    proto_item_set_len(item3, curr_offset - saved_offset3);
                }
                break;
            case 2:
                proto_tree_add_item_ret_uint(sub_tree2, hf_nas_5gs_mm_op_def_access_cat_criteria_s_nssai_count,
                                             tvb, curr_offset, 1, ENC_BIG_ENDIAN, &criteria_count);
                curr_offset++;
                for (k = 1; k <= criteria_count; k++) {
                    uint32_t s_nssai_len;
                    saved_offset3 = curr_offset;
                    sub_tree3 = proto_tree_add_subtree_format(sub_tree2, tvb, curr_offset, -1,
                                                              ett_nas_5gs_mm_op_def_acc_cat_criteria, &item3, "S-NSSAI %u", k);
                    proto_tree_add_item_ret_uint(sub_tree3, hf_nas_5gs_mm_op_def_access_cat_criteria_s_nssai_len,
                                                 tvb, curr_offset, 1, ENC_BIG_ENDIAN, &s_nssai_len);
                    curr_offset++;
                    curr_offset += de_nas_5gs_cmn_s_nssai(tvb, sub_tree3, pinfo, curr_offset, s_nssai_len, NULL, 0);
                    proto_item_set_len(item3, curr_offset - saved_offset3);
                }
                break;
            default:
                break;
            }
            proto_item_set_len(item2, curr_offset - saved_offset2);
        }
        if (psac) {
            /* 0 Spare    0 Spare    0 Spare    Standardized access category */
            proto_tree_add_bits_item(sub_tree, hf_nas_5gs_spare_bits, tvb,
                                     (curr_offset << 3), 3, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_tree, hf_nas_5gs_mm_op_def_access_cat_standardized_number,
                                tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        }
        curr_offset = saved_offset + length;
        proto_item_set_len(item, length + 1);
        i++;
    }

    return len;
}

static const value_string nas_5gs_mm_pld_cont_event_notif_ind_type_vals[] = {
    { 0x0, "SRVCC handover cancelled, IMS session re-establishment required" },
    {   0, NULL }
};

static const value_string nas_5gs_mm_pld_cont_opt_ie_type_vals[] = {
    { 0x12, "PDU session ID" },
    { 0x22, "S-NSSAI" },
    { 0x24, "Additional information" },
    { 0x25, "DNN" },
    { 0x37, "Back-off timer value" },
    { 0x58, "5GMM cause" },
    { 0x59, "Old PDU session ID" },
    { 0x80, "Request type" },
    { 0xa0, "MA PDU session information" },
    { 0xf0, "Release assistance indication" },
    {    0, NULL }
};

/*
 *   9.11.3.39    Payload container
 */
static uint16_t
// NOLINTNEXTLINE(misc-no-recursion)
de_nas_5gs_mm_pld_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    struct nas5gs_private_data *nas5gs_data = nas5gs_get_private_data(pinfo);

    increment_dissection_depth(pinfo);
    switch (nas5gs_data->payload_container_type) {
    case 1: /* N1 SM information */
        dissect_nas_5gs_common(tvb_new_subset_length(tvb, offset, len), pinfo, tree, 0, NULL);
        break;
    case 2: /* SMS */
        if (gsm_a_dtap_handle) {
            call_dissector(gsm_a_dtap_handle, tvb_new_subset_length(tvb, offset, len), pinfo, tree);
        } else {
            proto_tree_add_item(tree, hf_nas_5gs_mm_pld_cont, tvb, offset, len, ENC_NA);
        }
        break;
    case 3: /* LPP */
        if (lpp_handle) {
            call_dissector(lpp_handle, tvb_new_subset_length(tvb, offset, len), pinfo, tree);
        } else {
            proto_tree_add_item(tree, hf_nas_5gs_mm_pld_cont, tvb, offset, len, ENC_NA);
        }
        break;
    case 5: /* UE policy container */
        dissect_nas_5gs_updp(tvb_new_subset_length(tvb, offset, len), pinfo, tree);
        break;
    case 8: /* CIoT user data container */
        nas_5gs_decode_user_data_cont(tvb, tree, pinfo, offset, len, hf_nas_5gs_mm_pld_cont);
        break;
    case 9: /* service-level-AA container */
        de_nas_5gs_cmn_service_level_aa_cont(tvb, tree, pinfo, offset, len, NULL, 0);
        break;
    case 10: /* event notification */
        {
            uint32_t curr_offset, events_count, event_len;
            unsigned i;

            curr_offset = offset;
            proto_tree_add_item_ret_uint(tree, hf_nas_5gs_mm_pld_cont_event_notif_ind_nb, tvb, curr_offset, 1, ENC_NA, &events_count);
            curr_offset++;
            for (i = 0; i < events_count; i++) {
                proto_item *item;
                proto_tree *subtree;

                subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_pld_cont_event_notif_ind, &item, "Event notification indicator %d", i + 1);
                proto_tree_add_item(subtree, hf_nas_5gs_mm_pld_cont_event_notif_ind_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                curr_offset++;
                proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_pld_cont_event_notif_ind_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &event_len);
                curr_offset++;
                proto_item_set_len(item, event_len + 2);
                if (event_len > 0) {
                    proto_tree_add_item(subtree, hf_nas_5gs_mm_pld_cont_event_notif_ind_val, tvb, curr_offset, event_len, ENC_NA);
                    curr_offset += event_len;
                }
            }
        }
        break;
    case 15: /* multiple payloads */
        {
            uint32_t curr_offset, entry_offset, payloads_count, payload_len, opt_ies_count, payload_type;
            uint32_t opt_ie_type, opt_ie_len, type_backup;
            unsigned i, j;

            curr_offset = offset;
            proto_tree_add_item_ret_uint(tree, hf_nas_5gs_mm_pld_cont_nb_entries, tvb, curr_offset, 1, ENC_NA, &payloads_count);
            curr_offset++;
            for (i = 0; i < payloads_count; i++) {
                proto_item *item;
                proto_tree *subtree, *subtree2;

                entry_offset = curr_offset;
                subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_pld_cont_pld_entry, &item, "Payload container entry %d", i + 1);
                proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_pld_cont_pld_cont_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &payload_len);
                proto_item_set_len(item, payload_len + 2);
                curr_offset += 2;
                proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_pld_cont_nb_opt_ies, tvb, curr_offset, 1, ENC_NA, &opt_ies_count);
                proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_pld_cont_pld_cont_type, tvb, curr_offset, 1, ENC_NA, &payload_type);
                curr_offset++;
                for (j = 0; j < opt_ies_count; j++) {
                    item = proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_pld_cont_opt_ie_type, tvb, curr_offset, 1, ENC_NA, &opt_ie_type);
                    curr_offset++;
                    subtree2 = proto_item_add_subtree(item, ett_nas_5gs_mm_pld_cont_opt_ie);
                    proto_tree_add_item_ret_uint(subtree2, hf_nas_5gs_mm_pld_cont_opt_ie_len, tvb, curr_offset, 1, ENC_NA, &opt_ie_len);
                    curr_offset++;
                    switch (opt_ie_type) {
                    case 0x12:
                        de_nas_5gs_mm_pdu_ses_id_2(tvb, subtree2, pinfo, curr_offset, opt_ie_len, NULL, 0);
                        break;
                    case 0x22:
                        de_nas_5gs_cmn_s_nssai(tvb, subtree2, pinfo, curr_offset, opt_ie_len, NULL, 0);
                        break;
                    case 0x24:
                        de_nas_5gs_cmn_add_inf(tvb, subtree2, pinfo, curr_offset, opt_ie_len, NULL, 0);
                        break;
                    case 0x25:
                        de_nas_5gs_cmn_dnn(tvb, subtree2, pinfo, curr_offset, opt_ie_len, NULL, 0);
                        break;
                    case 0x37:
                        de_gc_timer3(tvb, subtree2, pinfo, curr_offset, opt_ie_len, NULL, 0);
                        break;
                    case 0x58:
                        nas_5gs_mm_5gmm_status(tvb, subtree2, pinfo, curr_offset, opt_ie_len);
                        break;
                    case 0x59:
                        de_nas_5gs_mm_pdu_ses_id_2(tvb, subtree2, pinfo, curr_offset, opt_ie_len, NULL, 0);
                        break;
                    case 0x80:
                        de_nas_5gs_mm_req_type(tvb, subtree2, pinfo, curr_offset, opt_ie_len, NULL, 0);
                        break;
                    case 0xa0:
                        de_nas_5gs_mm_ma_pdu_ses_inf(tvb, subtree2, pinfo, curr_offset, opt_ie_len, NULL, 0);
                        break;
                    case 0xf0:
                        de_esm_rel_assist_ind(tvb, subtree2, pinfo, curr_offset, opt_ie_len, NULL, 0);
                        break;
                    default:
                        proto_tree_add_item(subtree2, hf_nas_5gs_mm_pld_cont_opt_ie_val, tvb, curr_offset, opt_ie_len, ENC_NA);
                        break;
                    }
                    curr_offset += opt_ie_len;
                }
                type_backup = nas5gs_data->payload_container_type;
                nas5gs_data->payload_container_type = payload_type;
                /* N.B. this recursive call can overwrite nas5gs_data->payload_container_type */
                de_nas_5gs_mm_pld_cont(tvb, subtree, pinfo, curr_offset, payload_len - (curr_offset - entry_offset), NULL, 0);
                curr_offset = entry_offset + payload_len + 2;
                nas5gs_data->payload_container_type = type_backup;
            }
        }
        break;
    default:
        proto_tree_add_item(tree, hf_nas_5gs_mm_pld_cont, tvb, offset, len, ENC_NA);
        break;
    }
    decrement_dissection_depth(pinfo);

    return len;
}

/*
 *   9.11.3.40    Payload container type
 */
static const value_string nas_5gs_mm_pld_cont_type_vals[] = {
    { 0x01, "N1 SM information" },
    { 0x02, "SMS" },
    { 0x03, "LTE Positioning Protocol (LPP) message container" },
    { 0x04, "SOR transparent container" },
    { 0x05, "UE policy container" },
    { 0x06, "UE parameters update transparent container" },
    { 0x07, "Location services message container" },
    { 0x08, "CIoT user data container" },
    { 0x09, "Service-level-AA container" },
    { 0x0a, "Event notification" },
    { 0x0b, "UPP-CMI container" },
    { 0x0c, "SLPP message container" },
    { 0x0f, "Multiple payloads" },
    {    0, NULL } };

static uint16_t
de_nas_5gs_mm_pld_cont_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{
    struct nas5gs_private_data *nas5gs_data = nas5gs_get_private_data(pinfo);

    proto_tree_add_item_ret_uint(tree, hf_nas_5gs_mm_pld_cont_type, tvb, offset, 1, ENC_BIG_ENDIAN, &nas5gs_data->payload_container_type);

    return 1;
}

/*
 *   9.11.3.41    PDU session identity 2
 */
static uint16_t
de_nas_5gs_mm_pdu_ses_id_2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_pdu_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}

/*
 *   9.11.3.42    PDU session reactivation result
 */


static true_false_string tfs_nas_5gs_pdu_ses_rect_res_psi = {
    "1",
    "0"
};

static uint16_t
de_nas_5gs_mm_pdu_ses_react_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    int curr_offset;

    static int * const psi_0_7_flags[] = {
        &hf_nas_5gs_pdu_ses_rect_res_psi_7_b7,
        &hf_nas_5gs_pdu_ses_rect_res_psi_6_b6,
        &hf_nas_5gs_pdu_ses_rect_res_psi_5_b5,
        &hf_nas_5gs_pdu_ses_rect_res_psi_4_b4,
        &hf_nas_5gs_pdu_ses_rect_res_psi_3_b3,
        &hf_nas_5gs_pdu_ses_rect_res_psi_2_b2,
        &hf_nas_5gs_pdu_ses_rect_res_psi_1_b1,
        &hf_nas_5gs_pdu_ses_rect_res_psi_0_b0,
        NULL
         };

        static int * const psi_8_15_flags[] = {
        &hf_nas_5gs_pdu_ses_rect_res_psi_15_b7,
        &hf_nas_5gs_pdu_ses_rect_res_psi_14_b6,
        &hf_nas_5gs_pdu_ses_rect_res_psi_13_b5,
        &hf_nas_5gs_pdu_ses_rect_res_psi_12_b4,
        &hf_nas_5gs_pdu_ses_rect_res_psi_11_b3,
        &hf_nas_5gs_pdu_ses_rect_res_psi_10_b2,
        &hf_nas_5gs_pdu_ses_rect_res_psi_9_b1,
        &hf_nas_5gs_pdu_ses_rect_res_psi_8_b0,
        NULL
         };

    curr_offset = offset;
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, psi_0_7_flags, ENC_BIG_ENDIAN);
    curr_offset++;

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, psi_8_15_flags, ENC_BIG_ENDIAN);
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_5gs_extraneous_data);

    return (curr_offset - offset);

}

/*
 *   9.11.3.43    PDU session reactivation result error cause
 */
static uint16_t
de_nas_5gs_mm_pdu_ses_react_res_err_c(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset;

    /*Partial service area list*/
    while ((curr_offset - offset) < len) {
        proto_tree_add_item(tree, hf_nas_5gs_pdu_session_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
        proto_tree_add_item(tree, hf_nas_5gs_mm_5gmm_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
    }

    return len;
}

/*
*   9.11.3.44    PDU session status
*/

static true_false_string tfs_nas_5gs_pdu_ses_sts_psi = {
    "Not PDU SESSION INACTIVE",
    "PDU SESSION INACTIVE"
};

static uint16_t
de_nas_5gs_mm_pdu_ses_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    int curr_offset;

    static int * const psi_0_7_flags[] = {
        &hf_nas_5gs_pdu_ses_sts_psi_7_b7,
        &hf_nas_5gs_pdu_ses_sts_psi_6_b6,
        &hf_nas_5gs_pdu_ses_sts_psi_5_b5,
        &hf_nas_5gs_pdu_ses_sts_psi_4_b4,
        &hf_nas_5gs_pdu_ses_sts_psi_3_b3,
        &hf_nas_5gs_pdu_ses_sts_psi_2_b2,
        &hf_nas_5gs_pdu_ses_sts_psi_1_b1,
        &hf_nas_5gs_pdu_ses_sts_psi_0_b0,
        NULL
    };

    static int * const psi_8_15_flags[] = {
        &hf_nas_5gs_pdu_ses_sts_psi_15_b7,
        &hf_nas_5gs_pdu_ses_sts_psi_14_b6,
        &hf_nas_5gs_pdu_ses_sts_psi_13_b5,
        &hf_nas_5gs_pdu_ses_sts_psi_12_b4,
        &hf_nas_5gs_pdu_ses_sts_psi_11_b3,
        &hf_nas_5gs_pdu_ses_sts_psi_10_b2,
        &hf_nas_5gs_pdu_ses_sts_psi_9_b1,
        &hf_nas_5gs_pdu_ses_sts_psi_8_b0,
        NULL
    };

    curr_offset = offset;
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, psi_0_7_flags, ENC_BIG_ENDIAN);
    curr_offset++;

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, psi_8_15_flags, ENC_BIG_ENDIAN);
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_5gs_extraneous_data);

    return (curr_offset - offset);

}


/*
 *   9.11.3.45    PLMN list
 */
/* See subclause 10.5.1.13 in 3GPP TS 24.008 */

/*
 *   9.11.3.46    Rejected NSSAI
 */
static const value_string nas_5gs_mm_rej_s_nssai_cause_vals[] = {
    { 0x00, "S-NSSAI not available in the current PLMN or SNPN" },
    { 0x01, "S-NSSAI not available in the current registration area" },
    { 0x02, "S-NSSAI not available due to the failed or revoked network slice-specific authentication and authorization" },
    {    0, NULL } };

static uint16_t
de_nas_5gs_mm_rej_nssai(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    proto_tree* sub_tree;
    proto_item* item;
    unsigned num_items = 1;
    uint32_t curr_offset = offset;
    uint32_t start_offset, nssai_len;

    /* Rejected NSSAI */
    while ((curr_offset - offset) < len) {
        start_offset = curr_offset;
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_rej_nssai, &item, "Rejected S-NSSAI %u", num_items++);

        /* Length of rejected S-NSSAI Cause value */
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_mm_len_of_rej_s_nssai, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &nssai_len);
        proto_tree_add_item(sub_tree, hf_nas_5gs_mm_rej_s_nssai_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
        /* SST */
        proto_tree_add_item(sub_tree, hf_nas_5gs_mm_sst, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset += 1;
        if (nssai_len > 1) {
            /* SD    octet 3 - octet 5* */
            proto_tree_add_item(sub_tree, hf_nas_5gs_mm_sd, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
            curr_offset += 3;
        }
        proto_item_set_len(item, curr_offset - start_offset);
    }

    return len;
}

/*
 *  9.11.3.46A     Release assistance indication
 */
/* See subclause 9.9.4.25 in 3GPP TS 24.301 */

/*
*     9.11.3.47    Request type
*/
static const value_string nas_5gs_mm_req_type_vals[] = {
    { 0x01, "Initial request" },
    { 0x02, "Existing PDU session" },
    { 0x03, "Initial emergency request" },
    { 0x04, "Existing emergency PDU session" },
    { 0x05, "Modification request" },
    { 0x06, "MA PDU request" },
    { 0x07, "Reserved" },
    { 0, NULL } };

static uint16_t
de_nas_5gs_mm_req_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{

    proto_tree_add_item(tree, hf_nas_5gs_mm_req_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}


/*
 *    9.11.3.48    S1 UE network capability
 */
/* See subclause 9.9.3.34 in 3GPP TS 24.301 */

/*
 *   9.11.3.48A    S1 UE security capability
 */
/*See subclause 9.9.3.36 in 3GPP TS 24.301 */

/*
 *     9.11.3.49    Service area list
 */
static true_false_string tfs_nas_5gs_sal_al_t = {
    "TAIs in the list are in the non-allowed area",
    "TAIs in the list are in the allowed area"
};

static const value_string nas_5gs_mm_sal_t_li_values[] = {
    { 0x00, "list of TACs belonging to one PLMN, with non-consecutive TAC values" },
    { 0x01, "list of TACs belonging to one PLMN, with consecutive TAC values" },
    { 0x02, "list of TAIs belonging to different PLMNs" },
    { 0x03, "All TAIs belonging to the PLMN are in the allowed area" },
    { 0, NULL } };

static const value_string nas_5gs_mm_sal_num_e_vals[] = {
    { 0x00, "1" },
    { 0x01, "2" },
    { 0x02, "3" },
    { 0x03, "4" },
    { 0x04, "5" },
    { 0x05, "6" },
    { 0x06, "7" },
    { 0x07, "8" },
    { 0x08, "9" },
    { 0x09, "10" },
    { 0x0a, "11" },
    { 0x0b, "12" },
    { 0x0c, "13" },
    { 0x0d, "14" },
    { 0x0e, "15" },
    { 0x0f, "16" },
    { 0, NULL } };



static uint16_t
de_nas_5gs_mm_sal(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    proto_tree *sub_tree;
    proto_item *item;

    static int * const flags_sal[] = {
        &hf_nas_5gs_mm_sal_al_t,
        &hf_nas_5gs_mm_sal_t_li,
        &hf_nas_5gs_mm_sal_num_e,
        NULL
    };

    unsigned num_par_sal = 1;
    uint32_t curr_offset = offset;
    uint32_t start_offset;
    uint8_t sal_head, sal_t_li, sal_num_e;

    /*Partial service area list*/
    while ((curr_offset - offset) < len) {
        start_offset = curr_offset;
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_part_sal, &item, "Partial service area list  %u", num_par_sal);
        /*Head of Partial service area list*/
        /* Allowed type    Type of list    Number of elements    octet 1 */
        sal_head = tvb_get_uint8(tvb, curr_offset);
        sal_t_li = (sal_head & 0x60) >> 5;
        sal_num_e = (sal_head & 0x1f) + 1;
        proto_tree_add_bitmask_list(sub_tree, tvb, curr_offset, 1, flags_sal, ENC_BIG_ENDIAN);
        curr_offset++;
        switch (sal_t_li) {
        case 0:
            /*octet 2  MCC digit2  MCC digit1*/
            /*octet 3  MNC digit3  MCC digit3*/
            /*octet 4  MNC digit2  MNC digit1*/
            dissect_e212_mcc_mnc(tvb, pinfo, sub_tree, curr_offset, E212_5GSTAI, true);
            curr_offset += 3;
            while (sal_num_e > 0) {
                proto_tree_add_item(sub_tree, hf_nas_5gs_tac, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
                curr_offset += 3;
                sal_num_e--;
            }
            break;
        case 1:
            /*octet 2  MCC digit2  MCC digit1*/
            /*octet 3  MNC digit3  MCC digit3*/
            /*octet 4  MNC digit2  MNC digit1*/
            dissect_e212_mcc_mnc(tvb, pinfo, sub_tree, curr_offset, E212_5GSTAI, true);
            curr_offset += 3;

            /*octet 5  TAC 1*/
            proto_tree_add_item(sub_tree, hf_nas_5gs_tac, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
            curr_offset+=3;
            break;
        case 2:
            while (sal_num_e > 0) {
                /*octet 2  MCC digit2  MCC digit1*/
                /*octet 3  MNC digit3  MCC digit3*/
                /*octet 4  MNC digit2  MNC digit1*/
                dissect_e212_mcc_mnc(tvb, pinfo, sub_tree, curr_offset, E212_5GSTAI, true);
                curr_offset += 3;

                /*octet 5  TAC 1*/
                proto_tree_add_item(sub_tree, hf_nas_5gs_tac, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
                curr_offset += 3;

                sal_num_e--;
            }
            break;
        case 3:
            dissect_e212_mcc_mnc(tvb, pinfo, sub_tree, curr_offset, E212_5GSTAI, true);
            curr_offset += 3;
            break;
        default:
            proto_tree_add_expert(sub_tree, pinfo, &ei_nas_5gs_unknown_value, tvb, curr_offset, len - 1);
        }



        /*calculate the length of IE?*/
        proto_item_set_len(item, curr_offset - start_offset);
        /*calculate the number of Partial service area list*/
        num_par_sal++;
    }

    return len;
}


/*
 *     9.11.3.50    Service type
 */

/* Used inline as H1 (Upper nibble)*/
static const value_string nas_5gs_mm_serv_type_vals[] = {
    { 0x00, "Signalling" },
    { 0x01, "Data" },
    { 0x02, "Mobile terminated services" },
    { 0x03, "Emergency services" },
    { 0x04, "Emergency services fallback" },
    { 0x05, "High priority access" },
    { 0x06, "Elevated signalling" },
    {    0, NULL }
};

static uint16_t
de_nas_5gs_mm_serv_type(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{

    proto_tree_add_item(tree, hf_nas_5gs_mm_serv_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    return len;
}

/*
 *   9.11.3.50A    SMS indication
 */
static uint16_t
de_nas_5gs_mm_sms_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{

    static int * const flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_spare_b1,
        &hf_nas_5gs_mm_sms_indic_sai,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return len;
}

/*
 *    9.11.3.51    SOR transparent container
 */
static true_false_string tfs_nas_5gs_list_type = {
    "PLMN ID and access technology list",
    "Secured packet"
};

static true_false_string tfs_nas_5gs_list_ind = {
    "List of preferred PLMN/access technology combinations is provided",
    "No list of preferred PLMN/access technology combinations is provided"
};

static true_false_string tfs_nas_5gs_sor_data_type = {
    "Carries acknowledgement of successful reception of the steering of roaming information",
    "Carries steering of roaming information"
};

static true_false_string tfs_nas_5gs_sor_sssi = {
    "SOR-SNPN-SI present",
    "subscribed SNPN or HPLMN indication that 'no change of the SOR-SNPN-SI stored in the UE is needed and thus no SOR-SNPN-SI is provided'"
};

static uint16_t
de_nas_5gs_mm_sor_transp_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    /* Layout differs depending on SOR data type*/
    static int * const flags_dt0[] = {
    &hf_nas_5gs_spare_b7,
    &hf_nas_5gs_spare_b6,
    &hf_nas_5gs_spare_b5,
    &hf_nas_5gs_sor_hdr0_ap,
    &hf_nas_5gs_sor_hdr0_ack,
    &hf_nas_5gs_sor_hdr0_list_type,
    &hf_nas_5gs_sor_hdr0_list_ind,
    &hf_nas_5gs_sor_hdr0_sor_data_type,
    NULL
    };

    static int * const flags_dt1[] = {
    &hf_nas_5gs_spare_b7,
    &hf_nas_5gs_spare_b6,
    &hf_nas_5gs_spare_b5,
    &hf_nas_5gs_spare_b4,
    &hf_nas_5gs_sor_msssnpnsils,
    &hf_nas_5gs_sor_mssnpnsi,
    &hf_nas_5gs_sor_mssi,
    &hf_nas_5gs_sor_hdr0_sor_data_type,
    NULL
    };
    /* 3GPP TS 31.102 [22] subclause 4.2.5 */
    static int * const flags_access_tech_1[] = {
    &hf_nas_5gs_access_tech_o1_b7,
    &hf_nas_5gs_access_tech_o1_b6,
    &hf_nas_5gs_access_tech_o1_b5,
    &hf_nas_5gs_access_tech_o1_b4,
    &hf_nas_5gs_access_tech_o1_b3,
    &hf_nas_5gs_rfu_b2,
    &hf_nas_5gs_rfu_b1,
    &hf_nas_5gs_rfu_b0,
    NULL
    };

    static int * const flags_access_tech_2[] = {
    &hf_nas_5gs_access_tech_o2_b7,
    &hf_nas_5gs_access_tech_o2_b6,
    &hf_nas_5gs_access_tech_o2_b5,
    &hf_nas_5gs_access_tech_o2_b4,
    &hf_nas_5gs_access_tech_o2_b3,
    &hf_nas_5gs_access_tech_o2_b2,
    &hf_nas_5gs_rfu_b1,
    &hf_nas_5gs_rfu_b0,
    NULL
    };

    proto_tree *sub_tree;

    uint8_t oct, data_type, list_type, ap;
    uint32_t curr_offset = offset;
    int i = 1;

    oct = tvb_get_uint8(tvb, offset);
    data_type = oct & 0x01;
    if (data_type == 0) {
        /* SOR header    octet 4*/
        proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags_dt0, ENC_BIG_ENDIAN);
        curr_offset++;
        list_type = (oct & 0x4) >> 2;
        ap = (oct & 0x10) >> 4;
        /* SOR-MAC-IAUSF    octet 5-20 */
        proto_tree_add_item(tree, hf_nas_5gs_sor_mac_iausf, tvb, curr_offset, 16, ENC_NA);
        curr_offset += 16;
        /* CounterSOR    octet 21-22 */
        proto_tree_add_item(tree, hf_nas_5gs_counter_sor, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
        curr_offset += 2;
        if (list_type == 0) {
            /* Secured packet    octet 23* - 2048* */
            proto_tree_add_item(tree, hf_nas_5gs_sor_sec_pkt, tvb, curr_offset, len - 19, ENC_NA);
            curr_offset = curr_offset + (len - 19);
        } else if (ap == 1) {
            uint32_t plmn_id_act_len, cont_len;
            uint64_t oct_o_flags;

            static int * const flags_oct_o[] = {
                &hf_nas_5gs_sor_sssli,
                &hf_nas_5gs_sor_sssi,
                &hf_nas_5gs_sor_sscmi,
                &hf_nas_5gs_sor_si,
                NULL
            };

            proto_tree_add_item_ret_uint(tree, hf_nas_5gs_sor_plmn_id_act_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &plmn_id_act_len);
            curr_offset++;
            while ((curr_offset - offset) < plmn_id_act_len) {
                sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, 5, ett_nas_5gs_mm_sor, NULL, "List item %u", i);
                curr_offset = dissect_e212_mcc_mnc(tvb, pinfo, sub_tree, curr_offset, E212_NONE, true);
                curr_offset += 3;
                proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags_access_tech_1, ENC_BIG_ENDIAN);
                curr_offset++;
                proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags_access_tech_2, ENC_BIG_ENDIAN);
                curr_offset++;
                i++;
            }
            proto_tree_add_bitmask_list_ret_uint64(tree, tvb, curr_offset, 1, flags_oct_o, ENC_BIG_ENDIAN, &oct_o_flags);
            curr_offset++;
            if (oct_o_flags & 0x01) {
                proto_tree_add_item_ret_uint(tree, hf_nas_5gs_sor_cmci_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &cont_len);
                curr_offset += 2;
                proto_tree_add_item(tree, hf_nas_5gs_sor_cmci_payload, tvb, curr_offset, len, ENC_NA);
                curr_offset += len;
            }
            if (oct_o_flags & 0x04) {
                proto_tree_add_item_ret_uint(tree, hf_nas_5gs_sor_snpn_si_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &cont_len);
                curr_offset += 2;
                proto_tree_add_item(tree, hf_nas_5gs_sor_snpn_si_payload, tvb, curr_offset, len, ENC_NA);
                curr_offset += len;
            }
            if (oct_o_flags & 0x08) {
                proto_tree_add_item_ret_uint(tree, hf_nas_5gs_sor_snpn_si_ls_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &cont_len);
                curr_offset += 2;
                proto_tree_add_item(tree, hf_nas_5gs_sor_snpn_si_ls_payload, tvb, curr_offset, len, ENC_NA);
                curr_offset += len;
            }
        } else {
            /* PLMN ID and access technology list    octet 23*-102* */
            while ((curr_offset - offset) < len) {
                sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, 5, ett_nas_5gs_mm_sor, NULL, "List item %u", i);
                /* The PLMN ID and access technology list consists of PLMN ID and access technology identifier
                 * and are coded as specified in 3GPP TS 31.102 [22] subclause 4.2.5
                 *  PLMN
                 * Contents:
                 * - Mobile Country Code (MCC) followed by the Mobile Network Code (MNC).
                 * Coding:
                 * - according to TS 24.008 [9].
                 */
                /* PLMN ID 1    octet 23*- 25* */
                curr_offset = dissect_e212_mcc_mnc(tvb, pinfo, sub_tree, curr_offset, E212_NONE, true);
                /* access technology identifier 1    octet 26*- 27* */
                proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags_access_tech_1, ENC_BIG_ENDIAN);
                curr_offset++;
                proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags_access_tech_2, ENC_BIG_ENDIAN);
                curr_offset++;
                i++;
            }
        }

    } else {
        /* SOR header    octet 4*/
        proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags_dt1, ENC_BIG_ENDIAN);
        curr_offset++;
        /* SOR-MAC-IUE    octet 5 - 20*/
        proto_tree_add_item(tree, hf_nas_5gs_sor_mac_iue, tvb, curr_offset, 16, ENC_NA);
        curr_offset+=16;
    }

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_5gs_extraneous_data);

    return (curr_offset - offset);

}

/*
 *     9.11.3.52    Time zone
 */
/* See subclause 10.5.3.8 in 3GPP TS 24.008 */

/*
 *     9.11.3.53    Time zone and time
 */
/* See subclause 10.5.3.9 in 3GPP TS 24.00 */

/*
 *   9.11.3.53A    UE parameters update transparent container
 */
static uint16_t
de_nas_5gs_mm_ue_par_upd_transp_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}


/*
 *     9.11.3.54    UE security capability
 */

static uint16_t
de_nas_5gs_mm_ue_sec_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    uint32_t curr_offset;

    static int * const oct3_flags[] = {
        &hf_nas_5gs_mm_5g_ea0,
        &hf_nas_5gs_mm_128_5g_ea1,
        &hf_nas_5gs_mm_128_5g_ea2,
        &hf_nas_5gs_mm_128_5g_ea3,
        &hf_nas_5gs_mm_5g_ea4,
        &hf_nas_5gs_mm_5g_ea5,
        &hf_nas_5gs_mm_5g_ea6,
        &hf_nas_5gs_mm_5g_ea7,
        NULL
    };

    static int * const oct4_flags[] = {
        &hf_nas_5gs_mm_5g_ia0,
        &hf_nas_5gs_mm_5g_128_ia1,
        &hf_nas_5gs_mm_5g_128_ia2,
        &hf_nas_5gs_mm_5g_128_ia3,
        &hf_nas_5gs_mm_5g_ia4,
        &hf_nas_5gs_mm_5g_ia5,
        &hf_nas_5gs_mm_5g_ia6,
        &hf_nas_5gs_mm_5g_ia7,
        NULL
    };

    static int * const oct5_flags[] = {
        &hf_nas_5gs_mm_eea0,
        &hf_nas_5gs_mm_128eea1,
        &hf_nas_5gs_mm_128eea2,
        &hf_nas_5gs_mm_eea3,
        &hf_nas_5gs_mm_eea4,
        &hf_nas_5gs_mm_eea5,
        &hf_nas_5gs_mm_eea6,
        &hf_nas_5gs_mm_eea7,
        NULL
    };

    static int * const oct6_flags[] = {
        &hf_nas_5gs_mm_eia0,
        &hf_nas_5gs_mm_128eia1,
        &hf_nas_5gs_mm_128eia2,
        &hf_nas_5gs_mm_eia3,
        &hf_nas_5gs_mm_eia4,
        &hf_nas_5gs_mm_eia5,
        &hf_nas_5gs_mm_eia6,
        &hf_nas_5gs_mm_eia7,
        NULL
    };

    curr_offset = offset;


    /* 5G-EA0    128-5G-EA1    128-5G-EA2    128-5G-EA3    5G-EA4    5G-EA5    5G-EA6    5G-EA7    octet 3 */
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, oct3_flags, ENC_NA);
    curr_offset++;

    /* 5G-IA0    128-5G-IA1    128-5G-IA2    128-5G-IA3    5G-IA4    5G-IA5    5G-IA6    5G-IA7 octet 4 */
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, oct4_flags, ENC_NA);
    curr_offset++;

    if (len == 2) {
        return len;
    }

    /* EEA0    128-EEA1    128-EEA2    128-EEA3    EEA4    EEA5    EEA6    EEA7 octet 5 */
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, oct5_flags, ENC_NA);
    curr_offset++;

    /* EIA0    128-EIA1    128-EIA2    128-EIA3    EIA4    EIA5    EIA6    EIA7 octet 6 */
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, oct6_flags, ENC_NA);


    return len;
}

/*
 * 9.11.3.55    UE's usage setting
 */
static true_false_string tfs_nas_5gs_mm_ue_usage_setting = {
    "Data centric",
    "Voice centric"
};

static uint16_t
de_nas_5gs_mm_ue_usage_set(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    static int * const flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_spare_b1,
        &hf_nas_5gs_mm_ue_usage_setting,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return len;
}

/*
 *    9.11.3.56    UE status
 */

static true_false_string tfs_nas_5gs_mm_n1_mod = {
    "UE is in 5GMM-REGISTERED state",
    "UE is not in 5GMM-REGISTERED state"
};

static true_false_string tfs_nas_5gs_mm_s1_mod = {
    "UE is in EMM-REGISTERED state",
    "UE is not in EMM-REGISTERED state"
};



static uint16_t
de_nas_5gs_mm_ue_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{
    static int * const flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_mm_n1_mode_reg_b1,
        &hf_nas_5gs_mm_s1_mode_reg_b0,
        NULL
    };

    /* 0 Spare    0 Spare    0 Spare    0 Spare    0 Spare    0 Spare    N1 mode    S1 mode reg */
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.11.3.57    Uplink data status
 */

static true_false_string tfs_nas_5gs_ul_data_sts_psi = {
    "uplink data are pending",
    "no uplink data are pending"
};

static uint16_t
de_nas_5gs_mm_ul_data_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    int curr_offset;

    static int * const psi_0_7_flags[] = {
        &hf_nas_5gs_ul_data_sts_psi_7_b7,
        &hf_nas_5gs_ul_data_sts_psi_6_b6,
        &hf_nas_5gs_ul_data_sts_psi_5_b5,
        &hf_nas_5gs_ul_data_sts_psi_4_b4,
        &hf_nas_5gs_ul_data_sts_psi_3_b3,
        &hf_nas_5gs_ul_data_sts_psi_2_b2,
        &hf_nas_5gs_ul_data_sts_psi_1_b1,
        &hf_nas_5gs_ul_data_sts_psi_0_b0,
        NULL
    };

    static int * const psi_8_15_flags[] = {
        &hf_nas_5gs_ul_data_sts_psi_15_b7,
        &hf_nas_5gs_ul_data_sts_psi_14_b6,
        &hf_nas_5gs_ul_data_sts_psi_13_b5,
        &hf_nas_5gs_ul_data_sts_psi_12_b4,
        &hf_nas_5gs_ul_data_sts_psi_11_b3,
        &hf_nas_5gs_ul_data_sts_psi_10_b2,
        &hf_nas_5gs_ul_data_sts_psi_9_b1,
        &hf_nas_5gs_ul_data_sts_psi_8_b0,
        NULL
    };

    curr_offset = offset;
    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, psi_0_7_flags, ENC_BIG_ENDIAN);
    curr_offset++;

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, psi_8_15_flags, ENC_BIG_ENDIAN);
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_5gs_extraneous_data);

    return (curr_offset - offset);
}

/*
 * 9.11.3.58 Void
 * 9.11.3.59 Void
 * 9.11.3.60 Void
 * 9.11.3.61 Void
 * 9.11.3.62 Void
 * 9.11.3.63 Void
 * 9.11.3.64 Void
 * 9.11.3.65 Void
 * 9.11.3.66 Void
 * 9.11.3.67 Void
 */

/*
 * 9.11.3.68 UE radio capability ID
 */
/*
 * The UE radio capability ID contents contain the UE radio capability ID as specified in 3GPP TS 23.003
 * with each digit coded in BCD, starting with the first digit coded in bits 4 to 1 of octet 3,
 * the second digit coded in bits 8 to 5 of octet 3, and so on. If the UE radio capability ID contains
 * an odd number of digits, bits 8 to 5 of the last octet (octet n) shall be coded as "1111".
*/

uint16_t
de_nas_5gs_mm_ue_radio_cap_id(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    int curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_nas_5gs_mm_ue_radio_cap_id, tvb, curr_offset, len, ENC_BCD_DIGITS_0_9|ENC_LITTLE_ENDIAN);

    return len;
}

/*
 * 9.11.3.69    UE radio capability ID deletion indication
 */
static const value_string nas_5gs_mm_ue_radio_cap_id_del_req_vals[] = {
    { 0x0, "UE radio capability ID deletion not requested" },
    { 0x1, "Network-assigned UE radio capability IDs deletion requested" },
    {   0, NULL }
};

static uint16_t
de_nas_5gs_mm_ue_radio_cap_id_del_ind(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    static int* const flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_mm_ue_radio_cap_id_del_req,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.11.3.70    Truncated 5G-S-TMSI configuration
 */
static const value_string nas_5gs_mm_amf_trunc_set_id_vals[] = {
    { 0x0, "reserved" },
    { 0x1, "1 least significant bit of the AMF Set ID" },
    { 0x2, "2 least significant bit of the AMF Set ID" },
    { 0x3, "3 least significant bit of the AMF Set ID" },
    { 0x4, "4 least significant bit of the AMF Set ID" },
    { 0x5, "5 least significant bit of the AMF Set ID" },
    { 0x6, "6 least significant bit of the AMF Set ID" },
    { 0x7, "7 least significant bit of the AMF Set ID" },
    { 0x8, "8 least significant bit of the AMF Set ID" },
    { 0x9, "9 least significant bit of the AMF Set ID" },
    { 0xa, "10 least significant bit of the AMF Set ID" },
    {   0, NULL }
};

static const value_string nas_5gs_mm_amf_trunc_pointer_vals[] = {
    { 0x0, "reserved" },
    { 0x1, "1 least significant bit of the AMF Pointer" },
    { 0x2, "2 least significant bit of the AMF Pointer" },
    { 0x3, "3 least significant bit of the AMF Pointer" },
    { 0x4, "4 least significant bit of the AMF Pointer" },
    { 0x5, "5 least significant bit of the AMF Pointer" },
    { 0x6, "6 least significant bit of the AMF Pointer" },
    {   0, NULL }
};

static uint16_t
de_nas_5gs_mm_truncated_5g_s_tmsi_conf(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_mm_trunc_amf_set_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_trunc_amf_pointer, tvb, offset, 1, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.11.3.71    WUS assistance information
 */
/* See subclause 9.9.3.62 in 3GPP TS 24.301 */

/*
 * 9.11.3.72    N5GC indication
 */
static uint16_t
de_nas_5gs_mm_n5gc_indication(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char* add_string _U_, int string_len _U_)
{
    static int* const flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_spare_b1,
        &hf_nas_5gs_mm_n5gcreg_b0,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;

}

/*
 * 9.11.3.73    NB-N1 mode DRX parameters
 */
static const value_string nas_5gs_mm_nb_n1_drx_params_vals[] = {
    { 0x0, "DRX value not specified"},
    { 0x1, "DRX cycle parameter T = 32"},
    { 0x2, "DRX cycle parameter T = 64"},
    { 0x3, "DRX cycle parameter T = 128"},
    { 0x4, "DRX cycle parameter T = 256"},
    { 0x5, "DRX cycle parameter T = 512"},
    { 0x7, "DRX cycle parameter T = 1024"},
    { 0, NULL }
};

static uint16_t
de_nas_5gs_mm_nb_n1_mode_drx_pars(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_bits_item(tree, hf_nas_5gs_spare_bits, tvb, offset << 3, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_nb_n1_drx_value, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.11.3.74    Additional configuration indication
 */
static true_false_string tfs_nas_5gs_mm_scmr = {
    "release of N1 NAS signalling connection not required",
    "no additional information"
};

static uint16_t
de_nas_5gs_mm_additional_conf_ind(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char* add_string _U_, int string_len _U_)
{
    static int* const flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_spare_b1,
        &hf_nas_5gs_mm_scmr,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.11.3.75    Extended rejected NSSAI
 */
static const value_string nas_5gs_mm_extended_rejected_s_nssai_type_of_list_vals[] = {
    { 0x00, "list of S-NSSAIs without any associated back-off timer value" },
    { 0x01, "list of S-NSSAIs with one associated back-off timer value that applies to all S-NSSAIs in the list" },
    {    0, NULL }
};

static const value_string nas_5gs_mm_extended_rejected_s_nssai_number_of_element_vals[] = {
    { 0x00, "1 element" },
    { 0x01, "2 elements" },
    { 0x02, "3 elements" },
    { 0x03, "4 elements" },
    { 0x04, "5 elements" },
    { 0x05, "6 elements" },
    { 0x06, "7 elements" },
    { 0x07, "8 elements" },
    {    0, NULL }
};

static const value_string nas_5gs_mm_extended_rej_s_nssai_cause_vals[] = {
    { 0x00, "S-NSSAI not available in the current PLMN or SNPN" },
    { 0x01, "S-NSSAI not available in the current registration area" },
    { 0x02, "S-NSSAI not available due to the failed or revoked network slice-specific authentication and authorization" },
    { 0x03, "S-NSSAI not available due to maximum number of UEs reached" },
    {    0, NULL }
};

static uint16_t
de_nas_5gs_mm_extended_rejected_nssai(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree* sub_partial_tree;
    proto_tree* sub_rejected_tree;
    proto_item* item;
    int i;
    unsigned num_partial_items = 1;
    uint32_t curr_offset = offset;
    uint32_t type_of_list, number_of_element, nssai_len;

    /* Rejected NSSAI */
    while ((curr_offset - offset) < len) {
        sub_partial_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_partial_extended_rejected_nssai_list,
            &item, "Partial extended rejected NSSAI list %u", num_partial_items);

        proto_tree_add_item(sub_partial_tree, hf_nas_5gs_mm_extended_rejected_nssai_spare, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_uint(sub_partial_tree, hf_nas_5gs_mm_extended_rejected_nssai_type_of_list, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &type_of_list);
        proto_tree_add_item_ret_uint(sub_partial_tree, hf_nas_5gs_mm_extended_rejected_nssai_number_of_element, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &number_of_element);
        curr_offset++;

        if (type_of_list > 0) {
            item = proto_tree_add_item(sub_partial_tree, hf_nas_5gs_mm_extended_rejected_nssai_back_off_timer, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            de_gc_timer3(tvb, proto_item_add_subtree(item, ett_nas_5gs_mm_ext_rej_nssai_back_off_timer), pinfo, curr_offset, 1, NULL, 0);
            curr_offset++;
        }

        for (i = 0; i < ((int)number_of_element + 1); i++)
        {
            sub_rejected_tree = proto_tree_add_subtree_format(sub_partial_tree, tvb, curr_offset, -1, ett_nas_5gs_mm_ext_rej_nssai,
                &item, "Rejected S-NSSAI %u", i+1);

            /* Octet 3 and octet 4 shall always be included*/
            proto_tree_add_item_ret_uint(sub_rejected_tree, hf_nas_5gs_mm_len_of_rejected_s_nssai, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &nssai_len);
            proto_tree_add_item(sub_rejected_tree, hf_nas_5gs_mm_rejected_s_nssai_cause_value, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            proto_item_set_len(item, nssai_len);
            curr_offset++;
            proto_tree_add_item(sub_rejected_tree, hf_nas_5gs_mm_sst, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            curr_offset++;
            if (nssai_len < 3) {
                continue;
            }
            /* If the octet 5 is included, then octet 6 and octet 7 shall be included.*/
            proto_tree_add_item(sub_rejected_tree, hf_nas_5gs_mm_sd, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
            curr_offset += 3;
            if (nssai_len < 6) {
                continue;
            }
            /* If the octet 8 is included, then octets 9, 10, and 11 may be included*/
            /* Mapped HPLMN SST */
            proto_tree_add_item(sub_rejected_tree, hf_nas_5gs_mm_mapped_hplmn_sst, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            curr_offset += 1;
            if (nssai_len < 7) {
                continue;
            }
            /* Mapped HPLMN SD */
            proto_tree_add_item(sub_rejected_tree, hf_nas_5gs_mm_mapped_hplmn_ssd, tvb, offset, 3, ENC_BIG_ENDIAN);
            curr_offset += 3;
        }
        num_partial_items++;
    }
    return len;
}

/*
 * 9.11.3.76    UE request type
 */
/* See subclause 9.9.3.65 in 3GPP TS 24.301 */

/*
 * 9.11.3.77    Paging restriction
 */
static const value_string nas_5gs_mm_paging_restriction_type_vals[] = {
    { 0x00, "reserved" },
    { 0x01, "All paging is restricted" },
    { 0x02, "All paging is restricted except for voice service" },
    { 0x03, "All paging is restricted except for specified PDU session(s)" },
    { 0x04, "All paging is restricted except for voice service and specified PDU session(s)" },
    {    0, NULL }
};


static uint16_t
de_nas_5gs_mm_paging_restriction(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint64_t type;

    static int * const flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_mm_paging_restriction_type,
        NULL
    };

    static int * const psi_0_7_flags[] = {
        &hf_nas_5gs_mm_paging_restriction_psi_7,
        &hf_nas_5gs_mm_paging_restriction_psi_6,
        &hf_nas_5gs_mm_paging_restriction_psi_5,
        &hf_nas_5gs_mm_paging_restriction_psi_4,
        &hf_nas_5gs_mm_paging_restriction_psi_3,
        &hf_nas_5gs_mm_paging_restriction_psi_2,
        &hf_nas_5gs_mm_paging_restriction_psi_1,
        &hf_nas_5gs_mm_paging_restriction_psi_0,
        NULL
    };

    static int * const psi_8_15_flags[] = {
        &hf_nas_5gs_mm_paging_restriction_psi_15,
        &hf_nas_5gs_mm_paging_restriction_psi_14,
        &hf_nas_5gs_mm_paging_restriction_psi_13,
        &hf_nas_5gs_mm_paging_restriction_psi_12,
        &hf_nas_5gs_mm_paging_restriction_psi_11,
        &hf_nas_5gs_mm_paging_restriction_psi_10,
        &hf_nas_5gs_mm_paging_restriction_psi_9,
        &hf_nas_5gs_mm_paging_restriction_psi_8,
        NULL
    };

    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN, &type);
    if (type == 3 || type == 4) {
        proto_tree_add_bitmask_list(tree, tvb, offset+1, 1, psi_0_7_flags, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask_list(tree, tvb, offset+2, 1, psi_8_15_flags, ENC_BIG_ENDIAN);
    }

    return len;
}

/*
 * 9.11.3.79    NID
 */
static const dgt_set_t dgt0_f_bcd = {
    {
        /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f */
           '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
    }
};

static uint16_t
de_nas_5gs_mm_nid(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    char *nid;

    proto_tree_add_item(tree, hf_nas_5gs_mm_nid_assign_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    nid = tvb_get_bcd_string(pinfo->pool, tvb, offset, 6, &dgt0_f_bcd, true, true, false);
    proto_tree_add_string(tree, hf_nas_5gs_mm_nid_value, tvb, offset, 6, nid);

    return len;
}

/*
 * 9.11.3.80    PEIPS assistance information
 */
static const value_string nas_5gs_mm_peips_assist_info_ue_paging_probability_info_vals[] = {
  {  0, "p00" },
  {  1, "p05" },
  {  2, "p10" },
  {  3, "p15" },
  {  4, "p20" },
  {  5, "p25" },
  {  6, "p30" },
  {  7, "p35" },
  {  8, "p40" },
  {  9, "p45" },
  { 10, "p50" },
  { 11, "p55" },
  { 12, "p60" },
  { 13, "p65" },
  { 14, "p70" },
  { 15, "p75" },
  { 16, "p80" },
  { 17, "p85" },
  { 18, "p90" },
  { 19, "p95" },
  { 20, "p100" },
  {  0, NULL }
};
static value_string_ext nas_5gs_mm_peips_assist_info_ue_paging_probability_info_vals_ext =
    VALUE_STRING_EXT_INIT(nas_5gs_mm_peips_assist_info_ue_paging_probability_info_vals);

static uint16_t
de_nas_5gs_mm_peips_assist_info(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset, i;

    curr_offset = offset;
    i = 1;
    while ((curr_offset - offset) < len) {
        proto_tree *subtree;
        uint32_t type;

        subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, 1, ett_nas_5gs_mm_peips_assist_info, NULL, "PEIPS assistance information type %u", i);
        proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_peips_assist_info_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &type);
        if (type == 0)
            proto_tree_add_item(subtree, hf_nas_5gs_mm_peips_assist_info_paging_subgroup_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        else if (type == 1)
            proto_tree_add_item(subtree, hf_nas_5gs_mm_peips_assist_info_ue_paging_probability_info, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
        i++;
    }

    return len;
}

/*
 * 9.11.3.81    5GS additional request result
 */
static const value_string nas_5gs_mm_add_req_res_prd_vals[] = {
  { 0, "no additional information" },
  { 1, "paging restriction is accepted" },
  { 2, "paging restriction is rejected" },
  { 0, NULL }
};

static uint16_t
de_nas_5gs_mm_5gs_add_req_res(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    static int* const flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_mm_add_req_res_prd,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.11.3.82    NSSRG information
 */
static uint16_t
de_nas_5gs_mm_nssrg_info(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset, i = 1;

    while ((curr_offset - offset) < len) {
        proto_item *item;
        proto_tree *subtree;
        uint32_t start_offset, nssrg_len, s_nssai_len;

        subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_nssrg_info, &item, "NSSRG values for S-NSSAI %u", i);
        proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_nssrg_info_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &nssrg_len);
        curr_offset++;
        proto_item_set_len(item, nssrg_len + 1);
        start_offset = curr_offset;
        proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_nssrg_info_s_nssai_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &s_nssai_len);
        curr_offset++;
        curr_offset += de_nas_5gs_cmn_s_nssai(tvb, subtree, pinfo, curr_offset, s_nssai_len, NULL, 0);
        while ((curr_offset - start_offset) < nssrg_len) {
            proto_tree_add_item(subtree, hf_nas_5gs_mm_nssrg_info_nssrg, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            curr_offset++;
        }
        i++;
    }

    return len;
}

/*
 * 9.11.3.83    List of PLMNs to be used in disaster condition
 */
static uint16_t
de_nas_5gs_mm_plmns_list_disaster_cond(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset, i = 1;

    while ((curr_offset - offset) < len) {
        proto_tree *subtree;

        subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, 3, ett_nas_5gs_mm_plmns_list_disaster_cond, NULL, "PLMN ID %u", i++);
        dissect_e212_mcc_mnc(tvb, pinfo, subtree, curr_offset, E212_5GSTAI, true);
        curr_offset += 3;
    }

    return len;
}

/*
 * 9.11.3.84    Registration wait range
 */
static uint16_t
de_nas_5gs_mm_reg_wait_range(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_nas_5gs_mm_reg_wait_range, NULL, "Minimum registration wait time");
    de_gc_timer(tvb, subtree, pinfo, offset, 1, NULL, 0);
    subtree = proto_tree_add_subtree(tree, tvb, offset+1, 1, ett_nas_5gs_mm_reg_wait_range, NULL, "Minimum registration wait time");
    de_gc_timer(tvb, subtree, pinfo, offset, 1, NULL, 0);

    return len;
}

/*
 * 9.11.3.85    PLMN identity
 */
static uint16_t
de_nas_5gs_mm_plmn_id(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, E212_5GSTAI, true);

    return len;
}

/*
 * 9.11.3.86    Extended CAG information list
 */
static uint16_t
de_nas_5gs_mm_ext_cag_info_list(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_ , int string_len _U_)
{
    return dissect_nas_5gs_mm_cag_information_list(tvb, tree, pinfo, offset, len, true);
}

/*
 * 9.11.3.87    NSAG information
 */
static uint16_t
de_nas_5gs_mm_nsag_info(tvbuff_t* tvb _U_, proto_tree* tree _U_, packet_info* pinfo _U_,
    uint32_t offset _U_, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset, i = 1;

    while ((curr_offset - offset) < len) {
        proto_item *item;
        proto_tree *subtree;
        uint32_t nsag_len, s_nssai_len, tai_len;

        subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_nsag_info, &item, "NSSRG values for S-NSSAI %u", i);
        proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_nsag_info_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &nsag_len);
        curr_offset++;
        proto_item_set_len(item, nsag_len + 1);
        proto_tree_add_item(subtree, hf_nas_5gs_mm_nsag_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_nsag_info_s_nssai_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &s_nssai_len);
        curr_offset++;
        curr_offset += de_nas_5gs_cmn_s_nssai(tvb, subtree, pinfo, curr_offset, s_nssai_len, NULL, 0);
        proto_tree_add_item(subtree, hf_nas_5gs_mm_nsag_prio, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
        proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_nsag_tais_list_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &tai_len);
        curr_offset++;
        if (tai_len) {
            curr_offset += de_nas_5gs_mm_5gs_ta_id_list(tvb, subtree, pinfo, curr_offset, tai_len, NULL, 0);
        }
        i++;
    }

    return len;
}

/*
 * 9.11.3.88    ProSe relay transaction identity
 */
static void
nas_5gs_mm_prose_relay_trans_id(char *s, uint32_t val)
{
    if (val == 0)
        snprintf(s, ITEM_LABEL_LENGTH, "No ProSe relay transaction identity assigned (0)");
    else if (val == 255)
        snprintf(s, ITEM_LABEL_LENGTH, "Reserved (255)");
    else
        snprintf(s, ITEM_LABEL_LENGTH, "%u", val);
}

static uint16_t
de_nas_5gs_mm_prose_relay_trans_id(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_mm_prose_relay_trans_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.11.3.89    Relay key request parameters
 */
static true_false_string tfs_nas_5gs_mm_relay_key_req_params_uit = {
    "CP-PRUK ID",
    "SUCI"
};

static uint16_t
de_nas_5gs_mm_relay_key_req_params(tvbuff_t* tvb _U_, proto_tree* tree _U_, packet_info* pinfo _U_,
    uint32_t offset _U_, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset;

    proto_tree_add_item(tree, hf_nas_5gs_mm_relay_key_req_params_relay_service_code, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
    curr_offset += 3;
    proto_tree_add_item(tree, hf_nas_5gs_mm_relay_key_req_params_nonce_1, tvb, offset, 16, ENC_NA);
    curr_offset += 16;
    proto_tree_add_bits_item(tree, hf_nas_5gs_spare_bits, tvb, (curr_offset << 3), 7, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_relay_key_req_params_uit, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;
    proto_tree_add_item(tree, hf_nas_5gs_mm_relay_key_req_params_ue_id, tvb, curr_offset, len - (curr_offset - offset), ENC_NA);

    return len;
}

/*
 * 9.11.3.90    Relay key response parameters
 */
static uint16_t
de_nas_5gs_mm_relay_key_resp_params(tvbuff_t* tvb _U_, proto_tree* tree _U_, packet_info* pinfo _U_,
    uint32_t offset _U_, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset;

    proto_tree_add_item(tree, hf_nas_5gs_mm_relay_key_resp_params_key_knr_prose, tvb, curr_offset, 32, ENC_NA);
    curr_offset += 32;
    proto_tree_add_item(tree, hf_nas_5gs_mm_relay_key_resp_params_nonce_2, tvb, offset, 16, ENC_NA);
    curr_offset += 16;
    proto_tree_add_item(tree, hf_nas_5gs_mm_relay_key_resp_params_cp_pruk_id, tvb, curr_offset, len - (curr_offset - offset), ENC_NA);

    return len;
}

/*
 * 9.11.3.91    Priority indicator
 */
static true_false_string tfs_nas_5gs_mm_prio_ind_mcsi = {
    "Access identity 2 valid",
    "Access identity 2 not valid"
};

static true_false_string tfs_nas_5gs_mm_prio_ind_mpsi = {
    "Access identity 1 valid",
    "Access identity 1 not valid"
};

static uint16_t
de_nas_5gs_mm_prio_ind(tvbuff_t* tvb _U_, proto_tree* tree _U_, packet_info* pinfo _U_,
    uint32_t offset _U_, unsigned len _U_,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_bits_item(tree, hf_nas_5gs_spare_bits, tvb, (offset << 3) + 4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_prio_ind_mcsi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_prio_ind_mpsi, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.11.3.92    SNPN list
 */
static uint16_t
de_nas_5gs_mm_snpn_list(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset, i = 1;

    while ((curr_offset - offset) < len) {
        proto_tree *subtree;
        char *nid;

        subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, 9, ett_nas_5gs_mm_snpn_list, NULL, "SNPN identity %u", i++);
        dissect_e212_mcc_mnc(tvb, pinfo, subtree, curr_offset, E212_NONE, true);
        curr_offset += 3;
        nid = tvb_get_bcd_string(pinfo->pool, tvb, curr_offset, 6, &dgt0_f_bcd, true, true, false);
        proto_tree_add_string(subtree, hf_nas_5gs_mm_nid_value, tvb, curr_offset, 6, nid);
        curr_offset += 6;
    }

    return len;
}

/*
 * 9.11.3.93    N3IWF identifier
 */
static const value_string nas_5gs_mm_n3iwf_id_type_vals[] = {
    { 1, "IPv4" },
    { 2, "IPv6" },
    { 3, "IPv4v6" },
    { 4, "FQDN" },
    { 0, NULL }
};

static uint16_t
de_nas_5gs_mm_n3iwf_id(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t type;

    proto_tree_add_item_ret_uint(tree, hf_nas_5gs_mm_n3iwf_id_type, tvb, offset, 1, ENC_BIG_ENDIAN, &type);
    switch (type) {
    case 1:
        proto_tree_add_item(tree, hf_nas_5gs_mm_n3iwf_id_ipv4, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        break;
    case 2:
        proto_tree_add_item(tree, hf_nas_5gs_mm_n3iwf_id_ipv6, tvb, offset+1, 16, ENC_NA);
        break;
    case 3:
        proto_tree_add_item(tree, hf_nas_5gs_mm_n3iwf_id_ipv4, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_nas_5gs_mm_n3iwf_id_ipv6, tvb, offset+5, 16, ENC_NA);
        break;
    case 4:
        proto_tree_add_item(tree, hf_nas_5gs_mm_n3iwf_id_fqdn, tvb, offset+1, len-1, ENC_APN_STR|ENC_NA);
        break;
    default:
        break;
    }

    return len;
}

/*
 * 9.11.3.94    TNAN information
 */
static uint16_t
de_nas_5gs_mm_tnan_info(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_ ,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset, ret_len;
    static int * const flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_mm_tnan_info_ssid_ind,
        &hf_nas_5gs_mm_tnan_info_tngf_id_ind,
        NULL
    };
    uint64_t ret_flags;

    proto_tree_add_bitmask_list_ret_uint64(tree, tvb, curr_offset, 1, flags, ENC_BIG_ENDIAN, &ret_flags);
    curr_offset++;
    if (ret_flags & 0x01) {
        proto_tree_add_item_ret_uint(tree, hf_nas_5gs_mm_tnan_info_tngf_id_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &ret_len);
        curr_offset++;
        proto_tree_add_item(tree, hf_nas_5gs_mm_tnan_info_tngf_id, tvb, curr_offset, ret_len, ENC_NA);
        curr_offset += ret_len;
    }
    if (ret_flags & 0x02) {
        proto_tree_add_item_ret_uint(tree, hf_nas_5gs_mm_tnan_info_ssid_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &ret_len);
        curr_offset++;
        proto_tree_add_item(tree, hf_nas_5gs_mm_tnan_info_ssid, tvb, curr_offset, ret_len, ENC_NA);
        curr_offset += ret_len;
    }

    return len;
}

/*
 * 9.11.3.95    RAN timing synchronization
 */
static uint16_t
de_nas_5gs_mm_ran_timing_sync(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_bits_item(tree, hf_nas_5gs_spare_bits, tvb, offset << 3, 7, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_ran_timing_sync_recreq, tvb, offset, 1, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.11.3.96    Extended LADN information
 */
static uint16_t
de_nas_5gs_mm_ext_ladn_info(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset;
    unsigned i = 1;

    while ((curr_offset - offset) < len) {
        proto_tree *subtree;
        proto_item *item;
        uint32_t start_offset = curr_offset, ret_len;

        subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_ext_ladn_info, &item, "LADN %u", i++);
        proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &ret_len);
        curr_offset++;
        curr_offset += de_nas_5gs_cmn_dnn(tvb, subtree, pinfo, curr_offset, len, NULL, 0);
        proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &ret_len);
        curr_offset++;
        curr_offset += de_nas_5gs_cmn_s_nssai(tvb, subtree, pinfo, curr_offset, ret_len, NULL, 0);
        proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &ret_len);
        curr_offset++;
        curr_offset += de_nas_5gs_mm_5gs_ta_id_list(tvb, subtree, pinfo, curr_offset, ret_len, NULL, 0);
        proto_item_set_len(item, curr_offset - start_offset);
    }

    return len;
}

/*
 * 9.11.3.97    Alternative NSSAI
 */
static uint16_t
de_nas_5gs_mm_alt_nssai(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset;
    unsigned i = 1;

    while ((curr_offset - offset) < len) {
        proto_tree *subtree, *subtree2;
        proto_item *item, *item2;
        uint32_t start_offset = curr_offset, start_offset2, ret_len;

        subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_alt_nssai, &item, "Entry %u", i++);
        subtree2 = proto_tree_add_subtree(subtree, tvb, curr_offset, -1, ett_nas_5gs_mm_alt_nssai_replaced, &item2, "S-NSSAI to be replaced");
        start_offset2 = curr_offset;
        proto_tree_add_item_ret_uint(subtree2, hf_nas_5gs_mm_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &ret_len);
        curr_offset++;
        curr_offset += de_nas_5gs_cmn_s_nssai(tvb, subtree2, pinfo, curr_offset, ret_len, NULL, 0);
        proto_item_set_len(item2, curr_offset - start_offset2);
        subtree2 = proto_tree_add_subtree(subtree, tvb, curr_offset, -1, ett_nas_5gs_mm_alt_nssai_alternative, &item2, "Alternative S-NSSAI");
        start_offset2 = curr_offset;
        proto_tree_add_item_ret_uint(subtree2, hf_nas_5gs_mm_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &ret_len);
        curr_offset++;
        curr_offset += de_nas_5gs_cmn_s_nssai(tvb, subtree2, pinfo, curr_offset, ret_len, NULL, 0);
        proto_item_set_len(item2, curr_offset - start_offset2);
        proto_item_set_len(item, curr_offset - start_offset);
    }

    return len;
}

/*
 * 9.11.3.98    Type 6 IE container
 */
#define TYPE6_IE_TLV_E(EOT_iei, EOT_pdu_type, EOT_elem_idx, EOT_elem_name_addition) \
{\
    if ((signed)curr_len <= 0) return len; \
    if ((consumed = elem_tlv_e(tvb, tree, pinfo, (uint8_t) EOT_iei, EOT_pdu_type, EOT_elem_idx, curr_offset, curr_len, EOT_elem_name_addition)) > 0) \
    { \
        curr_offset += consumed; \
        curr_len -= consumed; \
    } \
}

static uint16_t
de_nas_5gs_mm_type_6_ie_cont(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Information elements and IEIs for the Registration accept type 6 IE container */
    /* 01 Extended LADN information    Extended LADN information    9.11.3.96    O    TLV-E    15-1787 */
    TYPE6_IE_TLV_E(0x01, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EXT_LADN_INFO, NULL);
    /* 02 S-NSSAI location validity information    S-NSSAI location validity information    9.11.3.100    O    TLV-E    17-38611 */
    TYPE6_IE_TLV_E(0x02, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_S_NSSAI_LOC_VALID_INFO, NULL);
    /* 03 Partially allowed NSSAI    Partial NSSAI    9.11.3.103    O    TLV-E    3-808 */
    TYPE6_IE_TLV_E(0x03, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PARTIAL_NSSAI, " - Partially allowed NSSAI");
    /* 04 Partially allowed NSSAI    Partial NSSAI    9.11.3.103    O    TLV-E    3-808 */
    TYPE6_IE_TLV_E(0x04, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PARTIAL_NSSAI, " - Partially rejected NSSAI");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

    return len;
}

/*
 * 9.11.9.99    Non-3GPP access path switching indication
 */
static uint16_t
de_nas_5gs_mm_n3gpp_acc_path_switch_ind(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_bits_item(tree, hf_nas_5gs_spare_bits, tvb, offset << 3, 7, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_n3gpp_acc_path_switch_ind_naps, tvb, offset, 1, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.11.3.100   S-NSSAI location validity information
 */
static uint16_t
de_nas_5gs_mm_s_nssai_loc_valid_info(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset;
    unsigned i = 1;

    while ((curr_offset - offset) < len) {
        proto_tree *subtree;
        proto_item *item;
        uint32_t start_offset = curr_offset, length, j;

        subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_s_nssai_loc_valid_info, &item, "Per-S-NSSAI location validity information for S-NSSAI %u", i++);
        proto_tree_add_item(subtree, hf_nas_5gs_mm_s_nssai_loc_valid_info_per_s_nssai_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
        curr_offset += 2;
        proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &length);
        curr_offset++;
        curr_offset += de_nas_5gs_cmn_s_nssai(tvb, subtree, pinfo, curr_offset, length, NULL, 0);
        proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_s_nssai_loc_valid_info_per_s_nssai_nb_nr_cgi, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &length);
        curr_offset++;
        for (j = 0; j < length; j++) {
            proto_tree_add_item(subtree, hf_nas_5gs_mm_s_nssai_loc_valid_info_per_s_nssai_nr_cell_id, tvb, curr_offset, 5, ENC_BIG_ENDIAN);
            curr_offset += 5;
            curr_offset = dissect_e212_mcc_mnc(tvb, pinfo, tree, curr_offset, E212_NONE, true);
        }
        proto_item_set_len(item, curr_offset - start_offset);
    }

    return len;
}

/*
 * 9.11.3.101   S-NSSAI time validity information
 */
static const value_string nas_5gs_mm_s_nssai_time_valid_info_time_window_recurrence_pattern_vals[] = {
    { 0, "Everyday" },
    { 1, "Every weekday" },
    { 2, "Every week" },
    { 3, "Every 2 weeks" },
    { 4, "Every month (absolute)" },
    { 5, "Every month (relative)" },
    { 6, "Every quarter (absolute)" },
    { 7, "Every quarter (relative)" },
    { 8, "Every 6 months (absolute)" },
    { 9, "Every 6 months (relative)" },
    { 0, NULL }
};

static uint16_t
de_nas_5gs_mm_s_nssai_time_valid_info(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset;
    unsigned i = 1;

    while ((curr_offset - offset) < len) {
        proto_tree *subtree;
        proto_item *item;
        uint32_t start_offset = curr_offset, length, start_offset2, time_window_len;

        subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_s_nssai_time_valid_info, &item, "Per-S-NSSAI time validity information for S-NSSAI %u", i++);
        proto_tree_add_item(subtree, hf_nas_5gs_mm_s_nssai_time_valid_info_per_s_nssai_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
        proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &length);
        curr_offset++;
        curr_offset += de_nas_5gs_cmn_s_nssai(tvb, subtree, pinfo, curr_offset, length, NULL, 0);
        proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_s_nssai_time_valid_info_per_s_nssai_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &length);
        curr_offset++;
        start_offset2 = curr_offset;
        while ((curr_offset - start_offset2) < length) {
            proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_s_nssai_time_valid_info_time_window_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &time_window_len);
            curr_offset++;
            proto_tree_add_item(subtree, hf_nas_5gs_mm_s_nssai_time_valid_info_time_window_start_time, tvb, curr_offset, 8, ENC_NA);
            curr_offset += 8;
            proto_tree_add_item(subtree, hf_nas_5gs_mm_s_nssai_time_valid_info_time_window_stop_time, tvb, curr_offset, 8, ENC_NA);
            curr_offset += 8;
            if (time_window_len >= 9) {
                proto_tree_add_bits_item(tree, hf_nas_5gs_spare_bits, tvb, offset << 3, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_nas_5gs_mm_s_nssai_time_valid_info_time_window_recurrence_pattern, tvb, offset, 1, ENC_BIG_ENDIAN);
                curr_offset++;
                if (time_window_len >= 10) {
                    proto_tree_add_item(subtree, hf_nas_5gs_mm_s_nssai_time_valid_info_time_window_recurrence_end_time, tvb, curr_offset, 8, ENC_NA);
                    curr_offset += 8;
                }
            }
        }
        proto_item_set_len(item, curr_offset - start_offset);
    }

    return len;
}

/*
 * 9.11.3.102   Non-3GPP path switching information
 */
static uint16_t
de_nas_5gs_mm_n3gpp_path_switch_info(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_bits_item(tree, hf_nas_5gs_spare_bits, tvb, offset << 3, 7, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_n3gpp_path_switch_info_nsonr, tvb, offset, 1, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.11.3.103   Partial NSSAI
 */
static uint16_t
de_nas_5gs_mm_partial_nssai(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset, ret_len;

    while ((curr_offset - offset) < len) {
        proto_tree_add_item_ret_uint(tree, hf_nas_5gs_mm_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &ret_len);
        curr_offset++;
        if (ret_len > 0)
            curr_offset += de_nas_5gs_cmn_s_nssai(tvb, tree, pinfo, curr_offset, ret_len, NULL, 0);
        proto_tree_add_item_ret_uint(tree, hf_nas_5gs_mm_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &ret_len);
        curr_offset++;
        if (ret_len > 0)
            curr_offset += de_nas_5gs_mm_5gs_ta_id_list(tvb, tree, pinfo, curr_offset, ret_len, NULL, 0);
    }

    return len;
}

/*
 * 9.11.3.104   AUN3 indication
 */
static uint16_t
de_nas_5gs_mm_au3n_ind(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_bits_item(tree, hf_nas_5gs_spare_bits, tvb, offset << 3, 7, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_au3n_ind_aun3reg, tvb, offset, 1, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.11.3.105   Feature authorization indication
 */
static const value_string nas_5gs_mm_feat_auth_ind_mbsrai_vals[] = {
    { 0, "no information" },
    { 1, "not authorized to operate as MBSR but allowed to operate as a UE" },
    { 2, "authorized to operate as MBSR" },
    { 0, NULL }
};

static uint16_t
de_nas_5gs_mm_feat_auth_ind(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_bits_item(tree, hf_nas_5gs_spare_bits, tvb, offset << 3, 6, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_feat_auth_ind_mbsrai, tvb, offset, 1, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.11.3.106   Payload container information
 */
static const true_false_string tfs_nas_5gs_mm_payload_cont_info_pru = {
    "Payload container related to PRU",
    "Payload container not related to PRU"
};

static uint16_t
de_nas_5gs_mm_payload_cont_info(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_bits_item(tree, hf_nas_5gs_spare_bits, tvb, offset << 3, 7, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_payload_cont_info_pru, tvb, offset, 1, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.11.3.107   AUN3 device security key
 */
static const value_string nas_5gs_mm_aun3_device_sec_key_askt_vals[] = {
    { 0, "Master session key is included" },
    { 1, "K_WAGF key is included" },
    { 0, NULL }
};

static uint16_t
de_nas_5gs_mm_aun3_device_sec_key(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t ret_len;

    proto_tree_add_bits_item(tree, hf_nas_5gs_spare_bits, tvb, offset << 3, 6, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_aun3_device_sec_key_askt, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_nas_5gs_mm_aun3_device_sec_key_key_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN, &ret_len);
    proto_tree_add_item(tree, hf_nas_5gs_mm_aun3_device_sec_key_key, tvb, offset + 2, ret_len, ENC_NA);

    return len;
}

/*
 * 9.11.3.108   On-demand NSSAI
 */
static uint16_t
de_nas_5gs_mm_on_demand_nssai(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset;
    unsigned i = 1;

    while ((curr_offset - offset) < len) {
        proto_tree *subtree;
        proto_item *item;
        uint32_t start_offset = curr_offset, length, ret_len;

        subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_mm_on_demand_nssai, &item, "Information of on-demand S-NSSAI %u", i++);
        proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_on_demand_nssai_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &length);
        curr_offset++;
        proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_mm_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &ret_len);
        curr_offset++;
        curr_offset += de_nas_5gs_cmn_s_nssai(tvb, subtree, pinfo, curr_offset, ret_len, NULL, 0);
        if ((curr_offset < start_offset) < (length + 1)) {
            proto_tree_add_item(subtree, hf_nas_5gs_mm_on_demand_nssai_slice_dereg_inactiv_timer, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
            curr_offset += 2;
        }
        proto_item_set_len(item, curr_offset - start_offset);
    }

    return len;
}

/*
 * 9.11.3.109   Extended 5GMM cause
 */
static const true_false_string tfs_nas_5gs_mm_ext_5gmm_cause_sat_nr = {
    "Satellite NG-RAN allowed in PLMN",
    "Satellite NG-RAN not allowed in PLMN"
};

static uint16_t
de_nas_5gs_mm_ext_5gmm_cause(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_bits_item(tree, hf_nas_5gs_spare_bits, tvb, offset << 3, 7, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_ext_5gmm_cause_sat_nr, tvb, offset, 1, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.11.4    5GS session management (5GSM) information elements
 */

/*
 * 9.11.4.1 5GSM capability
 */
static const value_string nas_5gs_sm_atsss_st_b3_b6_vals[] = {
    { 0x0, "ATSSS not supported" },
    { 0x1, "ATSSS Low-Layer functionality with any steering mode allowed for ATSSS-LL supported" },
    { 0x2, "MPTCP functionality with any steering mode and ATSSS-LL functionality with only active-standby steering mode supported" },
    { 0x3, "MPTCP functionality with any steering mode and ATSSS-LL functionality with any steering mode allowed for ATSSS-LL supported" },
    { 0x4, "MPQUIC functionality with any steering mode and ATSSS-LL functionality with only active-standby steering mode supported" },
    { 0x5, "MPQUIC functionality with any steering mode and ATSSS-LL functionality with any steering mode allowed for ATSSS-LL supported" },
    { 0x6, "MPTCP functionality with any steering mode, MPQUIC functionality with any steering mode and ATSSS-LL functionality with only active-standby steering mode supported" },
    { 0x7, "MPTCP functionality with any steering mode, MPQUIC functionality with any steering mode and ATSSS-LL functionality with any steering mode allowed for ATSSS-LL supported" },
    { 0,   NULL }
};

static uint16_t
de_nas_5gs_sm_5gsm_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset;

    static int * const flags1[] = {
        &hf_nas_5gs_sm_tpmic_b7,
        &hf_nas_5gs_sm_atsss_st_b3_b6,
        &hf_nas_5gs_sm_ept_s1_b2,
        &hf_nas_5gs_sm_mh6_pdu_b1,
        &hf_nas_5gs_sm_rqos_b0,
        NULL
    };

    static int * const flags2[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_sm_sdnaepc_b1,
        &hf_nas_5gs_sm_apmqf_b0,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags1, ENC_BIG_ENDIAN);
    curr_offset++;

    if ((curr_offset - offset) >= len)
        return (len);

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags2, ENC_BIG_ENDIAN);
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_5gs_extraneous_data);

    return (curr_offset - offset);
}

/*
 *     9.11.4.2    5GSM cause
 */

const value_string nas_5gs_sm_cause_vals[] = {
    { 0x08, "Operator determined barring" },
    { 0x1a, "Insufficient resources" },
    { 0x1b, "Missing or unknown DNN" },
    { 0x1c, "Unknown PDU session type" },
    { 0x1d, "User authentication or authorization failed" },
    { 0x1f, "Request rejected, unspecified" },
    { 0x20, "Service option not supported" },
    { 0x21, "Requested service option not subscribed" },
    { 0x22, "Service option temporarily out of order" }, /* no more defined, kept for backward compatibility */
    { 0x23, "PTI already in use" },
    { 0x24, "Regular deactivation" },
    { 0x25, "5GS QoS not accepted" },
    { 0x26, "Network failure" },
    { 0x27, "Reactivation requested" },
    { 0x29, "Semantic error in the TFT operation" },
    { 0x2a, "Syntactical error in the TFT operation" },
    { 0x2b, "Invalid PDU session identity" },
    { 0x2c, "Semantic errors in packet filter(s)" },
    { 0x2d, "Syntactical error in packet filter(s)" },
    { 0x2e, "Out of LADN service area" },
    { 0x2f, "PTI mismatch" },
    { 0x32, "PDU session type IPv4 only allowed" },
    { 0x33, "PDU session type IPv6 only allowed" },
    { 0x36, "PDU session does not exist" },
    { 0x39, "PDU session type IPv4v6 only allowed" },
    { 0x3a, "PDU session type Unstructured only allowed" },
    { 0x3b, "Unsupported 5QI value" },
    { 0x3d, "PDU session type Ethernet only allowed" },
    { 0x43, "Insufficient resources for specific slice and DNN" },
    { 0x44, "Not supported SSC mode" },
    { 0x45, "Insufficient resources for specific slice" },
    { 0x46, "Missing or unknown DNN in a slice" },
    { 0x51, "Invalid PTI value" },
    { 0x52, "Maximum data rate per UE for user-plane integrity protection is too low" },
    { 0x53, "Semantic error in the QoS operation" },
    { 0x54, "Syntactical error in the QoS operation" },
    { 0x55, "Invalid mapped EPS bearer identity" },
    { 0x56, "UAS services not allowed" },
    { 0x5f, "Semantically incorrect message" },
    { 0x60, "Invalid mandatory information" },
    { 0x61, "Message type non-existent or not implemented" },
    { 0x62, "Message type not compatible with the protocol state" },
    { 0x63, "Information element non-existent or not implemented" },
    { 0x64, "Conditional IE error" },
    { 0x65, "Message not compatible with the protocol state" },
    { 0x6f, "Protocol error, unspecified" },
    { 0,    NULL }
};

static uint16_t
de_nas_5gs_sm_5gsm_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{
    uint32_t cause;

    proto_tree_add_item_ret_uint(tree, hf_nas_5gs_sm_5gsm_cause, tvb, offset, 1, ENC_BIG_ENDIAN, &cause);

    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
        val_to_str_const(cause, nas_5gs_sm_cause_vals, "Unknown"));


    return 1;
}

/*
 * 9.11.4.3 Always-on PDU session indication
 */
static true_false_string tfs_nas_5gs_sm_apsi = {
    "required",
    "not allowed"
};

static uint16_t
de_nas_5gs_sm_always_on_pdu_ses_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    static int * const flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_spare_b1,
        &hf_nas_5gs_sm_apsi,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.11.4.4 Always-on PDU session requested
 */
static uint16_t
de_nas_5gs_sm_always_on_pdu_ses_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    static int * const flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_spare_b1,
        &hf_nas_5gs_sm_apsr,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.11.4.5    Allowed SSC mode
 */

static uint16_t
de_nas_5gs_sm_5gsm_allowed_ssc_mode(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{

    static int * const flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_sm_all_ssc_mode_b2,
        &hf_nas_5gs_sm_all_ssc_mode_b1,
        &hf_nas_5gs_sm_all_ssc_mode_b0,
        NULL
    };


    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}

/*
 *     9.11.4.6    Extended protocol configuration options
 */
/* See subclause 10.5.6.3A in 3GPP TS 24.008 */

/*
 * 9.11.4.7 Integrity protection maximum data rate
 */
static const value_string nas_5gs_sm_int_prot_max_data_rate_vals[] = {
    { 0x00, "64 kbps" },
    { 0x01, "NULL" },
    { 0xff, "Full data rate" },
    { 0,    NULL }
};

static uint16_t
de_nas_5gs_sm_int_prot_max_data_rte(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{
    /* Maximum data rate per UE for user-plane integrity protection for uplink */
    proto_tree_add_item(tree, hf_nas_5gs_sm_int_prot_max_data_rate_ul, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Maximum data rate per UE for user-plane integrity protection for downlink */
    proto_tree_add_item(tree, hf_nas_5gs_sm_int_prot_max_data_rate_dl, tvb, offset+1, 1, ENC_BIG_ENDIAN);

    return 2;
}

/*
 *     9.11.4.8 Mapped EPS bearer contexts
 */
static const value_string nas_5gs_sm_mapd_eps_b_cont_opt_code_vals[] = {
    { 0x0,  "Reserved" },
    { 0x01, "Create new EPS bearer" },
    { 0x02, "Delete existing EPS bearer" },
    { 0x03, "Modify existing EPS bearer" },
    { 0,    NULL }
};

static const value_string nas_5gs_sm_mapd_eps_b_cont_E_vals[] = {
    { 0x0,  "parameters list is not included" },
    { 0x01, "parameters list is included" },
    { 0,    NULL }
};

static const value_string nas_5gs_sm_mapd_eps_b_cont_E_Modify_vals[] = {
    { 0x0,  "extension of previously provided parameters list" },
    { 0x01, "replacement of all previously provided parameters list" },
    { 0,    NULL }
};

static const value_string nas_5gs_sm_mapd_eps_b_cont_param_id_vals[] = {
    { 0x01, "Mapped EPS QoS parameters" },
    { 0x02, "Mapped extended EPS QoS parameters" },
    { 0x03, "Traffic flow template" },
    { 0x04, "APN-AMBR" },
    { 0x05, "Extended APN-AMBR" },
    { 0,    NULL }
};

static uint16_t
de_nas_5gs_sm_mapped_eps_b_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{

    uint32_t curr_offset;
    proto_tree * sub_tree, *sub_tree1;
    uint32_t num_cont, length, opt_code, num_eps_parms, param_id;
    proto_item * item;
    unsigned i;

    curr_offset = offset;
    num_cont = 1;

    static int * const mapd_eps_b_cont_flags[] = {
        &hf_nas_5gs_sm_mapd_eps_b_cont_opt_code,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_sm_mapd_eps_b_cont_E,
        &hf_nas_5gs_sm_mapd_eps_b_cont_num_eps_parms,
        NULL
     };

    static int * const mapd_eps_b_cont_flags_modify[] = {
        &hf_nas_5gs_sm_mapd_eps_b_cont_opt_code,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_sm_mapd_eps_b_cont_E_mod,
        &hf_nas_5gs_sm_mapd_eps_b_cont_num_eps_parms,
        NULL
    };

    /* The IE contains a number of Mapped EPS bearer context */
    while ((curr_offset - offset) < len) {
        /* Figure 9.11.4.5.2: Mapped EPS bearer context */
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_sm_mapd_eps_b_cont, &item,
            "Mapped EPS bearer context %u", num_cont);

        /* EPS bearer identity */
        proto_tree_add_item(sub_tree, hf_nas_5gs_sm_mapd_eps_b_cont_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;

        /* Length of Mapped EPS bearer context*/
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_sm_length, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &length);
        curr_offset += 2;

        /*  8     7     6     5     4     3     2     1          */
        /* operation code | spare | E | number of EPS params     */
        proto_item_set_len(item, length + 3);

        num_eps_parms = tvb_get_uint8(tvb, curr_offset);

        opt_code = (num_eps_parms & 0xc0) >> 6;
        num_eps_parms = num_eps_parms & 0x0f;

        /* operation code = 3 Modify existing EPS bearer */
        if (opt_code == 3) {
            proto_tree_add_bitmask_list(sub_tree, tvb, curr_offset, 1, mapd_eps_b_cont_flags_modify, ENC_BIG_ENDIAN);

        } else {
            proto_tree_add_bitmask_list(sub_tree, tvb, curr_offset, 1, mapd_eps_b_cont_flags, ENC_BIG_ENDIAN);

        }
        curr_offset++;
        i = 1;

        /* EPS parameters list */
        while (num_eps_parms > 0) {

            sub_tree1 = proto_tree_add_subtree_format(sub_tree, tvb, curr_offset, -1, ett_nas_5gs_sm_mapd_eps_b_cont_params_list, &item,
                "EPS parameter %u", i);

            /* EPS parameter identifier */
            proto_tree_add_item_ret_uint(sub_tree1, hf_nas_5gs_sm_mapd_eps_b_cont_param_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &param_id);
            proto_item_append_text(item, " - %s", val_to_str_const(param_id, nas_5gs_sm_mapd_eps_b_cont_param_id_vals, "Unknown"));
            curr_offset++;

            /*length of the EPS parameter contents field */
            proto_tree_add_item_ret_uint(sub_tree1, hf_nas_5gs_sm_length, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &length);
            curr_offset++;

            proto_item_set_len(item, length + 2);
            /*content of the EPS parameter contents field */
            switch (param_id) {
            case 1:
                /* 01H (Mapped EPS QoS parameters) */
                de_esm_qos(tvb, sub_tree1, pinfo, curr_offset, length, NULL, 0);
                break;
            case 2:
                /* 02H (Mapped extended EPS QoS parameters) */
                de_esm_ext_eps_qos(tvb, sub_tree1, pinfo, curr_offset, length, NULL, 0);
                break;
            case 3:
                /* 03H (Traffic flow template)*/
                de_sm_tflow_temp(tvb, sub_tree1, pinfo, curr_offset, length, NULL, 0);
                break;
            case 4:
                /* 04H (APN-AMBR) */
                de_esm_apn_aggr_max_br(tvb, sub_tree1, pinfo, curr_offset, length, NULL, 0);
                break;
            case 5:
                /* 05H (extended APN-AMBR). */
                de_esm_ext_apn_agr_max_br(tvb, sub_tree1, pinfo, curr_offset, length, NULL, 0);
                break;
            default:
                proto_tree_add_item(sub_tree1, hf_nas_5gs_sm_mapd_eps_b_cont_eps_param_cont, tvb, curr_offset, length, ENC_NA);
                break;
            }
            curr_offset +=length;
            i++;
            num_eps_parms--;
        }

        num_cont++;
    }

    return len;


}

/*
 *     9.11.4.9    Maximum number of supported packet filters
 */
static uint16_t
de_nas_5gs_sm_max_num_sup_pkt_flt(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{
    static int * const flags[] = {
        &hf_nas_5gs_sm_max_nb_sup_pkt_flt_nb,
        &hf_nas_5gs_sm_max_nb_sup_pkt_flt_spare,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 2, flags, ENC_BIG_ENDIAN);

    return 2;
}

/*
 *     9.11.4.10    PDU address
 */

static const value_string nas_5gs_sm_pdu_ses_type_vals[] = {
    { 0x1, "IPv4" },
    { 0x2, "IPv6" },
    { 0x3, "IPv4v6" },
    { 0,    NULL }
};


static uint16_t
de_nas_5gs_sm_pdu_address(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    proto_item *ti;
    bool si6lla;
    uint32_t pdu_addr;
    uint8_t interface_id[8];

    /* 0 Spare    0 Spare    0 Spare    0 Spare    SI6LLA    PDU session type value */
    proto_tree_add_item_ret_boolean(tree, hf_nas_5gs_sm_si6lla, tvb, offset, 1, ENC_BIG_ENDIAN, &si6lla);
    ti = proto_tree_add_item_ret_uint(tree, hf_nas_5gs_sm_pdu_ses_type, tvb, offset, 1, ENC_BIG_ENDIAN, &pdu_addr);
    offset++;

    /* PDU address information */
    switch (pdu_addr) {
    case 1:
        /* IPv4 */
        proto_tree_add_item(tree, hf_nas_5gs_sm_pdu_addr_inf_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    case 2:
        /* If the PDU session type value indicates IPv6, the PDU address information in octet 4 to octet 11
         * contains an interface identifier for the IPv6 link local address.
         */
        tvb_memcpy(tvb, interface_id, offset, 8);
        proto_tree_add_bytes_format_value(tree, hf_nas_5gs_sm_pdu_addr_inf_ipv6, tvb, offset, 8, NULL,
                                          "::%x:%x:%x:%x", pntoh16(&interface_id[0]), pntoh16(&interface_id[2]),
                                          pntoh16(&interface_id[4]), pntoh16(&interface_id[6]));
        offset += 8;
        break;
    case 3:
        /* If the PDU session type value indicates IPv4v6, the PDU address information in octet 4 to octet 11
         * contains an interface identifier for the IPv6 link local address and in octet 12 to octet 15
         * contains an IPv4 address.
         */
        tvb_memcpy(tvb, interface_id, offset, 8);
        proto_tree_add_bytes_format_value(tree, hf_nas_5gs_sm_pdu_addr_inf_ipv6, tvb, offset, 8, NULL,
                                          "::%x:%x:%x:%x", pntoh16(&interface_id[0]), pntoh16(&interface_id[2]),
                                          pntoh16(&interface_id[4]), pntoh16(&interface_id[6]));
        offset += 8;
        proto_tree_add_item(tree, hf_nas_5gs_sm_pdu_addr_inf_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    default:
        expert_add_info(pinfo, ti, &ei_nas_5gs_unknown_value);
        return len;
    }

    /* SMF's IPv6 link local address */
    if (si6lla) {
        proto_tree_add_item(tree, hf_nas_5gs_sm_smf_ipv6_lla, tvb, offset, 16, ENC_NA);
    }

    return len;
}

/*
 *     9.11.4.11    PDU session type
 */
static const value_string nas_5gs_pdu_session_type_values[] = {
    { 0x1, "IPv4" },
    { 0x2, "Ipv6" },
    { 0x3, "Ipv4v6" },
    { 0x4, "Unstructured" },
    { 0x5, "Ethernet" },
    { 0, NULL }
 };


static uint16_t
de_nas_5gs_sm_pdu_session_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{

    proto_tree_add_item(tree, hf_nas_5gs_sm_pdu_session_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.11.4.12 QoS flow descriptions
 */

static const value_string nas_5gs_sm_qos_des_flow_opt_code_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "Create new QoS flow description" },
    { 0x02, "Delete existing QoS flow description" },
    { 0x03, "Modify existing QoS flow description" },
    { 0,    NULL }
};

static const value_string nas_5gs_sm_param_id_values[] = {
    { 0x01, "5QI" },
    { 0x02, "GFBR uplink" },
    { 0x03, "GFBR downlink" },
    { 0x04, "MFBR uplink" },
    { 0x05, "MFBR downlink" },
    { 0x06, "Averaging window" },
    { 0x07, "EPS bearer identity" },
    { 0, NULL }
};

uint16_t
de_nas_5gs_sm_qos_flow_des(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{

    proto_tree *sub_tree, *sub_tree2;
    proto_item *item, *sub_item;
    int i = 1, j;
    uint32_t param_len, param_id;
    uint32_t curr_offset, start_offset, start_offset2;
    uint8_t num_param;
    uint32_t unit, mult, val;
    const char *unit_str;
    int hf_unit, hf_val;

    static int * const param_flags[] = {
        &hf_nas_5gs_sm_e,
        &hf_nas_5gs_sm_nof_params,
        NULL
    };

    curr_offset = offset;

    while ((curr_offset - offset) < len) {

        /* QoS flow description */
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, len - (curr_offset - offset), ett_nas_5gs_sm_qos_params, &item, "QoS flow description %u", i);
        start_offset = curr_offset;

        /* 0 0 QFI */
        proto_tree_add_item(sub_tree, hf_nas_5gs_sm_qfi, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset += 1;

        /* Operation code */
        proto_tree_add_item(sub_tree, hf_nas_5gs_sm_qos_des_flow_opt_code, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;

        /* 0 Spare    E    Number of parameters */
        j = 1;
        num_param = tvb_get_uint8(tvb, curr_offset);
        num_param = num_param & 0x3f;
        proto_tree_add_bitmask_list(sub_tree, tvb, curr_offset, 1, param_flags, ENC_BIG_ENDIAN);
        curr_offset++;


        while (num_param > 0) {
            /* Parameter list */
            sub_tree2 = proto_tree_add_subtree_format(sub_tree, tvb, curr_offset, len - (curr_offset - offset), ett_nas_5gs_sm_qos_rules, &sub_item, "Parameter %u", j);
            start_offset2 = curr_offset;

            /* Parameter identifier */
            proto_tree_add_item_ret_uint(sub_tree2, hf_nas_5gs_sm_param_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &param_id);
            proto_item_append_text(item, " - %s", val_to_str_const(param_id, nas_5gs_sm_param_id_values, "Unknown"));
            curr_offset++;
            /* Length of parameter contents */
            proto_tree_add_item_ret_uint(sub_tree2, hf_nas_5gs_sm_param_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &param_len);
            curr_offset++;

            /*parameter content*/
            switch (param_id) {
                /* 01H (5QI)*/
            case 0x01:
                proto_tree_add_item(sub_tree2, hf_nas_5gs_sm_5qi, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                curr_offset += param_len;
                break;
                /* 02H (GFBR uplink); 04H (MFBR uplink);*/
            case 0x02:
            case 0x03:
            case 0x04:
            case 0x05:
                if (param_id == 2) {
                    hf_unit = hf_nas_5gs_sm_unit_for_gfbr_ul;
                    hf_val = hf_nas_5gs_sm_gfbr_ul;
                } else if (param_id == 3) {
                    hf_unit = hf_nas_5gs_sm_unit_for_gfbr_dl;
                    hf_val = hf_nas_5gs_sm_gfbr_dl;
                } else if (param_id == 4) {
                    hf_unit = hf_nas_5gs_sm_unit_for_mfbr_ul;
                    hf_val = hf_nas_5gs_sm_mfbr_ul;
                } else {
                    hf_unit = hf_nas_5gs_sm_unit_for_mfbr_dl;
                    hf_val = hf_nas_5gs_sm_mfbr_dl;
                }
                proto_tree_add_item_ret_uint(sub_tree2, hf_unit, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &unit);
                curr_offset++;
                mult = get_ext_ambr_unit(unit, &unit_str);
                val = tvb_get_ntohs(tvb, curr_offset);
                proto_tree_add_uint_format_value(sub_tree2, hf_val, tvb, curr_offset, param_len - 1,
                    val, "%u %s (%u)", val * mult, unit_str, val);
                curr_offset += (param_len - 1);
                break;
            case 0x06:
                proto_tree_add_item(sub_tree2, hf_nas_5gs_sm_averaging_window, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                curr_offset += param_len;
                break;
            case 0x07:
                proto_tree_add_item(sub_tree2, hf_nas_5gs_sm_eps_bearer_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                curr_offset += param_len;
                break;
            default:
                proto_tree_add_item(sub_tree2, hf_nas_5gs_sm_param_cont, tvb, curr_offset, param_len, ENC_NA);
                curr_offset += param_len;
                break;
            }
            num_param--;
            j++;
            proto_item_set_len(sub_item, curr_offset - start_offset2);
        }
        i++;
        proto_item_set_len(item, curr_offset - start_offset);
    }

    return len;
}
/*
 *     9.11.4.13    QoS rules
 */

static true_false_string tfs_nas_5gs_sm_dqr = {
    "The QoS rule is the default QoS rule",
    "The QoS rule is not the default QoS rule"
};

static const value_string nas_5gs_rule_operation_code_values[] = {
    { 0x0, "Reserved" },
    { 0x1, "Create new QoS rule" },
    { 0x2, "Delete existing QoS rule" },
    { 0x3, "Modify existing QoS rule and add packet filters" },
    { 0x4, "Modify existing QoS rule and replace packet filters" },
    { 0x5, "Modify existing QoS rule and delete packet filters" },
    { 0x6, "Modify existing QoS rule without modifying packet filters" },
    { 0x7, "Reserved" },
    { 0, NULL }
 };

static const value_string nas_5gs_sm_pf_type_values[] = {
    { 0x01, "Match-all type" },
    { 0x10, "IPv4 remote address type" },
    { 0x11, "IPv4 local address type" },
    { 0x21, "IPv6 remote address/prefix length type" },
    { 0x23, "IPv6 local address/prefix length type" },
    { 0x30, "Protocol identifier/Next header type" },
    { 0x40, "Single local port type" },
    { 0x41, "Local port range type" },
    { 0x50, "Single remote port type" },
    { 0x51, "Remote port range type" },
    { 0x60, "Security parameter index type" },
    { 0x70, "Type of service/Traffic class type" },
    { 0x80, "Flow label type" },
    { 0x81, "Destination MAC address type" },
    { 0x82, "Source MAC address type" },
    { 0x83, "802.1Q C-TAG VID type" },
    { 0x84, "802.1Q S-TAG VID type" },
    { 0x85, "802.1Q C-TAG PCP/DEI type" },
    { 0x86, "802.1Q S-TAG PCP/DEI type" },
    { 0x87, "Ethertype type" },
    { 0x88, "Destination MAC address range" },
    { 0x89, "Source MAC address range" },
    { 0, NULL }
 };

static const value_string nas_5gs_sm_pkt_flt_dir_values[] = {
    { 0x00, "Reserved" },
    { 0x01, "Downlink only" },
    { 0x02, "Uplink only" },
    { 0x03, "Bidirectional" },
    { 0, NULL }
 };

uint16_t
de_nas_5gs_sm_qos_rules(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{

    proto_tree *sub_tree, *sub_tree2, *sub_tree3;
    proto_item *item, *item2;
    int i = 1, j, k = 1;
    uint32_t qos_rule_id, pf_len, pf_type, pfc_len;
    uint32_t length, curr_offset, saved_offset, start_offset;
    uint8_t num_pkt_flt, rop;

    static int * const pkt_flt_flags[] = {
        &hf_nas_5gs_sm_rop,
        &hf_nas_5gs_sm_dqr,
        &hf_nas_5gs_sm_nof_pkt_filters,
        NULL
    };

    curr_offset = offset;

    while ((curr_offset - offset) < len) {

        /* QoS Rule */
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_sm_qos_rules, &item, "QoS rule %u", i);

        /* QoS rule identifier Octet 4*/
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_sm_qos_rule_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &qos_rule_id);
        curr_offset += 1;
        /* Length of QoS rule Octet 5 - 6*/
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_sm_length, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &length);
        curr_offset += 2;

        saved_offset = curr_offset;
        proto_item_set_len(item, length + 3);

        /* Rule operation code    DQR bit    Number of packet filters */
        num_pkt_flt = tvb_get_uint8(tvb, curr_offset);
        rop = num_pkt_flt >> 5;
        num_pkt_flt = num_pkt_flt & 0x0f;
        proto_tree_add_bitmask_list(sub_tree, tvb, curr_offset, 1, pkt_flt_flags, ENC_BIG_ENDIAN);
        curr_offset++;

        /* For the "delete existing QoS rule" operation and for the "modify existing QoS rule without modifying packet filters"
         * operation, the number of packet filters shall be coded as 0.
         */
        if ((rop == 0) || (rop == 7)) {
            /* Reserved */
            proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_unknown_value, tvb, curr_offset, length - 1);
            i++;
            curr_offset += (length - 1);
            continue;
        }
        if (((rop == 2) || (rop == 6)) && (num_pkt_flt != 0)) {
            proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_num_pkt_flt, tvb, curr_offset, length - 1);
            i++;
            curr_offset += (length - 1);
            continue;
        }
        if ((rop == 2) && (length > 1)) {
            proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_extraneous_data, tvb, curr_offset, length - 1);
            i++;
            curr_offset += (length - 1);
            continue;
        }

        /* Packet filter list */
        j = 1;
        while (num_pkt_flt > 0) {
            sub_tree2 = proto_tree_add_subtree_format(sub_tree, tvb, curr_offset, -1, ett_nas_5gs_sm_qos_rules, &item, "Packet filter %u", j);
            start_offset = curr_offset;
            if (rop == 5) {
                /* modify existing QoS rule and delete packet filters */
                /* 0    0    0    0    Packet filter identifier x*/
                proto_tree_add_item(sub_tree2, hf_nas_5gs_sm_pkt_flt_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                curr_offset++;
            } else {
                /* "create new QoS rule", or "modify existing QoS rule and add packet filters"
                 * or "modify existing QoS rule and replace packet filters"
                 */
                 /* 0    0    Packet filter direction 1    Packet filter identifier 1*/
                proto_tree_add_item(sub_tree2, hf_nas_5gs_sm_pkt_flt_dir, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sub_tree2, hf_nas_5gs_sm_pkt_flt_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                curr_offset++;
                /* Length of packet filter contents */
                proto_tree_add_item_ret_uint(sub_tree2, hf_nas_5gs_sm_pf_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &pf_len);
                curr_offset++;

                k = 1;
                /* Packet filter contents */
                while (pf_len > 0) {
                    sub_tree3 = proto_tree_add_subtree_format(sub_tree2, tvb, curr_offset, -1, ett_nas_5gs_sm_pkt_filter_components, &item2, "Packet filter component %u", k);
                    /* Each packet filter component shall be encoded as a sequence of a one octet packet filter component type identifier
                     * and a fixed length packet filter component value field.
                     * The packet filter component type identifier shall be transmitted first.
                     */
                    proto_tree_add_item_ret_uint(sub_tree3, hf_nas_5gs_sm_pf_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &pf_type);
                    curr_offset++;
                    /* Packet filter length contains the length of component type and content */
                    pf_len--;
                    switch (pf_type) {
                    case 1:
                        /* Match-all type
                         * . If the "match-all type" packet filter component is present in the packet filter, no other packet filter
                         * component shall be present in the packet filter and the length of the packet filter contents field shall
                         * be set to one.
                         */
                        pfc_len = 0;
                        break;
                    case 16:
                        /* For "IPv4 remote address type", the packet filter component value field shall be encoded as a sequence
                         * of a four octet IPv4 address field and a four octet IPv4 address mask field.
                         * The IPv4 address field shall be transmitted first.
                         */
                    case 17:
                        /* For "IPv4 local address type", the packet filter component value field shall be encoded as defined
                         * for "IPv4 remote address type"
                         */
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_sm_pdu_addr_inf_ipv4, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
                        curr_offset += 4;
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_addr_mask_ipv4, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
                        curr_offset += 4;
                        pfc_len = 8;
                        break;
                    case 33:
                    case 35:
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_ipv6, tvb, curr_offset, 16, ENC_NA);
                        curr_offset += 16;
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_ipv6_prefix_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        curr_offset++;
                        pfc_len = 17;
                        break;
                    case 48:
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_protocol_identifier_or_next_hd, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        curr_offset++;
                        pfc_len = 1;
                        break;
                    case 64:
                    case 80:
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_single_port_type, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                        curr_offset += 2;
                        pfc_len = 2;
                        break;
                    case 65:
                    case 81:
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_port_range_type_low, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                        curr_offset += 2;
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_port_range_type_high, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                        curr_offset += 2;
                        pfc_len = 4;
                        break;
                    case 96:
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_sec_param_idx, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
                        curr_offset += 4;
                        pfc_len = 4;
                        break;
                    case 112:
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_tos_tc_val, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        curr_offset++;
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_tos_tc_mask, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        curr_offset++;
                        pfc_len = 2;
                        break;
                    case 128:
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_flow_label, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
                        curr_offset += 3;
                        pfc_len = 3;
                        break;
                    case 129:
                    case 130:
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_mac_addr, tvb, curr_offset, 6, ENC_NA);
                        curr_offset += 6;
                        pfc_len = 6;
                        break;
                    case 131:
                    case 132:
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_vlan_tag_vid, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                        curr_offset += 2;
                        pfc_len = 2;
                        break;
                    case 133:
                    case 134:
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_vlan_tag_pcp, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_vlan_tag_dei, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                        curr_offset++;
                        pfc_len = 1;
                        break;
                    case 135:
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_ethertype, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
                        curr_offset += 2;
                        pfc_len = 2;
                        break;
                    case 136:
                    case 137:
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_mac_addr_low, tvb, curr_offset, 6, ENC_NA);
                        curr_offset += 6;
                        proto_tree_add_item(sub_tree3, hf_nas_5gs_mac_addr_high, tvb, curr_offset, 6, ENC_NA);
                        curr_offset += 6;
                        pfc_len = 12;
                        break;
                    default:
                        proto_tree_add_expert(sub_tree3, pinfo, &ei_nas_5gs_not_diss, tvb, curr_offset, pf_len);
                        curr_offset += pf_len;
                        pfc_len = pf_len;
                        break;
                    }
                    pf_len -= pfc_len;
                    k++;
                    proto_item_set_len(item2, pfc_len + 1);
                }
            }
            num_pkt_flt--;
            j++;
            proto_item_set_len(item, curr_offset - start_offset);

        }
        if (rop != 2 && (curr_offset - saved_offset) < length) { /* Delete existing QoS rule */
            /* QoS rule precedence (octet z+1)
            * For the "delete existing QoS rule" operation, the QoS rule precedence value field shall not be included.
            * For the "create new QoS rule" operation, the QoS rule precedence value field shall be included.
            */
            proto_tree_add_item(sub_tree, hf_nas_5gs_sm_qos_rule_precedence, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            curr_offset++;
            if ((curr_offset - saved_offset) < length) {
                /* QoS flow identifier (QFI) (bits 6 to 1 of octet z+2)
                * For the "delete existing QoS rule" operation, the QoS flow identifier value field shall not be included.
                * For the "create new QoS rule" operation, the QoS flow identifier value field shall be included.
                */
                proto_tree_add_item(sub_tree, hf_nas_5gs_spare_b7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                /* Segregation bit (bit 7 of octet z+2) */
                if (pinfo->link_dir == P2P_DIR_UL)
                    proto_tree_add_item(sub_tree, hf_nas_5gs_sm_segregation, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                else
                    proto_tree_add_item(sub_tree, hf_nas_5gs_spare_b6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(sub_tree, hf_nas_5gs_sm_qfi, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
                curr_offset++;
            }
        }

        i++;
    }

    return len;
}

/*
 *      9.11.4.14    Session-AMBR
 */

static const value_string nas_5gs_sm_unit_for_session_ambr_values[] = {
    { 0x00, "value is not used" },
    { 0x01, "value is incremented in multiples of 1 Kbps" },
    { 0x02, "value is incremented in multiples of 4 Kbps" },
    { 0x03, "value is incremented in multiples of 16 Kbps" },
    { 0x04, "value is incremented in multiples of 64 Kbps" },
    { 0x05, "value is incremented in multiples of 256 kbps" },
    { 0x06, "value is incremented in multiples of 1 Mbps" },
    { 0x07, "value is incremented in multiples of 4 Mbps" },
    { 0x08, "value is incremented in multiples of 16 Mbps" },
    { 0x09, "value is incremented in multiples of 64 Mbps" },
    { 0x0a, "value is incremented in multiples of 256 Mbps" },
    { 0x0b, "value is incremented in multiples of 1 Gbps" },
    { 0x0c, "value is incremented in multiples of 4 Gbps" },
    { 0x0d, "value is incremented in multiples of 16 Gbps" },
    { 0x0e, "value is incremented in multiples of 64 Gbps" },
    { 0x0f, "value is incremented in multiples of 256 Gbps" },
    { 0x10, "value is incremented in multiples of 1 Tbps" },
    { 0x11, "value is incremented in multiples of 4 Tbps" },
    { 0x12, "value is incremented in multiples of 16 Tbps" },
    { 0x13, "value is incremented in multiples of 64 Tbps" },
    { 0x14, "value is incremented in multiples of 256 Tbps" },
    { 0x15, "value is incremented in multiples of 1 Pbps" },
    { 0x16, "value is incremented in multiples of 4 Pbps" },
    { 0x17, "value is incremented in multiples of 16 Pbps" },
    { 0x18, "value is incremented in multiples of 64 Pbps" },
    { 0x19, "value is incremented in multiples of 256 Pbps" },
    { 0, NULL }
};


uint16_t
de_nas_5gs_sm_session_ambr(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    uint32_t unit, mult, ambr_val;
    const char *unit_str;

    /* Unit for Session-AMBR for downlink */
    proto_tree_add_item_ret_uint(tree, hf_nas_5gs_sm_unit_for_session_ambr_dl, tvb, offset, 1, ENC_BIG_ENDIAN, &unit);
    offset++;

    /* Session-AMBR for downlink (octets 4 and 5) */
    mult = get_ext_ambr_unit(unit, &unit_str);
    ambr_val = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_nas_5gs_sm_session_ambr_dl, tvb, offset, 2,
        ambr_val, "%u %s (%u)", ambr_val * mult, unit_str, ambr_val);
    offset += 2;

    proto_tree_add_item_ret_uint(tree, hf_nas_5gs_sm_unit_for_session_ambr_ul, tvb, offset, 1, ENC_NA, &unit);
    offset++;
    mult = get_ext_ambr_unit(unit, &unit_str);
    ambr_val = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_nas_5gs_sm_session_ambr_ul, tvb, offset, 2,
        ambr_val, "%u %s (%u)", ambr_val * mult, unit_str, ambr_val);

    return len;
}

/*
 *      9.11.4.15    SM PDU DN request container
 */
/* The SM PDU DN request container contains a DN-specific identity of the UE in the network access identifier (NAI) format */
static uint16_t
de_nas_5gs_sm_pdu_dn_req_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_sm_dm_spec_id, tvb, offset, len, ENC_UTF_8|ENC_NA);

    return len;
}

/*
 *      9.11.4.16    SSC mode
 */

static const value_string nas_5gs_sc_mode_values[] = {
    { 0x1, "SSC mode 1" },
    { 0x2, "SSC mode 2" },
    { 0x3, "SSC mode 3" },
    { 0, NULL }
 };


static uint16_t
de_nas_5gs_sm_ssc_mode(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{

    proto_tree_add_item(tree, hf_nas_5gs_sm_sc_mode, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * 9.11.4.17 Re-attempt indicator
 */
static true_false_string tfs_nas_5gs_sm_eplmnc = {
    "UE is not allowed to re-attempt the procedure in an equivalent PLMN",
    "UE is allowed to re-attempt the procedure in an equivalent PLMN"
};

static true_false_string tfs_nas_5gs_sm_ratc = {
    "UE is not allowed to re-attempt the procedure in S1 mode",
    "UE is allowed to re-attempt the procedure in S1 mode"
};

static uint16_t
de_nas_5gs_sm_re_attempt_ind(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    static int* const flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_sm_eplmnc,
        &hf_nas_5gs_sm_ratc,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return len;
}
/*
 * 9.11.4.18 5GSM network feature support
 */
static uint16_t
de_nas_5gs_sm_5gsm_nw_feature_sup(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset;

    static int* const flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_sm_naps,
        &hf_nas_5gs_sm_ept_s1,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags, ENC_BIG_ENDIAN);
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_5gs_extraneous_data);

    return (curr_offset - offset);
}
/*
 * 9.11.4.19 Void
 */

/*
 * 9.11.4.20 Serving PLMN rate control
 * See subclause 9.9.4.28 in 3GPP TS 24.301
 */

/*
 * 9.11.4.21 5GSM congestion re-attempt indicator
 */
static true_false_string tfs_5gs_sm_catbo = {
    "The back-off timer is applied in the current access type",
    "The back-off timer is applied in both 3GPP access type and non-3GPP access type"
};

static true_false_string tfs_5gs_sm_abo = {
    "The back-off timer is applied in all PLMNs or all equivalent SNPNs",
    "The back-off timer is applied in the registered PLMN or registered SNPN"
};

static uint16_t
de_nas_5gs_sm_5gsm_cong_re_attempt_ind(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    static int* const flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_sm_catbo,
        &hf_nas_5gs_sm_abo,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.11.4.22 ATSSS container
 */
static uint16_t
de_nas_5gs_sm_atsss_cont(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_sm_atsss_cont, tvb, offset, len, ENC_NA);

    return len;
}

/*
 * 9.11.4.23 Control plane only indication
 */
static true_false_string tfs_5gs_sm_cpoi = {
    "PDU session can be used for control plane CIoT 5GS optimization only",
    "reserved"
};

static uint16_t
de_nas_5gs_sm_ctl_plane_only_ind(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char* add_string _U_, int string_len _U_)
{
    static int* const flags[] = {
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_spare_b1,
        &hf_nas_5gs_sm_cpoi,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);

    return 1;
}
/*
 * 9.11.4.24 IP header compression configuration
 */
static const value_string nas_5gs_sm_ip_hdr_comp_config_add_ip_hdr_compr_cxt_setup_params_type_vals[] = {
    { 0x00, "0x0000 (No Compression)" },
    { 0x01, "0x0002 (UDP/IP)" },
    { 0x02, "0x0003 (ESP/IP)" },
    { 0x03, "0x0004 (IP)" },
    { 0x04, "0x0006 (TCP/IP)" },
    { 0x05, "0x0102 (UDP/IP)" },
    { 0x06, "0x0103 (ESP/IP)" },
    { 0x07, "0x0104 (IP)" },
    { 0x08, "Other" },
    { 0x0, NULL }
};

static uint16_t
de_nas_5gs_sm_ip_hdr_comp_conf(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset;

    static int * const flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_sm_ip_hdr_comp_config_p0104,
        &hf_nas_5gs_sm_ip_hdr_comp_config_p0103,
        &hf_nas_5gs_sm_ip_hdr_comp_config_p0102,
        &hf_nas_5gs_sm_ip_hdr_comp_config_p0006,
        &hf_nas_5gs_sm_ip_hdr_comp_config_p0004,
        &hf_nas_5gs_sm_ip_hdr_comp_config_p0003,
        &hf_nas_5gs_sm_ip_hdr_comp_config_p0002,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags, ENC_NA);
    curr_offset++;
    proto_tree_add_item(tree, hf_nas_5gs_sm_ip_hdr_comp_config_max_cid, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    curr_offset += 2;

    if ((curr_offset - offset) >= len) {
        return len;
    }

    proto_tree_add_item(tree, hf_nas_5gs_sm_ip_hdr_comp_config_add_ip_hdr_compr_cxt_setup_params_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;
    proto_tree_add_item(tree, hf_nas_5gs_sm_ip_hdr_comp_config_add_ip_hdr_compr_cxt_setup_params_cont, tvb, curr_offset, len - (curr_offset - offset), ENC_NA);

    return len;
}
/*
 * 9.11.4.25 DS-TT Ethernet port MAC address
 */
static uint16_t
de_nas_5gs_sm_ds_tt_eth_port_mac_addr(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_sm_ds_tt_eth_port_mac_addr, tvb, offset, 6, ENC_NA);

    return len;
}

/*
 * 9.11.4.26 UE-DS-TT residence time
 */
static uint16_t
de_nas_5gs_sm_ue_ds_tt_residence_t(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_sm_ue_ds_tt_residence_time, tvb, offset, 8, ENC_NA);

    return len;
}

/*
* 9.11.4.27 Port management information container
*/
static uint16_t
de_nas_5gs_sm_port_mgnt_inf_cont(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_sm_port_mgmt_info_cont, tvb, offset, len, ENC_NA);

    return len;
}

/*
 * 9.11.4.28 Ethernet header compression configuration
 */
static const value_string nas_5gs_sm_eth_hdr_comp_config_cid_len_vals[] = {
    { 0x0, "Ethernet header compression not used" },
    { 0x1, "7 bits" },
    { 0x2, "15 bits" },
    { 0x0, NULL }
};

static uint16_t
de_nas_5gs_sm_eth_hdr_comp_conf(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    static int * const flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_sm_eth_hdr_comp_config_cid_len,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_NA);

    return len;
}

/*
 * 9.11.4.29 Remote UE context list
 */
static uint16_t
de_nas_5gs_sm_remote_ue_ctx_list(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 * 9.11.4.30 Requested MBS container
 */
static uint16_t
de_nas_5gs_sm_req_mbs_cont(tvbuff_t* tvb _U_, proto_tree* tree _U_, packet_info* pinfo _U_,
    uint32_t offset _U_, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 * 9.11.4.31 Received MBS container
 */
static uint16_t
de_nas_5gs_sm_rec_mbs_cont(tvbuff_t* tvb _U_, proto_tree* tree _U_, packet_info* pinfo _U_,
    uint32_t offset _U_, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 * 9.11.4.32 PDU session pair ID
 */
static uint16_t
de_nas_5gs_sm_pdu_session_pair_id(tvbuff_t* tvb _U_, proto_tree* tree _U_, packet_info* pinfo _U_,
    uint32_t offset _U_, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_sm_pdu_session_pair_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.11.4.33 RSN
 */
static const value_string nas_5gs_sm_pdu_session_rsn_vals[] = {
    { 0x0, "v1"},
    { 0x1, "v2"},
    {   0, NULL }
};

static uint16_t
de_nas_5gs_sm_rsn(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_sm_pdu_session_rsn, tvb, offset, 1, ENC_BIG_ENDIAN);

    return len;
}

/*
 * 9.11.4.36 N3QAI
 */
static uint16_t
de_nas_5gs_sm_n3qai(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 * 9.11.4.37 Non-3GPP delay budget
 */
static uint16_t
de_nas_5gs_sm_n3gpp_delay_budget(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 * 9.11.4.38 URSP rule enforcement reports
 */
static uint16_t
de_nas_5gs_sm_ursp_rule_enforce_reports(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 * 9.11.4.39 Protocol description
 */
static uint16_t
de_nas_5gs_sm_prot_desc(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, len);

    return len;
}

/*
 *   9.10.2    Common information elements
 */

/* 9.10.2.1    Additional information*/

static uint16_t
de_nas_5gs_cmn_add_inf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_cmn_add_info, tvb, offset, len, ENC_NA);

    return len;
}

/*
 * 9.11.2.1A    Access type
 */
static const value_string nas_5gs_cmn_acc_type_vals[] = {
    { 0x1, "3GPP access"},
    { 0x2, "Non-3GPP access"},
    {   0, NULL }
};

static int* const nas_5gs_cmn_access_type_flags[] = {
    &hf_nas_5gs_spare_b3,
    &hf_nas_5gs_spare_b2,
    &hf_nas_5gs_cmn_acc_type,
    NULL
};

static uint16_t
de_nas_5gs_cmn_access_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len _U_,
    char *add_string _U_, int string_len _U_)
{

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, nas_5gs_cmn_access_type_flags, ENC_BIG_ENDIAN);

    return 1;

}

/*
 * 9.11.2.1B    DNN
 */

uint16_t
de_nas_5gs_cmn_dnn(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{

    uint32_t    curr_offset;
    proto_item *pi;

    curr_offset = offset;
    /* A DNN value field contains an APN as defined in 3GPP TS 23.003 */

    pi = proto_tree_add_item(tree, hf_nas_5gs_cmn_dnn, tvb, curr_offset, len, ENC_APN_STR | ENC_NA);

    if (len > 100) {
        expert_add_info(pinfo, pi, &ei_nas_5gs_dnn_too_long);
    }
    curr_offset += len;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_5gs_extraneous_data);

    return (curr_offset - offset);

}

/* 9.11.2.2    EAP message*/

static uint16_t
de_nas_5gs_cmn_eap_msg(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    /* EAP message as specified in IETF RFC 3748 */
    if (eap_handle) {
        col_append_str(pinfo->cinfo, COL_PROTOCOL, "/");
        col_set_fence(pinfo->cinfo, COL_PROTOCOL);
        col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_set_fence(pinfo->cinfo, COL_INFO);
        call_dissector(eap_handle, tvb_new_subset_length(tvb, offset, len), pinfo, tree);
    }

    return len;
}

/* 9.11.2.3    GPRS timer */
/* See subclause 10.5.7.3 in 3GPP TS 24.008 */

/* 9.11.2.4    GPRS timer 2*/
/* See subclause 10.5.7.4 in 3GPP TS 24.008 */

/* 9.11.2.5    GPRS timer 3*/
/* See subclause 10.5.7.4a in 3GPP TS 24.008 */

/* 9.11.2.8    S-NSSAI */
uint16_t
de_nas_5gs_cmn_s_nssai(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    /* SST
    * This field contains the 8 bit SST value. The coding of the SST value part is defined in 3GPP TS 23.003
    */
    proto_tree_add_item(tree, hf_nas_5gs_mm_sst, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (len == 1) {
        return len;
    }
    offset += 1;
    if (len > 2) {
        /* SD */
        proto_tree_add_item(tree, hf_nas_5gs_mm_sd, tvb, offset, 3, ENC_BIG_ENDIAN);
        if (len == 4) {
            return len;
        }
        offset += 3;
    }
    /* Mapped HPLMN SST */
    proto_tree_add_item(tree, hf_nas_5gs_mm_mapped_hplmn_sst, tvb, offset, 1, ENC_BIG_ENDIAN);
    if ((len == 2) || (len == 5)) {
        return len;
    }
    offset += 1;
    /* Mapped HPLMN SD */
    proto_tree_add_item(tree, hf_nas_5gs_mm_mapped_hplmn_ssd, tvb, offset, 3, ENC_BIG_ENDIAN);

    return len;
}

/*
* 9.11.2.9    S1 mode to N1 mode NAS transparent container
*/
    /* Message authentication code */
    /* Type of ciphering algorithmType of integrity protection algorithm */
    /* 0 Spare NCC TSC Key set identifier in 5G */
    /* Spare */
    /* Spare */

/* 9.11.2.10    Service-level-AA container */
#define NAS_5GS_TV_IE_MASK    0x80
#define NAS_5GS_TV_IE_VAL     0x80
#define NAS_5GS_TLV_E_IE_MASK 0xf0
#define NAS_5GS_TLV_E_IE_VAL  0x70

static const value_string nas_5gs_cmn_service_level_aa_param_type_vals[] = {
    { 0x10, "Service-level device ID"},
    { 0x20, "Service-level-AA server address"},
    { 0x30, "Service-level-AA response"},
    { 0x40, "Service-level-AA payload type"},
    { 0x70, "Service-level-AA payload"},
    { 0xa0, "Service-level-AA pending indication"},
    {    0, NULL }
};

static const value_string nas_5gs_cmn_service_level_aa_param_serv_addr_type_vals[] = {
    { 1, "IPv4"},
    { 2, "IPv6"},
    { 3, "IPv4v6"},
    { 4, "FQDN"},
    { 0, NULL }
};

static const value_string nas_5gs_cmn_service_level_aa_param_resp_c2ar_vals[] = {
    { 0, "No information"},
    { 1, "C2 authorization was successful"},
    { 2, "C2 authorization was not successful or C2 authorization is revoked"},
    { 3, "Reserved"},
    { 0, NULL }
};

static const value_string nas_5gs_cmn_service_level_aa_param_resp_slar_vals[] = {
    { 0, "No information"},
    { 1, "Service level authentication and authorization was successful"},
    { 2, "Service level authentication and authorization was not successful or service level authorization is revoked"},
    { 3, "Reserved"},
    { 0, NULL }
};

static const value_string nas_5gs_cmn_service_level_aa_param_payload_type_vals[] = {
    { 1, "UUAA payload"},
    { 2, "C2 authorization payload"},
    { 0, NULL }
};

static true_false_string nas_5gs_cmn_service_level_aa_param_pending_ind_slapi_value = {
    "Service-level-AA procedure is to be performed",
    "Reserved"
};

static true_false_string nas_5gs_enabled_not_enabled_value = {
    "Enabled",
    "Not enabled"
};

uint16_t
de_nas_5gs_cmn_service_level_aa_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_,
    uint32_t offset, unsigned len,
    char *add_string _U_, int string_len _U_)
{
    uint32_t curr_offset, i;

    curr_offset = offset;
    i = 0;
    while ((curr_offset - offset) < len) {
        proto_item *item;
        proto_tree *subtree;
        uint32_t type, param_len, param_offset = curr_offset;

        subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_cmn_service_level_aa_cont_param, &item, "Service-level-AA parameter %d", i + 1);
        type = tvb_get_uint8(tvb, curr_offset);
        if ((type & NAS_5GS_TV_IE_MASK) == NAS_5GS_TV_IE_VAL) {
            param_len = 0;
            type &= 0xf0;
        }
        proto_tree_add_uint(subtree, hf_nas_5gs_cmn_service_level_aa_param_type, tvb, curr_offset, 1, type);
        curr_offset++;
        if ((type & NAS_5GS_TLV_E_IE_MASK) == NAS_5GS_TLV_E_IE_VAL) {
            proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_cmn_service_level_aa_param_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &param_len);
            curr_offset += 2;
        } else {
            proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_cmn_service_level_aa_param_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &param_len);
            curr_offset++;
        }
        proto_item_set_len(item, curr_offset + param_len - param_offset);
        switch (type) {
        case 0x10:
            proto_tree_add_item(subtree, hf_nas_5gs_cmn_service_level_aa_param_device_id, tvb, curr_offset, param_len, ENC_UTF_8|ENC_NA);
            break;
        case 0x20:
            {
                uint32_t addr_type;

                proto_tree_add_item_ret_uint(subtree, hf_nas_5gs_cmn_service_level_aa_param_addr_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &addr_type);
                switch (addr_type) {
                case 1:
                    proto_tree_add_item(subtree, hf_nas_5gs_cmn_service_level_aa_param_addr_ipv4, tvb, curr_offset+1, 4, ENC_BIG_ENDIAN);
                    break;
                case 2:
                    proto_tree_add_item(subtree, hf_nas_5gs_cmn_service_level_aa_param_addr_ipv6, tvb, curr_offset+1, 16, ENC_NA);
                    break;
                case 3:
                    proto_tree_add_item(subtree, hf_nas_5gs_cmn_service_level_aa_param_addr_ipv4, tvb, curr_offset+1, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(subtree, hf_nas_5gs_cmn_service_level_aa_param_addr_ipv6, tvb, curr_offset+5, 16, ENC_NA);
                    break;
                case 4:
                    proto_tree_add_item(subtree, hf_nas_5gs_cmn_service_level_aa_param_addr_fqdn, tvb, curr_offset+1, param_len-1, ENC_APN_STR|ENC_NA);
                    break;
                default:
                    break;
                }
            }
            break;
        case 0x30:
            {
                static int * const flags[] = {
                    &hf_nas_5gs_spare_b7,
                    &hf_nas_5gs_spare_b6,
                    &hf_nas_5gs_spare_b5,
                    &hf_nas_5gs_spare_b4,
                    &hf_nas_5gs_cmn_service_level_aa_param_resp_c2ar,
                    &hf_nas_5gs_cmn_service_level_aa_param_resp_slar,
                    NULL
                };
                proto_tree_add_bitmask_list(subtree, tvb, curr_offset, 1, flags, ENC_BIG_ENDIAN);
            }
            break;
        case 0x40:
            proto_tree_add_item(subtree, hf_nas_5gs_cmn_service_level_aa_param_payload_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            break;
        case 0x70:
            proto_tree_add_item(subtree, hf_nas_5gs_cmn_service_level_aa_param_payload, tvb, curr_offset, param_len, ENC_NA);
            break;
        case 0xa0:
            {
                static int * const flags[] = {
                    &hf_nas_5gs_spare_b3,
                    &hf_nas_5gs_spare_b2,
                    &hf_nas_5gs_spare_b1,
                    &hf_nas_5gs_cmn_service_level_aa_param_pending_ind_slapi,
                    NULL
                };
                /* curr_offset was already incremented, need to use previous byte */
                proto_tree_add_bitmask_list(subtree, tvb, curr_offset-1, 1, flags, ENC_BIG_ENDIAN);
            }
            break;
        case 0x50:
            {
                static int * const flags[] = {
                    &hf_nas_5gs_spare_b3,
                    &hf_nas_5gs_spare_b2,
                    &hf_nas_5gs_spare_b1,
                    &hf_nas_5gs_cmn_service_level_aa_param_service_status_ind_uas,
                    NULL
                };
                /* curr_offset was already incremented, need to use previous byte */
                proto_tree_add_bitmask_list(subtree, tvb, curr_offset-1, 1, flags, ENC_BIG_ENDIAN);
            }
            break;
        default:
            proto_tree_add_item(subtree, hf_nas_5gs_cmn_service_level_aa_param_unknown, tvb, curr_offset, param_len, ENC_NA);
            break;
        }
        curr_offset += param_len;
        i++;
    }
    return len;
}

/*
 * Note this enum must be of the same size as the element decoding list
 */
typedef enum
{
    DE_NAS_5GS_CMN_ADD_INF,                      /* 9.11.2.1     Additional information*/
    DE_NAS_5GS_ACCESS_TYPE,                      /* 9.11.2.1A    Access type */
    DE_NAS_5GS_CMN_DNN,                          /* 9.11.2.1B    DNN*/
    DE_NAS_5GS_CMN_EAP_MESSAGE,                  /* 9.11.2.2     EAP message*/
    DE_NAS_5GS_CMN_GPRS_TIMER,                   /* 9.11.2.3     GPRS timer */
    DE_NAS_5GS_CMN_GPRS_TIMER2,                  /* 9.11.2.4     GPRS timer 2*/
    DE_NAS_5GS_CMN_GPRS_TIMER3,                  /* 9.11.2.5     GPRS timer 3*/
    DE_NAS_5GS_CMN_INTRA_N1_MODE_NAS_TRANS_CONT, /* 9.11.2.6     Intra N1 mode NAS transparent container*/
    DE_NAS_5GS_CMN_N1_TO_S1_MODE_TRANS_CONT,     /* 9.11.2.7     N1 mode to S1 mode NAS transparent container */
    DE_NAS_5GS_CMN_S_NSSAI,                      /* 9.11.2.8     S-NSSAI */
    DE_NAS_5GS_CMN_S1_TO_N1_MODE_TRANS_CONT,     /* 9.11.2.9     S1 mode to N1 mode NAS transparent container */
    DE_NAS_5GS_CMN_SERVICE_LEVEL_AA_CONT,        /* 9.11.2.10    Service-level-AA container */
    DE_NAS_5GS_COMMON_NONE                       /* NONE */
}
nas_5gs_common_elem_idx_t;

static const value_string nas_5gs_common_elem_strings[] = {
    { DE_NAS_5GS_CMN_ADD_INF,                       "Additional information" },                          /* 9.11.2.1     Additional information*/
    { DE_NAS_5GS_ACCESS_TYPE,                       "Access type"},                                      /* 9.11.2.1A    Access type */
    { DE_NAS_5GS_CMN_DNN,                           "DNN" },                                             /* 9.11.2.1B    DNN*/
    { DE_NAS_5GS_CMN_EAP_MESSAGE,                   "EAP message" },                                     /* 9.11.2.2     EAP message*/
    { DE_NAS_5GS_CMN_GPRS_TIMER,                    "GPRS timer" },                                      /* 9.11.2.3     GPRS timer*/
    { DE_NAS_5GS_CMN_GPRS_TIMER2,                   "GPRS timer 2" },                                    /* 9.11.2.4     GPRS timer 2*/
    { DE_NAS_5GS_CMN_GPRS_TIMER3,                   "GPRS timer 3" },                                    /* 9.11.2.5     GPRS timer 3*/
    { DE_NAS_5GS_CMN_INTRA_N1_MODE_NAS_TRANS_CONT,  "Intra N1 mode NAS transparent container" },         /* 9.11.2.6     Intra N1 mode NAS transparent container*/
    { DE_NAS_5GS_CMN_N1_TO_S1_MODE_TRANS_CONT,      "N1 mode to S1 mode NAS transparent container" },    /* 9.11.2.7     N1 mode to S1 mode NAS transparent container */
    { DE_NAS_5GS_CMN_S_NSSAI,                       "S-NSSAI" },                                         /* 9.11.2.8     S-NSSAI */
    { DE_NAS_5GS_CMN_S1_TO_N1_MODE_TRANS_CONT,      "S1 mode to N1 mode NAS transparent container" },    /* 9.11.2.9     S1 mode to N1 mode NAS transparent container */
    { DE_NAS_5GS_CMN_SERVICE_LEVEL_AA_CONT,         "Service-level-AA container" },                      /* 9.11.2.10    Service-level-AA container */
    { 0, NULL }
};
value_string_ext nas_5gs_common_elem_strings_ext = VALUE_STRING_EXT_INIT(nas_5gs_common_elem_strings);

#define NUM_NAS_5GS_COMMON_ELEM array_length(nas_5gs_common_elem_strings)
int ett_nas_5gs_common_elem[NUM_NAS_5GS_COMMON_ELEM];


uint16_t(*nas_5gs_common_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string, int string_len) = {
        /*  9.10.2    Common information elements */
        de_nas_5gs_cmn_add_inf,                      /* 9.11.2.1     Additional information*/
        de_nas_5gs_cmn_access_type,                  /* 9.11.2.1A    Access type */
        de_nas_5gs_cmn_dnn,                          /* 9.11.2.1B    DNN*/
        de_nas_5gs_cmn_eap_msg,                      /* 9.11.2.2     EAP message*/
        NULL,                                        /* 9.11.2.3     GPRS timer*/
        NULL,                                        /* 9.11.2.4     GPRS timer 2*/
        NULL,                                        /* 9.11.2.5     GPRS timer 3*/
        NULL,                                        /* 9.11.2.6     Intra N1 mode NAS transparent container*/
        NULL,                                        /* 9.11.2.7     N1 mode to S1 mode NAS transparent container */
        de_nas_5gs_cmn_s_nssai,                      /* 9.11.2.8     S-NSSAI */
        NULL,                                        /* 9.11.2.9     S1 mode to N1 mode NAS transparent container */
        de_nas_5gs_cmn_service_level_aa_cont,        /* 9.11.2.10    Service-level-AA container */
        NULL,   /* NONE */
};



/*
 * 9.11.3    5GS mobility management (5GMM) information elements
 */
#if 0
typedef enum
{
    DE_NAS_5GS_MM_5GMM_CAP,                  /* 9.11.3.1     5GMM capability*/
    DE_NAS_5GS_MM_5GMM_CAUSE,                /* 9.11.3.2     5GMM cause*/
    DE_NAS_5GS_MM_5GS_DRX_PARAM,             /* 9.11.3.2A    5GS DRX parameters*/
    DE_NAS_5GS_MM_5GS_IDENTITY_TYPE,         /* 9.11.3.3     5GS identity type*/
    DE_NAS_5GS_MM_5GS_MOBILE_ID,             /* 9.11.3.4     5GS mobile identity*/
    DE_NAS_5GS_MM_5GS_NW_FEAT_SUP,           /* 9.11.3.5     5GS network feature support*/
    DE_NAS_5GS_MM_5GS_REG_RES,               /* 9.11.3.6     5GS registration result*/
    DE_NAS_5GS_MM_5GS_REG_TYPE,              /* 9.11.3.7     5GS registration type*/
    DE_NAS_5GS_MM_5GS_TA_ID,                 /* 9.11.3.8     5GS tracking area identity */
    DE_NAS_5GS_MM_5GS_TA_ID_LIST,            /* 9.11.3.9     5GS tracking area identity list */
    DE_NAS_5GS_MM_UPDATE_TYPE,               /* 9.11.3.9A    5GS update type */
    DE_NAS_5GS_MM_ABBA,                      /* 9.11.3.10    ABBA */
                                             /* 9.11.3.11    void */
    DE_NAS_5GS_MM_ADD_5G_SEC_INF,            /* 9.11.3.12    Additional 5G security information */
    DE_NAS_5GS_MM_ADD_INF_REQ,               /* 9.11.3.12A   Additional information requested */
    DE_NAS_5GS_MM_ALLOW_PDU_SES_STS,         /* 9.11.3.13    Allowed PDU session status*/
    DE_NAS_5GS_MM_AUT_FAIL_PAR,              /* 9.11.3.14    Authentication failure parameter */
    DE_NAS_5GS_MM_AUT_PAR_AUTN,              /* 9.11.3.15    Authentication parameter AUTN*/
    DE_NAS_5GS_MM_AUT_PAR_RAND,              /* 9.11.3.16    Authentication parameter RAND*/
    DE_NAS_5GS_MM_AUT_RESP_PAR,              /* 9.11.3.17    Authentication response parameter */
    DE_NAS_5GS_MM_CONF_UPD_IND,              /* 9.11.3.18    Configuration update indication*/
    DE_NAS_5GS_MM_CAG_INFORMATION_LIST,      /* 9.11.3.18A   CAG information list*/
    DE_NAS_5GS_MM_CIOT_SMALL_DATA_CONT,      /* 9.11.3.18B   CIoT small data container */
    DE_NAS_5GS_MM_CIPHERING_KEY_DATA,        /* 9.11.3.18C   Ciphering key data*/
    DE_NAS_5GS_MM_CTRL_PLANE_SERVICE_TYPE,   /* 9.11.3.18D   Control plane service type*/
    DE_NAS_5GS_MM_DLGT_SAVING_TIME,          /* 9.11.3.19    Daylight saving time*/
    DE_NAS_5GS_MM_DE_REG_TYPE,               /* 9.11.3.20    De-registration type*/
                                             /* 9.11.3.21    Void */
                                             /* 9.11.3.22    Void*/
    DE_NAS_5GS_MM_EMRG_NR_LIST,              /* 9.11.3.23    Emergency number list */
    DE_NAS_5GS_MM_EPS_BEARER_CTX_STATUS,     /* 9.11.3.23A   EPS bearer context status */
    DE_NAS_5GS_MM_EPS_NAS_MSG_CONT,          /* 9.11.3.24    EPS NAS message container */
    DE_NAS_5GS_MM_EPS_NAS_SEC_ALGO,          /* 9.11.3.25    EPS NAS security algorithms */
    DE_NAS_5GS_MM_EXT_EMERG_NUM_LIST,        /* 9.11.3.26    Extended emergency number list */
    DE_NAS_5GS_MM_EXTENDED_DRX_PARAMETERS,   /* 9.11.3.26A   Extended DRX parameters */
                                             /* 9.11.3.27    Void*/
    DE_NAS_5GS_MM_IMEISV_REQ,                /* 9.11.3.28    IMEISV request*/
    DE_NAS_5GS_MM_LADN_INDIC,                /* 9.11.3.29    LADN indication*/
    DE_NAS_5GS_MM_LADN_INF,                  /* 9.11.3.30    LADN information */
    DE_NAS_5GS_MM_MICO_IND,                  /* 9.11.3.31    MICO indication*/
    DE_NAS_5GS_MM_MA_PDU_SES_INF,            /* 9.11.3.31A   MA PDU session information */
    DE_NAS_5GS_MM_MAPPED_NSSAI,              /* 9.11.3.31B   Mapped NSSAI */
    DE_NAS_5GS_MM_MOBILE_STATION_CLSMK_2,    /* 9.11.3.31C   Mobile station classmark 2 */
    DE_NAS_5GS_MM_NAS_KEY_SET_ID,            /* 9.11.3.32    NAS key set identifier*/
    DE_NAS_5GS_MM_NAS_KEY_SET_ID_H1,         /* 9.11.3.32    NAS key set identifier*/
    DE_NAS_5GS_MM_NAS_MSG_CONT,              /* 9.11.3.33    NAS message container*/
    DE_NAS_5GS_MM_NAS_SEC_ALGO,              /* 9.11.3.34    NAS security algorithms*/
    DE_NAS_5GS_MM_NW_NAME,                   /* 9.11.3.35    Network name*/
    DE_NAS_5GS_MM_NW_SLICING_IND,            /* 9.11.3.36    Network slicing indication */
    DE_NAS_5GS_MM_NW_NON_3GPP_NW_PROV_POL,   /* 9.11.3.36A   Non-3GPP NW provided policies */
    DE_NAS_5GS_MM_NSSAI,                     /* 9.11.3.37    NSSAI*/
    DE_NAS_5GS_MM_NSSAI_INC_MODE,            /* 9.11.3.37A   NSSAI inclusion mode */
    DE_NAS_5GS_MM_OP_DEF_ACC_CAT_DEF,        /* 9.11.3.38    Operator-defined access category definitions */
    DE_NAS_5GS_MM_PLD_CONT,                  /* 9.11.3.39    Payload container*/
    DE_NAS_5GS_MM_PLD_CONT_TYPE,             /* 9.11.3.40    Payload container type*/
    DE_NAS_5GS_MM_PDU_SES_ID_2,              /* 9.11.3.41    PDU session identity 2 */
    DE_NAS_5GS_MM_PDU_SES_REACT_RES,         /* 9.11.3.42    PDU session reactivation result*/
    DE_NAS_5GS_MM_PDU_SES_REACT_RES_ERR_C,   /* 9.11.3.43    PDU session reactivation result error cause */
    DE_NAS_5GS_MM_PDU_SES_STATUS,            /* 9.11.3.44    PDU session status */
    DE_NAS_5GS_MM_PLMN_LIST,                 /* 9.11.3.45    PLMN list*/
    DE_NAS_5GS_MM_REJ_NSSAI,                 /* 9.11.3.46    Rejected NSSAI*/
    DE_NAS_5GS_MM_REL_ASS_IND,               /* 9.11.3.46A   Release assistance indication*/
    DE_NAS_5GS_MM_REQ_TYPE,                  /* 9.11.3.47    Request type */
    DE_NAS_5GS_MM_S1_UE_NW_CAP,              /* 9.11.3.48    S1 UE network capability*/
    DE_NAS_5GS_MM_S1_UE_SEC_CAP,             /* 9.11.3.48A   S1 UE security capability*/
    DE_NAS_5GS_MM_SAL,                       /* 9.11.3.49    Service area list*/
    DE_NAS_5GS_MM_SERV_TYPE,                 /* 9.11.3.50    Service type,*/
    DE_NAS_5GS_MM_SMS_IND,                   /* 9.11.3.50A   SMS indication */
    DE_NAS_5GS_MM_SOR_TRANSP_CONT,           /* 9.11.3.51    SOR transparent container */
    DE_NAS_5GS_MM_SUPPORTED_CODEC_LIST,      /* 9.11.3.51A   Supported codec list */
    DE_NAS_5GS_MM_TZ,                        /* 9.11.3.52    Time zone*/
    DE_NAS_5GS_MM_TZ_AND_T,                  /* 9.11.3.53    Time zone and time*/
    DE_NAS_5GS_MM_UE_PAR_UPD_TRANSP_CONT,    /* 9.11.3.53A   UE parameters update transparent container */
    DE_NAS_5GS_MM_UE_SEC_CAP,                /* 9.11.3.54    UE security capability*/
    DE_NAS_5GS_MM_UE_USAGE_SET,              /* 9.11.3.55    UE's usage setting */
    DE_NAS_5GS_MM_UE_STATUS,                 /* 9.11.3.56    UE status */
    DE_NAS_5GS_MM_UL_DATA_STATUS,            /* 9.11.3.57    Uplink data status */
    DE_NAS_5GS_MM_UE_RADIO_CAP_ID,           /* 9.11.3.68    UE radio capability ID*/
    DE_NAS_5GS_MM_UE_RADIO_CAP_ID_DEL_IND,   /* 9.11.3.69    UE radio capability ID deletion indication*/
    DE_NAS_5GS_MM_TRUNCATED_5G_S_TMSI_CONF,  /* 9.11.3.70    Truncated 5G-S-TMSI configuration*/
    DE_NAS_5GS_MM_WUS_ASSISTANCE_INF,        /* 9.11.3.71    WUS assistance information*/
    DE_NAS_5GS_MM_N5GC_INDICATION,           /* 9.11.3.72    N5GC indication*/
    DE_NAS_5GS_MM_NB_N1_MODE_DRX_PARS,       /* 9.11.3.73    NB-N1 mode DRX parameters*/
    DE_NAS_5GS_MM_ADDITIONAL_CONF_IND,       /* 9.11.3.74    Additional configuration indication*/
    DE_NAS_5GS_MM_EXTENDED_REJECTED_NSSAI,   /* 9.11.3.75    Extended rejected NSSAI*/
    DE_NAS_5GS_MM_UE_REQUEST_TYPE,           /* 9.11.3.76    UE request type */
    DE_NAS_5GS_MM_PAGING_RESTRICTION,        /* 9.11.3.77    Paging restriction */
    DE_NAS_5GS_MM_NID,                       /* 9.11.3.79    NID */
    DE_NAS_5GS_MM_PEIPS_ASSIST_INFO,         /* 9.11.3.80    PEIPS assistance information */
    DE_NAS_5GS_MM_5GS_ADD_REQ_RES,           /* 9.11.3.81    5GS additional request result */
    DE_NAS_5GS_MM_NSSRG_INFO,                /* 9.11.3.82    NSSRG information */
    DE_NAS_5GS_MM_PLMNS_LIST_DISASTER_COND,  /* 9.11.3.83    List of PLMNs to be used in disaster condition */
    DE_NAS_5GS_MM_REG_WAIT_RANGE,            /* 9.11.3.84    Registration wait range */
    DE_NAS_5GS_MM_PLMN_ID,                   /* 9.11.3.85    PLMN identity */
    DE_NAS_5GS_MM_EXT_CAG_INFO_LIST,         /* 9.11.3.86    Extended CAG information list */
    DE_NAS_5GS_MM_NSAG_INFO,                 /* 9.11.3.87    NSAG information */
    DE_NAS_5GS_MM_PROSE_RELAY_TRANS_ID,      /* 9.11.3.88    ProSe relay transaction identity */
    DE_NAS_5GS_MM_RELAY_KEY_REQ_PARAMS,      /* 9.11.3.89    Relay key request parameters */
    DE_NAS_5GS_MM_RELAY_KEY_RESP_PARAMS,     /* 9.11.3.90    Relay key response parameters */
    DE_NAS_5GS_MM_PRIO_IND,                  /* 9.11.3.91    Priority indicator */
    DE_NAS_5GS_MM_SNPN_LIST,                 /* 9.11.3.92    SNPN list */
    DE_NAS_5GS_MM_N3IWF_ID,                  /* 9.11.3.93    N3IWF identifier */
    DE_NAS_5GS_MM_TNAN_INFO,                 /* 9.11.3.94    TNAN information */
    DE_NAS_5GS_MM_RAN_TIMING_SYNC,           /* 9.11.3.95    RAN timing synchronization */
    DE_NAS_5GS_MM_EXT_LADN_INFO,             /* 9.11.3.96    Extended LADN information */
    DE_NAS_5GS_MM_ALT_NSSAI,                 /* 9.11.3.97    Alternative NSSAI */
    DE_NAS_5GS_MM_TYPE_6_IE_CONT,            /* 9.11.3.98    Type 6 IE container */
    DE_NAS_5GS_MM_N3GPP_ACC_PATH_SWITCH_IND, /* 9.11.9.99    Non-3GPP access path switching indication */
    DE_NAS_5GS_MM_S_NSSAI_LOC_VALID_INFO,    /* 9.11.3.100   S-NSSAI location validity information */
    DE_NAS_5GS_MM_S_NSSAI_TIME_VALID_INFO,   /* 9.11.3.101   S-NSSAI time validity information */
    DE_NAS_5GS_MM_N3GPP_PATH_SWITCH_INFO,    /* 9.11.3.102   Non-3GPP path switching information */
    DE_NAS_5GS_MM_PARTIAL_NSSAI,             /* 9.11.3.103   Partial NSSAI */
    DE_NAS_5GS_MM_AU3N_IND,                  /* 9.11.3.104   AUN3 indication */
    DE_NAS_5GS_MM_FEAT_AUTH_IND,             /* 9.11.3.105   Feature authorization indication */
    DE_NAS_5GS_MM_PAYLOAD_CONT_INFO,         /* 9.11.3.106   Payload container information */
    DE_NAS_5GS_MM_AUN3_DEVICE_SEC_KEY,       /* 9.11.3.107   AUN3 device security key */
    DE_NAS_5GS_MM_ON_DEMAND_NSSAI,           /* 9.11.3.108   On-demand NSSAI */
    DE_NAS_5GS_MM_EXT_5GMM_CAUSE,            /* 9.11.3.109   Extended 5GMM cause */

    DE_NAS_5GS_MM_NONE        /* NONE */
}
nas_5gs_mm_elem_idx_t;
#endif

static const value_string nas_5gs_mm_elem_strings[] = {
    { DE_NAS_5GS_MM_5GMM_CAP,                   "5GMM capability" },                    /* 9.11.3.1     5GMM capability*/
    { DE_NAS_5GS_MM_5GMM_CAUSE,                 "5GMM cause" },                         /* 9.11.3.2     5GMM cause*/
    { DE_NAS_5GS_MM_5GS_DRX_PARAM,              "5GS DRX parameters" },                 /* 9.11.3.2A    5GS DRX parameters*/
    { DE_NAS_5GS_MM_5GS_IDENTITY_TYPE,          "5GS identity type" },                  /* 9.11.3.3     5GS identity type*/
    { DE_NAS_5GS_MM_5GS_MOBILE_ID,              "5GS mobile identity" },                /* 9.11.3.4     5GS mobile identity*/
    { DE_NAS_5GS_MM_5GS_NW_FEAT_SUP,            "5GS network feature support" },        /* 9.11.3.5     5GS network feature support*/
    { DE_NAS_5GS_MM_5GS_REG_RES,                "5GS registration result" },            /* 9.11.3.6     5GS registration result*/
    { DE_NAS_5GS_MM_5GS_REG_TYPE,               "5GS registration type" },              /* 9.11.3.7     5GS registration type*/
    { DE_NAS_5GS_MM_5GS_TA_ID,                  "5GS tracking area identity" },         /* 9.11.3.8     5GS tracking area identity */
    { DE_NAS_5GS_MM_5GS_TA_ID_LIST,             "5GS tracking area identity list" },    /* 9.11.3.9     5GS tracking area identity list*/
    { DE_NAS_5GS_MM_UPDATE_TYPE,                "5GS update type" },                    /* 9.11.3.9A    5GS update type */
    { DE_NAS_5GS_MM_ABBA,                       "ABBA" },                               /* 9.11.3.10    ABBA */
                                                                                        /* 9.11.3.11    Void */
    { DE_NAS_5GS_MM_ADD_5G_SEC_INF,             "Additional 5G security information" }, /* 9.11.3.12    Additional 5G security information */
    { DE_NAS_5GS_MM_ADD_INF_REQ,                "Additional information requested" },   /* 9.11.3.12A   Additional information requested */
    { DE_NAS_5GS_MM_ALLOW_PDU_SES_STS,          "Allowed PDU session status" },         /* 9.11.3.13    Allowed PDU session status*/
    { DE_NAS_5GS_MM_AUT_FAIL_PAR,               "Authentication failure parameter" },   /* 9.11.3.14    Authentication failure parameter*/
    { DE_NAS_5GS_MM_AUT_PAR_AUTN,               "Authentication parameter AUTN" },      /* 9.11.3.15    Authentication parameter AUTN*/
    { DE_NAS_5GS_MM_AUT_PAR_RAND,               "Authentication parameter RAND" },      /* 9.11.3.16    Authentication parameter RAND*/
    { DE_NAS_5GS_MM_AUT_RESP_PAR,               "Authentication response parameter" },  /* 9.11.3.17    Authentication response parameter*/
    { DE_NAS_5GS_MM_CONF_UPD_IND,               "Configuration update indication" },    /* 9.11.3.18    Configuration update indication*/
    { DE_NAS_5GS_MM_CAG_INFORMATION_LIST,       "CAG information list" },               /* 9.11.3.18A   CAG information list*/
    { DE_NAS_5GS_MM_CIOT_SMALL_DATA_CONT,       "CIoT small data container" },          /* 9.11.3.18B   CIoT small data container */
    { DE_NAS_5GS_MM_CIPHERING_KEY_DATA,         "Ciphering key data" },                 /* 9.11.3.18C   Ciphering key data*/
    { DE_NAS_5GS_MM_CTRL_PLANE_SERVICE_TYPE,    "Control plane service type" },         /* 9.11.3.18D   Control plane service type*/
    { DE_NAS_5GS_MM_DLGT_SAVING_TIME,           "Daylight saving time" },               /* 9.11.3.19    Daylight saving time*/
    { DE_NAS_5GS_MM_DE_REG_TYPE,                "De-registration type" },               /* 9.11.3.20    De-registration type*/
                                                                                        /* 9.11.3.21    Void */
                                                                                        /* 9.11.3.22    Void*/
    { DE_NAS_5GS_MM_EMRG_NR_LIST,               "Emergency number list" },              /* 9.11.3.23    Emergency number list*/
    { DE_NAS_5GS_MM_EPS_BEARER_CTX_STATUS,      "EPS bearer context status" },          /* 9.11.3.23A   EPS bearer context status */
    { DE_NAS_5GS_MM_EPS_NAS_MSG_CONT,           "EPS NAS message container" },          /* 9.11.3.24    EPS NAS message container*/
    { DE_NAS_5GS_MM_EPS_NAS_SEC_ALGO,           "EPS NAS security algorithms" },        /* 9.11.3.25    EPS NAS security algorithms*/
    { DE_NAS_5GS_MM_EXT_EMERG_NUM_LIST,         "Extended emergency number list" },     /* 9.11.3.26    Extended emergency number list */
    { DE_NAS_5GS_MM_EXTENDED_DRX_PARAMETERS,    "Extended DRX parameters" },            /* 9.11.3.26A   Extended DRX parameters */
                                                                                        /* 9.11.3.27    Void*/
    { DE_NAS_5GS_MM_IMEISV_REQ,                 "IMEISV request" },                     /* 9.11.3.28    IMEISV request*/
    { DE_NAS_5GS_MM_LADN_INDIC,                 "LADN indication" },                    /* 9.11.3.29    LADN indication*/
    { DE_NAS_5GS_MM_LADN_INF,                   "LADN information" },                   /* 9.11.3.30    LADN information*/
    { DE_NAS_5GS_MM_MICO_IND,                   "MICO indication" },                    /* 9.11.3.31    MICO indication*/
    { DE_NAS_5GS_MM_MA_PDU_SES_INF,             "MA PDU session information" },         /* 9.11.3.31A   MA PDU session information */
    { DE_NAS_5GS_MM_MAPPED_NSSAI,               "Mapped NSSAI" },                       /* 9.11.3.31B   Mapped NSSAI */
    { DE_NAS_5GS_MM_MOBILE_STATION_CLSMK_2,     "Mobile station classmark 2" },         /* 9.11.3.31C   Mobile station classmark 2 */
    { DE_NAS_5GS_MM_NAS_KEY_SET_ID,             "NAS key set identifier" },             /* 9.11.3.32    NAS key set identifier*/
    { DE_NAS_5GS_MM_NAS_KEY_SET_ID_H1,          "NAS key set identifier" },             /* 9.11.3.32    NAS key set identifier*/
    { DE_NAS_5GS_MM_NAS_MSG_CONT,               "NAS message container" },              /* 9.11.3.33    NAS message container*/
    { DE_NAS_5GS_MM_NAS_SEC_ALGO,               "NAS security algorithms" },            /* 9.11.3.34    NAS security algorithms*/
    { DE_NAS_5GS_MM_NW_NAME,                    "Network name" },                       /* 9.11.3.35    Network name*/
    { DE_NAS_5GS_MM_NW_SLICING_IND,             "Network slicing indication" },         /* 9.11.3.36    Network slicing indication */
    { DE_NAS_5GS_MM_NW_NON_3GPP_NW_PROV_POL,    "Non-3GPP NW provided policies" },      /* 9.11.3.36A   Non-3GPP NW provided policies */
    { DE_NAS_5GS_MM_NSSAI,                      "NSSAI" },                              /* 9.11.3.37    NSSAI*/
    { DE_NAS_5GS_MM_NSSAI_INC_MODE,             "NSSAI inclusion mode" },               /* 9.11.3.37A   NSSAI inclusion mode */
    { DE_NAS_5GS_MM_OP_DEF_ACC_CAT_DEF,         "Operator-defined access category definitions" },/* 9.11.3.38    Operator-defined access category definitions */

    { DE_NAS_5GS_MM_PLD_CONT,                   "Payload container" },                  /* 9.11.3.39    Payload container*/
    { DE_NAS_5GS_MM_PLD_CONT_TYPE,              "Payload container type" },             /* 9.11.3.40    Payload container type*/
    { DE_NAS_5GS_MM_PDU_SES_ID_2,               "PDU session identity 2" },             /* 9.11.3.42    PDU session identity 2*/
    { DE_NAS_5GS_MM_PDU_SES_REACT_RES,          "PDU session reactivation result" },    /* 9.11.3.43    PDU session reactivation result*/
    { DE_NAS_5GS_MM_PDU_SES_REACT_RES_ERR_C,    "PDU session reactivation result error cause" },    /* 9.11.3.43    PDU session reactivation result error cause*/
    { DE_NAS_5GS_MM_PDU_SES_STATUS,             "PDU session status" },                 /* 9.11.3.44    PDU session status*/
    { DE_NAS_5GS_MM_PLMN_LIST,                  "PLMN list" },                          /* 9.11.3.45    PLMN list*/
    { DE_NAS_5GS_MM_REJ_NSSAI,                  "Rejected NSSAI" },                     /* 9.11.3.46    Rejected NSSAI*/
    { DE_NAS_5GS_MM_REL_ASS_IND,                "Release assistance indication" },      /* 9.11.3.46A   Release assistance indication*/
    { DE_NAS_5GS_MM_REQ_TYPE,                   "Request type" },                       /* 9.11.3.47    Request type*/
    { DE_NAS_5GS_MM_S1_UE_NW_CAP,               "S1 UE network capability" },           /* 9.11.3.48    S1 UE network capability*/
    { DE_NAS_5GS_MM_S1_UE_SEC_CAP,              "S1 UE security capability" },          /* 9.11.3.48A   S1 UE security capability*/
    { DE_NAS_5GS_MM_SAL,                        "Service area list" },                  /* 9.11.3.49    Service area list*/
    { DE_NAS_5GS_MM_SERV_TYPE,                  "Service type" },                       /* 9.11.3.50    Service type*/
    { DE_NAS_5GS_MM_SMS_IND,                    "SMS indication" },                     /* 9.11.3.50A   SMS indication */
    { DE_NAS_5GS_MM_SOR_TRANSP_CONT,            "SOR transparent container" },          /* 9.11.3.51    SOR transparent container */
    { DE_NAS_5GS_MM_SUPPORTED_CODEC_LIST,       "Supported codec list" },               /* 9.11.3.51A   Supported codec list */
    { DE_NAS_5GS_MM_TZ,                         "Time zone" },                          /* 9.11.3.52    Time zone*/
    { DE_NAS_5GS_MM_TZ_AND_T,                   "Time zone and time" },                 /* 9.11.3.53    Time zone and time*/
    { DE_NAS_5GS_MM_UE_PAR_UPD_TRANSP_CONT,     "UE parameters update transparent container" }, /* 9.11.3.53A   UE parameters update transparent container */
    { DE_NAS_5GS_MM_UE_SEC_CAP,                 "UE security capability" },             /* 9.11.3.54    UE security capability*/
    { DE_NAS_5GS_MM_UE_USAGE_SET,               "UE's usage setting" },                 /* 9.11.3.55    UE's usage setting*/
    { DE_NAS_5GS_MM_UE_STATUS,                  "UE status" },                          /* 9.11.3.56    UE status*/
    { DE_NAS_5GS_MM_UL_DATA_STATUS,             "Uplink data status" },                 /* 9.11.3.57    Uplink data status*/
    { DE_NAS_5GS_MM_UE_RADIO_CAP_ID,            "UE radio capability ID" },             /* 9.11.3.68    UE radio capability ID*/
    { DE_NAS_5GS_MM_UE_RADIO_CAP_ID_DEL_IND,    "UE radio capability ID deletion indication" },/* 9.11.3.69    UE radio capability ID deletion indication*/
    { DE_NAS_5GS_MM_TRUNCATED_5G_S_TMSI_CONF,   "Truncated 5G-S-TMSI configuration" },  /* 9.11.3.70    Truncated 5G-S-TMSI configuration*/
    { DE_NAS_5GS_MM_WUS_ASSISTANCE_INF,         "WUS assistance information" },         /* 9.11.3.71    WUS assistance information*/
    { DE_NAS_5GS_MM_N5GC_INDICATION,            "N5GC indication" },                    /* 9.11.3.72    N5GC indication*/
    { DE_NAS_5GS_MM_NB_N1_MODE_DRX_PARS,        "NB-N1 mode DRX parameters" },          /* 9.11.3.73    NB-N1 mode DRX parameters*/
    { DE_NAS_5GS_MM_ADDITIONAL_CONF_IND,        "Additional configuration indication" },/* 9.11.3.74    Additional configuration indication*/
    { DE_NAS_5GS_MM_EXTENDED_REJECTED_NSSAI,    "Extended rejected NSSAI" },            /* 9.11.3.75    Extended rejected NSSAI*/
    { DE_NAS_5GS_MM_UE_REQUEST_TYPE,            "UE request type" },                    /* 9.11.3.76    UE request type */
    { DE_NAS_5GS_MM_PAGING_RESTRICTION,         "Paging restriction" },                 /* 9.11.3.77    Paging restriction */
    { DE_NAS_5GS_MM_NID,                        "NID" },                                /* 9.11.3.79    NID */
    { DE_NAS_5GS_MM_PEIPS_ASSIST_INFO,          "PEIPS assistance information" },       /* 9.11.3.80    PEIPS assistance information */
    { DE_NAS_5GS_MM_5GS_ADD_REQ_RES,            "5GS additional request result" },      /* 9.11.3.81    5GS additional request result */
    { DE_NAS_5GS_MM_NSSRG_INFO,                 "NSSRG information" },                  /* 9.11.3.82    NSSRG information */
    { DE_NAS_5GS_MM_PLMNS_LIST_DISASTER_COND,   "List of PLMNs to be used in disaster condition" },/* 9.11.3.83    List of PLMNs to be used in disaster condition */
    { DE_NAS_5GS_MM_REG_WAIT_RANGE,             "Registration wait range" },            /* 9.11.3.84    Registration wait range */
    { DE_NAS_5GS_MM_PLMN_ID,                    "PLMN identity" },                      /* 9.11.3.85    PLMN identity */
    { DE_NAS_5GS_MM_EXT_CAG_INFO_LIST,          "Extended CAG information list" },      /* 9.11.3.86    Extended CAG information list */
    { DE_NAS_5GS_MM_NSAG_INFO,                  "NSAG information" },                   /* 9.11.3.87    NSAG information */
    { DE_NAS_5GS_MM_PROSE_RELAY_TRANS_ID,       "ProSe relay transaction identity" },   /* 9.11.3.88    ProSe relay transaction identity */
    { DE_NAS_5GS_MM_RELAY_KEY_REQ_PARAMS,       "Relay key request parameters" },       /* 9.11.3.89    Relay key request parameters */
    { DE_NAS_5GS_MM_RELAY_KEY_RESP_PARAMS,      "Relay key response parameters" },      /* 9.11.3.90    Relay key response parameters */
    { DE_NAS_5GS_MM_PRIO_IND,                   "Priority indicator" },                 /* 9.11.3.91    Priority indicator */
    { DE_NAS_5GS_MM_SNPN_LIST,                  "SNPN list" },                          /* 9.11.3.92    SNPN list */
    { DE_NAS_5GS_MM_N3IWF_ID,                   "N3IWF identifier" },                   /* 9.11.3.93    N3IWF identifier */
    { DE_NAS_5GS_MM_TNAN_INFO,                  "TNAN information" },                   /* 9.11.3.94    TNAN information */
    { DE_NAS_5GS_MM_RAN_TIMING_SYNC,            "RAN timing synchronization" },         /* 9.11.3.95    RAN timing synchronization */
    { DE_NAS_5GS_MM_EXT_LADN_INFO,              "Extended LADN information" },          /* 9.11.3.96    Extended LADN information */
    { DE_NAS_5GS_MM_ALT_NSSAI,                  "Alternative NSSAI" },                  /* 9.11.3.97    Alternative NSSAI */
    { DE_NAS_5GS_MM_TYPE_6_IE_CONT,             "Type 6 IE container" },                /* 9.11.3.98    Type 6 IE container */
    { DE_NAS_5GS_MM_N3GPP_ACC_PATH_SWITCH_IND,  "Non-3GPP access path switching indication" },/* 9.11.9.99    Non-3GPP access path switching indication */
    { DE_NAS_5GS_MM_S_NSSAI_LOC_VALID_INFO,     "S-NSSAI location validity information" },/* 9.11.3.100   S-NSSAI location validity information */
    { DE_NAS_5GS_MM_S_NSSAI_TIME_VALID_INFO,    "S-NSSAI time validity information" },  /* 9.11.3.101   S-NSSAI time validity information */
    { DE_NAS_5GS_MM_N3GPP_PATH_SWITCH_INFO,     "Non-3GPP path switching information" },/* 9.11.3.102   Non-3GPP path switching information */
    { DE_NAS_5GS_MM_PARTIAL_NSSAI,              "Partial NSSAI" },                      /* 9.11.3.103   Partial NSSAI */
    { DE_NAS_5GS_MM_AU3N_IND,                   "AUN3 indication" },                    /* 9.11.3.104   AUN3 indication */
    { DE_NAS_5GS_MM_FEAT_AUTH_IND,              "Feature authorization indication" },   /* 9.11.3.105   Feature authorization indication */
    { DE_NAS_5GS_MM_PAYLOAD_CONT_INFO,          "Payload container information" },      /* 9.11.3.106   Payload container information */
    { DE_NAS_5GS_MM_AUN3_DEVICE_SEC_KEY,        "AUN3 device security key" },           /* 9.11.3.107   AUN3 device security key */
    { DE_NAS_5GS_MM_ON_DEMAND_NSSAI,            "On-demand NSSAI" },                    /* 9.11.3.108   On-demand NSSAI */
    { DE_NAS_5GS_MM_EXT_5GMM_CAUSE,             "Extended 5GMM cause" },                /* 9.11.3.109   Extended 5GMM cause */

    { 0, NULL }
};
value_string_ext nas_5gs_mm_elem_strings_ext = VALUE_STRING_EXT_INIT(nas_5gs_mm_elem_strings);

#define NUM_NAS_5GS_MM_ELEM array_length(nas_5gs_mm_elem_strings)
int ett_nas_5gs_mm_elem[NUM_NAS_5GS_MM_ELEM];

uint16_t(*nas_5gs_mm_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string, int string_len) = {
        /*  9.11.3    5GS mobility management (5GMM) information elements */
        de_nas_5gs_mm_5gmm_cap,                  /* 9.11.3.1     5GMM capability*/
        de_nas_5gs_mm_5gmm_cause,                /* 9.11.3.2     5GMM cause*/
        de_nas_5gs_mm_5gs_drx_param,             /* 9.11.3.2A    5GS DRX parameters*/
        de_nas_5gs_mm_5gs_identity_type,         /* 9.11.3.3     5GS identity type*/
        de_nas_5gs_mm_5gs_mobile_id,             /* 9.11.3.4     5GS mobile identity*/
        de_nas_5gs_mm_5gs_nw_feat_sup,           /* 9.11.3.5     5GS network feature support*/
        de_nas_5gs_mm_5gs_reg_res,               /* 9.11.3.6     5GS registration result*/
        de_nas_5gs_mm_5gs_reg_type,              /* 9.11.3.7     5GS registration type*/
        de_nas_5gs_mm_5gs_ta_id,                 /* 9.11.3.8     5GS tracking area identity */
        de_nas_5gs_mm_5gs_ta_id_list,            /* 9.11.3.9     5GS tracking area identity list */
        de_nas_5gs_mm_update_type,               /* 9.11.3.9A    5GS update type */
        de_nas_5gs_mm_abba,                      /* 9.11.3.10    ABBA */
                                                 /* 9.11.3.11    Void */
        de_nas_5gs_mm_add_5g_sec_inf,            /* 9.11.3.12    Additional 5G security information */
        de_nas_5gs_mm_add_inf_req,               /* 9.11.3.12A   Additional information requested */
        de_nas_5gs_mm_allow_pdu_ses_sts,         /* 9.11.3.13    Allowed PDU session status*/
        NULL,                                    /* 9.11.3.14    Authentication failure parameter */
        NULL,                                    /* 9.11.3.15    Authentication parameter AUTN*/
        NULL,                                    /* 9.11.3.16    Authentication parameter RAND*/
        NULL,                                    /* 9.11.3.17    Authentication response parameter */
        de_nas_5gs_mm_conf_upd_ind,              /* 9.11.3.18    Configuration update indication*/
        de_nas_5gs_mm_cag_information_list,      /* 9.11.3.18A   CAG information list*/
        de_nas_5gs_mm_ciot_small_data_cont,      /* 9.11.3.18B   CIoT small data container */
        de_nas_5gs_mm_ciphering_key_data,        /* 9.11.3.18C   Ciphering key data*/
        de_nas_5gs_mm_ctrl_plane_service_type,   /* 9.11.3.18D   Control plane service type*/

        NULL,                                    /* 9.11.3.19    Daylight saving time*/
        de_nas_5gs_mm_de_reg_type,               /* 9.11.3.20    De-registration type*/
                                                 /* 9.11.3.21    Void */
                                                 /* 9.11.3.22    Void*/
        NULL,                                    /* 9.11.3.23    Emergency number list*/
        NULL,                                    /* 9.11.3.23A   EPS bearer context status */
        de_nas_5gs_mm_eps_nas_msg_cont,          /* 9.11.3.24    EPS NAS message container*/
        NULL,                                    /* 9.11.3.25    EPS NAS security algorithms*/
        NULL,                                    /* 9.11.3.26    Extended emergency number list*/
        NULL,                                    /* 9.11.3.26A   Extended DRX parameters */
                                                 /* 9.11.3.27    Void*/
        NULL,                                    /* 9.11.3.28    IMEISV request*/
        de_nas_5gs_mm_ladn_indic,                /* 9.11.3.29    LADN indication*/
        de_nas_5gs_mm_ladn_inf,                  /* 9.11.3.30    LADN information*/
        de_nas_5gs_mm_mico_ind,                  /* 9.11.3.31    MICO indication*/
        de_nas_5gs_mm_ma_pdu_ses_inf,            /* 9.11.3.31A   MA PDU session information */
        de_nas_5gs_mm_mapped_nssai,              /* 9.11.3.31B   Mapped NSSAI */
        NULL,                                    /* 9.11.3.31C   Mobile station classmark 2 */

        de_nas_5gs_mm_nas_key_set_id,            /* 9.11.3.32    NAS key set identifier*/
        de_nas_5gs_mm_nas_key_set_id_h1,         /* 9.11.3.32    NAS key set identifier*/
        de_nas_5gs_mm_nas_msg_cont,              /* 9.11.3.33    NAS message container*/
        de_nas_5gs_mm_nas_sec_algo,              /* 9.11.3.34    NAS security algorithms*/
        NULL,                                    /* 9.11.3.35    Network name*/
        de_nas_5gs_mm_nw_slicing_ind,            /* 9.11.3.36    Network slicing indication */
        NULL,                                    /* 9.11.3.36A   Non-3GPP NW provided policies */
        de_nas_5gs_mm_nssai,                     /* 9.11.3.37    NSSAI*/
        de_nas_5gs_mm_nssai_inc_mode,            /* 9.11.3.37A   NSSAI inclusion mode */
        de_nas_5gs_mm_op_def_acc_cat_def,        /* 9.11.3.38    Operator-defined access category definitions */
        de_nas_5gs_mm_pld_cont,                  /* 9.11.3.39    Payload container*/
        de_nas_5gs_mm_pld_cont_type,             /* 9.11.3.40    Payload container type*/
        de_nas_5gs_mm_pdu_ses_id_2,              /* 9.11.3.41    PDU session identity 2*/
        de_nas_5gs_mm_pdu_ses_react_res,         /* 9.11.3.42    PDU session reactivation result*/
        de_nas_5gs_mm_pdu_ses_react_res_err_c,   /* 9.11.3.43    PDU session reactivation result error cause */
        de_nas_5gs_mm_pdu_ses_status,            /* 9.11.3.44    PDU session status*/
        NULL,                                    /* 9.11.3.45    PLMN list*/
        de_nas_5gs_mm_rej_nssai,                 /* 9.11.3.46    Rejected NSSAI*/
        NULL,                                    /* 9.11.3.46A   Release assistance indication*/
        de_nas_5gs_mm_req_type,                  /* 9.11.3.47    Request type*/
        NULL,                                    /* 9.11.3.48    S1 UE network capability*/
        NULL,                                    /* 9.11.3.48A   S1 UE security capability*/
        de_nas_5gs_mm_sal,                       /* 9.11.3.49    Service area list*/
        de_nas_5gs_mm_serv_type,                 /* 9.11.3.50    Service type*/
        de_nas_5gs_mm_sms_ind,                   /* 9.11.3.50A   SMS indication */
        de_nas_5gs_mm_sor_transp_cont,           /* 9.11.3.51    SOR transparent container */
        NULL,                                    /* 9.11.3.51A   Supported codec list */
        NULL,                                    /* 9.11.3.52    Time zone*/
        NULL,                                    /* 9.11.3.53    Time zone and time*/
        de_nas_5gs_mm_ue_par_upd_transp_cont,    /* 9.11.3.53A   UE parameters update transparent container */
        de_nas_5gs_mm_ue_sec_cap,                /* 9.11.3.54    UE security capability*/
        de_nas_5gs_mm_ue_usage_set,              /* 9.11.3.55    UE's usage setting*/
        de_nas_5gs_mm_ue_status,                 /* 9.11.3.56    UE status*/
        de_nas_5gs_mm_ul_data_status,            /* 9.11.3.57    Uplink data status*/
        de_nas_5gs_mm_ue_radio_cap_id,           /* 9.11.3.68    UE radio capability ID*/
        de_nas_5gs_mm_ue_radio_cap_id_del_ind,   /* 9.11.3.69    UE radio capability ID deletion indication*/
        de_nas_5gs_mm_truncated_5g_s_tmsi_conf,  /* 9.11.3.70    Truncated 5G-S-TMSI configuration*/
        NULL,                                    /* 9.11.3.71    WUS assistance information*/
        de_nas_5gs_mm_n5gc_indication,           /* 9.11.3.72    N5GC indication*/
        de_nas_5gs_mm_nb_n1_mode_drx_pars,       /* 9.11.3.73    NB-N1 mode DRX parameters*/
        de_nas_5gs_mm_additional_conf_ind,       /* 9.11.3.74    Additional configuration indication*/
        de_nas_5gs_mm_extended_rejected_nssai,   /* 9.11.3.75    Extended rejected NSSAI*/
        NULL,                                    /* 9.11.3.76    UE request type */
        de_nas_5gs_mm_paging_restriction,        /* 9.11.3.77    Paging restriction */
        de_nas_5gs_mm_nid,                       /* 9.11.3.79    NID */
        de_nas_5gs_mm_peips_assist_info,         /* 9.11.3.80    PEIPS assistance information */
        de_nas_5gs_mm_5gs_add_req_res,           /* 9.11.3.81    5GS additional request result */
        de_nas_5gs_mm_nssrg_info,                /* 9.11.3.82    NSSRG information */
        de_nas_5gs_mm_plmns_list_disaster_cond,  /* 9.11.3.83    List of PLMNs to be used in disaster condition */
        de_nas_5gs_mm_reg_wait_range,            /* 9.11.3.84    Registration wait range */
        de_nas_5gs_mm_plmn_id,                   /* 9.11.3.85    PLMN identity */
        de_nas_5gs_mm_ext_cag_info_list,         /* 9.11.3.86    Extended CAG information list */
        de_nas_5gs_mm_nsag_info,                 /* 9.11.3.87    NSAG information */
        de_nas_5gs_mm_prose_relay_trans_id,      /* 9.11.3.88    ProSe relay transaction identity */
        de_nas_5gs_mm_relay_key_req_params,      /* 9.11.3.89    Relay key request parameters */
        de_nas_5gs_mm_relay_key_resp_params,     /* 9.11.3.90    Relay key response parameters */
        de_nas_5gs_mm_prio_ind,                  /* 9.11.3.91    Priority indicator */
        de_nas_5gs_mm_snpn_list,                 /* 9.11.3.92    SNPN list */
        de_nas_5gs_mm_n3iwf_id,                  /* 9.11.3.93    N3IWF identifier */
        de_nas_5gs_mm_tnan_info,                 /* 9.11.3.94    TNAN information */
        de_nas_5gs_mm_ran_timing_sync,           /* 9.11.3.95    RAN timing synchronization */
        de_nas_5gs_mm_ext_ladn_info,             /* 9.11.3.96    Extended LADN information */
        de_nas_5gs_mm_alt_nssai,                 /* 9.11.3.97    Alternative NSSAI */
        de_nas_5gs_mm_type_6_ie_cont,            /* 9.11.3.98    Type 6 IE container */
        de_nas_5gs_mm_n3gpp_acc_path_switch_ind, /* 9.11.9.99    Non-3GPP access path switching indication */
        de_nas_5gs_mm_s_nssai_loc_valid_info,    /* 9.11.3.100   S-NSSAI location validity information */
        de_nas_5gs_mm_s_nssai_time_valid_info,   /* 9.11.3.101   S-NSSAI time validity information */
        de_nas_5gs_mm_n3gpp_path_switch_info,    /* 9.11.3.102   Non-3GPP path switching information */
        de_nas_5gs_mm_partial_nssai,             /* 9.11.3.103   Partial NSSAI */
        de_nas_5gs_mm_au3n_ind,                  /* 9.11.3.104   AUN3 indication */
        de_nas_5gs_mm_feat_auth_ind,             /* 9.11.3.105   Feature authorization indication */
        de_nas_5gs_mm_payload_cont_info,         /* 9.11.3.106   Payload container information */
        de_nas_5gs_mm_aun3_device_sec_key,       /* 9.11.3.107   AUN3 device security key */
        de_nas_5gs_mm_on_demand_nssai,           /* 9.11.3.108   On-demand NSSAI */
        de_nas_5gs_mm_ext_5gmm_cause,            /* 9.11.3.109   Extended 5GMM cause */

        NULL,   /* NONE */
};


/*
 * 9.11.4    5GS session management (5GSM) information elements
 */

typedef enum
{

    DE_NAS_5GS_SM_5GSM_CAP,                 /* 9.11.4.1    5GSM capability */
    DE_NAS_5GS_SM_5GSM_CAUSE,               /* 9.11.4.2    5GSM cause */
    DE_NAS_5GS_SM_ALWAYS_ON_PDU_SES_IND,    /* 9.11.4.3    Always-on PDU session indication */
    DE_NAS_5GS_SM_ALWAYS_ON_PDU_SES_REQ,    /* 9.11.4.4    Always-on PDU session requested */
    DE_NAS_5GS_SM_5GSM_ALLOWED_SSC_MODE,    /* 9.11.4.5    Allowed SSC mode */
    DE_NAS_5GS_SM_EXT_PROT_CONF_OPT,        /* 9.11.4.6    Extended protocol configuration options */
    DE_NAS_5GS_SM_INT_PROT_MAX_DATA_RTE,    /* 9.11.4.7    Integrity protection maximum data rate */
    DE_NAS_5GS_SM_MAPPED_EPS_B_CONT,        /* 9.11.4.8    Mapped EPS bearer contexts */
    DE_NAS_5GS_SM_MAX_NUM_SUP_PKT_FLT,      /* 9.11.4.9    Maximum number of supported packet filters */
    DE_NAS_5GS_SM_PDU_ADDRESS,              /* 9.11.4.10   PDU address */
    DE_NAS_5GS_SM_PDU_SESSION_TYPE,         /* 9.11.4.11   PDU session type */
    DE_NAS_5GS_SM_QOS_FLOW_DES,             /* 9.11.4.12   QoS flow descriptions */
    DE_NAS_5GS_SM_QOS_RULES,                /* 9.11.4.13   QoS rules */
    DE_NAS_5GS_SM_SESSION_AMBR,             /* 9.11.4.14   Session-AMBR */
    DE_NAS_5GS_SM_PDU_DN_REQ_CONT,          /* 9.11.4.15   SM PDU DN request container */
    DE_NAS_5GS_SM_SSC_MODE,                 /* 9.11.4.16   SSC mode */
    DE_NAS_5GS_SM_RE_ATTEMPT_IND,           /* 9.11.4.17   Re-attempt indicator */
    DE_NAS_5GS_SM_5GSM_NW_FEATURE_SUP,      /* 9.11.4.18   5GSM network feature support */
                                            /* 9.11.4.19   Void */
    DE_NAS_5GS_SM_SERVING_PLMN_RTE_CTL,     /* 9.11.4.20   Serving PLMN rate control */
    DE_NAS_5GS_SM_5GSM_CONG_RE_ATTEMPT_IND, /* 9.11.4.21   5GSM congestion re-attempt indicator */
    DE_NAS_5GS_SM_ATSSS_CONT,               /* 9.11.4.22   ATSSS container */
    DE_NAS_5GS_SM_CTL_PLANE_ONLY_IND,       /* 9.11.4.23   Control plane only indication */
    DE_NAS_5GS_SM_IP_HDR_COMP_CONF,         /* 9.11.4.24   IP header compression configuration */
    DE_NAS_5GS_SM_DS_TT_ETH_PORT_MAC_ADDR,  /* 9.11.4.25   DS-TT Ethernet port MAC address */
    DE_NAS_5GS_SM_UE_DS_TT_RESIDENCE_T,     /* 9.11.4.26   UE-DS-TT residence time */
    DE_NAS_5GS_SM_PORT_MGNT_INF_CONT,       /* 9.11.4.27   Port management information container */
    DE_NAS_5GS_SM_ETH_HDR_COMP_CONF,        /* 9.11.4.28   Ethernet header compression configuration */
    DE_NAS_5GS_SM_REMOTE_UE_CTX_LIST,       /* 9.11.4.29   Remote UE context list */
    DE_NAS_5GS_SM_REQ_MBS_CONT,             /* 9.11.4.30   Requested MBS container */
    DE_NAS_5GS_SM_REC_MBS_CONT,             /* 9.11.4.31   Received MBS container */
    DE_NAS_5GS_SM_PDU_SESSION_PAIR_ID,      /* 9.11.4.32   PDU session pair ID */
    DE_NAS_5GS_SM_RSN,                      /* 9.11.4.33   RSN */
    DE_NAS_5GS_SM_N3QAI,                    /* 9.11.4.36   N3QAI */
    DE_NAS_5GS_SM_N3GPP_DELAY_BUDGET,       /* 9.11.4.37   Non-3GPP delay budget */
    DE_NAS_5GS_SM_URSP_RULE_ENFORCE_REPORTS,/* 9.11.4.38   URSP rule enforcement reports */
    DE_NAS_5GS_SM_PROT_DESC,                /* 9.11.4.39   Protocol description */

    DE_NAS_5GS_SM_NONE        /* NONE */
}
nas_5gs_sm_elem_idx_t;


static const value_string nas_5gs_sm_elem_strings[] = {
    { DE_NAS_5GS_SM_5GSM_CAP, "5GSM capability" },                                         /* 9.11.4.1    5GSM capability */
    { DE_NAS_5GS_SM_5GSM_CAUSE, "5GSM cause" },                                            /* 9.11.4.2    5GSM cause */
    { DE_NAS_5GS_SM_ALWAYS_ON_PDU_SES_IND, "Always-on PDU session indication" },           /* 9.11.4.3    Always-on PDU session indication */
    { DE_NAS_5GS_SM_ALWAYS_ON_PDU_SES_REQ, "Always-on PDU session requested" },            /* 9.11.4.4    Always-on PDU session requested */
    { DE_NAS_5GS_SM_5GSM_ALLOWED_SSC_MODE, "Allowed SSC mode" },                           /* 9.11.4.5    Allowed SSC mode */
    { DE_NAS_5GS_SM_EXT_PROT_CONF_OPT, "Extended protocol configuration options" },        /* 9.11.4.6    Extended protocol configuration options */
    { DE_NAS_5GS_SM_INT_PROT_MAX_DATA_RTE, "Integrity protection maximum data rate" },     /* 9.11.4.7    Integrity protection maximum data rate */
    { DE_NAS_5GS_SM_MAPPED_EPS_B_CONT, "Mapped EPS bearer contexts" },                     /* 9.11.4.8    Mapped EPS bearer contexts */
    { DE_NAS_5GS_SM_MAX_NUM_SUP_PKT_FLT, "Maximum number of supported packet filters" },   /* 9.11.4.9    Maximum number of supported packet filters */
    { DE_NAS_5GS_SM_PDU_ADDRESS, "PDU address" },                                          /* 9.11.4.10   PDU address */
    { DE_NAS_5GS_SM_PDU_SESSION_TYPE, "PDU session type" },                                /* 9.11.4.11   PDU session type */
    { DE_NAS_5GS_SM_QOS_FLOW_DES, "QoS flow descriptions" },                               /* 9.11.4.12   QoS flow descriptions */
    { DE_NAS_5GS_SM_QOS_RULES, "QoS rules" },                                              /* 9.11.4.13   QoS rules */
    { DE_NAS_5GS_SM_SESSION_AMBR, "Session-AMBR" },                                        /* 9.11.4.14   Session-AMBR */
    { DE_NAS_5GS_SM_PDU_DN_REQ_CONT, "SM PDU DN request container" },                      /* 9.11.4.15   SM PDU DN request container */
    { DE_NAS_5GS_SM_SSC_MODE, "SSC mode" },                                                /* 9.11.4.16   SSC mode */
    { DE_NAS_5GS_SM_RE_ATTEMPT_IND, "Re-attempt indicator" },                              /* 9.11.4.17   Re-attempt indicator */
    { DE_NAS_5GS_SM_5GSM_NW_FEATURE_SUP, "5GSM network feature support" },                 /* 9.11.4.18   5GSM network feature support */
                                                                                           /* 9.11.4.19   Void */
    { DE_NAS_5GS_SM_SERVING_PLMN_RTE_CTL, "Serving PLMN rate control" },                   /* 9.11.4.20   Serving PLMN rate control */
    { DE_NAS_5GS_SM_5GSM_CONG_RE_ATTEMPT_IND, "5GSM congestion re-attempt indicator" },    /* 9.11.4.21   5GSM congestion re-attempt indicator */
    { DE_NAS_5GS_SM_ATSSS_CONT, "ATSSS container" },                                       /* 9.11.4.22   ATSSS container */
    { DE_NAS_5GS_SM_CTL_PLANE_ONLY_IND, "Control plane only indication" },                 /* 9.11.4.23   Control plane only indication */
    { DE_NAS_5GS_SM_IP_HDR_COMP_CONF, "IP header compression configuration" },             /* 9.11.4.24   IP header compression configuration */
    { DE_NAS_5GS_SM_DS_TT_ETH_PORT_MAC_ADDR, " DS-TT Ethernet port MAC address" },         /* 9.11.4.25   DS-TT Ethernet port MAC address */
    { DE_NAS_5GS_SM_UE_DS_TT_RESIDENCE_T, "UE-DS-TT residence time" },                     /* 9.11.4.26   UE-DS-TT residence time */
    { DE_NAS_5GS_SM_PORT_MGNT_INF_CONT, "Port management information container" },         /* 9.11.4.27   Port management information container */
    { DE_NAS_5GS_SM_ETH_HDR_COMP_CONF, "Ethernet header compression configuration" },      /* 9.11.4.28   Ethernet header compression configuration */
    { DE_NAS_5GS_SM_REMOTE_UE_CTX_LIST, "Remote UE context list" },                        /* 9.11.4.29   Remote UE context list */
    { DE_NAS_5GS_SM_REQ_MBS_CONT, "Requested MBS container" },                             /* 9.11.4.30   Requested MBS container */
    { DE_NAS_5GS_SM_REC_MBS_CONT, "Received MBS container" },                              /* 9.11.4.30   Received MBS container */
    { DE_NAS_5GS_SM_PDU_SESSION_PAIR_ID, "PDU session pair ID" },                          /* 9.11.4.32   PDU session pair ID */
    { DE_NAS_5GS_SM_RSN, "RSN" },                                                          /* 9.11.4.33   RSN */
    { DE_NAS_5GS_SM_N3QAI, "N3QAI" },                                                      /* 9.11.4.36   N3QAI */
    { DE_NAS_5GS_SM_N3GPP_DELAY_BUDGET, "Non-3GPP delay budget" },                         /* 9.11.4.37   Non-3GPP delay budget */
    { DE_NAS_5GS_SM_URSP_RULE_ENFORCE_REPORTS, "URSP rule enforcement reports" },          /* 9.11.4.38   URSP rule enforcement reports */
    { DE_NAS_5GS_SM_PROT_DESC, "Protocol description" },                                   /* 9.11.4.39   Protocol description */

    { 0, NULL }
};
value_string_ext nas_5gs_sm_elem_strings_ext = VALUE_STRING_EXT_INIT(nas_5gs_sm_elem_strings);

#define NUM_NAS_5GS_SM_ELEM array_length(nas_5gs_sm_elem_strings)
int ett_nas_5gs_sm_elem[NUM_NAS_5GS_SM_ELEM];

uint16_t(*nas_5gs_sm_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
    uint32_t offset, unsigned len,
    char *add_string, int string_len) = {
        /*  5GS session management (5GSM) information elements */
        de_nas_5gs_sm_5gsm_cap,                 /* 9.11.4.1    5GSM capability */
        de_nas_5gs_sm_5gsm_cause,               /* 9.11.4.2    5GSM cause */
        de_nas_5gs_sm_always_on_pdu_ses_ind,    /* 9.11.4.3    Always-on PDU session indication */
        de_nas_5gs_sm_always_on_pdu_ses_req,    /* 9.11.4.4    Always-on PDU session requested */
        de_nas_5gs_sm_5gsm_allowed_ssc_mode,    /* 9.11.4.5    Allowed SSC mode */
        NULL,                                   /* 9.11.4.6    Extended protocol configuration options */
        de_nas_5gs_sm_int_prot_max_data_rte,    /* 9.11.4.7    Integrity protection maximum data rate */
        de_nas_5gs_sm_mapped_eps_b_cont,        /* 9.11.4.8    Mapped EPS bearer contexts */
        de_nas_5gs_sm_max_num_sup_pkt_flt,      /* 9.11.4.9    Maximum number of supported packet filters */
        de_nas_5gs_sm_pdu_address,              /* 9.11.4.10   PDU address */
        de_nas_5gs_sm_pdu_session_type,         /* 9.11.4.11   PDU session type */
        de_nas_5gs_sm_qos_flow_des,             /* 9.11.4.12   QoS flow descriptions */
        de_nas_5gs_sm_qos_rules,                /* 9.11.4.13    QoS rules */
        de_nas_5gs_sm_session_ambr,             /* 9.11.4.14   Session-AMBR */
        de_nas_5gs_sm_pdu_dn_req_cont,          /* 9.11.4.15   SM PDU DN request container */
        de_nas_5gs_sm_ssc_mode,                 /* 9.11.4.16   SSC mode */
        de_nas_5gs_sm_re_attempt_ind,           /* 9.11.4.17   Re-attempt indicator */
        de_nas_5gs_sm_5gsm_nw_feature_sup,      /* 9.11.4.18   5GSM network feature support */
                                                /* 9.11.4.19   Void */
        NULL,                                   /* 9.11.4.20   Serving PLMN rate control */
        de_nas_5gs_sm_5gsm_cong_re_attempt_ind, /* 9.11.4.21   5GSM congestion re-attempt indicator */
        de_nas_5gs_sm_atsss_cont,               /* 9.11.4.22   ATSSS container */
        de_nas_5gs_sm_ctl_plane_only_ind,       /* 9.11.4.23   Control plane only indication */
        de_nas_5gs_sm_ip_hdr_comp_conf,         /* 9.11.4.24   IP header compression configuration */
        de_nas_5gs_sm_ds_tt_eth_port_mac_addr,  /* 9.11.4.25   DS-TT Ethernet port MAC address */
        de_nas_5gs_sm_ue_ds_tt_residence_t,     /* 9.11.4.26   UE-DS-TT residence time */
        de_nas_5gs_sm_port_mgnt_inf_cont,       /* 9.11.4.27   Port management information container */
        de_nas_5gs_sm_eth_hdr_comp_conf,        /* 9.11.4.28   Ethernet header compression configuration */
        de_nas_5gs_sm_remote_ue_ctx_list,       /* 9.11.4.29   Remote UE context list */
        de_nas_5gs_sm_req_mbs_cont,             /* 9.11.4.30   Requested MBS container */
        de_nas_5gs_sm_rec_mbs_cont,             /* 9.11.4.31   Received MBS container */
        de_nas_5gs_sm_pdu_session_pair_id,      /* 9.11.4.32   PDU session pair ID */
        de_nas_5gs_sm_rsn,                      /* 9.11.4.33   RSN */
        de_nas_5gs_sm_n3qai,                    /* 9.11.4.36   N3QAI */
        de_nas_5gs_sm_n3gpp_delay_budget,       /* 9.11.4.37   Non-3GPP delay budget */
        de_nas_5gs_sm_ursp_rule_enforce_reports,/* 9.11.4.38   URSP rule enforcement reports */
        de_nas_5gs_sm_prot_desc,                /* 9.11.4.39   Protocol description */

        NULL,   /* NONE */
};

/* Gap fill msg decoding*/
static void
nas_5gs_exp_not_dissected_yet(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{

    proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_msg_not_dis, tvb, offset, len);
}

/*
 * 8.2.1    Authentication request
 */
static void
nas_5gs_mm_authentication_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*ngKSI     NAS key set identifier 9.11.3.29    M    V    1/2  */
    /* Spare half octet    Spare half octet     9.5    M    V    1/2 H1 */
    proto_tree_add_item(tree, hf_nas_5gs_spare_half_octet, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_KEY_SET_ID, " - ngKSI", ei_nas_5gs_missing_mandatory_element);
    /* ABBA    ABBA 9.11.3.10    M    LV    3-n */
    ELEM_MAND_LV(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_ABBA, NULL, ei_nas_5gs_missing_mandatory_element);
    /*21    Authentication parameter RAND (5G authentication challenge)    Authentication parameter RAND     9.11.3.13    O    TV    17*/
    ELEM_OPT_TV(0x21, GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_RAND, " - 5G authentication challenge");
    /*20    Authentication parameter AUTN (5G authentication challenge)    Authentication parameter AUTN     9.11.3.14    O    TLV    18*/
    ELEM_OPT_TLV(0x20, GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_AUTN, " - 5G authentication challenge");
    /*78    EAP message    EAP message 9.10.2.2    O    TLV-E    7-1503 */
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL);


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}
/*
 *8.2.2    Authentication response
 */
static void
nas_5gs_mm_authentication_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 2D    Authentication response parameter    Authentication response parameter 9.11.3.15    O    TLV    6-18 */
    ELEM_OPT_TLV( 0x2d, NAS_PDU_TYPE_EMM, DE_EMM_AUTH_RESP_PAR, NULL);
    /* 78 EAP message    EAP message     9.10.2.2    O    TLV-E    7-1503 */
    ELEM_OPT_TLV_E(0x78,  NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.3 Authentication result
 */
static void
nas_5gs_mm_authentication_result(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* ngKSI    NAS key set identifier 9.11.3.27    M    V    1/2
       Spare half octet    Spare half octet 9.5    M    V    1/2  H1 */
    proto_tree_add_item(tree, hf_nas_5gs_spare_half_octet, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_KEY_SET_ID, " - ngKSI", ei_nas_5gs_missing_mandatory_element);
    /* EAP message    EAP message     9.11.2.2    M    LV-E    7-1503 */
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL, ei_nas_5gs_missing_mandatory_element);
    /* 38    ABBA    ABBA 9.11.3.10    O    TLV    4-n */
    ELEM_OPT_TLV(0x38, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_ABBA, NULL);
    /* 55    AUN3 device security key    AUN3 device security key 9.11.3.107    O    TLV    36-n */
    ELEM_OPT_TLV(0x55, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_AUN3_DEVICE_SEC_KEY, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}
/*
 * 8.2.4 Authentication failure
 */
static void
nas_5gs_mm_authentication_failure(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 5GMM cause   5GMM cause     9.11.3.2  M   V   1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_element);

    /* 30    Authentication failure parameter    Authentication failure parameter 9.11.3.14    O    TLV    16 */
    ELEM_OPT_TLV(0x30, GSM_A_PDU_TYPE_DTAP, DE_AUTH_FAIL_PARAM, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}
/*
 * 8.2.5 Authentication reject
 */
static void
nas_5gs_mm_authentication_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 78    EAP message    EAP message 9.11.2.2    O    TLV-E    7-1503 */
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL);


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.6 Registration request
 */

static void
nas_5gs_mm_registration_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: UE to network */
    pinfo->link_dir = P2P_DIR_UL;

    /* Initialize the private struct */
    nas5gs_get_private_data(pinfo);

    /*    ngKSI    NAS key set identifier 9.11.3.32    M    V    1/2 H1*/
    /*   5GS registration type    5GS registration type 9.11.3.7    M    V    1/2  H0*/
    ELEM_MAND_VV_SHORT(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_REG_TYPE, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_KEY_SET_ID_H1, ei_nas_5gs_missing_mandatory_element);

    /*    Mobile identity    5GS mobile identity 9.11.3.4    M    LV-E    6-n*/
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_MOBILE_ID, NULL, ei_nas_5gs_missing_mandatory_element);

    /*C-    Non-current native NAS KSI    NAS key set identifier 9.11.3.32    O    TV    1*/
    ELEM_OPT_TV_SHORT(0xc0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_KEY_SET_ID, " - native KSI");

    /*10    5GMM capability    5GMM capability 9.11.3.1    O    TLV    3-15*/
    ELEM_OPT_TLV(0x10, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAP, NULL);

    /*2E    UE security capability    UE security capability 9.11.3.54    O    TLV    4-10*/
    ELEM_OPT_TLV(0x2e, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_UE_SEC_CAP, NULL);

    /*2F    Requested NSSAI    NSSAI 9.11.3.37    O    TLV    4-74*/
    ELEM_OPT_TLV(0x2f, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NSSAI, " - Requested NSSAI");

    /*52    Last visited registered TAI    5GS tracking area identity 9.11.3.8    O    TV    7 */
    ELEM_OPT_TV(0x52, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_TA_ID, " - Last visited registered TAI");

    /*17    S1 UE network capability    S1 UE network capability 9.11.3.48    O    TLV    4-15 */
    ELEM_OPT_TLV(0x17, NAS_PDU_TYPE_EMM, DE_EMM_UE_NET_CAP, NULL);

    /*40    Uplink data status    Uplink data status 9.11.3.57    O    TLV    4-34 */
    ELEM_OPT_TLV(0x40, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_UL_DATA_STATUS, NULL);

    /*50    PDU session status    PDU session status 9.11.3.44    O    TLV    4-34 */
    ELEM_OPT_TLV(0x50, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PDU_SES_STATUS, NULL);

    /*B-    MICO indication    MICO indication 9.11.3.31    O    TV    1*/
    ELEM_OPT_TV_SHORT(0xb0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_MICO_IND, NULL);

    /*2B    UE status    UE status 9.11.3.56    O    TLV    3*/
    ELEM_OPT_TLV(0x2b, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_UE_STATUS, NULL);

    /*77    Additional GUTI    5GS mobile identity 9.11.3.4    O    TLV-E    14 */
    ELEM_OPT_TLV_E(0x77, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_MOBILE_ID, " -  Additional GUTI");

    /*25    Allowed PDU session status    Allowed PDU session status         9.11.3.13    O    TLV    4 - 34 */
    ELEM_OPT_TLV(0x25, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_ALLOW_PDU_SES_STS, NULL);

    /*18    UE's usage setting    UE's usage setting         9.11.3.55    O    TLV    3 */
    ELEM_OPT_TLV(0x18, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_UE_USAGE_SET, NULL);

    /*51    Requested DRX parameters    5GS DRX parameters 9.11.3.2A    O    TLV    3 */
    ELEM_OPT_TLV(0x51, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_DRX_PARAM, " - Requested DRX parameters");

    /*70    EPS NAS message container    EPS NAS message container 9.11.3.24    O    TLV-E    4-n */
    ELEM_OPT_TLV_E(0x70, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EPS_NAS_MSG_CONT, NULL);

    /* 74    LADN indication    LADN indication 9.11.3.29    O    TLV-E    3-811 */
    ELEM_OPT_TLV_E(0x74, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_LADN_INDIC, NULL);

    /* 8-    Payload container type    Payload container type 9.11.3.40    O    TV    1 */
    ELEM_OPT_TV_SHORT(0x80, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PLD_CONT_TYPE, NULL);

    /* 7B    Payload container     Payload container 9.11.3.39    O    TLV-E    4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PLD_CONT, NULL);

    /* 9-    Network slicing indication    Network slicing indication 9.11.3.36    O    TV    1 */
    ELEM_OPT_TV_SHORT(0x90, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NW_SLICING_IND, NULL);

    /* 53    5GS update type    5GS update type 9.11.3.9A    O    TLV    3 */
    ELEM_OPT_TLV(0x53, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_UPDATE_TYPE, NULL);

    /* 41    Mobile station classmark 2    Mobile station classmark 2    9.11.3.31C    O    TLV 5 */
    ELEM_OPT_TLV(0x41, NAS_PDU_TYPE_COMMON, DE_EPS_MS_CM_2 , NULL );

    /* 42    Supported Codecs    Supported Codec List    9.11.3.51A    O    TLV 5-n */
    ELEM_OPT_TLV(0x42, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, " - Supported Codecs");

    /* 71    NAS message container    NAS message container 9.11.3.33    O    TLV-E    4-n */
    ELEM_OPT_TLV_E(0x71, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_MSG_CONT, NULL);

    /* 60    EPS bearer context status    EPS bearer context status 9.11.3.23A    O    TLV    4 */
    ELEM_OPT_TLV(0x60, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_EPS_BE_CTX_STATUS, NULL);

    /* 6E    Requested extended DRX parameters    Extended DRX parameters 9.11.3.60    O    TLV    3-4 */
    ELEM_OPT_TLV(0x6E, GSM_A_PDU_TYPE_GM, DE_EXT_DRX_PARAMS, NULL);
    /* 6A    T3324 value    GPRS timer 3 9.11.2.5    O    TLV    3 */
    ELEM_OPT_TLV(0x6A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - T3324 value");
    /* 67    UE radio capability ID    UE radio capability ID 9.11.3.68    O    TLV    3-n */
    ELEM_OPT_TLV(0x67, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_UE_RADIO_CAP_ID, NULL);
    /* 35    Requested mapped NSSAI    Mapped NSSAI 9.11.3.31B    O    TLV    3-42 */
    ELEM_OPT_TLV(0x35, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_MAPPED_NSSAI, NULL);
    /* 48    Additional information requested    Additional information requested 9.11.3.12A    O    TLV    3 */
    ELEM_OPT_TLV(0x48, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_ADD_INF_REQ, NULL);
    /* 1A    Requested WUS assistance information    WUS assistance information 9.11.3.71    O    TLV    3-n */
    ELEM_OPT_TLV(0x1A, NAS_PDU_TYPE_EMM, DE_EMM_WUS_ASSIST_INFO, " - Requested");
    /* A-    N5GC indication    N5GC indication 9.11.3.72    O    T    1 */
    ELEM_OPT_TV_SHORT(0xA0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_N5GC_INDICATION, NULL);
    /* 30    Requested NB-N1 mode DRX parameters    NB-N1 mode DRX parameters 9.11.3.73    O    TLV    3 */
    ELEM_OPT_TLV(0x30, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NB_N1_MODE_DRX_PARS, NULL);
    /* 29    UE request type    UE request type 9.11.3.76    O    TLV    3 */
    ELEM_OPT_TLV(0x29, NAS_PDU_TYPE_EMM, DE_EMM_UE_REQUEST_TYPE, NULL);
    /* 28    Paging restriction    Paging restriction 9.11.3.77    O    TLV    3-35 */
    ELEM_OPT_TLV(0x28, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PAGING_RESTRICTION, NULL);
    /* 72    Service-level-AA container    Service-level-AA container 9.11.2.10    O    TLV-E    4-65538 */
    ELEM_OPT_TLV_E(0x72, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_SERVICE_LEVEL_AA_CONT, NULL);
    /* 32    NID    NID 9.11.3.79    O    TLV    8 */
    ELEM_OPT_TLV(0x32, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NID, NULL);
    /* 16    UE determined PLMN with disaster condition    PLMN identity 9.11.3.85    O    TLV    5 */
    ELEM_OPT_TLV(0x16, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PLMN_ID, " - UE determined PLMN with disaster condition");
    /* 2A    Requested PEIPS assistance information    PEIPS assistance information 9.11.3.80    O    TLV    3-n */
    ELEM_OPT_TLV(0x2A, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PEIPS_ASSIST_INFO, " - Requested");
    /* 3B    Requested T3512 value    GPRS timer 3     9.11.2.5    O    TLV    3 */
    ELEM_OPT_TLV(0x3B, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Requested T3512 value");
    /* 3C    Unavailability information    Unavailability information     9.11.2.20    O    TLV    3-9 */
    ELEM_OPT_TLV(0x3C, NAS_PDU_TYPE_EMM, DE_EMM_UNAVAIL_INFO, NULL);
    /* 3F    Non-3GPP path switching information    Non-3GPP path switching information     9.11.3.102    O    TLV    3 */
    ELEM_OPT_TLV(0x3F, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_N3GPP_PATH_SWITCH_INFO, NULL);
    /* 56    AUN3 indication    AUN3 indication     9.11.3.104    O    TLV    3 */
    ELEM_OPT_TLV(0x56, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_AU3N_IND, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.7    Registration accept
 */

static void
nas_5gs_mm_registration_accept(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*      5GS registration result    5GS registration result     9.11.3.6    M    LV    2*/
    ELEM_MAND_LV(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_REG_RES, NULL, ei_nas_5gs_missing_mandatory_element);
    /*77    5G-GUTI    5GS mobile identity 9.11.3.4    O    TLV-E    14 */
    ELEM_OPT_TLV_E(0x77, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_MOBILE_ID, " - 5G-GUTI");
    /*4A    Equivalent PLMNs    PLMN list     9.11.3.33    O    TLV    5-47*/
    ELEM_OPT_TLV(0x4a, GSM_A_PDU_TYPE_COMMON, DE_PLMN_LIST, " - Equivalent PLMNs");
    /*54    TAI list    Tracking area identity list     9.11.3.9    O    TLV    9-114 */
    ELEM_OPT_TLV(0x54, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_TA_ID_LIST, NULL);
    /*15    Allowed NSSAI    NSSAI     9.11.3.28    O    TLV    4-74*/
    ELEM_OPT_TLV(0x15, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NSSAI, " - Allowed NSSAI");
    /*11    Rejected NSSAI    Rejected NSSAI     9.11.3.46    O    TLV    4-42*/
    ELEM_OPT_TLV(0x11, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_REJ_NSSAI, NULL);
    /*31    Configured NSSAI    NSSAI 9.11.3.34    O    TLV    4-146 */
    ELEM_OPT_TLV(0x31, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NSSAI, " - Configured NSSAI");
    /*21    5GS network feature support    5GS network feature support 9.11.3.5    O    TLV    3-5 */
    ELEM_OPT_TLV(0x21, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_NW_FEAT_SUP, NULL);
    /*50    PDU session status    PDU session status     9.10.2.2    O    TLV    4*/
    ELEM_OPT_TLV(0x50, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PDU_SES_STATUS, NULL);
    /*26    PDU session reactivation result    PDU session reactivation result     9.11.3.32    O    TLV    4-32*/
    ELEM_OPT_TLV(0x26, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PDU_SES_REACT_RES, NULL);
    /*72    PDU session reactivation result error cause PDU session reactivation result error cause 9.11.3.40  O TLV-E  5-515*/
    ELEM_OPT_TLV_E(0x72, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PDU_SES_REACT_RES_ERR_C, NULL);
    /*79    LADN information    LADN information     9.11.3.19    O    TLV-E    11-1579*/
    ELEM_OPT_TLV_E(0x79, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_LADN_INF, NULL);
    /*B-    MICO indication    MICO indication     9.11.3.31    O    TV    1*/
    ELEM_OPT_TV_SHORT(0xb0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_MICO_IND, NULL);
    /* 9-    Network slicing indication    Network slicing indication 9.11.3.36    O    TV    1 */
    ELEM_OPT_TV_SHORT(0x90, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NW_SLICING_IND, NULL);
    /*27    Service area list    Service area list     9.11.3.47    O    TLV    6-194*/
    ELEM_OPT_TLV(0x27, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_SAL, NULL);
    /*5E    T3512 value    GPRS timer 3     9.11.2.5    O    TLV    3*/
    ELEM_OPT_TLV(0x5E, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - T3512 value");
    /*5D    Non-3GPP de-registration timer value    GPRS timer 2     9.11.3.20    O    TLV    3*/
    ELEM_OPT_TLV(0x5D, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - Non-3GPP de-registration timer value");
    /*16    T3502 value    GPRS timer 2     9.10.2.4     O    TLV    3*/
    ELEM_OPT_TLV(0x16, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3502 value");
    /*34    Emergency number list    Emergency number list     9.11.3.17    O    TLV    5-50*/
    ELEM_OPT_TLV(0x34, GSM_A_PDU_TYPE_DTAP, DE_EMERGENCY_NUM_LIST, NULL);
    /*7A    Extended emergency number list    Extended emergency number list 9.11.3.24    O    TLV-E    7-65538 */
    ELEM_OPT_TLV_E(0x7A, NAS_PDU_TYPE_EMM, DE_EMM_EXT_EMERG_NUM_LIST, NULL);
    /*73    SOR transparent container    SOR transparent container 9.11.3.51    O    TLV-E    20-2048 */
    ELEM_OPT_TLV_E(0x73, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_SOR_TRANSP_CONT, NULL);
    /*78    EAP message    EAP message 9.10.2.2    O    TLV-E    7-1503 */
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL);
    /* A-    NSSAI inclusion mode    NSSAI inclusion mode 9.11.3.37A    O    TV    1 */
    ELEM_OPT_TV_SHORT(0xA0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NSSAI_INC_MODE, NULL);
    /* 76    Operator-defined access category definitions    Operator-defined access category definitions 9.11.3.38    O    TLV-E    3-8323 */
    ELEM_OPT_TLV_E(0x76, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_OP_DEF_ACC_CAT_DEF, NULL);
    /* 51    Negotiated DRX parameters    5GS DRX parameters 9.11.3.2A    O    TLV    3 */
    ELEM_OPT_TLV(0x51, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_DRX_PARAM, " -  Negotiated DRX parameters");
    /* D-    Non-3GPP NW policies    Non-3GPP NW provided policies 9.11.3.36A    O    TV    1 */
    ELEM_OPT_TV_SHORT(0xD0, GSM_A_PDU_TYPE_GM, DE_NON_3GPP_NW_PROV_POL, NULL);
    /* 60    EPS bearer context status    EPS bearer context status 9.11.3.59    O    TLV    4 */
    ELEM_OPT_TLV(0x60, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_EPS_BE_CTX_STATUS, NULL);
    /* 6E    Negotiated extended DRX parameters    Extended DRX parameters 9.11.3.60    O    TLV    3-4 */
    ELEM_OPT_TLV(0x6E, GSM_A_PDU_TYPE_GM, DE_EXT_DRX_PARAMS, NULL);
    /* 6C    T3447 value    GPRS timer 3 9.11.2.5    O    TLV    3 */
    ELEM_OPT_TLV(0x6C, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - T3447 value");
    /* 6B    T3448 value    GPRS timer 3 9.11.2.4    O    TLV    3 */
    ELEM_OPT_TLV(0x6B, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3448 value");
    /* 6A    T3324 value    GPRS timer 3 9.11.2.5    O    TLV    3 */
    ELEM_OPT_TLV(0x6A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - T3324 value");
    /* 67    UE radio capability ID    UE radio capability ID 9.11.3.yy    O    TLV    3-n */
    ELEM_OPT_TLV(0x67, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_UE_RADIO_CAP_ID, NULL);
    /* E-    UE radio capability ID deletion indication    UE radio capability ID deletion indication 9.11.3.69    O    TV    1 */
    ELEM_OPT_TV_SHORT(0xE0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_UE_RADIO_CAP_ID_DEL_IND, NULL);
    /* 39    Pending NSSAI    NSSAI 9.11.3.37    O    TLV    4-146 */
    ELEM_OPT_TLV(0x39, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NSSAI, " - Pending NSSAI");
    /* 74    Ciphering key data    Ciphering key data 9.11.3.18C    O    TLV-E    34-n */
    ELEM_OPT_TLV_E(0x74, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_CIPHERING_KEY_DATA, NULL);
    /* 75    CAG information list    CAG information list 9.11.3.18A    O    TLV-E    3-n */
    ELEM_OPT_TLV_E(0x75, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_CAG_INFORMATION_LIST, NULL);
    /* 1B    Truncated 5G-S-TMSI configuration    Truncated 5G-S-TMSI configuration 9.11.3.70    O    TLV    3 */
    ELEM_OPT_TLV(0x1B, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_TRUNCATED_5G_S_TMSI_CONF, NULL);
    /* 1C    Negotiated WUS assistance information    WUS assistance information 9.11.3.71    O    TLV    3-n */
    ELEM_OPT_TLV(0x1C, NAS_PDU_TYPE_EMM, DE_EMM_WUS_ASSIST_INFO, " - Negotiated");
    /* 29    Negotiated NB-N1 mode DRX parameters    NB-N1 mode DRX parameters 9.11.3.73    O    TLV    3 */
    ELEM_OPT_TLV(0x29, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NB_N1_MODE_DRX_PARS, NULL);
    /* 68    Extended rejected NSSAI    Extended rejected NSSAI 9.11.3.75    O    TLV    5-90 */
    ELEM_OPT_TLV(0x68, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EXTENDED_REJECTED_NSSAI, NULL);
    /* 7B    Service-level-AA container    Service-level-AA container 9.11.2.10    O    TLV-E    4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_SERVICE_LEVEL_AA_CONT, NULL);
    /* 33    Negotiated PEIPS assistance information    PEIPS assistance information 9.11.3.80    O    TLV    3-n */
    ELEM_OPT_TLV(0x33, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PEIPS_ASSIST_INFO, " - Negotiated");
    /* 35    5GS additional request result    5GS additional request result 9.11.3.81    O    TLV    3 */
    ELEM_OPT_TLV(0x35, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_ADD_REQ_RES, NULL);
    /* 70    NSSRG information    NSSRG information 9.11.3.82    O    TLV-E    7-4099 */
    ELEM_OPT_TLV_E(0x70, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NSSRG_INFO, NULL);
    /* 14    Disaster roaming wait range    Registration wait range 9.11.3.84    O    TLV    4 */
    ELEM_OPT_TLV(0x14, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_REG_WAIT_RANGE, " - Disaster roaming");
    /* 2C    Disaster return wait range    Registration wait range 9.11.3.84    O    TLV    4 */
    ELEM_OPT_TLV(0x2C, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_REG_WAIT_RANGE, " - Disaster return");
    /* 13    List of PLMNs to be used in disaster condition    List of PLMNs to be used in disaster condition 9.11.3.83    O    TLV    2-n */
    ELEM_OPT_TLV(0x13, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PLMNS_LIST_DISASTER_COND, NULL);
    /* 1D    Forbidden TAI(s) for the list of "5GS forbidden tracking areas for roaming"    5GS tracking area identity list 9.11.3.9    O    TLV    9-114 */
    ELEM_OPT_TLV(0x1D, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_TA_ID_LIST, " - Forbidden TAI(s) for the list of \"5GS forbidden tracking areas for roaming\"");
    /* 1E    Forbidden TAI(s) for the list of "5GS forbidden tracking areas for regional provision of service"    5GS tracking area identity list 9.11.3.9    O    TLV    9-114 */
    ELEM_OPT_TLV(0x1E, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_TA_ID_LIST, " - Forbidden TAI(s) for the list of \"5GS forbidden tracking areas for regional provision of service\"");
    /* 71    Extended CAG information list    Extended CAG information list 9.11.3.86    O    TLV-E    3-n */
    ELEM_OPT_TLV_E(0x71, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EXT_CAG_INFO_LIST, NULL);
    /* 7C    NSAG information    NSAG information 9.11.3.87    O    TLV-E    9-3143 */
    ELEM_OPT_TLV_E(0x7C, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NSAG_INFO, NULL);
    /* 3D    Equivalent SNPNs    SNPN list 9.11.3.92    O    TLV    11-137 */
    ELEM_OPT_TLV(0x3D, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_SNPN_LIST, " - Equivalent SNPNs");
    /* 32    NID    NID 9.11.3.79    O    TLV    8 */
    ELEM_OPT_TLV(0x32, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NID, NULL);
    /* 7D    Registration accept type 6 IE container    Type 6 IE container 9.11.3.98    O    TLV-E    6-65538 */
    ELEM_OPT_TLV_E(0x7D, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_TYPE_6_IE_CONT, " - Registration accept type 6 IE container");
    /* 4B    RAN timing synchronization    RAN timing synchronization 9.11.3.95    O    TLV    3 */
    ELEM_OPT_TLV(0x4B, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_RAN_TIMING_SYNC, NULL);
    /* 4C    Alternative NSSAI    Alternative NSSAI 9.11.3.97    O    TLV    2-146 */
    ELEM_OPT_TLV(0x4C, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_ALT_NSSAI, NULL);
    /* 4F    Maximum time offset    GPRS timer 3 9.11.2.5    O    TLV    3 */
    ELEM_OPT_TLV(0x4F, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Maximum time offset");
    /* 5B    S-NSSAI time validity information    S-NSSAI time validity information 9.11.3.101    O    TLV    23-257 */
    ELEM_OPT_TLV(0x5B, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_S_NSSAI_TIME_VALID_INFO, NULL);
    /* 3C   Unavailability configuration    Unavailability configuration 9.11.2.21    O    TLV 3-9 */
    ELEM_OPT_TLV(0x3C, NAS_PDU_TYPE_EMM, DE_EMM_UNAVAIL_CONFIG, NULL);
    /* 5C    Feature authorization indication    Feature authorization indication 9.11.3.105    O    TLV    3-257 */
    ELEM_OPT_TLV(0x5C, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_FEAT_AUTH_IND, NULL);
    /* 61    On-demand NSSAI    On-demand NSSAI 9.11.3.108    O    TLV    5-210 */
    ELEM_OPT_TLV(0x61, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_ON_DEMAND_NSSAI, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.8 Registration complete
 */
static void
nas_5gs_mm_registration_complete(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 73    SOR transparent container    SOR transparent container 9.11.3.51    O    TLV-E    20-2048 */
    ELEM_OPT_TLV_E(0x73, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_SOR_TRANSP_CONT, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
* 8.2.9 Registration reject
*/
static void
nas_5gs_mm_registration_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 5GMM cause   5GMM cause     9.11.3.2  M   V   1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_element);
    /* 5F  T3346 value GPRS timer 2     9.11.3.16   O   TLV 3 */
    ELEM_OPT_TLV(0x5F, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3346 value");
    /* 16    T3502 value    GPRS timer 2 9.10.2.4    O    TLV    3 */
    ELEM_OPT_TLV(0x16, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3502 value");
    /* 78    EAP message    EAP message 9.10.2.2    O    TLV-E    7-1503 */
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL);
    /* 69    Rejected NSSAI    Rejected NSSAI 9.11.3.46    O    TLV    4-42 DE_NAS_5GS_MM_REJ_NSSAI*/
    ELEM_OPT_TLV(0x69, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_REJ_NSSAI, NULL);
    /* 75    CAG information list    CAG information list 9.11.3.18A    O    TLV-E    3-n */
    ELEM_OPT_TLV_E(0x75, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_CAG_INFORMATION_LIST, NULL);
    /* 68    Extended rejected NSSAI    Extended rejected NSSAI 9.11.3.75    O    TLV    5-90 */
    ELEM_OPT_TLV(0x68, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EXTENDED_REJECTED_NSSAI, NULL);
    /* 2C    Disaster return wait range    Registration wait range 9.11.3.84    O    TLV    4 */
    ELEM_OPT_TLV(0x2C, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_REG_WAIT_RANGE, " - Disaster return");
    /* 71    Extended CAG information list    Extended CAG information list 9.11.3.86    O    TLV-E    3-n */
    ELEM_OPT_TLV_E(0x71, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EXT_CAG_INFO_LIST, NULL);
    /* 3A    Lower bound timer value    GPRS timer 3 9.11.2.5    O    TLV    3 */
    ELEM_OPT_TLV(0x3A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Lower bound timer value");
    /* 1D    Forbidden TAI(s) for the list of "5GS forbidden tracking areas for roaming"    5GS tracking area identity list 9.11.3.9    O    TLV    9-114 */
    ELEM_OPT_TLV(0x1D, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_TA_ID_LIST, " - Forbidden TAI(s) for the list of \"5GS forbidden tracking areas for roaming\"");
    /* 1E    Forbidden TAI(s) for the list of "5GS forbidden tracking areas for regional provision of service"    5GS tracking area identity list 9.11.3.9    O    TLV    9-114 */
    ELEM_OPT_TLV(0x1E, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_TA_ID_LIST, " - Forbidden TAI(s) for the list of \"5GS forbidden tracking areas for regional provision of service\"");
    /* 3E    N3IWF identifier    N3IWF identifier 9.11.3.93    O    TLV    7-n */
    ELEM_OPT_TLV(0x3E, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_N3IWF_ID, NULL);
    /* 4D    TNAN information    TNAN information 9.11.3.94    O    TLV    3-n */
    ELEM_OPT_TLV(0x4D, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_TNAN_INFO, NULL);
    /* 62    Extended 5GMM cause    Extended 5GMM cause 9.11.3.109    O    TLV    3 */
    ELEM_OPT_TLV(0x62, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EXT_5GMM_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.10    UL NAS transport
 */
static void
nas_5gs_mm_ul_nas_transp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    /* Direction: UE to network */
    pinfo->link_dir = P2P_DIR_UL;

    curr_offset = offset;
    curr_len = len;

    /* Initialize the private struct */
    nas5gs_get_private_data(pinfo);

    /*Payload container type    Payload container type     9.11.3.31    M    V    1/2 */
    /*Spare half octet    Spare half octet    9.5    M    V    1/2*/
    proto_tree_add_item(tree, hf_nas_5gs_spare_half_octet, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PLD_CONT_TYPE, NULL, ei_nas_5gs_missing_mandatory_element);
    /*Payload container    Payload container    9.11.3.30    M    LV-E    3-65537*/
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PLD_CONT, NULL, ei_nas_5gs_missing_mandatory_element);
    /*12    PDU session ID    PDU session identity 2 9.11.3.41    C    TV    2 */
    ELEM_OPT_TV(0x12, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PDU_SES_ID_2, " - PDU session ID");
    /*59    Old PDU session ID    PDU session identity 2 9.11.3.41    O    TV    2 */
    ELEM_OPT_TV(0x59, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PDU_SES_ID_2, " - Old PDU session ID");
    /*8-    Request type    Request type    9.11.3.42    O    TV    1 */
    ELEM_OPT_TV_SHORT(0x80, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_REQ_TYPE, NULL);
    /*22    S-NSSAI    S-NSSAI    9.11.2.8    O    TLV    3-10 */
    ELEM_OPT_TLV(0x22, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_S_NSSAI, NULL);
    /*25    DNN    DNN    9.11.2.1B    O    TLV    3-102 */
    ELEM_OPT_TLV(0x25, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_DNN, NULL);
    /*24    Additional information    Additional information    9.10.2.1    O    TLV    3-n */
    ELEM_OPT_TLV(0x24, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_ADD_INF, NULL);
    /* A-    MA PDU session information    MA PDU session information 9.11.3.31A    O    TV    1 DE_NAS_5GS_MM_MA_PDU_SES_INF*/
    ELEM_OPT_TV_SHORT(0xA0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_MA_PDU_SES_INF, NULL);
    /* F-    Release assistance indication    Release assistance indication 9.11.3.46A    O    TV    1 */
    ELEM_OPT_TV_SHORT(0xF0, NAS_PDU_TYPE_ESM, DE_ESM_REL_ASSIST_IND, NULL);
    /*4E    Non-3GPP access path switching indication    Non-3GPP access path switching indication    9.11.3.99    O    TLV    3 */
    ELEM_OPT_TLV(0x4E, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_N3GPP_ACC_PATH_SWITCH_IND, NULL);
    /*5A    Alternative S-NSSAI    S-NSSAI    9.11.2.8    O    TLV    3-10 */
    ELEM_OPT_TLV(0x5A, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_S_NSSAI, " - Alternative S-NSSAI");
    /* 9-    Payload container information    Payload container information 9.11.3.106    O    TV    1 */
    ELEM_OPT_TV_SHORT(0x90, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PAYLOAD_CONT_INFO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
* 8.2.11 DL NAS transport
*/
static void
nas_5gs_mm_dl_nas_transp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    /* Direction: network to UE */
    pinfo->link_dir = P2P_DIR_DL;

    curr_offset = offset;
    curr_len = len;

    /* Initialize the private struct */
    nas5gs_get_private_data(pinfo);

    /*Payload container type    Payload container type     9.11.3.40    M    V    1/2 H0*/
    /*Spare half octet    Spare half octet    9.5    M    V    1/2 H1*/
    proto_tree_add_item(tree, hf_nas_5gs_spare_half_octet, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PLD_CONT_TYPE, NULL, ei_nas_5gs_missing_mandatory_element);
    /*Payload container    Payload container    9.11.3.39    M    LV-E    3-65537*/
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PLD_CONT, NULL, ei_nas_5gs_missing_mandatory_element);
    /*12    PDU session ID    PDU session identity 2 9.11.3.41    C    TV    2 */
    ELEM_OPT_TV(0x12, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PDU_SES_ID_2, " - PDU session ID");
    /*24    Additional information    Additional information    9.10.2.1    O    TLV    3-n*/
    ELEM_OPT_TLV(0x24, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_ADD_INF, NULL);
    /*58    5GMM cause    5GMM cause 9.11.3.2    O    TV    2 */
    ELEM_OPT_TV(0x58, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAUSE, NULL);
    /*37    Back-off timer value    GPRS timer 3 9.11.2.5    O    TLV    3 */
    ELEM_OPT_TLV(0x37, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Back-off timer value");
    /*3A    Lower bound timer value    GPRS timer 3 9.11.2.5    O    TLV    3 */
    ELEM_OPT_TLV(0x3A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Lower bound timer value");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.12 De-registration request (UE originating de-registration)
 */
static void
nas_5gs_mm_de_reg_req_ue_orig(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* De-registration type    De-registration type     9.11.3.18   M   V   1 */
    /* ngKSI    NAS key set identifier 9.11.3.32    M    V    1/2 H1 */
    ELEM_MAND_VV_SHORT(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_DE_REG_TYPE, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_KEY_SET_ID_H1, ei_nas_5gs_missing_mandatory_element);
    /*5GS mobile identity     5GS mobile identity 9.11.3.4    M    LV-E    6-n */
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_MOBILE_ID, NULL, ei_nas_5gs_missing_mandatory_element);
    /* 3C    Unavailability information    Unavailability information     9.11.2.20    O    TLV    3-9 */
    ELEM_OPT_TLV(0x3C, NAS_PDU_TYPE_EMM, DE_EMM_UNAVAIL_INFO, NULL);
    /* 71    NAS message container    NAS message container 9.11.3.33    O    TLV-E    4-n */
    ELEM_OPT_TLV_E(0x71, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_MSG_CONT, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.13 De-registration accept (UE originating de-registration)
 */
/* No data */

/*
 * 8.2.14 De-registration request (UE terminated de-registration)
 */
static void
nas_5gs_mm_de_registration_req_ue_term(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* De-registration type    De-registration type 9.11.3.20   M   V   1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_DE_REG_TYPE, NULL, ei_nas_5gs_missing_mandatory_element);
    /* Spare half octet    Spare half octet 9.5    M    V    1/2 */
    /* 58 5GMM cause   5GMM cause     9.11.3.2  O   TV   2 */
    ELEM_OPT_TV(0x58, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAUSE, NULL);
    /* 5F  T3346 value GPRS timer 2     9.11.2.4   O   TLV 3 */
    ELEM_OPT_TLV(0x5F, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3346 value");
    /* 6D    Rejected NSSAI    Rejected NSSAI 9.11.3.46    O    TLV    4-42 */
    ELEM_OPT_TLV(0x6D, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_REJ_NSSAI, NULL);
    /* 75    CAG information list    CAG information list 9.11.3.18A    O    TLV-E    3-n */
    ELEM_OPT_TLV_E(0x75, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_CAG_INFORMATION_LIST, NULL);
    /* 68    Extended rejected NSSAI    Extended rejected NSSAI 9.11.3.75    O    TLV    5-90 */
    ELEM_OPT_TLV(0x68, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EXTENDED_REJECTED_NSSAI, NULL);
    /* 2C    Disaster return wait range    Registration wait range 9.11.3.84    O    TLV    4 */
    ELEM_OPT_TLV(0x2C, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_REG_WAIT_RANGE, " - Disaster return");
    /* 71    Extended CAG information list    Extended CAG information list 9.11.3.86    O    TLV-E    3-n */
    ELEM_OPT_TLV_E(0x71, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EXT_CAG_INFO_LIST, NULL);
    /* 3A    Lower bound timer value    GPRS timer 3 9.11.2.5    O    TLV    3 */
    ELEM_OPT_TLV(0x3A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Lower bound timer value");
    /* 1D    Forbidden TAI(s) for the list of "5GS forbidden tracking areas for roaming"    5GS tracking area identity list 9.11.3.9    O    TLV    9-114 */
    ELEM_OPT_TLV(0x1D, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_TA_ID_LIST, " - Forbidden TAI(s) for the list of \"5GS forbidden tracking areas for roaming\"");
    /* 1E    Forbidden TAI(s) for the list of "5GS forbidden tracking areas for regional provision of service"    5GS tracking area identity list 9.11.3.9    O    TLV    9-114 */
    ELEM_OPT_TLV(0x1E, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_TA_ID_LIST, " - Forbidden TAI(s) for the list of \"5GS forbidden tracking areas for regional provision of service\"");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.15 De-registration accept (UE terminated de-registration)
 */
 /* No data */


/*
 * 8.2.16 Service request
 */
static void
nas_5gs_mm_service_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* ngKSI     NAS key set identifier 9.11.3.29    M    V    1/2 */
    /* Service type    Service type 9.11.3.50    M    V    1/2 */
    ELEM_MAND_VV_SHORT(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_KEY_SET_ID, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_SERV_TYPE, ei_nas_5gs_missing_mandatory_element);
    /* 5G-S-TMSI    5GS mobile identity 9.11.3.4    M    LV    6 */
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_MOBILE_ID, NULL, ei_nas_5gs_missing_mandatory_element);
    /*40    Uplink data status    Uplink data status         9.11.3.53    O    TLV    4 - 34*/
    ELEM_OPT_TLV(0x40, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_UL_DATA_STATUS, NULL);
    /*50    PDU session status    PDU session status         9.11.3.40    O    TLV    4 - 34*/
    ELEM_OPT_TLV(0x50, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PDU_SES_STATUS, NULL);
    /*25    Allowed PDU session status    Allowed PDU session status         9.11.3.11    O    TLV    4 - 34*/
    ELEM_OPT_TLV(0x25, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_ALLOW_PDU_SES_STS, NULL);
    /* 71    NAS message container    NAS message container 9.11.3.33    O    TLV-E    4-n */
    ELEM_OPT_TLV_E(0x71, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_MSG_CONT, NULL);
    /* 29    UE request type    UE request type 9.11.3.76    O    TLV    3 */
    ELEM_OPT_TLV(0x29, NAS_PDU_TYPE_EMM, DE_EMM_UE_REQUEST_TYPE, NULL);
    /* 28    Paging restriction    Paging restriction 9.11.3.77    O    TLV    3-35 */
    ELEM_OPT_TLV(0x28, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PAGING_RESTRICTION, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
  * 8.2.17 Service accept
 */
static void
nas_5gs_mm_service_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*50    PDU session status    PDU session status     9.11.3.44    O    TLV    4-34*/
    ELEM_OPT_TLV(0x50, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PDU_SES_STATUS, NULL);

    /*26    PDU session reactivation result    PDU session reactivation result 9.11.3.42    O    TLV    4-32*/
    ELEM_OPT_TLV(0x26, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PDU_SES_REACT_RES, NULL);
    /*72    PDU session reactivation result error cause    PDU session reactivation result error cause 9.11.3.43    O    TLV-E    5-515 */
    ELEM_OPT_TLV_E(0x72, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PDU_SES_REACT_RES_ERR_C, NULL);
    /*78    EAP message    EAP message     9.11.2.2    O    TLV-E    7-1503*/
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL);
    /* 6B    T3448 value    GPRS timer 2 9.11.2.4    O    TLV    3 */
    ELEM_OPT_TLV(0x6B, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3448 value");
    /* 34    5GS additional request result    5GS additional request result 9.11.3.81    O    TLV    3 */
    ELEM_OPT_TLV(0x34, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_ADD_REQ_RES, NULL);
    /* 1D    Forbidden TAI(s) for the list of "5GS forbidden tracking areas for roaming"    5GS tracking area identity list 9.11.3.9    O    TLV    9-114 */
    ELEM_OPT_TLV(0x1D, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_TA_ID_LIST, " - Forbidden TAI(s) for the list of \"5GS forbidden tracking areas for roaming\"");
    /* 1E    Forbidden TAI(s) for the list of "5GS forbidden tracking areas for regional provision of service"    5GS tracking area identity list 9.11.3.9    O    TLV    9-114 */
    ELEM_OPT_TLV(0x1E, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_TA_ID_LIST, " - Forbidden TAI(s) for the list of \"5GS forbidden tracking areas for regional provision of service\"");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);
}

/*
 * 8.2.18 Service reject
 */
static void
nas_5gs_mm_service_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 5GMM cause   5GMM cause     9.11.3.2  M   V   1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_element);
    /*50    PDU session status    PDU session status 9.11.3.44    O    TLV    4*/
    ELEM_OPT_TLV(0x50, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PDU_SES_STATUS, NULL);
    /* 5F  T3346 value GPRS timer 2     9.11.2.4   O   TLV 3 */
    ELEM_OPT_TLV(0x5F, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3346 value");
    /* 78    EAP message    EAP message 9.11.2.2    O    TLV-E    7-1503 */
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL);
    /* 6B    T3448 value    GPRS timer 3 9.11.2.4    O    TLV    3 */
    ELEM_OPT_TLV(0x6B, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2, " - T3448 value");
    /* 75    CAG information list    CAG information list 9.11.3.18A    O    TLV-E    3-n */
    ELEM_OPT_TLV_E(0x75, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_CAG_INFORMATION_LIST, NULL);
    /* 2C    Disaster return wait range    Registration wait range 9.11.3.84    O    TLV    4 */
    ELEM_OPT_TLV(0x2C, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_REG_WAIT_RANGE, " - Disaster return");
    /* 71    Extended CAG information list    Extended CAG information list 9.11.3.86    O    TLV-E    3-n */
    ELEM_OPT_TLV_E(0x71, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EXT_CAG_INFO_LIST, NULL);
    /* 3A    Lower bound timer value    GPRS timer 3 9.11.2.5    O    TLV    3 */
    ELEM_OPT_TLV(0x3A, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Lower bound timer value");
    /* 1D    Forbidden TAI(s) for the list of "5GS forbidden tracking areas for roaming"    5GS tracking area identity list 9.11.3.9    O    TLV    9-114 */
    ELEM_OPT_TLV(0x1D, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_TA_ID_LIST, " - Forbidden TAI(s) for the list of \"5GS forbidden tracking areas for roaming\"");
    /* 1E    Forbidden TAI(s) for the list of "5GS forbidden tracking areas for regional provision of service"    5GS tracking area identity list 9.11.3.9    O    TLV    9-114 */
    ELEM_OPT_TLV(0x1E, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_TA_ID_LIST, " - Forbidden TAI(s) for the list of \"5GS forbidden tracking areas for regional provision of service\"");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.19 Configuration update command
 */
static void
nas_5gs_mm_conf_upd_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*D-    Configuration update indication    Configuration update indication 9.11.3.16    O    TV    1 */
    ELEM_OPT_TV_SHORT(0xD0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_CONF_UPD_IND, NULL);
    /*77    5G-GUTI    5GS mobile identity     9.11.3.4    O    TLV    TBD*/
    ELEM_OPT_TLV_E(0x77, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_MOBILE_ID, NULL);
    /*54    TAI list    Tracking area identity list     9.11.3.45    O    TLV    8-98*/
    ELEM_OPT_TLV(0x54, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_TA_ID_LIST, NULL);
    /*15    Allowed NSSAI    NSSAI     9.11.3.28    O    TLV    4-74*/
    ELEM_OPT_TLV(0x15, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NSSAI, " - Allowed NSSAI");
    /*27    Service area list    Service area list     9.11.3.39    O    TLV    6-194 */
    ELEM_OPT_TLV(0x27, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_SAL, NULL);
    /*43    Full name for network    Network name     9.11.3.26    O    TLV    3-n*/
    ELEM_OPT_TLV(0x43, GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME, " - Full name for network");
    /*45    Short name for network    Network name     9.11.3.26    O    TLV    3-n*/
    ELEM_OPT_TLV(0x45, GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME, " - Short Name");
    /*46    Local time zone    Time zone     9.11.3.52    O    TV    2*/
    ELEM_OPT_TV(0x46, GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE, " - Local");
    /*47    Universal time and local time zone    Time zone and time     9.11.3.53    O    TV    8*/
    ELEM_OPT_TV(0x47, GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE_TIME, " - Universal Time and Local Time Zone");
    /*49    Network daylight saving time    Daylight saving time     9.11.3.11    O    TLV    3*/
    ELEM_OPT_TLV(0x49, GSM_A_PDU_TYPE_DTAP, DE_DAY_SAVING_TIME, NULL);
    /*79    LADN information    LADN information     9.11.3.19    O    TLV-E    11-1579*/
    ELEM_OPT_TLV_E(0x79, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_LADN_INF, NULL);
    /*B-    MICO indication    MICO indication     9.11.3.31    O    TV    1*/
    ELEM_OPT_TV_SHORT(0xB0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_MICO_IND, NULL);
    /* 9-    Network slicing indication    Network slicing indication 9.11.3.36    O    TV    1 */
    ELEM_OPT_TV_SHORT(0x90, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NW_SLICING_IND, NULL);
    /*31    Configured NSSAI    NSSAI     9.11.3.28    O    TLV    4-74*/
    ELEM_OPT_TLV(0x31, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NSSAI, " - Configured NSSAI");
    /*11    Rejected NSSAI     Rejected NSSAI   9.11.3.46   O   TLV   4-42*/
    ELEM_OPT_TLV(0x11, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_REJ_NSSAI, NULL);
    /* 76    Operator-defined access category definitions    Operator-defined access category definitions 9.11.3.38    O    TLV-E    3-8323 */
    ELEM_OPT_TLV_E(0x76, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_OP_DEF_ACC_CAT_DEF, NULL);
    /* F-    SMS indication    SMS indication 9.10.3.50A    O    TV    1 */
    ELEM_OPT_TV_SHORT(0xF0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_SMS_IND, NULL);
    /* 6C    T3447 value    GPRS timer 3 9.11.2.5    O    TLV    3 */
    ELEM_OPT_TLV(0x6c, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - T3447");
    /* 75    C75    CAG information list    CAG information list 9.11.3.18A    O    TLV-E    3-n  */
    ELEM_OPT_TLV_E(0x75, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_CAG_INFORMATION_LIST, NULL);
    /* 67    UE radio capability ID    UE radio capability ID 9.11.3.68    O    TLV    3-n  */
    ELEM_OPT_TLV(0x67, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_UE_RADIO_CAP_ID, NULL);
    /* A-    UE radio capability ID deletion indication    UE radio capability ID deletion indication 9.11.3.69    O    TV    1 */
    ELEM_OPT_TV_SHORT(0xA0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_UE_RADIO_CAP_ID_DEL_IND, NULL);
    /* 44    5GS registration result    5GS registration result 9.11.3.6    O    TLV    3 */
    ELEM_OPT_TLV(0x44, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_REG_RES, NULL);
    /* 1B    Truncated 5G-S-TMSI configuration    Truncated 5G-S-TMSI configuration 9.11.3.70    O    TLV    3 */
    ELEM_OPT_TLV(0x1B, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_TRUNCATED_5G_S_TMSI_CONF, NULL);
    /* C-    Additional configuration indication    Additional configuration indication 9.11.3.74    O    TV    1 */
    ELEM_OPT_TV_SHORT(0xC0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_ADDITIONAL_CONF_IND, NULL);
    /* 68    Extended rejected NSSAI    Extended rejected NSSAI 9.11.3.75    O    TLV    5-90 */
    ELEM_OPT_TLV(0x68, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EXTENDED_REJECTED_NSSAI, NULL);
    /* 72    Service-level-AA container    Service-level-AA container 9.11.2.10    O    TLV-E    4-65538 */
    ELEM_OPT_TLV_E(0x72, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_SERVICE_LEVEL_AA_CONT, NULL);
    /* 70    NSSRG information    NSSRG information 9.11.3.82    O    TLV-E    7-4099 */
    ELEM_OPT_TLV_E(0x70, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NSSRG_INFO, NULL);
    /* 14    Disaster roaming wait range    Registration wait range 9.11.3.84    O    TLV    4 */
    ELEM_OPT_TLV(0x14, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_REG_WAIT_RANGE, " - Disaster roaming");
    /* 2C    Disaster return wait range    Registration wait range 9.11.3.84    O    TLV    4 */
    ELEM_OPT_TLV(0x2C, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_REG_WAIT_RANGE, " - Disaster return");
    /* 13    List of PLMNs to be used in disaster condition    List of PLMNs to be used in disaster condition 9.11.3.83    O    TLV    2-n */
    ELEM_OPT_TLV(0x13, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PLMNS_LIST_DISASTER_COND, NULL);
    /* 71    Extended CAG information list    Extended CAG information list 9.11.3.86    O    TLV-E    3-n */
    ELEM_OPT_TLV_E(0x71, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EXT_CAG_INFO_LIST, NULL);
    /* 1F    Updated PEIPS assistance information    PEIPS assistance information 9.11.3.80    O    TLV    3-n */
    ELEM_OPT_TLV(0x1F, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PEIPS_ASSIST_INFO, " - Updated");
    /* 73    NSAG information    NSAG information 9.11.3.87    O    TLV-E    9-3143 */
    ELEM_OPT_TLV_E(0x73, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NSAG_INFO, NULL);
    /* E-    Priority indicator    Priority indicator 9.11.3.91    O    TV    1 */
    ELEM_OPT_TV_SHORT(0xE0, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PRIO_IND, NULL);
    /* 4B    RAN timing synchronization    RAN timing synchronization 9.11.3.95    O    TLV    3 */
    ELEM_OPT_TLV(0x4B, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_RAN_TIMING_SYNC, NULL);
    /* 78    Extended LADN information    Extended LADN information 9.11.3.96    O    TLV-E    3-1787 */
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_EXT_LADN_INFO, NULL);
    /* 4C    Alternative NSSAI    Alternative NSSAI 9.11.3.97    O    TLV    2-146 */
    ELEM_OPT_TLV(0x4C, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_ALT_NSSAI, NULL);
    /* 7B    S-NSSAI location validity information    S-NSSAI location validity information 9.11.3.100    O    TLV-E    17-38611 */
    ELEM_OPT_TLV_E(0x7B, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_ALT_NSSAI, NULL);
    /* 5B    S-NSSAI time validity information    S-NSSAI time validity information 9.11.3.101    O    TLV    23-257 */
    ELEM_OPT_TLV(0x5B, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_S_NSSAI_TIME_VALID_INFO, NULL);
    /* 4F    Maximum time offset    GPRS timer 3 9.11.2.5    O    TLV    3 */
    ELEM_OPT_TLV(0x4F, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Maximum time offset");
    /* 74    Partially allowed NSSAI    Partial NSSAI 9.11.3.103    O    TLV-E    3-808 */
    ELEM_OPT_TLV_E(0x74, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PARTIAL_NSSAI, " - Partially allowed NSSAI");
    /* 7A    Partially rejected NSSAI    Partial NSSAI 9.11.3.103    O    TLV-E    3-808 */
    ELEM_OPT_TLV_E(0x7A, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PARTIAL_NSSAI, " - Partially rejected NSSAI");
    /* 5C    Feature authorization indication    Feature authorization indication 9.11.3.105    O    TLV    3-257 */
    ELEM_OPT_TLV(0x5C, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_FEAT_AUTH_IND, NULL);
    /* 61    On-demand NSSAI    On-demand NSSAI 9.11.3.108    O    TLV    5-210 */
    ELEM_OPT_TLV(0x61, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_ON_DEMAND_NSSAI, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.20 Configuration update complete
 */
static void
nas_5gs_mm_conf_update_comp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* No Data */
    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);
}
/*
 * 8.2.21 Identity request
 */
static void
nas_5gs_mm_id_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*     Identity type    5GS identity type 9.11.3.3    M    V    1/2 */
    /* Spare half octet    Spare half octet 9.5    M    V    1/2 */
    proto_tree_add_item(tree, hf_nas_5gs_spare_half_octet, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_IDENTITY_TYPE, NULL, ei_nas_5gs_missing_mandatory_element);


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.22 Identity response
 */
static void
nas_5gs_mm_id_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Mobile identity  5GS mobile identity 9.11.3.4    M    LV-E    3-n  */
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_MOBILE_ID, NULL, ei_nas_5gs_missing_mandatory_element);


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.23 Notification
 */
static void
nas_5gs_mm_notification(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Access type    Access type 9.11.2.1A    M    V    1/2 DE_NAS_5GS_ACCESS_TYPE */
    /* Spare half octet    Spare half octet 9.5    M    V    1/2  */
    proto_tree_add_item(tree, hf_nas_5gs_spare_half_octet, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_ACCESS_TYPE, NULL, ei_nas_5gs_missing_mandatory_element);


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.24 Notification response
 */
static void
nas_5gs_mm_notification_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 50    PDU session status    PDU session status 9.11.3.40    O    TLV    4-34 */
    ELEM_OPT_TLV(0x50, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PDU_SES_STATUS, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.25 Security mode command
 */
static void
nas_5gs_mm_sec_mode_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: network to UE */
    /*Selected NAS security algorithms    NAS security algorithms     9.11.3.34    M    V    1  */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_SEC_ALGO, NULL, ei_nas_5gs_missing_mandatory_element);
    /*ngKSI     NAS key set identifier 9.11.3.32    M    V    1/2  */
    /* Spare half octet    Spare half octet     9.5    M    V    1/2 */
    proto_tree_add_item(tree, hf_nas_5gs_spare_half_octet, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_KEY_SET_ID, " - ngKSI", ei_nas_5gs_missing_mandatory_element);
    /*Replayed UE security capabilities    UE security capability     9.11.3.54    M    LV    3-5*/
    ELEM_MAND_LV(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_UE_SEC_CAP, " - Replayed UE security capabilities", ei_nas_5gs_missing_mandatory_element);
    /*E-    IMEISV request    IMEISV request     9.11.3.28    O    TV    1*/
    ELEM_OPT_TV_SHORT(0xE0, NAS_PDU_TYPE_EMM, DE_EMM_IMEISV_REQ, NULL);
    /*57    Selected EPS NAS security algorithms    EPS NAS security algorithms 9.11.3.25    O    TV    2 */
    ELEM_OPT_TV(0x57, NAS_PDU_TYPE_EMM, DE_EMM_NAS_SEC_ALGS, " - Selected EPS NAS security algorithms");
    /*36    Additional 5G security information    Additional 5G security information 9.11.3.12    O    TLV    3 */
    ELEM_OPT_TLV(0x36, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_ADD_5G_SEC_INF, NULL);
    /*78    EAP message    EAP message     9.10.2.2    O    TLV-E    7*/
    ELEM_OPT_TLV_E(0x78,  NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL);
    /*38    ABBA    ABBA 9.11.3.10    O    TLV    4-n */
    ELEM_OPT_TLV(0x38, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_ABBA, NULL);
    /*19    Replayed S1 UE security capabilities    S1 UE security capability 9.11.3.48A    O    TLV    4-7 */
    ELEM_OPT_TLV(0x19, NAS_PDU_TYPE_EMM, DE_EMM_UE_SEC_CAP, " - Replayed S1 UE security capabilities");
    /* 55    AUN3 device security key    AUN3 device security key 9.11.3.107    O    TLV    36-257 */
    ELEM_OPT_TLV(0x55, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_AUN3_DEVICE_SEC_KEY, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.26 Security mode complete
 */
static void
nas_5gs_mm_sec_mode_comp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 77    IMEISV    5G mobile identity 9.11.3.4    O    TLV-E    11 */
    ELEM_OPT_TLV_E(0x77, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_MOBILE_ID, NULL);
    /* 71    NAS message container    NAS message container 9.11.3.33    O    TLV-E    4-n */
    ELEM_OPT_TLV_E(0x71, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_MSG_CONT, NULL);
    /* 78    non-IMEISV PEI    5GS mobile identity 9.11.3.4    O    TLV-E    7-n */
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GS_MOBILE_ID, " - non-IMEISV PEI");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.27 Security mode reject
 */

static void
nas_5gs_mm_sec_mode_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 5GMM cause    5GMM cause 9.11.3.2    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_element);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.28    Security protected 5GS NAS message
 */

/*
 * 8.2.29 5GMM status
 */

static void
nas_5gs_mm_5gmm_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: both*/
    /* 5GMM cause    5GMM cause 9.11.3.2    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_5GMM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_element);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.30    Control Plane Service request
 */

static void
nas_5gs_mm_control_plane_service_req(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* UE to network */
    pinfo->link_dir = P2P_DIR_UL;

    /*     Control plane service type    Control plane service type 9.11.3.18D    M    V    1/2 */
    /*     ngKSI     NAS key set identifier 9.11.3.32    M    V    1/2 */
    ELEM_MAND_VV_SHORT(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_CTRL_PLANE_SERVICE_TYPE, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_KEY_SET_ID_H1, ei_nas_5gs_missing_mandatory_element);
    /* 6F    CIoT small data container    CIoT small data container 9.11.3.18B    O    TLV    4-257 */
    ELEM_OPT_TLV(0x6f, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_CIOT_SMALL_DATA_CONT, NULL);
    /* 8-    Payload container type    Payload container type 9.11.3.40    O    TV    1 */
    ELEM_OPT_TV_SHORT(0x80, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PLD_CONT_TYPE, NULL);
    /* 7B    Payload container    Payload container 9.11.3.39    O    TLV-E    4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PLD_CONT, NULL);
    /* 12    PDU session ID    PDU session identity 2 9.11.3.41    C    TV    2 */
    ELEM_OPT_TV(0x12, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PDU_SES_ID_2, " - PDU session ID");
    /* 50    PDU session status    PDU session status 9.11.3.44    O    TLV    4-34 */
    ELEM_OPT_TLV(0x50, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PDU_SES_STATUS, NULL);
    /* F-    Release assistance indication    Release assistance indication 9.11.3.46A    O    TV    1  */
    ELEM_OPT_TV_SHORT(0xF0, NAS_PDU_TYPE_ESM, DE_ESM_REL_ASSIST_IND, NULL);
    /* 40    Uplink data status    Uplink data status 9.11.3.57    O    TLV    4-34 */
    ELEM_OPT_TLV(0x40, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_UL_DATA_STATUS, NULL);
    /* 71    NAS message container    NAS message container 9.11.3.33    O    TLV-E    4-n */
    ELEM_OPT_TLV_E(0x71, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_NAS_MSG_CONT, NULL);
    /* 24    Additional information    Additional information 9.11.2.1    O    TLV    3-n */
    ELEM_OPT_TLV_E(0x71, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_ADD_INF, NULL);
    /* 25    Allowed PDU session status    Allowed PDU session status 9.11.3.11    O    TLV    4-34 */
    ELEM_OPT_TLV(0x25, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_ALLOW_PDU_SES_STS, NULL);
    /* 29    UE request type    UE request type 9.11.3.76    O    TLV    3 */
    ELEM_OPT_TLV(0x29, NAS_PDU_TYPE_EMM, DE_EMM_UE_REQUEST_TYPE, NULL);
    /* 28    Paging restriction    Paging restriction 9.11.3.77    O    TLV    3-35 */
    ELEM_OPT_TLV(0x28, NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PAGING_RESTRICTION, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.31    Network slice-specific authentication command
 */
static void
nas_5gs_mm_nw_slice_spec_auth_cmd(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* network to UE */
    /* S-NSSAI    S-NSSAI 9.11.2.8    M    LV    2-5 */
    ELEM_MAND_LV(NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_S_NSSAI, NULL, ei_nas_5gs_missing_mandatory_element);
    /* EAP message    EAP message 9.11.2.2    M    LV-E    6-1502 */
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL, ei_nas_5gs_missing_mandatory_element);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.32    Network slice-specific authentication complete
 */
static void
nas_5gs_mm_nw_slice_spec_auth_comp(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* UE to network */
    /* S-NSSAI    S-NSSAI 9.11.2.8    M    LV    2-5 */
    ELEM_MAND_LV(NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_S_NSSAI, NULL, ei_nas_5gs_missing_mandatory_element);
    /* EAP message    EAP message 9.11.2.2    M    LV-E    6-1502 */
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL, ei_nas_5gs_missing_mandatory_element);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.33    Network slice-specific authentication result
 */
static void
nas_5gs_mm_nw_slice_spec_auth_res(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* network to UE */
    /* S-NSSAI    S-NSSAI 9.11.2.8    M    LV    2-5 */
    ELEM_MAND_LV(NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_S_NSSAI, NULL, ei_nas_5gs_missing_mandatory_element);
    /* EAP message    EAP message 9.11.2.2    M    LV-E    6-1502 */
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL, ei_nas_5gs_missing_mandatory_element);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.2.34    Relay key request
 */
static void
nas_5gs_mm_relay_key_request(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* UE to network */
    /* PRTI    ProSe relay transaction identity 9.11.3.88    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PROSE_RELAY_TRANS_ID, NULL, ei_nas_5gs_missing_mandatory_element);
    /* Relay key request parameters    Relay key request parameters 9.11.3.89    M    LV-E    22-65537 */
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_RELAY_KEY_REQ_PARAMS, NULL, ei_nas_5gs_missing_mandatory_element);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);
}

/*
 * 8.2.35    Relay key accept
 */
static void
nas_5gs_mm_relay_key_accept(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* network to UE */
    /* PRTI    ProSe relay transaction identity 9.11.3.88    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PROSE_RELAY_TRANS_ID, NULL, ei_nas_5gs_missing_mandatory_element);
    /* Relay key response parameters    Relay key response parameters 9.11.3.90    M    LV-E    51-65537 */
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_RELAY_KEY_REQ_PARAMS, NULL, ei_nas_5gs_missing_mandatory_element);
    /* 78    EAP message    EAP message 9.10.2.2    O    TLV-E    7 - 1503 */
    ELEM_OPT_TLV_E(0x78,  NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);
}

/*
 * 8.2.36    Relay key reject
 */
static void
nas_5gs_mm_relay_key_reject(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* network to UE */
    /* PRTI    ProSe relay transaction identity 9.11.3.88    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PROSE_RELAY_TRANS_ID, NULL, ei_nas_5gs_missing_mandatory_element);
    /* 78    EAP message    EAP message 9.10.2.2    O    TLV-E    7 - 1503 */
    ELEM_OPT_TLV_E(0x78,  NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);
}

/*
 * 8.2.37    Relay authentication request
 */
static void
nas_5gs_mm_relay_authentication_request(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* network to UE */
    /* PRTI    ProSe relay transaction identity 9.11.3.88    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PROSE_RELAY_TRANS_ID, NULL, ei_nas_5gs_missing_mandatory_element);
    /* EAP message    EAP message 9.10.2.2    O    LV-E    6 - 1502 */
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL, ei_nas_5gs_missing_mandatory_element);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);
}

/*
 * 8.2.38    Relay authentication response
 */
static void
nas_5gs_mm_relay_authentication_response(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* UE to network */
    /* PRTI    ProSe relay transaction identity 9.11.3.88    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_MM, DE_NAS_5GS_MM_PROSE_RELAY_TRANS_ID, NULL, ei_nas_5gs_missing_mandatory_element);
    /* EAP message    EAP message 9.10.2.2    O    LV-E    6 - 1502 */
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL, ei_nas_5gs_missing_mandatory_element);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);
}

/* 8.3 5GS session management messages */

/*
 * 8.3.1 PDU session establishment request
 */
static void
nas_5gs_sm_pdu_ses_est_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: UE to network */
    pinfo->link_dir = P2P_DIR_UL;

    /*Integrity protection maximum data rate    Integrity protection maximum data rate 9.11.4.7    M    V    2*/
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_INT_PROT_MAX_DATA_RTE, NULL, ei_nas_5gs_missing_mandatory_element);
    /*9-    PDU session type    PDU session type     9.11.4.5    O    TV    1*/
    ELEM_OPT_TV_SHORT(0x90, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_PDU_SESSION_TYPE, NULL);
    /*A-    SSC mode    SSC mode     9.11.4.9    O    TV    1*/
    ELEM_OPT_TV_SHORT(0xa0, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_SSC_MODE, NULL);
    /*28    5GSM capability    5GSM capability     9.11.4.10    O    TLV    3-15 */
    ELEM_OPT_TLV(0x28, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAP, NULL);
    /*55    Maximum number of supported packet filter    Maximum number of supported packet filter   9.11.4.9    O    TV    3*/
    ELEM_OPT_TV(0x55, NAS_5GS_PDU_TYPE_SM,  DE_NAS_5GS_SM_MAX_NUM_SUP_PKT_FLT, NULL);
    /* B-    Always-on PDU session requested    Always-on PDU session requested 9.11.4.4    O    TV    1 */
    ELEM_OPT_TV_SHORT(0xB0, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_ALWAYS_ON_PDU_SES_REQ, NULL);
    /*39    SM PDU DN request container    SM PDU DN request container 9.11.4.15    O    TLV    3-255 */
    ELEM_OPT_TLV(0x39, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_PDU_DN_REQ_CONT, NULL);
    /*7B    Extended protocol configuration options    Extended protocol configuration options     9.11.4.2    O    TLV-E    4-65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);
    /* 66    Header compression configuration    Header compression configuration 9.11.4.24    O    TLV    5-257 */
    ELEM_OPT_TLV(0x66, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_IP_HDR_COMP_CONF, NULL);
    /* 6E    DS-TT Ethernet port MAC address    DS-TT Ethernet port MAC address 9.11.4.25    O    TLV    8 */
    ELEM_OPT_TLV(0x6E, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_DS_TT_ETH_PORT_MAC_ADDR, NULL);
    /* 6F    UE-DS-TT residence time    UE-DS-TT residence time 9.11.4.26    O    TLV    10 */
    ELEM_OPT_TLV(0x6F, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_UE_DS_TT_RESIDENCE_T, NULL);
    /* 74    Port management information container    Port management information container 9.11.4.27    O    TLV-E    8-65538 */
    ELEM_OPT_TLV_E(0x74, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_PORT_MGNT_INF_CONT, NULL);
    /* 1F    Ethernet header compression configuration    Ethernet header compression configuration 9.11.4.28    O    TLV    3 */
    ELEM_OPT_TLV(0x1F, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_ETH_HDR_COMP_CONF, NULL);
    /* 29    Suggested interface identifier    PDU address 9.11.4.10    O    TLV    11 */
    ELEM_OPT_TLV(0x29, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_PDU_ADDRESS, " - Suggested interface identifier");
    /* 72    Service-level-AA container    Service-level-AA container 9.11.2.10    O    TLV-E    4-65538 */
    ELEM_OPT_TLV_E(0x72, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_SERVICE_LEVEL_AA_CONT, NULL);
    /* 70    Requested MBS container    Requested MBS container 9.11.4.30    O    TLV-E    8-65538 */
    ELEM_OPT_TLV_E(0x70, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_REQ_MBS_CONT, NULL);
    /* 34    PDU session pair ID    PDU session pair ID 9.11.4.32    O    TLV    3 */
    ELEM_OPT_TLV(0x34, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_PDU_SESSION_PAIR_ID, NULL);
    /* 35    RSN    RSN 9.11.4.33    O    TLV    3 */
    ELEM_OPT_TLV(0x35, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_RSN, NULL);
    /* 36    URSP rule enforcement reports    URSP rule enforcement reports 9.11.4.38    O    TLV    4-n */
    ELEM_OPT_TLV(0x36, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_URSP_RULE_ENFORCE_REPORTS, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.2 PDU session establishment accept
 */
static void
nas_5gs_sm_pdu_ses_est_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: network to UE */
    pinfo->link_dir = P2P_DIR_DL;

    /*Selected SSC mode    SSC mode 9.11.4.9    M    V    1/2 H1*/
    proto_tree_add_item(tree, hf_nas_5gs_sm_sel_sc_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    /*Selected PDU session type    PDU session type 9.11.4.5    M    V    1/2 H0*/
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_PDU_SESSION_TYPE, " - Selected PDU session type", ei_nas_5gs_missing_mandatory_element);
    /*Authorized QoS rules    QoS rules 9.11.4.6    M    LV-E    2-65537 DE_NAS_5GS_SM_QOS_RULES*/
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_QOS_RULES, " - Authorized QoS rules", ei_nas_5gs_missing_mandatory_element);
    /*Session AMBR    Session-AMBR 9.11.4.14    M    LV    7 */
    ELEM_MAND_LV(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_SESSION_AMBR, NULL, ei_nas_5gs_missing_mandatory_element);
    /*59    5GSM cause    5GSM cause 9.11.4.2    O    TV    2*/
    ELEM_OPT_TV(0x59, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL);
    /*29    PDU address    PDU address 9.11.4.10    O    TLV    7 */
    ELEM_OPT_TLV(0x29, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_PDU_ADDRESS, NULL);
    /*56    RQ timer value    GPRS timer 9.10.2.3    O    TV    2*/
    ELEM_OPT_TV(0x56, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, " - RQ timer value");
    /*22    S-NSSAI    S-NSSAI 9.11.2.8    O    TLV    3-6*/
    ELEM_OPT_TLV(0x22, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_S_NSSAI, NULL);
    /* 8-    Always-on PDU session indication    Always-on PDU session indication 9.11.4.3    O    TV    1 */
    ELEM_OPT_TV_SHORT(0x80, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_ALWAYS_ON_PDU_SES_IND, NULL);
    /* 75    Mapped EPS bearer contexts    Mapped EPS bearer contexts 9.11.4.9    O    TLV-E    7-65538 */
    ELEM_OPT_TLV_E(0x75, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_MAPPED_EPS_B_CONT, NULL);
    /*78    EAP message    EAP message 9.11.3.14    O    TLV-E    7-1503*/
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL);
    /*79    Authorized QoS flow descriptions    QoS flow descriptions 9.11.4.12    O    TLV-E    6-65538 */
    ELEM_OPT_TLV_E(0x79, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_QOS_FLOW_DES, " - Authorized");
    /*7B    Extended protocol configuration options    Extended protocol configuration options 9.11.4.2    O    TLV-E    4-65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);
    /* 25    DNN    DNN 9.11.2.1B    O    TLV    3-102 */
    ELEM_OPT_TLV(0x25, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_DNN, NULL);
    /* 17    5GSM network feature support    5GSM network feature support 9.11.4.18    O    TLV    3-15  */
    ELEM_OPT_TLV(0x17, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_NW_FEATURE_SUP, NULL);
    /* 18    Serving PLMN rate control    Serving PLMN rate control 9.11.4.20    O    TLV    4  */
    ELEM_OPT_TLV(0x18, NAS_PDU_TYPE_ESM, DE_ESM_SERV_PLMN_RATE_CTRL, NULL);
    /* 77    ATSSS container    ATSSS container 9.11.4.22    O    TLV-E    3-65538  */
    ELEM_OPT_TLV_E(0x77, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_ATSSS_CONT, NULL);
    /* C-    Control plane only indication    Control plane only indication 9.11.4.23    O    TV    1  */
    ELEM_OPT_TV_SHORT(0xC0, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_CTL_PLANE_ONLY_IND, NULL);
    /* 66    IP header compression configuration    IP header compression configuration 9.11.4.24    O    TLV    5-257 */
    ELEM_OPT_TLV(0x66, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_IP_HDR_COMP_CONF, NULL);
    /* 1F    Ethernet header compression configuration    Ethernet header compression configuration 9.11.4.28    O    TLV    3 */
    ELEM_OPT_TLV(0x1F, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_ETH_HDR_COMP_CONF, NULL);
    /* 72    Service-level-AA container    Service-level-AA container 9.11.2.10    O    TLV-E    4-65538 */
    ELEM_OPT_TLV_E(0x72, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_SERVICE_LEVEL_AA_CONT, NULL);
    /* 71    Received MBS container    Received MBS container 9.11.4.31    O    TLV-E    8-65538 */
    ELEM_OPT_TLV_E(0x71, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_REC_MBS_CONT, NULL);
    /* 70    N3QAI    N3QAI 9.11.4.36    O    TLV-E    9-n */
    ELEM_OPT_TLV_E(0x70, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_N3QAI, NULL);
    /* 36    Protocol description    Protocol description 9.11.4.39    O    TLV-E    6-n */
    ELEM_OPT_TLV_E(0x36, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_PROT_DESC, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.3 PDU session establishment reject
 */

static void
nas_5gs_sm_pdu_ses_est_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: network to UE */
    pinfo->link_dir = P2P_DIR_DL;

    /* 5GSM cause    5GSM cause 9.11.4.2    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, " - ESM cause", ei_nas_5gs_missing_mandatory_element);
    /*37    Back-off timer value    GPRS timer 3 9.11.2.5    O    TLV    3 */
    ELEM_OPT_TLV(0x37, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Back-off timer value");
    /*F-    Allowed SSC mode    Allowed SSC mode 9.11.4.3    O    TV    1*/
    ELEM_OPT_TV_SHORT(0xF0, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_ALLOWED_SSC_MODE, NULL);
    /*78    EAP message    EAP message 9.11.3.14    O    TLV - E    7 - 1503*/
    ELEM_OPT_TLV_E(0x78,  NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL);
    /* 61    5GSM congestion re-attempt indicator    5GSM congestion re-attempt indicator 9.11.4.21    O    TLV    3 */
    ELEM_OPT_TLV(0x61, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CONG_RE_ATTEMPT_IND, NULL);
    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.11.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);
    /* 1D    Re-attempt indicator    Re-attempt indicator 9.11.4.17    O    TLV    3  */
    ELEM_OPT_TLV(0x1D, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_RE_ATTEMPT_IND, NULL);
    /* 72    Service-level-AA container    Service-level-AA container 9.11.2.10    O    TLV-E    4-65538 */
    ELEM_OPT_TLV_E(0x72, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_SERVICE_LEVEL_AA_CONT, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.4 PDU session authentication command
 */

static void
nas_5gs_sm_pdu_ses_auth_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: network to UE */
    pinfo->link_dir = P2P_DIR_DL;

    /*EAP message    EAP message 9.11.2.2    M    LV-E    6-1502 */
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL, ei_nas_5gs_missing_mandatory_element);

    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.11.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}
/*
 * 8.3.5 PDU session authentication complete
 */

static void
nas_5gs_sm_pdu_ses_auth_comp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: UE to network */
    pinfo->link_dir = P2P_DIR_UL;

    /*EAP message    EAP message 9.11.2.2    M    LV-E    6-1502 */
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL, ei_nas_5gs_missing_mandatory_element);

    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.11.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);


    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.6 PDU session authentication result
 */
static void
nas_5gs_sm_pdu_ses_auth_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: network to UE */
    pinfo->link_dir = P2P_DIR_DL;

    /*EAP message    EAP message 9.11.2.2    O    TLV-E    7-1503 */
    ELEM_OPT_TLV_E(0x78, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL);

    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.11.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 *8.3.7 PDU session modification request
 */

static void
nas_5gs_sm_pdu_ses_mod_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: UE to network */
    pinfo->link_dir = P2P_DIR_UL;

    /* 28    5GSM capability    5GSM capability 9.11.4.10    O    TLV    3-15 */
    ELEM_OPT_TLV(0x28, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAP, NULL);
    /* 59    5GSM cause    5GSM cause 9.11.4.2    O    TV    2 */
    ELEM_OPT_TV(0x59, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL);
    /* 55    Maximum number of supported packet filter    Maximum number of supported packet filter   9.11.4.6    O    TV    3*/
    ELEM_OPT_TV(0x55, NAS_5GS_PDU_TYPE_SM,  DE_NAS_5GS_SM_MAX_NUM_SUP_PKT_FLT, NULL);
    /* B-    Always-on PDU session requested    Always-on PDU session requested 9.11.4.4    O    TV    1 */
    ELEM_OPT_TV_SHORT(0xB0, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_ALWAYS_ON_PDU_SES_REQ, NULL);
    /* 13    Integrity protection maximum data rate    Integrity protection maximum data rate 9.11.4.7    O    TV    3 */
    ELEM_OPT_TV(0x13, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_INT_PROT_MAX_DATA_RTE, NULL);
    /* 7A    Requested QoS rules    QoS rules 9.11.4.6    O    TLV-E    3-65538 */
    ELEM_OPT_TLV_E(0x7A, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_QOS_RULES, " - Requested QoS rules");
    /* 79    Requested QoS flow descriptions    QoS flow descriptions 9.11.4.12    O    TLV-E    5-65538 */
    ELEM_OPT_TLV_E(0x79, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_QOS_FLOW_DES, " - Authorized");
    /* 75    Mapped EPS bearer contexts    Mapped EPS bearer contexts 9.11.4.8    O    TLV-E    7-65538 */
    ELEM_OPT_TLV_E(0x75, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_MAPPED_EPS_B_CONT, NULL);
    /* 7B    Extended protocol configuration options    Extended protocol configuration options    9.11.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);
    /* 74    Port management information container    Port management information container 9.11.4.27    O    TLV-E    4-65538 */
    ELEM_OPT_TLV_E(0x74, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_PORT_MGNT_INF_CONT, NULL);
    /* 66    IP header compression configuration    Header compression configuration 9.11.4.24    O    TLV    5-257 */
    ELEM_OPT_TLV(0x66, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_IP_HDR_COMP_CONF, NULL);
    /* 1F    Ethernet header compression configuration    Ethernet header compression configuration 9.11.4.28    O    TLV    3 */
    ELEM_OPT_TLV(0x1F, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_ETH_HDR_COMP_CONF, NULL);
    /* 70    Requested MBS container    Requested MBS container 9.11.4.30    O    TLV-E    8-65538 */
    ELEM_OPT_TLV_E(0x70, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_REQ_MBS_CONT, NULL);
    /* 72    Service-level-AA container    Service-level-AA container 9.11.2.10    O    TLV-E    4-65538 */
    ELEM_OPT_TLV_E(0x72, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_SERVICE_LEVEL_AA_CONT, NULL);
    /* 73    Non-3GPP delay budget    Non-3GPP delay budget 9.11.4.37    O    TLV-E    6-n */
    ELEM_OPT_TLV_E(0x73, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_N3GPP_DELAY_BUDGET, NULL);
    /* 36    URSP rule enforcement reports    URSP rule enforcement reports 9.11.4.38    O    TLV    4-n */
    ELEM_OPT_TLV(0x36, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_URSP_RULE_ENFORCE_REPORTS, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.8    PDU session modification reject
 */

static void
nas_5gs_sm_pdu_ses_mod_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: network to UE */
    pinfo->link_dir = P2P_DIR_DL;

    /* 5GSM cause    5GSM cause 9.11.4.2    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_element);

    /*37    Back-off timer value    GPRS timer 3 9.11.2.5    O    TLV    3 */
    ELEM_OPT_TLV(0x37, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Back-off timer value");

    /* 61    5GSM congestion re-attempt indicator    5GSM congestion re-attempt indicator 9.11.4.21    O    TLV    3 */
    ELEM_OPT_TLV(0x61, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CONG_RE_ATTEMPT_IND, NULL);

    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.11.4.6    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    /* 1D    Re-attempt indicator    Re-attempt indicator 9.11.4.17    O    TLV    3  */
    ELEM_OPT_TLV(0x1D, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_RE_ATTEMPT_IND, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
* 8.3.9 PDU session modification command
*/

static void
nas_5gs_sm_pdu_ses_mod_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: network to UE */
    pinfo->link_dir = P2P_DIR_DL;

    /*59    5GSM cause    5GSM cause 9.11.4.2    O    TV    2*/
    ELEM_OPT_TV(0x59, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL);
    /*2A    Session AMBR    Session-AMBR     9.11.4.14    O    TLV    8*/
    ELEM_OPT_TLV(0x2A, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_SESSION_AMBR, NULL);
    /*56    RQ timer value    GPRS timer     9.11.4.3    O    TV    2*/
    ELEM_OPT_TV(0x56, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, " - PDU session release time");
    /* 8-   Always-on PDU session indication    Always-on PDU session indication 9.11.4.3    O    TV    1 */
    ELEM_OPT_TV_SHORT(0x80, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_ALWAYS_ON_PDU_SES_IND, NULL);
    /*7A    Authorized QoS rules    QoS rules     9.11.4.6    O    TLV-E    3-65538*/
    ELEM_OPT_TLV_E(0x7A, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_QOS_RULES, " - Authorized QoS rules");
    /*75    Mapped EPS bearer contexts     Mapped EPS  bearer contexts     9.11.4.5    O    TLV-E    7-65538*/
    ELEM_OPT_TLV_E(0x75, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_MAPPED_EPS_B_CONT, NULL);
    /*79    Authorized QoS flow descriptions     QoS flow descriptions     9.11.4.12    O    TLV-E    6-65538*/
    ELEM_OPT_TLV_E(0x79, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_QOS_FLOW_DES, " - Authorized");
    /*7B    Extended protocol configuration options    Extended protocol configuration options     9.11.4.2    O    TLV-E    4-65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);
    /* 77    ATSSS container    ATSSS container 9.11.4.22    O    TLV-E    3-65538  */
    ELEM_OPT_TLV_E(0x77, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_ATSSS_CONT, NULL);
    /* 66    66    IP header compression configuration    IP header compression configuration 9.11.4.24    O    TLV    5-257  */
    ELEM_OPT_TLV(0x66, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_IP_HDR_COMP_CONF, NULL);
    /* 74    Port management information container    Port management information container 9.11.4.27    O    TLV-E    4-65538 */
    ELEM_OPT_TLV_E(0x74, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_PORT_MGNT_INF_CONT, NULL);
    /* 1E    Serving PLMN rate control    Serving PLMN rate control 9.11.4.20    O    TLV    4 */
    ELEM_OPT_TLV(0x1E, NAS_PDU_TYPE_ESM, DE_ESM_SERV_PLMN_RATE_CTRL, NULL);
    /* 1F    Ethernet header compression configuration    Ethernet header compression configuration 9.11.4.28    O    TLV    3 */
    ELEM_OPT_TLV(0x1F, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_ETH_HDR_COMP_CONF, NULL);
    /* 71    Received MBS container    Received MBS container 9.11.4.31    O    TLV-E    8-65538 */
    ELEM_OPT_TLV_E(0x71, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_REC_MBS_CONT, NULL);
    /* 72    Service-level-AA container    Service-level-AA container 9.11.2.10    O    TLV-E    4-65538 */
    ELEM_OPT_TLV_E(0x72, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_SERVICE_LEVEL_AA_CONT, NULL);
    /* 5A    Alternative S-NSSAI    S-NSSAI    9.11.2.8    O    TLV    3-10 */
    ELEM_OPT_TLV(0x5A, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_S_NSSAI, " - Alternative S-NSSAI");
    /* 70    N3QAI    N3QAI 9.11.4.36    O    TLV-E    9-n */
    ELEM_OPT_TLV_E(0x70, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_N3QAI, NULL);
    /* 38    Protocol description    Protocol description 9.11.4.39    O    TLV-E    6-n */
    ELEM_OPT_TLV_E(0x38, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_PROT_DESC, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.10 PDU session modification complete
 */

static void
nas_5gs_sm_pdu_ses_mod_comp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: UE to network */
    pinfo->link_dir = P2P_DIR_UL;

    /* 7B    Extended protocol configuration options    Extended protocol configuration options    9.11.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);
    /* 59    5GSM cause    5GSM cause 9.11.4.2    O    TV    2*/
    ELEM_OPT_TV(0x59, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL);
    /* 7B    Extended protocol configuration options    Extended protocol configuration options 9.11.4.6    O    TLV-E    4-65538 */
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);
    /* 74    Port management information container    Port management information container 9.11.4.27    O    TLV-E    4-65538 */
    ELEM_OPT_TLV_E(0x74, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_PORT_MGNT_INF_CONT, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.11 PDU session modification command reject
 */

static void
nas_5gs_sm_pdu_ses_mod_com_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: UE to network */
    pinfo->link_dir = P2P_DIR_UL;

    /* 5GSM cause    5GSM cause 9.11.4.2    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_element);
    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.11.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.12 PDU session release request
 */

static void
nas_5gs_sm_pdu_ses_rel_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: UE to network */
    pinfo->link_dir = P2P_DIR_UL;

    /* 59    5GSM cause    5GSM cause 9.11.4.2    O    TV    2 */
    ELEM_OPT_TV(0x59, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL);
    /* 7B    Extended protocol configuration options    Extended protocol configuration options    9.11.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.13 PDU session release reject
 */

static void
nas_5gs_sm_pdu_ses_rel_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: network to UE */
    pinfo->link_dir = P2P_DIR_DL;

    /* 5GSM cause    5GSM cause 9.11.4.2    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_element);
    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.11.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
 * 8.3.14 PDU session release command
 */

static void
nas_5gs_sm_pdu_ses_rel_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: network to UE */
    pinfo->link_dir = P2P_DIR_DL;

    /* 5GSM cause    5GSM cause 9.11.4.2    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_element);
    /*37    Back-off timer value    GPRS timer 3 9.11.2.5    O    TLV    3 */
    ELEM_OPT_TLV(0x37, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_3, " - Back-off timer value");
    /*78    EAP message    EAP message 9.10.2.2    O    TLV - E    7 - 1503*/
    ELEM_OPT_TLV_E(0x78,  NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL);
    /* 61    5GSM congestion re-attempt indicator    5GSM congestion re-attempt indicator 9.11.4.21    O    TLV    3 */
    ELEM_OPT_TLV(0x61, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CONG_RE_ATTEMPT_IND, NULL);
    /* 7B    Extended protocol configuration options    Extended protocol configuration options    9.11.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);
    /* D-    Access type    Access type 9.11.2.1A    O    TV    1 */
    ELEM_OPT_TV_SHORT(0xD0, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_ACCESS_TYPE, NULL);
    /* 72    Service-level-AA container    Service-level-AA container 9.11.2.10    O    TLV-E    4-65538 */
    ELEM_OPT_TLV_E(0x72, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_SERVICE_LEVEL_AA_CONT, NULL);
    /* 5A    Alternative S-NSSAI    S-NSSAI    9.11.2.8    O    TLV    3-10 */
    ELEM_OPT_TLV(0x5A, NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_S_NSSAI, " - Alternative S-NSSAI");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);

}

/*
* 8.3.15 PDU session release complete
*/

static void
nas_5gs_sm_pdu_ses_rel_comp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: UE to network */
    pinfo->link_dir = P2P_DIR_UL;

    /* 59    5GSM cause    5GSM cause 9.11.4.2    O    TV    2 */
    ELEM_OPT_TV(0x59, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL);
    /*7B    Extended protocol configuration options    Extended protocol configuration options    9.11.4.2    O    TLV - E    4 - 65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);
}

/*
 * 8.3.16 5GSM status
 */

static void
nas_5gs_sm_5gsm_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: both */
    /* 5GSM cause    5GSM cause 9.11.4.2    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL, ei_nas_5gs_missing_mandatory_element);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);
}

/*
 * 8.3.17 Service-level authentication command
 */

static void
nas_5gs_sm_serv_level_auth_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: network to UE */
    /* Service-level-AA container    Service-level-AA container 9.11.2.10    M    LV-E    5-n */
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_SERVICE_LEVEL_AA_CONT, NULL, ei_nas_5gs_missing_mandatory_element);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);
}

/*
 * 8.3.18 Service-level authentication complete
 */

static void
nas_5gs_sm_serv_level_auth_comp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: UE to network */
    /* Service-level-AA container    Service-level-AA container 9.11.2.10    M    LV-E    5-n */
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_SERVICE_LEVEL_AA_CONT, NULL, ei_nas_5gs_missing_mandatory_element);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);
}

/*
 * 8.3.19 Remote UE report
 */

static void
nas_5gs_sm_remote_ue_report(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: UE to network */
    /* 76    Remote UE context connected    Remote UE context list 9.11.4.29    O    TLV-E    16-65538 */
    ELEM_OPT_TLV_E(0x76, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_REMOTE_UE_CTX_LIST, " - Connected");
    /* 70    Remote UE context disconnected    Remote UE context list 9.11.4.29    O    TLV-E    16-65538 */
    ELEM_OPT_TLV_E(0x70, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_REMOTE_UE_CTX_LIST, " - Disconnected");

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);
}

/*
 * 8.3.20 Remote UE report response
 */

static void
nas_5gs_sm_remote_ue_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: network to UE */

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);
}

/* TS 29.502 6.1.6.4.4 n1SmInfoFromUe, n1SmInfoToUe, unknownN1SmInfo */

/*
 * 6.1.6.4.4-1 n1SmInfoFromUE
 */
static void
nas_5gs_n1_sm_info_from_ue(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: UE to network */
    pinfo->link_dir = P2P_DIR_UL;

    /*9-    PDU session type    PDU session type     9.11.4.5    O    TV    1*/
    ELEM_OPT_TV_SHORT(0x90, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_PDU_SESSION_TYPE, NULL);

    /*A-    SSC mode    SSC mode     9.11.4.9    O    TV    1*/
    ELEM_OPT_TV_SHORT(0xa0, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_SSC_MODE, NULL);

    /*55    Maximum number of supported packet filter    Maximum number of supported packet filter   9.11.4.9    O    TV    3*/
    ELEM_OPT_TV(0x55, NAS_5GS_PDU_TYPE_SM,  DE_NAS_5GS_SM_MAX_NUM_SUP_PKT_FLT, NULL);

    /* 13    Integrity protection maximum data rate    Integrity protection maximum data rate 9.11.4.7    O    TV    3 */
    ELEM_OPT_TV(0x13, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_INT_PROT_MAX_DATA_RTE, NULL);

    /*39    SM PDU DN request container    SM PDU DN request container 9.11.4.15    O    TLV    3-255 */
    ELEM_OPT_TLV(0x39, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_PDU_DN_REQ_CONT, NULL);

    /*7B    Extended protocol configuration options    Extended protocol configuration options     9.11.4.2    O    TLV-E    4-65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    /*78    EAP message    EAP message 9.10.2.2    O    TLV - E    7 - 1503*/
    ELEM_OPT_TLV_E(0x78,  NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL);

    /* 7A    Requested QoS rules    QoS rules 9.11.4.13    O    TLV-E    3-65538 */
    ELEM_OPT_TLV_E(0x7A, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_QOS_RULES, " - Requested QoS rules");

    /*79    Requested QoS flow descriptions     QoS flow descriptions     9.11.4.12    O    TLV-E    6-65538*/
    ELEM_OPT_TLV_E(0x79, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_QOS_FLOW_DES, " - Requested");

    /* 59    5GSM cause    5GSM cause 9.11.4.2    O    TV    2 */
    ELEM_OPT_TV(0x59, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL);

    /*28    5GSM capability    5GSM capability     9.11.4.10    O    TLV    3-15 */
    ELEM_OPT_TLV(0x28, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAP, NULL);

    /*75    Mapped EPS bearer contexts     Mapped EPS  bearer contexts     9.11.4.5    O    TLV-E    7-65538*/
    ELEM_OPT_TLV_E(0x75, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_MAPPED_EPS_B_CONT, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);
}

/*
 * 6.1.6.4.4-2 n1SmInfoToUE
 */
static void
nas_5gs_n1_sm_info_to_ue(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: network to UE*/
    pinfo->link_dir = P2P_DIR_DL;

    /*56    RQ timer value    GPRS timer     9.11.4.3    O    TV    2*/
    ELEM_OPT_TV(0x56, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, " - PDU session release time");

    /*78    EAP message    EAP message 9.10.2.2    O    TLV - E    7 - 1503*/
    ELEM_OPT_TLV_E(0x78,  NAS_5GS_PDU_TYPE_COMMON, DE_NAS_5GS_CMN_EAP_MESSAGE, NULL);

    /*F-    Allowed SSC mode    Allowed SSC mode 9.11.4.3    O    TV    1*/
    ELEM_OPT_TV_SHORT(0xF0, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_ALLOWED_SSC_MODE, NULL);

    /*7B    Extended protocol configuration options    Extended protocol configuration options     9.11.4.2    O    TLV-E    4-65538*/
    ELEM_OPT_TLV_E(0x7B, NAS_PDU_TYPE_ESM, DE_ESM_EXT_PCO, NULL);

    /* 59    5GSM cause    5GSM cause 9.11.4.2    O    TV    2 */
    ELEM_OPT_TV(0x59, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_5GSM_CAUSE, NULL);

    /*75    Mapped EPS bearer contexts     Mapped EPS  bearer contexts     9.11.4.5    O    TLV-E    7-65538*/
    ELEM_OPT_TLV_E(0x75, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_MAPPED_EPS_B_CONT, NULL);

    /* 77    ATSSS container    ATSSS container 9.11.4.22    O    TLV-E    3-65538  */
    ELEM_OPT_TLV_E(0x77, NAS_5GS_PDU_TYPE_SM, DE_NAS_5GS_SM_ATSSS_CONT, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);
}

/*
 * 6.1.6.4.4 unknownN1SmInfo
 */
static void
nas_5gs_unknown_n1_sm_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: network to UE*/
    pinfo->link_dir = P2P_DIR_DL;

    EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_nas_5gs_extraneous_data);
}

/* Traffic descriptor component type identifier */
static const value_string nas_5gs_ursp_traff_desc_component_type_values[] = {
    { 0x01, "Match-all type" },
    { 0x08, "OS Id + OS App Id type" },
    { 0x10, "IPv4 remote address type" },
    { 0x21, "IPv6 remote address/prefix length type" },
    { 0x30, "Protocol identifier/next header type" },
    { 0x50, "Single remote port type" },
    { 0x51, "Remote port range type" },
    { 0x52, "IP 3 tuple type" },
    { 0x60, "Security parameter index type" },
    { 0x70, "Type of service/traffic class type" },
    { 0x80, "Flow label type" },
    { 0x81, "Destination MAC address type" },
    { 0x83, "802.1Q C-TAG VID type" },
    { 0x84, "802.1Q S-TAG VID type" },
    { 0x85, "802.1Q C-TAG PCP/DEI type" },
    { 0x86, "802.1Q S-TAG PCP/DEI type" },
    { 0x87, "Ethertype type" },
    { 0x88, "DNN type" },
    { 0x90, "Connection capabilities type" },
    { 0x91, "Destination FQDN" },
    { 0x92, "Regular expression" },
    { 0xa0, "OS App Id type" },
    { 0xa1, "Destination MAC address range type"},
    { 0, NULL }
};

static const range_string nas_5gs_ursp_traff_desc_conn_cap_values[] = {
    { 0x01, 0x01, "IMS" },
    { 0x02, 0x02, "MMS" },
    { 0x04, 0x04, "SUPL" },
    { 0x08, 0x08, "Internet" },
    { 0x20, 0x3f, "Operator specific" },
    { 0, 0, NULL }
};

static void
de_nas_5gs_ursp_traff_desc(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
    int len = tvb_reported_length(tvb);
    uint32_t traff_desc;
    int offset = 0;
    uint32_t length, i;

    /*
    Traffic descriptor (octets v+5 to w)
    The traffic descriptor field is of variable size and contains a variable number (at least one) of traffic descriptor components.
    Each traffic descriptor component shall be encoded as a sequence of one octet traffic descriptor component type identifier
    and a traffic descriptor component value field. The traffic descriptor component type identifier shall be transmitted first.
    */
    while (offset < len) {
        proto_tree_add_item_ret_uint(tree, hf_nas_5gs_ursp_traff_desc, tvb, offset, 1, ENC_BIG_ENDIAN, &traff_desc);
        offset++;
        switch (traff_desc) {
        case 0x01:
            /* Match-all type*/
            return;
        case 0x08:
            /* For "OS Id + OS App Id type", the traffic descriptor component value field shall be encoded as
               a sequence of a sixteen octet OS Id field, a one octet OS App Id length field, and an OS App Id field.
               The OS Id field shall be transmitted first. The OS Id field contains a Universally Unique IDentifier (UUID)
               as specified in IETF RFC 4122 [16]. */
            proto_tree_add_item(tree, hf_nas_5gs_os_id, tvb, offset, 16, ENC_BIG_ENDIAN);
            offset += 16;
            proto_tree_add_item_ret_uint(tree, hf_nas_5gs_os_app_id_len, tvb, offset, 1, ENC_BIG_ENDIAN, &length);
            offset += 1;
            proto_tree_add_item(tree, hf_nas_5gs_os_app_id, tvb, offset, length, ENC_NA);
            offset += length;
            break;
        case 0x10:
            /* For "IPv4 remote address type", the traffic descriptor component value field shall be encoded as
                a sequence of a four octet IPv4 address field and a four octet IPv4 address mask field.
                The IPv4 address field shall be transmitted first. */
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_ipv4_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case 0x21:
            /* For "IPv6 remote address/prefix length type", the traffic descriptor component value field shall be encoded as
               a sequence of a sixteen octet IPv6 address field and one octet prefix length field.
               The IPv6 address field shall be transmitted first. */
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_ipv6, tvb, offset, 16, ENC_NA);
            offset += 16;
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_ipv6_prefix_len, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        case 0x30:
            /* For "protocol identifier/next header type", the traffic descriptor component value field shall be encoded as
               one octet which specifies the IPv4 protocol identifier or Ipv6 next header. */
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_next_hdr, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case 0x50:
            /* For "single remote port type", the traffic descriptor component value field shall be encoded as
               two octets which specify a port number. */
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_single_remote_port, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case 0x51:
            /* For "remote port range type", the traffic descriptor component value field shall be encoded as a sequence of
               a two octet port range low limit field and a two octet port range high limit field.
               The port range low limit field shall be transmitted first. */
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_remote_port_range_low, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_remote_port_range_high, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
            /* For "IP 3 tuple type", the traffic descriptor component value field shall be encoded as a
               sequence of a one octet IP 3 tuple information bitmap field where:
               - bit 1 set to zero indicates that the IPv4 address field is absent;
               - bit 1 set to one indicates that the IPv4 address field is present;
               - bit 2 set to zero indicates that the IPv6 remote address/prefix length field is absent;
               - bit 2 set to one indicates that the IPv6 remote address/prefix length field is present;
               - bit 3 set to zero indicates that the protocol identifier/next header field is absent;
               - bit 3 set to one indicates that the protocol identifier/next header field is present;
               - bit 4 set to zero indicates that the single remote port field is absent;
               - bit 4 set to one indicates that the single remote port field is present;
               - bit 5 set to zero indicates that the remote port range field is absent;
               - bit 5 set to one indicates that the remote port range field is present; and
               - bits 6,7, and 8 are spare bits;
               followed by a four octet IPv4 address field and a four octet IPv4 address mask field, if
               the IPv4 address field is present;
               followed by a sixteen octet IPv6 address field and one octet prefix length field, if the
               IPv6 remote address/prefix length field is present;
               followed by one octet which specifies the IPv4 protocol identifier or IPv6 next header, if
               the protocol identifier/next header field is present;
               followed by two octets which specify a port number, if the single remote port field is
               present;
               followed by a two octet port range low limit field and a two octet port range high limit
               field, if the remote port range field is present.
               The IP 3 tuple information bitmap field shall be transmitted first.
               The traffic descriptor component value field shall not contain both the IPv4 address
               field and the IPv6 remote address/prefix length field. If the traffic descriptor component
               value field contains both the IPv4 address field and the IPv6 remote address/prefix
               length field, the receiving entity shall ignore the URSP rule.
               The traffic descriptor component value field shall not contain both the single remote
               port field and the remote port range field. If the traffic descriptor component value field
               contains both the single remote port field and the remote port range field, the receiving
               entity shall ignore the URSP rule.
               The traffic descriptor component value field shall contain at least one of the IPv4
               address field, IPv6 remote address/prefix length field, the protocol identifier/next
               header field, the single remote port field and the remote port range field, otherwise the
               receiving entity shall ignore the URSP rule. */
        case 0x60:
            /* For "security parameter index type", the traffic descriptor component value field shall be encoded as
               four octets which specify the IPSec security parameter index. */
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_sec_param_index, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case 0x70:
            /* For "type of service/traffic class type", the traffic descriptor component value field shall be encoded as a
            sequence of a one octet type-of-service/traffic class field and a one octet type-of-service/traffic class mask field.
            The type-of-service/traffic class field shall be transmitted first. */
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_tos_tc, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_tos_tc_mask, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        case 0x80:
            /* For "flow label type", the traffic descriptor component value field shall be encoded as three octets
            which specify the IPv6 flow label. The bits 8 through 5 of the first octet shall be spare whereas the
            remaining 20 bits shall contain the IPv6 flow label. */
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_flow_label, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;
            break;
        case 0x81:
            /* For "destination MAC address type", the traffic descriptor component value field shall be encoded as
               6 octets which specify a MAC address. */
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_dest_mac_addr, tvb, offset, 6, ENC_NA);
            offset += 6;
            break;
        case 0x83:
            /* For "802.1Q C-TAG VID type", the traffic descriptor component value field shall be encoded as
               two octets which specify the VID of the customer-VLAN tag (C-TAG).
               The bits 8 through 5 of the first octet shall be spare whereas the remaining 12 bits shall contain the VID. */
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_ctag_vid, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case 0x84:
            /* For "802.1Q S-TAG VID type", the traffic descriptor component value field shall be encoded as
               two octets which specify the VID of the service-VLAN tag (S-TAG).
               The bits 8 through 5 of the first octet shall be spare whereas the remaining 12 bits shall contain the VID. */
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_stag_vid, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case 0x85:
            /* For "802.1Q C-TAG PCP/DEI type", the traffic descriptor component value field shall be encoded as
               one octet which specifies the 802.1Q C-TAG PCP and DEI. The bits 8 through 5 of the octet shall be spare,
               and the bits 4 through 2 contain the PCP and bit 1 contains the DEI. */
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_ctag_pcp, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_ctag_dei, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        case 0x86:
            /* For "802.1Q S-TAG PCP/DEI type", the traffic descriptor component value field shall be encoded as
               one octet which specifies the 802.1Q S-TAG PCP.
               The bits 8 through 5 of the octet shall be spare, and the bits 4 through 2 contain the PCP and bit 1 contains the DEI. */
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_stag_pcp, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_stag_dei, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        case 0x87:
            /* For "ethertype type", the traffic descriptor component value field shall be encoded as
               two octets which specify an ethertype. */
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_ethertype, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case 0x88:
            /* For "DNN type", the traffic descriptor component value field shall be encoded as
               a sequence of a one octet DNN length field and a DNN value field of a variable size.
               The DNN value contains an APN as defined in 3GPP TS 23.003 [4]. */
            proto_tree_add_item_ret_uint(tree, hf_nas_5gs_dnn_len, tvb, offset, 1, ENC_BIG_ENDIAN, &length);
            offset++;
            de_nas_5gs_cmn_dnn(tvb, tree, pinfo, offset, length, NULL, 0);
            offset += length;
            break;
        case 0x90:
            /* For "connection capabilities” type, the traffic descriptor component value field shall be encoded as
               a sequence of one octet for number of network capabilities followed by one or more octets,
               each containing a connection capability identifier encoded as follows:
               Bits
               8 7 6 5 4 3 2 1
               0 0 0 0 0 0 0 1 IMS
               0 0 0 0 0 0 1 0 MMS
               0 0 0 0 0 1 0 0 SUPL
               0 0 0 0 1 0 0 0 Internet
               All other values are spare. If received they shall be interpreted as unknown. */
            proto_tree_add_item_ret_uint(tree, hf_nas_5gs_ursp_traff_desc_conn_cap_len, tvb, offset, 1, ENC_NA, &length);
            offset += 1;
            for (i = 0; i < length; i++)
                proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_conn_cap, tvb, offset+i, 1, ENC_NA);
            offset += length;
            break;
        case 0x91:
            /* For "destination FQDN" type, the traffic descriptor component value field shall be encoded as
               a sequence of one octet destination FQDN length field and a destination FQDN value of variable size.
               The destination FQDN value field shall be encoded as defined in IETF RFC 1035 [12]. */
            proto_tree_add_item_ret_uint(tree, hf_nas_5gs_ursp_traff_desc_dest_fqdn_len, tvb, offset, 1, ENC_NA, &length);
            offset += 1;
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_dest_fqdn, tvb, offset, length, ENC_APN_STR|ENC_NA);
            offset += length;
            break;
            /* For "regular expression" type, the traffic descriptor component value field shall be
               encoded as a sequence of one octet regular expression length field and a regular
               expression value of variable size. The regular expression value field shall take the form
               of Extended Regular Expressions (ERE) as defined in chapter 9 in IEEE 1003.1-
               2004 Part 1 [19]. */
        case 0xa0:
            /* For "OS App Id type", the traffic descriptor component value field shall be encoded as
               a one octet OS App Id length field and an OS App Id field. */
            proto_tree_add_item_ret_uint(tree, hf_nas_5gs_os_app_id_len, tvb, offset, 1, ENC_BIG_ENDIAN, &length);
            offset += 1;
            proto_tree_add_item(tree, hf_nas_5gs_os_app_id, tvb, offset, length, ENC_NA);
            offset += length;
            break;
        case 0xa1:
            /* For "destination MAC address range type", the traffic descriptor component value field
               shall be encoded as a sequence of a 6 octet destination MAC address range low limit
               field and a 6 octet destination MAC address range high limit field. The destination MAC
               address range low limit field shall be transmitted first.*/
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_dest_mac_addr_range_low, tvb, offset, 6, ENC_NA);
            offset += 6;
            proto_tree_add_item(tree, hf_nas_5gs_ursp_traff_desc_dest_mac_addr_range_high, tvb, offset, 6, ENC_NA);
            offset += 6;
            break;
        default:
            proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, -1);
            return;
        }
    }
}

/*
Route selection descriptor contents (octets b+5 to c)
The route selection descriptor contents field is of variable size and contains a variable number (at least one)
of route selection descriptor components. Each route selection descriptor component shall be encoded as a sequence of
a one octet route selection descriptor component type identifier and
a route selection descriptor component value field.
The route selection descriptor component type identifier shall be transmitted first.

Route selection descriptor component type identifier
Bits
8 7 6 5 4 3 2 1
0 0 0 0 0 0 0 1    SSC mode type
0 0 0 0 0 0 1 0    S-NSSAI type
0 0 0 0 0 1 0 0    DNN type
0 0 0 0 1 0 0 0    PDU session type type
0 0 0 1 0 0 0 0    Preferred access type type
0 0 0 1 0 0 0 1    Multi-access preference type
0 0 1 0 0 0 0 0    Non-seamless non-3GPP offload indication type
0 1 0 0 0 0 0 0    Location criteria type
1 0 0 0 0 0 0 0    Time window type
1 0 0 0 0 0 0 1    5G ProSe layer-3 UE-to-network relay offload indication type
1 0 0 0 0 0 1 0    PDU session pair ID type (NOTE 5)
1 0 0 0 0 0 1 1    RSN type (NOTE 5)

All other values are spare. If received they shall be interpreted as unknown.

*/
static const value_string nas_5gs_ursp_r_sel_desc_comp_type_values[] = {
    { 0x01, "SSC mode" },
    { 0x02, "S-NSSAI" },
    { 0x04, "DNN" },
    { 0x08, "PDU session type" },
    { 0x10, "Preferred access type" },
    { 0x11, "Multi-access preference" },
    { 0x20, "Non-seamless non-3GPP offload indication" },
    { 0x40, "Location criteria type" },
    { 0x80, "Time window type" },
    { 0x81, "5G ProSe layer-3 UE-to-network relay offload type" },
    { 0x82, "PDU session pair ID type" },
    { 0x83, "RSN type" },
    { 0, NULL }
};

static void
de_nas_5gs_ursp_r_sel_desc(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
    int len = tvb_reported_length(tvb);
    uint32_t type_id;
    int offset = 0;
    uint32_t length;

    while (offset < len) {

        /* Route selection descriptor component type identifier */
        proto_tree_add_item_ret_uint(tree, hf_nas_5gs_ursp_ursp_r_sel_desc_comp_type, tvb, offset, 1, ENC_BIG_ENDIAN, &type_id);
        offset++;

        switch (type_id) {
        case 0x01: /* SSC mode*/
            /* For "SSC mode type", the route selection descriptor component value field shall be encoded as a
               one octet SSC mode field. The bits 8 through 4 of the octet shall be spare,
               and the bits 3 through 1 shall be encoded as the value part of the SSC mode information element
               defined in subclause 9.11.4.16 of 3GPP TS 24.501.
               The "SSC mode type" route selection descriptor component shall not appear more than once
               in the route selection descriptor.*/
            proto_tree_add_item(tree, hf_nas_5gs_sm_sc_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;
        case 0x02: /* S-NSSAI type*/
            /* For "S-NSSAI type", the route selection descriptor component value field shall be
             * encoded as a sequence of a one octet S-NSSAI length field and an S-NSSAI value
             * field of a variable size. The S-NSSAI value shall be encoded as the value part of the
             * S-NSSAI information element defined in clause 9.11.2.8 of 3GPP TS 24.501 [11], without
             * the mapped HPLMN SST field and without the mapped HPLMN SD field. */
            proto_tree_add_item_ret_uint(tree, hf_nas_5gs_mm_len_of_mapped_s_nssai, tvb, offset, 1, ENC_BIG_ENDIAN, &length);
            offset++;
            de_nas_5gs_cmn_s_nssai(tvb, tree, pinfo, offset, length, NULL, 0);
            offset += length;
            break;
        case 0x04: /* DNN */
            /* For "DNN type", the route selection descriptor component value field shall be encoded as a
               sequence of a one octet DNN length field and a DNN value field of a variable size.
               The DNN value contains an APN as defined in 3GPP TS 23.003.*/
            proto_tree_add_item_ret_uint(tree, hf_nas_5gs_dnn_len, tvb, offset, 1, ENC_BIG_ENDIAN, &length);
            offset++;
            de_nas_5gs_cmn_dnn(tvb, tree, pinfo, offset, length, NULL, 0);
            offset += length;
            break;
        case 0x08: /* PDU session type*/
            /* For "PDU session type type", the route selection descriptor component value field shall be encoded as a
               one octet PDU session type field. The bits 8 through 4 of the octet shall be spare, and the bits 3 through 1
               shall be encoded as the value part of the PDU session type information element defined in
               subclause 9.11.4.11 of 3GPP TS 24.501.
               The "PDU session type type" route selection descriptor component shall not appear more than once
               in the route selection descriptor.*/
            proto_tree_add_item(tree, hf_nas_5gs_sm_pdu_session_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;
        case 0x10: /* preferred access type type */
            /* For "preferred access type type", the route selection descriptor component value field shall be encoded as a
               one octet preferred access type field. The bits 8 through 3 shall be spare, and the bits 2 and 1 shall be
               encoded as the value part of the access type information element defined in subclause 9.11.2.1A of 3GPP TS 24.501.
               The "preferred access type type" route selection descriptor component shall not appear more than once
               in the route selection descriptor.*/
            proto_tree_add_bitmask_list(tree, tvb, offset, 1, nas_5gs_cmn_access_type_flags, ENC_BIG_ENDIAN);
            offset++;
            break;
        case  0x11: /* Multi-access preference */
            /* For "multi-access preference type", the route selection descriptor component value field shall be of zero length.
               The "multi-access preference type" route selection descriptor component shall not appear more than once
               in the route selection descriptor.
               The "multi-access preference type" route selection descriptor component in the route selection descriptor
               indicates the multi-access preference.*/
            break;
        case 0x20: /* non-seamless non-3GPP offload indication type */
            /* For "non-seamless non-3GPP offload indication type", the route selection descriptor component shall not include
               the route selection descriptor component value field.
               The "non-seamless non-3GPP offload indication type" route selection descriptor component shall not appear more than once
               in the route selection descriptor.
               If the "non-seamless non-3GPP offload indication type" route selection descriptor component is included
               in a route selection descriptor, there shall be no route selection descriptor component with a type other than
               "non-seamless non-3GPP offload indication type" in the route selection descriptor.*/
            break;
        default:
            proto_tree_add_expert(tree, pinfo, &ei_nas_5gs_ie_not_dis, tvb, offset, -1);
            return;
        }
    }

}
/* Dissect UE policy part encoded as specified in 3GPP TS 24.526 */
static void
de_nas_5gs_ue_policies_ursp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
    proto_tree* sub_tree, * traff_desc_sub_tree, *r_sel_list_tree, *r_sel_tree, *r_sel_desc_sub_tree;
    proto_item* item, *r_sel_list;
    uint32_t len = tvb_reported_length(tvb);
    uint32_t curr_offset = 0, offset;
    uint32_t list_len, traff_desc_len, r_sel_desc_lst_len, r_sel_desc_len, r_sel_desc_cont_len;

    int i = 0;
    while ((curr_offset) < len) {
        i++;
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_ue_policies_ursp, &item,
            "URSP rule %u", i);
        /* Length of URSP rule octet v octet v+1 */
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_ursp_rule_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &list_len);
        proto_item_set_len(item, list_len + 2);
        curr_offset += 2;

        /* Precedence value of URSP rule octet v+2 */
        proto_tree_add_item(sub_tree, hf_nas_5gs_ursp_rule_prec, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset += 1;

        /* Length of traffic descriptor octet v+3 octet v+4 */
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_ursp_traff_desc_lst_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &traff_desc_len);
        curr_offset += 2;

        /* Traffic descriptor octet v+5 octet w */
        traff_desc_sub_tree = proto_tree_add_subtree(sub_tree, tvb, curr_offset, traff_desc_len, ett_nas_5gs_ursp_traff_desc, NULL, "Traffic descriptor");
        de_nas_5gs_ursp_traff_desc(tvb_new_subset_length(tvb, curr_offset, traff_desc_len), pinfo, traff_desc_sub_tree);
        curr_offset += traff_desc_len;

        /* Length of route selection descriptor list octet w+1 octet w+2 */
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_ursp_r_sel_desc_lst_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &r_sel_desc_lst_len);
        curr_offset += 2;

        /* Route selection descriptor list */
        offset = curr_offset;
        r_sel_list = proto_tree_add_item(sub_tree, hf_nas_5gs_ursp_r_sel_desc_lst, tvb, curr_offset, r_sel_desc_lst_len, ENC_NA);
        r_sel_list_tree = proto_item_add_subtree(r_sel_list, ett_nas_5gs_usrp_r_sel_list);
        int j = 0;
        while ((curr_offset - offset) < r_sel_desc_lst_len) {
            j++;
            r_sel_tree = proto_tree_add_subtree_format(r_sel_list_tree, tvb, curr_offset, -1, ett_nas_5gs_usrp_r_sel, &item,
                                                       "Route selection descriptor %u", j);
            /* Length of route selection descriptor octet b octet b+1 */
            proto_tree_add_item_ret_uint(r_sel_tree, hf_nas_5gs_ursp_traff_desc_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &r_sel_desc_len);
            curr_offset += 2;
            /* Precedence value of route selection descriptor octet b + 2 */
            proto_tree_add_item(r_sel_tree, hf_nas_5gs_ursp_r_sel_des_prec, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            curr_offset++;

            /* Length of route selection descriptor contents octet b + 3 octet b + 4 */
            proto_tree_add_item_ret_uint(r_sel_tree, hf_nas_5gs_ursp_r_sel_des_cont_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &r_sel_desc_cont_len);
            curr_offset += 2;
            /* Route selection descriptor contents octet b+5 octet c */
            r_sel_desc_sub_tree = proto_tree_add_subtree(r_sel_tree, tvb, curr_offset, r_sel_desc_cont_len, ett_nas_5gs_ursp_r_sel_desc_cont, NULL, "Route selection descriptor contents");
            de_nas_5gs_ursp_r_sel_desc(tvb_new_subset_length(tvb, curr_offset, r_sel_desc_cont_len), pinfo, r_sel_desc_sub_tree);
            curr_offset += r_sel_desc_cont_len;
        }
        curr_offset = offset + r_sel_desc_lst_len;
    }

}

/* D.6.2 UE policy section management list */

static const value_string nas_5gs_updp_ue_policy_part_type_vals[] = {
    { 0x0,    "Reserved"},
    { 0x1,    "URSP"},
    { 0x2,    "ANDSP"},
    { 0,    NULL }
};

static uint16_t
de_nas_5gs_updp_ue_policy_section_mgm_lst(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree *sub_tree, *sub_tree2, *sub_tree3;
    proto_item* item;
    uint32_t curr_offset = offset;
    uint32_t sub_list_len, instr_len, policy_len;

    /* UE policy section management list contents Octet 4 - Octet z*/
    int i = 0;
    while ((curr_offset - offset) < len) {
        /* UE policy section management sublist (PLMN X) */
        i++;
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_updp_ue_policy_section_mgm_lst, &item,
            "UE policy section management sublist (PLMN %u)", i);
        /* Length of UE policy section management sublist */
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_updp_ue_pol_sect_sublst_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &sub_list_len);
        proto_item_set_len(item, sub_list_len + 2);
        curr_offset += 2;
        /* MCC digit 2    MCC digit 1
         * MNC digit 3    MCC digit 3
         * MNC digit 2    MNC digit 1
         */
        curr_offset = dissect_e212_mcc_mnc(tvb, pinfo, sub_tree, curr_offset, E212_NONE, true);
        /* UE policy section management sublist contents*/
        /* Instruction X */
        int j = 1;
        sub_list_len = sub_list_len - 3;
        while (sub_list_len > 0){
            sub_tree2 = proto_tree_add_subtree_format(sub_tree, tvb, curr_offset, -1, ett_nas_5gs_updp_ue_policy_section_mgm_sublst, &item,
                "Instruction %u", j);
            /* Instruction contents length */
            proto_tree_add_item_ret_uint(sub_tree2, hf_nas_5gs_updp_instr_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &instr_len);
            curr_offset += 2;
            /* UPSC */
            proto_tree_add_item(sub_tree2, hf_nas_5gs_updp_upsc, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
            curr_offset += 2;
            proto_item_set_len(item, instr_len + 2);
            /* UE policy section contents */
            sub_list_len = sub_list_len - instr_len - 2;
            instr_len = instr_len - 2;
            int k = 1;
            while (instr_len > 0) {
                uint32_t ue_policy_type;
                sub_tree3 = proto_tree_add_subtree_format(sub_tree2, tvb, curr_offset, -1, ett_nas_5gs_updp_ue_policy_section_mgm_sublst, &item,
                    "UE policy part %u", k);
                /* UE policy part contents length */
                proto_tree_add_item_ret_uint(sub_tree3, hf_nas_5gs_updp_policy_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &policy_len);
                curr_offset += 2;
                proto_item_set_len(item, policy_len + 2);
                /* UE policy part type */
                proto_tree_add_item_ret_uint(sub_tree3, hf_nas_5gs_updp_ue_policy_part_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &ue_policy_type);
                curr_offset++;
                /* UE policy part contents, This field contains a UE policy part encoded as specified in 3GPP TS 24.526 */
                switch (ue_policy_type) {
                case 1: /* 5.2 Encoding of UE policy part type URSP */
                    de_nas_5gs_ue_policies_ursp(tvb_new_subset_length(tvb, curr_offset, policy_len - 1), pinfo, sub_tree3);
                    break;
                default:
                    proto_tree_add_item(sub_tree3, hf_nas_5gs_updp_ue_policy_part_cont, tvb, curr_offset, policy_len - 1, ENC_NA);
                    break;
                }
                curr_offset += (policy_len - 1);
                instr_len = instr_len - (policy_len + 2);
                k++;
            }
            j++;
        }
    }

    return len;
}

/* D.6.3 UE policy section management result */
static uint16_t
de_nas_5gs_updp_ue_policy_section_mgm_res(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree *sub_tree, *sub_tree2;
    proto_item* item;
    uint32_t curr_offset = offset;
    uint32_t number_of_result;

    /* UE policy section management result contents Octet 4 - Octet z*/
    int i = 0;
    while ((curr_offset - offset) < len) {
        /* UE policy section management subresult (PLMN X) */
        i++;
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_updp_ue_policy_section_mgm_lst, &item,
            "UE policy section management subresult (PLMN %u)", i);
        /* Number of result */
        proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_updp_ue_pol_sect_subresult_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &number_of_result);
        curr_offset += 1;
        /* MCC digit 2    MCC digit 1
         * MNC digit 3    MCC digit 3
         * MNC digit 2    MNC digit 1
         */
        curr_offset = dissect_e212_mcc_mnc(tvb, pinfo, sub_tree, curr_offset, E212_NONE, true);
        /* UE policy section management subresult contents*/
        /* Result X */
        int j = 1;
        while (number_of_result > 0){
            sub_tree2 = proto_tree_add_subtree_format(sub_tree, tvb, curr_offset, -1, ett_nas_5gs_updp_ue_policy_section_mgm_sublst, &item,
                "Result %u", j);
            /* UPSC */
            proto_tree_add_item(sub_tree2, hf_nas_5gs_updp_upsc, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
            curr_offset += 2;
            /* Failed instruction order */
            proto_tree_add_item(sub_tree2, hf_nas_5gs_updp_failed_instruction_order, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
            curr_offset += 2;
            /* Cause */
            proto_tree_add_item(sub_tree2, hf_nas_5gs_upds_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            curr_offset += 1;
            j++;
            number_of_result--;
        }
    }

    return len;
}

/* D.6.4 UPSI list */
static uint16_t
de_nas_5gs_updp_upsi_list(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree* sub_tree;
    proto_item* item;
    uint32_t curr_offset = offset;
    uint32_t end_offset = offset + len;
    int32_t sublist_len;

    /* UPSI sublist (PLMN 1) */
    int i = 1;
    while (curr_offset < end_offset ) {
        sub_tree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nas_5gs_updp_upsi_list, &item,
            " UPSI sublist (PLMN %u)", i++);
        proto_tree_add_item_ret_int(sub_tree, hf_nas_5gs_upsi_sublist_len, tvb, curr_offset, 2, ENC_BIG_ENDIAN, &sublist_len);
        proto_item_set_len(item, sublist_len + 2);
        curr_offset += 2;
        curr_offset = dissect_e212_mcc_mnc(tvb, pinfo, sub_tree, curr_offset, E212_NONE, true);
        sublist_len -= 3;
        while (sublist_len > 0) {
            proto_tree_add_item(sub_tree, hf_nas_5gs_upsc, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
            curr_offset += 2;
            sublist_len -= 2;
        }
    }


    return len;
}

/* D.6.5 UE policy classmark */
static uint16_t
de_nas_5gs_updp_ue_policy_cm(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    static int* const flags_oct3[] = {
    &hf_nas_5gs_spare_b7,
    &hf_nas_5gs_spare_b6,
    &hf_nas_5gs_spare_b5,
    &hf_nas_5gs_spare_b4,
    &hf_nas_5gs_spare_b3,
    &hf_nas_5gs_spare_b2,
    &hf_nas_5gs_spare_b1,
    &hf_nas_5gs_sup_andsp,
    NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_oct3, ENC_NA);

    return len;
}

/* D.6.6 UE OS Id */
static uint16_t
de_nas_5gs_updp_ue_os_id(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset;
    /* OS Id:
    * The OS Id is coded as a sequence of a sixteen octet OS Id value field.
    *  The OS Id value field is defined as Universally Unique IDentifier (UUID) as specified in IETF RFC 4122 [35A].
    */
    proto_tree_add_item(tree, hf_nas_5gs_ue_os_id, tvb, curr_offset, len, ENC_BIG_ENDIAN);

    return len;
}

/* D.6.7 UE policy network classmark */
static true_false_string tfs_nas_5gs_nssui = {
    "UE is not allowed to accept URSP signalled by non-subscribed SNPNs",
    "UE is allowed to accept URSP signalled by non-subscribed SNPNs"
};

static uint16_t
de_nas_5gs_updp_ue_policy_nw_classmark(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_nas_5gs_spare_bits, tvb, (curr_offset << 3), 7, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_nssui, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    while ((curr_offset - offset) < len) {
        proto_tree_add_item(tree, hf_nas_5gs_spare_bits, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
    }

    return len;
}

/* 24.587 8.3.1 UPDS cause */
static const value_string nas_5gs_updp_upds_cause_vals[] = {
    { 0x1f, "Request rejected, unspecified"},
    { 0x20, "Service option not supported"},
    { 0x22, "Service option temporarily out of order"},
    { 0x23, "PTI already in use"},
    { 0x5f, "Semantically incorrect message"},
    { 0x60, "Invalid mandatory information"},
    { 0x61, "Message type non-existent or not implemented"},
    { 0x62, "Message type not compatible with the protocol state"},
    { 0x53, "Information element non-existent or not implemented"},
    { 0x64, "Conditional IE error"},
    { 0x6f, "Protocol error, unspecified"},
    { 0,    NULL }
};

static uint16_t
de_nas_5gs_updp_upds_cause(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo _U_,
    uint32_t offset, unsigned len,
    char* add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_upds_cause, tvb, offset, 1, ENC_BIG_ENDIAN);

    return len;
}

/* 24.587 8.3.2 Requested UE policies */
static uint16_t
de_nas_5gs_updp_req_ue_policies(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len _U_,
    char* add_string _U_, int string_len _U_)
{
    uint32_t curr_offset = offset;

    static int* const flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_spare_b4,
        &hf_nas_5gs_spare_b3,
        &hf_nas_5gs_spare_b2,
        &hf_nas_5gs_v2xuui,
        &hf_nas_5gs_v2xpc5i,
        NULL
    };

    proto_tree_add_bitmask_list(tree, tvb, curr_offset, 1, flags, ENC_BIG_ENDIAN);
    curr_offset++;

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_nas_5gs_extraneous_data);

    return (curr_offset - offset);
}

/* D.6 Information elements coding */
typedef enum
{
    DE_NAS_5GS_UPDP_UE_POLICY_SECTION_MGM_LST,          /* D.6.2 UE policy section management list */
    DE_NAS_5GS_UPDP_UE_POLICY_SECTION_MGM_RES,          /* D.6.3 UE policy section management result */
    DE_NAS_5GS_UPDP_UPSI_LIST,                          /* D.6.4 UPSI list */
    DE_NAS_5GS_UPDP_UE_POLICY_CM,                       /* D.6.5 UE policy classmark */
    DE_NAS_5GS_UPDP_UE_OS_ID,                           /* D.6.6 UE OS Id */
    DE_NAS_5GS_UPDP_UE_POLICY_NW_CLASSMARK,             /* D.6.7 UE policy network classmark */

    DE_NAS_5GS_UPDP_UPDS_CAUSE,                         /* 24.587 8.3.1 UPDS cause */
    DE_NAS_5GS_UPDP_REQ_UE_POLICIES,                    /* 24.587 8.3.2 Requested UE policies */

    DE_NAS_5GS_UPDP_NONE                                /* NONE */
}
nas_5gs_updp_elem_idx_t;

static const value_string nas_5gs_updp_elem_strings[] = {
    { DE_NAS_5GS_UPDP_UE_POLICY_SECTION_MGM_LST, "UE policy section management list" },                  /* D.6.2 UE policy section management list */
    { DE_NAS_5GS_UPDP_UE_POLICY_SECTION_MGM_RES, "UE policy section management result" },                /* D.6.3 UE policy section management result */
    { DE_NAS_5GS_UPDP_UPSI_LIST,                 "UPSI list" },                                          /* D.6.4 UPSI list */
    { DE_NAS_5GS_UPDP_UE_POLICY_CM,              "UE policy classmark" },                                /* D.6.5 UE policy classmark */
    { DE_NAS_5GS_UPDP_UE_OS_ID,                  "UE OS Id" },                                           /* D.6.6 UE OS Id */
    { DE_NAS_5GS_UPDP_UE_POLICY_NW_CLASSMARK,    "UE policy network classmark" },                        /* D.6.7 UE policy network classmark */

    { DE_NAS_5GS_UPDP_UPDS_CAUSE,                "UPDS cause" },                                         /* 24.587 8.3.1 UPDS cause */
    { DE_NAS_5GS_UPDP_REQ_UE_POLICIES,           "Requested UE policies" },                              /* 24.587 8.3.2 Requested UE policies */

    { 0, NULL }
};
value_string_ext nas_5gs_updp_elem_strings_ext = VALUE_STRING_EXT_INIT(nas_5gs_updp_elem_strings);

#define NUM_NAS_5GS_UPDP_ELEM array_length(nas_5gs_updp_elem_strings)
int ett_nas_5gs_updp_elem[NUM_NAS_5GS_UPDP_ELEM];

uint16_t(*nas_5gs_updp_elem_fcn[])(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo,
    uint32_t offset, unsigned len,
    char* add_string, int string_len) = {
        /*  5GS session management (5GSM) information elements */
        de_nas_5gs_updp_ue_policy_section_mgm_lst,          /* D.6.2 UE policy section management list */
        de_nas_5gs_updp_ue_policy_section_mgm_res,          /* D.6.3 UE policy section management result */
        de_nas_5gs_updp_upsi_list,                          /* D.6.4 UPSI list */
        de_nas_5gs_updp_ue_policy_cm,                       /* D.6.5 UE policy classmark */
        de_nas_5gs_updp_ue_os_id,                           /* D.6.6 UE OS Id */
        de_nas_5gs_updp_ue_policy_nw_classmark,             /* D.6.7 UE policy network classmark */

        de_nas_5gs_updp_upds_cause,                         /* 24.587 8.3.1 UPDS cause */
        de_nas_5gs_updp_req_ue_policies,                    /* 24.587 8.3.2 Requested UE policies */

        NULL,   /* NONE */
};


/* D.5.1 Manage UE policy command */
static void
nas_5gs_updp_manage_ue_policy_cmd(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: network to UE */
    pinfo->link_dir = P2P_DIR_DL;

    /* UE policy section management list    UE policy section management list     D.6.2    M    LV-E    11-65537 */
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_UPDP, DE_NAS_5GS_UPDP_UE_POLICY_SECTION_MGM_LST, NULL, ei_nas_5gs_missing_mandatory_element);

    /* 42    UE policy network classmark    UE policy network classmark D.6.7    O    TLV    3-5 */
    ELEM_OPT_TLV(0x42, NAS_5GS_PDU_TYPE_UPDP, DE_NAS_5GS_UPDP_UE_POLICY_NW_CLASSMARK, NULL);

}

/* D.5.2 Manage UE policy complete */
/*
Direction:        UE to network
 No data
*/

static void
nas_5gs_updp_manage_ue_policy_cmd_cmpl(tvbuff_t* tvb _U_, proto_tree* tree _U_, packet_info* pinfo, uint32_t offset _U_, unsigned len _U_)
{
    /*  Direction: UE to network */
    pinfo->link_dir = P2P_DIR_UL;

    /* No data */
}

/* D.5.3 Manage UE policy command reject*/
static void
nas_5gs_updp_manage_ue_policy_cmd_rej(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /*  Direction: UE to network */
    pinfo->link_dir = P2P_DIR_UL;

    /* UE policy section management result    UE policy section management result D.6.3    M    LV-E    11-65537 */
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_UPDP, DE_NAS_5GS_UPDP_UE_POLICY_SECTION_MGM_RES, NULL, ei_nas_5gs_missing_mandatory_element);

}


/* D.5.4 UE state indication */
static void
nas_5gs_updp_ue_state_indication(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: UE to network */
    pinfo->link_dir = P2P_DIR_UL;

    /* UPSI list    UPSI list     D.6.4    M    LV-E    9-65537*/
    ELEM_MAND_LV_E(NAS_5GS_PDU_TYPE_UPDP, DE_NAS_5GS_UPDP_UPSI_LIST, NULL, ei_nas_5gs_missing_mandatory_element);

    /* UE policy classmark    UE policy classmark     D.6.5    M    LV    2 - 4*/
    ELEM_MAND_LV(NAS_5GS_PDU_TYPE_UPDP, DE_NAS_5GS_UPDP_UE_POLICY_CM, NULL, ei_nas_5gs_missing_mandatory_element);

    /* 41    UE OS Id    OS Id D.6.6    O    TLV    18-242 */
    ELEM_OPT_TLV(0x41, NAS_5GS_PDU_TYPE_UPDP, DE_NAS_5GS_UPDP_UE_OS_ID, NULL);

}


/* 24.587 7.2.1 UE policy provisioning request */
static void
nas_5gs_updp_ue_policy_prov_req(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: UE to network */
    pinfo->link_dir = P2P_DIR_UL;

    /* Requested UE policies    Requested UE policies    8.3.2    M    LV    2-3 */
    ELEM_MAND_LV(NAS_5GS_PDU_TYPE_UPDP, DE_NAS_5GS_UPDP_REQ_UE_POLICIES, NULL, ei_nas_5gs_missing_mandatory_element);

}


/* 24.587 7.2.2 UE policy provisioning reject */
static void
nas_5gs_updp_ue_policy_prov_rej(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo, uint32_t offset, unsigned len)
{
    uint32_t curr_offset;
    uint32_t consumed;
    unsigned   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Direction: UE to network */
    pinfo->link_dir = P2P_DIR_DL;

    /* UPDS cause    UPDS cause    8.3.1    M    V    1 */
    ELEM_MAND_V(NAS_5GS_PDU_TYPE_UPDP, DE_NAS_5GS_UPDP_UPDS_CAUSE, NULL, ei_nas_5gs_missing_mandatory_element);

}


/* 9.7  Message type */

/* 5GS mobility management messages */
static const value_string nas_5gs_mm_message_type_vals[] = {
    { 0x41,    "Registration request"},
    { 0x42,    "Registration accept"},
    { 0x43,    "Registration complete"},
    { 0x44,    "Registration reject"},
    { 0x45,    "Deregistration request (UE originating)"},
    { 0x46,    "Deregistration accept (UE originating)"},
    { 0x47,    "Deregistration request (UE terminated)"},
    { 0x48,    "Deregistration accept (UE terminated)"},

    { 0x49,    "Not used in current version"},
    { 0x4a,    "Not used in current version" },
    { 0x4b,    "Not used in current version" },

    { 0x4c,    "Service request"},
    { 0x4d,    "Service reject"},
    { 0x4e,    "Service accept"},
    { 0x4f,    "Control plane service request"},

    { 0x50,    "Network slice-specific authentication command"},
    { 0x51,    "Network slice-specific authentication complete"},
    { 0x52,    "Network slice-specific authentication result"},
    { 0x53,    "Not used in current version"},
    { 0x54,    "Configuration update command"},
    { 0x55,    "Configuration update complete"},
    { 0x56,    "Authentication request"},
    { 0x57,    "Authentication response"},
    { 0x58,    "Authentication reject"},
    { 0x59,    "Authentication failure"},
    { 0x5a,    "Authentication result"},
    { 0x5b,    "Identity request"},
    { 0x5c,    "Identity response"},
    { 0x5d,    "Security mode command"},
    { 0x5e,    "Security mode complete"},
    { 0x5f,    "Security mode reject"},

    { 0x60,    "Not used in current version"},
    { 0x61,    "Not used in current version"},
    { 0x62,    "Not used in current version"},
    { 0x63,    "Not used in current version"},

    { 0x64,    "5GMM status"},
    { 0x65,    "Notification"},
    { 0x66,    "Notification response"},
    { 0x67,    "UL NAS transport"},
    { 0x68,    "DL NAS transport"},

    { 0x69,    "Relay key request"},
    { 0x6a,    "Relay key accept"},
    { 0x6b,    "Relay key reject"},
    { 0x6c,    "Relay authentication request"},
    { 0x6d,    "Relay authentication response"},
    { 0,    NULL }
};

static value_string_ext nas_5gs_mm_msg_strings_ext = VALUE_STRING_EXT_INIT(nas_5gs_mm_message_type_vals);

#define NUM_NAS_5GS_MM_MSG array_length(nas_5gs_mm_message_type_vals)
static int ett_nas_5gs_mm_msg[NUM_NAS_5GS_MM_MSG];
static void(*nas_5gs_mm_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len) = {
    nas_5gs_mm_registration_req,                /* 0x41    Registration request */
    nas_5gs_mm_registration_accept,             /* 0x42    Registration accept */
    nas_5gs_mm_registration_complete,           /* 0x43    Registration complete */
    nas_5gs_mm_registration_rej,                /* 0x44    Registration reject */
    nas_5gs_mm_de_reg_req_ue_orig,              /* 0x45    Deregistration request (UE originating) */
    NULL,                                       /* 0x46    Deregistration accept (UE originating) No data*/
    nas_5gs_mm_de_registration_req_ue_term,     /* 0x47    Deregistration request (UE terminated) */
    NULL,                                       /* 0x48    Deregistration accept (UE terminated) No data */

    nas_5gs_exp_not_dissected_yet,              /* 0x49    Not used in current version */
    nas_5gs_exp_not_dissected_yet,              /* 0x4a    Not used in current version */
    nas_5gs_exp_not_dissected_yet,              /* 0x4b    Not used in current version */

    nas_5gs_mm_service_req,                     /* 0x4c    Service request */
    nas_5gs_mm_service_rej,                     /* 0x4d    Service reject */
    nas_5gs_mm_service_acc,                     /* 0x4e    Service accept */
    nas_5gs_mm_control_plane_service_req,       /* 0x4f    Control plane service request */

    nas_5gs_mm_nw_slice_spec_auth_cmd,          /* 0x50    Network slice-specific authentication command */
    nas_5gs_mm_nw_slice_spec_auth_comp,         /* 0x51    Network slice-specific authentication complete */
    nas_5gs_mm_nw_slice_spec_auth_res,          /* 0x52    Network slice-specific authentication result */
    nas_5gs_exp_not_dissected_yet,              /* 0x53    Not used in current version */
    nas_5gs_mm_conf_upd_cmd,                    /* 0x54    Configuration update command */
    nas_5gs_mm_conf_update_comp,                /* 0x55    Configuration update complete */
    nas_5gs_mm_authentication_req,              /* 0x56    Authentication request */
    nas_5gs_mm_authentication_resp,             /* 0x57    Authentication response */
    nas_5gs_mm_authentication_rej,              /* 0x58    Authentication reject */
    nas_5gs_mm_authentication_failure,          /* 0x59    Authentication failure */
    nas_5gs_mm_authentication_result,           /* 0x5a    Authentication result */
    nas_5gs_mm_id_req,                          /* 0x5b    Identity request */
    nas_5gs_mm_id_resp,                         /* 0x5c    Identity response */
    nas_5gs_mm_sec_mode_cmd,                    /* 0x5d    Security mode command */
    nas_5gs_mm_sec_mode_comp,                   /* 0x5e    Security mode complete */
    nas_5gs_mm_sec_mode_rej,                    /* 0x5f    Security mode reject */

    nas_5gs_exp_not_dissected_yet,              /* 0x60    Not used in current version */
    nas_5gs_exp_not_dissected_yet,              /* 0x61    Not used in current version */
    nas_5gs_exp_not_dissected_yet,              /* 0x62    Not used in current version */
    nas_5gs_exp_not_dissected_yet,              /* 0x63    Not used in current version */

    nas_5gs_mm_5gmm_status,                     /* 0x64    5GMM status */
    nas_5gs_mm_notification,                    /* 0x65    Notification */
    nas_5gs_mm_notification_resp,               /* 0x66    Notification */
    nas_5gs_mm_ul_nas_transp,                   /* 0x67    UL NAS transport */
    nas_5gs_mm_dl_nas_transp,                   /* 0x68    DL NAS transport */

    nas_5gs_mm_relay_key_request,               /* 0x69    Relay key request */
    nas_5gs_mm_relay_key_accept,                /* 0x6a    Relay key accept */
    nas_5gs_mm_relay_key_reject,                /* 0x6b    Relay key reject */
    nas_5gs_mm_relay_authentication_request,    /* 0x6c    Relay authentication request */
    nas_5gs_mm_relay_authentication_response,   /* 0x6d    Relay authentication response */
    NULL,   /* NONE */

};


    /* 5GS session management messages */
    static const value_string nas_5gs_sm_message_type_vals[] = {

    { 0xc1,    "PDU session establishment request"},
    { 0xc2,    "PDU session establishment accept"},
    { 0xc3,    "PDU session establishment reject"},

    { 0xc4,    "Not used in current version"},

    { 0xc5,    "PDU session authentication command"},
    { 0xc6,    "PDU session authentication complete"},
    { 0xc7,    "PDU session authentication result"},

    { 0xc8,    "Not used in current version"},

    { 0xc9,    "PDU session modification request"},
    { 0xca,    "PDU session modification reject"},
    { 0xcb,    "PDU session modification command"},
    { 0xcc,    "PDU session modification complete"},
    { 0xcd,    "PDU session modification command reject"},

    { 0xce,    "Not used in current version"},
    { 0xcf,    "Not used in current version"},
    { 0xd0,    "Not used in current version"},

    { 0xd1,    "PDU session release request"},
    { 0xd2,    "PDU session release reject"},
    { 0xd3,    "PDU session release command"},
    { 0xd4,    "PDU session release complete"},

    { 0xd5,    "Not used in current version"},

    { 0xd6,    "5GSM status"},

    { 0xd7,    "Not used in current version"},

    { 0xd8,    "Service-level authentication command"},
    { 0xd9,    "Service-level authentication complete"},

    { 0xda,    "Remote UE report"},
    { 0xdb,    "Remote UE report response"},
    { 0,    NULL }
};
static value_string_ext nas_5gs_sm_msg_strings_ext = VALUE_STRING_EXT_INIT(nas_5gs_sm_message_type_vals);

#define NUM_NAS_5GS_SM_MSG array_length(nas_5gs_sm_message_type_vals)
static int ett_nas_5gs_sm_msg[NUM_NAS_5GS_SM_MSG];

static void(*nas_5gs_sm_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len) = {
    nas_5gs_sm_pdu_ses_est_req,            /* 0xc1     PDU session establishment request */
    nas_5gs_sm_pdu_ses_est_acc,            /* 0xc2     PDU session establishment accept */
    nas_5gs_sm_pdu_ses_est_rej,            /* 0xc3     PDU session establishment reject */

    nas_5gs_exp_not_dissected_yet,         /* 0xc4     Not used in current version */

    nas_5gs_sm_pdu_ses_auth_cmd,           /* 0xc5     PDU session authentication command */
    nas_5gs_sm_pdu_ses_auth_comp,          /* 0xc6     PDU session authentication complete */
    nas_5gs_sm_pdu_ses_auth_res,           /* 0xc7     PDU session authentication result */

    nas_5gs_exp_not_dissected_yet,         /* 0xc8     Not used in current version */

    nas_5gs_sm_pdu_ses_mod_req,            /* 0xc9     PDU session modification request */
    nas_5gs_sm_pdu_ses_mod_rej,            /* 0xca     PDU session modification reject */
    nas_5gs_sm_pdu_ses_mod_cmd,            /* 0xcb     PDU session modification command */
    nas_5gs_sm_pdu_ses_mod_comp,           /* 0xcc     PDU session modification complete */
    nas_5gs_sm_pdu_ses_mod_com_rej,        /* 0xcd     PDU session modification command reject */

    nas_5gs_exp_not_dissected_yet,         /* 0xce     Not used in current version */
    nas_5gs_exp_not_dissected_yet,         /* 0xcf     Not used in current version */
    nas_5gs_exp_not_dissected_yet,         /* 0xd0     Not used in current version */

    nas_5gs_sm_pdu_ses_rel_req,            /* 0xd1     PDU session release request */
    nas_5gs_sm_pdu_ses_rel_rej,            /* 0xd2     PDU session release reject */
    nas_5gs_sm_pdu_ses_rel_cmd,            /* 0xd3     PDU session release command */
    nas_5gs_sm_pdu_ses_rel_comp,           /* 0xd4     PDU session release complete */

    nas_5gs_exp_not_dissected_yet,         /* 0xd5     Not used in current version */

    nas_5gs_sm_5gsm_status,                /* 0xd6     5GSM status */

    nas_5gs_exp_not_dissected_yet,         /* 0xd7     Not used in current version */

    nas_5gs_sm_serv_level_auth_cmd,        /* 0xd8     Service-level authentication command */
    nas_5gs_sm_serv_level_auth_comp,       /* 0xd9     Service-level authentication complete */

    nas_5gs_sm_remote_ue_report,           /* 0xda     Remote UE report */
    nas_5gs_sm_remote_ue_resp,             /* 0xdb     Remote UE report response */

    NULL,   /* NONE */

};

/* Table D.6.1.1: UE policy delivery service message type */
static const value_string nas_5gs_updp_msg_strings[] = {
    { 0x0,    "Reserved"},
    { 0x1,    "MANAGE UE POLICY COMMAND"},
    { 0x2,    "MANAGE UE POLICY COMPLETE"},
    { 0x3,    "MANAGE UE POLICY COMMAND REJECT"},
    { 0x4,    "UE STATE INDICATION"},
    { 0x5,    "UE POLICY PROVISIONING REQUEST"},
    { 0x6,    "UE POLICY PROVISIONING REJECT"},
    { 0,    NULL }
};
static value_string_ext nas_5gs_updp_msg_strings_ext = VALUE_STRING_EXT_INIT(nas_5gs_updp_msg_strings);

#define NUM_NAS_5GS_UPDP_MSG array_length(nas_5gs_updp_msg_strings)
static int ett_nas_5gs_updp_msg[NUM_NAS_5GS_UPDP_MSG];

static void(*nas_5gs_updp_msg_fcn[])(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo, uint32_t offset, unsigned len) = {
    nas_5gs_exp_not_dissected_yet,         /* 0x0     Reserved */
    nas_5gs_updp_manage_ue_policy_cmd,     /* 0x1     MANAGE UE POLICY COMMAND */
    nas_5gs_updp_manage_ue_policy_cmd_cmpl,/* 0x2     MANAGE UE POLICY COMPLETE */
    nas_5gs_updp_manage_ue_policy_cmd_rej, /* 0x3     MANAGE UE POLICY COMMAND REJECT */
    nas_5gs_updp_ue_state_indication,      /* 0x4     UE STATE INDICATION */
    nas_5gs_updp_ue_policy_prov_req,       /* 0x5     UE POLICY PROVISIONING REQUEST */
    nas_5gs_updp_ue_policy_prov_rej,       /* 0x6     UE POLICY PROVISIONING REJECT */

    NULL,   /* NONE */

};

static void
get_nas_5gsmm_msg_params(uint8_t oct, const char **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn_p)
{
    int             idx;

    *msg_str = try_val_to_str_idx_ext((uint32_t)(oct & 0xff), &nas_5gs_mm_msg_strings_ext, &idx);
    *hf_idx = hf_nas_5gs_mm_msg_type;
    if (*msg_str != NULL) {
        *ett_tree = ett_nas_5gs_mm_msg[idx];
        *msg_fcn_p = nas_5gs_mm_msg_fcn[idx];
    }
}

static void
get_nas_5gssm_msg_params(uint8_t oct, const char **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn_p)
{
    int             idx;

    *msg_str = try_val_to_str_idx_ext((uint32_t)(oct & 0xff), &nas_5gs_sm_msg_strings_ext, &idx);
    *hf_idx = hf_nas_5gs_sm_msg_type;
    if (*msg_str != NULL) {
        *ett_tree = ett_nas_5gs_sm_msg[idx];
        *msg_fcn_p = nas_5gs_sm_msg_fcn[idx];
    }
}

static void
get_nas_5gs_updp_msg_params(uint8_t oct, const char** msg_str, int* ett_tree, int* hf_idx, msg_fcn* msg_fcn_p)
{
    int             idx;

    *msg_str = try_val_to_str_idx_ext((uint32_t)(oct & 0xff), &nas_5gs_updp_msg_strings_ext, &idx);
    *hf_idx = hf_nas_5gs_updp_msg_type;
    if (*msg_str != NULL) {
        *ett_tree = ett_nas_5gs_updp_msg[idx];
        *msg_fcn_p = nas_5gs_updp_msg_fcn[idx];
    }
}

static void
dissect_nas_5gs_sm_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    const char *msg_str;
    uint32_t     len;
    int          ett_tree;
    int          hf_idx;
    void(*msg_fcn_p)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len);
    uint8_t      oct;

    len = tvb_reported_length(tvb);

    /* Message type IE*/
    oct = tvb_get_uint8(tvb, offset);
    msg_fcn_p = NULL;
    ett_tree = -1;
    hf_idx = -1;
    msg_str = NULL;

    get_nas_5gssm_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &msg_fcn_p);

    if (msg_str) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, msg_str);
    }
    else {
        proto_tree_add_expert_format(tree, pinfo, &ei_nas_5gs_sm_unknown_msg_type, tvb, offset, 1, "Unknown Message Type 0x%02x", oct);
        return;
    }

    /*
    * Add NAS message name
    */
    proto_tree_add_item(tree, hf_idx, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /*
    * decode elements
    */
    if (msg_fcn_p == NULL)
    {
        if (tvb_reported_length_remaining(tvb, offset)) {
            proto_tree_add_item(tree, hf_nas_5gs_msg_elems, tvb, offset, len - offset, ENC_NA);
        }
    }
    else
    {
        (*msg_fcn_p)(tvb, tree, pinfo, offset, len - offset);
    }

}

static void
dissect_nas_5gs_mm_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{

    const char *msg_str;
    uint32_t     len;
    int          ett_tree;
    int          hf_idx;
    void(*msg_fcn_p)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len);
    uint8_t      oct;

    len = tvb_reported_length(tvb);

    /* Message type IE*/
    oct = tvb_get_uint8(tvb, offset);
    msg_fcn_p = NULL;
    ett_tree = -1;
    hf_idx = -1;
    msg_str = NULL;

    get_nas_5gsmm_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &msg_fcn_p);

    if (msg_str) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, msg_str);
    }
    else {
        proto_tree_add_expert_format(tree, pinfo, &ei_nas_5gs_mm_unknown_msg_type, tvb, offset, 1, "Unknown Message Type 0x%02x", oct);
        return;
    }

    /*
    * Add NAS message name
    */
    proto_tree_add_item(tree, hf_idx, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /*
    * decode elements
    */
    if (msg_fcn_p == NULL)
    {
        if (tvb_reported_length_remaining(tvb, offset)) {
            proto_tree_add_item(tree, hf_nas_5gs_msg_elems, tvb, offset, len - offset, ENC_NA);
        }
    }
    else
    {
        (*msg_fcn_p)(tvb, tree, pinfo, offset, len - offset);
    }

}

/* 6.1.6.4.4 n1SmInfoFromUe, n1SmInfoToUe, unknownN1SmInfo */
static void
dissect_nas_5gs_sm_info(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, const char *n1_msg_class)
{
    uint32_t     len;
    void(*msg_fcn_p)(tvbuff_t * tvb, proto_tree * tree, packet_info * pinfo, uint32_t offset, unsigned len);

    /* make entry in the Protocol column on summary display */
    col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "NAS-5GS");

    len = tvb_reported_length(tvb);
    msg_fcn_p = NULL;

    if (!strcmp(n1_msg_class, N1_SMINFO_FROM_UE)) {
        msg_fcn_p = nas_5gs_n1_sm_info_from_ue;
    } else if (!strcmp(n1_msg_class, N1_SMINFO_TO_UE)) {
        msg_fcn_p = nas_5gs_n1_sm_info_to_ue;
    } else if (!strcmp(n1_msg_class, UNKNOWN_N1_SMINFO)) {
        msg_fcn_p = nas_5gs_unknown_n1_sm_info;
    } else {
        proto_tree_add_expert_format(tree, pinfo, &ei_nas_5gs_sm_unknown_msg_type, tvb, offset, -1, "Unknown Message Type");
        return;
    }

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, n1_msg_class);

    /*
    * Add PDCP message name
    */
    proto_tree_add_item(tree, hf_nas_5gs_sm_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /*
    * decode elements
    */
    (*msg_fcn_p)(tvb, tree, pinfo, offset, len - offset);

}

/* UPDP */
/* D.6.1 UE policy delivery service message type */

void
dissect_nas_5gs_updp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

    const char* msg_str;
    uint32_t     len;
    int          ett_tree;
    int          hf_idx;
    void(*msg_fcn_p)(tvbuff_t * tvb, proto_tree * tree, packet_info * pinfo, uint32_t offset, unsigned len);
    uint8_t      oct;
    int          offset = 0;

    len = tvb_reported_length(tvb);

    /* 9.6  Procedure transaction identity
    * Bits 1 to 8 of the third octet of every 5GSM message contain the procedure transaction identity.
    * The procedure transaction identity and its use are defined in 3GPP TS 24.007
    * XXX Only 5GSM ?
    */
    proto_tree_add_item(tree, hf_nas_5gs_proc_trans_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Message type IE*/
    oct = tvb_get_uint8(tvb, offset);
    msg_fcn_p = NULL;
    ett_tree = -1;
    hf_idx = -1;
    msg_str = NULL;

    get_nas_5gs_updp_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &msg_fcn_p);

    if (msg_str) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, msg_str);
    }
    else {
        proto_tree_add_expert_format(tree, pinfo, &ei_nas_5gs_updp_unknown_msg_type, tvb, offset, 1, "Unknown Message Type 0x%02x", oct);
        return;
    }

    /*
    * Add PDCP message name
    */
    proto_tree_add_item(tree, hf_idx, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /*
    * decode elements
    */
    if (msg_fcn_p == NULL)
    {
        if (tvb_reported_length_remaining(tvb, offset)) {
            proto_tree_add_item(tree, hf_nas_5gs_msg_elems, tvb, offset, len - offset, ENC_NA);
        }
    }
    else
    {
        (*msg_fcn_p)(tvb, tree, pinfo, offset, len - offset);
    }

}


const value_string nas_5gs_pdu_session_id_vals[] = {
    { 0x00, "No PDU session identity assigned" },
    { 0x01, "PDU session identity value 1" },
    { 0x02, "PDU session identity value 2" },
    { 0x03, "PDU session identity value 3" },
    { 0x04, "PDU session identity value 4" },
    { 0x05, "PDU session identity value 5" },
    { 0x06, "PDU session identity value 6" },
    { 0x07, "PDU session identity value 7" },
    { 0x08, "PDU session identity value 8" },
    { 0x09, "PDU session identity value 9" },
    { 0x0a, "PDU session identity value 10" },
    { 0x0b, "PDU session identity value 11" },
    { 0x0c, "PDU session identity value 12" },
    { 0x0d, "PDU session identity value 13" },
    { 0x0e, "PDU session identity value 14" },
    { 0x0f, "PDU session identity value 15" },
    { 0, NULL }
};

static int
dissect_nas_5gs_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, void* data)
{
    proto_tree *sub_tree;
    uint32_t epd;

    /* Plain NAS 5GS Message */
    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nas_5gs_plain, NULL, "Plain NAS 5GS Message");
    /* Extended protocol discriminator  octet 1 */
    proto_tree_add_item_ret_uint(sub_tree, hf_nas_5gs_epd, tvb, offset, 1, ENC_BIG_ENDIAN, &epd);
    offset++;
    /* Security header type associated with a spare half octet; or
     * PDU session identity octet 2
     */
    switch (epd) {
    case TGPP_PD_5GMM:
        /* 9.5  Spare half octet
        * Bits 5 to 8 of the second octet of every 5GMM message contains the spare half octet
        * which is filled with spare bits set to zero.
        */
        proto_tree_add_item(sub_tree, hf_nas_5gs_spare_half_octet, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_nas_5gs_security_header_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case TGPP_PD_5GSM:
        /* 9.4  PDU session identity
        * Bits 1 to 8 of the second octet of every 5GSM message contain the PDU session identity IE.
        * The PDU session identity and its use to identify a message flow are defined in 3GPP TS 24.007
        */
        proto_tree_add_item(sub_tree, hf_nas_5gs_pdu_session_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* 9.6  Procedure transaction identity
        * Bits 1 to 8 of the third octet of every 5GSM message contain the procedure transaction identity.
        * The procedure transaction identity and its use are defined in 3GPP TS 24.007
        * XXX Only 5GSM ?
        */
        proto_tree_add_item(sub_tree, hf_nas_5gs_proc_trans_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    default:
        if ((epd & 0xf) == 15 && gsm_a_dtap_handle) {
            /* dissect Test Procedure messages */
            return call_dissector_with_data(gsm_a_dtap_handle, tvb_new_subset_remaining(tvb, offset - 1), pinfo, sub_tree, data);
        }
        proto_tree_add_expert_format(sub_tree, pinfo, &ei_nas_5gs_unknown_pd, tvb, offset, -1, "Not a NAS 5GS PD %u (%s)",
            epd, val_to_str_const(epd, nas_5gs_epd_vals, "Unknown"));
        return 0;

    }
    offset++;

    switch (epd) {
    case TGPP_PD_5GMM:
        /* 5GS mobility management messages */
        dissect_nas_5gs_mm_msg(tvb, pinfo, sub_tree, offset);
        break;
    case TGPP_PD_5GSM:
        /* 5GS session management messages. */
        dissect_nas_5gs_sm_msg(tvb, pinfo, sub_tree, offset);
        break;
    default:
        DISSECTOR_ASSERT_NOT_REACHED();
        break;
    }

    return tvb_reported_length(tvb);
}

static int
dissect_nas_5gs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_item *item;
    proto_tree *nas_5gs_tree, *sub_tree;
    int offset = 0;
    uint8_t sec_hdr_type, ext_pd;
    struct nas5gs_private_data *nas5gs_data = nas5gs_get_private_data(pinfo);

    /* make entry in the Protocol column on summary display */
    col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "NAS-5GS");

    item = proto_tree_add_item(tree, proto_nas_5gs, tvb, 0, -1, ENC_NA);
    nas_5gs_tree = proto_item_add_subtree(item, ett_nas_5gs);

    /* Extended protocol discriminator                              octet 1 */
    ext_pd = tvb_get_uint8(tvb, offset);
    if (ext_pd == TGPP_PD_5GSM) {
        return dissect_nas_5gs_common(tvb, pinfo, nas_5gs_tree, offset, data);
    }
    /* Security header type associated with a spare half octet; or
    * PDU session identity                                         octet 2 */
    /* Determine if it's a plain 5GS NAS Message or not */
    sec_hdr_type = tvb_get_uint8(tvb, offset + 1);
    nas5gs_data->sec_hdr_type = sec_hdr_type;
    if (sec_hdr_type == NAS_5GS_PLAIN_NAS_MSG) {
        return dissect_nas_5gs_common(tvb, pinfo, nas_5gs_tree, offset, data);
    }
    /* Security protected NAS 5GS message*/
    sub_tree = proto_tree_add_subtree(nas_5gs_tree, tvb, offset, 7, ett_nas_5gs_sec, NULL, "Security protected NAS 5GS message");

    /* Extended protocol discriminator  octet 1 */
    proto_tree_add_item(sub_tree, hf_nas_5gs_epd, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Security header type associated with a spare half octet    octet 2 */
    proto_tree_add_item(sub_tree, hf_nas_5gs_spare_half_octet, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_nas_5gs_security_header_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Message authentication code octet 3 - 6 */
    proto_tree_add_item(sub_tree, hf_nas_5gs_msg_auth_code, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    /* Sequence number    octet 7 */
    proto_tree_add_item(sub_tree, hf_nas_5gs_seq_no, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if ((sec_hdr_type != NAS_5GS_INTEG_CIPH_NAS_MSG && sec_hdr_type != NAS_5GS_INTEG_CIPH_NEW_NAS_MSG) ||
        g_nas_5gs_null_decipher) {
        return dissect_nas_5gs_common(tvb, pinfo, nas_5gs_tree, offset, data);
    } else {
        proto_tree_add_subtree(nas_5gs_tree, tvb, offset, -1, ett_nas_5gs_enc, NULL, "Encrypted data");
    }

    return tvb_reported_length(tvb);
}

/* 9.11.2.6 Intra N1 mode NAS transparent container */
static true_false_string nas_5gs_kacf_tfs = {
    "A new K_AMF has been calculated by the network",
    "A new K_AMF has not been calculated by the network"
};

void
de_nas_5gs_intra_n1_mode_nas_transparent_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_)
{
    int offset = 0;

    static int * const flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_spare_b6,
        &hf_nas_5gs_spare_b5,
        &hf_nas_5gs_kacf,
        &hf_nas_5gs_mm_tsc,
        &hf_nas_5gs_mm_nas_key_set_id,
        NULL
    };

    proto_tree_add_item(tree, hf_nas_5gs_msg_auth_code, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_nas_5gs_mm_nas_sec_algo_enc, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_nas_sec_algo_ip, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_NA);
    offset++;
    proto_tree_add_item(tree, hf_nas_5gs_seq_no, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 9.11.2.7 N1 mode to S1 mode NAS transparent container */
void
de_nas_5gs_n1_mode_to_s1_mode_nas_transparent_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_)
{
    proto_tree_add_item(tree, hf_nas_5gs_seq_no, tvb, 0, 1, ENC_BIG_ENDIAN);
}

/* 9.11.2.9 S1 mode to N1 mode NAS transparent container */
void
de_nas_5gs_s1_mode_to_n1_mode_nas_transparent_cont(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_)
{
    int offset = 0;

    static int * const oct8_flags[] = {
        &hf_nas_5gs_spare_b7,
        &hf_nas_5gs_ncc,
        &hf_nas_5gs_mm_tsc,
        &hf_nas_5gs_mm_nas_key_set_id,
        NULL
    };

    proto_tree_add_item(tree, hf_nas_5gs_msg_auth_code, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_nas_5gs_mm_nas_sec_algo_enc, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_nas_5gs_mm_nas_sec_algo_ip, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, oct8_flags, ENC_NA);
    offset++;
    proto_tree_add_item(tree, hf_nas_5gs_spare_octet, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_nas_5gs_spare_octet, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/* 3GPP TS 29.502 chapter 6.1.6.4.2 and 29.518 chapter 6.1.6.4.2 */
static int
dissect_nas_5gs_media_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    int ret;
    char *json_data;
    const char *n1_msg_class, *str;
    jsmntok_t *tokens, *cur_tok;
    dissector_handle_t subdissector;
    tvbuff_t* json_tvb = (tvbuff_t*)p_get_proto_data(pinfo->pool, pinfo, proto_json, 0);
    media_content_info_t *content_info = (media_content_info_t *)data;

    if (!json_tvb || !content_info || !content_info->content_id)
        return 0;

    json_data = tvb_get_string_enc(pinfo->pool, json_tvb, 0, tvb_reported_length(json_tvb), ENC_UTF_8|ENC_NA);
    ret = json_parse(json_data, NULL, 0);
    if (ret <= 0)
        return 0;
    tokens = wmem_alloc_array(pinfo->pool, jsmntok_t, ret);
    if (json_parse(json_data, tokens, ret) <= 0)
        return 0;
    cur_tok = json_get_object(json_data, tokens, "n1MessageContainer");
    if (cur_tok) {
        n1_msg_class = json_get_string(json_data, cur_tok, "n1MessageClass");
        if (!n1_msg_class)
            return 0;
        cur_tok = json_get_object(json_data, cur_tok, "n1MessageContent");
        if (!cur_tok)
            return 0;
        str = json_get_string(json_data, cur_tok, "contentId");
    } else {
        cur_tok = json_get_object(json_data, tokens, "n1SmMsg");
        if (cur_tok) {
            n1_msg_class = "SM";
            str = json_get_string(json_data, cur_tok, "contentId");
        } else {
            /* TS 29.502 ch6.1.6.4.4 n1SmInfoFromUe, n1SmInfoToUe, unknownN1SmInfo */
            cur_tok = json_get_object(json_data, tokens, N1_SMINFO_FROM_UE);
            n1_msg_class = N1_SMINFO_FROM_UE;

            if (!cur_tok) {
                cur_tok = json_get_object(json_data, tokens, N1_SMINFO_TO_UE);
                n1_msg_class = N1_SMINFO_TO_UE;
            }
            if (!cur_tok) {
                cur_tok = json_get_object(json_data, tokens, UNKNOWN_N1_SMINFO);
                n1_msg_class = UNKNOWN_N1_SMINFO;
            }
            if (cur_tok) {
                str = json_get_string(json_data, cur_tok, "contentId");
            } else {
                return 0;
            }
        }
    }
    if (!str || strcmp(str, content_info->content_id))
        return 0;
    if (!strcmp(n1_msg_class, "5GMM") ||
        !strcmp(n1_msg_class, "SM")) {
        subdissector = nas_5gs_handle;
    } else if (!strcmp(n1_msg_class, N1_SMINFO_FROM_UE) ||
               !strcmp(n1_msg_class, N1_SMINFO_TO_UE) ||
               !strcmp(n1_msg_class, UNKNOWN_N1_SMINFO)) {
        dissect_nas_5gs_sm_info(tvb, pinfo, tree, 0, n1_msg_class);
        return tvb_captured_length(tvb);
    } else if (!strcmp(n1_msg_class, "LPP")) {
        subdissector = lpp_handle;
    } else if (!strcmp(n1_msg_class, "SMS")) {
        subdissector = gsm_a_dtap_handle;
    } else if (!strcmp(n1_msg_class, "UPDP")) {
        /* UE policy delivery service */
        dissect_nas_5gs_updp(tvb, pinfo, tree);
        return tvb_captured_length(tvb);
    } else {
        subdissector = NULL;
    }

    if (subdissector) {
        call_dissector_with_data(subdissector, tvb, pinfo, tree, NULL);
        return tvb_captured_length(tvb);
  } else {
        return 0;
  }
}

static unsigned
get_nas_5gs_tcp_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	return tvb_get_ntohs(tvb, offset) + 2;
}

static int
dissect_nas_5gs_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    col_clear(pinfo->cinfo, COL_INFO);
    return dissect_nas_5gs(tvb_new_subset_remaining(tvb, 2), pinfo, tree, data);
}

static int
dissect_nas_5gs_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, true, 2, get_nas_5gs_tcp_len,
                     dissect_nas_5gs_tcp_pdu, data);
    return tvb_reported_length(tvb);
}

/* Heuristic dissector looks for "nas-5gs" string at packet start */
static bool dissect_nas_5gs_heur(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree, void *data _U_)
{
    int offset = 0;
    tvbuff_t *nas_tvb;

    /* Needs to be at least as long as:
       - the signature string
       - at least one byte of NAS PDU payload */
    if (tvb_captured_length_remaining(tvb, offset) < (int)(strlen(PFNAME)+1)) {
        return false;
    }

    /* OK, compare with signature string */
    if (tvb_strneql(tvb, offset, PFNAME, strlen(PFNAME)) != 0) {
        return false;
    }
    offset += (int)strlen(PFNAME);

    /* Clear protocol name */
    col_clear(pinfo->cinfo, COL_PROTOCOL);

    /* Clear info column */
    col_clear(pinfo->cinfo, COL_INFO);

    /* Create tvb that starts at actual NAS PDU */
    nas_tvb = tvb_new_subset_remaining(tvb, offset);
    dissect_nas_5gs(nas_tvb, pinfo, tree, NULL);

    return true;
}

void
proto_register_nas_5gs(void)
{

    /* List of fields */

    static hf_register_info hf[] = {
        { &hf_nas_5gs_epd,
        { "Extended protocol discriminator",   "nas-5gs.epd",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_epd_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_bits,
        { "Spare",   "nas-5gs.spare_bits",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_b7,
        { "Spare",   "nas-5gs.spare_b7",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_b6,
        { "Spare",   "nas-5gs.spare_b6",
            FT_UINT8, BASE_DEC, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_b5,
        { "Spare",   "nas-5gs.spare_b5",
            FT_UINT8, BASE_DEC, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_b4,
        { "Spare",   "nas-5gs.spare_b4",
            FT_UINT8, BASE_DEC, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_b3,
        { "Spare",   "nas-5gs.spare_b3",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_b2,
        { "Spare",   "nas-5gs.spare_b2",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_b1,
        { "Spare",   "nas-5gs.spare_b1",
            FT_UINT8, BASE_DEC, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_b0,
        { "Spare",   "nas-5gs.spare_b0",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_rfu_b2,
        { "Reserved for Future Use(RFU)",   "nas-5gs.rfu.b2",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_rfu_b1,
        { "Reserved for Future Use(RFU)",   "nas-5gs.rfu.b1",
            FT_UINT8, BASE_DEC, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_rfu_b0,
        { "Reserved for Future Use(RFU)",   "nas-5gs.rfu.b0",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },

        { &hf_nas_5gs_security_header_type,
        { "Security header type",   "nas-5gs.security_header_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_security_header_type_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_msg_auth_code,
        { "Message authentication code",   "nas-5gs.msg_auth_code",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_seq_no,
        { "Sequence number",   "nas-5gs.seq_no",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_msg_type,
        { "Message type",   "nas-5gs.mm.message_type",
        FT_UINT8, BASE_HEX | BASE_EXT_STRING, &nas_5gs_mm_msg_strings_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_msg_type,
        { "Message type",   "nas-5gs.sm.message_type",
        FT_UINT8, BASE_HEX | BASE_EXT_STRING, &nas_5gs_sm_msg_strings_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_updp_msg_type,
        { "Message type",   "nas-5gs.updp.message_type",
        FT_UINT8, BASE_HEX | BASE_EXT_STRING, &nas_5gs_updp_msg_strings_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_common_elem_id,
            { "Element ID", "nas-5gs.common.elem_id",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_elem_id,
            { "Element ID", "nas-5gs.mm.elem_id",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_elem_id,
            { "Element ID", "nas-5gs.sm.elem_id",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_updp_elem_id,
            { "Element ID", "nas-5gs.updp.elem_id",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_proc_trans_id,
        { "Procedure transaction identity",   "nas-5gs.proc_trans_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_half_octet,
        { "Spare Half Octet",   "nas-5gs.spare_half_octet",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_spare_octet,
        { "Spare", "nas-5gs.spare_octet",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_session_id,
        { "PDU session identity",   "nas-5gs.pdu_session_id",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_pdu_session_id_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_msg_elems,
        { "Message Elements", "nas-5gs.message_elements",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_cmn_add_info,
        { "Additional information", "nas-5gs.cmn.add_info",
            FT_BYTES, BASE_NONE, NULL,0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_cmn_acc_type,
        { "Access type", "nas-5gs.cmn.acc_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_cmn_acc_type_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_nas_5gs_cmn_dnn,
        { "DNN", "nas-5gs.cmn.dnn",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_cmn_service_level_aa_param_type,
        { "Type of service-level-AA parameter", "nas-5gs.cmn.service_level_aa_param.type",
            FT_UINT8, BASE_HEX, VALS(nas_5gs_cmn_service_level_aa_param_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_cmn_service_level_aa_param_len,
        { "Length of service-level-AA parameter", "nas-5gs.cmn.service_level_aa_param.len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_cmn_service_level_aa_param_device_id,
        { "Service-level device ID", "nas-5gs.cmn.service_level_aa_param.device_id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_cmn_service_level_aa_param_addr_type,
        { "Service-level-AA server address type", "nas-5gs.cmn.service_level_aa_param.addr.type",
            FT_UINT8, BASE_HEX, VALS(nas_5gs_cmn_service_level_aa_param_serv_addr_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_cmn_service_level_aa_param_addr_ipv4,
        { "Service-level-AA server address IPv4", "nas-5gs.cmn.service_level_aa_param.addr.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_cmn_service_level_aa_param_addr_ipv6,
        { "Service-level-AA server address IPv6", "nas-5gs.cmn.service_level_aa_param.addr.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_cmn_service_level_aa_param_addr_fqdn,
        { "Service-level-AA server address FQDN", "nas-5gs.cmn.service_level_aa_param.addr.fqdn",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_cmn_service_level_aa_param_resp_c2ar,
        { "C2 authorization result field (C2AR)", "nas-5gs.cmn.service_level_aa_param.response.c2ar",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_cmn_service_level_aa_param_resp_c2ar_vals), 0x0c,
            NULL, HFILL }
        },
        { &hf_nas_5gs_cmn_service_level_aa_param_resp_slar,
        { "Service-level-AA result field (SLAR)", "nas-5gs.cmn.service_level_aa_param.response.slar",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_cmn_service_level_aa_param_resp_slar_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_nas_5gs_cmn_service_level_aa_param_payload_type,
        { "Service-level-AA payload type", "nas-5gs.cmn.service_level_aa_param.payload_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_cmn_service_level_aa_param_payload_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_cmn_service_level_aa_param_payload,
        { "Service-level-AA payload", "nas-5gs.cmn.service_level_aa_param.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_cmn_service_level_aa_param_pending_ind_slapi,
        { "Service-level-AA pending indication (SLAPI)", "nas-5gs.cmn.service_level_aa_param.pending_indication.slapi",
            FT_BOOLEAN, 8, TFS(&nas_5gs_cmn_service_level_aa_param_pending_ind_slapi_value), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_cmn_service_level_aa_param_service_status_ind_uas,
        { "UAS", "nas-5gs.cmn.service_level_aa_param.service_status_indication.uas",
            FT_BOOLEAN, 8, TFS(&nas_5gs_enabled_not_enabled_value), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_cmn_service_level_aa_param_unknown,
        { "Value of service-level-AA parameter", "nas-5gs.cmn.service_level_aa_param.unknown",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_for,
        { "Follow-On Request bit (FOR)",   "nas-5gs.mm.for",
            FT_BOOLEAN, 8, TFS(&nas_5gs_for_tfs), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_sms_requested,
        { "SMS over NAS transport requested (SMS requested)",   "nas-5gs.mm.sms_requested",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ng_ran_rcu,
        { "NG-RAN Radio Capability Update (NG-RAN-RCU)", "nas-5gs.mm.ng_ran_rcu",
            FT_BOOLEAN, 8, TFS(&tfs_needed_not_needed), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5gs_pnb_ciot,
        { "5GS Preferred CIoT network behaviour (5GS PNB-CIoT)", "nas-5gs.mm.5gs_pnb_ciot",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_5gs_pnb_ciot_values), 0x0c,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eps_pnb_ciot,
        { "EPS Preferred CIoT network behaviour (EPS-PNB-CIoT)", "nas-5gs.mm.eps_pnb_ciot",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_eps_pnb_ciot_values), 0x30,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5gs_reg_type,
        { "5GS registration type",   "nas-5gs.mm.5gs_reg_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_registration_type_values), 0x07,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_tsc,
        { "Type of security context flag (TSC)",   "nas-5gs.mm.tsc",
            FT_BOOLEAN, 8, TFS(&nas_5gs_mm_tsc_tfs), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nas_key_set_id,
        { "NAS key set identifier",   "nas-5gs.mm.nas_key_set_id",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_tsc_h1,
        { "Type of security context flag (TSC)",   "nas-5gs.mm.tsc.h1",
            FT_BOOLEAN, 8, TFS(&nas_5gs_mm_tsc_tfs), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nas_key_set_id_h1,
        { "NAS key set identifier",   "nas-5gs.mm.nas_key_set_id.h1",
            FT_UINT8, BASE_DEC, NULL, 0x70,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5gmm_cause,
        { "5GMM cause",   "nas-5gs.mm.5gmm_cause",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_cause_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pld_cont_type,
        { "Payload container type",   "nas-5gs.mm.pld_cont_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_pld_cont_type_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_sst,
        { "Slice/service type (SST)",   "nas-5gs.mm.sst",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_sst_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_sd,
        { "Slice differentiator (SD)",   "nas-5gs.mm.mm_sd",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_mapped_hplmn_sst,
        { "Mapped HPLMN SST",   "nas-5gs.mm.mapped_hplmn_sst",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_mapped_hplmn_ssd,
        { "Mapped HPLMN SD",   "nas-5gs.mm.mapped_hplmn_ssd",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_switch_off,
        { "Switch off",   "nas-5gs.mm.switch_off",
            FT_BOOLEAN, 8, TFS(&nas_5gs_mm_switch_off_tfs), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_re_reg_req,
        { "Re-registration required",   "nas-5gs.mm.re_reg_req",
            FT_BOOLEAN, 8, TFS(&nas_5gs_mm_re_reg_req_tfs), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_acc_type,
        { "Access type",   "nas-5gs.mm.acc_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_acc_type_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_raai_b0,
        { "Registration Area Allocation Indication (RAAI)",   "nas-5gs.mm.raai_b0",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_raai), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_sprti_b1,
        { "Strictly Periodic Registration Timer Indication (SPRTI)",   "nas-5gs.mm.sprti_b1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ma_pdu_session_info_value,
        { "MA PDU session information value",   "nas-5gs.mm.ma_pdu_session_info_value",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_ma_pdu_session_info_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_len_of_mapped_s_nssai,
        { "Length of Mapped S-NSSAI content",   "nas-5gs.mm.len_of_mapped_s_nssai",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_conf_upd_ind_ack_b0,
        { "Acknowledgement",   "nas-5gs.mm.conf_upd_ind.ack",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_conf_upd_ind_red_b1,
        { "Registration",   "nas-5gs.mm.conf_upd_ind.red",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_cag_info_entry_len,
        { "Length of entry contents",   "nas-5gs.mm.cag_info.entry.len",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_cag_info_entry_cag_only,
        { "CAG only",   "nas-5gs.mm.cag_info.entry.cag_only",
            FT_BOOLEAN, 8, TFS(&tfs_5gs_mm_cag_info_entry_cag_only), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_cag_info_entry_lci,
        { "Length of CAG-IDs indicator (LCI)",   "nas-5gs.mm.cag_info.entry.lci",
            FT_BOOLEAN, 8, TFS(&tfs_present_absent), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_cag_info_entry_caili,
        { "CAG-ID with additional information list indicator (CAILI)",   "nas-5gs.mm.cag_info.entry.caili",
            FT_BOOLEAN, 8, TFS(&tfs_present_absent), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_cag_info_entry_cag_without_add_info_list_len,
        { "Length of CAG-IDs without additional information list",   "nas-5gs.mm.cag_info.entry.cag_without_add_info_list_len",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_cag_info_entry_cag_with_add_info_list_len,
        { "Length of CAG-IDs with additional information list contents",   "nas-5gs.mm.cag_info.entry.cag_with_add_info_list_len",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_cag_info_entry_cag_with_add_info_len,
        { "Length of CAG-ID with additional information contents",   "nas-5gs.mm.cag_info.entry.cag_with_add_info_len",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_cag_info_entry_cag_id,
        { "CAG-ID",   "nas-5gs.mm.cag_info.entry.cag_id",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_cag_info_entry_svii,
        { "Spare validity information indicator (SVII)",   "nas-5gs.mm.cag_info.entry.svii",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_present_absent), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_cag_info_entry_tvii,
        { "Time validity information indicator (TVII)",   "nas-5gs.mm.cag_info.entry.tvii",
            FT_BOOLEAN, 8, TFS(&tfs_present_absent), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_cag_info_entry_nb_time_periods,
        { "Number of time periods",   "nas-5gs.mm.cag_info.entry.nb_time_periods",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_cag_info_entry_time_period,
        { "Number of time periods",   "nas-5gs.mm.cag_info.entry.time_period",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciot_small_data_cont_data_type,
        { "Data type",   "nas-5gs.mm.ciot_small_data_cont.data_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_ciot_small_data_cont_data_type_values), 0xe0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciot_small_data_cont_ddx,
        { "Downlink data expected (DDX)",   "nas-5gs.mm.ciot_small_data_cont.ddx",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_ciot_small_data_cont_ddx_values), 0x18,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciot_small_data_cont_pdu_session_id,
        { "PDU session identity",   "nas-5gs.mm.ciot_small_data_cont.pdu_session_id",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_pdu_session_id_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciot_small_data_cont_add_info_len,
        { "Length of additional information",   "nas-5gs.mm.ciot_small_data_cont.add_info_len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciot_small_data_cont_add_info,
        { "Additional information",   "nas-5gs.mm.ciot_small_data_cont.add_info",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciot_small_data_cont_data_contents,
        { "Data contents",   "nas-5gs.mm.ciot_small_data_cont.data_contents",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_1,
        { "Ciphering data set for E-UTRA positioning SIB type 1-1","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_1_1",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_2,
        { "Ciphering data set for E-UTRA positioning SIB type 1-2","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_1_2",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_3,
        { "Ciphering data set for E-UTRA positioning SIB type 1-3","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_1_3",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_4,
        { "Ciphering data set for E-UTRA positioning SIB type 1-4","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_1_4",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_5,
        { "Ciphering data set for E-UTRA positioning SIB type 1-5","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_1_5",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_6,
        { "Ciphering data set for E-UTRA positioning SIB type 1-6","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_1_6",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_7,
        { "Ciphering data set for E-UTRA positioning SIB type 1-7","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_1_7",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_8,
        { "Ciphering data set for E-UTRA positioning SIB type 1-8","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_1_8",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_1,
        { "Ciphering data set for E-UTRA positioning SIB type 2-1","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_1",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_2,
        { "Ciphering data set for E-UTRA positioning SIB type 2-2","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_2",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_3,
        { "Ciphering data set for E-UTRA positioning SIB type 2-3","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_3",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_4,
        { "Ciphering data set for E-UTRA positioning SIB type 2-4","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_4",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_5,
        { "Ciphering data set for E-UTRA positioning SIB type 2-5","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_5",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_6,
        { "Ciphering data set for E-UTRA positioning SIB type 2-6","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_6",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_7,
        { "Ciphering data set for E-UTRA positioning SIB type 2-7","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_7",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_8,
        { "Ciphering data set for E-UTRA positioning SIB type 2-8","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_8",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_9,
        { "Ciphering data set for E-UTRA positioning SIB type 2-9","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_9",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_10,
        { "Ciphering data set for E-UTRA positioning SIB type 2-10","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_10",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_11,
        { "Ciphering data set for E-UTRA positioning SIB type 2-11","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_11",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_12,
        { "Ciphering data set for E-UTRA positioning SIB type 2-12","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_12",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_13,
        { "Ciphering data set for E-UTRA positioning SIB type 2-13","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_13",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_14,
        { "Ciphering data set for E-UTRA positioning SIB type 2-14","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_14",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_15,
        { "Ciphering data set for E-UTRA positioning SIB type 2-15","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_15",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_16,
        { "Ciphering data set for E-UTRA positioning SIB type 2-16","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_16",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_17,
        { "Ciphering data set for E-UTRA positioning SIB type 2-17","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_17",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_18,
        { "Ciphering data set for E-UTRA positioning SIB type 2-18","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_18",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_19,
        { "Ciphering data set for E-UTRA positioning SIB type 2-19","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_19",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_20,
        { "Ciphering data set for E-UTRA positioning SIB type 2-20","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_20",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_21,
        { "Ciphering data set for E-UTRA positioning SIB type 2-21","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_21",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_22,
        { "Ciphering data set for E-UTRA positioning SIB type 2-22","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_22",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_23,
        { "Ciphering data set for E-UTRA positioning SIB type 2-23","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_23",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_24,
        { "Ciphering data set for E-UTRA positioning SIB type 2-24","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_24",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_2_25,
        { "Ciphering data set for E-UTRA positioning SIB type 2-25","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_2_25",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_3_1,
        { "Ciphering data set for E-UTRA positioning SIB type 3-1","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_3_1",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_4_1,
        { "Ciphering data set for E-UTRA positioning SIB type 4-1","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_4_1",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_5_1,
        { "Ciphering data set for E-UTRA positioning SIB type 5-1","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_5_1",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_9,
        { "Ciphering data set for E-UTRA positioning SIB type 1-9","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_1_9",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_type_1_10,
        { "Ciphering data set for E-UTRA positioning SIB type 1-10","nas-5gs.mm.ciph_key_data.eutra_pos_sib_type_1_10",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_1,
        { "Ciphering data set for NR positioning SIB type 1-1","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_1_1",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_2,
        { "Ciphering data set for NR positioning SIB type 1-2","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_1_2",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_3,
        { "Ciphering data set for NR positioning SIB type 1-3","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_1_3",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_4,
        { "Ciphering data set for NR positioning SIB type 1-4","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_1_4",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_5,
        { "Ciphering data set for NR positioning SIB type 1-5","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_1_5",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_6,
        { "Ciphering data set for NR positioning SIB type 1-6","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_1_6",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_7,
        { "Ciphering data set for NR positioning SIB type 1-7","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_1_7",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_8,
        { "Ciphering data set for NR positioning SIB type 1-8","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_1_8",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_1,
        { "Ciphering data set for NR positioning SIB type 2-1","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_1",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_2,
        { "Ciphering data set for NR positioning SIB type 2-2","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_2",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_3,
        { "Ciphering data set for NR positioning SIB type 2-3","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_3",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_4,
        { "Ciphering data set for NR positioning SIB type 2-4","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_4",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_5,
        { "Ciphering data set for NR positioning SIB type 2-5","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_5",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_6,
        { "Ciphering data set for NR positioning SIB type 2-6","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_6",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_7,
        { "Ciphering data set for NR positioning SIB type 2-7","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_7",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_8,
        { "Ciphering data set for NR positioning SIB type 2-8","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_8",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_9,
        { "Ciphering data set for NR positioning SIB type 2-9","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_9",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_10,
        { "Ciphering data set for NR positioning SIB type 2-10","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_10",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_11,
        { "Ciphering data set for NR positioning SIB type 2-11","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_11",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_12,
        { "Ciphering data set for NR positioning SIB type 2-12","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_12",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_13,
        { "Ciphering data set for NR positioning SIB type 2-13","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_13",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_14,
        { "Ciphering data set for NR positioning SIB type 2-14","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_14",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_15,
        { "Ciphering data set for NR positioning SIB type 2-15","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_15",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_16,
        { "Ciphering data set for NR positioning SIB type 2-16","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_16",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_17,
        { "Ciphering data set for NR positioning SIB type 2-17","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_17",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_18,
        { "Ciphering data set for NR positioning SIB type 2-18","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_18",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_19,
        { "Ciphering data set for NR positioning SIB type 2-19","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_19",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_20,
        { "Ciphering data set for NR positioning SIB type 2-20","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_20",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_21,
        { "Ciphering data set for NR positioning SIB type 2-21","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_21",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_22,
        { "Ciphering data set for NR positioning SIB type 2-22","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_22",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_23,
        { "Ciphering data set for NR positioning SIB type 2-23","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_23",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_3_1,
        { "Ciphering data set for NR positioning SIB type 3-1","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_3_1",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_4_1,
        { "Ciphering data set for NR positioning SIB type 4-1","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_4_1",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_5_1,
        { "Ciphering data set for NR positioning SIB type 5-1","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_5_1",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_1,
        { "Ciphering data set for NR positioning SIB type 6-1","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_6_1",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_2,
        { "Ciphering data set for NR positioning SIB type 6-2","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_6_2",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_3,
        { "Ciphering data set for NR positioning SIB type 6-3","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_6_3",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_4,
        { "Ciphering data set for NR positioning SIB type 6-4","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_6_4",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_5,
        { "Ciphering data set for NR positioning SIB type 6-5","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_6_5",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_6_6,
        { "Ciphering data set for NR positioning SIB type 6-6","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_6_6",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_9,
        { "Ciphering data set for NR positioning SIB type 1-9","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_1_9",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_1_10,
        { "Ciphering data set for NR positioning SIB type 1-10","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_1_10",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_24,
        { "Ciphering data set for NR positioning SIB type 2-24","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_24",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_type_2_25,
        { "Ciphering data set for NR positioning SIB type 2-25","nas-5gs.mm.ciph_key_data.nr_pos_sib_type_2_25",
            FT_BOOLEAN, 8, TFS(&tfs_applicable_not_applicable), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_ciphering_set_id,
        { "Ciphering set ID","nas-5gs.mm.ciph_key_data.ciphering_set_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_ciphering_key,
            { "Ciphering key","nas-5gs.mm.ciph_key_data.ciphering_key",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_c0_len,
            { "c0 length","nas-5gs.mm.ciph_key_data.c0_len",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_c0,
            { "c0","nas-5gs.mm.ciph_key_data.c0",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_eutra_pos_sib_len,
            { "E-UTRA posSIB length","nas-5gs.mm.ciph_key_data.eutra_pos_sib_len",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_nr_pos_sib_len,
            { "NR posSIB length","nas-5gs.mm.ciph_key_data.nr_pos_sib_len",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_validity_start_time,
        { "Validity start time", "nas-5gs.mm.ciph_key_data.validity_start_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_validity_duration,
        { "Validity duration", "nas-5gs.mm.ciph_key_data.validity_duration",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_minute_minutes), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ciph_key_data_tais_list_len,
        { "TAIs list length", "nas-5gs.mm.ciph_key_data.tais_list_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ctrl_plane_serv_type,
        { "Control plane service type", "nas-5gs.mm.ctrl_plane_serv_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_ctrl_plane_serv_type_values), 0x07,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nas_sec_algo_enc,
        { "Type of ciphering algorithm",   "nas-5gs.mm.nas_sec_algo_enc",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_type_of_enc_algo_vals), 0xf0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nas_sec_algo_ip,
        { "Type of integrity protection algorithm",   "nas-5gs.mm.nas_sec_algo_ip",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_type_of_ip_algo_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_s1_mode_b0,
        { "EPC NAS supported (S1 mode)",   "nas-5gs.mm.s1_mode_b0",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ho_attach_b1,
        { "ATTACH REQUEST message containing PDN CONNECTIVITY REQUEST message for handover support (HO attach)",   "nas-5gs.mm.ho_attach_b1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_lpp_cap_b2,
        { "LTE Positioning Protocol (LPP) capability",   "nas-5gs.mm.lpp_cap_b2",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_restrict_ec_b3,
        { "Restriction on use of enhanced coverage support (RestrictEC)",   "nas-5gs.mm.restrict_ec_b3",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_cp_ciot_b4,
        { "Control plane CIoT 5GS optimization (5G-CP CIoT)",   "nas-5gs.mm.5g_cp_ciot_b4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_n3_data_b5,
        { "N3 data transfer (N3 data)",   "nas-5gs.mm.n3_data_b5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_iphc_cp_ciot_b6,
        { "IP header compression for control plane CIoT 5GS optimization (5G-IPHC-CP CIoT)",   "nas-5gs.mm.5g_iphc_cp_ciot_b6",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_sgc_b7,
        { "Service gap control (SGC)",   "nas-5gs.mm.sgc_b7",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_srvcc_b0,
        { "5G-SRVCC from NG-RAN to UTRAN (5GSRVCC) capability",   "nas-5gs.mm.5g_srvcc_b0",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_up_ciot_b1,
        { "User plane CIoT 5GS optimization (5G-UP CIoT)",   "nas-5gs.mm.5g_up_ciot_b1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_v2x_b2,
        { "V2X capability (V2X)",   "nas-5gs.mm.v2x_b2",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_v2xcepc5_b3,
        { "V2X communication over E-UTRA-PC5 capability (V2XCEPC5)",   "nas-5gs.mm.v2xcepc5_b3",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_v2xcnpc5_b4,
        { "V2X communication over NR-PC5 capability (V2XCNPC5)",   "nas-5gs.mm.v2xcnpc5_b4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_lcs_b5,
        { "Location Services (5G-LCS) notification mechanisms capability",   "nas-5gs.mm.5g_lcs_b5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nssaa_b6,
        { "Network slice-specific authentication and authorization (NSSAA)",   "nas-5gs.mm.nssaa_b6",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_racs_b7,
        { "Radio capability signalling optimisation (RACS) capability",   "nas-5gs.mm.racs_b7",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_cag_b0,
        { "Closed Access Group (CAG) capability",   "nas-5gs.mm.cag_b0",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_wsusa_b1,
        { "WUS assistance (WUSA) information reception capability",   "nas-5gs.mm.wsusa_b1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_multiple_up_b2,
        { "Multiple user-plane resources support (multipleUP)",   "nas-5gs.mm.multiple_up_b2",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ehc_cp_ciot_b3,
        { "Ethernet header compression for control plane CIoT 5GS optimization (5G-EHC-CP CIoT)",   "nas-5gs.mm.ehc_cp_ciot_b3",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_er_nssai_b4,
        { "Extended rejected NSSAI (ER-NSSAI)",   "nas-5gs.mm.er_nssai_b4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_prose_dd_b5,
        { "5G ProSe direct discovery (5G ProSe-dd)",   "nas-5gs.mm.prose_dd_b5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_prose_dc_b6,
        { "5G ProSe direct communication (5G ProSe-dc)",   "nas-5gs.mm.prose_dc_b6",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_prose_l2relay_b7,
        { "5G ProSe layer-2 UE-to-network-relay (5G ProSe-l2relay)",   "nas-5gs.mm.prose_l2relay_b7",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_prose_l3relay_b0,
        { "5G ProSe layer-3 UE-to-network-relay (5G ProSe-l3relay)",   "nas-5gs.mm.5g_prose_l3relay_b0",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_prose_l2rmt_b1,
        { "5G ProSe layer-2 UE-to-network-remote (5G ProSe-l2rmt)",   "nas-5gs.mm.5g_prose_l2rmt_b1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_prose_l3rmt_b2,
        { "5G ProSe layer-3 UE-to-network-remote (5G ProSe-l3rmt)",   "nas-5gs.mm.5g_prose_l3rmt_b2",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nr_pssi_b3,
        { "NR paging subgroup support indication (NR-PSSI)",   "nas-5gs.mm.nr_pssi_b3",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ncr_b4,
        { "N1 NAS signalling connection release (NCR)",   "nas-5gs.mm.ncr_b4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_piv_b5,
        { "Paging indication for voice services (PIV)",   "nas-5gs.mm.piv_b5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_rpr_b6,
        { "Reject paging request (RPR)",   "nas-5gs.mm.rpr_b6",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pr_b7,
        { "Paging restriction (PR)",   "nas-5gs.mm.pr_b7",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nssrg_b0,
        { "NSSRG",   "nas-5gs.mm.nssrg_b0",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_mint_b1,
        { "Minimization of service interruption (MINT)",   "nas-5gs.mm.mint_b1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_event_notif_b2,
        { "Event notification",   "nas-5gs.mm.event_notif_b2",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ssnpnsi_b3,
        { "SOR-SNPN-SI (SSNPNSI)",   "nas-5gs.mm.ssnpnsi_b3",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ex_cag_b4,
        { "Extended CAG information list support (Ex-CAG)",   "nas-5gs.mm.ex_cag_b4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nsag_b5,
        { "NSAG",   "nas-5gs.mm.nsag_b5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_uas_b6,
        { "UAS",   "nas-5gs.mm.uas_b6",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_mpsiu_b7,
        { "MPSIU",   "nas-5gs.mm.mpsiu_b7",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_rcmap_b0,
        { "RCMAP",   "nas-5gs.mm.rcmap_b0",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_rcman_b1,
        { "RCMAN",   "nas-5gs.mm.rcman_b1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_esi_b2,
        { "ESI",   "nas-5gs.mm.esi_b2",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eci_b3,
        { "ECI",   "nas-5gs.mm.eci_b3",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_rantiming_b4,
        { "RANtiming",   "nas-5gs.mm.rantiming_b4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ladn_ds_b5,
        { "LADN-DS",   "nas-5gs.mm.ladn_ds_b5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nsr_b6,
        { "NSR",   "nas-5gs.mm.nsr_b6",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_sbts_b7,
        { "SBTS",   "nas-5gs.mm.sbts_b7",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_a2xepc5_b0,
        { "A2XEPC5",   "nas-5gs.mm.a2xepc5_b0",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_a2xnpc5_b1,
        { "A2XNPC5",   "nas-5gs.mm.a2xnpc5_b1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_un_per_b2,
        { "UN-PER",   "nas-5gs.mm.un_per_b2",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_sbns_b3,
        { "SBNS",   "nas-5gs.mm.sbns_b3",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_rslps_b4,
        { "RSLPS",   "nas-5gs.mm.rslps_b4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_prose_l2u2u_relay_b5,
        { "5G ProSe-l2U2U relay",   "nas-5gs.mm.5g_prose_l2u2u_relay_b5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_prose_l3u2u_relay_b6,
        { "5G ProSe-l3U2U relay",   "nas-5gs.mm.5g_prose_l3u2u_relay_b6",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_prose_l2end_b7,
        { "5G ProSe-l2end",   "nas-5gs.mm.5g_prose_l2end_b7",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_prose_l3end_b0,
        { "5G ProSe-l3end",   "nas-5gs.mm.5g_prose_l3end_b0",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_rslp_b1,
        { "RSLP",   "nas-5gs.mm.rslp_b1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pns_b2,
        { "PNS",   "nas-5gs.mm.pns_b2",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_lcs_upp_b3,
        { "LCS-UPP",   "nas-5gs.mm.lcs_upp_b3",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_supl_b4,
        { "SUPL",   "nas-5gs.mm.supl_b4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_tempns_b5,
        { "TempNS",   "nas-5gs.mm.tempns_b5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_slvi_b6,
        { "SLVI",   "nas-5gs.mm.slvi_b6",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_a2x_uu_b7,
        { "A2X-Uu",   "nas-5gs.mm.a2x_uu_b7",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_mcsiu_b0,
        { "MCSIU",   "nas-5gs.mm.mcsiu_b0",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nvl_satnr_b1,
        { "NVL-SATNR",   "nas-5gs.mm.nvl_satnr_b1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_rslpl_b2,
        { "RSLPL",   "nas-5gs.mm.rslpl_b2",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nsuc_b3,
        { "NSUC",   "nas-5gs.mm.nsuc_b3",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_type_id,
        { "Type of identity",   "nas-5gs.mm.type_id",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_type_id_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_odd_even,
        { "Odd/even indication","nas-5gs.mm.odd_even",
            FT_BOOLEAN, 8, TFS(&nas_5gs_odd_even_tfs), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_length,
        { "Length",   "nas-5gs.mm.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_abba,
        { "ABBA Contents",   "nas-5gs.mm.abba_contents",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pld_cont,
        { "Payload container",   "nas-5gs.mm.pld_cont",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pld_cont_event_notif_ind_nb,
        { "Number of event notification indicators",   "nas-5gs.mm.pld_cont.event_notif_ind.nb",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pld_cont_event_notif_ind_type,
        { "Type of event notification indicator",   "nas-5gs.mm.pld_cont.event_notif_ind.type",
            FT_UINT8, BASE_HEX, VALS(nas_5gs_mm_pld_cont_event_notif_ind_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pld_cont_event_notif_ind_len,
        { "Length of event notification indicator",   "nas-5gs.mm.pld_cont.event_notif_ind.len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pld_cont_event_notif_ind_val,
        { "Value of event notification indicator",   "nas-5gs.mm.pld_cont.event_notif_ind.val",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pld_cont_nb_entries,
        { "Number of entries",   "nas-5gs.mm.pld_cont.nb_entries",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pld_cont_pld_cont_len,
        { "Length of Payload container entry",   "nas-5gs.mm.pld_cont.pld_cont_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pld_cont_nb_opt_ies,
        { "Number of optional IEs",   "nas-5gs.mm.pld_cont.nb_opt_ies",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pld_cont_pld_cont_type,
        { "Payload container type",   "nas-5gs.mm.pld_cont.pld_cont_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_pld_cont_type_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pld_cont_opt_ie_type,
        { "Type of optional IE",   "nas-5gs.mm.pld_cont.opt_ie_type",
            FT_UINT8, BASE_HEX, VALS(nas_5gs_mm_pld_cont_opt_ie_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pld_cont_opt_ie_len,
        { "Length of optional IE",   "nas-5gs.mm.pld_cont.opt_ie_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pld_cont_opt_ie_val,
        { "Value of optional IE",   "nas-5gs.mm.pld_cont.opt_ie_val",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_req_type,
        { "Request type",   "nas-5gs.mm.req_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_req_type_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_serv_type,
        { "Service type",   "nas-5gs.mm.serv_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_serv_type_vals), 0x70,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ea0,
        { "5G-EA0","nas-5gs.mm.5g_ea0",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_128_5g_ea1,
        { "128-5G-EA1","nas-5gs.mm.128_5g_ea1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_128_5g_ea2,
        { "128-5G-EA2","nas-5gs.mm.128_5g_ea2",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_128_5g_ea3,
        { "128-5G-EA3","nas-5gs.mm.128_5g_ea3",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ea4,
        { "5G-EA4","nas-5gs.mm.5g_ea4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ea5,
        { "5G-EA5","nas-5gs.mm.5g_ea5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ea6,
        { "5G-EA6","nas-5gs.mm.5g_ea6",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ea7,
        { "5G-EA7","nas-5gs.mm.5g_ea7",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ia0,
        { "5G-IA0","nas-5gs.mm.ia0",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_128_ia1,
        { "128-5G-IA1","nas-5gs.mm.5g_128_ia1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_128_ia2,
        { "128-5G-IA2","nas-5gs.mm.5g_128_ia2",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_128_ia3,
        { "128-5G-IA3","nas-5gs.mm.5g_128_ia3",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ia4,
        { "5G-IA4","nas-5gs.mm.5g_128_ia4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ia5,
        { "5G-IA5","nas-5gs.mm.5g_ia5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ia6,
        { "5G-IA6","nas-5gs.mm.5g_ia6",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5g_ia7,
        { "5G-IA7","nas-5gs.mm.5g_ia7",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eea0,
        { "EEA0","nas-5gs.mm.eea0",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_128eea1,
        { "128-EEA1","nas-5gs.mm.128eea1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_128eea2,
        { "128-EEA2","nas-5gs.mm.128eea2",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eea3,
        { "128-EEA3","nas-5gs.mm.eea3",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eea4,
        { "EEA4","nas-5gs.mm.eea4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eea5,
        { "EEA5","nas-5gs.mm.eea5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eea6,
        { "EEA6","nas-5gs.mm.eea6",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eea7,
        { "EEA7","nas-5gs.mm.eea7",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eia0,
        { "EIA0","nas-5gs.mm.eia0",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_128eia1,
        { "128-EIA1","nas-5gs.mm.128eia1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_128eia2,
        { "128-EIA2","nas-5gs.mm.128eia2",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eia3,
        { "128-EIA3","nas-5gs.mm.eia3",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eia4,
        { "EIA4","nas-5gs.mm.eia4",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eia5,
        { "EIA5","nas-5gs.mm.eia5",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eia6,
        { "EIA6","nas-5gs.mm.eia6",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eia7,
        { "EIA7","nas-5gs.mm.eia7",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_n1_mode_reg_b1,
        { "N1 mode reg","nas-5gs.mm.n1_mode_reg_b1",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_mm_n1_mod), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_s1_mode_reg_b0,
        { "S1 mode reg","nas-5gs.mm.s1_mode_reg_b0",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_mm_s1_mod), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_sal_al_t,
        { "Allowed type","nas-5gs.mm.sal_al_t",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_sal_al_t), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_sal_t_li,
        { "Type of list",   "nas-5gs.mm.sal_t_li",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_sal_t_li_values), 0x60,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_sal_num_e,
        { "Number of elements",   "nas-5gs.mm.sal_num_e",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_sal_num_e_vals), 0x1f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pdu_session_type,
        { "PDU session type",   "nas-5gs.sm.pdu_session_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_pdu_session_type_values), 0x07,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_0_b0,
        { "Spare","nas-5gs.pdu_ses_sts_psi_0_b0",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_1_b1,
        { "PSI(1)","nas-5gs.pdu_ses_sts_psi_1_b1",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_2_b2,
        { "PSI(2)","nas-5gs.pdu_ses_sts_psi_2_b2",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_3_b3,
        { "PSI(3)","nas-5gs.pdu_ses_sts_psi_3_b3",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_4_b4,
        { "PSI(4)","nas-5gs.pdu_ses_sts_psi_4_b4",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_5_b5,
        { "PSI(5)","nas-5gs.pdu_ses_sts_psi_5_b5",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_6_b6,
        { "PSI(6)","nas-5gs.pdu_ses_sts_psi_6_b6",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_7_b7,
        { "PSI(7)","nas-5gs.pdu_ses_sts_psi_7_b7",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_8_b0,
        { "PSI(8)","nas-5gs.pdu_ses_sts_psi_8_b0",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_9_b1,
        { "PSI(9)","nas-5gs.pdu_ses_sts_psi_9_b1",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_10_b2,
        { "PSI(10)","nas-5gs.pdu_ses_sts_psi_10_b2",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_11_b3,
        { "PSI(11)","nas-5gs.pdu_ses_sts_psi_11_b3",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_12_b4,
        { "PSI(12)","nas-5gs.pdu_ses_sts_psi_12_b4",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_13_b5,
        { "PSI(13)","nas-5gs.pdu_ses_sts_psi_13_b5",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_14_b6,
        { "PSI(14)","nas-5gs.pdu_ses_sts_psi_14_b6",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_sts_psi_15_b7,
        { "PSI(15)","nas-5gs.pdu_ses_sts_psi_15_b7",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_sts_psi), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_rect_res_psi_0_b0,
        { "PSI(0) Spare","nas-5gs.pdu_ses_rect_res_psi_0_b0",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_rect_res_psi), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_rect_res_psi_1_b1,
        { "PSI(1)","nas-5gs.pdu_ses_rect_res_psi_1_b1",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_rect_res_psi), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_rect_res_psi_2_b2,
        { "PSI(2)","nas-5gs.pdu_ses_rect_res_psi_2_b2",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_rect_res_psi), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_rect_res_psi_3_b3,
        { "PSI(3)","nas-5gs.pdu_ses_rect_res_psi_3_b3",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_rect_res_psi), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_rect_res_psi_4_b4,
        { "PSI(4)","nas-5gs.pdu_ses_rect_res_psi_4_b4",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_rect_res_psi), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_rect_res_psi_5_b5,
        { "PSI(5)","nas-5gs.pdu_ses_rect_res_psi_5_b5",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_rect_res_psi), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_rect_res_psi_6_b6,
        { "PSI(6)","nas-5gs.pdu_ses_rect_res_psi_6_b6",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_rect_res_psi), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_rect_res_psi_7_b7,
        { "PSI(7)","nas-5gs.pdu_ses_rect_res_psi_7_b7",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_rect_res_psi), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_rect_res_psi_8_b0,
        { "PSI(8)","nas-5gs.pdu_ses_rect_res_psi_8_b0",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_rect_res_psi), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_rect_res_psi_9_b1,
        { "PSI(9)","nas-5gs.pdu_ses_rect_res_psi_9_b1",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_rect_res_psi), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_rect_res_psi_10_b2,
        { "PSI(10)","nas-5gs.pdu_ses_rect_res_psi_10_b2",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_rect_res_psi), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_rect_res_psi_11_b3,
        { "PSI(11)","nas-5gs.pdu_ses_rect_res_psi_11_b3",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_rect_res_psi), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_rect_res_psi_12_b4,
        { "PSI(12)","nas-5gs.pdu_ses_rect_res_psi_12_b4",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_rect_res_psi), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_rect_res_psi_13_b5,
        { "PSI(13)","nas-5gs.pdu_ses_res_psi_13_b5",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_rect_res_psi), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_rect_res_psi_14_b6,
        { "PSI(14)","nas-5gs.pdu_ses_res_psi_14_b6",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_rect_res_psi), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_pdu_ses_rect_res_psi_15_b7,
        { "PSI(15)","nas-5gs.pdu_ses_res_psi_15_b7",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_pdu_ses_rect_res_psi), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_0_b0,
        { "Spare","nas-5gs.ul_data_sts_psi_0_b0",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_1_b1,
        { "PSI(1)","nas-5gs.ul_data_sts_psi_1_b1",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_2_b2,
        { "PSI(2)","nas-5gs.ul_data_sts_psi_2_b2",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_3_b3,
        { "PSI(3)","nas-5gs.ul_data_sts_psi_3_b3",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_4_b4,
        { "PSI(4)","nas-5gs.ul_data_sts_psi_4_b4",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_5_b5,
        { "PSI(5)","nas-5gs.ul_data_sts_psi_5_b5",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_6_b6,
        { "PSI(6)","nas-5gs.ul_data_sts_psi_6_b6",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_7_b7,
        { "PSI(7)","nas-5gs.ul_data_sts_psi_7_b7",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_8_b0,
        { "PSI(8)","nas-5gs.ul_data_sts_psi_8_b0",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_9_b1,
        { "PSI(9)","nas-5gs.ul_data_sts_psi_9_b1",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_10_b2,
        { "PSI(10)","nas-5gs.ul_data_sts_psi_10_b2",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_11_b3,
        { "PSI(11)","nas-5gs.ul_data_sts_psi_11_b3",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_12_b4,
        { "PSI(12)","nas-5gs.ul_data_sts_psi_12_b4",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_13_b5,
        { "PSI(13)","nas-5gs.ul_data_sts_psi_13_b5",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_14_b6,
        { "PSI(14)","nas-5gs.ul_data_sts_psi_14_b6",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ul_data_sts_psi_15_b7,
        { "PSI(15)","nas-5gs.ul_data_sts_psi_15_b7",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_ul_data_sts_psi), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_allow_pdu_ses_sts_psi_0_b0,
        { "Spare","nas-5gs.allow_pdu_ses_sts_psi_0_b0",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_allow_pdu_ses_sts_psi_1_b1,
        { "PSI(1)","nas-5gs.allow_pdu_ses_sts_psi_1_b1",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_allow_pdu_ses_sts_psi), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_allow_pdu_ses_sts_psi_2_b2,
        { "PSI(2)","nas-5gs.allow_pdu_ses_sts_psi_2_b2",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_allow_pdu_ses_sts_psi), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_allow_pdu_ses_sts_psi_3_b3,
        { "PSI(3)","nas-5gs.allow_pdu_ses_sts_psi_3_b3",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_allow_pdu_ses_sts_psi), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_allow_pdu_ses_sts_psi_4_b4,
        { "PSI(4)","nas-5gs.allow_pdu_ses_sts_psi_4_b4",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_allow_pdu_ses_sts_psi), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_allow_pdu_ses_sts_psi_5_b5,
        { "PSI(5)","nas-5gs.allow_pdu_ses_sts_psi_5_b5",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_allow_pdu_ses_sts_psi), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_allow_pdu_ses_sts_psi_6_b6,
        { "PSI(6)","nas-5gs.allow_pdu_ses_sts_psi_6_b6",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_allow_pdu_ses_sts_psi), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_allow_pdu_ses_sts_psi_7_b7,
        { "PSI(7)","nas-5gs.allow_pdu_ses_sts_psi_7_b7",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_allow_pdu_ses_sts_psi), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_allow_pdu_ses_sts_psi_8_b0,
        { "PSI(8)","nas-5gs.allow_pdu_ses_sts_psi_8_b0",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_allow_pdu_ses_sts_psi), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_allow_pdu_ses_sts_psi_9_b1,
        { "PSI(9)","nas-5gs.allow_pdu_ses_sts_psi_9_b1",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_allow_pdu_ses_sts_psi), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_allow_pdu_ses_sts_psi_10_b2,
        { "PSI(10)","nas-5gs.allow_pdu_ses_sts_psi_10_b2",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_allow_pdu_ses_sts_psi), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_allow_pdu_ses_sts_psi_11_b3,
        { "PSI(11)","nas-5gs.allow_pdu_ses_sts_psi_11_b3",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_allow_pdu_ses_sts_psi), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_allow_pdu_ses_sts_psi_12_b4,
        { "PSI(12)","nas-5gs.allow_pdu_ses_sts_psi_12_b4",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_allow_pdu_ses_sts_psi), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_allow_pdu_ses_sts_psi_13_b5,
        { "PSI(13)","nas-5gs.allow_pdu_ses_sts_psi_13_b5",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_allow_pdu_ses_sts_psi), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_allow_pdu_ses_sts_psi_14_b6,
        { "PSI(14)","nas-5gs.allow_pdu_ses_sts_psi_14_b6",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_allow_pdu_ses_sts_psi), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_allow_pdu_ses_sts_psi_15_b7,
        { "PSI(15)","nas-5gs.allow_pdu_ses_sts_psi_15_b7",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_allow_pdu_ses_sts_psi), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_sc_mode,
        { "SSC mode",   "nas-5gs.sm.sc_mode",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sc_mode_values), 0x07,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_eplmnc,
        { "EPLMNC",   "nas-5gs.sm.eplmnc",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_sm_eplmnc), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_ratc,
        { "RATC",   "nas-5gs.sm.ratc",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_sm_ratc), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_naps,
        { "Non-3GPP access path switching (NAPS)",   "nas-5gs.sm.naps",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_ept_s1,
        { "Ethernet PDN type in S1 mode (EPT-S1)",   "nas-5gs.sm.ept_s1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_catbo,
        { "Current Access Type Back-off timer (CATBO)",   "nas-5gs.sm.catbo",
            FT_BOOLEAN, 8, TFS(&tfs_5gs_sm_catbo), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_abo,
        { "All PLMNs Back-off timer (ABO)",   "nas-5gs.sm.abo",
            FT_BOOLEAN, 8, TFS(&tfs_5gs_sm_abo), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_atsss_cont,
        { "ATSSS container contents",   "nas-5gs.sm.atsss_cont",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_cpoi,
        { "Control plane only indication value (CPOI)",   "nas-5gs.sm.cpoi",
            FT_BOOLEAN, 8, TFS(&tfs_5gs_sm_cpoi), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_ip_hdr_comp_config_p0104,
        { "RoHC profile 0x0104 (IP)", "nas-5gs.sm.ip_hdr_comp_config.p0104",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_ip_hdr_comp_config_p0103,
        { "RoHC profile 0x0103 (ESP/IP)", "nas-5gs.sm.ip_hdr_comp_config.p0103",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_ip_hdr_comp_config_p0102,
        { "RoHC profile 0x0102 (UDP/IP)", "nas-5gs.sm.ip_hdr_comp_config.p0102",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_ip_hdr_comp_config_p0006,
        { "RoHC profile 0x0006 (TCP/IP)", "nas-5gs.sm.ip_hdr_comp_config.p0006",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_ip_hdr_comp_config_p0004,
        { "RoHC profile 0x0004 (IP)", "nas-5gs.sm.ip_hdr_comp_config.p0004",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_ip_hdr_comp_config_p0003,
        { "RoHC profile 0x0003 (ESP/IP)", "nas-5gs.sm.ip_hdr_comp_config.p0003",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_ip_hdr_comp_config_p0002,
        { "RoHC profile 0x0002 (UDP/IP)", "nas-5gs.sm.ip_hdr_comp_config.p0002",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_ip_hdr_comp_config_max_cid,
        { "MAX_CID", "nas-5gs.sm.ip_hdr_comp_config.max_cid",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_ip_hdr_comp_config_add_ip_hdr_compr_cxt_setup_params_type,
        { "Additional header compression context setup parameters type", "nas-5gs.sm.ip_hdr_comp_config.add_hdr_compr_cxt_setup_params_type",
            FT_UINT8, BASE_HEX, VALS(nas_5gs_sm_ip_hdr_comp_config_add_ip_hdr_compr_cxt_setup_params_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_ip_hdr_comp_config_add_ip_hdr_compr_cxt_setup_params_cont,
        { "Additional header compression context setup parameters container", "nas-5gs.sm.ip_hdr_comp_config.add_hdr_compr_cxt_setup_params_cont",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_ds_tt_eth_port_mac_addr,
        { "DS-TT Ethernet port MAC address", "nas-5gs.sm.ds_tt_eth_port_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_ue_ds_tt_residence_time,
        { "UE-DS-TT residence time", "nas-5gs.sm.ue_ds_tt_residence_time",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_port_mgmt_info_cont,
        { "Port management information container", "nas-5gs.sm.port_mgmt_info_cont",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_eth_hdr_comp_config_cid_len,
        { "Port management information container", "nas-5gs.sm.eth_hdr_comp_config.cid_len",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_eth_hdr_comp_config_cid_len_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pdu_session_pair_id,
        { "PDU session pair ID", "nas-5gs.sm.pdu_session_pair_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pdu_session_rsn,
        { "RSN", "nas-5gs.sm.rsn",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_pdu_session_rsn_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_sel_sc_mode,
        { "Selected SSC mode",   "nas-5gs.sm.sel_sc_mode",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sc_mode_values), 0x70,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_tpmic_b7,
        { "Transfer of port management information containers (TPMIC)",   "nas-5gs.sm.tpmic",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_atsss_st_b3_b6,
        { "Supported ATSSS steering functionalities and steering modes (ATSSS-ST)",   "nas-5gs.sm.atsss_st",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_atsss_st_b3_b6_vals), 0x78,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_ept_s1_b2,
        { "Ethernet PDN type in S1 mode (EPT-S1)",   "nas-5gs.sm.ept_s1",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_mh6_pdu_b1,
        { "Multi-homed IPv6 PDU session (MH6-PDU)",   "nas-5gs.sm.mh6_pdu",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_rqos_b0,
        { "Reflective QoS (RqoS)",   "nas-5gs.sm.rqos",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_sdnaepc_b1,
        { "Secondary DN authentication and authorization over EPC (SDNAEPC)",   "nas-5gs.sm.sdnaepc",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_apmqf_b0,
        { "Access performance measurements per QoS flow rule (APMQF)",   "nas-5gs.sm.apmqf",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_5gsm_cause,
        { "5GSM cause",   "nas-5gs.sm.5gsm_cause",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_cause_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_apsi,
        { "Always-on PDU session",   "nas-5gs.sm.apsi",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_sm_apsi), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_apsr,
        { "Always-on PDU session",   "nas-5gs.sm.apsr",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_int_prot_max_data_rate_ul,
        { "Integrity protection maximum data rate for uplink",   "nas-5gs.sm.int_prot_max_data_rate_ul",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_int_prot_max_data_rate_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_int_prot_max_data_rate_dl,
        { "Integrity protection maximum data rate for downlink",   "nas-5gs.sm.int_prot_max_data_rate_dl",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_int_prot_max_data_rate_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_si6lla,
        { "SMF's IPv6 link local address (SI6LLA)",   "nas-5gs.sm.si6lla",
            FT_BOOLEAN, 8, TFS(&tfs_present_absent), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pdu_ses_type,
        { "PDU session type",   "nas-5gs.sm.pdu_ses_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_pdu_ses_type_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pdu_addr_inf_ipv4,
        { "PDU address information", "nas-5gs.sm.pdu_addr_inf_ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pdu_addr_inf_ipv6,
        { "PDU address information", "nas-5gs.sm.pdu_addr_inf_ipv6",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_smf_ipv6_lla,
        { "SMF's IPv6 link local address", "nas-5gs.sm.smf_ipv6_lla",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_qos_rule_id,
        { "QoS rule identifier",   "nas-5gs.sm.qos_rule_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_length,
        { "Length",   "nas-5gs.sm.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_rop,
        { "Rule operation code",   "nas-5gs.sm.rop",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_rule_operation_code_values), 0xe0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_dqr,
        { "DQR",   "nas-5gs.sm.dqr",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_sm_dqr), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_nof_pkt_filters,
        { "Number of packet filters",   "nas-5gs.sm.nof_pkt_filters",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pkt_flt_dir,
        { "Packet filter direction",   "nas-5gs.sm.pkt_flt_dir",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_pkt_flt_dir_values), 0x30,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pkt_flt_id,
        { "Packet filter identifier",   "nas-5gs.sm.pkt_flt_id",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pf_len,
        { "Length",   "nas-5gs.sm.pf_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_pf_type,
        { "Packet filter component type",   "nas-5gs.sm.pf_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_pf_type_values), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_e,
        { "E bit",   "nas-5gs.sm.e",
            FT_UINT8, BASE_DEC, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_nof_params,
        { "Number of parameters",   "nas-5gs.sm.nof_params",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_param_id,
        { "Parameter identifier",   "nas-5gs.sm.param_id",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_param_id_values), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_param_len,
        { "Length",   "nas-5gs.sm.param_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_addr_mask_ipv4,
        { "IPv4 address mask", "nas-5gs.ipv4_address_mask",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ipv6,
        { "IPv6 address", "nas-5gs.ipv6_address",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ipv6_prefix_len,
        { "IPv6 prefix length", "nas-5gs.ipv6_prefix_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_protocol_identifier_or_next_hd,
        { "Protocol identifier/Next header type", "nas-5gs.protocol_identifier_or_next_hd",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_qos_rule_precedence,
        { "QoS rule precedence",   "nas-5gs.sm.qos_rule_precedence",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_segregation,
        { "Segregation",   "nas-5gs.sm.segregation",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_param_cont,
        { "Parameter content",   "nas-5gs.sm.param_content",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_5qi,
        { "5QI",   "nas-5gs.sm.5qi",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_unit_for_gfbr_ul,
        { "Unit for GFBR uplink",   "nas-5gs.sm.unit_for_gfbr_ul",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_unit_for_session_ambr_values), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_gfbr_ul,
        { "GFBR uplink",   "nas-5gs.sm.gfbr_ul",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_unit_for_gfbr_dl,
        { "Unit for GFBR downlink",   "nas-5gs.sm.unit_for_gfbr_dl",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_unit_for_session_ambr_values), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_gfbr_dl,
        { "GFBR downlink",   "nas-5gs.sm.gfbr_dl",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_unit_for_mfbr_ul,
        { "Unit for MFBR uplink",   "nas-5gs.sm.unit_for_mfbr_ul",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_unit_for_session_ambr_values), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_mfbr_ul,
        { "MFBR uplink",   "nas-5gs.sm.mfbr_ul",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_unit_for_mfbr_dl,
        { "Unit for MFBR downlink",   "nas-5gs.sm.unit_for_mfbr_dl",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_unit_for_session_ambr_values), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_mfbr_dl,
        { "MFBR downlink",   "nas-5gs.sm.mfbr_dl",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_averaging_window,
        { "Averaging window",   "nas-5gs.sm.averaging_window",
            FT_UINT16, BASE_DEC | BASE_UNIT_STRING, UNS(&units_millisecond_milliseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_eps_bearer_id,
        { "EPS bearer identity",   "nas-5gs.sm.eps_bearer_id",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_qfi,
        { "Qos flow identifier",   "nas-5gs.sm.qfi",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_mapd_eps_b_cont_id,
        { "EPS bearer identity",   "nas-5gs.sm.mapd_eps_b_cont_id",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_mapd_eps_b_cont_opt_code,
        { "Operation code",   "nas-5gs.sm.mapd_eps_b_cont_opt_code",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_mapd_eps_b_cont_opt_code_vals), 0xc0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_qos_des_flow_opt_code,
        { "Operation code",   "nas-5gs.sm.hf_nas_5gs_sm_qos_des_flow_opt_code",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_qos_des_flow_opt_code_vals), 0xe0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_mapd_eps_b_cont_E,
        { "E bit",   "nas-5gs.sm.mapd_eps_b_cont_E",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_mapd_eps_b_cont_E_vals), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_mapd_eps_b_cont_E_mod,
        { "E bit",   "nas-5gs.sm.mapd_eps_b_cont_E_mod",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_mapd_eps_b_cont_E_Modify_vals), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_mapd_eps_b_cont_num_eps_parms,
        { "Number of EPS parameters",   "nas-5gs.sm.mapd_eps_b_cont_num_eps_parms",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_mapd_eps_b_cont_param_id,
        { "EPS parameter identity",   "nas-5gs.sm.mapd_eps_b_cont_param_id",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_mapd_eps_b_cont_param_id_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_unit_for_session_ambr_dl,
         { "Unit for Session-AMBR for downlink",   "nas-5gs.sm.unit_for_session_ambr_dl",
             FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_unit_for_session_ambr_values), 0x0,
             NULL, HFILL }
        },
        { &hf_nas_5gs_sm_unit_for_session_ambr_ul,
        { "Unit for Session-AMBR for uplink",   "nas-5gs.sm.unit_for_session_ambr_ul",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_sm_unit_for_session_ambr_values), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_session_ambr_dl,
        { "Session-AMBR for downlink",   "nas-5gs.sm.session_ambr_dl",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_session_ambr_ul,
        { "Session-AMBR for uplink",   "nas-5gs.sm.session_ambr_ul",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_dm_spec_id,
        { "DN-specific identity",   "nas-5gs.sm.dm_spec_id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_all_ssc_mode_b0,
        { "SSC mode 1",   "nas-5gs.sm.all_ssc_mode_b0",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_all_ssc_mode_b1,
        { "SSC mode 2",   "nas-5gs.sm.all_ssc_mode_b1",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_all_ssc_mode_b2,
        { "SSC mode 3",   "nas-5gs.sm.all_ssc_mode_b2",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_supi_fmt,
        { "SUPI format","nas-5gs.mm.suci.supi_fmt",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_supi_fmt_vals), 0x70,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_routing_indicator,
        { "Routing indicator",   "nas-5gs.mm.suci.routing_indicator",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_prot_scheme_id,
        { "Protection scheme Id",   "nas-5gs.mm.suci.scheme_id",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_prot_scheme_id_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_pki,
        { "Home network public key identifier",   "nas-5gs.mm.suci.pki",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_suci_msin,
        { "MSIN", "nas-5gs.mm.suci.msin",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_scheme_output,
        { "Scheme output", "nas-5gs.mm.suci.scheme_output",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_scheme_output_ecc_public_key,
        { "ECC ephemeral public key", "nas-5gs.mm.suci.scheme_output.ecc_public_key",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_scheme_output_ciphertext,
        { "Ciphertext", "nas-5gs.mm.suci.scheme_output.ciphertext",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_scheme_output_mac_tag,
        { "MAC tag", "nas-5gs.mm.suci.scheme_output.mac_tag",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_suci_nai,
        { "NAI", "nas-5gs.mm.suci.nai",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_imei,
        { "IMEI", "nas-5gs.mm.imei",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_imeisv,
        { "IMEISV", "nas-5gs.mm.imeisv",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_mauri,
        { "MAC address usage restriction indication (MAURI)", "nas-5gs.mm.mauri",
            FT_BOOLEAN, 8, TFS(&nas_5gs_mauri_tfs), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_mac_addr,
        { "MAC address", "nas-5gs.mm.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_eui_64,
        { "EUI-64", "nas-5gs.mm.eui_64",
            FT_EUI64, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_reg_res_res,
        { "5GS registration result",   "nas-5gs.mm.reg_res.res",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_reg_res_values), 0x07,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_reg_res_sms_allowed,
        { "SMS over NAS",   "nas-5gs.mm.reg_res.sms_all",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_reg_res_nssaa_perf,
        { "NSSAA Performed",   "nas-5gs.mm.reg_res.nssaa_perf",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_mm_reg_res_nssaa_perf), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_reg_res_emergency_reg,
        { "Emergency registered",   "nas-5gs.mm.reg_res.emergency_reg",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_mm_reg_res_emergency_reg), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_reg_res_disaster_roaming_reg_res,
        { "Disaster roaming registration result",   "nas-5gs.mm.reg_res.disaster_roaming_reg_res",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_mm_reg_res_disaster_roaming_reg_res), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_amf_region_id,
        { "AMF Region ID",   "nas-5gs.amf_region_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_amf_set_id,
        { "AMF Set ID",   "nas-5gs.amf_set_id",
            FT_UINT16, BASE_DEC, NULL, 0xffc0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_amf_pointer,
        { "AMF Pointer",   "nas-5gs.amf_pointer",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_5g_tmsi,
        { "5G-TMSI",   "nas-5gs.5g_tmsi",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_ims_vops_3gpp,
        { "IMS voice over PS session indicator (IMS VoPS)",   "nas-5gs.nw_feat_sup.vops_3gpp",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_ims_vops_n3gpp,
        { "IMS voice over PS session over non-3GPP access indicator (IMS-VoPS-N3GPP)",   "nas-5gs.nw_feat_sup.vops_n3gpp",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_ims_emc_b3b2,
        { "Emergency service support indicator (EMC)",   "nas-5gs.nw_feat_sup.emc",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_nw_feat_sup_emc_values), 0x0c,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_ims_emf_b5b4,
        { "Emergency service fallback indicator (EMF)",   "nas-5gs.nw_feat_sup.emf",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_nw_feat_sup_emf_values), 0x30,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_ims_iwk_n26_b6,
        { "Interworking without N26 (IWK N26)",   "nas-5gs.nw_feat_sup.iwk_n26",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_mpsi_b7,
        { "MPS indicator (MPSI)",   "nas-5gs.nw_feat_sup.mpsi",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_nw_feat_sup_mpsi), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_emcn3,
        { "Emergency services over non-3GPP access (EMCN3)",   "nas-5gs.nw_feat_sup.emcn3",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_mcsi,
        { "MCS indicator (MCSI)",   "nas-5gs.nw_feat_sup.mcsi",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_nw_feat_sup_mcsi), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_restrict_ec,
        { "Restriction on enhanced coverage (RestrictEC)",   "nas-5gs.nw_feat_sup.restrict_ec",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_nw_feat_sup_restrict_ec_values), 0x0c,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_5g_cp_ciot,
        { "Control plane CIoT 5GS optimization (5G-CP CIoT)",   "nas-5gs.nw_feat_sup.5g_cp_ciot",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_n3_data,
        { "N3 data transfer (N3 data)",   "nas-5gs.nw_feat_sup.n3_data",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_5g_iphc_cp_ciot,
        { "IP header compression for control plane CIoT 5GS optimization (5G-IPHC-CP CIoT)",   "nas-5gs.nw_feat_sup.5g_iphc_cp_ciot",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_5g_ciot_up,
        { "User plane CIoT 5GS optimization (5G-UP CIoT)",   "nas-5gs.nw_feat_sup.5g_ciot_up",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_5g_lcs,
        { "Location Services indicator in 5GC (5G-LCS)",   "nas-5gs.nw_feat_sup.5g_lcs",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_ats_ind,
        { "ATSSS support indicator (ATS-IND)",   "nas-5gs.nw_feat_sup.ats_ind",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_5g_ehc_cp_ciot,
        { "Ethernet header compression for control plane CIoT 5GS optimization (5G-EHC-CP CIoT)",   "nas-5gs.nw_feat_sup.5g_ehc_cp_ciot",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_ncr,
        { "N1 NAS signalling connection release (NCR)",   "nas-5gs.nw_feat_sup.ncr",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_piv,
        { "Paging indication for voice services (PIV)",   "nas-5gs.nw_feat_sup.piv",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_rpr,
        { "Reject paging request (RPR)",   "nas-5gs.nw_feat_sup.rpr",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_pr,
        { "Paging restriction (PR)",   "nas-5gs.nw_feat_sup.pr",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_un_per,
        { "Unavailability period (UN-PER)",   "nas-5gs.nw_feat_sup.un_per",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_naps,
        { "Non-3GPP access path switching (NAPS)",   "nas-5gs.nw_feat_sup.naps",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_lcs_upp,
        { "LCS-UPP user plane positioning (LCS-UPP)",   "nas-5gs.nw_feat_sup.lcs_upp",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_supl,
        { "SUPL user plane positioning (SUPL)",   "nas-5gs.nw_feat_sup.supl",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nw_feat_sup_rslp,
        { "Ranging and sidelink positioning support (RSLP)",   "nas-5gs.nw_feat_sup.rslp",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },


        { &hf_nas_5gs_tac,
        { "TAC",   "nas-5gs.tac",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_tal_t_li,
        { "Type of list",   "nas-5gs.mm.tal_t_li",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_tal_t_li_values), 0x60,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_tal_num_e,
        { "Number of elements",   "nas-5gs.mm.tal_num_e",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_tal_num_e), 0x1f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_mapd_eps_b_cont_eps_param_cont,
        { "EPS parameter contents",   "nas-5gs.sm.mapd_eps_b_cont_eps_param_cont",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_max_nb_sup_pkt_flt_nb,
        { "Maximum number of supported packet filters", "nas-5gs.sm.max_nb_sup_pkt_flt.nb",
            FT_UINT16, BASE_DEC, NULL, 0xffe0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sm_max_nb_sup_pkt_flt_spare,
        { "Spare", "nas-5gs.sm.max_nb_sup_pkt_flt.spare",
            FT_UINT16, BASE_HEX, NULL, 0x001f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_kacf,
        { "K_AMF change flag", "nas-5gs.kacf",
            FT_BOOLEAN, 8, TFS(&nas_5gs_kacf_tfs), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ncc,
        { "NCC", "nas-5gs.ncc",
            FT_UINT8, BASE_DEC, NULL, 0x70,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_rinmr,
        { "Retransmission of initial NAS message request (RINMR)", "nas-5gs.mm.rinmr",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_hdp,
        { "Horizontal derivation parameter (HDP)", "nas-5gs.mm.hdp",
            FT_BOOLEAN, 8, TFS(&tfs_required_not_required), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_cipher_key,
        { "Cipher Key", "nas-5gs.mm.cipher_key",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_dcni,
        { "Default configured NSSAI indication (DCNI)", "nas-5gs.mm.dcni",
            FT_BOOLEAN, 8, TFS(&nas_5gs_mm_dcni_tfs), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nssci,
        { "Network slicing subscription change indication (NSSCI)", "nas-5gs.mm.nssci",
            FT_BOOLEAN, 8, TFS(&tfs_changed_not_changed), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nssai_inc_mode,
        { "NSSAI inclusion mode", "nas-5gs.mm.nssai_inc_mode",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_nssai_inc_mode_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ue_usage_setting,
        { "UE's usage setting", "nas-5gs.mm.ue_usage_setting",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_mm_ue_usage_setting), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_5gs_drx_param,
        { "DRX value", "nas-5gs.mm.drx_value",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_drx_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_op_def_access_cat_len,
        { "Length of operator-defined access category definition contents", "nas-5gs.mm.operator_defined_access_cat.len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_op_def_access_cat_precedence,
        { "Precedence", "nas-5gs.mm.operator_defined_access_cat.precedence",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_op_def_access_cat_psac,
        { "Presence of standardized access category", "nas-5gs.mm.operator_defined_access_cat.psac",
            FT_BOOLEAN, 8, TFS(&tfs_included_not_included), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_op_def_access_cat_number,
        { "Access category number", "nas-5gs.mm.operator_defined_access_cat.number",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(nas_5gs_mm_access_cat_number), 0x1f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_op_def_access_cat_criteria_length,
        { "Length of criteria", "nas-5gs.mm.operator_defined_access_cat.criteria_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_op_def_access_cat_criteria_type,
        { "Criteria type", "nas-5gs.mm.operator_defined_access_cat.criteria_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_op_def_access_cat_criteria_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_op_def_access_cat_criteria_dnn_count,
        { "DNN count", "nas-5gs.mm.operator_defined_access_cat.criteria_dnn_count",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_op_def_access_cat_criteria_dnn_len,
        { "DNN length", "nas-5gs.mm.operator_defined_access_cat.criteria_dnn_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_op_def_access_cat_criteria_os_id_os_app_id_count,
        { "OS Id + OS App Id count", "nas-5gs.mm.operator_defined_access_cat.criteria_os_id_os_app_id_count",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_op_def_access_cat_criteria_os_id,
        { "OS Id", "nas-5gs.mm.operator_defined_access_cat.criteria_os_id",
            FT_GUID, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_op_def_access_cat_criteria_os_app_id_len,
        { "OS App Id length", "nas-5gs.mm.operator_defined_access_cat.criteria_os_app_id_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_op_def_access_cat_criteria_os_app_id,
        { "OS App Id", "nas-5gs.mm.operator_defined_access_cat.criteria_os_app_id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_op_def_access_cat_criteria_s_nssai_count,
        { "S-NSSAI count", "nas-5gs.mm.operator_defined_access_cat.criteria_s_nssai_count",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_op_def_access_cat_criteria_s_nssai_len,
        { "S-NSSAI length", "nas-5gs.mm.operator_defined_access_cat.criteria_s_nssai_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_op_def_access_cat_standardized_number,
        { "Standardized access category number", "nas-5gs.mm.operator_defined_access_cat.standardized_number",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(nas_5gs_mm_access_standardized_cat_number), 0x1f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_sms_indic_sai,
        { "SMS over NAS",   "nas-5gs.mm.ms_indic.sai",
            FT_BOOLEAN, 8, TFS(&tfs_allowed_not_allowed), 0x01,
            "SMS availability indication (SAI)", HFILL }
        },
        { &hf_nas_5gs_sor_hdr0_ap,
        { "Additional parameters (AP)",   "nas-5gs.sor_hdr0.ap",
            FT_BOOLEAN, 8, TFS(&tfs_included_not_included), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_hdr0_ack,
        { "Acknowledgement (ACK)",   "nas-5gs.sor_hdr0.ack",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_hdr0_list_type,
        { "List type",   "nas-5gs.sor_hdr0.list_type",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_list_type), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_hdr0_list_ind,
        { "List indication",   "nas-5gs.sor_hdr0.list_ind",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_list_ind), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_hdr0_sor_data_type,
        { "SOR data type",   "nas-5gs.sor.sor_data_type",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_sor_data_type), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_mssi,
        { "ME support of SOR-CMCI indicator (MSSI)",   "nas-5gs.sor.mssi",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_mssnpnsi,
        { "ME support of SOR-SNPN-SI indicator (MSSNPNSI)",   "nas-5gs.sor.mssnpnsi",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_msssnpnsils,
        { "MS support of SOR-SNPN-SI-LS indicator (MSSNPNSILS)",   "nas-5gs.sor.msssnpnsils",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_mac_iue,
        { "SOR-MAC-IUE", "nas-5gs.mm.sor_mac_iue",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_mac_iausf,
        { "SOR-MAC-IAUSF", "nas-5gs.mm.sor_mac_iausf",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_counter_sor,
        { "CounterSOR", "nas-5gs.mm.counter_sor",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_sec_pkt,
        { "Secured packet", "nas-5gs.mm.sor_sec_pkt",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_sssli,
        { "SOR-SNPN-SI-LS indicator", "nas-5gs.mm.sor_sssli",
            FT_BOOLEAN, 8, TFS(&tfs_present_absent), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_sssi,
        { "SOR-SNPN-SI indicator", "nas-5gs.mm.sor_sssi",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_sor_sssi), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_sscmi,
        { "Store SOR-CMCI in ME indicator (SSCMI)", "nas-5gs.mm.sor_sscmi",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_si,
        { "SOR-CMCI indicator (SI)", "nas-5gs.mm.sor_si",
            FT_BOOLEAN, 8, TFS(&tfs_present_absent), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_plmn_id_act_len,
        { "Length of PLMN ID and access technology list", "nas-5gs.mm.sor_plmn_id_act_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_cmci_len,
        { "Length of SOR-CMCI contents", "nas-5gs.mm.sor_cmci_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_cmci_payload,
        { "SOR-CMCI contents payload", "nas-5gs.mm.sor_cmci_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_snpn_si_len,
        { "Length of SOR-SNPN-SI contents", "nas-5gs.mm.snpn_si_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_snpn_si_payload,
        { "SOR-SNPN-SI contents payload", "nas-5gs.mm.snpn_si_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_snpn_si_ls_len,
        { "Length of SOR-SNPN-SI-LS contents", "nas-5gs.mm.snpn_si_ls_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sor_snpn_si_ls_payload,
        { "SOR-SNPN-SI-LS contents payload", "nas-5gs.mm.snpn_si_ls_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_access_tech_o1_b7,
        { "Access technology UTRAN",   "nas-5gs.access_tech_o1_b7.utran",
            FT_BOOLEAN, 8, TFS(&tfs_selected_not_selected), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_access_tech_o1_b6,
        { "Access technology E-UTRAN",   "nas-5gs.access_tech_o1_b6.e_utran",
            FT_BOOLEAN, 8, TFS(&tfs_selected_not_selected), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_access_tech_o1_b5,
        { "Access technology E-UTRAN in WB-S1 mode",   "nas-5gs.access_tech_o1_b5.e_utran_in_wb_s1_mode",
            FT_BOOLEAN, 8, TFS(&tfs_selected_not_selected), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_access_tech_o1_b4,
        { "Access technology E-UTRAN in NB-S1 mode",   "nas-5gs.access_tech_o1_b4.e_utran_in_nb_s1_mode",
            FT_BOOLEAN, 8, TFS(&tfs_selected_not_selected), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_access_tech_o1_b3,
        { "Access technology NG-RAN",   "nas-5gs.access_tech_o1_b3.ng_ran",
            FT_BOOLEAN, 8, TFS(&tfs_selected_not_selected), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_access_tech_o2_b7,
        { "Access technology GSM",   "nas-5gs.access_tech_o2_b7.gsm",
            FT_BOOLEAN, 8, TFS(&tfs_selected_not_selected), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_access_tech_o2_b6,
        { "Access technology GSM COMPACT",   "nas-5gs.access_tech_o2_b6.gsm_compact",
            FT_BOOLEAN, 8, TFS(&tfs_selected_not_selected), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_access_tech_o2_b5,
        { "Access technology CDMA2000 HRPD",   "nas-5gs.access_tech_o2_b5.cdma2000_hrpd",
            FT_BOOLEAN, 8, TFS(&tfs_selected_not_selected), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_access_tech_o2_b4,
        { "Access technology CDMA2000 1xRTT",   "nas-5gs.access_tech_o2_b4.cdma2000_1x_rtt",
            FT_BOOLEAN, 8, TFS(&tfs_selected_not_selected), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_access_tech_o2_b3,
        { "Access technology EC-GSM-IoT",   "nas-5gs.access_tech_o2_b3.ec_gsm_iot",
            FT_BOOLEAN, 8, TFS(&tfs_selected_not_selected), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_access_tech_o2_b2,
        { "Access technology GSM",   "nas-5gs.access_tech_o2_b2.gsm",
            FT_BOOLEAN, 8, TFS(&tfs_selected_not_selected), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_single_port_type,
        { "Port number", "nas-5gs.single_port_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_port_range_type_low,
        { "Port range low limit", "nas-5gs.port_range_low_limit",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_port_range_type_high,
        { "Port range high limit", "nas-5gs.port_range_high_limit",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sec_param_idx,
        { "Security parameter index", "nas-5gs.security_parameter_index",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_tos_tc_val,
        { "Type of service/Traffic class value", "nas-5gs.tos_tc_value",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_tos_tc_mask,
        { "Type of service/Traffic class mask", "nas-5gs.tos_tc_mask",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_flow_label,
        { "Flow label", "nas-5gs.flow_label",
            FT_UINT24, BASE_HEX, NULL, 0x0fffff,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mac_addr,
        { "MAC address", "nas-5gs.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_vlan_tag_vid,
        { "VID", "nas-5gs.vlan_tag_vid",
            FT_UINT16, BASE_HEX, NULL, 0x0fff,
            NULL, HFILL }
        },
        { &hf_nas_5gs_vlan_tag_pcp,
        { "PCP", "nas-5gs.vlan_tag_pcp",
            FT_UINT8, BASE_HEX, NULL, 0x0e,
            NULL, HFILL }
        },
        { &hf_nas_5gs_vlan_tag_dei,
        { "DEI", "nas-5gs.vlan_tag_dei",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ethertype,
        { "Ethertype", "nas-5gs.ethertype",
            FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mac_addr_low,
        { "MAC address range low limit", "nas-5gs.mac_addr_low",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mac_addr_high,
        { "MAC address range high limit", "nas-5gs.mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_updp_ue_pol_sect_sublst_len,
        { "Length", "nas-5gs.updp.ue_pol_sect_sublst_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_updp_ue_pol_sect_subresult_len,
        { "Number of results", "nas-5gs.updp.ue_pol_sect_subresult_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_updp_instr_len,
        { "Length", "nas-5gs.updp.instr_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_updp_upsc,
        { "UPSC", "nas-5gs.updp.upsc",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_updp_failed_instruction_order,
        { "Failed instruction order", "nas-5gs.updp.failed_instruction_order",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_updp_policy_len,
        { "Length", "nas-5gs.updp.policy_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_updp_ue_policy_part_type,
        { "UE policy part type", "nas-5gs.updp.ue_policy_part_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_updp_ue_policy_part_type_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_updp_ue_policy_part_cont,
        { "UE policy part contents", "nas-5gs.updp.ue_policy_part_cont",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_rule_len,
        { "Length", "nas-5gs.ursp.rule_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_rule_prec,
        { "Precedence", "nas-5gs.ursp.rule_prec",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_lst_len,
        { "Length", "nas-5gs.ursp.traff_desc_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc,
        { "Traffic descriptor", "nas-5gs.ursp.traff_desc",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_ursp_traff_desc_component_type_values), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_r_sel_desc_lst_len,
        { "Length", "nas-5gs.ursp.r_sel_desc_lst_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_r_sel_desc_lst,
        { "Route selection descriptor list", "nas-5gs.ursp.r_sel_desc_lst",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_ipv4,
        { "IPv4 address", "nas-5gs.ursp.traff_desc.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_ipv4_mask,
        { "IPv4 mask", "nas-5gs.ursp.traff_desc.ipv4_mask",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_ipv6,
        { "IPv6 address", "nas-5gs.ursp.traff_desc.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_ipv6_prefix_len,
        { "IPv6 prefix length", "nas-5gs.ursp.traff_desc.ipv6_prefix_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_next_hdr,
        { "Protocol identifier/next header type", "nas-5gs.ursp.traff_desc.next_hdr",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_single_remote_port,
        { "Remote port", "nas-5gs.ursp.traff_desc.single_remote_port",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_remote_port_range_low,
        { "Remote port range low", "nas-5gs.ursp.traff_desc.remote_port_range_low",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_remote_port_range_high,
        { "Remote port range high", "nas-5gs.ursp.traff_desc.remote_port_range_high",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_sec_param_index,
        { "Security parameter index", "nas-5gs.ursp.traff_desc.sec_param_index",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_tos_tc,
        { "Type of service/traffic class", "nas-5gs.ursp.traff_desc.tos_tc",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_tos_tc_mask,
        { "Type of service/traffic class mask", "nas-5gs.ursp.traff_desc.tos_tc_mask",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_flow_label,
        { "Flow label", "nas-5gs.ursp.traff_desc.flow_label",
            FT_UINT24, BASE_HEX, NULL, 0x0fffff,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_dest_mac_addr,
        { "Destination MAC address", "nas-5gs.ursp.traff_desc.dest_mac_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_ctag_vid,
        { "802.1Q C-TAG VID", "nas-5gs.ursp.traff_desc.ctag_vid",
            FT_UINT16, BASE_HEX, NULL, 0x0fff,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_stag_vid,
        { "802.1Q S-TAG VID", "nas-5gs.ursp.traff_desc.stag_vid",
            FT_UINT16, BASE_HEX, NULL, 0x0fff,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_ctag_pcp,
        { "802.1Q C-TAG PCP", "nas-5gs.ursp.traff_desc.ctag_pcp",
            FT_UINT8, BASE_HEX, NULL, 0x0e,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_ctag_dei,
        { "802.1Q C-TAG DEI", "nas-5gs.ursp.traff_desc.ctag_dei",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_stag_pcp,
        { "802.1Q S-TAG PCP", "nas-5gs.ursp.traff_desc.stag_pcp",
            FT_UINT8, BASE_HEX, NULL, 0x0e,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_stag_dei,
        { "802.1Q S-TAG DEI", "nas-5gs.ursp.traff_desc.stag_dei",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_ethertype,
        { "Ethertype", "nas-5gs.ursp.traff_desc.ethertype",
            FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_conn_cap_len,
        { "Connection capabilities length", "nas-5gs.ursp.traff_desc.conn_cap_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_conn_cap,
        { "Connection capability", "nas-5gs.ursp.traff_desc.conn_cap",
            FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(nas_5gs_ursp_traff_desc_conn_cap_values), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_dest_fqdn_len,
        { "Destination FQDN length", "nas-5gs.ursp.traff_desc.dest_fqdn_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_dest_fqdn,
        { "Destination FQDN", "nas-5gs.ursp.traff_desc.dest_fqdn",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_dest_mac_addr_range_low,
        { "Destination MAC address range low", "nas-5gs.ursp.traff_desc.dest_mac_addr_range_low",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_dest_mac_addr_range_high,
        { "Destination MAC address range high", "nas-5gs.ursp.traff_desc.dest_mac_addr_range_high",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_traff_desc_len,
        { "Length", "nas-5gs.ursp.r_sel_desc_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_r_sel_des_prec,
        { "Precedence", "nas-5gs.ursp.r_sel_des_prec",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_r_sel_des_cont_len,
        { "Length", "nas-5gs.ursp.r_sel_des_cont_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ursp_ursp_r_sel_desc_comp_type,
        { "Route selection descriptor component type identifier", "nas-5gs.ursp.r_sel_desc_comp_type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_ursp_r_sel_desc_comp_type_values), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_dnn_len,
        { "Length", "nas-5gs.dnn_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_sup_andsp,
        { "Support ANDSP",   "nas-5gs.sup_andsp",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_nssui,
        { "Non-subscribed SNPN signalled URSP handling indication (NSSUI)",   "nas-5gs.nssui",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_nssui), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_upsi_sublist_len,
        { "Length", "nas-5gs.upsi_sublist_len",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_upsc,
        { "UPSC", "nas-5gs.upsc",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_os_id,
          { "OS id(UUID)", "nas-5gs.os_id",
            FT_GUID, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },
        { &hf_nas_5gs_upds_cause,
        { "UPDS cause", "nas-5gs.upds_cause",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_updp_upds_cause_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_v2xuui,
        { "UE policies for V2X communication over Uu indicator (V2XUUI)", "nas-5gs.v2xuui",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_v2xpc5i,
        { "UE policies for V2X communication over PC5 indicator (V2XPC5I)", "nas-5gs.v2xpc5i",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_os_app_id_len,
        { "Length", "nas-5gs.app_id_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_os_app_id,
          { "OS App id", "nas-5gs.os_app_id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },
        { &hf_nas_5gs_mm_len_of_rej_s_nssai,
        { "Length of rejected S-NSSAI", "nas-5gs.mm.len_of_rej_s_nssai",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_rej_s_nssai_cause,
        { "Cause", "nas-5gs.mm.rej_s_nssai.cause",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_rej_s_nssai_cause_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ue_radio_cap_id,
        { "UE radio capability ID", "nas-5gs.mm.ue_radio_cap_id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ue_radio_cap_id_del_req,
        { "Deletion request", "nas-5gs.mm.ue_radio_cap_id_del_req",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_ue_radio_cap_id_del_req_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_trunc_amf_set_id,
        { "Truncated AMF Set ID value", "nas-5gs.mm.trunc_amf_set_id",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_amf_trunc_set_id_vals), 0xf0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_trunc_amf_pointer,
        { "Truncated AMF Pointer value", "nas-5gs.mm.trunc_amf_pointer",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_amf_trunc_pointer_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_n5gcreg_b0,
        { "N5GC device indication bit (N5GCREG)",   "nas-5gs.mm.n5gcreg",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nb_n1_drx_value,
        { "NB-N1 mode DRX value", "nas-5gs.mm.nb_n1_drx_value",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_nb_n1_drx_params_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_scmr,
        { "Signalling connection maintain request (SCMR)",   "nas-5gs.mm.scmr",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_mm_scmr), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_extended_rejected_nssai_number_of_element,
        { "Number of element",   "nas-5gs.mm.extended_rejected_nssai.number_of_element",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_extended_rejected_s_nssai_number_of_element_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_extended_rejected_nssai_type_of_list,
        { "Type of list",   "nas-5gs.mm.extended_rejected_nssai.type_of_list",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_extended_rejected_s_nssai_type_of_list_vals), 0x70,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_extended_rejected_nssai_spare,
        { "Spare",   "nas-5gs.mm.extended_rejected_nssai.spare",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_extended_rejected_nssai_back_off_timer,
        { "Back-off timer value",   "nas-5gs.mm.extended_rejected_nssai.back_off_timer",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_len_of_rejected_s_nssai,
        { "Length of rejected S-NSSAI",   "nas-5gs.mm.rejected_s_nssai.length",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_rejected_s_nssai_cause_value,
        { "Cause value",   "nas-5gs.mm.rejected_s_nssai.cause_value",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_extended_rej_s_nssai_cause_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_paging_restriction_type,
        { "Paging restriction type",   "nas-5gs.mm.paging_restriction.type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_paging_restriction_type_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_paging_restriction_psi_7,
        { "PSI(7)",   "nas-5gs.mm.paging_restriction.psi_7",
            FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_paging_restriction_psi_6,
        { "PSI(6)",   "nas-5gs.mm.paging_restriction.psi_6",
            FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_paging_restriction_psi_5,
        { "PSI(5)",   "nas-5gs.mm.paging_restriction.psi_5",
            FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_paging_restriction_psi_4,
        { "PSI(4)",   "nas-5gs.mm.paging_restriction.psi_4",
            FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_paging_restriction_psi_3,
        { "PSI(3)",   "nas-5gs.mm.paging_restriction.psi_3",
            FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_paging_restriction_psi_2,
        { "PSI(2)",   "nas-5gs.mm.paging_restriction.psi_2",
            FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_paging_restriction_psi_1,
        { "PSI(1)",   "nas-5gs.mm.paging_restriction.psi_1",
            FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_paging_restriction_psi_0,
        { "PSI(0)",   "nas-5gs.mm.paging_restriction.psi_0",
            FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_paging_restriction_psi_15,
        { "PSI(15)",   "nas-5gs.mm.paging_restriction.psi_15",
            FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x80,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_paging_restriction_psi_14,
        { "PSI(14)",   "nas-5gs.mm.paging_restriction.psi_14",
            FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x40,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_paging_restriction_psi_13,
        { "PSI(13)",   "nas-5gs.mm.paging_restriction.psi_13",
            FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x20,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_paging_restriction_psi_12,
        { "PSI(12)",   "nas-5gs.mm.paging_restriction.psi_12",
            FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x10,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_paging_restriction_psi_11,
        { "PSI(11)",   "nas-5gs.mm.paging_restriction.psi_11",
            FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x08,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_paging_restriction_psi_10,
        { "PSI(10)",   "nas-5gs.mm.paging_restriction.psi_10",
            FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x04,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_paging_restriction_psi_9,
        { "PSI(9)",   "nas-5gs.mm.paging_restriction.psi_9",
            FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_paging_restriction_psi_8,
        { "PSI(8)",   "nas-5gs.mm.paging_restriction.psi_8",
            FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nid_assign_mode,
        { "Assignment mode",   "nas-5gs.mm.nid.assign_mode",
            FT_UINT8, BASE_HEX, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nid_value,
        { "NID value",   "nas-5gs.mm.nid.value",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_peips_assist_info_type,
        { "Type of information",   "nas-5gs.mm.eips_assist_info.type",
            FT_UINT8, BASE_DEC, NULL, 0xe0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_peips_assist_info_paging_subgroup_id,
        { "Paging subgroup ID",   "nas-5gs.mm.eips_assist_info.paging_subgroup_id",
            FT_UINT8, BASE_DEC, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_peips_assist_info_ue_paging_probability_info,
        { "UE paging probability information",   "nas-5gs.mm.eips_assist_info.ue_paging_probability_info",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &nas_5gs_mm_peips_assist_info_ue_paging_probability_info_vals_ext, 0x1f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_add_req_res_prd,
        { "Paging restriction decision (PRD)",   "nas-5gs.mm.add_request_result.prd",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_add_req_res_prd_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nssrg_info_len,
        { "Length of NSSRG values for S-NSSAI",   "nas-5gs.mm.nssrg_info.len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nssrg_info_s_nssai_len,
        { "S-NSSAI length",   "nas-5gs.mm.nssrg_info.s_nssai_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nssrg_info_nssrg,
        { "NSSRG",   "nas-5gs.mm.nssrg_info.nssrg",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nsag_info_len,
        { "Length of NSAG",   "nas-5gs.mm.nsag_info.len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nsag_id,
        { "NSAG identifier",   "nas-5gs.mm.nsag_info.identifier",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nsag_info_s_nssai_len,
        { "Length of S-NSSAI list of NSAG",   "nas-5gs.mm.nsag_info.s_nssai_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nsag_prio,
        { "NSAG priority",   "nas-5gs.mm.nsag_info.priority",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_nsag_tais_list_len,
        { "TAIs list length",   "nas-5gs.mm.nsag_info.tais_list_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_prose_relay_trans_id,
        { "ProSe relay transaction identity", "nas-5gs.mm.prose_relay_trans_id",
            FT_UINT8, BASE_CUSTOM, CF_FUNC(nas_5gs_mm_prose_relay_trans_id), 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_relay_key_req_params_relay_service_code,
        { "Relay service code", "nas-5gs.mm.relay_key_req_params.relay_service_code",
            FT_UINT24, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_relay_key_req_params_nonce_1,
        { "Nonce_1", "nas-5gs.mm.relay_key_req_params.nonce_1",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_relay_key_req_params_uit,
        { "UE ID type (UIT)", "nas-5gs.mm.relay_key_req_params.uit",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_mm_relay_key_req_params_uit), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_relay_key_req_params_ue_id,
        { "UE identity", "nas-5gs.mm.relay_key_req_params.ue_id",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_relay_key_resp_params_key_knr_prose,
        { "Key KNR_ProSe", "nas-5gs.mm.relay_key_resp_params.key_knr_prose",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_relay_key_resp_params_nonce_2,
        { "Nonce_2", "nas-5gs.mm.relay_key_resp_params.nonce_2",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_relay_key_resp_params_cp_pruk_id,
        { "CP-PRUK ID", "nas-5gs.mm.relay_key_resp_params.cp_pruk_id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_prio_ind_mcsi,
        { "MCS indicator (MCSI)", "nas-5gs.mm.priority_indicator.mcsi",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_mm_prio_ind_mcsi), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_prio_ind_mpsi,
        { "MPS indicator (MPSI)", "nas-5gs.mm.priority_indicator.mpsi",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_mm_prio_ind_mpsi), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_n3iwf_id_type,
        { "N3IWF identifier type", "nas-5gs.mm.n3iwf_id.type",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_n3iwf_id_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_n3iwf_id_ipv4,
        { "N3IWF address IPv4", "nas-5gs.mm.n3iwf_id.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_n3iwf_id_ipv6,
        { "N3IWF address IPv6", "nas-5gs.mm.n3iwf_id.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_n3iwf_id_fqdn,
        { "N3IWF address FQDN", "nas-5gs.mm.n3iwf_id.fqdn",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_tnan_info_ssid_ind,
        { "SSID indication", "nas-5gs.mm.tnan_info.ssid_ind",
            FT_BOOLEAN, 8, TFS(&tfs_included_not_included), 0x02,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_tnan_info_tngf_id_ind,
        { "TNGF ID indication", "nas-5gs.mm.tnan_info.tngf_id_ind",
            FT_BOOLEAN, 8, TFS(&tfs_included_not_included), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_tnan_info_tngf_id_len,
        { "TNGF ID length", "nas-5gs.mm.tnan_info.tngf_id_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_tnan_info_tngf_id,
        { "TNGF ID", "nas-5gs.mm.tnan_info.tngf_id",
            FT_BYTES, BASE_SHOW_UTF_8_PRINTABLE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_tnan_info_ssid_len,
        { "SSID length", "nas-5gs.mm.tnan_info.ssid_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_tnan_info_ssid,
        { "SSID", "nas-5gs.mm.tnan_info.ssid",
            FT_BYTES, BASE_SHOW_UTF_8_PRINTABLE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ran_timing_sync_recreq,
        { "RecReq", "nas-5gs.mm.ran_timing_sync.recreq",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_n3gpp_acc_path_switch_ind_naps,
        { "Non-3GPP access path switching (NAPS)", "nas-5gs.mm.n3gpp_acc_path_switch_ind.naps",
            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_s_nssai_loc_valid_info_per_s_nssai_len,
        { "Length of Per-S-NSSAI location validity information for S-NSSAI", "nas-5gs.mm.s_nssai_loc_valid_info.per_s_nssai_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_s_nssai_loc_valid_info_per_s_nssai_nb_nr_cgi,
        { "Number of NR CGIs", "nas-5gs.mm.s_nssai_loc_valid_info.nb_nr_cgi",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_s_nssai_loc_valid_info_per_s_nssai_nr_cell_id,
        { "NR Cell ID", "nas-5gs.mm.s_nssai_loc_valid_info.nr_cell_id",
            FT_UINT40, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_s_nssai_time_valid_info_per_s_nssai_len,
        { "Length of Per-S-NSSAI time validity information for S-NSSAI", "nas-5gs.mm.s_nssai_time_valid_info.per_s_nssai_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_s_nssai_time_valid_info_time_window_len,
        { "Length of Time window", "nas-5gs.mm.s_nssai_time_valid_info.time_window_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_s_nssai_time_valid_info_time_window_start_time,
        { "Start time", "nas-5gs.mm.s_nssai_time_valid_info.time_window_start_time",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_s_nssai_time_valid_info_time_window_stop_time,
        { "Stop time", "nas-5gs.mm.s_nssai_time_valid_info.time_window_stop_time",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_s_nssai_time_valid_info_time_window_recurrence_pattern,
        { "Recurrence pattern", "nas-5gs.mm.s_nssai_time_valid_info.time_window_recurrence_pattern",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_s_nssai_time_valid_info_time_window_recurrence_pattern_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_s_nssai_time_valid_info_time_window_recurrence_end_time,
        { "Recurrence end time", "nas-5gs.mm.s_nssai_time_valid_info.recurrence_end_time",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_n3gpp_path_switch_info_nsonr,
        { "Non-3GPP path switching while using old non-3GPP resources (NSONR)", "nas-5gs.mm.n3gpp_path_switch_info.nsonr",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_au3n_ind_aun3reg,
        { "AUN3 device registration (AUN3REG)", "nas-5gs.mm.au3n_ind.aun3reg",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_feat_auth_ind_mbsrai,
        { "MBSR authorization indication (MBSRAI)", "nas-5gs.mm.feat_auth_ind.mbsrai",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_feat_auth_ind_mbsrai_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_payload_cont_info_pru,
        { "PRU related content (PRU)", "nas-5gs.mm.payload_cont_info.pru",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_mm_payload_cont_info_pru), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_aun3_device_sec_key_askt,
        { "AUN3 device security key type (ASKT)", "nas-5gs.mm.aun3_device_sec_key.askt",
            FT_UINT8, BASE_DEC, VALS(nas_5gs_mm_aun3_device_sec_key_askt_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_aun3_device_sec_key_key_len,
        { "Length of key content", "nas-5gs.mm.aun3_device_sec_key.key_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_aun3_device_sec_key_key,
        { "Key content", "nas-5gs.mm.aun3_device_sec_key.key",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_on_demand_nssai_len,
        { "Length of Information of on-demand S-NSSAI", "nas-5gs.mm.on_demand_nssai.len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_on_demand_nssai_slice_dereg_inactiv_timer,
        { "Slice deregistration inactivity timer", "nas-5gs.mm.on_demand_nssai.slice_dereg_inactiv_timer",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_seconds), 0x0,
            NULL, HFILL }
        },
        { &hf_nas_5gs_mm_ext_5gmm_cause_sat_nr,
        { "PRU related content (PRU)", "nas-5gs.mm.ext_5gmm_cause.sat_nr",
            FT_BOOLEAN, 8, TFS(&tfs_nas_5gs_mm_ext_5gmm_cause_sat_nr), 0x01,
            NULL, HFILL }
        },
        { &hf_nas_5gs_ue_os_id,
        { "UE OS ID UUID", "nas-5gs.ue_os_id",
            FT_GUID, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    unsigned  i;
    unsigned  last_offset;

    /* Setup protocol subtree array */
#define NUM_INDIVIDUAL_ELEMS    53
    int *ett[NUM_INDIVIDUAL_ELEMS +
        NUM_NAS_5GS_COMMON_ELEM +
        NUM_NAS_5GS_MM_MSG + NUM_NAS_5GS_MM_ELEM +
        NUM_NAS_5GS_SM_MSG + NUM_NAS_5GS_SM_ELEM +
        NUM_NAS_5GS_UPDP_MSG + NUM_NAS_5GS_UPDP_ELEM
    ];

    ett[0] = &ett_nas_5gs;
    ett[1] = &ett_nas_5gs_mm_nssai;
    ett[2] = &ett_nas_5gs_mm_pdu_ses_id;
    ett[3] = &ett_nas_5gs_sm_qos_rules;
    ett[4] = &ett_nas_5gs_sm_qos_params;
    ett[5] = &ett_nas_5gs_plain;
    ett[6] = &ett_nas_5gs_sec;
    ett[7] = &ett_nas_5gs_mm_part_sal;
    ett[8] = &ett_nas_5gs_mm_part_tal;
    ett[9] = &ett_nas_5gs_sm_mapd_eps_b_cont;
    ett[10] = &ett_nas_5gs_sm_mapd_eps_b_cont_params_list;
    ett[11] = &ett_nas_5gs_enc;
    ett[12] = &ett_nas_5gs_mm_ladn_indic;
    ett[13] = &ett_nas_5gs_mm_sor;
    ett[14] = &ett_nas_5gs_sm_pkt_filter_components;
    ett[15] = &ett_nas_5gs_updp_ue_policy_section_mgm_lst;
    ett[16] = &ett_nas_5gs_updp_ue_policy_section_mgm_sublst;
    ett[17] = &ett_nas_5gs_ue_policies_ursp;
    ett[18] = &ett_nas_5gs_ursp_traff_desc;
    ett[19] = &ett_nas_5gs_usrp_r_sel_list;
    ett[20] = &ett_nas_5gs_usrp_r_sel;
    ett[21] = &ett_nas_5gs_ursp_r_sel_desc_cont;
    ett[22] = &ett_nas_5gs_updp_upsi_list;
    ett[23] = &ett_nas_5gs_mm_rej_nssai;
    ett[24] = &ett_nas_5gs_mm_scheme_output;
    ett[25] = &ett_nas_5gs_mm_pld_cont_pld_entry;
    ett[26] = &ett_nas_5gs_mm_pld_cont_opt_ie;
    ett[27] = &ett_nas_5gs_mm_cag_info_entry;
    ett[28] = &ett_nas_5gs_ciot_small_data_cont_data_contents;
    ett[29] = &ett_nas_5gs_user_data_cont;
    ett[30] = &ett_nas_5gs_ciph_data_set;
    ett[31] = &ett_nas_5gs_mm_mapped_nssai;
    ett[32] = &ett_nas_5gs_mm_partial_extended_rejected_nssai_list;
    ett[33] = &ett_nas_5gs_mm_ext_rej_nssai_back_off_timer;
    ett[34] = &ett_nas_5gs_mm_ext_rej_nssai;
    ett[35] = &ett_nas_5gs_mm_op_def_acc_cat_def;
    ett[36] = &ett_nas_5gs_mm_op_def_acc_cat_criteria_component;
    ett[37] = &ett_nas_5gs_mm_op_def_acc_cat_criteria;
    ett[38] = &ett_nas_5gs_cmn_service_level_aa_cont_param;
    ett[39] = &ett_nas_5gs_mm_pld_cont_event_notif_ind;
    ett[40] = &ett_nas_5gs_mm_peips_assist_info;
    ett[41] = &ett_nas_5gs_mm_nssrg_info;
    ett[42] = &ett_nas_5gs_mm_plmns_list_disaster_cond;
    ett[43] = &ett_nas_5gs_mm_reg_wait_range;
    ett[44] = &ett_nas_5gs_mm_nsag_info;
    ett[45] = &ett_nas_5gs_mm_snpn_list;
    ett[46] = &ett_nas_5gs_mm_ext_ladn_info;
    ett[47] = &ett_nas_5gs_mm_alt_nssai;
    ett[48] = &ett_nas_5gs_mm_alt_nssai_replaced;
    ett[49] = &ett_nas_5gs_mm_alt_nssai_alternative;
    ett[50] = &ett_nas_5gs_mm_s_nssai_loc_valid_info;
    ett[51] = &ett_nas_5gs_mm_s_nssai_time_valid_info;
    ett[52] = &ett_nas_5gs_mm_on_demand_nssai;

    last_offset = NUM_INDIVIDUAL_ELEMS;

    for (i = 0; i < NUM_NAS_5GS_COMMON_ELEM; i++, last_offset++)
    {
        ett[last_offset] = &ett_nas_5gs_common_elem[i];
    }

    /* MM */
    for (i = 0; i < NUM_NAS_5GS_MM_MSG; i++, last_offset++)
    {
        ett[last_offset] = &ett_nas_5gs_mm_msg[i];
    }

    for (i = 0; i < NUM_NAS_5GS_MM_ELEM; i++, last_offset++)
    {
        ett[last_offset] = &ett_nas_5gs_mm_elem[i];
    }

    for (i = 0; i < NUM_NAS_5GS_SM_MSG; i++, last_offset++)
    {
        ett[last_offset] = &ett_nas_5gs_sm_msg[i];
    }

    for (i = 0; i < NUM_NAS_5GS_SM_ELEM; i++, last_offset++)
    {
        ett[last_offset] = &ett_nas_5gs_sm_elem[i];
    }

    for (i = 0; i < NUM_NAS_5GS_UPDP_MSG; i++, last_offset++)
    {
        ett[last_offset] = &ett_nas_5gs_updp_msg[i];
    }

    for (i = 0; i < NUM_NAS_5GS_UPDP_ELEM; i++, last_offset++)
    {
        ett[last_offset] = &ett_nas_5gs_updp_elem[i];
    }

    static ei_register_info ei[] = {
    { &ei_nas_5gs_extraneous_data, { "nas-5gs.extraneous_data", PI_PROTOCOL, PI_NOTE, "Extraneous Data, dissector bug or later version spec(report to wireshark.org)", EXPFILL }},
    { &ei_nas_5gs_unknown_pd,{ "nas-5gs.unknown_pd", PI_PROTOCOL, PI_ERROR, "Unknown protocol discriminator", EXPFILL } },
    { &ei_nas_5gs_mm_unknown_msg_type,{ "nas-5gs.mm.unknown_msg_type", PI_PROTOCOL, PI_WARN, "Unknown Message Type", EXPFILL } },
    { &ei_nas_5gs_sm_unknown_msg_type,{ "nas-5gs.sm.unknown_msg_type", PI_PROTOCOL, PI_WARN, "Unknown Message Type", EXPFILL } },
    { &ei_nas_5gs_updp_unknown_msg_type,{ "nas-5gs.updp.unknown_msg_type", PI_PROTOCOL, PI_WARN, "Unknown Message Type", EXPFILL } },
    { &ei_nas_5gs_msg_not_dis,{ "nas-5gs.msg_not_dis", PI_PROTOCOL, PI_WARN, "MSG IEs not dissected yet", EXPFILL } },
    { &ei_nas_5gs_ie_not_dis,{ "nas-5gs.ie_not_dis", PI_PROTOCOL, PI_WARN, "IE not dissected yet", EXPFILL } },
    { &ei_nas_5gs_missing_mandatory_element,{ "nas-5gs.missing_mandatory_element", PI_PROTOCOL, PI_ERROR, "Missing Mandatory element, rest of dissection is suspect", EXPFILL } },
    { &ei_nas_5gs_dnn_too_long,{ "nas-5gs.dnn_too_long", PI_PROTOCOL, PI_ERROR, "DNN encoding has more than 100 octets", EXPFILL } },
    { &ei_nas_5gs_unknown_value,{ "nas-5gs.unknown_value", PI_PROTOCOL, PI_ERROR, "Value not according to (decoded)specification", EXPFILL } },
    { &ei_nas_5gs_num_pkt_flt,{ "nas-5gs.num_pkt_flt", PI_PROTOCOL, PI_ERROR, "num_pkt_flt != 0", EXPFILL } },
    { &ei_nas_5gs_not_diss,{ "nas-5gs.not_diss", PI_PROTOCOL, PI_NOTE, "Not dissected yet", EXPFILL } },
    };

    expert_module_t* expert_nas_5gs;
    module_t *nas_5GS_module;

    /* Register protocol */
    proto_nas_5gs = proto_register_protocol(PNAME, PSNAME, PFNAME);
    /* Register fields and subtrees */
    proto_register_field_array(proto_nas_5gs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_nas_5gs = expert_register_protocol(proto_nas_5gs);
    expert_register_field_array(expert_nas_5gs, ei, array_length(ei));

    /* Backward compatibility with old filters name */
    proto_register_alias(proto_nas_5gs, "nas_5gs");

    /* Register dissector */
    nas_5gs_handle = register_dissector(PFNAME, dissect_nas_5gs, proto_nas_5gs);

    nas_5GS_module = prefs_register_protocol(proto_nas_5gs, proto_reg_handoff_nas_5gs);

    prefs_register_bool_preference(nas_5GS_module,
        "null_decipher",
        "Try to detect and decode 5G-EA0 ciphered messages",
        "This should work when the NAS ciphering algorithm is NULL (5G-EEA0)",
        &g_nas_5gs_null_decipher);

    prefs_register_enum_preference(nas_5GS_module, "decode_user_data_container_as",
                                   "Try to decode User Data Container content as",
                                   NULL,
                                   &g_nas_5gs_decode_user_data_container_as,
                                   nas_5gs_user_data_container_as_vals, false);

    prefs_register_dissector_preference(nas_5GS_module, "non_ip_data_dissector",
                                        "Dissector name for non IP data", NULL,
                                        &g_nas_5gs_non_ip_data_dissector);
}

void
proto_reg_handoff_nas_5gs(void)
{
    static bool initialized = false;

    if (!initialized) {
        heur_dissector_add("udp", dissect_nas_5gs_heur, "NAS-5GS over UDP", "nas_5gs_udp", proto_nas_5gs, HEURISTIC_DISABLE);
        eap_handle = find_dissector("eap");
        nas_eps_handle = find_dissector("nas-eps");
        lpp_handle = find_dissector("lpp");
        gsm_a_dtap_handle = find_dissector("gsm_a_dtap");
        ipv4_handle = find_dissector("ip");
        ipv6_handle = find_dissector("ipv6");
        ethernet_handle = find_dissector("eth_withoutfcs");
        dissector_add_string("media_type", "application/vnd.3gpp.5gnas", create_dissector_handle(dissect_nas_5gs_media_type, proto_nas_5gs));
        dissector_add_for_decode_as("tcp.port", create_dissector_handle(dissect_nas_5gs_tcp, proto_nas_5gs));
        proto_json = proto_get_id_by_filter_name("json");
        initialized = true;
    }
    if (g_nas_5gs_non_ip_data_dissector[0] != '\0') {
        non_ip_data_handle = find_dissector(g_nas_5gs_non_ip_data_dissector);
    } else {
        non_ip_data_handle = NULL;
    }
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

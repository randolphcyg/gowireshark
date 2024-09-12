/* packet-cfdp.c
 * Routines for CCSDS File Delivery Protocol (CFDP) dissection
 * Copyright 2013, Juan Antonio Montesinos juan.mondl@gmail.com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Slightly updated to allow more in-depth decoding when called
 * with the 'dissect_as_subtree' method and to leverage some
 * of the bitfield display operations: Keith Scott
 * <kscott@mitre.org>.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-cfdp.h"

/* The CFDP standard can be found here:
 * https://public.ccsds.org/Pubs/727x0b4s.pdf
 *
 * The Store and Forward Overlay Operations are not included.
 */

void proto_register_cfdp(void);
void proto_reg_handoff_cfdp(void);

/* Initialize the protocol and registered fields */
static int proto_cfdp;
static int hf_cfdp_flags;
static int hf_cfdp_byte2;
static int hf_cfdp_proxy_fault_hdl_overr;
static int hf_cfdp_proxy_trans_mode;
static int hf_cfdp_proxy_segment_control_byte;
static int hf_cfdp_proxy_put_resp;
static int hf_cfdp_orig_trans_id;
static int hf_cfdp_remote_stat_rep_req;
static int hf_cfdp_remote_stat_rep_resp;
static int hf_cfdp_finish_pdu_flags;
static int hf_cfdp_remote_suspend_resume_req;
static int hf_cfdp_remote_suspend_resume_resp;
static int hf_cfdp_version;
static int hf_cfdp_pdu_type;
static int hf_cfdp_direction;
static int hf_cfdp_trans_mode;
static int hf_cfdp_trans_mode_2;
static int hf_cfdp_crc_flag;
static int hf_cfdp_res1;
static int hf_cfdp_data_length;
static int hf_cfdp_file_data_pdu;
static int hf_cfdp_res2;
static int hf_cfdp_entid_length;
static int hf_cfdp_res3;
static int hf_cfdp_transeqnum_length;
static int hf_cfdp_srcid;
static int hf_cfdp_transeqnum;
static int hf_cfdp_dstid;
static int hf_cfdp_file_directive_type;
static int hf_cfdp_file_data_offset;
static int hf_cfdp_progress;
static int hf_cfdp_dir_code_ack;
static int hf_cfdp_dir_subtype_ack;
static int hf_cfdp_condition_code;
static int hf_cfdp_spare_one;
static int hf_cfdp_spare_one_2;
static int hf_cfdp_spare_two;
static int hf_cfdp_spare_four;
static int hf_cfdp_spare_five;
static int hf_cfdp_spare_five_2;
static int hf_cfdp_spare_seven;
static int hf_cfdp_spare_seven_2;
static int hf_cfdp_trans_stat_ack;
static int hf_cfdp_file_checksum;
static int hf_cfdp_file_size;
static int hf_cfdp_end_system_stat;
static int hf_cfdp_delivery_code;
static int hf_cfdp_file_stat;
static int hf_cfdp_segment_control;
static int hf_cfdp_src_file_name_len;
static int hf_cfdp_src_file_name;
static int hf_cfdp_dst_file_name_len;
static int hf_cfdp_dst_file_name;
static int hf_cfdp_first_file_name_len;
static int hf_cfdp_first_file_name;
static int hf_cfdp_second_file_name_len;
static int hf_cfdp_second_file_name;
static int hf_cfdp_nak_st_scope;
static int hf_cfdp_nak_sp_scope;
static int hf_cfdp_crc;
static int hf_cfdp_action_code;
static int hf_cfdp_status_code_1;
static int hf_cfdp_status_code_2;
static int hf_cfdp_status_code_3;
static int hf_cfdp_status_code_4;
static int hf_cfdp_status_code_5;
static int hf_cfdp_status_code_6;
static int hf_cfdp_status_code_7;
static int hf_cfdp_status_code_8;
static int hf_cfdp_handler_code;
static int hf_cfdp_proxy_msg_type;
static int hf_cfdp_proxy_segment_control;
static int hf_cfdp_proxy_delivery_code;
static int hf_cfdp_response_req;
static int hf_cfdp_directory_name;
static int hf_cfdp_directory_file_name;
static int hf_cfdp_listing_resp_code;
static int hf_cfdp_report_file_name;
static int hf_cfdp_trans_stat;
static int hf_cfdp_trans_stat_2;
static int hf_cfdp_rep_resp_code;
static int hf_cfdp_suspension_ind;
static int hf_cfdp_tlv_len;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_cfdp_filestore_message_len;
static int hf_cfdp_filestore_message;
static int hf_cfdp_entity;
static int hf_cfdp_message_to_user;
static int hf_cfdp_flow_label;
static int hf_cfdp_segment_requests;
static int hf_cfdp_user_data;

/* Initialize the subtree pointers */
static int ett_cfdp;
static int ett_cfdp_header;
static int ett_cfdp_flags;
static int ett_cfdp_byte2;
static int ett_cfdp_proxy_fault_hdl_overr;
static int ett_cfdp_proxy_trans_mode;
static int ett_cfdp_proxy_segment_control_byte;
static int ett_cfdp_proxy_put_resp;
static int ett_cfdp_orig_trans_id;
static int ett_cfdp_remote_stat_rep_req;
static int ett_cfdp_remote_stat_rep_resp;
static int ett_cfdp_file_directive_header;
static int ett_cfdp_file_data_header;
static int ett_cfdp_finish_pdu_flags;
static int ett_cfdp_remote_suspend_resume_req;
static int ett_cfdp_remote_suspend_resume_resp;
static int ett_cfdp_fault_location;
static int ett_cfdp_crc;
static int ett_cfdp_filestore_req;
static int ett_cfdp_filestore_resp;
static int ett_cfdp_msg_to_user;
static int ett_cfdp_fault_hdl_overr;
static int ett_cfdp_flow_label;
static int ett_cfdp_proto;

static expert_field ei_cfdp_bad_length;


static dissector_handle_t cfdp_handle;

/* Some parameters */
#define CFDP_HEADER_FIXED_FIELDS_LEN 4
#define CFDP_APID 2045

/* Bitmask for the first byte of the Header */
#define HDR_VERSION_CFDP    0xe0
#define HDR_TYPE_CFDP       0x10
#define HDR_DIR             0x08
#define HDR_TMODE           0x04
#define HDR_CRCF            0x02
#define HDR_RES1            0x01

/* Bitmask for the second byte of the Header */
#define HDR_RES2            0x80
#define HDR_LEN_ENT_ID      0x70
#define HDR_RES3            0x08
#define HDR_LEN_TSEQ_NUM    0x07

/* File Directive Codes */
#define EOF_PDU          4
#define FINISHED_PDU     5
#define ACK_PDU          6
#define METADATA_PDU     7
#define NAK_PDU          8
#define PROMPT_PDU       9
#define KEEP_ALIVE_PDU  12

/* TLV Types */
#define FILESTORE_REQ    0
#define FILESTORE_RESP   1
#define MSG_TO_USER      2
#define FAULT_HDL_OVERR  4
#define FLOW_LABEL       5
#define FAULT_LOCATION   6

/* ID for reserved CFDP Messages  */
#define CFDP_MSG_TO_USER 0x63666470

/* Proxy Operations Message Types */
#define PROXY_PUT_REQ           0x00
#define PROXY_MSG_TO_USER       0x01
#define PROXY_FILESTORE_REQ     0x02
#define PROXY_FAULT_HDL_OVERR   0x03
#define PROXY_TRANS_MODE        0x04
#define PROXY_FLOW_LABEL        0x05
#define PROXY_SEGMENT_CONTROL   0x06
#define PROXY_PUT_RESP          0x07
#define PROXY_FILESTORE_RESP    0x08
#define PROXY_PUT_CANCEL        0x09
#define ORIG_TRANS_ID           0x0A
#define DIRECTORY_LIST_REQ      0x10
#define DIRECTORY_LIST_RESP     0x11
#define REMOTE_STAT_REP_REQ     0x20
#define REMOTE_STAT_REP_RESP    0x21
#define REMOTE_SUSPEND_REQ      0x30
#define REMOTE_SUSPEND_RESP     0x31
#define REMOTE_RESUME_REQ       0x38
#define REMOTE_RESUME_RESP      0x39

/* PDU Type */
static const value_string cfdp_pdu_type[] = {
    { 0, "File Directive" },
    { 1, "File Data" },
    { 0, NULL }
};

/* PDU Direction */
static const value_string cfdp_direction[] = {
    { 0, "Toward file receiver" },
    { 1, "Toward file sender" },
    { 0, NULL }
};

/* Transmission mode */
static const value_string cfdp_trans_mode[] = {
    { 0, "Acknowledged" },
    { 1, "Unacknowledged" },
    { 0, NULL }
};

/* CRC */
static const value_string cfdp_crc_flag[] = {
    { 0, "CRC not present" },
    { 1, "CRC present" },
    { 0, NULL }
};

/* File Directive PDU Type */
static const value_string cfdp_file_directive_type[] = {
    {  4, "EOF PDU"},
    {  5, "Finished PDU"},
    {  6, "ACK PDU"},
    {  7, "Metadata PDU"},
    {  8, "NACK PDU"},
    {  9, "Prompt PDU"},
    { 12, "Keep Alive PDU"},
    {  0, NULL}
};

/* Condition codes */
static const value_string cfdp_condition_codes[] = {
    {  0, "No error"},
    {  1, "Positive ACK limit reached"},
    {  2, "Keep alive limit reached"},
    {  3, "Invalid transmission mode"},
    {  4, "Filestore rejection"},
    {  5, "File checksum failure"},
    {  6, "File size error"},
    {  7, "NAK limit reached"},
    {  8, "Inactivity detected"},
    {  9, "Check limit reached"},
    { 14, "Suspend.request received"},
    { 15, "Cancel.request received"},
    {  0, NULL }
};

/* Transaction status */
static const value_string cfdp_trans_stat_ack[] = {
    { 0, "Undefined" },
    { 1, "Active" },
    { 2, "Terminated" },
    { 3, "Unrecognized" },
    { 0, NULL }
};

/* End system status */
static const value_string cfdp_end_system_stat[] = {
    { 0, "Generated by Waypoint" },
    { 1, "Generated by End System" },
    { 0, NULL }
};

/* Delivery code */
static const value_string cfdp_delivery_code[] = {
    { 0, "Data Complete" },
    { 1, "Data incomplete" },
    { 0, NULL }
};

/* Filestore operations action code */
static const value_string cfdp_action_code[] = {
    { 0, "Create File" },
    { 1, "Delete File" },
    { 2, "Rename File" },
    { 3, "Append File" },
    { 4, "Replace File" },
    { 5, "Create Directory" },
    { 6, "Remove Directory" },
    { 7, "Deny File (delete if present)" },
    { 8, "Deny Directory (remove if present)" },
    { 0, NULL }
};

/* Filestore operations status codes */
static const value_string cfdp_status_code_1[] = {
    { 0, "Successful" },
    { 1, "Create not allowed" },
    { 8, "Not performed" },
    { 0, NULL }
};

static const value_string cfdp_status_code_2[] = {
    { 0, "Successful" },
    { 1, "File does not exist" },
    { 2, "Delete not allowed" },
    { 8, "Not performed" },
    { 0, NULL }
};

static const value_string cfdp_status_code_3[] = {
    { 0, "Successful" },
    { 1, "Old File Name does not exist" },
    { 2, "New File Name already exists" },
    { 3, "Rename not allowed" },
    { 8, "Not performed" },
    { 0, NULL }
};

static const value_string cfdp_status_code_4[] = {
    { 0, "Successful" },
    { 1, "File Name 1 does not exist" },
    { 2, "File Name 2 does not exist" },
    { 3, "Append not allowed" },
    { 8, "Not performed" },
    { 0, NULL }
};

static const value_string cfdp_status_code_5[] = {
    { 0, "Successful" },
    { 1, "File Name 1 does not exist" },
    { 2, "File Name 2 does not exist" },
    { 3, "Replace not allowed" },
    { 8, "Not performed" },
    { 0, NULL }
};

static const value_string cfdp_status_code_6[] = {
    { 0, "Successful" },
    { 1, "Directory cannot be created" },
    { 8, "Not performed" },
    { 0, NULL }
};

static const value_string cfdp_status_code_7[] = {
    { 0, "Successful" },
    { 1, "Directory does not exist" },
    { 2, "Delete not allowed" },
    { 8, "Not performed" },
    { 0, NULL }
};

static const value_string cfdp_status_code_8[] = {
    { 0, "Successful" },
    { 1, "Delete not allowed" },
    { 8, "Not performed" },
    { 0, NULL }
};

/* Finished PDU File Status */
static const value_string cfdp_file_stat[] = {
    { 0, "Delivery file discarded deliberately" },
    { 1, "Delivery file discarded due to filestore rejection" },
    { 2, "Delivery file retained in filestore successfully" },
    { 3, "Delivery file status unreported" },
    { 0, NULL }
};

/* Segmentation control */
static const value_string cfdp_segment_control[] = {
    { 0, "Record boundaries respected" },
    { 1, "Record boundaries not respected" },
    { 0, NULL }
};

/* Fault handler override Handler code*/
static const value_string cfdp_handler_codes[] = {
    { 1, "issue Notice of Cancellation" },
    { 2, "issue Notice of Suspension" },
    { 3, "Ignore error" },
    { 4, "Abandon transaction" },
    { 0, NULL }
};

/* Type of Proxy message */
static const value_string cfdp_proxy_msg_type[] = {
    { 0x00, "Proxy Put Request"},
    { 0x01, "Proxy Message To User"},
    { 0x02, "Proxy Filestore Request"},
    { 0x03, "Proxy Fault Handler Override"},
    { 0x04, "Proxy Transmission Mode"},
    { 0x05, "Proxy Flow Label"},
    { 0x06, "Proxy Segmentation Control"},
    { 0x07, "Proxy Put Response"},
    { 0x08, "Proxy Filestore Response"},
    { 0x09, "Proxy Put Cancel"},
    { 0x0A, "Originating Transaction ID"},
    { 0x10, "Directory Listing Request"},
    { 0x11, "Directory Listing Response"},
    { 0x20, "Remote Status Report Request"},
    { 0x21, "Remote Status Report Response"},
    { 0x30, "Remote Suspend Request"},
    { 0x31, "Remote Suspend Response"},
    { 0x38, "Remote Resume Request"},
    { 0x39, "Remote Resume Response"},
    { 0, NULL }
};
static value_string_ext cfdp_proxy_msg_type_ext = VALUE_STRING_EXT_INIT(cfdp_proxy_msg_type);

/* Prompt PDU Response required */
static const value_string cfdp_response_req[] = {
    { 0, "NAK" },
    { 1, "Keep Alive" },
    { 0, NULL }
};

/* Listing response code */
static const value_string cfdp_listing_resp_code[] = {
    { 0, "Successful" },
    { 1, "Unsuccessful" },
    { 0, NULL }
};

/* Report response code */
static const value_string cfdp_rep_resp_code[] = {
    { 0, "Unsuccessful" },
    { 1, "Successful" },
    { 0, NULL }
};

/* Suspension indication */
static const value_string cfdp_suspension_ind[] = {
    { 0, "Not Suspended" },
    { 1, "Suspended" },
    { 0, NULL }
};

/* File Directive codes */
static const value_string cfdp_directive_codes[] = {
    { 0x04, "EOF" },
    { 0x05, "Finished" },
    { 0x06, "ACK" },
    { 0x07, "Metadata" },
    { 0x08, "NAK" },
    { 0x09, "Prompt" },
    { 0x0C, "Keep Alive" },
    { 0, NULL }
};

static int * const cfdp_flags[] = {
  &hf_cfdp_version,
  &hf_cfdp_pdu_type,
  &hf_cfdp_direction,
  &hf_cfdp_trans_mode,
  &hf_cfdp_crc_flag,
  &hf_cfdp_res1,
  NULL
};

static int * const cfdp_byte2[] = {
    &hf_cfdp_res2,
    &hf_cfdp_entid_length,
    &hf_cfdp_res3,
    &hf_cfdp_transeqnum_length,
    NULL
};

static int * const cfdp_proxy_fault_hdl_overr[] = {
    &hf_cfdp_condition_code,
    &hf_cfdp_handler_code,
    NULL
};

static int * const cfdp_proxy_trans_mode [] = {
    &hf_cfdp_spare_seven_2,
    &hf_cfdp_trans_mode_2,
    NULL
};

static int * const cfdp_proxy_segment_control_byte [] = {
    &hf_cfdp_spare_seven_2,
    &hf_cfdp_proxy_segment_control,
    NULL
};

static int * const cfdp_proxy_put_resp [] = {
    &hf_cfdp_condition_code,
    &hf_cfdp_spare_one,
    &hf_cfdp_proxy_delivery_code,
    &hf_cfdp_file_stat,
    NULL
};

static int * const cfdp_orig_trans_id[] = {
    &hf_cfdp_res2,
    &hf_cfdp_entid_length,
    &hf_cfdp_res3,
    &hf_cfdp_transeqnum_length,
    NULL
};

static int * const cfdp_remote_stat_rep_req[] = {
    &hf_cfdp_res2,
    &hf_cfdp_entid_length,
    &hf_cfdp_res3,
    &hf_cfdp_transeqnum_length,
    NULL
};

static int * const cfdp_remote_stat_rep_resp[] = {
    &hf_cfdp_trans_stat,
    &hf_cfdp_spare_five,
    &hf_cfdp_rep_resp_code,
    &hf_cfdp_spare_one_2,
    &hf_cfdp_entid_length,
    &hf_cfdp_spare_one,
    &hf_cfdp_transeqnum_length,
    NULL
};

static int * const cfdp_finish_pdu_flags [] = {
    &hf_cfdp_condition_code,
    &hf_cfdp_end_system_stat,
    &hf_cfdp_delivery_code,
    &hf_cfdp_file_stat,
    NULL
};

/* 6.6.3.2 (1 byte) */
static int * const cfdp_remote_suspend_resume_req [] = {
    &hf_cfdp_spare_one_2,
    &hf_cfdp_entid_length,
    &hf_cfdp_spare_one,
    &hf_cfdp_transeqnum_length,
    NULL
};


/* 6.6.4.2 (2 bytes) */
static int * const cfdp_remote_suspend_resume_resp [] = {
    &hf_cfdp_suspension_ind,
    &hf_cfdp_trans_stat_2,
    &hf_cfdp_spare_five_2,
    &hf_cfdp_spare_one_2,
    &hf_cfdp_entid_length,
    &hf_cfdp_spare_one,
    &hf_cfdp_transeqnum_length,
    NULL
};



/* Dissect the Source Entity ID field */
static void
dissect_cfdp_src_entity_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset, uint8_t len_ent_id)
{
    if(len_ent_id > 0 && len_ent_id <= 8){
        proto_tree_add_item(tree, hf_cfdp_srcid, tvb, offset, len_ent_id, ENC_BIG_ENDIAN);
    }
    else{
        proto_tree_add_expert_format(tree, pinfo, &ei_cfdp_bad_length, tvb, offset, 0, "Wrong length for the entity ID");
    }
}

/* Dissect the Destination Entity ID field */
static void
dissect_cfdp_dst_entity_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset, uint8_t len_ent_id)
{
    if(len_ent_id > 0 && len_ent_id <= 8){
        proto_tree_add_item(tree, hf_cfdp_dstid, tvb, offset, len_ent_id, ENC_BIG_ENDIAN);
    }
    else{
        proto_tree_add_expert_format(tree, pinfo, &ei_cfdp_bad_length, tvb, offset, 0, "Wrong length for the entity ID");
    }
}

/* Dissect the Transaction Sequence Number field */
static void
dissect_cfdp_tseq_num(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset, uint8_t len_tseq_num)
{
    if(len_tseq_num > 0 && len_tseq_num <= 8){
        proto_tree_add_item(tree, hf_cfdp_transeqnum, tvb, offset, len_tseq_num, ENC_BIG_ENDIAN);
    }
    else{
        proto_tree_add_expert_format(tree, pinfo, &ei_cfdp_bad_length, tvb, offset, 0, "Wrong length for transaction sequence number");
    }
}

/* Dissect the Filestore Request TLV */
static uint32_t dissect_cfdp_filestore_req_tlv(tvbuff_t *tvb, proto_tree *tree, uint32_t ext_offset){

    uint8_t tlv_len;

    uint32_t offset = ext_offset;
    uint32_t length;

    /* Get field length */
    tlv_len = tvb_get_uint8(tvb, offset);
    offset += 1;
    if(tlv_len > 0){
        proto_tree  *cfdp_filestore_req_tree;
        uint8_t aux_byte;

        /* Create a TLV subtree */
        cfdp_filestore_req_tree = proto_tree_add_subtree(tree, tvb, offset-2, tlv_len+2,
            ett_cfdp_filestore_req, NULL, "Filestore Request TLV");

        proto_tree_add_uint(cfdp_filestore_req_tree, hf_cfdp_tlv_len, tvb, offset-1, 1, tlv_len);

        aux_byte = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint(cfdp_filestore_req_tree, hf_cfdp_action_code, tvb, offset, 1, aux_byte);
        proto_tree_add_uint(cfdp_filestore_req_tree, hf_cfdp_spare_four, tvb, offset, 1, aux_byte);
        offset += 1;

        proto_tree_add_item_ret_uint(cfdp_filestore_req_tree, hf_cfdp_first_file_name_len, tvb, offset, 1, ENC_NA, &length);
        offset += 1;
        if(length > 0){
            proto_tree_add_item(cfdp_filestore_req_tree, hf_cfdp_first_file_name, tvb, offset, length, ENC_ASCII);
        }
        offset += length;

        proto_tree_add_item_ret_uint(cfdp_filestore_req_tree, hf_cfdp_second_file_name_len, tvb, offset, 1, ENC_NA, &length);
        offset += 1;
        if(length > 0){
            proto_tree_add_item(cfdp_filestore_req_tree, hf_cfdp_second_file_name, tvb, offset, length, ENC_ASCII);
        }
        offset += length;
    }

    return offset;
}

/* Dissect the Filestore Response TLV */
static uint32_t dissect_cfdp_filestore_resp_tlv(tvbuff_t *tvb, proto_tree *tree, uint32_t ext_offset){

    uint8_t tlv_len;

    uint32_t offset = ext_offset;

    /* Get field length */
    tlv_len = tvb_get_uint8(tvb, offset);
    offset += 1;
    if(tlv_len > 0){
        proto_tree  *cfdp_filestore_resp_tree;
        uint8_t aux_byte;
        uint32_t length;

        /* Create a subtree */
        cfdp_filestore_resp_tree = proto_tree_add_subtree(tree, tvb, offset-2, tlv_len+2,
                        ett_cfdp_filestore_resp, NULL, "Filestore Response TLV");

        proto_tree_add_uint(cfdp_filestore_resp_tree, hf_cfdp_tlv_len, tvb, offset-1, 1, tlv_len);

        aux_byte = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint(cfdp_filestore_resp_tree, hf_cfdp_action_code, tvb, offset, 1, aux_byte);
        switch((aux_byte & 0xF0) >> 4){
            case 0:
                proto_tree_add_uint(cfdp_filestore_resp_tree, hf_cfdp_status_code_1, tvb, offset, 1, aux_byte);
                break;
            case 1:
                proto_tree_add_uint(cfdp_filestore_resp_tree, hf_cfdp_status_code_2, tvb, offset, 1, aux_byte);
                break;
            case 2:
                proto_tree_add_uint(cfdp_filestore_resp_tree, hf_cfdp_status_code_3, tvb, offset, 1, aux_byte);
                break;
            case 3:
                proto_tree_add_uint(cfdp_filestore_resp_tree, hf_cfdp_status_code_4, tvb, offset, 1, aux_byte);
                break;
            case 4:
                proto_tree_add_uint(cfdp_filestore_resp_tree, hf_cfdp_status_code_5, tvb, offset, 1, aux_byte);
                break;
            case 5:
                proto_tree_add_uint(cfdp_filestore_resp_tree, hf_cfdp_status_code_6, tvb, offset, 1, aux_byte);
                break;
            case 6:
                proto_tree_add_uint(cfdp_filestore_resp_tree, hf_cfdp_status_code_7, tvb, offset, 1, aux_byte);
                break;
            case 7: case 8:
                proto_tree_add_uint(cfdp_filestore_resp_tree, hf_cfdp_status_code_8, tvb, offset, 1, aux_byte);
                break;

            default:
                break;
        }
        offset += 1;

        proto_tree_add_item_ret_uint(cfdp_filestore_resp_tree, hf_cfdp_first_file_name_len, tvb, offset, 1, ENC_NA, &length);
        offset += 1;
        if(length > 0){
            proto_tree_add_item(cfdp_filestore_resp_tree, hf_cfdp_first_file_name, tvb, offset, length, ENC_ASCII);
        }
        offset += length;

        proto_tree_add_item_ret_uint(cfdp_filestore_resp_tree, hf_cfdp_second_file_name_len, tvb, offset, 1, ENC_NA, &length);
        offset += 1;
        if(length > 0){
            proto_tree_add_item(cfdp_filestore_resp_tree, hf_cfdp_second_file_name, tvb, offset, length, ENC_ASCII);
        }
        offset += length;

        /* Filestore Message */
        proto_tree_add_item_ret_uint(cfdp_filestore_resp_tree, hf_cfdp_filestore_message_len, tvb, offset, 1, ENC_NA, &length);
        offset += 1;
        if(length > 0){
            proto_tree_add_item(cfdp_filestore_resp_tree, hf_cfdp_filestore_message, tvb, offset, length, ENC_NA);
        }
        offset += length;
    }

    return offset+1;
}

/* Dissect the Fault Location TLV */
static uint32_t dissect_cfdp_fault_location_tlv(tvbuff_t *tvb, proto_tree *tree, uint32_t ext_offset){

    uint8_t tlv_len;

    uint32_t offset = ext_offset;

    /* Get field length */
    tlv_len = tvb_get_uint8(tvb, offset);
    offset += 1;
    if(tlv_len > 0){
        proto_tree  *cfdp_fault_location_tree;

        /* Create a subtree */
        cfdp_fault_location_tree = proto_tree_add_subtree(tree, tvb, offset-2, tlv_len+2,
                                        ett_cfdp_fault_location, NULL, "Fault location TLV");

        proto_tree_add_uint(cfdp_fault_location_tree, hf_cfdp_tlv_len, tvb, offset-1, 1, tlv_len);

        proto_tree_add_item(cfdp_fault_location_tree, hf_cfdp_entity, tvb, offset, tlv_len, ENC_NA);
        offset += tlv_len;
    }

    return offset;
}

/* Dissect the Message to User TLV */
static uint32_t dissect_cfdp_msg_to_user_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t ext_offset){

    uint8_t tlv_type;
    uint8_t tlv_len;
    proto_tree  *cfdp_msg_to_user_tree;

    uint32_t offset = ext_offset;
    uint32_t msg_to_user_id;

    uint64_t retval;

    int len_ent_id;
    int len_tseq_num;

    /* Get tlv len */
    tlv_len = tvb_get_uint8(tvb, offset);
    offset += 1;

    /* Create a subtree */
    cfdp_msg_to_user_tree = proto_tree_add_subtree(tree, tvb, offset-2, tlv_len+2,
                                    ett_cfdp_filestore_resp, NULL, "Message To User TLV");

    proto_tree_add_uint(cfdp_msg_to_user_tree, hf_cfdp_tlv_len, tvb, offset-1, 1, tlv_len);

    msg_to_user_id = tvb_get_ntohl(tvb, offset);
    /* Proxy operations */
    if(msg_to_user_id == CFDP_MSG_TO_USER){
        offset += 4;
        tlv_type =  tvb_get_uint8(tvb, offset);
        proto_tree_add_uint(cfdp_msg_to_user_tree, hf_cfdp_proxy_msg_type, tvb, offset, 1, tlv_type);
        offset += 1;
        switch(tlv_type){

            case PROXY_PUT_REQ:
                tlv_len = tvb_get_uint8(tvb, offset);
                offset += 1;
                dissect_cfdp_dst_entity_id(tvb, pinfo, cfdp_msg_to_user_tree, offset, tlv_len);
                offset += tlv_len;

                tlv_len = tvb_get_uint8(tvb, offset);
                offset += 1;
                proto_tree_add_item(cfdp_msg_to_user_tree, hf_cfdp_src_file_name, tvb, offset, tlv_len, ENC_ASCII);
                offset += tlv_len;

                tlv_len = tvb_get_uint8(tvb, offset);
                offset += 1;
                proto_tree_add_item(cfdp_msg_to_user_tree, hf_cfdp_dst_file_name, tvb, offset, tlv_len, ENC_ASCII);
                offset += tlv_len;

                break;

            case PROXY_MSG_TO_USER:
                tlv_len = tvb_get_uint8(tvb, offset);
                offset += 1;
                proto_tree_add_item(cfdp_msg_to_user_tree, hf_cfdp_message_to_user, tvb, offset, tlv_len, ENC_NA);
                offset += tlv_len;
                break;

            case PROXY_FILESTORE_REQ:
                offset = dissect_cfdp_filestore_req_tlv(tvb, cfdp_msg_to_user_tree, offset);
                break;

            case PROXY_FAULT_HDL_OVERR:
                proto_tree_add_bitmask(cfdp_msg_to_user_tree, tvb, offset,
                                     hf_cfdp_proxy_fault_hdl_overr,
                                     ett_cfdp_proxy_fault_hdl_overr,
                                     cfdp_proxy_fault_hdl_overr,
                                     ENC_BIG_ENDIAN);
                offset += 1;
                break;

            case PROXY_TRANS_MODE:
                proto_tree_add_bitmask(cfdp_msg_to_user_tree, tvb, offset,
                                     hf_cfdp_proxy_trans_mode,
                                     ett_cfdp_proxy_trans_mode,
                                     cfdp_proxy_trans_mode,
                                     ENC_BIG_ENDIAN);
                offset += 1;
                break;

            case PROXY_FLOW_LABEL:
                proto_tree_add_item(cfdp_msg_to_user_tree, hf_cfdp_flow_label, tvb, offset, tlv_len, ENC_NA);
                break;

            case PROXY_SEGMENT_CONTROL:
                proto_tree_add_bitmask(cfdp_msg_to_user_tree, tvb, offset,
                                     hf_cfdp_proxy_segment_control_byte,
                                     ett_cfdp_proxy_segment_control_byte,
                                     cfdp_proxy_segment_control_byte,
                                     ENC_BIG_ENDIAN);
                offset += 1;
                break;

            case PROXY_PUT_RESP:
                proto_tree_add_bitmask(cfdp_msg_to_user_tree, tvb, offset,
                                     hf_cfdp_proxy_put_resp,
                                     ett_cfdp_proxy_put_resp,
                                     cfdp_proxy_put_resp,
                                     ENC_BIG_ENDIAN);
                offset += 1;
                break;

            case PROXY_FILESTORE_RESP:
                offset = dissect_cfdp_filestore_req_tlv(tvb, cfdp_msg_to_user_tree, offset);
                break;

            case PROXY_PUT_CANCEL:
                break;

            case ORIG_TRANS_ID:
                proto_tree_add_bitmask_ret_uint64(cfdp_msg_to_user_tree, tvb, offset,
                                     hf_cfdp_orig_trans_id,
                                     ett_cfdp_orig_trans_id,
                                     cfdp_orig_trans_id,
                                     ENC_BIG_ENDIAN,
                                     &retval);
                offset += 1;

                len_ent_id = ((retval & HDR_LEN_ENT_ID) >> 4) + 1;
                dissect_cfdp_src_entity_id(tvb, pinfo, cfdp_msg_to_user_tree, offset, len_ent_id);
                offset += len_ent_id;

                len_tseq_num = (retval & HDR_LEN_TSEQ_NUM) +1;
                dissect_cfdp_tseq_num(tvb, pinfo, cfdp_msg_to_user_tree, offset, len_tseq_num);
                offset += len_tseq_num;

                break;

            case DIRECTORY_LIST_REQ:
                /* Directory Name */
                tlv_len =  tvb_get_uint8(tvb, offset);
                offset += 1;
                proto_tree_add_item(cfdp_msg_to_user_tree, hf_cfdp_directory_name, tvb, offset, tlv_len, ENC_ASCII);
                offset += tlv_len;
                /* Directory File Name */
                tlv_len =  tvb_get_uint8(tvb, offset);
                offset += 1;
                proto_tree_add_item(cfdp_msg_to_user_tree, hf_cfdp_directory_file_name, tvb, offset, tlv_len, ENC_ASCII);
                offset += tlv_len;
                break;

            case DIRECTORY_LIST_RESP:
                /* Listing Response Code */
                proto_tree_add_item(cfdp_msg_to_user_tree, hf_cfdp_listing_resp_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                /* Directory Name */
                tlv_len =  tvb_get_uint8(tvb, offset);
                offset += 1;
                proto_tree_add_item(cfdp_msg_to_user_tree, hf_cfdp_directory_name, tvb, offset, tlv_len, ENC_ASCII);
                offset += tlv_len;
                /* Directory File Name */
                tlv_len =  tvb_get_uint8(tvb, offset);
                offset += 1;
                proto_tree_add_item(cfdp_msg_to_user_tree, hf_cfdp_directory_file_name, tvb, offset, tlv_len, ENC_ASCII);
                offset += tlv_len;
                break;

            case REMOTE_STAT_REP_REQ:
                proto_tree_add_bitmask_ret_uint64(cfdp_msg_to_user_tree, tvb, offset,
                                     hf_cfdp_remote_stat_rep_req,
                                     ett_cfdp_remote_stat_rep_req,
                                     cfdp_remote_stat_rep_req,
                                     ENC_BIG_ENDIAN,
                                     &retval);
                offset += 1;

                len_ent_id = ((retval & HDR_LEN_ENT_ID) >> 4) + 1;
                dissect_cfdp_src_entity_id(tvb, pinfo, cfdp_msg_to_user_tree, offset, len_ent_id);
                offset += len_ent_id;

                len_tseq_num = (retval & HDR_LEN_TSEQ_NUM) +1;
                dissect_cfdp_tseq_num(tvb, pinfo, cfdp_msg_to_user_tree, offset, len_tseq_num);
                offset += len_tseq_num;

                /* Report File Name */
                tlv_len =  tvb_get_uint8(tvb, offset);
                offset += 1;
                proto_tree_add_item(cfdp_msg_to_user_tree, hf_cfdp_report_file_name, tvb, offset, tlv_len, ENC_ASCII);
                offset += tlv_len;
                break;

            case REMOTE_STAT_REP_RESP:
                proto_tree_add_bitmask_ret_uint64(cfdp_msg_to_user_tree, tvb, offset,
                                     hf_cfdp_remote_stat_rep_resp,
                                     ett_cfdp_remote_stat_rep_resp,
                                     cfdp_remote_stat_rep_resp,
                                     ENC_BIG_ENDIAN,
                                     &retval);

                len_ent_id = ((retval & (HDR_LEN_ENT_ID<<8)) >> 12) + 1;
                dissect_cfdp_src_entity_id(tvb, pinfo, cfdp_msg_to_user_tree, offset, len_ent_id);
                offset += len_ent_id;

                len_tseq_num = (retval & HDR_LEN_TSEQ_NUM) +1;
                dissect_cfdp_tseq_num(tvb, pinfo, cfdp_msg_to_user_tree, offset, len_tseq_num);
                offset += len_tseq_num;
                break;

            case REMOTE_SUSPEND_REQ:
            case REMOTE_RESUME_REQ:
                proto_tree_add_bitmask_ret_uint64(cfdp_msg_to_user_tree, tvb, offset,
                                     hf_cfdp_remote_suspend_resume_req,
                                     ett_cfdp_remote_suspend_resume_req,
                                     cfdp_remote_suspend_resume_req,
                                     ENC_BIG_ENDIAN,
                                     &retval);

                offset += 1;

                len_ent_id = ((retval & HDR_LEN_ENT_ID) >> 4) + 1;
                dissect_cfdp_src_entity_id(tvb, pinfo, cfdp_msg_to_user_tree, offset, len_ent_id);
                offset += len_ent_id;

                len_tseq_num = (retval & HDR_LEN_TSEQ_NUM) +1;
                dissect_cfdp_tseq_num(tvb, pinfo, cfdp_msg_to_user_tree, offset, len_tseq_num);
                offset += len_tseq_num;
                break;

            case REMOTE_SUSPEND_RESP:
            case REMOTE_RESUME_RESP:
                proto_tree_add_bitmask_ret_uint64(cfdp_msg_to_user_tree, tvb, offset,
                                     hf_cfdp_remote_suspend_resume_resp,
                                     ett_cfdp_remote_suspend_resume_resp,
                                     cfdp_remote_suspend_resume_resp,
                                     ENC_BIG_ENDIAN,
                                     &retval);
                offset += 2;

                len_ent_id = ((retval & HDR_LEN_ENT_ID) >> 4) + 1;
                dissect_cfdp_src_entity_id(tvb, pinfo, cfdp_msg_to_user_tree, offset, len_ent_id);
                offset += len_ent_id;

                len_tseq_num = (retval & HDR_LEN_TSEQ_NUM) +1;
                dissect_cfdp_tseq_num(tvb, pinfo, cfdp_msg_to_user_tree, offset, len_tseq_num);
                offset += len_tseq_num;
                break;

            default:
                break;
        }
    }else{
        proto_tree_add_item(cfdp_msg_to_user_tree, hf_cfdp_message_to_user, tvb, offset, tlv_len, ENC_NA);
        offset += tlv_len;
    }

    return offset;
}

/* Dissect the Fault Handler Override TLV */
static uint32_t dissect_cfdp_fault_handler_overr_tlv(tvbuff_t *tvb, proto_tree *tree, uint32_t ext_offset){

    uint8_t aux_byte, tlv_len;
    proto_tree  *cfdp_fault_hdl_overr_tree;

    uint32_t offset = ext_offset;

    /* Get tlv len */
    tlv_len = tvb_get_uint8(tvb, offset);
    offset += 1;

    /* Create a subtree */
    cfdp_fault_hdl_overr_tree = proto_tree_add_subtree(tree, tvb, offset-2, tlv_len+2,
                        ett_cfdp_fault_hdl_overr, NULL, "Fault Handler Override TLV");

    proto_tree_add_uint(cfdp_fault_hdl_overr_tree, hf_cfdp_tlv_len, tvb, offset-1, 1, tlv_len);

    aux_byte = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(cfdp_fault_hdl_overr_tree, hf_cfdp_condition_code, tvb, offset, 1, aux_byte);
    proto_tree_add_uint(cfdp_fault_hdl_overr_tree, hf_cfdp_handler_code, tvb, offset, 1, aux_byte);
    offset += 1;

    return offset;
}

/* Dissect the Flow Label TLV */
static uint32_t dissect_cfdp_flow_label_tlv(tvbuff_t *tvb, proto_tree *tree, uint32_t ext_offset){

    uint8_t tlv_len;
    proto_tree  *cfdp_flow_label_tree;

    uint32_t offset = ext_offset;

    /* Get tlv len */
    tlv_len = tvb_get_uint8(tvb, offset);
    offset += 1;

    /* Create a subtree */
    cfdp_flow_label_tree = proto_tree_add_subtree(tree, tvb, offset-2, tlv_len+2,
                                        ett_cfdp_flow_label, NULL, "Flow Label TLV");

    /* It is undefined, so no specific encoding */
    proto_tree_add_item(cfdp_flow_label_tree, hf_cfdp_flow_label, tvb, offset, tlv_len, ENC_NA);

    return offset;
}

/* Dissect the End of File PDU */
static uint32_t dissect_cfdp_eof_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t ext_offset, unsigned ext_packet_len){

    uint8_t aux_byte, tlv_type, tlv_len;
    proto_tree  *cfdp_fault_location_tree;

    uint32_t offset = ext_offset;
    unsigned   cfdp_packet_data_length = ext_packet_len;

    aux_byte = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(tree, hf_cfdp_condition_code, tvb, offset, 1, aux_byte);
    proto_tree_add_uint(tree, hf_cfdp_spare_four, tvb, offset, 1, aux_byte);
    offset += 1;

    col_add_fstr(pinfo->cinfo, COL_INFO, "EOF (%s)",  val_to_str_const((aux_byte & 0xF0) >> 4, cfdp_condition_codes, "Reserved Code"));

    proto_tree_add_checksum(tree, tvb, offset, hf_cfdp_file_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
    offset += 4;

    proto_tree_add_item(tree, hf_cfdp_file_size, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if(offset < cfdp_packet_data_length){
        tlv_type = tvb_get_uint8(tvb, offset);
        offset += 1;
        if(tlv_type == FAULT_LOCATION){
            tlv_len = tvb_get_uint8(tvb, offset);
            offset += 1;
            cfdp_fault_location_tree = proto_tree_add_subtree(tree, tvb, offset-2, tlv_len+2,
                        ett_cfdp_fault_location, NULL, "Fault location TLV");

            proto_tree_add_item(cfdp_fault_location_tree, hf_cfdp_entity, tvb, offset, tlv_len, ENC_NA);
            offset += tlv_len;
        }
    }

    return offset;
}

/* Dissect the Finished PDU */
static uint32_t dissect_cfdp_finished_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t ext_offset, unsigned ext_packet_len){

    uint32_t offset = ext_offset;
    uint8_t tlv_type;
    uint64_t aux_byte;

    unsigned cfdp_packet_data_length = offset+ext_packet_len;

    proto_tree_add_bitmask_ret_uint64(tree, tvb, offset,
                         hf_cfdp_finish_pdu_flags,
                         ett_cfdp_finish_pdu_flags,
                         cfdp_finish_pdu_flags,
                         ENC_BIG_ENDIAN,
                         &aux_byte);
    offset += 1;

    col_add_fstr(pinfo->cinfo, COL_INFO, "Finished PDU (%s)",  val_to_str_const((aux_byte & 0xF0) >> 4, cfdp_condition_codes, "Reserved Code"));

    /* Add TLV fields */
    while(offset < cfdp_packet_data_length-1){
        tlv_type = tvb_get_uint8(tvb, offset);
        offset += 1;
        switch(tlv_type){
            case 0x00:
                offset += 2;
                break;
            case FILESTORE_RESP:
                offset = dissect_cfdp_filestore_resp_tlv(tvb, tree, offset);
                break;

            case FAULT_LOCATION:
                offset = dissect_cfdp_fault_location_tlv(tvb, tree, offset);
                break;

            default:
                break;
        }
    }

    return offset;
}

/* Dissect the ACK PDU */
static uint32_t dissect_cfdp_ack_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t ext_offset){

    uint8_t aux_byte;
    uint32_t offset = ext_offset;

    aux_byte = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(tree, hf_cfdp_dir_code_ack, tvb, offset, 1, aux_byte);
    proto_tree_add_uint(tree, hf_cfdp_dir_subtype_ack, tvb, offset, 1, aux_byte);
    offset += 1;

    col_add_fstr(pinfo->cinfo, COL_INFO, "ACK PDU (%s)",  val_to_str_const((aux_byte & 0xF0) >> 4, cfdp_directive_codes, "Unknown PDU"));

    aux_byte = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(tree, hf_cfdp_condition_code, tvb, offset, 1, aux_byte);
    proto_tree_add_uint(tree, hf_cfdp_spare_two, tvb, offset, 1, aux_byte);
    proto_tree_add_uint(tree, hf_cfdp_trans_stat_ack, tvb, offset, 1, aux_byte);
    offset += 1;

    return offset;
}

/* Dissect the Metadata PDU */
static uint32_t dissect_cfdp_metadata_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t ext_offset, unsigned ext_packet_len){

    uint8_t aux_byte, tlv_type;
    unsigned  cfdp_packet_data_length = ext_packet_len;
    uint32_t length;

    uint32_t offset = ext_offset;

    aux_byte = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(tree, hf_cfdp_segment_control, tvb, offset, 1, aux_byte);
    proto_tree_add_uint(tree, hf_cfdp_spare_seven, tvb, offset, 1, aux_byte);
    offset += 1;
    proto_tree_add_item(tree, hf_cfdp_file_size, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint(tree, hf_cfdp_src_file_name_len, tvb, offset, 1, ENC_NA, &length);
    offset += 1;
    if(length >0){
        proto_tree_add_item(tree, hf_cfdp_src_file_name, tvb, offset, length, ENC_ASCII);
    }
    offset += length;
    proto_tree_add_item_ret_uint(tree, hf_cfdp_dst_file_name_len, tvb, offset, 1, ENC_NA, &length);
    offset += 1;
    if(length >0){
        proto_tree_add_item(tree, hf_cfdp_dst_file_name, tvb, offset, length, ENC_ASCII);
    }
    offset += length;
    /* Add TLV fields */
    while(offset < cfdp_packet_data_length){
        tlv_type = tvb_get_uint8(tvb, offset);
        offset += 1;
        switch(tlv_type){
            case FILESTORE_REQ:
                offset = dissect_cfdp_filestore_req_tlv(tvb, tree, offset);
                break;

            case MSG_TO_USER:
                offset = dissect_cfdp_msg_to_user_tlv(tvb, pinfo, tree, offset);
                break;

            case FAULT_HDL_OVERR:
                offset = dissect_cfdp_fault_handler_overr_tlv(tvb, tree, offset);
                break;

            case FLOW_LABEL:
                offset = dissect_cfdp_flow_label_tlv(tvb, tree, offset);
                break;

            default:
                break;
        }
    }

    return offset;
}

/* Dissect the NAK PDU */
static uint32_t dissect_cfdp_nak_pdu(tvbuff_t *tvb, proto_tree *tree, uint32_t ext_offset, unsigned ext_packet_len){

    uint32_t offset = ext_offset;
    unsigned cfdp_packet_data_length = ext_packet_len;

    proto_tree_add_item(tree, hf_cfdp_nak_st_scope, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_cfdp_nak_sp_scope, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_cfdp_segment_requests, tvb, offset, cfdp_packet_data_length-9, ENC_NA);
    offset += cfdp_packet_data_length-9;

    return offset;
}

/* Dissect the Prompt PDU */
static uint32_t dissect_cfdp_prompt_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t ext_offset){

    uint8_t aux_byte;
    uint32_t offset = ext_offset;

    aux_byte = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(tree, hf_cfdp_response_req, tvb, offset, 1, aux_byte);
    proto_tree_add_uint(tree, hf_cfdp_spare_seven, tvb, offset, 1, aux_byte);
    offset += 1;

    col_add_fstr(pinfo->cinfo, COL_INFO, "Prompt PDU (%s)",  val_to_str_const((aux_byte & 0x80) >> 7, cfdp_response_req, "Unknown"));

    return offset;
}

/* Dissect the Keep Alive PDU */
static uint32_t dissect_cfdp_keep_alive_pdu(tvbuff_t *tvb, proto_tree *tree, uint32_t ext_offset){

    uint32_t offset = ext_offset;

    proto_tree_add_item(tree, hf_cfdp_progress, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/* Code to actually dissect the packets */
static int
dissect_cfdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int          offset          = 0;
    proto_item  *cfdp_packet;
    proto_item  *cfdp_tree;
    proto_item  *cfdp_header;
    proto_tree  *cfdp_header_tree;
    int cfdp_packet_length;
    int cfdp_packet_reported_length;
    int cfdp_packet_header_length;
    int cfdp_packet_data_length;
    int length;
    uint8_t first_byte;
    uint64_t retval;
    int len_ent_id;
    int len_tseq_num;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CFDP");
    col_clear(pinfo->cinfo, COL_INFO);

    cfdp_packet_reported_length = tvb_reported_length_remaining(tvb, 0);
    cfdp_packet_header_length = (tvb_get_uint8(tvb, 3) & HDR_LEN_TSEQ_NUM) + 1 + 2*(((tvb_get_uint8(tvb, 3) & HDR_LEN_ENT_ID) >>4) +1) + CFDP_HEADER_FIXED_FIELDS_LEN;
    cfdp_packet_length = tvb_get_ntohs(tvb, 1) + cfdp_packet_header_length;

    /* Min length is size of header plus 2 octets, whereas max length is reported length.
     * If the length field in the CFDP header is outside of these bounds,
     * use the value it violates.  Otherwise, use the length field value.
     */
    if(cfdp_packet_length > cfdp_packet_reported_length)
        length = cfdp_packet_reported_length;
    else if(cfdp_packet_length < cfdp_packet_header_length + 2)
        length = cfdp_packet_header_length + 2;
    else
        length = cfdp_packet_length;

    /* Build the cfdp tree */
    cfdp_packet = proto_tree_add_item(tree, proto_cfdp, tvb, 0, length, ENC_NA);
    cfdp_tree   = proto_item_add_subtree(cfdp_packet, ett_cfdp);

    cfdp_header_tree = proto_tree_add_subtree(cfdp_tree, tvb, offset, cfdp_packet_header_length,
                                                                ett_cfdp_header, &cfdp_header, "CFDP Header");

    first_byte = tvb_get_uint8(tvb, offset);

    /* CRC code is not included in the packet data length */
    cfdp_packet_data_length = tvb_get_ntohs(tvb, 1)-2*((first_byte & HDR_CRCF) >>1);

    proto_tree_add_bitmask(cfdp_header_tree, tvb, offset,
                         hf_cfdp_flags,
                         ett_cfdp_flags,
                         cfdp_flags,
                         ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(cfdp_header_tree, hf_cfdp_data_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_bitmask_ret_uint64(cfdp_header_tree, tvb, offset,
                         hf_cfdp_byte2,
                         ett_cfdp_byte2,
                         cfdp_byte2,
                         ENC_BIG_ENDIAN,
                         &retval);
    offset += 1;

    len_ent_id = ((retval & HDR_LEN_ENT_ID) >> 4) + 1;
    dissect_cfdp_src_entity_id(tvb, pinfo, cfdp_header_tree, offset, len_ent_id);
    offset += len_ent_id;

    len_tseq_num = (retval & HDR_LEN_TSEQ_NUM) +1;
    dissect_cfdp_tseq_num(tvb, pinfo, cfdp_header_tree, offset, len_tseq_num);
    offset += len_tseq_num;

    dissect_cfdp_dst_entity_id(tvb, pinfo, cfdp_header_tree, offset, len_ent_id);
    offset += len_ent_id;

    proto_item_set_end(cfdp_header, tvb, offset);

    /* Build the File Directive or the File Data tree */
    if(!(first_byte & HDR_TYPE_CFDP))
    {
        proto_item *cfdp_file_directive_header;
        proto_tree *cfdp_file_directive_header_tree;
        uint8_t     directive_code;

        cfdp_file_directive_header_tree = proto_tree_add_subtree(cfdp_tree, tvb, offset, cfdp_packet_data_length,
                                                        ett_cfdp_file_directive_header, &cfdp_file_directive_header, "CFDP File Directive");

        directive_code = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint(cfdp_file_directive_header_tree, hf_cfdp_file_directive_type, tvb, offset, 1, directive_code);
        offset += 1;

        col_add_fstr(pinfo->cinfo, COL_INFO, "%s PDU",  val_to_str(directive_code, cfdp_directive_codes, "Reserved (%d)"));

        switch(directive_code)
        {
            case EOF_PDU:
                offset = dissect_cfdp_eof_pdu(tvb, pinfo, cfdp_file_directive_header_tree, offset, cfdp_packet_data_length);
                break;

            case FINISHED_PDU:
                offset = dissect_cfdp_finished_pdu(tvb, pinfo, cfdp_file_directive_header_tree, offset, cfdp_packet_data_length);
                break;

            case ACK_PDU:
                offset = dissect_cfdp_ack_pdu(tvb, pinfo, cfdp_file_directive_header_tree, offset);
                break;

            case METADATA_PDU:
                offset = dissect_cfdp_metadata_pdu(tvb, pinfo, cfdp_file_directive_header_tree, offset, cfdp_packet_data_length);
                break;

            case NAK_PDU:
                offset = dissect_cfdp_nak_pdu(tvb, cfdp_file_directive_header_tree, offset, cfdp_packet_data_length);
                break;

            case PROMPT_PDU:
                offset = dissect_cfdp_prompt_pdu(tvb, pinfo, cfdp_file_directive_header_tree, offset);
                break;

            case KEEP_ALIVE_PDU:
                offset = dissect_cfdp_keep_alive_pdu(tvb, cfdp_file_directive_header_tree, offset);
                break;

            default:
                break;
        }

        proto_item_set_end(cfdp_file_directive_header, tvb, offset);

    }else{
        proto_tree  *cfdp_file_data_header_tree;

        col_set_str(pinfo->cinfo, COL_INFO, "File Data PDU");

        cfdp_file_data_header_tree = proto_tree_add_subtree(cfdp_tree, tvb, offset, cfdp_packet_data_length,
                                                            ett_cfdp_file_data_header, NULL, "CFDP File Data");

        proto_tree_add_item(cfdp_file_data_header_tree, hf_cfdp_file_data_offset, tvb, offset, 4, ENC_BIG_ENDIAN);

        offset += 4;

        proto_tree_add_item(cfdp_file_data_header_tree, hf_cfdp_user_data, tvb, offset, cfdp_packet_data_length-4, ENC_NA);
        offset += cfdp_packet_data_length-4;

    }
    if(first_byte & HDR_CRCF){
        proto_item  *cfdp_crc;
        proto_tree  *cfdp_crc_tree;

        cfdp_crc_tree = proto_tree_add_subtree(cfdp_tree, tvb, offset, 2, ett_cfdp_crc, &cfdp_crc, "CRC");

        proto_tree_add_item(cfdp_crc_tree, hf_cfdp_crc, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_item_set_end(cfdp_crc, tvb, offset);
    }
    /* Give the data dissector any bytes past the CFDP packet length */
    call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, tree);
    return tvb_captured_length(tvb);
}

void
dissect_cfdp_as_subtree(tvbuff_t *tvb,  packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_tree  *cfdp_header_tree = NULL;
    proto_tree *cfdp_sub_tree = NULL;
    proto_item *payload_item = NULL;
    proto_tree *cfdp_tree = NULL;
    proto_item  *cfdp_header;
    int cfdp_data_len;
    int len_ent_id;
    int len_tseq_num;
    uint64_t first_byte;
    uint64_t retval;

    cfdp_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_cfdp_proto,
                                       &payload_item, "Payload Data: CFDP Protocol");

    cfdp_sub_tree   = proto_item_add_subtree(cfdp_tree, ett_cfdp);
    cfdp_header_tree = proto_tree_add_subtree(cfdp_sub_tree, tvb, offset, -1,
                                              ett_cfdp_header, &cfdp_header, "CFDP Header");

    proto_tree_add_bitmask_ret_uint64(cfdp_header_tree, tvb, offset,
                         hf_cfdp_flags,
                         ett_cfdp_flags,
                         cfdp_flags,
                         ENC_BIG_ENDIAN,
                         &first_byte);
    offset += 1;

    unsigned cfdp_data_end;
    cfdp_data_len = tvb_get_uint16 (tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(cfdp_header_tree, hf_cfdp_data_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_bitmask_ret_uint64(cfdp_header_tree, tvb, offset,
                         hf_cfdp_byte2,
                         ett_cfdp_byte2,
                         cfdp_byte2,
                         ENC_BIG_ENDIAN,
                         &retval);
    offset += 1;

    len_ent_id = ((retval & HDR_LEN_ENT_ID) >> 4) + 1;
    dissect_cfdp_src_entity_id(tvb, pinfo, cfdp_header_tree, offset, len_ent_id);
    offset += len_ent_id;

    len_tseq_num = (retval & HDR_LEN_TSEQ_NUM) +1;
    dissect_cfdp_tseq_num(tvb, pinfo, cfdp_header_tree, offset, len_tseq_num);
    offset += len_tseq_num;

    dissect_cfdp_dst_entity_id(tvb, pinfo, cfdp_header_tree, offset, len_ent_id);
    offset += len_ent_id;

    cfdp_data_end = offset+cfdp_data_len;

    /* Build the File Directive or the File Data tree */
    if(!(first_byte & HDR_TYPE_CFDP))
    {
        proto_item *cfdp_file_directive_header;
        proto_tree *cfdp_file_directive_header_tree;
        uint8_t     directive_code;

        cfdp_file_directive_header_tree = proto_tree_add_subtree(cfdp_tree, tvb, offset, cfdp_data_len,
                                                        ett_cfdp_file_directive_header, &cfdp_file_directive_header,
                                                        "CFDP File Directive");

        directive_code = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint(cfdp_file_directive_header_tree, hf_cfdp_file_directive_type, tvb, offset, 1, directive_code);
        offset += 1;

        col_add_fstr(pinfo->cinfo, COL_INFO, "%s PDU",  val_to_str(directive_code, cfdp_directive_codes, "Reserved (%d)"));

        switch(directive_code)
        {
            case EOF_PDU:
                offset = dissect_cfdp_eof_pdu(tvb, pinfo, cfdp_file_directive_header_tree, offset, cfdp_data_len);
                break;

            case FINISHED_PDU:
                offset = dissect_cfdp_finished_pdu(tvb, pinfo, cfdp_file_directive_header_tree, offset, cfdp_data_len);
                break;

            case ACK_PDU:
                offset = dissect_cfdp_ack_pdu(tvb, pinfo, cfdp_file_directive_header_tree, offset);
                break;

            case METADATA_PDU:
                offset = dissect_cfdp_metadata_pdu(tvb, pinfo, cfdp_file_directive_header_tree, offset, cfdp_data_len);
                break;

            case PROMPT_PDU:
                offset = dissect_cfdp_prompt_pdu(tvb, pinfo, cfdp_file_directive_header_tree, offset);
                break;

            case KEEP_ALIVE_PDU:
                offset = dissect_cfdp_keep_alive_pdu(tvb, cfdp_file_directive_header_tree, offset);
                break;

            default:
                break;
        }

    }else{
        proto_tree  *cfdp_file_data_header_tree;

        col_set_str(pinfo->cinfo, COL_INFO, "File Data PDU");

        cfdp_file_data_header_tree = proto_tree_add_subtree(cfdp_tree, tvb, offset, cfdp_data_len,
                                                            ett_cfdp_file_data_header, NULL, "CFDP File Data");

        proto_tree_add_item(cfdp_file_data_header_tree, hf_cfdp_file_data_offset, tvb, offset, 4, ENC_BIG_ENDIAN);

        offset += 4;

        proto_tree_add_item(cfdp_file_data_header_tree, hf_cfdp_user_data, tvb, offset, cfdp_data_len-4, ENC_NA);
        offset += cfdp_data_len-4;

    }
    if(first_byte & HDR_CRCF){
        proto_item  *cfdp_crc;
        proto_tree  *cfdp_crc_tree;

        cfdp_crc_tree = proto_tree_add_subtree(cfdp_tree, tvb, offset, 2, ett_cfdp_crc, &cfdp_crc, "CRC");

        proto_tree_add_item(cfdp_crc_tree, hf_cfdp_crc, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_item_set_end(cfdp_crc, tvb, offset);
    }

    if ( cfdp_data_end>(unsigned)offset ) {
        proto_tree_add_string(cfdp_header_tree, hf_cfdp_file_data_pdu, tvb, offset, cfdp_data_len,
                              wmem_strdup_printf(pinfo->pool, "<%d bytes>", cfdp_data_len));
    }
    return;
}

void
proto_register_cfdp(void)
{
    static hf_register_info hf[] = {

        { &hf_cfdp_flags,
        { "Flags", "cfdp.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_byte2,
        { "Byte2", "cfdp.byte2",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_proxy_fault_hdl_overr,
        { "Proxy Fault HDL Overr", "cfdp.proxy_fault_hdl_overr",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_proxy_trans_mode,
        { "Proxy Transmission Mode", "cfdp.proxy_trans_mode",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_proxy_segment_control_byte,
        { "Proxy Segment Control", "cfdp.proxy_segment_control",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_proxy_put_resp,
        { "Proxy Put Response", "cfdp.proxy_put_response",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_orig_trans_id,
        { "Originating Transaction ID", "cfdp.orig_trans_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_remote_stat_rep_req,
        { "Remote Status Report Request", "cfdp.remote_status_rep_req",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_remote_stat_rep_resp,
        { "Remote Status Report Response", "cfdp.remote_status_rep_resp",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_finish_pdu_flags,
        { "Finish PDU flags", "cfdp.finish_pdu_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_remote_suspend_resume_req,
        { "Remote Suspend/Resume Request", "cfdp.remote_suspend_resume_req",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_remote_suspend_resume_resp,
        { "Remote Suspend/Resume Response", "cfdp.remote_suspend_resume_resp",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_version,
        { "Version", "cfdp.version",
            FT_UINT8, BASE_DEC, NULL, HDR_VERSION_CFDP,
            NULL, HFILL }
        },
        { &hf_cfdp_pdu_type,
            { "PDU Type", "cfdp.pdu_type",
            FT_UINT8, BASE_DEC, VALS(cfdp_pdu_type), HDR_TYPE_CFDP,
            NULL, HFILL }
        },
        { &hf_cfdp_direction,
            { "Direction", "cfdp.direction",
            FT_UINT8, BASE_DEC, VALS(cfdp_direction), HDR_DIR,
            NULL, HFILL }
        },
        { &hf_cfdp_trans_mode,
            { "Trans. Mode", "cfdp.trans_mode",
            FT_UINT8, BASE_DEC, VALS(cfdp_trans_mode), HDR_TMODE,
            NULL, HFILL }
        },
        { &hf_cfdp_trans_mode_2,
            { "Trans. Mode", "cfdp.trans_mode",
            FT_UINT8, BASE_DEC, VALS(cfdp_trans_mode), 0x01,
            NULL, HFILL }
        },
        { &hf_cfdp_crc_flag,
            { "CRC Flag", "cfdp.crc_flag",
            FT_UINT8, BASE_DEC, VALS(cfdp_crc_flag), HDR_CRCF,
            NULL, HFILL }
        },
        { &hf_cfdp_res1,
            { "Bit reserved 1", "cfdp.res1",
            FT_UINT8, BASE_DEC, NULL, HDR_RES1,
            NULL, HFILL }
        },
        { &hf_cfdp_data_length,
            { "PDU Data length", "cfdp.data_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        {&hf_cfdp_file_data_pdu,
         {"CFDP File PDU Data", "cfdp.file_data_pdu",
          FT_STRINGZPAD, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_cfdp_res2,
            { "Bit reserved 2", "cfdp.res2",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_cfdp_entid_length,
            { "Length of entity IDs", "cfdp.entid_length",
            FT_UINT8, BASE_DEC, NULL, 0x70,
            NULL, HFILL }
        },
        { &hf_cfdp_res3,
            { "Bit reserved 3", "cfdp.res3",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_cfdp_transeqnum_length,
            { "Length of Transaction sequence number", "cfdp.transeqnum_length",
            FT_UINT8, BASE_DEC, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_cfdp_srcid,
            { "Source entity ID", "cfdp.srcid",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_transeqnum,
            { "Transaction sequence number", "cfdp.transeqnum",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_dstid,
            { "Destination entity ID", "cfdp.dstid",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_file_directive_type,
            { "File Directive type", "cfdp.fdtype",
            FT_UINT8, BASE_DEC, VALS(cfdp_file_directive_type), 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_file_data_offset,
            { "Offset", "cfdp.offset",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_progress,
            { "Progress", "cfdp.progress",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_dir_code_ack,
            { "PDU acknowledged", "cfdp.dir_code_ack",
            FT_UINT8, BASE_DEC, VALS(cfdp_file_directive_type), 0xf0,
            NULL, HFILL }
        },
        { &hf_cfdp_dir_subtype_ack,
            { "Directive subtype code", "cfdp.dir_subtype_ack",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_cfdp_condition_code,
            { "Condition Code", "cfdp.condition_code",
            FT_UINT8, BASE_DEC, VALS(cfdp_condition_codes), 0xf0,
            NULL, HFILL }
        },
        { &hf_cfdp_spare_one,
            { "Spare", "cfdp.spare_one",
            FT_UINT8, BASE_DEC, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_cfdp_spare_one_2,
            { "Spare", "cfdp.spare_one_2",
            FT_UINT16, BASE_DEC, NULL, 0x0080,
            NULL, HFILL }
        },
        { &hf_cfdp_spare_two,
            { "Spare", "cfdp.spare_two",
            FT_UINT8, BASE_DEC, NULL, 0x0c,
            NULL, HFILL }
        },
        { &hf_cfdp_spare_four,
            { "Spare", "cfdp.spare_four",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_cfdp_spare_five,
            { "Spare", "cfdp.spare_five_b",
            FT_UINT16, BASE_DEC, NULL, 0x3E00,
            NULL, HFILL }
        },
        { &hf_cfdp_spare_five_2,
            { "Spare", "cfdp.spare_five_b",
            FT_UINT16, BASE_DEC, NULL, 0x1F00,
            NULL, HFILL }
        },
        { &hf_cfdp_spare_seven,
            { "Spare", "cfdp.spare_seven",
            FT_UINT8, BASE_DEC, NULL, 0x7f,
            NULL, HFILL }
        },
        { &hf_cfdp_spare_seven_2,
            { "Spare", "cfdp.spare_seven_2",
            FT_UINT8, BASE_DEC, NULL, 0xfe,
            NULL, HFILL }
        },
        { &hf_cfdp_trans_stat_ack,
            { "Transaction status", "cfdp.trans_stat_ack",
            FT_UINT8, BASE_DEC, VALS(cfdp_trans_stat_ack), 0x03,
            NULL, HFILL }
        },
        { &hf_cfdp_trans_stat,
            { "Transaction status B", "cfdp.trans_stat_b",
            FT_UINT16, BASE_DEC, VALS(cfdp_trans_stat_ack), 0xC000,
            NULL, HFILL }
        },
        { &hf_cfdp_trans_stat_2,
            { "Transaction status", "cfdp.trans_stat_2_b",
            FT_UINT16, BASE_DEC, VALS(cfdp_trans_stat_ack), 0x6000,
            NULL, HFILL }
        },
        { &hf_cfdp_file_checksum,
            { "Checksum", "cfdp.checksum",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_file_size,
            { "File size", "cfdp.file_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_end_system_stat,
            { "End system status", "cfdp.end_system_stat",
            FT_UINT8, BASE_DEC, VALS(cfdp_end_system_stat), 0x08,
            NULL, HFILL }
        },
        { &hf_cfdp_delivery_code,
            { "Delivery code", "cfdp.delivery_code",
            FT_UINT8, BASE_DEC, VALS(cfdp_delivery_code), 0x04,
            NULL, HFILL }
        },
        { &hf_cfdp_file_stat,
            { "File status", "cfdp.file_status",
            FT_UINT8, BASE_DEC, VALS(cfdp_file_stat), 0x03,
            NULL, HFILL }
        },
        { &hf_cfdp_segment_control,
            { "Segmentation control", "cfdp.segment_control",
            FT_UINT8, BASE_DEC, VALS(cfdp_segment_control), 0x80,
            NULL, HFILL }
        },
        { &hf_cfdp_tlv_len,
            { "Length", "cfdp.tlv_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_src_file_name_len,
            {"Length of source file name", "cfdp.src_file_name_len", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cfdp_src_file_name,
            {"Source file name", "cfdp.src_file_name", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cfdp_dst_file_name_len,
            {"Length of destination file name", "cfdp.dst_file_name_len", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cfdp_dst_file_name,
            {"Destination file name", "cfdp.dst_file_name", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cfdp_first_file_name_len,
            {"Length of first file name", "cfdp.first_file_name_len", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cfdp_first_file_name,
            {"First file name", "cfdp.first_file_name", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cfdp_second_file_name_len,
            {"Length of second file name", "cfdp.second_file_name_len", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cfdp_second_file_name,
            {"Second file name", "cfdp.second_file_name", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cfdp_nak_st_scope,
            {"Start of scope", "cfdp.nak_st_scope", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cfdp_nak_sp_scope,
            {"End of scope", "cfdp.nak_sp_scope", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cfdp_crc,
            {"CRC", "cfdp.crc", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cfdp_action_code,
            {"Action code", "cfdp.action_code", FT_UINT8, BASE_DEC, VALS(cfdp_action_code), 0xF0,
            NULL, HFILL}
        },
        { &hf_cfdp_status_code_1,
            {"Status code", "cfdp.status_code_1", FT_UINT8, BASE_DEC, VALS(cfdp_status_code_1), 0x0F,
            NULL, HFILL}
        },
        { &hf_cfdp_status_code_2,
            {"Status code", "cfdp.status_code_2", FT_UINT8, BASE_DEC, VALS(cfdp_status_code_2), 0x0F,
            NULL, HFILL}
        },
        { &hf_cfdp_status_code_3,
            {"Status code", "cfdp.status_code_3", FT_UINT8, BASE_DEC, VALS(cfdp_status_code_3), 0x0F,
            NULL, HFILL}
        },
        { &hf_cfdp_status_code_4,
            {"Status code", "cfdp.status_code_4", FT_UINT8, BASE_DEC, VALS(cfdp_status_code_4), 0x0F,
            NULL, HFILL}
        },
        { &hf_cfdp_status_code_5,
            {"Status code", "cfdp.status_code_5", FT_UINT8, BASE_DEC, VALS(cfdp_status_code_5), 0x0F,
            NULL, HFILL}
        },
        { &hf_cfdp_status_code_6,
            {"Status code", "cfdp.status_code_6", FT_UINT8, BASE_DEC, VALS(cfdp_status_code_6), 0x0F,
            NULL, HFILL}
        },
        { &hf_cfdp_status_code_7,
            {"Status code", "cfdp.status_code_7", FT_UINT8, BASE_DEC, VALS(cfdp_status_code_7), 0x0F,
            NULL, HFILL}
        },
        { &hf_cfdp_status_code_8,
            {"Status code", "cfdp.status_code_8", FT_UINT8, BASE_DEC, VALS(cfdp_status_code_8), 0x0F,
            NULL, HFILL}
        },
        { &hf_cfdp_handler_code,
            { "Handler Code", "cfdp.handler_code",
            FT_UINT8, BASE_DEC, VALS(cfdp_handler_codes), 0x0F,
            NULL, HFILL }
        },
        { &hf_cfdp_proxy_msg_type,
            { "Proxy Message Type", "cfdp.proxy_msg_type",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &cfdp_proxy_msg_type_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_cfdp_proxy_segment_control,
            { "Segmentation control", "cfdp.proxy_segment_control",
            FT_UINT8, BASE_DEC, VALS(cfdp_segment_control), 0x01,
            NULL, HFILL }
        },
        { &hf_cfdp_proxy_delivery_code,
            { "Delivery code", "cfdp.proxy_delivery_code",
            FT_UINT8, BASE_DEC, VALS(cfdp_delivery_code), 0x04,
            NULL, HFILL }
        },
        { &hf_cfdp_response_req,
            { "Response required", "cfdp.response_req",
            FT_UINT8, BASE_DEC, VALS(cfdp_response_req), 0x80,
            NULL, HFILL }
        },
        { &hf_cfdp_directory_name,
            {"Directory Name", "cfdp.directory_name", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cfdp_directory_file_name,
            {"Directory File Name", "cfdp.directory_file_name", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cfdp_listing_resp_code,
            {"Listing Response Code", "cfdp.listing_resp_code",
            FT_UINT8, BASE_DEC, VALS(cfdp_listing_resp_code), 0x80,
            NULL, HFILL}
        },
        { &hf_cfdp_report_file_name,
            {"Report File Name", "cfdp.report_file_name", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_cfdp_rep_resp_code,
            {"Report Response Code", "cfdp.rep_resp_code_b",
            FT_UINT16, BASE_DEC, VALS(cfdp_rep_resp_code), 0x0100,
            NULL, HFILL}
        },
        { &hf_cfdp_suspension_ind,
            {"Suspension indicator", "cfdp.suspension_ind_b",
            FT_UINT16, BASE_DEC, VALS(cfdp_suspension_ind), 0x8000,
            NULL, HFILL}
        },
        { &hf_cfdp_filestore_message_len,
            {"Length of filestore message", "cfdp.filestore_message_len", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },

        /* Generated from convert_proto_tree_add_text.pl */
        { &hf_cfdp_filestore_message, { "Filestore Message", "cfdp.filestore_message", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_cfdp_entity, { "Entity", "cfdp.entity", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_cfdp_message_to_user, { "Message to User", "cfdp.message_to_user", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_cfdp_flow_label, { "Flow label", "cfdp.flow_label", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_cfdp_segment_requests, { "Segment requests", "cfdp.segment_requests", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_cfdp_user_data, { "User Data", "cfdp.user_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_cfdp,
        &ett_cfdp_flags,
        &ett_cfdp_byte2,
        &ett_cfdp_proxy_fault_hdl_overr,
        &ett_cfdp_proxy_trans_mode,
        &ett_cfdp_proxy_segment_control_byte,
        &ett_cfdp_proxy_put_resp,
        &ett_cfdp_orig_trans_id,
        &ett_cfdp_remote_suspend_resume_req,
        &ett_cfdp_remote_suspend_resume_resp,
        &ett_cfdp_remote_stat_rep_req,
        &ett_cfdp_remote_stat_rep_resp,
        &ett_cfdp_finish_pdu_flags,
        &ett_cfdp_header,
        &ett_cfdp_file_directive_header,
        &ett_cfdp_file_data_header,
        &ett_cfdp_fault_location,
        &ett_cfdp_crc,
        &ett_cfdp_filestore_req,
        &ett_cfdp_filestore_resp,
        &ett_cfdp_msg_to_user,
        &ett_cfdp_fault_hdl_overr,
        &ett_cfdp_flow_label,
        &ett_cfdp_proto
    };

    static ei_register_info ei[] = {
        { &ei_cfdp_bad_length, { "cfdp.bad_length", PI_MALFORMED, PI_ERROR, "Bad length field", EXPFILL }},
    };

    expert_module_t* expert_cfdp;

    /* Register the protocol name and description */
    proto_cfdp = proto_register_protocol("CFDP", "CFDP", "cfdp");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_cfdp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_cfdp = expert_register_protocol(proto_cfdp);
    expert_register_field_array(expert_cfdp, ei, array_length(ei));

    cfdp_handle = register_dissector("cfdp", dissect_cfdp, proto_cfdp);
}

void
proto_reg_handoff_cfdp(void)
{
    dissector_add_uint("ccsds.apid", CFDP_APID, cfdp_handle);
    dissector_add_for_decode_as_with_preference("udp.port", cfdp_handle);
}

/*
 * Editor modelines - https://www.wireshark.org/tools/modelines.html
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

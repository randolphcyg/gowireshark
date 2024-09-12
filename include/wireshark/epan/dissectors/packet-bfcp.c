/* packet-bfcp.c
 * Routines for Binary Floor Control Protocol(BFCP) dissection
 * Copyright 2012, Nitinkumar Yemul <nitinkumaryemul@gmail.com>
 *
 * Updated with attribute dissection
 * Copyright 2012, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * BFCP Message structure is defined in RFC 8855
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/tfs.h>

#include "packet-bfcp.h"

void proto_register_bfcp(void);
void proto_reg_handoff_bfcp(void);

/* Initialize protocol and registered fields */
static int proto_bfcp;

static int hf_bfcp_version;
static int hf_bfcp_hdr_r_bit;
static int hf_bfcp_hdr_f_bit;
static int hf_bfcp_primitive;
static int hf_bfcp_payload_length;
static int hf_bfcp_conference_id;
static int hf_bfcp_transaction_id;
static int hf_bfcp_user_id;
static int hf_bfcp_fragment_offset;
static int hf_bfcp_fragment_length;
static int hf_bfcp_payload;
static int hf_bfcp_attribute_types;
static int hf_bfcp_attribute_types_m_bit;
static int hf_bfcp_attribute_length;
static int hf_bfcp_beneficiary_id;
static int hf_bfcp_floor_id;
static int hf_bfcp_floor_request_id;
static int hf_bfcp_priority;
static int hf_bfcp_request_status;
static int hf_bfcp_queue_pos;
static int hf_bfcp_error_code;
static int hf_bfcp_error_info_text;
static int hf_bfcp_part_prov_info_text;
static int hf_bfcp_status_info_text;
static int hf_bfcp_supp_attr;
static int hf_bfcp_supp_prim;
static int hf_bfcp_user_disp_name;
static int hf_bfcp_user_uri;
static int hf_bfcp_req_by_id;
static int hf_bfcp_padding;
static int hf_bfcp_error_specific_details;
/* BFCP setup fields */
static int hf_bfcp_setup;
static int hf_bfcp_setup_frame;
static int hf_bfcp_setup_method;

/* Initialize subtree pointers */
static int ett_bfcp;
static int ett_bfcp_setup;
static int ett_bfcp_attr;

static expert_field ei_bfcp_attribute_length_too_small;

static dissector_handle_t bfcp_handle;

#define BFCP_HDR_LEN 12

/* Initialize BFCP primitives */
static const value_string map_bfcp_primitive[] = {
	{ 0,  "<Invalid Primitive>"},
	{ 1,  "FloorRequest"},
	{ 2,  "FloorRelease"},
	{ 3,  "FloorRequestQuery"},
	{ 4,  "FloorRequestStatus"},
	{ 5,  "UserQuery"},
	{ 6,  "UserStatus"},
	{ 7,  "FloorQuery"},
	{ 8,  "FloorStatus"},
	{ 9,  "ChairAction"},
	{ 10, "ChairActionAck"},
	{ 11, "Hello"},
	{ 12, "HelloAck"},
	{ 13, "Error"},
	{ 14, "FloorRequestStatusAck"},
	{ 15, "ErrorAck"},
	{ 16, "FloorStatusAck"},
	{ 17, "Goodbye"},
	{ 18, "GoodbyeAck"},
	{ 0,  NULL},
};

static const value_string map_bfcp_attribute_types[] = {
	{ 0,  "<Invalid Primitive>"},
	{ 1,  "BeneficiaryID"},
	{ 2,  "FloorID"},
	{ 3,  "FloorRequestID"},
	{ 4,  "Priority"},
	{ 5,  "RequestStatus"},
	{ 6,  "ErrorCode"},
	{ 7,  "ErrorInfo"},
	{ 8,  "ParticipantProvidedInfo"},
	{ 9,  "StatusInfo"},
	{ 10, "SupportedAttributes"},
	{ 11, "SupportedPrimitives"},
	{ 12, "UserDisplayName"},
	{ 13, "UserURI"},
	{ 14, "BeneficiaryInformation"},
	{ 15, "FloorRequestInformation"},
	{ 16, "RequestedByInformation"},
	{ 17, "FloorRequestStatus"},
	{ 18, "OverallRequestStatus"},
	{ 0,  NULL},
};

static const value_string map_bfcp_request_status[] = {
	{ 0,  "<Invalid Primitive>"},
	{ 1,  "Pending"},
	{ 2,  "Accepted"},
	{ 3,  "Granted"},
	{ 4,  "Denied"},
	{ 5,  "Cancelled"},
	{ 6,  "Released"},
	{ 7,  "Revoked"},
	{ 0,  NULL},
};

/* 5.2.6.  ERROR-CODE */
static const value_string bfcp_error_code_valuse[] = {
	{ 1,  "Conference does not Exist"},
	{ 2,  "User does not Exist"},
	{ 3,  "Unknown Primitive"},
	{ 4,  "Unknown Mandatory Attribute"},
	{ 5,  "Unauthorized Operation"},
	{ 6,  "Invalid Floor ID"},
	{ 7,  "Floor Request ID Does Not Exist"},
	{ 8,  "You have Already Reached the Maximum Number of Ongoing Floor Requests for this Floor"},
	{ 9,  "Use TLS"},
	{ 10,  "Unable to Parse Message"},
	{ 11,  "Use DTLS"},
	{ 12,  "Unsupported Version"},
	{ 13,  "Incorrect Message Length"},
	{ 14,  "Generic Error"},

	{ 0,  NULL},
};

/*Define offset for fields in BFCP packet */
#define BFCP_OFFSET_TRANSACTION_INITIATOR  0
#define BFCP_OFFSET_PRIMITIVE              1
#define BFCP_OFFSET_PAYLOAD_LENGTH         2
#define BFCP_OFFSET_CONFERENCE_ID          4
#define BFCP_OFFSET_TRANSACTION_ID         8
#define BFCP_OFFSET_USER_ID               10
#define BFCP_OFFSET_PAYLOAD               12

/* Set up an BFCP conversation using the info given */
void
bfcp_add_address( packet_info *pinfo, port_type ptype,
		address *addr, int port,
		const char *setup_method, uint32_t setup_frame_number)
{
	address null_addr;
	conversation_t* p_conv;
	struct _bfcp_conversation_info *p_conv_data = NULL;

	/*
	* If this isn't the first time this packet has been processed,
	* we've already done this work, so we don't need to do it
	* again.
	*/
	if (PINFO_FD_VISITED(pinfo)) {
		return;
	}

	clear_address(&null_addr);

	/*
	* Check if the ip address and port combination is not
	* already registered as a conversation.
	*/
	p_conv = find_conversation( pinfo->num, addr, &null_addr, conversation_pt_to_conversation_type(ptype), port, 0,
				NO_ADDR_B | NO_PORT_B);

	/*
	* If not, create a new conversation.
	*/
	if (!p_conv) {
		p_conv = conversation_new( pinfo->num, addr, &null_addr, conversation_pt_to_conversation_type(ptype),
				   (uint32_t)port, 0,
				   NO_ADDR2 | NO_PORT2);
	}

	/* Set dissector */
	conversation_set_dissector(p_conv, bfcp_handle);

	/*
	* Check if the conversation has data associated with it.
	*/
	p_conv_data = (struct _bfcp_conversation_info *)conversation_get_proto_data(p_conv, proto_bfcp);

	/*
	* If not, add a new data item.
	*/
	if (!p_conv_data) {
	/* Create conversation data */
		p_conv_data = wmem_new0(wmem_file_scope(), struct _bfcp_conversation_info);
		conversation_add_proto_data(p_conv, proto_bfcp, p_conv_data);
	}

	/*
	* Update the conversation data.
	*/
	p_conv_data->setup_method_set = true;
	(void) g_strlcpy(p_conv_data->setup_method, setup_method, MAX_BFCP_SETUP_METHOD_SIZE);
	p_conv_data->setup_frame_number = setup_frame_number;
}

/* Look for conversation info and display any setup info found */
static void
show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Conversation and current data */
	conversation_t *p_conv = NULL;
	struct _bfcp_conversation_info *p_conv_data = NULL;

	/* Use existing packet data if available */
	p_conv_data = (struct _bfcp_conversation_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_bfcp, 0);

	if (!p_conv_data) {
	/* First time, get info from conversation */
	p_conv = find_conversation(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
				   conversation_pt_to_conversation_type(pinfo->ptype),
				   pinfo->destport, pinfo->srcport, 0);

		if (p_conv) {
			/* Look for data in conversation */
			struct _bfcp_conversation_info *p_conv_packet_data;
			p_conv_data = (struct _bfcp_conversation_info *)conversation_get_proto_data(p_conv, proto_bfcp);

			if (p_conv_data) {
				/* Save this conversation info into packet info */
				p_conv_packet_data = (struct _bfcp_conversation_info *)wmem_memdup(wmem_file_scope(),
				p_conv_data, sizeof(struct _bfcp_conversation_info));

				p_add_proto_data(wmem_file_scope(), pinfo, proto_bfcp, 0, p_conv_packet_data);
			}
		}
	}

	/* Create setup info subtree with summary info. */
	if (p_conv_data && p_conv_data->setup_method_set) {
		proto_tree *bfcp_setup_tree;
		proto_item *ti =  proto_tree_add_string_format(tree, hf_bfcp_setup, tvb, 0, 0,
							       "",
							       "Stream setup by %s (frame %u)",
							       p_conv_data->setup_method,
							       p_conv_data->setup_frame_number);
		proto_item_set_generated(ti);
		bfcp_setup_tree = proto_item_add_subtree(ti, ett_bfcp_setup);
		if (bfcp_setup_tree) {
			/* Add details into subtree */
			proto_item* item = proto_tree_add_uint(bfcp_setup_tree, hf_bfcp_setup_frame,
						   tvb, 0, 0, p_conv_data->setup_frame_number);
			proto_item_set_generated(item);
			item = proto_tree_add_string(bfcp_setup_tree, hf_bfcp_setup_method,
					 tvb, 0, 0, p_conv_data->setup_method);
			proto_item_set_generated(item);
		}
	}
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_bfcp_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int bfcp_payload_length)
{
	proto_item *ti, *item;
	proto_tree  *bfcp_attr_tree = NULL;
	int         attr_start_offset;
	int         length;
	uint8_t     attribute_type;
	int         read_attr = 0;
	uint8_t     first_byte, pad_len;

	increment_dissection_depth(pinfo);
	while ((tvb_reported_length_remaining(tvb, offset) >= 2) &&
			((bfcp_payload_length - read_attr) >= 2))
	{

		attr_start_offset = offset;
		first_byte = tvb_get_uint8(tvb, offset);

		/* Padding so continue to next attribute */
		if (first_byte == 0){
			read_attr++;
			continue;
		}

		ti = proto_tree_add_item(tree, hf_bfcp_attribute_types, tvb, offset, 1, ENC_BIG_ENDIAN);
		bfcp_attr_tree = proto_item_add_subtree(ti, ett_bfcp_attr);
		proto_tree_add_item(bfcp_attr_tree, hf_bfcp_attribute_types_m_bit, tvb, offset, 1, ENC_BIG_ENDIAN);

		attribute_type = (first_byte & 0xFE) >> 1;
		offset++;

	/*   Length: This 8-bit field contains the length of the attribute in
	 *   octets, excluding any padding defined for specific attributes.  The
	 *   length of attributes that are not grouped includes the Type, 'M' bit,
	 *   and Length fields.  The Length in grouped attributes is the length of
	 *   the grouped attribute itself (including Type, 'M' bit, and Length
	 *   fields) plus the total length (including padding) of all the included
	 *   attributes.
	 */

		item = proto_tree_add_item(bfcp_attr_tree, hf_bfcp_attribute_length, tvb, offset, 1, ENC_BIG_ENDIAN);
		length = tvb_get_uint8(tvb, offset);
		/* At least Type, M bit and Length fields */
		if (length < 2){
			expert_add_info_format(pinfo, item, &ei_bfcp_attribute_length_too_small,
					       "Attribute length is too small (%d bytes - minimum valid is 2)", length);
			break;
		}
		offset++;

		switch(attribute_type){
		case 1: /* Beneficiary ID */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_beneficiary_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			break;
		case 2: /* FLOOR-ID */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_floor_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			break;
		case 3: /* FLOOR-REQUEST-ID */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_floor_request_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			break;
		case 4: /* PRIORITY */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			break;
		case 5: /* REQUEST-STATUS */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_request_status, tvb, offset,1, ENC_BIG_ENDIAN);
			offset++;
			/* Queue Position */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_queue_pos, tvb, offset,1, ENC_BIG_ENDIAN);
			offset++;
			break;
		case 6: /* ERROR-CODE */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_error_code, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			if(length>3){
				/* We have Error Specific Details */
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_error_specific_details, tvb, offset, length-3, ENC_NA);
			}
			offset = offset + length-3;
			pad_len = length & 0x03;
			if(pad_len != 0){
				pad_len = 4 - pad_len;
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_padding, tvb, offset, pad_len, ENC_NA);
			}
			offset = offset + pad_len;
			break;
		case 7: /* ERROR-INFO */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_error_info_text, tvb, offset, length-2, ENC_ASCII);
			offset = offset + length-2;
			pad_len = length & 0x03;
			if(pad_len != 0){
				pad_len = 4 - pad_len;
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_padding, tvb, offset, pad_len, ENC_NA);
			}
			offset = offset + pad_len;
			break;
		case 8: /* PARTICIPANT-PROVIDED-INFO */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_part_prov_info_text, tvb, offset, length-2, ENC_ASCII);
			offset = offset + length-2;
			pad_len = length & 0x03;
			if(pad_len != 0){
				pad_len = 4 - pad_len;
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_padding, tvb, offset, pad_len, ENC_NA);
			}
			offset = offset + pad_len;
			break;
		case 9: /* STATUS-INFO */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_status_info_text, tvb, offset, length-2, ENC_ASCII);
			offset = offset + length-2;
			pad_len = length & 0x03;
			if(pad_len != 0){
				pad_len = 4 - pad_len;
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_padding, tvb, offset, pad_len, ENC_NA);
			}
			offset = offset + pad_len;
			break;
		case 10: /* SUPPORTED-ATTRIBUTES */

			while(offset < (attr_start_offset+length)){
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_supp_attr, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset+=1;
			}
			pad_len = length & 0x03;
			if(pad_len != 0){
				pad_len = 4 - pad_len;
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_padding, tvb, offset, pad_len, ENC_NA);
			}
			offset = offset + pad_len;
			break;
		case 11: /* SUPPORTED-PRIMITIVES */

			while(offset < (attr_start_offset+length)){
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_supp_prim, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset+=1;
			}
			pad_len = length & 0x03;
			if(pad_len != 0){
				pad_len = 4 - pad_len;
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_padding, tvb, offset, pad_len, ENC_NA);
			}
			offset = offset + pad_len;
			break;
		case 12: /* USER-DISPLAY-NAME */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_user_disp_name, tvb, offset, length-2, ENC_ASCII);
			offset = offset + length-2;
			pad_len = length & 0x03;
			if(pad_len != 0){
				pad_len = 4 - pad_len;
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_padding, tvb, offset, pad_len, ENC_NA);
			}
			offset = offset + pad_len;
			break;
		case 13: /* USER-URI */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_user_uri, tvb, offset, length-2, ENC_ASCII);
			offset = offset + length-2;
			pad_len = length & 0x03;
			if(pad_len != 0){
				pad_len = 4 - pad_len;
				proto_tree_add_item(bfcp_attr_tree, hf_bfcp_padding, tvb, offset, pad_len, ENC_NA);
			}
			offset = offset + pad_len;
			break;
		case 14: /* BENEFICIARY-INFORMATION */
			/*    The BENEFICIARY-INFORMATION attribute is a grouped attribute that
			 *   consists of a header, which is referred to as BENEFICIARY-
			 *   INFORMATION-HEADER, followed by a sequence of attributes.
			 */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_beneficiary_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			offset = dissect_bfcp_attributes(tvb, pinfo, bfcp_attr_tree, offset, length -4);
			break;
		case 15: /* FLOOR-REQUEST-INFORMATION */
			/*    The FLOOR-REQUEST-INFORMATION attribute is a grouped attribute that
			 *   consists of a header, which is referred to as FLOOR-REQUEST-
			 *   INFORMATION-HEADER, followed by a sequence of attributes.
			 */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_floor_request_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			offset = dissect_bfcp_attributes(tvb, pinfo, bfcp_attr_tree, offset, length -4);
			break;
		case 16: /*  REQUESTED-BY-INFORMATION */
			/*    The  REQUESTED-BY-INFORMATION attribute is a grouped attribute that
			 *   consists of a header, which is referred to as FLOOR-REQUEST-STATUS-
			 *   -HEADER, followed by a sequence of attributes.
			 */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_req_by_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			offset = dissect_bfcp_attributes(tvb, pinfo, bfcp_attr_tree, offset, length -4);
			break;
		case 17: /*  FLOOR-REQUEST-STATUS */
			/*    The  FLOOR-REQUEST-STATUS attribute is a grouped attribute that
			 *   consists of a header, which is referred to as OVERALL-REQUEST-STATUS-
			 *   -HEADER, followed by a sequence of attributes.
			 */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_floor_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			offset = dissect_bfcp_attributes(tvb, pinfo, bfcp_attr_tree, offset, length -4);
			break;
		case 18: /* OVERALL-REQUEST-STATUS */
			/*    The OVERALL-REQUEST-STATUS attribute is a grouped attribute that
			 *   consists of a header, which is referred to as FLOOR-REQUEST-
			 *   INFORMATION-HEADER, followed by a sequence of attributes.
			 */
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_floor_request_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			offset = dissect_bfcp_attributes(tvb, pinfo, bfcp_attr_tree, offset, length -4);
			break;

		default:
			proto_tree_add_item(bfcp_attr_tree, hf_bfcp_payload, tvb, offset, length-2, ENC_NA);
			/* Advance by any length attributable to payload */
			offset = offset + length - 2;
			break;
		}
		read_attr = read_attr + length;
	}
	decrement_dissection_depth(pinfo);

	return offset;
}


static bool
dissect_bfcp_heur_check(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
	uint8_t      primitive;
	uint8_t     first_byte;
	const char *str;


	/* Size of smallest BFCP packet: 12 octets */
	if (tvb_captured_length(tvb) < BFCP_HDR_LEN)
		return false;

	/* Check version and reserved bits in first byte */
	first_byte = tvb_get_uint8(tvb, 0);

	/* If first_byte of bfcp_packet is a combination of the
	 * version, the R-bit and the F-bit. The value must be:
	 * 0x20 || 0x30 || 0x40 || 0x48 || 0x50 || 0x58
	 * if the bit is set, otherwise it is not BFCP.
	 */
	if ((first_byte != 0x20) && (first_byte != 0x30) && (first_byte != 0x40) && (first_byte != 0x48) && (first_byte != 0x50) && (first_byte != 0x58))
		return false;

	primitive = tvb_get_uint8(tvb, 1);

	if ((primitive < 1) || (primitive > 18))
		return false;

	str = try_val_to_str(primitive, map_bfcp_primitive);
	if (NULL == str)
		return false;

	return true;
}

/* Code to actually dissect BFCP packets */
static int
dissect_bfcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	int          offset = 0;
	uint8_t      primitive;
	const char *str;
	int          bfcp_payload_length;
	bool         f_bit;
	proto_tree  *bfcp_tree;
	proto_item	*ti;

	if (!dissect_bfcp_heur_check(tvb, pinfo, tree, data))
		return 0;

	primitive = tvb_get_uint8(tvb, 1);
	str = try_val_to_str(primitive, map_bfcp_primitive);

	/* Make entries in Protocol column and Info column on summary display*/
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BFCP");
	col_add_str(pinfo->cinfo, COL_INFO, str);

	ti = proto_tree_add_item(tree, proto_bfcp, tvb, 0, -1, ENC_NA);
	bfcp_tree = proto_item_add_subtree(ti, ett_bfcp);
	show_setup_info(tvb, pinfo, bfcp_tree);
/*
  The following is the format of the common header.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Ver |R|F| Res |  Primitive    |        Payload Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Conference ID                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Transaction ID        |            User ID            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Fragment Offset (if F is set) | Fragment Length (if F is set) |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


*/
	/* Add items to BFCP tree */
	proto_tree_add_item(bfcp_tree, hf_bfcp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(bfcp_tree, hf_bfcp_hdr_r_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item_ret_boolean(bfcp_tree, hf_bfcp_hdr_f_bit, tvb, offset, 1, ENC_BIG_ENDIAN, &f_bit);
	/* Ver should be 1 over a reliable transport (TCP) and 2 over an
	 * unreliable transport (UDP). R and F should only be set on an
	 * unreliable transport. They should be ignored on a reliable
	 * transport.
	 *
	 * XXX: If it's version 1 and an unreliable transport, it may be
	 * a draft implementation.
	 * ( https://www.ietf.org/archive/id/draft-sandbakken-dispatch-bfcp-udp-03.html )
	 */
	offset++;
	proto_tree_add_item(bfcp_tree, hf_bfcp_primitive, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(bfcp_tree, hf_bfcp_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	proto_tree_add_item(bfcp_tree, hf_bfcp_conference_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;
	proto_tree_add_item(bfcp_tree, hf_bfcp_transaction_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	proto_tree_add_item(bfcp_tree, hf_bfcp_user_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	if (f_bit) {
		proto_tree_add_item(bfcp_tree, hf_bfcp_fragment_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
		proto_tree_add_item(bfcp_tree, hf_bfcp_fragment_length, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
	}

	bfcp_payload_length = tvb_get_ntohs(tvb,
						BFCP_OFFSET_PAYLOAD_LENGTH) * 4;

	/*offset = */dissect_bfcp_attributes(tvb, pinfo, bfcp_tree, offset, bfcp_payload_length);

	return tvb_captured_length(tvb);
}

static bool
dissect_bfcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	if (!dissect_bfcp_heur_check(tvb, pinfo, tree, data))
		return false;

	dissect_bfcp(tvb, pinfo, tree, data);
	return true;
}

void proto_register_bfcp(void)
{
	module_t *bfcp_module;
	expert_module_t* expert_bfcp;

	static hf_register_info hf[] = {
		{
			&hf_bfcp_version,
			{ "Version(ver)", "bfcp.ver",
			  FT_UINT8, BASE_DEC, NULL, 0xe0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_hdr_r_bit,
			{ "Transaction Responder (R)", "bfcp.hdr_r_bit",
			  FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_hdr_f_bit,
			{ "Fragmentation (F)", "bfcp.hdr_f_bit",
			  FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_primitive,
			{ "Primitive", "bfcp.primitive",
			  FT_UINT8, BASE_DEC, VALS(map_bfcp_primitive), 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_payload_length,
			{ "Payload Length", "bfcp.payload_length",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  "Length in 4-octet units, excluding the COMMON-HEADER", HFILL }
		},
		{
			&hf_bfcp_conference_id,
			{ "Conference ID", "bfcp.conference_id",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_transaction_id,
			{ "Transaction ID", "bfcp.transaction_id",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_user_id,
			{ "User ID", "bfcp.user_id",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_fragment_offset,
			{ "Fragment Offset", "bfcp.fragment_offset",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  "Number of 4-octet units contained in previous fragments, excluding the COMMON-HEADER", HFILL }
		},
		{
			&hf_bfcp_fragment_length,
			{ "Fragment Length", "bfcp.fragment_length",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  "Number of 4-octet units contained in this fragment, excluding the COMMON-HEADER", HFILL }
		},
		{
			&hf_bfcp_payload,
			{ "Payload", "bfcp.payload",
			  FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
			  HFILL }
		},
		{
			&hf_bfcp_attribute_types,
			{ "Attribute Type", "bfcp.attribute_type",
			  FT_UINT8, BASE_DEC, VALS(map_bfcp_attribute_types), 0xFE,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_attribute_types_m_bit,
			{ "Mandatory bit(M)", "bfcp.attribute_types_m_bit",
			  FT_BOOLEAN, 8, NULL, 0x01,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_attribute_length,
			{ "Attribute Length", "bfcp.attribute_length",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_beneficiary_id,
			{ "BENEFICIARY-ID", "bfcp.beneficiary_id",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_floor_id,
			{ "FLOOR-ID", "bfcp.floor_id",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_floor_request_id,
			{ "FLOOR-REQUEST-ID", "bfcp.floorrequest_id",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_priority,
			{ "FLOOR-REQUEST-ID", "bfcp.priority",
			  FT_UINT16, BASE_DEC, NULL, 0xe000,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_request_status,
			{ "Request Status", "bfcp.request_status",
			  FT_UINT8, BASE_DEC, VALS(map_bfcp_request_status), 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_queue_pos,
			{ "Queue Position", "bfcp.queue_pos",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_error_code,
			{ "Error Code", "bfcp.error_code",
			  FT_UINT8, BASE_DEC, VALS(bfcp_error_code_valuse), 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_error_info_text,
			{ "Text", "bfcp.error_info_text",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_part_prov_info_text,
			{ "Text", "bfcp.part_prov_info_text",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_status_info_text,
			{ "Text", "bfcp.status_info_text",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_supp_attr,
			{ "Supported Attribute", "bfcp.supp_attr",
			  FT_UINT8, BASE_DEC, VALS(map_bfcp_attribute_types), 0xFE,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_supp_prim,
			{ "Supported Primitive", "bfcp.supp_primitive",
			  FT_UINT8, BASE_DEC, VALS(map_bfcp_primitive), 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_user_disp_name,
			{ "Name", "bfcp.user_disp_name",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_user_uri,
			{ "URI", "bfcp.user_uri",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_req_by_id,
			{ "Requested-by ID", "bfcp.req_by_i",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_padding,
			{ "Padding", "bfcp.padding",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{
			&hf_bfcp_error_specific_details,
			{ "Error Specific Details", "bfcp.error_specific_details",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_bfcp_setup,
			{ "Stream setup", "bfcp.setup",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  "Stream setup, method and frame number", HFILL}
		},
		{ &hf_bfcp_setup_frame,
			{ "Setup frame", "bfcp.setup-frame",
			  FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			  "Frame that set up this stream", HFILL}
		},
		{ &hf_bfcp_setup_method,
			{ "Setup Method", "bfcp.setup-method",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  "Method used to set up this stream", HFILL}
		},
	};

	static int *ett[] = {
		&ett_bfcp,
		&ett_bfcp_setup,
		&ett_bfcp_attr,
	};

	static ei_register_info ei[] = {
		{ &ei_bfcp_attribute_length_too_small, { "bfcp.attribute_length.too_small", PI_MALFORMED, PI_ERROR, "Attribute length is too small", EXPFILL }},
	};

	/* Register protocol name and description */
	proto_bfcp = proto_register_protocol("Binary Floor Control Protocol", "BFCP", "bfcp");

	bfcp_handle = register_dissector("bfcp", dissect_bfcp, proto_bfcp);

	bfcp_module = prefs_register_protocol(proto_bfcp, NULL);

	prefs_register_obsolete_preference(bfcp_module, "enable");

	/* Register field and subtree array */
	proto_register_field_array(proto_bfcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_bfcp = expert_register_protocol(proto_bfcp);
	expert_register_field_array(expert_bfcp, ei, array_length(ei));
}

void proto_reg_handoff_bfcp(void)
{
	/* "Decode As" is always available;
	 *  Heuristic dissection in disabled by default since
	 *  the heuristic is quite weak.
	 */
	heur_dissector_add("tcp", dissect_bfcp_heur, "BFCP over TCP", "bfcp_tcp", proto_bfcp, HEURISTIC_DISABLE);
	heur_dissector_add("udp", dissect_bfcp_heur, "BFCP over UDP", "bfcp_udp", proto_bfcp, HEURISTIC_DISABLE);
	dissector_add_for_decode_as_with_preference("tcp.port", bfcp_handle);
	dissector_add_for_decode_as_with_preference("udp.port", bfcp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */

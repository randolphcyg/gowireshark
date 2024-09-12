/* packet-nbd.c
 * Routines for Network Block Device (NBD) dissection.
 *
 * Ronnie sahlberg 2006
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
#include "packet-tcp.h"

void proto_register_nbd(void);
void proto_reg_handoff_nbd(void);

static int proto_nbd;
static int hf_nbd_magic;
static int hf_nbd_type;
static int hf_nbd_error;
static int hf_nbd_handle;
static int hf_nbd_from;
static int hf_nbd_len;
static int hf_nbd_response_in;
static int hf_nbd_response_to;
static int hf_nbd_time;
static int hf_nbd_data;

static int ett_nbd;


static bool nbd_desegment = true;

typedef struct _nbd_transaction_t {
	uint32_t req_frame;
	uint32_t rep_frame;
	nstime_t req_time;
	uint32_t datalen;
	uint8_t type;
} nbd_transaction_t;
typedef struct _nbd_conv_info_t {
	wmem_tree_t *unacked_pdus;    /* indexed by handle, which wraps quite frequently  */
	wmem_tree_t *acked_pdus;    /* indexed by packet# and handle */
} nbd_conv_info_t;


#define NBD_REQUEST_MAGIC		0x25609513
#define NBD_RESPONSE_MAGIC		0x67446698

#define NBD_CMD_READ			0
#define NBD_CMD_WRITE			1
#define NBD_CMD_DISC			2
static const value_string nbd_type_vals[] = {
	{NBD_CMD_READ,	"NBD_CMD_READ"},
	{NBD_CMD_WRITE,	"NBD_CMD_WRITE"},
	{NBD_CMD_DISC,	"NBD_CMD_DISC"},
	{0, NULL}
};


/* This function will try to determine the complete size of a PDU
 * based on the information in the header.
 */
static unsigned
get_nbd_tcp_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_)
{
	uint32_t magic, type, packet;
	conversation_t *conversation;
	nbd_conv_info_t *nbd_info;
	nbd_transaction_t *nbd_trans=NULL;
	wmem_tree_key_t hkey[3];
	uint32_t handle[2];

	magic=tvb_get_ntohl(tvb, offset);

	switch(magic){
	case NBD_REQUEST_MAGIC:
		type=tvb_get_ntohl(tvb, offset+4);
		switch(type){
		case NBD_CMD_WRITE:
			return tvb_get_ntohl(tvb, offset+24)+28;
		default:
			return 28;
		}
	case NBD_RESPONSE_MAGIC:
		/*
		 * Do we have a conversation for this connection?
		 */
		conversation = find_conversation_pinfo(pinfo, 0);
		if (conversation == NULL) {
			/* No, so just return the rest of the current packet */
			return tvb_captured_length(tvb);
		}
		/*
		 * Do we have a state structure for this conv
		 */
		nbd_info = (nbd_conv_info_t *)conversation_get_proto_data(conversation, proto_nbd);
		if (!nbd_info) {
			/* No, so just return the rest of the current packet */
			return tvb_captured_length(tvb);
		}
		if(!pinfo->fd->visited){
			/*
			 * Do we have a state structure for this transaction
			 */
			handle[0]=tvb_get_ntohl(tvb, offset+8);
			handle[1]=tvb_get_ntohl(tvb, offset+12);
			hkey[0].length=2;
			hkey[0].key=handle;
			hkey[1].length=0;
			nbd_trans=(nbd_transaction_t *)wmem_tree_lookup32_array(nbd_info->unacked_pdus, hkey);
			if(!nbd_trans){
				/* No, so just return the rest of the current packet */
				return tvb_captured_length(tvb);
			}
		} else {
			/*
			 * Do we have a state structure for this transaction
			 */
			handle[0]=tvb_get_ntohl(tvb, offset+8);
			handle[1]=tvb_get_ntohl(tvb, offset+12);
			packet=pinfo->num;
			hkey[0].length=1;
			hkey[0].key=&packet;
			hkey[1].length=2;
			hkey[1].key=handle;
			hkey[2].length=0;
			nbd_trans=(nbd_transaction_t *)wmem_tree_lookup32_array(nbd_info->acked_pdus, hkey);
			if(!nbd_trans){
				/* No, so just return the rest of the current packet */
				return tvb_captured_length(tvb);
			}
		}
		/* If this is a read response we must add the datalen to
		 * the pdu size
		 */
		if(nbd_trans->type==NBD_CMD_READ){
			return 16+nbd_trans->datalen;
		} else {
			return 16;
		}
	default:
		break;
	}

	/* Did not really look like a NBD packet after all */
	return 0;
}

static int
dissect_nbd_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	uint32_t magic, error, packet;
	uint32_t handle[2];
	uint64_t from;
	int offset=0;
	proto_tree *tree=NULL;
	proto_item *item=NULL;
	conversation_t *conversation;
	nbd_conv_info_t *nbd_info;
	nbd_transaction_t *nbd_trans=NULL;
	wmem_tree_key_t hkey[3];

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NBD");

	col_clear(pinfo->cinfo, COL_INFO);

	item = proto_tree_add_item(parent_tree, proto_nbd, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_nbd);


	magic=tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_nbd_magic, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;


	/* grab what we need to do the request/response matching */
	switch(magic){
	case NBD_REQUEST_MAGIC:
	case NBD_RESPONSE_MAGIC:
		handle[0]=tvb_get_ntohl(tvb, offset+4);
		handle[1]=tvb_get_ntohl(tvb, offset+8);
		break;
	default:
		return 4;
	}

	conversation = find_or_create_conversation(pinfo);

	/*
	 * Do we already have a state structure for this conv
	 */
	nbd_info = (nbd_conv_info_t *)conversation_get_proto_data(conversation, proto_nbd);
	if (!nbd_info) {
		/* No.  Attach that information to the conversation, and add
		 * it to the list of information structures.
		 */
		nbd_info = wmem_new(wmem_file_scope(), nbd_conv_info_t);
		nbd_info->unacked_pdus = wmem_tree_new(wmem_file_scope());
		nbd_info->acked_pdus   = wmem_tree_new(wmem_file_scope());

		conversation_add_proto_data(conversation, proto_nbd, nbd_info);
	}
	if(!pinfo->fd->visited){
		if(magic==NBD_REQUEST_MAGIC){
			/* This is a request */
			nbd_trans=wmem_new(wmem_file_scope(), nbd_transaction_t);
			nbd_trans->req_frame=pinfo->num;
			nbd_trans->rep_frame=0;
			nbd_trans->req_time=pinfo->abs_ts;
			nbd_trans->type=tvb_get_ntohl(tvb, offset);
			nbd_trans->datalen=tvb_get_ntohl(tvb, offset+20);

			hkey[0].length=2;
			hkey[0].key=handle;
			hkey[1].length=0;

			wmem_tree_insert32_array(nbd_info->unacked_pdus, hkey, (void *)nbd_trans);
		} else if(magic==NBD_RESPONSE_MAGIC){
			hkey[0].length=2;
			hkey[0].key=handle;
			hkey[1].length=0;

			nbd_trans=(nbd_transaction_t *)wmem_tree_lookup32_array(nbd_info->unacked_pdus, hkey);
			if(nbd_trans){
				nbd_trans->rep_frame=pinfo->num;

				hkey[0].length=1;
				hkey[0].key=&nbd_trans->rep_frame;
				hkey[1].length=2;
				hkey[1].key=handle;
				hkey[2].length=0;
				wmem_tree_insert32_array(nbd_info->acked_pdus, hkey, (void *)nbd_trans);
				hkey[0].length=1;
				hkey[0].key=&nbd_trans->req_frame;
				hkey[1].length=2;
				hkey[1].key=handle;
				hkey[2].length=0;
				wmem_tree_insert32_array(nbd_info->acked_pdus, hkey, (void *)nbd_trans);
			}
		}
	} else {
		packet=pinfo->num;
		hkey[0].length=1;
		hkey[0].key=&packet;
		hkey[1].length=2;
		hkey[1].key=handle;
		hkey[2].length=0;

		nbd_trans=(nbd_transaction_t *)wmem_tree_lookup32_array(nbd_info->acked_pdus, hkey);
	}
	/* The bloody handles are reused !!! even though they are 64 bits.
	 * So we must verify we got the "correct" one
	 */
	if( (magic==NBD_RESPONSE_MAGIC)
	&&  (nbd_trans)
	&&  (pinfo->num<nbd_trans->req_frame) ){
		/* must have been the wrong one */
		nbd_trans=NULL;
	}

	if(!nbd_trans){
		/* create a "fake" nbd_trans structure */
		nbd_trans=wmem_new(pinfo->pool, nbd_transaction_t);
		nbd_trans->req_frame=0;
		nbd_trans->rep_frame=0;
		nbd_trans->req_time=pinfo->abs_ts;
		nbd_trans->type=0xff;
		nbd_trans->datalen=0;
	}

	/* print state tracking in the tree */
	if(magic==NBD_REQUEST_MAGIC){
		/* This is a request */
		if(nbd_trans->rep_frame){
			proto_item *it;

			it=proto_tree_add_uint(tree, hf_nbd_response_in, tvb, 0, 0, nbd_trans->rep_frame);
			proto_item_set_generated(it);
		}
	} else if(magic==NBD_RESPONSE_MAGIC){
		/* This is a reply */
		if(nbd_trans->req_frame){
			proto_item *it;
			nstime_t ns;

			it=proto_tree_add_uint(tree, hf_nbd_response_to, tvb, 0, 0, nbd_trans->req_frame);
			proto_item_set_generated(it);

			nstime_delta(&ns, &pinfo->abs_ts, &nbd_trans->req_time);
			it=proto_tree_add_time(tree, hf_nbd_time, tvb, 0, 0, &ns);
			proto_item_set_generated(it);
		}
	}


	switch(magic){
	case NBD_REQUEST_MAGIC:
		proto_tree_add_item(tree, hf_nbd_type, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+=4;

		proto_tree_add_item(tree, hf_nbd_handle, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset+=8;

		from=tvb_get_ntoh64(tvb, offset);
		proto_tree_add_item(tree, hf_nbd_from, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset+=8;

		proto_tree_add_item(tree, hf_nbd_len, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+=4;

		switch(nbd_trans->type){
		case NBD_CMD_WRITE:
			col_add_fstr(pinfo->cinfo, COL_INFO, "Write Request  Offset:0x%" PRIx64 " Length:%d", from, nbd_trans->datalen);
			break;
		case NBD_CMD_READ:
			col_add_fstr(pinfo->cinfo, COL_INFO, "Read Request  Offset:0x%" PRIx64 " Length:%d", from, nbd_trans->datalen);
			break;
		case NBD_CMD_DISC:
			col_set_str(pinfo->cinfo, COL_INFO, "Disconnect Request");
			break;
		}

		if(nbd_trans->type==NBD_CMD_WRITE){
			proto_tree_add_item(tree, hf_nbd_data, tvb, offset, nbd_trans->datalen, ENC_NA);
		}
		break;
	case NBD_RESPONSE_MAGIC:
		item=proto_tree_add_uint(tree, hf_nbd_type, tvb, 0, 0, nbd_trans->type);
		proto_item_set_generated(item);

		error=tvb_get_ntohl(tvb, offset);
		proto_tree_add_item(tree, hf_nbd_error, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+=4;

		proto_tree_add_item(tree, hf_nbd_handle, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset+=8;

		col_add_fstr(pinfo->cinfo, COL_INFO, "%s Response  Error:%d", (nbd_trans->type==NBD_CMD_WRITE)?"Write":"Read", error);

		if(nbd_trans->type==NBD_CMD_READ){
			proto_tree_add_item(tree, hf_nbd_data, tvb, offset, nbd_trans->datalen, ENC_NA);
		}
		break;
	}

	return tvb_captured_length(tvb);
}

static bool
dissect_nbd_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	uint32_t magic, type;

	/* We need at least this much to tell whether this is NBD or not */
	if(tvb_captured_length(tvb)<4){
		return false;
	}

	/* Check if it looks like NBD */
	magic=tvb_get_ntohl(tvb, 0);
	switch(magic){
	case NBD_REQUEST_MAGIC:
		/* requests are 28 bytes or more */
		if(tvb_captured_length(tvb)<28){
			return false;
		}
		/* verify type */
		type=tvb_get_ntohl(tvb, 4);
		switch(type){
		case NBD_CMD_READ:
		case NBD_CMD_WRITE:
		case NBD_CMD_DISC:
			break;
		default:
			return false;
		}

		tcp_dissect_pdus(tvb, pinfo, tree, nbd_desegment, 28, get_nbd_tcp_pdu_len, dissect_nbd_tcp_pdu, data);
		return true;
	case NBD_RESPONSE_MAGIC:
		/* responses are 16 bytes or more */
		if(tvb_captured_length(tvb)<16){
			return false;
		}
		tcp_dissect_pdus(tvb, pinfo, tree, nbd_desegment, 16, get_nbd_tcp_pdu_len, dissect_nbd_tcp_pdu, data);
		return true;
	default:
		break;
	}

	return false;
}

void proto_register_nbd(void)
{
	static hf_register_info hf[] = {
		{ &hf_nbd_magic,
		  { "Magic", "nbd.magic", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_type,
		  { "Type", "nbd.type", FT_UINT32, BASE_DEC,
		    VALS(nbd_type_vals), 0x0, NULL, HFILL }},
		{ &hf_nbd_error,
		  { "Error", "nbd.error", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_len,
		  { "Length", "nbd.len", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_handle,
		  { "Handle", "nbd.handle", FT_UINT64, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_from,
		  { "From", "nbd.from", FT_UINT64, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nbd_response_in,
		  { "Response In", "nbd.response_in", FT_FRAMENUM, BASE_NONE,
		    NULL, 0x0, "The response to this NBD request is in this frame", HFILL }},
		{ &hf_nbd_response_to,
		  { "Request In", "nbd.response_to", FT_FRAMENUM, BASE_NONE,
		    NULL, 0x0, "This is a response to the NBD request in this frame", HFILL }},
		{ &hf_nbd_time,
		  { "Time", "nbd.time", FT_RELATIVE_TIME, BASE_NONE,
		    NULL, 0x0, "The time between the Call and the Reply", HFILL }},

		{ &hf_nbd_data,
		  { "Data", "nbd.data", FT_BYTES, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},

	};


	static int *ett[] = {
		&ett_nbd,
	};

	module_t *nbd_module;

	proto_nbd = proto_register_protocol("Network Block Device",
	                                    "NBD", "nbd");
	proto_register_field_array(proto_nbd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	nbd_module = prefs_register_protocol(proto_nbd, NULL);
	prefs_register_bool_preference(nbd_module, "desegment_nbd_messages",
				       "Reassemble NBD messages spanning multiple TCP segments",
				       "Whether the NBD dissector should reassemble messages spanning multiple TCP segments."
				       " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings",
				       &nbd_desegment);

}

void
proto_reg_handoff_nbd(void)
{
	heur_dissector_add("tcp", dissect_nbd_tcp_heur, "NBD over TCP", "nbd_tcp", proto_nbd, HEURISTIC_ENABLE);
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

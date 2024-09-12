/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-pres.c                                                              */
/* asn2wrs.py -b -q -L -p pres -c ./pres.cnf -s ./packet-pres-template -D . -O ../.. ISO8823-PRESENTATION.asn ISO9576-PRESENTATION.asn */

/* packet-pres.c
 * Routine to dissect ISO 8823 OSI Presentation Protocol packets
 * Based on the dissector by
 * Yuriy Sidelnikov <YSidelnikov@hotmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <wsutil/array.h>

#include <epan/asn1.h>
#include <epan/oids.h>
#include "packet-ber.h"
#include "packet-ses.h"
#include "packet-pres.h"
#include "packet-rtse.h"


#define PNAME  "ISO 8823 OSI Presentation Protocol"
#define PSNAME "PRES"
#define PFNAME "pres"

#define CLPNAME  "ISO 9576-1 OSI Connectionless Presentation Protocol"
#define CLPSNAME "CLPRES"
#define CLPFNAME "clpres"

void proto_register_pres(void);
void proto_reg_handoff_pres(void);

/* Initialize the protocol and registered fields */
static int proto_pres;

/* Initialize the connectionless protocol */
static int proto_clpres;

/*      pointers for acse dissector  */
proto_tree *global_tree;
packet_info *global_pinfo;

static const char *abstract_syntax_name_oid;
static uint32_t presentation_context_identifier;

/* to keep track of presentation context identifiers and protocol-oids */
typedef struct _pres_ctx_oid_t {
	uint32_t ctx_id;
	char *oid;
	uint32_t idx;
} pres_ctx_oid_t;
static wmem_map_t *pres_ctx_oid_table;

typedef struct _pres_user_t {
   unsigned ctx_id;
   char *oid;
} pres_user_t;

static pres_user_t *pres_users;
static unsigned num_pres_users;

static int hf_pres_CP_type;
static int hf_pres_CPA_PPDU;
static int hf_pres_Abort_type;
static int hf_pres_CPR_PPDU;
static int hf_pres_Typed_data_type;

static int hf_pres_UD_type_PDU;                   /* UD_type */
static int hf_pres_mode_selector;                 /* Mode_selector */
static int hf_pres_x410_mode_parameters;          /* RTORQapdu */
static int hf_pres_normal_mode_parameters;        /* T_normal_mode_parameters */
static int hf_pres_protocol_version;              /* Protocol_version */
static int hf_pres_calling_presentation_selector;  /* Calling_presentation_selector */
static int hf_pres_called_presentation_selector;  /* Called_presentation_selector */
static int hf_pres_presentation_context_definition_list;  /* Presentation_context_definition_list */
static int hf_pres_default_context_name;          /* Default_context_name */
static int hf_pres_presentation_requirements;     /* Presentation_requirements */
static int hf_pres_user_session_requirements;     /* User_session_requirements */
static int hf_pres_protocol_options;              /* Protocol_options */
static int hf_pres_initiators_nominated_context;  /* Presentation_context_identifier */
static int hf_pres_extensions;                    /* T_extensions */
static int hf_pres_user_data;                     /* User_data */
static int hf_pres_cPR_PPDU_x400_mode_parameters;  /* RTOACapdu */
static int hf_pres_cPU_PPDU_normal_mode_parameters;  /* T_CPA_PPDU_normal_mode_parameters */
static int hf_pres_responding_presentation_selector;  /* Responding_presentation_selector */
static int hf_pres_presentation_context_definition_result_list;  /* Presentation_context_definition_result_list */
static int hf_pres_responders_nominated_context;  /* Presentation_context_identifier */
static int hf_pres_cPU_PPDU_x400_mode_parameters;  /* RTORJapdu */
static int hf_pres_cPR_PPDU_normal_mode_parameters;  /* T_CPR_PPDU_normal_mode_parameters */
static int hf_pres_default_context_result;        /* Default_context_result */
static int hf_pres_cPR_PPDU__provider_reason;     /* Provider_reason */
static int hf_pres_aru_ppdu;                      /* ARU_PPDU */
static int hf_pres_arp_ppdu;                      /* ARP_PPDU */
static int hf_pres_aRU_PPDU_x400_mode_parameters;  /* RTABapdu */
static int hf_pres_aRU_PPDU_normal_mode_parameters;  /* T_ARU_PPDU_normal_mode_parameters */
static int hf_pres_presentation_context_identifier_list;  /* Presentation_context_identifier_list */
static int hf_pres_aRU_PPDU_provider_reason;      /* Abort_reason */
static int hf_pres_event_identifier;              /* Event_identifier */
static int hf_pres_acPPDU;                        /* AC_PPDU */
static int hf_pres_acaPPDU;                       /* ACA_PPDU */
static int hf_pres_ttdPPDU;                       /* User_data */
static int hf_pres_presentation_context_addition_list;  /* Presentation_context_addition_list */
static int hf_pres_presentation_context_deletion_list;  /* Presentation_context_deletion_list */
static int hf_pres_presentation_context_addition_result_list;  /* Presentation_context_addition_result_list */
static int hf_pres_presentation_context_deletion_result_list;  /* Presentation_context_deletion_result_list */
static int hf_pres_Context_list_item;             /* Context_list_item */
static int hf_pres_presentation_context_identifier;  /* Presentation_context_identifier */
static int hf_pres_abstract_syntax_name;          /* Abstract_syntax_name */
static int hf_pres_transfer_syntax_name_list;     /* SEQUENCE_OF_Transfer_syntax_name */
static int hf_pres_transfer_syntax_name_list_item;  /* Transfer_syntax_name */
static int hf_pres_transfer_syntax_name;          /* Transfer_syntax_name */
static int hf_pres_mode_value;                    /* T_mode_value */
static int hf_pres_Presentation_context_deletion_list_item;  /* Presentation_context_identifier */
static int hf_pres_Presentation_context_deletion_result_list_item;  /* Presentation_context_deletion_result_list_item */
static int hf_pres_Presentation_context_identifier_list_item;  /* Presentation_context_identifier_list_item */
static int hf_pres_Result_list_item;              /* Result_list_item */
static int hf_pres_result;                        /* Result */
static int hf_pres_provider_reason;               /* T_provider_reason */
static int hf_pres_simply_encoded_data;           /* Simply_encoded_data */
static int hf_pres_fully_encoded_data;            /* Fully_encoded_data */
static int hf_pres_Fully_encoded_data_item;       /* PDV_list */
static int hf_pres_presentation_data_values;      /* T_presentation_data_values */
static int hf_pres_single_ASN1_type;              /* T_single_ASN1_type */
static int hf_pres_octet_aligned;                 /* T_octet_aligned */
static int hf_pres_arbitrary;                     /* BIT_STRING */
/* named bits */
static int hf_pres_Presentation_requirements_context_management;
static int hf_pres_Presentation_requirements_restoration;
static int hf_pres_Protocol_options_nominated_context;
static int hf_pres_Protocol_options_short_encoding;
static int hf_pres_Protocol_options_packed_encoding_rules;
static int hf_pres_Protocol_version_version_1;
static int hf_pres_User_session_requirements_half_duplex;
static int hf_pres_User_session_requirements_duplex;
static int hf_pres_User_session_requirements_expedited_data;
static int hf_pres_User_session_requirements_minor_synchronize;
static int hf_pres_User_session_requirements_major_synchronize;
static int hf_pres_User_session_requirements_resynchronize;
static int hf_pres_User_session_requirements_activity_management;
static int hf_pres_User_session_requirements_negotiated_release;
static int hf_pres_User_session_requirements_capability_data;
static int hf_pres_User_session_requirements_exceptions;
static int hf_pres_User_session_requirements_typed_data;
static int hf_pres_User_session_requirements_symmetric_synchronize;
static int hf_pres_User_session_requirements_data_separation;

/* Initialize the subtree pointers */
static int ett_pres;

static int ett_pres_CP_type;
static int ett_pres_T_normal_mode_parameters;
static int ett_pres_T_extensions;
static int ett_pres_CPA_PPDU;
static int ett_pres_T_CPA_PPDU_normal_mode_parameters;
static int ett_pres_CPR_PPDU;
static int ett_pres_T_CPR_PPDU_normal_mode_parameters;
static int ett_pres_Abort_type;
static int ett_pres_ARU_PPDU;
static int ett_pres_T_ARU_PPDU_normal_mode_parameters;
static int ett_pres_ARP_PPDU;
static int ett_pres_Typed_data_type;
static int ett_pres_AC_PPDU;
static int ett_pres_ACA_PPDU;
static int ett_pres_RS_PPDU;
static int ett_pres_RSA_PPDU;
static int ett_pres_Context_list;
static int ett_pres_Context_list_item;
static int ett_pres_SEQUENCE_OF_Transfer_syntax_name;
static int ett_pres_Default_context_name;
static int ett_pres_Mode_selector;
static int ett_pres_Presentation_context_deletion_list;
static int ett_pres_Presentation_context_deletion_result_list;
static int ett_pres_Presentation_context_identifier_list;
static int ett_pres_Presentation_context_identifier_list_item;
static int ett_pres_Presentation_requirements;
static int ett_pres_Protocol_options;
static int ett_pres_Protocol_version;
static int ett_pres_Result_list;
static int ett_pres_Result_list_item;
static int ett_pres_User_data;
static int ett_pres_Fully_encoded_data;
static int ett_pres_PDV_list;
static int ett_pres_T_presentation_data_values;
static int ett_pres_User_session_requirements;
static int ett_pres_UD_type;

static expert_field ei_pres_dissector_not_available;
static expert_field ei_pres_wrong_spdu_type;
static expert_field ei_pres_invalid_offset;

UAT_DEC_CB_DEF(pres_users, ctx_id, pres_user_t)
UAT_CSTRING_CB_DEF(pres_users, oid, pres_user_t)

static unsigned
pres_ctx_oid_hash(const void *k)
{
	const pres_ctx_oid_t *pco=(const pres_ctx_oid_t *)k;
	return pco->ctx_id;
}

static int
pres_ctx_oid_equal(const void *k1, const void *k2)
{
	const pres_ctx_oid_t *pco1=(const pres_ctx_oid_t *)k1;
	const pres_ctx_oid_t *pco2=(const pres_ctx_oid_t *)k2;
	return (pco1->ctx_id==pco2->ctx_id && pco1->idx==pco2->idx);
}

static void
register_ctx_id_and_oid(packet_info *pinfo _U_, uint32_t idx, const char *oid)
{
	pres_ctx_oid_t *pco, *tmppco;
	conversation_t *conversation;

	if (!oid) {
		/* we did not get any oid name, malformed packet? */
		return;
	}

	pco=wmem_new(wmem_file_scope(), pres_ctx_oid_t);
	pco->ctx_id=idx;
	pco->oid=wmem_strdup(wmem_file_scope(), oid);
	conversation=find_conversation_pinfo(pinfo, 0);
	if (conversation) {
		pco->idx = conversation->conv_index;
	} else {
		pco->idx = 0;
	}

	/* if this ctx already exists, remove the old one first */
	tmppco=(pres_ctx_oid_t *)wmem_map_lookup(pres_ctx_oid_table, pco);
	if (tmppco) {
		wmem_map_remove(pres_ctx_oid_table, tmppco);
	}
	wmem_map_insert(pres_ctx_oid_table, pco, pco);
}

static char *
find_oid_in_users_table(packet_info *pinfo, uint32_t ctx_id)
{
	unsigned i;

	for (i = 0; i < num_pres_users; i++) {
		pres_user_t *u = &(pres_users[i]);

		if (u->ctx_id == ctx_id) {
			/* Register oid so other dissectors can find this connection */
			register_ctx_id_and_oid(pinfo, u->ctx_id, u->oid);
			return u->oid;
		}
	}

	return NULL;
}

char *
find_oid_by_pres_ctx_id(packet_info *pinfo, uint32_t idx)
{
	pres_ctx_oid_t pco, *tmppco;
	conversation_t *conversation;

	pco.ctx_id=idx;
	conversation=find_conversation_pinfo(pinfo, 0);
	if (conversation) {
		pco.idx = conversation->conv_index;
	} else {
		pco.idx = 0;
	}

	tmppco=(pres_ctx_oid_t *)wmem_map_lookup(pres_ctx_oid_table, &pco);
	if (tmppco) {
		return tmppco->oid;
	}

	return find_oid_in_users_table(pinfo, idx);
}

static void *
pres_copy_cb(void *dest, const void *orig, size_t len _U_)
{
	pres_user_t *u = (pres_user_t *)dest;
	const pres_user_t *o = (const pres_user_t *)orig;

	u->ctx_id = o->ctx_id;
	u->oid = g_strdup(o->oid);

	return dest;
}

static void
pres_free_cb(void *r)
{
	pres_user_t *u = (pres_user_t *)r;

	g_free(u->oid);
}



static const value_string pres_T_mode_value_vals[] = {
  {   0, "x410-1984-mode" },
  {   1, "normal-mode" },
  { 0, NULL }
};


static int
dissect_pres_T_mode_value(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t Mode_selector_set[] = {
  { &hf_pres_mode_value     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_pres_T_mode_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_Mode_selector(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              Mode_selector_set, hf_index, ett_pres_Mode_selector);

  return offset;
}


static int * const Protocol_version_bits[] = {
  &hf_pres_Protocol_version_version_1,
  NULL
};

static int
dissect_pres_Protocol_version(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Protocol_version_bits, 1, hf_index, ett_pres_Protocol_version,
                                    NULL);

  return offset;
}



static int
dissect_pres_Presentation_selector(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_pres_Calling_presentation_selector(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pres_Presentation_selector(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_pres_Called_presentation_selector(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pres_Presentation_selector(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_pres_Presentation_context_identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  const char *name;
  char *oid;
  struct SESSION_DATA_STRUCTURE* session = (struct SESSION_DATA_STRUCTURE*)actx->private_data;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &presentation_context_identifier);


  if(session)
	session->pres_ctx_id = presentation_context_identifier;

  oid = find_oid_by_pres_ctx_id(actx->pinfo, presentation_context_identifier);

  if(oid && (name = oid_resolved_from_string(actx->pinfo->pool, oid))) {
	proto_item_append_text(actx->created_item, " (%s)", name);
  }


  return offset;
}



static int
dissect_pres_Abstract_syntax_name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &abstract_syntax_name_oid);

  return offset;
}



static int
dissect_pres_Transfer_syntax_name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Transfer_syntax_name_sequence_of[1] = {
  { &hf_pres_transfer_syntax_name_list_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pres_Transfer_syntax_name },
};

static int
dissect_pres_SEQUENCE_OF_Transfer_syntax_name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Transfer_syntax_name_sequence_of, hf_index, ett_pres_SEQUENCE_OF_Transfer_syntax_name);

  return offset;
}


static const ber_sequence_t Context_list_item_sequence[] = {
  { &hf_pres_presentation_context_identifier, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pres_Presentation_context_identifier },
  { &hf_pres_abstract_syntax_name, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pres_Abstract_syntax_name },
  { &hf_pres_transfer_syntax_name_list, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pres_SEQUENCE_OF_Transfer_syntax_name },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_Context_list_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	abstract_syntax_name_oid=NULL;
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Context_list_item_sequence, hf_index, ett_pres_Context_list_item);

	register_ctx_id_and_oid(actx->pinfo, presentation_context_identifier, abstract_syntax_name_oid);
  return offset;
}


static const ber_sequence_t Context_list_sequence_of[1] = {
  { &hf_pres_Context_list_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pres_Context_list_item },
};

static int
dissect_pres_Context_list(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Context_list_sequence_of, hf_index, ett_pres_Context_list);

  return offset;
}



static int
dissect_pres_Presentation_context_definition_list(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pres_Context_list(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t Default_context_name_sequence[] = {
  { &hf_pres_abstract_syntax_name, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_pres_Abstract_syntax_name },
  { &hf_pres_transfer_syntax_name, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_pres_Transfer_syntax_name },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_Default_context_name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Default_context_name_sequence, hf_index, ett_pres_Default_context_name);

  return offset;
}


static int * const Presentation_requirements_bits[] = {
  &hf_pres_Presentation_requirements_context_management,
  &hf_pres_Presentation_requirements_restoration,
  NULL
};

static int
dissect_pres_Presentation_requirements(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Presentation_requirements_bits, 2, hf_index, ett_pres_Presentation_requirements,
                                    NULL);

  return offset;
}


static int * const User_session_requirements_bits[] = {
  &hf_pres_User_session_requirements_half_duplex,
  &hf_pres_User_session_requirements_duplex,
  &hf_pres_User_session_requirements_expedited_data,
  &hf_pres_User_session_requirements_minor_synchronize,
  &hf_pres_User_session_requirements_major_synchronize,
  &hf_pres_User_session_requirements_resynchronize,
  &hf_pres_User_session_requirements_activity_management,
  &hf_pres_User_session_requirements_negotiated_release,
  &hf_pres_User_session_requirements_capability_data,
  &hf_pres_User_session_requirements_exceptions,
  &hf_pres_User_session_requirements_typed_data,
  &hf_pres_User_session_requirements_symmetric_synchronize,
  &hf_pres_User_session_requirements_data_separation,
  NULL
};

static int
dissect_pres_User_session_requirements(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    User_session_requirements_bits, 13, hf_index, ett_pres_User_session_requirements,
                                    NULL);

  return offset;
}


static int * const Protocol_options_bits[] = {
  &hf_pres_Protocol_options_nominated_context,
  &hf_pres_Protocol_options_short_encoding,
  &hf_pres_Protocol_options_packed_encoding_rules,
  NULL
};

static int
dissect_pres_Protocol_options(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Protocol_options_bits, 3, hf_index, ett_pres_Protocol_options,
                                    NULL);

  return offset;
}


static const ber_sequence_t T_extensions_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_T_extensions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_extensions_sequence, hf_index, ett_pres_T_extensions);

  return offset;
}



static int
dissect_pres_Simply_encoded_data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_pres_T_single_ASN1_type(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

 tvbuff_t	*next_tvb;
 char *oid;

	oid=find_oid_by_pres_ctx_id(actx->pinfo, presentation_context_identifier);
	if(oid){
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		call_ber_oid_callback(oid, next_tvb, offset, actx->pinfo, global_tree, actx->private_data);
	} else {
		proto_tree_add_expert(tree, actx->pinfo, &ei_pres_dissector_not_available,
								tvb, offset, -1);
	}


  return offset;
}



static int
dissect_pres_T_octet_aligned(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

 tvbuff_t	*next_tvb;
 char *oid;

	oid=find_oid_by_pres_ctx_id(actx->pinfo, presentation_context_identifier);
	if(oid){
		dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &next_tvb);
		call_ber_oid_callback(oid, next_tvb, offset, actx->pinfo, global_tree, actx->private_data);
	} else {
		proto_tree_add_expert(tree, actx->pinfo, &ei_pres_dissector_not_available,
								tvb, offset, -1);
		  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

	}



  return offset;
}



static int
dissect_pres_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const value_string pres_T_presentation_data_values_vals[] = {
  {   0, "single-ASN1-type" },
  {   1, "octet-aligned" },
  {   2, "arbitrary" },
  { 0, NULL }
};

static const ber_choice_t T_presentation_data_values_choice[] = {
  {   0, &hf_pres_single_ASN1_type, BER_CLASS_CON, 0, 0, dissect_pres_T_single_ASN1_type },
  {   1, &hf_pres_octet_aligned  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_pres_T_octet_aligned },
  {   2, &hf_pres_arbitrary      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_pres_BIT_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_T_presentation_data_values(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_presentation_data_values_choice, hf_index, ett_pres_T_presentation_data_values,
                                 NULL);

  return offset;
}


static const ber_sequence_t PDV_list_sequence[] = {
  { &hf_pres_transfer_syntax_name, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pres_Transfer_syntax_name },
  { &hf_pres_presentation_context_identifier, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pres_Presentation_context_identifier },
  { &hf_pres_presentation_data_values, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pres_T_presentation_data_values },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_PDV_list(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PDV_list_sequence, hf_index, ett_pres_PDV_list);

  return offset;
}


static const ber_sequence_t Fully_encoded_data_sequence_of[1] = {
  { &hf_pres_Fully_encoded_data_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pres_PDV_list },
};

static int
dissect_pres_Fully_encoded_data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Fully_encoded_data_sequence_of, hf_index, ett_pres_Fully_encoded_data);

  return offset;
}


static const value_string pres_User_data_vals[] = {
  {   0, "simply-encoded-data" },
  {   1, "fully-encoded-data" },
  { 0, NULL }
};

static const ber_choice_t User_data_choice[] = {
  {   0, &hf_pres_simply_encoded_data, BER_CLASS_APP, 0, BER_FLAGS_IMPLTAG, dissect_pres_Simply_encoded_data },
  {   1, &hf_pres_fully_encoded_data, BER_CLASS_APP, 1, BER_FLAGS_IMPLTAG, dissect_pres_Fully_encoded_data },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_User_data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 User_data_choice, hf_index, ett_pres_User_data,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_normal_mode_parameters_sequence[] = {
  { &hf_pres_protocol_version, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Protocol_version },
  { &hf_pres_calling_presentation_selector, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Calling_presentation_selector },
  { &hf_pres_called_presentation_selector, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Called_presentation_selector },
  { &hf_pres_presentation_context_definition_list, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Presentation_context_definition_list },
  { &hf_pres_default_context_name, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Default_context_name },
  { &hf_pres_presentation_requirements, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Presentation_requirements },
  { &hf_pres_user_session_requirements, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_User_session_requirements },
  { &hf_pres_protocol_options, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_pres_Protocol_options },
  { &hf_pres_initiators_nominated_context, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_pres_Presentation_context_identifier },
  { &hf_pres_extensions     , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL, dissect_pres_T_extensions },
  { &hf_pres_user_data      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pres_User_data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_T_normal_mode_parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_normal_mode_parameters_sequence, hf_index, ett_pres_T_normal_mode_parameters);

  return offset;
}


static const ber_sequence_t CP_type_set[] = {
  { &hf_pres_mode_selector  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_pres_Mode_selector },
  { &hf_pres_x410_mode_parameters, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_RTORQapdu },
  { &hf_pres_normal_mode_parameters, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_T_normal_mode_parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_CP_type(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              CP_type_set, hf_index, ett_pres_CP_type);

  return offset;
}



static int
dissect_pres_CPC_type(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pres_User_data(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_pres_Responding_presentation_selector(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pres_Presentation_selector(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string pres_Result_vals[] = {
  {   0, "acceptance" },
  {   1, "user-rejection" },
  {   2, "provider-rejection" },
  { 0, NULL }
};


static int
dissect_pres_Result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string pres_T_provider_reason_vals[] = {
  {   0, "reason-not-specified" },
  {   1, "abstract-syntax-not-supported" },
  {   2, "proposed-transfer-syntaxes-not-supported" },
  {   3, "local-limit-on-DCS-exceeded" },
  { 0, NULL }
};


static int
dissect_pres_T_provider_reason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t Result_list_item_sequence[] = {
  { &hf_pres_result         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_pres_Result },
  { &hf_pres_transfer_syntax_name, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Transfer_syntax_name },
  { &hf_pres_provider_reason, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_T_provider_reason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_Result_list_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Result_list_item_sequence, hf_index, ett_pres_Result_list_item);

  return offset;
}


static const ber_sequence_t Result_list_sequence_of[1] = {
  { &hf_pres_Result_list_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pres_Result_list_item },
};

static int
dissect_pres_Result_list(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Result_list_sequence_of, hf_index, ett_pres_Result_list);

  return offset;
}



static int
dissect_pres_Presentation_context_definition_result_list(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pres_Result_list(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t T_CPA_PPDU_normal_mode_parameters_sequence[] = {
  { &hf_pres_protocol_version, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Protocol_version },
  { &hf_pres_responding_presentation_selector, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Responding_presentation_selector },
  { &hf_pres_presentation_context_definition_result_list, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Presentation_context_definition_result_list },
  { &hf_pres_presentation_requirements, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Presentation_requirements },
  { &hf_pres_user_session_requirements, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_User_session_requirements },
  { &hf_pres_protocol_options, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_pres_Protocol_options },
  { &hf_pres_responders_nominated_context, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL, dissect_pres_Presentation_context_identifier },
  { &hf_pres_user_data      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pres_User_data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_T_CPA_PPDU_normal_mode_parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_CPA_PPDU_normal_mode_parameters_sequence, hf_index, ett_pres_T_CPA_PPDU_normal_mode_parameters);

  return offset;
}


static const ber_sequence_t CPA_PPDU_set[] = {
  { &hf_pres_mode_selector  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_pres_Mode_selector },
  { &hf_pres_cPR_PPDU_x400_mode_parameters, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_RTOACapdu },
  { &hf_pres_cPU_PPDU_normal_mode_parameters, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_T_CPA_PPDU_normal_mode_parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_CPA_PPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              CPA_PPDU_set, hf_index, ett_pres_CPA_PPDU);

  return offset;
}



static int
dissect_pres_Default_context_result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pres_Result(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string pres_Provider_reason_vals[] = {
  {   0, "reason-not-specified" },
  {   1, "temporary-congestion" },
  {   2, "local-limit-exceeded" },
  {   3, "called-presentation-address-unknown" },
  {   4, "protocol-version-not-supported" },
  {   5, "default-context-not-supported" },
  {   6, "user-data-not-readable" },
  {   7, "no-PSAP-available" },
  { 0, NULL }
};


static int
dissect_pres_Provider_reason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_CPR_PPDU_normal_mode_parameters_sequence[] = {
  { &hf_pres_protocol_version, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Protocol_version },
  { &hf_pres_responding_presentation_selector, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Responding_presentation_selector },
  { &hf_pres_presentation_context_definition_result_list, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Presentation_context_definition_result_list },
  { &hf_pres_default_context_result, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Default_context_result },
  { &hf_pres_cPR_PPDU__provider_reason, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Provider_reason },
  { &hf_pres_user_data      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pres_User_data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_T_CPR_PPDU_normal_mode_parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_CPR_PPDU_normal_mode_parameters_sequence, hf_index, ett_pres_T_CPR_PPDU_normal_mode_parameters);

  return offset;
}


static const value_string pres_CPR_PPDU_vals[] = {
  {   0, "x400-mode-parameters" },
  {   1, "normal-mode-parameters" },
  { 0, NULL }
};

static const ber_choice_t CPR_PPDU_choice[] = {
  {   0, &hf_pres_cPU_PPDU_x400_mode_parameters, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_rtse_RTORJapdu },
  {   1, &hf_pres_cPR_PPDU_normal_mode_parameters, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pres_T_CPR_PPDU_normal_mode_parameters },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_CPR_PPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CPR_PPDU_choice, hf_index, ett_pres_CPR_PPDU,
                                 NULL);

  return offset;
}


static const ber_sequence_t Presentation_context_identifier_list_item_sequence[] = {
  { &hf_pres_presentation_context_identifier, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pres_Presentation_context_identifier },
  { &hf_pres_transfer_syntax_name, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pres_Transfer_syntax_name },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_Presentation_context_identifier_list_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Presentation_context_identifier_list_item_sequence, hf_index, ett_pres_Presentation_context_identifier_list_item);

  return offset;
}


static const ber_sequence_t Presentation_context_identifier_list_sequence_of[1] = {
  { &hf_pres_Presentation_context_identifier_list_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pres_Presentation_context_identifier_list_item },
};

static int
dissect_pres_Presentation_context_identifier_list(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Presentation_context_identifier_list_sequence_of, hf_index, ett_pres_Presentation_context_identifier_list);

  return offset;
}


static const ber_sequence_t T_ARU_PPDU_normal_mode_parameters_sequence[] = {
  { &hf_pres_presentation_context_identifier_list, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Presentation_context_identifier_list },
  { &hf_pres_user_data      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pres_User_data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_T_ARU_PPDU_normal_mode_parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_ARU_PPDU_normal_mode_parameters_sequence, hf_index, ett_pres_T_ARU_PPDU_normal_mode_parameters);

  return offset;
}


static const value_string pres_ARU_PPDU_vals[] = {
  {   0, "x400-mode-parameters" },
  {   1, "normal-mode-parameters" },
  { 0, NULL }
};

static const ber_choice_t ARU_PPDU_choice[] = {
  {   0, &hf_pres_aRU_PPDU_x400_mode_parameters, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_rtse_RTABapdu },
  {   1, &hf_pres_aRU_PPDU_normal_mode_parameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_pres_T_ARU_PPDU_normal_mode_parameters },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_ARU_PPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ARU_PPDU_choice, hf_index, ett_pres_ARU_PPDU,
                                 NULL);

  return offset;
}


static const value_string pres_Abort_reason_vals[] = {
  {   0, "reason-not-specified" },
  {   1, "unrecognized-ppdu" },
  {   2, "unexpected-ppdu" },
  {   3, "unexpected-session-service-primitive" },
  {   4, "unrecognized-ppdu-parameter" },
  {   5, "unexpected-ppdu-parameter" },
  {   6, "invalid-ppdu-parameter-value" },
  { 0, NULL }
};


static int
dissect_pres_Abort_reason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t reason;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &reason);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (%s)", val_to_str(reason, pres_Abort_reason_vals, "unknown: %d"));


  return offset;
}


static const value_string pres_Event_identifier_vals[] = {
  {   0, "cp-PPDU" },
  {   1, "cpa-PPDU" },
  {   2, "cpr-PPDU" },
  {   3, "aru-PPDU" },
  {   4, "arp-PPDU" },
  {   5, "ac-PPDU" },
  {   6, "aca-PPDU" },
  {   7, "td-PPDU" },
  {   8, "ttd-PPDU" },
  {   9, "te-PPDU" },
  {  10, "tc-PPDU" },
  {  11, "tcc-PPDU" },
  {  12, "rs-PPDU" },
  {  13, "rsa-PPDU" },
  {  14, "s-release-indication" },
  {  15, "s-release-confirm" },
  {  16, "s-token-give-indication" },
  {  17, "s-token-please-indication" },
  {  18, "s-control-give-indication" },
  {  19, "s-sync-minor-indication" },
  {  20, "s-sync-minor-confirm" },
  {  21, "s-sync-major-indication" },
  {  22, "s-sync-major-confirm" },
  {  23, "s-p-exception-report-indication" },
  {  24, "s-u-exception-report-indication" },
  {  25, "s-activity-start-indication" },
  {  26, "s-activity-resume-indication" },
  {  27, "s-activity-interrupt-indication" },
  {  28, "s-activity-interrupt-confirm" },
  {  29, "s-activity-discard-indication" },
  {  30, "s-activity-discard-confirm" },
  {  31, "s-activity-end-indication" },
  {  32, "s-activity-end-confirm" },
  { 0, NULL }
};


static int
dissect_pres_Event_identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ARP_PPDU_sequence[] = {
  { &hf_pres_aRU_PPDU_provider_reason, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Abort_reason },
  { &hf_pres_event_identifier, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Event_identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_ARP_PPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ARP_PPDU_sequence, hf_index, ett_pres_ARP_PPDU);

  return offset;
}


static const value_string pres_Abort_type_vals[] = {
  {   0, "aru-ppdu" },
  {   1, "arp-ppdu" },
  { 0, NULL }
};

static const ber_choice_t Abort_type_choice[] = {
  {   0, &hf_pres_aru_ppdu       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_pres_ARU_PPDU },
  {   1, &hf_pres_arp_ppdu       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pres_ARP_PPDU },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_Abort_type(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Abort_type_choice, hf_index, ett_pres_Abort_type,
                                 NULL);

  return offset;
}



static int
dissect_pres_Presentation_context_addition_list(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pres_Context_list(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t Presentation_context_deletion_list_sequence_of[1] = {
  { &hf_pres_Presentation_context_deletion_list_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pres_Presentation_context_identifier },
};

static int
dissect_pres_Presentation_context_deletion_list(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Presentation_context_deletion_list_sequence_of, hf_index, ett_pres_Presentation_context_deletion_list);

  return offset;
}


static const ber_sequence_t AC_PPDU_sequence[] = {
  { &hf_pres_presentation_context_addition_list, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Presentation_context_addition_list },
  { &hf_pres_presentation_context_deletion_list, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Presentation_context_deletion_list },
  { &hf_pres_user_data      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pres_User_data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_AC_PPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AC_PPDU_sequence, hf_index, ett_pres_AC_PPDU);

  return offset;
}



static int
dissect_pres_Presentation_context_addition_result_list(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pres_Result_list(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string pres_Presentation_context_deletion_result_list_item_vals[] = {
  {   0, "acceptance" },
  {   1, "user-rejection" },
  { 0, NULL }
};


static int
dissect_pres_Presentation_context_deletion_result_list_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t Presentation_context_deletion_result_list_sequence_of[1] = {
  { &hf_pres_Presentation_context_deletion_result_list_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pres_Presentation_context_deletion_result_list_item },
};

static int
dissect_pres_Presentation_context_deletion_result_list(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Presentation_context_deletion_result_list_sequence_of, hf_index, ett_pres_Presentation_context_deletion_result_list);

  return offset;
}


static const ber_sequence_t ACA_PPDU_sequence[] = {
  { &hf_pres_presentation_context_addition_result_list, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Presentation_context_addition_result_list },
  { &hf_pres_presentation_context_deletion_result_list, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Presentation_context_deletion_result_list },
  { &hf_pres_user_data      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pres_User_data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_ACA_PPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ACA_PPDU_sequence, hf_index, ett_pres_ACA_PPDU);

  return offset;
}


static const value_string pres_Typed_data_type_vals[] = {
  {   0, "acPPDU" },
  {   1, "acaPPDU" },
  {   2, "ttdPPDU" },
  { 0, NULL }
};

static const ber_choice_t Typed_data_type_choice[] = {
  {   0, &hf_pres_acPPDU         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_pres_AC_PPDU },
  {   1, &hf_pres_acaPPDU        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_pres_ACA_PPDU },
  {   2, &hf_pres_ttdPPDU        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_pres_User_data },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_Typed_data_type(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Typed_data_type_choice, hf_index, ett_pres_Typed_data_type,
                                 NULL);

  return offset;
}


static const ber_sequence_t RS_PPDU_sequence[] = {
  { &hf_pres_presentation_context_identifier_list, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Presentation_context_identifier_list },
  { &hf_pres_user_data      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pres_User_data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_RS_PPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RS_PPDU_sequence, hf_index, ett_pres_RS_PPDU);

  return offset;
}


static const ber_sequence_t RSA_PPDU_sequence[] = {
  { &hf_pres_presentation_context_identifier_list, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Presentation_context_identifier_list },
  { &hf_pres_user_data      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pres_User_data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_RSA_PPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RSA_PPDU_sequence, hf_index, ett_pres_RSA_PPDU);

  return offset;
}


static const ber_sequence_t UD_type_sequence[] = {
  { &hf_pres_protocol_version, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Protocol_version },
  { &hf_pres_calling_presentation_selector, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Calling_presentation_selector },
  { &hf_pres_called_presentation_selector, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Called_presentation_selector },
  { &hf_pres_presentation_context_definition_list, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pres_Presentation_context_definition_list },
  { &hf_pres_user_data      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pres_User_data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pres_UD_type(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UD_type_sequence, hf_index, ett_pres_UD_type);

  return offset;
}


/*--- PDUs ---*/

static int dissect_UD_type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pres_UD_type(false, tvb, offset, &asn1_ctx, tree, hf_pres_UD_type_PDU);
  return offset;
}



/*
 * Dissect an PPDU.
 */
static int
dissect_ppdu(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, struct SESSION_DATA_STRUCTURE* local_session)
{
	proto_item *ti;
	proto_tree *pres_tree;
	struct SESSION_DATA_STRUCTURE* session;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	/* do we have spdu type from the session dissector?  */
	if (local_session == NULL) {
		proto_tree_add_expert(tree, pinfo, &ei_pres_wrong_spdu_type, tvb, offset, -1);
		return 0;
	}

	session = local_session;
	if (session->spdu_type == 0) {
		proto_tree_add_expert_format(tree, pinfo, &ei_pres_wrong_spdu_type, tvb, offset, -1,
			"Internal error:wrong spdu type %x from session dissector.",session->spdu_type);
		return 0;
	}

	/*  set up type of PPDU */
	col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str_ext(session->spdu_type, &ses_vals_ext, "Unknown PPDU type (0x%02x)"));

	asn1_ctx.private_data = session;

	ti = proto_tree_add_item(tree, proto_pres, tvb, offset, -1, ENC_NA);
	pres_tree = proto_item_add_subtree(ti, ett_pres);

	switch (session->spdu_type) {
		case SES_CONNECTION_REQUEST:
			offset = dissect_pres_CP_type(false, tvb, offset, &asn1_ctx, pres_tree, hf_pres_CP_type);
			break;
		case SES_CONNECTION_ACCEPT:
			offset = dissect_pres_CPA_PPDU(false, tvb, offset, &asn1_ctx, pres_tree, hf_pres_CPA_PPDU);
			break;
		case SES_ABORT:
		case SES_ABORT_ACCEPT:
			offset = dissect_pres_Abort_type(false, tvb, offset, &asn1_ctx, pres_tree, hf_pres_Abort_type);
			break;
		case SES_DATA_TRANSFER:
			offset = dissect_pres_CPC_type(false, tvb, offset, &asn1_ctx, pres_tree, hf_pres_user_data);
			break;
		case SES_TYPED_DATA:
			offset = dissect_pres_Typed_data_type(false, tvb, offset, &asn1_ctx, pres_tree, hf_pres_Typed_data_type);
			break;
		case SES_RESYNCHRONIZE:
			offset = dissect_pres_RS_PPDU(false, tvb, offset, &asn1_ctx, pres_tree, -1);
			break;
		case SES_RESYNCHRONIZE_ACK:
			offset = dissect_pres_RSA_PPDU(false, tvb, offset, &asn1_ctx, pres_tree, -1);
			break;
		case SES_REFUSE:
			offset = dissect_pres_CPR_PPDU(false, tvb, offset, &asn1_ctx, pres_tree, hf_pres_CPR_PPDU);
			break;
		default:
			offset = dissect_pres_CPC_type(false, tvb, offset, &asn1_ctx, pres_tree, hf_pres_user_data);
			break;
	}

	return offset;
}

static int
dissect_pres(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
	int offset = 0, old_offset;
	struct SESSION_DATA_STRUCTURE* session;

	session = ((struct SESSION_DATA_STRUCTURE*)data);

	/* first, try to check length   */
	/* do we have at least 4 bytes  */
	if (!tvb_bytes_exist(tvb, 0, 4)) {
		if (session && session->spdu_type != SES_MAJOR_SYNC_POINT) {
			proto_tree_add_item(parent_tree, hf_pres_user_data, tvb, offset,
					    tvb_reported_length_remaining(tvb,offset), ENC_NA);
			return 0;  /* no, it isn't a presentation PDU */
		}
	}

	/* save pointers for calling the acse dissector  */
	global_tree = parent_tree;
	global_pinfo = pinfo;

	/* if the session unit-data packet then we process it */
	/* as a connectionless presentation protocol unit data */
	if (session && session->spdu_type == CLSES_UNIT_DATA) {
		proto_tree * clpres_tree = NULL;
		proto_item *ti;

		col_set_str(pinfo->cinfo, COL_PROTOCOL, "CL-PRES");
  		col_clear(pinfo->cinfo, COL_INFO);

		if (parent_tree) {
			ti = proto_tree_add_item(parent_tree, proto_clpres, tvb, offset, -1, ENC_NA);
			clpres_tree = proto_item_add_subtree(ti, ett_pres);
		}

		/* dissect the packet */
		dissect_UD_type_PDU(tvb, pinfo, clpres_tree, NULL);
		return tvb_captured_length(tvb);
	}

	/*  we can't make any additional checking here   */
	/*  postpone it before dissector will have more information */

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "PRES");
  	col_clear(pinfo->cinfo, COL_INFO);

	if (session && session->spdu_type == SES_MAJOR_SYNC_POINT) {
		/* This is a reassembly initiated in packet-ses */
		char *oid = find_oid_by_pres_ctx_id (pinfo, session->pres_ctx_id);
		if (oid) {
			call_ber_oid_callback (oid, tvb, offset, pinfo, parent_tree, session);
		} else {
			proto_tree_add_item(parent_tree, hf_pres_user_data, tvb, offset,
					    tvb_reported_length_remaining(tvb,offset), ENC_NA);
		}
		return tvb_captured_length(tvb);
	}

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		old_offset = offset;
		offset = dissect_ppdu(tvb, offset, pinfo, parent_tree, session);
		if (offset <= old_offset) {
			proto_tree_add_expert(parent_tree, pinfo, &ei_pres_invalid_offset, tvb, offset, -1);
			break;
		}
	}

	return tvb_captured_length(tvb);
}


/*--- proto_register_pres -------------------------------------------*/
void proto_register_pres(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_pres_CP_type,
      { "CP-type", "pres.cptype",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_CPA_PPDU,
      { "CPA-PPDU", "pres.cpapdu",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_Abort_type,
      { "Abort type", "pres.aborttype",
        FT_UINT32, BASE_DEC, VALS(pres_Abort_type_vals), 0,
        NULL, HFILL }},
    { &hf_pres_CPR_PPDU,
      { "CPR-PPDU", "pres.cprtype",
        FT_UINT32, BASE_DEC, VALS(pres_CPR_PPDU_vals), 0,
        NULL, HFILL }},
    { &hf_pres_Typed_data_type,
      { "Typed data type", "pres.Typed_data_type",
        FT_UINT32, BASE_DEC, VALS(pres_Typed_data_type_vals), 0,
        NULL, HFILL }},

    { &hf_pres_UD_type_PDU,
      { "UD-type", "pres.UD_type_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_mode_selector,
      { "mode-selector", "pres.mode_selector_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_x410_mode_parameters,
      { "x410-mode-parameters", "pres.x410_mode_parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTORQapdu", HFILL }},
    { &hf_pres_normal_mode_parameters,
      { "normal-mode-parameters", "pres.normal_mode_parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_protocol_version,
      { "protocol-version", "pres.protocol_version",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_calling_presentation_selector,
      { "calling-presentation-selector", "pres.calling_presentation_selector",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_called_presentation_selector,
      { "called-presentation-selector", "pres.called_presentation_selector",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_presentation_context_definition_list,
      { "presentation-context-definition-list", "pres.presentation_context_definition_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_default_context_name,
      { "default-context-name", "pres.default_context_name_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_presentation_requirements,
      { "presentation-requirements", "pres.presentation_requirements",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_user_session_requirements,
      { "user-session-requirements", "pres.user_session_requirements",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_protocol_options,
      { "protocol-options", "pres.protocol_options",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_initiators_nominated_context,
      { "initiators-nominated-context", "pres.initiators_nominated_context",
        FT_INT32, BASE_DEC, NULL, 0,
        "Presentation_context_identifier", HFILL }},
    { &hf_pres_extensions,
      { "extensions", "pres.extensions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_user_data,
      { "user-data", "pres.user_data",
        FT_UINT32, BASE_DEC, VALS(pres_User_data_vals), 0,
        NULL, HFILL }},
    { &hf_pres_cPR_PPDU_x400_mode_parameters,
      { "x410-mode-parameters", "pres.x410_mode_parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTOACapdu", HFILL }},
    { &hf_pres_cPU_PPDU_normal_mode_parameters,
      { "normal-mode-parameters", "pres.normal_mode_parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_CPA_PPDU_normal_mode_parameters", HFILL }},
    { &hf_pres_responding_presentation_selector,
      { "responding-presentation-selector", "pres.responding_presentation_selector",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_presentation_context_definition_result_list,
      { "presentation-context-definition-result-list", "pres.presentation_context_definition_result_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_responders_nominated_context,
      { "responders-nominated-context", "pres.responders_nominated_context",
        FT_INT32, BASE_DEC, NULL, 0,
        "Presentation_context_identifier", HFILL }},
    { &hf_pres_cPU_PPDU_x400_mode_parameters,
      { "x400-mode-parameters", "pres.x400_mode_parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTORJapdu", HFILL }},
    { &hf_pres_cPR_PPDU_normal_mode_parameters,
      { "normal-mode-parameters", "pres.normal_mode_parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_CPR_PPDU_normal_mode_parameters", HFILL }},
    { &hf_pres_default_context_result,
      { "default-context-result", "pres.default_context_result",
        FT_INT32, BASE_DEC, VALS(pres_Result_vals), 0,
        NULL, HFILL }},
    { &hf_pres_cPR_PPDU__provider_reason,
      { "provider-reason", "pres.provider_reason",
        FT_INT32, BASE_DEC, VALS(pres_Provider_reason_vals), 0,
        NULL, HFILL }},
    { &hf_pres_aru_ppdu,
      { "aru-ppdu", "pres.aru_ppdu",
        FT_UINT32, BASE_DEC, VALS(pres_ARU_PPDU_vals), 0,
        NULL, HFILL }},
    { &hf_pres_arp_ppdu,
      { "arp-ppdu", "pres.arp_ppdu_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_aRU_PPDU_x400_mode_parameters,
      { "x400-mode-parameters", "pres.x400_mode_parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTABapdu", HFILL }},
    { &hf_pres_aRU_PPDU_normal_mode_parameters,
      { "normal-mode-parameters", "pres.normal_mode_parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ARU_PPDU_normal_mode_parameters", HFILL }},
    { &hf_pres_presentation_context_identifier_list,
      { "presentation-context-identifier-list", "pres.presentation_context_identifier_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_aRU_PPDU_provider_reason,
      { "provider-reason", "pres.provider_reason",
        FT_INT32, BASE_DEC, VALS(pres_Abort_reason_vals), 0,
        "Abort_reason", HFILL }},
    { &hf_pres_event_identifier,
      { "event-identifier", "pres.event_identifier",
        FT_INT32, BASE_DEC, VALS(pres_Event_identifier_vals), 0,
        NULL, HFILL }},
    { &hf_pres_acPPDU,
      { "acPPDU", "pres.acPPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AC_PPDU", HFILL }},
    { &hf_pres_acaPPDU,
      { "acaPPDU", "pres.acaPPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ACA_PPDU", HFILL }},
    { &hf_pres_ttdPPDU,
      { "ttdPPDU", "pres.ttdPPDU",
        FT_UINT32, BASE_DEC, VALS(pres_User_data_vals), 0,
        "User_data", HFILL }},
    { &hf_pres_presentation_context_addition_list,
      { "presentation-context-addition-list", "pres.presentation_context_addition_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_presentation_context_deletion_list,
      { "presentation-context-deletion-list", "pres.presentation_context_deletion_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_presentation_context_addition_result_list,
      { "presentation-context-addition-result-list", "pres.presentation_context_addition_result_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_presentation_context_deletion_result_list,
      { "presentation-context-deletion-result-list", "pres.presentation_context_deletion_result_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_Context_list_item,
      { "Context-list item", "pres.Context_list_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_presentation_context_identifier,
      { "presentation-context-identifier", "pres.presentation_context_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_abstract_syntax_name,
      { "abstract-syntax-name", "pres.abstract_syntax_name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_transfer_syntax_name_list,
      { "transfer-syntax-name-list", "pres.transfer_syntax_name_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Transfer_syntax_name", HFILL }},
    { &hf_pres_transfer_syntax_name_list_item,
      { "Transfer-syntax-name", "pres.Transfer_syntax_name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_transfer_syntax_name,
      { "transfer-syntax-name", "pres.transfer_syntax_name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_mode_value,
      { "mode-value", "pres.mode_value",
        FT_INT32, BASE_DEC, VALS(pres_T_mode_value_vals), 0,
        NULL, HFILL }},
    { &hf_pres_Presentation_context_deletion_list_item,
      { "Presentation-context-identifier", "pres.Presentation_context_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_Presentation_context_deletion_result_list_item,
      { "Presentation-context-deletion-result-list item", "pres.Presentation_context_deletion_result_list_item",
        FT_INT32, BASE_DEC, VALS(pres_Presentation_context_deletion_result_list_item_vals), 0,
        NULL, HFILL }},
    { &hf_pres_Presentation_context_identifier_list_item,
      { "Presentation-context-identifier-list item", "pres.Presentation_context_identifier_list_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_Result_list_item,
      { "Result-list item", "pres.Result_list_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_result,
      { "result", "pres.result",
        FT_INT32, BASE_DEC, VALS(pres_Result_vals), 0,
        NULL, HFILL }},
    { &hf_pres_provider_reason,
      { "provider-reason", "pres.provider_reason",
        FT_INT32, BASE_DEC, VALS(pres_T_provider_reason_vals), 0,
        NULL, HFILL }},
    { &hf_pres_simply_encoded_data,
      { "simply-encoded-data", "pres.simply_encoded_data",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_fully_encoded_data,
      { "fully-encoded-data", "pres.fully_encoded_data",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_Fully_encoded_data_item,
      { "PDV-list", "pres.PDV_list_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_presentation_data_values,
      { "presentation-data-values", "pres.presentation_data_values",
        FT_UINT32, BASE_DEC, VALS(pres_T_presentation_data_values_vals), 0,
        NULL, HFILL }},
    { &hf_pres_single_ASN1_type,
      { "single-ASN1-type", "pres.single_ASN1_type_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pres_octet_aligned,
      { "octet-aligned", "pres.octet_aligned",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_octet_aligned", HFILL }},
    { &hf_pres_arbitrary,
      { "arbitrary", "pres.arbitrary",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_pres_Presentation_requirements_context_management,
      { "context-management", "pres.Presentation.requirements.context.management",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_pres_Presentation_requirements_restoration,
      { "restoration", "pres.Presentation.requirements.restoration",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_pres_Protocol_options_nominated_context,
      { "nominated-context", "pres.Protocol.options.nominated.context",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_pres_Protocol_options_short_encoding,
      { "short-encoding", "pres.Protocol.options.short.encoding",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_pres_Protocol_options_packed_encoding_rules,
      { "packed-encoding-rules", "pres.Protocol.options.packed.encoding.rules",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_pres_Protocol_version_version_1,
      { "version-1", "pres.Protocol.version.version.1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_pres_User_session_requirements_half_duplex,
      { "half-duplex", "pres.User.session.requirements.half.duplex",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_pres_User_session_requirements_duplex,
      { "duplex", "pres.User.session.requirements.duplex",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_pres_User_session_requirements_expedited_data,
      { "expedited-data", "pres.User.session.requirements.expedited.data",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_pres_User_session_requirements_minor_synchronize,
      { "minor-synchronize", "pres.User.session.requirements.minor.synchronize",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_pres_User_session_requirements_major_synchronize,
      { "major-synchronize", "pres.User.session.requirements.major.synchronize",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_pres_User_session_requirements_resynchronize,
      { "resynchronize", "pres.User.session.requirements.resynchronize",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_pres_User_session_requirements_activity_management,
      { "activity-management", "pres.User.session.requirements.activity.management",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_pres_User_session_requirements_negotiated_release,
      { "negotiated-release", "pres.User.session.requirements.negotiated.release",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_pres_User_session_requirements_capability_data,
      { "capability-data", "pres.User.session.requirements.capability.data",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_pres_User_session_requirements_exceptions,
      { "exceptions", "pres.User.session.requirements.exceptions",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_pres_User_session_requirements_typed_data,
      { "typed-data", "pres.User.session.requirements.typed.data",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_pres_User_session_requirements_symmetric_synchronize,
      { "symmetric-synchronize", "pres.User.session.requirements.symmetric.synchronize",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_pres_User_session_requirements_data_separation,
      { "data-separation", "pres.User.session.requirements.data.separation",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
		&ett_pres,
    &ett_pres_CP_type,
    &ett_pres_T_normal_mode_parameters,
    &ett_pres_T_extensions,
    &ett_pres_CPA_PPDU,
    &ett_pres_T_CPA_PPDU_normal_mode_parameters,
    &ett_pres_CPR_PPDU,
    &ett_pres_T_CPR_PPDU_normal_mode_parameters,
    &ett_pres_Abort_type,
    &ett_pres_ARU_PPDU,
    &ett_pres_T_ARU_PPDU_normal_mode_parameters,
    &ett_pres_ARP_PPDU,
    &ett_pres_Typed_data_type,
    &ett_pres_AC_PPDU,
    &ett_pres_ACA_PPDU,
    &ett_pres_RS_PPDU,
    &ett_pres_RSA_PPDU,
    &ett_pres_Context_list,
    &ett_pres_Context_list_item,
    &ett_pres_SEQUENCE_OF_Transfer_syntax_name,
    &ett_pres_Default_context_name,
    &ett_pres_Mode_selector,
    &ett_pres_Presentation_context_deletion_list,
    &ett_pres_Presentation_context_deletion_result_list,
    &ett_pres_Presentation_context_identifier_list,
    &ett_pres_Presentation_context_identifier_list_item,
    &ett_pres_Presentation_requirements,
    &ett_pres_Protocol_options,
    &ett_pres_Protocol_version,
    &ett_pres_Result_list,
    &ett_pres_Result_list_item,
    &ett_pres_User_data,
    &ett_pres_Fully_encoded_data,
    &ett_pres_PDV_list,
    &ett_pres_T_presentation_data_values,
    &ett_pres_User_session_requirements,
    &ett_pres_UD_type,
  };

  static ei_register_info ei[] = {
     { &ei_pres_dissector_not_available, { "pres.dissector_not_available", PI_UNDECODED, PI_WARN, "Dissector is not available", EXPFILL }},
     { &ei_pres_wrong_spdu_type, { "pres.wrong_spdu_type", PI_PROTOCOL, PI_WARN, "Internal error:can't get spdu type from session dissector", EXPFILL }},
     { &ei_pres_invalid_offset, { "pres.invalid_offset", PI_MALFORMED, PI_ERROR, "Internal error:can't get spdu type from session dissector", EXPFILL }},
  };

  static uat_field_t users_flds[] = {
    UAT_FLD_DEC(pres_users,ctx_id,"Context Id","Presentation Context Identifier"),
    UAT_FLD_CSTRING(pres_users,oid,"Syntax Name OID","Abstract Syntax Name (Object Identifier)"),
    UAT_END_FIELDS
  };

  uat_t* users_uat = uat_new("PRES Users Context List",
                             sizeof(pres_user_t),
                             "pres_context_list",
                             true,
                             &pres_users,
                             &num_pres_users,
                             UAT_AFFECTS_DISSECTION, /* affects dissection of packets, but not set of named fields */
                             "ChPresContextList",
                             pres_copy_cb,
                             NULL,
                             pres_free_cb,
                             NULL,
                             NULL,
                             users_flds);

  expert_module_t* expert_pres;
  module_t *pres_module;

  /* Register protocol */
  proto_pres = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("pres", dissect_pres, proto_pres);

  /* Register connectionless protocol (just for the description) */
  proto_clpres = proto_register_protocol(CLPNAME, CLPSNAME, CLPFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pres, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_pres = expert_register_protocol(proto_pres);
  expert_register_field_array(expert_pres, ei, array_length(ei));
  pres_ctx_oid_table = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), pres_ctx_oid_hash, pres_ctx_oid_equal);

  pres_module = prefs_register_protocol(proto_pres, NULL);

  prefs_register_uat_preference(pres_module, "users_table", "Users Context List",
                                "A table that enumerates user protocols to be used against"
                                " specific presentation context identifiers",
                                users_uat);
}


/*--- proto_reg_handoff_pres ---------------------------------------*/
void proto_reg_handoff_pres(void) {

/*	register_ber_oid_dissector("0.4.0.0.1.1.1.1", dissect_pres, proto_pres,
	  "itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) abstractSyntax(1) pres(1) version1(1)"); */

}

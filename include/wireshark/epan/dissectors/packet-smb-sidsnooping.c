/* packet-smb-sidsnooping.c
 * Routines for snooping SID to name mappings
 * Copyright 2003, Ronnie Sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <wsutil/report_message.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-smb.h"
#include "packet-smb-sidsnooping.h"

void proto_register_smb_sidsnooping(void);

#if 0
static int hf_lsa;
static int hf_lsa_opnum;
#endif
static int hf_lsa_info_level;
static int hf_lsa_domain;
static int hf_nt_domain_sid;
static int hf_samr_hnd;
static int hf_samr_rid;
static int hf_samr_acct_name;
static int hf_samr_level;


GHashTable *sid_name_table;


static GHashTable *ctx_handle_table;


static bool lsa_policy_information_tap_installed;
static bool samr_query_dispinfo_tap_installed;


const char *
find_sid_name(const char *sid)
{
	return (const char *)g_hash_table_lookup(sid_name_table, sid);
}

static void
add_sid_name_mapping(const char *sid, const char *name)
{
	if (find_sid_name(sid)) {
		return;
	}

	g_hash_table_insert(sid_name_table, g_strdup(sid), g_strdup(name));
}



/*
 * QueryDispInfo :
 * level  1 : user displayinfo 1
 */
static tap_packet_status
samr_query_dispinfo(void *dummy _U_, packet_info *pinfo, epan_dissect_t *edt, const void *pri, tap_flags_t flags _U_)
{
	const dcerpc_info *ri=(const dcerpc_info *)pri;
	void *old_ctx=NULL;
	char *pol_name;
	char *sid;
	int sid_len;
	int num_rids;
	int num_names;
	GPtrArray *gp;
	GPtrArray *gp_rids;
	GPtrArray *gp_names;
	field_info *fi;
	field_info *fi_rid;
	field_info *fi_name;
	char sid_name_str[256];
	int info_level;

	gp=proto_get_finfo_ptr_array(edt->tree, hf_samr_level);
	if(!gp || gp->len!=1){
		return TAP_PACKET_DONT_REDRAW;
	}
	fi=(field_info *)gp->pdata[0];
	info_level = fvalue_get_sinteger(fi->value);

	if(info_level!=1){
		return TAP_PACKET_DONT_REDRAW;
	}

	if(!ri){
		return TAP_PACKET_DONT_REDRAW;
	}
	if(!ri->call_data){
		return TAP_PACKET_DONT_REDRAW;
	}
	if(ri->ptype == PDU_REQ){
		gp=proto_get_finfo_ptr_array(edt->tree, hf_samr_hnd);
		if(!gp || gp->len!=1){
			return TAP_PACKET_DONT_REDRAW;
		}
		fi=(field_info *)gp->pdata[0];

		old_ctx=g_hash_table_lookup(ctx_handle_table, GINT_TO_POINTER(pinfo->num));
		if(old_ctx){
			g_hash_table_remove(ctx_handle_table, GINT_TO_POINTER(pinfo->num));
		}
		if(!old_ctx){
			old_ctx=wmem_memdup(wmem_file_scope(), fvalue_get_bytes_data(fi->value), 20);
		}
		g_hash_table_insert(ctx_handle_table, GINT_TO_POINTER(pinfo->num), old_ctx);

		return TAP_PACKET_DONT_REDRAW;
	}

	if(!ri->call_data->req_frame){
		return TAP_PACKET_DONT_REDRAW;
	}

	old_ctx=g_hash_table_lookup(ctx_handle_table, GINT_TO_POINTER(ri->call_data->req_frame));
	if(!old_ctx){
		return TAP_PACKET_DONT_REDRAW;
	}

	if (!dcerpc_fetch_polhnd_data((e_ctx_hnd *)old_ctx, &pol_name, NULL, NULL, NULL, ri->call_data->req_frame)) {
		return TAP_PACKET_DONT_REDRAW;
	}

	if (!pol_name)
		return TAP_PACKET_DONT_REDRAW;

	sid=strstr(pol_name,"S-1-5");
	if(!sid){
		return TAP_PACKET_DONT_REDRAW;
	}

	for(sid_len=4;1;sid_len++){
		if((sid[sid_len]>='0') && (sid[sid_len]<='9')){
			continue;
		}
		if(sid[sid_len]=='-'){
			continue;
		}
		break;
	}

	gp_rids=proto_get_finfo_ptr_array(edt->tree, hf_samr_rid);
	if(!gp_rids || gp_rids->len<1){
		return TAP_PACKET_DONT_REDRAW;
	}
	num_rids=gp_rids->len;
	gp_names=proto_get_finfo_ptr_array(edt->tree, hf_samr_acct_name);
	if(!gp_names || gp_names->len<1){
		return TAP_PACKET_DONT_REDRAW;
	}
	num_names=gp_names->len;

	if(num_rids>num_names){
		num_rids=num_names;
	}

	for(;num_rids;num_rids--){
		int len=sid_len;
		if (len > 247)
			len = 247;

		fi_rid=(field_info *)gp_rids->pdata[num_rids-1];
		fi_name=(field_info *)gp_names->pdata[num_rids-1];
		(void) g_strlcpy(sid_name_str, sid, 256);
		sid_name_str[len++]='-';
		snprintf(sid_name_str+len, 256-len, "%d", fvalue_get_sinteger(fi_rid->value));
		add_sid_name_mapping(sid_name_str, fvalue_get_string(fi_name->value));
	}
	return TAP_PACKET_REDRAW;
}

/*
 * PolicyInformation :
 * level  3 : PRIMARY_DOMAIN_INFO lsa.domain_sid -> lsa.domain
 * level  5 : ACCOUNT_DOMAIN_INFO lsa.domain_sid -> lsa.domain
 * level 12 : DNS_DOMAIN_INFO     lsa.domain_sid -> lsa.domain
 */
static tap_packet_status
lsa_policy_information(void *dummy _U_, packet_info *pinfo _U_, epan_dissect_t *edt, const void *pri _U_, tap_flags_t flags _U_)
{
	GPtrArray *gp;
	field_info *fi;
	const char *domain;
	const char *sid;
	int info_level;

	gp=proto_get_finfo_ptr_array(edt->tree, hf_lsa_info_level);
	if(!gp || gp->len!=1){
		return TAP_PACKET_DONT_REDRAW;
	}
	fi=(field_info *)gp->pdata[0];
	info_level = fvalue_get_sinteger(fi->value);

	switch(info_level){
	case 3:
	case 5:
	case 12:
		gp=proto_get_finfo_ptr_array(edt->tree, hf_lsa_domain);
		if(!gp || gp->len!=1){
			return TAP_PACKET_DONT_REDRAW;
		}
		fi=(field_info *)gp->pdata[0];
		domain=fvalue_get_string(fi->value);

		gp=proto_get_finfo_ptr_array(edt->tree, hf_nt_domain_sid);
		if(!gp || gp->len!=1){
			return TAP_PACKET_DONT_REDRAW;
		}
		fi=(field_info *)gp->pdata[0];
		sid=fvalue_get_string(fi->value);

		add_sid_name_mapping(sid, domain);
		break;
	}
	return TAP_PACKET_DONT_REDRAW;
}


static int
ctx_handle_equal(const void *k1, const void *k2)
{
	int sn1 = GPOINTER_TO_INT(k1);
	int sn2 = GPOINTER_TO_INT(k2);

	return sn1==sn2;
}

static unsigned
ctx_handle_hash(const void *k)
{
	int sn = GPOINTER_TO_INT(k);

	return sn;
}


static void
sid_snooping_init(void)
{
	GString *error_string;

	if(lsa_policy_information_tap_installed){
		remove_tap_listener(&lsa_policy_information_tap_installed);
		lsa_policy_information_tap_installed=false;
	}
	if(samr_query_dispinfo_tap_installed){
		remove_tap_listener(&samr_query_dispinfo_tap_installed);
		samr_query_dispinfo_tap_installed=false;
	}

	sid_name_table = g_hash_table_new_full(g_str_hash, g_str_equal,
		g_free, g_free);
	ctx_handle_table = g_hash_table_new(ctx_handle_hash, ctx_handle_equal);
/* TODO this code needs to be rewritten from scratch
   disabling it now so that it won't cause wireshark to abort due to
   unknown hf fields
 */
sid_name_snooping=false;

	if(!sid_name_snooping){
		return;
	}



#if 0
	hf_lsa		  = proto_get_id_by_filter_name("lsa");
	hf_lsa_opnum	  = proto_registrar_get_id_byname("lsa.opnum");
#endif
	hf_nt_domain_sid  = proto_registrar_get_id_byname("nt.domain_sid");
	hf_lsa_domain	  = proto_registrar_get_id_byname("lsa.domain");
	hf_lsa_info_level = proto_registrar_get_id_byname("lsa.info.level");
	hf_samr_hnd	  = proto_registrar_get_id_byname("samr.handle");
	hf_samr_rid	  = proto_registrar_get_id_byname("samr.rid");
	hf_samr_acct_name = proto_registrar_get_id_byname("samr.acct_name");
	hf_samr_level	  = proto_registrar_get_id_byname("samr.level");


	error_string=register_tap_listener("dcerpc",
	    &lsa_policy_information_tap_installed,
	    "lsa.policy_information and ( lsa.info.level or lsa.domain or nt.domain_sid )",
	    TL_REQUIRES_PROTO_TREE, NULL, lsa_policy_information, NULL, NULL);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */

		report_failure( "Couldn't register proto_reg_handoff_smb_sidsnooping()/lsa_policy_information tap: %s\n",
		    error_string->str);
		g_string_free(error_string, true);
		return;
	}
	lsa_policy_information_tap_installed=true;

	error_string=register_tap_listener("dcerpc",
	    &samr_query_dispinfo_tap_installed,
	    "samr and samr.opnum==40 and ( samr.handle or samr.rid or samr.acct_name or samr.level )",
	    TL_REQUIRES_PROTO_TREE, NULL, samr_query_dispinfo, NULL, NULL);
	if(error_string){
		/* error, we failed to attach to the tap. clean up */

		report_failure( "Couldn't register proto_reg_handoff_smb_sidsnooping()/samr_query_dispinfo tap: %s\n",
		    error_string->str);
		g_string_free(error_string, true);
		return;
	}
	samr_query_dispinfo_tap_installed=true;
}

static void
sid_snooping_cleanup(void)
{
	g_hash_table_destroy(sid_name_table);
	g_hash_table_destroy(ctx_handle_table);
}

void
proto_register_smb_sidsnooping(void)
{
	register_init_routine(sid_snooping_init);
	register_cleanup_routine(sid_snooping_cleanup);
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

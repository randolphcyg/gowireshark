/* packet-collectd.c
 * Routines for collectd (http://collectd.org/) network plugin dissection
 *
 * https://github.com/collectd/collectd/wiki/Binary-protocol
 *
 * Copyright 2008 Bruno Premont <bonbons at linux-vserver.org>
 * Copyright 2009-2013 Florian Forster <octo at collectd.org>
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
#include <epan/proto_data.h>
#include <epan/stats_tree.h>
#include <epan/to_str.h>
#include <epan/uat.h>
#include <epan/exceptions.h>

#include <wsutil/str_util.h>
#include <wsutil/wsgcrypt.h>

#define STR_NONNULL(str) ((str) ? ((const char*)str) : "(null)")

#define TYPE_HOST            0x0000
#define TYPE_TIME            0x0001
#define TYPE_TIME_HR         0x0008
#define TYPE_PLUGIN          0x0002
#define TYPE_PLUGIN_INSTANCE 0x0003
#define TYPE_TYPE            0x0004
#define TYPE_TYPE_INSTANCE   0x0005
#define TYPE_VALUES          0x0006
#define TYPE_INTERVAL        0x0007
#define TYPE_INTERVAL_HR     0x0009
#define TYPE_MESSAGE         0x0100
#define TYPE_SEVERITY        0x0101
#define TYPE_SIGN_SHA256     0x0200
#define TYPE_ENCR_AES256     0x0210

void proto_register_collectd(void);

static dissector_handle_t collectd_handle;

#define TAP_DATA_KEY 0
#define COL_DATA_KEY 1

typedef struct value_data_s {
	const uint8_t *host;
	int host_off;
	int host_len;
	uint64_t time_value;
	int time_off;
	uint64_t interval;
	int interval_off;
	const uint8_t *plugin;
	int plugin_off;
	int plugin_len;
	const uint8_t *plugin_instance;
	int plugin_instance_off;
	int plugin_instance_len;
	const uint8_t *type;
	int type_off;
	int type_len;
	const uint8_t *type_instance;
	int type_instance_off;
	int type_instance_len;
} value_data_t;

typedef struct notify_data_s {
	const uint8_t *host;
	int host_off;
	int host_len;
	uint64_t time_value;
	int time_off;
	uint64_t severity;
	int severity_off;
	const uint8_t *message;
	int message_off;
	int message_len;
} notify_data_t;

struct string_counter_s;
typedef struct string_counter_s string_counter_t;
struct string_counter_s
{
	const char *string;
	int    count;
	string_counter_t *next;
};

typedef struct tap_data_s {
	int values_num;

	string_counter_t *hosts;
	string_counter_t *plugins;
	string_counter_t *types;
} tap_data_t;

typedef struct column_data_s {
	unsigned pkt_plugins;
	unsigned pkt_values;
	unsigned pkt_messages;
	unsigned pkt_unknown;
	unsigned pkt_errors;

	const uint8_t *pkt_host;
} column_data_t;

static const value_string part_names[] = {
	{ TYPE_VALUES,          "VALUES" },
	{ TYPE_TIME,            "TIME" },
	{ TYPE_TIME_HR,         "TIME_HR" },
	{ TYPE_INTERVAL,        "INTERVAL" },
	{ TYPE_INTERVAL_HR,     "INTERVAL_HR" },
	{ TYPE_HOST,            "HOST" },
	{ TYPE_PLUGIN,          "PLUGIN" },
	{ TYPE_PLUGIN_INSTANCE, "PLUGIN_INSTANCE" },
	{ TYPE_TYPE,            "TYPE" },
	{ TYPE_TYPE_INSTANCE,   "TYPE_INSTANCE" },
	{ TYPE_MESSAGE,         "MESSAGE" },
	{ TYPE_SEVERITY,        "SEVERITY" },
	{ TYPE_SIGN_SHA256,     "SIGNATURE" },
	{ TYPE_ENCR_AES256,     "ENCRYPTED_DATA" },
	{ 0, NULL }
};

#define TYPE_VALUE_COUNTER  0x00
#define TYPE_VALUE_GAUGE    0x01
#define TYPE_VALUE_DERIVE   0x02
#define TYPE_VALUE_ABSOLUTE 0x03
static const value_string valuetypenames[] = {
	{ TYPE_VALUE_COUNTER,   "COUNTER" },
	{ TYPE_VALUE_GAUGE,     "GAUGE" },
	{ TYPE_VALUE_DERIVE,    "DERIVE" },
	{ TYPE_VALUE_ABSOLUTE,  "ABSOLUTE" },
	{ 0, NULL }
};

#define SEVERITY_FAILURE  0x01
#define SEVERITY_WARNING  0x02
#define SEVERITY_OKAY     0x04
static const val64_string severity_names[] = {
	{ SEVERITY_FAILURE,  "FAILURE" },
	{ SEVERITY_WARNING,  "WARNING" },
	{ SEVERITY_OKAY,     "OKAY" },
	{ 0, NULL }
};

#define UDP_PORT_COLLECTD 25826 /* Not IANA registered */

static int proto_collectd;
static int tap_collectd                = -1;

static int hf_collectd_type;
static int hf_collectd_length;
static int hf_collectd_data;
static int hf_collectd_data_host;
static int hf_collectd_data_time;
static int hf_collectd_data_interval;
static int hf_collectd_data_plugin;
static int hf_collectd_data_plugin_inst;
static int hf_collectd_data_type;
static int hf_collectd_data_type_inst;
static int hf_collectd_data_valcnt;
static int hf_collectd_val_type;
static int hf_collectd_val_counter;
static int hf_collectd_val_gauge;
static int hf_collectd_val_derive;
static int hf_collectd_val_absolute;
static int hf_collectd_val_unknown;
static int hf_collectd_data_severity;
static int hf_collectd_data_message;
static int hf_collectd_data_sighash;
static int hf_collectd_data_sighash_status;
static int hf_collectd_data_initvec;
static int hf_collectd_data_username_len;
static int hf_collectd_data_username;
static int hf_collectd_data_encrypted;

static int ett_collectd;
static int ett_collectd_string;
static int ett_collectd_integer;
static int ett_collectd_part_value;
static int ett_collectd_value;
static int ett_collectd_valinfo;
static int ett_collectd_signature;
static int ett_collectd_encryption;
static int ett_collectd_dispatch;
static int ett_collectd_invalid_length;
static int ett_collectd_unknown;

static int st_collectd_packets = -1;
static int st_collectd_values  = -1;
static int st_collectd_values_hosts   = -1;
static int st_collectd_values_plugins = -1;
static int st_collectd_values_types   = -1;

static expert_field ei_collectd_type;
static expert_field ei_collectd_invalid_length;
static expert_field ei_collectd_data_valcnt;
static expert_field ei_collectd_garbage;
static expert_field ei_collectd_sighash_bad;

/* Prototype for the handoff function */
void proto_reg_handoff_collectd (void);

typedef struct {
	char *username;
	char *password;

	bool cipher_hd_created;
	bool md_hd_created;
	gcry_cipher_hd_t cipher_hd;
	gcry_md_hd_t md_hd;

} uat_collectd_record_t;

static uat_collectd_record_t *uat_collectd_records;

static uat_t *collectd_uat;
static unsigned num_uat;

UAT_CSTRING_CB_DEF(uat_collectd_records, username, uat_collectd_record_t)
UAT_CSTRING_CB_DEF(uat_collectd_records, password, uat_collectd_record_t)

static void*
uat_collectd_record_copy_cb(void* n, const void* o, size_t size _U_) {
	uat_collectd_record_t* new_rec = (uat_collectd_record_t *)n;
	const uat_collectd_record_t* old_rec = (const uat_collectd_record_t *)o;

	new_rec->username = g_strdup(old_rec->username);
	new_rec->password = g_strdup(old_rec->password);

	new_rec->cipher_hd_created = FALSE;
	new_rec->md_hd_created = FALSE;

	return new_rec;
}

static bool
uat_collectd_record_update_cb(void* r, char** err _U_) {
	uat_collectd_record_t* rec = (uat_collectd_record_t *)r;

	if (rec->cipher_hd_created) {
		gcry_cipher_close(rec->cipher_hd);
		rec->cipher_hd_created = false;
	}
	if (rec->md_hd_created) {
		gcry_md_close(rec->md_hd);
		rec->md_hd_created = false;
	}

	return true;
}

static void
uat_collectd_record_free_cb(void* r) {
	uat_collectd_record_t* rec = (uat_collectd_record_t *)r;

	g_free(rec->username);
	g_free(rec->password);

	if (rec->cipher_hd_created) {
		gcry_cipher_close(rec->cipher_hd);
		rec->cipher_hd_created = false;
	}
	if (rec->md_hd_created) {
		gcry_md_close(rec->md_hd);
		rec->md_hd_created = false;
	}
}

static uat_collectd_record_t*
collectd_get_record(const char* username)
{
	uat_collectd_record_t *record = NULL;
	for (unsigned i = 0; i < num_uat; ++i) {
		record = &uat_collectd_records[i];
		if (strcmp(username, record->username) == 0) {
			return record;
		}
	}
	return NULL;
}

static gcry_cipher_hd_t*
collectd_get_cipher(const char* username)
{
	uat_collectd_record_t *record = collectd_get_record(username);
	if (record == NULL) {
		return NULL;
	}
	if (record->cipher_hd_created) {
		return &record->cipher_hd;
	}
	gcry_error_t err;
	unsigned char password_hash[32];
	DISSECTOR_ASSERT(record->password);
	gcry_md_hash_buffer(GCRY_MD_SHA256, password_hash, record->password, strlen(record->password));
	if (gcry_cipher_open(&record->cipher_hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OFB, 0)) {
		gcry_cipher_close(record->cipher_hd);
		ws_debug("error opening aes256 cipher handle");
		return NULL;
	}

	err = gcry_cipher_setkey(record->cipher_hd, password_hash, sizeof(password_hash));
	if (err != 0) {
		gcry_cipher_close(record->cipher_hd);
		ws_debug("error setting key");
		return NULL;
	}
	record->cipher_hd_created = true;
	return &record->cipher_hd;
}

static gcry_md_hd_t*
collectd_get_md(const char* username)
{
	uat_collectd_record_t *record = collectd_get_record(username);
	if (record == NULL) {
		return NULL;
	}
	if (record->md_hd_created) {
		gcry_md_reset(record->md_hd);
		return &record->md_hd;
	}
	gcry_error_t err;
	DISSECTOR_ASSERT(record->password);
	err = gcry_md_open(&record->md_hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
	if (err != 0) {
		gcry_md_close(record->md_hd);
		ws_debug("error opening sha256 message digest handle: %s", gcry_strerror(err));
		return NULL;
	}

	err = gcry_md_setkey(record->md_hd, record->password, strlen(record->password));
	if (err != 0) {
		gcry_md_close(record->md_hd);
		ws_debug("error setting key: %s", gcry_strerror(err));
		return NULL;
	}
	record->md_hd_created = true;
	return &record->md_hd;
}

static nstime_t
collectd_time_to_nstime (uint64_t t)
{
	nstime_t nstime = NSTIME_INIT_ZERO;
	nstime.secs = (time_t) (t / 1073741824);
	nstime.nsecs = (int) (((double) (t % 1073741824)) / 1.073741824);

	return (nstime);
}

static void
collectd_stats_tree_init (stats_tree *st)
{
	st_collectd_packets = stats_tree_create_node (st, "Packets", 0, STAT_DT_INT, false);
	st_collectd_values = stats_tree_create_node (st, "Values", 0, STAT_DT_INT, true);

	st_collectd_values_hosts = stats_tree_create_pivot (st, "By host",
							   st_collectd_values);
	st_collectd_values_plugins = stats_tree_create_pivot (st, "By plugin",
							      st_collectd_values);
	st_collectd_values_types = stats_tree_create_pivot (st, "By type",
							    st_collectd_values);
} /* void collectd_stats_tree_init */

static tap_packet_status
collectd_stats_tree_packet (stats_tree *st, packet_info *pinfo _U_,
			    epan_dissect_t *edt _U_, const void *user_data, tap_flags_t flags _U_)
{
	const tap_data_t *td;
	string_counter_t *sc;

	td = (const tap_data_t *)user_data;
	if (td == NULL)
		return (TAP_PACKET_DONT_REDRAW);

	tick_stat_node (st, "Packets", 0, false);
	increase_stat_node (st, "Values", 0, true, td->values_num);

	for (sc = td->hosts; sc != NULL; sc = sc->next)
	{
		int i;
		for (i = 0; i < sc->count; i++)
			stats_tree_tick_pivot (st, st_collectd_values_hosts,
					       sc->string);
	}

	for (sc = td->plugins; sc != NULL; sc = sc->next)
	{
		int i;
		for (i = 0; i < sc->count; i++)
			stats_tree_tick_pivot (st, st_collectd_values_plugins,
					       sc->string);
	}

	for (sc = td->types; sc != NULL; sc = sc->next)
	{
		int i;
		for (i = 0; i < sc->count; i++)
			stats_tree_tick_pivot (st, st_collectd_values_types,
					       sc->string);
	}

	return (TAP_PACKET_REDRAW);
} /* int collectd_stats_tree_packet */

static void
collectd_stats_tree_register (void)
{
	stats_tree_register ("collectd", "collectd", "Collectd", 0,
			     collectd_stats_tree_packet,
			     collectd_stats_tree_init, NULL);
} /* void register_collectd_stat_trees */

static void
collectd_proto_tree_add_assembled_metric (tvbuff_t *tvb,
		int offset, int length,
		value_data_t const *vdispatch, proto_tree *root)
{
	proto_item *root_item;
	proto_tree *subtree;
	nstime_t nstime;

	subtree = proto_tree_add_subtree(root, tvb, offset + 6, length - 6,
			ett_collectd_dispatch, &root_item, "Assembled metric");
	proto_item_set_generated (root_item);

	proto_tree_add_string (subtree, hf_collectd_data_host, tvb,
			vdispatch->host_off, vdispatch->host_len,
			STR_NONNULL (vdispatch->host));

	proto_tree_add_string (subtree, hf_collectd_data_plugin, tvb,
			vdispatch->plugin_off, vdispatch->plugin_len,
			STR_NONNULL (vdispatch->plugin));

	if (vdispatch->plugin_instance)
		proto_tree_add_string (subtree,
				hf_collectd_data_plugin_inst, tvb,
				vdispatch->plugin_instance_off,
				vdispatch->plugin_instance_len,
				vdispatch->plugin_instance);

	proto_tree_add_string (subtree, hf_collectd_data_type, tvb,
			vdispatch->type_off, vdispatch->type_len,
			STR_NONNULL (vdispatch->type));

	if (vdispatch->type_instance)
		proto_tree_add_string (subtree,
				hf_collectd_data_type_inst, tvb,
				vdispatch->type_instance_off,
				vdispatch->type_instance_len,
				vdispatch->type_instance);

	nstime = collectd_time_to_nstime (vdispatch->time_value);
	proto_tree_add_time (subtree, hf_collectd_data_time, tvb,
			vdispatch->time_off, /* length = */ 8, &nstime);

	nstime = collectd_time_to_nstime (vdispatch->interval);
	proto_tree_add_time (subtree, hf_collectd_data_interval, tvb,
			vdispatch->interval_off, /* length = */ 8, &nstime);
}

static void
collectd_proto_tree_add_assembled_notification (tvbuff_t *tvb,
		int offset, int length,
		notify_data_t const *ndispatch, proto_tree *root)
{
	proto_item *root_item;
	proto_tree *subtree;
	nstime_t nstime;

	subtree = proto_tree_add_subtree(root, tvb, offset + 6, length - 6,
			ett_collectd_dispatch, &root_item, "Assembled notification");
	proto_item_set_generated (root_item);

	proto_tree_add_string (subtree, hf_collectd_data_host, tvb,
			ndispatch->host_off, ndispatch->host_len,
			STR_NONNULL (ndispatch->host));

	nstime = collectd_time_to_nstime (ndispatch->time_value);
	proto_tree_add_time (subtree, hf_collectd_data_time, tvb,
			ndispatch->time_off, /* length = */ 8, &nstime);

	proto_tree_add_uint64 (subtree, hf_collectd_data_severity, tvb,
			ndispatch->severity_off, /* length = */ 8,
			ndispatch->severity);

	proto_tree_add_string (subtree, hf_collectd_data_message, tvb,
			ndispatch->message_off, ndispatch->message_len,
			ndispatch->message);
}

static int
dissect_collectd_string (tvbuff_t *tvb, packet_info *pinfo, int type_hf,
			 int offset, int *ret_offset, int *ret_length,
			 const uint8_t **ret_string, proto_tree *tree_root,
			 proto_item **ret_item)
{
	proto_tree *pt;
	proto_item *pi;
	int type;
	int length;
	int size;

	size = tvb_reported_length_remaining (tvb, offset);
	if (size < 4)
	{
		/* This should never happen, because `dissect_collectd' checks
		 * for this condition already. */
		return (-1);
	}

	type   = tvb_get_ntohs(tvb, offset);
	length = tvb_get_ntohs(tvb, offset + 2);

	pt = proto_tree_add_subtree_format(tree_root, tvb, offset, length,
				  ett_collectd_string, &pi, "collectd %s segment: ",
				  val_to_str_const (type, part_names, "UNKNOWN"));

	if (length > size)
	{
		proto_item_append_text(pt, "Length = %i <BAD>", length);
		expert_add_info_format(pinfo, pt, &ei_collectd_invalid_length,
					"String part with invalid part length: "
					"Part is longer than rest of package.");
		return (-1);
	}

	*ret_offset = offset + 4;
	*ret_length = length - 4;

	proto_tree_add_uint (pt, hf_collectd_type, tvb, offset, 2, type);
	proto_tree_add_uint (pt, hf_collectd_length, tvb, offset + 2, 2, length);
	proto_tree_add_item_ret_string (pt, type_hf, tvb, *ret_offset, *ret_length, ENC_ASCII, pinfo->pool, ret_string);

	proto_item_append_text(pt, "\"%s\"", *ret_string);

	if (ret_item != NULL)
		*ret_item = pi;

	return 0;
} /* int dissect_collectd_string */

static int
dissect_collectd_integer (tvbuff_t *tvb, packet_info *pinfo, int type_hf,
			  int offset, int *ret_offset, uint64_t *ret_value,
			  proto_tree *tree_root, proto_item **ret_item)
{
	proto_tree *pt;
	proto_item *pi;
	int type;
	int length;
	int size;

	size = tvb_reported_length_remaining (tvb, offset);
	if (size < 4)
	{
		/* This should never happen, because `dissect_collectd' checks
		 * for this condition already. */
		return (-1);
	}

	type   = tvb_get_ntohs(tvb, offset);
	length = tvb_get_ntohs(tvb, offset + 2);

	if (size < 12)
	{
		pt = proto_tree_add_subtree_format(tree_root, tvb, offset, -1,
					  ett_collectd_integer, NULL, "collectd %s segment: <BAD>",
					  val_to_str_const (type, part_names, "UNKNOWN"));

		proto_tree_add_uint (pt, hf_collectd_type, tvb, offset, 2,
				     type);
		proto_tree_add_uint (pt, hf_collectd_length, tvb, offset + 2, 2,
				     length);
		proto_tree_add_expert_format(pt, pinfo, &ei_collectd_garbage, tvb, offset + 4, -1,
					  "Garbage at end of packet: Length = %i <BAD>",
					  size - 4);

		return (-1);
	}

	if (length != 12)
	{
		pt = proto_tree_add_subtree_format(tree_root, tvb, offset, -1,
					  ett_collectd_integer, &pi, "collectd %s segment: <BAD>",
					  val_to_str_const (type, part_names, "UNKNOWN"));

		proto_tree_add_uint (pt, hf_collectd_type, tvb, offset, 2,
				     type);
		pi = proto_tree_add_uint (pt, hf_collectd_length, tvb,
					  offset + 2, 2, length);
		expert_add_info_format(pinfo, pi, &ei_collectd_invalid_length,
					"Invalid length field for an integer part.");

		return (-1);
	}

	*ret_offset = offset + 4;
	*ret_value = tvb_get_ntoh64 (tvb, offset + 4);

	/* Convert the version 4.* time format to the version 5.* time format. */
	if ((type == TYPE_TIME) || (type == TYPE_INTERVAL))
		*ret_value *= 1073741824;

	/* Create an entry in the protocol tree for this part. The value is
	 * printed depending on the "type" variable: TIME{,_HR} as absolute
	 * time, INTERVAL{,_HR} as relative time, uint64 otherwise. */
	if ((type == TYPE_TIME) || (type == TYPE_TIME_HR))
	{
		nstime_t nstime;
		char *strtime;

		nstime = collectd_time_to_nstime (*ret_value);
		strtime = abs_time_to_str (pinfo->pool, &nstime, ABSOLUTE_TIME_LOCAL, /* show_zone = */ true);
		pt = proto_tree_add_subtree_format(tree_root, tvb, offset, length,
					  ett_collectd_integer, &pi, "collectd %s segment: %s",
					  val_to_str_const (type, part_names, "UNKNOWN"),
					  STR_NONNULL (strtime));
	}
	else if ((type == TYPE_INTERVAL) || (type == TYPE_INTERVAL_HR))
	{
		nstime_t nstime;
		char *strtime;

		nstime = collectd_time_to_nstime (*ret_value);
		strtime = rel_time_to_str (pinfo->pool, &nstime);
		pt = proto_tree_add_subtree_format(tree_root, tvb, offset, length,
					  ett_collectd_integer, &pi, "collectd %s segment: %s",
					  val_to_str_const (type, part_names, "UNKNOWN"),
					  strtime);
	}
	else
	{
		pt = proto_tree_add_subtree_format(tree_root, tvb, offset, length,
					  ett_collectd_integer, &pi, "collectd %s segment: %"PRIu64,
					  val_to_str_const (type, part_names, "UNKNOWN"),
					  *ret_value);
	}

	if (ret_item != NULL)
		*ret_item = pi;

	proto_tree_add_uint (pt, hf_collectd_type, tvb, offset, 2, type);
	proto_tree_add_uint (pt, hf_collectd_length, tvb, offset + 2, 2,
			     length);
	if ((type == TYPE_TIME) || (type == TYPE_INTERVAL)
	    || (type == TYPE_TIME_HR) || (type == TYPE_INTERVAL_HR))
	{
		nstime_t nstime;

		nstime = collectd_time_to_nstime (*ret_value);
		proto_tree_add_time (pt, type_hf, tvb, offset + 4, 8, &nstime);
	}
	else
	{
		proto_tree_add_item (pt, type_hf, tvb, offset + 4, 8, ENC_BIG_ENDIAN);
	}

	return 0;
} /* int dissect_collectd_integer */

static void
dissect_collectd_values(tvbuff_t *tvb, int msg_off, int val_cnt,
			proto_tree *collectd_tree)
{
	proto_tree *values_tree, *value_tree;
	int i;

	values_tree = proto_tree_add_subtree_format(collectd_tree, tvb, msg_off + 6, val_cnt * 9,
				  ett_collectd_value, NULL, "%d value%s", val_cnt,
				  plurality (val_cnt, "", "s"));

	for (i = 0; i < val_cnt; i++)
	{
		int value_offset;

		int value_type_offset;
		uint8_t value_type;

		/* Calculate the offsets of the type byte and the actual value. */
		value_offset = msg_off + 6
				+ val_cnt  /* value types */
				+ (i * 8); /* previous values */

		value_type_offset = msg_off + 6 + i;
		value_type = tvb_get_uint8 (tvb, value_type_offset);

		switch (value_type) {
		case TYPE_VALUE_COUNTER:
		{
			uint64_t val64;

			val64 = tvb_get_ntoh64 (tvb, value_offset);
			value_tree = proto_tree_add_subtree_format(values_tree, tvb, msg_off + 6,
						  val_cnt * 9, ett_collectd_valinfo, NULL,
						  "Counter: %"PRIu64, val64);

			proto_tree_add_item (value_tree, hf_collectd_val_type,
					     tvb, value_type_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item (value_tree,
					     hf_collectd_val_counter, tvb,
					     value_offset, 8, ENC_BIG_ENDIAN);
			break;
		}

		case TYPE_VALUE_GAUGE:
		{
			double val;

			val = tvb_get_letohieee_double (tvb, value_offset);
			value_tree = proto_tree_add_subtree_format(values_tree, tvb, msg_off + 6,
						  val_cnt * 9, ett_collectd_valinfo, NULL,
						  "Gauge: %g", val);

			proto_tree_add_item (value_tree, hf_collectd_val_type,
					     tvb, value_type_offset, 1, ENC_BIG_ENDIAN);
			/* Set the `little endian' flag to true here, because
			 * collectd stores doubles in x86 representation. */
			proto_tree_add_item (value_tree, hf_collectd_val_gauge,
					     tvb, value_offset, 8, ENC_LITTLE_ENDIAN);
			break;
		}

		case TYPE_VALUE_DERIVE:
		{
			int64_t val64;

			val64 = tvb_get_ntoh64 (tvb, value_offset);
			value_tree = proto_tree_add_subtree_format(values_tree, tvb, msg_off + 6,
						  val_cnt * 9, ett_collectd_valinfo, NULL,
						  "Derive: %"PRIi64, val64);

			proto_tree_add_item (value_tree, hf_collectd_val_type,
					     tvb, value_type_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item (value_tree,
					     hf_collectd_val_derive, tvb,
					     value_offset, 8, ENC_BIG_ENDIAN);
			break;
		}

		case TYPE_VALUE_ABSOLUTE:
		{
			uint64_t val64;

			val64 = tvb_get_ntoh64 (tvb, value_offset);
			value_tree = proto_tree_add_subtree_format(values_tree, tvb, msg_off + 6,
						  val_cnt * 9, ett_collectd_valinfo, NULL,
						  "Absolute: %"PRIu64, val64);

			proto_tree_add_item (value_tree, hf_collectd_val_type,
					     tvb, value_type_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item (value_tree,
					     hf_collectd_val_absolute, tvb,
					     value_offset, 8, ENC_BIG_ENDIAN);
			break;
		}

		default:
		{
			uint64_t val64;

			val64 = tvb_get_ntoh64 (tvb, value_offset);
			value_tree = proto_tree_add_subtree_format(values_tree, tvb, msg_off + 6,
						  val_cnt * 9, ett_collectd_valinfo, NULL,
						  "Unknown: %"PRIx64,
						  val64);

			proto_tree_add_item (value_tree, hf_collectd_val_type,
					     tvb, value_type_offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item (value_tree, hf_collectd_val_unknown,
					     tvb, value_offset, 8, ENC_BIG_ENDIAN);
			break;
		}
		} /* switch (value_type) */
	} /* for (i = 0; i < val_cnt; i++) */
} /* void dissect_collectd_values */

static int
dissect_collectd_part_values (tvbuff_t *tvb, packet_info *pinfo, int offset,
			      value_data_t *vdispatch, proto_tree *tree_root)
{
	proto_tree *pt;
	proto_item *pi;
	int type;
	int length;
	int size;
	int values_count;
	int corrected_values_count;

	size = tvb_reported_length_remaining (tvb, offset);
	if (size < 4)
	{
		/* This should never happen, because `dissect_collectd' checks
		 * for this condition already. */
		return (-1);
	}

	type   = tvb_get_ntohs (tvb, offset);
	length = tvb_get_ntohs (tvb, offset + 2);

	if (size < 15)
	{
		pt = proto_tree_add_subtree_format(tree_root, tvb, offset, -1,
					  ett_collectd_part_value, NULL, "collectd %s segment: <BAD>",
					  val_to_str_const (type, part_names, "UNKNOWN"));

		proto_tree_add_uint (pt, hf_collectd_type, tvb, offset, 2, type);
		proto_tree_add_uint (pt, hf_collectd_length, tvb, offset + 2, 2,
				     length);
		proto_tree_add_expert_format(pt, pinfo, &ei_collectd_garbage, tvb, offset + 4, -1,
					  "Garbage at end of packet: Length = %i <BAD>",
					  size - 4);
		return (-1);
	}

	if ((length < 15) || ((length % 9) != 6))
	{
		pt = proto_tree_add_subtree_format(tree_root, tvb, offset, -1,
					  ett_collectd_part_value, &pi, "collectd %s segment: <BAD>",
					  val_to_str_const (type, part_names, "UNKNOWN"));

		proto_tree_add_uint (pt, hf_collectd_type, tvb, offset, 2, type);
		pi = proto_tree_add_uint (pt, hf_collectd_length, tvb,
					  offset + 2, 2, length);
		expert_add_info_format(pinfo, pi, &ei_collectd_invalid_length,
					"Invalid length field for a values part.");

		return (-1);
	}

	values_count = tvb_get_ntohs (tvb, offset + 4);
	corrected_values_count = (length - 6) / 9;

	if (values_count != corrected_values_count)
	{
		pt = proto_tree_add_subtree_format(tree_root, tvb, offset, length,
		      ett_collectd_part_value, NULL,
					  "collectd %s segment: %d (%d) value%s <BAD>",
					  val_to_str_const (type, part_names, "UNKNOWN"),
					  values_count, corrected_values_count,
					  plurality(values_count, "", "s"));
	}
	else
	{
		pt = proto_tree_add_subtree_format(tree_root, tvb, offset, length,
		      ett_collectd_part_value, NULL,
					  "collectd %s segment: %d value%s",
					  val_to_str_const (type, part_names, "UNKNOWN"),
					  values_count,
					  plurality(values_count, "", "s"));
	}

	proto_tree_add_uint (pt, hf_collectd_type, tvb, offset, 2, type);
	proto_tree_add_uint (pt, hf_collectd_length, tvb, offset + 2, 2, length);

	pi = proto_tree_add_item (pt, hf_collectd_data_valcnt, tvb,
				  offset + 4, 2, ENC_BIG_ENDIAN);
	if (values_count != corrected_values_count)
		expert_add_info(pinfo, pi, &ei_collectd_data_valcnt);

	values_count = corrected_values_count;

	dissect_collectd_values (tvb, offset, values_count, pt);
	collectd_proto_tree_add_assembled_metric (tvb, offset + 6, length - 6,
			vdispatch, pt);

	return 0;
} /* void dissect_collectd_part_values */

static int
dissect_collectd_signature (tvbuff_t *tvb, packet_info *pinfo,
			    int offset, proto_tree *tree_root)
{
	proto_item *pi;
	proto_tree *pt;
	int type;
	int length;
	int size;
	const uint8_t *username;

	size = tvb_reported_length_remaining (tvb, offset);
	if (size < 4)
	{
		/* This should never happen, because `dissect_collectd' checks
		 * for this condition already. */
		return (-1);
	}

	type   = tvb_get_ntohs (tvb, offset);
	length = tvb_get_ntohs (tvb, offset + 2);

	if (size < 36) /* remaining packet size too small for signature */
	{
		pt = proto_tree_add_subtree_format(tree_root, tvb, offset, -1,
					  ett_collectd_signature, NULL, "collectd %s segment: <BAD>",
					  val_to_str_const (type, part_names, "UNKNOWN"));

		proto_tree_add_uint (pt, hf_collectd_type, tvb, offset, 2, type);
		proto_tree_add_uint (pt, hf_collectd_length, tvb, offset + 2, 2,
				     length);
		proto_tree_add_expert_format(pt, pinfo, &ei_collectd_garbage, tvb, offset + 4, -1,
					  "Garbage at end of packet: Length = %i <BAD>",
					  size - 4);
		return (-1);
	}

	if (length < 36)
	{
		pt = proto_tree_add_subtree_format(tree_root, tvb, offset, -1,
					  ett_collectd_signature, NULL, "collectd %s segment: <BAD>",
					  val_to_str_const (type, part_names, "UNKNOWN"));

		proto_tree_add_uint (pt, hf_collectd_type, tvb, offset, 2, type);
		pi = proto_tree_add_uint (pt, hf_collectd_length, tvb,
					  offset + 2, 2, length);
		expert_add_info_format(pinfo, pi, &ei_collectd_invalid_length,
					"Invalid length field for a signature part.");

		return (-1);
	}

	pt = proto_tree_add_subtree_format(tree_root, tvb, offset, length,
				  ett_collectd_signature, NULL, "collectd %s segment: HMAC-SHA-256",
				  val_to_str_const (type, part_names, "UNKNOWN"));

	proto_tree_add_uint (pt, hf_collectd_type, tvb, offset, 2, type);
	proto_tree_add_uint (pt, hf_collectd_length, tvb, offset + 2, 2,
			     length);
	// proto_tree_add_checksum adds two ti but only returns the first,
	// which makes it hard to move the username after the second item,
	// so extract the string directly, then add a username item later.
	//
	// XXX - Are we sure this string is ASCII? Probably UTF-8 these days.
	// The same goes for all the other strings in the protocol.
	username = tvb_get_string_enc(pinfo->pool, tvb, offset + 36, length - 36, ENC_ASCII);
	uint8_t *hash = NULL;
	gcry_md_hd_t *md_hd = collectd_get_md(username);
	if (md_hd) {
		uint8_t *buffer = tvb_memdup(pinfo->pool, tvb, offset + 36, tvb_reported_length_remaining(tvb, offset + 36));
		gcry_md_write(*md_hd, buffer, size - 36);
		hash = gcry_md_read(*md_hd, GCRY_MD_SHA256);
		if (hash == NULL) {
			ws_debug("gcry_md_read failed");
		}
	}
	proto_tree_add_checksum_bytes(pt, tvb, offset + 4, hf_collectd_data_sighash,
		hf_collectd_data_sighash_status, &ei_collectd_sighash_bad, pinfo,
		hash, 32, hash ? PROTO_CHECKSUM_VERIFY : PROTO_CHECKSUM_NO_FLAGS);
	proto_tree_add_item(pt, hf_collectd_data_username, tvb, offset + 36, length - 36, ENC_ASCII);
	return 0;
} /* int dissect_collectd_signature */

/* We recurse after decrypting. In practice encryption is always the first
 * part and contains everything, so we could avoid recursion by checking
 * for it at the start of dissect_collect and not try to decrypt encrypted
 * parts in other positions. */
static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_collectd_parts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_);

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_collectd_encrypted(tvbuff_t *tvb, packet_info *pinfo,
			   int offset, proto_tree *tree_root)
{
	proto_item *pi;
	proto_tree *pt;
	int type;
	int length;
	int size;
	int username_length;
	const uint8_t *username;

	size = tvb_reported_length_remaining (tvb, offset);
	if (size < 4)
	{
		/* This should never happen, because `dissect_collectd' checks
		 * for this condition already. */
		return (-1);
	}

	type   = tvb_get_ntohs (tvb, offset);
	length = tvb_get_ntohs (tvb, offset + 2);

	if (size < 42) /* remaining packet size too small for signature */
	{
		pt = proto_tree_add_subtree_format(tree_root, tvb, offset, -1,
					  ett_collectd_encryption, NULL, "collectd %s segment: <BAD>",
					  val_to_str_const (type, part_names, "UNKNOWN"));

		proto_tree_add_uint (pt, hf_collectd_type, tvb, offset, 2, type);
		proto_tree_add_uint (pt, hf_collectd_length, tvb, offset + 2, 2,
				     length);
		proto_tree_add_expert_format(pt, pinfo, &ei_collectd_garbage, tvb, offset + 4, -1,
					  "Garbage at end of packet: Length = %i <BAD>",
					  size - 4);
		return (-1);
	}

	if (length < 42)
	{
		pt = proto_tree_add_subtree_format(tree_root, tvb, offset, -1,
					  ett_collectd_encryption, NULL, "collectd %s segment: <BAD>",
					  val_to_str_const (type, part_names, "UNKNOWN"));

		proto_tree_add_uint (pt, hf_collectd_type, tvb, offset, 2, type);
		pi = proto_tree_add_uint (pt, hf_collectd_length, tvb,
					  offset + 2, 2, length);
		expert_add_info_format(pinfo, pi, &ei_collectd_invalid_length,
					"Invalid length field for an encryption part.");

		return (-1);
	}

	username_length = tvb_get_ntohs (tvb, offset + 4);
	if (username_length > (length - 42))
	{
		pt = proto_tree_add_subtree_format(tree_root, tvb, offset, -1,
					  ett_collectd_encryption, NULL, "collectd %s segment: <BAD>",
					  val_to_str_const (type, part_names, "UNKNOWN"));

		proto_tree_add_uint (pt, hf_collectd_type, tvb, offset, 2, type);
		proto_tree_add_uint (pt, hf_collectd_length, tvb,
				     offset + 2, 2, length);
		pi = proto_tree_add_uint (pt, hf_collectd_data_username_len, tvb,
					  offset + 4, 2, length);
		expert_add_info_format(pinfo, pi, &ei_collectd_invalid_length,
					"Invalid username length field for an encryption part.");

		return (-1);
	}

	pt = proto_tree_add_subtree_format(tree_root, tvb, offset, length,
				  ett_collectd_encryption, NULL, "collectd %s segment: AES-256",
				  val_to_str_const (type, part_names, "UNKNOWN"));

	proto_tree_add_uint(pt, hf_collectd_type, tvb, offset, 2, type);
	offset += 2;
	proto_tree_add_uint(pt, hf_collectd_length, tvb, offset, 2, length);
	offset += 2;
	proto_tree_add_uint(pt, hf_collectd_data_username_len, tvb, offset, 2, username_length);
	offset += 2;
	proto_tree_add_item_ret_string(pt, hf_collectd_data_username, tvb, offset, username_length, ENC_ASCII, pinfo->pool, &username);
	offset += username_length;

	proto_tree_add_item(pt, hf_collectd_data_initvec, tvb,
			     offset, 16, ENC_NA);
	offset += 16;

	int buffer_size = length - (22 + username_length);
	// Must be >= 20 (checked above)
	proto_tree_add_item(pt, hf_collectd_data_encrypted, tvb,
			    offset,
			    buffer_size, ENC_NA);
	gcry_cipher_hd_t *cipher_hd;
	cipher_hd = collectd_get_cipher(username);
	if (cipher_hd) {
		gcry_error_t err;
		uint8_t iv[16];
		tvb_memcpy(tvb, iv, offset - 16, 16);
		err = gcry_cipher_setiv(*cipher_hd, iv, 16);
		if (err != 0) {
			ws_debug("error setting key: %s", gcry_strerror(err));
			return 0; // Should there be another return code for this?
		}
		uint8_t *buffer = tvb_memdup(pinfo->pool, tvb, offset, buffer_size);
		err = gcry_cipher_decrypt(*cipher_hd, buffer, buffer_size, NULL, 0);
		if (err != 0) {
			ws_debug("gcry_cipher_decrypt failed: %s", gcry_strerror(err));
			return 0; // Should there be another return code for this?
		}
		tvbuff_t *decrypted_tvb = tvb_new_child_real_data(tvb, buffer, buffer_size, buffer_size);
		add_new_data_source(pinfo, decrypted_tvb, "Decrypted collectd");
		uint8_t hash[20];
		gcry_md_hash_buffer(GCRY_MD_SHA1, hash, buffer + 20, buffer_size - 20);
		proto_tree_add_checksum_bytes(pt, decrypted_tvb, 0, hf_collectd_data_sighash,
			hf_collectd_data_sighash_status, &ei_collectd_sighash_bad, pinfo,
			hash, 20, PROTO_CHECKSUM_VERIFY);
		if (tvb_memeql(decrypted_tvb, 0, hash, 20) == 0) {
			// We recurse here, but consumed 22 + username_len bytes
			// so we'll run out of packet before stack exhaustion.
			dissect_collectd_parts(tvb_new_subset_remaining(decrypted_tvb, 20), pinfo, tree_root, NULL);
		}
	}
	return 0;
} /* int dissect_collectd_encrypted */

static int
stats_account_string (wmem_allocator_t *scope, string_counter_t **ret_list, const char *new_value)
{
	string_counter_t *entry;

	if (ret_list == NULL)
		return (-1);

	if (new_value == NULL)
		new_value = "(null)";

	for (entry = *ret_list; entry != NULL; entry = entry->next)
		if (strcmp (new_value, entry->string) == 0)
		{
			entry->count++;
			return 0;
		}

	entry = (string_counter_t *)wmem_alloc0 (scope, sizeof (*entry));
	entry->string = wmem_strdup (scope, new_value);
	entry->count = 1;
	entry->next = *ret_list;

	*ret_list = entry;

	return 0;
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_collectd_parts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *collectd_tree, void* data _U_)
{
	int offset;
	int size;
	value_data_t vdispatch;
	notify_data_t ndispatch;
	int status;
	proto_item *pi;
	proto_tree *pt;

	memset(&vdispatch, '\0', sizeof(vdispatch));
	memset(&ndispatch, '\0', sizeof(ndispatch));

	tap_data_t *tap_data = p_get_proto_data(pinfo->pool, pinfo, proto_collectd, TAP_DATA_KEY);
	column_data_t *col_data = p_get_proto_data(pinfo->pool, pinfo, proto_collectd, COL_DATA_KEY);

	status = 0;
	offset = 0;
	size = tvb_reported_length(tvb);
	while ((size > 0) && (status == 0))
	{
		int part_type;
		int part_length;

		/* Check if there are at least four bytes left first.
		 * Four bytes are used to read the type and the length
		 * of the next part. If there's less, there's some garbage
		 * at the end of the packet. */
		if (size < 4)
		{
			proto_tree_add_expert_format(collectd_tree, pinfo, &ei_collectd_garbage, tvb,
						  offset, -1,
						  "Garbage at end of packet: Length = %i <BAD>",
						  size);
			col_data->pkt_errors++;
			break;
		}

		/* dissect a message entry */
		part_type = tvb_get_ntohs (tvb, offset);
		part_length  = tvb_get_ntohs (tvb, offset + 2);

		/* Check if the length of the part is in the valid range. Don't
		 * confuse this with the above: Here we check the information
		 * provided in the packet.. */
		if ((part_length < 4) || (part_length > size))
		{
			pt = proto_tree_add_subtree_format(collectd_tree, tvb,
						  offset, part_length, ett_collectd_invalid_length, NULL,
						  "collectd %s segment: Length = %i <BAD>",
						  val_to_str_const (part_type, part_names, "UNKNOWN"),
						  part_length);

			proto_tree_add_uint (pt, hf_collectd_type, tvb, offset,
					     2, part_type);
			pi = proto_tree_add_uint (pt, hf_collectd_length, tvb,
					     offset + 2, 2, part_length);

			if (part_length < 4)
				expert_add_info_format(pinfo, pi, &ei_collectd_invalid_length,
							"Bad part length: Is %i, expected at least 4",
							part_length);
			else
				expert_add_info_format(pinfo, pi, &ei_collectd_invalid_length,
							"Bad part length: Larger than remaining packet size.");

			col_data->pkt_errors++;
			break;
		}

		/* The header information looks okay, let's tend to the actual
		 * payload in this part. */
		switch (part_type) {
		case TYPE_HOST:
		{
			status = dissect_collectd_string (tvb, pinfo,
					hf_collectd_data_host,
					offset,
					&vdispatch.host_off,
					&vdispatch.host_len,
					&vdispatch.host,
					collectd_tree, /* item = */ NULL);
			if (status != 0)
				col_data->pkt_errors++;
			else
			{
				if (col_data->pkt_host == NULL)
					col_data->pkt_host = vdispatch.host;
				ndispatch.host_off = vdispatch.host_off;
				ndispatch.host_len = vdispatch.host_len;
				ndispatch.host = vdispatch.host;
			}

			break;
		}

		case TYPE_PLUGIN:
		{
			status = dissect_collectd_string (tvb, pinfo,
					hf_collectd_data_plugin,
					offset,
					&vdispatch.plugin_off,
					&vdispatch.plugin_len,
					&vdispatch.plugin,
					collectd_tree, /* item = */ NULL);
			if (status != 0)
				col_data->pkt_errors++;
			else
				col_data->pkt_plugins++;

			break;
		}

		case TYPE_PLUGIN_INSTANCE:
		{
			status = dissect_collectd_string (tvb, pinfo,
					hf_collectd_data_plugin_inst,
					offset,
					&vdispatch.plugin_instance_off,
					&vdispatch.plugin_instance_len,
					&vdispatch.plugin_instance,
					collectd_tree, /* item = */ NULL);
			if (status != 0)
				col_data->pkt_errors++;

			break;
		}

		case TYPE_TYPE:
		{
			status = dissect_collectd_string (tvb, pinfo,
					hf_collectd_data_type,
					offset,
					&vdispatch.type_off,
					&vdispatch.type_len,
					&vdispatch.type,
					collectd_tree, /* item = */ NULL);
			if (status != 0)
				col_data->pkt_errors++;

			break;
		}

		case TYPE_TYPE_INSTANCE:
		{
			status = dissect_collectd_string (tvb, pinfo,
					hf_collectd_data_type_inst,
					offset,
					&vdispatch.type_instance_off,
					&vdispatch.type_instance_len,
					&vdispatch.type_instance,
					collectd_tree, /* item = */ NULL);
			if (status != 0)
				col_data->pkt_errors++;

			break;
		}

		case TYPE_TIME:
		case TYPE_TIME_HR:
		{
			pi = NULL;
			status = dissect_collectd_integer (tvb, pinfo,
					hf_collectd_data_time,
					offset,
					&vdispatch.time_off,
					&vdispatch.time_value,
					collectd_tree, &pi);
			if (status != 0)
				col_data->pkt_errors++;

			break;
		}

		case TYPE_INTERVAL:
		case TYPE_INTERVAL_HR:
		{
			status = dissect_collectd_integer (tvb, pinfo,
					hf_collectd_data_interval,
					offset,
					&vdispatch.interval_off,
					&vdispatch.interval,
					collectd_tree, /* item = */ NULL);
			if (status != 0)
				col_data->pkt_errors++;

			break;
		}

		case TYPE_VALUES:
		{
			status = dissect_collectd_part_values (tvb, pinfo,
					offset,
					&vdispatch,
					collectd_tree);
			if (status != 0)
				col_data->pkt_errors++;
			else
				col_data->pkt_values++;

			tap_data->values_num++;
			stats_account_string (pinfo->pool,
					      &tap_data->hosts,
					      vdispatch.host);
			stats_account_string (pinfo->pool,
					      &tap_data->plugins,
					      vdispatch.plugin);
			stats_account_string (pinfo->pool,
					      &tap_data->types,
					      vdispatch.type);

			break;
		}

		case TYPE_MESSAGE:
		{
			pi = NULL;
			status = dissect_collectd_string (tvb, pinfo,
					hf_collectd_data_message,
					offset,
					&ndispatch.message_off,
					&ndispatch.message_len,
					&ndispatch.message,
					collectd_tree, &pi);
			if (status != 0)
			{
				col_data->pkt_errors++;
				break;
			}
			col_data->pkt_messages++;

			pt = proto_item_get_subtree (pi);

			collectd_proto_tree_add_assembled_notification (tvb,
					offset + 4, part_length - 1,
					&ndispatch, pt);

			break;
		}

		case TYPE_SEVERITY:
		{
			pi = NULL;
			status = dissect_collectd_integer (tvb, pinfo,
					hf_collectd_data_severity,
					offset,
					&ndispatch.severity_off,
					&ndispatch.severity,
					collectd_tree, &pi);
			if (status != 0)
				col_data->pkt_errors++;
			else
			{
				proto_item_set_text (pi,
						"collectd SEVERITY segment: "
						"%s (%"PRIu64")",
						val64_to_str_const (ndispatch.severity, severity_names, "UNKNOWN"),
						ndispatch.severity);
			}

			break;
		}

		case TYPE_SIGN_SHA256:
		{
			status = dissect_collectd_signature (tvb, pinfo,
							     offset,
							     collectd_tree);
			if (status != 0)
				col_data->pkt_errors++;

			break;
		}

		case TYPE_ENCR_AES256:
		{
			status = dissect_collectd_encrypted (tvb, pinfo,
					offset, collectd_tree);
			if (status != 0)
				col_data->pkt_errors++;

			break;
		}

		default:
		{
			col_data->pkt_unknown++;
			pt = proto_tree_add_subtree_format(collectd_tree, tvb,
						  offset, part_length, ett_collectd_unknown, NULL,
						  "collectd %s segment: %i bytes",
						  val_to_str_const(part_type, part_names, "UNKNOWN"),
						  part_length);

			pi = proto_tree_add_uint (pt, hf_collectd_type, tvb,
						  offset, 2, part_type);
			proto_tree_add_uint (pt, hf_collectd_length, tvb,
						  offset + 2, 2, part_length);
			proto_tree_add_item (pt, hf_collectd_data, tvb,
					     offset + 4, part_length - 4, ENC_NA);

			expert_add_info_format(pinfo, pi, &ei_collectd_type,
						"Unknown part type %#x. Cannot decode data.",
						part_type);
		}
		} /* switch (part_type) */

		offset  += part_length;
		size    -= part_length;
	} /* while ((size > 4) && (status == 0)) */

	return tvb_captured_length(tvb);
}

static int
dissect_collectd (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *pi;
	proto_tree *collectd_tree;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "collectd");
	col_clear(pinfo->cinfo, COL_INFO);

	tap_data_t *tap_data = wmem_new0(pinfo->pool, tap_data_t);
	p_add_proto_data(pinfo->pool, pinfo, proto_collectd, TAP_DATA_KEY, tap_data);

	column_data_t *col_data = wmem_new0(pinfo->pool, column_data_t);
	p_add_proto_data(pinfo->pool, pinfo, proto_collectd, COL_DATA_KEY, col_data);

	/* create the collectd protocol tree */
	pi = proto_tree_add_item(tree, proto_collectd, tvb, 0, -1, ENC_NA);
	collectd_tree = proto_item_add_subtree(pi, ett_collectd);

	dissect_collectd_parts(tvb, pinfo, collectd_tree, data);

	/* Put summary information in columns */
	col_add_fstr(pinfo->cinfo, COL_INFO, "Host=%s, %2d value%s for %d plugin%s %d message%s",
			col_data->pkt_host,
			col_data->pkt_values, plurality(col_data->pkt_values, " ", "s"),
			col_data->pkt_plugins, plurality(col_data->pkt_plugins, ", ", "s,"),
			col_data->pkt_messages, plurality(col_data->pkt_messages, ", ", "s"));

	if (col_data->pkt_unknown) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %d unknown",
			col_data->pkt_unknown);
	}

	if (col_data->pkt_errors) {
		col_add_fstr(pinfo->cinfo, COL_INFO, ", %d error%s",
			col_data->pkt_errors, plurality(col_data->pkt_errors, "", "s"));
	}

	/* Dispatch tap data. */
	tap_queue_packet(tap_collectd, pinfo, tap_data);

	return tvb_captured_length(tvb);
} /* void dissect_collectd */

void proto_register_collectd(void)
{
	expert_module_t* expert_collectd;
	module_t *collectd_module;

	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_collectd_type,
			{ "Type", "collectd.type", FT_UINT16, BASE_HEX,
				VALS(part_names), 0x0, NULL, HFILL }
		},
		{ &hf_collectd_length,
			{ "Length", "collectd.len", FT_UINT16, BASE_DEC,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_data,
			{ "Payload", "collectd.data", FT_BYTES, BASE_NONE,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_data_host,
			{ "Host name", "collectd.data.host", FT_STRING, BASE_NONE,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_data_interval,
			{ "Interval", "collectd.data.interval", FT_RELATIVE_TIME, BASE_NONE,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_data_time,
			{ "Timestamp", "collectd.data.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_data_plugin,
			{ "Plugin", "collectd.data.plugin", FT_STRING, BASE_NONE,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_data_plugin_inst,
			{ "Plugin instance", "collectd.data.plugin.inst", FT_STRING, BASE_NONE,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_data_type,
			{ "Type", "collectd.data.type", FT_STRING, BASE_NONE,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_data_type_inst,
			{ "Type instance", "collectd.data.type.inst", FT_STRING, BASE_NONE,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_data_valcnt,
			{ "Value count", "collectd.data.valcnt", FT_UINT16, BASE_DEC,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_val_type,
			{ "Value type", "collectd.val.type", FT_UINT8, BASE_HEX,
				VALS(valuetypenames), 0x0, NULL, HFILL }
		},
		{ &hf_collectd_val_counter,
			{ "Counter value", "collectd.val.counter", FT_UINT64, BASE_DEC,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_val_gauge,
			{ "Gauge value", "collectd.val.gauge", FT_DOUBLE, BASE_NONE,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_val_derive,
			{ "Derive value", "collectd.val.derive", FT_INT64, BASE_DEC,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_val_absolute,
			{ "Absolute value", "collectd.val.absolute", FT_UINT64, BASE_DEC,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_val_unknown,
			{ "Value of unknown type", "collectd.val.unknown", FT_UINT64, BASE_HEX,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_data_severity,
			{ "Severity", "collectd.data.severity", FT_UINT64, BASE_HEX | BASE_VAL64_STRING,
				VALS64(severity_names),
				0x0, NULL, HFILL }
		},
		{ &hf_collectd_data_message,
			{ "Message", "collectd.data.message", FT_STRING, BASE_NONE,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_data_sighash,
			{ "Signature", "collectd.data.sighash", FT_BYTES, BASE_NONE,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_data_sighash_status,
			{ "Signature", "collectd.data.sighash.status", FT_UINT8, BASE_NONE,
				VALS(proto_checksum_vals), 0x0, NULL, HFILL }
		},
		{ &hf_collectd_data_initvec,
			{ "Init vector", "collectd.data.initvec", FT_BYTES, BASE_NONE,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_data_username_len,
			{ "Username length", "collectd.data.username_length", FT_UINT16, BASE_DEC,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_data_username,
			{ "Username", "collectd.data.username", FT_STRING, BASE_NONE,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_collectd_data_encrypted,
			{ "Encrypted data", "collectd.data.encrypted", FT_BYTES, BASE_NONE,
				NULL, 0x0, NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_collectd,
		&ett_collectd_string,
		&ett_collectd_integer,
		&ett_collectd_part_value,
		&ett_collectd_value,
		&ett_collectd_valinfo,
		&ett_collectd_signature,
		&ett_collectd_encryption,
		&ett_collectd_dispatch,
		&ett_collectd_invalid_length,
		&ett_collectd_unknown,
	};

	static ei_register_info ei[] = {
		{ &ei_collectd_invalid_length, { "collectd.invalid_length", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
		{ &ei_collectd_garbage, { "collectd.garbage", PI_MALFORMED, PI_ERROR, "Garbage at end of packet", EXPFILL }},
		{ &ei_collectd_data_valcnt, { "collectd.data.valcnt.mismatch", PI_MALFORMED, PI_WARN, "Number of values and length of part do not match. Assuming length is correct.", EXPFILL }},
		{ &ei_collectd_type, { "collectd.type.unknown", PI_UNDECODED, PI_NOTE, "Unknown part type", EXPFILL }},
		{ &ei_collectd_sighash_bad, { "collectd.data.sighash.bad", PI_CHECKSUM, PI_ERROR, "Bad hash", EXPFILL }},
	};

	/* Register the protocol name and description */
	proto_collectd = proto_register_protocol("collectd network data", "collectd", "collectd");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_collectd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_collectd = expert_register_protocol(proto_collectd);
	expert_register_field_array(expert_collectd, ei, array_length(ei));

	collectd_module = prefs_register_protocol(proto_collectd, NULL);

	static uat_field_t collectd_uat_flds[] = {
		UAT_FLD_CSTRING(uat_collectd_records, username, "Username", "Username"),
		UAT_FLD_CSTRING(uat_collectd_records, password, "Password", "Password"),
		UAT_END_FIELDS
	};

	collectd_uat = uat_new("collectd Authentication",
		sizeof(uat_collectd_record_t),
		"collectd",
		true,
		&uat_collectd_records,
		&num_uat,
		UAT_AFFECTS_DISSECTION,
		NULL,
		uat_collectd_record_copy_cb,
		uat_collectd_record_update_cb,
		uat_collectd_record_free_cb,
		NULL,
		NULL,
		collectd_uat_flds);

	prefs_register_uat_preference(collectd_module, "auth", "Authentication", "A table of user credentials for verifying signatures and decrypting encrypted packets", collectd_uat);

	tap_collectd = register_tap ("collectd");

	collectd_handle = register_dissector("collectd", dissect_collectd, proto_collectd);
}

void proto_reg_handoff_collectd (void)
{
	dissector_add_uint_with_preference("udp.port", UDP_PORT_COLLECTD, collectd_handle);

	collectd_stats_tree_register ();
} /* void proto_reg_handoff_collectd */

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

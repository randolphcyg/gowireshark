/* packet-who.c
 * Routines for who protocol (see man rwhod)
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>


/*
 *
RWHOD(8)                 UNIX System Manager's Manual                 RWHOD(8)


     The messages sent and received, are of the form:

           struct  outmp {
0                   char    out_line[8];             tty name
8                   char    out_name[8];             user id
16                   long    out_time;               time on
           };

           struct  whod {
 0                   char    wd_vers;
 1                   char    wd_type;
 2                   char    wd_fill[2];
 4                   int     wd_sendtime;
 8                   int     wd_recvtime;
12                   char    wd_hostname[32];
44                   int     wd_loadav[3];
56                   int     wd_boottime;
60                   struct  whoent {
                           struct  outmp we_utmp;
(20 each)                  int     we_idle;
                   } wd_we[1024 / sizeof (struct whoent)];
           };
 *
 */

void proto_register_who(void);
void proto_reg_handoff_who(void);

static dissector_handle_t who_handle;

static int proto_who;
static int hf_who_vers;
static int hf_who_type;
static int hf_who_sendtime;
static int hf_who_recvtime;
static int hf_who_hostname;
static int hf_who_loadav_5;
static int hf_who_loadav_10;
static int hf_who_loadav_15;
static int hf_who_boottime;
static int hf_who_whoent;
static int hf_who_tty;
static int hf_who_uid;
static int hf_who_timeon;
static int hf_who_idle;

static int ett_who;
static int ett_whoent;

#define UDP_PORT_WHO    513

static void dissect_whoent(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree);

static int
dissect_who(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int		offset = 0;
	proto_tree	*who_tree;
	proto_item	*who_ti;
	uint8_t		*server_name;
	double		loadav_5 = 0.0, loadav_10 = 0.0, loadav_15 = 0.0;

	/* Summary information */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "WHO");
	col_clear(pinfo->cinfo, COL_INFO);

	who_ti = proto_tree_add_item(tree, proto_who, tvb, offset, -1, ENC_NA);
	who_tree = proto_item_add_subtree(who_ti, ett_who);

	proto_tree_add_item(who_tree, hf_who_vers, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(who_tree, hf_who_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* 2 filler bytes */
	offset += 2;

	if (tree) {
		proto_tree_add_item(who_tree, hf_who_sendtime, tvb, offset, 4,
		    ENC_TIME_SECS|ENC_BIG_ENDIAN);
	}
	offset += 4;

	if (tree) {
		proto_tree_add_item(who_tree, hf_who_recvtime, tvb, offset, 4,
		    ENC_TIME_SECS|ENC_BIG_ENDIAN);
	}
	offset += 4;

	server_name = tvb_get_stringzpad(pinfo->pool, tvb, offset, 32, ENC_ASCII|ENC_NA);
	proto_tree_add_string(who_tree, hf_who_hostname, tvb, offset, 32, server_name);
	offset += 32;

	loadav_5  = tvb_get_ntohl(tvb, offset) / 100.0;
	proto_tree_add_double(who_tree, hf_who_loadav_5, tvb, offset,
		    4, loadav_5);
	offset += 4;

	loadav_10 = tvb_get_ntohl(tvb, offset) / 100.0;
	proto_tree_add_double(who_tree, hf_who_loadav_10, tvb, offset,
		    4, loadav_10);
	offset += 4;

	loadav_15 = tvb_get_ntohl(tvb, offset) / 100.0;
	proto_tree_add_double(who_tree, hf_who_loadav_15, tvb, offset,
		    4, loadav_15);
	offset += 4;

	/* Summary information */
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %.02f %.02f %.02f",
				server_name, loadav_5, loadav_10, loadav_15);

	if (tree) {
		proto_tree_add_item(who_tree, hf_who_boottime, tvb, offset, 4,
		    ENC_TIME_SECS|ENC_BIG_ENDIAN);
		offset += 4;

		dissect_whoent(pinfo, tvb, offset, who_tree);
	}

	return tvb_captured_length(tvb);
}

/* The man page says that (1024 / sizeof(struct whoent)) is the maximum number
 * of whoent structures in the packet. */
#define SIZE_OF_WHOENT	24
#define MAX_NUM_WHOENTS	(1024 / SIZE_OF_WHOENT)

static void
dissect_whoent(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree	*whoent_tree = NULL;
	proto_item	*whoent_ti = NULL;
	int		line_offset = offset;
	uint8_t		*out_line;
	uint8_t		*out_name;
	int		whoent_num = 0;
	uint32_t		idle_secs; /* say that out loud... */

	while (tvb_reported_length_remaining(tvb, line_offset) > 0
	    && whoent_num < MAX_NUM_WHOENTS) {
		whoent_ti = proto_tree_add_item(tree, hf_who_whoent, tvb,
		    line_offset, SIZE_OF_WHOENT, ENC_NA);
		whoent_tree = proto_item_add_subtree(whoent_ti, ett_whoent);

		out_line = tvb_get_stringzpad(pinfo->pool, tvb, line_offset, 8, ENC_ASCII|ENC_NA);
		proto_tree_add_string(whoent_tree, hf_who_tty, tvb, line_offset,
		    8, out_line);
		line_offset += 8;

		out_name = tvb_get_stringzpad(pinfo->pool, tvb, line_offset, 8, ENC_ASCII|ENC_NA);
		proto_tree_add_string(whoent_tree, hf_who_uid, tvb, line_offset,
		    8, out_name);
		line_offset += 8;

		proto_tree_add_item(whoent_tree, hf_who_timeon, tvb,
		    line_offset, 4, ENC_TIME_SECS|ENC_BIG_ENDIAN);
		line_offset += 4;

		idle_secs = tvb_get_ntohl(tvb, line_offset);
		proto_tree_add_uint_format(whoent_tree, hf_who_idle, tvb,
		    line_offset, 4, idle_secs, "Idle: %s",
		    signed_time_secs_to_str(pinfo->pool, idle_secs));
		line_offset += 4;

		whoent_num++;
	}
}

void
proto_register_who(void)
{
	static hf_register_info hf[] = {
		{ &hf_who_vers,
		{ "Version",	"who.vers", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_type,
		{ "Type",	"who.type", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_sendtime,
		{ "Send Time",	"who.sendtime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_recvtime,
		{ "Receive Time", "who.recvtime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_hostname,
		{ "Hostname", "who.hostname", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_loadav_5,
		{ "Load Average Over Past  5 Minutes", "who.loadav_5", FT_DOUBLE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_loadav_10,
		{ "Load Average Over Past 10 Minutes", "who.loadav_10", FT_DOUBLE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_loadav_15,
		{ "Load Average Over Past 15 Minutes", "who.loadav_15", FT_DOUBLE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_boottime,
		{ "Boot Time", "who.boottime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_whoent,
		{ "Who utmp Entry", "who.entry", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_tty,
		{ "TTY Name", "who.tty", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_uid,
		{ "User ID", "who.uid", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_timeon,
		{ "Time On", "who.timeon", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_idle,
		{ "Time Idle", "who.idle", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_who,
		&ett_whoent,
	};

	proto_who = proto_register_protocol("Who", "WHO", "who");
	who_handle = register_dissector("who", dissect_who, proto_who);
	proto_register_field_array(proto_who, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_who(void)
{
	dissector_add_uint_with_preference("udp.port", UDP_PORT_WHO, who_handle);
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

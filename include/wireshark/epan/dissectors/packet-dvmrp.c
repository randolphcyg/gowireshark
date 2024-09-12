/* packet-dvmrp.c   2001 Ronnie Sahlberg <See AUTHORS for email>
 * Routines for IGMP/DVMRP packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
/*


			DVMRP	DVMRP
	code		v1	v3

	0x01		*	*
	0x02		*	*
	0x03		x
	0x04		x
	0x07			x
	0x08			x
	0x09			x


	* V3 has len>=8 and byte[6]==0xff and byte[7]==0x03


	DVMRP is defined in the following RFCs
	RFC1075 Version 1
	draft-ietf-idmr-dvmrp-v3-10.txt Version 3

	V1 and V3 can be distinguished by looking at bytes 6 and 7 in the
	IGMP/DVMRP header.
	If header[6]==0xff and header[7]==0x03 we have version 3.


	RFC1075 has typos in 3.12.2 and 3.12.4, see if you can spot them.
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/tfs.h>
#include "packet-igmp.h"

void proto_register_dvmrp(void);
void proto_reg_handoff_dvmrp(void);

static dissector_handle_t dvmrp_handle;

static int proto_dvmrp;
static int hf_version;
static int hf_type;
static int hf_code_v1;
static int hf_checksum;
static int hf_checksum_status;
static int hf_reserved;
static int hf_commands;
static int hf_command;
static int hf_count;
static int hf_afi;
static int hf_netmask;
static int hf_metric;
static int hf_dest_unr;
static int hf_split_horiz;
static int hf_infinity;
static int hf_daddr;
static int hf_maddr;
static int hf_hold;
static int hf_code_v3;
static int hf_capabilities;
static int hf_cap_leaf;
static int hf_cap_prune;
static int hf_cap_genid;
static int hf_cap_mtrace;
static int hf_cap_snmp;
static int hf_cap_netmask;
static int hf_min_ver;
static int hf_maj_ver;
static int hf_genid;
static int hf_route;
static int hf_saddr;
static int hf_life;
static int hf_local;
static int hf_threshold;
static int hf_flags;
static int hf_flag_tunnel;
static int hf_flag_srcroute;
static int hf_flag_down;
static int hf_flag_disabled;
static int hf_flag_querier;
static int hf_flag_leaf;
static int hf_ncount;
static int hf_neighbor;

static int ett_dvmrp;
static int ett_commands;
static int ett_capabilities;
static int ett_flags;
static int ett_route;

static expert_field ei_checksum;

static bool strict_v3;

#define DVMRP_TYPE				0x13
static const value_string dvmrp_type[] = {
	{DVMRP_TYPE,	"DVMRP"	},
	{0,		NULL}
};

#define DVMRP_V1_RESPONSE			1
#define DVMRP_V1_REQUEST			2
#define DVMRP_V1_NON_MEMBERSHIP_REPORT		3
#define DVMRP_V1_NON_MEMBERSHIP_CANCELLATION	4
static const value_string code_v1[] = {
	{DVMRP_V1_RESPONSE,			"Response"			},
	{DVMRP_V1_REQUEST,			"Request"			},
	{DVMRP_V1_NON_MEMBERSHIP_REPORT,	"Non-membership report"		},
	{DVMRP_V1_NON_MEMBERSHIP_CANCELLATION,	"Non-membership cancellation"	},
	{0,					NULL}
};

#define DVMRP_V3_PROBE				0x1
#define DVMRP_V3_REPORT				0x2
#define DVMRP_V3_ASK_NEIGHBORS			0x3
#define DVMRP_V3_NEIGHBORS			0x4
#define DVMRP_V3_ASK_NEIGHBORS_2		0x5
#define DVMRP_V3_NEIGHBORS_2			0x6
#define DVMRP_V3_PRUNE				0x7
#define DVMRP_V3_GRAFT				0x8
#define DVMRP_V3_GRAFT_ACK			0x9
static const value_string code_v3[] = {
	{DVMRP_V3_PROBE,		"Probe"},
	{DVMRP_V3_REPORT,		"Report"},
	{DVMRP_V3_ASK_NEIGHBORS,	"Ask Neighbors"},
	{DVMRP_V3_NEIGHBORS,		"Neighbors"},
	{DVMRP_V3_ASK_NEIGHBORS_2,	"Ask Neighbors 2"},
	{DVMRP_V3_NEIGHBORS_2,		"Neighbors 2"},
	{DVMRP_V3_PRUNE,		"Prune"},
	{DVMRP_V3_GRAFT,		"Graft"},
	{DVMRP_V3_GRAFT_ACK,		"Graft ACK"},
	{0,				NULL}
};

#define DVMRP_V3_CAP_LEAF	0x01
#define DVMRP_V3_CAP_PRUNE	0x02
#define DVMRP_V3_CAP_GENID	0x04
#define DVMRP_V3_CAP_MTRACE	0x08
#define DVMRP_V3_CAP_SNMP	0x10
#define DVMRP_V3_CAP_NETMASK	0x20

#define DVMRP_V3_FLAG_TUNNEL	0x01
#define DVMRP_V3_FLAG_SRCROUTE	0x02
#define DVMRP_V3_FLAG_DOWN	0x10
#define DVMRP_V3_FLAG_DISABLED	0x20
#define DVMRP_V3_FLAG_QUERIER	0x40
#define DVMRP_V3_FLAG_LEAF	0x80


#define V1_COMMAND_NULL		0
#define V1_COMMAND_AFI		2
#define V1_COMMAND_SUBNETMASK	3
#define V1_COMMAND_METRIC	4
#define V1_COMMAND_FLAGS0	5
#define V1_COMMAND_INFINITY	6
#define V1_COMMAND_DA		7
#define V1_COMMAND_RDA		8
#define V1_COMMAND_NMR		9
#define V1_COMMAND_NMR_CANCEL	10
static const value_string command[] = {
	{V1_COMMAND_NULL,	"NULL"	},
	{V1_COMMAND_AFI,	"Address Family Indicator"},
	{V1_COMMAND_SUBNETMASK,	"Subnetmask"},
	{V1_COMMAND_METRIC,	"Metric"},
	{V1_COMMAND_FLAGS0,	"Flags0"},
	{V1_COMMAND_INFINITY,	"Infinity"},
	{V1_COMMAND_DA,		"Destination Address"},
	{V1_COMMAND_RDA,	"Requested Destination Address"},
	{V1_COMMAND_NMR,	"Non-Membership Report"},
	{V1_COMMAND_NMR_CANCEL,	"Non-Membership Report Cancel"},
	{0,			NULL}
};

#define V1_AFI_IP		2
static const value_string afi[] = {
	{V1_AFI_IP,	"IP v4 Family"},
	{0,		NULL}
};

static const true_false_string tfs_dest_unreach = {
	"Destination Unreachable",
	"NOT Destination Unreachable"
};

static const true_false_string tfs_split_horiz = {
	"Split Horizon concealed route",
	"NOT Split Horizon concealed route"
};

static const true_false_string tfs_cap_leaf = {
	"Leaf",
	"NOT Leaf"
};
static const true_false_string tfs_cap_prune = {
	"Prune capable",
	"NOT Prune capable"
};
static const true_false_string tfs_cap_genid = {
	"Genid capable",
	"NOT Genid capable"
};
static const true_false_string tfs_cap_mtrace = {
	"Multicast Traceroute capable",
	"NOT Multicast Traceroute capable"
};
static const true_false_string tfs_cap_snmp = {
	"SNMP capable",
	"NOT SNMP capable"
};
static const true_false_string tfs_cap_netmask = {
	"Netmask capable",
	"NOT Netmask capable"
};

static int
dissect_v3_report(tvbuff_t *tvb, proto_tree *parent_tree, int offset)
{
	uint8_t m0,m1,m2,m3;
	uint8_t s0,s1,s2,s3;
	uint8_t metric;
	uint32_t ip;

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		proto_tree *tree;
		proto_item *item;
		int old_offset_a = offset;

		item = proto_tree_add_item(parent_tree, hf_route,
				tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_route);

		m0 = 0xff;
		/* read the mask */
		m1 = tvb_get_uint8(tvb, offset);
		m2 = tvb_get_uint8(tvb, offset+1);
		m3 = tvb_get_uint8(tvb, offset+2);

		ip = m3;
		ip = (ip<<8)|m2;
		ip = (ip<<8)|m1;
		ip = (ip<<8)|m0;
		proto_tree_add_ipv4(tree, hf_netmask, tvb, offset, 3, ip);

		offset += 3;

		/* read every srcnet, metric  pairs */
		do {
			int old_offset_b = offset;
			m0 = 0xff;

			s1 = 0;
			s2 = 0;
			s3 = 0;

			s0 = tvb_get_uint8(tvb, offset);
			offset += 1;
			if (m1) {
				s1 = tvb_get_uint8(tvb, offset);
				offset += 1;
			}
			if (m2) {
				s2 = tvb_get_uint8(tvb, offset);
				offset += 1;
			}
			if (m3) {
				s3 = tvb_get_uint8(tvb, offset);
				offset += 1;
			}

			/* handle special case for default route V3/3.4.3 */
			if ((!m1)&&(!m2)&&(!m3)&&(!s0)) {
				m0 = 0;
			}

			ip = s3;
			ip = (ip<<8)|s2;
			ip = (ip<<8)|s1;
			ip = (ip<<8)|s0;
			proto_tree_add_ipv4_format(tree, hf_saddr, tvb,
				old_offset_b, offset-old_offset_b, ip,
				"%s %d.%d.%d.%d (netmask %d.%d.%d.%d)",
				m0?"Source Network":"Default Route",
				s0,s1,s2,s3,m0,m1,m2,m3);

			metric = tvb_get_uint8(tvb, offset);
			proto_tree_add_uint(tree, hf_metric, tvb,
				offset, 1, metric&0x7f);
			offset += 1;


		} while (!(metric&0x80));

		proto_item_set_len(item, offset-old_offset_a);
	}

	return offset;
}

static int
dissect_dvmrp_v3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	uint8_t code;

	/* version */
	proto_tree_add_uint(parent_tree, hf_version, tvb, 0, 0, 3);

	/* type of command */
	proto_tree_add_uint(parent_tree, hf_type, tvb, offset, 1, 0x13);
	offset += 1;

	/* code */
	code = tvb_get_uint8(tvb, offset);
	proto_tree_add_uint(parent_tree, hf_code_v3, tvb, offset, 1, code);
	offset += 1;
	col_add_fstr(pinfo->cinfo, COL_INFO,
			"V%d %s",3 ,val_to_str(code, code_v3,
				"Unknown Type:0x%02x"));

	/* checksum */
	igmp_checksum(parent_tree, tvb, hf_checksum, hf_checksum_status, &ei_checksum, pinfo, 0);
	offset += 2;

	/* skip unused byte */
	proto_tree_add_item(parent_tree, hf_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 1;

	/* PROBE and NEIGHBORS 2 packets have capabilities flags, unused
	   for other packets */
	if (code==DVMRP_V3_PROBE || code==DVMRP_V3_NEIGHBORS_2) {
		static int * const capabilities[] = {
			&hf_cap_netmask,
			&hf_cap_snmp,
			&hf_cap_mtrace,
			&hf_cap_genid,
			&hf_cap_prune,
			&hf_cap_leaf,
			NULL
		};

		proto_tree_add_bitmask(parent_tree, tvb, offset, hf_capabilities,
			       ett_capabilities, capabilities, ENC_NA);
	}
	offset += 1;

	/* minor version */
	proto_tree_add_item(parent_tree, hf_min_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* major version */
	proto_tree_add_item(parent_tree, hf_maj_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	switch (code) {
	case DVMRP_V3_PROBE:
		/* generation id */
		proto_tree_add_item(parent_tree, hf_genid, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		while (tvb_reported_length_remaining(tvb, offset)>=4) {
			proto_tree_add_item(parent_tree, hf_neighbor,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
		break;
	case DVMRP_V3_REPORT:
		offset = dissect_v3_report(tvb, parent_tree, offset);
		break;
	case DVMRP_V3_PRUNE:
		/* source address */
		proto_tree_add_item(parent_tree, hf_saddr,
			tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		/* group address */
		proto_tree_add_item(parent_tree, hf_maddr,
			tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		/* prune lifetime */
		proto_tree_add_item(parent_tree, hf_life,
			tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		/* source netmask */
		if (tvb_reported_length_remaining(tvb, offset)>=4) {
			proto_tree_add_item(parent_tree, hf_netmask,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
		break;
	case DVMRP_V3_GRAFT:
		/* source address */
		proto_tree_add_item(parent_tree, hf_saddr,
			tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		/* group address */
		proto_tree_add_item(parent_tree, hf_maddr,
			tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		/* source netmask */
		if (tvb_reported_length_remaining(tvb, offset)>=4) {
			proto_tree_add_item(parent_tree, hf_netmask,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
		break;
	case DVMRP_V3_GRAFT_ACK:
		/* source address */
		proto_tree_add_item(parent_tree, hf_saddr,
			tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		/* group address */
		proto_tree_add_item(parent_tree, hf_maddr,
			tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		/* source netmask */
		if (tvb_reported_length_remaining(tvb, offset)>=4) {
			proto_tree_add_item(parent_tree, hf_netmask,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
		break;
	case DVMRP_V3_ASK_NEIGHBORS:
	case DVMRP_V3_NEIGHBORS:
		/* XXX - obsolete, and the draft doesn't describe them */
		break;
	case DVMRP_V3_ASK_NEIGHBORS_2:
		/* No data */
		break;
	case DVMRP_V3_NEIGHBORS_2:
		while (tvb_reported_length_remaining(tvb, offset)>=12) {
			uint8_t neighbor_count;

			/* local address */
			proto_tree_add_item(parent_tree, hf_local,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			/* Metric */
			proto_tree_add_item(parent_tree, hf_metric,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			/* Threshold */
			proto_tree_add_item(parent_tree, hf_threshold,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			/* Flags */
			{
				proto_tree *tree;
				proto_item *item;

				item = proto_tree_add_item(parent_tree, hf_flags,
					tvb, offset, 1, ENC_NA);
				tree = proto_item_add_subtree(item, ett_flags);

				proto_tree_add_item(tree, hf_flag_tunnel, tvb,
					offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_flag_srcroute, tvb,
					offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_flag_down, tvb,
					offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_flag_disabled, tvb,
					offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_flag_querier, tvb,
					offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_flag_leaf, tvb,
					offset, 1, ENC_BIG_ENDIAN);
			}
			offset += 1;
			/* Neighbor count */
			neighbor_count = tvb_get_uint8(tvb, offset);
			proto_tree_add_item(parent_tree, hf_ncount,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			while ((tvb_reported_length_remaining(tvb, offset)>=4)
				&& (neighbor_count>0)) {
				proto_tree_add_item(parent_tree, hf_neighbor,
					tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				neighbor_count--;
			}
		}
		break;
	}

	return offset;
}


static int
dissect_dvmrp_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	uint8_t code;
	uint8_t af=2; /* default */

	/* version */
	proto_tree_add_uint(parent_tree, hf_version, tvb, 0, 0, 1);

	/* type of command */
	proto_tree_add_uint(parent_tree, hf_type, tvb, offset, 1, 0x13);
	offset += 1;

	/* code */
	code = tvb_get_uint8(tvb, offset);
	proto_tree_add_uint(parent_tree, hf_code_v1, tvb, offset, 1, code);
	offset += 1;
	col_add_fstr(pinfo->cinfo, COL_INFO,
			"V%d %s",1 ,val_to_str(code, code_v1,
				"Unknown Type:0x%02x"));

	/* checksum */
	igmp_checksum(parent_tree, tvb, hf_checksum, hf_checksum_status, &ei_checksum, pinfo, 0);
	offset += 2;

	/* decode all the v1 commands */
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		proto_tree *tree;
		proto_item *item;
		uint8_t cmd,count;
		int old_offset = offset;

		item = proto_tree_add_item(parent_tree, hf_commands,
				tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_commands);

		cmd = tvb_get_uint8(tvb, offset);
		proto_tree_add_uint(tree, hf_command, tvb,
			offset, 1, cmd);
		offset += 1;

		switch (cmd){
		case V1_COMMAND_NULL:
			offset += 1; /* skip ignored/pad byte*/
			if (item) {
				proto_item_set_text(item, "Command: NULL");
			}
			break;
		case V1_COMMAND_AFI:
			af = tvb_get_uint8(tvb, offset);
			proto_tree_add_uint(tree, hf_afi, tvb,
				offset, 1, af);
			offset += 1;
			if (item) {
				proto_item_set_text(item, "%s: %s",
					val_to_str(cmd, command, "Unknown Command:0x%02x"),
					val_to_str(af, afi, "Unknown Family:0x%02x")
				);
			}
			break;
		case V1_COMMAND_SUBNETMASK:
			count = tvb_get_uint8(tvb, offset);
			proto_tree_add_uint(tree, hf_count, tvb,
				offset, 1, count);
			offset += 1;
			if (count) { /* must be 0 or 1 */
				proto_tree_add_item(tree, hf_netmask,
					tvb, offset, 4, ENC_BIG_ENDIAN);
				if (item) {
					proto_item_set_text(item, "%s: %d.%d.%d.%d",
						val_to_str(cmd, command, "Unknown Command:0x%02x"),
						tvb_get_uint8(tvb, offset),
						tvb_get_uint8(tvb, offset+1),
						tvb_get_uint8(tvb, offset+2),
						tvb_get_uint8(tvb, offset+3));
				}
				offset += 4;
			} else {
				if (item) {
					proto_item_set_text(item, "%s: <no mask supplied>",
						val_to_str(cmd, command, "Unknown Command:0x%02x"));
				}
			}
			break;
		case V1_COMMAND_METRIC:
			proto_tree_add_item(tree, hf_metric, tvb,
				offset, 1, ENC_BIG_ENDIAN);
			if (item) {
				proto_item_set_text(item, "%s: %d",
					val_to_str(cmd, command, "Unknown Command:0x%02x"),
					tvb_get_uint8(tvb, offset));
			}
			offset += 1;
			break;
		case V1_COMMAND_FLAGS0:
			count = tvb_get_uint8(tvb, offset);
			proto_tree_add_boolean(tree, hf_dest_unr, tvb, offset, 1, count);
			proto_tree_add_boolean(tree, hf_split_horiz, tvb, offset, 1, count);
			if (item) {
				proto_item_set_text(item, "%s: 0x%02x",
					val_to_str(cmd, command, "Unknown Command:0x%02x"), count);
			}
			offset += 1;
			break;
		case V1_COMMAND_INFINITY:
			proto_tree_add_item(tree, hf_infinity, tvb,
				offset, 1, ENC_BIG_ENDIAN);
			if (item) {
				proto_item_set_text(item, "%s: %d",
					val_to_str(cmd, command, "Unknown Command:0x%02x"), tvb_get_uint8(tvb, offset));
			}
			offset += 1;
			break;
		case V1_COMMAND_DA:
		case V1_COMMAND_RDA: /* same as DA */
			count = tvb_get_uint8(tvb, offset);
			proto_tree_add_uint(tree, hf_count, tvb,
				offset, 1, count);
			offset += 1;
			while (count--) {
				proto_tree_add_item(tree, hf_daddr,
					tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			if (item) {
				proto_item_set_text(item, "%s",
					val_to_str(cmd, command, "Unknown Command:0x%02x"));
			}
			break;
		case V1_COMMAND_NMR:
			count = tvb_get_uint8(tvb, offset);
			proto_tree_add_uint(tree, hf_count, tvb,
				offset, 1, count);
			offset += 1;
			while (count--) {
				proto_tree_add_item(tree, hf_maddr,
					tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(tree, hf_hold, tvb,
					offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			if (item) {
				proto_item_set_text(item, "%s",
					val_to_str(cmd, command, "Unknown Command:0x%02x"));
			}
			break;
		case V1_COMMAND_NMR_CANCEL:
			count = tvb_get_uint8(tvb, offset);
			proto_tree_add_uint(tree, hf_count, tvb,
				offset, 1, count);
			offset += 1;
			while (count--) {
				proto_tree_add_item(tree, hf_maddr,
					tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}
			if (item) {
				proto_item_set_text(item, "%s",
					val_to_str(cmd, command, "Unknown Command:0x%02x"));
			}
			break;
		}

		proto_item_set_len(item, offset-old_offset);
	}

	return offset;
}

/* This function is only called from the IGMP dissector */
static int
dissect_dvmrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	proto_tree *tree;
	proto_item *item;
	int offset = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DVMRP");
	col_clear(pinfo->cinfo, COL_INFO);

	item = proto_tree_add_item(parent_tree, proto_dvmrp, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_dvmrp);

	if ((tvb_captured_length_remaining(tvb, offset)>=8)
	 && (((tvb_get_uint8(tvb, 6)==0xff)
	 && (tvb_get_uint8(tvb, 7)==0x03))
	     || !strict_v3)) {
		offset = dissect_dvmrp_v3(tvb, pinfo, tree, offset);
	} else {
		offset = dissect_dvmrp_v1(tvb, pinfo, tree, offset);
	}

	proto_item_set_len(item, offset);
	return offset;
}

void
proto_register_dvmrp(void)
{
	static hf_register_info hf[] = {
		{ &hf_version,
			{ "DVMRP Version", "dvmrp.version", FT_UINT8, BASE_DEC,
			  NULL, 0, NULL, HFILL }},

		{ &hf_type,
			{ "Type", "dvmrp.type", FT_UINT8, BASE_HEX,
			  VALS(dvmrp_type), 0, "DVMRP Packet Type", HFILL }},

		{ &hf_code_v1,
			{ "Code", "dvmrp.v1.code", FT_UINT8, BASE_HEX,
			  VALS(code_v1), 0, "DVMRP Packet Code", HFILL }},

		{ &hf_checksum,
			{ "Checksum", "dvmrp.checksum", FT_UINT16, BASE_HEX,
			  NULL, 0, "DVMRP Checksum", HFILL }},

		{ &hf_checksum_status,
			{ "Checksum Status", "dvmrp.checksum.status", FT_UINT8, BASE_NONE,
			  VALS(proto_checksum_vals), 0x0, NULL, HFILL }},

		{ &hf_reserved,
			{ "Reserved", "dvmrp.reserved", FT_UINT16, BASE_HEX,
			  NULL, 0, "DVMRP v3 Reserved", HFILL }},

		{ &hf_commands,
			{ "Commands", "dvmrp.commands", FT_NONE, BASE_NONE,
			  NULL, 0, "DVMRP V1 Commands", HFILL }},

		{ &hf_command,
			{ "Command", "dvmrp.command", FT_UINT8, BASE_HEX,
			  VALS(command), 0, "DVMRP V1 Command", HFILL }},

		{ &hf_afi,
			{ "Address Family", "dvmrp.afi", FT_UINT8, BASE_HEX,
			  VALS(afi), 0, "DVMRP Address Family Indicator", HFILL }},

		{ &hf_count,
			{ "Count", "dvmrp.count", FT_UINT8, BASE_HEX,
			  NULL, 0, NULL, HFILL }},

		{ &hf_netmask,
			{ "Netmask", "dvmrp.netmask", FT_IPv4, BASE_NETMASK,
			  NULL, 0, "DVMRP Netmask", HFILL }},

		{ &hf_metric,
			{ "Metric", "dvmrp.metric", FT_UINT8, BASE_DEC,
			  NULL, 0, "DVMRP Metric", HFILL }},

		{&hf_dest_unr,
			{ "Destination Unreachable", "dvmrp.dest_unreach", FT_BOOLEAN, 8,
			TFS(&tfs_dest_unreach), 0x01, NULL, HFILL }},

		{&hf_split_horiz,
			{ "Split Horizon", "dvmrp.split_horiz", FT_BOOLEAN, 8,
			TFS(&tfs_split_horiz), 0x02, "Split Horizon concealed route", HFILL }},

		{ &hf_infinity,
			{ "Infinity", "dvmrp.infinity", FT_UINT8, BASE_DEC,
			  NULL, 0, "DVMRP Infinity", HFILL }},

		{ &hf_daddr,
			{ "Dest Addr", "dvmrp.daddr", FT_IPv4, BASE_NONE,
			  NULL, 0, "DVMRP Destination Address", HFILL }},

		{ &hf_maddr,
			{ "Multicast Addr", "dvmrp.maddr", FT_IPv4, BASE_NONE,
			  NULL, 0, "DVMRP Multicast Address", HFILL }},

		{ &hf_hold,
			{ "Hold Time", "dvmrp.hold", FT_UINT32, BASE_DEC,
			  NULL, 0, "DVMRP Hold Time in seconds", HFILL }},

		{ &hf_code_v3,
			{ "Code", "dvmrp.v3.code", FT_UINT8, BASE_HEX,
			  VALS(code_v3), 0, "DVMRP Packet Code", HFILL }},

		{ &hf_capabilities,
			{ "Capabilities", "dvmrp.capabilities", FT_UINT8, BASE_HEX,
			  NULL, 0, "DVMRP V3 Capabilities", HFILL }},

		{&hf_cap_leaf,
			{ "Leaf", "dvmrp.cap.leaf", FT_BOOLEAN, 8,
			TFS(&tfs_cap_leaf), DVMRP_V3_CAP_LEAF, NULL, HFILL }},

		{&hf_cap_prune,
			{ "Prune", "dvmrp.cap.prune", FT_BOOLEAN, 8,
			TFS(&tfs_cap_prune), DVMRP_V3_CAP_PRUNE, "Prune capability", HFILL }},

		{&hf_cap_genid,
			{ "Genid", "dvmrp.cap.genid", FT_BOOLEAN, 8,
			TFS(&tfs_cap_genid), DVMRP_V3_CAP_GENID, "Genid capability", HFILL }},

		{&hf_cap_mtrace,
			{ "Mtrace", "dvmrp.cap.mtrace", FT_BOOLEAN, 8,
			TFS(&tfs_cap_mtrace), DVMRP_V3_CAP_MTRACE, "Mtrace capability", HFILL }},

		{&hf_cap_snmp,
			{ "SNMP", "dvmrp.cap.snmp", FT_BOOLEAN, 8,
			TFS(&tfs_cap_snmp), DVMRP_V3_CAP_SNMP, "SNMP capability", HFILL }},

		{&hf_cap_netmask,
			{ "Netmask", "dvmrp.cap.netmask", FT_BOOLEAN, 8,
			TFS(&tfs_cap_netmask), DVMRP_V3_CAP_NETMASK, "Netmask capability", HFILL }},

		{ &hf_min_ver,
			{ "Minor Version", "dvmrp.min_ver", FT_UINT8, BASE_HEX,
			  NULL, 0, "DVMRP Minor Version", HFILL }},

		{ &hf_maj_ver,
			{ "Major Version", "dvmrp.maj_ver", FT_UINT8, BASE_HEX,
			  NULL, 0, "DVMRP Major Version", HFILL }},

		{ &hf_genid,
			{ "Generation ID", "dvmrp.genid", FT_UINT32, BASE_DEC,
			  NULL, 0, "DVMRP Generation ID", HFILL }},

		{ &hf_route,
			{ "Route", "dvmrp.route", FT_NONE, BASE_NONE,
			  NULL, 0, "DVMRP V3 Route Report", HFILL }},

		{ &hf_saddr,
			{ "Source Addr", "dvmrp.saddr", FT_IPv4, BASE_NONE,
			  NULL, 0, "DVMRP Source Address", HFILL }},

		{ &hf_life,
			{ "Prune lifetime", "dvmrp.lifetime", FT_UINT32, BASE_DEC,
			  NULL, 0, "DVMRP Prune Lifetime", HFILL }},

		{ &hf_local,
			{ "Local Addr", "dvmrp.local", FT_IPv4, BASE_NONE,
			  NULL, 0, "DVMRP Local Address", HFILL }},

		{ &hf_threshold,
			{ "Threshold", "dvmrp.threshold", FT_UINT8, BASE_DEC,
			NULL, 0, "DVMRP Interface Threshold", HFILL }},

		{ &hf_flags,
			{ "Flags", "dvmrp.flags", FT_NONE, BASE_NONE,
			NULL, 0, "DVMRP Interface Flags", HFILL }},

		{ &hf_flag_tunnel,
			{ "Tunnel", "dvmrp.flag.tunnel", FT_BOOLEAN, 8,
			NULL, DVMRP_V3_FLAG_TUNNEL, "Neighbor reached via tunnel", HFILL }},

		{ &hf_flag_srcroute,
			{ "Source Route", "dvmrp.flag.srcroute", FT_BOOLEAN, 8,
			NULL, DVMRP_V3_FLAG_SRCROUTE, "Tunnel uses IP source routing", HFILL }},

		{ &hf_flag_down,
			{ "Down", "dvmrp.flag.down", FT_BOOLEAN, 8,
			NULL, DVMRP_V3_FLAG_DOWN, "Operational status down", HFILL }},

		{ &hf_flag_disabled,
			{ "Disabled", "dvmrp.flag.disabled", FT_BOOLEAN, 8,
			NULL, DVMRP_V3_FLAG_DISABLED, "Administrative status down", HFILL }},

		{ &hf_flag_querier,
			{ "Querier", "dvmrp.flag.querier", FT_BOOLEAN, 8,
			NULL, DVMRP_V3_FLAG_QUERIER, "Querier for interface", HFILL }},

		{ &hf_flag_leaf,
			{ "Leaf", "dvmrp.flag.leaf", FT_BOOLEAN, 8,
			NULL, DVMRP_V3_FLAG_LEAF, "No downstream neighbors on interface", HFILL }},

		{ &hf_ncount,
			{ "Neighbor Count", "dvmrp.ncount", FT_UINT8, BASE_DEC,
			NULL, 0, "DVMRP Neighbor Count", HFILL }},

		{ &hf_neighbor,
			{ "Neighbor Addr", "dvmrp.neighbor", FT_IPv4, BASE_NONE,
			  NULL, 0, "DVMRP Neighbor Address", HFILL }}
	};
	static int *ett[] = {
		&ett_dvmrp,
		&ett_commands,
		&ett_capabilities,
		&ett_flags,
		&ett_route
	};

	static ei_register_info ei[] = {
		{ &ei_checksum, { "dvmrp.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
	};

	expert_module_t* expert_dvmrp;

	module_t *module_dvmrp;

	proto_dvmrp = proto_register_protocol("Distance Vector Multicast Routing Protocol", "DVMRP", "dvmrp");
	proto_register_field_array(proto_dvmrp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_dvmrp = expert_register_protocol(proto_dvmrp);
	expert_register_field_array(expert_dvmrp, ei, array_length(ei));

	module_dvmrp = prefs_register_protocol(proto_dvmrp, NULL);

	prefs_register_bool_preference(module_dvmrp, "strict_v3", "Allow strict DVMRP V3 only",
		"Allow only packets with Major=0x03//Minor=0xFF as DVMRP V3 packets",
		&strict_v3);

	dvmrp_handle = register_dissector("dvmrp", dissect_dvmrp, proto_dvmrp);
}

void
proto_reg_handoff_dvmrp(void)
{
	dissector_add_uint("igmp.type", IGMP_DVMRP, dvmrp_handle);
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

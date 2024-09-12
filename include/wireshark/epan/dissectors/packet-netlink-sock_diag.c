/* packet-netlink-sock_diag.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/aftypes.h>
#include <epan/etypes.h>
#include <epan/ipproto.h>
#include <epan/strutil.h>
#include "packet-netlink.h"

void proto_register_netlink_sock_diag(void);
void proto_reg_handoff_netlink_sock_diag(void);

typedef struct {
	packet_info *pinfo;
} netlink_sock_diag_info_t;

static int proto_netlink_sock_diag;

static dissector_handle_t netlink_sock_diag_handle;

enum {
/* sock diag values for nlmsghdr.nlmsg_type from: */

	/* <include/uapi/linux/inet_diag.h> (compat) */
	WS_TCPDIAG_GETSOCK     = 18,
	WS_DCCPDIAG_GETSOCK    = 19,

	/* <include/uapi/linux/sock_diag.h> */
	WS_SOCK_DIAG_BY_FAMILY = 20,
	WS_SOCK_DESTROY        = 21
};

enum {
	/* </usr/include/<platform>/bits/socket_type.h> */
	WS_SOCK_STREAM    =  1,
	WS_SOCK_DGRAM     =  2,
	WS_SOCK_RAW       =  3,
	WS_SOCK_RDM       =  4,
	WS_SOCK_SEQPACKET =  5,
	WS_SOCK_DCCP      =  6,
	WS_SOCK_PACKET    = 10
};

/*  SOCK_CLOEXEC = 02000000 */
/* SOCK_NONBLOCK = 00004000 */

enum ws_unix_diag_show_mask {
	/* show mask for unix diag from <include/uapi/linux/unix_diag.h> */
	WS_UDIAG_SHOW_NAME     = 0x00000001,
	WS_UDIAG_SHOW_VFS      = 0x00000002,
	WS_UDIAG_SHOW_PEER     = 0x00000004,
	WS_UDIAG_SHOW_ICONS    = 0x00000008,
	WS_UDIAG_SHOW_RQLEN    = 0x00000010,
	WS_UDIAG_SHOW_MEMINFO  = 0x00000020,
	WS_UDIAG_SHOW_UID      = 0x00000040
};

enum ws_unix_diag_attr_type {
	/* netlink attributes for unix diag from <include/uapi/linux/unix_diag.h> */
	WS_UNIX_DIAG_NAME     = 0,
	WS_UNIX_DIAG_VFS      = 1,
	WS_UNIX_DIAG_PEER     = 2,
	WS_UNIX_DIAG_ICONS    = 3,
	WS_UNIX_DIAG_RQLEN    = 4,
	WS_UNIX_DIAG_MEMINFO  = 5,
	WS_UNIX_DIAG_SHUTDOWN = 6,
	WS_UNIX_DIAG_UID      = 7
};

enum ws_inet_diag_attr_type {
	/* netlink attributes for inet diag from <include/uapi/linux/inet_diag.h> */
	WS_INET_DIAG_NONE      = 0,
	WS_INET_DIAG_MEMINFO   = 1,
	WS_INET_DIAG_INFO      = 2,
	WS_INET_DIAG_VEGASINFO = 3,
	WS_INET_DIAG_CONG      = 4,
	WS_INET_DIAG_TOS       = 5,
	WS_INET_DIAG_TCLASS    = 6,
	WS_INET_DIAG_SKMEMINFO = 7,
	WS_INET_DIAG_SHUTDOWN  = 8,
	WS_INET_DIAG_DCTCPINFO = 9,
	WS_INET_DIAG_PROTOCOL  = 10,
	WS_INET_DIAG_SKV6ONLY  = 11,
	WS_INET_DIAG_LOCALS    = 12,
	WS_INET_DIAG_PEERS     = 13,
	WS_INET_DIAG_PAD       = 14,
	WS_INET_DIAG_MARK      = 15,
	WS_INET_DIAG_BBRINFO   = 16,
	WS_INET_DIAG_CLASS_ID  = 17,
	WS_INET_DIAG_MD5SIG    = 18,
	WS_INET_DIAG_ULP_INFO  = 19,
	WS_INET_DIAG_SK_BPF_STORAGES = 20,
	WS_INET_DIAG_CGROUP_ID = 21,
	WS_INET_DIAG_SOCKOPT   = 22,
};

enum ws_netlink_diag_show_type {
	/* show mask for netlink diag from <include/uapi/linux/netlink_diag.h> */
	WS_NDIAG_SHOW_MEMINFO   = 0x00000001,
	WS_NDIAG_SHOW_GROUPS    = 0x00000002,
	WS_NDIAG_SHOW_RING_CFG  = 0x00000004,
	WS_NDIAG_SHOW_FLAGS     = 0x00000008,
};

enum ws_netlink_diag_attr_type {
	/* netlink attributes for netlink diag from <include/uapi/linux/netlink_diag.h> */
	WS_NETLINK_DIAG_MEMINFO = 0,
	WS_NETLINK_DIAG_GROUPS  = 1,
	WS_NETLINK_DIAG_RX_RING = 2,
	WS_NETLINK_DIAG_TX_RING = 3,
	WS_NETLINK_DIAG_FLAGS   = 4,
};

enum ws_packet_diag_show_mask {
	/* show mask for packet diag from <include/uapi/linux/packet_diag.h> */
	WS_PACKET_SHOW_INFO        = 0x00000001,
	WS_PACKET_SHOW_MCLIST      = 0x00000002,
	WS_PACKET_SHOW_RING_CFG    = 0x00000004,
	WS_PACKET_SHOW_FANOUT      = 0x00000008,
	WS_PACKET_SHOW_MEMINFO     = 0x00000010,
	WS_PACKET_SHOW_FILTER      = 0x00000020
};

enum ws_packet_diag_attr_type {
	/* netlink attributes for packet diag from <include/uapi/linux/packet_diag.h> */
	WS_PACKET_DIAG_INFO     = 0,
	WS_PACKET_DIAG_MCLIST   = 1,
	WS_PACKET_DIAG_RX_RING  = 2,
	WS_PACKET_DIAG_TX_RING  = 3,
	WS_PACKET_DIAG_FANOUT   = 4,
	WS_PACKET_DIAG_UID      = 5,
	WS_PACKET_DIAG_MEMINFO  = 6,
	WS_PACKET_DIAG_FILTER   = 7
};

enum {
	/* based on kernel include <include/net/tcp_states.h> with WS_ without TCP_ (it's not only used by tcp) */
	WS_ESTABLISHED = 1,
	WS_SYN_SENT    = 2,
	WS_SYN_RECV    = 3,
	WS_FIN_WAIT1   = 4,
	WS_FIN_WAIT2   = 5,
	WS_TIME_WAIT   = 6,
	WS_CLOSE       = 7,
	WS_CLOSE_WAIT  = 8,
	WS_LAST_ACK    = 9,
	WS_LISTEN      = 10,
	WS_CLOSING     = 11,
	WS_NEW_SYNC_RECV = 12
};

static int hf_netlink_sock_diag_cookie;
static int hf_netlink_sock_diag_family;
static int hf_netlink_sock_diag_fwd_alloc;
static int hf_netlink_sock_diag_inet_attr;
static int hf_netlink_sock_diag_inet_dport;
static int hf_netlink_sock_diag_inet_dst_ip4;
static int hf_netlink_sock_diag_inet_dst_ip6;
static int hf_netlink_sock_diag_inet_extended;
static int hf_netlink_sock_diag_inet_interface;
static int hf_netlink_sock_diag_inet_padding;
static int hf_netlink_sock_diag_inet_proto;
static int hf_netlink_sock_diag_inet_sport;
static int hf_netlink_sock_diag_inet_src_ip4;
static int hf_netlink_sock_diag_inet_src_ip6;
static int hf_netlink_sock_diag_inet_states;
static int hf_netlink_sock_diag_inode;
static int hf_netlink_sock_diag_netlink_attr;
static int hf_netlink_sock_diag_netlink_dst_port_id;
static int hf_netlink_sock_diag_netlink_port_id;
static int hf_netlink_sock_diag_netlink_proto;
static int hf_netlink_sock_diag_netlink_show;
static int hf_netlink_sock_diag_netlink_show_groups;
static int hf_netlink_sock_diag_netlink_show_meminfo;
static int hf_netlink_sock_diag_netlink_show_ring_cfg;
static int hf_netlink_sock_diag_nltype;
static int hf_netlink_sock_diag_packet_attr;
static int hf_netlink_sock_diag_packet_proto;
static int hf_netlink_sock_diag_packet_show;
static int hf_netlink_sock_diag_packet_show_fanout;
static int hf_netlink_sock_diag_packet_show_filter;
static int hf_netlink_sock_diag_packet_show_info;
static int hf_netlink_sock_diag_packet_show_mclist;
static int hf_netlink_sock_diag_packet_show_meminfo;
static int hf_netlink_sock_diag_packet_show_ring_cfg;
static int hf_netlink_sock_diag_rcvbuf;
static int hf_netlink_sock_diag_rmem_alloc;
static int hf_netlink_sock_diag_rqueue;
static int hf_netlink_sock_diag_shutdown;
static int hf_netlink_sock_diag_sndbuf;
static int hf_netlink_sock_diag_state;
static int hf_netlink_sock_diag_type;
static int hf_netlink_sock_diag_unix_attr;
static int hf_netlink_sock_diag_unix_name;
static int hf_netlink_sock_diag_unix_peer_inode;
static int hf_netlink_sock_diag_unix_show;
static int hf_netlink_sock_diag_unix_show_icons;
static int hf_netlink_sock_diag_unix_show_meminfo;
static int hf_netlink_sock_diag_unix_show_name;
static int hf_netlink_sock_diag_unix_show_peer;
static int hf_netlink_sock_diag_unix_show_rqlen;
static int hf_netlink_sock_diag_unix_show_vfs;
static int hf_netlink_sock_diag_wmem_alloc;
static int hf_netlink_sock_diag_wmem_queued;
static int hf_netlink_sock_diag_wqueue;

static int ett_netlink_sock_diag;
static int ett_netlink_sock_diag_show;
static int ett_netlink_sock_diag_attr;

static const true_false_string _tfs_show_do_not_show = { "Show", "Don't show" };

static const value_string socket_type_vals[] = {
	{ WS_SOCK_STREAM,	"SOCK_STREAM" },
	{ WS_SOCK_DGRAM,	"SOCK_DGRAM" },
	{ WS_SOCK_RAW,		"SOCK_RAW" },
	{ WS_SOCK_RDM,		"SOCK_RDM" },
	{ WS_SOCK_SEQPACKET,	"SOCK_SEQPACKET" },
	{ WS_SOCK_DCCP,		"SOCK_DCCP" },
	{ WS_SOCK_PACKET,	"SOCK_PACKET" },
	{ 0, NULL }
};

static const value_string socket_state_vals[] = {
	{ WS_ESTABLISHED, "ESTABLISHED" },
	{ WS_SYN_SENT,    "SYN_SENT" },
	{ WS_SYN_RECV,    "SYN_RECV" },
	{ WS_FIN_WAIT1,   "FIN_WAIT1" },
	{ WS_FIN_WAIT2,   "FIN_WAIT2" },
	{ WS_TIME_WAIT,   "TIME_WAIT" },
	{ WS_CLOSE,       "CLOSE" },
	{ WS_CLOSE_WAIT,  "CLOSE_WAIT" },
	{ WS_LAST_ACK,    "LAST_ACK" },
	{ WS_LISTEN,      "LISTEN" },
	{ WS_CLOSING,     "CLOSING" },
	{ WS_NEW_SYNC_RECV, "NEW_SYNC_RECV" },
	{ 0, NULL }
};

/* Generic */

static int
_tvb_check_if_zeros(tvbuff_t *tvb, int offset, int len)
{
	/* padding, all bytes should be 0, if not display as unknown */
	while (len >= 0) {
		if (tvb_get_uint8(tvb, offset) != 0)
			return 1;

		offset++;
		len--;
	}
	return 0;
}

static void
_dissect_padding(proto_tree *tree _U_, tvbuff_t *tvb, int offset, int len)
{
	if (_tvb_check_if_zeros(tvb, offset, len)) {
		/* XXX, tree, expert info */
	}
}

/* Sock diag meminfo */

static int
dissect_sock_diag_meminfo(proto_tree *tree, netlink_sock_diag_info_t *info _U_, struct packet_netlink_data *nl_data, tvbuff_t *tvb, int offset, int len)
{
	static int *hfs[] = {
		&hf_netlink_sock_diag_rmem_alloc,
		&hf_netlink_sock_diag_rcvbuf,
		&hf_netlink_sock_diag_wmem_alloc,
		&hf_netlink_sock_diag_sndbuf,
		&hf_netlink_sock_diag_fwd_alloc,
		&hf_netlink_sock_diag_wmem_queued,
		/* XXX OPTMEM */
		/* XXX BACKLOG */
	};

	unsigned i;

	if (len == 0 || (len % 4) != 0)
		return 0;

	for (i = 0; len >= 4 && i < G_N_ELEMENTS(hfs); i++) {
		proto_tree_add_item(tree, *hfs[i], tvb, offset, 4, nl_data->encoding);
		offset += 4; len -= 4;
	}

	if (len != 0) {
		/* XXX, unknown */
	}

	return 1;
}

/* Sock diag Cookie */

static void
sock_diag_proto_tree_add_cookie(proto_tree *tree, netlink_sock_diag_info_t *info _U_, struct packet_netlink_data *nl_data _U_, tvbuff_t *tvb, int offset)
{
	uint64_t cookie;

	cookie = tvb_get_letohl(tvb, offset + 4);
	cookie <<= 32;
	cookie |= tvb_get_letohl(tvb, offset);

	/* XXX support for INET_DIAG_NOCOOKIE (~0) */

	proto_tree_add_uint64(tree, hf_netlink_sock_diag_cookie, tvb, offset, 8, cookie);
}

static const value_string netlink_sock_diag_shutdown_flags_vals[] = {
	{ 0, "No shutdown" },
	{ 1, "Receptions disallowed" },
	{ 2, "Transmissions disallowed" },
	{ 3, "Receptions and transmissions disallowed" },
	{ 0, NULL }
};

static void
sock_diag_proto_tree_add_shutdown(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	uint8_t how = tvb_get_uint8(tvb, offset);

	proto_tree_add_item(tree, hf_netlink_sock_diag_shutdown, tvb, offset, 1, ENC_NA);

	proto_item_append_text(tree, ": %s", val_to_str(how, netlink_sock_diag_shutdown_flags_vals, "Invalid how value (%x)"));
}

/* AF_UNIX attributes */

static const value_string netlink_sock_diag_unix_attr_vals[] = {
	{ WS_UNIX_DIAG_NAME, "Name" },
	{ WS_UNIX_DIAG_VFS,  "VFS" },
	{ WS_UNIX_DIAG_PEER, "Peer" },
	{ WS_UNIX_DIAG_ICONS, "Icons" },
	{ WS_UNIX_DIAG_RQLEN, "RQ len" },
	{ WS_UNIX_DIAG_MEMINFO, "meminfo" },
	{ WS_UNIX_DIAG_SHUTDOWN, "shutdown" },
	{ 0, NULL }
};

static int
dissect_netlink_unix_sock_diag_reply_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_unix_diag_attr_type type = (enum ws_unix_diag_attr_type) nla_type;
	netlink_sock_diag_info_t *info = (netlink_sock_diag_info_t *) data;

	switch (type) {
		case WS_UNIX_DIAG_NAME:
		{
			const char *name;

			/* XXX make it nicer */
			if (len > 0 && tvb_get_uint8(tvb, offset) == '\0') {
				name = wmem_strconcat(wmem_packet_scope(),
					"@",
					tvb_get_string_enc(wmem_packet_scope(), tvb, offset+1, len-1, ENC_ASCII | ENC_NA),
					NULL);
			} else
				name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, len, ENC_ASCII | ENC_NA);

			proto_item_append_text(tree, ": %s", name);
			proto_tree_add_string(tree, hf_netlink_sock_diag_unix_name, tvb, offset, len, name);
			return 1;
		}

		case WS_UNIX_DIAG_PEER:
			if (len == 4) {
				uint32_t value;
				proto_tree_add_item_ret_uint(tree, hf_netlink_sock_diag_unix_peer_inode, tvb, offset, 4, nl_data->encoding, &value);
				proto_item_append_text(tree, ": Peer inode %u", value);
				return 1;
			}
			return 0;

		case WS_UNIX_DIAG_RQLEN:
			if (len == 8) {
				/* XXX, if socket in WS_LISTEN it's reporting sk->sk_receive_queue.qlen, sk->sk_max_ack_backlog */
				proto_tree_add_item(tree, hf_netlink_sock_diag_rqueue, tvb, offset, 4, nl_data->encoding);
				proto_tree_add_item(tree, hf_netlink_sock_diag_wqueue, tvb, offset, 4, nl_data->encoding);
				return 1;
			}
			return 0;

		case WS_UNIX_DIAG_MEMINFO:
			return dissect_sock_diag_meminfo(tree, info, nl_data, tvb, offset, len);

		case WS_UNIX_DIAG_SHUTDOWN:
			if (len == 1)
				sock_diag_proto_tree_add_shutdown(tree, tvb, offset);
			return 0;

		case WS_UNIX_DIAG_VFS:
		case WS_UNIX_DIAG_ICONS:
		default:
			return 0;
	}
}

/* AF_UNIX */

static int
dissect_sock_diag_unix_reply(tvbuff_t *tvb, netlink_sock_diag_info_t *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, hf_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* XXX, validate: SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET */
	proto_tree_add_item(tree, hf_netlink_sock_diag_type, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* XXX, validate */
	proto_tree_add_item(tree, hf_netlink_sock_diag_state, tvb, offset, 1, ENC_NA);
	offset += 1;

	_dissect_padding(tree, tvb, offset, 1);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_sock_diag_inode, tvb, offset, 4, nl_data->encoding);
	offset += 4;

	sock_diag_proto_tree_add_cookie(tree, info, nl_data, tvb, offset);
	offset += 8;

	return dissect_netlink_attributes_to_end(tvb, hf_netlink_sock_diag_unix_attr, ett_netlink_sock_diag_attr, info, nl_data, tree, offset, dissect_netlink_unix_sock_diag_reply_attrs);
}

/* AF_UNIX request */

static int
dissect_sock_diag_unix_request_show(tvbuff_t *tvb, netlink_sock_diag_info_t *info _U_, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *flags_tree;

	ti = proto_tree_add_item(tree, hf_netlink_sock_diag_unix_show, tvb, offset, 4, nl_data->encoding);
	flags_tree = proto_item_add_subtree(ti, ett_netlink_sock_diag_show);

	proto_tree_add_item(flags_tree, hf_netlink_sock_diag_unix_show_name, tvb, offset, 4, nl_data->encoding);
	proto_tree_add_item(flags_tree, hf_netlink_sock_diag_unix_show_vfs, tvb, offset, 4, nl_data->encoding);
	proto_tree_add_item(flags_tree, hf_netlink_sock_diag_unix_show_peer, tvb, offset, 4, nl_data->encoding);
	proto_tree_add_item(flags_tree, hf_netlink_sock_diag_unix_show_icons, tvb, offset, 4, nl_data->encoding);
	proto_tree_add_item(flags_tree, hf_netlink_sock_diag_unix_show_rqlen, tvb, offset, 4, nl_data->encoding);
	proto_tree_add_item(flags_tree, hf_netlink_sock_diag_unix_show_meminfo, tvb, offset, 4, nl_data->encoding);
	/* XXX, unknown */

	offset += 4;

	return offset;
}

static int
dissect_sock_diag_unix_request(tvbuff_t *tvb, netlink_sock_diag_info_t *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, hf_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* XXX, AF_UNIX don't have protocols - 0 */
	offset += 1;

	_dissect_padding(tree, tvb, offset, 2);
	offset += 2;

	/* states */
	offset += 4;

	proto_tree_add_item(tree, hf_netlink_sock_diag_inode, tvb, offset, 4, nl_data->encoding);
	offset += 4;

	offset = dissect_sock_diag_unix_request_show(tvb, info, nl_data, tree, offset);

	sock_diag_proto_tree_add_cookie(tree, info, nl_data, tvb, offset);
	offset += 8;

	return offset;
}

/* AF_INET attributes */

static const value_string netlink_sock_diag_inet_attr_vals[] = {
	{ WS_INET_DIAG_MEMINFO,    "meminfo" },
	{ WS_INET_DIAG_INFO,       "info" },
	{ WS_INET_DIAG_VEGASINFO,  "vegasinfo" },
	{ WS_INET_DIAG_CONG,       "cong" },
	{ WS_INET_DIAG_TOS,        "tos" },
	{ WS_INET_DIAG_TCLASS,     "tclass" },
	{ WS_INET_DIAG_SKMEMINFO,  "skmeminfo" },
	{ WS_INET_DIAG_SHUTDOWN,   "shutdown" },
	{ WS_INET_DIAG_DCTCPINFO,  "dctcpinfo" },
	{ WS_INET_DIAG_PROTOCOL,   "protocol" },
	{ WS_INET_DIAG_SKV6ONLY,   "skv6only" },
	{ WS_INET_DIAG_LOCALS,     "locals" },
	{ WS_INET_DIAG_PEERS,      "peers" },
	{ WS_INET_DIAG_PAD,        "pad" },
	{ WS_INET_DIAG_MARK,       "mark" },
	{ WS_INET_DIAG_BBRINFO,    "bbrinfo" },
	{ WS_INET_DIAG_CLASS_ID,   "class_id" },
	{ WS_INET_DIAG_MD5SIG,     "md5sig" },
	{ WS_INET_DIAG_ULP_INFO,   "ulp_info" },
	{ WS_INET_DIAG_SK_BPF_STORAGES, "sk_bpf_storages" },
	{ WS_INET_DIAG_CGROUP_ID,  "cgroup_id" },
	{ WS_INET_DIAG_SOCKOPT,    "sockopt" },
	{ 0, NULL }
};

static int
dissect_sock_diag_inet_attributes(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_inet_diag_attr_type type = (enum ws_inet_diag_attr_type) nla_type;
	netlink_sock_diag_info_t *info = (netlink_sock_diag_info_t *) data;

	switch (type) {
		case WS_INET_DIAG_MEMINFO:
			if (len == 16) {
				proto_tree_add_item(tree, hf_netlink_sock_diag_rmem_alloc, tvb, offset, 4, nl_data->encoding);
				offset += 4;

				proto_tree_add_item(tree, hf_netlink_sock_diag_wmem_queued, tvb, offset, 4, nl_data->encoding);
				offset += 4;

				proto_tree_add_item(tree, hf_netlink_sock_diag_fwd_alloc, tvb, offset, 4, nl_data->encoding);
				offset += 4;

				proto_tree_add_item(tree, hf_netlink_sock_diag_wmem_alloc, tvb, offset, 4, nl_data->encoding);
				/*offset += 4;*/

				return 1;
			}
			return 0;

		case WS_INET_DIAG_SKMEMINFO:
			return dissect_sock_diag_meminfo(tree, info, nl_data, tvb, offset, len);

		case WS_INET_DIAG_SHUTDOWN:
			if (len == 1)
				sock_diag_proto_tree_add_shutdown(tree, tvb, offset);
			return 0;

		case WS_INET_DIAG_INFO:
		case WS_INET_DIAG_VEGASINFO:
		case WS_INET_DIAG_CONG:
		case WS_INET_DIAG_TOS:
		case WS_INET_DIAG_TCLASS:
		case WS_INET_DIAG_DCTCPINFO:
		case WS_INET_DIAG_PROTOCOL:
		case WS_INET_DIAG_SKV6ONLY:
		case WS_INET_DIAG_LOCALS:
		case WS_INET_DIAG_PEERS:
		case WS_INET_DIAG_PAD:
		case WS_INET_DIAG_MARK:
		case WS_INET_DIAG_BBRINFO:
		default:
			return 0;
	}
}

/* AF_INET sockid */

static int
dissect_sock_diag_inet_sockid(tvbuff_t *tvb, netlink_sock_diag_info_t *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset, int family)
{
	proto_tree_add_item(tree, hf_netlink_sock_diag_inet_sport, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_netlink_sock_diag_inet_dport, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	switch (family) {
		case LINUX_AF_INET:
			proto_tree_add_item(tree, hf_netlink_sock_diag_inet_src_ip4, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			_dissect_padding(tree, tvb, offset, 12);
			offset += 12;

			proto_tree_add_item(tree, hf_netlink_sock_diag_inet_dst_ip4, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			_dissect_padding(tree, tvb, offset, 12);
			offset += 12;
			break;

		case LINUX_AF_INET6:
			proto_tree_add_item(tree, hf_netlink_sock_diag_inet_src_ip6, tvb, offset, 16, ENC_NA);
			offset += 16;

			proto_tree_add_item(tree, hf_netlink_sock_diag_inet_dst_ip6, tvb, offset, 16, ENC_NA);
			offset += 16;
			break;

		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			break;
	}

	proto_tree_add_item(tree, hf_netlink_sock_diag_inet_interface, tvb, offset, 4, nl_data->encoding);
	offset += 4;

	sock_diag_proto_tree_add_cookie(tree, info, nl_data, tvb, offset);
	offset += 8;

	return offset;
}

/* AF_INET */

static int
dissect_sock_diag_inet_reply(tvbuff_t *tvb, netlink_sock_diag_info_t *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	uint8_t af_family;

	af_family = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(tree, hf_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_sock_diag_state, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* XXX timer retrans */
	offset += 2;

	offset = dissect_sock_diag_inet_sockid(tvb, info, nl_data, tree, offset, af_family);

	/* XXX expires */
	offset += 4;

	proto_tree_add_item(tree, hf_netlink_sock_diag_rqueue, tvb, offset, 4, nl_data->encoding);
	offset += 4;

	proto_tree_add_item(tree, hf_netlink_sock_diag_wqueue, tvb, offset, 4, nl_data->encoding);
	offset += 4;

	/* XXX uid */
	offset += 4;

	proto_tree_add_item(tree, hf_netlink_sock_diag_inode, tvb, offset, 4, nl_data->encoding);
	offset += 4;

	return dissect_netlink_attributes_to_end(tvb, hf_netlink_sock_diag_inet_attr, ett_netlink_sock_diag_attr, info, nl_data, tree, offset, dissect_sock_diag_inet_attributes);
}

/* AF_INET request */

static int
dissect_sock_diag_inet_request(tvbuff_t *tvb, netlink_sock_diag_info_t *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	uint8_t af_family;

	af_family = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(tree, hf_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_sock_diag_inet_proto, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* XXX ext: INET_DIAG_MEMINFO, INET_DIAG_INFO, ... */

	proto_tree_add_item(tree, hf_netlink_sock_diag_inet_extended, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* padding for backwards compatibility */
	_dissect_padding(tree, tvb, offset, 1);
	proto_tree_add_item(tree, hf_netlink_sock_diag_inet_padding, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* XXX states (bit of sk_state) */
	proto_tree_add_item(tree, hf_netlink_sock_diag_inet_states, tvb, offset, 4, ENC_NA);
	offset += 4;

	offset = dissect_sock_diag_inet_sockid(tvb, info, nl_data, tree, offset, af_family);

	return offset;
}

/* AF_NETLINK attributes */

static const value_string netlink_sock_diag_netlink_vals[] = {
	{ WS_NETLINK_DIAG_MEMINFO,  "Memory info" },
	{ WS_NETLINK_DIAG_GROUPS,   "groups" },
	{ WS_NETLINK_DIAG_RX_RING,  "RX ring configuration" },
	{ WS_NETLINK_DIAG_TX_RING,  "TX ring configuration" },
	{ 0, NULL }
};

static int
dissect_sock_diag_netlink_attributes(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_netlink_diag_attr_type type = (enum ws_netlink_diag_attr_type) nla_type;
	netlink_sock_diag_info_t *info = (netlink_sock_diag_info_t *) data;

	switch (type) {
		case WS_NETLINK_DIAG_MEMINFO:
			return dissect_sock_diag_meminfo(tree, info, nl_data, tvb, offset, len);

		case WS_NETLINK_DIAG_GROUPS:
		case WS_NETLINK_DIAG_RX_RING:
		case WS_NETLINK_DIAG_TX_RING:
		default:
			return 0;
	}
}

/* AF_NETLINK */

static int
dissect_sock_diag_netlink_reply(tvbuff_t *tvb, netlink_sock_diag_info_t *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, hf_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* ti = */ proto_tree_add_item(tree, hf_netlink_sock_diag_type, tvb, offset, 1, ENC_NA);
	switch (tvb_get_uint8(tvb, offset)) {
		case WS_SOCK_DGRAM:
		case WS_SOCK_RAW:
			break;
		default:
			/* XXX expert_add_info(info->pinfo, ti, &ei_netlink_sock_diag_incorrect_type); */
			break;
	}
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_sock_diag_netlink_proto, tvb, offset, 1, ENC_NA);
	offset += 1;

	/* XXX, validate */
	proto_tree_add_item(tree, hf_netlink_sock_diag_state, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_sock_diag_netlink_port_id, tvb, offset, 4, nl_data->encoding);
	offset += 4;

	proto_tree_add_item(tree, hf_netlink_sock_diag_netlink_dst_port_id, tvb, offset, 4, nl_data->encoding);
	offset += 4;

	/* XXX dst group */
	offset += 4;

	proto_tree_add_item(tree, hf_netlink_sock_diag_inode, tvb, offset, 4, nl_data->encoding);
	offset += 4;

	sock_diag_proto_tree_add_cookie(tree, info, nl_data, tvb, offset);
	offset += 8;

	return dissect_netlink_attributes_to_end(tvb, hf_netlink_sock_diag_netlink_attr, ett_netlink_sock_diag_attr, info, nl_data, tree, offset, dissect_sock_diag_netlink_attributes);
}

/* AF_NETLINK request */

static int
dissect_sock_diag_netlink_request_show(tvbuff_t *tvb, netlink_sock_diag_info_t *info _U_, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *flags_tree;

	ti = proto_tree_add_item(tree, hf_netlink_sock_diag_netlink_show, tvb, offset, 4, nl_data->encoding);
	flags_tree = proto_item_add_subtree(ti, ett_netlink_sock_diag_show);

	proto_tree_add_item(flags_tree, hf_netlink_sock_diag_netlink_show_meminfo, tvb, offset, 4, nl_data->encoding);
	proto_tree_add_item(flags_tree, hf_netlink_sock_diag_netlink_show_groups, tvb, offset, 4, nl_data->encoding);
	proto_tree_add_item(flags_tree, hf_netlink_sock_diag_netlink_show_ring_cfg, tvb, offset, 4, nl_data->encoding);
	/* XXX, unknown */

	offset += 4;

	return offset;
}

static int
dissect_sock_diag_netlink_request(tvbuff_t *tvb, netlink_sock_diag_info_t *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	/* XXX, 255 for all */
	proto_tree_add_item(tree, hf_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_sock_diag_netlink_proto, tvb, offset, 1, ENC_NA);
	offset += 1;

	_dissect_padding(tree, tvb, offset, 2);
	offset += 2;

	proto_tree_add_item(tree, hf_netlink_sock_diag_inode, tvb, offset, 4, nl_data->encoding);
	offset += 4;

	offset = dissect_sock_diag_netlink_request_show(tvb, info, nl_data, tree, offset);

	sock_diag_proto_tree_add_cookie(tree, info, nl_data, tvb, offset);
	offset += 8;

	return offset;
}

/* AF_PACKET attributes */

static int
dissect_netlink_packet_sock_diag_reply_attrs(tvbuff_t *tvb, void *data, struct packet_netlink_data *nl_data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_packet_diag_attr_type type = (enum ws_packet_diag_attr_type) nla_type;
	netlink_sock_diag_info_t *info = (netlink_sock_diag_info_t *) data;

	switch (type) {
		case WS_PACKET_DIAG_MEMINFO:
			return dissect_sock_diag_meminfo(tree, info, nl_data, tvb, offset, len);

		case WS_PACKET_DIAG_INFO:
		case WS_PACKET_DIAG_MCLIST:
		case WS_PACKET_DIAG_RX_RING:
		case WS_PACKET_DIAG_TX_RING:
		case WS_PACKET_DIAG_FANOUT:
		case WS_PACKET_DIAG_UID:
		case WS_PACKET_DIAG_FILTER:
		default:
			return 0;
	}
}

static const value_string netlink_sock_diag_packet_vals[] = {
	{ WS_PACKET_DIAG_INFO,    "info" },
	{ WS_PACKET_DIAG_MCLIST,  "mclist" },
	{ WS_PACKET_DIAG_RX_RING, "rxring" },
	{ WS_PACKET_DIAG_TX_RING, "txring" },
	{ WS_PACKET_DIAG_FANOUT,  "fanout" },
	{ WS_PACKET_DIAG_UID,     "uid" },
	{ WS_PACKET_DIAG_MEMINFO, "meminfo" },
	{ WS_PACKET_DIAG_FILTER,  "filter" },
	{ 0, NULL }
};

/* AF_PACKET */

static int
dissect_sock_diag_packet_reply(tvbuff_t *tvb, netlink_sock_diag_info_t *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, hf_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_sock_diag_type, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_sock_diag_packet_proto, tvb, offset, 2, nl_data->encoding);
	offset += 2;

	proto_tree_add_item(tree, hf_netlink_sock_diag_inode, tvb, offset, 4, nl_data->encoding);
	offset += 4;

	sock_diag_proto_tree_add_cookie(tree, info, nl_data, tvb, offset);
	offset += 8;

	return dissect_netlink_attributes_to_end(tvb, hf_netlink_sock_diag_packet_attr, ett_netlink_sock_diag_attr, info, nl_data, tree, offset, dissect_netlink_packet_sock_diag_reply_attrs);
}

/* AF_PACKET request */

static int
dissect_sock_diag_packet_request_show(tvbuff_t *tvb, netlink_sock_diag_info_t *info _U_, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *flags_tree;

	ti = proto_tree_add_item(tree, hf_netlink_sock_diag_packet_show, tvb, offset, 4, nl_data->encoding);
	flags_tree = proto_item_add_subtree(ti, ett_netlink_sock_diag_show);

	proto_tree_add_item(flags_tree, hf_netlink_sock_diag_packet_show_info, tvb, offset, 4, nl_data->encoding);
	proto_tree_add_item(flags_tree, hf_netlink_sock_diag_packet_show_mclist, tvb, offset, 4, nl_data->encoding);
	proto_tree_add_item(flags_tree, hf_netlink_sock_diag_packet_show_ring_cfg, tvb, offset, 4, nl_data->encoding);
	proto_tree_add_item(flags_tree, hf_netlink_sock_diag_packet_show_fanout, tvb, offset, 4, nl_data->encoding);
	proto_tree_add_item(flags_tree, hf_netlink_sock_diag_packet_show_meminfo, tvb, offset, 4, nl_data->encoding);
	proto_tree_add_item(flags_tree, hf_netlink_sock_diag_packet_show_filter, tvb, offset, 4, nl_data->encoding);
	/* XXX, unknown */

	offset += 4;

	return offset;
}

static int
dissect_sock_diag_packet_request(tvbuff_t *tvb, netlink_sock_diag_info_t *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, hf_netlink_sock_diag_family, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_netlink_sock_diag_packet_proto, tvb, offset, 1, ENC_NA);
	offset += 1;

	_dissect_padding(tree, tvb, offset, 2);
	offset += 2;

	proto_tree_add_item(tree, hf_netlink_sock_diag_inode, tvb, offset, 4, nl_data->encoding);
	offset += 4;

	offset = dissect_sock_diag_packet_request_show(tvb, info, nl_data, tree, offset);

	sock_diag_proto_tree_add_cookie(tree, info, nl_data, tvb, offset);
	offset += 8;

	return offset;
}

/* WS_SOCK_DIAG_BY_FAMILY dissection */

static int
dissect_sock_diag_by_family(tvbuff_t *tvb, netlink_sock_diag_info_t *info, struct packet_netlink_data *nl_data, proto_tree *tree, int offset)
{
	const bool is_req = (info->pinfo->p2p_dir == P2P_DIR_SENT);
	uint8_t af_family;

	af_family = tvb_get_uint8(tvb, offset);

	switch (af_family) {
		case LINUX_AF_LOCAL:
			offset = (is_req) ?
				dissect_sock_diag_unix_request(tvb, info, nl_data, tree, offset) :
				dissect_sock_diag_unix_reply(tvb, info, nl_data, tree, offset);
			break;

		case LINUX_AF_INET:
		case LINUX_AF_INET6:
			offset = (is_req) ?
				dissect_sock_diag_inet_request(tvb, info, nl_data, tree, offset) :
				dissect_sock_diag_inet_reply(tvb, info, nl_data, tree, offset);
			break;

		case LINUX_AF_NETLINK:
			offset = (is_req) ?
				dissect_sock_diag_netlink_request(tvb, info, nl_data, tree, offset) :
				dissect_sock_diag_netlink_reply(tvb, info, nl_data, tree, offset);
			break;

		case LINUX_AF_PACKET:
			offset = (is_req) ?
				dissect_sock_diag_packet_request(tvb, info, nl_data, tree, offset) :
				dissect_sock_diag_packet_reply(tvb, info, nl_data, tree, offset);
			break;
	}

	return offset;
}

static const value_string netlink_sock_diag_type_vals[] = {
	{ WS_TCPDIAG_GETSOCK,     "TCPDIAG_GETSOCK" },
	{ WS_DCCPDIAG_GETSOCK,    "DCCPDIAG_GETSOCK" },
	{ WS_SOCK_DIAG_BY_FAMILY, "SOCK_DIAG_BY_FAMILY" },
	{ WS_SOCK_DESTROY,        "SOCK_DESTROY" },
	{ 0, NULL }
};

static int
dissect_netlink_sock_diag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	struct packet_netlink_data *nl_data = (struct packet_netlink_data *)data;
	netlink_sock_diag_info_t info;
	proto_tree *nlmsg_tree;
	proto_item *pi;
	int offset = 0;

	DISSECTOR_ASSERT(nl_data && nl_data->magic == PACKET_NETLINK_MAGIC);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Netlink sock diag");
	col_clear(pinfo->cinfo, COL_INFO);

	pi = proto_tree_add_item(tree, proto_netlink_sock_diag, tvb, 0, -1, ENC_NA);
	nlmsg_tree = proto_item_add_subtree(pi, ett_netlink_sock_diag);

	/* Netlink message header (nlmsghdr) */
	offset = dissect_netlink_header(tvb, nlmsg_tree, offset, nl_data->encoding, hf_netlink_sock_diag_nltype, NULL);

	info.pinfo = pinfo;

	switch (nl_data->type) {
		case WS_TCPDIAG_GETSOCK:
		case WS_DCCPDIAG_GETSOCK:
			/* XXX, inet_diag_rcv_msg_compat */
			break;

		case WS_SOCK_DIAG_BY_FAMILY:
			offset = dissect_sock_diag_by_family(tvb, &info, nl_data, nlmsg_tree, offset);
			break;
	}

	return offset;
}

void
proto_register_netlink_sock_diag(void)
{
	static hf_register_info hf[] = {
		{ &hf_netlink_sock_diag_family,
			{ "Family", "netlink-sock_diag.family",
			  FT_UINT8, BASE_DEC | BASE_EXT_STRING, &linux_af_vals_ext, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_type,
			{ "Type", "netlink-sock_diag.type",
			  FT_UINT8, BASE_DEC, VALS(socket_type_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_state,
			{ "State", "netlink-sock_diag.state",
			  FT_UINT8, BASE_DEC, VALS(socket_state_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_inode,
			{ "Inode", "netlink-sock_diag.inode",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_rqueue,
			{ "Recv Queue", "netlink-sock_diag.recv_queue",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_wqueue,
			{ "Send Queue", "netlink-sock_diag.send_queue",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_rmem_alloc,
			{ "Read allocation", "netlink-sock_diag.rmem_alloc",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_rcvbuf,
			{ "Recv buffer", "netlink-sock_diag.rcvbuf",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_wmem_alloc,
			{ "Write allocation", "netlink-sock_diag.wmem_alloc",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_sndbuf,
			{ "Send buffer", "netlink-sock_diag.sndbuf",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_fwd_alloc,
			{ "Forward allocation", "netlink-sock_diag.fwd_alloc",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_wmem_queued,
			{ "Write allocation queued", "netlink-sock_diag.wmem_queued",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_cookie,
			{ "Cookie", "netlink-sock_diag.cookie",
			  FT_UINT64, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_shutdown,
			{ "Shutdown flag", "netlink-sock_diag.shutdown",
			  FT_UINT8, BASE_HEX, VALS(netlink_sock_diag_shutdown_flags_vals), 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_unix_attr,
			{ "Type", "netlink-sock_diag.unix_attr",
			  FT_UINT16, BASE_DEC, VALS(netlink_sock_diag_unix_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_unix_name,
			{ "Name", "netlink-sock_diag.unix_name",
			  FT_STRINGZ, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_unix_peer_inode,
			{ "Peer inode", "netlink-sock_diag.unix_peer_inode",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_unix_show,
			{ "Show", "netlink-sock_diag.unix_show",
			  FT_UINT32, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_unix_show_name,
			{ "Name", "netlink-sock_diag.unix_show.name",
			  FT_BOOLEAN, 32, TFS(&_tfs_show_do_not_show), WS_UDIAG_SHOW_NAME,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_unix_show_vfs,
			{ "VFS inode info", "netlink-sock_diag.unix_show.vfs",
			  FT_BOOLEAN, 32, TFS(&_tfs_show_do_not_show), WS_UDIAG_SHOW_VFS,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_unix_show_peer,
			{ "Peer socket info", "netlink-sock_diag.unix_show.peer",
			  FT_BOOLEAN, 32, TFS(&_tfs_show_do_not_show), WS_UDIAG_SHOW_PEER,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_unix_show_icons,
			{ "Pending connections", "netlink-sock_diag.unix_show.icons",
			  FT_BOOLEAN, 32, TFS(&_tfs_show_do_not_show), WS_UDIAG_SHOW_ICONS,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_unix_show_rqlen,
			{ "skb receive queue len", "netlink-sock_diag.unix_show.rqlen",
			  FT_BOOLEAN, 32, TFS(&_tfs_show_do_not_show), WS_UDIAG_SHOW_RQLEN,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_unix_show_meminfo,
			{ "Memory info of a socket", "netlink-sock_diag.unix_show.meminfo",
			  FT_BOOLEAN, 32, TFS(&_tfs_show_do_not_show), WS_UDIAG_SHOW_MEMINFO,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_inet_attr,
			{ "Type", "netlink-sock_diag.inet_attr",
			  FT_UINT16, BASE_DEC, VALS(netlink_sock_diag_inet_attr_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_inet_sport,
			{ "Source port", "netlink-sock_diag.inet_sport",
			  FT_UINT16, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_inet_dport,
			{ "Dest port", "netlink-sock_diag.inet_dport",
			  FT_UINT16, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_inet_src_ip4,
			{ "Source IP", "netlink-sock_diag.inet_src_ip4",
			  FT_IPv4, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_inet_dst_ip4,
			{ "Dest IP", "netlink-sock_diag.inet_dest_ip4",
			  FT_IPv4, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_inet_src_ip6,
			{ "Source IP", "netlink-sock_diag.inet_src_ip6",
			  FT_IPv6, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_inet_dst_ip6,
			{ "Dest IP", "netlink-sock_diag.inet_dest_ip6",
			  FT_IPv6, BASE_NONE, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_inet_interface,
			{ "Interface", "netlink-sock_diag.inet_interface",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_inet_proto,
			{ "Protocol", "netlink-sock_diag.inet_protocol",
			  FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_inet_extended,
			{ "Requested info", "netlink-sock_diag.inet_extended",
			  FT_UINT8, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_inet_padding,
			{ "v2 Padding or v1 info", "netlink-sock_diag.inet_padding",
			  FT_UINT8, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_inet_states,
			{ "State filter", "netlink-sock_diag.inet_states",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_netlink_attr,
			{ "Type", "netlink-sock_diag.netlink_attr",
			  FT_UINT16, BASE_DEC, VALS(netlink_sock_diag_netlink_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_netlink_proto,
			{ "Protocol", "netlink-sock_diag.netlink_protocol",
			  FT_UINT8, BASE_DEC | BASE_EXT_STRING, &netlink_family_vals_ext, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_netlink_port_id,
			{ "Port ID", "netlink-sock_diag.netlink_portid",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_netlink_dst_port_id,
			{ "Dest Port ID", "netlink-sock_diag.netlink_dst_portid",
			  FT_UINT32, BASE_DEC, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_netlink_show,
			{ "Show", "netlink-sock_diag.netlink_show",
			  FT_UINT32, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_netlink_show_meminfo,
			{ "Memory info of a socket", "netlink-sock_diag.netlink_show.meminfo",
			  FT_BOOLEAN, 32, TFS(&_tfs_show_do_not_show), WS_NDIAG_SHOW_MEMINFO,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_netlink_show_groups,
			{ "Groups of a netlink socket", "netlink-sock_diag.netlink_show.groups",
			  FT_BOOLEAN, 32, TFS(&_tfs_show_do_not_show), WS_NDIAG_SHOW_GROUPS,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_netlink_show_ring_cfg,
			{ "Ring configuration", "netlink-sock_diag.netlink_show.ring_cfg",
			  FT_BOOLEAN, 32, TFS(&_tfs_show_do_not_show), WS_NDIAG_SHOW_RING_CFG,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_packet_attr,
			{ "Type", "netlink-sock_diag.netlink_attr",
			  FT_UINT16, BASE_DEC, VALS(netlink_sock_diag_packet_vals), NLA_TYPE_MASK,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_packet_proto,
			{ "Protocol", "netlink-sock_diag.packet_protocol",
			  FT_UINT16, BASE_HEX, VALS(etype_vals) /* XXX + Linux specific */, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_packet_show,
			{ "Show", "netlink-sock_diag.packet_show",
			  FT_UINT32, BASE_HEX, NULL, 0x00,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_packet_show_info,
			{ "Basic packet_sk information", "netlink-sock_diag.packet_show.info",
			  FT_BOOLEAN, 32, TFS(&_tfs_show_do_not_show), WS_PACKET_SHOW_INFO,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_packet_show_mclist,
			{ "Set of packet_diag_mclist-s", "netlink-sock_diag.packet_show.mclist",
			  FT_BOOLEAN, 32, TFS(&_tfs_show_do_not_show), WS_PACKET_SHOW_MCLIST,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_packet_show_ring_cfg,
			{ "Rings configuration parameters", "netlink-sock_diag.packet_show.ring_cfg",
			  FT_BOOLEAN, 32, TFS(&_tfs_show_do_not_show), WS_PACKET_SHOW_RING_CFG,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_packet_show_fanout,
			{ "Fanout", "netlink-sock_diag.packet_show.fanout",
			  FT_BOOLEAN, 32, TFS(&_tfs_show_do_not_show), WS_PACKET_SHOW_FANOUT,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_packet_show_meminfo,
			{ "memory info", "netlink-sock_diag.packet_show.meminfo",
			  FT_BOOLEAN, 32, TFS(&_tfs_show_do_not_show), WS_PACKET_SHOW_MEMINFO,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_packet_show_filter,
			{ "Filter", "netlink-sock_diag.packet_show.filter",
			  FT_BOOLEAN, 32, TFS(&_tfs_show_do_not_show), WS_PACKET_SHOW_FILTER,
			  NULL, HFILL }
		},
		{ &hf_netlink_sock_diag_nltype,
			{ "Message type", "netlink-sock_diag.nltype",
			  FT_UINT16, BASE_DEC, VALS(netlink_sock_diag_type_vals), 0x00,
			  NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_netlink_sock_diag,
		&ett_netlink_sock_diag_show,
		&ett_netlink_sock_diag_attr
	};

	proto_netlink_sock_diag = proto_register_protocol("Linux netlink sock diag protocol", "sock_diag", "netlink-sock_diag" );
	proto_register_field_array(proto_netlink_sock_diag, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_sock_diag_handle = register_dissector("netlink-sock_diag", dissect_netlink_sock_diag, proto_netlink_sock_diag);
}

void
proto_reg_handoff_netlink_sock_diag(void)
{
	dissector_add_uint("netlink.protocol", WS_NETLINK_SOCK_DIAG, netlink_sock_diag_handle);
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

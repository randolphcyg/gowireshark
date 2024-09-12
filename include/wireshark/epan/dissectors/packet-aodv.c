/* packet-aodv.c
 * Routines for AODV dissection
 * Copyright 2000, Erik Nordstrom <erik.nordstrom@it.uu.se>
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
#include <epan/expert.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>

/*
 * See
 *
 *      RFC 3561 (which indicates that, for IPv6, the only change is that
 *      the address fields are enlarged)
 *
 *      http://www.cs.ucsb.edu/~ebelding/txt/aodv6.txt
 *
 *      http://www.tcs.hut.fi/~anttit/manet/drafts/draft-perkins-aodv6-01.txt
 *
 *      (both of the above two are draft-perkins-manet-aodv6-01.txt, which
 *      is from November 2000)
 */
void proto_register_aodv(void);
void proto_reg_handoff_aodv(void);
static dissector_handle_t aodv_handle;

#define INET6_ADDRLEN   16
#define UDP_PORT_AODV   654

/* Message Types */
#define RREQ                     1
#define RREP                     2
#define RERR                     3
#define RREP_ACK                 4
#define DRAFT_01_V6_RREQ        16
#define DRAFT_01_V6_RREP        17
#define DRAFT_01_V6_RERR        18
#define DRAFT_01_V6_RREP_ACK    19

/* Extension Types */
#define AODV_EXT        1
#define AODV_EXT_INT    2
#define AODV_EXT_NTP    3

/* Flag bits: */
#define RREQ_UNKNSEQ    0x0800
#define RREQ_DESTONLY   0x1000
#define RREQ_GRATRREP   0x2000
#define RREQ_REP        0x4000
#define RREQ_JOIN       0x8000

#define RREP_ACK_REQ    0x4000
#define RREP_REP        0x8000

#define RERR_NODEL      0x8000

static const value_string type_vals[] = {
    { RREQ,                 "Route Request" },
    { RREP,                 "Route Reply" },
    { RERR,                 "Route Error" },
    { RREP_ACK,             "Route Reply Acknowledgment"},
    { DRAFT_01_V6_RREQ,     "draft-perkins-manet-aodv6-01 IPv6 Route Request"},
    { DRAFT_01_V6_RREP,     "draft-perkins-manet-aodv6-01 IPv6 Route Reply"},
    { DRAFT_01_V6_RERR,     "draft-perkins-manet-aodv6-01 IPv6 Route Error"},
    { DRAFT_01_V6_RREP_ACK, "draft-perkins-manet-aodv6-01 IPv6 Route Reply Acknowledgment"},
    { 0,                    NULL }
};

static const value_string exttype_vals[] = {
    { AODV_EXT,     "None"},
    { AODV_EXT_INT, "Hello Interval"},
    { AODV_EXT_NTP, "Timestamp"},
    { 0,            NULL}
};

typedef struct v6_ext {
    uint8_t type;
    uint8_t length;
} aodv_ext_t;

/* Initialize the protocol and registered fields */
static int proto_aodv;
static int hf_aodv_type;
static int hf_aodv_flags;
static int hf_aodv_prefix_sz;
static int hf_aodv_hopcount;
static int hf_aodv_rreq_id;
static int hf_aodv_dest_ip;
static int hf_aodv_dest_ipv6;
static int hf_aodv_dest_seqno;
static int hf_aodv_orig_ip;
static int hf_aodv_orig_ipv6;
static int hf_aodv_orig_seqno;
static int hf_aodv_lifetime;
static int hf_aodv_destcount;
static int hf_aodv_unreach_dest_ip;
static int hf_aodv_unreach_dest_ipv6;
/* static int hf_aodv_unreach_dest_seqno; */
static int hf_aodv_flags_rreq_join;
static int hf_aodv_flags_rreq_repair;
static int hf_aodv_flags_rreq_gratuitous;
static int hf_aodv_flags_rreq_destinationonly;
static int hf_aodv_flags_rreq_unknown;
static int hf_aodv_flags_rrep_repair;
static int hf_aodv_flags_rrep_ack;
static int hf_aodv_flags_rerr_nodelete;
static int hf_aodv_ext_type;
static int hf_aodv_ext_length;
static int hf_aodv_ext_interval;
static int hf_aodv_ext_timestamp;

/* Initialize the subtree pointers */
static int ett_aodv;
static int ett_aodv_flags;
static int ett_aodv_unreach_dest;
static int ett_aodv_extensions;

static expert_field ei_aodv_ext_length;
static expert_field ei_aodv_type;

/* Code to actually dissect the packets */

static void
dissect_aodv_ext(tvbuff_t * tvb, packet_info *pinfo, int offset, proto_tree * tree)
{
    proto_tree *ext_tree;
    proto_item *len_item;
    uint8_t     type, len;

again:
    if ((int) tvb_reported_length(tvb) <= offset)
        return;                 /* No more options left */

    type = tvb_get_uint8(tvb, offset);
    len = tvb_get_uint8(tvb, offset + 1);

    ext_tree = proto_tree_add_subtree(tree, tvb, offset, 2 + len, ett_aodv_extensions, NULL, "Extensions");

    proto_tree_add_item(ext_tree, hf_aodv_ext_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    len_item = proto_tree_add_uint(ext_tree, hf_aodv_ext_length, tvb, offset + 1, 1, len);
    if (len == 0) {
        expert_add_info(pinfo, len_item, &ei_aodv_ext_length);
        return;                 /* we must not try to decode this */
    }

    offset += 2;

    switch (type) {
    case AODV_EXT_INT:
        proto_tree_add_item(ext_tree, hf_aodv_ext_interval,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        break;
    case AODV_EXT_NTP:
        proto_tree_add_item(ext_tree, hf_aodv_ext_timestamp,
                            tvb, offset, 8, ENC_BIG_ENDIAN);
        break;
    default:
            break;
    }
    /* If multifield extensions appear, we need more
     * sophisticated handler.  For now, this is okay. */

    offset += len;
    goto again;
}

static void
dissect_aodv_rreq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *aodv_tree,
                  proto_item *ti, bool is_ipv6)
{
    int                offset = 1;
    uint8_t            hop_count;
    uint32_t           rreq_id;
    const char        *dest_addr_v4;
    const char        *dest_addr_v6;
    uint32_t           dest_seqno;
    const char        *orig_addr_v4;
    const char        *orig_addr_v6;
    uint32_t           orig_seqno;
    int                extlen;
    static int * const aodv_flags[] = {
        &hf_aodv_flags_rreq_join,
        &hf_aodv_flags_rreq_repair,
        &hf_aodv_flags_rreq_gratuitous,
        &hf_aodv_flags_rreq_destinationonly,
        &hf_aodv_flags_rreq_unknown,
        NULL
    };

    proto_tree_add_bitmask_with_flags(aodv_tree, tvb, offset, hf_aodv_flags,
                   ett_aodv_flags, aodv_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_TFS | BMT_NO_INT);
    offset += 2;        /* skip reserved byte */

    hop_count = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(aodv_tree, hf_aodv_hopcount, tvb, offset, 1,
                            hop_count);
    offset += 1;

    rreq_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(aodv_tree, hf_aodv_rreq_id, tvb, offset, 4,
                                        rreq_id);
    offset += 4;

    if (is_ipv6) {
        dest_addr_v6 = tvb_ip6_to_str(pinfo->pool, tvb, offset);
        if (aodv_tree) {
            proto_tree_add_item(aodv_tree, hf_aodv_dest_ipv6, tvb, offset,
                                INET6_ADDRLEN, ENC_NA);
            proto_item_append_text(ti, ", Dest IP: %s", dest_addr_v6);
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, ", D: %s", dest_addr_v6);
        offset += INET6_ADDRLEN;
    } else {
        dest_addr_v4 = tvb_ip_to_str(pinfo->pool, tvb, offset);
        if (aodv_tree) {
            proto_tree_add_item(aodv_tree, hf_aodv_dest_ip, tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            proto_item_append_text(ti, ", Dest IP: %s", dest_addr_v4);
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, ", D: %s", dest_addr_v4);
        offset += 4;
    }

    dest_seqno = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(aodv_tree, hf_aodv_dest_seqno, tvb, offset, 4,
                                        dest_seqno);
    offset += 4;

    if (is_ipv6) {
        orig_addr_v6 = tvb_ip6_to_str(pinfo->pool, tvb, offset);
        if (aodv_tree) {
            proto_tree_add_item(aodv_tree, hf_aodv_orig_ipv6, tvb, offset,
                                INET6_ADDRLEN, ENC_NA);
            proto_item_append_text(ti, ", Orig IP: %s", orig_addr_v6);
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, ", O: %s", orig_addr_v6);
        offset += INET6_ADDRLEN;
    } else {
        orig_addr_v4 = tvb_ip_to_str(pinfo->pool, tvb, offset);
        if (aodv_tree) {
            proto_tree_add_item(aodv_tree, hf_aodv_orig_ip, tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            proto_item_append_text(ti, ", Orig IP: %s", orig_addr_v4);
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, ", O: %s", orig_addr_v4);
        offset += 4;
    }

    orig_seqno = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(aodv_tree, hf_aodv_orig_seqno, tvb, offset, 4,
                                        orig_seqno);
    col_append_fstr(pinfo->cinfo, COL_INFO, " Id=%u Hcnt=%u DSN=%u OSN=%u",
                    rreq_id,
                    hop_count,
                    dest_seqno,
                    orig_seqno);
    offset += 4;

    extlen = tvb_reported_length_remaining(tvb, offset);
    if (extlen > 0)
        dissect_aodv_ext(tvb, pinfo, offset, aodv_tree);
}

static void
dissect_aodv_rrep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *aodv_tree,
                  proto_item *ti, bool is_ipv6)
{
    int                offset = 1;
    uint16_t           flags;
    uint8_t            prefix_sz;
    uint8_t            hop_count;
    const char        *dest_addr_v4;
    const char        *dest_addr_v6;
    uint32_t           dest_seqno;
    const char        *orig_addr_v4;
    const char        *orig_addr_v6;
    uint32_t           lifetime;
    int                extlen;
    static int * const aodv_flags[] = {
        &hf_aodv_flags_rrep_repair,
        &hf_aodv_flags_rrep_ack,
        NULL
    };

    flags = tvb_get_ntohs(tvb, offset);
    proto_tree_add_bitmask_with_flags(aodv_tree, tvb, offset, hf_aodv_flags,
                   ett_aodv_flags, aodv_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_TFS | BMT_NO_INT);
    offset += 1;

    prefix_sz = flags & 0x1F;
    if (aodv_tree)
        proto_tree_add_uint(aodv_tree, hf_aodv_prefix_sz, tvb, offset, 1,
                            prefix_sz);
    offset += 1;

    hop_count = tvb_get_uint8(tvb, offset);
    if (aodv_tree)
        proto_tree_add_uint(aodv_tree, hf_aodv_hopcount, tvb, offset, 1,
                            hop_count);
    offset += 1;

    if (is_ipv6) {
        dest_addr_v6 = tvb_ip6_to_str(pinfo->pool, tvb, offset);
        if (aodv_tree) {
            proto_tree_add_item(aodv_tree, hf_aodv_dest_ipv6, tvb, offset,
                                INET6_ADDRLEN, ENC_NA);
            proto_item_append_text(ti, ", Dest IP: %s", dest_addr_v6);
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, ", D: %s", dest_addr_v6);
        offset += INET6_ADDRLEN;
    } else {
        dest_addr_v4 = tvb_ip_to_str(pinfo->pool, tvb, offset);
        if (aodv_tree) {
            proto_tree_add_item(aodv_tree, hf_aodv_dest_ip, tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            proto_item_append_text(ti, ", Dest IP: %s", dest_addr_v4);
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, ", D: %s", dest_addr_v4);
        offset += 4;
    }

    dest_seqno = tvb_get_ntohl(tvb, offset);
    if (aodv_tree)
        proto_tree_add_uint(aodv_tree, hf_aodv_dest_seqno, tvb, offset, 4,
                            dest_seqno);
    offset += 4;

    if (is_ipv6) {
        orig_addr_v6 = tvb_ip6_to_str(pinfo->pool, tvb, offset);
        if (aodv_tree) {
            proto_tree_add_item(aodv_tree, hf_aodv_orig_ipv6, tvb, offset,
                                INET6_ADDRLEN, ENC_NA);
            proto_item_append_text(ti, ", Orig IP: %s", orig_addr_v6);
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, ", O: %s", orig_addr_v6);
        offset += INET6_ADDRLEN;
    } else {
        orig_addr_v4 = tvb_ip_to_str(pinfo->pool, tvb, offset);
        if (aodv_tree) {
            proto_tree_add_item(aodv_tree, hf_aodv_orig_ip, tvb, offset, 4,
                                ENC_BIG_ENDIAN);
            proto_item_append_text(ti, ", Orig IP: %s", orig_addr_v4);
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, ", O: %s", orig_addr_v4);
        offset += 4;
    }

    lifetime = tvb_get_ntohl(tvb, offset);
    if (aodv_tree) {
        proto_tree_add_uint(aodv_tree, hf_aodv_lifetime, tvb, offset, 4,
                            lifetime);
        proto_item_append_text(ti, ", Lifetime=%u", lifetime);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " Hcnt=%u DSN=%u Lifetime=%u",
                    hop_count,
                    dest_seqno,
                    lifetime);
    offset += 4;

    extlen = tvb_reported_length_remaining(tvb, offset);
    if (extlen > 0)
        dissect_aodv_ext(tvb, pinfo, offset, aodv_tree);
}

static void
dissect_aodv_rerr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *aodv_tree,
                  bool is_ipv6)
{
    int         offset = 1;
    proto_tree *aodv_unreach_dest_tree;
    uint8_t     dest_count;
    int         i;
    static int * const aodv_flags[] = {
        &hf_aodv_flags_rerr_nodelete,
        NULL
    };

    proto_tree_add_bitmask_with_flags(aodv_tree, tvb, offset, hf_aodv_flags,
                   ett_aodv_flags, aodv_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_TFS | BMT_NO_INT);
    offset += 2;        /* skip reserved byte */

    dest_count = tvb_get_uint8(tvb, offset);
    if (aodv_tree)
        proto_tree_add_uint(aodv_tree, hf_aodv_destcount, tvb, offset, 1,
                            dest_count);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Dest Count=%u",
                        dest_count);
    offset += 1;

    if (is_ipv6) {
        aodv_unreach_dest_tree = proto_tree_add_subtree(aodv_tree, tvb, offset,
                                 (INET6_ADDRLEN + 4)*dest_count, ett_aodv_unreach_dest, NULL,
                                 "Unreachable Destinations");
        for (i = 0; i < dest_count; i++) {
            proto_tree_add_item(aodv_unreach_dest_tree,
                                hf_aodv_unreach_dest_ipv6,
                                tvb, offset, INET6_ADDRLEN, ENC_NA);
            offset += INET6_ADDRLEN;
            proto_tree_add_item(aodv_unreach_dest_tree, hf_aodv_dest_seqno,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
    } else {
        aodv_unreach_dest_tree = proto_tree_add_subtree(aodv_tree, tvb, offset, (4 + 4)*dest_count,
                                 ett_aodv_unreach_dest, NULL, "Unreachable Destinations");
        for (i = 0; i < dest_count; i++) {
            proto_tree_add_item(aodv_unreach_dest_tree, hf_aodv_unreach_dest_ip,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(aodv_unreach_dest_tree, hf_aodv_dest_seqno,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
    }
}

static void
dissect_aodv_draft_01_v6_rreq(tvbuff_t *tvb, packet_info *pinfo,
                              proto_tree *aodv_tree, proto_item *ti)
{
    int                offset = 1;
    uint8_t            hop_count;
    uint32_t           rreq_id;
    uint32_t           dest_seqno;
    uint32_t           orig_seqno;
    const char        *dest_addr_v6;
    const char        *orig_addr_v6;
    int                extlen;
    static int * const aodv_flags[] = {
        &hf_aodv_flags_rreq_join,
        &hf_aodv_flags_rreq_repair,
        &hf_aodv_flags_rreq_gratuitous,
        &hf_aodv_flags_rreq_destinationonly,
        &hf_aodv_flags_rreq_unknown,
        NULL
    };

    proto_tree_add_bitmask_with_flags(aodv_tree, tvb, offset, hf_aodv_flags,
                   ett_aodv_flags, aodv_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_TFS | BMT_NO_INT);
    offset += 2;        /* skip reserved byte */

    hop_count = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(aodv_tree, hf_aodv_hopcount, tvb, offset, 1,
                             hop_count);
    offset += 1;

    rreq_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(aodv_tree, hf_aodv_rreq_id, tvb, offset, 4,
                            rreq_id);
    offset += 4;

    dest_seqno = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(aodv_tree, hf_aodv_dest_seqno, tvb, offset, 4,
                            dest_seqno);
    offset += 4;

    orig_seqno = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(aodv_tree, hf_aodv_orig_seqno, tvb, offset, 4,
                            orig_seqno);
    offset += 4;

    dest_addr_v6 = tvb_ip6_to_str(pinfo->pool, tvb, offset);
    if (aodv_tree) {
        proto_tree_add_item(aodv_tree, hf_aodv_dest_ipv6, tvb, offset,
                            INET6_ADDRLEN, ENC_NA);
        proto_item_append_text(ti, ", Dest IP: %s", dest_addr_v6);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ", D: %s", dest_addr_v6);
    offset += INET6_ADDRLEN;

    orig_addr_v6 = tvb_ip6_to_str(pinfo->pool, tvb, offset);
    if (aodv_tree) {
        proto_tree_add_item(aodv_tree, hf_aodv_orig_ipv6, tvb, offset,
                            INET6_ADDRLEN, ENC_NA);
        proto_item_append_text(ti, ", Orig IP: %s", orig_addr_v6);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO,
                        ", O: %s Id=%u Hcnt=%u DSN=%u OSN=%u",
                        orig_addr_v6,
                        rreq_id,
                        hop_count,
                        dest_seqno,
                        orig_seqno);
    offset += INET6_ADDRLEN;

    extlen = tvb_reported_length_remaining(tvb, offset);
    if (extlen > 0)
        dissect_aodv_ext(tvb, pinfo, offset, aodv_tree);
}

static void
dissect_aodv_draft_01_v6_rrep(tvbuff_t *tvb, packet_info *pinfo,
                              proto_tree *aodv_tree, proto_item *ti)
{
    int                offset = 1;
    uint16_t           flags;
    uint8_t            prefix_sz;
    uint8_t            hop_count;
    uint32_t           dest_seqno;
    const char        *dest_addr_v6;
    const char        *orig_addr_v6;
    uint32_t           lifetime;
    int                extlen;
    static int * const aodv_flags[] = {
        &hf_aodv_flags_rrep_repair,
        &hf_aodv_flags_rrep_ack,
        NULL
    };

    flags = tvb_get_ntohs(tvb, offset);
    proto_tree_add_bitmask_with_flags(aodv_tree, tvb, offset, hf_aodv_flags,
                   ett_aodv_flags, aodv_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_TFS | BMT_NO_INT);
    offset += 1;

    prefix_sz = flags & 0x7F;
    proto_tree_add_uint(aodv_tree, hf_aodv_prefix_sz, tvb, offset, 1,
                            prefix_sz);
    offset += 1;

    hop_count = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(aodv_tree, hf_aodv_hopcount, tvb, offset, 1,
                            hop_count);
    offset += 1;

    dest_seqno = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(aodv_tree, hf_aodv_dest_seqno, tvb, offset, 4,
                            dest_seqno);
    offset += 4;

    dest_addr_v6 = tvb_ip6_to_str(pinfo->pool, tvb, offset);
    if (aodv_tree) {
        proto_tree_add_item(aodv_tree, hf_aodv_dest_ipv6, tvb, offset,
                            INET6_ADDRLEN, ENC_NA);
        proto_item_append_text(ti, ", Dest IP: %s", dest_addr_v6);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ", D: %s", dest_addr_v6);
    offset += INET6_ADDRLEN;

    orig_addr_v6 = tvb_ip6_to_str(pinfo->pool, tvb, offset);
    if (aodv_tree) {
        proto_tree_add_item(aodv_tree, hf_aodv_orig_ipv6, tvb, offset,
                            INET6_ADDRLEN, ENC_NA);
        proto_item_append_text(ti, ", Orig IP: %s", orig_addr_v6);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ", O: %s", orig_addr_v6);
    offset += INET6_ADDRLEN;

    lifetime = tvb_get_ntohl(tvb, offset);
    if (aodv_tree) {
        proto_tree_add_uint(aodv_tree, hf_aodv_lifetime, tvb, offset, 4,
                            lifetime);
        proto_item_append_text(ti, ", Lifetime=%u", lifetime);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " Hcnt=%u DSN=%u Lifetime=%u",
                        hop_count,
                        dest_seqno,
                        lifetime);
    offset += 4;

    extlen = tvb_reported_length_remaining(tvb, offset);
    if (extlen > 0)
        dissect_aodv_ext(tvb, pinfo, offset, aodv_tree);
}

static void
dissect_aodv_draft_01_v6_rerr(tvbuff_t *tvb, packet_info *pinfo,
                              proto_tree *aodv_tree)
{
    int         offset = 1;
    proto_tree *aodv_unreach_dest_tree;
    uint8_t     dest_count;
    int         i;
    static int * const aodv_flags[] = {
        &hf_aodv_flags_rerr_nodelete,
        NULL
    };

    proto_tree_add_bitmask_with_flags(aodv_tree, tvb, offset, hf_aodv_flags,
                   ett_aodv_flags, aodv_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_TFS | BMT_NO_INT);
    offset += 2;        /* skip reserved byte */

    dest_count = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(aodv_tree, hf_aodv_destcount, tvb, offset, 1,
                            dest_count);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Dest Count=%u",
                        dest_count);
    offset += 1;

    aodv_unreach_dest_tree = proto_tree_add_subtree(aodv_tree, tvb, offset,
                             (4 + INET6_ADDRLEN)*dest_count,
                             ett_aodv_unreach_dest, NULL,
                             "Unreachable Destinations");
    for (i = 0; i < dest_count; i++) {
        proto_tree_add_item(aodv_unreach_dest_tree, hf_aodv_dest_seqno,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(aodv_unreach_dest_tree,
                            hf_aodv_unreach_dest_ipv6,
                            tvb, offset, INET6_ADDRLEN, ENC_NA);
        offset += INET6_ADDRLEN;
    }
}

static int
dissect_aodv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti, *type_item;
    proto_tree *aodv_tree;
    bool        is_ipv6;
    uint8_t     type;

/* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AODV");

    col_clear(pinfo->cinfo, COL_INFO);

    /* Is this running over IPv6? */
    is_ipv6 = (pinfo->src.type == AT_IPv6);

    /* Check the type of AODV packet. */
    type = tvb_get_uint8(tvb, 0);
    if (try_val_to_str(type, type_vals) == NULL) {
        /*
         * We assume this is not an AODV packet.
         */
        return 0;
    }


    col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str(type, type_vals,
                           "Unknown AODV Packet Type (%u)"));
        ti = proto_tree_add_protocol_format(tree, proto_aodv, tvb, 0, -1,
            "Ad hoc On-demand Distance Vector Routing Protocol, %s",
            val_to_str(type, type_vals, "Unknown AODV Packet Type (%u)"));
        aodv_tree = proto_item_add_subtree(ti, ett_aodv);

        type_item = proto_tree_add_uint(aodv_tree, hf_aodv_type, tvb, 0, 1, type);

    switch (type) {
    case RREQ:
        dissect_aodv_rreq(tvb, pinfo, aodv_tree, ti, is_ipv6);
        break;
    case RREP:
        dissect_aodv_rrep(tvb, pinfo, aodv_tree, ti, is_ipv6);
        break;
    case RERR:
        dissect_aodv_rerr(tvb, pinfo, aodv_tree, is_ipv6);
        break;
    case RREP_ACK:
        break;
    case DRAFT_01_V6_RREQ:
        dissect_aodv_draft_01_v6_rreq(tvb, pinfo, aodv_tree, ti);
        break;
    case DRAFT_01_V6_RREP:
        dissect_aodv_draft_01_v6_rrep(tvb, pinfo, aodv_tree, ti);
        break;
    case DRAFT_01_V6_RERR:
        dissect_aodv_draft_01_v6_rerr(tvb, pinfo, aodv_tree);
        break;
    case DRAFT_01_V6_RREP_ACK:
        break;
    default:
        expert_add_info(pinfo, type_item, &ei_aodv_type);
    }

    return tvb_reported_length(tvb);
}


/* Register the protocol with Wireshark */
void
proto_register_aodv(void)
{
    static hf_register_info hf[] = {
        { &hf_aodv_type,
          { "Type", "aodv.type",
            FT_UINT8, BASE_DEC, VALS(type_vals), 0x0,
            "AODV packet type", HFILL }
        },
        { &hf_aodv_flags,
          { "Flags", "aodv.flags",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_aodv_flags_rreq_join,
          { "RREQ Join", "aodv.flags.rreq_join",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), RREQ_JOIN,
            NULL, HFILL }
        },
        { &hf_aodv_flags_rreq_repair,
          { "RREQ Repair", "aodv.flags.rreq_repair",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), RREQ_REP,
            NULL, HFILL }
        },
        { &hf_aodv_flags_rreq_gratuitous,
          { "RREQ Gratuitous RREP", "aodv.flags.rreq_gratuitous",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), RREQ_GRATRREP,
            NULL, HFILL }
        },
        { &hf_aodv_flags_rreq_destinationonly,
          { "RREQ Destination only", "aodv.flags.rreq_destinationonly",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), RREQ_DESTONLY,
            NULL, HFILL }
        },
        { &hf_aodv_flags_rreq_unknown,
          { "RREQ Unknown Sequence Number", "aodv.flags.rreq_unknown",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), RREQ_UNKNSEQ,
            NULL, HFILL }
        },
        { &hf_aodv_flags_rrep_repair,
          { "RREP Repair", "aodv.flags.rrep_repair",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), RREP_REP,
            NULL, HFILL }
        },
        { &hf_aodv_flags_rrep_ack,
          { "RREP Acknowledgement", "aodv.flags.rrep_ack",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), RREP_ACK_REQ,
            NULL, HFILL }
        },
        { &hf_aodv_flags_rerr_nodelete,
          { "RERR No Delete", "aodv.flags.rerr_nodelete",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), RERR_NODEL,
            NULL, HFILL }
        },
        { &hf_aodv_prefix_sz,
          { "Prefix Size", "aodv.prefix_sz",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_aodv_hopcount,
          { "Hop Count", "aodv.hopcount",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_aodv_rreq_id,
          { "RREQ Id", "aodv.rreq_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_aodv_dest_ip,
          { "Destination IP", "aodv.dest_ip",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            "Destination IP Address", HFILL }
        },
        { &hf_aodv_dest_ipv6,
          { "Destination IPv6", "aodv.dest_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            "Destination IPv6 Address", HFILL}
        },
        { &hf_aodv_dest_seqno,
          { "Destination Sequence Number", "aodv.dest_seqno",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_aodv_orig_ip,
          { "Originator IP", "aodv.orig_ip",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            "Originator IP Address", HFILL }
        },
        { &hf_aodv_orig_ipv6,
          { "Originator IPv6", "aodv.orig_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            "Originator IPv6 Address", HFILL}
        },
        { &hf_aodv_orig_seqno,
          { "Originator Sequence Number", "aodv.orig_seqno",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_aodv_lifetime,
          { "Lifetime", "aodv.lifetime",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_aodv_destcount,
          { "Destination Count", "aodv.destcount",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Unreachable Destinations Count", HFILL }
        },
        { &hf_aodv_unreach_dest_ip,
          { "Unreachable Destination IP", "aodv.unreach_dest_ip",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            "Unreachable Destination IP Address", HFILL }
        },
        { &hf_aodv_unreach_dest_ipv6,
          { "Unreachable Destination IPv6", "aodv.unreach_dest_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            "Unreachable Destination IPv6 Address", HFILL}
        },
#if 0
        { &hf_aodv_unreach_dest_seqno,
          { "Unreachable Destination Sequence Number", "aodv.unreach_dest_seqno",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
#endif
        { &hf_aodv_ext_type,
          { "Extension Type", "aodv.ext_type",
            FT_UINT8, BASE_DEC, VALS(exttype_vals), 0x0,
            "Extension Format Type", HFILL}
        },
        { &hf_aodv_ext_length,
          { "Extension Length", "aodv.ext_length",
            FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes), 0x0,
            "Extension Data Length", HFILL}
        },
        { &hf_aodv_ext_interval,
          { "Hello Interval", "aodv.hello_interval",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Hello Interval Extension", HFILL}
         },
        { &hf_aodv_ext_timestamp,
          { "Timestamp", "aodv.timestamp",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Timestamp Extension", HFILL}
         },
    };

/* Setup protocol subtree array */
    static int *ett[] = {
        &ett_aodv,
        &ett_aodv_flags,
        &ett_aodv_unreach_dest,
        &ett_aodv_extensions,
    };

    static ei_register_info ei[] = {
        { &ei_aodv_ext_length, { "aodv.ext_length.invalid", PI_MALFORMED, PI_ERROR, "Invalid option length", EXPFILL }},
        { &ei_aodv_type, { "aodv.ext_type.unknown", PI_PROTOCOL, PI_WARN, "Unknown AODV Packet Type", EXPFILL }},
    };

    expert_module_t* expert_aodv;

/* Register the protocol name and description */
    proto_aodv = proto_register_protocol("Ad hoc On-demand Distance Vector Routing Protocol", "AODV", "aodv");
    aodv_handle = register_dissector("aodv", dissect_aodv, proto_aodv);

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_aodv, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_aodv = expert_register_protocol(proto_aodv);
    expert_register_field_array(expert_aodv, ei, array_length(ei));
}


void
proto_reg_handoff_aodv(void)
{
    dissector_add_uint_with_preference("udp.port", UDP_PORT_AODV, aodv_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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

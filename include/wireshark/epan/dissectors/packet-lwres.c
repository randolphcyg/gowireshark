/* packet-lwres.c
 * Routines for light weight reslover (lwres, part of BIND9) packet disassembly
 *
 * Copyright (c) 2003 by Oleg Terletsky <oleg.terletsky@comverse.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/strutil.h>

#include "packet-dns.h"

void proto_register_lwres(void);
void proto_reg_handoff_lwres(void);

static dissector_handle_t lwres_handle;

#define LWRES_LWPACKET_LENGTH           (4 * 5 + 2 * 4)
#define LWRES_LWPACKETFLAG_RESPONSE     0x0001U /* if set, pkt is a response */
#define LWRES_LWPACKETVERSION_0         0

#define LW_LENGTH_OFFSET         0
#define LW_VERSION_OFFSET        4
#define LW_PKTFLASG_OFFSET       6
#define LW_SERIAL_OFFSET         8
#define LW_OPCODE_OFFSET        12
#define LW_RESULT_OFFSET        16
#define LW_RECVLEN_OFFSET       20
#define LW_AUTHTYPE_OFFSET      24
#define LW_AUTHLEN_OFFSET       26

#define LWRES_OPCODE_NOOP               0x00000000U
#define LWRES_OPCODE_GETADDRSBYNAME     0x00010001U
#define LWRES_OPCODE_GETNAMEBYADDR      0x00010002U
#define LWRES_OPCODE_GETRDATABYNAME     0x00010003U

static const value_string opcode_values[] = {
    { LWRES_OPCODE_NOOP,            "Noop" },
    { LWRES_OPCODE_GETADDRSBYNAME,  "getaddrbyname" },
    { LWRES_OPCODE_GETNAMEBYADDR,   "getnamebyaddr" },
    { LWRES_OPCODE_GETRDATABYNAME,  "getrdatabyname" },
    { 0, NULL },
};


#define LWRES_R_SUCCESS                  0
#define LWRES_R_NOMEMORY                 1
#define LWRES_R_TIMEOUT                  2
#define LWRES_R_NOTFOUND                 3
#define LWRES_R_UNEXPECTEDEND            4       /* unexpected end of input */
#define LWRES_R_FAILURE                  5       /* generic failure */
#define LWRES_R_IOERROR                  6
#define LWRES_R_NOTIMPLEMENTED           7
#define LWRES_R_UNEXPECTED               8
#define LWRES_R_TRAILINGDATA             9
#define LWRES_R_INCOMPLETE              10
#define LWRES_R_RETRY                   11
#define LWRES_R_TYPENOTFOUND            12
#define LWRES_R_TOOLARGE                13

#define T_A     1
#define T_NS    2
#define T_MX    15
#define T_SRV   33


static const value_string t_types[] = {
    { T_A,      "T_A" },
    { T_NS,     "T_NS" },
    { T_MX,     "T_MX" },
    { T_SRV,    "T_SRV" },
    { 0,        NULL },
};




static const value_string result_values[]  = {
    { LWRES_R_SUCCESS,          "Success" },
    { LWRES_R_NOMEMORY,         "No memory" },
    { LWRES_R_TIMEOUT,          "Timeout" },
    { LWRES_R_NOTFOUND,         "Not found" },
    { LWRES_R_UNEXPECTEDEND,    "Unexpected end of input" },
    { LWRES_R_FAILURE,          "Generic failure" },
    { LWRES_R_IOERROR,          "I/O Error" },
    { LWRES_R_NOTIMPLEMENTED,   "Not Implemented"},
    { LWRES_R_UNEXPECTED,       "Unexpected" },
    { LWRES_R_TRAILINGDATA,     "Trailing data" },
    { LWRES_R_INCOMPLETE,       "Incomplete" },
    { LWRES_R_RETRY,            "Retry" },
    { LWRES_R_TYPENOTFOUND,     "Type not found" },
    { LWRES_R_TOOLARGE,         "Too large" },
    { 0,                        NULL },
};

static int hf_length;
static int hf_version;
static int hf_flags;
static int hf_serial;
static int hf_opcode;
static int hf_result;
static int hf_recvlen;
static int hf_authtype;
static int hf_authlen;

static int hf_rflags;
static int hf_rdclass;
static int hf_rdtype;
static int hf_namelen;
static int hf_req_name;

static int hf_ttl;
static int hf_nrdatas;
static int hf_nsigs;
static int hf_realnamelen;
static int hf_realname;


static int hf_a_record;
static int hf_a_rec_len;
static int hf_srv_prio;
static int hf_srv_weight;
static int hf_srv_port;
static int hf_srv_dname;

static int hf_adn_flags;
static int hf_adn_addrtype;
static int hf_adn_namelen;
static int hf_adn_name;

static int hf_adn_realname;
static int hf_adn_aliasname;

static int hf_adn_naddrs;
static int hf_adn_naliases;
static int hf_adn_family;
static int hf_adn_addr_len;
static int hf_adn_addr_addr;

static int hf_ns_dname;

static int ett_lwres;
static int ett_rdata_req;
static int ett_rdata_resp;
static int ett_a_rec;
static int ett_a_rec_addr;
static int ett_srv_rec;
static int ett_srv_rec_item;
static int ett_adn_request;
static int ett_adn_resp;
static int ett_adn_alias;
static int ett_adn_addr;
static int ett_nba_request;
static int ett_nba_resp;
static int ett_noop;

static int ett_mx_rec;
static int ett_mx_rec_item;

static int ett_ns_rec;
static int ett_ns_rec_item;



#define LWRES_UDP_PORT 921 /* Not IANA registered */

/* Define the lwres proto */
static int proto_lwres;


/* Define many many headers for mgcp */

static const value_string message_types_values[] = {
    { 1,        "REQUEST " },
    { 2,        "RESPONSE" },
    { 0,        NULL },
};

static void dissect_getnamebyaddr_request(tvbuff_t* tvb, packet_info *pinfo, proto_tree* lwres_tree)
{
    uint32_t flags,family;
    unsigned   addrlen, slen;
    const char* addrs;

    proto_tree* nba_request_tree;

    flags = tvb_get_ntohl(tvb, LWRES_LWPACKET_LENGTH);
    family = tvb_get_ntohl(tvb, LWRES_LWPACKET_LENGTH + 4);
    addrlen = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH + 8);
    addrs = tvb_ip_to_str(pinfo->pool, tvb, LWRES_LWPACKET_LENGTH + 10);
    slen = (int)strlen(addrs);

    if (lwres_tree == NULL)
        return;

    nba_request_tree = proto_tree_add_subtree(lwres_tree,tvb,LWRES_LWPACKET_LENGTH,LWRES_LWPACKET_LENGTH+14,
                                        ett_nba_request,NULL,"getnamebyaddr parameters");

    proto_tree_add_uint(nba_request_tree, hf_adn_flags, tvb,
                LWRES_LWPACKET_LENGTH, 4, flags);

    proto_tree_add_uint(nba_request_tree, hf_adn_family, tvb,
                LWRES_LWPACKET_LENGTH + 4, 4, family);

    proto_tree_add_uint(nba_request_tree, hf_adn_addr_len, tvb,
                LWRES_LWPACKET_LENGTH + 8, 2, addrlen);

    proto_tree_add_string(nba_request_tree, hf_adn_addr_addr, tvb,
                  LWRES_LWPACKET_LENGTH + 10, slen, addrs);

}

static void dissect_getnamebyaddr_response(tvbuff_t* tvb, packet_info *pinfo, proto_tree* lwres_tree)
{
    uint32_t i, offset;
    uint16_t naliases,realnamelen,aliaslen;
    char *aliasname;

    proto_tree* nba_resp_tree;
    proto_tree* alias_tree;

    if(lwres_tree == NULL)
        return;

    nba_resp_tree = proto_tree_add_subtree(lwres_tree, tvb, LWRES_LWPACKET_LENGTH, 10, ett_nba_resp, NULL, "getnamebyaddr records");

    naliases = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH + 4);
    realnamelen = tvb_get_ntohs(tvb,LWRES_LWPACKET_LENGTH + 4 + 2);

    proto_tree_add_item(nba_resp_tree,
                        hf_adn_flags,
                        tvb,
                        LWRES_LWPACKET_LENGTH,
                        4,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(nba_resp_tree,
                        hf_adn_naliases,
                        tvb,
                        LWRES_LWPACKET_LENGTH + 4,
                        2,
                        ENC_BIG_ENDIAN);

    proto_tree_add_item(nba_resp_tree,
                        hf_adn_namelen,
                        tvb,
                        LWRES_LWPACKET_LENGTH + 6,
                        2,
                        ENC_BIG_ENDIAN);

    proto_tree_add_item(nba_resp_tree,
                        hf_adn_realname,
                        tvb,
                        LWRES_LWPACKET_LENGTH + 8,
                        realnamelen,
                        ENC_ASCII);

    offset=LWRES_LWPACKET_LENGTH + 8 + realnamelen;

    if(naliases)
    {
        for(i=0; i<naliases; i++)
        {
            aliaslen = tvb_get_ntohs(tvb, offset);
            aliasname = tvb_get_string_enc(pinfo->pool, tvb, offset + 2, aliaslen, ENC_ASCII);

            alias_tree = proto_tree_add_subtree_format(nba_resp_tree, tvb, offset, 2 + aliaslen,
                                ett_adn_alias, NULL, "Alias %s",aliasname);

            proto_tree_add_item(alias_tree,
                                hf_adn_namelen,
                                tvb,
                                offset,
                                2,
                                ENC_BIG_ENDIAN);

            proto_tree_add_item(alias_tree,
                                hf_adn_aliasname,
                                tvb,
                                offset + 2,
                                aliaslen,
                                ENC_ASCII);

            offset+=(2 + aliaslen + 1);
        }
    }
}

static void dissect_getaddrsbyname_request(tvbuff_t* tvb, proto_tree* lwres_tree)
{
    uint16_t namelen;

    proto_tree* adn_request_tree;

    namelen  = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH + 8);

    if(lwres_tree == NULL)
        return;

    adn_request_tree = proto_tree_add_subtree(lwres_tree,tvb,
                    LWRES_LWPACKET_LENGTH,10+namelen+1,
                    ett_adn_request, NULL,
                    "getaddrbyname parameters");

    proto_tree_add_item(adn_request_tree,
                hf_adn_flags,
                tvb,
                LWRES_LWPACKET_LENGTH+0,
                sizeof(uint32_t),
                ENC_BIG_ENDIAN);

    proto_tree_add_item(adn_request_tree,
                hf_adn_addrtype,
                tvb,
                LWRES_LWPACKET_LENGTH+4,
                sizeof(uint32_t),
                ENC_BIG_ENDIAN);

    proto_tree_add_item(adn_request_tree,
                hf_adn_namelen,
                tvb,
                LWRES_LWPACKET_LENGTH+8,
                sizeof(uint16_t),
                ENC_BIG_ENDIAN);

    proto_tree_add_item(adn_request_tree,
                hf_adn_name,
                tvb,
                LWRES_LWPACKET_LENGTH+10,
                namelen,
                ENC_ASCII);

}


static void dissect_getaddrsbyname_response(tvbuff_t* tvb, packet_info *pinfo, proto_tree* lwres_tree)
{
    uint32_t family ,i, offset;
    uint16_t naliases, naddrs, realnamelen, length, aliaslen;
    const char* addrs;
    unsigned slen;
    char *aliasname;

    proto_tree *adn_resp_tree;
    proto_tree *alias_tree;
    proto_tree *addr_tree;



    if(lwres_tree == NULL)
        return;

    adn_resp_tree = proto_tree_add_subtree(lwres_tree, tvb, LWRES_LWPACKET_LENGTH, 10,
                                        ett_adn_resp, NULL, "getaddrbyname records");

    naliases = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH + 4);
    naddrs   = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH + 6);
    realnamelen = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH + 8);


    proto_tree_add_item(adn_resp_tree, hf_adn_flags, tvb,
                LWRES_LWPACKET_LENGTH, 4, ENC_BIG_ENDIAN);

    proto_tree_add_item(adn_resp_tree, hf_adn_naliases, tvb,
                LWRES_LWPACKET_LENGTH + 4, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(adn_resp_tree, hf_adn_naddrs, tvb,
                LWRES_LWPACKET_LENGTH + 6, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(adn_resp_tree, hf_adn_namelen, tvb,
                LWRES_LWPACKET_LENGTH + 8, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(adn_resp_tree, hf_adn_realname, tvb,
                LWRES_LWPACKET_LENGTH + 10, realnamelen, ENC_ASCII);

    offset = LWRES_LWPACKET_LENGTH + 10 + realnamelen + 1;

    if(naliases)
    {
        for(i=0; i<naliases; i++)
        {
            aliaslen = tvb_get_ntohs(tvb, offset);
            aliasname = tvb_get_string_enc(pinfo->pool, tvb, offset + 2, aliaslen, ENC_ASCII);

            alias_tree = proto_tree_add_subtree_format(adn_resp_tree, tvb, offset, 2 + aliaslen,
                                                        ett_adn_alias, NULL, "Alias %s",aliasname);

            proto_tree_add_uint(alias_tree, hf_adn_namelen, tvb,
                        offset, 2, aliaslen);

            proto_tree_add_item(alias_tree, hf_adn_aliasname, tvb,
                        offset + 2, aliaslen, ENC_ASCII);

            offset+=(2 + aliaslen + 1);
        }
    }

    if(naddrs)
    {
        for(i=0; i < naddrs; i++)
        {
            family = tvb_get_ntohl(tvb, offset);
            length = tvb_get_ntohs(tvb, offset + 4);
            addrs = tvb_ip_to_str(pinfo->pool, tvb, offset + 6);
            slen = (int)strlen(addrs);

            addr_tree = proto_tree_add_subtree_format(adn_resp_tree,tvb, offset, 4+2+4, ett_adn_addr, NULL, "Address %s", addrs);

            proto_tree_add_uint(addr_tree, hf_adn_family, tvb,
                        offset, 4, family);

            proto_tree_add_uint(addr_tree, hf_adn_addr_len, tvb,
                        offset + 4, 2, length);

            proto_tree_add_string(addr_tree, hf_adn_addr_addr, tvb,
                          offset + 6, slen, addrs);

            offset+= 4 + 2 + 4;
        }
    }


}

static void dissect_a_records(tvbuff_t* tvb, packet_info *pinfo, proto_tree* tree,uint32_t nrec,int offset)
{
    uint32_t i, curr;
    const char* addrs;
    proto_tree* a_rec_tree;
    proto_tree* addr_tree;

    if(tree == NULL)
        return;

    a_rec_tree = proto_tree_add_subtree(tree,tvb,offset,
                (int)((sizeof(uint32_t) + sizeof(uint16_t)) * nrec),
                ett_a_rec, NULL, "A records");

    for(i=0; i<nrec; i++)
    {

        curr = offset + (int)((sizeof(uint32_t)+sizeof(uint16_t)) * i);

        addrs = tvb_ip_to_str(pinfo->pool, tvb, curr+2);

        addr_tree = proto_tree_add_subtree_format(a_rec_tree, tvb, curr,
                            6, ett_a_rec_addr, NULL, "Address %s", addrs);

        proto_tree_add_item(addr_tree, hf_a_rec_len, tvb, curr,
                    sizeof(uint16_t), ENC_BIG_ENDIAN);

        proto_tree_add_item(addr_tree, hf_a_record, tvb, curr + 2, 4, ENC_BIG_ENDIAN);
    }

}

static void dissect_srv_records(tvbuff_t* tvb, packet_info *pinfo, proto_tree* tree,uint32_t nrec,int offset)
{
    uint32_t i, curr;
    uint16_t /*len, namelen,*/ priority, weight, port;
    int dlen;
    unsigned used_bytes;
    const char *dname;

    proto_item* srv_rec_tree, *rec_tree;

    if(tree == NULL)
        return;

    srv_rec_tree = proto_tree_add_subtree_format(tree, tvb, offset, offset, ett_srv_rec, NULL, "SRV records (%d)", nrec);

    curr = offset;

    for(i=0; i < nrec; i++)
    {
        /*len =      tvb_get_ntohs(tvb, curr);*/
        priority = tvb_get_ntohs(tvb, curr + 2);
        weight   = tvb_get_ntohs(tvb, curr + 4);
        port     = tvb_get_ntohs(tvb, curr + 6);
        /*namelen = len - 8;*/

        used_bytes = get_dns_name(tvb, curr + 8, 0, curr + 8, &dname, &dlen);

        rec_tree = proto_tree_add_subtree_format(srv_rec_tree, tvb, curr, 6,
                    ett_srv_rec_item, NULL,
                    "SRV record:pri=%d,w=%d,port=%d,dname=%s",
                    priority, weight, port, format_text(pinfo->pool, dname, dlen));

        proto_tree_add_uint(rec_tree,
                        hf_srv_prio,
                        tvb,
                        curr + 2,
                        2,
                        priority);

        proto_tree_add_uint(rec_tree,
                        hf_srv_weight,
                        tvb,
                        curr + 4,
                        2,
                        weight);

        proto_tree_add_uint(rec_tree,
                        hf_srv_port,
                        tvb,
                        curr + 6,
                        2,
                        port);


        proto_tree_add_string(rec_tree,
                            hf_srv_dname,
                            tvb,
                            curr + 8,
                            used_bytes,
                            format_text(pinfo->pool, dname, dlen));

        curr+=(int)((sizeof(short)*4) + used_bytes);

    }

}

static void dissect_mx_records(tvbuff_t* tvb, packet_info *pinfo, proto_tree* tree, uint32_t nrec, int offset)
{

    unsigned i, curr;
    unsigned priority;
    int dlen;
    unsigned used_bytes;
    const char *dname;

    proto_tree* mx_rec_tree, *rec_tree;


    if(tree == NULL)
        return;

    mx_rec_tree = proto_tree_add_subtree_format(tree, tvb, offset, offset, ett_mx_rec, NULL, "MX records (%d)", nrec);

    curr = offset;
    for(i=0; i < nrec; i++)
    {
        /*len =       tvb_get_ntohs(tvb, curr);*/
        priority = tvb_get_ntohs(tvb, curr + 2);
        /*namelen  =  len - 4;*/

        used_bytes  = get_dns_name(tvb, curr + 4, 0, curr + 4, &dname, &dlen);

        rec_tree = proto_tree_add_subtree_format(mx_rec_tree, tvb, curr,6,ett_mx_rec_item,NULL,
                        "MX record: pri=%d,dname=%s", priority,
                        format_text(pinfo->pool, dname, dlen));


        proto_tree_add_item(rec_tree,
                            hf_srv_prio,
                            tvb,
                            curr + 2,
                            2,
                            ENC_BIG_ENDIAN);

        proto_tree_add_string(rec_tree,
                            hf_srv_dname,
                            tvb,
                            curr + 4,
                            used_bytes,
                            format_text(pinfo->pool, dname, dlen));

        curr+=(int)((sizeof(short)*2) + used_bytes);


    }

}

static void dissect_ns_records(tvbuff_t* tvb, packet_info *pinfo, proto_tree* tree, uint32_t nrec, int offset)
{
    unsigned i, curr;
    int dlen;
    const char *dname;
    unsigned used_bytes;

    proto_tree* ns_rec_tree, *rec_tree;

    if(tree == NULL)
        return;

    ns_rec_tree = proto_tree_add_subtree_format(tree, tvb, offset, offset, ett_ns_rec, NULL, "NS record (%d)", nrec);

    curr=offset;

    for(i=0;i<nrec;i++)
    {
        /*len = tvb_get_ntohs(tvb, curr);*/
        /*namelen = len - 2;*/

        used_bytes = get_dns_name(tvb, curr + 2, 0, curr + 2, &dname, &dlen);

        rec_tree = proto_tree_add_subtree_format(ns_rec_tree, tvb, curr,4, ett_ns_rec_item, NULL, "NS record: dname=%s",
                        format_text(pinfo->pool, dname, dlen));

        proto_tree_add_string(rec_tree,
                            hf_ns_dname,
                            tvb,
                            curr + 2,
                            used_bytes,
                            format_text(pinfo->pool, dname, dlen));
        curr+=(int)(sizeof(short) + used_bytes);

    }


}

static void dissect_rdata_request(tvbuff_t* tvb, proto_tree* lwres_tree)
{
    uint16_t namelen;

    proto_tree* rdata_request_tree;

    namelen = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH+8);

    if(lwres_tree == NULL)
        return;

    rdata_request_tree =
            proto_tree_add_subtree(lwres_tree,tvb,LWRES_LWPACKET_LENGTH,10+namelen+1,ett_rdata_req,NULL,"RDATA request parameters");

    proto_tree_add_item(rdata_request_tree,
            hf_rflags,
            tvb,
            LWRES_LWPACKET_LENGTH+0,
            sizeof(uint32_t),
            ENC_BIG_ENDIAN);

    proto_tree_add_item(rdata_request_tree,
            hf_rdclass,
            tvb,
            LWRES_LWPACKET_LENGTH+4,
            sizeof(uint16_t),
            ENC_BIG_ENDIAN);

    proto_tree_add_item(rdata_request_tree,
            hf_rdtype,
            tvb,
            LWRES_LWPACKET_LENGTH+6,
            sizeof(uint16_t),
            ENC_BIG_ENDIAN);

    proto_tree_add_item(rdata_request_tree,
            hf_namelen,
            tvb,
            LWRES_LWPACKET_LENGTH+8,
            sizeof(uint16_t),
            ENC_BIG_ENDIAN);

    proto_tree_add_item(rdata_request_tree,
            hf_req_name,
            tvb,
            LWRES_LWPACKET_LENGTH+10,
            namelen,
                ENC_ASCII);

}

static void dissect_rdata_response(tvbuff_t* tvb, packet_info *pinfo, proto_tree* lwres_tree)
{
    unsigned offset;
    unsigned rdtype, nrdatas, realnamelen;

    proto_tree* rdata_resp_tree;

    rdtype =  tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH+6);
    nrdatas = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH+12);
    realnamelen = tvb_get_ntohs(tvb,LWRES_LWPACKET_LENGTH+16);

    offset = LWRES_LWPACKET_LENGTH + 18 + realnamelen + 1;

    if(lwres_tree == NULL)
        return;

    rdata_resp_tree = proto_tree_add_subtree(lwres_tree,tvb,LWRES_LWPACKET_LENGTH, 18+realnamelen+1,ett_rdata_resp,NULL,"RDATA response");

    proto_tree_add_item(rdata_resp_tree,
                        hf_rflags,
                        tvb,
                        LWRES_LWPACKET_LENGTH+0,
                        sizeof(uint32_t),
                        ENC_BIG_ENDIAN);

    proto_tree_add_item(rdata_resp_tree,
                        hf_rdclass,
                        tvb,
                        LWRES_LWPACKET_LENGTH+4,
                        sizeof(uint16_t),
                        ENC_BIG_ENDIAN);

    proto_tree_add_item(rdata_resp_tree,
                        hf_rdtype,
                        tvb,
                        LWRES_LWPACKET_LENGTH+6,
                        sizeof(uint16_t),
                        ENC_BIG_ENDIAN);

    proto_tree_add_item(rdata_resp_tree,
            hf_ttl,
            tvb,
            LWRES_LWPACKET_LENGTH+8,
            sizeof(uint32_t),
            ENC_BIG_ENDIAN);

    proto_tree_add_item(rdata_resp_tree,
            hf_nrdatas,
            tvb,
            LWRES_LWPACKET_LENGTH+12,
            sizeof(uint16_t),
            ENC_BIG_ENDIAN);

    proto_tree_add_item(rdata_resp_tree,
            hf_nsigs,
            tvb,
            LWRES_LWPACKET_LENGTH+14,
            sizeof(uint16_t),
            ENC_BIG_ENDIAN);

    proto_tree_add_item(rdata_resp_tree,
            hf_realnamelen,
            tvb,
            LWRES_LWPACKET_LENGTH+16,
            sizeof(uint16_t),
            ENC_BIG_ENDIAN);

    proto_tree_add_item(rdata_resp_tree,
                        hf_realname,
                        tvb,
                        LWRES_LWPACKET_LENGTH+18,
                        realnamelen,
                ENC_ASCII);

    switch(rdtype)
    {
        case T_A:
            dissect_a_records(tvb,pinfo,rdata_resp_tree,nrdatas,offset);
        break;

        case T_SRV:
            dissect_srv_records(tvb,pinfo,rdata_resp_tree,nrdatas, offset);
        break;

        case T_MX:
            dissect_mx_records(tvb,pinfo,rdata_resp_tree,nrdatas, offset);
        break;

        case T_NS:
            dissect_ns_records(tvb,pinfo,rdata_resp_tree,nrdatas, offset);
        break;
    }

}

static void dissect_noop(tvbuff_t* tvb, proto_tree* lwres_tree)
{
    uint16_t datalen;

    proto_tree* noop_tree;

    datalen = tvb_get_ntohs(tvb, LWRES_LWPACKET_LENGTH);

    if(lwres_tree == NULL)
        return;

    noop_tree = proto_tree_add_subtree(lwres_tree, tvb, LWRES_LWPACKET_LENGTH, 10, ett_noop, NULL, "Noop record");

    proto_tree_add_uint(noop_tree, hf_length, tvb,
                LWRES_LWPACKET_LENGTH, sizeof(uint16_t), datalen);

    tvb_ensure_bytes_exist(tvb, LWRES_LWPACKET_LENGTH, datalen);

}

static void dissect_getaddrsbyname(tvbuff_t* tvb, packet_info *pinfo, proto_tree* lwres_tree, int type)
{
    if(type == 1)
        dissect_getaddrsbyname_request(tvb, lwres_tree);
    else
        dissect_getaddrsbyname_response(tvb, pinfo, lwres_tree);
}

static void dissect_getnamebyaddr(tvbuff_t* tvb, packet_info *pinfo, proto_tree* lwres_tree, int type)
{
    if(type == 1)
        dissect_getnamebyaddr_request(tvb, pinfo, lwres_tree);
    else
        dissect_getnamebyaddr_response(tvb, pinfo, lwres_tree);
}

static void dissect_getrdatabyname(tvbuff_t* tvb, packet_info *pinfo _U_, proto_tree* lwres_tree, int type)
{
    if(type == 1)
        dissect_rdata_request(tvb, lwres_tree);
    else
        dissect_rdata_response(tvb, pinfo, lwres_tree);
}

static int
dissect_lwres(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    uint16_t version, flags, authtype, authlength ;
    uint32_t length, opcode, result, recvlength, serial;
    uint32_t message_type;

    proto_item* lwres_item;
    proto_tree* lwres_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "lw_res");
    length = tvb_get_ntohl(tvb, LW_LENGTH_OFFSET);
    version = tvb_get_ntohs(tvb, LW_VERSION_OFFSET);
    flags = tvb_get_ntohs(tvb, LW_PKTFLASG_OFFSET);
    serial = tvb_get_ntohl(tvb, LW_SERIAL_OFFSET);
    opcode = tvb_get_ntohl(tvb,LW_OPCODE_OFFSET);
    result = tvb_get_ntohl(tvb, LW_RESULT_OFFSET);
    recvlength = tvb_get_ntohl(tvb, LW_RECVLEN_OFFSET);
    authtype = tvb_get_ntohs(tvb, LW_AUTHTYPE_OFFSET);
    authlength = tvb_get_ntohs(tvb, LW_AUTHLEN_OFFSET);

    message_type = (flags & LWRES_LWPACKETFLAG_RESPONSE) ? 2 : 1;

    if(flags & LWRES_LWPACKETFLAG_RESPONSE)
    {
        col_add_fstr(pinfo->cinfo, COL_INFO,
            "%s, opcode=%s, serial=0x%x, result=%s",
                val_to_str_const((uint32_t)message_type,message_types_values,"unknown"),
                val_to_str_const(opcode, opcode_values, "unknown"),
                serial,
                val_to_str_const(result,result_values,"unknown"));
    }
    else
    {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                "%s, opcode=%s, serial=0x%x",
                val_to_str_const((uint32_t)message_type,message_types_values,"unknown"),
                val_to_str_const(opcode, opcode_values, "unknown"),
        serial);
    }

    if(tree == NULL)
        return tvb_captured_length(tvb);

    lwres_item = proto_tree_add_item(tree,proto_lwres, tvb,0, -1, ENC_NA);
    lwres_tree = proto_item_add_subtree(lwres_item, ett_lwres);

    proto_tree_add_uint(lwres_tree,
            hf_length,
            tvb,
            LW_LENGTH_OFFSET,
            sizeof(uint32_t),
            length);


    proto_tree_add_uint(lwres_tree,
                hf_version,
                tvb,
                LW_VERSION_OFFSET,
                sizeof(uint16_t),
                version);




    proto_tree_add_uint(lwres_tree,
                hf_flags,
                tvb,
                LW_PKTFLASG_OFFSET,
                sizeof(uint16_t),
                flags);

    proto_tree_add_uint(lwres_tree,
                hf_serial,
                tvb,
                LW_SERIAL_OFFSET,
                sizeof(uint32_t),
                serial);

    proto_tree_add_uint(lwres_tree,
                hf_opcode,
                tvb,
                LW_OPCODE_OFFSET,
                sizeof(uint32_t),
                opcode);

    proto_tree_add_uint(lwres_tree,
                hf_result,
                tvb,
                LW_RESULT_OFFSET,
                sizeof(uint32_t),
                result);

    proto_tree_add_uint(lwres_tree,
                hf_recvlen,
                tvb,
                LW_RECVLEN_OFFSET,
                sizeof(uint32_t),
                recvlength);

    proto_tree_add_uint(lwres_tree,
                hf_authtype,
                tvb,
                LW_AUTHTYPE_OFFSET,
                sizeof(uint16_t),
                authtype);

    proto_tree_add_uint(lwres_tree,
                hf_authlen,
                tvb,
                LW_AUTHLEN_OFFSET,
                sizeof(uint16_t),
                authlength);

    if(!result)
    {
        switch(opcode)
        {
            case LWRES_OPCODE_NOOP:
                dissect_noop(tvb, lwres_tree);
            break;

            case LWRES_OPCODE_GETADDRSBYNAME:
                dissect_getaddrsbyname(tvb, pinfo, lwres_tree, message_type);
            break;

            case LWRES_OPCODE_GETNAMEBYADDR:
                dissect_getnamebyaddr(tvb, pinfo, lwres_tree, message_type);
            break;

            case LWRES_OPCODE_GETRDATABYNAME:
                dissect_getrdatabyname(tvb, pinfo, lwres_tree, message_type);
            break;
        }
    }
    return tvb_captured_length(tvb);
}


void
proto_register_lwres(void)
{
    static hf_register_info hf[] = {
        { &hf_length,
          { "Length", "lwres.length", FT_UINT32, BASE_DEC, NULL, 0x0,
            "lwres length", HFILL }},

        { &hf_version,
          { "Version", "lwres.version", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres version", HFILL }},

        { &hf_flags,
          { "Packet Flags", "lwres.flags", FT_UINT16, BASE_HEX, NULL, 0x0,
            "lwres flags", HFILL }},

        { &hf_serial,
          { "Serial", "lwres.serial", FT_UINT32, BASE_HEX, NULL, 0x0,
            "lwres serial", HFILL }},

        { &hf_opcode,
          { "Operation code", "lwres.opcode", FT_UINT32, BASE_DEC, VALS(opcode_values), 0x0,
            "lwres opcode", HFILL }},

        { &hf_result,
          { "Result", "lwres.result", FT_UINT32, BASE_DEC, VALS(result_values), 0x0,
            "lwres result", HFILL }},

        { &hf_recvlen,
          { "Received length", "lwres.recvlen", FT_UINT32, BASE_DEC, NULL, 0x0,
            "lwres recvlen", HFILL }},

        { &hf_authtype,
          { "Auth. type", "lwres.authtype", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres authtype", HFILL }},

        { &hf_authlen,
          { "Auth. length", "lwres.authlen", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres authlen", HFILL }},

        { &hf_rflags,
          { "Flags", "lwres.rflags", FT_UINT32, BASE_HEX, NULL, 0x0,
            "lwres rflags", HFILL }},
        { &hf_rdclass,
          { "Class", "lwres.class", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres class", HFILL }},

        { &hf_rdtype,
          { "Type", "lwres.type", FT_UINT16, BASE_DEC, VALS(t_types), 0x0,
            "lwres type", HFILL }},

        { &hf_namelen,
          { "Name length", "lwres.namelen", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres namelen", HFILL }},

        { &hf_req_name,
          { "Domain name", "lwres.reqdname", FT_STRING, BASE_NONE, NULL, 0x0,
            "lwres reqdname", HFILL }},

        { &hf_ttl,
          { "Time To Live", "lwres.ttl", FT_UINT32, BASE_DEC, NULL, 0x0,
            "lwres ttl", HFILL }},

        { &hf_nrdatas,
          { "Number of rdata records", "lwres.nrdatas", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres nrdatas", HFILL }},

        { &hf_nsigs,
          { "Number of signature records", "lwres.nsigs", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres nsigs", HFILL }},

        { &hf_realnamelen,
          { "Real name length", "lwres.realnamelen", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres realnamelen", HFILL }},

        { &hf_realname,
          { "Real doname name", "lwres.realname", FT_STRING, BASE_NONE, NULL, 0x0,
            "lwres realname", HFILL }},

        { &hf_a_record,
          { "IPv4 Address", "lwres.arecord", FT_UINT32, BASE_DEC, NULL, 0x0,
            "lwres arecord", HFILL }},

        { &hf_a_rec_len,
          { "Length", "lwres.areclen", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres areclen", HFILL }},

        { &hf_srv_prio,
          { "Priority", "lwres.srv.priority", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres srv prio", HFILL }},

        { &hf_srv_weight,
          { "Weight", "lwres.srv.weight", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres srv weight", HFILL }},

        { &hf_srv_port,
          { "Port", "lwres.srv.port", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres srv port", HFILL }},

        { &hf_srv_dname,
          { "DNAME", "lwres.srv.dname", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_adn_flags,
          { "Flags", "lwres.adn.flags", FT_UINT32, BASE_HEX, NULL, 0x0,
            "lwres adn flags", HFILL }},

        { &hf_adn_addrtype,
          { "Address type", "lwres.adn.addrtype", FT_UINT32, BASE_DEC, NULL, 0x0,
            "lwres adn addrtype", HFILL }},

        { &hf_adn_namelen,
          { "Name length", "lwres.adn.namelen", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres adn namelen", HFILL }},

        { &hf_adn_name,
          { "Name", "lwres.adn.name", FT_STRING, BASE_NONE, NULL, 0x0,
            "lwres adn name", HFILL }},

        { &hf_adn_naliases,
          { "Number of aliases", "lwres.adn.naliases", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres adn naliases", HFILL }},

        { &hf_adn_naddrs,
          { "Number of addresses", "lwres.adn.naddrs", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres adn naddrs", HFILL }},

        { &hf_adn_realname,
          { "Real name", "lwres.adn.realname", FT_STRING, BASE_NONE, NULL, 0x0,
            "lwres adn realname", HFILL }},

        { &hf_adn_aliasname,
          { "Alias name", "lwres.adn.aliasname", FT_STRING, BASE_NONE, NULL, 0x0,
            "lwres adn aliasname", HFILL }},

        { &hf_adn_family,
          { "Address family", "lwres.adn.addr.family", FT_UINT32, BASE_DEC, NULL, 0x0,
            "lwres adn addr family", HFILL }},

        { &hf_adn_addr_len,
          { "Address length", "lwres.adn.addr.length", FT_UINT16, BASE_DEC, NULL, 0x0,
            "lwres adn addr length", HFILL }},

        { &hf_adn_addr_addr,
          { "IP Address", "lwres.adn.addr.addr", FT_STRING, BASE_NONE, NULL, 0x0,
            "lwres adn addr addr", HFILL }},

        { &hf_ns_dname,
          { "Name", "lwres.ns.dname", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        /* Add more fields here */
    };

    static int *ett[] = {
        &ett_lwres,
        &ett_rdata_req,
        &ett_rdata_resp,
        &ett_a_rec,
        &ett_a_rec_addr,
        &ett_srv_rec,
        &ett_srv_rec_item,
        &ett_adn_request,
        &ett_adn_resp,
        &ett_adn_alias,
        &ett_adn_addr,
        &ett_nba_request,
        &ett_nba_resp,
        &ett_mx_rec,
        &ett_mx_rec_item,
        &ett_ns_rec,
        &ett_ns_rec_item,
        &ett_noop,
    };

    proto_lwres = proto_register_protocol("Light Weight DNS RESolver (BIND9)", "LWRES", "lwres");

    proto_register_field_array(proto_lwres, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    lwres_handle = register_dissector("lwres", dissect_lwres, proto_lwres);
}

/* The registration hand-off routine */
void
proto_reg_handoff_lwres(void)
{
    dissector_add_uint_with_preference("udp.port", LWRES_UDP_PORT, lwres_handle);
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

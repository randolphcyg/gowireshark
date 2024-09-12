/* packet-hiqnet.c
 * Harman HiQnet protocol dissector for Wireshark
 * By Raphael Doursenaud <rdoursenaud@free.fr>
 * Copyright 2014 Raphael Doursenaud
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
#include "packet-tcp.h"

/*
 * See
 *      https://adn.harmanpro.com/site_elements/resources/487_1411413911/HiQnet_third-party_programmers_quick-start_guide_original.pdf
 *      https://adn.harmanpro.com/site_elements/resources/515_1414083576/HiQnet_Third_Party_Programmers_Guide_v2_original.pdf
 */

#define HIQNET_PORT 3804

#define HIQNET_FLAGS_MASK   0x016f

#define HIQNET_REQACK_FLAG      0x0001
#define HIQNET_ACK_FLAG         0x0002
#define HIQNET_INFO_FLAG        0x0004
#define HIQNET_ERROR_FLAG       0x0008
#define HIQNET_GUARANTEED_FLAG  0x0020
#define HIQNET_MULTIPART_FLAG   0x0040
#define HIQNET_SESSION_NUMBER_FLAG     0x0100

#define HIQNET_SUBSCRIPTION_TYPE_MASK      0x07

#define HIQNET_SUBSCRIPTION_FLAGS_MASK      0x0001

#define HIQNET_CATEGORIES_MASK  0x00004ffe

#define HIQNET_APPLICATION_CAT  0x00000002
#define HIQNET_CONF_CAT         0x00000004
#define HIQNET_AUDIONET_CAT     0x00000008
#define HIQNET_CTRLNET_CAT      0x00000010
#define HIQNET_VENDNET_CAT      0x00000020
#define HIQNET_STARTUP_CAT      0x00000040
#define HIQNET_DSP_CAT          0x00000080
#define HIQNET_MISC_CAT         0x00000100
#define HIQNET_CTRLLOG_CAT      0x00000200
#define HIQNET_FOREIGNPROTO_CAT 0x00000400
#define HIQNET_DIGIO_CAT        0x00000800
#define HIQNET_CTRLSURF_CAT     0x00004000

/* Routing layer message IDs */
#define HIQNET_DISCOINFO_MSG        0x0000
#define HIQNET_RESERVED0_MSG        0x0001
#define HIQNET_GETNETINFO_MSG       0x0002
#define HIQNET_RESERVED1_MSG        0x0003
#define HIQNET_REQADDR_MSG          0x0004
#define HIQNET_ADDRUSED_MSG         0x0005
#define HIQNET_SETADDR_MSG          0x0006
#define HIQNET_GOODBYE_MSG          0x0007
#define HIQNET_HELLO_MSG            0x0008

/* Other message IDs */
#define HIQNET_MULTPARMSET_MSG      0x0100
#define HIQNET_MULTOBJPARMSET_MSG   0x0101
#define HIQNET_PARMSETPCT_MSG       0x0102
#define HIQNET_MULTPARMGET_MSG      0x0103
#define HIQNET_GETATTR_MSG          0x010d
#define HIQNET_SETATTR_MSG          0x010e /* Reverse engineered. Not part of the official spec. */
#define HIQNET_MULTPARMSUB_MSG      0x010f
#define HIQNET_PARMSUBPCT_MSG       0x0111
#define HIQNET_MULTPARMUNSUB_MSG    0x0112
#define HIQNET_PARMSUBALL_MSG       0x0113
#define HIQNET_PARMUNSUBALL_MSG     0x0114
#define HIQNET_SUBEVTLOGMSGS_MSG    0x0115
#define HIQNET_GETVDLIST_MSG        0x011a
#define HIQNET_STORE_MSG            0x0124
#define HIQNET_RECALL_MSG           0x0125
#define HIQNET_LOCATE_MSG           0x0129
#define HIQNET_UNSUBEVTLOGMSGS_MSG  0x012b
#define HIQNET_REQEVTLOG_MSG        0x012c

#define HIQNET_TCPIP_NET    1
#define HIQNET_RS232_NET    4

static const value_string device_attributes_names[] = {
    { 0, "Class Name" },
    { 1, "Name String" },
    /* Device Manager attributes */
    { 2, "Flags" },
    { 3, "Serial Number" },
    { 4, "Software Version" },
    { 0, NULL }
};

static const value_string messageidnames[] = {
    { HIQNET_DISCOINFO_MSG, "DiscoInfo" },
    { HIQNET_RESERVED0_MSG, "Reserved" },
    { HIQNET_GETNETINFO_MSG, "GetNetworkInfo" },
    { HIQNET_RESERVED1_MSG, "Reserved" },
    { HIQNET_REQADDR_MSG, "RequestAddress" },
    { HIQNET_ADDRUSED_MSG, "AddressUsed" },
    { HIQNET_SETADDR_MSG, "SetAddress" },
    { HIQNET_GOODBYE_MSG, "Goodbye" },
    { HIQNET_HELLO_MSG, "Hello" },
    { HIQNET_MULTPARMSET_MSG, "MultiParamSet" },
    { HIQNET_MULTOBJPARMSET_MSG, "MultiObjectParamSet" },
    { HIQNET_PARMSETPCT_MSG, "ParamSetPercent" },
    { HIQNET_MULTPARMGET_MSG, "MultiParamGet" },
    { HIQNET_GETATTR_MSG, "GetAttributes" },
    { HIQNET_MULTPARMSUB_MSG, "MultiParamSubscribe" },
    { HIQNET_PARMSUBPCT_MSG, "ParamSubscribePercent" },
    { HIQNET_SETATTR_MSG, "SetAttribute" }, /* Reverse engineered. Not part of the official spec. */
    { HIQNET_MULTPARMUNSUB_MSG, "MultiParamUnsubscribe" },
    { HIQNET_PARMSUBALL_MSG, "ParameterSubscribeAll" },
    { HIQNET_PARMUNSUBALL_MSG, "ParameterUnSubscribeAll" },
    { HIQNET_SUBEVTLOGMSGS_MSG, "Subscribe Event Log Messages" },
    { HIQNET_GETVDLIST_MSG, "GetVDList" },
    { HIQNET_STORE_MSG, "Store" },
    { HIQNET_RECALL_MSG, "Recall" },
    { HIQNET_LOCATE_MSG, "Locate" },
    { HIQNET_UNSUBEVTLOGMSGS_MSG, "Unsubscribe Event Log Messages" },
    { HIQNET_REQEVTLOG_MSG, "Request Event Log" },
    { 0, NULL }
};

#if 0
static const value_string flagnames[] = {
    { HIQNET_REQACK_FLAG, "Request Acknowledgement" },
    { HIQNET_ACK_FLAG, "Acknowledgement" },
    { HIQNET_INFO_FLAG, "Information" },
    { HIQNET_ERROR_FLAG, "Error" },
    { HIQNET_GUARANTEED_FLAG, "Guaranteed" },
    { HIQNET_MULTIPART_FLAG, "Multi-part" },
    { HIQNET_SESSION_NUMBER_FLAG, "Session Number" },
    { 0, NULL }
};
#endif

#define HIQNET_DATATYPE_BYTE    0
#define HIQNET_DATATYPE_UBYTE   1
#define HIQNET_DATATYPE_WORD    2
#define HIQNET_DATATYPE_UWORD   3
#define HIQNET_DATATYPE_LONG    4
#define HIQNET_DATATYPE_ULONG   5
#define HIQNET_DATATYPE_FLOAT32 6
#define HIQNET_DATATYPE_FLOAT64 7
#define HIQNET_DATATYPE_BLOCK   8
#define HIQNET_DATATYPE_STRING  9
#define HIQNET_DATATYPE_LONG64  10
#define HIQNET_DATATYPE_ULONG64 11

static const value_string datatypenames[] = {
    { HIQNET_DATATYPE_BYTE,    "BYTE" },
    { HIQNET_DATATYPE_UBYTE,   "UBYTE" },
    { HIQNET_DATATYPE_WORD,    "WORD" },
    { HIQNET_DATATYPE_UWORD,   "UWORD" },
    { HIQNET_DATATYPE_LONG,    "LONG" },
    { HIQNET_DATATYPE_ULONG,   "ULONG" },
    { HIQNET_DATATYPE_FLOAT32, "FLOAT32" },
    { HIQNET_DATATYPE_FLOAT64, "FLOAT64" },
    { HIQNET_DATATYPE_BLOCK,   "BLOCK" },
    { HIQNET_DATATYPE_STRING,  "STRING" },
    { HIQNET_DATATYPE_LONG64,  "LONG64" },
    { HIQNET_DATATYPE_ULONG64, "ULONG64" },
    { 0, NULL }
};

static const value_string actionnames[] = {
    { 0, "Parameters" },
    { 1, "Subscriptions" },
    { 2, "Scenes" },
    { 3, "Snapshots" },
    { 4, "Presets" },
    { 5, "Venue" },
    { 0, NULL }
};

static const value_string timenames[] = {
    { 0x0000, "Turn off locate LEDs" },
    { 0xffff, "Turn on locate LEDs" },
    { 0, NULL }
};

static const value_string eventcategorynames[] = {
    { 0, "Unassigned" },
    { 1, "Application" },
    { 2, "Configuration" },
    { 3, "Audio Network" },
    { 4, "Control Network" },
    { 5, "Vendor Network" },
    { 6, "Startup" },
    { 7, "DSP" },
    { 8, "Miscellaneous" },
    { 9, "Control Logic" },
    { 10, "Foreign Protocol" },
    { 11, "Digital I/O" },
    { 12, "Unassigned" },
    { 13, "Unassigned" },
    { 14, "Control Surface" },
    { 15, "Unassigned" },
    { 16, "Unassigned" },
    { 17, "Unassigned" },
    { 18, "Unassigned" },
    { 19, "Unassigned" },
    { 20, "Unassigned" },
    { 21, "Unassigned" },
    { 22, "Unassigned" },
    { 23, "Unassigned" },
    { 24, "Unassigned" },
    { 25, "Unassigned" },
    { 26, "Unassigned" },
    { 27, "Unassigned" },
    { 28, "Unassigned" },
    { 29, "Unassigned" },
    { 30, "Unassigned" },
    { 31, "Unassigned" },
    { 0, NULL }
};

static const value_string eventidnames[] = {
    { 0x0001, "Invalid Version" },
    { 0x0002, "Invalid Length" },
    { 0x0003, "Invalid Virtual Device" },
    { 0x0004, "Invalid Object" },
    { 0x0005, "Invalid Parameter" },
    { 0x0006, "Invalid Message ID" },
    { 0x0007, "Invalid Value" },
    { 0x0008, "Resource Unavailable" },
    { 0x0009, "Unsupported" },
    { 0x000a, "Invalid Virtual Device Class" },
    { 0x000b, "Invalid Object Class" },
    { 0x000c, "Invalid Parameter Class" },
    { 0x000d, "Invalid Attribute ID" },
    { 0x000e, "Invalid DataType" },
    { 0x000f, "Invalid Configuration" },
    { 0x0010, "Flash Error" },
    { 0x0011, "Not a Router" },
    { 0, NULL }
};

static const value_string prioritynames[] = {
    { 0, "Fault" },
    { 1, "Warning" },
    { 2, "Information" },
    { 0, NULL }
};

static const value_string networknames[] = {
    { HIQNET_TCPIP_NET, "TCP/IP" },
    { 2, "Reserved" },
    { 3, "Reserved" },
    { HIQNET_RS232_NET, "RS232" },
    { 0, NULL }
};

static const value_string paritynames[] = {
    { 0, "None" },
    { 1, "Odd" },
    { 2, "Even" },
    { 3, "Mark" },
    { 4, "Space" },
    { 0, NULL }
};

static const value_string stopbitsnames[] = {
    { 0, "1 Bits" },
    { 1, "1.5 Bits" },
    { 2, "2 Bits" },
    { 0, NULL }
};

static const value_string flowcontrolnames[] = {
    { 0, "None" },
    { 1, "Hardware" },
    { 2, "XON/OFF" },
    { 0, NULL }
};

static int proto_hiqnet;

static int hf_hiqnet_version;

static int ett_hiqnet;
static int ett_hiqnet_flags;
static int ett_hiqnet_cats;

static int hf_hiqnet_headerlen;
static int hf_hiqnet_messagelen;
static int hf_hiqnet_sourcedev;
static int hf_hiqnet_sourceaddr;
static int hf_hiqnet_destdev;
static int hf_hiqnet_destaddr;
static int hf_hiqnet_messageid;
static int hf_hiqnet_flags;
static int hf_hiqnet_reqack_flag;
static int hf_hiqnet_ack_flag;
static int hf_hiqnet_info_flag;
static int hf_hiqnet_error_flag;
static int hf_hiqnet_guaranteed_flag;
static int hf_hiqnet_multipart_flag;
static int hf_hiqnet_session_number_flag;
static int hf_hiqnet_hopcnt;
static int hf_hiqnet_seqnum;
static int hf_hiqnet_errcode;
static int hf_hiqnet_errstr;
static int hf_hiqnet_startseqno;
static int hf_hiqnet_rembytes;
static int hf_hiqnet_sessnum;
static int hf_hiqnet_cost;
static int hf_hiqnet_sernumlen;
static int hf_hiqnet_sernum;
static int hf_hiqnet_maxmsgsize;
static int hf_hiqnet_keepaliveperiod;
static int hf_hiqnet_netid;
static int hf_hiqnet_macaddr;
static int hf_hiqnet_dhcp;
static int hf_hiqnet_ipaddr;
static int hf_hiqnet_subnetmsk;
static int hf_hiqnet_gateway;
static int hf_hiqnet_flagmask;
static int hf_hiqnet_paramcount;
static int hf_hiqnet_paramid;
static int hf_hiqnet_vdobject;
static int hf_hiqnet_subtype;
static int hf_hiqnet_sensrate;
static int hf_hiqnet_subflags;
static int hf_hiqnet_subcount;
static int hf_hiqnet_pubparmid;
static int hf_hiqnet_subaddr;
static int hf_hiqnet_subparmid;
static int hf_hiqnet_reserved0;
static int hf_hiqnet_reserved1;
static int hf_hiqnet_attrcount;
static int hf_hiqnet_attrid;
static int hf_hiqnet_datatype;
static int hf_hiqnet_datalen;
static int hf_hiqnet_byte_value;
static int hf_hiqnet_ubyte_value;
static int hf_hiqnet_word_value;
static int hf_hiqnet_uword_value;
static int hf_hiqnet_long_value;
static int hf_hiqnet_ulong_value;
static int hf_hiqnet_float32_value;
static int hf_hiqnet_float64_value;
static int hf_hiqnet_block_value;
static int hf_hiqnet_string_value;
static int hf_hiqnet_long64_value;
static int hf_hiqnet_ulong64_value;
static int hf_hiqnet_wrkgrppath;
static int hf_hiqnet_numvds;
static int hf_hiqnet_vdaddr;
static int hf_hiqnet_vdclassid;
static int hf_hiqnet_stract;
static int hf_hiqnet_strnum;
static int hf_hiqnet_scope;
static int hf_hiqnet_recact;
static int hf_hiqnet_recnum;
static int hf_hiqnet_strlen;
static int hf_hiqnet_time;
static int hf_hiqnet_maxdatasize;
static int hf_hiqnet_catfilter;
static int hf_hiqnet_app_cat;
static int hf_hiqnet_conf_cat;
static int hf_hiqnet_audionet_cat;
static int hf_hiqnet_ctrlnet_cat;
static int hf_hiqnet_vendnet_cat;
static int hf_hiqnet_startup_cat;
static int hf_hiqnet_dsp_cat;
static int hf_hiqnet_misc_cat;
static int hf_hiqnet_ctrlog_cat;
static int hf_hiqnet_foreignproto_cat;
static int hf_hiqnet_digio_cat;
static int hf_hiqnet_ctrlsurf_cat;
static int hf_hiqnet_entrieslen;
static int hf_hiqnet_category;
static int hf_hiqnet_eventid;
static int hf_hiqnet_priority;
static int hf_hiqnet_eventseqnum;
static int hf_hiqnet_eventtime;
static int hf_hiqnet_eventdate;
static int hf_hiqnet_eventinfo;
static int hf_hiqnet_eventadddata;
static int hf_hiqnet_objcount;
static int hf_hiqnet_paramval;
static int hf_hiqnet_ifacecount;
static int hf_hiqnet_comid;
static int hf_hiqnet_baudrate;
static int hf_hiqnet_parity;
static int hf_hiqnet_stopbits;
static int hf_hiqnet_databits;
static int hf_hiqnet_flowcontrol;
static int hf_hiqnet_devaddr;
static int hf_hiqnet_newdevaddr;

static expert_field ei_hiqnet_datatype;

static int * const hiqnet_flag_fields[] = {
    &hf_hiqnet_reqack_flag,
    &hf_hiqnet_ack_flag,
    &hf_hiqnet_info_flag,
    &hf_hiqnet_error_flag,
    &hf_hiqnet_guaranteed_flag,
    &hf_hiqnet_multipart_flag,
    &hf_hiqnet_session_number_flag,
    NULL
};

static int * const hiqnet_cat_fields[] = {
    &hf_hiqnet_app_cat,
    &hf_hiqnet_conf_cat,
    &hf_hiqnet_audionet_cat,
    &hf_hiqnet_ctrlnet_cat,
    &hf_hiqnet_vendnet_cat,
    &hf_hiqnet_startup_cat,
    &hf_hiqnet_dsp_cat,
    &hf_hiqnet_misc_cat,
    &hf_hiqnet_ctrlog_cat,
    &hf_hiqnet_foreignproto_cat,
    &hf_hiqnet_digio_cat,
    &hf_hiqnet_ctrlsurf_cat,
    NULL
};

void proto_register_hiqnet(void);
void proto_reg_handoff_hiqnet(void);

static dissector_handle_t hiqnet_udp_handle;
static dissector_handle_t hiqnet_tcp_handle;

static void
hiqnet_display_vdobjectaddr(proto_tree *hiqnet_tree, int hf_hiqnet, tvbuff_t *tvb, int offset) {
    proto_tree_add_bytes_format_value(hiqnet_tree, hf_hiqnet, tvb, offset, 4, NULL,
        "%u.%u.%u.%u",
        tvb_get_uint8(tvb, offset), /* Virtual Device address */
        tvb_get_uint8(tvb, offset + 1), /* Object address part 1 */
        tvb_get_uint8(tvb, offset + 2), /* Object address part 2 */
        tvb_get_uint8(tvb, offset + 3)); /* Object address part 3 */
}


static int
hiqnet_display_tcpipnetinfo(proto_tree *hiqnet_payload_tree, tvbuff_t *tvb, int offset) {
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_macaddr, tvb, offset, 6, ENC_NA);
    offset += 6;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_dhcp, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_ipaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_subnetmsk, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_gateway, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    return offset;
}


static int
hiqnet_display_rs232netinfo(proto_tree *hiqnet_payload_tree, tvbuff_t *tvb, int offset) {
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_comid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_baudrate, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_parity, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_stopbits, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_databits, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_flowcontrol, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    return offset;
}


static int
hiqnet_display_netinfo(proto_tree *hiqnet_payload_tree, tvbuff_t *tvb, int offset) {
    unsigned netid = 0;
    netid = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_netid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    if (netid == HIQNET_TCPIP_NET) {
            offset = hiqnet_display_tcpipnetinfo(hiqnet_payload_tree, tvb, offset);
    }
    if (netid == HIQNET_RS232_NET) {
        offset = hiqnet_display_rs232netinfo(hiqnet_payload_tree, tvb, offset);
    }
    return offset;
}


static int
hiqnet_display_sernum(proto_tree *hiqnet_payload_tree, tvbuff_t *tvb, int offset) {
    int str_len;
    str_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_sernumlen, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_sernum, tvb, offset, str_len, ENC_NA);
    offset += str_len;
    return offset;
}


static int
hiqnet_display_paramsub(proto_tree *hiqnet_payload_tree, tvbuff_t *tvb, int offset) {
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_pubparmid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_subaddr, tvb, offset, 6, ENC_NA);
    offset += 6;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_subparmid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_reserved0, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_reserved1, tvb, offset, 2, ENC_NA);
    offset += 2;
    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_sensrate, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    return offset;
}


/* TODO: decode flags for attributes and parameters */
static int
hiqnet_display_data(proto_tree *hiqnet_payload_tree, packet_info *pinfo, tvbuff_t *tvb, int offset) {
    uint32_t datatype;
    uint32_t datalen;
    proto_item* ti;

    ti = proto_tree_add_item_ret_uint(hiqnet_payload_tree, hf_hiqnet_datatype, tvb, offset, 1, ENC_BIG_ENDIAN, &datatype);
    offset += 1;
    switch (datatype) {

    case HIQNET_DATATYPE_BYTE:
        proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_byte_value, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;

    case HIQNET_DATATYPE_UBYTE:
        proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_ubyte_value, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;

    case HIQNET_DATATYPE_WORD:
        proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_word_value, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        break;

    case HIQNET_DATATYPE_UWORD:
        proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_uword_value, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        break;

    case HIQNET_DATATYPE_LONG:
        proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_long_value, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;

    case HIQNET_DATATYPE_ULONG:
        proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_ulong_value, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;

    case HIQNET_DATATYPE_FLOAT32:
        proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_float32_value, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;

    case HIQNET_DATATYPE_FLOAT64:
        proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_float64_value, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        break;

    case HIQNET_DATATYPE_BLOCK:
        proto_tree_add_item_ret_uint(hiqnet_payload_tree, hf_hiqnet_datalen, tvb, offset, 2, ENC_BIG_ENDIAN, &datalen);
        offset += 2;
        proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_block_value, tvb, offset, datalen, ENC_NA);
        offset += datalen;
        break;

    case HIQNET_DATATYPE_STRING:
        proto_tree_add_item_ret_uint(hiqnet_payload_tree, hf_hiqnet_datalen, tvb, offset, 2, ENC_BIG_ENDIAN, &datalen);
        offset += 2;
        proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_string_value, tvb, offset, datalen, ENC_UCS_2|ENC_BIG_ENDIAN);
        offset += datalen;
        break;

    case HIQNET_DATATYPE_LONG64:
        proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_long64_value, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        break;

    case HIQNET_DATATYPE_ULONG64:
        proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_ulong64_value, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        break;

    default:
        /* Flag an error, and punt and assume these values have no length. */
        expert_add_info(pinfo, ti, &ei_hiqnet_datatype);
        break;
    }
    return offset;
}

static int
dissect_hiqnet_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    uint8_t headerlen = 0;
    uint32_t messagelen = 0;
    uint16_t srcdev = 0;
    uint8_t srcvdaddr = 0;
    uint8_t srcob0addr = 0;
    uint8_t srcob1addr = 0;
    uint8_t srcob2addr = 0;
    uint16_t dstdev = 0;
    uint8_t dstvdaddr = 0;
    uint8_t dstob0addr = 0;
    uint8_t dstob1addr = 0;
    uint8_t dstob2addr = 0;
    uint16_t messageid = 0;
    uint16_t flags = 0;
    uint16_t paramcount = 0;
    uint16_t subcount = 0;
    uint16_t attrcount = 0;
    int str_len = 0;
    uint16_t vdscount = 0;
    uint16_t eventscount = 0;
    uint16_t objcount = 0;
    uint16_t ifacecount = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HiQnet");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    srcdev = tvb_get_ntohs(tvb, 6);
    srcvdaddr = tvb_get_uint8(tvb, 8);
    srcob0addr = tvb_get_uint8(tvb, 9);
    srcob1addr = tvb_get_uint8(tvb, 10);
    srcob2addr = tvb_get_uint8(tvb, 11);
    dstdev = tvb_get_ntohs(tvb, 12);
    dstvdaddr = tvb_get_uint8(tvb, 14);
    dstob0addr = tvb_get_uint8(tvb, 15);
    dstob1addr = tvb_get_uint8(tvb, 16);
    dstob2addr = tvb_get_uint8(tvb, 17);
    messageid = tvb_get_ntohs(tvb, 18);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Msg: %s, Src: %u.%u.%u.%u.%u, Dst: %u.%u.%u.%u.%u",
        val_to_str(messageid, messageidnames, "Unknown (0x%04x)"),
        srcdev, srcvdaddr, srcob0addr, srcob1addr, srcob2addr,
        dstdev, dstvdaddr, dstob0addr, dstob1addr, dstob2addr);

    if (tree) { /* we are being asked for details */
        proto_item *ti = NULL;
        proto_item *item = NULL;
        proto_tree *hiqnet_tree = NULL;
        proto_tree *hiqnet_header_tree = NULL;
        proto_tree *hiqnet_session_tree = NULL;
        proto_tree *hiqnet_error_tree = NULL;
        proto_tree *hiqnet_multipart_tree = NULL;
        proto_tree *hiqnet_payload_tree = NULL;
        proto_tree *hiqnet_parameter_tree = NULL;
        proto_tree *hiqnet_attribute_tree = NULL;
        proto_tree *hiqnet_vds_tree = NULL;
        proto_tree *hiqnet_event_tree = NULL;
        proto_tree *hiqnet_subscription_tree = NULL;
        proto_tree *hiqnet_object_tree = NULL;
        proto_tree *hiqnet_ifaces_tree = NULL;
        int offset = 0;

        messagelen = tvb_get_ntohl(tvb, 2);
        ti = proto_tree_add_item(tree, proto_hiqnet, tvb, 0, messagelen, ENC_NA);
        proto_item_append_text(ti, ", Msg: %s",
            val_to_str(messageid, messageidnames, "Unknown (0x%04x)"));
        proto_item_append_text(ti, ", Src %u.%u.%u.%u.%u",
            srcdev, srcvdaddr, srcob0addr, srcob1addr, srcob2addr);
        proto_item_append_text(ti, ", Dst: %u.%u.%u.%u.%u",
            dstdev, dstvdaddr, dstob0addr, dstob1addr, dstob2addr);
        hiqnet_tree = proto_item_add_subtree(ti, ett_hiqnet);

        /* Header subtree */
        headerlen =  tvb_get_uint8(tvb, 1);
        hiqnet_header_tree = proto_tree_add_subtree(hiqnet_tree, tvb, 0, headerlen, ett_hiqnet, NULL, "Header");

        /* Standard header */
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_headerlen, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_messagelen, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_sourcedev, tvb, offset, 2, ENC_BIG_ENDIAN);
        item = proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_devaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_item_set_hidden(item);
        offset += 2;
        hiqnet_display_vdobjectaddr(hiqnet_header_tree, hf_hiqnet_sourceaddr, tvb, offset);
        offset += 4;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_destdev, tvb, offset, 2, ENC_BIG_ENDIAN);
        item = proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_devaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_item_set_hidden(item);
        offset += 2;
        hiqnet_display_vdobjectaddr(hiqnet_header_tree, hf_hiqnet_destaddr, tvb, offset);
        offset += 4;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_messageid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        flags = tvb_get_ntohs(tvb, offset);
        proto_tree_add_bitmask(hiqnet_header_tree, tvb, offset, hf_hiqnet_flags,
                               ett_hiqnet_flags, hiqnet_flag_fields, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_hopcnt, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(hiqnet_header_tree, hf_hiqnet_seqnum, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* Optional headers */
        if (flags & HIQNET_ERROR_FLAG) {
            /* TODO: mark the erroneous frame */
            hiqnet_error_tree = proto_tree_add_subtree(hiqnet_header_tree, tvb, offset, 2, ett_hiqnet, NULL, "Error");
            proto_tree_add_item(hiqnet_error_tree, hf_hiqnet_errcode, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(hiqnet_error_tree, hf_hiqnet_errstr, tvb, offset, headerlen - offset, ENC_UCS_2|ENC_BIG_ENDIAN);
        }
        if (flags & HIQNET_MULTIPART_FLAG) {
            /* TODO: rebuild the full message */
            hiqnet_multipart_tree = proto_tree_add_subtree(hiqnet_header_tree, tvb, offset, 2, ett_hiqnet, NULL, "Multi-part");
            proto_tree_add_item(hiqnet_multipart_tree, hf_hiqnet_startseqno, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(hiqnet_multipart_tree, hf_hiqnet_rembytes, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        if (flags & HIQNET_SESSION_NUMBER_FLAG) {
            hiqnet_session_tree = proto_tree_add_subtree(hiqnet_header_tree, tvb, offset, 2, ett_hiqnet, NULL, "Session");
            proto_tree_add_item(hiqnet_session_tree, hf_hiqnet_sessnum, tvb, offset, 2, ENC_BIG_ENDIAN);
        }

        /* Payload(s) */
        offset = headerlen; /* Make sure we are at the payload start */
        hiqnet_payload_tree = proto_tree_add_subtree(
            hiqnet_tree, tvb, offset, messagelen - headerlen, ett_hiqnet, NULL, "Payload");
        switch(messageid) {
            case HIQNET_DISCOINFO_MSG :
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_devaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_cost, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                offset = hiqnet_display_sernum(hiqnet_payload_tree, tvb, offset);
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_maxmsgsize, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_keepaliveperiod, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                hiqnet_display_netinfo(hiqnet_payload_tree, tvb, offset);
                break;
            case HIQNET_HELLO_MSG :
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_sessnum, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_bitmask(hiqnet_payload_tree, tvb, offset, hf_hiqnet_flagmask,
                               ett_hiqnet_flags, hiqnet_flag_fields, ENC_BIG_ENDIAN);
                break;
            case HIQNET_MULTPARMGET_MSG :
                paramcount = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_paramcount, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                while (paramcount > 0) {
                    hiqnet_parameter_tree = proto_tree_add_subtree(
                        hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Parameter");
                    proto_tree_add_item(hiqnet_parameter_tree, hf_hiqnet_paramid, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    if (flags & HIQNET_INFO_FLAG) { /* This is not a request */
                        offset = hiqnet_display_data(hiqnet_parameter_tree, pinfo, tvb, offset);
                    }
                    paramcount -= 1;
                }
                break;
            case HIQNET_MULTPARMSET_MSG :
                paramcount = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_paramcount, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                while (paramcount > 0) {
                    hiqnet_parameter_tree = proto_tree_add_subtree(
                        hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Parameter");
                    proto_tree_add_item(hiqnet_parameter_tree, hf_hiqnet_paramid, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    offset = hiqnet_display_data(hiqnet_parameter_tree, pinfo, tvb, offset);
                    paramcount -= 1;
                }
                break;
            case HIQNET_PARMSUBALL_MSG :
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_devaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                hiqnet_display_vdobjectaddr(hiqnet_payload_tree, hf_hiqnet_vdobject, tvb, offset);
                offset += 4;
                /* TODO: can be decoded in two ways (old and new) */
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_sensrate, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* TODO: decode and display */
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_subflags, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case HIQNET_PARMUNSUBALL_MSG : /* Reverse engineered. Not part of the official spec. */
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_devaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                hiqnet_display_vdobjectaddr(hiqnet_payload_tree, hf_hiqnet_vdobject, tvb, offset);
                offset += 4;
                /* TODO: can be decoded in two ways (old and new) */
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case HIQNET_MULTPARMSUB_MSG :
                /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
                subcount = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_subcount, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                while (subcount > 0) {
                    hiqnet_subscription_tree = proto_tree_add_subtree(
                        hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Subscription");
                    offset = hiqnet_display_paramsub(hiqnet_subscription_tree, tvb, offset);
                    subcount -= 1;
                }
                break;
            case HIQNET_GOODBYE_MSG :
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_devaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case HIQNET_GETATTR_MSG :
                attrcount = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_attrcount, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                if (flags & HIQNET_INFO_FLAG) { /* This not a request */
                    while (attrcount > 0) {
                        hiqnet_attribute_tree = proto_tree_add_subtree(
                            hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Attribute");
                        proto_tree_add_item(hiqnet_attribute_tree, hf_hiqnet_attrid, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        offset = hiqnet_display_data(hiqnet_attribute_tree, pinfo, tvb, offset);
                        attrcount -= 1;
                    }
                } else { /* This may be a request */
                    while (attrcount > 0) {
                        proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_attrid, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        attrcount -= 1;
                    }
                }
                break;
            case HIQNET_GETVDLIST_MSG :
                /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
                str_len = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_strlen, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_wrkgrppath, tvb, offset, str_len, ENC_UCS_2|ENC_BIG_ENDIAN);
                offset += str_len;
                if (flags & HIQNET_INFO_FLAG) { /* This is not a request */
                    vdscount = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_numvds, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    while (vdscount > 0) {
                        hiqnet_vds_tree = proto_tree_add_subtree(
                            hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Virtual Devices");
                        proto_tree_add_item(hiqnet_vds_tree, hf_hiqnet_vdaddr, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_item(hiqnet_vds_tree, hf_hiqnet_vdclassid, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        vdscount -= 1;
                    }
                }
                break;
            case HIQNET_STORE_MSG :
                /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_stract, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_strnum, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                str_len = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_strlen, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_wrkgrppath, tvb, offset, str_len, ENC_UCS_2|ENC_BIG_ENDIAN);
                offset += str_len;
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_scope, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case HIQNET_RECALL_MSG :
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_recact, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_recnum, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                str_len = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_strlen, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_wrkgrppath, tvb, offset, str_len, ENC_UCS_2|ENC_BIG_ENDIAN);
                offset += str_len;
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_scope, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case HIQNET_LOCATE_MSG :
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_time, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                hiqnet_display_sernum(hiqnet_payload_tree, tvb, offset);
                break;
            case HIQNET_SUBEVTLOGMSGS_MSG :
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_maxdatasize, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_bitmask(hiqnet_payload_tree, tvb, offset, hf_hiqnet_catfilter,
                               ett_hiqnet_cats, hiqnet_cat_fields, ENC_BIG_ENDIAN);
                break;
            case HIQNET_UNSUBEVTLOGMSGS_MSG :
                proto_tree_add_bitmask(hiqnet_payload_tree, tvb, offset, hf_hiqnet_catfilter,
                               ett_hiqnet_cats, hiqnet_cat_fields, ENC_BIG_ENDIAN);
                break;
            case HIQNET_REQEVTLOG_MSG :
                /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
                if (flags & HIQNET_INFO_FLAG) { /* This is not a request */
                    eventscount = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_entrieslen, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    while (eventscount > 0) {
                        hiqnet_event_tree = proto_tree_add_subtree(
                            hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Event");

                        proto_tree_add_item(hiqnet_event_tree, hf_hiqnet_category, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;

                        proto_tree_add_item(hiqnet_event_tree, hf_hiqnet_eventid, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(hiqnet_event_tree, hf_hiqnet_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_item(hiqnet_event_tree, hf_hiqnet_eventseqnum, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        str_len = tvb_get_ntohs(tvb, offset);
                        proto_tree_add_item(hiqnet_event_tree, hf_hiqnet_eventtime, tvb, offset, str_len, ENC_UCS_2|ENC_BIG_ENDIAN);
                        offset += str_len;
                        str_len = tvb_get_ntohs(tvb, offset);
                        proto_tree_add_item(hiqnet_event_tree, hf_hiqnet_eventdate, tvb, offset, str_len, ENC_UCS_2|ENC_BIG_ENDIAN);
                        offset += str_len;
                        str_len = tvb_get_ntohs(tvb, offset);
                        proto_tree_add_item(hiqnet_event_tree, hf_hiqnet_eventinfo, tvb, offset, str_len, ENC_UCS_2|ENC_BIG_ENDIAN);
                        offset += str_len;
                        str_len = tvb_get_ntohs(tvb, offset);
                        proto_tree_add_item(
                            hiqnet_event_tree, hf_hiqnet_eventadddata, tvb, offset, str_len, ENC_NA);
                        offset += str_len;
                        eventscount -= 1;
                    }
                }
                break;
            case HIQNET_MULTPARMUNSUB_MSG :
                /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
                subcount = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_subcount, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                while (subcount > 0) {
                    hiqnet_subscription_tree = proto_tree_add_subtree(
                        hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Subscription");
                    proto_tree_add_item(hiqnet_subscription_tree, hf_hiqnet_pubparmid, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(hiqnet_subscription_tree, hf_hiqnet_subparmid, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    subcount -= 1;
                }
                break;
            case HIQNET_MULTOBJPARMSET_MSG :
                /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
                objcount = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_objcount, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                while (objcount > 0) {
                    hiqnet_object_tree = proto_tree_add_subtree(
                        hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Object");
                    hiqnet_display_vdobjectaddr(hiqnet_header_tree, hf_hiqnet_vdobject, tvb, offset);
                    offset += 4;
                    paramcount = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_item(hiqnet_object_tree, hf_hiqnet_paramcount, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    while (paramcount > 0) {
                        hiqnet_parameter_tree = proto_tree_add_subtree(
                            hiqnet_object_tree, tvb, offset, -1, ett_hiqnet, NULL, "Parameter");
                        proto_tree_add_item(hiqnet_parameter_tree, hf_hiqnet_paramid, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        offset = hiqnet_display_data(hiqnet_parameter_tree, pinfo, tvb, offset);
                        paramcount -= 1;
                    }
                    objcount -= 1;
                }
                break;
            case HIQNET_PARMSETPCT_MSG :
                /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
                paramcount = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_paramcount, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                while (paramcount > 0) {
                    hiqnet_parameter_tree = proto_tree_add_subtree(
                        hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Parameter");
                    proto_tree_add_item(hiqnet_parameter_tree, hf_hiqnet_paramid, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    /* TODO: docode paramval is in percentage represented as a 1.15 signed fixed point format */
                    proto_tree_add_item(hiqnet_parameter_tree, hf_hiqnet_paramval, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    paramcount -= 1;
                }
                break;
            case HIQNET_PARMSUBPCT_MSG :
                /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
                subcount = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_subcount, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                while (subcount > 0) {
                    hiqnet_subscription_tree = proto_tree_add_subtree(
                        hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Subscription");
                    offset = hiqnet_display_paramsub(hiqnet_subscription_tree, tvb, offset);
                    subcount -= 1;
                }
                break;
            case HIQNET_GETNETINFO_MSG :
                /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
                offset = hiqnet_display_sernum(hiqnet_payload_tree, tvb, offset);
                if (flags & HIQNET_INFO_FLAG) { /* This is not a request */
                    ifacecount = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_ifacecount, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    while (ifacecount > 0) {
                        hiqnet_ifaces_tree = proto_tree_add_subtree(
                            hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Interface");
                        proto_tree_add_item(hiqnet_ifaces_tree, hf_hiqnet_maxmsgsize, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        offset = hiqnet_display_netinfo(hiqnet_ifaces_tree, tvb, offset);
                        ifacecount -= 1;
                    }
                }
                break;
            case HIQNET_REQADDR_MSG :
                /* FIXME: Not tested, straight from the spec, never occurred with the devices I own */
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_devaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case HIQNET_SETADDR_MSG :
                offset = hiqnet_display_sernum(hiqnet_payload_tree, tvb, offset);
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_newdevaddr, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                hiqnet_display_netinfo(hiqnet_payload_tree, tvb, offset);
                break;
            case HIQNET_SETATTR_MSG : /* Reverse engineered. Not part of the official spec. */
                attrcount = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(hiqnet_payload_tree, hf_hiqnet_attrcount, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                while (attrcount > 0) {
                    hiqnet_attribute_tree = proto_tree_add_subtree(
                        hiqnet_payload_tree, tvb, offset, -1, ett_hiqnet, NULL, "Attribute");
                    proto_tree_add_item(hiqnet_attribute_tree, hf_hiqnet_attrid, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    offset = hiqnet_display_data(hiqnet_attribute_tree, pinfo, tvb, offset);
                    attrcount -= 1;
                }
                break;
                /* FIXME: Messages unknown, assumed without payload */
            case HIQNET_RESERVED0_MSG:
            case HIQNET_RESERVED1_MSG:
                /* Message without payload */
            case HIQNET_ADDRUSED_MSG:
                break;
            default : /* Unknown message or malformed packet */
                /* TODO: display something useful? */
                break;
        }
    }
    return tvb_reported_length(tvb);
}


static unsigned
get_hiqnet_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    /* length is at offset + 2 */
    return tvb_get_ntohl(tvb, offset + 2);
}

/* Fixme: For multiple hiqnet PDUS in a single TCP or UDP packet,
   the INFO column shows the information only for the last PDU */

static int
dissect_hiqnet_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, true, 6,
                     get_hiqnet_pdu_len, dissect_hiqnet_pdu, data);
    return tvb_captured_length(tvb);
}

static int
dissect_hiqnet_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int       offset = 0;
    tvbuff_t *next_tvb;
    int       offset_before;
    unsigned  plen;
    unsigned  captured_length;

    /* loop on (possibly multiple) hiqnet PDUs in UDP payload */
    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        plen = get_hiqnet_pdu_len(pinfo, tvb, offset, NULL);
        captured_length = tvb_captured_length_remaining(tvb, offset);

        if (captured_length > plen)
            captured_length = plen;
        next_tvb = tvb_new_subset_length_caplen(tvb, offset, captured_length, plen);

        dissect_hiqnet_pdu(next_tvb, pinfo, tree, data);

        /*
         * Step to the next PDU.
         * Make sure we don't overflow.
         */
        offset_before = offset;
        offset += plen;
        if (offset <= offset_before)
            break;
    }
    return tvb_captured_length(tvb);
}

void
proto_register_hiqnet(void)
{
    static hf_register_info hf[] = {
        { &hf_hiqnet_version,
            { "Version", "hiqnet.version",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_headerlen,
            { "Header length", "hiqnet.hlen",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_messagelen,
            { "Message length", "hiqnet.mlen",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_sourcedev,
            { "Source device", "hiqnet.srcdev",
                FT_UINT16, BASE_DEC_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_sourceaddr,
            { "Source address", "hiqnet.srcaddr",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_destdev,
            { "Destination device", "hiqnet.dstdev",
                FT_UINT16, BASE_DEC_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_destaddr,
            { "Destination address", "hiqnet.dstaddr",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_messageid,
            { "Message ID", "hiqnet.msgid",
                FT_UINT16, BASE_HEX,
                VALS(messageidnames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_flags,
            { "Flags", "hiqnet.flags",
                FT_UINT16, BASE_HEX,
                NULL, HIQNET_FLAGS_MASK,
                NULL, HFILL }
        },
        { &hf_hiqnet_reqack_flag,
            { "Request Acknowledgement", "hiqnet.flags.reqack",
                FT_BOOLEAN, 16,
                NULL, HIQNET_REQACK_FLAG,
                NULL, HFILL }
        },
        { &hf_hiqnet_ack_flag,
            { "Acknowledgement", "hiqnet.flags.ack",
                FT_BOOLEAN, 16,
                NULL, HIQNET_ACK_FLAG,
                NULL, HFILL }
        },
        { &hf_hiqnet_info_flag,
            { "Information", "hiqnet.flags.info",
                FT_BOOLEAN, 16,
                NULL, HIQNET_INFO_FLAG,
                NULL, HFILL }
        },
        { &hf_hiqnet_error_flag,
            { "Error", "hiqnet.flags.error",
                FT_BOOLEAN, 16,
                NULL, HIQNET_ERROR_FLAG,
                NULL, HFILL }
        },
        { &hf_hiqnet_guaranteed_flag,
            { "Guaranteed", "hiqnet.flags.guar",
                FT_BOOLEAN, 16,
                NULL, HIQNET_GUARANTEED_FLAG,
                NULL, HFILL }
        },
        { &hf_hiqnet_multipart_flag,
            { "Multipart", "hiqnet.flags.multi",
                FT_BOOLEAN, 16,
                NULL, HIQNET_MULTIPART_FLAG,
                NULL, HFILL }
        },
        { &hf_hiqnet_session_number_flag,
            { "Session Number", "hiqnet.flags.session_number",
                FT_BOOLEAN, 16,
                NULL, HIQNET_SESSION_NUMBER_FLAG,
                NULL, HFILL }
        },
        { &hf_hiqnet_hopcnt,
            { "Hop count", "hiqnet.hc",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_seqnum,
            { "Sequence number", "hiqnet.seqnum",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_errcode,
            { "Error code", "hiqnet.errcode",
                FT_UINT8, BASE_DEC_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_errstr,
            { "Error string", "hiqnet.errstr",
                FT_STRINGZ, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_startseqno,
            { "Start seq. no.", "hiqnet.ssno",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_rembytes,
            { "Remaining bytes", "hiqnet.rembytes",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_sessnum,
            { "Session number", "hiqnet.sessnum",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_cost,
            { "Cost", "hiqnet.cost",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_sernumlen,
            { "Serial number length", "hiqnet.sernumlen",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_sernum,
            { "Serial number", "hiqnet.sernum",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_maxmsgsize,
            { "Max message size", "hiqnet.maxmsgsize",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_keepaliveperiod,
            { "Keepalive period (ms)", "hiqnet.keepaliveperiod",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_netid,
            { "Network ID", "hiqnet.netid",
                FT_UINT8, BASE_DEC,
                VALS(networknames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_macaddr,
            { "MAC address", "hiqnet.macaddr",
                FT_ETHER, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_dhcp,
            { "DHCP", "hiqnet.dhcp",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_ipaddr,
            { "IP Address", "hiqnet.ipaddr",
                FT_IPv4, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_subnetmsk,
            { "Subnet mask", "hiqnet.subnetmsk",
                FT_IPv4, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_gateway,
            { "Gateway", "hiqnet.gateway",
                FT_IPv4, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_flagmask,
            { "Flag mask", "hiqnet.flagmask",
                FT_UINT16, BASE_HEX,
                NULL, HIQNET_FLAGS_MASK,
                NULL, HFILL }
        },
        { &hf_hiqnet_paramcount,
            { "Parameter count", "hiqnet.paramcount",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_paramid,
            { "Parameter ID", "hiqnet.paramid",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_vdobject,
            { "Virtual Device Object", "hiqnet.vdobject",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_subtype,
            { "Subscription Type (New Style)", "hiqnet.subtype",
                FT_UINT8, BASE_DEC,
                NULL, HIQNET_SUBSCRIPTION_TYPE_MASK,
                NULL, HFILL }
        },
        /* FIXME: decode old style subscription type
        { &hf_hiqnet_subtypeold,
            { "Subscription Type (Old Style)", "hiqnet.subtype",
                FT_UINT8, BASE_DEC,
                VALS(subscription_types_oldstyle_names), 0x0,
                NULL, HFILL }
        },
        */
        { &hf_hiqnet_sensrate,
            { "Sensor Rate (ms)", "hiqnet.sensrate",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_subflags,
            { "Subscription Flags", "hiqnet.subflags",
                FT_UINT16, BASE_HEX,
                NULL, HIQNET_SUBSCRIPTION_FLAGS_MASK,
                NULL, HFILL }
        },
        { &hf_hiqnet_subcount,
            { "No of Subscriptions", "hiqnet.subcount",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_pubparmid,
            { "Publisher Parameter ID", "hiqnet.pubparmid",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_subaddr,
            { "Subscriber Address", "hiqnet.subaddr",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_subparmid,
            { "Subscriber Parameter ID", "hiqnet.subparmid",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_reserved0,
            { "Reserved", "hiqnet.reserved0",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_reserved1,
            { "Reserved", "hiqnet.reserved1",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_attrcount,
            { "Attribute count", "hiqnet.attrcount",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_attrid,
            { "Attribute ID", "hiqnet.attrid",
                FT_UINT16, BASE_DEC,
                VALS(device_attributes_names), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_datatype,
            { "Data type", "hiqnet.datatype",
                FT_UINT8, BASE_HEX,
                VALS(datatypenames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_datalen,
            { "Data length", "hiqnet.datalen",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_byte_value,
            { "Value", "hiqnet.byte_value",
                FT_INT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_ubyte_value,
            { "Value", "hiqnet.ubyte_value",
                FT_UINT8, BASE_DEC_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_word_value,
            { "Value", "hiqnet.word_value",
                FT_INT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_uword_value,
            { "Value", "hiqnet.uword_value",
                FT_UINT16, BASE_DEC_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_long_value,
            { "Value", "hiqnet.long_value",
                FT_INT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_ulong_value,
            { "Value", "hiqnet.ulong_value",
                FT_UINT32, BASE_DEC_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_float32_value,
            { "Value", "hiqnet.float32_value",
                FT_FLOAT, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_float64_value,
            { "Value", "hiqnet.float64_value",
                FT_DOUBLE, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_block_value,
            { "Value", "hiqnet.block_value",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        /* Counted *and* null-terminated */
        { &hf_hiqnet_string_value,
            { "Value", "hiqnet.string_value",
                FT_STRINGZ, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_long64_value,
            { "Value", "hiqnet.long64_value",
                FT_INT64, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_ulong64_value,
            { "Value", "hiqnet.ulong64_value",
                FT_UINT64 , BASE_DEC_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_wrkgrppath,
            { "Workgroup Path", "hiqnet.wrkgrppath",
                FT_STRINGZ, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_numvds,
            { "Number of Virtual Devices", "hiqnet.numvds",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_vdaddr,
            { "Virtual Device Address", "hiqnet.vdaddr",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_vdclassid,
            { "Virtual Device Class ID", "hiqnet.vdclassid",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_stract,
            { "Store Action", "hiqnet.stract",
                FT_UINT8, BASE_DEC,
                VALS(actionnames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_strnum,
            { "Store Number", "hiqnet.strnum",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_scope,
            { "Scope", "hiqnet.scope",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_recact,
            { "Recall Action", "hiqnet.rec.act",
                FT_UINT8, BASE_DEC,
                VALS(actionnames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_recnum,
            { "Recall Number", "hiqnet.recnum",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_strlen,
            { "String length", "hiqnet.strlen",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_time,
            { "Locate time (ms)", "hiqnet.time",
                FT_UINT16, BASE_DEC,
                VALS(timenames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_maxdatasize,
            { "Maximum Data Size", "hiqnet.maxdatasize",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_catfilter,
            { "Category Filter", "hiqnet.catfilter",
                FT_UINT32, BASE_HEX,
                NULL, HIQNET_CATEGORIES_MASK,
                NULL, HFILL }
        },
        { &hf_hiqnet_app_cat,
            { "Application", "hiqnet.appcat",
                FT_BOOLEAN, 32,
                NULL, HIQNET_APPLICATION_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_conf_cat,
            { "Configuration", "hiqnet.confcat",
                FT_BOOLEAN, 32,
                NULL, HIQNET_CONF_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_audionet_cat,
            { "Audio Network", "hiqnet.audionetcat",
                FT_BOOLEAN, 32,
                NULL, HIQNET_AUDIONET_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_ctrlnet_cat,
            { "Control Network", "hiqnet.ctrlnetcat",
                FT_BOOLEAN, 32,
                NULL, HIQNET_CTRLNET_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_vendnet_cat,
            { "Vendor Network", "hiqnet.vendnetcat",
                FT_BOOLEAN, 32,
                NULL, HIQNET_VENDNET_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_startup_cat,
            { "Startup", "hiqnet.startupcat",
                FT_BOOLEAN, 32,
                NULL, HIQNET_STARTUP_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_dsp_cat,
            { "DSP", "hiqnet.dspcat",
                FT_BOOLEAN, 32,
                NULL, HIQNET_DSP_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_misc_cat,
            { "Miscellaneous", "hiqnet.misccat",
                FT_BOOLEAN, 32,
                NULL, HIQNET_MISC_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_ctrlog_cat,
            { "Control Logic", "hiqnet.crtllogcat",
                FT_BOOLEAN, 32,
                NULL, HIQNET_CTRLLOG_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_foreignproto_cat,
            { "Foreign Protocol", "hiqnet.foreignprotocat",
                FT_BOOLEAN, 32,
                NULL, HIQNET_FOREIGNPROTO_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_digio_cat,
            { "Digital I/O", "hiqnet.digiocat",
                FT_BOOLEAN, 32,
                NULL, HIQNET_DIGIO_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_ctrlsurf_cat,
            { "Control Surface", "hiqnet.ctrlsurfcat",
                FT_BOOLEAN, 32,
                NULL, HIQNET_CTRLSURF_CAT,
                NULL, HFILL }
        },
        { &hf_hiqnet_entrieslen,
            { "Number of Entries", "hiqnet.entrieslen",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_category,
            { "Category", "hiqnet.cat",
                FT_UINT16, BASE_HEX,
                VALS(eventcategorynames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_eventid,
            { "Event ID", "hiqnet.eventid",
                FT_UINT16, BASE_DEC,
                VALS(eventidnames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_priority,
            { "Priority", "hiqnet.priority",
                FT_UINT8, BASE_DEC,
                VALS(prioritynames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_eventseqnum,
            { "Sequence Number", "hiqnet.eventseqnum",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_eventtime,
            { "Time", "hiqnet.eventtime",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_eventdate,
            { "Date", "hiqnet.eventdate",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_eventinfo,
            { "Information", "hiqnet.information",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_eventadddata,
            { "Additional Data", "hiqnet.eventadddata",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_objcount,
            { "Object Count", "hiqnet.objcount",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_paramval,
            { "Parameter Value (%)", "hiqnet.paramval",
                FT_INT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_ifacecount,
            { "Interface Count", "hiqnet.ifacecount",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_comid,
            { "Com Port Identifier", "hiqnet.comid",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_baudrate,
            { "Baud Rate", "hiqnet.baudrate",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_parity,
            { "Parity", "hiqnet.parity",
                FT_UINT8, BASE_DEC,
                VALS(paritynames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_stopbits,
            { "Stop Bits", "hiqnet.stopbits",
                FT_UINT8, BASE_DEC,
                VALS(stopbitsnames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_databits,
            { "Data Bits", "hiqnet.databits",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_flowcontrol,
            { "Flowcontrol", "hiqnet.flowcontrol",
                FT_UINT8, BASE_DEC,
                VALS(flowcontrolnames), 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_devaddr,
            { "Device Address", "hiqnet.device",
                FT_UINT16, BASE_DEC_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_hiqnet_newdevaddr,
            { "New Device Address", "hiqnet.device",
                FT_UINT16, BASE_DEC_HEX,
                NULL, 0x0,
                NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_hiqnet,
        &ett_hiqnet_flags,
        &ett_hiqnet_cats
    };

    static ei_register_info ei[] = {
        { &ei_hiqnet_datatype, { "hiqnet.datatype.invalid", PI_PROTOCOL, PI_WARN, "Invalid datatype", EXPFILL }},
    };

    expert_module_t* expert_hiqnet;

    proto_hiqnet = proto_register_protocol ("Harman HiQnet", "HiQnet", "hiqnet");

    proto_register_field_array(proto_hiqnet, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_hiqnet = expert_register_protocol(proto_hiqnet);
    expert_register_field_array(expert_hiqnet, ei, array_length(ei));

    hiqnet_udp_handle = register_dissector("hiqnet.udp", dissect_hiqnet_udp, proto_hiqnet);
    hiqnet_tcp_handle = register_dissector("hiqnet.tcp", dissect_hiqnet_tcp, proto_hiqnet);
}


void
proto_reg_handoff_hiqnet(void)
{
    dissector_add_uint_with_preference("udp.port", HIQNET_PORT, hiqnet_udp_handle);
    dissector_add_uint_with_preference("tcp.port", HIQNET_PORT, hiqnet_tcp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 expandtab:
 * :indentSize=4:noTabs=true:
 */

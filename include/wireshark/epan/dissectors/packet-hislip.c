/* packet-hislip.c
 * Routines for High-Speed LAN Instrument Protocol dissection
 * by Marcel Essig <essig.marcel@gmail.com>
 * and Guido Kiener <guido.kiener@rohde-schwarz.com>
 * Copyright (C) 2014 Rohde & Schwarz GmbH & Co. KG
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*  See http://ivifoundation.org/downloads/Class%20Specifications/IVI-6.1_HiSLIP-1.1-2011-02-24.pdf
    IVI VI-6.1: High-Speed LAN Instrument Protocol (HiSLIP)-*/


#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include "packet-tcp.h"

#define PROTO_TAG_HiSLIP    "HiSLIP"
#define FRAME_HEADER_LEN    16
#define MAX_DATA_SHOW_SIZE  60

/*Messagetypes*/
#define HISLIP_INITIALIZE                       0
#define HISLIP_INITIALIZERESPONSE               1
#define HISLIP_FATALERROR                       2
#define HISLIP_ERROR                            3
#define HISLIP_ASYNCLOCK                        4
#define HISLIP_ASYNCLOCK_RESPONSE               5
#define HISLIP_DATA                             6
#define HISLIP_DATAEND                          7
#define HISLIP_DEVICECLEARCOMPLETE              8
#define HISLIP_DEVICECLEARACKNOWLEDGE           9
#define HISLIP_ASYNCREMOTELOCALCONTROL         10
#define HISLIP_ASYNCREMOTELOCALRESPONSE        11
#define HISLIP_TRIGGER                         12
#define HISLIP_INTERRUPTED                     13
#define HISLIP_ASYNCINTERRUPTED                14
#define HISLIP_ASYNCMAXIMUMMESSAGESIZE         15
#define HISLIP_ASYNCMAXIMUMMESSAGESIZERESPONSE 16
#define HISLIP_ASYNCINITIALIZE                 17
#define HISLIP_ASYNCINITIALIZERESPONSE         18
#define HISLIP_ASYNCDEVICECLEAR                19
#define HISLIP_ASYNCSERVICEREQUEST             20
#define HISLIP_ASYNCSTATUSQUERY                21
#define HISLIP_ASYNCSTATUSRESPONSE             22
#define HISLIP_ASYNCDEVICECLEARACKNOWLEDGE     23
#define HISLIP_ASYNCLOCKINFO                   24
#define HISLIP_ASYNCLOCKINFORESPONSE           25



static int proto_hislip;

static dissector_handle_t hislip_handle;

/* Request/Response tracking*/

typedef struct _hislip_transaction_t
{
    uint32_t req_frame;
    uint32_t rep_frame;
    uint8_t messagetype;
    uint8_t controlcode;
    uint32_t messagepara;
} hislip_transaction_t;

typedef struct _hislip_conv_info_t
{
    uint8_t connectiontype;
    wmem_tree_t *pdus;
 }hislip_conv_info_t;


typedef struct _hislipinfo
{
    uint8_t messagetype;
    uint8_t controlcode;
    uint32_t messageparameter;
    uint64_t payloadlength;
    unsigned  offset;
    proto_item *hislip_item;
} hislipinfo;


void proto_register_hislip(void);
void proto_reg_handoff_hislip(void);

#define HISLIP_PORT     4880

/*Field indexs*/
static int hf_hislip_prologue;
static int hf_hislip_messagetype;
static int hf_hislip_controlcode;
static int hf_hislip_controlcode_rmt;
static int hf_hislip_controlcode_overlap;
static int hf_hislip_controlcode_asynclock_code;
static int hf_hislip_controlcode_asynclockresponse_code_request;
static int hf_hislip_controlcode_asynclockresponse_code_release;
static int hf_hislip_controlcode_asynclockinforesponse_code;
static int hf_hislip_controlcode_feature_negotiation;
static int hf_hislip_controlcode_asyncremotelocalcontrol_code;
static int hf_hislip_controlcode_stb;
static int hf_hislip_messageparameter;
static int hf_hislip_payloadlength;
static int hf_hislip_data;
static int hf_hislip_msgpara_messageid;
static int hf_hislip_msgpara_sessionid;
static int hf_hislip_msgpara_serverproto;
static int hf_hislip_msgpara_vendorID;
static int hf_hislip_msgpara_clientproto;
static int hf_hislip_msgpara_clients;
static int hf_hislip_msgpara_timeout;
static int hf_hislip_fatalerrcode;
static int hf_hislip_nonfatalerrorcode;
static int hf_hislip_syn;
static int hf_hislip_asyn;
static int hf_hislip_retransmission;
static int hf_hislip_request;
static int hf_hislip_maxmessagesize;
static int hf_hislip_response;

/*Subtree index*/
static int ett_hislip;
static int ett_hislip_msgpara;


static expert_field ei_wrong_prologue;
static expert_field ei_msg_not_null;

static const range_string messagetypestring[] =
{
    { HISLIP_INITIALIZE                     , HISLIP_INITIALIZE                     , "Initialize" },
    { HISLIP_INITIALIZERESPONSE             , HISLIP_INITIALIZERESPONSE             , "InitializeResponse" },
    { HISLIP_FATALERROR                     , HISLIP_FATALERROR                     , "FatalError" },
    { HISLIP_ERROR                          , HISLIP_ERROR                          , "Error" },
    { HISLIP_ASYNCLOCK                      , HISLIP_ASYNCLOCK                      , "AsyncLock" },
    { HISLIP_ASYNCLOCK_RESPONSE             , HISLIP_ASYNCLOCK_RESPONSE             , "AsyncLockResponse" },
    { HISLIP_DATA                           , HISLIP_DATA                           , "Data" },
    { HISLIP_DATAEND                        , HISLIP_DATAEND                        , "DataEnd" },
    { HISLIP_DEVICECLEARCOMPLETE            , HISLIP_DEVICECLEARCOMPLETE            , "DeviceClearComplete" },
    { HISLIP_DEVICECLEARACKNOWLEDGE         , HISLIP_DEVICECLEARACKNOWLEDGE         , "DeviceClearAcknowledge" },
    { HISLIP_ASYNCREMOTELOCALCONTROL        , HISLIP_ASYNCREMOTELOCALCONTROL        , "AsyncRemoteLocalControl" },
    { HISLIP_ASYNCREMOTELOCALRESPONSE       , HISLIP_ASYNCREMOTELOCALRESPONSE       , "AsyncRemoteLocalResponse" },
    { HISLIP_TRIGGER                        , HISLIP_TRIGGER                        , "Trigger" },
    { HISLIP_INTERRUPTED                    , HISLIP_INTERRUPTED                    , "Interrupted" },
    { HISLIP_ASYNCINTERRUPTED               , HISLIP_ASYNCINTERRUPTED               , "AsyncInterrupted" },
    { HISLIP_ASYNCMAXIMUMMESSAGESIZE        , HISLIP_ASYNCMAXIMUMMESSAGESIZE        , "AsyncMaximumMessageSize" },
    { HISLIP_ASYNCMAXIMUMMESSAGESIZERESPONSE, HISLIP_ASYNCMAXIMUMMESSAGESIZERESPONSE, "AsyncMaximumMessageSizeResponse" },
    { HISLIP_ASYNCINITIALIZE                , HISLIP_ASYNCINITIALIZE                , "AsyncInitialize" },
    { HISLIP_ASYNCINITIALIZERESPONSE        , HISLIP_ASYNCINITIALIZERESPONSE        , "AsyncInitializeResponse" },
    { HISLIP_ASYNCDEVICECLEAR               , HISLIP_ASYNCDEVICECLEAR               , "AsyncDeviceClear" },
    { HISLIP_ASYNCSERVICEREQUEST            , HISLIP_ASYNCSERVICEREQUEST            , "AsyncServiceRequest" },
    { HISLIP_ASYNCSTATUSQUERY               , HISLIP_ASYNCSTATUSQUERY               , "AsyncStatusQuery" },
    { HISLIP_ASYNCSTATUSRESPONSE            , HISLIP_ASYNCSTATUSRESPONSE            , "AsyncStatusResponse" },
    { HISLIP_ASYNCDEVICECLEARACKNOWLEDGE    , HISLIP_ASYNCDEVICECLEARACKNOWLEDGE    , "AsyncDeviceClearAcknowledge" },
    { HISLIP_ASYNCLOCKINFO                  , HISLIP_ASYNCLOCKINFO                  , "AsyncLockInfo" },
    { HISLIP_ASYNCLOCKINFORESPONSE          , HISLIP_ASYNCLOCKINFORESPONSE          , "AsyncLockInfoResponse" },
    { 26                                    , 127                                   , "reserved for future use"},
    {128                                    , 255                                   , "VendorSpecific" },
    {  0                                    ,   0                                   , NULL }
};


static const value_string rmt[] =
{
        { 0, "RMT was not delivered" },
        { 1, "RMT was delivered" },
        { 0, NULL }
};

static const value_string overlap[] =
{
        { 0, "Prefer Synchronized" },
        { 1, "Prefer Overlap" },
        { 0, NULL }
};

static const value_string asynclock_code[] =
{
        { 0, "Release" },
        { 1, "Request" },
        { 0, NULL }
};

static const value_string asynclockresponse_code_request[] =
{
        { 0, "Failure" },
        { 1, "Success" },
        { 3, "Error" },
        { 0, NULL }
};

static const value_string asynclockresponse_code_release[] =
{
        { 1, "Success exclusive" },
        { 2, "Success shared" },
        { 3, "Error" },
        { 0, NULL }
};

static const value_string asynclockinforesponse_code[] =
{
        { 0, "No exclusive lock granted" },
        { 1, "Exclusive lock granted" },
        { 0, NULL }
};

static const value_string feature_negotiation[] =
{
        { 0, "Synchronized mode" },
        { 1, "Overlapped mode" },
        { 0, NULL }
};

static const value_string asyncremotelocalcontrol_code[] =
{
        { 0, "Disable remote" },
        { 1, "Enable remote" },
        { 2, "Disable remote and go to local" },
        { 3, "Enable remote and go to remote" },
        { 4, "Enable remote and lock out local" },
        { 5, "Enable remote, go to remote, and set local lockout" },
        { 6, "Go to local without changing state of remote enable" },
        { 0, NULL }
};

static const value_string remotetype[] =
{
        { 0, "(VI_GPIB_REN_DEASSERT)" },
        { 1, "(VI_GPIB_REN_ASSERT)" },
        { 2, "(VI_GPIB_REN_DEASSERT_GTL)" },
        { 3, "(VI_GPIB_REN_ASSERT_ADDRESS)" },
        { 4, "(VI_GPIB_REN_ASSERT_LLO)" },
        { 5, "(VI_GPIB_REN_ASSERT_ADDRESS_LLO)" },
        { 6, "(VI_GPIB_REN_ADDRESS_GTL)" },
        { 0, NULL}
};

static const range_string fatalerrortype[] =
{
    {  0,  0, "Unidentified error" },
    {  1,  1, "Poorly formed message header" },
    {  2,  2, "Attempt to use connection without both channels established" },
    {  3,  3, "Invalid Initialization Sequence" },
    {  4,  4, "Server refused connection due to maximum number of clients exceeded" },
    {  5,127, "Reserved for HiSLIP extensions" },
    {128,255, "Device defined errors" },
    {  0,  0, NULL }
};

static const range_string nonfatalerrortype[] =
{
    {  0,  0, "Unidentified error" },
    {  1,  1, "Unrecognized Message Type" },
    {  2,  2, "Unrecognized control code" },
    {  3,  3, "Unrecognized Vendor Defined Message" },
    {  4,  4, "Message too large" },
    {  5,127, "Reserved for HiSLIP extensions" },
    {128,255, "Device defined errors" },
    {  0,  0, NULL }
};

/*See http://ivifoundation.org/specifications/default.aspx
    VPP-9: Instrument Vendor Abbreviations Table 3-1 */
/* Sorted by value (spec is not quite in order) */
static const value_string vendorID[] =
{
        { 0x4143, "Applicos BV" },
        { 0x4144, "Ando Electric Company Limited" },
        { 0x4146, "Aeroflex Laboratories" },
        { 0x4147, "Agilent Technologies" },
        { 0x4149, "AIM GmbH" },
        { 0x414D, "AMP Incorporated" },
        { 0x414E, "Analogic, Corp." },
        { 0x414F, "AOIP Instrumentation" },
        { 0x4150, "Audio Precision, Inc" },
        { 0x4151, "Acqiris" },
        { 0x4153, "ASCOR Incorporated" },
        { 0x4154, "Thurlby Thandar Instruments Limited" }, /* Astronics Test Systems Inc ? */
        { 0x4155, "Anritsu Company" },
/*        { 0x4155, "Serendipity Systems, Inc." }, XXX - duplicate of "Anritsu Company" */
        { 0x4156, "Advantest Corporation" },
        { 0x4241, "BAE Systems" },
        { 0x4242, "B&B Technologies" },
        { 0x424B, "Bruel & Kjaer" },
        { 0x4255, "Bustec Production Ltd." },
        { 0x4341, "CAL-AV Labs, Inc." },
        { 0x4343, "Compressor Controls Corporation" },
        { 0x4348, "C&H Technologies, Inc." },
        { 0x4349, "Cambridge Instruments" },
        { 0x4359, "CYTEC Corporation" },
        { 0x4450, "Directed Perceptions Inc." },
        { 0x4453, "DSP Technology Inc." },
        { 0x4456, "IBEKO POWER AB" },
        { 0x464C, "Fluke Company Inc." },
        { 0x464F, "fos4X GmbH" },
        { 0x4749, "EIP Microwave, Inc." },
        { 0x474b, "gnubi communications, Inc." },
        { 0x4750, "Hewlett-Packard Company" },
        { 0x4752, "GenRad" },
        { 0x4754, "Giga-tronics, Inc." },
        { 0x4848, "Hoecherl & Hackl GmbH" },
        { 0x4943, "Integrated Control Systems" },
        { 0x4945, "Instrumentation Engineering, Inc." },
        { 0x4946, "IFR" },
        { 0x4953, "Intepro Systems" },
        { 0x4B45, "Keithley Instruments" },
        { 0x4B49, "Kikusui Inc." },
        { 0x4B50, "Kepco, Inc." },
        { 0x4B53, "KineticSystems, Corp." },
        { 0x4B54, "Keysight Technologies (Reserved)" },
        { 0x4C43, "LeCroy" },
        { 0x4C50, "LitePoint Corporation" },
        { 0x4D41, "North Atlantic Instruments" },
        { 0x4D48, "NH Research" },
        { 0x4D49, "Marconi Instruments" },
        { 0x4D50, "MAC Panel Company" },
        { 0x4D53, "Microscan" },
        { 0x4D54, "ManTech Test Systems" },
        { 0x4D57, "Pacific MindWorks, Inc." },
        { 0x4E44, "Newland Design + Associate, Inc."},
        { 0x4E49, "National Instruments Corp." },
        { 0x4E54, "NEUTRIK AG" },
        { 0x5043, "Picotest" },
        { 0x5045, "PesMatrix Inc."},
        { 0x5049, "Pickering Interfaces" },
        { 0x504D, "Phase Metrics" },
        { 0x5054, "Power-Tek Inc." },
        { 0x5241, "Radisys Corp." },
        { 0x5246, "ThinkRF Corporation" },
        { 0x5249, "Racal Instruments, Inc." },
        { 0x5253, "Rohde & Schwarz GmbH" },
        { 0x5343, "Scicom" },
        { 0x5349, "SignalCraft Technologies Inc." },
        { 0x534C, "Schlumberger Technologies" },
        { 0x5352, "Scientific Research Corporation" },
/*        { 0x5352, "Sony/Tektronix Corporation" }, XXX - duplicate of "Scientific Research Corporation" */
        { 0x5353, "Spectrum Signal Processing, Inc." },
        { 0x5354, "Sony/Tekronix Corporation" },
        { 0x5441, "Talon Instruments" },
        { 0x5445, "Teradyne" },
        { 0x544B, "Tektronix, Inc." },
        { 0x544D, "Transmagnetics, Inc." },
        { 0x5453, "Test & Measurement Systems Inc." },
        { 0x5454, "TTI Testron, Inc." },
        { 0x554E, "Holding 'Informtest'" },
        { 0x5553, "Universal Switching Corporation" },
        { 0x5641, "VXIbus Associates, Inc." },
        { 0x5645, "Vencon Technologies Inc." },
        { 0x5650, "Virginia Panel, Corp." },
        { 0x5654, "VXI Technology, Inc." },
        { 0x5747, "Wandel & Goltermann" },
        { 0x5754, "Wavetek Corp." },
        { 0x575a, "Welzek" },
        { 0x594B, "Yokogawa Electric Corporation" },
        { 0x5A54, "ZTEC" },
        { 0, NULL }
};
static value_string_ext vendorID_ext = VALUE_STRING_EXT_INIT(vendorID);

static void
decode_messagepara(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, hislipinfo *data)
{

    proto_item * item = NULL;
    proto_tree *msgpara_tree;
    item = proto_tree_add_item(tree, hf_hislip_messageparameter, tvb, data->offset, 4, ENC_NA);
    msgpara_tree = proto_item_add_subtree(item, ett_hislip_msgpara);

    switch (data->messagetype)
    {
    case HISLIP_INITIALIZE:

        proto_tree_add_item(msgpara_tree, hf_hislip_msgpara_clientproto, tvb, data->offset, 2, ENC_BIG_ENDIAN );
        data->offset += 2;
        proto_tree_add_item(msgpara_tree, hf_hislip_msgpara_vendorID, tvb, data->offset, 2, ENC_BIG_ENDIAN );
        data->offset += 2;
        break;


    case HISLIP_INITIALIZERESPONSE:

        proto_tree_add_item(msgpara_tree, hf_hislip_msgpara_serverproto, tvb, data->offset, 2, ENC_BIG_ENDIAN );
        data->offset += 2;
        proto_tree_add_item(msgpara_tree, hf_hislip_msgpara_sessionid, tvb, data->offset, 2, ENC_BIG_ENDIAN );
        data->offset += 2;
        break;


    case HISLIP_ASYNCLOCK:

        /*Request or Release?*/
        if (data->controlcode)
        {   /*Request*/
            proto_tree_add_item(msgpara_tree, hf_hislip_msgpara_timeout, tvb, data->offset, 4, ENC_BIG_ENDIAN);
        }
        else
        {    /*Release*/
            proto_tree_add_item(msgpara_tree, hf_hislip_msgpara_messageid, tvb, data->offset, 4, ENC_BIG_ENDIAN);
        }
        data->offset += 4;
        break;


     case HISLIP_ASYNCLOCKINFORESPONSE:

        proto_tree_add_item(msgpara_tree, hf_hislip_msgpara_clients, tvb, data->offset, 4, ENC_BIG_ENDIAN );
        data->offset += 4;
        break;


    case HISLIP_ASYNCINITIALIZE:

        data->offset += 2;
        proto_tree_add_item(msgpara_tree, hf_hislip_msgpara_sessionid, tvb, data->offset, 2, ENC_BIG_ENDIAN);
        data->offset += 2;
        break;


    case HISLIP_ASYNCINITIALIZERESPONSE:

        data->offset += 2;
        proto_tree_add_item(msgpara_tree, hf_hislip_msgpara_vendorID, tvb, data->offset, 2, ENC_BIG_ENDIAN );
        data->offset += 2;
        break;


    case HISLIP_DATA:
    case HISLIP_DATAEND:
    case HISLIP_TRIGGER:
    case HISLIP_INTERRUPTED:
    case HISLIP_ASYNCINTERRUPTED:
    case HISLIP_ASYNCSTATUSQUERY:
    case HISLIP_ASYNCREMOTELOCALCONTROL:

         proto_tree_add_item(msgpara_tree, hf_hislip_msgpara_messageid, tvb, data->offset, 4, ENC_BIG_ENDIAN );
         proto_item_append_text(data->hislip_item, ", MessageId: 0x%0x", data->messageparameter);
         data->offset += 4;
         break;


    default:

         if (data->messageparameter != 0)
         {
            proto_tree_add_expert(msgpara_tree, pinfo, &ei_msg_not_null, tvb, data->offset, 4);
         }
         data->offset += 4;
    }
}



static void
decode_controlcode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, hislipinfo *data, uint8_t oldcontrolvalue)
{
    proto_item * item = NULL;
    switch (data->messagetype )
    {
    case HISLIP_DATA:
    case HISLIP_DATAEND:
    case HISLIP_TRIGGER:
    case HISLIP_ASYNCSTATUSQUERY:

        proto_tree_add_item(tree, hf_hislip_controlcode_rmt, tvb, data->offset, 1, ENC_BIG_ENDIAN );
        break;


    case HISLIP_INITIALIZERESPONSE:

        proto_tree_add_item(tree, hf_hislip_controlcode_overlap, tvb, data->offset, 1, ENC_BIG_ENDIAN );
        col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", val_to_str_const(data->controlcode, overlap, "Unknown"));
        proto_item_append_text(data->hislip_item, ", %s", val_to_str_const(data->controlcode, overlap, "Unknown"));
        break;


    case HISLIP_ASYNCLOCK:

        item = proto_tree_add_item(tree, hf_hislip_controlcode_asynclock_code, tvb, data->offset, 1, ENC_BIG_ENDIAN );
        col_append_fstr(pinfo->cinfo, COL_INFO, " [%s", val_to_str_const(data->controlcode, asynclock_code, "Unknown"));
        proto_item_append_text(data->hislip_item, ", %s", val_to_str_const(data->controlcode, asynclock_code, "Unknown"));

        /*if release add ] and leave*/
        if (data->controlcode != 1)
        {
            col_append_str(pinfo->cinfo, COL_INFO, "]");
            break;
        }

        /*shared (Datalength != 0)or exclusive*/
        if (data->payloadlength == 0)
        {

            proto_item_append_text(item, "[Exclusive]");
            col_append_str(pinfo->cinfo, COL_INFO, " Exclusive]");
            proto_item_append_text(data->hislip_item, " (Exclusive)");
        }
        else
        {
            proto_item_append_text(item, "[Shared]");
            col_append_str(pinfo->cinfo, COL_INFO, " Shared]");
            proto_item_append_text(data->hislip_item, " (Shared)");
        }
        break;


    case HISLIP_FATALERROR:

        proto_tree_add_item(tree, hf_hislip_fatalerrcode, tvb, data->offset, 1, ENC_BIG_ENDIAN );
        col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", rval_to_str_const(data->controlcode, fatalerrortype, "Unknown"));
        proto_item_append_text(data->hislip_item, ", %s", rval_to_str_const(data->controlcode, fatalerrortype, "Unknown"));
        break;


    case HISLIP_ERROR:

        proto_tree_add_item(tree, hf_hislip_nonfatalerrorcode, tvb, data->offset, 1, ENC_BIG_ENDIAN );
        col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", rval_to_str_const(data->controlcode, nonfatalerrortype, "Unknown"));
        proto_item_append_text(data->hislip_item, ", %s", rval_to_str_const(data->controlcode, nonfatalerrortype, "Unknown"));
        break;


    case HISLIP_ASYNCLOCK_RESPONSE:

        /*Response of Request or Release*/
        if (oldcontrolvalue == 1)
        {   /*Requestresponse*/
            proto_tree_add_item(tree, hf_hislip_controlcode_asynclockresponse_code_request, tvb, data->offset, 1, ENC_BIG_ENDIAN );
            col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", val_to_str_const(data->controlcode, asynclockresponse_code_request, "Unknown"));
            proto_item_append_text(data->hislip_item, ", %s", val_to_str_const(data->controlcode, asynclockresponse_code_request, "Unknown"));
        }
        else
        {   /*Releaseresponse*/
            proto_tree_add_item(tree, hf_hislip_controlcode_asynclockresponse_code_release, tvb, data->offset, 1, ENC_BIG_ENDIAN );
            col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", val_to_str_const(data->controlcode, asynclockresponse_code_release, "Unknown"));
            proto_item_append_text(data->hislip_item, ", %s", val_to_str_const(data->controlcode, asynclockresponse_code_release, "Unknown"));
        }
        break;


    case HISLIP_ASYNCLOCKINFORESPONSE:

        proto_tree_add_item(tree, hf_hislip_controlcode_asynclockinforesponse_code, tvb, data->offset, 1, ENC_BIG_ENDIAN );
        col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", val_to_str_const(data->controlcode, asynclockinforesponse_code, "Unknown"));
        proto_item_append_text(data->hislip_item, ", %s", val_to_str_const(data->controlcode, asynclockinforesponse_code, "Unknown"));
        break;


    case HISLIP_ASYNCREMOTELOCALCONTROL:

        item = proto_tree_add_item(tree, hf_hislip_controlcode_asyncremotelocalcontrol_code, tvb, data->offset, 1, ENC_BIG_ENDIAN );
        proto_item_append_text(item, " %s", val_to_str_const(data->controlcode, remotetype, "Unknown"));
        col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", val_to_str_const(data->controlcode, asyncremotelocalcontrol_code, "Unknown"));
        proto_item_append_text(data->hislip_item, ", %s", val_to_str_const(data->controlcode, asyncremotelocalcontrol_code, "Unknown"));

        break;


    case HISLIP_ASYNCSTATUSRESPONSE:
    case HISLIP_ASYNCSERVICEREQUEST:

        proto_tree_add_item(tree, hf_hislip_controlcode_stb, tvb, data->offset, 1, ENC_BIG_ENDIAN );
        col_append_fstr(pinfo->cinfo, COL_INFO, " STB (0x%x)", data->controlcode);
        proto_item_append_text(data->hislip_item, ", STB (0x%x)", data->controlcode);
        break;

    case HISLIP_ASYNCDEVICECLEARACKNOWLEDGE:
    case HISLIP_DEVICECLEARCOMPLETE:
    case HISLIP_DEVICECLEARACKNOWLEDGE:

        proto_tree_add_item(tree, hf_hislip_controlcode_feature_negotiation, tvb, data->offset, 1, ENC_BIG_ENDIAN );
        col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", val_to_str_const(data->controlcode&0x01, feature_negotiation, "Unknown"));
        break;

    default:
        proto_tree_add_item(tree, hf_hislip_controlcode, tvb, data->offset, 1, ENC_BIG_ENDIAN);

    }

    data->offset++;
}



static void
decode_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, hislipinfo *data)
{
    proto_item * item = NULL;
    /*check for data in packet*/
    if (data->payloadlength != 0)
    {
        uint64_t datalength;
        double max_message_size;

        switch (data->messagetype)
        {
        case HISLIP_DATA:
        case HISLIP_DATAEND:
        case HISLIP_INITIALIZE:

            datalength = MAX_DATA_SHOW_SIZE;

            if (data->payloadlength <= datalength)
                datalength = data->payloadlength;

            col_append_fstr(pinfo->cinfo, COL_INFO, " %s", tvb_format_text(pinfo->pool, tvb, data->offset, (uint32_t)datalength));
            proto_tree_add_item(tree, hf_hislip_data, tvb, data->offset, -1, ENC_UTF_8 |ENC_NA);

            break;

        case HISLIP_ASYNCMAXIMUMMESSAGESIZE:
        case HISLIP_ASYNCMAXIMUMMESSAGESIZERESPONSE:

            max_message_size = (double)tvb_get_ntoh64(tvb, data->offset);
            max_message_size = max_message_size/1048576.0;

            item = proto_tree_add_item(tree, hf_hislip_maxmessagesize, tvb, data->offset, 8, ENC_BIG_ENDIAN);
            proto_item_append_text(item, " bytes (%.2f Mbytes)", max_message_size);
            col_append_fstr(pinfo->cinfo, COL_INFO, " Max Message Size: %.2f Mbytes", max_message_size);

            break;

        default:

            proto_tree_add_item(tree, hf_hislip_data, tvb, data->offset, -1, ENC_UTF_8 | ENC_NA);

        }
    }

    data->offset  += (uint32_t)data->payloadlength;
}



/*Search for Retransmission*/
static uint32_t
search_for_retransmission(wmem_tree_t *pdus, hislipinfo *data, uint32_t fnum )
{

    hislip_transaction_t *hislip_trans;

    hislip_trans = (hislip_transaction_t *)wmem_tree_lookup32_le(pdus, fnum-1);

    if (hislip_trans)
    {
        if (hislip_trans->messagetype == data->messagetype && hislip_trans->rep_frame == 0)
            return hislip_trans->req_frame;
    }

    return 0;
}


static uint8_t
is_connection_syn_or_asyn(uint8_t messagetype)
{
    if (messagetype >= HISLIP_ASYNCINTERRUPTED)
    {
        return HISLIP_ASYNCINITIALIZE;
    }
    else
    {
        switch (messagetype)
        {
        case HISLIP_ASYNCLOCK:
        case HISLIP_ASYNCLOCK_RESPONSE:
        case HISLIP_ASYNCREMOTELOCALCONTROL:
        case HISLIP_ASYNCREMOTELOCALRESPONSE:

            return HISLIP_ASYNCINITIALIZE;

        default:

            return HISLIP_INITIALIZE;
        }
    }
}


static int
dissect_hislip_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    conversation_t *conversation;
    hislip_conv_info_t *hislip_info;
    hislip_transaction_t *hislip_trans;
    proto_tree *hislip_tree;
    proto_item *it = NULL;
    hislipinfo hislip_data;
    uint8_t oldcontrolvalue = 0;
    uint32_t frame_number;

    hislip_tree  = NULL;
    conversation = NULL;
    hislip_info  = NULL;
    memset(&hislip_data, 0, sizeof(hislip_data));


    /*Write "HiSLIP" in the protocol column*/
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_HiSLIP);

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);


    /*Get Message Type*/
    hislip_data.messagetype = tvb_get_uint8(tvb, hislip_data.offset+2);
    /*Get Control Code*/
    hislip_data.controlcode = tvb_get_uint8(tvb, hislip_data.offset+3);
    /*Get Message Parameter*/
    hislip_data.messageparameter = tvb_get_ntohl(tvb, hislip_data.offset+4);
    /*Get Payload Length*/
    hislip_data.payloadlength = tvb_get_ntoh64(tvb, hislip_data.offset+8);


    /* Write Messagetype in the info column */
    col_add_str(pinfo->cinfo, COL_INFO, rval_to_str_const(hislip_data.messagetype, messagetypestring, "Unknown"));


    if (tree)
    {
        hislip_data.hislip_item = proto_tree_add_item(tree, proto_hislip, tvb, 0, -1, ENC_NA);
        hislip_tree = proto_item_add_subtree(hislip_data.hislip_item, ett_hislip);
    }

    if (tvb_get_ntohs(tvb, 0) != 0x4853)
    {
        expert_add_info(pinfo, hislip_data.hislip_item, &ei_wrong_prologue);
    }

    conversation = find_or_create_conversation(pinfo);

    /*Do we already have a state structure for this conv*/
    hislip_info = (hislip_conv_info_t *)conversation_get_proto_data(conversation, proto_hislip);
    if (!hislip_info)
    {
        hislip_info = (hislip_conv_info_t *)wmem_alloc(wmem_file_scope(), (sizeof(hislip_conv_info_t)));
        hislip_info->connectiontype = is_connection_syn_or_asyn(hislip_data.messagetype);
        hislip_info->pdus = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conversation, proto_hislip, (void *)hislip_info);
    }

    /*synchronous or asynchronous channel*/
    if(hislip_info->connectiontype == HISLIP_INITIALIZE)
    {
        proto_item_append_text(hislip_data.hislip_item, " (Synchron)");
        it = proto_tree_add_item(hislip_tree, hf_hislip_syn, tvb, 0, 0, ENC_NA);
    }
    else
    {
        proto_item_append_text(hislip_data.hislip_item," (Asynchron)");
        it = proto_tree_add_item(hislip_tree, hf_hislip_asyn, tvb, 0, 0, ENC_NA);
    }
    proto_item_set_generated(it);

    switch(hislip_data.messagetype)
    {
    case HISLIP_ASYNCLOCK:
    case HISLIP_ASYNCINITIALIZE:
    case HISLIP_ASYNCMAXIMUMMESSAGESIZE:
    case HISLIP_INITIALIZE:
    case HISLIP_ASYNCSTATUSQUERY:
    case HISLIP_ASYNCLOCKINFO:

        /*Request*/
        if(!PINFO_FD_VISITED(pinfo))
        {
            /* This is a new request */
            hislip_trans = wmem_new(wmem_file_scope(), hislip_transaction_t);
            hislip_trans->req_frame = pinfo->num;
            hislip_trans->rep_frame = 0;
            hislip_trans->messagetype = hislip_data.messagetype;
            hislip_trans->controlcode = hislip_data.controlcode;
            wmem_tree_insert32(hislip_info->pdus, pinfo->num , (void *)hislip_trans);
        }
        else
        {
            hislip_trans = (hislip_transaction_t *)wmem_tree_lookup32(hislip_info->pdus, pinfo->num);
        }
        if(hislip_trans && hislip_trans->rep_frame != 0)
        {
            it = proto_tree_add_uint(hislip_tree, hf_hislip_response, tvb, 0, 0, hislip_trans->rep_frame);
            proto_item_set_generated(it);
        }

        /*Retransmission*/
        if((frame_number = search_for_retransmission(hislip_info->pdus, &hislip_data , pinfo->num))!=0)
        {
            it = proto_tree_add_uint( hislip_tree, hf_hislip_retransmission, tvb, 0, 0, frame_number);
            proto_item_set_generated(it);
        }

        break;


    case HISLIP_ASYNCLOCK_RESPONSE:
    case HISLIP_ASYNCINITIALIZERESPONSE:
    case HISLIP_ASYNCMAXIMUMMESSAGESIZERESPONSE:
    case HISLIP_INITIALIZERESPONSE:
    case HISLIP_ASYNCSTATUSRESPONSE:
    case HISLIP_ASYNCLOCKINFORESPONSE:

        /*Response*/
        hislip_trans = (hislip_transaction_t *) wmem_tree_lookup32_le( hislip_info->pdus, pinfo->num);
        if (hislip_trans)
        {
            hislip_trans->rep_frame = pinfo->num;
            oldcontrolvalue = hislip_trans->controlcode;
            it = proto_tree_add_uint( hislip_tree, hf_hislip_request,tvb, 0, 0, hislip_trans->req_frame);
            proto_item_set_generated(it);
        }
        break;


    default:
        ;

    }


    /* Actually dissect fields */

    /* TODO: could control whether this is shown by preference? */
    proto_tree_add_item(hislip_tree, hf_hislip_prologue, tvb, hislip_data.offset, 2, ENC_ASCII);
    hislip_data.offset += 2;

    proto_tree_add_item(hislip_tree, hf_hislip_messagetype, tvb, hislip_data.offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(hislip_data.hislip_item, ", %s", rval_to_str_const(hislip_data.messagetype, messagetypestring, "Unknown"));
    hislip_data.offset += 1;

    decode_controlcode(tvb, pinfo, hislip_tree, &hislip_data, oldcontrolvalue );

    decode_messagepara(tvb, pinfo, hislip_tree, &hislip_data);

    proto_tree_add_item(hislip_tree, hf_hislip_payloadlength, tvb, hislip_data.offset, 8, ENC_BIG_ENDIAN);
    hislip_data.offset += 8;

    decode_data(tvb, pinfo, hislip_tree, &hislip_data );

    return tvb_captured_length(tvb);

}

static unsigned
get_hislip_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                       int offset, void *data _U_)
{
    /* Data length */
    uint64_t length = tvb_get_ntoh64(tvb, offset+8);
    /* Header length */
    length += FRAME_HEADER_LEN;

    return (uint32_t)length;
}

static int
dissect_hislip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /*Reassembling TCP fragments*/
    tcp_dissect_pdus(tvb, pinfo, tree, true, FRAME_HEADER_LEN,
                     get_hislip_message_len, dissect_hislip_message, data);

    return tvb_captured_length(tvb);
}

/*Heuristic*/
static bool
dissect_hislip_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /*  min. 16 bytes?*/
    if (tvb_captured_length(tvb) < FRAME_HEADER_LEN)
        return false;

    /*first two byte == "HS"*/
    if (tvb_get_ntohs(tvb, 0) != 0x4853)
        return false;

    /* XXX: Can it be assumed that all following packets for this connection will also be 'hislip' ?
     *      If so, conversation_set_dissector() should be called.
     */
    dissect_hislip(tvb, pinfo, tree, data);
    return true;

}


/*Register HiSLIP with Wireshark*/
void
proto_register_hislip(void)
{

    expert_module_t* expert_hislip;
    module_t * hislip_module;

    static hf_register_info hf[] = {
        { &hf_hislip_prologue,
        { "Prologue", "hislip.prologue", FT_STRING, BASE_NONE, NULL, 0x0,
        "HiSLIP Message Prologue (should be \"HS\")", HFILL }},
        { &hf_hislip_messagetype,
        { "Message Type", "hislip.messagetype", FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(messagetypestring), 0x0,
        "HiSLIP Message Type", HFILL }},
        { &hf_hislip_controlcode,
        { "Control Code", "hislip.controlcode", FT_UINT8, BASE_DEC, NULL, 0x0,
        "HiSLIP Control Code", HFILL }},
        { &hf_hislip_controlcode_rmt,
        { "Control Code", "hislip.controlcode.rmt", FT_UINT8, BASE_HEX, VALS(rmt), 0x0,
        "HiSLIP RMT", HFILL }},
        { &hf_hislip_controlcode_overlap,
        { "Control Code", "hislip.controlcode.overlap", FT_UINT8, BASE_HEX, VALS(overlap), 0x0,
        "HiSLIP overlap", HFILL }},
        { &hf_hislip_controlcode_asynclockinforesponse_code,
        { "Control Code", "hislip.controlcode.asynclockinforesponse", FT_UINT8, BASE_HEX, VALS(asynclockinforesponse_code), 0x0,
        "HiSLIP asynclockinforesponse", HFILL }},
        { &hf_hislip_controlcode_asynclockresponse_code_release,
        { "Control Code", "hislip.controlcode.asynclockresponse", FT_UINT8, BASE_HEX, VALS(asynclockresponse_code_release), 0x0,
        "HiSLIP asynclockresponse code", HFILL }},
        { &hf_hislip_controlcode_asynclockresponse_code_request,
        { "Control Code", "hislip.controlcode.asynclockresponse", FT_UINT8, BASE_HEX, VALS(asynclockresponse_code_request), 0x0,
        "HiSLIP asynclockresponse code", HFILL }},
        { &hf_hislip_controlcode_asyncremotelocalcontrol_code,
        { "Control Code", "hislip.controlcode.asyncremotelocalcontrol", FT_UINT8, BASE_HEX, VALS(asyncremotelocalcontrol_code), 0x0,
        "HiSLIP asyncremotelocalcontrol", HFILL }},
        { &hf_hislip_controlcode_feature_negotiation,
        { "Control Code", "hislip.controlcode.featurenegotiation", FT_UINT8, BASE_HEX, VALS(feature_negotiation), 0x0,
        "HiSLIP feature", HFILL }},
        { &hf_hislip_controlcode_asynclock_code,
        { "Control Code", "hislip.controlcode.asynclockcode", FT_UINT8, BASE_HEX, VALS(asynclock_code), 0x0,
        "HiSLIP asynclock code", HFILL }},
        { &hf_hislip_controlcode_stb,
        { "STB", "hislip.controlcode.stb", FT_UINT8, BASE_HEX, NULL, 0x0,
        "HiSLIP Status Byte", HFILL }},
        { &hf_hislip_payloadlength,
        { "Payload Length", "hislip.payloadlength", FT_UINT64, BASE_DEC, NULL, 0x0,
        "HiSLIP Payload Length", HFILL }},
        { &hf_hislip_messageparameter,
        { "Message Parameter", "hislip.msgpara", FT_NONE, BASE_NONE, NULL, 0x0,
        "HiSLIP Message Parameter", HFILL }},
        { &hf_hislip_msgpara_messageid,
        { "MessageID", "hislip.msgpara.messageid", FT_UINT32, BASE_HEX, NULL, 0x0,
        "HiSLIP MessageID", HFILL }},
        { &hf_hislip_msgpara_sessionid,
        { "SessionID", "hislip.msgpara.sessionid", FT_UINT16, BASE_HEX, NULL, 0x0,
        "HiSLIP SessionID", HFILL }},
        { &hf_hislip_msgpara_serverproto,
        { "Server version", "hislip.msgpara.servproto", FT_UINT16, BASE_HEX, NULL, 0x0,
        "HiSLIP Server Protocol version", HFILL }},
        { &hf_hislip_msgpara_vendorID,
        { "VendorID", "hislip.msgpara.vendorID", FT_UINT16, BASE_HEX|BASE_EXT_STRING, &vendorID_ext, 0x0,
        "HiSLIP VendorID", HFILL }},
        { &hf_hislip_msgpara_clientproto,
        { "Client version", "hislip.msgpara.clientproto", FT_UINT16, BASE_HEX, NULL, 0x0,
        "HiSLIP Client protocol version", HFILL }},
        { &hf_hislip_msgpara_clients,
        { "HiSLIP clients holding locks", "hislip.msgpara.clients", FT_UINT32, BASE_DEC, NULL, 0x0,
        "HiSLIP clients holding locks on the server", HFILL }},
        { &hf_hislip_msgpara_timeout,
        { "Timeout[ms]", "hislip.msgpara.timeout", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Time out from a AsyncLock message", HFILL }},
        { &hf_hislip_data,
        { "Data", "hislip.data", FT_STRING, BASE_NONE, NULL, 0x0,
        "HiSLIP Payload", HFILL }},
        { &hf_hislip_request,
        { "Request", "hislip.response", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "This is a response to the HiSLIP request in this frame", HFILL }},
        { &hf_hislip_response,
        { "Response", "hislip.request", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "A Request in this frame", HFILL }},
        { &hf_hislip_syn,
        { "Synchronous Channel", "hislip.syn", FT_NONE, BASE_NONE, NULL, 0x0,
        "This is the HiSLIP Synchronous Channel", HFILL }},
        { &hf_hislip_asyn,
        { "Asynchronous Channel", "hislip.asyn", FT_NONE, BASE_NONE, NULL, 0x0,
        "This is the HiSLIP Asynchronous Channel", HFILL }},
        { &hf_hislip_fatalerrcode,
        { "Fatalerror Code", "hislip.fatalerrcode", FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(fatalerrortype), 0x0,
        "HiSLIP Fatalerror Code", HFILL }},
        { &hf_hislip_retransmission,
        { "Retransmission from", "hislip.retrans", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "HiSLIP Retransmission", HFILL }},
        { &hf_hislip_nonfatalerrorcode,
        { "Nonfatalerror Code", "hislip.nonfatalerrorcode", FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(nonfatalerrortype), 0x0,
        "HiSLIP Nonfatalerror Code", HFILL }},
        { &hf_hislip_maxmessagesize,
        { "Max Message Size", "hislip.maxmsgsize", FT_UINT64, BASE_DEC, NULL, 0x0,
        "HiSLIP Maximum Message Size", HFILL }}
    };


    static int *ett[] = {
        &ett_hislip,
        &ett_hislip_msgpara
    };


    static ei_register_info ei[] = {
        { &ei_wrong_prologue, { "hislip.wrongprologue", PI_UNDECODED, PI_WARN, "Frame hasn't 'HS' as Prologue", EXPFILL }},
        { &ei_msg_not_null, { "hislip.msgnotnull", PI_PROTOCOL, PI_WARN, "Message Parameter isn't 0", EXPFILL }}
    };

    proto_hislip = proto_register_protocol("High-Speed LAN Instrument Protocol", "HiSLIP", "hislip");

    expert_hislip = expert_register_protocol(proto_hislip);
    expert_register_field_array(expert_hislip, ei, array_length(ei));

    proto_register_field_array(proto_hislip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    hislip_module = prefs_register_protocol(proto_hislip, NULL);
    prefs_register_obsolete_preference(hislip_module, "enable_heuristic");

    hislip_handle = register_dissector("hislip", dissect_hislip, proto_hislip);
}

void
proto_reg_handoff_hislip(void)
{
    /* disabled by default since heuristic is weak */
    heur_dissector_add("tcp", dissect_hislip_heur, "HiSLIP over TCP", "hislip_tcp", proto_hislip, HEURISTIC_DISABLE);

    dissector_add_uint_with_preference("tcp.port", HISLIP_PORT, hislip_handle);
}

/*
 * Editor modelines - https://www.wireshark.org/tools/modelines.html
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

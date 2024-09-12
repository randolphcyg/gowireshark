/* packet-rtcp.c
 *
 * Routines for RTCP dissection
 * RTCP = Real-time Transport Control Protocol
 *
 * Copyright 2000, Philips Electronics N.V.
 * Written by Andreas Sikkema <h323@ramdyne.nl>
 *
 * Copyright 2004, Anders Broman <anders.broman@ericsson.com>
 *
 * Copyright 2005, Nagarjuna Venna <nvenna@brixnet.com>
 *
 * Copyright 2010, Matteo Valdina <zanfire@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This dissector tries to dissect the RTCP protocol according to Annex A
 * of ITU-T Recommendation H.225.0 (02/98) and RFC 3550 (obsoleting 1889).
 * H.225.0 literally copies RFC 1889, but omitting a few sections.
 *
 * RTCP traffic is traditionally handled by an uneven UDP portnumber. This
 * can be any port number, but there is a registered port available, port 5005
 * See Annex B of ITU-T Recommendation H.225.0, section B.7
 *
 * Note that nowadays RTP and RTCP are often multiplexed onto a single port,
 * per RFC 5671.
 *
 * Information on PoC can be found from
 *    https://www.omaspecworks.org (OMA SpecWorks, formerly the Open
 *    Mobile Alliance - http://www.openmobilealliance.org/)
 *
 * RTCP XR is specified in RFC 3611.
 *
 * See also https://www.iana.org/assignments/rtp-parameters
 *
 * RTCP FB is specified in RFC 4585 and extended by RFC 5104
 *
 * MS-RTP: Real-time Transport Protocol (RTP) Extensions
 *    https://docs.microsoft.com/en-us/openspecs/office_protocols/ms-rtp
 */

/*
 * The part of this dissector for IDMS XR blocks was written by
 * Torsten Loebner (loebnert@googlemail.com) in the context of a graduation
 * project with the research organization TNO in Delft, Netherland.
 * The extension is based on the RTCP XR block specified in
 * ETSI TS 182 063 v3.5.2 Annex W (https://www.etsi.org/deliver/etsi_ts/183000_183099/183063/),
 * which was registered by IANA as RTCP XR Block Type 12
 * (https://www.iana.org/assignments/rtcp-xr-block-types/rtcp-xr-block-types.xml).
 */

#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/unit_strings.h>

#include <wsutil/array.h>
#include "packet-rtcp.h"
#include "packet-rtp.h"
#include "packet-gsm_a_common.h"

#include <epan/conversation.h>

#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/proto_data.h>

void proto_register_rtcp(void);
void proto_reg_handoff_rtcp(void);

/* Version is the first 2 bits of the first octet*/
#define RTCP_VERSION(octet) ((octet) >> 6)

/* Padding is the third bit; no need to shift, because true is any value
   other than 0! */
#define RTCP_PADDING(octet) ((octet) & 0x20)

/* Receiver/ Sender count is the 5 last bits  */
#define RTCP_COUNT(octet)   ((octet) & 0x1F)

/* Metric block for RTCP Congestion Control Feedback [RFC8888]
    0 1 2 3 4 5 6 7 8 0 1 2 3 4 5 6 7 8
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |R|ECN|            ATO              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   */
#define RTCP_CCFB_RECEIVED(metric_block) (((metric_block) & 0x8000) >> 15)
#define RTCP_CCFB_ECN(metric_block) (((metric_block) & 0x6000) >> 13)
#define RTCP_CCFB_ATO(metric_block) ((metric_block) & 0x1FFF)

#define RTCP_TRANSPORT_CC_HEADER_LENGTH   12
static int rtcp_padding_set = 0;

static dissector_handle_t rtcp_handle;
static dissector_handle_t srtcp_handle;
static dissector_handle_t ms_pse_handle;
static dissector_handle_t rtcp_rtpfb_nack_handle;
static dissector_handle_t rtcp_rtpfb_tmmbr_handle;
static dissector_handle_t rtcp_rtpfb_tmmbn_handle;
static dissector_handle_t rtcp_rtpfb_ccfb_handle;
static dissector_handle_t rtcp_rtpfb_transport_cc_handle;
static dissector_handle_t rtcp_rtpfb_undecoded_fci_handle;


/* add dissector table to permit sub-protocol registration */
static dissector_table_t rtcp_dissector_table;
static dissector_table_t rtcp_psfb_dissector_table;
static dissector_table_t rtcp_rtpfb_dissector_table;
static dissector_table_t rtcp_pse_dissector_table;

static const value_string rtcp_version_vals[] =
{
    { 2, "RFC 1889 Version" },
    { 0, "Old VAT Version" },
    { 1, "First Draft Version" },
    { 0, NULL },
};

#define RTCP_PT_MIN  192
/* Supplemental H.261 specific RTCP packet types according to Section C.3.5 */
#define RTCP_FIR     192
#define RTCP_NACK    193
#define RTCP_SMPTETC 194
#define RTCP_IJ      195
/* RTCP packet types according to Section A.11.1 */
/* And https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml */
#define RTCP_SR      200
#define RTCP_RR      201
#define RTCP_SDES    202
#define RTCP_BYE     203
#define RTCP_APP     204
#define RTCP_RTPFB   205
#define RTCP_PSFB    206
#define RTCP_XR      207
#define RTCP_AVB     208
#define RTCP_RSI     209
#define RTCP_TOKEN   210

#define RTCP_PT_MAX  210

static const value_string rtcp_packet_type_vals[] =
{
    { RTCP_SR,      "Sender Report" },
    { RTCP_RR,      "Receiver Report" },
    { RTCP_SDES,    "Source description" },
    { RTCP_BYE,     "Goodbye" },
    { RTCP_APP,     "Application specific" },
    { RTCP_RTPFB,   "Generic RTP Feedback" },
    { RTCP_PSFB,    "Payload-specific Feedback" },
    { RTCP_XR,      "Extended report (RFC 3611)"},
    { RTCP_AVB,     "AVB RTCP packet (IEEE1733)" },
    { RTCP_RSI,     "Receiver Summary Information" },
    { RTCP_TOKEN,   "Port Mapping" },
    { RTCP_FIR,     "Full Intra-frame Request (H.261)" },
    { RTCP_NACK,    "Negative Acknowledgement (H.261)" },
    { RTCP_SMPTETC, "SMPTE time-code mapping" },
    { RTCP_IJ,      "Extended inter-arrival jitter report" },
    { 0,         NULL }
};

/* RTCP SDES types (Section A.11.2) */
#define RTCP_SDES_END         0
#define RTCP_SDES_CNAME       1
#define RTCP_SDES_NAME        2
#define RTCP_SDES_EMAIL       3
#define RTCP_SDES_PHONE       4
#define RTCP_SDES_LOC         5
#define RTCP_SDES_TOOL        6
#define RTCP_SDES_NOTE        7
#define RTCP_SDES_PRIV        8
#define RTCP_SDES_H323_CADDR  9
#define RTCP_SDES_APSI       10

static const value_string rtcp_sdes_type_vals[] =
{
    { RTCP_SDES_END,        "END" },
    { RTCP_SDES_CNAME,      "CNAME (user and domain)" },
    { RTCP_SDES_NAME,       "NAME (common name)" },
    { RTCP_SDES_EMAIL,      "EMAIL (e-mail address)" },
    { RTCP_SDES_PHONE,      "PHONE (phone number)" },
    { RTCP_SDES_LOC,        "LOC (geographic location)" },
    { RTCP_SDES_TOOL,       "TOOL (name/version of source app)" },
    { RTCP_SDES_NOTE,       "NOTE (note about source)" },
    { RTCP_SDES_PRIV,       "PRIV (private extensions)" },
    { RTCP_SDES_H323_CADDR, "H323-CADDR (H.323 callable address)" },
    { RTCP_SDES_APSI,       "Application Specific Identifier" },
    { 0,               NULL }
};

/* RTCP XR Blocks (Section 4, RTC 3611)
 * or https://www.iana.org/assignments/rtcp-xr-block-types */
#define RTCP_XR_LOSS_RLE     1
#define RTCP_XR_DUP_RLE      2
#define RTCP_XR_PKT_RXTIMES  3
#define RTCP_XR_REF_TIME     4
#define RTCP_XR_DLRR         5
#define RTCP_XR_STATS_SUMRY  6
#define RTCP_XR_VOIP_METRCS  7
#define RTCP_XR_BT_XNQ       8
#define RTCP_XR_TI_VOIP      9
#define RTCP_XR_PR_LOSS_RLE 10
#define RTCP_XR_MC_ACQ      11
#define RTCP_XR_IDMS        12

static const value_string rtcp_xr_type_vals[] =
{
    { RTCP_XR_LOSS_RLE,     "Loss Run Length Encoding Report Block" },
    { RTCP_XR_DUP_RLE,      "Duplicate Run Length Encoding Report Block" },
    { RTCP_XR_PKT_RXTIMES,  "Packet Receipt Times Report Block" },
    { RTCP_XR_REF_TIME,     "Receiver Reference Time Report Block" },
    { RTCP_XR_DLRR,         "DLRR Report Block" },
    { RTCP_XR_STATS_SUMRY,  "Statistics Summary Report Block" },
    { RTCP_XR_VOIP_METRCS,  "VoIP Metrics Report Block" },
    { RTCP_XR_BT_XNQ,       "BT XNQ RTCP XR (RFC5093) Report Block" },
    { RTCP_XR_TI_VOIP,      "Texas Instruments Extended VoIP Quality Block" },
    { RTCP_XR_PR_LOSS_RLE,  "Post-repair Loss RLE Report Block" },
    { RTCP_XR_MC_ACQ,       "Multicast Acquisition Report Block" },
    { RTCP_XR_IDMS,         "Inter-destination Media Synchronization Block" }, /* [https://www.etsi.org/deliver/etsi_ts/183000_183099/183063/][ETSI 183 063][Miguel_Angel_Reina_Ortega] */
    { 0, NULL}
};

/* XR VoIP Metrics Block - PLC Algorithms */
static const value_string rtcp_xr_plc_algo_vals[] =
{
    { 0, "Unspecified" },
    { 1, "Disabled" },
    { 2, "Enhanced" },
    { 3, "Standard" },
    { 0, NULL }
};

/* XR VoIP Metrics Block - JB Adaptive */
static const value_string rtcp_xr_jb_adaptive_vals[] =
{
    { 0, "Unknown" },
    { 1, "Reserved" },
    { 2, "Non-Adaptive" },
    { 3, "Adaptive" },
    { 0, NULL }
};

/* XR Stats Summary Block - IP TTL or Hop Limit */
static const value_string rtcp_xr_ip_ttl_vals[] =
{
    { 0, "No TTL Values" },
    { 1, "IPv4" },
    { 2, "IPv6" },
    { 3, "Undefined" },
    { 0, NULL }
};

/* XR IDMS synchronization packet sender type */
static const value_string rtcp_xr_idms_spst[] =
{
    {  0, "Reserved" },
    {  1, "SC" },
    {  2, "MSAS" },
    {  3, "SC' INPUT" },
    {  4, "SC' OUTPUT" },
    {  5, "Reserved" },
    {  6, "Reserved" },
    {  7, "Reserved" },
    {  8, "Reserved" },
    {  9, "Reserved" },
    { 10, "Reserved" },
    { 11, "Reserved" },
    { 12, "Reserved" },
    { 13, "Reserved" },
    { 14, "Reserved" },
    { 15, "Reserved" },
    { 0, NULL }
};

/* RTCP Application PoC1 Value strings
 * OMA-TS-PoC-UserPlane-V1_0-20060609-A
 */

#define TBCP_BURST_REQUEST                  0
#define TBCP_BURST_GRANTED                  1
#define TBCP_BURST_TAKEN_EXPECT_NO_REPLY    2
#define TBCP_BURST_DENY                     3
#define TBCP_BURST_RELEASE                  4
#define TBCP_BURST_IDLE                     5
#define TBCP_BURST_REVOKE                   6
#define TBCP_BURST_ACKNOWLEDGMENT           7
#define TBCP_QUEUE_STATUS_REQUEST           8
#define TBCP_QUEUE_STATUS_RESPONSE          9
#define TBCP_DISCONNECT                    11
#define TBCP_CONNECT                       15
#define TBCP_BURST_TAKEN_EXPECT_REPLY      18


static const value_string rtcp_app_poc1_floor_cnt_type_vals[] =
{
    {  TBCP_BURST_REQUEST,                 "TBCP Talk Burst Request"},
    {  TBCP_BURST_GRANTED,                 "TBCP Talk Burst Granted"},
    {  TBCP_BURST_TAKEN_EXPECT_NO_REPLY,   "TBCP Talk Burst Taken (no ack expected)"},
    {  TBCP_BURST_DENY,                    "TBCP Talk Burst Deny"},
    {  TBCP_BURST_RELEASE,                 "TBCP Talk Burst Release"},
    {  TBCP_BURST_IDLE,                    "TBCP Talk Burst Idle"},
    {  TBCP_BURST_REVOKE,                  "TBCP Talk Burst Revoke"},
    {  TBCP_BURST_ACKNOWLEDGMENT,          "TBCP Talk Burst Acknowledgement"},
    {  TBCP_QUEUE_STATUS_REQUEST,          "TBCP Queue Status Request"},
    {  TBCP_QUEUE_STATUS_RESPONSE,         "TBCP Queue Status Response"},
    {  TBCP_DISCONNECT,                    "TBCP Disconnect"},
    {  TBCP_CONNECT,                       "TBCP Connect"},
    {  TBCP_BURST_TAKEN_EXPECT_REPLY,      "TBCP Talk Burst Taken (ack expected)"},
    {  0,   NULL }
};

static const value_string rtcp_app_poc1_reason_code1_vals[] =
{
    {  1,   "Another PoC User has permission"},
    {  2,   "Internal PoC server error"},
    {  3,   "Only one participant in the group"},
    {  4,   "Retry-after timer has not expired"},
    {  5,   "Listen only"},
    {  0,   NULL }
};

static const value_string rtcp_app_poc1_reason_code2_vals[] =
{
    {  1,   "Only one user"},
    {  2,   "Talk burst too long"},
    {  3,   "No permission to send a Talk Burst"},
    {  4,   "Talk burst pre-empted"},
    {  0,   NULL }
};

static const value_string rtcp_app_poc1_reason_code_ack_vals[] =
{
    {  0,   "Accepted"},
    {  1,   "Busy"},
    {  2,   "Not accepted"},
    {  0,   NULL }
};
static const value_string rtcp_app_poc1_conn_sess_type_vals[] =
{
    {  0,   "None"},
    {  1,   "1-to-1"},
    {  2,   "Ad-hoc"},
    {  3,   "Pre-arranged"},
    {  4,   "Chat"},
    {  0,   NULL }
};

static const value_string rtcp_app_poc1_qsresp_priority_vals[] =
{
    {  0,   "No priority (un-queued)"},
    {  1,   "Normal priority"},
    {  2,   "High priority"},
    {  3,   "Pre-emptive priority"},
    {  0,   NULL }
};

/* 3GPP 29.414 RTP Multiplexing */
static const value_string rtcp_app_mux_selection_vals[] =
{
    {  0,   "No multiplexing applied"},
    {  1,   "Multiplexing without RTP header compression applied"},
    {  2,   "Multiplexing with RTP header compression applied"},
    {  3,   "Reserved"},
    {  0,   NULL}
};

/* RFC 4585, RFC 5104, RFC 6051, RFC 6285, RFC 6642, RFC 6679, RFC 7728,
 * 3GPP TS 26.114 v16.3.0, RFC 8888 and
 * draft-holmer-rmcat-transport-wide-cc-extensions-01
 */
static const value_string rtcp_rtpfb_fmt_vals[] =
{
    {   1,  "Generic negative acknowledgement (NACK)"},
    {   3,  "Temporary Maximum Media Stream Bit Rate Request (TMMBR)"},
    {   4,  "Temporary Maximum Media Stream Bit Rate Notification (TMMBN)"},
    {   5,  "RTCP Rapid Resynchronisation Request (RTCP-SR-REQ)"},
    {   6,  "Rapid Acquisition of Multicast Sessions (RAMS)"},
    {   7,  "Transport-Layer Third-Party Loss Early Indication (TLLEI)"},
    {   8,  "RTCP ECN Feedback (RTCP-ECN-FB)"},
    {   9,  "Media Pause/Resume (PAUSE-RESUME)"},
    {  10,  "Delay Budget Information (DBI)"},
    {  11,  "RTP Congestion Control Feedback (CCFB)"},
    {  15,  "Transport-wide Congestion Control (Transport-cc)"},
    {  31,  "Reserved for future extensions"},
    {   0,  NULL }
};

static const value_string rtcp_psfb_fmt_vals[] =
{
    {   1,  "Picture Loss Indication"},
    {   2,  "Slice Loss Indication"},
    {   3,  "Reference Picture Selection Indication"},
    {   4,  "Full Intra Request (FIR) Command"},
    {   5,  "Temporal-Spatial Trade-off Request (TSTR)"},
    {   6,  "Temporal-Spatial Trade-off Notification (TSTN)"},
    {   7,  "Video Back Channel Message (VBCM)"},
    {  15,  "Application Layer Feedback"},
    {  31,  "Reserved for future extensions"},
    {   0,  NULL }
};

static const value_string rtcp_psfb_fmt_summary_vals[] =
{
    {   1,  "PLI"},
    {   2,  "SLI"},
    {   3,  "RPSI"},
    {   4,  "FIR"},
    {   5,  "TSTR"},
    {   6,  "TSTN"},
    {   7,  "VBCM"},
    {  15,  "ALFB"},
    {  31,  "Reserved"},
    {   0,  NULL }
};

/* Microsoft Profile Specific Extension Types */
static const value_string rtcp_ms_profile_extension_vals[] =
{
    {   1,  "MS - Estimated Bandwidth"},
    {   4,  "MS - Packet Loss Notification"},
    {   5,  "MS - Video Preference"},
    {   6,  "MS - Padding"},
    {   7,  "MS - Policy Server Bandwidth"},
    {   8,  "MS - TURN Server Bandwidth"},
    {   9,  "MS - Audio Healer Metrics"},
    {   10,  "MS - Receiver-side Bandwidth Limit"},
    {   11,  "MS - Packet Train Packet"},
    {   12,  "MS - Peer Info Exchange"},
    {   13,  "MS - Network Congestion Notification"},
    {   14,  "MS - Modality Send Bandwidth Limit"},
    {   0,  NULL }
};

static const value_string rtcp_ssrc_values[] = {
    {  0xFFFFFFFF,   "SOURCE_NONE" },
    {  0xFFFFFFFE,   "SOURCE_ANY" },
    {   0,  NULL }
};

/* TS 24.380 V17.7.0 */
static const value_string rtcp_mcpt_subtype_vals[] = {
    { 0x00,  "Floor Request" },
    { 0x01,  "Floor Granted" },
    { 0x02,  "Floor Taken" },
    { 0x03,  "Floor Deny" },
    { 0x04,  "Floor Release" },
    { 0x05,  "Floor Idle" },
    { 0x06,  "Floor Revoke" },
    { 0x08,  "Floor Queue Position Request" },
    { 0x09,  "Floor Queue Position Info" },
    { 0x0a,  "Floor Ack" },
    { 0x0b,  "Unicast Media Flow Control" },
    { 0x0e,  "Floor Queued Cancel" },
    { 0x0f,  "Floor Release Multi Talker" },

    { 0x11,  "Floor Granted(ack req)" },
    { 0x12,  "Floor Taken(ack req)" },
    { 0x13,  "Floor Deny(ack req)" },
    { 0x14,  "Floor Release(ack req)" },
    { 0x15,  "Floor Idle(ack req)" },
    { 0x19,  "Floor Queue Position Info(ack req)" },
    { 0x1b,  "Unicast Media Flow Control(ack req)" },
    { 0x1e,  "Floor Queued Cancel(ack req)" },

    { 0,  NULL }
};

/* TS 24.380 V17.7.0 */
static const value_string rtcp_mccp_subtype_vals[] = {
    { 0x00,  "Map Group To Bearer" },
    { 0x01,  "Unmap Group To Bearer" },
    { 0x02,  "Application Paging" },
    { 0x03,  "Bearer Announcement" },
    { 0,  NULL }
};


/* TS 24.380 V17.7.0 */
static const value_string rtcp_mcpt_field_id_vals[] = {
    { 0,  "Floor Priority" },
    { 1,  "Duration" },
    { 2,  "Reject Cause" },
    { 3,  "Queue Info" },
    { 4,  "Granted Party's Identity" },
    { 5,  "Permission to Request the Floor" },
    { 6,  "User ID" },
    { 7,  "Queue Size" },
    { 8,  "Message Sequence-Number" },
    { 9,  "Queued User ID" },
    { 10,  "Source" },
    { 11,  "Track Info" },
    { 12,  "Message Type" },
    { 13,  "Floor Indicator" },
    { 14,  "SSRC" },
    { 15,  "List of Granted Users" },
    { 16,  "List of SSRCs" },
    { 17,  "Functional Alias" },
    { 18,  "List of Functional Aliases" },
    { 19,  "Location" },
    { 20,  "List of Locations" },
    { 21,  "Queued Floor Requests Purpose" },
    { 22,  "List of Queued Users" },
    { 23,  "Response State" },
    { 24,  "Media Flow Control Indicator" },

    { 102,  "Floor Priority" },
    { 103,  "Duration" },
    { 104,  "Reject Cause" },
    { 105,  "Queue Info" },
    { 106,  "Granted Party's Identity" },
    { 108,  "Permission to Request the Floor" },
    { 109,  "User ID" },
    { 110,  "Queue Size" },
    { 111,  "Message SequenceNumber" },
    { 112,  "Queued User ID" },
    { 113,  "Source" },
    { 114,  "Track Info" },
    { 115,  "Message Type" },
    { 116,  "Floor Indicator" },

    { 0,  NULL }
};

/* TS 24.380 V17.7.0 */
static const value_string rtcp_mccp_field_id_vals[] = {
    { 0,  "Subchannel" },
    { 1,  "TMGI" },
    { 2,  "MCPTT Group ID" },
    { 3,  "Monitoring State" },
    { 0,  NULL }
};


/* RTCP header fields                   */
static int proto_rtcp;
static int proto_srtcp;
static int proto_rtcp_ms_pse;
static int proto_rtcp_rtpfb_nack;
static int proto_rtcp_rtpfb_tmmbr;
static int proto_rtcp_rtpfb_tmmbn;
static int proto_rtcp_rtpfb_ccfb;
static int proto_rtcp_rtpfb_transport_cc;
static int proto_rtcp_rtpfb_undecoded_fci;
static int hf_rtcp_version;
static int hf_rtcp_padding;
static int hf_rtcp_rc;
static int hf_rtcp_sc;
static int hf_rtcp_pt;
static int hf_rtcp_length;
static int hf_rtcp_ssrc_sender;
static int hf_rtcp_ssrc_media_source;
static int hf_rtcp_ntp;
static int hf_rtcp_ntp_msw;
static int hf_rtcp_ntp_lsw;
static int hf_rtcp_timebase_indicator;
static int hf_rtcp_identity;
static int hf_rtcp_stream_id;
static int hf_rtcp_as_timestamp;
static int hf_rtcp_rtp_timestamp;
static int hf_rtcp_sender_pkt_cnt;
static int hf_rtcp_sender_oct_cnt;
static int hf_rtcp_ssrc_source;
static int hf_rtcp_ssrc_fraction;
static int hf_rtcp_ssrc_cum_nr;
static int hf_rtcp_ssrc_discarded;
/* First the 32 bit number, then the split
 * up 16 bit values */
/* These two are added to a subtree */
static int hf_rtcp_ssrc_ext_high_seq;
static int hf_rtcp_ssrc_high_seq;
static int hf_rtcp_ssrc_high_cycles;
static int hf_rtcp_ssrc_jitter;
static int hf_rtcp_ssrc_lsr;
static int hf_rtcp_ssrc_dlsr;
/* static int hf_rtcp_ssrc_csrc; */
static int hf_rtcp_sdes_type;
static int hf_rtcp_sdes_length;
static int hf_rtcp_sdes_text;
static int hf_rtcp_sdes_prefix_len;
static int hf_rtcp_sdes_prefix_string;
static int hf_rtcp_subtype;
static int hf_rtcp_name_ascii;
static int hf_rtcp_app_data;
static int hf_rtcp_app_data_str;
static int hf_rtcp_fsn;
static int hf_rtcp_blp;
static int hf_rtcp_padding_count;
static int hf_rtcp_padding_data;
static int hf_rtcp_profile_specific_extension_type;
static int hf_rtcp_profile_specific_extension_length;
static int hf_rtcp_profile_specific_extension;
static int hf_rtcp_app_poc1;
static int hf_rtcp_app_poc1_sip_uri;
static int hf_rtcp_app_poc1_disp_name;
static int hf_rtcp_app_poc1_priority;
static int hf_rtcp_app_poc1_request_ts;
static int hf_rtcp_app_poc1_stt;
static int hf_rtcp_app_poc1_partic;
static int hf_rtcp_app_poc1_ssrc_granted;
static int hf_rtcp_app_poc1_last_pkt_seq_no;
static int hf_rtcp_app_poc1_ignore_seq_no;
static int hf_rtcp_app_poc1_reason_code1;
static int hf_rtcp_app_poc1_reason1_phrase;
static int hf_rtcp_app_poc1_reason_code2;
static int hf_rtcp_app_poc1_new_time_request;
static int hf_rtcp_app_poc1_ack_subtype;
static int hf_rtcp_app_poc1_ack_reason_code;
static int hf_rtcp_app_poc1_qsresp_priority;
static int hf_rtcp_app_poc1_qsresp_position;
static int hf_rtcp_app_poc1_conn_content[5];
static int hf_rtcp_app_poc1_conn_session_type;
static int hf_rtcp_app_poc1_conn_add_ind_mao;
static int hf_rtcp_app_poc1_conn_sdes_items[5];
static int hf_rtcp_app_mux;
static int hf_rtcp_app_mux_mux;
static int hf_rtcp_app_mux_cp;
static int hf_rtcp_app_mux_selection;
static int hf_rtcp_app_mux_localmuxport;
static int hf_rtcp_xr_block_type;
static int hf_rtcp_xr_block_specific;
static int hf_rtcp_xr_block_length;
static int hf_rtcp_xr_thinning;
static int hf_rtcp_xr_voip_metrics_burst_density;
static int hf_rtcp_xr_voip_metrics_gap_density;
static int hf_rtcp_xr_voip_metrics_burst_duration;
static int hf_rtcp_xr_voip_metrics_gap_duration;
static int hf_rtcp_xr_voip_metrics_rtdelay;
static int hf_rtcp_xr_voip_metrics_esdelay;
static int hf_rtcp_xr_voip_metrics_siglevel;
static int hf_rtcp_xr_voip_metrics_noiselevel;
static int hf_rtcp_xr_voip_metrics_rerl;
static int hf_rtcp_xr_voip_metrics_gmin;
static int hf_rtcp_xr_voip_metrics_rfactor;
static int hf_rtcp_xr_voip_metrics_extrfactor;
static int hf_rtcp_xr_voip_metrics_moslq;
static int hf_rtcp_xr_voip_metrics_moscq;
static int hf_rtcp_xr_voip_metrics_plc;
static int hf_rtcp_xr_voip_metrics_jbadaptive;
static int hf_rtcp_xr_voip_metrics_jbrate;
static int hf_rtcp_xr_voip_metrics_jbnominal;
static int hf_rtcp_xr_voip_metrics_jbmax;
static int hf_rtcp_xr_voip_metrics_jbabsmax;
static int hf_rtcp_xr_stats_loss_flag;
static int hf_rtcp_xr_stats_dup_flag;
static int hf_rtcp_xr_stats_jitter_flag;
static int hf_rtcp_xr_stats_ttl;
static int hf_rtcp_xr_beginseq;
static int hf_rtcp_xr_endseq;
static int hf_rtcp_xr_chunk_null_terminator;
static int hf_rtcp_xr_chunk_length;
static int hf_rtcp_xr_chunk_bit_vector;
static int hf_rtcp_xr_receipt_time_seq;
static int hf_rtcp_xr_stats_lost;
static int hf_rtcp_xr_stats_dups;
static int hf_rtcp_xr_stats_minjitter;
static int hf_rtcp_xr_stats_maxjitter;
static int hf_rtcp_xr_stats_meanjitter;
static int hf_rtcp_xr_stats_devjitter;
static int hf_rtcp_xr_stats_minttl;
static int hf_rtcp_xr_stats_maxttl;
static int hf_rtcp_xr_stats_meanttl;
static int hf_rtcp_xr_stats_devttl;
static int hf_rtcp_xr_timestamp;
static int hf_rtcp_xr_lrr;
static int hf_rtcp_xr_dlrr;
static int hf_rtcp_xr_idms_spst;
static int hf_rtcp_xr_idms_pt;
static int hf_rtcp_xr_idms_msci;
static int hf_rtcp_xr_idms_source_ssrc;
static int hf_rtcp_xr_idms_ntp_rcv_ts;
static int hf_rtcp_xr_idms_rtp_ts;
static int hf_rtcp_xr_idms_ntp_pres_ts;
static int hf_rtcp_length_check;
static int hf_rtcp_rtpfb_ccfb_beginseq;
static int hf_rtcp_rtpfb_ccfb_numreports;
static int hf_rtcp_rtpfb_ccfb_received;
static int hf_rtcp_rtpfb_ccfb_ecn;
static int hf_rtcp_rtpfb_ccfb_ato;
static int hf_rtcp_rtpfb_ccfb_padding;
static int hf_rtcp_rtpfb_ccfb_timestamp;
static int hf_rtcp_rtpfb_fmt;
static int hf_rtcp_rtpfb_nack_pid;
static int hf_rtcp_rtpfb_nack_blp;
static int hf_rtcp_rtpfb_transport_cc_fci_base_seq;
static int hf_rtcp_rtpfb_transport_cc_fci_pkt_stats_cnt;
static int hf_rtcp_rtpfb_transport_cc_fci_ref_time;
static int hf_rtcp_rtpfb_transport_cc_fci_fb_pkt_cnt;
static int hf_rtcp_rtpfb_transport_cc_fci_pkt_chunk;
static int hf_rtcp_rtpfb_transport_cc_fci_recv_delta_1_byte;
static int hf_rtcp_rtpfb_transport_cc_fci_recv_delta_2_bytes;
static int hf_rtcp_rtpfb_transport_cc_fci_recv_delta_padding;
static int hf_rtcp_psfb_fmt;
static int hf_rtcp_fci;
static int hf_rtcp_psfb_fir_fci_ssrc;
static int hf_rtcp_psfb_fir_fci_csn;
static int hf_rtcp_psfb_fir_fci_reserved;
static int hf_rtcp_psfb_sli_first;
static int hf_rtcp_psfb_sli_number;
static int hf_rtcp_psfb_sli_picture_id;
static int hf_rtcp_psfb_remb_fci_identifier;
static int hf_rtcp_psfb_remb_fci_number_ssrcs;
static int hf_rtcp_psfb_remb_fci_ssrc;
static int hf_rtcp_psfb_remb_fci_exp;
static int hf_rtcp_psfb_remb_fci_mantissa;
static int hf_rtcp_psfb_remb_fci_bitrate;
static int hf_rtcp_rtpfb_tmbbr_fci_ssrc;
static int hf_rtcp_rtpfb_tmbbr_fci_exp;
static int hf_rtcp_rtpfb_tmbbr_fci_mantissa;
static int hf_rtcp_rtpfb_tmbbr_fci_bitrate;
static int hf_rtcp_rtpfb_tmbbr_fci_measuredoverhead;
static int hf_srtcp_e;
static int hf_srtcp_index;
static int hf_srtcp_mki;
static int hf_srtcp_auth_tag;
static int hf_rtcp_xr_btxnq_begseq;               /* added for BT XNQ block (RFC5093) */
static int hf_rtcp_xr_btxnq_endseq;
static int hf_rtcp_xr_btxnq_vmaxdiff;
static int hf_rtcp_xr_btxnq_vrange;
static int hf_rtcp_xr_btxnq_vsum;
static int hf_rtcp_xr_btxnq_cycles;
static int hf_rtcp_xr_btxnq_jbevents;
static int hf_rtcp_xr_btxnq_tdegnet;
static int hf_rtcp_xr_btxnq_tdegjit;
static int hf_rtcp_xr_btxnq_es;
static int hf_rtcp_xr_btxnq_ses;
static int hf_rtcp_xr_btxnq_spare;

/* RTCP setup fields */
static int hf_rtcp_setup;
static int hf_rtcp_setup_frame;
static int hf_rtcp_setup_method;

/* RTCP roundtrip delay fields */
static int hf_rtcp_last_sr_timestamp_frame;
static int hf_rtcp_time_since_last_sr;
static int hf_rtcp_roundtrip_delay;

/* MS Profile Specific Extension Fields */
static int hf_rtcp_pse_ms_bandwidth;
static int hf_rtcp_pse_ms_confidence_level;
static int hf_rtcp_pse_ms_seq_num;
static int hf_rtcp_pse_ms_frame_resolution_width;
static int hf_rtcp_pse_ms_frame_resolution_height;
static int hf_rtcp_pse_ms_bitrate;
static int hf_rtcp_pse_ms_frame_rate;
static int hf_rtcp_pse_ms_concealed_frames;
static int hf_rtcp_pse_ms_stretched_frames;
static int hf_rtcp_pse_ms_compressed_frames;
static int hf_rtcp_pse_ms_total_frames;
static int hf_rtcp_pse_ms_receive_quality_state;
static int hf_rtcp_pse_ms_fec_distance_request;
static int hf_rtcp_pse_ms_last_packet_train;
static int hf_rtcp_pse_ms_packet_idx;
static int hf_rtcp_pse_ms_packet_cnt;
static int hf_rtcp_pse_ms_packet_train_byte_cnt;
static int hf_rtcp_pse_ms_inbound_bandwidth;
static int hf_rtcp_pse_ms_outbound_bandwidth;
static int hf_rtcp_pse_ms_no_cache;
static int hf_rtcp_pse_ms_congestion_info;
static int hf_rtcp_pse_ms_modality;
/* Microsoft PLI Extension */
static int hf_rtcp_psfb_pli_ms_request_id;
static int hf_rtcp_psfb_pli_ms_sfr;
/* Microsoft Video Source Request */
static int hf_rtcp_psfb_ms_type;
static int hf_rtcp_psfb_ms_length;
static int hf_rtcp_psfb_ms_msi;
static int hf_rtcp_psfb_ms_vsr_request_id;
static int hf_rtcp_psfb_ms_vsr_version;
static int hf_rtcp_psfb_ms_vsr_key_frame_request;
static int hf_rtcp_psfb_ms_vsr_num_entries;
static int hf_rtcp_psfb_ms_vsr_entry_length;
static int hf_rtcp_psfb_ms_vsre_payload_type;
static int hf_rtcp_psfb_ms_vsre_ucconfig_mode;
static int hf_rtcp_psfb_ms_vsre_no_sp_frames;
static int hf_rtcp_psfb_ms_vsre_baseline;
static int hf_rtcp_psfb_ms_vsre_cgs;
static int hf_rtcp_psfb_ms_vsre_aspect_ratio_bitmask;
static int hf_rtcp_psfb_ms_vsre_aspect_ratio_4by3;
static int hf_rtcp_psfb_ms_vsre_aspect_ratio_16by9;
static int hf_rtcp_psfb_ms_vsre_aspect_ratio_1by1;
static int hf_rtcp_psfb_ms_vsre_aspect_ratio_3by4;
static int hf_rtcp_psfb_ms_vsre_aspect_ratio_9by16;
static int hf_rtcp_psfb_ms_vsre_aspect_ratio_20by3;
static int hf_rtcp_psfb_ms_vsre_max_width;
static int hf_rtcp_psfb_ms_vsre_max_height;
static int hf_rtcp_psfb_ms_vsre_min_bitrate;
static int hf_rtcp_psfb_ms_vsre_bitrate_per_level;
static int hf_rtcp_psfb_ms_vsre_bitrate_histogram;
static int hf_rtcp_psfb_ms_vsre_frame_rate_mask;
static int hf_rtcp_psfb_ms_vsre_frame_rate_7_5;
static int hf_rtcp_psfb_ms_vsre_frame_rate_12_5;
static int hf_rtcp_psfb_ms_vsre_frame_rate_15;
static int hf_rtcp_psfb_ms_vsre_frame_rate_25;
static int hf_rtcp_psfb_ms_vsre_frame_rate_30;
static int hf_rtcp_psfb_ms_vsre_frame_rate_50;
static int hf_rtcp_psfb_ms_vsre_frame_rate_60;
static int hf_rtcp_psfb_ms_vsre_must_instances;
static int hf_rtcp_psfb_ms_vsre_may_instances;
static int hf_rtcp_psfb_ms_vsre_quality_histogram;
static int hf_rtcp_psfb_ms_vsre_max_pixels;

static int hf_rtcp_mcptt_fld_id;
static int hf_rtcp_mcptt_fld_len;
static int hf_rtcp_mcptt_fld_val;
static int hf_rtcp_mcptt_granted_partys_id;
static int hf_rtcp_app_data_padding;
static int hf_rtcp_mcptt_priority;
static int hf_rtcp_mcptt_duration;
static int hf_rtcp_mcptt_user_id;
static int hf_rtcp_mcptt_floor_ind;
static int hf_rtcp_mcptt_rej_cause;
static int hf_rtcp_mcptt_rej_cause_floor_deny;
static int hf_rtcp_mcptt_rej_cause_floor_revoke;
static int hf_rtcp_mcptt_rej_phrase;
static int hf_rtcp_mcptt_queue_pos_inf;
static int hf_rtcp_mcptt_queue_pri_lev;
static int hf_rtcp_mcptt_perm_to_req_floor;
static int hf_rtcp_mcptt_queue_size;
static int hf_rtcp_mcptt_msg_seq_num;
static int hf_rtcp_mcptt_queued_user_id;
static int hf_rtcp_mcptt_source;
static int hf_rtcp_mcptt_queueing_cap;
static int hf_rtcp_mcptt_part_type_len;
static int hf_rtcp_mcptt_participant_type;
static int hf_rtcp_mcptt_participant_ref;
static int hf_rtcp_mcptt_ssrc;
static int hf_rtcp_mcptt_num_users;
static int hf_rtcp_mcptt_user_id_len;
static int hf_rtcp_spare16;
static int hf_rtcp_mcptt_num_ssrc;
static int hf_rtcp_mcptt_func_alias;
static int hf_rtcp_mcptt_num_fas;
static int hf_rtcp_mcptt_fa_len;
static int hf_rtcp_mcptt_loc_type;
static int hf_rtcp_mcptt_cellid;
static int hf_rtcp_mcptt_enodebid;
static int hf_rtcp_mcptt_ecgi_eci;
static int hf_rtcp_mcptt_tac;
static int hf_rtcp_mcptt_mbms_serv_area;
static int hf_rtcp_mcptt_mbsfn_area_id;
static int hf_rtcp_mcptt_lat;
static int hf_rtcp_mcptt_long;
static int hf_rtcp_mcptt_msg_type;
static int hf_rtcp_mcptt_num_loc;
static int hf_rtcp_mcptt_str;
static int hf_rtcp_mccp_len;
static int hf_rtcp_mccp_field_id;
static int hf_rtcp_mcptt_group_id;
static int hf_rtcp_mccp_audio_m_line_no;
static int hf_rtcp_mccp_floor_m_line_no;
static int hf_rtcp_mccp_ip_version;
static int hf_rtcp_mccp_floor_port_no;
static int hf_rtcp_mccp_media_port_no;
static int hf_rtcp_mccp_ipv4;
static int hf_rtcp_mccp_ipv6;
static int hf_rtcp_mccp_tmgi;
static int hf_rtcp_encrypted;

/* RTCP fields defining a sub tree */
static int ett_rtcp;
static int ett_rtcp_sr;
static int ett_rtcp_rr;
static int ett_rtcp_sdes;
static int ett_rtcp_bye;
static int ett_rtcp_app;
static int ett_rtcp_rtpfb;
static int ett_rtcp_rtpfb_ccfb_fci;
static int ett_rtcp_rtpfb_ccfb_media_source;
static int ett_rtcp_rtpfb_ccfb_metric_blocks;
static int ett_rtcp_rtpfb_ccfb_metric_block;
static int ett_rtcp_psfb;
static int ett_rtcp_xr;
static int ett_rtcp_fir;
static int ett_rtcp_nack;
static int ett_ssrc;
static int ett_ssrc_item;
static int ett_ssrc_ext_high;
static int ett_sdes;
static int ett_sdes_item;
static int ett_PoC1;
static int ett_mux;
static int ett_rtcp_setup;
static int ett_rtcp_roundtrip_delay;
static int ett_xr_block;
static int ett_xr_block_contents;
static int ett_xr_ssrc;
static int ett_xr_loss_chunk;
static int ett_poc1_conn_contents;
static int ett_rtcp_nack_blp;
static int ett_pse;
static int ett_ms_vsr;
static int ett_ms_vsr_entry;
static int ett_ms_ds;
static int ett_rtcp_mcpt;
static int ett_rtcp_mcptt_participant_ref;
static int ett_rtcp_mcptt_eci;
static int ett_rtcp_mccp_tmgi;

static expert_field ei_rtcp_not_final_padding;
static expert_field ei_rtcp_bye_reason_not_padded;
static expert_field ei_rtcp_xr_block_length_bad;
static expert_field ei_rtcp_roundtrip_delay;
static expert_field ei_rtcp_length_check;
static expert_field ei_rtcp_roundtrip_delay_negative;
static expert_field ei_rtcp_psfb_ms_type;
static expert_field ei_rtcp_missing_sender_ssrc;
static expert_field ei_rtcp_missing_block_header;
static expert_field ei_rtcp_block_length;
static expert_field ei_srtcp_encrypted_payload;
static expert_field ei_rtcp_rtpfb_transportcc_bad;
static expert_field ei_rtcp_rtpfb_fmt_not_implemented;
static expert_field ei_rtcp_rtpfb_ccfb_too_many_reports;
static expert_field ei_rtcp_mcptt_unknown_fld;
static expert_field ei_rtcp_mcptt_location_type;
static expert_field ei_rtcp_appl_extra_bytes;
static expert_field ei_rtcp_appl_not_ascii;
static expert_field ei_rtcp_appl_non_conformant;
static expert_field ei_rtcp_appl_non_zero_pad;

enum default_protocol_type {
    RTCP_PROTO_RTCP,
    RTCP_PROTO_SRTCP
};

static const enum_val_t rtcp_default_protocol_vals[] = {
  {"RTCP",  "RTCP",  RTCP_PROTO_RTCP},
  {"SRTCP", "SRTCP", RTCP_PROTO_SRTCP},
  {NULL, NULL, -1}
};

static int global_rtcp_default_protocol = RTCP_PROTO_RTCP;

/* Main dissection function */
static int dissect_rtcp( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);
static int dissect_srtcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data);

/* Displaying set info */
static bool global_rtcp_show_setup_info = true;
static void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Related to roundtrip calculation (using LSR and DLSR) */
static bool global_rtcp_show_roundtrip_calculation;
#define MIN_ROUNDTRIP_TO_REPORT_DEFAULT 10
static unsigned global_rtcp_show_roundtrip_calculation_minimum = MIN_ROUNDTRIP_TO_REPORT_DEFAULT;
static void remember_outgoing_sr(packet_info *pinfo, uint32_t lsr);
static void calculate_roundtrip_delay(tvbuff_t *tvb, packet_info *pinfo,
                                      proto_tree *tree, uint32_t lsr, uint32_t dlsr);
static void add_roundtrip_delay_info(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree,
                                     unsigned frame,
                                     unsigned gap_between_reports, int delay);

enum application_specific_encoding_type {
    RTCP_APP_NONE,
    RTCP_APP_MCPTT
};

static const enum_val_t rtcp_application_specific_encoding_vals[] = {
  {"None", "None", RTCP_APP_NONE},
  {"MCPT", "MCPT", RTCP_APP_MCPTT},
  {NULL, NULL, -1}
};

static int preferences_application_specific_encoding = RTCP_APP_NONE;


/* Set up an RTCP conversation using the info given */
void srtcp_add_address( packet_info *pinfo,
                       address *addr, int port,
                       int other_port,
                       const char *setup_method, uint32_t setup_frame_number,
                       struct srtp_info *srtcp_info)
{
    address                         null_addr;
    conversation_t                 *p_conv;
    struct _rtcp_conversation_info *p_conv_data;

    /*
     * If this isn't the first time this packet has been processed,
     * we've already done this work, so we don't need to do it
     * again.
     */
    if (pinfo->fd->visited)
    {
        return;
    }

    clear_address(&null_addr);

    /*
     * Check if the ip address and port combination is not
     * already registered as a conversation.
     */
    p_conv = find_conversation( setup_frame_number, addr, &null_addr, CONVERSATION_UDP, port, other_port,
                                NO_ADDR_B | (!other_port ? NO_PORT_B : 0));

    /*
     * If not, create a new conversation.
     */
    if ( ! p_conv ) {
        p_conv = conversation_new( setup_frame_number, addr, &null_addr, CONVERSATION_UDP,
                                   (uint32_t)port, (uint32_t)other_port,
                                   NO_ADDR2 | (!other_port ? NO_PORT2 : 0));
    }

    /* Set dissector */
    conversation_set_dissector(p_conv, rtcp_handle);

    /*
     * Check if the conversation has data associated with it.
     */
    p_conv_data = (struct _rtcp_conversation_info *)conversation_get_proto_data(p_conv, proto_rtcp);

    /*
     * If not, add a new data item.
     */
    if ( ! p_conv_data ) {
        /* Create conversation data */
        p_conv_data = wmem_new0(wmem_file_scope(), struct _rtcp_conversation_info);
        conversation_add_proto_data(p_conv, proto_rtcp, p_conv_data);
    }

    /*
     * Update the conversation data.
     */
    p_conv_data->setup_method_set = true;
    (void) g_strlcpy(p_conv_data->setup_method, setup_method, MAX_RTCP_SETUP_METHOD_SIZE);
    p_conv_data->setup_frame_number = setup_frame_number;
    p_conv_data->srtcp_info = srtcp_info;
}

/* Set up an RTCP conversation using the info given */
void rtcp_add_address( packet_info *pinfo,
                       address *addr, int port,
                       int other_port,
                       const char *setup_method, uint32_t setup_frame_number)
{
    srtcp_add_address(pinfo, addr, port, other_port, setup_method, setup_frame_number, NULL);
}

static bool
dissect_rtcp_heur( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data )
{
    unsigned int offset = 0;
    unsigned int first_byte;
    unsigned int packet_type;

    if (tvb_captured_length(tvb) < 2)
        return false;

    /* Look at first byte */
    first_byte = tvb_get_uint8(tvb, offset);

    /* Are version bits set to 2? */
    if (((first_byte & 0xC0) >> 6) != 2)
    {
        return false;
    }

    /* Look at packet type */
    packet_type = tvb_get_uint8(tvb, offset + 1);

    /* First packet within compound packet is supposed to be a sender
       or receiver report. (However, see RFC 5506 which allows the
       use of non-compound RTCP packets in some circumstances.)
       - allow BYE because this happens anyway
       - allow APP because TBCP ("PoC1") packets aren't compound...
       - allow PSFB for MS */
    if (!((packet_type == RTCP_SR)  || (packet_type == RTCP_RR) ||
          (packet_type == RTCP_BYE) || (packet_type == RTCP_APP) ||
          (packet_type == RTCP_PSFB)))
    {
        return false;
    }

    /* Overall length must be a multiple of 4 bytes */
    if (tvb_reported_length(tvb) % 4)
    {
        return false;
    }

    /* OK, dissect as RTCP */

    /* XXX: This heuristic doesn't differentiate between RTCP and SRTCP.
     * There are some possible extra heuristics: looking to see if there's
     * extra length (that is not padding), looking if padding is enabled
     * but the last byte is inconsistent with padding, stepping through
     * compound packets and seeing if it looks encrypted at some point, etc.
     */
    if (global_rtcp_default_protocol == RTCP_PROTO_RTCP) {
        dissect_rtcp(tvb, pinfo, tree, data);
    } else {
        dissect_srtcp(tvb, pinfo, tree, data);
    }

    return true;
}

/* Dissect the length field. Append to this field text indicating the number of
   actual bytes this translates to (i.e. (raw value + 1) * 4) */
static int dissect_rtcp_length_field( proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_item     *ti;
    unsigned short  raw_length = tvb_get_ntohs( tvb, offset );

    ti = proto_tree_add_item( tree, hf_rtcp_length, tvb, offset, 2,  ENC_BIG_ENDIAN);
    proto_item_append_text(ti, " (%u bytes)", (raw_length+1)*4);
    offset += 2;
    return offset;
}

static int
dissect_rtcp_rtpfb_header(tvbuff_t *tvb, int offset, proto_tree *rtcp_tree)
{
    /* Feedback message type, 8 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_rtpfb_fmt, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset++;

    /* Packet type, 8 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset++;

    offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);

    /* SSRC of packet sender, 32 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_ssrc_sender, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    return offset;
}

static int
dissect_rtcp_nack( tvbuff_t *tvb, int offset, proto_tree *tree )
{
    /* Packet type = FIR (H261) */
    proto_tree_add_item( tree, hf_rtcp_rc, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset++;
    /* Packet type, 8 bits  = APP */
    proto_tree_add_item( tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset++;

    /* Packet length in 32 bit words minus one */
    offset = dissect_rtcp_length_field(tree, tvb, offset);

    /* SSRC  */
    proto_tree_add_item( tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* FSN, 16 bits */
    proto_tree_add_item( tree, hf_rtcp_fsn, tvb, offset, 2, ENC_BIG_ENDIAN );
    offset += 2;

    /* BLP, 16 bits */
    proto_tree_add_item( tree, hf_rtcp_blp, tvb, offset, 2, ENC_BIG_ENDIAN );
    offset += 2;

    return offset;
}

static int
dissect_rtcp_rtpfb_tmmbr_tmmbn_fci( tvbuff_t *tvb, int offset, proto_tree *rtcp_tree, proto_item *top_item, int num_fci, bool is_notification)
{
    uint8_t exp;
    uint32_t mantissa;
    proto_tree *fci_tree;

    if (is_notification) {
        fci_tree = proto_tree_add_subtree_format( rtcp_tree, tvb, offset, 8, ett_ssrc, NULL, "TMMBN %d", num_fci );
    } else {
        fci_tree = proto_tree_add_subtree_format( rtcp_tree, tvb, offset, 8, ett_ssrc, NULL, "TMMBR %d", num_fci );
    }

    /* SSRC 32 bit*/
    proto_tree_add_item( fci_tree, hf_rtcp_rtpfb_tmbbr_fci_ssrc, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;
    /* Exp 6 bit*/
    proto_tree_add_item( fci_tree, hf_rtcp_rtpfb_tmbbr_fci_exp, tvb, offset, 1, ENC_BIG_ENDIAN );
    exp = (tvb_get_uint8(tvb, offset) & 0xfc) >> 2;
    /* Mantissa 17 bit*/
    proto_tree_add_item( fci_tree, hf_rtcp_rtpfb_tmbbr_fci_mantissa, tvb, offset, 3, ENC_BIG_ENDIAN );
    mantissa = (tvb_get_ntohl( tvb, offset) & 0x3fffe00) >> 9;
    proto_tree_add_string_format_value( fci_tree, hf_rtcp_rtpfb_tmbbr_fci_bitrate, tvb, offset, 3, "", "%u*2^%u", mantissa, exp);
    offset += 3;
    /* Overhead */
    proto_tree_add_item( fci_tree, hf_rtcp_rtpfb_tmbbr_fci_measuredoverhead, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset += 1;

    if (top_item != NULL) {
        if (is_notification == 1) {
            proto_item_append_text(top_item, ": TMMBN: %u*2^%u", mantissa, exp);
        } else {
            proto_item_append_text(top_item, ": TMMBR: %u*2^%u", mantissa, exp);
        }
    }

    return offset;
}

static int
dissect_rtcp_rtpfb_tmmbr( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *rtcp_tree, void *data _U_)
{
    int offset = 0;
    proto_item *top_item = proto_tree_get_parent(rtcp_tree);

    int packet_len = tvb_get_uint16( tvb, offset + 2, ENC_BIG_ENDIAN);

    offset = dissect_rtcp_rtpfb_header(tvb, offset, rtcp_tree);

    /* SSRC of media source, 32 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_ssrc_media_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* Feedback Control Information */
    uint32_t num_fci = 0;
    while (offset < packet_len)
    {
        num_fci++;
        offset = dissect_rtcp_rtpfb_tmmbr_tmmbn_fci( tvb, offset, rtcp_tree, top_item, num_fci, false);
    }

    return offset;
}

static int
dissect_rtcp_rtpfb_tmmbn( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *rtcp_tree, void *data _U_)
{
    int offset = 0;
    proto_item *top_item = proto_tree_get_parent(rtcp_tree);

    int packet_len = tvb_get_uint16( tvb, offset + 2, ENC_BIG_ENDIAN);

    offset = dissect_rtcp_rtpfb_header(tvb, offset, rtcp_tree);

    /* SSRC of media source, 32 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_ssrc_media_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* Feedback Control Information */
    uint32_t num_fci = 0;
    while (offset < packet_len)
    {
        num_fci++;
        offset = dissect_rtcp_rtpfb_tmmbr_tmmbn_fci( tvb, offset, rtcp_tree, top_item, num_fci, true);
    }

    return offset;
}

static int
dissect_rtcp_rtpfb_ccfb_fci( tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *fci_tree, int packet_len)
{
    proto_tree *media_source_ssrc_tree;
    proto_item *metric_blocks_item;
    proto_tree *metric_blocks_tree;
    proto_item *metric_block_tree;
    proto_item *ato_item;

    /* SSRC of media source, 32 bits */
    const uint32_t media_source_ssrc = tvb_get_uint32( tvb, offset, 4);
    media_source_ssrc_tree =
      proto_tree_add_subtree_format( fci_tree, tvb, 0, 0, ett_rtcp_rtpfb_ccfb_media_source, NULL,
                                     "Media Source Stream: 0x%"PRIx32 " (%"PRIu32 ")", media_source_ssrc, media_source_ssrc);

    proto_tree_add_item( media_source_ssrc_tree, hf_rtcp_ssrc_media_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    proto_tree_add_item( media_source_ssrc_tree, hf_rtcp_rtpfb_ccfb_beginseq, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    const uint16_t num_of_reported_pkts = tvb_get_uint16( tvb, offset, ENC_BIG_ENDIAN) + 1;
    proto_tree_add_uint_format( media_source_ssrc_tree, hf_rtcp_rtpfb_ccfb_numreports, tvb, offset, 2,
                                num_of_reported_pkts, "Number of metric blocks: %" PRIu16, num_of_reported_pkts);

    metric_blocks_tree = proto_tree_add_subtree(media_source_ssrc_tree, tvb, 0, 0, ett_rtcp_rtpfb_ccfb_metric_blocks,
                                                &metric_blocks_item, "Metric Blocks");
    proto_item_set_generated( metric_blocks_item);

    if (num_of_reported_pkts > 16384)
    {
      expert_add_info(pinfo, metric_blocks_tree, &ei_rtcp_rtpfb_ccfb_too_many_reports);
      return packet_len;
    }

    for (int i = 0; i < num_of_reported_pkts; i++)
    {
      offset += 2;

      const uint16_t metric_block = tvb_get_uint16( tvb, offset, ENC_BIG_ENDIAN);
      const uint16_t received = RTCP_CCFB_RECEIVED(metric_block);
      const uint16_t ecn = RTCP_CCFB_ECN(metric_block);
      float ato = RTCP_CCFB_ATO(metric_block);
      float ato_ms = ato / 1024 * 1000;

      metric_block_tree =
        proto_tree_add_subtree_format( metric_blocks_tree, tvb, 0, 0, ett_rtcp_rtpfb_ccfb_metric_block, NULL,
                                       "Metric Block (R:%"PRIu32", ECN:%"PRIu32", ATO:%f ms)", received, ecn, ato_ms);
      proto_tree_add_item( metric_block_tree, hf_rtcp_rtpfb_ccfb_received, tvb, offset, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item( metric_block_tree, hf_rtcp_rtpfb_ccfb_ecn, tvb, offset, 2, ENC_BIG_ENDIAN);

      ato_item = proto_tree_add_item( metric_block_tree, hf_rtcp_rtpfb_ccfb_ato, tvb, offset, 2, ENC_BIG_ENDIAN);
      proto_item_append_text(ato_item, " (%f ms)", ato_ms);
    }

    offset += 2;
    if (num_of_reported_pkts % 2 == 1)
    {
      proto_tree_add_item( metric_blocks_tree, hf_rtcp_rtpfb_ccfb_padding, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
    }

    return offset;
}

static int
dissect_rtcp_rtpfb_ccfb( tvbuff_t *tvb, packet_info *pinfo, proto_tree *rtcp_tree, void *data _U_)
{
  int offset = 0;
  proto_tree *fci_tree;
  proto_item *fci_item;

  int packet_len = tvb_get_uint16( tvb, offset + 2, ENC_BIG_ENDIAN);

  offset = dissect_rtcp_rtpfb_header( tvb, offset, rtcp_tree);

  fci_tree = proto_tree_add_subtree( rtcp_tree, tvb, 0, 0, ett_rtcp_rtpfb_ccfb_fci,
                                     &fci_item, "Feedback Control Information (FCI)");
  proto_item_set_generated( fci_item);

  /* We can have multiple SSRC streams for which we are sending feedback (for which
   * RTP packets have been received). Every iteration in while loop will dissect info
   * for one source SSRC stream. Last 4 bytes are reserved for timestamp field.
   */
  while (offset < packet_len - 4)
  {
    offset = dissect_rtcp_rtpfb_ccfb_fci( tvb, offset, pinfo, fci_tree, packet_len);
  }

  proto_tree_add_item( rtcp_tree, hf_rtcp_rtpfb_ccfb_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  return offset;
}

/* Dissect Application Specific Feedback messages */
static int
dissect_rtcp_asfb_ms( tvbuff_t *tvb, int offset, proto_tree *tree, packet_info *pinfo)
{
    uint8_t num_entries;
    uint8_t desc = 0;
    uint16_t type;
    uint16_t length;
    uint8_t i;
    uint32_t msi;
    uint32_t min_bitrate, bitrate_per_level;
    proto_tree *rtcp_ms_vsr_tree;
    proto_tree *rtcp_ms_vsr_entry_tree;
    proto_tree *rtcp_ms_ds_tree;
    proto_item *item, *type_item;

    type = tvb_get_ntohs(tvb, offset);
    type_item = proto_tree_add_item( tree, hf_rtcp_psfb_ms_type, tvb, offset, 2, ENC_BIG_ENDIAN );
    offset += 2;

    length = tvb_get_ntohs(tvb, offset) - 4;
    proto_tree_add_item( tree, hf_rtcp_psfb_ms_length, tvb, offset, 2, ENC_BIG_ENDIAN );
    offset += 2;

    if (type == 1)
    {
        rtcp_ms_vsr_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_ms_vsr, &item, "MS Video Source Request");

        col_append_str(pinfo->cinfo, COL_INFO, "( MS-VSR )");

        item = proto_tree_add_item( rtcp_ms_vsr_tree, hf_rtcp_psfb_ms_msi, tvb, offset, 4, ENC_BIG_ENDIAN );
        msi = tvb_get_ntohl (tvb, offset);
        /* Decode if it is NONE or ANY and add to line */
        proto_item_append_text(item," %s", val_to_str_const(msi, rtcp_ssrc_values, ""));
        offset += 4;

        proto_tree_add_item( rtcp_ms_vsr_tree, hf_rtcp_psfb_ms_vsr_request_id, tvb, offset, 2, ENC_BIG_ENDIAN );
        offset += 2;
        /* 2 reserved bytes */
        offset += 2;
        proto_tree_add_item( rtcp_ms_vsr_tree, hf_rtcp_psfb_ms_vsr_version, tvb, offset, 1, ENC_BIG_ENDIAN );
        offset++;
        proto_tree_add_item( rtcp_ms_vsr_tree, hf_rtcp_psfb_ms_vsr_key_frame_request, tvb, offset, 1, ENC_BIG_ENDIAN );
        offset++;
        num_entries = tvb_get_uint8(tvb, offset);
        proto_tree_add_item( rtcp_ms_vsr_tree, hf_rtcp_psfb_ms_vsr_num_entries, tvb, offset, 1, ENC_BIG_ENDIAN );
        offset++;
        proto_tree_add_item( rtcp_ms_vsr_tree, hf_rtcp_psfb_ms_vsr_entry_length, tvb, offset, 1, ENC_BIG_ENDIAN );
        offset++;
        /* 4 reserved bytes */
        offset += 4;

        while (num_entries-- && tvb_captured_length_remaining (tvb, offset) >= 0x44)
        {
            rtcp_ms_vsr_entry_tree = proto_tree_add_subtree_format(rtcp_ms_vsr_tree, tvb, offset, 0x44,
                                     ett_ms_vsr_entry, NULL, "MS Video Source Request Entry #%d", ++desc);

            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_payload_type,    tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_ucconfig_mode,  tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_no_sp_frames,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_baseline,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_cgs,  tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_aspect_ratio_bitmask,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_aspect_ratio_20by3,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_aspect_ratio_9by16,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_aspect_ratio_3by4,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_aspect_ratio_1by1,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_aspect_ratio_16by9,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_aspect_ratio_4by3,  tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_max_width,  tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_max_height,  tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_min_bitrate,  tvb, offset, 4, ENC_BIG_ENDIAN);
            min_bitrate = tvb_get_ntohl (tvb, offset);
            offset += 4;
            /* 4 Reserved bytes */
            offset += 4;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_bitrate_per_level,  tvb, offset, 4, ENC_BIG_ENDIAN);
            bitrate_per_level = tvb_get_ntohl (tvb, offset);
            offset += 4;
            for (i = 0 ; i < 10 ; i++)
            {
                item = proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_bitrate_histogram,  tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_item_prepend_text(item,"Bitrate %d - %d ",
                        min_bitrate + i * bitrate_per_level,
                        min_bitrate + (i + 1) * bitrate_per_level);
                offset += 2;
            }
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_frame_rate_mask,  tvb, offset, 4, ENC_BIG_ENDIAN);
            offset +=3;      /* Move to low byte of mask where valid setting are */
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_frame_rate_60,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_frame_rate_50,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_frame_rate_30,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_frame_rate_25,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_frame_rate_15,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_frame_rate_12_5,  tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_frame_rate_7_5,  tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_must_instances,  tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_may_instances,  tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            for (i = 0 ; i < 8 ; i++)
            {
                item = proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_quality_histogram,  tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_item_prepend_text(item, "Quality Level %d ", i+1 );
                offset += 2;
            }
            proto_tree_add_item (rtcp_ms_vsr_entry_tree, hf_rtcp_psfb_ms_vsre_max_pixels,  tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
    }
    else if (type == 3)
    {
        /* MS Dominant Speaker History */
        rtcp_ms_ds_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_ms_ds, NULL, "MS Dominant Speaker History");
        col_append_str(pinfo->cinfo, COL_INFO, "( MS-DSH )");
        while (length-- && tvb_captured_length_remaining (tvb, offset) >= 4)
        {
            item = proto_tree_add_item( rtcp_ms_ds_tree, hf_rtcp_psfb_ms_msi, tvb, offset, 4, ENC_BIG_ENDIAN );
            msi = tvb_get_ntohl (tvb, offset);
            proto_item_append_text(item," %s", val_to_str_const(msi, rtcp_ssrc_values, ""));
            offset += 4;
            length --;
        }
    }
    else
    {
        expert_add_info(pinfo, type_item, &ei_rtcp_psfb_ms_type);
        offset += tvb_captured_length_remaining (tvb, offset);
    }
    return offset;
}

static int
dissect_rtcp_psfb_remb( tvbuff_t *tvb, int offset, proto_tree *rtcp_tree, proto_item *top_item, int num_fci, int *read_fci)
{
    unsigned    exp, indexSsrcs;
    uint8_t     numberSsrcs;
    uint64_t    mantissa, bitrate;
    proto_tree *fci_tree;

    fci_tree = proto_tree_add_subtree_format( rtcp_tree, tvb, offset, 8, ett_ssrc, NULL, "REMB %d", num_fci );

    /* Unique identifier 'REMB' */
    proto_tree_add_item( fci_tree, hf_rtcp_psfb_remb_fci_identifier, tvb, offset, 4, ENC_ASCII );
    offset += 4;

    /* Number of ssrcs - they will each be parsed below */
    proto_tree_add_item( fci_tree, hf_rtcp_psfb_remb_fci_number_ssrcs, tvb, offset, 1, ENC_BIG_ENDIAN );
    numberSsrcs = tvb_get_uint8( tvb, offset);
    offset += 1;

    /* Exp 6 bit*/
    proto_tree_add_item( fci_tree, hf_rtcp_psfb_remb_fci_exp, tvb, offset, 1, ENC_BIG_ENDIAN );
    exp = (tvb_get_uint8(tvb, offset) & 0xfc) ;
    exp = exp >> 2;

    /* Mantissa 18 bit*/
    proto_tree_add_item( fci_tree, hf_rtcp_psfb_remb_fci_mantissa, tvb, offset, 3, ENC_BIG_ENDIAN );
    mantissa = (tvb_get_ntohl( tvb, offset - 1) & 0x0003ffff);
    bitrate = mantissa << exp;
    proto_tree_add_string_format_value( fci_tree, hf_rtcp_psfb_remb_fci_bitrate, tvb, offset, 3, "", "%" PRIu64, bitrate);
    offset += 3;

    for  (indexSsrcs = 0; indexSsrcs < numberSsrcs; indexSsrcs++)
    {
        /* SSRC 32 bit*/
        proto_tree_add_item( fci_tree, hf_rtcp_psfb_remb_fci_ssrc, tvb, offset, 4, ENC_BIG_ENDIAN );
        offset += 4;
    }

    if (top_item != NULL) {
        proto_item_append_text(top_item, ": REMB: max bitrate=%" PRIu64, bitrate);
    }
    *read_fci = 2 + (numberSsrcs);

    return offset;
}

static int
dissect_rtcp_rtpfb_transport_cc_fci( tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *rtcp_tree, int pkt_len)
{
    proto_tree *fci_tree, *pkt_chunk_tree, *recv_delta_tree;
    proto_item *item       = NULL;
    uint8_t *delta_array;
    uint16_t *pkt_seq_array;
    uint32_t i, pkt_base_seq, pkt_seq_num, pkt_count, delta_index = 0;
    int fci_length        = pkt_len - RTCP_TRANSPORT_CC_HEADER_LENGTH;
    int padding_length     = offset;

    fci_tree = proto_tree_add_subtree_format( rtcp_tree, tvb, offset, fci_length, ett_ssrc, NULL, "Transport-cc" );

    /* base sequence number */
    proto_tree_add_item_ret_uint( fci_tree, hf_rtcp_rtpfb_transport_cc_fci_base_seq, tvb, offset, 2, ENC_BIG_ENDIAN, &pkt_base_seq );
    offset += 2;
    pkt_seq_num = pkt_base_seq;

    /* packet status count */
    proto_tree_add_item_ret_uint( fci_tree, hf_rtcp_rtpfb_transport_cc_fci_pkt_stats_cnt, tvb, offset, 2, ENC_BIG_ENDIAN, &pkt_count );
    offset += 2;

    delta_array   = wmem_alloc0_array( pinfo->pool, int8_t, pkt_count );
    pkt_seq_array = wmem_alloc0_array( pinfo->pool, int16_t, pkt_count );

    /* reference time */
    proto_tree_add_item( fci_tree, hf_rtcp_rtpfb_transport_cc_fci_ref_time, tvb, offset, 3, ENC_BIG_ENDIAN );
    offset += 3;

    /* feedback packet count */
    proto_tree_add_item( fci_tree, hf_rtcp_rtpfb_transport_cc_fci_fb_pkt_cnt, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset += 1;

    /* packet chunk */
    pkt_chunk_tree = proto_tree_add_subtree_format( fci_tree, tvb, offset, 0, ett_ssrc, NULL, "Packet Chunks" );

    for (i = 0; i < pkt_count; )
    {
        uint32_t chunk = 0;
        item = proto_tree_add_item_ret_uint( pkt_chunk_tree, hf_rtcp_rtpfb_transport_cc_fci_pkt_chunk, tvb, offset, 2, ENC_BIG_ENDIAN, &chunk );

        /* Packet Status Symbols */
        /**
         * 00 Packet not received
         * 01 Packet received, small delta
         * 10 Packet received, large or negative delta
         * 11 [Reserved]
         */
        if ( !(chunk & 0x8000) )
        {
            /* Run length chunk, first bit is zero */
            unsigned length = chunk & 0x1FFF;

            if ( length <= 0 || pkt_count - delta_index < length )
            {
                /* Malformed packet (zero or too many packets), stop parsing. */
                proto_tree_add_expert(pkt_chunk_tree, pinfo, &ei_rtcp_rtpfb_transportcc_bad, tvb, offset, 2);
                offset += 2;
                return offset;
            }

            if ( !(chunk & 0x6000) )
            {
                proto_item_append_text( item, " [Run Length Chunk] Packet not received. Length : %d", length);
                pkt_seq_num += length;
            }
            else if ( chunk & 0x2000 )
            {
                proto_item_append_text( item, " [Run Length Chunk] Small Delta. Length : %d", length);
                for (unsigned j = 0; j < length; j++)
                {
                    /*1 means 1 byte delta, 2 means 2 bytes delta*/
                    delta_array[delta_index+j] = 1;
                    pkt_seq_array[delta_index+j] = pkt_seq_num++;
                }
                delta_index += length;
            }
            else if ( chunk & 0x4000 )
            {
                proto_item_append_text( item, " [Run Length Chunk] Large or Negative Delta. Length : %d", length);
                for (unsigned j = 0; j < length; j++)
                {
                    delta_array[delta_index+j] = 2;
                    pkt_seq_array[delta_index+j] = pkt_seq_num++;
                }
                delta_index += length;
            }
            else
            {
                proto_item_append_text( item, " [Run Length Chunk] [Reserved]. Length : %d", length);
                pkt_seq_num += length;
            }

            i += length;

        }
        else
        {
            wmem_strbuf_t* status = wmem_strbuf_new(pinfo->pool, "|");

            /* Status Vector Chunk, first bit is one */
            if ( !(chunk & 0x4000) )
            {
                /* 1 bit symbols */

                int data = chunk & 0x3FFF;
                int chunk_count = 14;

                for (int k = 0; k < chunk_count; k++)
                {
                    if ( (data & (0x2000>>k)) == 0 )
                    {
                        if ( i + k < pkt_count )
                        {
                            wmem_strbuf_append(status, " N |");
                            pkt_seq_num++;
                        }
                        else
                        {
                            /* padding */
                            wmem_strbuf_append(status, " _ |");
                        }
                    }
                    else
                    {
                        if (delta_index >= pkt_count) {
                            /* Malformed packet (too many status packets). */
                            proto_tree_add_expert(pkt_chunk_tree, pinfo, &ei_rtcp_rtpfb_transportcc_bad, tvb, offset, 2);
                            offset += 2;
                            return offset;
                        }
                        wmem_strbuf_append(status, " R |");
                        delta_array[delta_index] = 1;
                        pkt_seq_array[delta_index] = pkt_seq_num++;
                        delta_index++;
                    }
                }
                proto_item_append_text( item, " [1 bit Status Vector Chunk]: %s", wmem_strbuf_get_str(status));
                i += chunk_count;
            }
            else
            {
                /* 2 bits symbols */
                int chunk_count = 7;
                int data = chunk & 0x3FFF;

                for (int k = 0; k < chunk_count; k++)
                {
                    switch ( (data & (0x3000 >> (2*k))) >> ( 2 * (6-k) ) )
                    {
                        case 0: /*00 packet not received*/
                            if ( i + k < pkt_count )
                            {
                                wmem_strbuf_append(status, " NR |");
                                pkt_seq_num++;
                            }
                            else
                            {
                                /*padding*/
                                wmem_strbuf_append(status, " __ |");
                            }
                            break;

                        case 1: /*01 Packet received, small delta*/
                            if (delta_index >= pkt_count) {
                                /* Malformed packet (too many status packets). */
                                proto_tree_add_expert(pkt_chunk_tree, pinfo, &ei_rtcp_rtpfb_transportcc_bad, tvb, offset, 2);
                                offset += 2;
                                return offset;
                            }
                            wmem_strbuf_append(status, " SD |");
                            delta_array[delta_index] = 1;
                            pkt_seq_array[delta_index] = pkt_seq_num++;
                            delta_index++;
                            break;

                        case 2: /*10 Packet received, large or negative delta*/
                            if (delta_index >= pkt_count) {
                                /* Malformed packet (too many status packets). */
                                proto_tree_add_expert(pkt_chunk_tree, pinfo, &ei_rtcp_rtpfb_transportcc_bad, tvb, offset, 2);
                                offset += 2;
                                return offset;
                            }
                            wmem_strbuf_append(status, " LD |");
                            delta_array[delta_index] = 2;
                            pkt_seq_array[delta_index] = pkt_seq_num++;
                            delta_index++;
                            break;

                        case 3: /*11 packet received, w/o(wrong? overflow?) timestamp*/
                        default:
                            /*TODO: process overflow status which is not details on draft.*/
                            wmem_strbuf_append(status, " WO |");
                            pkt_seq_num++;
                            break;

                    }
                }

                proto_item_append_text( item, " [2 bits Status Vector Chunk]: %s", wmem_strbuf_get_str(status));
                i += chunk_count;
            }

        }

        offset += 2;
    }

    /* recv delta */
    recv_delta_tree = proto_tree_add_subtree_format( fci_tree, tvb, offset, 0, ett_ssrc, NULL, "Recv Delta" );
    for (i = 0; i < pkt_count; i++ )
    {
        if ( delta_array[i] == 1 )
        {
            /*1 byte delta*/
            uint32_t delta;
            item = proto_tree_add_item_ret_uint( recv_delta_tree, hf_rtcp_rtpfb_transport_cc_fci_recv_delta_1_byte, tvb, offset, 1, ENC_BIG_ENDIAN, &delta );

            proto_item_append_text( item, " Small Delta: [seq: %d] %lf ms", pkt_seq_array[i], delta*250.0/1000);

            offset += 1;
        }
        else if ( delta_array[i] == 2 )
        {
            /*2 bytes delta*/
            int16_t delta;
            item = proto_tree_add_item( recv_delta_tree, hf_rtcp_rtpfb_transport_cc_fci_recv_delta_2_bytes, tvb, offset, 2, ENC_BIG_ENDIAN);
            delta = tvb_get_ntohs(tvb, offset);

            if ( delta < 0 )
            {
                proto_item_append_text( item, " Negative Delta: [seq: %d] %lf ms", pkt_seq_array[i], delta*250.0/1000 );
            }
            else
            {
                proto_item_append_text( item, " Large Delta: [seq: %d] %lf ms", pkt_seq_array[i], delta*250.0/1000 );
            }

            offset += 2;
        }
        else
        {
            /*End with 0*/
            break;
        }
    }

    /* padding */
    padding_length = fci_length - (offset - padding_length);
    if ( padding_length > 0 )
    {
        proto_tree_add_item( recv_delta_tree, hf_rtcp_rtpfb_transport_cc_fci_recv_delta_padding, tvb, offset, padding_length, ENC_BIG_ENDIAN );
        offset += padding_length;
        rtcp_padding_set = 0;  /* consume RTCP padding here */
    }

    /* delta_array / pkt_seq_array will be freed out of pinfo->pool */
    delta_array = NULL;
    pkt_seq_array = NULL;

    return offset;
}

static int
dissect_rtcp_rtpfb_transport_cc( tvbuff_t *tvb, packet_info *pinfo, proto_tree *rtcp_tree, void *data _U_)
{
    int offset = 0;

    int packet_len = tvb_get_uint16( tvb, offset + 2, ENC_BIG_ENDIAN);

    offset = dissect_rtcp_rtpfb_header( tvb, offset, rtcp_tree);

    /* SSRC of media source, 32 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_ssrc_media_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    while (offset < packet_len)
    {
        offset = dissect_rtcp_rtpfb_transport_cc_fci( tvb, offset, pinfo, rtcp_tree, packet_len);
    }

    return offset;
}

static int
dissect_rtcp_rtpfb_nack_fci( tvbuff_t *tvb, int offset, proto_tree *rtcp_tree, proto_item *top_item)
{
    int           i;
    int           nack_num_frames_lost;
    proto_tree   *bitfield_tree;
    unsigned int  rtcp_rtpfb_nack_pid;
    unsigned int  rtcp_rtpfb_nack_blp;
    proto_item   *ti;

    proto_tree_add_item(rtcp_tree, hf_rtcp_rtpfb_nack_pid, tvb, offset, 2, ENC_BIG_ENDIAN);
    rtcp_rtpfb_nack_pid = tvb_get_ntohs(tvb, offset);
    offset += 2;

    ti = proto_tree_add_item(rtcp_tree, hf_rtcp_rtpfb_nack_blp, tvb, offset, 2, ENC_BIG_ENDIAN);
    rtcp_rtpfb_nack_blp = tvb_get_ntohs(tvb, offset);
    bitfield_tree = proto_item_add_subtree(ti, ett_rtcp_nack_blp);
    nack_num_frames_lost = 1;
    if (rtcp_rtpfb_nack_blp) {
        proto_item_append_text(ti, " (Frames");
        for (i = 0; i < 16; i ++) {
            if (rtcp_rtpfb_nack_blp & (1<<i)) {
                proto_tree_add_uint_format(bitfield_tree, hf_rtcp_rtpfb_nack_pid, tvb, offset, 2, rtcp_rtpfb_nack_pid + i + 1,
                    "Frame %u also lost", rtcp_rtpfb_nack_pid + i + 1);
                proto_item_append_text(ti, " %u", rtcp_rtpfb_nack_pid + i + 1);
                nack_num_frames_lost ++;
            }
        }
        proto_item_append_text(ti, " lost)");
    } else {
        proto_item_append_text(ti, " (No additional frames lost)");
    }
    offset += 2;

    if (top_item != NULL) {
        proto_item_append_text(top_item, ": NACK: %d frames lost", nack_num_frames_lost);
    }
    return offset;
}

static int
dissect_rtcp_rtpfb_nack( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *rtcp_tree, void *data _U_)
{
    int offset = 0;
    proto_item *top_item = proto_tree_get_parent(rtcp_tree);

    int packet_len = tvb_get_uint16( tvb, offset + 2, ENC_BIG_ENDIAN);

    offset = dissect_rtcp_rtpfb_header( tvb, offset, rtcp_tree);

    /* SSRC of media source, 32 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_ssrc_media_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    while (offset < packet_len)
    {
        offset = dissect_rtcp_rtpfb_nack_fci( tvb, offset, rtcp_tree, top_item);
    }

    return offset;
}

static int
dissect_rtcp_rtpfb_undecoded( tvbuff_t *tvb, packet_info *pinfo, proto_tree *rtcp_tree, void *data _U_)
{
    int offset = 0;
    int packet_len = tvb_get_uint16( tvb, offset + 2, ENC_BIG_ENDIAN);

    offset = dissect_rtcp_rtpfb_header( tvb, offset, rtcp_tree);

    /* SSRC of media source, 32 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_ssrc_media_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    proto_item *ti = proto_tree_add_item(rtcp_tree, hf_rtcp_fci, tvb, offset, packet_len - offset, ENC_NA );
    expert_add_info(pinfo, ti, &ei_rtcp_rtpfb_fmt_not_implemented);

    return packet_len;
}

static int
dissect_rtcp_rtpfb( tvbuff_t *tvb, int offset, proto_tree *rtcp_tree, packet_info *pinfo)
{
    unsigned int rtcp_rtpfb_fmt;
    int          packet_length;

    /* Transport layer FB message */
    /* Feedback message type (FMT): 5 bits */
    rtcp_rtpfb_fmt = (tvb_get_uint8(tvb, offset) & 0x1f);

    /* Packet length in 32 bit words MINUS one, 16 bits */
    packet_length = (tvb_get_ntohs(tvb, offset + 2) + 1) * 4;

    tvbuff_t *subtvb = tvb_new_subset_length(tvb, offset, packet_length);
    if (dissector_try_uint (rtcp_rtpfb_dissector_table, rtcp_rtpfb_fmt, subtvb, pinfo, rtcp_tree))
    {
      return offset + packet_length;
    }
    else /* RTPFB FMT types that are still unassigned by IANA */
    {
      int start_offset = offset;

      offset = dissect_rtcp_rtpfb_header( tvb, offset, rtcp_tree);

      /* SSRC of media source, 32 bits */
      proto_tree_add_item( rtcp_tree, hf_rtcp_ssrc_media_source, tvb, offset, 4, ENC_BIG_ENDIAN );
      offset += 4;

      proto_tree_add_item(rtcp_tree, hf_rtcp_fci, tvb, offset, start_offset + packet_length - offset, ENC_NA );
      return offset + packet_length;
    }
}

static int
dissect_rtcp_psfb( tvbuff_t *tvb, int offset, proto_tree *rtcp_tree,
    int packet_length, proto_item *top_item _U_, packet_info *pinfo _U_)
{
    unsigned int  counter;
    unsigned int  num_fci;
    unsigned int  read_fci;
    proto_tree   *fci_tree;
    proto_item   *ti;
    unsigned int  rtcp_psfb_fmt;
    int           base_offset = offset;
    int           i;

    /* Payload-specific FB message */
    /* Feedback message type (FMT): 5 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_psfb_fmt, tvb, offset, 1, ENC_BIG_ENDIAN );
    rtcp_psfb_fmt = (tvb_get_uint8(tvb, offset) & 0x1f);
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s  ",
                  val_to_str_const(rtcp_psfb_fmt, rtcp_psfb_fmt_summary_vals, "Unknown"));

    offset++;

    /* Packet type, 8 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset++;

    /* Packet length in 32 bit words MINUS one, 16 bits */
    num_fci = (tvb_get_ntohs(tvb, offset) - 2);
    offset  = dissect_rtcp_length_field(rtcp_tree, tvb, offset);

    /* SSRC of packet sender, 32 bits */
    proto_tree_add_item( rtcp_tree, hf_rtcp_ssrc_sender, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* SSRC of media source, 32 bits */
    ti = proto_tree_add_item( rtcp_tree, hf_rtcp_ssrc_media_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    /* Decode if it is NONE or ANY and add to line */
    proto_item_append_text(ti," %s", val_to_str_const(tvb_get_ntohl(tvb,offset), rtcp_ssrc_values, ""));
    offset += 4;

    /* Check if we have a type specific dissector,
     * if we do, just return from here
     */
    if (packet_length > 12) {
      tvbuff_t *subtvb = tvb_new_subset_length(tvb, offset, packet_length - 12);

      if (dissector_try_uint (rtcp_psfb_dissector_table, rtcp_psfb_fmt,
              subtvb, pinfo, rtcp_tree))
        return base_offset + packet_length;
    }

    /* Feedback Control Information (FCI) */
    counter  = 0;
    read_fci = 0;
    while ( read_fci < num_fci ) {
        switch (rtcp_psfb_fmt)
        {
        case 1:     /* Picture Loss Indications (PLI) */
        {
            /* Handle MS PLI Extension */
            fci_tree = proto_tree_add_subtree_format( rtcp_tree, tvb, offset, 12, ett_ssrc, NULL, "MS PLI");
            proto_tree_add_item( fci_tree, hf_rtcp_psfb_pli_ms_request_id, tvb, offset, 2, ENC_BIG_ENDIAN );
            offset += 2;
            /* 2 reserved bytes */
            offset += 2;
            for (i = 0 ; i < 8 ; i++)
            {
                ti = proto_tree_add_item( fci_tree, hf_rtcp_psfb_pli_ms_sfr, tvb, offset, 1, ENC_BIG_ENDIAN );
                proto_item_prepend_text(ti,"PRID %d - %d ",
                        i * 8, (i+1) * 8 - 1);
                offset++;
            }
            read_fci += 3;
            break;
        }
        case 2:     /* Slice Loss Indication (SLI) */
            /* Handle SLI */
            fci_tree = proto_tree_add_subtree_format( rtcp_tree, tvb, offset, 4, ett_ssrc, NULL, "SLI %u", ++counter );
            proto_tree_add_item( fci_tree, hf_rtcp_psfb_sli_first,      tvb, offset, 4, ENC_BIG_ENDIAN );
            proto_tree_add_item( fci_tree, hf_rtcp_psfb_sli_number,     tvb, offset, 4, ENC_BIG_ENDIAN );
            proto_tree_add_item( fci_tree, hf_rtcp_psfb_sli_picture_id, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset +=4;
            read_fci++;
            break;
        case 4:     /* Handle FIR */
        {
            /* Create a new subtree for a length of 8 bytes */
            fci_tree  = proto_tree_add_subtree_format( rtcp_tree, tvb, offset, 8, ett_ssrc, NULL, "FIR %u", ++counter );
            /* SSRC 32 bit*/
            proto_tree_add_item( fci_tree, hf_rtcp_psfb_fir_fci_ssrc, tvb, offset, 4, ENC_BIG_ENDIAN );
            offset   += 4;
            /* Command Sequence Number 8 bit*/
            proto_tree_add_item( fci_tree, hf_rtcp_psfb_fir_fci_csn, tvb, offset, 1, ENC_BIG_ENDIAN );
            /*proto_tree_add_item( ssrc_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );*/
            offset   += 1;
            /* Reserved 24 bit*/
            proto_tree_add_item( fci_tree, hf_rtcp_psfb_fir_fci_reserved, tvb, offset, 3, ENC_BIG_ENDIAN );
            offset   += 3;
            read_fci += 2;
            break;
        }
        case 15:
        {
            /*
             * Handle Application Layer Feedback messages.
             *
             * XXX - how do we determine how to interpret these?
             *
             * REMB (Receiver Estimated Maximum Bitrate) is, according
             * to section 2.3 "Signaling of use of this extension" of
             * https://tools.ietf.org/html/draft-alvestrand-rmcat-remb-03,
             * indicated as an SDP option when the session is set up.
             *
             * MS-RTP is, according to MS-RTP and according to MS-SDPEXT
             * section 3.1.5.30.2 "a=rtcp-fb attribute", indicated as an
             * SDP option when the session is set up.
             *
             * Those would work if we have the SDP setup traffic and parse
             * the a=rtcp-fb attribute, but if we don't, we'd need to have
             * the user specify it somehow.
             */
            uint32_t magic_value = tvb_get_ntohl( tvb, offset);
            /* look for string literal 'REMB' which is 0x52454d42 hex */
            if (magic_value == 0x52454d42) {
                /* Handle REMB (Receiver Estimated Maximum Bitrate) - https://tools.ietf.org/html/draft-alvestrand-rmcat-remb-00 */
                offset = dissect_rtcp_psfb_remb(tvb, offset, rtcp_tree, top_item, counter, &read_fci);
            } else {
                /* Handle MS Application Layer Feedback Messages - MS-RTP */
                offset = dissect_rtcp_asfb_ms(tvb, offset, rtcp_tree, pinfo);
                read_fci = num_fci;     /* Consume all the bytes. */
            }
            break;
        }
        case 3:             /* Reference Picture Selection Indication (RPSI) - Not decoded*/
        default:
            /* Consume anything left so it doesn't make an infinite loop. */
            read_fci = num_fci;
            break;
        }
    }

    /* Append undecoded FCI information */
    if ((packet_length - (offset - base_offset)) > 0) {
        proto_tree_add_item( rtcp_tree, hf_rtcp_fci, tvb, offset, packet_length - (offset - base_offset), ENC_NA );
        offset = base_offset + packet_length;
    }
    return offset;
}

static int
dissect_rtcp_fir( tvbuff_t *tvb, int offset, proto_tree *tree )
{
    /* Packet type = FIR (H261) */
    proto_tree_add_item( tree, hf_rtcp_rc, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset++;
    /* Packet type, 8 bits  = APP */
    proto_tree_add_item( tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
    offset++;

    /* Packet length in 32 bit words minus one */
    offset = dissect_rtcp_length_field(tree, tvb, offset);

    /* SSRC  */
    proto_tree_add_item( tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    return offset;
}
static int
dissect_rtcp_app_poc1(tvbuff_t* tvb, packet_info* pinfo, int offset, proto_tree* tree,
   int packet_len, proto_item* subtype_item, unsigned rtcp_subtype)
{
    /* PoC1 Application */
    unsigned      item_len;
    uint8_t     t2timer_code, participants_code;
    unsigned      sdes_type;
    proto_tree* PoC1_tree;
    proto_item* PoC1_item;
    int padding;

    proto_item_append_text(subtype_item, " %s", val_to_str(rtcp_subtype, rtcp_app_poc1_floor_cnt_type_vals, "unknown (%u)"));
    col_add_fstr(pinfo->cinfo, COL_INFO, "(PoC1) %s", val_to_str(rtcp_subtype, rtcp_app_poc1_floor_cnt_type_vals, "unknown (%u)"));
    offset += 4;
    packet_len -= 4;
    if (packet_len == 0)
        return offset;      /* No more data */
    /* Create a subtree for the PoC1 Application items; we don't yet know
       the length */

       /* Top-level poc tree */
    PoC1_item = proto_tree_add_item(tree, hf_rtcp_app_poc1, tvb, offset, packet_len, ENC_NA);
    PoC1_tree = proto_item_add_subtree(PoC1_item, ett_PoC1);

    /* Dissect it according to its subtype */
    switch (rtcp_subtype) {

    case TBCP_BURST_REQUEST:
    {
        uint8_t code;
        uint16_t priority;

        /* Both items here are optional */
        if (tvb_reported_length_remaining(tvb, offset) == 0)
        {
            return offset;
        }

        /* Look for a code in the first byte */
        code = tvb_get_uint8(tvb, offset);
        offset += 1;

        /* Priority (optional) */
        if (code == 102)
        {
            item_len = tvb_get_uint8(tvb, offset);
            offset += 1;
            if (item_len != 2) /* SHALL be 2 */
                return offset;

            priority = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            col_append_fstr(pinfo->cinfo, COL_INFO,
                " \"%s\"",
                val_to_str_const(priority,
                    rtcp_app_poc1_qsresp_priority_vals,
                    "Unknown"));

            /* Look for (optional) next code */
            if (tvb_reported_length_remaining(tvb, offset) == 0)
            {
                return offset;
            }
            code = tvb_get_uint8(tvb, offset);
            offset += 1;

        }

        /* Request timestamp (optional) */
        if (code == 103)
        {
            char* buff;

            item_len = tvb_get_uint8(tvb, offset);
            offset += 1;
            if (item_len != 8) /* SHALL be 8 */
                return offset;

            proto_tree_add_item_ret_time_string(PoC1_tree, hf_rtcp_app_poc1_request_ts, tvb, offset, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN, pinfo->pool, &buff);

            offset += 8;

            col_append_fstr(pinfo->cinfo, COL_INFO, " ts=\"%s\"", buff);
        }
    }
    break;

    case TBCP_BURST_GRANTED:
    {
        proto_item* ti;
        uint16_t    stop_talking_time;
        uint16_t    participants;

        /* Stop talking timer (now mandatory) */
        t2timer_code = tvb_get_uint8(tvb, offset);
        offset += 1;
        if (t2timer_code != 101) /* SHALL be 101 */
            return offset;

        item_len = tvb_get_uint8(tvb, offset);
        offset += 1;
        if (item_len != 2) /* SHALL be 2 */
            return offset;

        stop_talking_time = tvb_get_ntohs(tvb, offset);
        ti = proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_stt, tvb, offset, 2, ENC_BIG_ENDIAN);

        /* Append text with meanings of value */
        switch (stop_talking_time)
        {
        case 0:
            proto_item_append_text(ti, " unknown");
            break;
        case 65535:
            proto_item_append_text(ti, " infinity");
            break;
        default:
            proto_item_append_text(ti, " seconds");
            break;
        }
        offset += item_len;

        col_append_fstr(pinfo->cinfo, COL_INFO, " stop-talking-time=%u",
            stop_talking_time);

        /* Participants (optional) */
        if (tvb_reported_length_remaining(tvb, offset) == 0)
        {
            return offset;
        }
        participants_code = tvb_get_uint8(tvb, offset);
        offset += 1;
        if (participants_code != 100) /* SHALL be 100 */
            return offset;

        item_len = tvb_get_uint8(tvb, offset);
        offset += 1;
        if (item_len != 2) /* SHALL be 2 */
            return offset;

        participants = tvb_get_ntohs(tvb, offset);
        ti = proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_partic, tvb, offset, 2, ENC_BIG_ENDIAN);

        /* Append text with meanings of extreme values */
        switch (participants)
        {
        case 0:
            proto_item_append_text(ti, " (not known)");
            break;
        case 65535:
            proto_item_append_text(ti, " (or more)");
            break;
        default:
            break;
        }
        offset += item_len;

        col_append_fstr(pinfo->cinfo, COL_INFO, " participants=%u",
            participants);
    }
    break;

    case TBCP_BURST_TAKEN_EXPECT_NO_REPLY:
    case TBCP_BURST_TAKEN_EXPECT_REPLY:
    {
        uint16_t participants;
        proto_item* ti;

        /* SSRC of PoC client */
        proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_ssrc_granted, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        packet_len -= 4;

        /* SDES type (must be CNAME) */
        sdes_type = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(PoC1_tree, hf_rtcp_sdes_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        packet_len--;
        if (sdes_type != RTCP_SDES_CNAME)
        {
            return offset;
        }

        /* SIP URI */
        item_len = tvb_get_uint8(tvb, offset);
        /* Item len of 1 because it's an FT_UINT_STRING... */
        proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_sip_uri,
            tvb, offset, 1, ENC_ASCII | ENC_BIG_ENDIAN);
        offset++;

        col_append_fstr(pinfo->cinfo, COL_INFO, " CNAME=\"%s\"",
            tvb_get_string_enc(pinfo->pool, tvb, offset, item_len, ENC_ASCII));

        offset += item_len;
        packet_len = packet_len - item_len - 1;

        /* In the application dependent data, the TBCP Talk Burst Taken message SHALL carry
         * a SSRC field and SDES items, CNAME and MAY carry SDES item NAME to identify the
         * PoC Client that has been granted permission to send a Talk Burst.
         *
         * The SDES item NAME SHALL be included if it is known by the PoC Server.
         * Therefore the length of the packet will vary depending on number of SDES items
         * and the size of the SDES items.
         */
        if (packet_len == 0)
            return offset;

        /* SDES type (must be NAME if present) */
        sdes_type = tvb_get_uint8(tvb, offset);
        if (sdes_type == RTCP_SDES_NAME) {
            proto_tree_add_item(PoC1_tree, hf_rtcp_sdes_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            packet_len--;

            /* Display name */
            item_len = tvb_get_uint8(tvb, offset);
            /* Item len of 1 because it's an FT_UINT_STRING... */
            proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_disp_name,
                tvb, offset, 1, ENC_ASCII | ENC_BIG_ENDIAN);
            offset++;

            col_append_fstr(pinfo->cinfo, COL_INFO, " DISPLAY-NAME=\"%s\"",
                tvb_get_string_enc(pinfo->pool, tvb, offset, item_len, ENC_ASCII));

            offset += item_len;
            packet_len = packet_len - item_len - 1;

            if (packet_len == 0) {
                return offset;
            }

            /* Move onto next 4-byte boundary */
            if (offset % 4) {
                int padding2 = (4 - (offset % 4));
                offset += padding2;
            }
        }

        /* Participants (optional) */
        if (tvb_reported_length_remaining(tvb, offset) == 0) {
            return offset;
        }
        participants_code = tvb_get_uint8(tvb, offset);
        offset += 1;
        if (participants_code != 100) { /* SHALL be 100 */
            return offset;
        }
        item_len = tvb_get_uint8(tvb, offset);
        offset += 1;
        if (item_len != 2) { /* SHALL be 2 */
            return offset;
        }

        participants = tvb_get_ntohs(tvb, offset);
        ti = proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_partic, tvb, offset, 2, ENC_BIG_ENDIAN);

        /* Append text with meanings of extreme values */
        switch (participants) {
        case 0:
            proto_item_append_text(ti, " (not known)");
            break;
        case 65535:
            proto_item_append_text(ti, " (or more)");
            break;
        default:
            break;
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, " Participants=%u",
            participants);
        offset += item_len;
    }
    break;

    case TBCP_BURST_DENY:
    {
        uint8_t reason_code;

        /* Reason code */
        reason_code = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_reason_code1, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        packet_len--;

        col_append_fstr(pinfo->cinfo, COL_INFO, " reason-code=\"%s\"",
            val_to_str_const(reason_code,
                rtcp_app_poc1_reason_code1_vals,
                "Unknown"));

        /* Reason phrase */
        item_len = tvb_get_uint8(tvb, offset);
        if (item_len != 0) {
            proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_reason1_phrase, tvb, offset, 1, ENC_ASCII | ENC_BIG_ENDIAN);
        }

        offset += (item_len + 1);
    }
    break;

    case TBCP_BURST_RELEASE:
    {
        uint16_t last_seq_no;
        /*uint16_t ignore_last_seq_no;*/

        /* Sequence number of last RTP packet in burst */
        proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_last_pkt_seq_no, tvb, offset, 2, ENC_BIG_ENDIAN);
        last_seq_no = tvb_get_ntohs(tvb, offset);

        /* Bit 16 is ignore flag */
        offset += 2;
        proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_ignore_seq_no, tvb, offset, 2, ENC_BIG_ENDIAN);
        /*ignore_last_seq_no = (tvb_get_ntohs(tvb, offset) & 0x8000);*/

                        /* XXX: Was the intention to also show the "ignore_last_seq_no' flag in COL_INFO ? */
        col_append_fstr(pinfo->cinfo, COL_INFO, " last_rtp_seq_no=%u",
            last_seq_no);

        /* 15 bits of padding follows */

        offset += 2;
    }
    break;

    case TBCP_BURST_IDLE:
        break;

    case TBCP_BURST_REVOKE:
    {
        /* Reason code */
        uint16_t reason_code = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_reason_code2, tvb, offset, 2, ENC_BIG_ENDIAN);

        /* The meaning of this field depends upon the reason code... */
        switch (reason_code)
        {
        case 1: /* Only one user */
            /* No additional info */
            break;
        case 2: /* Talk burst too long */
            /* Additional info is 16 bits with time (in seconds) client can request */
            proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_new_time_request, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            break;
        case 3: /* No permission */
            /* No additional info */
            break;
        case 4: /* Pre-empted */
            /* No additional info */
            break;
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, " reason-code=\"%s\"",
            val_to_str_const(reason_code,
                rtcp_app_poc1_reason_code2_vals,
                "Unknown"));
        offset += 4;
    }
    break;

    case TBCP_BURST_ACKNOWLEDGMENT:
    {
        uint8_t subtype;

        /* Code of message being acknowledged */
        subtype = (tvb_get_uint8(tvb, offset) & 0xf8) >> 3;
        proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_ack_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);

        col_append_fstr(pinfo->cinfo, COL_INFO, " (for %s)",
            val_to_str_const(subtype,
                rtcp_app_poc1_floor_cnt_type_vals,
                "Unknown"));

        /* Reason code only seen if subtype was Connect */
        if (subtype == TBCP_CONNECT)
        {
            proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_ack_reason_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        }

        /* 16 bits of padding follow */
        offset += 4;
    }
    break;

    case TBCP_QUEUE_STATUS_REQUEST:
        break;

    case TBCP_QUEUE_STATUS_RESPONSE:
    {
        uint16_t    position;
        proto_item* ti;

        /* Priority */
        proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_qsresp_priority, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* Queue position. 65535 indicates 'position not available' */
        position = tvb_get_ntohs(tvb, offset + 1);
        ti = proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_qsresp_position, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
        if (position == 0)
        {
            proto_item_append_text(ti, " (client is un-queued)");
        }
        if (position == 65535)
        {
            proto_item_append_text(ti, " (position not available)");
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, " position=%u", position);

        /* 1 bytes of padding  follows */

        offset += 4;
    }
    break;

    case TBCP_DISCONNECT:
        break;

    case TBCP_CONNECT:
    {
        proto_item* content;
        proto_tree* content_tree = proto_tree_add_subtree(PoC1_tree, tvb, offset, 2,
            ett_poc1_conn_contents, &content, "SDES item content");
        bool          contents[5];
        unsigned int  i;
        uint8_t       items_set = 0;

        uint16_t items_field = tvb_get_ntohs(tvb, offset);

        /* Dissect each defined bit flag in the SDES item content */
        for (i = 0; i < 5; i++)
        {
            proto_tree_add_item(content_tree, hf_rtcp_app_poc1_conn_content[i], tvb, offset, 2, ENC_BIG_ENDIAN);
            contents[i] = items_field & (1 << (15 - i));
            if (contents[i]) ++items_set;
        }

        /* Show how many flags were set */
        proto_item_append_text(content, " (%u items)", items_set);

        /* Session type */
        proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_conn_session_type, tvb, offset + 2, 1, ENC_BIG_ENDIAN);

        /* Additional indications */
        proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_conn_add_ind_mao, tvb, offset + 3, 1, ENC_BIG_ENDIAN);

        offset += 4;
        packet_len -= 4;

        /* One SDES item for every set flag in contents array */
        for (i = 0; i < array_length(contents); ++i) {
            if (contents[i]) {
                unsigned /*sdes_type2,*/ sdes_len2;
                /* (sdes_type2 not currently used...).  Could complain if type
                   doesn't match expected for item... */
                   /*sdes_type2 = tvb_get_uint8( tvb, offset );*/
                offset += 1;
                sdes_len2 = tvb_get_uint8(tvb, offset);

                /* Add SDES field indicated as present */
                proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_conn_sdes_items[i], tvb, offset, 1, ENC_BIG_ENDIAN);

                /* Move past field */
                offset += sdes_len2 + 1;
                packet_len -= (sdes_len2 + 2);
            }
        }
        break;
    }

    default:
        break;
    }

    padding = 0;
    if (offset % 4) {
        padding = (4 - (offset % 4));
    }

    if (padding) {
        proto_tree_add_item(PoC1_tree, hf_rtcp_app_data_padding, tvb, offset, padding, ENC_BIG_ENDIAN);
        offset += padding;
    }


    return offset;
}

static const value_string mcptt_floor_ind_vals[] = {
    { 0x0080, "Multi-talker" },
    { 0x0100, "Temporary group call" },
    { 0x0200, "Dual floor" },
    { 0x0400, "Queueing supported" },
    { 0x0800, "Imminent peril call" },
    { 0x1000, "Emergency call" },
    { 0x2000, "System call" },
    { 0x4000, "Broadcast group call" },
    { 0x8000, "Normal call" },
    { 0, NULL },
};

static const value_string rtcp_mcptt_rej_cause_floor_deny_vals[] = {
    { 0x1, "Another MCPTT client has permission" },
    { 0x2, "Internal floor control server error" },
    { 0x3, "Only one participant" },
    { 0x4, "Retry-after timer has not expired" },
    { 0x5, "Receive only" },
    { 0x6, "No resources available" },
    { 0x7, "Queue full" },
    { 0xff, "Other reason" },
    { 0, NULL },
};

static const value_string rtcp_mcptt_rej_cause_floor_revoke_vals[] = {
    { 0x1, "Only one MCPTT client" },
    { 0x2, "Media burst too long" },
    { 0x3, "No permission to send a Media Burst" },
    { 0x4, "Media Burst pre-empted" },
    { 0x6, "No resources available" },
    { 0xff, "Other reason" },
    { 0, NULL },
};

static const value_string rtcp_mcptt_perm_to_req_floor_vals[] = {
    { 0x0, "The receiver is not permitted to request floor" },
    { 0x1, "The receiver is permitted to request floor" },
    { 0, NULL },
};

static const value_string rtcp_mcptt_source_vals[] = {
    { 0x0, "The floor participant is the source" },
    { 0x1, "The participating MCPTT function is the source" },
    { 0x2, "The controlling MCPTT function is the source" },
    { 0x3, "The non-controlling MCPTT function is the source" },
    { 0, NULL },
};

static const value_string rtcp_mcptt_loc_type_vals[] = {
    { 0x0, "Not provided" },
    { 0x1, "ECGI" },
    { 0x2, "Tracking Area" },
    { 0x3, "PLMN ID" },
    { 0x4, "MBMS Service Area" },
    { 0x5, "MBSFN Area ID" },
    { 0x6, "Geographic coordinates" },
    { 0, NULL },
};

static int
dissect_rtcp_mcptt_location_ie(tvbuff_t* tvb, packet_info* pinfo, int offset, proto_tree* tree, uint32_t mcptt_fld_len)
{
    uint32_t loc_type;
    int start_offset = offset;
    static int * const ECGI_flags[] = {
        &hf_rtcp_mcptt_enodebid,
        &hf_rtcp_mcptt_cellid,
        NULL
    };

    /* Location  Type */
    proto_tree_add_item_ret_uint(tree, hf_rtcp_mcptt_loc_type, tvb, offset, 1, ENC_BIG_ENDIAN, &loc_type);
    offset += 1;

    switch (loc_type) {
    case 0:
        /* Not provided */
        break;
    case 1:
        /* ECGI - 56 bits = MCC + MNC + ECI*/
        dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, offset, E212_ECGI, true);
        offset += 3;
        proto_tree_add_bitmask(tree, tvb, offset, hf_rtcp_mcptt_ecgi_eci, ett_rtcp_mcptt_eci, ECGI_flags, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    case 2:
        /* Tracking Area - 40 bits = MCC + MNC + 16 bits */
        /* ECGI - 56 bits = MCC + MNC + ECI*/
        dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, offset, E212_ECGI, true);
        offset += 3;
        proto_tree_add_item(tree, hf_rtcp_mcptt_tac, tvb, offset, 2, ENC_NA);
        offset += 2;
        break;
    case 3:
        /* PLMN ID - 24 bits = MCC+MNC */
        dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, offset, E212_ECGI, true);
        offset += 3;
        break;
    case 4:
        /* MBMS Service Area - 16 bits = [0-65535] */
        proto_tree_add_item(tree, hf_rtcp_mcptt_mbms_serv_area, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        break;
    case 5:
        /* MBSFN Area ID - 8 bits = [0-255] */
        proto_tree_add_item(tree, hf_rtcp_mcptt_mbsfn_area_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;
    case 6:
        /* Geographic coordinates - 48 bits = latitude in first 24 bits + longitude in last 24 bits coded as
         * in subclause 6.1 in 3GPP TS 23.032
         * XXX Make use of dissect_geographical_description() ?
         */
        proto_tree_add_item(tree, hf_rtcp_mcptt_lat, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
        proto_tree_add_item(tree, hf_rtcp_mcptt_long, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
        break;
    default:
        proto_tree_add_expert(tree, pinfo, &ei_rtcp_mcptt_location_type, tvb, offset-1, 1);
        break;
    }
    if ((unsigned)(offset - start_offset) != mcptt_fld_len) {
        proto_tree_add_item(tree, hf_rtcp_app_data_padding, tvb, offset, offset - start_offset, ENC_BIG_ENDIAN);
        offset += (offset - start_offset);
    }

    return offset;
}

/* TS 24.380 */
static int
dissect_rtcp_app_mcpt(tvbuff_t* tvb, packet_info* pinfo, int offset, proto_tree* tree,
    int packet_len, proto_item* subtype_item, unsigned rtcp_subtype)
{

    proto_tree* sub_tree;
    uint32_t mcptt_fld_id, mcptt_fld_len;

    col_add_fstr(pinfo->cinfo, COL_INFO, "(MCPT) %s",
        val_to_str(rtcp_subtype, rtcp_mcpt_subtype_vals, "unknown (%u)"));

    proto_item_append_text(subtype_item, " %s", val_to_str(rtcp_subtype, rtcp_mcpt_subtype_vals, "unknown (%u)"));

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, packet_len, ett_rtcp_mcpt, NULL,
        "Mission Critical Push To Talk(MCPTT)");
    offset += 4;
    packet_len -= 4;

    if (packet_len == 0) {
        return offset;
    }

    if (tvb_ascii_isprint(tvb, offset, packet_len - 3)) {
        proto_tree_add_item(tree, hf_rtcp_mcptt_str, tvb, offset, packet_len, ENC_ASCII | ENC_NA);
        proto_tree_add_expert(sub_tree, pinfo, &ei_rtcp_appl_non_conformant, tvb, offset, packet_len);
        return offset + packet_len;
    }

    while (packet_len > 0) {
        proto_item* ti;
        int len_len, padding = 0;
        int start_offset = offset;
        /* Field ID 8 bits*/
        ti = proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_mcptt_fld_id, tvb, offset, 1, ENC_BIG_ENDIAN, &mcptt_fld_id);
        offset++;
        /* Length value
         * a length value which is:
         *  - one octet long, if the field ID is less than 192; and
         *  - two octets long, if the field ID is equal to or greater than 192;
         */
        if (mcptt_fld_id < 192) {
            len_len = 1;
        } else {
            len_len = 2;
        }
        proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_mcptt_fld_len, tvb, offset, len_len, ENC_BIG_ENDIAN, &mcptt_fld_len);
        offset += len_len;

        if ((1 + len_len + mcptt_fld_len) % 4) {
            padding = (4 - ((1 + len_len + mcptt_fld_len) % 4));
        }
        if (mcptt_fld_len != 0) {
            /* Field Value */
            switch (mcptt_fld_id) {
            case 0:
                /* Floor Priority */
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_priority, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;
            case 1:
                /* Duration */
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_duration, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;
            case 2:
            {
                /* Reject Cause */
                uint32_t cause = 0;
                switch (rtcp_subtype) {
                case 3:
                    /* Floor deny */
                    proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_mcptt_rej_cause_floor_deny, tvb, offset, 2, ENC_BIG_ENDIAN, &cause);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " - %s",
                        val_to_str_const(cause, rtcp_mcptt_rej_cause_floor_deny_vals, "Unknown"));
                    break;
                case 6:
                    /* Floor revoke */
                    proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_mcptt_rej_cause_floor_revoke, tvb, offset, 2, ENC_BIG_ENDIAN, &cause);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " - %s",
                        val_to_str_const(cause, rtcp_mcptt_rej_cause_floor_deny_vals, "Unknown"));
                    break;
                default:
                    proto_tree_add_item(sub_tree, hf_rtcp_mcptt_rej_cause, tvb, offset, 2, ENC_BIG_ENDIAN);
                    break;
                }
                offset += 2;
                /* If the length field is set to '2', there is no <Reject Phrase> value in the Reject Cause field */
                if (mcptt_fld_len == 2) {
                    break;
                }
                /* Reject Phrase */
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_rej_phrase, tvb, offset, mcptt_fld_len - 2, ENC_UTF_8 | ENC_NA);
                offset += (mcptt_fld_len - 2);
                break;
            }
            case 3:
                /* Queue Info*/
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_queue_pos_inf, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_queue_pri_lev, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                break;
            case 4:
            case 106:
                /* Granted Party's Identity */
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_granted_partys_id, tvb, offset, mcptt_fld_len, ENC_UTF_8 | ENC_NA);
                offset += mcptt_fld_len;
                break;
            case 5:
                /* Permission to Request the Floor */
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_perm_to_req_floor, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;
            case 6:
                /* User ID */
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_user_id, tvb, offset, mcptt_fld_len, ENC_UTF_8 | ENC_NA);
                offset += mcptt_fld_len;
                break;
            case 7:
                /* Queue Size */
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_queue_size, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;
            case 8:
                /* Message Sequence-Number */
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_msg_seq_num, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;
            case 9:
                /* Queued User ID */
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_queued_user_id, tvb, offset, mcptt_fld_len, ENC_UTF_8 | ENC_NA);
                offset += mcptt_fld_len;
                break;
            case 10:
                /* Source */
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_source, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;
            case 11:
            {
                uint32_t fld_len, num_ref;
                int rem_len = mcptt_fld_len;
                proto_tree* part_tree;
                /* Track Info */
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_queueing_cap, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                rem_len -= 1;
                proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_mcptt_part_type_len, tvb, offset, 1, ENC_BIG_ENDIAN, &fld_len);
                offset += 1;
                rem_len -= 1;
                int part_type_padding = (4 - (fld_len % 4));
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_participant_type, tvb, offset, fld_len, ENC_UTF_8 | ENC_NA);
                offset += fld_len;
                rem_len -= fld_len;
                if(part_type_padding > 0){
                    uint32_t data;
                    proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_app_data_padding, tvb, offset, part_type_padding, ENC_BIG_ENDIAN, &data);
                    if (data != 0) {
                        proto_tree_add_expert(sub_tree, pinfo, &ei_rtcp_appl_non_zero_pad, tvb, offset, part_type_padding);
                    }
                    offset += part_type_padding;
                    rem_len -= part_type_padding;
                }
                if (rem_len > 0) {
                    num_ref = 1;
                    /* Floor Participant Reference */
                    while (rem_len > 0) {
                        part_tree = proto_tree_add_subtree_format(sub_tree, tvb, offset, 4, ett_rtcp_mcptt_participant_ref, NULL, "Floor Participant Reference %u", num_ref);
                        proto_tree_add_item(part_tree, hf_rtcp_mcptt_participant_ref, tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        rem_len -= 4;
                        num_ref++;
                    }
                }
                break;
            }
            case 12:
                /* Message Type */
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_msg_type, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(sub_tree, hf_rtcp_spare16, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            case 13:
            {
                /* Floor Indicator */
                uint32_t floor_ind;
                proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_mcptt_floor_ind, tvb, offset, 2, ENC_BIG_ENDIAN, &floor_ind);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - %s",
                    val_to_str_const(floor_ind, mcptt_floor_ind_vals, "Unknown"));
                offset += 2;
                break;
            }
            case 14:
                /* SSRC */
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_ssrc, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(sub_tree, hf_rtcp_spare16, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;
            case 15:
                /* List of Granted Users */
            {
                uint32_t num_users, user_id_len;
                /* No of users */
                proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_mcptt_num_users, tvb, offset, 1, ENC_BIG_ENDIAN, &num_users);
                offset += 1;
                while (num_users > 0) {
                    proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_mcptt_user_id_len, tvb, offset, 1, ENC_BIG_ENDIAN, &user_id_len);
                    offset += 1;
                    proto_tree_add_item(sub_tree, hf_rtcp_mcptt_user_id, tvb, offset, user_id_len, ENC_UTF_8 | ENC_NA);
                    offset += user_id_len;
                    num_users--;
                }
                break;
            }
            case 16:
                /* List of SSRCs */
            {
                uint32_t num_ssrc;
                /* Number of SSRCs*/
                proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_mcptt_num_ssrc, tvb, offset, 1, ENC_BIG_ENDIAN, &num_ssrc);
                offset += 1;
                proto_tree_add_item(sub_tree, hf_rtcp_spare16, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                while (num_ssrc > 0) {
                    proto_tree_add_item(sub_tree, hf_rtcp_mcptt_ssrc, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    num_ssrc--;
                }
                break;
            }
            case 17:
                /* Functional Alias */
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_func_alias, tvb, offset, mcptt_fld_len, ENC_UTF_8 | ENC_NA);
                offset += mcptt_fld_len;
                break;

            case 18:
                /* List of Functional Aliases */
            {
                uint32_t num_fas, fa_len;
                /* No of FAs */
                proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_mcptt_num_fas, tvb, offset, 1, ENC_BIG_ENDIAN, &num_fas);
                offset += 1;
                while (num_fas > 0) {
                    proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_mcptt_fa_len, tvb, offset, 1, ENC_BIG_ENDIAN, &fa_len);
                    offset += 1;
                    proto_tree_add_item(sub_tree, hf_rtcp_mcptt_func_alias, tvb, offset, fa_len, ENC_UTF_8 | ENC_NA);
                    offset += fa_len;
                    num_fas--;
                }
                break;
            }

            case 19:
                /* Location */
                offset = dissect_rtcp_mcptt_location_ie(tvb, pinfo, offset, sub_tree, mcptt_fld_len);
                break;
            case 20:
                /* List of Locations */
            {
                uint32_t num_loc;
                /* Number of SSRCs*/
                proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_mcptt_num_loc, tvb, offset, 1, ENC_BIG_ENDIAN, &num_loc);
                offset += 1;

                while (num_loc > 0) {
                    offset = dissect_rtcp_mcptt_location_ie(tvb, pinfo, offset, sub_tree, mcptt_fld_len);
                    num_loc--;
                }
                break;
            }

            default:
                expert_add_info(pinfo, ti, &ei_rtcp_mcptt_unknown_fld);
                proto_tree_add_item(sub_tree, hf_rtcp_mcptt_fld_val, tvb, offset, mcptt_fld_len, ENC_NA);
                offset += mcptt_fld_len;
                break;
            }
        }
        if (padding) {
            uint32_t data;
            proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_app_data_padding, tvb, offset, padding, ENC_BIG_ENDIAN, &data);
            if (data != 0) {
                proto_tree_add_expert(sub_tree, pinfo, &ei_rtcp_appl_non_zero_pad, tvb, offset, padding);
            }
            offset += padding;
        }
        packet_len -= offset - start_offset;
        if (packet_len >= 4) {
            uint32_t dword = tvb_get_ntohl(tvb, offset);
            if (dword == 0) {
                /* Extra 4 zero bytes */
                proto_tree_add_expert(sub_tree, pinfo, &ei_rtcp_appl_extra_bytes, tvb, offset, 4);
                packet_len -= 4;
                offset += 4;
            }
        }
    }

    return offset;
}

/* TS 24.380 V 13.2.0*/
static int
dissect_rtcp_app_mccp(tvbuff_t* tvb, packet_info* pinfo, int offset, proto_tree* tree,
    int packet_len, proto_item* subtype_item, unsigned rtcp_subtype)
{

    proto_tree* sub_tree;
    uint32_t mccp_fld_id, mccp_fld_len;
    int total_packet_length;

    col_add_fstr(pinfo->cinfo, COL_INFO, "(MCCP) %s",
        val_to_str(rtcp_subtype, rtcp_mccp_subtype_vals, "unknown (%u)"));

    proto_item_append_text(subtype_item, " %s", val_to_str(rtcp_subtype, rtcp_mccp_subtype_vals, "unknown (%u)"));

    if (packet_len <= 0) {
        total_packet_length = tvb_reported_length_remaining(tvb, offset);
        proto_tree_add_expert_format(tree, pinfo, &ei_rtcp_length_check, tvb, offset, total_packet_length,
            "Incorrect RTCP packet length information (expected 0 bytes, found %d)",
            total_packet_length);
        packet_len = total_packet_length;
    }

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, packet_len, ett_rtcp_mcpt, NULL,
        "MBMS subchannel control");

    offset += 4;
    packet_len -= 4;

    if (packet_len == 0) {
        return offset;
    }

    while (packet_len > 0) {
        proto_item* ti;
        int padding = 0;
        int start_offset = offset;

        /* Each MBMS subchannel control specific field consists of an 8-bit <Field ID> item,
         * an 8-bit octet <Length> value item containing the length of the field value not
         * including <Field ID> or the <Length> value items.
         */
        ti = proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_mccp_field_id, tvb, offset, 1, ENC_BIG_ENDIAN, &mccp_fld_id);
        offset += 1;
        packet_len -= 1;
        proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_mccp_len, tvb, offset, 1, ENC_BIG_ENDIAN, &mccp_fld_len);
        offset += 1;
        packet_len -= 1;
        if ((2 + mccp_fld_len) % 4) {
            padding = (4 - ((2 + mccp_fld_len) % 4));
        }
        switch (mccp_fld_id) {
        case 0:
        {
            /* Subchannel */
            /*The <Audio m-line Number> value shall consist of 4 bit parameter giving the
             * number of the" m=audio" m-line in the SIP MESSAGE request announcing
             * the MBMS bearer described in 3GPP TS 24.379
             */
            uint32_t ip_ver, floor_m_line_no;
            proto_tree_add_item(sub_tree, hf_rtcp_mccp_audio_m_line_no, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* The <Floor m-line Number> value shall consist of 4 bit parameter giving the
             * number of the "m=application" m-line in the SIP MESSAGE request announcing
             * the MBMS bearer described in 3GPP TS 24.379 */
            proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_mccp_floor_m_line_no, tvb, offset, 1, ENC_BIG_ENDIAN, &floor_m_line_no);
            offset += 1;
            /* IP version */
            proto_tree_add_item_ret_uint(sub_tree, hf_rtcp_mccp_ip_version, tvb, offset, 1, ENC_BIG_ENDIAN, &ip_ver);
            offset += 1;
            /* Floor Port Number
             * If the <Floor m-line Number> value is equal to '0',
             * the <Floor control Port Number> value is not included in the MBMS Subchannel field.
             */
            if (floor_m_line_no > 0) {
                proto_tree_add_item(sub_tree, hf_rtcp_mccp_floor_port_no, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }
            /* Media Port Number */
            proto_tree_add_item(sub_tree, hf_rtcp_mccp_media_port_no, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            /* IP Address */
            if (ip_ver == 0) {
                proto_tree_add_item(sub_tree, hf_rtcp_mccp_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            } else {
                proto_tree_add_item(sub_tree, hf_rtcp_mccp_ipv6, tvb, offset, 16, ENC_NA);
                offset += 16;
            }
        }
            break;
        case 1:
            /* TMGI */
        {
            proto_tree* tmgi_tree;
            ti = proto_tree_add_item(sub_tree, hf_rtcp_mccp_tmgi, tvb, offset, mccp_fld_len, ENC_NA);
            tmgi_tree = proto_item_add_subtree(ti, ett_rtcp_mccp_tmgi);
            de_sm_tmgi(tvb, tmgi_tree, pinfo, offset, mccp_fld_len, NULL, 0);
            offset += mccp_fld_len;
        }
            break;
        case 3:
            /* MCPTT Group ID */
            proto_tree_add_item(sub_tree, hf_rtcp_mcptt_group_id, tvb, offset, mccp_fld_len, ENC_UTF_8 | ENC_NA);
            offset += mccp_fld_len;
            break;
        default:
            expert_add_info(pinfo, ti, &ei_rtcp_mcptt_unknown_fld);
            proto_tree_add_item(sub_tree, hf_rtcp_mcptt_fld_val, tvb, offset, mccp_fld_len, ENC_NA);
            offset += mccp_fld_len;
            break;
        }
        if (padding) {
            proto_tree_add_item(sub_tree, hf_rtcp_app_data_padding, tvb, offset, padding, ENC_BIG_ENDIAN);
            offset += padding;
        }
        packet_len -= offset - start_offset;
        if (packet_len >= 4) {
            uint32_t dword;
            if (mccp_fld_len % 4) {
                dword = tvb_get_ntohl(tvb, offset);
                padding = (4 - (mccp_fld_len % 4));
                dword = dword >> (padding * 8);
                if (dword == 0) {
                    /* Extra 4 zero bytes */
                    proto_tree_add_expert(sub_tree, pinfo, &ei_rtcp_appl_extra_bytes, tvb, offset, padding);
                    packet_len -= padding;
                    offset += padding;
                }
            }
        }

    }
    return offset;
}
static int
dissect_rtcp_app( tvbuff_t *tvb,packet_info *pinfo, int offset, proto_tree *tree, int packet_len,
                  proto_item *subtype_item, unsigned rtcp_subtype, uint32_t app_length )
{

    const uint8_t* ascii_name;
    bool is_ascii;

    /* XXX If more application types are to be dissected it may be useful to use a table like in packet-sip.c */
    static const char poc1_app_name_str[] = "PoC1";
    static const char mux_app_name_str[] = "3GPP";

    /* Application Name (ASCII) */
    is_ascii = tvb_ascii_isprint(tvb, offset, 4);
    if (is_ascii) {
        proto_tree_add_item_ret_string(tree, hf_rtcp_name_ascii, tvb, offset, 4, ENC_ASCII | ENC_NA, pinfo->pool, &ascii_name);
    } else {
        proto_tree_add_expert(tree, pinfo, &ei_rtcp_appl_not_ascii, tvb, offset, 4);
    }

    /* Applications specific data */
    if (rtcp_padding_set) {
        /* If there's padding present, we have to remove that from the data part
        * The last octet of the packet contains the length of the padding
        */
        packet_len -= tvb_get_uint8(tvb, offset + packet_len - 1);
    }

    if (is_ascii) {
        /* See if we can handle this application type */
        if (g_ascii_strncasecmp(ascii_name, poc1_app_name_str, 4) == 0)
        {
            offset = dissect_rtcp_app_poc1(tvb, pinfo, offset, tree, packet_len, subtype_item, rtcp_subtype);
        } else if (g_ascii_strncasecmp(ascii_name, mux_app_name_str, 4) == 0)
        {
            /* 3GPP Nb protocol extension (3GPP 29.414) for RTP Multiplexing */
            col_append_fstr(pinfo->cinfo, COL_INFO, "( %s ) subtype=%u", ascii_name, rtcp_subtype);
            offset += 4;
            packet_len -= 4;
            /* Applications specific data */
            if (rtcp_padding_set) {
                /* If there's padding present, we have to remove that from the data part
                * The last octet of the packet contains the length of the padding
                */
                packet_len -= tvb_get_uint8(tvb, offset + packet_len - 1);
            }
            if (packet_len == 4)
            {
                uint16_t local_port = 0;

                proto_item* mux_item = proto_tree_add_item(tree, hf_rtcp_app_mux, tvb, offset, packet_len, ENC_NA);
                proto_tree* mux_tree = proto_item_add_subtree(mux_item, ett_mux);
                proto_tree_add_item(mux_tree, hf_rtcp_app_mux_mux, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(mux_tree, hf_rtcp_app_mux_cp, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(mux_tree, hf_rtcp_app_mux_selection, tvb, offset, 1, ENC_BIG_ENDIAN);
                local_port = tvb_get_ntohs(tvb, offset + 2);
                proto_tree_add_uint(mux_tree, hf_rtcp_app_mux_localmuxport, tvb, offset + 2, 2, local_port * 2);
            } else
            {
                /* fall back to just showing the data if it's the wrong length */
                proto_tree_add_item(tree, hf_rtcp_app_data, tvb, offset, packet_len, ENC_NA);
            }
            if ((int)(offset + packet_len) >= offset)
                offset += packet_len;
            return offset;
        } else if (g_ascii_strncasecmp(ascii_name, "MCPT", 4) == 0) {
            offset = dissect_rtcp_app_mcpt(tvb, pinfo, offset, tree, packet_len, subtype_item, rtcp_subtype);
        } else if (g_ascii_strncasecmp(ascii_name, "MCCP", 4) == 0) {
            offset = dissect_rtcp_app_mccp(tvb, pinfo, offset, tree, packet_len, subtype_item, rtcp_subtype);
        } else {
            tvbuff_t* next_tvb;     /* tvb to pass to subdissector */
            /* tvb         == Pass the entire APP payload so the subdissector can have access to the
             * entire data set
             */
            next_tvb = tvb_new_subset_length(tvb, offset - 8, app_length + 4);
            /* look for registered sub-dissectors */
            if (dissector_try_string(rtcp_dissector_table, ascii_name, next_tvb, pinfo, tree, NULL)) {
                /* found subdissector - return tvb_reported_length */
                offset += 4;
                packet_len -= 4;
                if (rtcp_padding_set) {
                    /* If there's padding present, we have to remove that from the data part
                    * The last octet of the packet contains the length of the padding
                    */
                    packet_len -= tvb_get_uint8(tvb, offset + packet_len - 1);
                }
                if ((int)(offset + packet_len) >= offset)
                    offset += packet_len;
                return offset;
            } else
            {
                /* Unhandled application type, just show app name and raw data */
                col_append_fstr(pinfo->cinfo, COL_INFO, "( %s ) subtype=%u", ascii_name, rtcp_subtype);
                offset += 4;
                packet_len -= 4;
                /* Applications specific data */
                if (rtcp_padding_set) {
                    /* If there's padding present, we have to remove that from the data part
                    * The last octet of the packet contains the length of the padding
                    */
                    packet_len -= tvb_get_uint8(tvb, offset + packet_len - 1);
                }
                if (tvb_ascii_isprint(tvb, offset, packet_len)) {
                    proto_tree_add_item(tree, hf_rtcp_app_data_str, tvb, offset, packet_len, ENC_ASCII | ENC_NA);
                } else {
                    proto_tree_add_item(tree, hf_rtcp_app_data, tvb, offset, packet_len, ENC_NA);
                }
                if ((int)(offset + packet_len) >= offset)
                    offset += packet_len;
            }
        }
    } else {
        /* Unhandled application type, just show subtype and raw data */
        col_append_fstr(pinfo->cinfo, COL_INFO, "subtype=%u", rtcp_subtype);
        offset += 4;
        packet_len -= 4;
        /* Applications specific data */
        if (rtcp_padding_set) {
            /* If there's padding present, we have to remove that from the data part
            * The last octet of the packet contains the length of the padding
            */
            packet_len -= tvb_get_uint8(tvb, offset + packet_len - 1);
        }
        if (tvb_ascii_isprint(tvb, offset, packet_len)) {
            proto_tree_add_item(tree, hf_rtcp_app_data_str, tvb, offset, packet_len, ENC_ASCII | ENC_NA);
        } else {
            proto_tree_add_item(tree, hf_rtcp_app_data, tvb, offset, packet_len, ENC_NA);
        }
        if ((int)(offset + packet_len) >= offset)
            offset += packet_len;
    }
    return offset;
}


static int
dissect_rtcp_bye( tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree,
    int count, int packet_length )
{
    int chunk;
    unsigned int reason_length = 0;
    int          reason_offset = 0;

    chunk = 1;
    while ( chunk <= count ) {
        /* source identifier, 32 bits */
        proto_tree_add_item( tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        chunk++;
    }

    if (count * 4 < packet_length) {
        /* Bye reason consists of an 8 bit length l and a string with length l */
        reason_length = tvb_get_uint8( tvb, offset );
        proto_tree_add_item( tree, hf_rtcp_sdes_length, tvb, offset, 1, ENC_BIG_ENDIAN );
        offset++;

        reason_offset = offset;
        proto_tree_add_item( tree, hf_rtcp_sdes_text, tvb, offset, reason_length, ENC_ASCII);
        offset += reason_length;
    }

    /* BYE packet padded out if string didn't fit in previous word */
    if (offset % 4)
    {
        int pad_size = (4 - (offset % 4));
        int i;

        /* Check padding */
        for (i = 0; i < pad_size; i++)
        {
            if ((!(tvb_offset_exists(tvb, offset + i))) ||
                (tvb_get_uint8(tvb, offset + i) != 0))
            {
                proto_tree_add_expert(tree, pinfo, &ei_rtcp_bye_reason_not_padded, tvb, reason_offset, reason_length);
            }
        }

        offset += pad_size;
    }

    return offset;
}

static int
dissect_rtcp_sdes( tvbuff_t *tvb, int offset, proto_tree *tree, int count )
{
    int           chunk;
    proto_item   *sdes_item;
    proto_tree   *sdes_tree;
    proto_tree   *sdes_item_tree;
    proto_item   *ti;
    int           start_offset;
    int           items_start_offset;
    uint32_t      ssrc;
    unsigned int  item_len;
    unsigned int  sdes_type;
    unsigned int  prefix_len;

    chunk = 1;
    while ( chunk <= count ) {
        /* Create a subtree for this chunk; we don't yet know
           the length. */
        start_offset = offset;

        ssrc = tvb_get_ntohl( tvb, offset );
        sdes_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1,
            ett_sdes, &sdes_item, "Chunk %u, SSRC/CSRC 0x%X", chunk, ssrc);

        /* SSRC_n source identifier, 32 bits */
        proto_tree_add_item( sdes_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );
        offset += 4;

        /* Create a subtree for the SDES items; we don't yet know
           the length */
        items_start_offset = offset;
        sdes_item_tree = proto_tree_add_subtree(sdes_tree, tvb, offset, -1,
            ett_sdes_item, &ti, "SDES items" );

        /*
         * Not every message is ended with "null" bytes, so check for
         * end of frame as well.
         */
        while ( tvb_reported_length_remaining( tvb, offset ) > 0 ) {
            /* ID, 8 bits */
            sdes_type = tvb_get_uint8( tvb, offset );
            proto_tree_add_item( sdes_item_tree, hf_rtcp_sdes_type, tvb, offset, 1, ENC_BIG_ENDIAN );
            offset++;

            if ( sdes_type == RTCP_SDES_END ) {
                /* End of list */
                break;
            }

            /* Item length, 8 bits */
            item_len = tvb_get_uint8( tvb, offset );
            proto_tree_add_item( sdes_item_tree, hf_rtcp_sdes_length, tvb, offset, 1, ENC_BIG_ENDIAN );
            offset++;

            if ( item_len != 0 ) {
                if ( sdes_type == RTCP_SDES_PRIV ) {
                    /* PRIV adds two items between the
                     * SDES length and value - an 8 bit
                     * length giving the length of a
                     * "prefix string", and the string.
                     */
                    prefix_len = tvb_get_uint8( tvb, offset );
                    if ( prefix_len + 1 > item_len ) {
                        proto_tree_add_uint_format_value( sdes_item_tree,
                            hf_rtcp_sdes_prefix_len, tvb,
                            offset, 1, prefix_len,
                            "%u (bogus, must be <= %u)",
                            prefix_len, item_len - 1);
                        offset += item_len;
                        continue;
                    }
                    proto_tree_add_item( sdes_item_tree, hf_rtcp_sdes_prefix_len, tvb, offset, 1, ENC_BIG_ENDIAN );
                    offset++;

                    proto_tree_add_item( sdes_item_tree, hf_rtcp_sdes_prefix_string, tvb, offset, prefix_len, ENC_ASCII );
                    offset   += prefix_len;
                    item_len -= prefix_len +1;
                    if ( item_len == 0 )
                        continue;
                }
                proto_tree_add_item( sdes_item_tree, hf_rtcp_sdes_text, tvb, offset, item_len, ENC_ASCII );
                offset += item_len;
            }
        }

        /* Set the length of the items subtree. */
        proto_item_set_len(ti, offset - items_start_offset);

        /* 32 bits = 4 bytes, so.....
         * If offset % 4 != 0, we divide offset by 4, add one and then
         * multiply by 4 again to reach the boundary
         */
        if ( offset % 4 != 0 )
            offset = ((offset / 4) + 1 ) * 4;

        /* Set the length of this chunk. */
        proto_item_set_len(sdes_item, offset - start_offset);

        chunk++;
    }

    return offset;
}

static void parse_xr_type_specific_field(tvbuff_t *tvb, int offset, unsigned block_type,
                                         proto_tree *tree, uint8_t *thinning)
{
    static int * const flags[] = {
        &hf_rtcp_xr_stats_loss_flag,
        &hf_rtcp_xr_stats_dup_flag,
        &hf_rtcp_xr_stats_jitter_flag,
        &hf_rtcp_xr_stats_ttl,
        NULL
    };

    switch (block_type) {
        case RTCP_XR_LOSS_RLE:
        case RTCP_XR_DUP_RLE:
        case RTCP_XR_PKT_RXTIMES:
            *thinning = tvb_get_uint8(tvb, offset) & 0x0F;
            proto_tree_add_item(tree, hf_rtcp_xr_thinning, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;

        case RTCP_XR_STATS_SUMRY:
            proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);
            break;

        default:
            proto_tree_add_item(tree, hf_rtcp_xr_block_specific, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
    }
}

static bool validate_xr_block_length(tvbuff_t *tvb, packet_info *pinfo, int offset, unsigned block_type, unsigned block_len, proto_tree *tree)
{
    proto_item *ti;

    ti = proto_tree_add_uint(tree, hf_rtcp_xr_block_length, tvb, offset, 2, block_len);
    proto_item_append_text(ti, " (%u bytes)", (block_len)*4);
    switch (block_type) {
        case RTCP_XR_REF_TIME:
            if (block_len != 2)
                expert_add_info_format(pinfo, ti, &ei_rtcp_xr_block_length_bad, "Invalid block length, should be 2");
            return false;

        case RTCP_XR_STATS_SUMRY:
            if (block_len != 9)
                expert_add_info_format(pinfo, ti, &ei_rtcp_xr_block_length_bad, "Invalid block length, should be 9");
            return false;

        case RTCP_XR_VOIP_METRCS:
        case RTCP_XR_BT_XNQ:
            if (block_len != 8)
                expert_add_info_format(pinfo, ti, &ei_rtcp_xr_block_length_bad, "Invalid block length, should be 8");
            return false;

        case RTCP_XR_IDMS:
            if (block_len != 7)
                expert_add_info_format(pinfo, ti, &ei_rtcp_xr_block_length_bad, "Invalid block length, should be 7");
            return false;

        default:
            break;
    }
    return true;
}

static int
dissect_rtcp_xr(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree, int packet_len)
{
    unsigned    block_num;

    /* Packet length should at least be 4 */
    if (packet_len < 4) {
        proto_tree_add_expert(tree, pinfo, &ei_rtcp_missing_sender_ssrc, tvb, offset, packet_len);
        return offset + packet_len;
    }

    if (rtcp_padding_set) {
        /* If there's padding present, we have to remove that from the data part
        * The last octet of the packet contains the length of the padding
        */
        packet_len -= tvb_get_uint8(tvb, offset + packet_len - 1);
    }

    /* SSRC */
    proto_tree_add_item( tree, hf_rtcp_ssrc_sender, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset     += 4;
    packet_len -= 4;

    for( block_num = 1; packet_len > 0; block_num++) {
        unsigned block_type     = tvb_get_uint8(tvb, offset), block_length = 0;
        int   content_length = 0;
        uint8_t thinning = 0;
        /*bool valid = true;*/

        /* Create a subtree for this block, don't know the length yet*/
        proto_item *block;
        proto_tree *xr_block_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_xr_block, &block, "Block %u", block_num);
        proto_tree *content_tree;

        proto_tree_add_item(xr_block_tree, hf_rtcp_xr_block_type, tvb, offset, 1, ENC_BIG_ENDIAN);

        if (packet_len >= 2) {
            parse_xr_type_specific_field(tvb, offset + 1, block_type, xr_block_tree, &thinning);
            if (packet_len >= 4) {
                block_length = tvb_get_ntohs(tvb, offset + 2);
                /* XXX: What if false return from the following ?? */
                /*valid =*/ validate_xr_block_length(tvb, pinfo, offset + 2, block_type, block_length, xr_block_tree);
            }
        } else {
            expert_add_info(pinfo, block, &ei_rtcp_missing_block_header);
            return offset + packet_len;
        }

        content_length = block_length * 4;
        proto_item_set_len(block, content_length + 4);

        if (content_length > packet_len) {
            expert_add_info(pinfo, block, &ei_rtcp_block_length);
        }

        offset     += 4;
        packet_len -= 4;

        content_tree = proto_tree_add_subtree(xr_block_tree, tvb, offset, content_length, ett_xr_block_contents, NULL, "Contents");

        switch (block_type) {
        case RTCP_XR_VOIP_METRCS: {
            unsigned fraction_rate;

            /* Identifier */
            proto_tree_add_item(content_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Loss Rate */
            fraction_rate = tvb_get_uint8(tvb, offset);
            proto_tree_add_uint_format_value(content_tree, hf_rtcp_ssrc_fraction, tvb, offset, 1,
                                       fraction_rate, "%u / 256", fraction_rate);
            offset++;

            /* Discard Rate */
            fraction_rate = tvb_get_uint8(tvb, offset);
            proto_tree_add_uint_format_value(content_tree, hf_rtcp_ssrc_discarded, tvb, offset, 1,
                                       fraction_rate, "%u / 256", fraction_rate);
            offset++;

            /* Burst Density */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_burst_density, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* Gap Density */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_gap_density, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* Burst Duration */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_burst_duration, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Gap Duration */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_gap_duration, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Round Trip Delay */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_rtdelay, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* End System Delay */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_esdelay, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Signal Level */
            if (tvb_get_uint8(tvb, offset) == 0x7f)
                proto_tree_add_int_format_value(content_tree, hf_rtcp_xr_voip_metrics_siglevel, tvb, offset, 1, 0x7f, "Unavailable");
            else
                proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_siglevel, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* Noise Level */
            if (tvb_get_uint8(tvb, offset) == 0x7f)
                proto_tree_add_int_format_value(content_tree, hf_rtcp_xr_voip_metrics_noiselevel, tvb, offset, 1, 0x7f, "Unavailable");
            else
                proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_noiselevel, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* RERL */
            if (tvb_get_uint8(tvb, offset) == 0x7f)
                proto_tree_add_uint_format_value(content_tree, hf_rtcp_xr_voip_metrics_rerl, tvb, offset, 1, 0x7f, "Unavailable");
            else
                proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_rerl, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* GMin */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_gmin, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* R factor */
            if (tvb_get_uint8(tvb, offset) == 0x7f)
                proto_tree_add_uint_format_value(content_tree, hf_rtcp_xr_voip_metrics_rfactor, tvb, offset, 1, 0x7f, "Unavailable");
            else
                proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_rfactor, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* external R Factor */
            if (tvb_get_uint8(tvb, offset) == 0x7f)
                proto_tree_add_uint_format_value(content_tree, hf_rtcp_xr_voip_metrics_extrfactor, tvb, offset, 1, 0x7f, "Unavailable");
            else
                proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_extrfactor, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* MOS LQ */
            if (tvb_get_uint8(tvb, offset) == 0x7f)
                proto_tree_add_float_format_value(content_tree, hf_rtcp_xr_voip_metrics_moslq, tvb, offset, 1, 0x7f, "Unavailable");
            else
                proto_tree_add_float(content_tree, hf_rtcp_xr_voip_metrics_moslq, tvb, offset, 1,
                                 (float) (tvb_get_uint8(tvb, offset) / 10.0));
            offset++;

            /* MOS CQ */
            if (tvb_get_uint8(tvb, offset) == 0x7f)
                proto_tree_add_float_format_value(content_tree, hf_rtcp_xr_voip_metrics_moscq, tvb, offset, 1, 0x7f, "Unavailable");
            else
                proto_tree_add_float(content_tree, hf_rtcp_xr_voip_metrics_moscq, tvb, offset, 1,
                                     (float) (tvb_get_uint8(tvb, offset) / 10.0));
            offset++;

            /* PLC, JB Adaptive, JB Rate */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_plc, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_jbadaptive, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_jbrate, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 2; /* skip over reserved bit */

            /* JB Nominal */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_jbnominal, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* JB Max */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_jbmax, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* JB Abs max */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_jbabsmax, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            break;
        }

        case RTCP_XR_STATS_SUMRY: {
            /* Identifier */
            proto_tree_add_item(content_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Begin Seq */
            proto_tree_add_item(content_tree, hf_rtcp_xr_beginseq, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* End Seq */
            proto_tree_add_item(content_tree, hf_rtcp_xr_endseq, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Lost Pkts */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_lost, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Dup Pkts */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_dups, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Min Jitter */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_minjitter, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Max Jitter */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_maxjitter, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Mean Jitter */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_meanjitter, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Dev Jitter */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_devjitter, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Min TTL */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_minttl, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset ++;

            /* Max TTL */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_maxttl, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset ++;

            /* Mean TTL */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_meanttl, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset ++;

            /* Dev TTL */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_devttl, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset ++;

            break;
        }

        case RTCP_XR_REF_TIME: {
            proto_tree_add_item(content_tree, hf_rtcp_xr_timestamp, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            offset += 8;
            break;
        }

        case RTCP_XR_DLRR: {
            /* Each report block is 12 bytes */
            int sources = content_length / 12;
            int counter = 0;
            for(counter = 0; counter < sources; counter++) {
                /* Create a new subtree for a length of 12 bytes */
                proto_tree *ssrc_tree = proto_tree_add_subtree_format(content_tree, tvb, offset, 12, ett_xr_ssrc, NULL, "Source %u", counter + 1);

                /* SSRC_n source identifier, 32 bits */
                proto_tree_add_item(ssrc_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                /* Last RR timestamp */
                proto_tree_add_item(ssrc_tree, hf_rtcp_xr_lrr, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                /* Delay since last RR timestamp */
                proto_tree_add_item(ssrc_tree, hf_rtcp_xr_dlrr, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }

            if (content_length % 12 != 0)
                offset += content_length % 12;
            break;
        }

        case RTCP_XR_PKT_RXTIMES: {
            /* 8 bytes of fixed header */
            uint32_t rcvd_time;
            int count = 0, skip = 8;
            uint16_t begin = 0;

            /* Identifier */
            proto_tree_add_item(content_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Begin Seq */
            begin = tvb_get_ntohs(tvb, offset);
            /* Apply Thinning value */
            begin = (begin + ((1<<thinning)-1)) & ~((1<<thinning)-1);
            proto_tree_add_item(content_tree, hf_rtcp_xr_beginseq, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* End Seq */
            proto_tree_add_item(content_tree, hf_rtcp_xr_endseq, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            for(count = 0; skip < content_length; skip += 4, count++) {
                rcvd_time = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint_format(content_tree, hf_rtcp_xr_receipt_time_seq, tvb,
                                           offset, 4, rcvd_time, "Seq: %u, Receipt Time: %u",
                                           (begin + (count<<thinning)) % 65536, rcvd_time);
                offset += 4;
            }
            break;
        }

        case RTCP_XR_LOSS_RLE:
        case RTCP_XR_DUP_RLE: {
            /* 8 bytes of fixed header */
            int count = 0, skip = 8;
            proto_tree *chunks_tree;

            /* Identifier */
            proto_tree_add_item(content_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* Begin Seq */
            proto_tree_add_item(content_tree, hf_rtcp_xr_beginseq, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* End Seq */
            proto_tree_add_item(content_tree, hf_rtcp_xr_endseq, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* report Chunks */
            chunks_tree = proto_tree_add_subtree(content_tree, tvb, offset, content_length, ett_xr_loss_chunk, NULL, "Report Chunks");

            for(count = 1; skip < content_length; skip += 2, count++) {
                unsigned value = tvb_get_ntohs(tvb, offset);

                if (value == 0) {
                    proto_tree_add_none_format(chunks_tree, hf_rtcp_xr_chunk_null_terminator, tvb, offset, 2, "Chunk: %u -- Null Terminator ",
                                        count);
                } else if ( ! ( value & 0x8000 )) {
                    const char *run_type = (value & 0x4000) ? "1s" : "0s";
                    value &= 0x3FFF;
                    proto_tree_add_uint_format(chunks_tree, hf_rtcp_xr_chunk_length, tvb, offset, 2, value, "Chunk: %u -- Length Run %s, length: %u",
                                        count, run_type, value);
                } else {
                    proto_tree_add_uint_format(chunks_tree, hf_rtcp_xr_chunk_bit_vector, tvb, offset, 2, value &  0x7FFF,
                                        "Chunk: %u -- Bit Vector 0x%x", count, value &  0x7FFF);
                }
                offset += 2;
            }

            break;
        }
        case RTCP_XR_BT_XNQ: {                                      /* BT XNQ block as defined in RFC5093 */
            unsigned temp_value; /* used when checking spare bits in block type 8 */

            proto_tree_add_item(content_tree, hf_rtcp_xr_btxnq_begseq, tvb, offset, 2, ENC_BIG_ENDIAN);          /* Begin Sequence number */
            proto_tree_add_item(content_tree, hf_rtcp_xr_btxnq_endseq, tvb, offset+2, 2, ENC_BIG_ENDIAN);        /* End Sequence number */
            offset += 4;

            proto_tree_add_item(content_tree, hf_rtcp_xr_btxnq_vmaxdiff, tvb, offset, 2, ENC_BIG_ENDIAN);        /* vmaxdiff */
            proto_tree_add_item(content_tree, hf_rtcp_xr_btxnq_vrange, tvb, offset+2, 2, ENC_BIG_ENDIAN);        /* vrange */
            offset += 4;

            proto_tree_add_item(content_tree, hf_rtcp_xr_btxnq_vsum, tvb, offset, 4, ENC_BIG_ENDIAN);            /* vsum */
            offset += 4;

            proto_tree_add_item(content_tree, hf_rtcp_xr_btxnq_cycles, tvb, offset, 2, ENC_BIG_ENDIAN);          /* cycle count */
            proto_tree_add_item(content_tree, hf_rtcp_xr_btxnq_jbevents, tvb, offset+2, 2, ENC_BIG_ENDIAN);      /* jitter buffer events */
            offset += 4;

            temp_value = tvb_get_ntohl(tvb, offset);                                                    /* tDegNet */
            if ((temp_value & 0x0ff000000) != 0)
                proto_tree_add_string(content_tree, hf_rtcp_xr_btxnq_spare, tvb, offset, 1, "Warning - spare bits not 0");
            proto_tree_add_uint(content_tree, hf_rtcp_xr_btxnq_tdegnet, tvb, offset+1, 3, temp_value & 0x0ffffff);
            offset += 4;

            temp_value = tvb_get_ntohl(tvb, offset);                                                    /* tDegJit */
            if ((temp_value & 0x0ff000000) != 0)
                proto_tree_add_string(content_tree, hf_rtcp_xr_btxnq_spare, tvb, offset, 1, "Warning - spare bits not 0");
            proto_tree_add_uint(content_tree, hf_rtcp_xr_btxnq_tdegjit, tvb, offset+1, 3, temp_value & 0x0ffffff);
            offset += 4;

            temp_value = tvb_get_ntohl(tvb, offset);                                                    /* ES */
            if ((temp_value & 0x0ff000000) != 0)
                proto_tree_add_string(content_tree, hf_rtcp_xr_btxnq_spare, tvb, offset, 1, "Warning - spare bits not 0");
            proto_tree_add_uint(content_tree, hf_rtcp_xr_btxnq_es, tvb, offset+1, 3, temp_value & 0x0ffffff);
            offset += 4;

            temp_value = tvb_get_ntohl(tvb, offset);                                                    /* SES */
            if ((temp_value & 0x0ff000000) != 0)
                proto_tree_add_string(content_tree, hf_rtcp_xr_btxnq_spare, tvb, offset, 1, "Warning - spare bits not 0");
            proto_tree_add_uint(content_tree, hf_rtcp_xr_btxnq_ses, tvb, offset+1, 3, temp_value & 0x0ffffff);
            offset += 4;

            break;
        }
        case RTCP_XR_IDMS: {
            proto_item *item;
            int         hour,min,sec,msec;
            uint32_t    tmp_ts;
            offset -= 3;
            proto_tree_add_item(content_tree, hf_rtcp_xr_idms_spst, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset+=3;
            proto_tree_add_item(content_tree, hf_rtcp_xr_idms_pt, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(content_tree, hf_rtcp_xr_idms_msci, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(content_tree, hf_rtcp_xr_idms_source_ssrc, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(content_tree, hf_rtcp_xr_idms_ntp_rcv_ts, tvb, offset, 8, ENC_BIG_ENDIAN);
            item = proto_tree_add_item(content_tree, hf_rtcp_ntp, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            proto_item_set_generated(item);

            proto_tree_add_item(content_tree, hf_rtcp_xr_idms_rtp_ts, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;

            tmp_ts = tvb_get_ntohl(tvb,offset);
            hour   = (  (int) ( tmp_ts >> 16 ) ) / 3600;
            min    = (( (int) ( tmp_ts >> 16 ) ) - hour * 3600) / 60;
            sec    = (( (int) ( tmp_ts >> 16 ) ) - hour * 3600 - min * 60);
            msec   = (  (int) ( tmp_ts & 0x0000FFFF ) ) / 66;
            proto_tree_add_uint_format_value(content_tree, hf_rtcp_xr_idms_ntp_pres_ts, tvb, offset, 4, tmp_ts,
                                             "%d:%02d:%02d:%03d [h:m:s:ms]", hour,min,sec,msec);
            offset+=4;
        }
            break;
        default:
            /* skip over the unknown block */
            offset += content_length;
            break;
        } /* switch (block_type) */
        packet_len -= content_length;
    } /* for (block_num = ...) */
    return offset;
}

static int
dissect_rtcp_avb( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree,
    int packet_length _U_ )
{
    /* SSRC / CSRC */
    proto_tree_add_item( tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* Name (ASCII) */
    proto_tree_add_item( tree, hf_rtcp_name_ascii, tvb, offset, 4, ENC_ASCII );
    offset += 4;

    /* TimeBase Indicator */
    proto_tree_add_item( tree, hf_rtcp_timebase_indicator, tvb, offset, 2, ENC_BIG_ENDIAN );
    offset += 2;

    /* Identity */
    proto_tree_add_item( tree, hf_rtcp_identity, tvb, offset, 10, ENC_NA );
    offset += 10;

    /* Stream id, 64 bits */
    proto_tree_add_item( tree, hf_rtcp_stream_id, tvb, offset, 8, ENC_BIG_ENDIAN );
    offset += 8;

    /* AS timestamp, 32 bits */
    proto_tree_add_item( tree, hf_rtcp_as_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* RTP timestamp, 32 bits */
    proto_tree_add_item( tree, hf_rtcp_rtp_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    return offset;
}

static int
dissect_rtcp_rsi( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree,
    int packet_length )
{
    proto_item *item;

    /* SSRC / CSRC */
    proto_tree_add_item( tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* SSRC / CSRC */
    proto_tree_add_item( tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* NTP timestamp */
    proto_tree_add_item(tree, hf_rtcp_ntp_msw, tvb, offset, 4, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_rtcp_ntp_lsw, tvb, offset+4, 4, ENC_BIG_ENDIAN);

    item = proto_tree_add_item(tree, hf_rtcp_ntp, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
    proto_item_set_generated(item);
    offset += 8;

    /* Sub report blocks */

    return offset + (packet_length - 16);
}

static int
dissect_rtcp_token( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree,
                    int packet_len, unsigned rtcp_subtype _U_ )
{
    /* SSRC / CSRC */
    proto_tree_add_item( tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* subtypes */

    return offset + (packet_len - 4);
}

static int
dissect_ms_profile_specific_extensions(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pse_tree, void *data _U_)
{
    int16_t extension_type;
    int16_t extension_length;
    proto_item *pse_item;
    proto_item *item;
    int offset = 0;

    extension_type   = tvb_get_ntohs (tvb, offset);
    extension_length = tvb_get_ntohs (tvb, offset+2);
    if (extension_length < 4) {
        extension_length = 4; /* expert info? */
    }

    pse_item = proto_tree_get_parent(pse_tree);
    proto_item_append_text(pse_item, " (%s)",
            val_to_str_const(extension_type, rtcp_ms_profile_extension_vals, "Unknown"));
    col_append_fstr(pinfo->cinfo, COL_INFO, "PSE:%s  ",
                  val_to_str_const(extension_type, rtcp_ms_profile_extension_vals, "Unknown"));

    proto_tree_add_item(pse_tree, hf_rtcp_profile_specific_extension_type, tvb, offset,
            2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(pse_tree, hf_rtcp_profile_specific_extension_length, tvb, offset,
            2, ENC_BIG_ENDIAN);
    offset += 2;

    switch (extension_type)
    {
    case 1:
        /* MS Estimated Bandwidth */
        item = proto_tree_add_item(pse_tree, hf_rtcp_ssrc_sender, tvb, offset, 4, ENC_BIG_ENDIAN);
        /* Decode if it is NONE or ANY and add to line */
        proto_item_append_text(item," %s", val_to_str_const(tvb_get_ntohl (tvb, offset), rtcp_ssrc_values, ""));
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_bandwidth, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
        /* Confidence level byte is optional so check length first */
        if (extension_length == 16)
        {
            proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_confidence_level, tvb, offset + 8, 1, ENC_BIG_ENDIAN);
        }
        break;
    case 4:
        /* MS Packet Loss Notification */
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_seq_num, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        break;
    case 5:
        /* MS Video Preference */
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_frame_resolution_width, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_frame_resolution_height, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_bitrate, tvb, offset + 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_frame_rate, tvb, offset + 12, 2, ENC_BIG_ENDIAN);
        break;
    case 7:
        /* MS Policy Server Bandwidth */
        /* First 4 bytes are reserved */
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_bandwidth, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
        break;
    case 8:
        /* MS TURN Server Bandwidth */
        /* First 4 bytes are reserved */
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_bandwidth, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
        break;
    case 9:
        /* MS Audio Healer Metrics */
        item = proto_tree_add_item(pse_tree, hf_rtcp_ssrc_sender, tvb, offset, 4, ENC_BIG_ENDIAN);
        /* Decode if it is NONE or ANY and add to line */
        proto_item_append_text(item," %s", val_to_str_const(tvb_get_ntohl (tvb, offset), rtcp_ssrc_values, ""));
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_concealed_frames, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_stretched_frames, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_compressed_frames, tvb, offset+12, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_total_frames, tvb, offset+16, 4, ENC_BIG_ENDIAN);
        /* 2 bytes Reserved */
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_receive_quality_state, tvb, offset+22, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_fec_distance_request, tvb, offset+23, 1, ENC_BIG_ENDIAN);
        break;
    case 10:
        /* MS Receiver-side Bandwidth Limit */
        /* First 4 bytes are reserved */
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_bandwidth, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
        break;
    case 11:
        /* MS Packet Train Packet */
        item = proto_tree_add_item(pse_tree, hf_rtcp_ssrc_sender, tvb, offset, 4, ENC_BIG_ENDIAN);
        /* Decode if it is NONE or ANY and add to line */
        proto_item_append_text(item," %s", val_to_str_const(tvb_get_ntohl (tvb, offset), rtcp_ssrc_values, ""));
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_last_packet_train, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_packet_idx, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_packet_cnt, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_packet_train_byte_cnt, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        break;
    case 12:
        /* MS Peer Info Exchange */
        item = proto_tree_add_item(pse_tree, hf_rtcp_ssrc_sender, tvb, offset, 4, ENC_BIG_ENDIAN);
        /* Decode if it is NONE or ANY and add to line */
        proto_item_append_text(item," %s", val_to_str_const(tvb_get_ntohl (tvb, offset), rtcp_ssrc_values, ""));
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_inbound_bandwidth, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_outbound_bandwidth, tvb, offset + 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_no_cache, tvb, offset + 12, 1, ENC_BIG_ENDIAN);
        break;
    case 13:
        /* MS Network Congestion Notification */
        proto_tree_add_item(pse_tree, hf_rtcp_ntp_msw, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(pse_tree, hf_rtcp_ntp_lsw, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(pse_tree, hf_rtcp_ntp, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_congestion_info, tvb, offset + 12, 1, ENC_BIG_ENDIAN);
        break;
    case 14:
        /* MS Modality Send Bandwidth Limit */
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_modality, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* 3 bytes Reserved */
        proto_tree_add_item(pse_tree, hf_rtcp_pse_ms_bandwidth, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
        break;

    case 6:
        /* MS Padding */
    default:
        /* Unrecognized */
        proto_tree_add_item(pse_tree, hf_rtcp_profile_specific_extension, tvb, offset,
                extension_length - 4, ENC_NA);
        break;
    }
    offset += extension_length - 4;
    return offset;
}

static void
dissect_rtcp_profile_specific_extensions (packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree, int offset, int remaining)
{
    tvbuff_t   *next_tvb;
    proto_tree *pse_tree;
    proto_item *pse_item;
    int         bytes_consumed;
    uint16_t    extension_type;

    /* Profile-specific extensions, as by their name, are supposed to be
     * associated with a profile, negotiated in SDP or similar in the
     * Media Description ("m=" line). In practice, the standards the
     * define profile-specific extensions, like MS-RT, use the "RTP/AVP"
     * profile, so we can't use that. They do seem to use the first two
     * bytes as a type, though different standards disagree about the
     * the nature of the length field (bytes vs 32-bit words).
     *
     * So we use a FT_UINT16 dissector table. If that ever proves
     * insufficient, we could try a FT_NONE payload table.
     */
    col_append_str(pinfo->cinfo, COL_INFO, "(");
    while (remaining) {
        extension_type = tvb_get_ntohs(tvb, offset);
        next_tvb = tvb_new_subset_length(tvb, offset, remaining);
        pse_tree = proto_tree_add_subtree(tree, tvb, offset, remaining, ett_pse, &pse_item, "Profile Specific Extension");
        bytes_consumed = dissector_try_uint_new(rtcp_pse_dissector_table, extension_type, next_tvb, pinfo, pse_tree, false, NULL);
        if (!bytes_consumed) {
            proto_item_append_text(pse_item, " (Unknown)");
            col_append_str(pinfo->cinfo, COL_INFO, "PSE:Unknown ");
            proto_tree_add_item(pse_tree, hf_rtcp_profile_specific_extension, tvb, offset,
                    remaining, ENC_NA);
            bytes_consumed = remaining;
        }
        offset += bytes_consumed;
        remaining -= bytes_consumed;
    }
    col_append_str(pinfo->cinfo, COL_INFO, ") ");
}

static int
dissect_rtcp_rr( packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree,
    int count, int packet_length )
{
    int           counter;
    proto_tree   *ssrc_tree;
    proto_tree   *ssrc_sub_tree;
    proto_tree   *high_sec_tree;
    proto_item   *ti;
    uint8_t       rr_flt;
    int           rr_offset = offset;


    counter = 1;
    while ( counter <= count ) {
        uint32_t lsr, dlsr;

        /* Create a new subtree for a length of 24 bytes */
        ssrc_tree = proto_tree_add_subtree_format(tree, tvb, offset, 24,
            ett_ssrc, NULL, "Source %u", counter );

        /* SSRC_n source identifier, 32 bits */
        proto_tree_add_item( ssrc_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN );
        offset += 4;

        ssrc_sub_tree = proto_tree_add_subtree(ssrc_tree, tvb, offset, 20, ett_ssrc_item, NULL, "SSRC contents" );

        /* Fraction lost, 8bits */
        rr_flt = tvb_get_uint8( tvb, offset );
        proto_tree_add_uint_format_value( ssrc_sub_tree, hf_rtcp_ssrc_fraction, tvb,
            offset, 1, rr_flt, "%u / 256", rr_flt );
        offset++;

        /* Cumulative number of packets lost, 24 bits */
        proto_tree_add_item( ssrc_sub_tree, hf_rtcp_ssrc_cum_nr, tvb,
            offset, 3, ENC_BIG_ENDIAN );
        offset += 3;

        /* Extended highest sequence nr received, 32 bits
         * Just for the sake of it, let's add another subtree
         * because this might be a little clearer
         */
        ti = proto_tree_add_item( ssrc_tree, hf_rtcp_ssrc_ext_high_seq,
            tvb, offset, 4, ENC_BIG_ENDIAN );
        high_sec_tree = proto_item_add_subtree( ti, ett_ssrc_ext_high );
        /* Sequence number cycles */
        proto_tree_add_item( high_sec_tree, hf_rtcp_ssrc_high_cycles,
            tvb, offset, 2, ENC_BIG_ENDIAN );
        offset += 2;
        /* highest sequence number received */
        proto_tree_add_item( high_sec_tree, hf_rtcp_ssrc_high_seq,
            tvb, offset, 2, ENC_BIG_ENDIAN );
        offset += 2;

        /* Interarrival jitter */
        proto_tree_add_item( ssrc_tree, hf_rtcp_ssrc_jitter, tvb,
            offset, 4, ENC_BIG_ENDIAN );
        offset += 4;

        /* Last SR timestamp */
        lsr = tvb_get_ntohl( tvb, offset );
        proto_tree_add_item( ssrc_tree, hf_rtcp_ssrc_lsr, tvb,
                             offset, 4, ENC_BIG_ENDIAN );
        offset += 4;

        /* Delay since last SR timestamp */
        dlsr = tvb_get_ntohl( tvb, offset );
        ti = proto_tree_add_item( ssrc_tree, hf_rtcp_ssrc_dlsr, tvb,
                                  offset, 4, ENC_BIG_ENDIAN );
        proto_item_append_text(ti, " (%d milliseconds)",
                               (int)(((double)dlsr/(double)65536) * 1000.0));
        offset += 4;

        /* Do roundtrip calculation */
        if (global_rtcp_show_roundtrip_calculation)
        {
            /* Based on delay since SR was sent in other direction */
            calculate_roundtrip_delay(tvb, pinfo, ssrc_tree, lsr, dlsr);
        }

        counter++;
    }

    /* If length remaining, assume profile-specific extension bytes */
    if ((offset-rr_offset) < packet_length)
    {
        dissect_rtcp_profile_specific_extensions (pinfo, tvb, tree, offset, packet_length - (offset - rr_offset));
        offset = rr_offset + packet_length;
    }

    return offset;
}

static int
dissect_rtcp_sr( packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree,
    int count,  int packet_length )
{
    proto_item *item;
    uint32_t    ts_msw, ts_lsw;
    int         sr_offset = offset;

    /* NTP timestamp */
    ts_msw = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_rtcp_ntp_msw, tvb, offset, 4, ENC_BIG_ENDIAN);

    ts_lsw = tvb_get_ntohl(tvb, offset+4);
    proto_tree_add_item(tree, hf_rtcp_ntp_lsw, tvb, offset+4, 4, ENC_BIG_ENDIAN);

    item = proto_tree_add_item(tree, hf_rtcp_ntp, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
    proto_item_set_generated(item);
    offset += 8;

    /* RTP timestamp, 32 bits */
    proto_tree_add_item( tree, hf_rtcp_rtp_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;
    /* Sender's packet count, 32 bits */
    proto_tree_add_item( tree, hf_rtcp_sender_pkt_cnt, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;
    /* Sender's octet count, 32 bits */
    proto_tree_add_item( tree, hf_rtcp_sender_oct_cnt, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    /* Record the time of this packet in the sender's conversation */
    if (global_rtcp_show_roundtrip_calculation)
    {
        /* Use middle 32 bits of 64-bit time value */
        uint32_t lsr = ((ts_msw & 0x0000ffff) << 16 | (ts_lsw & 0xffff0000) >> 16);

        /* Record the time that we sent this in appropriate conversation */
        remember_outgoing_sr(pinfo, lsr);
    }

    /* The rest of the packet is equal to the RR packet */
    if ( count != 0 )
        offset = dissect_rtcp_rr( pinfo, tvb, offset, tree, count, packet_length-(offset-sr_offset) );
    else
    {
        /* If length remaining, assume profile-specific extension bytes */
        if ((offset-sr_offset) < packet_length)
        {
            dissect_rtcp_profile_specific_extensions (pinfo, tvb,  tree, offset, packet_length - (offset - sr_offset));
            offset = sr_offset + packet_length;
        }
    }

    return offset;
}

/* Look for conversation info and display any setup info found */
void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Conversation and current data */
    struct _rtcp_conversation_info *p_conv_data;

    /* Use existing packet data if available */
    p_conv_data = (struct _rtcp_conversation_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rtcp, 0);

    if (!p_conv_data)
    {
        conversation_t *p_conv;
        /* First time, get info from conversation */
        p_conv = find_conversation(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                                   conversation_pt_to_conversation_type(pinfo->ptype),
                                   pinfo->destport, pinfo->srcport, NO_ADDR_B);

        if (p_conv)
        {
            /* Look for data in conversation */
            struct _rtcp_conversation_info *p_conv_packet_data;
            p_conv_data = (struct _rtcp_conversation_info *)conversation_get_proto_data(p_conv, proto_rtcp);

            if (p_conv_data)
            {
                /* Save this conversation info into packet info */
                p_conv_packet_data = (struct _rtcp_conversation_info *)wmem_memdup(wmem_file_scope(),
                      p_conv_data, sizeof(struct _rtcp_conversation_info));

                p_add_proto_data(wmem_file_scope(), pinfo, proto_rtcp, 0, p_conv_packet_data);
            }
        }
    }

    /* Create setup info subtree with summary info. */
    if (p_conv_data && p_conv_data->setup_method_set)
    {
        proto_tree *rtcp_setup_tree;
        proto_item *ti =  proto_tree_add_string_format(tree, hf_rtcp_setup, tvb, 0, 0,
                                                       "",
                                                       "Stream setup by %s (frame %u)",
                                                       p_conv_data->setup_method,
                                                       p_conv_data->setup_frame_number);
        proto_item_set_generated(ti);
        rtcp_setup_tree = proto_item_add_subtree(ti, ett_rtcp_setup);
        if (rtcp_setup_tree)
        {
            /* Add details into subtree */
            proto_item *item = proto_tree_add_uint(rtcp_setup_tree, hf_rtcp_setup_frame,
                                                   tvb, 0, 0, p_conv_data->setup_frame_number);
            proto_item_set_generated(item);
            item = proto_tree_add_string(rtcp_setup_tree, hf_rtcp_setup_method,
                                         tvb, 0, 0, p_conv_data->setup_method);
            proto_item_set_generated(item);
        }
    }
}


/* Update conversation data to record time that outgoing rr/sr was sent */
static void remember_outgoing_sr(packet_info *pinfo, uint32_t lsr)
{
    conversation_t                 *p_conv;
    struct _rtcp_conversation_info *p_conv_data;
    struct _rtcp_conversation_info *p_packet_data;

    /* This information will be accessed when an incoming packet comes back to
       the side that sent this packet, so no use storing in the packet
       info.  However, do store the fact that we've already set this info
       before  */


    /**************************************************************************/
    /* First of all, see if we've already stored this information for this sr */

    /* Look first in packet info */
    p_packet_data = (struct _rtcp_conversation_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rtcp, 0);
    if (p_packet_data && p_packet_data->last_received_set &&
        (p_packet_data->last_received_frame_number >= pinfo->num))
    {
        /* We already did this, OK */
        return;
    }


    /**************************************************************************/
    /* Otherwise, we want to find/create the conversation and update it       */

    /* First time, get info from conversation.
       Even though we think of this as an outgoing packet being sent,
       we store the time as being received by the destination. */
    p_conv = find_conversation(pinfo->num, &pinfo->net_dst, &pinfo->net_src,
                               conversation_pt_to_conversation_type(pinfo->ptype),
                               pinfo->destport, pinfo->srcport, NO_ADDR_B);

    /* If the conversation doesn't exist, create it now. */
    if (!p_conv)
    {
        p_conv = conversation_new(pinfo->num, &pinfo->net_dst, &pinfo->net_src, CONVERSATION_UDP,
                                  pinfo->destport, pinfo->srcport,
                                  NO_ADDR2);
        if (!p_conv)
        {
            /* Give up if can't create it */
            return;
        }
    }


    /****************************************************/
    /* Now find/create conversation data                */
    p_conv_data = (struct _rtcp_conversation_info *)conversation_get_proto_data(p_conv, proto_rtcp);
    if (!p_conv_data)
    {
        /* Allocate memory for data */
        p_conv_data = wmem_new0(wmem_file_scope(), struct _rtcp_conversation_info);

        /* Add it to conversation. */
        conversation_add_proto_data(p_conv, proto_rtcp, p_conv_data);
    }

    /*******************************************************/
    /* Update conversation data                            */
    p_conv_data->last_received_set = true;
    p_conv_data->last_received_frame_number = pinfo->num;
    p_conv_data->last_received_timestamp = pinfo->abs_ts;
    p_conv_data->last_received_ts = lsr;


    /****************************************************************/
    /* Update packet info to record conversation state              */

    /* Will use/create packet info */
    if (!p_packet_data)
    {
        p_packet_data = wmem_new0(wmem_file_scope(), struct _rtcp_conversation_info);

        p_add_proto_data(wmem_file_scope(), pinfo, proto_rtcp, 0, p_packet_data);
    }

    /* Copy current conversation data into packet info */
    p_packet_data->last_received_set = true;
    p_packet_data->last_received_frame_number = p_conv_data->last_received_frame_number;
}


/* Use received sr to work out what the roundtrip delay is
   (at least between capture point and the other endpoint involved in
    the conversation) */
static void calculate_roundtrip_delay(tvbuff_t *tvb, packet_info *pinfo,
                                      proto_tree *tree, uint32_t lsr, uint32_t dlsr)
{
    /*****************************************************/
    /* This is called dissecting an SR.  We need to:
       - look in the packet info for stored calculation.  If found, use.
       - look up the conversation of the sending side to see when the
         'last SR' was detected (received)
       - calculate the network delay using the that packet time,
         this packet time, and dlsr
    *****************************************************/

    conversation_t                 *p_conv;
    struct _rtcp_conversation_info *p_conv_data;
    struct _rtcp_conversation_info *p_packet_data;


    /*************************************************/
    /* Look for previous result                      */
    p_packet_data = (struct _rtcp_conversation_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rtcp, 0);
    if (p_packet_data && p_packet_data->lsr_matched)
    {
        /* Show info. */
        add_roundtrip_delay_info(tvb, pinfo, tree,
                                 p_packet_data->calculated_delay_used_frame,
                                 p_packet_data->calculated_delay_report_gap,
                                 p_packet_data->calculated_delay);
        return;
    }


    /********************************************************************/
    /* Look for captured timestamp of last SR in conversation of sender */
    /* of this packet                                                   */
    p_conv = find_conversation(pinfo->num, &pinfo->net_src, &pinfo->net_dst,
                               conversation_pt_to_conversation_type(pinfo->ptype),
                               pinfo->srcport, pinfo->destport, NO_ADDR_B);
    if (!p_conv)
    {
        return;
    }

    /* Look for conversation data  */
    p_conv_data = (struct _rtcp_conversation_info *)conversation_get_proto_data(p_conv, proto_rtcp);
    if (!p_conv_data)
    {
        return;
    }

    if (p_conv_data->last_received_set)
    {
        /* Store result of calculation in packet info */
        if (!p_packet_data)
        {
            /* Create packet info if it doesn't exist */
            p_packet_data = wmem_new0(wmem_file_scope(), struct _rtcp_conversation_info);

            /* Set as packet info */
            p_add_proto_data(wmem_file_scope(), pinfo, proto_rtcp, 0, p_packet_data);
        }

        /* Don't allow match seemingly calculated from same (or later!) frame */
        if (pinfo->num <= p_conv_data->last_received_frame_number)
        {
            return;
        }

        /* The previous report must match the lsr given here */
        if (p_conv_data->last_received_ts == lsr)
        {
            /* Look at time of since original packet was sent */
            int seconds_between_packets = (int)
                  (pinfo->abs_ts.secs - p_conv_data->last_received_timestamp.secs);
            int nseconds_between_packets =
                  pinfo->abs_ts.nsecs - p_conv_data->last_received_timestamp.nsecs;

            int total_gap = (seconds_between_packets*1000) +
                             (nseconds_between_packets / 1000000);
            int dlsr_ms = (int)(((double)dlsr/(double)65536) * 1000.0);
            int delay;

            /* Delay is gap - dlsr  (N.B. this is allowed to be -ve) */
            delay = total_gap - dlsr_ms;

            /* Record that the LSR matches */
            p_packet_data->lsr_matched = true;

            /* No useful calculation can be done if dlsr not set... */
            if (dlsr)
            {
                p_packet_data->calculated_delay = delay;
                p_packet_data->calculated_delay_report_gap = total_gap;
                p_packet_data->calculated_delay_used_frame = p_conv_data->last_received_frame_number;
            }

            /* Show info. */
            add_roundtrip_delay_info(tvb, pinfo, tree,
                                     p_conv_data->last_received_frame_number,
                                     total_gap,
                                     delay);
        }
    }
}

/* Show the calculated roundtrip delay info by adding protocol tree items
   and appending text to the info column */
static void add_roundtrip_delay_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                     unsigned frame, unsigned gap_between_reports,
                                     int delay)
{
    /* 'Last SR' frame used in calculation.  Show this even if no delay shown */
    proto_item *item = proto_tree_add_uint(tree,
                                           hf_rtcp_last_sr_timestamp_frame,
                                           tvb, 0, 0, frame);
    proto_item_set_generated(item);

    /* Time elapsed since 'Last SR' time in capture */
    item = proto_tree_add_uint(tree,
                               hf_rtcp_time_since_last_sr,
                               tvb, 0, 0, gap_between_reports);
    proto_item_set_generated(item);

    /* Don't report on calculated delays below the threshold.
       Will report delays less than -threshold, to highlight
       problems with generated reports */
    if (abs(delay) < (int)global_rtcp_show_roundtrip_calculation_minimum)
    {
        return;
    }

    /* Calculated delay in ms */
    item = proto_tree_add_int(tree, hf_rtcp_roundtrip_delay, tvb, 0, 0, delay);
    proto_item_set_generated(item);

    /* Add to expert info */
    if (delay >= 0)
    {
        expert_add_info_format(pinfo, item, &ei_rtcp_roundtrip_delay, "RTCP round-trip delay detected (%d ms)", delay);
    }
    else
    {
        expert_add_info_format(pinfo, item, &ei_rtcp_roundtrip_delay_negative, "Negative RTCP round-trip delay detected (%d ms)", delay);
    }

    /* Report delay in INFO column */
    col_append_fstr(pinfo->cinfo, COL_INFO,
                    " (roundtrip delay <-> %s = %dms, using frame %u)  ",
                    address_to_str(pinfo->pool, &pinfo->net_src), delay, frame);
}

static int
rtcp_packet_type_to_tree( int rtcp_packet_type)
{
    int tree;

    switch(rtcp_packet_type) {
        case RTCP_SR:    tree = ett_rtcp_sr;    break;
        case RTCP_RR:    tree = ett_rtcp_rr;    break;
        case RTCP_SDES:  tree = ett_rtcp_sdes;  break;
        case RTCP_BYE:   tree = ett_rtcp_bye;   break;
        case RTCP_APP:   tree = ett_rtcp_app;   break;
        case RTCP_RTPFB: tree = ett_rtcp_rtpfb; break;
        case RTCP_PSFB:  tree = ett_rtcp_psfb;  break;
        case RTCP_XR:    tree = ett_rtcp_xr;    break;
        case RTCP_FIR:   tree = ett_rtcp_fir;   break;
        case RTCP_NACK:  tree = ett_rtcp_nack;  break;
        default:         tree = ett_rtcp;
    }
    return tree;
}

static int
dissect_rtcp_common( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_, bool is_srtp )
{
    proto_item       *ti;
    proto_tree       *rtcp_tree           = NULL;
    proto_item       *padding_item        = NULL;
    int               offset              = 0;
    int               total_packet_length = 0;
    unsigned          padding_offset      = 0;
    bool              srtcp_encrypted     = false;
    bool              srtcp_now_encrypted = false;
    conversation_t   *p_conv;
    struct srtp_info *srtcp_info          = NULL;
    uint32_t          srtcp_offset        = 0;
    uint32_t          srtcp_index         = 0;
    uint8_t           temp_byte;
    int proto_to_use = proto_rtcp;

    temp_byte = tvb_get_uint8(tvb, offset);
    /* RFC 7983 gives current best practice in demultiplexing RT[C]P packets:
     * Examine the first byte of the packet:
     *              +----------------+
     *              |        [0..3] -+--> forward to STUN
     *              |                |
     *              |      [16..19] -+--> forward to ZRTP
     *              |                |
     *  packet -->  |      [20..63] -+--> forward to DTLS
     *              |                |
     *              |      [64..79] -+--> forward to TURN Channel
     *              |                |
     *              |    [128..191] -+--> forward to RTP/RTCP
     *              +----------------+
     *
     * DTLS-SRTP MUST support multiplexing of DTLS and RTP over the same
     * port pair (RFCs 5764, 8835), and STUN packets sharing one port are
     * common as well. In WebRTC it's common to get a SDP early in the
     * setup process that sets up a RTCP conversation and sets the dissector
     * to RTCP, but to still get subsequent STUN and DTLS packets.
     *
     * XXX: Add a pref like RTP to specifically send the packet to the correct
     * other dissector. For now, rejecting packets works for the general setup,
     * since the other dissectors have fairly good heuristic dissectors that
     * are enabled by default.
     */

    /* first see if this conversation is encrypted SRTP, and if so do not try to dissect the payload(s) */
    p_conv = find_conversation(pinfo->num, &pinfo->net_src, &pinfo->net_dst,
                               conversation_pt_to_conversation_type(pinfo->ptype),
                               pinfo->srcport, pinfo->destport, NO_ADDR_B);
    if (p_conv)
    {
        struct _rtcp_conversation_info *p_conv_data;
        p_conv_data = (struct _rtcp_conversation_info *)conversation_get_proto_data(p_conv, proto_rtcp);
        if (p_conv_data && p_conv_data->srtcp_info)
        {
            bool e_bit;
            proto_to_use = proto_srtcp;
            srtcp_info = p_conv_data->srtcp_info;
            /* get the offset to the start of the SRTCP fields at the end of the packet */
            srtcp_offset = tvb_reported_length_remaining(tvb, offset) - srtcp_info->auth_tag_len - srtcp_info->mki_len - 4;
            /* It has been setup as SRTCP, but skip to the SRTCP E field at the end
               to see if this particular packet is encrypted or not. The E bit is the MSB. */
            srtcp_index = tvb_bytes_exist(tvb, srtcp_offset, 4) ? tvb_get_ntohl(tvb, srtcp_offset) : 0;
            e_bit = (srtcp_index & 0x80000000) ? true : false;
            srtcp_index &= 0x7fffffff;

            if (srtcp_info->encryption_algorithm!=SRTP_ENC_ALG_NULL) {
                /* just flag it for now - the first SR or RR header and SSRC are unencrypted */
                if (e_bit)
                    srtcp_encrypted = true;
            }
        }
    } else if (is_srtp) {
        /* We've been told to dissect this as SRTCP without conversation info
         * (so via Decode As or heuristic); since we don't know where the SRTCP
         * bits start, so we don't know if it's encrypted. Assume yes, to
         * avoid errors.
         */
        srtcp_encrypted = true;
        proto_to_use = proto_srtcp;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, (proto_to_use == proto_srtcp) ? "SRTCP" : "RTCP");

    if (RTCP_VERSION(temp_byte) != 2) {
        /* Unknown or unsupported version */
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown %s version %u", (proto_to_use == proto_srtcp) ? "SRTCP" : "RTCP", RTCP_VERSION(temp_byte));
        ti = proto_tree_add_item(tree, proto_to_use, tvb, offset, -1, ENC_NA );
        rtcp_tree = proto_item_add_subtree(ti, ett_rtcp);
        proto_tree_add_item( rtcp_tree, hf_rtcp_version, tvb,
                             offset, 1, ENC_BIG_ENDIAN);

        /* XXX: Offset is zero here, so in practice this rejects the packet
         * and lets heuristic dissectors make an attempt, though extra tree
         * entries appear on a tshark one pass even if some other dissector
         * claims the packet.
         */
        return offset;
    }
    /*
     * Check if there are at least 4 bytes left in the frame,
     * the last 16 bits of those is the length of the current
     * RTCP message. The last compound message contains padding,
     * that enables us to break from the while loop.
     */
    while ( !srtcp_now_encrypted && tvb_bytes_exist( tvb, offset, 4) ) {
        int elem_count;
        unsigned packet_type;
        int packet_length;
        /*
         * First retrieve the packet_type
         */
        packet_type = tvb_get_uint8( tvb, offset + 1 );

        /*
         * Check if it's a valid type
         */
        if ( ( packet_type < RTCP_PT_MIN ) || ( packet_type >  RTCP_PT_MAX ) )
            break;

        col_add_fstr(pinfo->cinfo, COL_INFO, "%s   ",
                      val_to_str_const(packet_type, rtcp_packet_type_vals, "Unknown"));

        /*
         * get the packet-length for the complete RTCP packet
         */
        packet_length = ( tvb_get_ntohs( tvb, offset + 2 ) + 1 ) * 4;
        total_packet_length += packet_length;

        ti = proto_tree_add_item(tree, proto_to_use, tvb, offset, packet_length, ENC_NA );
        proto_item_append_text(ti, " (%s)",
                               val_to_str_const(packet_type,
                                                rtcp_packet_type_vals,
                                                "Unknown"));

        rtcp_tree = proto_item_add_subtree( ti, rtcp_packet_type_to_tree(packet_type) );

        /* Conversation setup info */
        if (global_rtcp_show_setup_info)
        {
            show_setup_info(tvb, pinfo, rtcp_tree);
        }

        if (rtcp_padding_set)
        {
            /* Padding can't yet be set, since there is another packet */
            expert_add_info(pinfo, padding_item, &ei_rtcp_not_final_padding);
        }

        temp_byte = tvb_get_uint8( tvb, offset );

        proto_tree_add_item( rtcp_tree, hf_rtcp_version, tvb,
                             offset, 1, ENC_BIG_ENDIAN);
        rtcp_padding_set = RTCP_PADDING( temp_byte );
        padding_offset = offset + packet_length - 1;

        padding_item = proto_tree_add_boolean( rtcp_tree, hf_rtcp_padding, tvb,
                                               offset, 1, temp_byte );
        elem_count = RTCP_COUNT( temp_byte );

        switch ( packet_type ) {
            case RTCP_SR:
            case RTCP_RR:
                /* Receiver report count, 5 bits */
                proto_tree_add_uint( rtcp_tree, hf_rtcp_rc, tvb, offset, 1, temp_byte );
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);
                /* Sender Synchronization source, 32 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_ssrc_sender, tvb, offset, 4, ENC_BIG_ENDIAN );
                offset += 4;

                if (srtcp_encrypted) { /* rest of the payload is encrypted - do not try to dissect */
                    srtcp_now_encrypted = true;
                    break;
                }

                if ( packet_type == RTCP_SR )
                    offset = dissect_rtcp_sr( pinfo, tvb, offset, rtcp_tree, elem_count, packet_length-8 );
                else
                    offset = dissect_rtcp_rr( pinfo, tvb, offset, rtcp_tree, elem_count, packet_length-8 );
                break;
            case RTCP_SDES:
                /* Source count, 5 bits */
                proto_tree_add_uint( rtcp_tree, hf_rtcp_sc, tvb, offset, 1, temp_byte );
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);
                offset = dissect_rtcp_sdes( tvb, offset, rtcp_tree, elem_count );
                break;
            case RTCP_BYE:
                /* Source count, 5 bits */
                proto_tree_add_uint( rtcp_tree, hf_rtcp_sc, tvb, offset, 1, temp_byte );
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);
                offset = dissect_rtcp_bye( tvb, pinfo, offset, rtcp_tree, elem_count, packet_length-4 );
                break;
            case RTCP_APP: {
                /* Subtype, 5 bits */
                unsigned rtcp_subtype;
                unsigned app_length;
                proto_item* subtype_item;
                rtcp_subtype = elem_count;
                subtype_item = proto_tree_add_uint( rtcp_tree, hf_rtcp_subtype, tvb, offset, 1, elem_count );
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                app_length = tvb_get_ntohs( tvb, offset ) <<2;
                offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);
                /* SSRC / CSRC */
                proto_tree_add_item(rtcp_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                if (srtcp_encrypted) { /* rest of the payload is encrypted - do not try to dissect hf_rtcp_encrypted*/
                    proto_tree_add_item(rtcp_tree, hf_rtcp_encrypted, tvb, offset, -1, ENC_NA);
                    if (preferences_application_specific_encoding == RTCP_APP_MCPTT) {
                        col_add_fstr(pinfo->cinfo, COL_INFO, "(MCPT) %s",
                            val_to_str(rtcp_subtype, rtcp_mcpt_subtype_vals, "unknown (%u)"));

                        proto_item_append_text(subtype_item, " %s", val_to_str(rtcp_subtype, rtcp_mcpt_subtype_vals, "unknown (%u)"));
                    }

                    return tvb_reported_length(tvb);
                }
                offset = dissect_rtcp_app( tvb, pinfo, offset,rtcp_tree, packet_length - 8, subtype_item, rtcp_subtype, app_length);
            }
                break;
            case RTCP_XR:
                /* Reserved, 5 bits, Ignore */
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);
                offset = dissect_rtcp_xr( tvb, pinfo, offset, rtcp_tree, packet_length - 4 );
                break;
            case RTCP_AVB:
                /* Subtype, 5 bits */
                proto_tree_add_uint( rtcp_tree, hf_rtcp_subtype, tvb, offset, 1, elem_count );
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);
                offset = dissect_rtcp_avb( tvb, pinfo, offset, rtcp_tree, packet_length - 4 );
                break;
            case RTCP_RSI:
                /* Reserved, 5 bits, Ignore */
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);
                offset = dissect_rtcp_rsi( tvb, pinfo, offset, rtcp_tree, packet_length - 4 );
                break;
            case RTCP_TOKEN: {
                /* Subtype, 5 bits */
                unsigned rtcp_subtype;
                rtcp_subtype = elem_count;
                proto_tree_add_uint( rtcp_tree, hf_rtcp_subtype, tvb, offset, 1, elem_count );
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, ENC_BIG_ENDIAN );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                offset = dissect_rtcp_length_field(rtcp_tree, tvb, offset);
                offset = dissect_rtcp_token( tvb, pinfo, offset, rtcp_tree, packet_length - 4, rtcp_subtype );
            }
                break;
            case RTCP_FIR:
                offset = dissect_rtcp_fir( tvb, offset, rtcp_tree );
                break;
            case RTCP_NACK:
                offset = dissect_rtcp_nack( tvb, offset, rtcp_tree );
                break;
            case RTCP_RTPFB:
                offset = dissect_rtcp_rtpfb( tvb, offset, rtcp_tree, pinfo );
                break;
            case RTCP_PSFB:
                offset = dissect_rtcp_psfb( tvb, offset, rtcp_tree, packet_length, ti, pinfo );
                break;
            default:
                /*
                 * To prevent endless loops in case of an unknown message type
                 * increase offset. Some time the while will end :-)
                 */
                offset++;
                break;
        }

        col_set_fence(pinfo->cinfo, COL_INFO);
    }
    /* If the padding bit is set, the last octet of the
     * packet contains the length of the padding
     * We only have to check for this at the end of the LAST RTCP message
     */
    if ( rtcp_padding_set ) {
        unsigned padding_length;
        /* The last RTCP message in the packet has padding - find it.
         *
         * The padding count is found at an offset of padding_offset; it
         * contains the number of padding octets, including the padding
         * count itself.
         */
        padding_length = tvb_get_uint8( tvb, padding_offset);

        /* This length includes the padding length byte itself, so 0 is not
         * a valid value. */
        if (padding_length != 0) {
            proto_tree_add_item( rtcp_tree, hf_rtcp_padding_data, tvb, offset, padding_length - 1, ENC_NA );
            offset += padding_length - 1;
        }
        proto_tree_add_item( rtcp_tree, hf_rtcp_padding_count, tvb, offset, 1, ENC_BIG_ENDIAN );
        offset++;
    }

    /* If the payload was encrypted, the main payload was not dissected.
     */
    if (srtcp_encrypted == true) {
        /* If we don't have srtcp_info we cant calculate the length
         */
        if (srtcp_info) {
            proto_tree_add_expert(rtcp_tree, pinfo, &ei_srtcp_encrypted_payload, tvb, offset, srtcp_offset - offset);
            proto_tree_add_item(rtcp_tree, hf_srtcp_e, tvb, srtcp_offset, 4, ENC_BIG_ENDIAN);
            proto_tree_add_uint(rtcp_tree, hf_srtcp_index, tvb, srtcp_offset, 4, srtcp_index);
            srtcp_offset += 4;
            if (srtcp_info->mki_len) {
                proto_tree_add_item(rtcp_tree, hf_srtcp_mki, tvb, srtcp_offset, srtcp_info->mki_len, ENC_NA);
                srtcp_offset += srtcp_info->mki_len;
            }

            if (srtcp_info->auth_tag_len) {
                proto_tree_add_item(rtcp_tree, hf_srtcp_auth_tag, tvb, srtcp_offset, srtcp_info->auth_tag_len, ENC_NA);
                /*srtcp_offset += srtcp_info->auth_tag_len;*/
            }
        } else {
            proto_tree_add_expert(rtcp_tree, pinfo, &ei_srtcp_encrypted_payload, tvb, offset, -1);
        }
    }
    /* offset should be total_packet_length by now... */
    else if (offset == total_packet_length)
    {
        ti = proto_tree_add_boolean_format_value(rtcp_tree, hf_rtcp_length_check, tvb,
                                            0, 0, true, "OK - %u bytes",
                                            offset);
        /* Hidden might be less annoying here...? */
        proto_item_set_generated(ti);
    }
    else
    {
        ti = proto_tree_add_boolean_format_value(rtcp_tree, hf_rtcp_length_check, tvb,
                                            0, 0, false,
                                            "Wrong (expected %u bytes, found %d)",
                                            total_packet_length, offset);
        proto_item_set_generated(ti);

        expert_add_info_format(pinfo, ti, &ei_rtcp_length_check, "Incorrect RTCP packet length information (expected %u bytes, found %d)", total_packet_length, offset);
    }
    return tvb_captured_length(tvb);
}

static int
dissect_srtcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    return dissect_rtcp_common(tvb, pinfo, tree, data, true);
}

static int
dissect_rtcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    return dissect_rtcp_common(tvb, pinfo, tree, data, false);
}

static void
register_subdissectors_for_rtcp_rtpfb_dissector_table(void)
{
    proto_rtcp_rtpfb_nack = proto_register_protocol_in_name_only("Generic negative acknowledgement (NACK)", "RTCP NACK", "rtcp_rtpfb_nack", proto_rtcp, FT_BYTES);
    proto_rtcp_rtpfb_tmmbr =
        proto_register_protocol_in_name_only("Temporary Maximum Media Stream Bit Rate Request (TMMBR)", "RTCP TMMBR", "rtcp_rtpfb_tmmbr", proto_rtcp, FT_BYTES);
    proto_rtcp_rtpfb_tmmbn =
        proto_register_protocol_in_name_only("Temporary Maximum Media Stream Bit Rate Notification (TMMBN)", "RTCP TMMBN", "rtcp_rtpfb_tmmbn", proto_rtcp, FT_BYTES);
    proto_rtcp_rtpfb_ccfb = proto_register_protocol_in_name_only("RTP Congestion Control Feedback (CCFB)", "RTCP CCFB", "rtcp_rtpfb_ccfb", proto_rtcp, FT_BYTES);
    proto_rtcp_rtpfb_transport_cc =
        proto_register_protocol_in_name_only("Transport-wide Congestion Control (Transport-cc)", "RTCP Transport-CC", "rtcp_rtpfb_transport_cc", proto_rtcp, FT_BYTES);
    proto_rtcp_rtpfb_undecoded_fci = proto_register_protocol_in_name_only("Undecoded FCI", "Undecoded FCI", "rtcp_rtpfb_undecoded_fci", proto_rtcp, FT_BYTES);

    rtcp_rtpfb_nack_handle = register_dissector("rtcp_rtpfb_nack", dissect_rtcp_rtpfb_nack, proto_rtcp_rtpfb_nack);
    rtcp_rtpfb_tmmbr_handle = register_dissector("rtcp_rtpfb_tmmbr", dissect_rtcp_rtpfb_tmmbr, proto_rtcp_rtpfb_tmmbr);
    rtcp_rtpfb_tmmbn_handle = register_dissector("rtcp_rtpfb_tmmbn", dissect_rtcp_rtpfb_tmmbn, proto_rtcp_rtpfb_tmmbn);
    rtcp_rtpfb_ccfb_handle = register_dissector("rtcp_rtpfb_ccfb", dissect_rtcp_rtpfb_ccfb, proto_rtcp_rtpfb_ccfb);
    rtcp_rtpfb_transport_cc_handle = register_dissector("rtcp_rtpfb_transport_cc", dissect_rtcp_rtpfb_transport_cc, proto_rtcp_rtpfb_transport_cc);
    rtcp_rtpfb_undecoded_fci_handle = register_dissector("rtcp_rtpfb_undecoded_fci", dissect_rtcp_rtpfb_undecoded, proto_rtcp_rtpfb_undecoded_fci);
}

static void
add_entries_for_rtcp_rtpfb_dissector_table(void)
{
    /* Below rtcp-rtpfb-fmt values (1, 3, 4, 11, 15) have full decoding support */
    const uint32_t rtcp_rtpfb_nack_fmt = 1;
    const uint32_t rtcp_rtpfb_tmmbr_fmt = 3;
    const uint32_t rtcp_rtpfb_tmmbn_fmt = 4;
    const uint32_t rtcp_rtpfb_ccfb_fmt = 11;
    const uint32_t rtcp_rtpfb_transport_cc_fmt = 15;
    dissector_add_uint("rtcp.rtpfb.fmt", rtcp_rtpfb_nack_fmt, rtcp_rtpfb_nack_handle);
    dissector_add_uint("rtcp.rtpfb.fmt", rtcp_rtpfb_tmmbr_fmt, rtcp_rtpfb_tmmbr_handle);
    dissector_add_uint("rtcp.rtpfb.fmt", rtcp_rtpfb_tmmbn_fmt, rtcp_rtpfb_tmmbn_handle);
    dissector_add_uint("rtcp.rtpfb.fmt", rtcp_rtpfb_ccfb_fmt, rtcp_rtpfb_ccfb_handle);
    dissector_add_uint("rtcp.rtpfb.fmt", rtcp_rtpfb_transport_cc_fmt, rtcp_rtpfb_transport_cc_handle);

    /* Below rtcp-rtpfb-fmt values (2, 5 - 10) don't have support for FCI decoding */
    int rtcp_rtpfb_fmt = 2;
    dissector_add_uint("rtcp.rtpfb.fmt", rtcp_rtpfb_fmt, rtcp_rtpfb_undecoded_fci_handle);
    for (rtcp_rtpfb_fmt = 5; rtcp_rtpfb_fmt < 11; rtcp_rtpfb_fmt++) {
      dissector_add_uint("rtcp.rtpfb.fmt", rtcp_rtpfb_fmt, rtcp_rtpfb_undecoded_fci_handle);
    }
}

void
proto_register_rtcp(void)
{
    static hf_register_info hf[] = {
        {
            &hf_rtcp_version,
            {
                "Version",
                "rtcp.version",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_version_vals),
                0xC0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_padding,
            {
                "Padding",
                "rtcp.padding",
                FT_BOOLEAN,
                8,
                NULL,
                0x20,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rc,
            {
                "Reception report count",
                "rtcp.rc",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x1F,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_sc,
            {
                "Source count",
                "rtcp.sc",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x1F,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pt,
            {
                "Packet type",
                "rtcp.pt",
                FT_UINT8,
                BASE_DEC,
                VALS( rtcp_packet_type_vals ),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_length,
            {
                "Length",
                "rtcp.length",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                "32-bit words (-1) in packet", HFILL
            }
        },
        {
            &hf_rtcp_ssrc_sender,
            {
                "Sender SSRC",
                "rtcp.senderssrc",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_media_source,
            {
                "Media source SSRC",
                "rtcp.mediassrc",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ntp_msw,
            {
                "Timestamp, MSW",
                "rtcp.timestamp.ntp.msw",
                FT_UINT32,
                BASE_DEC_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ntp_lsw,
            {
                "Timestamp, LSW",
                "rtcp.timestamp.ntp.lsw",
                FT_UINT32,
                BASE_DEC_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ntp,
            {
                "MSW and LSW as NTP timestamp",
                "rtcp.timestamp.ntp",
                FT_ABSOLUTE_TIME,
                ABSOLUTE_TIME_UTC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_timebase_indicator,
            {
                "Timebase Indicator",
                "rtcp.timebase_indicator",
                FT_UINT16,
                BASE_DEC_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_identity,
            {
                "Identity",
                "rtcp.identity",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_stream_id,
            {
                "Stream id",
                "rtcp.stream_id",
                FT_UINT64,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_as_timestamp,
            {
                "AS timestamp",
                "rtcp.timestamp.as",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtp_timestamp,
            {
                "RTP timestamp",
                "rtcp.timestamp.rtp",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_sender_pkt_cnt,
            {
                "Sender's packet count",
                "rtcp.sender.packetcount",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_sender_oct_cnt,
            {
                "Sender's octet count",
                "rtcp.sender.octetcount",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_source,
            {
                "Identifier",
                "rtcp.ssrc.identifier",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_fraction,
            {
                "Fraction lost",
                "rtcp.ssrc.fraction",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_cum_nr,
            {
                "Cumulative number of packets lost",
                "rtcp.ssrc.cum_nr",
                FT_INT24,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_ext_high_seq,
            {
                "Extended highest sequence number received",
                "rtcp.ssrc.ext_high",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_high_seq,
            {
                "Highest sequence number received",
                "rtcp.ssrc.high_seq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_high_cycles,
            {
                "Sequence number cycles count",
                "rtcp.ssrc.high_cycles",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_jitter,
            {
                "Interarrival jitter",
                "rtcp.ssrc.jitter",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_lsr,
            {
                "Last SR timestamp",
                "rtcp.ssrc.lsr",
                FT_UINT32,
                BASE_DEC_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_ssrc_dlsr,
            {
                "Delay since last SR timestamp",
                "rtcp.ssrc.dlsr",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
#if 0
        {
            &hf_rtcp_ssrc_csrc,
            {
                "SSRC / CSRC identifier",
                "rtcp.sdes.ssrc_csrc",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
#endif
        {
            &hf_rtcp_sdes_type,
            {
                "Type",
                "rtcp.sdes.type",
                FT_UINT8,
                BASE_DEC,
                VALS( rtcp_sdes_type_vals ),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_sdes_length,
            {
                "Length",
                "rtcp.sdes.length",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_sdes_text,
            {
                "Text",
                "rtcp.sdes.text",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_sdes_prefix_len,
            {
                "Prefix length",
                "rtcp.sdes.prefix.length",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_sdes_prefix_string,
            {
                "Prefix string",
                "rtcp.sdes.prefix.string",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_subtype,
            {
                "Subtype",
                "rtcp.app.subtype",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x1f,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_name_ascii,
            {
                "Name (ASCII)",
                "rtcp.app.name",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_data,
            {
                "Application specific data",
                "rtcp.app.data",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_data_str,
            {
                "Application specific data",
                "rtcp.app.data_str",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1,
            {
                "PoC1 Application specific data",
                "rtcp.app.poc1",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_sip_uri,
            {
                "SIP URI",
                "rtcp.app.poc1.sip.uri",
                FT_UINT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_disp_name,
            {
                "Display Name",
                "rtcp.app.poc1.disp.name",
                FT_UINT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_priority,
            {
                "Priority",
                "rtcp.app.poc1.priority",
                FT_UINT16,
                BASE_DEC,
                VALS(rtcp_app_poc1_qsresp_priority_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_request_ts,
            {
                "Talk Burst Request Timestamp",
                "rtcp.app.poc1.request.ts",
                FT_ABSOLUTE_TIME,
                ABSOLUTE_TIME_NTP_UTC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_stt,
            {
                "Stop talking timer",
                "rtcp.app.poc1.stt",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_partic,
            {
                "Number of participants",
                "rtcp.app.poc1.participants",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_ssrc_granted,
            {
                "SSRC of client granted permission to talk",
                "rtcp.app.poc1.ssrc.granted",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_last_pkt_seq_no,
            {
                "Sequence number of last RTP packet",
                "rtcp.app.poc1.last.pkt.seq.no",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_ignore_seq_no,
            {
                "Ignore sequence number field",
                "rtcp.app.poc1.ignore.seq.no",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x8000,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_reason_code1,
            {
                "Reason code",
                "rtcp.app.poc1.reason.code",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_app_poc1_reason_code1_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_reason1_phrase,
            {
                "Reason Phrase",
                "rtcp.app.poc1.reason.phrase",
                FT_UINT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_reason_code2,
            {
                "Reason code",
                "rtcp.app.poc1.reason.code",
                FT_UINT16,
                BASE_DEC,
                VALS(rtcp_app_poc1_reason_code2_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_new_time_request,
            {
                "New time client can request (seconds)",
                "rtcp.app.poc1.new.time.request",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                "Time in seconds client can request for", HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_ack_subtype,
            {
                "Subtype",
                "rtcp.app.poc1.ack.subtype",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_app_poc1_floor_cnt_type_vals),
                0xf8,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_ack_reason_code,
            {
                "Reason code",
                "rtcp.app.poc1.ack.reason.code",
                FT_UINT16,
                BASE_DEC,
                VALS(rtcp_app_poc1_reason_code_ack_vals),
                0x07ff,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_qsresp_priority,
            {
                "Priority",
                "rtcp.app.poc1.qsresp.priority",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_app_poc1_qsresp_priority_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_qsresp_position,
            {
                "Position (number of clients ahead)",
                "rtcp.app.poc1.qsresp.position",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_content[0],
            {
                "Identity of inviting client",
                "rtcp.app.poc1.conn.content.a.id",
                FT_BOOLEAN,
                16,
                NULL,
                0x8000,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_content[1],
            {
                "Nick name of inviting client",
                "rtcp.app.poc1.conn.content.a.dn",
                FT_BOOLEAN,
                16,
                NULL,
                0x4000,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_content[2],
            {
                "Session identity",
                "rtcp.app.poc1.conn.content.sess.id",
                FT_BOOLEAN,
                16,
                NULL,
                0x2000,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_content[3],
            {
                "Group name",
                "rtcp.app.poc1.conn.content.grp.dn",
                FT_BOOLEAN,
                16,
                NULL,
                0x1000,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_content[4],
            {
                "Group identity",
                "rtcp.app.poc1.conn.content.grp.id",
                FT_BOOLEAN,
                16,
                NULL,
                0x0800,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_session_type,
            {
                "Session type",
                "rtcp.app.poc1.conn.session.type",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_app_poc1_conn_sess_type_vals),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_add_ind_mao,
            {
                "Manual answer override",
                "rtcp.app.poc1.conn.add.ind.mao",
                FT_BOOLEAN,
                8,
                NULL,
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_sdes_items[0],
            {
                "Identity of inviting client",
                "rtcp.app.poc1.conn.sdes.a.id",
                FT_UINT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_sdes_items[1],
            {
                "Nick name of inviting client",
                "rtcp.app.poc1.conn.sdes.a.dn",
                FT_UINT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_sdes_items[2],
            {
                "Session identity",
                "rtcp.app.poc1.conn.sdes.sess.id",
                FT_UINT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_sdes_items[3],
            {
                "Group Name",
                "rtcp.app.poc1.conn.sdes.grp.dn",
                FT_UINT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_poc1_conn_sdes_items[4],
            {
                "Group identity",
                "rtcp.app.poc1.conn.sdes.grp.id",
                FT_UINT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_mux,
            {
                "RtpMux Application specific data",
                "rtcp.app.mux",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_mux_mux,
            {
                "Multiplexing supported",
                "rtcp.app.mux.mux",
                FT_BOOLEAN,
                8,
                NULL,
                0x80,
                NULL, HFILL
            }
                },
        {
            &hf_rtcp_app_mux_cp,
            {
                "Header compression supported",
                "rtcp.app.mux.cp",
                FT_BOOLEAN,
                8,
                NULL,
                0x40,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_app_mux_selection,
            {
                "Multiplexing selection",
                "rtcp.app.mux.selection",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_app_mux_selection_vals),
                0x30,
                NULL, HFILL
            }
        },
                {
                    &hf_rtcp_app_mux_localmuxport,
            {
                "Local Mux Port",
                "rtcp.app.mux.muxport",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_fsn,
            {
                "First sequence number",
                "rtcp.nack.fsn",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_blp,
            {
                "Bitmask of following lost packets",
                "rtcp.nack.blp",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_padding_count,
            {
                "Padding count",
                "rtcp.padding.count",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_padding_data,
            {
                "Padding data",
                "rtcp.padding.data",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_profile_specific_extension_type,
            {
                "Extension Type",
                "rtcp.profile-specific-extension.type",
                FT_UINT16,
                BASE_DEC,
                VALS( rtcp_ms_profile_extension_vals ),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_profile_specific_extension_length,
            {
                "Extension Length",
                "rtcp.profile-specific-extension.length",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_profile_specific_extension,
            {
                "Profile-specific extension",
                "rtcp.profile-specific-extension",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_setup,
            {
                "Stream setup",
                "rtcp.setup",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "Stream setup, method and frame number", HFILL
            }
        },
        {
            &hf_rtcp_setup_frame,
            {
                "Setup frame",
                "rtcp.setup-frame",
                FT_FRAMENUM,
                BASE_NONE,
                NULL,
                0x0,
                "Frame that set up this stream", HFILL
            }
        },
        {
            &hf_rtcp_setup_method,
            {
                "Setup Method",
                "rtcp.setup-method",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "Method used to set up this stream", HFILL
            }
        },
        {
            &hf_rtcp_last_sr_timestamp_frame,
            {
                "Frame matching Last SR timestamp",
                "rtcp.lsr-frame",
                FT_FRAMENUM,
                BASE_NONE,
                NULL,
                0x0,
                "Frame matching LSR field (used to calculate roundtrip delay)", HFILL
            }
        },
        {
            &hf_rtcp_time_since_last_sr,
            {
                "Time since Last SR captured",
                "rtcp.lsr-frame-captured",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                "Time since frame matching LSR field was captured", HFILL
            }
        },
        {
            &hf_rtcp_roundtrip_delay,
            {
                "Roundtrip Delay(ms)",
                "rtcp.roundtrip-delay",
                FT_INT32,
                BASE_DEC,
                NULL,
                0x0,
                "Calculated roundtrip delay in ms", HFILL
            }
        },
        {
            &hf_rtcp_xr_block_type,
            {
                "Type",
                "rtcp.xr.bt",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_xr_type_vals),
                0x0,
                "Block Type", HFILL
            }
        },
        {
            &hf_rtcp_xr_block_specific,
            {
                "Type Specific",
                "rtcp.xr.bs",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "Reserved", HFILL
            }
        },
        {
            &hf_rtcp_xr_block_length,
            {
                "Length",
                "rtcp.xr.bl",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                "Block Length", HFILL
            }
        },
        {
            &hf_rtcp_ssrc_discarded,
            {
                "Fraction discarded",
                "rtcp.ssrc.discarded",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "Discard Rate", HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_burst_density,
            {
                "Burst Density",
                "rtcp.xr.voipmetrics.burstdensity",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_gap_density,
            {
                "Gap Density",
                "rtcp.xr.voipmetrics.gapdensity",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_burst_duration,
            {
                "Burst Duration(ms)",
                "rtcp.xr.voipmetrics.burstduration",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_gap_duration,
            {
                "Gap Duration(ms)",
                "rtcp.xr.voipmetrics.gapduration",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_rtdelay,
            {
                "Round Trip Delay(ms)",
                "rtcp.xr.voipmetrics.rtdelay",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_esdelay,
            {
                "End System Delay(ms)",
                "rtcp.xr.voipmetrics.esdelay",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_siglevel,
            {
                "Signal Level",
                "rtcp.xr.voipmetrics.signallevel",
                FT_INT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_noiselevel,
            {
                "Noise Level",
                "rtcp.xr.voipmetrics.noiselevel",
                FT_INT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_rerl,
            {
                "Residual Echo Return Loss",
                "rtcp.xr.voipmetrics.rerl",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_gmin,
            {
                "Gmin",
                "rtcp.xr.voipmetrics.gmin",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_rfactor,
            {
                "R Factor",
                "rtcp.xr.voipmetrics.rfactor",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "R Factor is in the range of 0 to 100", HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_extrfactor,
            {
                "External R Factor",
                "rtcp.xr.voipmetrics.extrfactor",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "R Factor is in the range of 0 to 100", HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_moslq,
            {
                "MOS - Listening Quality",
                "rtcp.xr.voipmetrics.moslq",
                FT_FLOAT,
                BASE_NONE,
                NULL,
                0x0,
                "MOS is in the range of 1 to 5", HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_moscq,
            {
                "MOS - Conversational Quality",
                "rtcp.xr.voipmetrics.moscq",
                FT_FLOAT,
                BASE_NONE,
                NULL,
                0x0,
                "MOS is in the range of 1 to 5", HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_plc,
            {
                "Packet Loss Concealment Algorithm",
                "rtcp.xr.voipmetrics.plc",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_xr_plc_algo_vals),
                0xC0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_jbadaptive,
            {
                "Adaptive Jitter Buffer Algorithm",
                "rtcp.xr.voipmetrics.jba",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_xr_jb_adaptive_vals),
                0x30,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_jbrate,
            {
                "Jitter Buffer Rate",
                "rtcp.xr.voipmetrics.jbrate",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0F,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_jbnominal,
            {
                "Nominal Jitter Buffer Size",
                "rtcp.xr.voipmetrics.jbnominal",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_jbmax,
            {
                "Maximum Jitter Buffer Size",
                "rtcp.xr.voipmetrics.jbmax",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_voip_metrics_jbabsmax,
            {
                "Absolute Maximum Jitter Buffer Size",
                "rtcp.xr.voipmetrics.jbabsmax",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_thinning,
            {
                "Thinning factor",
                "rtcp.xr.tf",
                FT_UINT8,
                BASE_DEC,
                                NULL,
                0x0F,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_loss_flag,
            {
                "Loss Report Flag",
                "rtcp.xr.stats.lrflag",
                FT_BOOLEAN,
                8,
                NULL,
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_dup_flag,
            {
                "Duplicates Report Flag",
                "rtcp.xr.stats.dupflag",
                FT_BOOLEAN,
                8,
                NULL,
                0x40,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_jitter_flag,
            {
                "Jitter Report Flag",
                "rtcp.xr.stats.jitterflag",
                FT_BOOLEAN,
                8,
                NULL,
                0x20,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_ttl,
            {
                "TTL or Hop Limit Flag",
                "rtcp.xr.stats.ttl",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_xr_ip_ttl_vals),
                0x18,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_endseq,
            {
                "End Sequence Number",
                "rtcp.xr.endseq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_chunk_null_terminator,
            {
                "Null Terminator",
                "rtcp.xr.chunk.null_terminator",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_chunk_length,
            {
                "Check length",
                "rtcp.xr.chunk.length",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_chunk_bit_vector,
            {
                "Bit Vector",
                "rtcp.xr.chunk.bit_vector",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },

        {
            &hf_rtcp_xr_beginseq,
            {
                "Begin Sequence Number",
                "rtcp.xr.beginseq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_receipt_time_seq,
            {
                "Receipt Time",
                "rtcp.xr.receipt_time_seq",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_lost,
            {
                "Lost Packets",
                "rtcp.xr.stats.lost",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_dups,
            {
                "Duplicate Packets",
                "rtcp.xr.stats.dups",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_minjitter,
            {
                "Minimum Jitter",
                "rtcp.xr.stats.minjitter",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_maxjitter,
            {
                "Maximum Jitter",
                "rtcp.xr.stats.maxjitter",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_meanjitter,
            {
                "Mean Jitter",
                "rtcp.xr.stats.meanjitter",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_devjitter,
            {
                "Standard Deviation of Jitter",
                "rtcp.xr.stats.devjitter",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_minttl,
            {
                "Minimum TTL or Hop Limit",
                "rtcp.xr.stats.minttl",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_maxttl,
            {
                "Maximum TTL or Hop Limit",
                "rtcp.xr.stats.maxttl",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_meanttl,
            {
                "Mean TTL or Hop Limit",
                "rtcp.xr.stats.meanttl",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_stats_devttl,
            {
                "Standard Deviation of TTL",
                "rtcp.xr.stats.devttl",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_timestamp,
            {
                "Timestamp",
                "rtcp.xr.timestamp",
                FT_ABSOLUTE_TIME,
                ABSOLUTE_TIME_UTC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_lrr,
            {
                "Last RR timestamp",
                "rtcp.xr.lrr",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_dlrr,
            {
                "Delay since last RR timestamp",
                "rtcp.xr.dlrr",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_length_check,
            {
                "RTCP frame length check",
                "rtcp.length_check",
                FT_BOOLEAN,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_fmt,
            {
                "RTCP Feedback message type (FMT)",
                "rtcp.rtpfb.fmt",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_rtpfb_fmt_vals),
                0x1f,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_fmt,
            {
                "RTCP Feedback message type (FMT)",
                "rtcp.psfb.fmt",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_psfb_fmt_vals),
                0x1f,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_nack_pid,
            {
                "RTCP Transport Feedback NACK PID",
                "rtcp.rtpfb.nack_pid",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_nack_blp,
            {
                "RTCP Transport Feedback NACK BLP",
                "rtcp.rtpfb.nack_blp",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_ccfb_beginseq,
            {
                "Begin Sequence Number",
                "rtcp.rtpfb.ccfb.beginseq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_ccfb_numreports,
            {
                "Number Of Reports",
                "rtcp.rtpfb.ccfb.numreports",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_ccfb_received,
            {
                "Received",
                "rtcp.rtpfb.ccfb.received",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x8000,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_ccfb_ecn,
            {
                "Explicit Congestion Notification",
                "rtcp.rtpfb.ccfb.ecn",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x6000,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_ccfb_ato,
            {
                "Arrival Time Offset",
                "rtcp.rtpfb.ccfb.ato",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x1FFF,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_ccfb_padding,
            {
                "Padding",
                "rtcp.rtpfb.ccfb.padding",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_ccfb_timestamp,
            {
                "Timestamp",
                "rtcp.rtpfb.ccfb.timestamp",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_fci,
            {
                "Feedback Control Information (FCI)",
                "rtcp.fci",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_idms_spst,
            {
                "Synchronization Packet Sender Type",
                "rtcp.xr.idms.spst",
                FT_UINT8,
                BASE_DEC,
                VALS(rtcp_xr_idms_spst),
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_idms_pt,
            {
                "Payload Type",
                "rtcp.xr.idms.pt",
                FT_UINT8,
                BASE_DEC,
                                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_idms_msci,
            {
                "Media Stream Correlation Identifier",
                "rtcp.xr.idms.msci",
                FT_UINT32,
                BASE_DEC,
                                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_idms_source_ssrc,
            {
                "Source SSRC",
                "rtcp.xr.idms.source_ssrc",
                FT_UINT32,
                BASE_DEC,
                                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_idms_ntp_rcv_ts,
            {
                "NTP Timestamp of packet reception",
                "rtcp.xr.idms.ntp_rcv_ts",
                FT_ABSOLUTE_TIME,
                ABSOLUTE_TIME_UTC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_idms_rtp_ts,
            {
                "RTP Timestamp of packet",
                "rtcp.xr.idms.rtp_ts",
                FT_UINT32,
                BASE_DEC,
                                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_idms_ntp_pres_ts,
            {
                "NTP Timestamp of presentation",
                "rtcp.xr.idms.ntp_pres_ts",
                FT_UINT32,
                BASE_DEC,
                                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_psfb_fir_fci_ssrc,
            {
                "SSRC",
                "rtcp.psfb.fir.fci.ssrc",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_psfb_fir_fci_csn,
            {
                "Command Sequence Number",
                "rtcp.psfb.fir.fci.csn",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_psfb_fir_fci_reserved,
            {
                "Reserved",
                "rtcp.psfb.fir.fci.reserved",
                FT_UINT24,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
            &hf_rtcp_psfb_sli_first,
            {
                "First MB",
                "rtcp.psfb.fir.sli.first",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0xFFF80000,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_sli_number,
            {
                "Number of MBs",
                "rtcp.psfb.fir.sli.number",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0007FFC0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_sli_picture_id,
            {
                "Picture ID",
                "rtcp.psfb.fir.sli.picture_id",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0000003F,
                NULL, HFILL
            }
        },
        {
      &hf_rtcp_psfb_remb_fci_identifier,
            {
                "Unique Identifier",
                "rtcp.psfb.remb.identifier",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_psfb_remb_fci_ssrc,
            {
                "SSRC",
                "rtcp.psfb.remb.fci.ssrc",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_psfb_remb_fci_number_ssrcs,
            {
                "Number of Ssrcs",
                "rtcp.psfb.remb.fci.number_ssrcs",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_psfb_remb_fci_exp,
            {
                "BR Exp",
                "rtcp.psfb.remb.fci.br_exp",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0xfc,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_psfb_remb_fci_mantissa,
            {
                "Br Mantissa",
                "rtcp.psfb.remb.fci.br_mantissa",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x03ffff,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_psfb_remb_fci_bitrate,
            {
                "Maximum bit rate",
                "rtcp.psfb.remb.fci.bitrate",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_rtpfb_tmbbr_fci_ssrc,
            {
                "SSRC",
                "rtcp.rtpfb.tmmbr.fci.ssrc",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_rtpfb_tmbbr_fci_exp,
            {
                "MxTBR Exp",
                "rtcp.rtpfb.tmmbr.fci.exp",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0xfc,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_rtpfb_tmbbr_fci_mantissa,
            {
                "MxTBR Mantissa",
                "rtcp.rtpfb.tmmbr.fci.mantissa",
                FT_UINT24,
                BASE_DEC,
                NULL,
                0x03fffe,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_rtpfb_tmbbr_fci_bitrate,
            {
                "Maximum total media bit rate",
                "rtcp.rtpfb.tmmbr.fci.bitrate",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
    {
      &hf_rtcp_rtpfb_tmbbr_fci_measuredoverhead,
            {
                "Measured Overhead",
                "rtcp.rtpfb.tmmbr.fci.measuredoverhead",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x01ff,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_transport_cc_fci_base_seq,
            {
                "Base Sequence Number",
                "rtcp.rtpfb.transportcc.baseseq",
                FT_UINT16,
                BASE_DEC_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_transport_cc_fci_pkt_stats_cnt,
            {
                "Packet Status Count",
                "rtcp.rtpfb.transportcc.statuscount",
                FT_UINT16,
                BASE_DEC_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_transport_cc_fci_ref_time,
            {
                "Reference Time",
                "rtcp.rtpfb.transportcc.reftime",
                FT_INT24,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_transport_cc_fci_fb_pkt_cnt,
            {
                "Feedback Packets Count",
                "rtcp.rtpfb.transportcc.pktcount",
                FT_UINT8,
                BASE_DEC_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_transport_cc_fci_pkt_chunk,
            {
                "Packet Chunk",
                "rtcp.rtpfb.transportcc.pktchunk",
                FT_UINT16,
                BASE_DEC_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_transport_cc_fci_recv_delta_1_byte,
            {
                "Recv Delta",
                "rtcp.rtpfb.transportcc.recv_delta",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_transport_cc_fci_recv_delta_2_bytes,
            {
                "Recv Delta",
                "rtcp.rtpfb.transportcc.recv_delta",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_rtpfb_transport_cc_fci_recv_delta_padding,
            {
                "Recv Delta Padding",
                "rtcp.rtpfb.transportcc.recv_delta.padding",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },


        {
            &hf_srtcp_e,
            {
                "SRTCP E flag",
                "srtcp.e",
                FT_BOOLEAN,
                32,
                NULL,
                0x80000000,
                "SRTCP Encryption Flag", HFILL
            }
        },
        {
            &hf_srtcp_index,
            {
                "SRTCP Index",
                "srtcp.index",
                FT_UINT32,
                BASE_DEC_HEX,
                NULL,
                0x7fffffff,
                NULL, HFILL
            }
        },
        {
            &hf_srtcp_mki,
            {
                "SRTCP MKI",
                "srtcp.mki",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0,
                "SRTCP Master Key Index", HFILL
            }
        },
        {
            &hf_srtcp_auth_tag,
            {
                "SRTCP Auth Tag",
                "srtcp.auth_tag",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0,
                "SRTCP Authentication Tag", HFILL
            }
        },
        /* additions for BT XNQ block as defined in RFC5093 */
        {
            &hf_rtcp_xr_btxnq_begseq,
            {
                "Starting sequence number",
                "rtcp.xr.btxnq.begseq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_endseq,
            {
                "Last sequence number",
                "rtcp.xr.btxnq.endseq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_vmaxdiff,
            {
                "Maximum IPDV difference in 1 cycle",
                "rtcp.xr.btxnq.vmaxdiff",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_vrange,
            {
                "Maximum IPDV difference seen to date",
                "rtcp.xr.btxnq.vrange",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_vsum,
            {
                "Sum of peak IPDV differences to date",
                "rtcp.xr.btxnq.vsum",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_cycles,
            {
                "Number of cycles in calculation",
                "rtcp.xr.btxnq.cycles",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_jbevents,
            {
                "Number of jitter buffer adaptations to date",
                "rtcp.xr.btxnq.jbevents",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_spare,
            {
                "Spare/reserved bits",
                "rtcp.xr.btxnq.spare",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_tdegnet,
            {
                "Time degraded by packet loss or late delivery",
                "rtcp.xr.btxnq.tdegnet",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_tdegjit,
            {
                "Time degraded by jitter buffer adaptation events",
                "rtcp.xr.btxnq.tdegjit",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_es,
            {
                "ES due to unavailable packet events",
                "rtcp.xr.btxnq.es",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_xr_btxnq_ses,
            {
                "SES due to unavailable packet events",
                "rtcp.xr.btxnq.ses",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        /* MS Profile Specific Extension Fields */
        {
            &hf_rtcp_pse_ms_bandwidth,
            {
                "Bandwidth",
                "rtcp.ms_pse.bandwidth",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_confidence_level,
            {
                "Confidence Level",
                "rtcp.ms_pse.confidence_level",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_seq_num,
            {
                "Sequence Number",
                "rtcp.ms_pse.seq_num",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_frame_resolution_width,
            {
                "Frame Resolution Width",
                "rtcp.ms_pse.frame_res_width",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_frame_resolution_height,
            {
                "Frame Resolution Height",
                "rtcp.ms_pse.frame_res_height",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_bitrate,
            {
                "Bitrate",
                "rtcp.ms_pse.bitrate",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_frame_rate,
            {
                "Frame Rate",
                "rtcp.ms_pse.frame_rate",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_concealed_frames,
            {
                "Concealed Frames",
                "rtcp.ms_pse.concealed_frames",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_stretched_frames,
            {
                "Stretched Frames",
                "rtcp.ms_pse.stretched_frames",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_compressed_frames,
            {
                "Compressed Frames",
                "rtcp.ms_pse.compressed_frames",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_total_frames,
            {
                "Total Frames",
                "rtcp.ms_pse.total_frames",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_receive_quality_state,
            {
                "Received Quality State",
                "rtcp.ms_pse.receive_quality_state",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_fec_distance_request,
            {
                "FEC Distance Request",
                "rtcp.ms_pse.fec_distance_request",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_last_packet_train,
            {
                "Last Packet Train Flag",
                "rtcp.ms_pse.last_packet_train",
                FT_BOOLEAN,
                8,
                NULL,
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_packet_idx,
            {
                "Packet Index",
                "rtcp.ms_pse.packet_index",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x7f,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_packet_cnt,
            {
                "Packet Count",
                "rtcp.ms_pse.packet_count",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x7f,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_packet_train_byte_cnt,
            {
                "Packet Train Byte Count",
                "rtcp.ms_pse.packet_train_byte_count",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_inbound_bandwidth,
            {
                "Inbound Link Bandwidth",
                "rtcp.ms_pse.inbound_bandwidth",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_outbound_bandwidth,
            {
                "Outbound Link Bandwidth",
                "rtcp.ms_pse.outbound_bandwidth",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_no_cache,
            {
                "No Cache Flag",
                "rtcp.ms_pse.no_cache",
                FT_BOOLEAN,
                8,
                NULL,
                0x80,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_congestion_info,
            {
                "Congestion Information",
                "rtcp.ms_pse.congestion_info",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_pse_ms_modality,
            {
                "Modality",
                "rtcp.ms_pse.modality",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },

        /* Microsoft PLI */
        {
            &hf_rtcp_psfb_pli_ms_request_id,
            {
                "Request ID",
                "rtcp.psfb.ms.pli.request_id",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_pli_ms_sfr,
            {
                "Sync Frame Request",
                "rtcp.psfb.ms.pli.sync_frame_request",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },

        /* Microsoft Application Feedback Video Source Request */
        {
            &hf_rtcp_psfb_ms_type,
            {
                "Application Layer Feedback Type",
                "rtcp.psfb.ms.afb_type",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_length,
            {
                "Length",
                "rtcp.psfb.ms.length",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_msi,
            {
                "Requested Media Source ID (MSI)",
                "rtcp.psfb.ms.msi",
                FT_UINT32,
                BASE_HEX_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsr_request_id,
            {
                "Request Id",
                "rtcp.psfb.ms.vsr.request_id",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsr_version,
            {
                "Version",
                "rtcp.psfb.ms.vsr.version",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsr_key_frame_request,
            {
                "Key Frame Request",
                "rtcp.psfb.ms.vsr.key_frame_request",
                FT_BOOLEAN,
                8,
                NULL,
                0x01,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsr_num_entries,
            {
                "Number of Entries",
                "rtcp.psfb.ms.vsr.num_entries",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsr_entry_length,
            {
                "Entry Length",
                "rtcp.psfb.ms.vsr.entry_length",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_payload_type,
            {
                "Payload Type",
                "rtcp.psfb.ms.vsr.entry.payload_type",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_ucconfig_mode,
            {
                "UCConfig Mode",
                "rtcp.psfb.ms.vsr.entry.ucconfig_mode",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_no_sp_frames,
            {
                "No support for SP Frames (RT only)",
                "rtcp.psfb.ms.vsr.entry.no_sp_frames",
                FT_BOOLEAN,
                8,
                NULL,
                0x04,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_baseline,
            {
                "Only Supports Constrained Baseline (H.264 only)",
                "rtcp.psfb.ms.vsr.entry.no_sp_baseline",
                FT_BOOLEAN,
                8,
                NULL,
                0x02,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_cgs,
            {
                "Supports CGS rewrite (H.264 only)",
                "rtcp.psfb.ms.vsr.entry.cgs",
                FT_BOOLEAN,
                8,
                NULL,
                0x01,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_aspect_ratio_bitmask,
            {
                "Aspect Ratio Bitmask",
                "rtcp.psfb.ms.vsr.entry.aspect_ratio",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_aspect_ratio_4by3,
            {
                "Aspect Ratio 4 by 3",
                "rtcp.psfb.ms.vsr.entry.aspect_ratio_4by3",
                FT_BOOLEAN,
                8,
                NULL,
                0x01,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_aspect_ratio_16by9,
            {
                "Aspect Ratio 16 by 9",
                "rtcp.psfb.ms.vsr.entry.aspect_ratio_16by9",
                FT_BOOLEAN,
                8,
                NULL,
                0x02,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_aspect_ratio_1by1,
            {
                "Aspect Ratio 1 by 1",
                "rtcp.psfb.ms.vsr.entry.aspect_ratio_1by1",
                FT_BOOLEAN,
                8,
                NULL,
                0x04,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_aspect_ratio_3by4,
            {
                "Aspect Ratio 3 by 4",
                "rtcp.psfb.ms.vsr.entry.aspect_ratio_3by4",
                FT_BOOLEAN,
                8,
                NULL,
                0x08,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_aspect_ratio_9by16,
            {
                "Aspect Ratio 9 by 16",
                "rtcp.psfb.ms.vsr.entry.aspect_ratio_9by16",
                FT_BOOLEAN,
                8,
                NULL,
                0x10,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_aspect_ratio_20by3,
            {
                "Aspect Ratio 20 by 3",
                "rtcp.psfb.ms.vsr.entry.aspect_ratio_20by3",
                FT_BOOLEAN,
                8,
                NULL,
                0x20,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_max_width,
            {
                "Max Width",
                "rtcp.psfb.ms.vsr.entry.max_width",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_max_height,
            {
                "Max Height",
                "rtcp.psfb.ms.vsr.entry.max_height",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_min_bitrate,
            {
                "Min bit rate",
                "rtcp.psfb.ms.vsr.entry.min_bitrate",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_bitrate_per_level,
            {
                "Bit rate per level",
                "rtcp.psfb.ms.vsr.entry.bitrate_per_level",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_bitrate_histogram,
            {
                "Receiver Count",
                "rtcp.psfb.ms.vsr.entry.bitrate_histogram",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_frame_rate_mask,
            {
                "Frame rate mask",
                "rtcp.psfb.ms.vsr.entry.frame_rate_mask",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_frame_rate_7_5,
            {
                "7.5 fps",
                "rtcp.psfb.ms.vsr.entry.frame_rate_7_5",
                FT_BOOLEAN,
                8,
                NULL,
                0x01,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_frame_rate_12_5,
            {
                "12.5 fps",
                "rtcp.psfb.ms.vsr.entry.frame_rate_12_5",
                FT_BOOLEAN,
                8,
                NULL,
                0x02,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_frame_rate_15,
            {
                "15 fps",
                "rtcp.psfb.ms.vsr.entry.frame_rate_15",
                FT_BOOLEAN,
                8,
                NULL,
                0x04,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_frame_rate_25,
            {
                "25 fps",
                "rtcp.psfb.ms.vsr.entry.frame_rate_25",
                FT_BOOLEAN,
                8,
                NULL,
                0x08,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_frame_rate_30,
            {
                "30 fps",
                "rtcp.psfb.ms.vsr.entry.frame_rate_30",
                FT_BOOLEAN,
                8,
                NULL,
                0x10,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_frame_rate_50,
            {
                "50 fps",
                "rtcp.psfb.ms.vsr.entry.frame_rate_50",
                FT_BOOLEAN,
                8,
                NULL,
                0x20,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_frame_rate_60,
            {
                "60 fps",
                "rtcp.psfb.ms.vsr.entry.frame_rate_60",
                FT_BOOLEAN,
                8,
                NULL,
                0x40,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_must_instances,
            {
                "Number of MUST instances",
                "rtcp.psfb.ms.vsr.entry.musts",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_may_instances,
            {
                "Number of MAY instances",
                "rtcp.psfb.ms.vsr.entry.mays",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_quality_histogram,
            {
                "Receiver Count",
                "rtcp.psfb.ms.vsr.entry.quality_histogram",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {
            &hf_rtcp_psfb_ms_vsre_max_pixels,
            {
                "Max Pixels per Frame",
                "rtcp.psfb.ms.vsr.entry.max_pixels",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL, HFILL
            }
        },
        {&hf_rtcp_mcptt_fld_id,
            { "Field Id", "rtcp.mcptt.fld_id",
            FT_UINT32, BASE_DEC, VALS(rtcp_mcpt_field_id_vals), 0x0,
            NULL, HFILL }
        },
        {&hf_rtcp_mcptt_fld_len,
            { "Length", "rtcp.mcptt.fld_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_fld_val,
        { "Field value", "rtcp.mcptt.fld_val",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_granted_partys_id,
        { "Granted Party's Identity", "rtcp.mcptt.granted_partys_id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_app_data_padding,
            { "Padding", "rtcp.app_data.padding",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_priority,
            { "Floor Priority", "rtcp.app_data.mcptt.priority",
            FT_UINT16, BASE_DEC, NULL, 0xff00,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_user_id,
            { "User ID", "rtcp.app_data.mcptt.user_id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_duration,
            { "Duration", "rtcp.app_data.mcptt.duration",
            FT_UINT16, BASE_DEC | BASE_UNIT_STRING, UNS(& units_second_seconds), 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_floor_ind,
            { "Floor Indicator", "rtcp.app_data.mcptt.floor_ind",
            FT_UINT16, BASE_DEC, VALS(mcptt_floor_ind_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_rej_cause,
            { "Reject Cause", "rtcp.app_data.mcptt.rej_cause",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_rej_cause_floor_deny,
            { "Reject Cause", "rtcp.app_data.mcptt.rej_cause.floor_deny",
            FT_UINT16, BASE_DEC, VALS(rtcp_mcptt_rej_cause_floor_deny_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_rej_cause_floor_revoke,
            { "Reject Cause", "rtcp.app_data.mcptt.rej_cause.floor_revoke",
            FT_UINT16, BASE_DEC, VALS(rtcp_mcptt_rej_cause_floor_revoke_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_rej_phrase,
        { "Reject Phrase", "rtcp.mcptt.rej_phrase",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_queue_pos_inf,
            { "Queue Position Info", "rtcp.app_data.mcptt.queue_pos_inf",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_queue_pri_lev,
            { "Queue Priority Level", "rtcp.app_data.mcptt.queue_pri_lev",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_perm_to_req_floor,
            { "Permission to Request the Floor", "rtcp.app_data.mcptt.perm_to_req_floor",
            FT_UINT16, BASE_DEC, VALS(rtcp_mcptt_perm_to_req_floor_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_queue_size,
            { "Queue Size", "rtcp.app_data.mcptt.queue_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_msg_seq_num,
            { "Message Sequence Number", "rtcp.app_data.mcptt.msg_seq_num",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_queued_user_id,
        { "Queued User ID", "rtcp.mcptt.queued_user_id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_source,
            { "Source", "rtcp.app_data.mcptt.source",
            FT_UINT16, BASE_DEC, VALS(rtcp_mcptt_source_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_queueing_cap,
            { "Queueing Capability", "rtcp.app_data.mcptt.queueing_cap",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_part_type_len,
            { "Participant Type Length", "rtcp.app_data.mcptt.part_type_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_participant_type,
        { "Participant Type", "rtcp.mcptt.participant_type",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_participant_ref,
            { "Floor Participant Reference", "rtcp.app_data.mcptt.floor_participant_ref",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_ssrc,
            { "SSRC", "rtcp.app_data.mcptt.rtcp",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_num_users,
            { "Number of users", "rtcp.app_data.mcptt.num_users",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_user_id_len,
            { "User ID length", "rtcp.app_data.mcptt.user_id_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_spare16,
            { "Spare", "rtcp.spare16",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_num_ssrc,
            { "Number of SSRC", "rtcp.app_data.mcptt.num_ssrc",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_func_alias,
        { "Functional Alias", "rtcp.mcptt.func_alias",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_fa_len,
            { "Functional Alias length", "rtcp.app_data.mcptt.fa_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_num_fas,
            { "Number of Functional Alias", "rtcp.app_data.mcptt.num_fa",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_loc_type,
            { "Location Type", "rtcp.app_data.mcptt.loc_type",
            FT_UINT8, BASE_DEC, VALS(rtcp_mcptt_loc_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_cellid,
         {"CellId", "rtcp.app_data.mcptt.cellid",
          FT_UINT32, BASE_DEC, NULL, 0xFF,
          NULL, HFILL}
        },
        { &hf_rtcp_mcptt_enodebid,
         { "eNodeB Id", "rtcp.app_data.mcptt.enodebid",
          FT_UINT32, BASE_DEC, NULL, 0x0FFFFF00,
          NULL, HFILL }
        },
        { &hf_rtcp_mcptt_ecgi_eci,
         {"ECI (E-UTRAN Cell Identifier)", "rtcp.app_data.mcptt.ecgi_eci",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        { &hf_rtcp_mcptt_tac,
            { "Tracking Area Code", "rtcp.app_data.mcptt.tac",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_mbms_serv_area,
            { "MBMS Service Area", "rtcp.app_data.mcptt.mbms_serv_area",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_mbsfn_area_id,
            { "MBSFN Area ID", "rtcp.app_data.mcptt.mbsfn_area_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_lat,
            { "Latitude value", "rtcp.app_data.mcptt.lat",
            FT_INT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_long,
            { "Longitude value", "rtcp.app_data.mcptt.long",
            FT_INT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_msg_type,
            { "Message Type", "rtcp.app_data.mcptt.msg_type",
            FT_UINT8, BASE_DEC, VALS(rtcp_mcpt_subtype_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_num_loc,
            { "Number of Locations", "rtcp.app_data.mcptt.num_loc",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_str,
            { "String", "rtcp.app_data.mcptt.str",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mccp_len,
            { "Length", "rtcp.app_data.mccp.len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mccp_field_id,
            { "Field id", "rtcp.app_data.mccp.field_id",
            FT_UINT8, BASE_DEC, VALS(rtcp_mccp_field_id_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mcptt_group_id,
            { "MCPTT Group Identity", "rtcp.app_data.mccp.mcptt_grp_id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mccp_audio_m_line_no,
            { "Audio m-line Number", "rtcp.app_data.mccp.audio_m_line_no",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_rtcp_mccp_floor_m_line_no,
            { "Floor m-line Number", "rtcp.app_data.mccp.floor_m_line_no",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_rtcp_mccp_ip_version,
            { "IP version", "rtcp.app_data.mccp.ip_version",
            FT_UINT8, BASE_DEC, NULL, 0xf0,
            NULL, HFILL }
        },
        { &hf_rtcp_mccp_floor_port_no,
            { "Floor Port Number", "rtcp.app_data.mccp.floor_port_no",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mccp_media_port_no,
            { "Media Port Number", "rtcp.app_data.mccp.media_port_no",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mccp_ipv4,
            { "IP Address", "rtcp.app_data.mccp.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mccp_ipv6,
            { "IP Address", "rtcp.app_data.mccp.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_mccp_tmgi,
            { "TMGI", "rtcp.app_data.mccp.tmgi",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rtcp_encrypted,
            { "Encrypted data", "rtcp.encrypted",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static int *ett[] =
    {
        &ett_rtcp,
        &ett_rtcp_sr,
        &ett_rtcp_rr,
        &ett_rtcp_sdes,
        &ett_rtcp_bye,
        &ett_rtcp_app,
        &ett_rtcp_rtpfb,
        &ett_rtcp_rtpfb_ccfb_fci,
        &ett_rtcp_rtpfb_ccfb_media_source,
        &ett_rtcp_rtpfb_ccfb_metric_blocks,
        &ett_rtcp_rtpfb_ccfb_metric_block,
        &ett_rtcp_psfb,
        &ett_rtcp_xr,
        &ett_rtcp_fir,
        &ett_rtcp_nack,
        &ett_ssrc,
        &ett_ssrc_item,
        &ett_ssrc_ext_high,
        &ett_sdes,
        &ett_sdes_item,
        &ett_PoC1,
        &ett_mux,
        &ett_rtcp_setup,
        &ett_rtcp_roundtrip_delay,
        &ett_xr_block,
        &ett_xr_block_contents,
        &ett_xr_ssrc,
        &ett_xr_loss_chunk,
        &ett_poc1_conn_contents,
        &ett_rtcp_nack_blp,
        &ett_pse,
        &ett_ms_vsr,
        &ett_ms_vsr_entry,
        &ett_ms_ds,
        &ett_rtcp_mcpt,
        &ett_rtcp_mcptt_participant_ref,
        &ett_rtcp_mcptt_eci,
        &ett_rtcp_mccp_tmgi
    };

    static ei_register_info ei[] = {
        { &ei_rtcp_not_final_padding, { "rtcp.not_final_padding", PI_PROTOCOL, PI_WARN, "Padding flag set on not final packet (see RFC3550, section 6.4.1)", EXPFILL }},
        { &ei_rtcp_bye_reason_not_padded, { "rtcp.bye_reason_not_padded", PI_MALFORMED, PI_WARN, "Reason string is not NULL padded (see RFC3550, section 6.6)", EXPFILL }},
        { &ei_rtcp_xr_block_length_bad, { "rtcp.invalid_block_length", PI_PROTOCOL, PI_WARN, "Invalid block length, should be 2", EXPFILL }},
        { &ei_rtcp_roundtrip_delay, { "rtcp.roundtrip-delay.expert", PI_SEQUENCE, PI_NOTE, "RTCP round-trip delay detected (%d ms)", EXPFILL }},
        { &ei_rtcp_roundtrip_delay_negative, { "rtcp.roundtrip-delay.negative", PI_SEQUENCE, PI_ERROR, "Negative RTCP round-trip delay detected (%d ms)", EXPFILL }},
        { &ei_rtcp_length_check, { "rtcp.length_check.bad", PI_MALFORMED, PI_WARN, "Incorrect RTCP packet length information (expected %u bytes, found %d)", EXPFILL }},
        { &ei_rtcp_psfb_ms_type, { "rtcp.psfb.ms.afb_type.unknown", PI_PROTOCOL, PI_WARN, "Unknown Application Layer Feedback Type", EXPFILL }},
        { &ei_rtcp_missing_sender_ssrc, { "rtcp.missing_sender_ssrc", PI_PROTOCOL, PI_WARN, "Missing Sender SSRC", EXPFILL }},
        { &ei_rtcp_missing_block_header, { "rtcp.missing_block_header", PI_PROTOCOL, PI_WARN, "Missing Required Block Headers", EXPFILL }},
        { &ei_rtcp_block_length, { "rtcp.block_length.invalid", PI_PROTOCOL, PI_WARN, "Block length is greater than packet length", EXPFILL }},
        { &ei_srtcp_encrypted_payload, { "srtcp.encrypted_payload", PI_UNDECODED, PI_WARN, "Encrypted RTCP Payload - not dissected", EXPFILL }},
        { &ei_rtcp_rtpfb_transportcc_bad, { "rtcp.rtpfb.transportcc_bad", PI_MALFORMED, PI_WARN, "Too many packet chunks (more than packet status count)", EXPFILL }},
        { &ei_rtcp_rtpfb_fmt_not_implemented, { "rtcp.rtpfb.fmt_not_implemented", PI_UNDECODED, PI_WARN, "RTPFB FMT not dissected, contact Wireshark developers if you want this to be supported", EXPFILL }},
        { &ei_rtcp_rtpfb_ccfb_too_many_reports, { "rtcp.mcptt.ccfb.invalid_pkt", PI_UNDECODED, PI_WARN, "RTPFB CCFB report block must not include more than 2^14 metric blocks", EXPFILL }},
        { &ei_rtcp_mcptt_unknown_fld, { "rtcp.mcptt.unknown_fld", PI_PROTOCOL, PI_WARN, "Unknown field", EXPFILL }},
        { &ei_rtcp_mcptt_location_type, { "rtcp.mcptt.location_type_uk", PI_PROTOCOL, PI_WARN, "Unknown location type", EXPFILL }},
        { &ei_rtcp_appl_extra_bytes, { "rtcp.appl.extra_bytes", PI_PROTOCOL, PI_ERROR, "Extra bytes detected", EXPFILL }},
        { &ei_rtcp_appl_not_ascii, { "rtcp.appl.not_ascii", PI_PROTOCOL, PI_ERROR, "Application name is not a string", EXPFILL }},
        { &ei_rtcp_appl_non_conformant, { "rtcp.appl.non_conformant", PI_PROTOCOL, PI_ERROR, "Data not according to standards", EXPFILL }},
        { &ei_rtcp_appl_non_zero_pad, { "rtcp.appl.non_zero_pad", PI_PROTOCOL, PI_ERROR, "Non zero padding detected, faulty encoding?", EXPFILL }},
    };

    module_t *rtcp_module, *srtcp_module;
    expert_module_t* expert_rtcp;

    proto_rtcp = proto_register_protocol("Real-time Transport Control Protocol", "RTCP", "rtcp");
    proto_srtcp = proto_register_protocol("Secure Real-time Transport Control Protocol", "SRTCP", "srtcp");
    proto_register_field_array(proto_rtcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_rtcp = expert_register_protocol(proto_rtcp);
    expert_register_field_array(expert_rtcp, ei, array_length(ei));

    rtcp_handle = register_dissector("rtcp", dissect_rtcp, proto_rtcp);
    srtcp_handle = register_dissector("srtcp", dissect_srtcp, proto_srtcp);

    rtcp_module = prefs_register_protocol(proto_rtcp, NULL);
    srtcp_module = prefs_register_protocol(proto_srtcp, NULL);

    prefs_register_enum_preference(rtcp_module, "default_protocol",
        "Default protocol",
        "The default protocol assumed by the heuristic dissector, "
        "which does not easily distinguish between RTCP and SRTCP.",
        &global_rtcp_default_protocol,
        rtcp_default_protocol_vals,
        false);

    prefs_register_bool_preference(rtcp_module, "show_setup_info",
        "Show stream setup information",
        "Where available, show which protocol and frame caused "
        "this RTCP stream to be created",
        &global_rtcp_show_setup_info);

    prefs_register_obsolete_preference(rtcp_module, "heuristic_rtcp");

    prefs_register_bool_preference(rtcp_module, "show_roundtrip_calculation",
        "Show relative roundtrip calculations",
        "Try to work out network delay by comparing time between packets "
        "as captured and delays as seen by endpoint",
        &global_rtcp_show_roundtrip_calculation);

    prefs_register_uint_preference(rtcp_module, "roundtrip_min_threshhold",
        "Minimum roundtrip calculation to report (ms)",
        "Minimum (absolute) calculated roundtrip delay time in milliseconds that "
        "should be reported",
        10, &global_rtcp_show_roundtrip_calculation_minimum);

    /* To get the subtype decoded for SRTP packets */
    prefs_register_enum_preference(srtcp_module, "decode_application_subtype",
        "Decode Application subtype as",
        "Decode the subtype as this application",
        &preferences_application_specific_encoding, rtcp_application_specific_encoding_vals, false);

    /* Register table for sub-dissectors */
    rtcp_dissector_table = register_dissector_table("rtcp.app.name", "RTCP Application Name", proto_rtcp, FT_STRING, STRING_CASE_SENSITIVE);
    rtcp_psfb_dissector_table = register_dissector_table("rtcp.psfb.fmt", "RTCP Payload Specific Feedback Message Format", proto_rtcp, FT_UINT8, BASE_DEC);
    rtcp_rtpfb_dissector_table = register_dissector_table("rtcp.rtpfb.fmt", "RTCP Generic RTP Feedback Message Format", proto_rtcp, FT_UINT8, BASE_DEC);
    rtcp_pse_dissector_table = register_dissector_table("rtcp.pse", "RTCP Profile Specific Extension", proto_rtcp, FT_UINT16, BASE_DEC);

    proto_rtcp_ms_pse = proto_register_protocol_in_name_only("Microsoft RTCP Profile Specific Extensions", "MS-RTP PSE", "rtcp_ms_pse", proto_rtcp, FT_BYTES);
    register_subdissectors_for_rtcp_rtpfb_dissector_table();

    ms_pse_handle = register_dissector("rtcp_ms_pse", dissect_ms_profile_specific_extensions, proto_rtcp_ms_pse);
}

void
proto_reg_handoff_rtcp(void)
{
    /*
     * Register this dissector as one that can be selected by a
     * UDP port number.
     */
    dissector_add_for_decode_as_with_preference("udp.port", rtcp_handle);
    dissector_add_for_decode_as("flip.payload", rtcp_handle );
    dissector_add_for_decode_as_with_preference("udp.port", srtcp_handle);

    for (int idx = 0; rtcp_ms_profile_extension_vals[idx].strptr != NULL; idx++) {
        dissector_add_uint("rtcp.pse", rtcp_ms_profile_extension_vals[idx].value, ms_pse_handle);
    }

    add_entries_for_rtcp_rtpfb_dissector_table();

    heur_dissector_add( "udp", dissect_rtcp_heur, "RTCP over UDP", "rtcp_udp", proto_rtcp, HEURISTIC_ENABLE);
    heur_dissector_add("stun", dissect_rtcp_heur, "RTCP over TURN", "rtcp_stun", proto_rtcp, HEURISTIC_ENABLE);
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

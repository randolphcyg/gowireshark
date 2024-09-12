/* packet-btavdtp.c
 * Routines for Bluetooth AVDTP dissection
 *
 * Copyright 2012, Michal Labedzki for Tieto Corporation
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
#include <epan/prefs.h>
#include <epan/unit_strings.h>

#include "packet-bluetooth.h"
#include "packet-btl2cap.h"
#include "packet-btavdtp.h"
#include "packet-btavrcp.h"
#include "packet-rtp.h"

#define AVDTP_MESSAGE_TYPE_MASK  0x03
#define AVDTP_PACKET_TYPE_MASK   0x0C
#define AVDTP_TRANSACTION_MASK   0xF0
#define AVDTP_SIGNAL_ID_MASK     0x3F
#define AVDTP_RFA0_MASK          0xC0

#define MESSAGE_TYPE_COMMAND          0x00
#define MESSAGE_TYPE_GENERAL_REJECT   0x01
#define MESSAGE_TYPE_ACCEPT           0x02
#define MESSAGE_TYPE_REJECT           0x03

#define PACKET_TYPE_SINGLE            0x00
#define PACKET_TYPE_START             0x01
#define PACKET_TYPE_CONTINUE          0x02
#define PACKET_TYPE_END               0x03

#define SIGNAL_ID_DISCOVER                  0x01
#define SIGNAL_ID_GET_CAPABILITIES          0x02
#define SIGNAL_ID_SET_CONFIGURATION         0x03
#define SIGNAL_ID_GET_CONFIGURATION         0x04
#define SIGNAL_ID_RECONFIGURE               0x05
#define SIGNAL_ID_OPEN                      0x06
#define SIGNAL_ID_START                     0x07
#define SIGNAL_ID_CLOSE                     0x08
#define SIGNAL_ID_SUSPEND                   0x09
#define SIGNAL_ID_ABORT                     0x0A
#define SIGNAL_ID_SECURITY_CONTROL          0x0B
#define SIGNAL_ID_GET_ALL_CAPABILITIES      0x0C
#define SIGNAL_ID_DELAY_REPORT              0x0D

#define SERVICE_CATEGORY_MEDIA_TRANSPORT     0x01
#define SERVICE_CATEGORY_REPORTING           0x02
#define SERVICE_CATEGORY_RECOVERY            0x03
#define SERVICE_CATEGORY_CONTENT_PROTECTION  0x04
#define SERVICE_CATEGORY_HEADER_COMPRESSION  0x05
#define SERVICE_CATEGORY_MULTIPLEXING        0x06
#define SERVICE_CATEGORY_MEDIA_CODEC         0x07
#define SERVICE_CATEGORY_DELAY_REPORTING     0x08

#define MEDIA_TYPE_AUDIO   0x00
#define MEDIA_TYPE_VIDEO   0x01

#define SEID_ACP     0x00
#define SEID_INT     0x01

#define STREAM_TYPE_MEDIA   0x00
#define STREAM_TYPE_SIGNAL  0x01

#define CODEC_DEFAULT         0xFFFF
#define CODEC_SBC             0x00
#define CODEC_MPEG12_AUDIO    0x01
#define CODEC_MPEG24_AAC      0x02
#define CODEC_ATRAC           0x04
#define CODEC_APT_X           0xFF01
#define CODEC_APT_X_HD        0xFF24
#define CODEC_LDAC            0xFFAA

#define CODECID_APT_X         0x0001
#define CODECID_APT_X_HD      0x0024

#define CODEC_H263_BASELINE   0x01
#define CODEC_MPEG4_VSP       0x02
#define CODEC_H263_PROFILE_3  0x03
#define CODEC_H263_PROFILE_8  0x04

#define CODEC_VENDOR          0xFF

#define HEADER_SIZE  2
#define SEP_MAX     64
#define SEP_SIZE     2

/* ========================================================== */
/* Story: RTP Player, conversation (probably reassemble too) use address:port as
   "key" to separate devices/streams. In Bluetooth World it is not enough to
   separate devices/streams. Example key:
        uint32_t interface_id (aka frame.interface_id)
        uint32_t adapter_id (interface like "bluetooth-monitor" or USB provide
                            more than one device over interface, so we must
                            separate information provided by each one)
        uint16_t hci_chandle (aka "connection handle" use to separate connections to devices)
        uint16_t l2cap_psm (like hci_chandle but over l2cap layer, need hci_chandle info because
                           the same PSM can be used over chandles)
        uint8_t rfcomm_channel (like l2cap_psm, but over RFCOMM layer...)
        etc. like
        uint8_t stram_endpoint_number
        uint32_t stream_number (to separate multiple streams for RTP Player)

    So keys can be various (length or type) and "ports" are not enough to sore
    all needed information. If one day that changed then all RTP_PLAYER_WORKAROUND
    block can be removed. This workaround use global number of streams (aka stream ID)
    to be used as port number in RTP Player to separate streams.
        */
#define RTP_PLAYER_WORKAROUND true

#if RTP_PLAYER_WORKAROUND == true
    wmem_tree_t *file_scope_stream_number = NULL;
#endif
/* ========================================================== */

static int proto_btavdtp;

static int hf_btavdtp_data;
static int hf_btavdtp_message_type;
static int hf_btavdtp_packet_type;
static int hf_btavdtp_transaction;
static int hf_btavdtp_signal;
static int hf_btavdtp_signal_id;
static int hf_btavdtp_rfa0;
static int hf_btavdtp_number_of_signal_packets;
static int hf_btavdtp_sep_seid;
static int hf_btavdtp_sep_inuse;
static int hf_btavdtp_sep_rfa0;
static int hf_btavdtp_sep_media_type;
static int hf_btavdtp_sep_type;
static int hf_btavdtp_sep_rfa1;
static int hf_btavdtp_error_code;
static int hf_btavdtp_acp_sep;
static int hf_btavdtp_acp_seid_item;
static int hf_btavdtp_int_seid_item;
static int hf_btavdtp_acp_seid;
static int hf_btavdtp_int_seid;
static int hf_btavdtp_service_category;
static int hf_btavdtp_rfa_seid;
static int hf_btavdtp_delay;
static int hf_btavdtp_length_of_service_category;
static int hf_btavdtp_recovery_type;
static int hf_btavdtp_maximum_recovery_window_size;
static int hf_btavdtp_maximum_number_of_media_packet_in_parity_code;
static int hf_btavdtp_multiplexing_fragmentation;
static int hf_btavdtp_multiplexing_rfa;
static int hf_btavdtp_multiplexing_tsid;
static int hf_btavdtp_multiplexing_tcid;
static int hf_btavdtp_multiplexing_entry_rfa;
static int hf_btavdtp_header_compression_backch;
static int hf_btavdtp_header_compression_media;
static int hf_btavdtp_header_compression_recovery;
static int hf_btavdtp_header_compression_rfa;
static int hf_btavdtp_content_protection_type;
static int hf_btavdtp_media_codec_media_type;
static int hf_btavdtp_media_codec_rfa;
static int hf_btavdtp_media_codec_unknown_type;
static int hf_btavdtp_media_codec_audio_type;
static int hf_btavdtp_media_codec_video_type;
static int hf_btavdtp_sbc_sampling_frequency_16000;
static int hf_btavdtp_sbc_sampling_frequency_32000;
static int hf_btavdtp_sbc_sampling_frequency_44100;
static int hf_btavdtp_sbc_sampling_frequency_48000;
static int hf_btavdtp_sbc_channel_mode_mono;
static int hf_btavdtp_sbc_channel_mode_dual_channel;
static int hf_btavdtp_sbc_channel_mode_stereo;
static int hf_btavdtp_sbc_channel_mode_joint_stereo;
static int hf_btavdtp_sbc_block_4;
static int hf_btavdtp_sbc_block_8;
static int hf_btavdtp_sbc_block_12;
static int hf_btavdtp_sbc_block_16;
static int hf_btavdtp_sbc_subbands_4;
static int hf_btavdtp_sbc_subbands_8;
static int hf_btavdtp_sbc_allocation_method_snr;
static int hf_btavdtp_sbc_allocation_method_loudness;
static int hf_btavdtp_sbc_min_bitpool;
static int hf_btavdtp_sbc_max_bitpool;
static int hf_btavdtp_mpeg12_layer_1;
static int hf_btavdtp_mpeg12_layer_2;
static int hf_btavdtp_mpeg12_layer_3;
static int hf_btavdtp_mpeg12_crc_protection;
static int hf_btavdtp_mpeg12_channel_mode_mono;
static int hf_btavdtp_mpeg12_channel_mode_dual_channel;
static int hf_btavdtp_mpeg12_channel_mode_stereo;
static int hf_btavdtp_mpeg12_channel_mode_joint_stereo;
static int hf_btavdtp_mpeg12_rfa;
static int hf_btavdtp_mpeg12_mpf_2;
static int hf_btavdtp_mpeg12_sampling_frequency_16000;
static int hf_btavdtp_mpeg12_sampling_frequency_22050;
static int hf_btavdtp_mpeg12_sampling_frequency_24000;
static int hf_btavdtp_mpeg12_sampling_frequency_32000;
static int hf_btavdtp_mpeg12_sampling_frequency_44100;
static int hf_btavdtp_mpeg12_sampling_frequency_48000;
static int hf_btavdtp_mpeg12_vbr_supported;
static int hf_btavdtp_mpeg12_bit_rate;
static int hf_btavdtp_mpeg24_object_type_mpeg2_aac_lc;
static int hf_btavdtp_mpeg24_object_type_mpeg4_aac_lc;
static int hf_btavdtp_mpeg24_object_type_mpeg4_aac_ltp;
static int hf_btavdtp_mpeg24_object_type_mpeg4_aac_scalable;
static int hf_btavdtp_mpeg24_object_type_rfa;
static int hf_btavdtp_mpeg24_sampling_frequency_8000;
static int hf_btavdtp_mpeg24_sampling_frequency_11025;
static int hf_btavdtp_mpeg24_sampling_frequency_12000;
static int hf_btavdtp_mpeg24_sampling_frequency_16000;
static int hf_btavdtp_mpeg24_sampling_frequency_22050;
static int hf_btavdtp_mpeg24_sampling_frequency_24000;
static int hf_btavdtp_mpeg24_sampling_frequency_32000;
static int hf_btavdtp_mpeg24_sampling_frequency_44100;
static int hf_btavdtp_mpeg24_sampling_frequency_48000;
static int hf_btavdtp_mpeg24_sampling_frequency_64000;
static int hf_btavdtp_mpeg24_sampling_frequency_88200;
static int hf_btavdtp_mpeg24_sampling_frequency_96000;
static int hf_btavdtp_mpeg24_channels_1;
static int hf_btavdtp_mpeg24_channels_2;
static int hf_btavdtp_mpeg24_rfa;
static int hf_btavdtp_mpeg24_vbr_supported;
static int hf_btavdtp_mpeg24_bit_rate;
static int hf_btavdtp_atrac_version;
static int hf_btavdtp_atrac_channel_mode_single_channel;
static int hf_btavdtp_atrac_channel_mode_dual_channel;
static int hf_btavdtp_atrac_channel_mode_joint_stereo;
static int hf_btavdtp_atrac_rfa1;
static int hf_btavdtp_atrac_rfa2;
static int hf_btavdtp_atrac_sampling_frequency_44100;
static int hf_btavdtp_atrac_sampling_frequency_48000;
static int hf_btavdtp_atrac_vbr_supported;
static int hf_btavdtp_atrac_bit_rate;
static int hf_btavdtp_atrac_maximum_sul;
static int hf_btavdtp_atrac_rfa3;
static int hf_btavdtp_vendor_specific_aptx_sampling_frequency_16000;
static int hf_btavdtp_vendor_specific_aptx_sampling_frequency_32000;
static int hf_btavdtp_vendor_specific_aptx_sampling_frequency_44100;
static int hf_btavdtp_vendor_specific_aptx_sampling_frequency_48000;
static int hf_btavdtp_vendor_specific_aptx_channel_mode_mono;
static int hf_btavdtp_vendor_specific_aptx_channel_mode_dual_channel;
static int hf_btavdtp_vendor_specific_aptx_channel_mode_stereo;
static int hf_btavdtp_vendor_specific_aptx_channel_mode_joint_stereo;
static int hf_btavdtp_vendor_specific_aptxhd_sampling_frequency_16000;
static int hf_btavdtp_vendor_specific_aptxhd_sampling_frequency_32000;
static int hf_btavdtp_vendor_specific_aptxhd_sampling_frequency_44100;
static int hf_btavdtp_vendor_specific_aptxhd_sampling_frequency_48000;
static int hf_btavdtp_vendor_specific_aptxhd_channel_mode_mono;
static int hf_btavdtp_vendor_specific_aptxhd_channel_mode_dual_channel;
static int hf_btavdtp_vendor_specific_aptxhd_channel_mode_stereo;
static int hf_btavdtp_vendor_specific_aptxhd_channel_mode_joint_stereo;
static int hf_btavdtp_vendor_specific_aptxhd_rfa;
static int hf_btavdtp_vendor_specific_ldac_rfa1;
static int hf_btavdtp_vendor_specific_ldac_sampling_frequency_44100;
static int hf_btavdtp_vendor_specific_ldac_sampling_frequency_48000;
static int hf_btavdtp_vendor_specific_ldac_sampling_frequency_88200;
static int hf_btavdtp_vendor_specific_ldac_sampling_frequency_96000;
static int hf_btavdtp_vendor_specific_ldac_sampling_frequency_176400;
static int hf_btavdtp_vendor_specific_ldac_sampling_frequency_192000;
static int hf_btavdtp_vendor_specific_ldac_rfa2;
static int hf_btavdtp_vendor_specific_ldac_channel_mode_mono;
static int hf_btavdtp_vendor_specific_ldac_channel_mode_dual_channel;
static int hf_btavdtp_vendor_specific_ldac_channel_mode_stereo;
static int hf_btavdtp_h263_level_10;
static int hf_btavdtp_h263_level_20;
static int hf_btavdtp_h263_level_30;
static int hf_btavdtp_h263_level_rfa;
static int hf_btavdtp_mpeg4_level_0;
static int hf_btavdtp_mpeg4_level_1;
static int hf_btavdtp_mpeg4_level_2;
static int hf_btavdtp_mpeg4_level_3;
static int hf_btavdtp_mpeg4_level_rfa;
static int hf_btavdtp_vendor_id;
static int hf_btavdtp_vendor_specific_codec_id;
static int hf_btavdtp_vendor_specific_value;
static int hf_btavdtp_vendor_specific_apt_codec_id;
static int hf_btavdtp_vendor_specific_ldac_codec_id;
static int hf_btavdtp_capabilities;
static int hf_btavdtp_service;
static int hf_btavdtp_service_multiplexing_entry;

static int ett_btavdtp;
static int ett_btavdtp_sep;
static int ett_btavdtp_capabilities;
static int ett_btavdtp_service;

static expert_field ei_btavdtp_sbc_min_bitpool_out_of_range;
static expert_field ei_btavdtp_sbc_max_bitpool_out_of_range;
static expert_field ei_btavdtp_unexpected_losc_data;

static dissector_handle_t btavdtp_handle;
static dissector_handle_t bta2dp_handle;
static dissector_handle_t btvdp_handle;
static dissector_handle_t rtp_handle;

static wmem_tree_t *channels;
static wmem_tree_t *sep_list;
static wmem_tree_t *sep_open;
static wmem_tree_t *media_packet_times;

/* A2DP declarations */
static int proto_bta2dp;
static int ett_bta2dp;
static int proto_bta2dp_cph_scms_t;
static int ett_bta2dp_cph_scms_t;

static int hf_bta2dp_acp_seid;
static int hf_bta2dp_int_seid;
static int hf_bta2dp_codec;
static int hf_bta2dp_vendor_id;
static int hf_bta2dp_vendor_codec_id;
static int hf_bta2dp_content_protection;
static int hf_bta2dp_stream_start_in_frame;
static int hf_bta2dp_stream_end_in_frame;
static int hf_bta2dp_stream_number;
static int hf_bta2dp_l_bit;
static int hf_bta2dp_cp_bit;
static int hf_bta2dp_reserved;

static dissector_handle_t sbc_handle;
static dissector_handle_t mp2t_handle;
static dissector_handle_t mpeg_audio_handle;
static dissector_handle_t atrac_handle;

static bool  force_a2dp_scms_t;
static int       force_a2dp_codec = CODEC_DEFAULT;

static const enum_val_t pref_a2dp_codec[] = {
    { "default",     "Default",      CODEC_DEFAULT },
    { "sbc",         "SBC",          CODEC_SBC },
    { "mp2t",        "MPEG12 AUDIO", CODEC_MPEG12_AUDIO },
    { "mpeg-audio",  "MPEG24 AAC",   CODEC_MPEG24_AAC },
/* XXX: Not supported in Wireshark yet  { "atrac",      "ATRAC",                                  CODEC_ATRAC },*/
    { "aptx",        "aptX",         CODEC_APT_X },
    { "aptx-hd",     "aptX HD",      CODEC_APT_X_HD },
    { "ldac",        "LDAC",         CODEC_LDAC },
    { NULL, NULL, 0 }
};


/* VDP declarations */
static int proto_btvdp;
static int ett_btvdp;
static int proto_btvdp_cph_scms_t;
static int ett_btvdp_cph_scms_t;

static int hf_btvdp_acp_seid;
static int hf_btvdp_int_seid;
static int hf_btvdp_codec;
static int hf_btvdp_vendor_id;
static int hf_btvdp_vendor_codec_id;
static int hf_btvdp_content_protection;
static int hf_btvdp_stream_start_in_frame;
static int hf_btvdp_stream_end_in_frame;
static int hf_btvdp_stream_number;
static int hf_btvdp_l_bit;
static int hf_btvdp_cp_bit;
static int hf_btvdp_reserved;

static dissector_handle_t h263_handle;
static dissector_handle_t mp4v_es_handle;

static bool  force_vdp_scms_t;
static int       force_vdp_codec = CODEC_H263_BASELINE;

static const enum_val_t pref_vdp_codec[] = {
    { "h263",    "H263",      CODEC_H263_BASELINE },
    { "mp4v-es", "MPEG4 VSP", CODEC_MPEG4_VSP },
    { NULL, NULL, 0 }
};

/* APT-X Codec */
static int  proto_aptx;
static int  hf_aptx_data;
static int  hf_aptx_cumulative_frame_duration;
static int  hf_aptx_delta_time;
static int  hf_aptx_avrcp_song_position;
static int  hf_aptx_delta_time_from_the_beginning;
static int  hf_aptx_cumulative_duration;
static int  hf_aptx_diff;
static int ett_aptx;
static dissector_handle_t aptx_handle;

/* LDAC Codec */
static int  proto_ldac;
static int  hf_ldac_fragmented;
static int  hf_ldac_starting_packet;
static int  hf_ldac_last_packet;
static int  hf_ldac_rfa;
static int  hf_ldac_number_of_frames;

static int hf_ldac_syncword;
static int hf_ldac_sampling_frequency;
static int hf_ldac_channel_config_index;
static int hf_ldac_frame_length_h;
static int hf_ldac_frame_length_l;
static int hf_ldac_frame_status;

static int hf_ldac_expected_data_speed;

static int  hf_ldac_data;
static int ett_ldac;
static int ett_ldac_list;
static expert_field ei_ldac_syncword;
static expert_field ei_ldac_truncated_or_bad_length;
static dissector_handle_t ldac_handle;
#define LDAC_CCI_MONO   0x0
#define LDAC_CCI_DUAL   0x1
#define LDAC_CCI_STEREO 0x2
static const value_string ldac_channel_config_index_vals[] = {
    { LDAC_CCI_MONO,  "Mono"},
    { LDAC_CCI_DUAL,  "Dual Channel"},
    { LDAC_CCI_STEREO,  "Stereo"},
    { 0, NULL }
};

#define LDAC_FSID_044       0x0
#define LDAC_FSID_048       0x1
#define LDAC_FSID_088       0x2
#define LDAC_FSID_096       0x3
#define LDAC_FSID_176       0x4
#define LDAC_FSID_192       0x5

static const value_string ldac_sampling_frequency_vals[] = {
    { LDAC_FSID_044,  "44.1 kHz"},
    { LDAC_FSID_048,  "48.0 kHz"},
    { LDAC_FSID_088,  "88.2 kHz"},
    { LDAC_FSID_096,  "96.0 kHz"},
    { LDAC_FSID_176,  "176.4 kHz"},
    { LDAC_FSID_192,  "192.0 kHz"},
    { 0, NULL }
};


static const value_string message_type_vals[] = {
    { 0x00,  "Command" },
    { 0x01,  "GeneralReject" },
    { 0x02,  "ResponseAccept" },
    { 0x03,  "ResponseReject" },
    { 0, NULL }
};

static const value_string packet_type_vals[] = {
    { 0x00,  "Single" },
    { 0x01,  "Start" },
    { 0x02,  "Continue" },
    { 0x03,  "End" },
    { 0, NULL }
};

static const value_string signal_id_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "Discover" },
    { 0x02, "GetCapabilities" },
    { 0x03, "SetConfiguration" },
    { 0x04, "GetConfiguration" },
    { 0x05, "Reconfigure" },
    { 0x06, "Open" },
    { 0x07, "Start" },
    { 0x08, "Close" },
    { 0x09, "Suspend" },
    { 0x0A, "Abort" },
    { 0x0B, "SecurityControl" },
    { 0x0C, "GetAllCapabilities" },
    { 0x0D, "DelayReport" },
    { 0, NULL }
};

static const value_string media_type_vals[] = {
    { 0x00,  "Audio" },
    { 0x01,  "Video" },
    { 0x02,  "Multimedia" },
    { 0, NULL }
};

static const value_string sep_type_vals[] = {
    { 0x00,  "Source" },
    { 0x01,  "Sink" },
    { 0, NULL }
};

static const value_string true_false[] = {
    { 0x00,  "False" },
    { 0x01,  "True" },
    { 0, NULL }
};

static const value_string error_code_vals[] = {
    /* ACP to INT, Signal Response Header Error Codes */
    { 0x01,  "Bad Header Format" },
    /* ACP to INT, Signal Response Payload Format Error Codes */
    { 0x11,  "Bad Length" },
    { 0x12,  "Bad ACP SEID" },
    { 0x13,  "SEP In Use" },
    { 0x14,  "SEP Not In Use" },
    { 0x17,  "Bad Service Category" },
    { 0x18,  "Bad Payload Format" },
    { 0x19,  "Not Supported Command" },
    { 0x1A,  "Invalid Capabilities" },
    /* ACP to INT, Signal Response Transport Service Capabilities Error Codes */
    { 0x22,  "Bad Recovery Type" },
    { 0x23,  "Bad Media Transport Format" },
    { 0x25,  "Bad Recovery Format" },
    { 0x26,  "Bad Header Compression Format" },
    { 0x27,  "Bad Content Protection Format" },
    { 0x28,  "Bad Multiplexing Format" },
    { 0x29,  "Unsupported Configuration" },
    /* ACP to INT, Procedure Error Codes */
    { 0x31,  "Bad State" },
    /* GAVDTP */
    { 0x80,  "The Service Category Stated is Invalid" },
    { 0x81,  "Lack of Resource New Stream Context" },
    /* A2DP */
    { 0xC1,  "Invalid Codec Type" },
    { 0xC2,  "Not Supported Codec Type" },
    { 0xC3,  "Invalid Sampling Frequency" },
    { 0xC4,  "Not Supported Sampling Frequency" },
    { 0xC5,  "Invalid Channel Mode" },
    { 0xC6,  "Not Supported Channel Mode" },
    { 0xC7,  "Invalid Subbands" },
    { 0xC8,  "Not Supported Subbands" },
    { 0xC9,  "Invalid Allocation Method" },
    { 0xCA,  "Not Supported Allocation Method" },
    { 0xCB,  "Invalid Minimum Bitpool Value" },
    { 0xCC,  "Not Supported Minimum Bitpool Value" },
    { 0xCD,  "Invalid Maximum Bitpool Value" },
    { 0xCE,  "Not Supported Maximum Bitpool Value" },
    { 0xCF,  "Invalid Layer" },
    { 0xD0,  "Not Supported Layer" },
    { 0xD1,  "Not Supported CRC" },
    { 0xD2,  "Not Supported MPF" },
    { 0xD3,  "Not Supported VBR" },
    { 0xD4,  "Invalid Bit Rate" },
    { 0xD5,  "Not Supported Bit Rate" },
    { 0xD6,  "Invalid Object Type" },
    { 0xD7,  "Not Supported Object Type" },
    { 0xD8,  "Invalid Channels" },
    { 0xD9,  "Not Supported Channels" },
    { 0xDA,  "Invalid Version" },
    { 0xDB,  "Not Supported Version" },
    { 0xDC,  "Not Supported Maximum SUL" },
    { 0xDD,  "Invalid Block Length" },
    { 0xE0,  "Invalid Content Protection Type" },
    { 0xE1,  "Invalid Content Protection Format" },
    { 0xE2,  "Invalid Coded Parameter" },
    { 0xE3,  "Not Supported Codec Parameter" },
    { 0, NULL }
};

static const value_string service_category_vals[] = {
    { 0x01,  "Media Transport" },
    { 0x02,  "Reporting" },
    { 0x03,  "Recovery" },
    { 0x04,  "Content Protection" },
    { 0x05,  "Header Compression" },
    { 0x06,  "Multiplexing" },
    { 0x07,  "Media Codec" },
    { 0x08,  "Delay Reporting" },
    { 0, NULL }
};

static const value_string recovery_type_vals[] = {
    { 0x00,  "Forbidden" },
    { 0x01,  "RFC2733" },
    { 0, NULL }
};

static const value_string multiplexing_tsid_vals[] = {
    { 0x00,  "Used for TSID query" },
    { 0x1F,  "RFD" },
    { 0, NULL }
};

static const value_string multiplexing_tcid_vals[] = {
    { 0x00,  "Used for TCID query" },
    { 0x1F,  "RFD" },
    { 0, NULL }
};

static const value_string media_codec_audio_type_vals[] = {
    { 0x00,  "SBC" },
    { 0x01,  "MPEG-1,2 Audio" },
    { 0x02,  "MPEG-2,4 AAC" },
    { 0x04,  "ATRAC family" },
    { 0xFF,  "non-A2DP" },
    { 0, NULL }
};

static const value_string media_codec_video_type_vals[] = {
    { 0x01,  "H.263 baseline" },
    { 0x02,  "MPEG-4 Visual Simple Profile" },
    { 0x03,  "H.263 profile 3" },
    { 0x04,  "H.263 profile 8" },
    { 0xFF,  "non-VDP" },
    { 0, NULL }
};

static const value_string content_protection_type_vals[] = {
    { 0x01,  "DTCP" },
    { 0x02,  "SCMS-T" },
    { 0, NULL }
};

static const value_string vendor_apt_codec_vals[] = {
    { CODECID_APT_X,     "aptX" },
    { CODECID_APT_X_HD,  "aptX HD" },
    { 0, NULL }
};

static const value_string vendor_ldac_codec_vals[] = {
    { 0x00AA,  "LDAC" },
    { 0, NULL }
};

enum sep_state {
    SEP_STATE_FREE,
    SEP_STATE_OPEN,
    SEP_STATE_IN_USE
};

typedef struct _sep_entry_t {
    uint8_t        seid;
    uint8_t        type;
    uint8_t        media_type;
    uint8_t        int_seid;
    int            codec;
    uint32_t       vendor_id;
    uint16_t       vendor_codec;
    uint8_t        configuration_length;
    uint8_t       *configuration;
    int            content_protection_type;

    enum sep_state state;
} sep_entry_t;

typedef struct _sep_data_t {
    int       codec;
    uint32_t  vendor_id;
    uint16_t  vendor_codec;
    uint8_t   configuration_length;
    uint8_t  *configuration;
    uint8_t   acp_seid;
    uint8_t   int_seid;
    int       content_protection_type;
    uint32_t  stream_start_in_frame;
    uint32_t  stream_end_in_frame;
    uint32_t  stream_number;
    media_packet_info_t  *previous_media_packet_info;
    media_packet_info_t  *current_media_packet_info;
} sep_data_t;

typedef struct _media_stream_number_value_t {
    uint32_t     stream_start_in_frame;
    uint32_t     stream_end_in_frame;
    uint32_t     stream_number;
} media_stream_number_value_t;

typedef struct _channels_info_t {
    uint32_t      control_local_cid;
    uint32_t      control_remote_cid;
    uint32_t      media_local_cid;
    uint32_t      media_remote_cid;
    wmem_tree_t  *stream_numbers;
    uint32_t      disconnect_in_frame;
    uint32_t     *l2cap_disconnect_in_frame;
    uint32_t     *hci_disconnect_in_frame;
    uint32_t     *adapter_disconnect_in_frame;
    sep_entry_t  *sep;
} channels_info_t;


void proto_register_btavdtp(void);
void proto_reg_handoff_btavdtp(void);
void proto_register_bta2dp(void);
void proto_reg_handoff_bta2dp(void);
void proto_register_bta2dp_content_protection_header_scms_t(void);
void proto_register_btvdp(void);
void proto_reg_handoff_btvdp(void);
void proto_register_btvdp_content_protection_header_scms_t(void);
void proto_register_aptx(void);
void proto_register_ldac(void);


static const char *
get_sep_type(uint32_t interface_id,
    uint32_t adapter_id, uint32_t chandle, uint32_t direction, uint32_t seid, uint32_t frame_number)
{
    wmem_tree_key_t   key[6];
    wmem_tree_t      *subtree;
    sep_entry_t      *sep;

    key[0].length = 1;
    key[0].key    = &interface_id;
    key[1].length = 1;
    key[1].key    = &adapter_id;
    key[2].length = 1;
    key[2].key    = &chandle;
    key[3].length = 1;
    key[3].key    = &direction;
    key[4].length = 1;
    key[4].key    = &seid;
    key[5].length = 0;
    key[5].key    = NULL;

    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(sep_list, key);
    sep = (subtree) ? (sep_entry_t *) wmem_tree_lookup32_le(subtree, frame_number) : NULL;
    if (sep) {
        return val_to_str_const(sep->type, sep_type_vals, "unknown");
    }

    return "unknown";
}

static const char *
get_sep_media_type(uint32_t interface_id,
    uint32_t adapter_id, uint32_t chandle, uint32_t direction, uint32_t seid, uint32_t frame_number)
{
    wmem_tree_key_t   key[6];
    wmem_tree_t      *subtree;
    sep_entry_t      *sep;

    key[0].length = 1;
    key[0].key    = &interface_id;
    key[1].length = 1;
    key[1].key    = &adapter_id;
    key[2].length = 1;
    key[2].key    = &chandle;
    key[3].length = 1;
    key[3].key    = &direction;
    key[4].length = 1;
    key[4].key    = &seid;
    key[5].length = 0;
    key[5].key    = NULL;

    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(sep_list, key);
    sep = (subtree) ? (sep_entry_t *) wmem_tree_lookup32_le(subtree, frame_number) : NULL;
    if (sep) {
        return val_to_str_const(sep->media_type, media_type_vals, "unknown");
    }

    return "unknown";
}


static int
dissect_sep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
    uint32_t interface_id, uint32_t adapter_id, uint32_t chandle)
{
    proto_tree       *sep_tree;
    proto_item       *sep_item;
    unsigned         i_sep  = 1;
    unsigned         media_type;
    unsigned         type;
    unsigned         seid;
    unsigned         in_use;
    unsigned         items;
    uint32_t         direction;

    /* Reverse direction to avoid mass reversing it, because this is only case
       when SEP is provided in ACP role, otherwise INT frequently asking for it
    */
    direction = (pinfo->p2p_dir == P2P_DIR_SENT) ? P2P_DIR_RECV : P2P_DIR_SENT;
    items = tvb_reported_length_remaining(tvb, offset) / 2;
    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        seid = tvb_get_uint8(tvb, offset);
        in_use = seid & 0x02;
        seid = seid >> 2;
        media_type = tvb_get_uint8(tvb, offset + 1) >> 4;
        type = (tvb_get_uint8(tvb, offset + 1) & 0x08) >> 3;
        sep_item = proto_tree_add_none_format(tree, hf_btavdtp_acp_sep, tvb, offset, 2, "ACP SEP [%u - %s %s] item %u/%u",
                seid, val_to_str_const(media_type, media_type_vals, "unknown"),
                val_to_str_const(type, sep_type_vals, "unknown"), i_sep, items);
        sep_tree = proto_item_add_subtree(sep_item, ett_btavdtp_sep);

        proto_tree_add_item(sep_tree, hf_btavdtp_sep_seid , tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sep_tree, hf_btavdtp_sep_inuse, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sep_tree, hf_btavdtp_sep_rfa0 , tvb, offset, 1, ENC_NA);
        offset+=1;

        proto_tree_add_item(sep_tree, hf_btavdtp_sep_media_type, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sep_tree, hf_btavdtp_sep_type      , tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sep_tree, hf_btavdtp_sep_rfa1      , tvb, offset, 1, ENC_NA);

        if (!pinfo->fd->visited) {
            sep_entry_t     *sep_data;
            wmem_tree_key_t  key[7];
            uint32_t         frame_number = pinfo->num;

            key[0].length = 1;
            key[0].key    = &interface_id;
            key[1].length = 1;
            key[1].key    = &adapter_id;
            key[2].length = 1;
            key[2].key    = &chandle;
            key[3].length = 1;
            key[3].key    = &direction;
            key[4].length = 1;
            key[4].key    = &seid;
            key[5].length = 1;
            key[5].key    = &frame_number;
            key[6].length = 0;
            key[6].key    = NULL;

            sep_data = wmem_new0(wmem_file_scope(), sep_entry_t);
            sep_data->seid = seid;
            sep_data->type = type;
            sep_data->media_type = media_type;
            sep_data->codec = -1;
            if (in_use) {
                sep_data->state = SEP_STATE_IN_USE;
            } else {
                sep_data->state = SEP_STATE_FREE;
            }

            wmem_tree_insert32_array(sep_list, key, sep_data);
        }

        offset += 1;
        i_sep += 1;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " - items: %u", items);
    return offset;
}


static int
dissect_codec(tvbuff_t *tvb, packet_info *pinfo, proto_item *service_item, proto_tree *tree, int offset,
        unsigned losc, int media_type, int media_codec_type, uint32_t *vendor_id, uint16_t *vendor_codec)
{
    proto_item    *pitem;
    uint32_t       value;
    uint8_t       *value8 = (uint8_t *) &value;

    switch(media_type) {
        case MEDIA_TYPE_AUDIO:
            switch(media_codec_type) {
                case CODEC_SBC:
                    proto_tree_add_item(tree, hf_btavdtp_sbc_sampling_frequency_16000, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_sampling_frequency_32000, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_sampling_frequency_44100, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_sampling_frequency_48000, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_channel_mode_mono, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_channel_mode_dual_channel, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_channel_mode_stereo, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_channel_mode_joint_stereo, tvb, offset, 1, ENC_NA);

                    proto_tree_add_item(tree, hf_btavdtp_sbc_block_4, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_block_8, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_block_12, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_block_16, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_subbands_4, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_subbands_8, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_allocation_method_snr, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_sbc_allocation_method_loudness, tvb, offset + 1, 1, ENC_NA);

                    pitem = proto_tree_add_item(tree, hf_btavdtp_sbc_min_bitpool, tvb, offset + 2, 1, ENC_NA);
                    value = tvb_get_uint8(tvb, offset + 2);
                    if (value < 2 || value > 250) {
                        expert_add_info(pinfo, pitem, &ei_btavdtp_sbc_min_bitpool_out_of_range);
                    }

                    pitem = proto_tree_add_item(tree, hf_btavdtp_sbc_max_bitpool, tvb, offset + 3, 1, ENC_NA);
                    value = tvb_get_uint8(tvb, offset + 3);
                    if (value < 2 || value > 250) {
                        expert_add_info(pinfo, pitem, &ei_btavdtp_sbc_max_bitpool_out_of_range);
                    }

                    value = tvb_get_h_uint32(tvb, offset);
                    if (value) {
                        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s%s%s%s%s| %s%s%s%s%s| block: %s%s%s%s%s| subbands: %s%s%s| allocation: %s%s%s| bitpool: %u..%u)",
                            (value8[0] & 0x80) ? "16000 " : "",
                            (value8[0] & 0x40) ? "32000 " : "",
                            (value8[0] & 0x20) ? "44100 " : "",
                            (value8[0] & 0x10) ? "48000 " : "",
                            (value8[0] & 0xF0) ? "" : "not set ",
                            (value8[0] & 0x08) ? "Mono " : "",
                            (value8[0] & 0x04) ? "DualChannel " : "",
                            (value8[0] & 0x02) ? "Stereo " : "",
                            (value8[0] & 0x01) ? "JointStereo " : "",
                            (value8[0] & 0x0F) ? "" : "not set ",
                            (value8[1] & 0x80) ? "4 " : "",
                            (value8[1] & 0x40) ? "8 " : "",
                            (value8[1] & 0x20) ? "12 " : "",
                            (value8[1] & 0x10) ? "16 " : "",
                            (value8[1] & 0xF0) ? "" : "not set ",
                            (value8[1] & 0x08) ? "4 " : "",
                            (value8[1] & 0x04) ? "8 " : "",
                            (value8[1] & 0x0C) ? "" : "not set ",
                            (value8[1] & 0x02) ? "SNR " : "",
                            (value8[1] & 0x01) ? "Loudness " : "",
                            (value8[1] & 0x03) ? "" : "not set ",
                            value8[2],
                            value8[3]);

                        proto_item_append_text(service_item, " (%s%s%s%s%s| %s%s%s%s%s| block: %s%s%s%s%s| subbands: %s%s%s| allocation: %s%s%s| bitpool: %u..%u)",
                            (value8[0] & 0x80) ? "16000 " : "",
                            (value8[0] & 0x40) ? "32000 " : "",
                            (value8[0] & 0x20) ? "44100 " : "",
                            (value8[0] & 0x10) ? "48000 " : "",
                            (value8[0] & 0xF0) ? "" : "not set ",
                            (value8[0] & 0x08) ? "Mono " : "",
                            (value8[0] & 0x04) ? "DualChannel " : "",
                            (value8[0] & 0x02) ? "Stereo " : "",
                            (value8[0] & 0x01) ? "JointStereo " : "",
                            (value8[0] & 0x0F) ? "" : "not set ",
                            (value8[1] & 0x80) ? "4 " : "",
                            (value8[1] & 0x40) ? "8 " : "",
                            (value8[1] & 0x20) ? "12 " : "",
                            (value8[1] & 0x10) ? "16 " : "",
                            (value8[1] & 0xF0) ? "" : "not set ",
                            (value8[1] & 0x08) ? "4 " : "",
                            (value8[1] & 0x04) ? "8 " : "",
                            (value8[1] & 0x0C) ? "" : "not set ",
                            (value8[1] & 0x02) ? "SNR " : "",
                            (value8[1] & 0x01) ? "Loudness " : "",
                            (value8[1] & 0x03) ? "" : "not set ",
                            value8[2],
                            value8[3]);
                    } else {
                        col_append_str(pinfo->cinfo, COL_INFO, " (none)");
                        proto_item_append_text(service_item, " (none)");
                    }

                    break;
                case CODEC_MPEG12_AUDIO:
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_layer_1, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_layer_2, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_layer_3, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_crc_protection, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_channel_mode_mono, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_channel_mode_dual_channel, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_channel_mode_stereo, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_channel_mode_joint_stereo, tvb, offset, 1, ENC_NA);

                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_rfa, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_mpf_2, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_sampling_frequency_16000, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_sampling_frequency_22050, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_sampling_frequency_24000, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_sampling_frequency_32000, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_sampling_frequency_44100, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_sampling_frequency_48000, tvb, offset + 1, 1, ENC_NA);

                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_vbr_supported, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg12_bit_rate, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
                    break;
                case CODEC_MPEG24_AAC:
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_object_type_mpeg2_aac_lc, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_object_type_mpeg4_aac_lc, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_object_type_mpeg4_aac_ltp, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_object_type_mpeg4_aac_scalable, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_object_type_rfa, tvb, offset, 1, ENC_NA);

                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_8000, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_11025, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_12000, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_16000, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_22050, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_24000, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_32000, tvb, offset + 1, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_44100, tvb, offset + 1, 1, ENC_NA);

                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_48000, tvb, offset + 2, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_64000, tvb, offset + 2, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_88200, tvb, offset + 2, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_sampling_frequency_96000, tvb, offset + 2, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_channels_1, tvb, offset + 2, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_channels_2, tvb, offset + 2, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_rfa, tvb, offset + 2, 1, ENC_NA);

                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_vbr_supported, tvb, offset + 3, 3, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg24_bit_rate, tvb, offset + 3, 3, ENC_BIG_ENDIAN);
                    break;
                case CODEC_ATRAC:
                    proto_tree_add_item(tree, hf_btavdtp_atrac_version, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_atrac_channel_mode_single_channel, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_atrac_channel_mode_dual_channel, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_atrac_channel_mode_joint_stereo, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_atrac_rfa1, tvb, offset, 1, ENC_NA);

                    proto_tree_add_item(tree, hf_btavdtp_atrac_rfa2, tvb, offset + 1, 3, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tree, hf_btavdtp_atrac_sampling_frequency_44100, tvb, offset + 1, 3, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tree, hf_btavdtp_atrac_sampling_frequency_48000, tvb, offset + 1, 3, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tree, hf_btavdtp_atrac_vbr_supported, tvb, offset + 3, 3, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tree, hf_btavdtp_atrac_bit_rate, tvb, offset + 3, 3, ENC_BIG_ENDIAN);

                    proto_tree_add_item(tree, hf_btavdtp_atrac_maximum_sul, tvb, offset + 4, 2, ENC_BIG_ENDIAN);

                    proto_tree_add_item(tree, hf_btavdtp_atrac_rfa3, tvb, offset + 6, 1, ENC_NA);
                    break;
                case CODEC_VENDOR: /* non-A2DP */
                    proto_tree_add_item(tree, hf_btavdtp_vendor_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);

                    if (vendor_id)
                        *vendor_id = tvb_get_letohl(tvb, offset);

                    if (vendor_codec)
                        *vendor_codec = tvb_get_letohs(tvb, offset + 4);

                    switch (tvb_get_letohl(tvb, offset)) {
                        case 0x004F: /* APT Licensing Ltd. */
                        case 0x00D7: /* Qualcomm technologies, Inc. */
                            proto_tree_add_item(tree, hf_btavdtp_vendor_specific_apt_codec_id, tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
                            value = tvb_get_letohs(tvb, offset + 4);

                            if (value == CODECID_APT_X || value == CODECID_APT_X_HD) { /* APT-X or APT-X HD Codec */
                                if (value == CODECID_APT_X) {
                                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptx_sampling_frequency_16000, tvb, offset + 6, 1, ENC_NA);
                                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptx_sampling_frequency_32000, tvb, offset + 6, 1, ENC_NA);
                                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptx_sampling_frequency_44100, tvb, offset + 6, 1, ENC_NA);
                                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptx_sampling_frequency_48000, tvb, offset + 6, 1, ENC_NA);
                                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptx_channel_mode_mono, tvb, offset + 6, 1, ENC_NA);
                                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptx_channel_mode_dual_channel, tvb, offset + 6, 1, ENC_NA);
                                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptx_channel_mode_stereo, tvb, offset + 6, 1, ENC_NA);
                                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptx_channel_mode_joint_stereo, tvb, offset + 6, 1, ENC_NA);
                                } else {
                                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptxhd_sampling_frequency_16000, tvb, offset + 6, 1, ENC_NA);
                                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptxhd_sampling_frequency_32000, tvb, offset + 6, 1, ENC_NA);
                                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptxhd_sampling_frequency_44100, tvb, offset + 6, 1, ENC_NA);
                                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptxhd_sampling_frequency_48000, tvb, offset + 6, 1, ENC_NA);
                                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptxhd_channel_mode_mono, tvb, offset + 6, 1, ENC_NA);
                                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptxhd_channel_mode_dual_channel, tvb, offset + 6, 1, ENC_NA);
                                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptxhd_channel_mode_stereo, tvb, offset + 6, 1, ENC_NA);
                                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptxhd_channel_mode_joint_stereo, tvb, offset + 6, 1, ENC_NA);
                                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_aptxhd_rfa, tvb, offset + 7, 4, ENC_NA);
                                }

                                col_append_fstr(pinfo->cinfo, COL_INFO, " (%s -",
                                    val_to_str_const(value, vendor_apt_codec_vals, "unknown codec"));
                                proto_item_append_text(service_item, " (%s -",
                                    val_to_str_const(value, vendor_apt_codec_vals, "unknown codec"));

                                value = tvb_get_uint8(tvb, offset + 6);
                                if (value) {
                                    col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s%s%s%s,%s%s%s%s%s)",
                                        (value & 0x80) ? " 16000" : "",
                                        (value & 0x40) ? " 32000" : "",
                                        (value & 0x20) ? " 44100" : "",
                                        (value & 0x10) ? " 48000" : "",
                                        (value & 0xF0) ? "" : "not set ",
                                        (value & 0x08) ? " Mono" : "",
                                        (value & 0x04) ? " DualChannel" : "",
                                        (value & 0x02) ? " Stereo" : "",
                                        (value & 0x01) ? " JointStereo" : "",
                                        (value & 0x0F) ? "" : "not set ");

                                    proto_item_append_text(service_item, "%s%s%s%s%s,%s%s%s%s%s)",
                                        (value & 0x80) ? " 16000" : "",
                                        (value & 0x40) ? " 32000" : "",
                                        (value & 0x20) ? " 44100" : "",
                                        (value & 0x10) ? " 48000" : "",
                                        (value & 0xF0) ? "" : "not set ",
                                        (value & 0x08) ? " Mono" : "",
                                        (value & 0x04) ? " DualChannel" : "",
                                        (value & 0x02) ? " Stereo" : "",
                                        (value & 0x01) ? " JointStereo" : "",
                                        (value & 0x0F) ? "" : "not set ");
                                } else {
                                    col_append_str(pinfo->cinfo, COL_INFO, " none)");
                                    proto_item_append_text(service_item, " none)");
                                }
                            } else {
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_value, tvb, offset + 6, losc - 6, ENC_NA);
                            }
                            break;
                        case 0x012D: /* Sony Corporation. */
                            proto_tree_add_item(tree, hf_btavdtp_vendor_specific_ldac_codec_id, tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
                            value = tvb_get_letohs(tvb, offset + 4);

                            if (value == 0x00AA) { /* LDAC Codec */
                                int value2;
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_ldac_rfa1, tvb, offset + 6, 1, ENC_NA);
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_ldac_sampling_frequency_44100, tvb, offset + 6, 1, ENC_NA);
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_ldac_sampling_frequency_48000, tvb, offset + 6, 1, ENC_NA);
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_ldac_sampling_frequency_88200, tvb, offset + 6, 1, ENC_NA);
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_ldac_sampling_frequency_96000, tvb, offset + 6, 1, ENC_NA);
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_ldac_sampling_frequency_176400, tvb, offset + 6, 1, ENC_NA);
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_ldac_sampling_frequency_192000, tvb, offset + 6, 1, ENC_NA);
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_ldac_rfa2, tvb, offset + 7, 1, ENC_NA);
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_ldac_channel_mode_mono, tvb, offset + 7, 1, ENC_NA);
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_ldac_channel_mode_dual_channel, tvb, offset + 7, 1, ENC_NA);
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_ldac_channel_mode_stereo, tvb, offset + 7, 1, ENC_NA);

                                col_append_fstr(pinfo->cinfo, COL_INFO, " (%s -",
                                    val_to_str_const(value, vendor_ldac_codec_vals, "unknown codec"));
                                proto_item_append_text(service_item, " (%s -",
                                    val_to_str_const(value, vendor_ldac_codec_vals, "unknown codec"));

                                value = tvb_get_uint8(tvb, offset + 6);
                                value2 = tvb_get_uint8(tvb, offset + 7);
                                if (value != 0 && value2 != 0) {
                                    col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s%s%s%s%s,%s%s%s)",
                                        (value & 0x20) ? " 44100" : "",
                                        (value & 0x10) ? " 48000" : "",
                                        (value & 0x08) ? " 88200" : "",
                                        (value & 0x04) ? " 96000" : "",
                                        (value & 0x02) ? "176400" : "",
                                        (value & 0x01) ? "192000" : "",
                                        (value2 & 0x04) ? " Mono" : "",
                                        (value2 & 0x02) ? " DualChannel" : "",
                                        (value2 & 0x01) ? " Stereo" : "");

                                    proto_item_append_text(service_item, "%s%s%s%s%s%s,%s%s%s)",
                                        (value & 0x20) ? " 44100" : "",
                                        (value & 0x10) ? " 48000" : "",
                                        (value & 0x08) ? " 88200" : "",
                                        (value & 0x04) ? " 96000" : "",
                                        (value & 0x02) ? "176400" : "",
                                        (value & 0x01) ? "192000" : "",
                                        (value2 & 0x04) ? " Mono" : "",
                                        (value2 & 0x02) ? " DualChannel" : "",
                                        (value2 & 0x01) ? " Stereo" : "");
                                } else {
                                    col_append_str(pinfo->cinfo, COL_INFO, " none)");
                                    proto_item_append_text(service_item, " none)");
                                }
                            } else {
                                proto_tree_add_item(tree, hf_btavdtp_vendor_specific_value, tvb, offset + 6, losc - 6, ENC_NA);
                            }
                            break;
                        default:
                            proto_tree_add_item(tree, hf_btavdtp_vendor_specific_codec_id, tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(tree, hf_btavdtp_vendor_specific_value, tvb, offset + 6, losc - 6, ENC_NA);
                    }

                    break;
                default:
                    proto_tree_add_item(tree, hf_btavdtp_data, tvb, offset, losc, ENC_NA);
            }
            break;
        case MEDIA_TYPE_VIDEO:
            switch(media_codec_type) {
                case CODEC_H263_BASELINE:
                case CODEC_H263_PROFILE_3:
                case CODEC_H263_PROFILE_8:
                    proto_tree_add_item(tree, hf_btavdtp_h263_level_10, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_h263_level_20, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_h263_level_30, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_h263_level_rfa, tvb, offset, 1, ENC_NA);
                    break;
                case CODEC_MPEG4_VSP:
                    proto_tree_add_item(tree, hf_btavdtp_mpeg4_level_0, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg4_level_1, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg4_level_2, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg4_level_3, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(tree, hf_btavdtp_mpeg4_level_rfa, tvb, offset, 1, ENC_NA);
                    break;
                case CODEC_VENDOR: /* non-VDP */
                    proto_tree_add_item(tree, hf_btavdtp_vendor_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_codec_id, tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(tree, hf_btavdtp_vendor_specific_value, tvb, offset + 6, losc - 6, ENC_NA);
                    break;
                default:
                    proto_tree_add_item(tree, hf_btavdtp_data, tvb, offset, losc, ENC_NA);
            }
            break;
        default:
            proto_tree_add_item(tree, hf_btavdtp_data, tvb, offset, losc, ENC_NA);
    }

    offset += losc;

    return offset;
}


static int
dissect_capabilities(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, int offset, int *codec,
        int *content_protection_type, uint32_t *vendor_id,
        uint16_t *vendor_codec, uint32_t *configuration_offset,
        uint8_t *configuration_length)
{
    proto_item  *pitem                                        = NULL;
    proto_item  *ptree                                        = NULL;
    proto_tree  *capabilities_tree;
    proto_item  *capabilities_item;
    proto_tree  *service_tree                                 = NULL;
    proto_item  *service_item                                 = NULL;
    int         service_category                              = 0;
    int         losc                                          = 0;
    int         recovery_type                                 = 0;
    int         maximum_recovery_window_size                  = 0;
    int         maximum_number_of_media_packet_in_parity_code = 0;
    int         media_type                                    = 0;
    int         media_codec_type                              = 0;

    capabilities_item = proto_tree_add_item(tree, hf_btavdtp_capabilities, tvb, offset, tvb_reported_length(tvb) - offset, ENC_NA);
    capabilities_tree = proto_item_add_subtree(capabilities_item, ett_btavdtp_capabilities);

    if (codec)
        *codec = -1;

    if (vendor_id)
        *vendor_id = 0x003F; /* Bluetooth SIG */

    if (vendor_codec)
        *vendor_codec = 0;

    if (configuration_length)
        *configuration_length = 0;

    if (configuration_offset)
        *configuration_offset = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        service_category = tvb_get_uint8(tvb, offset);
        losc = tvb_get_uint8(tvb, offset + 1);
        service_item = proto_tree_add_none_format(capabilities_tree, hf_btavdtp_service, tvb, offset, 2 + losc, "Service: %s", val_to_str_const(service_category, service_category_vals, "RFD"));
        service_tree = proto_item_add_subtree(service_item, ett_btavdtp_service);

        proto_tree_add_item(service_tree, hf_btavdtp_service_category, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(service_tree, hf_btavdtp_length_of_service_category, tvb, offset, 1, ENC_NA);
        offset += 1;

        switch (service_category) {
            case SERVICE_CATEGORY_MEDIA_TRANSPORT:
            case SERVICE_CATEGORY_REPORTING:
            case SERVICE_CATEGORY_DELAY_REPORTING:
                /* losc should be 0 */
                break;
            case SERVICE_CATEGORY_RECOVERY:
                recovery_type = tvb_get_uint8(tvb, offset);
                pitem = proto_tree_add_item(service_tree, hf_btavdtp_recovery_type, tvb, offset, 1, ENC_NA);
                proto_item_append_text(pitem, " (%s)", val_to_str_const(recovery_type, recovery_type_vals, "RFD"));
                offset += 1;
                losc -= 1;

                maximum_recovery_window_size = tvb_get_uint8(tvb, offset);
                pitem = proto_tree_add_item(service_tree, hf_btavdtp_maximum_recovery_window_size, tvb, offset, 1, ENC_NA);
                if (maximum_recovery_window_size == 0x00) {
                    proto_item_append_text(pitem, " (Forbidden)");
                } else if (maximum_recovery_window_size >= 0x18) {
                    proto_item_append_text(pitem, " (Undocumented)");
                }
                offset += 1;
                losc -= 1;

                maximum_number_of_media_packet_in_parity_code = tvb_get_uint8(tvb, offset);
                proto_tree_add_item(service_tree, hf_btavdtp_maximum_number_of_media_packet_in_parity_code, tvb, offset, 1, ENC_NA);
                pitem = proto_tree_add_item(service_tree, hf_btavdtp_maximum_recovery_window_size, tvb, offset, 1, ENC_NA);
                if (maximum_number_of_media_packet_in_parity_code == 0x00) {
                    proto_item_append_text(pitem, " (Forbidden)");
                } else if (maximum_number_of_media_packet_in_parity_code >= 0x18) {
                    proto_item_append_text(pitem, " (Undocumented)");
                }
                offset += 1;
                losc -= 1;
                break;
            case SERVICE_CATEGORY_MEDIA_CODEC:
                if (configuration_length)
                    *configuration_length = losc;
                if (configuration_offset)
                    *configuration_offset = offset;

                media_type = tvb_get_uint8(tvb, offset) >> 4;
                proto_tree_add_item(service_tree, hf_btavdtp_media_codec_media_type, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(service_tree, hf_btavdtp_media_codec_rfa , tvb, offset, 1, ENC_NA);
                offset += 1;
                losc -= 1;

                media_codec_type = tvb_get_uint8(tvb, offset);
                if (codec) {
                    *codec = media_codec_type;
                }

                if (media_type == MEDIA_TYPE_AUDIO) {
                    proto_tree_add_item(service_tree, hf_btavdtp_media_codec_audio_type, tvb, offset, 1, ENC_NA);
                    proto_item_append_text(service_item, " - Audio %s",
                            val_to_str_const(media_codec_type, media_codec_audio_type_vals, "unknown codec"));
                    col_append_fstr(pinfo->cinfo, COL_INFO, " - Audio %s",
                            val_to_str_const(media_codec_type, media_codec_audio_type_vals, "unknown codec"));
                } else if (media_type == MEDIA_TYPE_VIDEO) {
                    proto_tree_add_item(service_tree, hf_btavdtp_media_codec_video_type, tvb, offset, 1, ENC_NA);
                    proto_item_append_text(service_item, " - Video %s",
                            val_to_str_const(media_codec_type, media_codec_video_type_vals, "unknown codec"));
                    col_append_fstr(pinfo->cinfo, COL_INFO, " - Video %s",
                            val_to_str_const(media_codec_type, media_codec_video_type_vals, "unknown codec"));
                } else {
                    proto_tree_add_item(service_tree, hf_btavdtp_media_codec_unknown_type, tvb, offset, 1, ENC_NA);
                    proto_item_append_text(service_item, " - Unknown 0x%02x", media_codec_type);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " - Unknown 0x%02x", media_codec_type);
                }
                offset += 1;
                losc -= 1;

                offset = dissect_codec(tvb, pinfo, service_item, service_tree,
                        offset, losc, media_type, media_codec_type,
                        vendor_id, vendor_codec);
                losc = 0;
                break;
            case SERVICE_CATEGORY_CONTENT_PROTECTION:
                proto_tree_add_item(service_tree, hf_btavdtp_content_protection_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                if (content_protection_type) {
                    *content_protection_type = tvb_get_letohs(tvb, offset);
                }
                proto_item_append_text(service_item, " - %s",
                    val_to_str_const(tvb_get_letohs(tvb, offset), content_protection_type_vals, "unknown"));

                offset += 2;
                losc -= 2;

                if (losc > 0) {
                    proto_tree_add_item(service_tree, hf_btavdtp_data, tvb, offset, losc, ENC_NA);
                    offset += losc;
                    losc = 0;
                }
                break;
            case SERVICE_CATEGORY_HEADER_COMPRESSION:
                proto_tree_add_item(service_tree, hf_btavdtp_header_compression_backch,   tvb, offset, 1, ENC_NA);
                proto_tree_add_item(service_tree, hf_btavdtp_header_compression_media,    tvb, offset, 1, ENC_NA);
                proto_tree_add_item(service_tree, hf_btavdtp_header_compression_recovery, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(service_tree, hf_btavdtp_header_compression_rfa,      tvb, offset, 1, ENC_NA);
                offset += 1;
                losc -= 1;
                break;
            case SERVICE_CATEGORY_MULTIPLEXING:
                proto_tree_add_item(service_tree, hf_btavdtp_multiplexing_fragmentation, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(service_tree, hf_btavdtp_multiplexing_rfa, tvb, offset, 1, ENC_NA);
                offset += 1;
                losc -= 1;

                if (losc >= 2) {
                    pitem = proto_tree_add_none_format(service_tree, hf_btavdtp_service_multiplexing_entry, tvb, offset, 1 + losc, "Entry: Media Transport Session");
                    ptree = proto_item_add_subtree(pitem, ett_btavdtp_service);

                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_tsid, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_entry_rfa, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    losc -= 1;
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_tcid, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_entry_rfa, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    losc -= 1;
                }

                if (losc >= 2) {
                    pitem = proto_tree_add_none_format(service_tree, hf_btavdtp_service_multiplexing_entry, tvb, offset, 1 + losc, "Entry: Reporting Transport Session");
                    ptree = proto_item_add_subtree(pitem, ett_btavdtp_service);

                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_tsid, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_entry_rfa, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    losc -= 1;
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_tcid, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_entry_rfa, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    losc  -= 1;
                }

                if (losc >= 2) {
                    pitem = proto_tree_add_none_format(service_tree, hf_btavdtp_service_multiplexing_entry, tvb, offset, 1 + losc, "Entry: Recovery Transport Session");
                    ptree = proto_item_add_subtree(pitem, ett_btavdtp_service);

                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_tsid, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_entry_rfa, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    losc -= 1;
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_tcid, tvb, offset, 1, ENC_NA);
                    proto_tree_add_item(ptree, hf_btavdtp_multiplexing_entry_rfa, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    losc -= 1;
                }
                break;
            default:
                proto_tree_add_item(service_tree, hf_btavdtp_data, tvb, offset, losc, ENC_NA);
                offset += losc;
                losc = 0;
        }

        if (losc > 0) {
            pitem = proto_tree_add_item(service_tree, hf_btavdtp_data, tvb, offset, losc, ENC_NA);
            offset += losc;

            expert_add_info(pinfo, pitem, &ei_btavdtp_unexpected_losc_data);
        }
    }

    return offset;
}

static int
dissect_seid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
             int seid_side, int i_item, uint32_t *sep_seid,
             uint32_t interface_id, uint32_t adapter_id, uint32_t chandle,
             uint32_t frame_number)
{
    uint32_t     seid;
    proto_tree  *seid_tree     = NULL;
    proto_item  *seid_item     = NULL;
    uint32_t     direction;

    seid = tvb_get_uint8(tvb, offset) >> 2;
    if (sep_seid) {
        *sep_seid = seid;
    }

    if (seid_side == SEID_ACP) {
        direction = pinfo->p2p_dir;
        seid_item = proto_tree_add_none_format(tree, hf_btavdtp_acp_seid_item, tvb, offset, 1,
                "ACP SEID [%u - %s %s]", seid,
                    get_sep_media_type(interface_id, adapter_id, chandle, direction, seid, frame_number),
                    get_sep_type(interface_id, adapter_id, chandle, direction, seid, frame_number));
        seid_tree = proto_item_add_subtree(seid_item, ett_btavdtp_sep);
        proto_tree_add_item(seid_tree, hf_btavdtp_acp_seid, tvb, offset, 1, ENC_NA);
        if (i_item > 0) proto_item_append_text(seid_item, " item %u", i_item);

        col_append_fstr(pinfo->cinfo, COL_INFO, " - ACP SEID [%u - %s %s]",
                seid, get_sep_media_type(interface_id, adapter_id, chandle, direction, seid, frame_number),
                get_sep_type(interface_id, adapter_id, chandle, direction, seid, frame_number));
    } else {
        direction = (pinfo->p2p_dir == P2P_DIR_SENT) ? P2P_DIR_RECV : P2P_DIR_SENT;
        seid_item = proto_tree_add_none_format(tree, hf_btavdtp_int_seid_item, tvb, offset, 1,
                "INT SEID [%u - %s %s]", seid,
                    get_sep_media_type(interface_id, adapter_id, chandle, direction, seid, frame_number),
                    get_sep_type(interface_id, adapter_id, chandle, direction, seid, frame_number));
        seid_tree = proto_item_add_subtree(seid_item, ett_btavdtp_sep);
        proto_tree_add_item(seid_tree, hf_btavdtp_int_seid, tvb, offset, 1, ENC_NA);
        if (i_item > 0) proto_item_append_text(seid_item, " item %u", i_item);

        col_append_fstr(pinfo->cinfo, COL_INFO, " - INT SEID [%u - %s %s]",
                seid, get_sep_media_type(interface_id, adapter_id, chandle, direction, seid, frame_number),
                get_sep_type(interface_id, adapter_id, chandle, direction, seid, frame_number));
    }

    proto_tree_add_item(seid_tree, hf_btavdtp_rfa_seid, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}


static int
dissect_btavdtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item       *ti;
    proto_tree       *btavdtp_tree       = NULL;
    proto_tree       *signal_tree        = NULL;
    proto_item       *signal_item        = NULL;
    btl2cap_data_t   *l2cap_data;
    int              offset = 0;
    int              i_sep         = 1;
    int              packet_type   = 0;
    int              message_type  = 0;
    int              signal_id     = 0;
    unsigned         delay;
    wmem_tree_t      *subtree;
    wmem_tree_key_t  key[8];
    channels_info_t  *channels_info;
    uint32_t         interface_id;
    uint32_t         adapter_id;
    uint32_t         chandle;
    uint32_t         psm;
    uint32_t         direction;
    uint32_t         cid;
    uint32_t         frame_number;
    sep_entry_t      *sep;
    tvbuff_t         *next_tvb;
    uint32_t         seid;
    int              codec = -1;
    int              content_protection_type = 0;
    uint32_t         configuration_offset;
    uint8_t          configuration_length;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AVDTP");

    direction = pinfo->p2p_dir;
    switch (direction) {
        case P2P_DIR_SENT:
            col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;

        case P2P_DIR_RECV:
            col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
            col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection ");
            goto LABEL_data;
    }

    l2cap_data = (btl2cap_data_t *) data;
    DISSECTOR_ASSERT(l2cap_data);

    interface_id = l2cap_data->interface_id;
    adapter_id = l2cap_data->adapter_id;
    chandle = l2cap_data->chandle;
    psm = l2cap_data->psm;
    cid = l2cap_data->cid;
    frame_number = pinfo->num;

    key[0].length = 1;
    key[0].key    = &interface_id;
    key[1].length = 1;
    key[1].key    = &adapter_id;
    key[2].length = 1;
    key[2].key    = &chandle;
    key[3].length = 1;
    key[3].key    = &psm;
    key[4].length = 0;
    key[4].key    = NULL;

    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(channels, key);
    channels_info = (subtree) ? (channels_info_t *) wmem_tree_lookup32_le(subtree, frame_number) : NULL;
    if (!(channels_info &&
            ((*channels_info->adapter_disconnect_in_frame >= pinfo->num &&
            *channels_info->hci_disconnect_in_frame >= pinfo->num &&
            *channels_info->l2cap_disconnect_in_frame >= pinfo->num &&
            channels_info->disconnect_in_frame >= pinfo->num) ||
            (*channels_info->adapter_disconnect_in_frame == 0 ||
            *channels_info->hci_disconnect_in_frame == 0 ||
            *channels_info->l2cap_disconnect_in_frame == 0 ||
            channels_info->disconnect_in_frame == 0)))) {

        channels_info = (channels_info_t *) wmem_new (wmem_file_scope(), channels_info_t);
        channels_info->control_local_cid = l2cap_data->local_cid;
        channels_info->control_remote_cid = l2cap_data->remote_cid;
        channels_info->media_local_cid = BTL2CAP_UNKNOWN_CID;
        channels_info->media_remote_cid = BTL2CAP_UNKNOWN_CID;
        channels_info->disconnect_in_frame = bluetooth_max_disconnect_in_frame;
        channels_info->l2cap_disconnect_in_frame   = l2cap_data->disconnect_in_frame;
        channels_info->hci_disconnect_in_frame     = l2cap_data->hci_disconnect_in_frame;
        channels_info->adapter_disconnect_in_frame = l2cap_data->adapter_disconnect_in_frame;
        channels_info->sep = NULL;

        if (!pinfo->fd->visited || (
                *channels_info->adapter_disconnect_in_frame == 0 ||
                *channels_info->hci_disconnect_in_frame == 0 ||
                *channels_info->l2cap_disconnect_in_frame == 0 ||
                channels_info->disconnect_in_frame == 0)) {
            key[4].length = 1;
            key[4].key    = &frame_number;
            key[5].length = 0;
            key[5].key    = NULL;

            channels_info->stream_numbers = wmem_tree_new(wmem_file_scope());

            if (*channels_info->adapter_disconnect_in_frame > 0 &&
                    *channels_info->hci_disconnect_in_frame > 0 &&
                    *channels_info->l2cap_disconnect_in_frame > 0 &&
                    channels_info->disconnect_in_frame > 0) {
                wmem_tree_insert32_array(channels, key, channels_info);
            }
        } else {
            channels_info->stream_numbers = NULL;
        }
    }

    if (!(l2cap_data->local_cid == channels_info->control_local_cid &&
            l2cap_data->remote_cid == channels_info->control_remote_cid) &&
            (channels_info->media_local_cid == BTL2CAP_UNKNOWN_CID ||
            (l2cap_data->local_cid == channels_info->media_local_cid &&
            l2cap_data->remote_cid == channels_info->media_remote_cid))) {

        if (!pinfo->fd->visited && channels_info->media_local_cid == BTL2CAP_UNKNOWN_CID) {
            channels_info->media_local_cid = l2cap_data->local_cid;
            channels_info->media_remote_cid = l2cap_data->remote_cid;
        }
        /* Media Channel */

        if (!channels_info->sep) {
            ti = proto_tree_add_item(tree, proto_btavdtp, tvb, offset, -1, ENC_NA);
            btavdtp_tree = proto_item_add_subtree(ti, ett_btavdtp);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Media stream on cid=0x%04x", l2cap_data->cid);
            proto_tree_add_item(btavdtp_tree, hf_btavdtp_data, tvb, offset, -1, ENC_NA);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Media stream ACP SEID [%u - %s %s]",
                    channels_info->sep->seid, get_sep_media_type(
                            interface_id, adapter_id, chandle, direction,
                            channels_info->sep->seid,
                            frame_number),
                    get_sep_type(interface_id, adapter_id, chandle, direction,
                            channels_info->sep->seid,
                            frame_number));

            if (channels_info->sep->media_type == MEDIA_TYPE_AUDIO) {
                sep_data_t                    sep_data;
                media_stream_number_value_t  *media_stream_number_value;
                media_packet_info_t          *previous_media_packet_info;
                media_packet_info_t          *current_media_packet_info;
                nstime_t                      first_abs_ts;
                double                        cumulative_frame_duration;
                double                        avrcp_song_position = -1.0;
                btavrcp_song_position_data_t *song_position_data;

                sep_data.codec        = channels_info->sep->codec;
                sep_data.vendor_id    = channels_info->sep->vendor_id;
                sep_data.vendor_codec = channels_info->sep->vendor_codec;
                sep_data.acp_seid     = channels_info->sep->seid;
                sep_data.int_seid     = channels_info->sep->int_seid;
                sep_data.content_protection_type = channels_info->sep->content_protection_type;
                sep_data.stream_start_in_frame   = 0;
                sep_data.stream_end_in_frame     = 0;
                sep_data.configuration_length    = channels_info->sep->configuration_length;
                sep_data.configuration           = channels_info->sep->configuration;

                media_stream_number_value = (media_stream_number_value_t *) wmem_tree_lookup32_le(channels_info->stream_numbers, frame_number - 1);
                if (media_stream_number_value) {
                    sep_data.stream_number         = media_stream_number_value->stream_number;
                    if (media_stream_number_value->stream_start_in_frame == 0)
                        media_stream_number_value->stream_start_in_frame = pinfo->num;

                    if (!pinfo->fd->visited)
                        media_stream_number_value->stream_end_in_frame = pinfo->num;

                    sep_data.stream_start_in_frame = media_stream_number_value->stream_start_in_frame;
                    sep_data.stream_end_in_frame   = media_stream_number_value->stream_end_in_frame;
                } else {
                    sep_data.stream_number = 1;
                }

                key[0].length = 1;
                key[0].key    = &interface_id;
                key[1].length = 1;
                key[1].key    = &adapter_id;
                key[3].length = 1;
                key[3].key    = &cid;
                key[4].length = 1;
                key[4].key    = &direction;
                key[5].length = 0;
                key[5].key    = NULL;

                key[2].length = 0;
                key[2].key    = NULL;

                subtree = (wmem_tree_t *) wmem_tree_lookup32_array(btavrcp_song_positions, key);
                song_position_data = (subtree) ? (btavrcp_song_position_data_t *) wmem_tree_lookup32_le(subtree, frame_number) : NULL;
                if (song_position_data && (song_position_data->used_in_frame == 0 ||
                        song_position_data->used_in_frame == frame_number)) {
                    avrcp_song_position = song_position_data->song_position;
                    if (!pinfo->fd->visited)
                        song_position_data->used_in_frame = frame_number;
                }

                key[2].length = 1;
                key[2].key    = &chandle;

                subtree = (wmem_tree_t *) wmem_tree_lookup32_array(media_packet_times, key);
                previous_media_packet_info = (subtree) ? (media_packet_info_t *) wmem_tree_lookup32_le(subtree, frame_number - 1) : NULL;
                if (previous_media_packet_info && previous_media_packet_info->stream_number == sep_data.stream_number ) {
                    sep_data.previous_media_packet_info = previous_media_packet_info;
                    first_abs_ts = previous_media_packet_info->first_abs_ts;
                    cumulative_frame_duration = previous_media_packet_info->cumulative_frame_duration;
                    if (avrcp_song_position == -1.0)
                        avrcp_song_position = previous_media_packet_info->avrcp_song_position;
                    else
                        previous_media_packet_info->avrcp_song_position = avrcp_song_position;
                } else {
                    if (avrcp_song_position == -1.0)
                        avrcp_song_position = 0.0;
                    first_abs_ts = pinfo->abs_ts;
                    cumulative_frame_duration = 0.0;
                    sep_data.previous_media_packet_info = (media_packet_info_t *) wmem_new(wmem_epan_scope(), media_packet_info_t);
                    sep_data.previous_media_packet_info->abs_ts = pinfo->abs_ts;
                    sep_data.previous_media_packet_info->first_abs_ts = first_abs_ts;
                    sep_data.previous_media_packet_info->cumulative_frame_duration = cumulative_frame_duration;
                    sep_data.previous_media_packet_info->avrcp_song_position = avrcp_song_position;
                    sep_data.previous_media_packet_info->stream_number = sep_data.stream_number;
                }

                if (!pinfo->fd->visited) {
                    key[5].length = 1;
                    key[5].key    = &frame_number;
                    key[6].length = 0;
                    key[6].key    = NULL;

                    if (avrcp_song_position == -1.0)
                        avrcp_song_position = 0.0;

                    current_media_packet_info = wmem_new(wmem_file_scope(), media_packet_info_t);
                    current_media_packet_info->abs_ts = pinfo->abs_ts;
                    current_media_packet_info->first_abs_ts = first_abs_ts;
                    current_media_packet_info->cumulative_frame_duration = cumulative_frame_duration;
                    current_media_packet_info->avrcp_song_position = avrcp_song_position;
                    current_media_packet_info->stream_number = sep_data.stream_number;

                    wmem_tree_insert32_array(media_packet_times, key, current_media_packet_info);
                }

                key[5].length = 0;
                key[5].key    = NULL;

                subtree = (wmem_tree_t *) wmem_tree_lookup32_array(media_packet_times, key);
                current_media_packet_info = (subtree) ? (media_packet_info_t *) wmem_tree_lookup32(subtree, frame_number) : NULL;
                if (current_media_packet_info)
                    sep_data.current_media_packet_info = current_media_packet_info;
                else
                    sep_data.current_media_packet_info = NULL;

                next_tvb = tvb_new_subset_remaining(tvb, offset);
                call_dissector_with_data(bta2dp_handle, next_tvb, pinfo, tree, &sep_data);
            } else if (channels_info->sep->media_type == MEDIA_TYPE_VIDEO) {
                sep_data_t                    sep_data;
                media_stream_number_value_t  *media_stream_number_value;

                sep_data.codec        = channels_info->sep->codec;
                sep_data.vendor_id    = channels_info->sep->vendor_id;
                sep_data.vendor_codec = channels_info->sep->vendor_codec;
                sep_data.acp_seid     = channels_info->sep->seid;
                sep_data.int_seid     = channels_info->sep->int_seid;
                sep_data.content_protection_type = channels_info->sep->content_protection_type;
                sep_data.stream_start_in_frame   = 0;
                sep_data.stream_end_in_frame     = 0;
                sep_data.configuration_length    = channels_info->sep->configuration_length;
                sep_data.configuration           = channels_info->sep->configuration;

                media_stream_number_value = (media_stream_number_value_t *) wmem_tree_lookup32_le(channels_info->stream_numbers, frame_number - 1);
                if (media_stream_number_value) {
                    sep_data.stream_number = media_stream_number_value->stream_number;
                } else {
                    sep_data.stream_number = 1;
                }

                next_tvb = tvb_new_subset_remaining(tvb, offset);
                call_dissector_with_data(btvdp_handle, next_tvb, pinfo, tree, &sep_data);
            } else {
                ti = proto_tree_add_item(tree, proto_btavdtp, tvb, offset, -1, ENC_NA);
                btavdtp_tree = proto_item_add_subtree(ti, ett_btavdtp);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Media stream on cid=0x%04x", l2cap_data->cid);
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_data, tvb, offset, -1, ENC_NA);
            }
        }

        return tvb_reported_length(tvb);
    } else if (!(l2cap_data->local_cid == channels_info->control_local_cid &&
            l2cap_data->remote_cid == channels_info->control_remote_cid)) {
        /* Unknown Stream Channel */
        ti = proto_tree_add_item(tree, proto_btavdtp, tvb, offset, -1, ENC_NA);
        btavdtp_tree = proto_item_add_subtree(ti, ett_btavdtp);

        col_append_fstr(pinfo->cinfo, COL_INFO, "Unknown channel stream on cid=0x%04x", l2cap_data->cid);
        proto_tree_add_item(btavdtp_tree, hf_btavdtp_data, tvb, offset, -1, ENC_NA);
        return tvb_reported_length(tvb);
    }

    /* Signaling Channel */
    ti = proto_tree_add_item(tree, proto_btavdtp, tvb, offset, -1, ENC_NA);
    btavdtp_tree = proto_item_add_subtree(ti, ett_btavdtp);

    /* AVDTP signaling*/
    message_type = (tvb_get_uint8(tvb, offset) & AVDTP_MESSAGE_TYPE_MASK);
    packet_type = (tvb_get_uint8(tvb, offset) & AVDTP_PACKET_TYPE_MASK) >> 2;

    signal_item = proto_tree_add_item(btavdtp_tree, hf_btavdtp_signal, tvb, offset,
            (packet_type == PACKET_TYPE_START) ? 3 : 2, ENC_NA);
    signal_tree = proto_item_add_subtree(signal_item, ett_btavdtp_sep);

    proto_tree_add_item(signal_tree, hf_btavdtp_transaction, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(signal_tree, hf_btavdtp_packet_type, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(signal_tree, hf_btavdtp_message_type, tvb, offset, 1, ENC_NA);

    if (packet_type == PACKET_TYPE_START) {
        offset += 1;
        proto_tree_add_item(signal_tree, hf_btavdtp_number_of_signal_packets, tvb, offset, 1, ENC_NA);
    }

    if (packet_type == PACKET_TYPE_CONTINUE || packet_type == PACKET_TYPE_END) goto LABEL_data;

    offset += 1;
    proto_tree_add_item(signal_tree, hf_btavdtp_rfa0,         tvb, offset, 1, ENC_NA);
    proto_tree_add_item(signal_tree, hf_btavdtp_signal_id,    tvb, offset, 1, ENC_NA);

    signal_id   = tvb_get_uint8(tvb, offset) & AVDTP_SIGNAL_ID_MASK;
    proto_item_append_text(signal_item, ": %s (%s)",
            val_to_str_const(signal_id, signal_id_vals, "Unknown signal"),
            val_to_str_const(message_type, message_type_vals, "Unknown message type"));

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s - %s",
                    val_to_str_const(message_type, message_type_vals, "Unknown message type"),
                    val_to_str_const(signal_id, signal_id_vals, "Unknown signal"));

    offset += 1;
    if (message_type != MESSAGE_TYPE_GENERAL_REJECT) switch (signal_id) {
        case SIGNAL_ID_DISCOVER:
            if (message_type == MESSAGE_TYPE_COMMAND) break;
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            offset = dissect_sep(tvb, pinfo, btavdtp_tree, offset,
                    interface_id, adapter_id, chandle);
            break;
        case SIGNAL_ID_GET_CAPABILITIES:
        case SIGNAL_ID_GET_ALL_CAPABILITIES:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, NULL, interface_id,
                        adapter_id, chandle, frame_number);
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            offset = dissect_capabilities(tvb, pinfo, btavdtp_tree, offset, NULL, NULL, NULL, NULL, NULL, NULL);
            break;
        case SIGNAL_ID_SET_CONFIGURATION:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                uint32_t int_seid;
                uint32_t vendor_id;
                uint16_t vendor_codec;
                uint32_t reverse_direction;

                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, &seid, interface_id,
                        adapter_id, chandle, frame_number);
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_INT, 0, &int_seid, interface_id,
                        adapter_id, chandle, frame_number);
                offset = dissect_capabilities(tvb, pinfo, btavdtp_tree, offset,
                        &codec, &content_protection_type, &vendor_id,
                        &vendor_codec, &configuration_offset, &configuration_length);

                if (!pinfo->fd->visited) {
                    key[0].length = 1;
                    key[0].key    = &interface_id;
                    key[1].length = 1;
                    key[1].key    = &adapter_id;
                    key[2].length = 1;
                    key[2].key    = &chandle;
                    key[3].length = 1;
                    key[3].key    = &direction;
                    key[4].length = 1;
                    key[4].key    = &seid;
                    key[5].length = 0;
                    key[5].key    = NULL;

                    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(sep_list, key);
                    sep = (subtree) ? (sep_entry_t *) wmem_tree_lookup32_le(subtree, frame_number) : NULL;
                    if (sep) {
                        sep->codec = codec;
                        sep->vendor_id = vendor_id;
                        sep->vendor_codec = vendor_codec;
                        sep->content_protection_type = content_protection_type;
                        sep->int_seid = int_seid;
                        if (configuration_length > 0) {
                            sep->configuration_length = configuration_length;
                            sep->configuration = (uint8_t *) tvb_memdup(wmem_file_scope(),
                                    tvb, configuration_offset, configuration_length);
                        }

                        if (direction == P2P_DIR_SENT)
                            reverse_direction = P2P_DIR_RECV;
                        else if (direction == P2P_DIR_RECV)
                            reverse_direction = P2P_DIR_SENT;
                        else
                            reverse_direction = P2P_DIR_UNKNOWN;

                        key[3].length = 1;
                        key[3].key    = &reverse_direction;
                        key[4].length = 1;
                        key[4].key    = &int_seid;
                        key[5].length = 1;
                        key[5].key    = &frame_number;
                        key[6].length = 0;
                        key[6].key    = NULL;

                        wmem_tree_insert32_array(sep_list, key, sep);
                    }

                }

                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_service_category, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            break;
        case SIGNAL_ID_GET_CONFIGURATION:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, NULL, interface_id,
                        adapter_id, chandle, frame_number);
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            offset = dissect_capabilities(tvb, pinfo, btavdtp_tree, offset, NULL, NULL, NULL, NULL, NULL, NULL);
            break;
        case SIGNAL_ID_RECONFIGURE:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                uint32_t vendor_id;
                uint16_t vendor_codec;

                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, &seid, interface_id,
                        adapter_id, chandle, frame_number);
                offset = dissect_capabilities(tvb, pinfo, btavdtp_tree, offset,
                        &codec, &content_protection_type, &vendor_id,
                        &vendor_codec, &configuration_offset, &configuration_length);

                if (!pinfo->fd->visited) {
                    key[0].length = 1;
                    key[0].key    = &interface_id;
                    key[1].length = 1;
                    key[1].key    = &adapter_id;
                    key[2].length = 1;
                    key[2].key    = &chandle;
                    key[3].length = 1;
                    key[3].key    = &direction;
                    key[4].length = 1;
                    key[4].key    = &seid;
                    key[5].length = 0;
                    key[5].key    = NULL;

                    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(sep_list, key);
                    sep = (subtree) ? (sep_entry_t *) wmem_tree_lookup32_le(subtree, frame_number) : NULL;
                    if (sep) {
                        sep->codec = codec;
                        sep->vendor_id = vendor_id;
                        sep->vendor_codec = vendor_codec;
                        sep->content_protection_type = content_protection_type;
                        if (configuration_length > 0) {
                            sep->configuration_length = configuration_length;
                            sep->configuration = (uint8_t *) tvb_memdup(wmem_file_scope(),
                                    tvb, configuration_offset, configuration_length);
                        }
                    }
                }

                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_service_category, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            break;
        case SIGNAL_ID_OPEN:
             if (message_type == MESSAGE_TYPE_COMMAND) {
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, &seid, interface_id,
                        adapter_id, chandle, frame_number);

                if (!pinfo->fd->visited) {
                    key[0].length = 1;
                    key[0].key    = &interface_id;
                    key[1].length = 1;
                    key[1].key    = &adapter_id;
                    key[2].length = 1;
                    key[2].key    = &chandle;
                    key[3].length = 1;
                    key[3].key    = &direction;
                    key[4].length = 1;
                    key[4].key    = &seid;
                    key[5].length = 0;
                    key[5].key    = NULL;

                    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(sep_list, key);
                    sep = (subtree) ? (sep_entry_t *) wmem_tree_lookup32_le(subtree, frame_number) : NULL;
                    if (sep) {
                        sep->state = SEP_STATE_OPEN;

                        key[3].length = 1;
                        key[3].key    = &frame_number;
                        key[4].length = 0;
                        key[4].key    = NULL;

                        wmem_tree_insert32_array(sep_open, key, sep);
                    }
                }
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            if (message_type == MESSAGE_TYPE_ACCEPT && !pinfo->fd->visited) {

                key[0].length = 1;
                key[0].key    = &interface_id;
                key[1].length = 1;
                key[1].key    = &adapter_id;
                key[2].length = 1;
                key[2].key    = &chandle;
                key[3].length = 0;
                key[3].key    = NULL;

                subtree = (wmem_tree_t *) wmem_tree_lookup32_array(sep_open, key);
                sep = (subtree) ? (sep_entry_t *) wmem_tree_lookup32_le(subtree, frame_number) : NULL;
                if (sep && sep->state == SEP_STATE_OPEN) {
                    sep->state = SEP_STATE_IN_USE;
                    channels_info->sep = sep;
                }
            }
            break;
        case SIGNAL_ID_START:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                i_sep = 1;
                while (tvb_reported_length_remaining(tvb, offset) > 0) {
                    offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                            SEID_ACP, i_sep, NULL,
                            interface_id, adapter_id, chandle, frame_number);
                    i_sep += 1;
                }
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, NULL,
                        interface_id, adapter_id, chandle, frame_number);
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }

            if (message_type == MESSAGE_TYPE_ACCEPT && !pinfo->fd->visited) {
                media_stream_number_value_t  *media_stream_number_value;
                uint32_t                      stream_number = 0;

                media_stream_number_value = (media_stream_number_value_t *) wmem_tree_lookup32_le(channels_info->stream_numbers, frame_number - 1);
#if RTP_PLAYER_WORKAROUND == true
                {
                    media_stream_number_value_t  *file_scope_stream_number_value;

                    if (media_stream_number_value) {
                        stream_number = media_stream_number_value->stream_number;
                    } else {
                        file_scope_stream_number_value = (media_stream_number_value_t *) wmem_tree_lookup32_le(file_scope_stream_number, frame_number - 1);
                        if (file_scope_stream_number_value)
                            stream_number = file_scope_stream_number_value->stream_number + 1;
                        else
                            stream_number = 0;
                    }

                    file_scope_stream_number_value = wmem_new(wmem_file_scope(), media_stream_number_value_t);
                    file_scope_stream_number_value->stream_number = stream_number;
                    wmem_tree_insert32(file_scope_stream_number, frame_number, file_scope_stream_number_value);
                }
#else
                if (media_stream_number_value)
                    stream_number = media_stream_number_value->stream_number;
                else
                    stream_number = 0;
#endif

                media_stream_number_value = wmem_new(wmem_file_scope(), media_stream_number_value_t);
                media_stream_number_value->stream_number = stream_number + 1;
                media_stream_number_value->stream_start_in_frame = 0;
                media_stream_number_value->stream_end_in_frame = 0;

                wmem_tree_insert32(channels_info->stream_numbers, frame_number, media_stream_number_value);
            }
            break;
        case SIGNAL_ID_CLOSE:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, NULL, interface_id,
                        adapter_id, chandle, frame_number);
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            if (!pinfo->fd->visited && message_type == MESSAGE_TYPE_ACCEPT &&
                    channels_info->disconnect_in_frame > pinfo->num) {
                channels_info->disconnect_in_frame = pinfo->num;
            }
            break;
        case SIGNAL_ID_SUSPEND:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                i_sep = 1;
                while (tvb_reported_length_remaining(tvb, offset) > 0) {
                    offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                            SEID_ACP, i_sep, NULL,
                            interface_id, adapter_id, chandle, frame_number);
                    i_sep += 1;
                }
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, NULL, interface_id,
                        adapter_id, chandle, frame_number);
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            break;
        case SIGNAL_ID_ABORT:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, NULL, interface_id,
                        adapter_id, chandle, frame_number);
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            if (!pinfo->fd->visited && message_type == MESSAGE_TYPE_ACCEPT &&
                    channels_info->disconnect_in_frame > pinfo->num) {
                channels_info->disconnect_in_frame = pinfo->num;
            }
            break;
        case SIGNAL_ID_SECURITY_CONTROL:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, NULL, interface_id,
                        adapter_id, chandle, frame_number);
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_data, tvb, offset, -1, ENC_NA);
                offset += tvb_reported_length_remaining(tvb, offset);
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }

            proto_tree_add_item(btavdtp_tree, hf_btavdtp_data, tvb, offset, -1, ENC_NA);
            offset += tvb_reported_length_remaining(tvb, offset);
            break;
        case SIGNAL_ID_DELAY_REPORT:
            if (message_type == MESSAGE_TYPE_COMMAND) {
                proto_item  *pitem;
                delay = tvb_get_ntohs(tvb, offset + 1);
                col_append_fstr(pinfo->cinfo, COL_INFO, "(%u.%u ms)", delay/10, delay%10);
                offset = dissect_seid(tvb, pinfo, btavdtp_tree, offset,
                        SEID_ACP, 0, NULL,
                        interface_id, adapter_id, chandle, frame_number);
                pitem = proto_tree_add_item(btavdtp_tree, hf_btavdtp_delay, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_item_append_text(pitem, " (1/10 ms)");
                offset += 2;
                break;
            }
            if (message_type == MESSAGE_TYPE_REJECT) {
                proto_tree_add_item(btavdtp_tree, hf_btavdtp_error_code, tvb, offset, 1, ENC_NA);
                offset += 1;
                break;
            }
            break;
    }

    LABEL_data:

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(btavdtp_tree, hf_btavdtp_data, tvb, offset, -1, ENC_NA);
    }

    return offset;
}


void
proto_register_btavdtp(void)
{
    module_t *module;

    static hf_register_info hf[] = {
        { &hf_btavdtp_signal,
            { "Signal",                   "btavdtp.signal",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_message_type,
            { "Message Type",                   "btavdtp.message_type",
            FT_UINT8, BASE_HEX, VALS(message_type_vals), AVDTP_MESSAGE_TYPE_MASK,
            NULL, HFILL }
        },
        { &hf_btavdtp_packet_type,
            { "Packet Type",                    "btavdtp.packet_type",
            FT_UINT8, BASE_HEX, VALS(packet_type_vals), AVDTP_PACKET_TYPE_MASK,
            NULL, HFILL }
        },
        { &hf_btavdtp_transaction,
            { "Transaction",                    "btavdtp.transaction",
            FT_UINT8, BASE_HEX, NULL, AVDTP_TRANSACTION_MASK,
            NULL, HFILL }
        },
        { &hf_btavdtp_signal_id,
            { "Signal",                         "btavdtp.signal_id",
            FT_UINT8, BASE_HEX, VALS(signal_id_vals), AVDTP_SIGNAL_ID_MASK,
            NULL, HFILL }
        },
        { &hf_btavdtp_rfa0,
            { "RFA",                            "btavdtp.rfa0",
            FT_UINT8, BASE_HEX, NULL, AVDTP_RFA0_MASK,
            NULL, HFILL }
        },
        { &hf_btavdtp_number_of_signal_packets,
            { "Number of signal packets",       "btavdtp.num_signal_packets",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_btavdtp_error_code,
            { "Error Code",                     "btavdtp.error_code",
            FT_UINT8, BASE_HEX, VALS(error_code_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_sep_seid,
            { "SEID",                           "btavdtp.sep_seid",
            FT_UINT8, BASE_DEC, NULL, 0xFC,
            NULL, HFILL }
        },
        { &hf_btavdtp_sep_inuse,
            { "In Use",                         "btavdtp.sep_inuse",
            FT_UINT8, BASE_HEX, VALS(true_false), 0x02,
            NULL, HFILL }
        },
        { &hf_btavdtp_sep_rfa0,
            { "RFA0",                           "btavdtp.sep_rfa0",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavdtp_sep_media_type,
            { "Media Type",                     "btavdtp.sep_media_type",
            FT_UINT8, BASE_HEX, VALS(media_type_vals), 0xF0,
            NULL, HFILL }
        },
        { &hf_btavdtp_sep_type,
            { "Type",                           "btavdtp.sep_type",
            FT_UINT8, BASE_HEX, VALS(sep_type_vals), 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_sep_rfa1,
            { "RFA1",                           "btavdtp.sep_rfa1",
            FT_UINT8, BASE_HEX, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btavdtp_acp_sep,
            { "ACP SEP",                        "btavdtp.acp_sep",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_acp_seid_item,
            { "ACP SEID",                       "btavdtp.acp_seid_item",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_int_seid_item,
            { "INT SEID",                       "btavdtp.int_seid_item",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_acp_seid,
            { "ACP SEID",                       "btavdtp.acp_seid",
            FT_UINT8, BASE_DEC, NULL, 0xFC,
            NULL, HFILL }
        },
        { &hf_btavdtp_int_seid,
            { "INT SEID",                       "btavdtp.int_seid",
            FT_UINT8, BASE_DEC, NULL, 0xFC,
            NULL, HFILL }
        },
        { &hf_btavdtp_rfa_seid,
            { "RFA",                            "btavdtp.rfa_seid",
            FT_UINT8, BASE_HEX, NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_btavdtp_service_category,
            { "Service Category",               "btavdtp.service_category",
            FT_UINT8, BASE_HEX, VALS(service_category_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_length_of_service_category,
            { "Length of Service Category",     "btavdtp.length_of_service_category",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_delay,
            { "Delay",                          "btavdtp.delay",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_recovery_type,
            { "Service Category",               "btavdtp.recovery_type",
            FT_UINT8, BASE_HEX, VALS(recovery_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_maximum_recovery_window_size,
            { "Service Category",               "btavdtp.maximum_recovery_window_size",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_maximum_number_of_media_packet_in_parity_code,
            { "Service Category",               "btavdtp.maximum_number_of_media_packet_in_parity_code",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_multiplexing_fragmentation,
            { "Fragmentation",                  "btavdtp.multiplexing_fragmentation",
            FT_UINT8, BASE_HEX, VALS(true_false), 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_multiplexing_rfa,
            { "RFA",                            "btavdtp.multiplexing_rfa",
            FT_UINT8, BASE_HEX, NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_btavdtp_multiplexing_tsid,
            { "TSID",                           "btavdtp.multiplexing_tsid",
            FT_UINT8, BASE_HEX, VALS(multiplexing_tsid_vals), 0xF8,
            NULL, HFILL }
        },
        { &hf_btavdtp_multiplexing_tcid,
            { "TCID",                           "btavdtp.multiplexing_tcid",
            FT_UINT8, BASE_HEX, VALS(multiplexing_tcid_vals), 0xF8,
            NULL, HFILL }
        },
        { &hf_btavdtp_multiplexing_entry_rfa,
            { "RFA",                            "btavdtp.multiplexing_entry_rfa",
            FT_UINT8, BASE_HEX, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_btavdtp_header_compression_backch,
            { "BackCh",                         "btavdtp.header_compression_backch",
            FT_UINT8, BASE_HEX, VALS(true_false), 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_header_compression_media,
            { "Media",                          "btavdtp.header_compression_media",
            FT_UINT8, BASE_HEX, VALS(true_false), 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_header_compression_recovery,
            { "Recovery",                       "btavdtp.header_compression_recovery",
            FT_UINT8, BASE_HEX, VALS(true_false), 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_header_compression_rfa,
            { "RFA",                            "btavdtp.header_compression_rfa",
            FT_UINT8, BASE_HEX, NULL, 0x1f,
            NULL, HFILL }
        },
        { &hf_btavdtp_content_protection_type,
            { "Type",                           "btavdtp.content_protection_type",
            FT_UINT16, BASE_HEX, VALS(content_protection_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btavdtp_media_codec_media_type,
            { "Media Type",                     "btavdtp.media_codec_media_type",
            FT_UINT8, BASE_HEX, VALS(media_type_vals), 0xF0,
            NULL, HFILL }
        },
        { &hf_btavdtp_media_codec_rfa,
            { "RFA",                            "btavdtp.media_codec_rfa",
            FT_UINT8, BASE_HEX, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_btavdtp_media_codec_audio_type,
            { "Media Codec Audio Type",         "btavdtp.media_codec_audio_type",
            FT_UINT8, BASE_HEX, VALS(media_codec_audio_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_media_codec_video_type,
            { "Media Codec Video Type",         "btavdtp.media_codec_video_type",
            FT_UINT8, BASE_HEX, VALS(media_codec_video_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_media_codec_unknown_type,
            { "Media Codec Unknown Type",       "btavdtp.media_codec_unknown_type",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_sampling_frequency_16000,
            { "Sampling Frequency 16000 Hz",    "btavdtp.codec.sbc.sampling_frequency.16000",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_sampling_frequency_32000,
            { "Sampling Frequency 32000 Hz",    "btavdtp.codec.sbc.sampling_frequency.32000",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_sampling_frequency_44100,
            { "Sampling Frequency 44100 Hz",    "btavdtp.codec.sbc.sampling_frequency.44100",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_sampling_frequency_48000,
            { "Sampling Frequency 48000 Hz",    "btavdtp.codec.sbc.sampling_frequency.48000",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_channel_mode_mono,
            { "Channel Mode Mono",              "btavdtp.codec.sbc.channel_mode.mono",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_channel_mode_dual_channel,
            { "Channel Mode Dual Channel",      "btavdtp.codec.sbc.channel_mode.dual_channel",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_channel_mode_stereo,
            { "Channel Mode Stereo",            "btavdtp.codec.sbc.channel_mode.stereo",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_channel_mode_joint_stereo,
            { "Channel Mode Joint Stereo",      "btavdtp.codec.sbc.channel_mode.joint_stereo",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_block_4,
            { "Block Length 4",                 "btavdtp.codec.sbc.block.4",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_block_8,
            { "Block Length 8",                 "btavdtp.codec.sbc.block.8",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_block_12,
            { "Block Length 12",                "btavdtp.codec.sbc.block.12",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_block_16,
            { "Block Length 16",                "btavdtp.codec.sbc.block.16",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_subbands_4,
            { "Subbands 4",                     "btavdtp.codec.sbc.subbands.4",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_subbands_8,
            { "Subbands 8",                     "btavdtp.codec.sbc.subbands.8",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_allocation_method_snr,
            { "Allocation Method SNR",          "btavdtp.codec.sbc.allocation_method.snr",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_allocation_method_loudness,
            { "Allocation Method Loudness",     "btavdtp.codec.sbc.allocation_method.loudness",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_min_bitpool,
            { "Minimum Bitpool",                "btavdtp.codec.sbc.minimum_bitpool",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_sbc_max_bitpool,
            { "Maximum Bitpool",                "btavdtp.codec.sbc.maximum_bitpool",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_layer_1,
            { "MP1",                            "btavdtp.codec.mpeg12.layer_1",
            FT_BOOLEAN, 8, NULL, 0x80,
            "MPEG Layer 1", HFILL }
        },
        { &hf_btavdtp_mpeg12_layer_2,
            { "MP2",                            "btavdtp.codec.mpeg12.layer_2",
            FT_BOOLEAN, 8, NULL, 0x40,
            "MPEG Layer 2", HFILL }
        },
        { &hf_btavdtp_mpeg12_layer_3,
            { "MP3",                            "btavdtp.codec.mpeg12.layer_3",
            FT_BOOLEAN, 8, NULL, 0x20,
            "MPEG Layer 3", HFILL }
        },
        { &hf_btavdtp_mpeg12_crc_protection,
            { "CRC Protection",                 "btavdtp.codec.mpeg12.crc_protection",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_channel_mode_mono,
            { "Channel Mode Mono",              "btavdtp.codec.mpeg12.channel_mode.mono",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_channel_mode_dual_channel,
            { "Channel Mode Dual Channel",      "btavdtp.codec.mpeg12.channel_mode.dual_channel",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_channel_mode_stereo,
            { "Channel Mode Stereo",            "btavdtp.codec.mpeg12.channel_mode.stereo",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_channel_mode_joint_stereo,
            { "Channel Mode Joint Stereo",      "btavdtp.codec.mpeg12.channel_mode.joint_stereo",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_rfa,
            { "RFA",                            "btavdtp.codec.mpeg12.rfa",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_mpf_2,
            { "Media Payload Format 2",         "btavdtp.codec.mpeg12.mpf_2",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_sampling_frequency_16000,
            { "Sampling Frequency 16000 Hz",    "btavdtp.codec.sbc.sampling_frequency.16000",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_sampling_frequency_22050,
            { "Sampling Frequency 22050 Hz",    "btavdtp.codec.sbc.sampling_frequency.22050",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_sampling_frequency_24000,
            { "Sampling Frequency 24000 Hz",    "btavdtp.codec.sbc.sampling_frequency.24000",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_sampling_frequency_32000,
            { "Sampling Frequency 32000 Hz",    "btavdtp.codec.sbc.sampling_frequency.32000",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_sampling_frequency_44100,
            { "Sampling Frequency 44100 Hz",    "btavdtp.codec.sbc.sampling_frequency.44100",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_sampling_frequency_48000,
            { "Sampling Frequency 48000 Hz",    "btavdtp.codec.sbc.sampling_frequency.48000",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_vbr_supported,
            { "VBR Supported",                  "btavdtp.codec.mpeg12.vbr",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg12_bit_rate,
            { "Bit Rate",                       "btavdtp.codec.mpeg12.bit_rate",
            FT_UINT16, BASE_HEX, NULL, 0x7FFF,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_object_type_mpeg2_aac_lc,
            { "MPEG2 AAC LC",                   "btavdtp.codec.mpeg24.object_type.mpeg2_aac_lc",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_object_type_mpeg4_aac_lc,
            { "MPEG4 AAC LC",                   "btavdtp.codec.mpeg24.object_type.mpeg4_aac_lc",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_object_type_mpeg4_aac_ltp,
            { "MPEG4 AAC LTP",                  "btavdtp.codec.mpeg24.object_type.mpeg4_aac_ltp",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_object_type_mpeg4_aac_scalable,
            { "MPEG4 AAC Scalable",             "btavdtp.codec.mpeg24.object_type.mpeg4_aac_scalable",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_object_type_rfa,
            { "RFA",                            "btavdtp.codec.mpeg24.object_type.rfa",
            FT_UINT8, BASE_HEX, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_8000,
            { "Sampling Frequency 8000 Hz",     "btavdtp.codec.mpeg24.sampling_frequency.8000",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_11025,
            { "Sampling Frequency 11025 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.11025",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_12000,
            { "Sampling Frequency 12000 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.12000",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_16000,
            { "Sampling Frequency 16000 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.16000",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_22050,
            { "Sampling Frequency 22050 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.22050",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_24000,
            { "Sampling Frequency 24000 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.24000",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_32000,
            { "Sampling Frequency 32000 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.32000",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_44100,
            { "Sampling Frequency 44100 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.44100",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_48000,
            { "Sampling Frequency 48000 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.48000",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_64000,
            { "Sampling Frequency 64000 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.64000",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_88200,
            { "Sampling Frequency 88200 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.88200",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_sampling_frequency_96000,
            { "Sampling Frequency 96000 Hz",    "btavdtp.codec.mpeg24.sampling_frequency.96000",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_channels_1,
            { "Channels 1",                     "btavdtp.codec.mpeg24.channels.1",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_channels_2,
            { "Channels 2",                     "btavdtp.codec.mpeg24.channels.2",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_rfa,
            { "RFA",                            "btavdtp.codec.mpeg24.rfa",
            FT_UINT8, BASE_HEX, NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_vbr_supported,
            { "VBR Supported",                  "btavdtp.codec.mpeg24.vbr",
            FT_BOOLEAN, 24, NULL, 0x800000,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg24_bit_rate,
            { "Bit Rate",                       "btavdtp.codec.mpeg24.bit_rate",
            FT_UINT24, BASE_HEX, NULL, 0x7FFFFF,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_version,
            { "Version",                        "btavdtp.codec.atrac.version",
            FT_UINT8, BASE_DEC, NULL, 0xE0,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_channel_mode_single_channel,
            { "Channel Mode Single Channel",    "btavdtp.codec.atrac.channel_mode.single_channel",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_channel_mode_dual_channel,
            { "Channel Mode Dual Channel",      "btavdtp.codec.atrac.channel_mode.dual_channel",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_channel_mode_joint_stereo,
            { "Channel Mode Joint Stereo",      "btavdtp.codec.atrac.channel_mode.joint_stereo",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_rfa1,
            { "RFA",                            "btavdtp.codec.atrac.rfa1",
            FT_UINT8, BASE_HEX, NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_rfa2,
            { "RFA",                            "btavdtp.codec.atrac.rfa2",
            FT_UINT24, BASE_HEX, NULL, 0xC00000,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_sampling_frequency_44100,
            { "Sampling Frequency 44100 Hz",    "btavdtp.codec.sbc.sampling_frequency.44100",
            FT_BOOLEAN, 24, NULL, 0x200000,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_sampling_frequency_48000,
            { "Sampling Frequency 48000 Hz",    "btavdtp.codec.sbc.sampling_frequency.48000",
            FT_BOOLEAN, 24, NULL, 0x100000,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_vbr_supported,
            { "VBR Supported",                  "btavdtp.codec.atrac.vbr",
            FT_BOOLEAN, 24, NULL, 0x080000,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_bit_rate,
            { "Bit Rate",                       "btavdtp.codec.atrac.bit_rate",
            FT_UINT24, BASE_HEX, NULL, 0x07FFFF,
            NULL, HFILL }
        },
        { &hf_btavdtp_atrac_maximum_sul,
            { "Maximum SUL",                    "btavdtp.codec.atrac.maximum_sul",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Sound Unit Length (SUL) is one of the parameters that determine bit rate of the audio stream.", HFILL }
        },
        { &hf_btavdtp_atrac_rfa3,
            { "RFA",                            "btavdtp.codec.atrac.rfa3",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btavdtp_h263_level_10,
            { "H264 Level 10",                  "btavdtp.codec.h264.level.10",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_h263_level_20,
            { "H264 Level 20",                  "btavdtp.codec.h264.level.20",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_h263_level_30,
            { "H264 Level 30",                  "btavdtp.codec.h264.level.30",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_h263_level_rfa,
            { "H264 Level RFA",                 "btavdtp.codec.h264.level.rfa",
            FT_UINT8, BASE_HEX, NULL, 0x1F,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg4_level_0,
            { "MPEG Level 0",                   "btavdtp.codec.mpeg4.level.0",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg4_level_1,
            { "MPEG Level 1",                   "btavdtp.codec.mpeg4.level.1",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg4_level_2,
            { "MPEG Level 2",                   "btavdtp.codec.mpeg4.level.2",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg4_level_3,
            { "MPEG4 Level 3",                  "btavdtp.codec.mpeg4.level.3",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_mpeg4_level_rfa,
            { "MPEG4 Level RFA",                "btavdtp.codec.mpeg4.level.rfa",
            FT_UINT8, BASE_HEX, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_id,
            { "Vendor ID",                      "btavdtp.codec.vendor.vendor_id",
            FT_UINT32, BASE_HEX|BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_codec_id,
            { "Codec",                          "btavdtp.codec.vendor.codec_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_value,
            { "Value",                          "btavdtp.codec.vendor.value",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_apt_codec_id,
            { "Codec",                          "btavdtp.codec.vendor.codec_id",
            FT_UINT16, BASE_HEX, VALS(vendor_apt_codec_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptx_sampling_frequency_16000,
            { "Sampling Frequency 16000 Hz",    "btavdtp.codec.aptx.sampling_frequency.16000",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptx_sampling_frequency_32000,
            { "Sampling Frequency 32000 Hz",    "btavdtp.codec.aptx.sampling_frequency.32000",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptx_sampling_frequency_44100,
            { "Sampling Frequency 44100 Hz",    "btavdtp.codec.aptx.sampling_frequency.44100",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptx_sampling_frequency_48000,
            { "Sampling Frequency 48000 Hz",    "btavdtp.codec.aptx.sampling_frequency.48000",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptx_channel_mode_mono,
            { "Channel Mode Mono",              "btavdtp.codec.aptx.channel_mode.mono",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptx_channel_mode_dual_channel,
            { "Channel Mode Dual Channel",      "btavdtp.codec.aptx.channel_mode.dual_channel",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptx_channel_mode_stereo,
            { "Channel Mode Stereo",            "btavdtp.codec.aptx.channel_mode.stereo",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptx_channel_mode_joint_stereo,
            { "Channel Mode Joint Stereo",      "btavdtp.codec.aptx.channel_mode.joint_stereo",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptxhd_sampling_frequency_16000,
            { "Sampling Frequency 16000 Hz",    "btavdtp.codec.aptxhd.sampling_frequency.16000",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptxhd_sampling_frequency_32000,
            { "Sampling Frequency 32000 Hz",    "btavdtp.codec.aptxhd.sampling_frequency.32000",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptxhd_sampling_frequency_44100,
            { "Sampling Frequency 44100 Hz",    "btavdtp.codec.aptxhd.sampling_frequency.44100",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptxhd_sampling_frequency_48000,
            { "Sampling Frequency 48000 Hz",    "btavdtp.codec.aptxhd.sampling_frequency.48000",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptxhd_channel_mode_mono,
            { "Channel Mode Mono",              "btavdtp.codec.aptxhd.channel_mode.mono",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptxhd_channel_mode_dual_channel,
            { "Channel Mode Dual Channel",      "btavdtp.codec.aptxhd.channel_mode.dual_channel",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptxhd_channel_mode_stereo,
            { "Channel Mode Stereo",            "btavdtp.codec.aptxhd.channel_mode.stereo",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptxhd_channel_mode_joint_stereo,
            { "Channel Mode Joint Stereo",      "btavdtp.codec.aptxhd.channel_mode.joint_stereo",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_aptxhd_rfa,
            { "RFA",                            "btavdtp.codec.aptxhd.rfa",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_ldac_rfa1,
            { "RFA1",                           "btavdtp.codec.ldac.rfa1",
            FT_UINT8, BASE_HEX, NULL, 0xC0,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_ldac_codec_id,
            { "Codec",                          "btavdtp.codec.vendor.codec_id",
            FT_UINT16, BASE_HEX, VALS(vendor_ldac_codec_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_ldac_sampling_frequency_44100,
            { "Sampling Frequency 44100 Hz",    "btavdtp.codec.ldac.sampling_frequency.44100",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_ldac_sampling_frequency_48000,
            { "Sampling Frequency 48000 Hz",    "btavdtp.codec.ldac.sampling_frequency.48000",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_ldac_sampling_frequency_88200,
            { "Sampling Frequency 88200 Hz",    "btavdtp.codec.ldac.sampling_frequency.88200",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_ldac_sampling_frequency_96000,
            { "Sampling Frequency 96000 Hz",    "btavdtp.codec.ldac.sampling_frequency.96000",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_ldac_sampling_frequency_176400,
            { "Sampling Frequency 176400 Hz",    "btavdtp.codec.ldac.sampling_frequency.176400",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_ldac_sampling_frequency_192000,
            { "Sampling Frequency 192000 Hz",    "btavdtp.codec.ldac.sampling_frequency.192000",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_ldac_rfa2,
            { "RFA2",                           "btavdtp.codec.ldac.rfa2",
            FT_UINT8, BASE_HEX, NULL, 0xF8,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_ldac_channel_mode_mono,
            { "Channel Mode Mono",              "btavdtp.codec.ldac.channel_mode.mono",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_ldac_channel_mode_dual_channel,
            { "Channel Mode Dual Channel",      "btavdtp.codec.ldac.channel_mode.dual_channel",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btavdtp_vendor_specific_ldac_channel_mode_stereo,
            { "Channel Mode Stereo",            "btavdtp.codec.ldac.channel_mode.stereo",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btavdtp_capabilities,
            { "Capabilities",                   "btavdtp.capabilities",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btavdtp_service,
            { "Service",                        "btavdtp.service",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btavdtp_service_multiplexing_entry,
            { "Entry",                          "btavdtp.service_multiplexing_entry",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btavdtp_data,
            { "Data",                           "btavdtp.data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_btavdtp,
        &ett_btavdtp_sep,
        &ett_btavdtp_capabilities,
        &ett_btavdtp_service,
    };

    proto_btavdtp = proto_register_protocol("Bluetooth AVDTP Protocol", "BT AVDTP", "btavdtp");
    btavdtp_handle = register_dissector("btavdtp", dissect_btavdtp, proto_btavdtp);

    proto_register_field_array(proto_btavdtp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    module = prefs_register_protocol_subtree("Bluetooth", proto_btavdtp, NULL);
    prefs_register_static_text_preference(module, "avdtp.version",
            "Bluetooth Protocol AVDTP version: 1.3",
            "Version of protocol supported by this dissector.");

    channels             = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    sep_list             = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    sep_open             = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    media_packet_times   = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
#if RTP_PLAYER_WORKAROUND == true
    file_scope_stream_number = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
#endif
}

void
proto_reg_handoff_btavdtp(void)
{
    dissector_add_string("bluetooth.uuid", "19", btavdtp_handle);

    dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_AVDTP, btavdtp_handle);

    dissector_add_for_decode_as("btl2cap.cid", btavdtp_handle);
}


static int
dissect_aptx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item          *aptx_item;
    proto_tree          *aptx_tree;
    proto_item          *pitem;
    bta2dp_codec_info_t *info;
    double               cumulative_frame_duration = 0;

    info = (bta2dp_codec_info_t *) data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "aptX");

    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    case P2P_DIR_UNKNOWN:
        col_clear(pinfo->cinfo, COL_INFO);
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
            pinfo->p2p_dir);
        break;
    }

    col_append_str(pinfo->cinfo, COL_INFO, "aptX");

    aptx_item = proto_tree_add_item(tree, proto_aptx, tvb, 0, -1, ENC_NA);
    aptx_tree = proto_item_add_subtree(aptx_item, ett_aptx);

    proto_tree_add_item(aptx_tree, hf_aptx_data, tvb, 0, -1, ENC_NA);

    if (info && info->configuration && info->configuration_length >= 9) {
        bool fail = false;
        double expected_speed_data;
        double frame_duration;
        double frame_length = 2 * 2 * 4;
        int number_of_channels;
        int frequency;
        int sample_bits;

        switch (info->configuration[8] >> 4) {
        case 0x01:
            frequency = 48000;
            break;
        case 0x02:
            frequency = 44100;
            break;
        case 0x04:
            frequency = 32000;
            break;
        case 0x08:
            frequency = 16000;
            break;
        default:
            fail = true;
        }

        if (fail)
            return tvb_reported_length(tvb);

        switch (info->configuration[8] & 0x0F) {
        case 0x01:
        case 0x02:
        case 0x04:
            number_of_channels = 2;
            break;
        case 0x08:
            number_of_channels = 1;
            break;
        default:
            fail = true;
        }

        if (fail)
            return tvb_reported_length(tvb);

        sample_bits = 16;

        expected_speed_data = frequency * (sample_bits / 8.0) * number_of_channels;
        frame_duration = (((double) frame_length / (double) expected_speed_data) * 1000.0);

        cumulative_frame_duration = (tvb_reported_length(tvb) / 4.0) * frame_duration;

        pitem = proto_tree_add_double(aptx_tree, hf_aptx_cumulative_frame_duration, tvb, 0, 0, cumulative_frame_duration);
        proto_item_set_generated(pitem);

        if (info && info->previous_media_packet_info && info->current_media_packet_info) {
            nstime_t  delta;

            nstime_delta(&delta, &pinfo->abs_ts, &info->previous_media_packet_info->abs_ts);
            pitem = proto_tree_add_double(aptx_tree, hf_aptx_delta_time, tvb, 0, 0, nstime_to_msec(&delta));
            proto_item_set_generated(pitem);

            pitem = proto_tree_add_double(aptx_tree, hf_aptx_avrcp_song_position, tvb, 0, 0, info->previous_media_packet_info->avrcp_song_position);
            proto_item_set_generated(pitem);

            nstime_delta(&delta, &pinfo->abs_ts, &info->previous_media_packet_info->first_abs_ts);
            pitem = proto_tree_add_double(aptx_tree, hf_aptx_delta_time_from_the_beginning, tvb, 0, 0, nstime_to_msec(&delta));
            proto_item_set_generated(pitem);

            if (!pinfo->fd->visited)
                info->current_media_packet_info->cumulative_frame_duration += cumulative_frame_duration;

            pitem = proto_tree_add_double(aptx_tree, hf_aptx_cumulative_duration, tvb, 0, 0, info->previous_media_packet_info->cumulative_frame_duration);
            proto_item_set_generated(pitem);

            pitem = proto_tree_add_double(aptx_tree, hf_aptx_diff, tvb, 0, 0, info->previous_media_packet_info->cumulative_frame_duration - nstime_to_msec(&delta));
            proto_item_set_generated(pitem);
        }
    }

    return tvb_reported_length(tvb);
}

void
proto_register_aptx(void)
{
    static hf_register_info hf[] = {
        { &hf_aptx_data,
            { "Data",                            "aptx.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_aptx_cumulative_frame_duration,
            { "Cumulative Frame Duration",      "aptx.cumulative_frame_duration",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_aptx_delta_time,
            { "Delta time",                      "aptx.delta_time",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_aptx_avrcp_song_position,
            { "AVRCP Song Position",             "aptx.avrcp_song_position",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_aptx_delta_time_from_the_beginning,
            { "Delta time from the beginning",   "aptx.delta_time_from_the_beginning",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_aptx_cumulative_duration,
            { "Cumulative Music Duration",      "aptx.cumulative_music_duration",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_aptx_diff,
            { "Diff",                            "aptx.diff",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x00,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_aptx
    };

    proto_aptx = proto_register_protocol("aptX Codec", "aptX", "aptx");
    proto_register_field_array(proto_aptx, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    aptx_handle = register_dissector("aptx", dissect_aptx, proto_aptx);
}

static int
dissect_ldac(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *ti;
    proto_tree  *ldac_tree;
    proto_item  *pitem;
    proto_tree  *rtree;
    int         offset = 0;
    uint8_t     number_of_frames;
    uint8_t     syncword;
    uint8_t     byte;
    uint8_t     cci;
    unsigned    frequency;
    int         available;
    int         ldac_channels;
    int         counter = 1;
    int         frame_length;
    int         frame_sample_size;
    int         expected_speed_data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LDAC");

    ti = proto_tree_add_item(tree, proto_ldac, tvb, offset, -1, ENC_NA);
    ldac_tree = proto_item_add_subtree(ti, ett_ldac);

    proto_tree_add_item(ldac_tree, hf_ldac_fragmented,       tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ldac_tree, hf_ldac_starting_packet,  tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ldac_tree, hf_ldac_last_packet,      tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ldac_tree, hf_ldac_rfa,              tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ldac_tree, hf_ldac_number_of_frames, tvb, offset, 1, ENC_BIG_ENDIAN);
    number_of_frames = tvb_get_uint8(tvb, offset) & 0x0F;
    offset += 1;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        available = tvb_reported_length_remaining(tvb, offset);

        syncword = tvb_get_uint8(tvb, offset);
        if (syncword != 0xAA) {
            rtree = proto_tree_add_subtree_format(ldac_tree, tvb, offset, 1,
                    ett_ldac_list, NULL, "Frame: %3u/%3u", counter, number_of_frames);
            pitem = proto_tree_add_item(rtree, hf_ldac_syncword, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            expert_add_info(pinfo, pitem, &ei_ldac_syncword);
            break;
        }

        if (available > 1)  {
            byte = tvb_get_uint8(tvb, offset + 1);
            frequency = (byte & 0xE0) >> 5;
            cci = (byte & 0x18)>> 3;
            frame_length = byte & 0x07;
            frame_length <<= 6;
        } else {
            frequency = 0;
            cci = 0;
        }

        if (available > 2)  {
            byte = tvb_get_uint8(tvb, offset + 2);
            frame_length |= (byte & 0xFC) >> 2;
            frame_length +=1;
        } else {
            frame_length = 0;
        }

        rtree = proto_tree_add_subtree_format(ldac_tree, tvb, offset,
                3 + frame_length > available ? available : 3 + frame_length,
                ett_ldac_list, NULL, "Frame: %3u/%3u", counter, number_of_frames);

        if (3 + frame_length > available) {
            expert_add_info(pinfo, rtree, &ei_ldac_truncated_or_bad_length);
        }

        proto_tree_add_item(rtree, hf_ldac_syncword, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        if (cci == LDAC_CCI_MONO)
            ldac_channels = 1;
        else
            ldac_channels = 2;

        switch (frequency) {
            case LDAC_FSID_044:
                frequency = 44100;
                frame_sample_size = 128;
                break;
            case LDAC_FSID_048:
                frequency = 48000;
                frame_sample_size = 128;
                break;
            case LDAC_FSID_088:
                frequency = 88200;
                frame_sample_size = 256;
                break;
            case LDAC_FSID_096:
                frequency = 96000;
                frame_sample_size = 256;
                break;
            case LDAC_FSID_176:
                frequency = 176400;
                frame_sample_size = 512;
                break;
            case LDAC_FSID_192:
                frequency = 192000;
                frame_sample_size = 512;
                break;
            default:
                frequency = 0;
                frame_sample_size = 1;
        }

        proto_tree_add_item(rtree, hf_ldac_sampling_frequency, tvb, offset, 1, ENC_BIG_ENDIAN);
        pitem = proto_tree_add_item(rtree, hf_ldac_channel_config_index, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(pitem, ", Number of channels : %d", ldac_channels);
        proto_tree_add_item(rtree, hf_ldac_frame_length_h,  tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(rtree, hf_ldac_frame_length_l,  tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rtree, hf_ldac_frame_status,  tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(rtree, hf_ldac_data, tvb, offset, frame_length, ENC_NA);
        offset += frame_length;

        expected_speed_data = (8*(frame_length+3) * frequency) / (frame_sample_size*1000);
        pitem = proto_tree_add_uint(rtree, hf_ldac_expected_data_speed, tvb, offset, 0, expected_speed_data);
        proto_item_append_text(pitem, " kbits/sec");
        proto_item_set_generated(pitem);
        counter += 1;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " Frames=%u", number_of_frames);

    return offset;
}
void
proto_register_ldac(void)
{
    expert_module_t* expert_ldac;

    static hf_register_info hf[] = {
        { &hf_ldac_fragmented,
            { "Fragmented",                      "ldac.fragmented",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_ldac_starting_packet,
            { "Starting Packet",                 "ldac.starting_packet",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_ldac_last_packet,
            { "Last Packet",                     "ldac.last_packet",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_ldac_rfa,
            { "RFA",                             "ldac.rfa",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_ldac_number_of_frames,
            { "Number of Frames",                "ldac.number_of_frames",
            FT_UINT8, BASE_DEC, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_ldac_syncword,
            { "Sync Word",                       "ldac.syncword",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ldac_sampling_frequency,
            { "Sampling Frequency",              "ldac.sampling_frequency",
            FT_UINT8, BASE_HEX, VALS(ldac_sampling_frequency_vals), 0xE0,
            NULL, HFILL }
        },
        { &hf_ldac_channel_config_index,
            { "Channel Config Index",            "ldac.channel_config_index",
            FT_UINT8, BASE_HEX, VALS(ldac_channel_config_index_vals), 0x18,
            NULL, HFILL }
        },
        { &hf_ldac_frame_length_h,
            { "Frame Length Index(H)",           "ldac.frame_length_index_H",
              FT_UINT8, BASE_HEX, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_ldac_frame_length_l,
            { "Frame Length Index(L)",           "ldac.frame_length_index_L",
              FT_UINT8, BASE_HEX, NULL, 0xFC,
            NULL, HFILL }
        },
        { &hf_ldac_frame_status,
            { "Frame Status",                    "ldac.frame_status",
            FT_UINT8, BASE_DEC, NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_ldac_expected_data_speed,
            { "Bitrate",             "ldac.expected_speed_data",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ldac_data,
            { "Frame Data",                      "ldac.data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_ldac,
        &ett_ldac_list,
    };

    static ei_register_info ei[] = {
        { &ei_ldac_syncword, { "ldac.syncword.unexpected", PI_PROTOCOL, PI_WARN, "Unexpected syncword", EXPFILL }},
        { &ei_ldac_truncated_or_bad_length, { "ldac.data.truncated", PI_PROTOCOL, PI_WARN, "Either bad frame length or data truncated", EXPFILL }},
    };

    proto_ldac = proto_register_protocol("LDAC Codec", "LDAC", "ldac");

    proto_register_field_array(proto_ldac, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ldac = expert_register_protocol(proto_ldac);
    expert_register_field_array(expert_ldac, ei, array_length(ei));

    ldac_handle = register_dissector("ldac", dissect_ldac, proto_ldac);

}

static int
dissect_bta2dp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item          *ti;
    proto_tree          *bta2dp_tree;
    proto_item          *pitem;
    int                  offset = 0;
    dissector_handle_t   codec_dissector = NULL;
    bta2dp_codec_info_t  bta2dp_codec_info;
    sep_data_t           sep_data;
    bool                 no_avdtp_session;

    no_avdtp_session = (proto_btavdtp != (int) GPOINTER_TO_UINT(wmem_list_frame_data(
                wmem_list_frame_prev(wmem_list_tail(pinfo->layers)))));

    sep_data.codec = CODEC_SBC;
    sep_data.content_protection_type = 0;
    sep_data.acp_seid = 0;
    sep_data.int_seid = 0;
    sep_data.previous_media_packet_info = NULL;
    sep_data.current_media_packet_info = NULL;
    sep_data.stream_start_in_frame = 0;
    sep_data.stream_end_in_frame = 0;
    sep_data.stream_number = 1;
    sep_data.vendor_id = 0;
    sep_data.vendor_codec = 0;
    sep_data.configuration_length = 0;
    sep_data.configuration = NULL;

    if (force_a2dp_scms_t || force_a2dp_codec != CODEC_DEFAULT) {
        if (force_a2dp_scms_t)
            sep_data.content_protection_type = 2;
        else if (data && !no_avdtp_session)
            sep_data.content_protection_type = ((sep_data_t *) data)->content_protection_type;

        if (force_a2dp_codec != CODEC_DEFAULT)
            sep_data.codec = force_a2dp_codec;
        else if (data && !no_avdtp_session)
            sep_data.codec = ((sep_data_t *) data)->codec;
    } else {
        if (data && !no_avdtp_session)
            sep_data = *((sep_data_t *) data);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "A2DP");

    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    case P2P_DIR_UNKNOWN:
        col_clear(pinfo->cinfo, COL_INFO);
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
            pinfo->p2p_dir);
        break;
    }

    ti = proto_tree_add_item(tree, proto_bta2dp, tvb, offset, -1, ENC_NA);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Audio stream - %s",
            val_to_str_const(sep_data.codec, media_codec_audio_type_vals, "unknown codec"));

    bta2dp_tree = proto_item_add_subtree(ti, ett_bta2dp);

    pitem = proto_tree_add_uint(bta2dp_tree, hf_bta2dp_acp_seid, tvb, 0, 0, sep_data.acp_seid);
    proto_item_set_generated(pitem);

    pitem = proto_tree_add_uint(bta2dp_tree, hf_bta2dp_int_seid, tvb, 0, 0, sep_data.int_seid);
    proto_item_set_generated(pitem);

    pitem = proto_tree_add_uint(bta2dp_tree, hf_bta2dp_codec, tvb, 0, 0, sep_data.codec);
    proto_item_set_generated(pitem);

    if (sep_data.codec == 0xFF) { /* Vendor Specific Codec */
        pitem = proto_tree_add_uint(bta2dp_tree, hf_bta2dp_vendor_id, tvb, 0, 0, sep_data.vendor_id);
        proto_item_set_generated(pitem);

        pitem = proto_tree_add_uint(bta2dp_tree, hf_bta2dp_vendor_codec_id, tvb, 0, 0, sep_data.vendor_codec);
        proto_item_set_generated(pitem);

        if ((sep_data.vendor_id == 0x004F && sep_data.vendor_codec == CODECID_APT_X) ||
                (sep_data.vendor_id == 0x00D7 && sep_data.vendor_codec == CODECID_APT_X_HD))
            codec_dissector = aptx_handle;

        if (sep_data.vendor_id == 0x012D && sep_data.vendor_codec == 0x00AA)
            codec_dissector = ldac_handle;
    }

    if (sep_data.content_protection_type > 0) {
        pitem = proto_tree_add_uint(bta2dp_tree, hf_bta2dp_content_protection, tvb, 0, 0, sep_data.content_protection_type);
        proto_item_set_generated(pitem);
    }

    if (sep_data.stream_start_in_frame > 0) {
        pitem = proto_tree_add_uint(bta2dp_tree, hf_bta2dp_stream_start_in_frame, tvb, 0, 0, sep_data.stream_start_in_frame);
        proto_item_set_generated(pitem);
    }

    if (sep_data.stream_end_in_frame > 0) {
        pitem = proto_tree_add_uint(bta2dp_tree, hf_bta2dp_stream_end_in_frame, tvb, 0, 0, sep_data.stream_end_in_frame);
        proto_item_set_generated(pitem);
    }

    pitem = proto_tree_add_uint(bta2dp_tree, hf_bta2dp_stream_number, tvb, 0, 0, sep_data.stream_number);
    proto_item_set_generated(pitem);

    switch (sep_data.codec) {
        case CODEC_SBC:
            codec_dissector = sbc_handle;
            break;
         case CODEC_MPEG12_AUDIO:
            codec_dissector = mp2t_handle;
            break;
        case CODEC_MPEG24_AAC:
            codec_dissector = mpeg_audio_handle;
            break;
        case CODEC_ATRAC:
            codec_dissector = atrac_handle;
            break;
        case CODEC_APT_X:
        case CODEC_APT_X_HD:
            codec_dissector = aptx_handle;
            break;
        case CODEC_LDAC:
            codec_dissector = ldac_handle;
            break;
    }

    bta2dp_codec_info.codec_dissector            = codec_dissector;
    bta2dp_codec_info.configuration_length       = sep_data.configuration_length;
    bta2dp_codec_info.configuration              = sep_data.configuration;
    bta2dp_codec_info.content_protection_type    = sep_data.content_protection_type;
    bta2dp_codec_info.previous_media_packet_info = sep_data.previous_media_packet_info;
    bta2dp_codec_info.current_media_packet_info  = sep_data.current_media_packet_info;

#if RTP_PLAYER_WORKAROUND == true
    /* XXX: Workaround to get multiple RTP streams, because conversations are too
       weak to recognize Bluetooth streams (key is: uint32_t interface_id, uint32_t adapter_id, uint32_t chandle, uint32_t cid, uint32_t direction -> uint32_t stream_number) */
    pinfo->srcport = sep_data.stream_number;
    pinfo->destport = sep_data.stream_number;
#endif

    if (bta2dp_codec_info.content_protection_type == 0 && codec_dissector == aptx_handle) {
        call_dissector_with_data(aptx_handle, tvb, pinfo, tree, &bta2dp_codec_info);
    } else {
        bluetooth_add_address(pinfo, &pinfo->net_dst, sep_data.stream_number, "BT A2DP", pinfo->num, RTP_MEDIA_AUDIO, &bta2dp_codec_info);
        call_dissector(rtp_handle, tvb, pinfo, tree);
    }
    offset += tvb_reported_length_remaining(tvb, offset);

    return offset;
}

void
proto_register_bta2dp(void)
{
    module_t *module;

    static hf_register_info hf[] = {
        { &hf_bta2dp_acp_seid,
            { "ACP SEID",                        "bta2dp.acp_seid",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bta2dp_int_seid,
            { "INT SEID",                        "bta2dp.int_seid",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bta2dp_codec,
            { "Codec",                           "bta2dp.codec",
            FT_UINT8, BASE_HEX, VALS(media_codec_audio_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_bta2dp_vendor_id,
            { "Vendor ID",                       "bta2dp.codec.vendor.vendor_id",
            FT_UINT32, BASE_HEX|BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_bta2dp_vendor_codec_id,
            { "Vendor Codec",                    "bta2dp.codec.vendor.codec_id",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bta2dp_content_protection,
            { "Content Protection",              "bta2dp.content_protection",
            FT_UINT16, BASE_HEX, VALS(content_protection_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_bta2dp_stream_start_in_frame,
            { "Stream Start in Frame",           "bta2dp.stream_start_in_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bta2dp_stream_end_in_frame,
            { "Stream End in Frame",           "bta2dp.stream_end_in_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bta2dp_stream_number,
            { "Stream Number",                   "bta2dp.stream_number",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_bta2dp
    };

    proto_bta2dp = proto_register_protocol("Bluetooth A2DP Profile", "BT A2DP", "bta2dp");
    proto_register_field_array(proto_bta2dp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    bta2dp_handle = register_dissector("bta2dp", dissect_bta2dp, proto_bta2dp);

    module = prefs_register_protocol_subtree("Bluetooth", proto_bta2dp, NULL);
    prefs_register_static_text_preference(module, "a2dp.version",
            "Bluetooth Profile A2DP version: 1.3",
            "Version of profile supported by this dissector.");

    prefs_register_bool_preference(module, "a2dp.content_protection.scms_t",
            "Force SCMS-T decoding",
            "Force decoding stream as A2DP with Content Protection SCMS-T ",
            &force_a2dp_scms_t);

    prefs_register_enum_preference(module, "a2dp.codec",
            "Force codec",
            "Force decoding stream as A2DP with specified codec",
            &force_a2dp_codec, pref_a2dp_codec, false);
}

void
proto_reg_handoff_bta2dp(void)
{
    sbc_handle = find_dissector_add_dependency("sbc", proto_bta2dp);
    mp2t_handle = find_dissector_add_dependency("mp2t", proto_bta2dp);
    mpeg_audio_handle = find_dissector_add_dependency("mpeg-audio", proto_bta2dp);
/* TODO: ATRAC dissector does not exist yet */
    atrac_handle = find_dissector_add_dependency("atrac", proto_bta2dp);

    rtp_handle   = find_dissector_add_dependency("rtp", proto_bta2dp);

    dissector_add_string("bluetooth.uuid", "110a", bta2dp_handle);
    dissector_add_string("bluetooth.uuid", "110b", bta2dp_handle);
    dissector_add_string("bluetooth.uuid", "110d", bta2dp_handle);

    dissector_add_for_decode_as("btl2cap.cid", bta2dp_handle);
}

static int
dissect_btvdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item          *ti;
    proto_tree          *btvdp_tree;
    proto_item          *pitem;
    int                  offset = 0;
    dissector_handle_t   codec_dissector = NULL;
    btvdp_codec_info_t   btvdp_codec_info;
    sep_data_t           sep_data;
    bool                 no_avdtp_session;

    no_avdtp_session = (proto_btavdtp != (int) GPOINTER_TO_UINT(wmem_list_frame_data(
                wmem_list_frame_prev(wmem_list_tail(pinfo->layers)))));

    sep_data.codec = CODEC_H263_BASELINE;
    sep_data.content_protection_type = 0;
    sep_data.acp_seid = 0;
    sep_data.int_seid = 0;
    sep_data.previous_media_packet_info = NULL;
    sep_data.current_media_packet_info = NULL;
    sep_data.stream_start_in_frame = 0;
    sep_data.stream_end_in_frame = 0;
    sep_data.stream_number = 1;
    sep_data.vendor_id = 0;
    sep_data.vendor_codec = 0;
    sep_data.configuration_length = 0;
    sep_data.configuration = NULL;

    if (force_vdp_scms_t || force_vdp_codec) {
        if (force_vdp_scms_t)
            sep_data.content_protection_type = 2;
        else if (data  && !no_avdtp_session)
            sep_data.content_protection_type = ((sep_data_t *) data)->content_protection_type;

        if (force_vdp_codec)
            sep_data.codec = force_vdp_codec;
        else if (data  && !no_avdtp_session)
            sep_data.codec = ((sep_data_t *) data)->codec;
    } else {
        if (data  && !no_avdtp_session)
            sep_data = *((sep_data_t *) data);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VDP");

    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    case P2P_DIR_UNKNOWN:
        col_clear(pinfo->cinfo, COL_INFO);
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
            pinfo->p2p_dir);
        break;
    }

    ti = proto_tree_add_item(tree, proto_btvdp, tvb, offset, -1, ENC_NA);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Video stream - %s",
            val_to_str_const(sep_data.codec, media_codec_video_type_vals, "unknown codec"));

    btvdp_tree = proto_item_add_subtree(ti, ett_btvdp);

    pitem = proto_tree_add_uint(btvdp_tree, hf_btvdp_acp_seid, tvb, 0, 0, sep_data.acp_seid);
    proto_item_set_generated(pitem);

    pitem = proto_tree_add_uint(btvdp_tree, hf_btvdp_int_seid, tvb, 0, 0, sep_data.int_seid);
    proto_item_set_generated(pitem);

    pitem = proto_tree_add_uint(btvdp_tree, hf_btvdp_codec, tvb, 0, 0, sep_data.codec);
    proto_item_set_generated(pitem);

    if (sep_data.codec == 0xFF) { /* Vendor Specific Codec */
        pitem = proto_tree_add_uint(btvdp_tree, hf_btvdp_vendor_id, tvb, 0, 0, sep_data.vendor_id);
        proto_item_set_generated(pitem);

        pitem = proto_tree_add_uint(btvdp_tree, hf_btvdp_vendor_codec_id, tvb, 0, 0, sep_data.vendor_codec);
        proto_item_set_generated(pitem);
    }

    if (sep_data.content_protection_type > 0) {
        pitem = proto_tree_add_uint(btvdp_tree, hf_btvdp_content_protection, tvb, 0, 0, sep_data.content_protection_type);
        proto_item_set_generated(pitem);
    }

    if (sep_data.stream_start_in_frame > 0) {
        pitem = proto_tree_add_uint(btvdp_tree, hf_btvdp_stream_start_in_frame, tvb, 0, 0, sep_data.stream_start_in_frame);
        proto_item_set_generated(pitem);
    }

    if (sep_data.stream_end_in_frame > 0) {
        pitem = proto_tree_add_uint(btvdp_tree, hf_btvdp_stream_end_in_frame, tvb, 0, 0, sep_data.stream_end_in_frame);
        proto_item_set_generated(pitem);
    }

    pitem = proto_tree_add_uint(btvdp_tree, hf_btvdp_stream_number, tvb, 0, 0, sep_data.stream_number);
    proto_item_set_generated(pitem);

    switch (sep_data.codec) {
        case CODEC_H263_BASELINE:
        case CODEC_H263_PROFILE_3:
        case CODEC_H263_PROFILE_8:
            codec_dissector = h263_handle;
            break;
        case CODEC_MPEG4_VSP:
            codec_dissector = mp4v_es_handle;
            break;
    }

    btvdp_codec_info.codec_dissector = codec_dissector;
    btvdp_codec_info.content_protection_type = sep_data.content_protection_type;

#if RTP_PLAYER_WORKAROUND == true
    /* XXX: Workaround to get multiple RTP streams, because conversations are too
       weak to recognize Bluetooth streams (key is: uint32_t interface_id, uint32_t adapter_id, uint32_t chandle, uint32_t cid, uint32_t direction -> uint32_t stream_number) */
    pinfo->srcport = sep_data.stream_number;
    pinfo->destport = sep_data.stream_number;
#endif

    bluetooth_add_address(pinfo, &pinfo->net_dst, 0, "BT VDP", pinfo->num, RTP_MEDIA_VIDEO, &btvdp_codec_info);
    call_dissector(rtp_handle, tvb, pinfo, tree);
    offset += tvb_reported_length_remaining(tvb, offset);

    return offset;
}

void
proto_register_btvdp(void)
{
    module_t *module;
    expert_module_t* expert_btavdtp;

    static hf_register_info hf[] = {
        { &hf_btvdp_acp_seid,
            { "ACP SEID",                        "btvdp.acp_seid",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btvdp_int_seid,
            { "INT SEID",                        "btvdp.int_seid",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btvdp_codec,
            { "Codec",                           "btvdp.codec",
            FT_UINT8, BASE_HEX, VALS(media_codec_video_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btvdp_vendor_id,
            { "Vendor ID",                       "btvdp.codec.vendor.vendor_id",
            FT_UINT32, BASE_HEX|BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_btvdp_vendor_codec_id,
            { "Vendor Codec",                    "btvdp.codec.vendor.codec_id",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btvdp_content_protection,
            { "Content Protection",              "btvdp.content_protection",
            FT_UINT16, BASE_HEX, VALS(content_protection_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btvdp_stream_start_in_frame,
            { "Stream Start in Frame",           "btvdp.stream_start_in_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btvdp_stream_end_in_frame,
            { "Stream End in Frame",             "btvdp.stream_end_in_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btvdp_stream_number,
            { "Stream Number",                   "btvdp.stream_number",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_btvdp
    };

    static ei_register_info ei[] = {
        { &ei_btavdtp_sbc_min_bitpool_out_of_range, { "btavdtp.codec.sbc.minimum_bitpool.out_of_range", PI_PROTOCOL, PI_WARN, "Bitpool is out of range. Should be 2..250.", EXPFILL }},
        { &ei_btavdtp_sbc_max_bitpool_out_of_range, { "btavdtp.codec.sbc.maximum_bitpool.out_of_range", PI_PROTOCOL, PI_WARN, "Bitpool is out of range. Should be 2..250.", EXPFILL }},
        { &ei_btavdtp_unexpected_losc_data, { "btavdtp.unexpected_losc_data", PI_PROTOCOL, PI_WARN, "Unexpected losc data", EXPFILL }},
    };

    proto_btvdp = proto_register_protocol("Bluetooth VDP Profile", "BT VDP", "btvdp");
    btvdp_handle = register_dissector("btvdp", dissect_btvdp, proto_btvdp);
    proto_register_field_array(proto_btvdp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_btavdtp = expert_register_protocol(proto_btvdp);
    expert_register_field_array(expert_btavdtp, ei, array_length(ei));

    module = prefs_register_protocol_subtree("Bluetooth", proto_btvdp, NULL);
    prefs_register_static_text_preference(module, "vdp.version",
            "Bluetooth Profile VDP version: 1.1",
            "Version of profile supported by this dissector.");

    prefs_register_bool_preference(module, "vdp.content_protection.scms_t",
            "Force SCMS-T decoding",
            "Force decoding stream as VDP with Content Protection SCMS-T ",
            &force_vdp_scms_t);

    prefs_register_enum_preference(module, "vdp.codec",
            "Force codec",
            "Force decoding stream as VDP with specified codec",
            &force_vdp_codec, pref_vdp_codec, false);
}

void
proto_reg_handoff_btvdp(void)
{
    h263_handle = find_dissector_add_dependency("h263", proto_btvdp);
    mp4v_es_handle = find_dissector_add_dependency("mp4v-es", proto_btvdp);

    rtp_handle   = find_dissector_add_dependency("rtp", proto_btvdp);

    dissector_add_string("bluetooth.uuid", "1303", btvdp_handle);
    dissector_add_string("bluetooth.uuid", "1304", btvdp_handle);
    dissector_add_string("bluetooth.uuid", "1305", btvdp_handle);

    dissector_add_for_decode_as("btl2cap.cid", btvdp_handle);
}



static int
dissect_a2dp_cp_scms_t(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item  *main_item;
    proto_tree  *main_tree;
    int          offset = 0;

    main_item = proto_tree_add_item(tree, proto_bta2dp_cph_scms_t, tvb, offset, 1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_bta2dp_cph_scms_t);

    proto_tree_add_item(main_tree, hf_bta2dp_reserved , tvb, offset, 1, ENC_NA);
    proto_tree_add_item(main_tree, hf_bta2dp_cp_bit, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(main_tree, hf_bta2dp_l_bit , tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

void
proto_register_bta2dp_content_protection_header_scms_t(void)
{
    static hf_register_info hf[] = {
        { &hf_bta2dp_l_bit,
            { "L-bit",                           "bta2dp.content_protection_header.scms_t.l_bit",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_bta2dp_cp_bit,
            { "Cp-bit",                          "bta2dp.content_protection_header.scms_t.cp_bit",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_bta2dp_reserved,
            { "Reserved",                        "bta2dp.content_protection_header.scms_t.reserved",
            FT_BOOLEAN, 8, NULL, 0xFC,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_bta2dp_cph_scms_t
    };

    proto_bta2dp_cph_scms_t = proto_register_protocol("Bluetooth A2DP Content Protection Header SCMS-T", "BT A2DP Content Protection Header SCMS-T", "bta2dp_content_protection_header_scms_t");
    proto_register_field_array(proto_bta2dp_cph_scms_t, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("bta2dp_content_protection_header_scms_t", dissect_a2dp_cp_scms_t, proto_bta2dp_cph_scms_t);
}

static int
dissect_vdp_cp_scms_t(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item  *main_item;
    proto_tree  *main_tree;
    int          offset = 0;

    main_item = proto_tree_add_item(tree, proto_btvdp_cph_scms_t, tvb, offset, 1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_btvdp_cph_scms_t);

    proto_tree_add_item(main_tree, hf_btvdp_reserved , tvb, offset, 1, ENC_NA);
    proto_tree_add_item(main_tree, hf_btvdp_cp_bit, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(main_tree, hf_btvdp_l_bit , tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

void
proto_register_btvdp_content_protection_header_scms_t(void)
{
    static hf_register_info hf[] = {
        { &hf_btvdp_l_bit,
            { "L-bit",                           "btvdp.content_protection_header.scms_t.l_bit",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_btvdp_cp_bit,
            { "Cp-bit",                          "btvdp.content_protection_header.scms_t.cp_bit",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btvdp_reserved,
            { "Reserved",                        "btvdp.content_protection_header.scms_t.reserved",
            FT_BOOLEAN, 8, NULL, 0xFC,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_btvdp_cph_scms_t
    };

    proto_btvdp_cph_scms_t = proto_register_protocol("Bluetooth VDP Content Protection Header SCMS-T", "BT VDP Content Protection Header SCMS-T", "btvdp_content_protection_header_scms_t");
    proto_register_field_array(proto_btvdp_cph_scms_t, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("btvdp_content_protection_header_scms_t", dissect_vdp_cp_scms_t, proto_btvdp_cph_scms_t);
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

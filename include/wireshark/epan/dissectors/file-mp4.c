/* file-mp4.c
 * routines for dissection of MP4 files
 * Copyright 2013-2014, Martin Kaiser <martin@kaiser.cx>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* this dissector is based on
 * ISO/IEC 14496-12 (ISO base media file format) and
 * ISO/IEC 14496-14 (MP4 file format)
 * 3GPP TS 26.244 (Adaptive-Streaming profile)
 *
 * at the moment, it dissects the basic box structure and the payload of
 * some simple boxes */


#include "config.h"

#include <math.h>

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/expert.h>
#include <wsutil/array.h>
#include <wiretap/wtap.h>

#define MAKE_TYPE_VAL(a, b, c, d)   ((a)<<24 | (b)<<16 | (c)<<8 | (d))

/* Although the dissection of each box consumes a couple of bytes, it's
   possible to craft a file whose boxes recurse so deeply that wireshark
   crashes before we processed all data. Therefore, we limit the
   recursion level for boxes to a reasonable depth. */
#define MP4_BOX_MAX_REC_LVL  20

void proto_register_mp4(void);
void proto_reg_handoff_mp4(void);

static dissector_handle_t mp4_handle;

static int dissect_mp4_box(uint32_t parent_box_type _U_, unsigned depth,
        tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

static int proto_mp4;

static int ett_mp4;
static int ett_mp4_box;
static int ett_mp4_full_box_flags;
static int ett_mp4_entry;

static int hf_mp4_box_size;
static int hf_mp4_box_type_str;
static int hf_mp4_box_largesize;
static int hf_mp4_full_box_ver;
static int hf_mp4_full_box_flags;
static int hf_mp4_ftyp_brand;
static int hf_mp4_ftyp_ver;
static int hf_mp4_ftyp_add_brand;
static int hf_mp4_stsz_sample_size;
static int hf_mp4_stsz_sample_count;
static int hf_mp4_stsz_entry_size;
static int hf_mp4_stsc_entry_count;
static int hf_mp4_stsc_first_chunk;
static int hf_mp4_stsc_samples_per_chunk;
static int hf_mp4_stsc_sample_description_index;
static int hf_mp4_stco_entry_cnt;
static int hf_mp4_stco_chunk_offset;
static int hf_mp4_mvhd_creat_time;
static int hf_mp4_mvhd_mod_time;
static int hf_mp4_mvhd_timescale;
static int hf_mp4_mvhd_duration;
static int hf_mp4_mvhd_rate;
static int hf_mp4_mvhd_vol;
static int hf_mp4_mvhd_next_tid;
static int hf_mp4_mfhd_seq_num;
static int hf_mp4_tkhd_flags_enabled;
static int hf_mp4_tkhd_flags_in_movie;
static int hf_mp4_tkhd_flags_in_preview;
static int hf_mp4_tkhd_flags_size_is_aspect_ratio;
static int hf_mp4_tkhd_creat_time;
static int hf_mp4_tkhd_mod_time;
static int hf_mp4_tkhd_track_id;
static int hf_mp4_tkhd_duration;
static int hf_mp4_tkhd_width;
static int hf_mp4_tkhd_height;
static int hf_mp4_hdlr_type;
static int hf_mp4_hdlr_name;
static int hf_mp4_dref_entry_cnt;
static int hf_mp4_stsd_entry_cnt;
static int hf_mp4_url_flags_media_data_location;
static int hf_mp4_stts_entry_cnt;
static int hf_mp4_stts_sample_count;
static int hf_mp4_stts_sample_delta;
static int hf_mp4_ctts_sample_count;
static int hf_mp4_ctts_sample_offset_signed;
static int hf_mp4_ctts_sample_offset_unsigned;
static int hf_mp4_elst_entry_cnt;
static int hf_mp4_elst_segment_duration;
static int hf_mp4_elst_media_time;
static int hf_mp4_elst_media_rate_integer;
static int hf_mp4_elst_media_rate_fraction;
static int hf_mp4_sidx_reference_id;
static int hf_mp4_sidx_timescale;
static int hf_mp4_sidx_earliest_presentation_time_v0;
static int hf_mp4_sidx_first_offset_v0;
static int hf_mp4_sidx_earliest_presentation_time;
static int hf_mp4_sidx_first_offset;
static int hf_mp4_sidx_reserved;
static int hf_mp4_sidx_entry_cnt;
static int hf_mp4_sidx_reference_type;
static int hf_mp4_sidx_reference_size;
static int hf_mp4_sidx_subsegment_duration;
static int hf_mp4_sidx_starts_with_sap;
static int hf_mp4_sidx_sap_type;
static int hf_mp4_sidx_sap_delta_time;

static const value_string mp4_sidx_reference_type_vals[] = {
    { 0,  "Movie" },
    { 1,  "Index" },

    { 0,  NULL }
};

static expert_field ei_mp4_box_too_large;
static expert_field ei_mp4_too_many_rec_lvls;
static expert_field ei_mp4_mvhd_next_tid_unknown;

static uint32_t mvhd_timescale;

/* a box must at least have a 32bit len field and a 32bit type */
#define MIN_BOX_SIZE 8
/* an extended box has the first length field set to 1 */
#define BOX_SIZE_EXTENDED 1

/* the box type is stored as four text characters
   it is in network byte order and contains only printable characters
   for our internal handling, we convert this to a 32bit value */

#define BOX_TYPE_NONE  0x0 /* used for parent_box_type of a top-level box */
#define BOX_TYPE_FTYP  MAKE_TYPE_VAL('f', 't', 'y', 'p')
#define BOX_TYPE_MOOV  MAKE_TYPE_VAL('m', 'o', 'o', 'v')
#define BOX_TYPE_MVHD  MAKE_TYPE_VAL('m', 'v', 'h', 'd')
#define BOX_TYPE_TRAK  MAKE_TYPE_VAL('t', 'r', 'a', 'k')
#define BOX_TYPE_TKHD  MAKE_TYPE_VAL('t', 'k', 'h', 'd')
#define BOX_TYPE_MDIA  MAKE_TYPE_VAL('m', 'd', 'i', 'a')
#define BOX_TYPE_MDHD  MAKE_TYPE_VAL('m', 'd', 'h', 'd')
#define BOX_TYPE_HDLR  MAKE_TYPE_VAL('h', 'd', 'l', 'r')
#define BOX_TYPE_MINF  MAKE_TYPE_VAL('m', 'i', 'n', 'f')
#define BOX_TYPE_VMHD  MAKE_TYPE_VAL('v', 'm', 'h', 'd')
#define BOX_TYPE_SMHD  MAKE_TYPE_VAL('s', 'm', 'h', 'd')
#define BOX_TYPE_DINF  MAKE_TYPE_VAL('d', 'i', 'n', 'f')
#define BOX_TYPE_DREF  MAKE_TYPE_VAL('d', 'r', 'e', 'f')
#define BOX_TYPE_STBL  MAKE_TYPE_VAL('s', 't', 'b', 'l')
#define BOX_TYPE_STTS  MAKE_TYPE_VAL('s', 't', 't', 's')
#define BOX_TYPE_CTTS  MAKE_TYPE_VAL('c', 't', 't', 's')
#define BOX_TYPE_STSD  MAKE_TYPE_VAL('s', 't', 's', 'd')
#define BOX_TYPE_STSZ  MAKE_TYPE_VAL('s', 't', 's', 'z')
#define BOX_TYPE_STZ2  MAKE_TYPE_VAL('s', 't', 'z', '2')
#define BOX_TYPE_STSC  MAKE_TYPE_VAL('s', 't', 's', 'c')
#define BOX_TYPE_STCO  MAKE_TYPE_VAL('s', 't', 'c', 'o')
#define BOX_TYPE_STSS  MAKE_TYPE_VAL('s', 't', 's', 's')
#define BOX_TYPE_MVEX  MAKE_TYPE_VAL('m', 'v', 'e', 'x')
#define BOX_TYPE_MOOF  MAKE_TYPE_VAL('m', 'o', 'o', 'f')
#define BOX_TYPE_MEHD  MAKE_TYPE_VAL('m', 'e', 'h', 'd')
#define BOX_TYPE_TREX  MAKE_TYPE_VAL('t', 'r', 'e', 'x')
#define BOX_TYPE_MFHD  MAKE_TYPE_VAL('m', 'f', 'h', 'd')
#define BOX_TYPE_TRAF  MAKE_TYPE_VAL('t', 'r', 'a', 'f')
#define BOX_TYPE_TFHD  MAKE_TYPE_VAL('t', 'f', 'h', 'd')
#define BOX_TYPE_TRUN  MAKE_TYPE_VAL('t', 'r', 'u', 'n')
#define BOX_TYPE_MDAT  MAKE_TYPE_VAL('m', 'd', 'a', 't')
#define BOX_TYPE_UDTA  MAKE_TYPE_VAL('u', 'd', 't', 'a')
/* the box name is url + <space>, all names must be 4 characters long */
#define BOX_TYPE_URL_  MAKE_TYPE_VAL('u', 'r', 'l', ' ')
#define BOX_TYPE_EDTS  MAKE_TYPE_VAL('e', 'd', 't', 's')
#define BOX_TYPE_ELST  MAKE_TYPE_VAL('e', 'l', 's', 't')
#define BOX_TYPE_SIDX  MAKE_TYPE_VAL('s', 'i', 'd', 'x')
#define BOX_TYPE_STYP  MAKE_TYPE_VAL('s', 't', 'y', 'p')

#define TKHD_FLAG_ENABLED              0x000001
#define TKHD_FLAG_IN_MOVIE             0x000002
#define TKHD_FLAG_IN_PREVIEW           0x000004
#define TKHD_FLAG_SIZE_IS_ASPECT_RATIO 0x000008

/* the location for this URL box is the same as in the upper-level movie box */
#define ENTRY_FLAG_MOVIE 0x000001

static const value_string box_types[] = {
    { BOX_TYPE_FTYP, "File Type Box" },
    { BOX_TYPE_MOOV, "Movie Box" },
    { BOX_TYPE_MVHD, "Movie Header Box" },
    { BOX_TYPE_TRAK, "Track Box" },
    { BOX_TYPE_TKHD, "Track Header Box" },
    { BOX_TYPE_MDIA, "Media Box" },
    { BOX_TYPE_MDHD, "Media Header Box" },
    { BOX_TYPE_HDLR, "Handler Reference Box" },
    { BOX_TYPE_MINF, "Media Information Box" },
    { BOX_TYPE_VMHD, "Video Media Header Box" },
    { BOX_TYPE_SMHD, "Sound Media Header Box" },
    { BOX_TYPE_DINF, "Data Information Box" },
    { BOX_TYPE_DREF, "Data Reference Box" },
    { BOX_TYPE_STBL, "Sample to Group Box" },
    { BOX_TYPE_STTS, "Decoding Time To Sample Box" },
    { BOX_TYPE_CTTS, "Composition Time To Sample Box" },
    { BOX_TYPE_STSD, "Sample Description Box" },
    { BOX_TYPE_STSZ, "Sample Size Box" },
    { BOX_TYPE_STZ2, "Compact Sample Size Box" },
    { BOX_TYPE_STSC, "Sample To Chunk Box" },
    { BOX_TYPE_STCO, "Chunk Offset Box" },
    { BOX_TYPE_STSS, "Sync Sample Table" },
    { BOX_TYPE_MVEX, "Movie Extends Box" },
    { BOX_TYPE_MOOF, "Movie Fragment Box" },
    { BOX_TYPE_MEHD, "Movie Extends Header Box" },
    { BOX_TYPE_TREX, "Track Extends Box" },
    { BOX_TYPE_MFHD, "Movie Fragment Header Box" },
    { BOX_TYPE_TRAF, "Track Fragment Box" },
    { BOX_TYPE_TFHD, "Track Fragment Header Box" },
    { BOX_TYPE_TRUN, "Track Fragment Run Box" },
    { BOX_TYPE_MDAT, "Media Data Box" },
    { BOX_TYPE_UDTA, "User Data Box" },
    { BOX_TYPE_URL_, "URL Box" },
    { BOX_TYPE_EDTS, "Edit Box" },
    { BOX_TYPE_ELST, "Edit List Box" },
    { BOX_TYPE_SIDX, "Segment Index Box"},
    { BOX_TYPE_STYP, "Segment Type Box" },
    { 0, NULL }
};

/* convert a decimal number x into a double 0.x (e.g. 123 becomes 0.123) */
static inline double
make_fract(unsigned x)
{
    if (x==0)
        return 0.0;

    return (double)(x / exp(log(10.0)*(1+floor(log((double)x)/log(10.0)))));
}

static inline char *
timescaled_val_to_str(wmem_allocator_t *pool, uint64_t val)
{
    nstime_t nstime;

    if (mvhd_timescale == 0) {
        return wmem_strdup(pool, "no timescale");
    }

    nstime.secs = val / mvhd_timescale;
    nstime.nsecs = (val % mvhd_timescale) * (1000000000UL / mvhd_timescale);
    return rel_time_to_str(pool, &nstime);
}

static int
dissect_mp4_full_box(tvbuff_t *tvb, int offset, proto_tree *tree,
        int * const *flags_fields, uint8_t *version, uint32_t *flags)
{
    if (version) {
        *version = tvb_get_uint8(tvb, offset);
    }
    proto_tree_add_item(tree, hf_mp4_full_box_ver,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (flags) {
        *flags = tvb_get_ntoh24(tvb, offset);
    }
    if (flags_fields) {
        proto_tree_add_bitmask(tree, tvb, offset, hf_mp4_full_box_flags,
                ett_mp4_full_box_flags, flags_fields, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(tree, hf_mp4_full_box_flags,
                tvb, offset, 3, ENC_BIG_ENDIAN);
    }

    return 1 + 3;
}

static int
dissect_mp4_mvhd_body(tvbuff_t *tvb, int offset, int len _U_,
        packet_info *pinfo, unsigned depth _U_, proto_tree *tree)
{
    int         offset_start;
    uint8_t     version;
    uint8_t     time_len;
    uint64_t    duration;
    double      rate, vol;
    uint16_t    fract_dec;
    uint32_t    next_tid;
    proto_item *next_tid_it;

    offset_start = offset;

    offset += dissect_mp4_full_box (tvb, offset, tree, NULL, &version, NULL);

    /*
     * MPEG-4 Part 14 (MP4) is based on QuickTime, so it uses the
     * classic Mac OS time format.
     */
    time_len = (version==0) ? 4 : 8;
    proto_tree_add_item(tree, hf_mp4_mvhd_creat_time,
            tvb, offset, time_len, ENC_TIME_MP4_FILE_SECS|ENC_BIG_ENDIAN);
    offset += time_len;
    proto_tree_add_item(tree, hf_mp4_mvhd_mod_time,
            tvb, offset, time_len, ENC_TIME_MP4_FILE_SECS|ENC_BIG_ENDIAN);
    offset += time_len;

    mvhd_timescale = tvb_get_ntohl (tvb, offset);
    proto_tree_add_uint_format(tree, hf_mp4_mvhd_timescale,
            tvb, offset, 4, mvhd_timescale, "Timescale: %d units in one second",
            mvhd_timescale);
    offset += 4;

    if (time_len==4) {
        duration = tvb_get_ntohl(tvb, offset);
    } else {
        duration = tvb_get_ntoh64(tvb , offset);
    }
    if (mvhd_timescale == 0) {
        proto_tree_add_uint64_format(tree, hf_mp4_mvhd_duration,
                tvb, offset, time_len, duration,
                "Duration: no timescale (%" PRIu64 ")",
                duration);
    } else {
        proto_tree_add_uint64_format(tree, hf_mp4_mvhd_duration,
                tvb, offset, time_len, duration,
                "Duration: %f seconds (%" PRIu64 ")",
                (double) duration / mvhd_timescale, duration);
    }
    offset += time_len;

    rate = tvb_get_ntohs(tvb, offset);
    fract_dec = tvb_get_ntohs(tvb, offset+2);
    rate += make_fract(fract_dec);
    proto_tree_add_double(tree, hf_mp4_mvhd_rate, tvb, offset, 4, rate);
    offset += 4;

    vol = tvb_get_uint8(tvb, offset);
    fract_dec = tvb_get_uint8(tvb, offset+1);
    vol += make_fract(fract_dec);
    proto_tree_add_double(tree, hf_mp4_mvhd_vol, tvb, offset, 4, vol);
    offset += 2;

    offset += 2;   /* 16 bits reserved */
    offset += 2*4; /* 2 * uint32 reserved */

    offset += 9*4; /* XXX - unity matrix */
    offset += 6*4; /* 6 * 32 bits predefined = 0 */

    next_tid = tvb_get_ntohl(tvb, offset);
    next_tid_it = proto_tree_add_item(tree, hf_mp4_mvhd_next_tid,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    if (next_tid == UINT32_MAX)
        expert_add_info(pinfo, next_tid_it, &ei_mp4_mvhd_next_tid_unknown);
    offset += 4;

    return offset-offset_start;
}

static int
dissect_mp4_mfhd_body(tvbuff_t *tvb, int offset, int len _U_,
        packet_info *pinfo _U_, unsigned depth _U_, proto_tree *tree)
{
    int offset_start;

    offset_start = offset;

    offset += dissect_mp4_full_box (tvb, offset, tree, NULL, NULL, NULL);

    proto_tree_add_item(tree, hf_mp4_mfhd_seq_num,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset-offset_start;
}


static int
dissect_mp4_tkhd_body(tvbuff_t *tvb, int offset, int len _U_,
        packet_info *pinfo _U_, unsigned depth _U_, proto_tree *tree)
{
    int      offset_start;
    uint8_t  version;
    uint8_t  time_len;
    double   width, height;
    uint16_t fract_dec;
    static int * const flags[] = {
        &hf_mp4_tkhd_flags_enabled,
        &hf_mp4_tkhd_flags_in_movie,
        &hf_mp4_tkhd_flags_in_preview,
        &hf_mp4_tkhd_flags_size_is_aspect_ratio,
        NULL
    };

    offset_start = offset;

    offset += dissect_mp4_full_box (tvb, offset, tree, flags, &version, NULL);

    time_len = (version==0) ? 4 : 8;
    proto_tree_add_item(tree, hf_mp4_tkhd_creat_time,
            tvb, offset, time_len, ENC_TIME_MP4_FILE_SECS|ENC_BIG_ENDIAN);
    offset += time_len;
    proto_tree_add_item(tree, hf_mp4_tkhd_mod_time,
            tvb, offset, time_len, ENC_TIME_MP4_FILE_SECS|ENC_BIG_ENDIAN);
    offset += time_len;

    proto_tree_add_item(tree, hf_mp4_tkhd_track_id,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    offset += 4;   /* 32bit reserved */

    proto_tree_add_item(tree, hf_mp4_tkhd_duration,
            tvb, offset, time_len, ENC_BIG_ENDIAN);
    offset += time_len;

    offset += 2*4; /* 2*32bit reserved */
    offset += 2;   /* 16bit layer */
    offset += 2;   /* 16bit alternate_group */
    offset += 2;   /* 16bit volume */
    offset += 2;   /* 16bit reserved */
    offset += 9*4; /* 9*32bit matrix */

    width = tvb_get_ntohs(tvb, offset);
    fract_dec = tvb_get_ntohs(tvb, offset+2);
    width += make_fract(fract_dec);
    proto_tree_add_double(tree, hf_mp4_tkhd_width, tvb, offset, 4, width);
    offset += 4;

    height = tvb_get_ntohs(tvb, offset);
    fract_dec = tvb_get_ntohs(tvb, offset+2);
    height += make_fract(fract_dec);
    proto_tree_add_double(tree, hf_mp4_tkhd_height, tvb, offset, 4, height);
    offset += 4;

    return offset-offset_start;
}


static int
dissect_mp4_ftyp_body(tvbuff_t *tvb, int offset, int len,
        packet_info *pinfo _U_, unsigned depth _U_, proto_tree *tree)
{
    int offset_start;

    offset_start = offset;
    proto_tree_add_item(tree, hf_mp4_ftyp_brand,
            tvb, offset, 4, ENC_ASCII);
    offset += 4;
    proto_tree_add_item(tree, hf_mp4_ftyp_ver,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    while ((offset-offset_start) < len) {
        proto_tree_add_item(tree, hf_mp4_ftyp_add_brand,
                tvb, offset, 4, ENC_ASCII);
        offset += 4;
    }

    return offset - offset_start;
}


static int
dissect_mp4_stsz_body(tvbuff_t *tvb, int offset, int len _U_,
        packet_info *pinfo _U_, unsigned depth _U_, proto_tree *tree)
{
    int offset_start;
    uint32_t sample_size, sample_count, i;

    offset_start = offset;

    offset += dissect_mp4_full_box (tvb, offset, tree, NULL, NULL, NULL);

    sample_size = tvb_get_ntohl(tvb, offset);

    proto_tree_add_uint_format(tree, hf_mp4_stsz_sample_size,
            tvb, offset, 4, sample_size, "Sample size: %u%s", sample_size,
            sample_size == 0 ? " (samples have different sizes)" : "");
    /* XXX - expert info for sample size == 0 */
    offset += 4;

    sample_count = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_mp4_stsz_sample_count,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (sample_size != 0)
        return offset - offset_start;

    for (i=1; i<=sample_count; i++) {
        uint32_t entry_size;

        entry_size = tvb_get_ntohl(tvb, offset);
        proto_tree_add_uint_format(tree, hf_mp4_stsz_entry_size,
                tvb, offset, 4, entry_size, "Entry %u: Entry size: %u", i,
                entry_size);
        offset += 4;
    }

    return offset - offset_start;
}


static int
dissect_mp4_stsc_body(tvbuff_t *tvb, int offset, int len,
        packet_info *pinfo _U_, unsigned depth _U_, proto_tree *tree)
{
    uint32_t entry_count;
    uint32_t i;

    offset += dissect_mp4_full_box (tvb, offset, tree, NULL, NULL, NULL);

    proto_tree_add_item_ret_uint(tree, hf_mp4_stsc_entry_count, tvb, offset, 4,
            ENC_BIG_ENDIAN, &entry_count);
    offset += 4;

   for (i=1; i<=entry_count; i++) {
       proto_tree *subtree;
       proto_item *subtree_item;
       uint32_t first_chunk;
       uint32_t samples_per_chunk;
       uint32_t sample_description_index;

       subtree = proto_tree_add_subtree_format (tree, tvb, offset, 3 * 4,
               ett_mp4_entry, &subtree_item, "Entry %u:", i);

       proto_tree_add_item_ret_uint(subtree, hf_mp4_stsc_first_chunk,
               tvb, offset, 4, ENC_BIG_ENDIAN, &first_chunk);
       offset += 4;

       proto_tree_add_item_ret_uint(subtree, hf_mp4_stsc_samples_per_chunk,
               tvb, offset, 4, ENC_BIG_ENDIAN, &samples_per_chunk);
       offset += 4;

       proto_tree_add_item_ret_uint(subtree, hf_mp4_stsc_sample_description_index,
               tvb, offset, 4, ENC_BIG_ENDIAN, &sample_description_index);
       offset += 4;

       proto_item_append_text (subtree_item,
               " First chunk: %u; Samples per chunk: %u; Sample description index: %u",
               first_chunk, samples_per_chunk, sample_description_index);
    }

    return len;
}


static int
dissect_mp4_hdlr_body(tvbuff_t *tvb, int offset, int len _U_,
        packet_info *pinfo _U_, unsigned depth _U_, proto_tree *tree)
{
    int    offset_start;
    unsigned  hdlr_name_len;

    offset_start = offset;

    offset += dissect_mp4_full_box (tvb, offset, tree, NULL, NULL, NULL);
    /* XXX - put up an expert info if version!=0 */

    offset += 4;   /* four reserved 0 bytes */

    proto_tree_add_item(tree, hf_mp4_hdlr_type,
            tvb, offset, 4, ENC_ASCII);
    offset += 4;

    offset += 12;   /* 3x32bit reserved */

    /* name is a 0-terminated UTF-8 string, len includes the final 0 */
    hdlr_name_len = tvb_strsize(tvb, offset);
    proto_tree_add_item(tree, hf_mp4_hdlr_name,
            tvb, offset, hdlr_name_len, ENC_UTF_8);
    offset += hdlr_name_len;

    return offset-offset_start;
}


static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_mp4_dref_body(tvbuff_t *tvb, int offset, int len _U_,
        packet_info *pinfo, unsigned depth, proto_tree *tree)
{
    int      offset_start;
    uint32_t entry_cnt, i;
    int      ret;

    offset_start = offset;

    offset += dissect_mp4_full_box (tvb, offset, tree, NULL, NULL, NULL);
    /* XXX - put up an expert info if version!=0 */

    entry_cnt = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_mp4_dref_entry_cnt,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    for(i=0; i<entry_cnt; i++) {
        ret = dissect_mp4_box(BOX_TYPE_DREF, depth, tvb, offset, pinfo, tree);
        if (ret<=0)
            break;

        offset += ret;
    }

    return offset-offset_start;
}


static int
dissect_mp4_url_body(tvbuff_t *tvb, int offset, int len,
        packet_info *pinfo _U_, unsigned depth _U_, proto_tree *tree)
{
    uint32_t flags;
    static int * const flags_fields[] = {
        &hf_mp4_url_flags_media_data_location,
        NULL
    };

    dissect_mp4_full_box (tvb, offset, tree, flags_fields, NULL,
            &flags);
    /* XXX - put up an expert info if version!=0 */

#if 0
    if (flags&ENTRY_FLAG_MOVIE) {
    }
    else {
        /* XXX - dissect location string */
    }
#endif

    return len;
}


static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_mp4_stsd_body(tvbuff_t *tvb, int offset, int len,
        packet_info *pinfo, unsigned depth, proto_tree *tree)
{
    uint32_t entry_cnt, i;
    int      ret;

    offset += dissect_mp4_full_box (tvb, offset, tree, NULL, NULL, NULL);
    /* XXX - put up an expert info if version!=0 */

    entry_cnt = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_mp4_stsd_entry_cnt,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    for(i=0; i<entry_cnt; i++) {
        /* a sample entry has the same format as an mp4 box
           we call dissect_mp4_box() to dissect it
           alternatively, we could parse it ourselves, we'd then have to
           handle the extended lengths etc */

        /* XXX - dissect the content of each Sample Entry,
           this depends on the handler_type, we could add an optional
           void *data parameter to dissect_mp4_box() and handle sample
           entry boxes based on parent box and data parameter */
        ret = dissect_mp4_box(BOX_TYPE_STSD, depth, tvb, offset, pinfo, tree);
        if (ret<=0)
            break;

        offset += ret;
    }

    return len;
}

static int
dissect_mp4_stts_body(tvbuff_t *tvb, int offset, int len,
        packet_info *pinfo _U_, unsigned depth _U_, proto_tree *tree)
{
    uint32_t entry_cnt;
    unsigned i;

    offset += dissect_mp4_full_box (tvb, offset, tree, NULL, NULL, NULL);

    proto_tree_add_item_ret_uint(tree, hf_mp4_stts_entry_cnt,
            tvb, offset, 4, ENC_BIG_ENDIAN, &entry_cnt);
    offset += 4;

    for(i=0; i<entry_cnt; i++) {
        proto_tree *subtree;
        proto_item *subtree_item;
        uint32_t sample_count;
        uint32_t sample_delta;

        subtree = proto_tree_add_subtree_format (tree, tvb, offset, 2 * 4,
                ett_mp4_entry, &subtree_item, "Entry %u:", i + 1);

        proto_tree_add_item_ret_uint(subtree, hf_mp4_stts_sample_count,
                tvb, offset, 4, ENC_BIG_ENDIAN, &sample_count);
        offset += 4;

        proto_tree_add_item_ret_uint(subtree, hf_mp4_stts_sample_delta,
                tvb, offset, 4, ENC_BIG_ENDIAN, &sample_delta);
        offset += 4;

        proto_item_append_text (subtree_item,
                " Sample count: %u, Sample delta: %d",
                sample_count, sample_delta);
    }

    return len;
}


static int
dissect_mp4_stco_body(tvbuff_t *tvb, int offset, int len,
        packet_info *pinfo _U_, unsigned depth _U_, proto_tree *tree)
{
    uint32_t entry_cnt;
    uint32_t i;

    offset += dissect_mp4_full_box (tvb, offset, tree, NULL, NULL, NULL);

    proto_tree_add_item_ret_uint(tree, hf_mp4_stco_entry_cnt,
            tvb, offset, 4, ENC_BIG_ENDIAN, &entry_cnt);
    offset += 4;

    for(i=1; i<=entry_cnt; i++) {
        uint32_t chunk_offset;

        chunk_offset = tvb_get_ntohl(tvb, offset);
        proto_tree_add_uint_format(tree, hf_mp4_stco_chunk_offset,
                tvb, offset, 4, chunk_offset, "Entry %u: Chunk offset %u", i,
                chunk_offset);
        offset += 4;
    }

    return len;
}


static int
dissect_mp4_ctts_body(tvbuff_t *tvb, int offset, int len,
        packet_info *pinfo _U_, unsigned depth _U_, proto_tree *tree)
{
    uint8_t version;
    uint32_t entry_cnt;
    int sample_offset_hf;
    unsigned i;

    offset += dissect_mp4_full_box (tvb, offset, tree, NULL, &version, NULL);

    proto_tree_add_item_ret_uint(tree, hf_mp4_stts_entry_cnt,
            tvb, offset, 4, ENC_BIG_ENDIAN, &entry_cnt);
    offset += 4;

    sample_offset_hf = (version==1) ? hf_mp4_ctts_sample_offset_signed :
            hf_mp4_ctts_sample_offset_unsigned;

    for (i=0; i<entry_cnt; i++) {
        proto_tree *subtree;
        proto_item *subtree_item;
        uint32_t sample_count;
        uint32_t sample_delta;

        subtree = proto_tree_add_subtree_format(tree, tvb, offset, 2 * 4,
                ett_mp4_entry, &subtree_item, "Entry %u:", i + 1);

        proto_tree_add_item_ret_uint(subtree, hf_mp4_ctts_sample_count,
                tvb, offset, 4, ENC_BIG_ENDIAN, &sample_count);
        offset += 4;

        proto_tree_add_item_ret_uint(subtree, sample_offset_hf,
                tvb, offset, 4, ENC_BIG_ENDIAN, &sample_delta);
        offset += 4;

        proto_item_append_text(subtree_item,
                " Sample count: %u, Sample offset: %d",
                sample_count, sample_delta);
    }

    return len;
}

static int
dissect_mp4_elst_body(tvbuff_t *tvb, int offset, int len,
        packet_info *pinfo, unsigned depth _U_, proto_tree *tree)
{
    uint8_t version;
    uint32_t entry_cnt;
    unsigned i;

    offset += dissect_mp4_full_box (tvb, offset, tree, NULL, &version, NULL);

    proto_tree_add_item_ret_uint(tree, hf_mp4_elst_entry_cnt,
            tvb, offset, 4, ENC_BIG_ENDIAN, &entry_cnt);
    offset += 4;

    for(i=0; i<entry_cnt; i++) {
        proto_tree *subtree;
        proto_item *subtree_item;
        int field_length;
        uint64_t segment_duration;
        char *segment_duration_str;
        int64_t media_time;
        char *media_time_str;
        int32_t rate_int;
        int32_t rate_fraction;

        subtree = proto_tree_add_subtree_format (tree, tvb, offset, 2 * 4,
                ett_mp4_entry, &subtree_item, "Entry %u:", i + 1);

        field_length = (version==1) ? 8 : 4;

        if (version==1) {
            segment_duration = tvb_get_ntoh64(tvb, offset);
        } else {
            segment_duration = tvb_get_ntohl(tvb, offset);
        }
        segment_duration_str = timescaled_val_to_str(pinfo->pool, segment_duration);
        proto_tree_add_uint64_format(subtree, hf_mp4_elst_segment_duration,
                tvb, offset, field_length, segment_duration,
                "Segment duration: %s (%" PRIu64 ")",
                segment_duration_str, segment_duration);
        offset += field_length;

        if (version==1) {
            media_time = tvb_get_ntoh64(tvb, offset);
        } else {
            media_time = tvb_get_ntohl(tvb, offset);
        }
        media_time_str = timescaled_val_to_str(pinfo->pool, media_time);
        proto_tree_add_int64_format(subtree, hf_mp4_elst_media_time,
                tvb, offset, field_length, media_time,
                "Media time: %s (%" PRId64 ")",
                media_time_str, media_time);
        offset += field_length;

        proto_tree_add_item_ret_int(subtree, hf_mp4_elst_media_rate_integer,
                tvb, offset, 2, ENC_BIG_ENDIAN, &rate_int);
        offset += 2;

        proto_tree_add_item_ret_int(subtree, hf_mp4_elst_media_rate_fraction,
                tvb, offset, 2, ENC_BIG_ENDIAN, &rate_fraction);
        offset += 2;

        proto_item_append_text (subtree_item,
                " Segment duration: %s; Media time: %s; Media rate: %d.%d",
                segment_duration_str, media_time_str, rate_int, rate_fraction);
    }

    return len;
}

/* 3GPP TS 26.244 version 16.1.0 Release 16: 13.4 Segment Index Box */
static int
dissect_mp4_sidx_body(tvbuff_t *tvb, int offset, int len _U_,
        packet_info *pinfo _U_, unsigned depth _U_, proto_tree *tree)
{
    uint8_t  version;
    int      offset_start;
    uint16_t entry_cnt, i;

    offset_start = offset;

    offset += dissect_mp4_full_box (tvb, offset, tree, NULL, &version, NULL);

    proto_tree_add_item(tree, hf_mp4_sidx_reference_id,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_mp4_sidx_timescale,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (version == 0) {
        proto_tree_add_item(tree, hf_mp4_sidx_earliest_presentation_time_v0,
            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(tree, hf_mp4_sidx_first_offset_v0,
            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    } else {
        proto_tree_add_item(tree, hf_mp4_sidx_earliest_presentation_time,
            tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

        proto_tree_add_item(tree, hf_mp4_sidx_first_offset,
            tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    proto_tree_add_item(tree, hf_mp4_sidx_reserved,
            tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    entry_cnt = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_mp4_sidx_entry_cnt,
            tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    for(i=1; i<=entry_cnt; i++) {
        proto_tree *subtree;
        proto_item *subtree_item;

        subtree = proto_tree_add_subtree_format (tree, tvb, offset, 8,
               ett_mp4_entry, &subtree_item, "Entry %u:", i);

        proto_tree_add_item(subtree, hf_mp4_sidx_reference_type,
            tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_mp4_sidx_reference_size,
            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(subtree, hf_mp4_sidx_subsegment_duration,
            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(subtree, hf_mp4_sidx_starts_with_sap,
            tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_mp4_sidx_sap_type,
            tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_mp4_sidx_sap_delta_time,
            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    return offset-offset_start;
}

/* dissect a box, return its (standard or extended) length or 0 for error
   depth is the recursion level of the parent box */
static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_mp4_box(uint32_t parent_box_type _U_, unsigned depth,
        tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    int         offset_start;
    uint64_t    box_size;
    uint32_t    box_type;
    uint8_t    *box_type_str;
    proto_item *type_pi, *size_pi, *ext_size_pi = NULL;
    proto_tree *box_tree;
    int         ret;
    int         body_size;


    offset_start = offset;

    /* the following mechanisms are not supported for now
       - size==0, indicating that the box extends to the end of the file
       - extended box types */

    box_size = (uint64_t)tvb_get_ntohl(tvb, offset);
    if ((box_size != BOX_SIZE_EXTENDED) && (box_size < MIN_BOX_SIZE))
        return -1;

    box_type = tvb_get_ntohl(tvb, offset+4);
    box_type_str = tvb_get_string_enc(pinfo->pool, tvb,
            offset+4, 4, ENC_ASCII|ENC_NA);

    box_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_mp4_box, &type_pi, "%s (%s)",
            val_to_str_const(box_type, box_types, "unknown"), box_type_str);

    size_pi = proto_tree_add_item(box_tree, hf_mp4_box_size,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    if (box_size == BOX_SIZE_EXTENDED)
        proto_item_append_text(size_pi, " (actual size is in largesize)");

    offset += 4;
    proto_tree_add_item(box_tree, hf_mp4_box_type_str,
            tvb, offset, 4, ENC_ASCII);
    offset += 4;

    if (box_size == BOX_SIZE_EXTENDED) {
        box_size = tvb_get_ntoh64(tvb, offset);
        ext_size_pi = proto_tree_add_item(box_tree, hf_mp4_box_largesize,
                tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (box_size > INT_MAX) {
        /* this should be ok for ext_size_pi==NULL */
        expert_add_info(pinfo, ext_size_pi, &ei_mp4_box_too_large);
        return -1;
    }
    proto_item_set_len(type_pi, (int)box_size);
    body_size = (int)box_size - (offset-offset_start);

    depth++;
    if (depth > MP4_BOX_MAX_REC_LVL) {
        proto_tree_add_expert(tree, pinfo, &ei_mp4_too_many_rec_lvls,
                tvb, offset_start, (int)box_size);
        return -1;
    }

    /* we do not dissect full box version and flags here
       these two components are required by the function dissecting the body
       some fields of the body depend on the version and flags */

    /* XXX - check parent box if supplied */
    switch (box_type) {
        /* As per 3GPP TS 26.244 styp and ftyp boxes have the same format*/
        case BOX_TYPE_FTYP:
        case BOX_TYPE_STYP:
            dissect_mp4_ftyp_body(tvb, offset, body_size, pinfo, depth, box_tree);
            break;
        case BOX_TYPE_MVHD:
            dissect_mp4_mvhd_body(tvb, offset, body_size, pinfo, depth, box_tree);
            break;
        case BOX_TYPE_MFHD:
            dissect_mp4_mfhd_body(tvb, offset, body_size, pinfo, depth, box_tree);
            break;
        case BOX_TYPE_TKHD:
            dissect_mp4_tkhd_body(tvb, offset, body_size, pinfo, depth, box_tree);
            break;
        case BOX_TYPE_STSZ:
            dissect_mp4_stsz_body(tvb, offset, body_size, pinfo, depth, box_tree);
            break;
        case BOX_TYPE_STSC:
            dissect_mp4_stsc_body(tvb, offset, body_size, pinfo, depth, box_tree);
            break;
        case BOX_TYPE_HDLR:
            dissect_mp4_hdlr_body(tvb, offset, body_size, pinfo, depth, box_tree);
            break;
        case BOX_TYPE_DREF:
            dissect_mp4_dref_body(tvb, offset, body_size, pinfo, depth, box_tree);
            break;
        case BOX_TYPE_URL_:
            dissect_mp4_url_body(tvb, offset, body_size, pinfo, depth, box_tree);
            break;
        case BOX_TYPE_STSD:
            dissect_mp4_stsd_body(tvb, offset, body_size, pinfo, depth, box_tree);
            break;
        case BOX_TYPE_STTS:
            dissect_mp4_stts_body(tvb, offset, body_size, pinfo, depth, box_tree);
            break;
        case BOX_TYPE_STCO:
            dissect_mp4_stco_body(tvb, offset, body_size, pinfo, depth, box_tree);
            break;
        case BOX_TYPE_CTTS:
            dissect_mp4_ctts_body(tvb, offset, body_size, pinfo, depth, box_tree);
            break;
        case BOX_TYPE_ELST:
            dissect_mp4_elst_body(tvb, offset, body_size, pinfo, depth, box_tree);
            break;
        case BOX_TYPE_SIDX:
            dissect_mp4_sidx_body(tvb, offset, body_size, pinfo, depth, box_tree);
            break;
        case BOX_TYPE_MOOV:
        case BOX_TYPE_MOOF:
        case BOX_TYPE_STBL:
        case BOX_TYPE_MDIA:
        case BOX_TYPE_TRAK:
        case BOX_TYPE_TRAF:
        case BOX_TYPE_MINF:
        case BOX_TYPE_MVEX:
        case BOX_TYPE_DINF:
        case BOX_TYPE_UDTA:
        case BOX_TYPE_EDTS:
            while (offset-offset_start < (int)box_size) {
                ret = dissect_mp4_box(box_type, depth,
                        tvb, offset, pinfo, box_tree);
                if (ret <= 0)
                    break;
                offset += ret;
            }
            break;
        default:
            break;
    }

    return (int)box_size;
}


static int
dissect_mp4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int         offset = 0;
    uint32_t    box_type;
    proto_item *pi;
    proto_tree *mp4_tree;
    int         ret;

    /* to make sure that we have an mp4 file, we check that it starts with
        a box of a known type
       please note that we do not allow the first box to be an extended box
       this detection should be safe as long as the dissector is only called for
        the video/mp4 mime type
       when we read mp4 files directly, we might need stricter checks here */
    if (tvb_reported_length(tvb) < MIN_BOX_SIZE)
        return 0;
    box_type = tvb_get_ntohl(tvb, 4);
    if (try_val_to_str(box_type, box_types) == NULL)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MP4");
    col_clear(pinfo->cinfo, COL_INFO);

    pi = proto_tree_add_protocol_format(tree, proto_mp4,
            tvb, 0, (int)tvb_reported_length(tvb), "MP4");
    mp4_tree = proto_item_add_subtree(pi, ett_mp4);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        ret = dissect_mp4_box(BOX_TYPE_NONE, 0, tvb, offset, pinfo, mp4_tree);
        if (ret <= 0)
            break;
        offset += ret;
    }

    return offset;
}

void
proto_register_mp4(void)
{
    static hf_register_info hf[] = {
        { &hf_mp4_box_size,
            { "Box size", "mp4.box.size", FT_UINT32, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_mp4_box_type_str,
            { "Box type", "mp4.box.type_str", FT_STRING, BASE_NONE,
                NULL, 0, NULL, HFILL } },
        { &hf_mp4_box_largesize,
            { "Box size (largesize)", "mp4.box.largesize", FT_UINT64, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_mp4_full_box_ver,
            { "Box version", "mp4.full_box.version", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_mp4_full_box_flags,
            { "Flags", "mp4.full_box.flags", FT_UINT24, BASE_HEX,
                NULL, 0, NULL, HFILL } },
        { &hf_mp4_ftyp_brand,
            { "Brand", "mp4.ftyp.brand", FT_STRING, BASE_NONE,
                NULL, 0, NULL, HFILL } },
        { &hf_mp4_ftyp_ver,
            { "Version", "mp4.ftyp.version", FT_UINT32, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_mp4_ftyp_add_brand,
            { "Additional brand", "mp4.ftyp.additional_brand", FT_STRING,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_mp4_stsz_sample_size,
            { "Sample size", "mp4.stsz.sample_size", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_stsz_sample_count,
            { "Sample count", "mp4.stsz.sample_count", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_stsz_entry_size,
            { "Entry size", "mp4.stsz.entry_size", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_stsc_entry_count,
            { "Entry size", "mp4.stsc.entry_count", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_stsc_first_chunk,
            { "First chunk", "mp4.stsc.first_chunk", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_stsc_samples_per_chunk,
            { "Samples per chunk", "mp4.stsc.samples_per_chunk", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_stsc_sample_description_index,
            { "Sample description index", "mp4.stsc.sample_description_index", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_stco_entry_cnt,
            { "Entry count", "mp4.stco.entry_count", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_stco_chunk_offset,
            { "Entry count", "mp4.stco.chunk_offset", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_mvhd_creat_time,
            { "Creation time", "mp4.mvhd.creation_time", FT_ABSOLUTE_TIME,
                ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_mvhd_mod_time,
            { "Modification time", "mp4.mvhd.modification_time", FT_ABSOLUTE_TIME,
                ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_mvhd_timescale,
            { "Timescale", "mp4.mvhd.timescale", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_mvhd_duration,
            { "Duration", "mp4.mvhd.duration", FT_UINT64,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_mvhd_rate,
            { "Rate", "mp4.mvhd.rate", FT_DOUBLE,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_mp4_mvhd_vol,
            { "Volume", "mp4.mvhd.volume", FT_DOUBLE,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_mp4_mvhd_next_tid,
            { "Next Track ID", "mp4.mvhd.next_track_id", FT_UINT32,
                BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_mp4_mfhd_seq_num,
            { "Sequence number", "mp4.mfhd.sequence_number", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_tkhd_flags_enabled,
            { "Enabled", "mp4.tkhd.flags.enabled", FT_BOOLEAN,
                24, NULL, TKHD_FLAG_ENABLED, NULL, HFILL } },
        { &hf_mp4_tkhd_flags_in_movie,
            { "In movie", "mp4.tkhd.flags.in_movie", FT_BOOLEAN,
                24, NULL, TKHD_FLAG_IN_MOVIE, NULL, HFILL } },
        { &hf_mp4_tkhd_flags_in_preview,
            { "In preview", "mp4.tkhd.flags.in_preview", FT_BOOLEAN,
                24, NULL, TKHD_FLAG_IN_PREVIEW, NULL, HFILL } },
        { &hf_mp4_tkhd_flags_size_is_aspect_ratio,
            { "Size is aspect ratio", "mp4.tkhd.flags.size_is_aspect_ratio", FT_BOOLEAN,
                24, NULL, TKHD_FLAG_SIZE_IS_ASPECT_RATIO, NULL, HFILL } },
        { &hf_mp4_tkhd_creat_time,
            { "Creation time", "mp4.tkhd.creation_time", FT_ABSOLUTE_TIME,
                ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_tkhd_mod_time,
            { "Modification time", "mp4.tkhd.modification_time", FT_ABSOLUTE_TIME,
                ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_tkhd_track_id,
            { "Track ID", "mp4.tkhd.track_id", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_tkhd_duration,
            { "Duration", "mp4.tkhd.duration", FT_UINT64,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_tkhd_width,
            { "Width", "mp4.tkhd.width", FT_DOUBLE,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_mp4_tkhd_height,
            { "Height", "mp4.tkhd.height", FT_DOUBLE,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_mp4_hdlr_type,
            { "Handler type", "mp4.hdlr.type", FT_STRING,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_mp4_hdlr_name,
            { "Handler name", "mp4.hdlr.name", FT_STRINGZ,
                BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_mp4_dref_entry_cnt,
            { "Number of entries", "mp4.dref.entry_count", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_stsd_entry_cnt,
            { "Number of entries", "mp4.stsd.entry_count", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_url_flags_media_data_location,
            { "Media data location is defined in the movie box", "mp4.url.flags.media_data_location", FT_BOOLEAN,
                24, NULL, ENTRY_FLAG_MOVIE, NULL, HFILL } },
        { &hf_mp4_stts_entry_cnt,
            { "Number of entries", "mp4.stts.entry_count", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_stts_sample_count,
            { "Sample count", "mp4.stts.sample_count", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_stts_sample_delta,
            { "Sample delta", "mp4.stts.sample_delta", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_ctts_sample_count,
            { "Sample count", "mp4.ctts.sample_count", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_ctts_sample_offset_signed,
            { "Sample count", "mp4.ctts.sample_offset", FT_INT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_ctts_sample_offset_unsigned,
            { "Sample count", "mp4.ctts.sample_offset", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_elst_entry_cnt,
            { "Number of entries", "mp4.elst.entry_count", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_elst_segment_duration,
            { "Segment duration", "mp4.elst.segment_duration", FT_UINT64,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_elst_media_time,
            { "Media time", "mp4.elst.media_time", FT_INT64,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_elst_media_rate_integer,
            { "Media rate integer", "mp4.elst.media_rate_integer", FT_INT16,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_elst_media_rate_fraction,
            { "Media rate fraction", "mp4.elst.media_rate_fraction", FT_INT16,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_sidx_reference_id,
            { "Reference ID", "mp4.sidx.reference_id", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_sidx_timescale,
            { "Timescale", "mp4.sidx.timescale", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_sidx_earliest_presentation_time_v0,
            { "Earliest Presentation Time", "mp4.sidx.earliest_presentation_time", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_sidx_first_offset_v0,
            { "First Offset", "mp4.sidx.first_offset", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_sidx_earliest_presentation_time,
            { "Earliest Presentation Time", "mp4.sidx.earliest_presentation_time", FT_UINT64,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_sidx_first_offset,
            { "First Offset", "mp4.sidx.first_offset", FT_UINT64,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_sidx_reserved,
            { "Reserved", "mp4.sidx.reserved", FT_UINT16,
                BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_mp4_sidx_entry_cnt,
            { "Number of entries", "mp4.sidx.entry_count", FT_UINT16,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_sidx_reference_type,
            { "Reference Type", "mp4.sidx.reference_type", FT_UINT32,
                BASE_DEC, VALS(mp4_sidx_reference_type_vals), 0x80000000, NULL, HFILL } },
        { &hf_mp4_sidx_reference_size,
            { "Reference size", "mp4.sidx.reference_size", FT_UINT32,
                BASE_DEC, NULL, 0x7FFFFFFF, NULL, HFILL } },
        { &hf_mp4_sidx_subsegment_duration,
            { "Segment duration", "mp4.sidx.subsegment_duration", FT_UINT32,
                BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_mp4_sidx_starts_with_sap,
            { "Starts With SAP", "mp4.sidx.starts_with_sap", FT_BOOLEAN,
                32, NULL, 0x80000000, NULL, HFILL } },
        { &hf_mp4_sidx_sap_type,
            { "SAP Type", "mp4.sidx.sap_type", FT_UINT32,
                BASE_DEC, NULL, 0x70000000, NULL, HFILL } },
        { &hf_mp4_sidx_sap_delta_time,
            { "SAP Delta Time", "mp4.sidx.sap_delta_time", FT_UINT32,
                BASE_DEC, NULL, 0x0FFFFFFF, NULL, HFILL } },
    };

    static int *ett[] = {
        &ett_mp4,
        &ett_mp4_box,
        &ett_mp4_full_box_flags,
        &ett_mp4_entry,
    };

    static ei_register_info ei[] = {
        { &ei_mp4_box_too_large,
            { "mp4.box_too_large", PI_PROTOCOL, PI_WARN,
                "box size too large, dissection of this box is not supported", EXPFILL }},
        { &ei_mp4_too_many_rec_lvls,
            { "mp4.too_many_levels", PI_UNDECODED, PI_WARN,
                "too many recursion levels", EXPFILL }},
        { &ei_mp4_mvhd_next_tid_unknown,
            { "mp4.mvhd.next_tid_unknown", PI_PROTOCOL, PI_CHAT,
                "Next track ID is unknown. Search for an unused track ID if you want to insert a new track.", EXPFILL }}
    };

    expert_module_t *expert_mp4;

    proto_mp4 = proto_register_protocol("MP4 / ISOBMFF file format", "mp4", "mp4");

    proto_register_field_array(proto_mp4, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_mp4 = expert_register_protocol(proto_mp4);
    expert_register_field_array(expert_mp4, ei, array_length(ei));

    mp4_handle = register_dissector("mp4", dissect_mp4, proto_mp4);
}

void
proto_reg_handoff_mp4(void)
{
    dissector_add_string("media_type", "video/mp4", mp4_handle);
    dissector_add_string("media_type", "audio/mp4", mp4_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_MP4, mp4_handle);
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

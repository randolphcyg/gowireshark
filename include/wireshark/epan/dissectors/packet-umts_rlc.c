/* packet-umts_rlc.c
 * Routines for UMTS RLC (Radio Link Control) v9.3.0 disassembly
 * http://www.3gpp.org/ftp/Specs/archive/25_series/25.322/
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/conversation.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/show_exception.h>

#include <wiretap/wtap.h>

/*
 * Optional include, for KASUMI support,
 * see header file for more information.
 * */

#include "packet-umts_fp.h"
#include "packet-umts_rlc.h"
#include "packet-rrc.h"

/* TODO:
 * - distinguish between startpoints and endpoints?
 * - use sub_num in fragment identification?
 */

void proto_register_rlc(void);
void proto_reg_handoff_rlc(void);

int proto_umts_rlc;

extern int proto_fp;

/* Preference to perform reassembly */
static bool global_rlc_perform_reassemby = true;

/* Preference to expect RLC headers without payloads */
static bool global_rlc_headers_expected;

/* Preference to expect ONLY ciphered data */
static bool global_rlc_ciphered;

/* Preference to ignore ciphering state reported from RRC */
/* This is important for captures with deciphered traffic AND the original security RRC messages present*/
static bool global_ignore_rrc_ciphering_indication;

/* Preference to try deciphering */
static bool global_rlc_try_decipher;

#ifdef HAVE_UMTS_KASUMI
static const char *global_rlc_kasumi_key;
#endif

/* LI size preference */
#define RLC_LI_UPPERLAYER 255 /* LI-size comes from rlc_info struct rather than preference */
static int global_rlc_li_size = RLC_LI_UPPERLAYER;

static const enum_val_t li_size_enumvals[] = {
    {"7 bits", "7 bits", RLC_LI_7BITS},
    {"15 bits", "15 bits", RLC_LI_15BITS},
    {"Let upper layers decide", "Let upper layers decide", RLC_LI_UPPERLAYER},
    {NULL, NULL, -1}};

/* fields */
static int hf_rlc_seq;
static int hf_rlc_ext;
static int hf_rlc_pad;
static int hf_rlc_reassembled_data;
static int hf_rlc_frags;
static int hf_rlc_frag;
static int hf_rlc_duplicate_of;
static int hf_rlc_reassembled_in;
static int hf_rlc_he;
static int hf_rlc_dc;
static int hf_rlc_p;
static int hf_rlc_li;
static int hf_rlc_li_value;
static int hf_rlc_li_ext;
static int hf_rlc_li_data;
static int hf_rlc_data;
static int hf_rlc_ciphered_data;
static int hf_rlc_ciphered_lis_data;
static int hf_rlc_ctrl_type;
static int hf_rlc_r1;
static int hf_rlc_rsn;
static int hf_rlc_hfni;
static int hf_rlc_sufi;
static int hf_rlc_sufi_type;
static int hf_rlc_sufi_lsn;
static int hf_rlc_sufi_wsn;
static int hf_rlc_sufi_sn;
static int hf_rlc_sufi_l;
static int hf_rlc_sufi_fsn;
static int hf_rlc_sufi_len;
static int hf_rlc_sufi_bitmap;
static int hf_rlc_sufi_cw;
static int hf_rlc_sufi_n;
static int hf_rlc_sufi_sn_ack;
static int hf_rlc_sufi_sn_mrw;
static int hf_rlc_sufi_poll_sn;
static int hf_rlc_header_only;
static int hf_rlc_channel;
static int hf_rlc_channel_rbid;
static int hf_rlc_channel_dir;
static int hf_rlc_channel_ueid;
static int hf_rlc_sequence_number;
static int hf_rlc_length;
static int hf_rlc_bitmap_string;

/* subtrees */
static int ett_rlc;
static int ett_rlc_frag;
static int ett_rlc_fragments;
static int ett_rlc_sdu;
static int ett_rlc_sufi;
static int ett_rlc_bitmap;
static int ett_rlc_rlist;
static int ett_rlc_channel;

static expert_field ei_rlc_li_reserved;
static expert_field ei_rlc_he;
static expert_field ei_rlc_li_incorrect_mal;
static expert_field ei_rlc_sufi_cw;
static expert_field ei_rlc_kasumi_implementation_missing;
static expert_field ei_rlc_reassembly_unknown_error;
static expert_field ei_rlc_reassembly_lingering_endpoint;
static expert_field ei_rlc_sufi_len;
static expert_field ei_rlc_reassembly_fail_unfinished_sequence;
static expert_field ei_rlc_reassembly_fail_flag_set;
static expert_field ei_rlc_sufi_type;
static expert_field ei_rlc_reserved_bits_not_zero;
static expert_field ei_rlc_ctrl_type;
static expert_field ei_rlc_li_incorrect_warn;
static expert_field ei_rlc_li_too_many;
static expert_field ei_rlc_header_only;
static expert_field ei_rlc_ciphered_data;
static expert_field ei_rlc_no_per_frame_data;
static expert_field ei_rlc_incomplete_sequence;
static expert_field ei_rlc_unknown_udp_framing_tag;
static expert_field ei_rlc_missing_udp_framing_tag;

static dissector_handle_t ip_handle;
static dissector_handle_t rrc_handle;
static dissector_handle_t bmc_handle;

enum rlc_channel_type {
    RLC_PCCH,
    RLC_BCCH,
    RLC_UL_CCCH,
    RLC_DL_CCCH,
    RLC_UL_DCCH,
    RLC_DL_DCCH,
    RLC_PS_DTCH,
    RLC_DL_CTCH,
    RLC_UNKNOWN_CH
};

static const value_string rlc_dir_vals[] = {
    { P2P_DIR_UL, "Uplink" },
    { P2P_DIR_DL, "Downlink" },
    { 0, NULL }
};

static const true_false_string rlc_header_only_val = {
    "RLC PDU header only", "RLC PDU header and body present"
};

static const true_false_string rlc_ext_val = {
    "Next field is Length Indicator and E Bit", "Next field is data, piggybacked STATUS PDU or padding"
};

static const true_false_string rlc_dc_val = {
    "Data", "Control"
};

static const true_false_string rlc_p_val = {
    "Request a status report", "Status report not requested"
};

static const value_string rlc_he_vals[] = {
    { 0, "The succeeding octet contains data" },
    { 1, "The succeeding octet contains a length indicator and E bit" },
    { 2, "The succeeding octet contains data and the last octet of the PDU is the last octet of an SDU" },
    { 0, NULL }
};

#define RLC_STATUS      0x0
#define RLC_RESET       0x1
#define RLC_RESET_ACK   0x2
static const value_string rlc_ctrl_vals[] = {
    { RLC_STATUS,       "Status" },
    { RLC_RESET,        "Reset" },
    { RLC_RESET_ACK,    "Reset Ack" },
    { 0, NULL }
};

#define RLC_SUFI_NOMORE     0x0
#define RLC_SUFI_WINDOW     0x1
#define RLC_SUFI_ACK        0x2
#define RLC_SUFI_LIST       0x3
#define RLC_SUFI_BITMAP     0x4
#define RLC_SUFI_RLIST      0x5
#define RLC_SUFI_MRW        0x6
#define RLC_SUFI_MRW_ACK    0x7
#define RLC_SUFI_POLL       0x8
static const value_string rlc_sufi_vals[] = {
    { RLC_SUFI_NOMORE,  "No more data" },
    { RLC_SUFI_WINDOW,  "Window size" },
    { RLC_SUFI_ACK,     "Acknowledgement" },
    { RLC_SUFI_LIST,    "List" },
    { RLC_SUFI_BITMAP,  "Bitmap" },
    { RLC_SUFI_RLIST,   "Relative list" },
    { RLC_SUFI_MRW,     "Move receiving window" },
    { RLC_SUFI_MRW_ACK, "Move receiving window acknowledgement" },
    { RLC_SUFI_POLL,    "Poll" },
    { 0, NULL }
};

/* reassembly related data */
static GHashTable *fragment_table; /* table of not yet assembled fragments */
static GHashTable *endpoints; /* List of SDU-endpoints */
static GHashTable *reassembled_table; /* maps fragment -> complete sdu */
static GHashTable *sequence_table; /* channel -> seq */
static GHashTable *duplicate_table; /* duplicates */

/* identify an RLC channel, using one of two options:
 *  - via Radio Bearer ID and unique UE ID
 *  - via Radio Bearer ID and (VPI/VCI/CID) + Link ID
 */
struct rlc_channel {
    uint32_t         ueid;
    uint16_t         vpi;
    uint16_t         vci;
    uint8_t          cid;
    uint16_t         link;  /* link number */
    uint8_t          rbid;  /* radio bearer ID */
    uint8_t          dir;   /* direction */
    enum rlc_li_size li_size;
    enum rlc_mode    mode;
};

/* used for duplicate detection */
struct rlc_seq {
    uint32_t frame_num;
    nstime_t arrival;
    uint16_t seq;
    uint16_t oc;        /* overflow counter, this is not used? */
};

struct rlc_seqlist {
    struct rlc_channel ch;
    GList *list;
    /* We will store one seqlist per channel so this is a good place to indicate
     *  whether or not this channel's reassembly has failed or not. */
    unsigned fail_packet; /* Equal to packet where fail flag was set or 0 otherwise. */
};

/* fragment representation */
struct rlc_frag {
    uint32_t            frame_num;
    struct rlc_channel  ch;
    uint16_t            seq;  /* RLC sequence number */
    uint16_t            li;   /* LI within current RLC frame */
    uint16_t            len;  /* length of fragment data */
    uint8_t            *data; /* store fragment data here */

    struct rlc_frag *next; /* next fragment */
};

struct rlc_sdu {
    tvbuff_t        *tvb;     /* contains reassembled tvb */
    uint16_t         len;     /* total length of reassembled SDU */
    uint16_t         fragcnt; /* number of fragments within this SDU */
    uint8_t         *data;    /* reassembled data buffer */

    struct rlc_frag *reassembled_in;
    struct rlc_frag *frags;   /* pointer to list of fragments */
    struct rlc_frag *last;    /* pointer to last fragment */
};

struct rlc_li {
    uint16_t    li;   /* original li */
    uint16_t    len;  /* length of this data fragment */
    uint8_t     ext;  /* extension bit value */
    proto_tree *tree; /* subtree for this LI */
};

/*** KASUMI related variables and structs ***/
typedef struct umts_kat_key{    /*Stores 128-bits KASUMI key*/
    uint64_t high;       /*64 MSB*/
    uint64_t low;    /*64 LSB*/
}kasumi_key;


/*Counter used as input for confidentiality algorithm*/
static uint32_t ps_counter[31][2] ;
static bool counter_init[31][2];
static uint32_t max_counter;
static GTree  * counter_map;    /*Saves the countervalues at first pass through, since they will be update*/

/* hashtable functions for fragment table
 * rlc_channel -> SDU
 */
static unsigned
rlc_channel_hash(const void *key)
{
    const struct rlc_channel *ch = (const struct rlc_channel *)key;

    if (ch->ueid)
        return ch->ueid | ch->rbid | ch->mode;

    return (ch->vci << 16) | (ch->link << 16) | ch->vpi | ch->vci;
}

static gboolean
rlc_channel_equal(const void *a, const void *b)
{
    const struct rlc_channel *x = (const struct rlc_channel *)a, *y = (const struct rlc_channel *)b;

    if (x->ueid || y->ueid)
        return x->ueid == y->ueid &&
            x->rbid == y->rbid &&
            x->mode == y->mode &&
            x->dir == y->dir ? true : false;

    return x->vpi == y->vpi &&
        x->vci == y->vci &&
        x->cid == y->cid &&
        x->rbid == y->rbid &&
        x->mode == y->mode &&
        x->dir == y->dir &&
        x->link == y->link ? true : false;
}

static int
rlc_channel_assign(struct rlc_channel *ch, enum rlc_mode mode, packet_info *pinfo, struct atm_phdr *atm)
{
    rlc_info        *rlcinf;
    fp_info         *fpinf;

    fpinf = (fp_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_fp, 0);
    rlcinf = (rlc_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_umts_rlc, 0);
    if (!fpinf || !rlcinf) return -1;

    if (rlcinf->ueid[fpinf->cur_tb]) {
        ch->ueid = rlcinf->ueid[fpinf->cur_tb];
        ch->vpi = ch->vci = ch->link = ch->cid = 0;
    } else {
        if (!atm) return -1;
        ch->ueid = 1;
        ch->vpi = atm->vpi;
        ch->vci = atm->vci;
        ch->cid = atm->aal2_cid;
        ch->link = pinfo->link_number;
    }
    ch->rbid = rlcinf->rbid[fpinf->cur_tb];
    ch->dir = pinfo->link_dir;
    ch->mode = mode;
    ch->li_size = rlcinf->li_size[fpinf->cur_tb];

    return 0;
}

static struct rlc_channel *
rlc_channel_create(enum rlc_mode mode, packet_info *pinfo, struct atm_phdr *atm)
{
    struct rlc_channel *ch;
    int rv;

    ch = g_new0(struct rlc_channel, 1);
    rv = rlc_channel_assign(ch, mode, pinfo, atm);

    if (rv != 0) {
        /* channel assignment failed */
        g_free(ch);
        ch = NULL;
        REPORT_DISSECTOR_BUG("Failed to assign channel");
    }
    return ch;
}

static void
rlc_channel_delete(void *data)
{
    g_free(data);
}

/* hashtable functions for reassembled table
 * fragment -> SDU
 */
static unsigned
rlc_frag_hash(const void *key)
{
    const struct rlc_frag *frag = (const struct rlc_frag *)key;
    return (frag->frame_num << 12) | frag->seq;
}

static gboolean
rlc_frag_equal(const void *a, const void *b)
{
    const struct rlc_frag *x = (const struct rlc_frag *)a;
    const struct rlc_frag *y = (const struct rlc_frag *)b;

    return rlc_channel_equal(&x->ch, &y->ch) &&
        x->seq == y->seq &&
        x->frame_num == y->frame_num &&
        x->li == y->li ? true : false;
}

static struct rlc_sdu *
rlc_sdu_create(void)
{
    struct rlc_sdu *sdu;

    sdu = wmem_new0(wmem_file_scope(), struct rlc_sdu);
    return sdu;
}

static void
rlc_frag_delete(void *data)
{
    struct rlc_frag *frag = (struct rlc_frag *)data;

    if (frag->data) {
        wmem_free(wmem_file_scope(), frag->data);
        frag->data = NULL;
    }
}

static void
rlc_sdu_frags_delete(void *data)
{
    struct rlc_sdu  *sdu = (struct rlc_sdu *)data;
    struct rlc_frag *frag;

    frag = sdu->frags;
    while (frag) {
        if (frag->data) {
            wmem_free(wmem_file_scope(), frag->data);
        }
        frag->data = NULL;
        frag = frag->next;
    }
}

static int
rlc_frag_assign(struct rlc_frag *frag, enum rlc_mode mode, packet_info *pinfo,
        uint16_t seq, uint16_t li, struct atm_phdr *atm)
{
    frag->frame_num = pinfo->num;
    frag->seq       = seq;
    frag->li        = li;
    frag->len       = 0;
    frag->data      = NULL;
    rlc_channel_assign(&frag->ch, mode, pinfo, atm);

    return 0;
}

static int
rlc_frag_assign_data(struct rlc_frag *frag, tvbuff_t *tvb,
             uint16_t offset, uint16_t length)
{
    frag->len  = length;
    frag->data = (uint8_t *)tvb_memdup(wmem_file_scope(), tvb, offset, length);
    return 0;
}

static struct rlc_frag *
rlc_frag_create(tvbuff_t *tvb, enum rlc_mode mode, packet_info *pinfo,
        uint16_t offset, uint16_t length, uint16_t seq, uint16_t li,
        struct atm_phdr *atm)
{
    struct rlc_frag *frag;

    frag = wmem_new0(wmem_file_scope(), struct rlc_frag);
    rlc_frag_assign(frag, mode, pinfo, seq, li, atm);
    rlc_frag_assign_data(frag, tvb, offset, length);

    return frag;
}

static int
rlc_cmp_seq(const void *a, const void *b)
{
    const struct rlc_seq *_a = (const struct rlc_seq *)a, *_b = (const struct rlc_seq *)b;

    return  _a->seq < _b->seq ? -1 :
            _a->seq > _b->seq ?  1 :
            0;
}

static int moduloCompare(uint16_t a, uint16_t b, uint16_t modulus)
{
    int ret;
    a = a % modulus;
    b = b % modulus;

    if( a <= b ){
        ret = a - b;
    } else {
        ret = a - (b + modulus);
    }
    if( ret == (1 - modulus) ){
        ret = 1;
    }
    return ret;
}

static uint16_t getChannelSNModulus(struct rlc_channel * ch_lookup)
{
    if( RLC_UM == ch_lookup->mode){ /*FIXME: This is a very heuristic way to determine SN bitwidth. */
        return 128;
    } else {
        return 4096;
    }
}

/* "Value destroy" function called each time an entry is removed
 *  from the sequence_table hash.
 * It frees the GList pointed to by the entry.
 */
static void
free_sequence_table_entry_data(void *data)
{
    struct rlc_seqlist *list = (struct rlc_seqlist *)data;
    if (list->list != NULL) {
        g_list_free(list->list);
        list->list = NULL;   /* for good measure */
    }
}

/** Utility functions used for various comparisons/cleanups in tree **/
static int
rlc_simple_key_cmp(const void *b_ptr, const void *a_ptr, void *ignore _U_){
    if( GPOINTER_TO_INT(a_ptr) > GPOINTER_TO_INT(b_ptr) ){
        return  -1;
    }
    return GPOINTER_TO_INT(a_ptr) < GPOINTER_TO_INT(b_ptr);
}

static void
fragment_table_init(void)
{
    int i;
    fragment_table = g_hash_table_new_full(rlc_channel_hash, rlc_channel_equal, rlc_channel_delete, NULL);
    endpoints = g_hash_table_new_full(rlc_channel_hash, rlc_channel_equal, rlc_channel_delete, NULL);
    reassembled_table = g_hash_table_new_full(rlc_frag_hash, rlc_frag_equal,
        rlc_frag_delete, rlc_sdu_frags_delete);
    sequence_table = g_hash_table_new_full(rlc_channel_hash, rlc_channel_equal,
        NULL, free_sequence_table_entry_data);
    duplicate_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    /*Reset and or clear deciphering variables*/
    counter_map = g_tree_new_full(rlc_simple_key_cmp,NULL,NULL,rlc_channel_delete);
    for(i = 0; i< 31; i++ ){
        ps_counter[i][0] = 0;
        ps_counter[i][1] = 0;
        counter_init[i][0] = 0;
        counter_init[i][1] = 0;
    }
    max_counter = 0;
}

static void
fragment_table_cleanup(void)
{
    g_tree_destroy(counter_map);
    g_hash_table_destroy(fragment_table);
    g_hash_table_destroy(endpoints);
    g_hash_table_destroy(reassembled_table);
    g_hash_table_destroy(sequence_table);
    g_hash_table_destroy(duplicate_table);
}

/* add the list of fragments for this sdu to 'tree' */
static void
tree_add_fragment_list(struct rlc_sdu *sdu, tvbuff_t *tvb,packet_info *pinfo, proto_tree *tree)
{
    proto_item      *ti;
    proto_tree      *frag_tree;
    uint16_t         offset;
    struct rlc_frag *sdufrag;

    ti = proto_tree_add_item(tree, hf_rlc_frags, tvb, 0, -1, ENC_NA);
    proto_item_set_generated(ti);
    frag_tree = proto_item_add_subtree(ti, ett_rlc_fragments);
    proto_item_append_text(ti, " (%u bytes, %u fragments) ",
        sdu->len, sdu->fragcnt);
    sdufrag = sdu->frags;
    offset = 0;
    while (sdufrag) {
        if (sdufrag->len > 0) {
            proto_tree_add_uint_format(frag_tree, hf_rlc_frag, tvb, offset,
                sdufrag->len, sdufrag->frame_num, "Frame: %u, payload: %u-%u (%u bytes) (Seq: %u)",
                sdufrag->frame_num, offset, offset + sdufrag->len - 1, sdufrag->len, sdufrag->seq);
        } else {
            proto_tree_add_uint_format(frag_tree, hf_rlc_frag, tvb, offset,
                sdufrag->len, sdufrag->frame_num, "Frame: %u, payload: none (0 bytes) (Seq: %u)",
                sdufrag->frame_num, sdufrag->seq);
        }

        mark_frame_as_depended_upon(pinfo->fd, sdufrag->frame_num);

        offset += sdufrag->len;
        sdufrag = sdufrag->next;
    }
    ti = proto_tree_add_item(ti, hf_rlc_reassembled_data, tvb, 0, -1, ENC_NA);
    proto_item_set_generated(ti);
}

/* add the list of fragments for this sdu to 'tree' */
static void
tree_add_fragment_list_incomplete(struct rlc_sdu *sdu, tvbuff_t *tvb, proto_tree *tree)
{
    proto_item      *ti;
    proto_tree      *frag_tree;
    uint16_t         offset;
    struct rlc_frag *sdufrag;

    ti = proto_tree_add_item(tree, hf_rlc_frags, tvb, 0, 0, ENC_NA);
    proto_item_set_generated(ti);
    frag_tree = proto_item_add_subtree(ti, ett_rlc_fragments);
    proto_item_append_text(ti, " (%u bytes, %u fragments) ",
        sdu->len, sdu->fragcnt);
    sdufrag = sdu->frags;
    offset = 0;
    while (sdufrag) {
        proto_tree_add_uint_format(frag_tree, hf_rlc_frag, tvb, 0,
            0, sdufrag->frame_num, "Frame: %u, payload %u-%u (%u bytes) (Seq: %u)",
            sdufrag->frame_num, offset, offset + sdufrag->len - 1, sdufrag->len, sdufrag->seq);
        offset += sdufrag->len;
        sdufrag = sdufrag->next;
    }
}

/* Add the same description to too the two given proto_items */
static void
add_description(proto_item *li_ti, proto_item *length_ti,
                const char *format, ...)  G_GNUC_PRINTF(3, 4);
static void
add_description(proto_item *li_ti, proto_item *length_ti,
                const char *format, ...)
{
#define MAX_INFO_BUFFER 256
    static char info_buffer[MAX_INFO_BUFFER];

    va_list ap;

    va_start(ap, format);
    vsnprintf(info_buffer, MAX_INFO_BUFFER, format, ap);
    va_end(ap);

    proto_item_append_text(li_ti, " (%s)", info_buffer);
    proto_item_append_text(length_ti, " (%s)", info_buffer);
}

/* add information for an LI to 'tree' */
static proto_tree *
tree_add_li(enum rlc_mode mode, struct rlc_li *li, uint8_t li_idx, uint32_t hdr_offs,
        bool li_is_on_2_bytes, tvbuff_t *tvb, proto_tree *tree)
{
    proto_item *root_ti, *ti;
    proto_tree *li_tree;
    uint32_t    li_offs;
    uint64_t    length;

    if (!tree) return NULL;

    if (li_is_on_2_bytes) {
        li_offs = hdr_offs + li_idx*2;
        root_ti = proto_tree_add_item(tree, hf_rlc_li, tvb, li_offs, 2, ENC_NA);
        li_tree = proto_item_add_subtree(root_ti, ett_rlc_frag);
        ti = proto_tree_add_bits_ret_val(li_tree, hf_rlc_li_value, tvb, li_offs*8, 15, &length, ENC_BIG_ENDIAN);

        switch (li->li) {
            case 0x0000:
                add_description(root_ti, ti, "The previous RLC PDU was exactly filled with the last segment of an RLC SDU and there is no LI that indicates the end of the RLC SDU in the previous RLC PDU");
                break;
            case 0x7ffa:
                if (mode == RLC_UM) {
                    add_description(root_ti, ti, "The first data octet in this RLC PDU is the first octet of an RLC SDU and the second last octet in this RLC PDU is the last octet of the same RLC SDU. The remaining octet in the RLC PDU is ignored");
                } else {
                    add_description(root_ti, ti, "Reserved");
                }
                break;
            case 0x7ffb:
                add_description(root_ti, ti, "The second last octet in the previous RLC PDU is the last octet of an RLC SDU and there is no LI to indicate the end of SDU. The remaining octet in the previous RLC PDU is ignored");
                break;
            case 0x7ffc:
                if (mode == RLC_UM) {
                    add_description(root_ti, ti, "The first data octet in this RLC PDU is the first octet of an RLC SDU");
                } else {
                    add_description(root_ti, ti, "Reserved");
                }
                break;
            case 0x7ffd:
                if (mode == RLC_UM) {
                    add_description(root_ti, ti, "The first data octet in this RLC PDU is the first octet of an RLC SDU and the last octet in this RLC PDU is the last octet of the same RLC SDU");
                } else {
                    add_description(root_ti, ti, "Reserved");
                }
                break;
            case 0x7ffe:
                if (mode == RLC_UM) {
                    add_description(root_ti, ti, "The RLC PDU contains a segment of an SDU but neither the first octet nor the last octet of this SDU");
                } else {
                    add_description(root_ti, ti, "The rest of the RLC PDU includes a piggybacked STATUS PDU");
                }
                break;
            case 0x7fff:
                add_description(root_ti, ti, "The rest of the RLC PDU is padding");
                break;

            default:
                add_description(root_ti, ti, "length=%u", (uint16_t)length);
                break;
        }
        proto_tree_add_bits_item(li_tree, hf_rlc_li_ext, tvb, li_offs*8+15, 1, ENC_BIG_ENDIAN);
    } else {
        li_offs = hdr_offs + li_idx;
        root_ti = proto_tree_add_item(tree, hf_rlc_li, tvb, li_offs, 1, ENC_NA);
        li_tree = proto_item_add_subtree(root_ti, ett_rlc_frag);
        ti = proto_tree_add_bits_ret_val(li_tree, hf_rlc_li_value, tvb, li_offs*8, 7, &length, ENC_BIG_ENDIAN);
        switch (li->li) {
            case 0x00:
                add_description(root_ti, ti, "The previous RLC PDU was exactly filled with the last segment of an RLC SDU and there is no LI that indicates the end of the RLC SDU in the previous RLC PDU");
                break;
            case 0x7c:
                if (mode == RLC_UM) {
                    add_description(root_ti, ti, "The first data octet in this RLC PDU is the first octet of an RLC SDU");
                } else {
                    add_description(root_ti, ti, "Reserved");
                }
                break;
            case 0x7d:
                if (mode == RLC_UM) {
                    add_description(root_ti, ti, "The first data octet in this RLC PDU is the first octet of an RLC SDU and the last octet in this RLC PDU is the last octet of the same RLC SDU");
                } else {
                    add_description(root_ti, ti, "Reserved");
                }
                break;
            case 0x7e:
                if (mode == RLC_UM) {
                    add_description(root_ti, ti, "The RLC PDU contains a segment of an SDU but neither the first octet nor the last octet of this SDU");
                } else {
                    add_description(root_ti, ti, "The rest of the RLC PDU includes a piggybacked STATUS PDU");
                }
                break;
            case 0x7f:
                add_description(root_ti, ti, "The rest of the RLC PDU is padding");
                break;

            default:
                add_description(root_ti, ti, "length=%u", (uint16_t)length);
                break;
        }
        proto_tree_add_bits_item(li_tree, hf_rlc_li_ext, tvb, li_offs*8+7, 1, ENC_BIG_ENDIAN);
    }

    if (li->len > 0) {
        if (li->li > tvb_reported_length_remaining(tvb, hdr_offs)) return li_tree;
        if (li->len > li->li) return li_tree;
        ti = proto_tree_add_item(li_tree, hf_rlc_li_data, tvb, hdr_offs + li->li - li->len, li->len, ENC_NA);
        proto_item_set_hidden(ti);
    }

    return li_tree;
}

/* add a fragment to an SDU */
static int
rlc_sdu_add_fragment(enum rlc_mode mode, struct rlc_sdu *sdu, struct rlc_frag *frag)
{
    struct rlc_frag *tmp;

    if (!sdu->frags) {
        /* insert as first element */
        sdu->frags = frag;
        sdu->last = frag;
        sdu->fragcnt++;
        sdu->len += frag->len;
        return 0;
    }
    switch (mode) {
        case RLC_UM:
            /* insert as last element */
            sdu->last->next = frag;
            frag->next = NULL;
            sdu->last = frag;
            sdu->len += frag->len;
            break;
        case RLC_AM:
            /* insert ordered */
            tmp = sdu->frags;

            /* If receiving exotic border line sequence, e.g. 4094, 4095, 0, 1 */
            if (frag->seq+2048 < tmp->seq) {
                while (tmp->next && frag->seq+2048 < tmp->seq)
                    tmp = tmp->next;
                if (tmp->next == NULL) {
                    tmp->next = frag;
                    sdu->last = frag;
                } else {
                    while (tmp->next && tmp->next->seq < frag->seq)
                        tmp = tmp->next;
                    frag->next = tmp->next;
                    tmp->next = frag;
                    if (frag->next == NULL) sdu->last = frag;
                }
            } else { /* Receiving ordinary sequence */
                if (frag->seq < tmp->seq) {
                    /* insert as first element */
                    frag->next = tmp;
                    sdu->frags = frag;
                } else {
                    while (tmp->next && tmp->next->seq < frag->seq)
                        tmp = tmp->next;
                    frag->next = tmp->next;
                    tmp->next = frag;
                    if (frag->next == NULL) sdu->last = frag;
                }
            }
            sdu->len += frag->len;
            break;
        default:
            return -2;
    }
    sdu->fragcnt++;
    return 0;
}

static void
reassemble_data(struct rlc_channel *ch, struct rlc_sdu *sdu, struct rlc_frag *frag)
{
    struct rlc_frag *temp;
    uint16_t         offs = 0;

    if (!sdu || !ch || !sdu->frags) return;

    if (sdu->data) return; /* already assembled */

    if (frag)
        sdu->reassembled_in = frag;
    else
        sdu->reassembled_in = sdu->last;

    sdu->data = (uint8_t *)wmem_alloc(wmem_file_scope(), sdu->len);
    temp = sdu->frags;
    while (temp && ((offs + temp->len) <= sdu->len)) {
        if (temp->data) {
            memcpy(sdu->data + offs, temp->data, temp->len);
            wmem_free(wmem_file_scope(), temp->data);
        }
        temp->data = NULL;
        /* mark this fragment in reassembled table */
        g_hash_table_insert(reassembled_table, temp, sdu);

        offs += temp->len;
        temp = temp->next;
    }
}

#define RLC_ADD_FRAGMENT_FAIL_PRINT 0
#define RLC_ADD_FRAGMENT_DEBUG_PRINT 0
#if RLC_ADD_FRAGMENT_DEBUG_PRINT
static void
printends(GList * list)
{
    if (list == NULL)
        return;
    g_print("-> length: %d\n[", g_list_length(list));
    while (list)
    {
        g_print("%d ", GPOINTER_TO_INT(list->data));
        list = list->next;
    }
    g_print("]\n");
}
#endif

static struct rlc_frag **
get_frags(packet_info * pinfo, struct rlc_channel * ch_lookup, struct atm_phdr *atm)
{
    void *value = NULL;
    struct rlc_frag ** frags = NULL;
    /* Look for already created frags table */
    if (g_hash_table_lookup_extended(fragment_table, ch_lookup, NULL, &value)) {
        frags = (struct rlc_frag **)value;
    } else if (pinfo != NULL) {
        struct rlc_channel *ch;
        ch = rlc_channel_create(ch_lookup->mode, pinfo, atm);
        frags = (struct rlc_frag **)wmem_alloc0(wmem_file_scope(), sizeof(struct rlc_frag *) * 4096);
        g_hash_table_insert(fragment_table, ch, frags);
    } else {
        return NULL;
    }
    return frags;
}
static struct rlc_seqlist *
get_endlist(packet_info * pinfo, struct rlc_channel * ch_lookup, struct atm_phdr *atm)
{
    void *value = NULL;
    struct rlc_seqlist * endlist = NULL;
    /* If there already exists a frag table for this channel use that one. */
    if (g_hash_table_lookup_extended(endpoints, ch_lookup, NULL, &value)) {
        endlist = (struct rlc_seqlist *)value;
    } else if (pinfo != NULL) { /* Else create a new one. */
        struct rlc_channel * ch;

        endlist = wmem_new(wmem_file_scope(), struct rlc_seqlist);
        ch = rlc_channel_create(ch_lookup->mode, pinfo, atm);
        endlist->fail_packet = 0;
        endlist->list = NULL;
        endlist->list = g_list_prepend(endlist->list, GINT_TO_POINTER(-1));
        g_hash_table_insert(endpoints, ch, endlist);
    } else {
        return NULL;
    }
    return endlist;
}

static void
reassemble_sequence(struct rlc_frag ** frags, struct rlc_seqlist * endlist,
                    struct rlc_channel * ch_lookup, uint16_t start, uint16_t end)
{
    GList * element = NULL;
    struct rlc_sdu * sdu = rlc_sdu_create();

    uint16_t snmod = getChannelSNModulus(ch_lookup);

    /* Insert fragments into SDU. */
    for (; moduloCompare(start,end,snmod ) <= 0; start = (start+1)%snmod)
    {
        struct rlc_frag * tempfrag = NULL;
        tempfrag = frags[start]->next;
        frags[start]->next = NULL;
        rlc_sdu_add_fragment(ch_lookup->mode, sdu, frags[start]);
        frags[start] = tempfrag;
    }

    /* Remove first endpoint. */
    element = g_list_first(endlist->list);
    if (element) {
        endlist->list = g_list_remove_link(endlist->list, element);
        if (frags[end] != NULL) {
            if (endlist->list) {
                endlist->list->data = GINT_TO_POINTER((GPOINTER_TO_INT(endlist->list->data) - 1 + snmod) % snmod);
            }
        }
    }
    reassemble_data(ch_lookup, sdu, NULL);
}

/* Reset the specified channel's reassembly data, useful for when a sequence
 * resets on transport channel swap. */
/* TODO: not currently called */
void
rlc_reset_channel(enum rlc_mode mode, uint8_t rbid, uint8_t dir, uint32_t ueid,
                  struct atm_phdr *atm)
{
    struct rlc_frag ** frags = NULL;
    struct rlc_seqlist * endlist = NULL;
    struct rlc_channel ch_lookup;
    unsigned i;

    ch_lookup.mode = mode;
    ch_lookup.rbid = rbid;
    ch_lookup.dir = dir;
    ch_lookup.ueid = ueid;
    frags = get_frags(NULL, &ch_lookup, atm);
    endlist = get_endlist(NULL, &ch_lookup, atm);
    if (endlist) {
        endlist->fail_packet = 0;
        g_list_free(endlist->list);
        endlist->list = NULL;
    }

    if (frags) {
        for (i = 0; i < 4096; i++) {
            frags[i] = NULL;
        }
    }
}

/* add a new fragment to an SDU
 * if length == 0, just finalize the specified SDU
 */
static struct rlc_frag *
add_fragment(enum rlc_mode mode, tvbuff_t *tvb, packet_info *pinfo,
         proto_tree *tree, uint16_t offset, uint16_t seq, uint16_t num_li,
         uint16_t len, bool final, struct atm_phdr *atm)
{
    struct rlc_channel  ch_lookup;
    struct rlc_frag     frag_lookup, *frag = NULL;
    gpointer            orig_key = NULL, value = NULL;
    struct rlc_sdu     *sdu = NULL;
    struct rlc_frag ** frags = NULL;
    struct rlc_seqlist * endlist = NULL;
    GList * element = NULL;
    int snmod;

    if (rlc_channel_assign(&ch_lookup, mode, pinfo, atm) == -1) {
        return NULL;
    }
    rlc_frag_assign(&frag_lookup, mode, pinfo, seq, num_li, atm);
    #if RLC_ADD_FRAGMENT_DEBUG_PRINT
        g_print("packet: %d, channel (%d %d %d) seq: %u, num_li: %u, offset: %u, \n", pinfo->num, ch_lookup.dir, ch_lookup.rbid, ch_lookup.ueid, seq, num_li, offset);
    #endif

    snmod = getChannelSNModulus(&ch_lookup);

    /* look for an already assembled SDU */
    if (g_hash_table_lookup_extended(reassembled_table, &frag_lookup, &orig_key, &value)) {
        /* this fragment is already reassembled somewhere */
        frag = (struct rlc_frag *)orig_key;
        sdu = (struct rlc_sdu *)value;
        if (tree) {
            /* mark the fragment, if reassembly happened somewhere else */
            if (frag->seq != sdu->reassembled_in->seq ||
                frag->li != sdu->reassembled_in->li)
                proto_tree_add_uint(tree, hf_rlc_reassembled_in, tvb, 0, 0,
                    sdu->reassembled_in->frame_num);
        }
        return frag;
    }

    frags = get_frags(pinfo, &ch_lookup, atm);
    endlist = get_endlist(pinfo, &ch_lookup, atm);

    /* If already done reassembly */
    if (PINFO_FD_VISITED(pinfo)) {
        if (tree && len > 0) {
            if (endlist->list && endlist->list->next) {
                int16_t start = (GPOINTER_TO_INT(endlist->list->data) + 1) % snmod;
                int16_t end = GPOINTER_TO_INT(endlist->list->next->data);
                int16_t missing = start;
                bool wecanreasmmore = true;

                for (; moduloCompare(missing,end,snmod ) <= 0; missing = (missing+1)%snmod)
                {
                    if (frags[missing] == NULL) {
                        wecanreasmmore = false;
                        break;
                    }
                }

                if (wecanreasmmore) {
                    reassemble_sequence(frags, endlist, &ch_lookup, start, end);
                } else {
                    if (end >= 0 && end < snmod && frags[end]) {
                        proto_tree_add_expert_format(tree, pinfo, &ei_rlc_reassembly_fail_unfinished_sequence, tvb, 0, 0,
                                        "Did not perform reassembly because of unfinished sequence (%d->%d [packet %u]), could not find %d.", start, end, frags[end]->frame_num, missing);
                    } else {
                        proto_tree_add_expert_format(tree, pinfo, &ei_rlc_reassembly_fail_unfinished_sequence, tvb, 0, 0,
                                        "Did not perform reassembly because of unfinished sequence (%d->%d [could not determine packet]), could not find %d.", start, end, missing);
                    }
                }
            } else if (endlist->list) {
                if (endlist->fail_packet != 0 && endlist->fail_packet <= pinfo->num) {
                    proto_tree_add_expert_format(tree, pinfo, &ei_rlc_reassembly_fail_flag_set, tvb, 0, 0, "Did not perform reassembly because fail flag was set in packet %u.", endlist->fail_packet);
                } else {
                    int16_t end = GPOINTER_TO_INT(endlist->list->data);
                    if (end >= 0 && end < snmod && frags[end]) {
                        proto_tree_add_expert_format(tree, pinfo, &ei_rlc_reassembly_lingering_endpoint, tvb, 0, 0, "Did not perform reassembly because of unfinished sequence, found lingering endpoint (%d [packet %d]).", end, frags[end]->frame_num);
                    } else {
                        proto_tree_add_expert_format(tree, pinfo, &ei_rlc_reassembly_lingering_endpoint, tvb, 0, 0, "Did not perform reassembly because of unfinished sequence, found lingering endpoint (%d [could not determine packet]).", end);
                    }
                }
            } else {
                expert_add_info(pinfo, NULL, &ei_rlc_reassembly_unknown_error);
            }
        }
        return NULL; /* If already done reassembly and no SDU found, too bad */
    }

    if (endlist->fail_packet != 0) { /* don't continue after sh*t has hit the fan */
        return NULL;
    }

    frag = rlc_frag_create(tvb, mode, pinfo, offset, len, seq, num_li, atm);

    /* If frags[seq] is not NULL then we must have data from several PDUs in the
     * same RLC packet (using Length Indicators) or something has gone terribly
     * wrong. */
    if (frags[seq] != NULL) {
        if (num_li > 0) {
            struct rlc_frag * tempfrag = frags[seq];
            while (tempfrag->next != NULL)
                tempfrag = tempfrag->next;
            tempfrag->next = frag;
        } else { /* This should never happen */
            endlist->fail_packet = pinfo->num;
            return NULL;
        }
    } else {
        frags[seq] = frag;
    }

    /* It is also possible that frags[seq] is NULL even though we do have data
     * from several PDUs in the same RLC packet. This is if the reassembly is
     * not lagging behind at all because of perfectly ordered sequences. */
    if (endlist->list && num_li != 0) {
        int16_t first = GPOINTER_TO_INT(endlist->list->data);
        if (seq == first) {
            endlist->list->data = GINT_TO_POINTER(first-1);
        }
    }

    /* If this is an endpoint */
    if (final) {
        endlist->list = g_list_append(endlist->list, GINT_TO_POINTER((int)seq));
    }

    #if RLC_ADD_FRAGMENT_DEBUG_PRINT
    printends(endlist->list);
    #endif

    /* Try to reassemble SDU. */
    if (endlist->list && endlist->list->next) {
        int16_t start = (GPOINTER_TO_INT(endlist->list->data) + 1) % snmod;
        int16_t end = GPOINTER_TO_INT(endlist->list->next->data);
        if (frags[end] == NULL) {
#if RLC_ADD_FRAGMENT_FAIL_PRINT
            proto_tree_add_debug_text(tree, "frag[end] is null, this is probably because end was a startpoint but because of some error ended up being treated as an endpoint, setting fail flag, start %d, end %d, packet %u\n", start, end, pinfo->num);
#endif
            endlist->fail_packet = pinfo->num;
            return NULL;
        }

        /* If our endpoint is a LI=0 with no data. */
        if (start == end && frags[start]->len == 0) {
            element = g_list_first(endlist->list);
            if (element) {
                endlist->list = g_list_remove_link(endlist->list, element);
            }
            frags[start] = frags[start]->next;

            /* If frags[start] is not NULL now, then that means that there was
             * another fragment with the same seq number because of LI. If we
             * don't decrease the endpoint by 1 then that fragment will be
             * skipped and all hell will break lose. */
            if (frags[start] != NULL) {
                endlist->list->data = GINT_TO_POINTER(start-1);
            }
            /* NOTE: frags[start] is wmem_alloc'ed and will remain until file closes, we would want to free it here maybe. */
            return NULL;
        }

        #if RLC_ADD_FRAGMENT_DEBUG_PRINT
        g_print("start: %d, end: %d\n",start, end);
        #endif

        for (;  moduloCompare(start,end,snmod ) < 0; start = (start+1)%snmod)
        {
            if (frags[start] == NULL) {
                if (MIN((start-seq+snmod)%snmod, (seq-start+snmod)%snmod) >= snmod/4) {
#if RLC_ADD_FRAGMENT_FAIL_PRINT
                    proto_tree_add_debug_text(tree,
"Packet %u. Setting fail flag because RLC fragment with sequence number %u was \
too far away from an unfinished sequence (%u->%u). The missing sequence number \
is %u. The most recently complete sequence ended in packet %u.", pinfo->num, seq, 0, end, start, 0);
#endif
                    endlist->fail_packet = pinfo->num; /* If it has gone too far, give up */
                    return NULL;
                }
                return frag;
            }
        }
        start = (GPOINTER_TO_INT(endlist->list->data) + 1) % snmod;
        reassemble_sequence(frags, endlist, &ch_lookup, start, end);
    } else if (endlist->list) {
        int16_t first = (GPOINTER_TO_INT(endlist->list->data) + 1) % snmod;
        /* If the distance between the oldest stored endpoint in endlist and
         * this endpoint is too large, set fail flag. */
        if (MIN((first-seq+snmod)%snmod, (seq-first+snmod)%snmod) >= snmod/4) {
#if RLC_ADD_FRAGMENT_FAIL_PRINT
            proto_tree_add_debug_text(tree,
"Packet %u. Setting fail flag because RLC fragment with sequence number %u was \
too far away from an unfinished sequence with start %u and without end.", pinfo->num, seq, first);
#endif
            endlist->fail_packet = pinfo->num; /* Give up if things have gone too far. */
            return NULL;
        }
    }

    return frag;
}

/* is_data is used to identify rlc data parts that are not identified by an LI, but are at the end of
 * the RLC frame
 * these can be valid reassembly points, but only if the LI of the *next* relevant RLC frame is
 * set to '0' (this is indicated in the reassembled SDU
 */
static tvbuff_t *
get_reassembled_data(enum rlc_mode mode, tvbuff_t *tvb, packet_info *pinfo,
             proto_tree *tree, uint16_t seq, uint16_t num_li,
             struct atm_phdr *atm)
{
    gpointer         orig_frag, orig_sdu;
    struct rlc_sdu  *sdu;
    struct rlc_frag  lookup, *frag;

    rlc_frag_assign(&lookup, mode, pinfo, seq, num_li, atm);

    if (!g_hash_table_lookup_extended(reassembled_table, &lookup,
        &orig_frag, &orig_sdu))
        return NULL;

    sdu = (struct rlc_sdu *)orig_sdu;
    if (!sdu || !sdu->data)
        return NULL;

    /* TODO */
#if 0
    if (!rlc_frag_equal(&lookup, sdu->reassembled_in)) return NULL;
#endif

    frag = sdu->frags;
    while (frag->next) {
        if (frag->next->seq - frag->seq > 1) {
            proto_tree_add_expert(tree, pinfo, &ei_rlc_incomplete_sequence, tvb, 0, 0);
            tree_add_fragment_list_incomplete(sdu, tvb, tree);
            return NULL;
        }
        frag = frag->next;
    }

    sdu->tvb = tvb_new_child_real_data(tvb, sdu->data, sdu->len, sdu->len);
    add_new_data_source(pinfo, sdu->tvb, "Reassembled RLC Message");

    /* reassembly happened here, so create the fragment list */
    if (tree && sdu->fragcnt > 1)
        tree_add_fragment_list(sdu, sdu->tvb, pinfo, tree);

    return sdu->tvb;
}

#define RLC_RETRANSMISSION_TIMEOUT 5 /* in seconds */
static bool
rlc_is_duplicate(enum rlc_mode mode, packet_info *pinfo, uint16_t seq,
         uint32_t *original, struct atm_phdr *atm)
{
    GList              *element;
    struct rlc_seqlist  lookup, *list;
    struct rlc_seq      seq_item, *seq_new;
    uint16_t snmod;
    nstime_t delta;
    bool is_duplicate,is_unseen;

    if (rlc_channel_assign(&lookup.ch, mode, pinfo, atm) == -1)
        return false;
    list = (struct rlc_seqlist *)g_hash_table_lookup(sequence_table, &lookup.ch);
    if (!list) {
        /* we see this channel for the first time */
        list = (struct rlc_seqlist *)wmem_alloc0(wmem_file_scope(), sizeof(*list));
        rlc_channel_assign(&list->ch, mode, pinfo, atm);
        g_hash_table_insert(sequence_table, &list->ch, list);
    }
    seq_item.seq = seq;
    seq_item.frame_num = pinfo->num;

    /* When seq is 12 bit (in RLC protocol), it will wrap around after 4096. */
    /* Window size is at most 4095 so we remove packets further away than that */
    element = g_list_first(list->list);
    snmod = getChannelSNModulus(&lookup.ch);
    if (element) {
        seq_new = (struct rlc_seq *)element->data;
        /* Add SN modulus because %-operation for negative values in C is not equal to mathematical modulus */
        if (MIN((seq_new->seq-seq+snmod)%snmod, (seq-seq_new->seq+snmod)%snmod) >= snmod/4) {
            list->list = g_list_remove_link(list->list, element);
        }
    }

    is_duplicate = false;
    is_unseen = true;
    element = g_list_find_custom(list->list, &seq_item, rlc_cmp_seq);
    while(element) {
        /* Check if this is a different frame (by comparing frame numbers) which arrived less than */
        /* RLC_RETRANSMISSION_TIMEOUT seconds ago */
        seq_new = (struct rlc_seq *)element->data;
        if (seq_new->frame_num < seq_item.frame_num) {
            nstime_delta(&delta, &pinfo->abs_ts, &seq_new->arrival);
            if (delta.secs < RLC_RETRANSMISSION_TIMEOUT) {
                /* This is a duplicate. */
                if (original) {
                    /* Save the frame number where our sequence number was previously seen */
                    *original = seq_new->frame_num;
                }
                is_duplicate = true;
            }
        }
        else if (seq_new->frame_num == seq_item.frame_num) {
            /* Check if our frame is already in the list and this is a secondary check.*/
            /* in this case raise a flag so the frame isn't entered more than once to the list */
            is_unseen = false;
        }
        element = g_list_find_custom(element->next, &seq_item, rlc_cmp_seq);
    }
    if(is_unseen) {
        /* Add to list for the first time this frame is checked */
        seq_new = wmem_new0(wmem_file_scope(), struct rlc_seq);
        *seq_new = seq_item;
        seq_new->arrival = pinfo->abs_ts;
        list->list = g_list_append(list->list, seq_new); /* insert in order of arrival */
    }
    return is_duplicate;
}

static void
rlc_call_subdissector(enum rlc_channel_type channel, tvbuff_t *tvb,
              packet_info *pinfo, proto_tree *tree)
{
    bool is_rrc_payload = true;
    volatile dissector_handle_t next_dissector = NULL;
    enum rrc_message_type msgtype;

    switch (channel) {
        case RLC_UL_CCCH:
            msgtype = RRC_MESSAGE_TYPE_UL_CCCH;
            break;
        case RLC_DL_CCCH:
            msgtype = RRC_MESSAGE_TYPE_DL_CCCH;
            break;
        case RLC_DL_CTCH:
            /* Payload of DL CTCH is BMC*/
            is_rrc_payload = false;
            msgtype = RRC_MESSAGE_TYPE_INVALID;
            next_dissector = bmc_handle;
            break;
        case RLC_UL_DCCH:
            msgtype = RRC_MESSAGE_TYPE_UL_DCCH;
            break;
        case RLC_DL_DCCH:
            msgtype = RRC_MESSAGE_TYPE_DL_DCCH;
            break;
        case RLC_PCCH:
            msgtype = RRC_MESSAGE_TYPE_PCCH;
            break;
        case RLC_BCCH:
            msgtype = RRC_MESSAGE_TYPE_BCCH_FACH;
            break;
        case RLC_PS_DTCH:
            /* Payload of PS DTCH is PDCP or just IP*/
            is_rrc_payload = false;
            msgtype = RRC_MESSAGE_TYPE_INVALID;
            /* assume transparent PDCP for now */
            next_dissector = ip_handle;
            break;
        default:
            return; /* stop dissecting */
    }

    if (is_rrc_payload && msgtype != RRC_MESSAGE_TYPE_INVALID) {
        /* Passing the RRC sub type in the 'rrc_info' struct */
        struct rrc_info *rrcinf;
        fp_info *fpinf;
        fpinf = (fp_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_fp, 0);
        rrcinf = (rrc_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rrc, 0);
        if (!rrcinf) {
            rrcinf = (rrc_info *)wmem_alloc0(wmem_file_scope(), sizeof(struct rrc_info));
            p_add_proto_data(wmem_file_scope(), pinfo, proto_rrc, 0, rrcinf);
        }
        rrcinf->msgtype[fpinf->cur_tb] = msgtype;
        next_dissector = rrc_handle;
    }

    if(next_dissector != NULL) {
        TRY {
            call_dissector(next_dissector, tvb, pinfo, tree);
        }
        CATCH_NONFATAL_ERRORS {
            /*
             * Sub dissector threw an exception
             * Show the exception and continue dissecting other SDUs.
             */
            show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
        }
        ENDTRY;
        /* once the packet has been dissected, protect it from further changes using a 'fence' in the INFO column */
        col_append_str(pinfo->cinfo, COL_INFO," ");
        col_set_fence(pinfo->cinfo, COL_INFO);
    }
}

static void
add_channel_info(packet_info * pinfo, proto_tree * tree, fp_info * fpinf, rlc_info * rlcinf)
{
    proto_item * item;
    proto_tree * channel_tree ;

    item = proto_tree_add_item(tree, hf_rlc_channel, NULL, 0, 0, ENC_NA);
    channel_tree = proto_item_add_subtree(item, ett_rlc_channel);
    proto_item_append_text(item, " (rbid: %u, dir: %s, uid: 0x%08x)", rlcinf->rbid[fpinf->cur_tb],
                           val_to_str_const(pinfo->link_dir, rlc_dir_vals, "Unknown"), rlcinf->ueid[fpinf->cur_tb]);
    proto_item_set_generated(item);
    item = proto_tree_add_uint(channel_tree, hf_rlc_channel_rbid, NULL, 0, 0, rlcinf->rbid[fpinf->cur_tb]);
    proto_item_set_generated(item);
    item = proto_tree_add_uint(channel_tree, hf_rlc_channel_dir, NULL, 0, 0, pinfo->link_dir);
    proto_item_set_generated(item);
    item = proto_tree_add_uint(channel_tree, hf_rlc_channel_ueid, NULL, 0, 0, rlcinf->ueid[fpinf->cur_tb]);
    proto_item_set_generated(item);

}

#ifdef HAVE_UMTS_KASUMI
static uint8_t *
translate_hex_key(char * char_key){
    int i,j;
    uint8_t * key_in;

    key_in = wmem_alloc0(pinfo->pool, sizeof(uint8_t)*16);
    j= (int)(strlen(char_key)/2)-1;
    /*Translate "hex-string" into a byte aligned block */
    for(i = (int)strlen(char_key); i> 0; i-=2 ){
        key_in[j] =  ( (uint8_t)  (strtol( &char_key[i-2], NULL, 16 ) ));
        char_key[i-2] = '\0';
        j--;
    }
    return key_in;

}
#endif

/** @brief Deciphers a given tvb
 *
 * Note that the actual KASUMI implementation needs to be placed into
 * epan/crypt/kasumi.* by "end users" since due to patents the actual implementation
 * cannot be distributed openly at the moment.
 *
 * Refer to 3GPP TS 35.201 and 3GPP TS 35.202 for further information.
 *
 *  @param tvb The ciphered data.
 *  @param  pinfo Packet info.
 *  @param counter the COUNTER value input
 *  @param rbid the radiobear id
 *  @param dir Direction of the link
 *  @param header_size Size of the unciphered header
 *  @return tvb Returns a deciphered tvb
 */
static tvbuff_t *
#ifndef HAVE_UMTS_KASUMI
rlc_decipher_tvb(tvbuff_t *tvb _U_, packet_info *pinfo, uint32_t counter _U_,
                 uint8_t rbid _U_, bool dir _U_, uint8_t header_size _U_) {
    /*Check if we have a KASUMI implementation*/
    expert_add_info(pinfo, NULL, &ei_rlc_kasumi_implementation_missing);
    return NULL;
#else
rlc_decipher_tvb(tvbuff_t *tvb, packet_info *pinfo, uint32_t counter, uint8_t rbid, bool dir, uint8_t header_size) {
    uint8_t* out=NULL,*key_in = NULL;
    tvbuff_t *t;

    /*Fix the key into a byte block*/
    /*TODO: This should be done in a preferences callback function*/
    out = wmem_alloc0(pinfo->pool, strlen(global_rlc_kasumi_key)+1);
    memcpy(out,global_rlc_kasumi_key,strlen(global_rlc_kasumi_key));    /*Copy from preference const pointer*/
    key_in = translate_hex_key(out);    /*Translation*/

    /*Location for decrypted data & original RLC header*/
    out = tvb_memdup(pinfo->pool, tvb, 0, tvb_captured_length(tvb));

    /*Call f8 confidentiality function, note that rbid is zero indexed*/
    f8( key_in, counter, rbid-1, dir, &out[header_size], (tvb_captured_length(tvb)-header_size)*8 );

    /*Create new tvb.*/
    t = tvb_new_real_data(out,tvb_captured_length(tvb), tvb_reported_length(tvb));
    add_new_data_source(pinfo, t, "Deciphered RLC");
    return t;
#endif /* HAVE_UMTS_KASUMI */
}

/** @brief Checks if an RLC packet is ciphered, according to information reported from the RRC layer
 *
 *  @param pinfo Packet info.
 *  @param fpinf FP info
 *  @param rlcinf RLC info
 *  @param seq Sequence number of the RLC packet
 *  @return bool Returns true if the packet is ciphered and false otherwise
 */
static bool
is_ciphered_according_to_rrc(packet_info *pinfo, fp_info *fpinf, rlc_info *rlcinf ,uint16_t seq) {
    int16_t             cur_tb;
    uint32_t            ueid;
    rrc_ciphering_info *ciphering_info;
    uint8_t             rbid;
    uint8_t             direction;
    uint32_t            security_mode_frame_num;
    int32_t             ciphering_begin_seq;

    if(global_ignore_rrc_ciphering_indication) {
        return false;
    }

    cur_tb = fpinf->cur_tb;
    ueid = rlcinf->ueid[cur_tb];
    ciphering_info =  (rrc_ciphering_info *)g_tree_lookup(rrc_ciph_info_tree, GINT_TO_POINTER((int)ueid));
    if(ciphering_info != NULL) {
        rbid = rlcinf->rbid[cur_tb];
        direction = fpinf->is_uplink ? P2P_DIR_UL : P2P_DIR_DL;
        security_mode_frame_num = ciphering_info->setup_frame[direction];
        ciphering_begin_seq = ciphering_info->seq_no[rbid][direction];
        /* Making sure the rrc security message's frame number makes sense */
        if( security_mode_frame_num > 0 && security_mode_frame_num <= pinfo->num) {
            /* Making sure the sequence number where ciphering starts makes sense */
            /* TODO: This check is incorrect if the sequence numbers wrap around */
            if(ciphering_begin_seq >= 0 && ciphering_begin_seq <= seq){
				/* Finally, make sure the encryption algorithm isn't set to UEA0 (no ciphering)*/
                return ciphering_info->ciphering_algorithm != 0;
            }
        }
    }
    return false;
}

/*
 * @param key is created with GINT_TO_POINTER
 * @param value is a pointer to a uint32_t
 * @param data is a pointer to a uint32_t
 */
static gboolean
iter_same(void *key, void *value, void *data) {
    /*If true we found the correct frame*/
    if ((uint32_t)GPOINTER_TO_INT(key) > *(uint32_t*)data){
        *((uint32_t*)data) = *((uint32_t*)value);
        return true;
    }
    *((uint32_t*)data) = (uint32_t)GPOINTER_TO_INT(key);

    return true;
}

/**
 * Used for looking up and old ciphering counter value in the counter_map tree.
 * @param key is created with GINT_TO_POINTER
 * @param value is pointer to an array of 2 uint32_t
 * @param data is a pointer to an array of 3 uint32_t
 */
static gboolean
rlc_find_old_counter(void *key, void *value, void *data) {

    /*If true we found the correct frame*/
    if( (uint32_t)GPOINTER_TO_INT(key) >= ((uint32_t *)data)[0] ){
        return TRUE;
    }
    /*Overwrite the data since the previous one wasn't correct*/
    ((uint32_t*)data)[1] = ((uint32_t*)value)[0];
    ((uint32_t*)data)[2] = ((uint32_t*)value)[1];

    return FALSE;
}

static void
rlc_decipher(tvbuff_t *tvb, packet_info * pinfo, proto_tree * tree, fp_info * fpinf,
             rlc_info * rlcinf, uint16_t seq, enum rlc_mode mode)
{
    rrc_ciphering_info *ciphering_info;
    uint8_t indx, header_size, hfn_shift;
    int16_t pos;
    uint8_t ext;
    int ciphered_data_hf;

    indx = fpinf->is_uplink ? P2P_DIR_UL : P2P_DIR_DL;
    pos = fpinf->cur_tb;
    if (mode ==RLC_UM) {
        header_size = 1;
        hfn_shift = 7;
    } else {
        header_size = 2;
        hfn_shift = 12;
    }

    /*Ciphering info singled in RRC by securitymodecommands */
    ciphering_info =  (rrc_ciphering_info *)g_tree_lookup(rrc_ciph_info_tree, GINT_TO_POINTER((int)rlcinf->ueid[fpinf->cur_tb]));

    /*TODO: This doesn't really work for all packets..*/
    /*Check if we have ciphering info and that this frame is ciphered*/
    if(ciphering_info!=NULL && ( (ciphering_info->setup_frame[indx] > 0 && ciphering_info->setup_frame[indx] < pinfo->num && ciphering_info->seq_no[rlcinf->rbid[pos]][indx] == -1)  ||
                     (ciphering_info->setup_frame[indx] < pinfo->num && ciphering_info->seq_no[rlcinf->rbid[pos]][indx] >= 0  && ciphering_info->seq_no[rlcinf->rbid[pos]][indx] <= seq) )){

        tvbuff_t *t;

        /*Check if this counter has been initialized*/
        if(!counter_init[rlcinf->rbid[pos]][indx] ){
            uint32_t frame_num = pinfo->num;

            /*Initializes counter*/
            counter_init[rlcinf->rbid[pos]][0] = true;
            counter_init[rlcinf->rbid[pos]][1] = true;
            /*Find appropriate start value*/
            g_tree_foreach(ciphering_info->start_ps, (GTraverseFunc)iter_same, &frame_num);

            /*Set COUNTER value accordingly as specified by 6.4.8 in 3GPP TS 33.102 */
            if(max_counter +2 > frame_num && ciphering_info->seq_no[rlcinf->rbid[pos]][indx] == -1){
                ps_counter[rlcinf->rbid[pos]][0] = (max_counter+2) << hfn_shift;
                ps_counter[rlcinf->rbid[pos]][1] = (max_counter+2) << hfn_shift;
            }else{
                ps_counter[rlcinf->rbid[pos]][0] = frame_num << hfn_shift;
                ps_counter[rlcinf->rbid[pos]][1] = frame_num << hfn_shift;
            }

            if(!tree){
                /*Preserve counter value for next dissection round*/
                uint32_t * ciph;
                ciph = g_new(uint32_t, 2);
                ciph[0] = ps_counter[rlcinf->rbid[pos]][0];
                ciph[1] = ps_counter[rlcinf->rbid[pos]][1];
                g_tree_insert(counter_map, GINT_TO_POINTER((int)pinfo->num), ciph);
            }

        }
        /*Update the maximal COUNTER value seen so far*/
        max_counter = MAX(max_counter,((ps_counter[rlcinf->rbid[pos]][indx]) | seq) >> hfn_shift);

    /*XXX: Since RBID in umts isn't configured properly..*/
        if(rlcinf->rbid[pos] == 9 ){
            if(tree){
                uint32_t frame_num[3];
                /*Set frame num we will be "searching" around*/
                frame_num[0] = pinfo->num;
                /*Find the correct counter value*/
                g_tree_foreach(counter_map, (GTraverseFunc)rlc_find_old_counter, &frame_num[0]);
                t = rlc_decipher_tvb(tvb, pinfo, (frame_num[indx+1] | seq),16,!fpinf->is_uplink,header_size);
            }else{
                t = rlc_decipher_tvb(tvb, pinfo, ((ps_counter[rlcinf->rbid[pos]][indx]) | seq),16,!fpinf->is_uplink,header_size);
            }
        }else{
            if(tree){
                /*We need to find the original counter value for second dissection pass*/
                uint32_t frame_num[3];
                frame_num[0] = pinfo->num;
                g_tree_foreach(counter_map, (GTraverseFunc)rlc_find_old_counter, &frame_num[0]);
                t = rlc_decipher_tvb(tvb, pinfo, (frame_num[indx+1] | seq),rlcinf->rbid[pos],!fpinf->is_uplink,header_size);
            }else
                t = rlc_decipher_tvb(tvb, pinfo, ((ps_counter[rlcinf->rbid[pos]][indx]) | seq),rlcinf->rbid[pos],!fpinf->is_uplink,header_size);
        }

        /*Update the hyperframe number*/
        if(seq == 4095){

            ps_counter[rlcinf->rbid[pos]][indx] += 1 << hfn_shift;

            if(!tree){/*Preserve counter for second packet analysis run*/
                uint32_t * ciph;
                ciph = g_new(uint32_t, 2);
                ciph[0] = ps_counter[rlcinf->rbid[pos]][0];
                ciph[1] = ps_counter[rlcinf->rbid[pos]][1];
                g_tree_insert(counter_map, GINT_TO_POINTER((int)pinfo->num+1), ciph);
            }
        }

        /*Unable to decipher the packet*/
        if(t == NULL){
            /* Choosing the right field text ("LIs & Data" or just "Data") based on extension bit / header extension */
            ext = tvb_get_uint8(tvb, header_size - 1) & 0x01;
            ciphered_data_hf = (ext == 1) ? hf_rlc_ciphered_lis_data : hf_rlc_ciphered_data;
            /* Adding ciphered payload field to tree */
            proto_tree_add_item(tree, ciphered_data_hf, tvb, header_size, -1, ENC_NA);
            proto_tree_add_expert(tree, pinfo, &ei_rlc_ciphered_data, tvb, header_size, -1);
            col_append_str(pinfo->cinfo, COL_INFO, "[Ciphered Data]");
            return;

        }else{
            col_append_str(pinfo->cinfo, COL_INFO, "[Deciphered Data]");

            /*TODO: Old tvb should be freed here?*/
        }
    }
}

static void
dissect_rlc_tm(enum rlc_channel_type channel, tvbuff_t *tvb, packet_info *pinfo,
           proto_tree *top_level, proto_tree *tree)
{
    fp_info       *fpinf;
    rlc_info      *rlcinf;

    fpinf = (fp_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_fp, 0);
    rlcinf = (rlc_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_umts_rlc, 0);

    if (tree) {
        if (fpinf && rlcinf) {
            /* Add "channel" information, very useful for debugging. */
            add_channel_info(pinfo, tree, fpinf, rlcinf);
        }
        proto_tree_add_item(tree, hf_rlc_data, tvb, 0, -1, ENC_NA);
    }
    rlc_call_subdissector(channel, tvb, pinfo, top_level);
}


static void
rlc_um_reassemble(tvbuff_t *tvb, uint16_t offs, packet_info *pinfo, proto_tree *tree,
          proto_tree *top_level, enum rlc_channel_type channel, uint16_t seq,
          struct rlc_li *li, uint16_t num_li, bool li_is_on_2_bytes,
          struct atm_phdr *atm)
{
    uint8_t   i;
    bool      dissected = false;
    int       length;
    tvbuff_t *next_tvb  = NULL;

    /* perform reassembly now */
    for (i = 0; i < num_li; i++) {
        if ((!li_is_on_2_bytes && (li[i].li == 0x7f)) || (li[i].li == 0x7fff)) {
            /* padding, must be last LI */
            if (tree) {
                proto_tree_add_item(tree, hf_rlc_pad, tvb, offs, tvb_captured_length_remaining(tvb, offs), ENC_NA);
            }
            offs += tvb_captured_length_remaining(tvb, offs);
        } else if ((!li_is_on_2_bytes && (li[i].li == 0x7c)) || (li[i].li == 0x7ffc)) {
            /* a new SDU starts here, mark this seq as the first PDU. */
            struct rlc_channel  ch_lookup;
            struct rlc_seqlist * endlist = NULL;
            if( -1 != rlc_channel_assign(&ch_lookup, RLC_UM, pinfo, atm ) ){
                endlist = get_endlist(pinfo, &ch_lookup, atm);
                endlist->list->data = GINT_TO_POINTER((int)seq);
                endlist->fail_packet=0;
            }

        } else if (li[i].li == 0x7ffa) {
            /* the first data octet in this RLC PDU is the first octet of an RLC SDU
               and the second last octet in this RLC PDU is the last octet of the same RLC SDU */
            length = tvb_reported_length_remaining(tvb, offs);
            if (length > 1) {
                length--;
                if (tree && length) {
                    proto_tree_add_item(tree, hf_rlc_data, tvb, offs, length, ENC_NA);
                }
                if (global_rlc_perform_reassemby) {
                    add_fragment(RLC_UM, tvb, pinfo, li[i].tree, offs, seq, i, length, true, atm);
                    next_tvb = get_reassembled_data(RLC_UM, tvb, pinfo, tree, seq, i, atm);
                }
                offs += length;
            }
            if (tree) {
                proto_tree_add_item(tree, hf_rlc_pad, tvb, offs, 1, ENC_NA);
            }
            offs += 1;
        } else {
            if (tree && li[i].len) {
                proto_tree_add_item(tree, hf_rlc_data, tvb, offs, li[i].len, ENC_NA);
            }
            if (global_rlc_perform_reassemby) {
                add_fragment(RLC_UM, tvb, pinfo, li[i].tree, offs, seq, i, li[i].len, true, atm);
                next_tvb = get_reassembled_data(RLC_UM, tvb, pinfo, tree, seq, i, atm);
            }
        }
        if (next_tvb) {
            dissected = true;
            rlc_call_subdissector(channel, next_tvb, pinfo, top_level);
            next_tvb = NULL;
        }
        offs += li[i].len;
    }

    /* is there data left? */
    if (tvb_reported_length_remaining(tvb, offs) > 0) {
        if (tree) {
            proto_tree_add_item(tree, hf_rlc_data, tvb, offs, -1, ENC_NA);
        }
        if (global_rlc_perform_reassemby) {
            /* add remaining data as fragment */
            add_fragment(RLC_UM, tvb, pinfo, tree, offs, seq, i, tvb_captured_length_remaining(tvb, offs), false, atm);
            if (dissected == false)
                col_set_str(pinfo->cinfo, COL_INFO, "[RLC UM Fragment]");
        }
    }
    if (dissected == false)
        col_append_fstr(pinfo->cinfo, COL_INFO, "[RLC UM Fragment]  SN=%u", seq);
    else
        if (channel == RLC_UNKNOWN_CH)
            col_append_fstr(pinfo->cinfo, COL_INFO, "[RLC UM Data]  SN=%u", seq);
}

static int16_t
rlc_decode_li(enum rlc_mode mode, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
          struct rlc_li *li, uint8_t max_li, bool li_on_2_bytes)
{
    uint32_t    hdr_len, offs = 0, li_offs;
    uint8_t     ext, num_li = 0;
    uint16_t    next_bytes, prev_li = 0;
    proto_item *malformed;
    uint16_t    total_len;

    switch (mode) {
        case RLC_AM:
            offs = 1;
            break;
        case RLC_UM:
            offs = 0;
            break;
        case RLC_TM:
            /* fall through */
        case RLC_UNKNOWN_MODE:
        default:
            return -1;
    }
    hdr_len = offs;
    /* calculate header length */
    ext = tvb_get_uint8(tvb, hdr_len++) & 0x01;
    while (ext) {
        next_bytes = li_on_2_bytes ? tvb_get_ntohs(tvb, hdr_len) : tvb_get_uint8(tvb, hdr_len);
        ext = next_bytes & 0x01;
        hdr_len += li_on_2_bytes ? 2 : 1;
    }
    total_len = tvb_captured_length_remaining(tvb, hdr_len);

    /* do actual evaluation of LIs */
    ext = tvb_get_uint8(tvb, offs++) & 0x01;
    li_offs = offs;
    while (ext) {
        if (li_on_2_bytes) {
            next_bytes = tvb_get_ntohs(tvb, offs);
            offs += 2;
        } else {
            next_bytes = tvb_get_uint8(tvb, offs++);
        }
        ext = next_bytes & 0x01;
        li[num_li].ext = ext;
        li[num_li].li = next_bytes >> 1;

        if (li_on_2_bytes) {
            switch (li[num_li].li) {
                case 0x0000: /* previous segment was the last one */
                case 0x7ffb: /* previous PDU contains last segment of SDU (minus last byte) */
                case 0x7ffe: /* contains piggybacked STATUS in AM or segment in UM */
                case 0x7fff: /* padding */
                    li[num_li].len = 0;
                    break;
                case 0x7ffa: /* contains exactly one SDU (minus last byte), UM only */
                case 0x7ffc: /* start of a new SDU, UM only */
                case 0x7ffd: /* contains exactly one SDU, UM only */
                    li[num_li].len = 0;
                    if (mode == RLC_UM) {
                        /* valid for UM */
                        break;
                    }
                    /*invalid for AM */
                    /* add malformed LI for investigation */
                    malformed = tree_add_li(mode, &li[num_li], num_li, li_offs, li_on_2_bytes, tvb, tree);
                    expert_add_info(pinfo, malformed, &ei_rlc_li_reserved);
                    return -1; /* just give up on this */
                default:
                    /* since the LI is an offset (from the end of the header), it
                    * may not be larger than the total remaining length and no
                    * LI may be smaller than its preceding one
                    */
                    if (((li[num_li].li > total_len) && !global_rlc_headers_expected)
                        || (li[num_li].li < prev_li)) {
                        /* add malformed LI for investigation */
                        li[num_li].len = 0;
                        malformed = tree_add_li(mode, &li[num_li], num_li, li_offs, li_on_2_bytes, tvb, tree);
                        expert_add_info(pinfo, malformed, &ei_rlc_li_incorrect_warn);
                        return -1; /* just give up on this */
                    }
                    li[num_li].len = li[num_li].li - prev_li;
                    prev_li = li[num_li].li;
            }
        } else {
            switch (li[num_li].li) {
                case 0x00: /* previous segment was the last one */
                case 0x7e: /* contains piggybacked STATUS in AM or segment in UM */
                case 0x7f: /* padding */
                    li[num_li].len = 0;
                    break;
                case 0x7c: /* start of a new SDU, UM only */
                case 0x7d: /* contains exactly one SDU, UM only */
                    li[num_li].len = 0;
                    if (mode == RLC_UM) {
                        /* valid for UM */
                        break;
                    }
                    /*invalid for AM */
                    /* add malformed LI for investigation */
                    malformed = tree_add_li(mode, &li[num_li], num_li, li_offs, li_on_2_bytes, tvb, tree);
                    expert_add_info(pinfo, malformed, &ei_rlc_li_reserved);
                    return -1; /* just give up on this */
                default:
                    /* since the LI is an offset (from the end of the header), it
                    * may not be larger than the total remaining length and no
                    * LI may be smaller than its preceding one
                    */
                    li[num_li].len = li[num_li].li - prev_li;
                    if (((li[num_li].li > total_len) && !global_rlc_headers_expected)
                        || (li[num_li].li < prev_li)) {
                        /* add malformed LI for investigation */
                        li[num_li].len = 0;
                        malformed = tree_add_li(mode, &li[num_li], num_li, li_offs, li_on_2_bytes, tvb, tree);
                        expert_add_info_format(pinfo, malformed, &ei_rlc_li_incorrect_mal, "Incorrect LI value 0x%x", li[num_li].li);
                        return -1; /* just give up on this */
                    }
                    prev_li = li[num_li].li;
            }
        }
        li[num_li].tree = tree_add_li(mode, &li[num_li], num_li, li_offs, li_on_2_bytes, tvb, tree);
        num_li++;

        if (num_li >= max_li) {
            /* OK, so this is not really a malformed packet, but for now,
            * we will treat it as such, so that it is marked in some way */
            expert_add_info(pinfo, li[num_li-1].tree, &ei_rlc_li_too_many);
            return -1;
        }
    }
    return num_li;
}

static void
dissect_rlc_um(enum rlc_channel_type channel, tvbuff_t *tvb, packet_info *pinfo,
           proto_tree *top_level, proto_tree *tree, struct atm_phdr *atm)
{
#define MAX_LI 16
    struct rlc_li  li[MAX_LI];
    fp_info       *fpinf;
    rlc_info      *rlcinf;
    uint32_t       orig_num;
    uint8_t        seq;
    uint8_t        ext;
    uint8_t        next_byte;
    uint16_t       offs = 0;
    int16_t        cur_tb, num_li  = 0;
    bool           is_truncated, li_is_on_2_bytes;
    proto_item    *truncated_ti;
    bool           ciphered_according_to_rrc = false;
    bool           ciphered_flag = false;
    bool           deciphered_flag = false;
    int            ciphered_data_hf;


    next_byte = tvb_get_uint8(tvb, offs++);
    seq = next_byte >> 1;

    fpinf = (fp_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_fp, 0);
    rlcinf = (rlc_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_umts_rlc, 0);

    if (tree) {
        if (fpinf && rlcinf) {
            /* Add "channel" information, very useful for debugging. */
            add_channel_info(pinfo, tree, fpinf, rlcinf);
        }
        /* show sequence number and extension bit */
        proto_tree_add_bits_item(tree, hf_rlc_seq, tvb, 0, 7, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(tree, hf_rlc_ext, tvb, 7, 1, ENC_BIG_ENDIAN);
    }

    if (!fpinf || !rlcinf) {
        proto_tree_add_expert(tree, pinfo, &ei_rlc_no_per_frame_data, tvb, 0, -1);
        return;
    }

    cur_tb = fpinf->cur_tb;
    ciphered_according_to_rrc = is_ciphered_according_to_rrc(pinfo, fpinf, rlcinf, (uint16_t)seq);
    ciphered_flag = rlcinf->ciphered[cur_tb];
    deciphered_flag = rlcinf->deciphered[cur_tb];
    if (((ciphered_according_to_rrc || ciphered_flag) && !deciphered_flag) || global_rlc_ciphered) {
        if(global_rlc_try_decipher){
            rlc_decipher(tvb, pinfo, tree, fpinf, rlcinf, seq, RLC_UM);
        }else{
            /* Choosing the right field text ("LIs & Data" or just "Data") based on extension bit */
            ext = tvb_get_uint8(tvb, 0) & 0x01;
            ciphered_data_hf = (ext == 1) ? hf_rlc_ciphered_lis_data : hf_rlc_ciphered_data;
            /* Adding ciphered payload field to tree */
            proto_tree_add_item(tree, ciphered_data_hf, tvb, offs, -1, ENC_NA);
            proto_tree_add_expert(tree, pinfo, &ei_rlc_ciphered_data, tvb, offs, -1);
            col_append_str(pinfo->cinfo, COL_INFO, "[Ciphered Data]");
            return;
        }
    }

    if (global_rlc_li_size == RLC_LI_UPPERLAYER) {
        if (rlcinf->li_size[cur_tb] == RLC_LI_VARIABLE) {
            li_is_on_2_bytes = (tvb_reported_length(tvb) > 125) ? true : false;
        } else {
            li_is_on_2_bytes = (rlcinf->li_size[cur_tb] == RLC_LI_15BITS) ? true : false;
        }
    } else { /* Override rlcinf configuration with preference. */
        li_is_on_2_bytes = (global_rlc_li_size == RLC_LI_15BITS) ? true : false;
    }



    num_li = rlc_decode_li(RLC_UM, tvb, pinfo, tree, li, MAX_LI, li_is_on_2_bytes);
    if (num_li == -1) return; /* something went wrong */
    offs += ((li_is_on_2_bytes) ? 2 : 1) * num_li;

    if (global_rlc_headers_expected) {
        /* There might not be any data, if only header was logged */
        is_truncated = (tvb_captured_length_remaining(tvb, offs) == 0);
        truncated_ti = proto_tree_add_boolean(tree, hf_rlc_header_only, tvb, 0, 0,
                                              is_truncated);
        if (is_truncated) {
            proto_item_set_generated(truncated_ti);
            expert_add_info(pinfo, truncated_ti, &ei_rlc_header_only);
            return;
        } else {
            proto_item_set_hidden(truncated_ti);
        }
    }

    /* do not detect duplicates or reassemble, if prefiltering is done */
    if (pinfo->num == 0) return;
    /* check for duplicates */
    if (rlc_is_duplicate(RLC_UM, pinfo, seq, &orig_num, atm) == true) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "[RLC UM Fragment] [Duplicate]  SN=%u", seq);
        proto_tree_add_uint(tree, hf_rlc_duplicate_of, tvb, 0, 0, orig_num);
        return;
    }
    rlc_um_reassemble(tvb, offs, pinfo, tree, top_level, channel, seq, li, num_li, li_is_on_2_bytes, atm);
}

static void
dissect_rlc_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, uint16_t offset)
{
    uint8_t     sufi_type, bits;
    uint64_t    len, sn, wsn, lsn, l;
    uint16_t    value, previous_sn;
    bool        isErrorBurstInd;
    int         bit_offset, previous_bit_offset;
    unsigned    i, j;
    proto_tree *sufi_tree, *bitmap_tree, *rlist_tree;
    proto_item *sufi_item, *ti;
    #define BUFF_SIZE 41
    char       *buff                     = NULL;
    uint8_t     cw[15];
    uint8_t     sufi_start_offset;
    bool        seen_last                = false;
    uint16_t    number_of_bitmap_entries = 0;

    bit_offset = offset*8 + 4; /* first SUFI type is always 4 bit shifted */

    while (!seen_last && tvb_reported_length_remaining(tvb, bit_offset/8) > 0) {
        /* SUFI */
        sufi_type = tvb_get_bits8(tvb, bit_offset, 4);
        sufi_start_offset = bit_offset/8;
        sufi_item = proto_tree_add_item(tree, hf_rlc_sufi, tvb, sufi_start_offset, 0, ENC_NA);
        sufi_tree = proto_item_add_subtree(sufi_item, ett_rlc_sufi);
        proto_tree_add_bits_item(sufi_tree, hf_rlc_sufi_type, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(sufi_item, " (%s)", val_to_str_const(sufi_type, rlc_sufi_vals, "Unknown"));
        bit_offset += 4;
        switch (sufi_type) {
            case RLC_SUFI_NOMORE:
                seen_last = true;
                break;
            case RLC_SUFI_ACK:
                proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_lsn, tvb, bit_offset, 12, &lsn, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " LSN=%u", (uint16_t)lsn);
                proto_item_append_text(sufi_item, " LSN=%u", (uint16_t)lsn);
                bit_offset += 12;
                seen_last = true;
                break;
            case RLC_SUFI_WINDOW:
                proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_wsn, tvb, bit_offset, 12, &wsn, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO, " WSN=%u", (uint16_t)wsn);
                bit_offset += 12;
                break;
            case RLC_SUFI_LIST:
                proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_len, tvb, bit_offset, 4, &len, ENC_BIG_ENDIAN);
                col_append_fstr(pinfo->cinfo, COL_INFO,  " LIST(%u) - ", (uint8_t)len);
                bit_offset += 4;
                if (len) {
                    while (len) {
                        ti = proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_sn, tvb, bit_offset, 12, &sn, ENC_BIG_ENDIAN);
                        proto_item_append_text(ti, " (AMD PDU not correctly received)");
                        bit_offset += 12;
                        ti = proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_l, tvb, bit_offset, 4, &l, ENC_BIG_ENDIAN);
                        if (l) {
                            proto_item_append_text(ti, " (all consecutive AMD PDUs up to SN %u not correctly received)",
                                                   (unsigned)(sn+l)&0xfff);
                            col_append_fstr(pinfo->cinfo, COL_INFO,  "%u-%u ", (uint16_t)sn, (unsigned)(sn+l)&0xfff);
                        }
                        else {
                            col_append_fstr(pinfo->cinfo, COL_INFO,  "%u ", (uint16_t)sn);
                        }
                        bit_offset += 4;
                        len--;
                    }
                } else {
                    expert_add_info(pinfo, tree, &ei_rlc_sufi_len);
                }
                break;
            case RLC_SUFI_BITMAP:
                proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_len, tvb, bit_offset, 4, &len, ENC_BIG_ENDIAN);
                bit_offset += 4;
                len++; /* bitmap is len + 1 */
                proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_fsn, tvb, bit_offset, 12, &sn, ENC_BIG_ENDIAN);
                bit_offset += 12;
                proto_tree_add_item(sufi_tree, hf_rlc_sufi_bitmap, tvb, bit_offset/8, (int)len, ENC_NA);
                bitmap_tree = proto_tree_add_subtree(sufi_tree, tvb, bit_offset/8, (int)len, ett_rlc_bitmap, &ti, "Decoded bitmap:");
                col_append_str(pinfo->cinfo, COL_INFO, " BITMAP=(");

                buff = (char *)wmem_alloc(pinfo->pool, BUFF_SIZE);
                for (i=0; i<len; i++) {
                    bits = tvb_get_bits8(tvb, bit_offset, 8);
                    for (l=0, j=0; l<8; l++) {
                        if ((bits << l) & 0x80) {
                            j += snprintf(&buff[j], BUFF_SIZE-j, "%4u,", (unsigned)(sn+(8*i)+l)&0xfff);
                            col_append_fstr(pinfo->cinfo, COL_INFO, " %u", (unsigned)(sn+(8*i)+l)&0xfff);
                            number_of_bitmap_entries++;
                        } else {
                            j += snprintf(&buff[j], BUFF_SIZE-j, "    ,");
                        }
                    }
                    proto_tree_add_string_format(bitmap_tree, hf_rlc_bitmap_string, tvb, bit_offset/8, 1, buff, "%s", buff);
                    bit_offset += 8;
                }
                proto_item_append_text(ti, " (%u SNs)", number_of_bitmap_entries);
                col_append_str(pinfo->cinfo, COL_INFO, " )");
                break;
            case RLC_SUFI_RLIST:
                previous_bit_offset = bit_offset;
                proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_len, tvb, bit_offset, 4, &len, ENC_BIG_ENDIAN);
                bit_offset += 4;
                proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_fsn, tvb, bit_offset, 12, &sn, ENC_BIG_ENDIAN);
                bit_offset += 12;
                proto_item_append_text(sufi_item, " (%u codewords)", (uint16_t)len);

                for (i=0; i<len; i++) {
                    ti = proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_cw, tvb, bit_offset, 4, &l, ENC_BIG_ENDIAN);
                    if (l == 0x01) {
                        proto_item_append_text(ti, " (Error burst indication)");
                    }
                    bit_offset += 4;
                    cw[i] = (uint8_t)l;
                }
                if (len && (((cw[len-1] & 0x01) == 0) || (cw[len-1] == 0x01))) {
                    expert_add_info(pinfo, tree, &ei_rlc_sufi_cw);
                } else {
                    rlist_tree = proto_tree_add_subtree(sufi_tree, tvb, previous_bit_offset/8, (bit_offset-previous_bit_offset)/8, ett_rlc_rlist, NULL, "Decoded list:");
                    proto_tree_add_uint_format_value(rlist_tree, hf_rlc_sequence_number, tvb, (previous_bit_offset+4)/8, 12/8, (uint32_t)sn, "%u (AMD PDU not correctly received)", (unsigned)sn);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " RLIST=(%u", (unsigned)sn);

                    for (i=0, isErrorBurstInd=false, j=0, previous_sn=(uint16_t)sn, value=0; i<len; i++) {
                        if (cw[i] == 0x01) {
                            isErrorBurstInd = true;
                        } else {
                            value |= (cw[i] >> 1) << j;
                            j += 3;
                            if (cw[i] & 0x01) {
                                if (isErrorBurstInd) {
                                    previous_sn = (previous_sn + value) & 0xfff;
                                    ti = proto_tree_add_uint(rlist_tree, hf_rlc_length, tvb, (previous_bit_offset+16+4*i)/8, 1, value);
                                    if (value) {
                                        proto_item_append_text(ti, "  (all consecutive AMD PDUs up to SN %u not correctly received)", previous_sn);
                                        col_append_fstr(pinfo->cinfo, COL_INFO, " ->%u", previous_sn);
                                    }
                                    isErrorBurstInd = false;
                                } else {
                                    value = (value + previous_sn) & 0xfff;
                                    proto_tree_add_uint_format_value(rlist_tree, hf_rlc_sequence_number, tvb, (previous_bit_offset+16+4*i)/8, 1, value, "%u (AMD PDU not correctly received)",value);
                                    col_append_fstr(pinfo->cinfo, COL_INFO, " %u", value);
                                    previous_sn = value;
                                }
                                value = j = 0;
                            }
                        }
                    }
                    col_append_str(pinfo->cinfo, COL_INFO, ")");
                }
                break;
            case RLC_SUFI_MRW_ACK:
                col_append_str(pinfo->cinfo, COL_INFO, " MRW-ACK");
                proto_tree_add_bits_item(sufi_tree, hf_rlc_sufi_n, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
                bit_offset += 4;
                proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_sn_ack, tvb, bit_offset, 12, &sn, ENC_BIG_ENDIAN);
                bit_offset += 12;
                col_append_fstr(pinfo->cinfo, COL_INFO, " SN=%u", (uint16_t)sn);
                break;
            case RLC_SUFI_MRW:
                col_append_str(pinfo->cinfo, COL_INFO, " MRW");
                proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_len, tvb, bit_offset, 4, &len, ENC_BIG_ENDIAN);
                bit_offset += 4;
                if (len) {
                    while (len) {
                        proto_tree_add_bits_ret_val(sufi_tree, hf_rlc_sufi_sn_mrw, tvb, bit_offset, 12, &sn, ENC_BIG_ENDIAN);
                        col_append_fstr(pinfo->cinfo, COL_INFO, " SN=%u", (uint16_t)sn);
                        bit_offset += 12;
                        len--;
                    }
                } else {
                    /* only one SN_MRW field is present */
                    ti = proto_tree_add_bits_item(sufi_tree, hf_rlc_sufi_sn_mrw, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
                    proto_item_append_text(ti, " (RLC SDU to be discarded in the Receiver extends above the configured transmission window in the Sender)");
                    bit_offset += 12;
                }
                proto_tree_add_bits_item(sufi_tree, hf_rlc_sufi_n, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
                bit_offset += 4;
                break;
            case RLC_SUFI_POLL:
                proto_tree_add_bits_item(sufi_tree, hf_rlc_sufi_poll_sn, tvb, bit_offset, 12, ENC_BIG_ENDIAN);
                bit_offset += 12;
                break;

            default:
                expert_add_info(pinfo, tree, &ei_rlc_sufi_type);
                return; /* invalid value, ignore the rest */
        }

        /* Set extent of SUFI root */
        proto_item_set_len(sufi_item, ((bit_offset+7)/8) - sufi_start_offset);
    }
}

static void
dissect_rlc_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    uint8_t     type, next_byte;
    proto_item *ti;
    uint64_t    r1;
    uint64_t    rsn, hfn;

    next_byte = tvb_get_uint8(tvb, 0);
    type = (next_byte >> 4) & 0x07;

    ti = proto_tree_add_bits_item(tree, hf_rlc_ctrl_type, tvb, 1, 3, ENC_BIG_ENDIAN);
    switch (type) {
        case RLC_STATUS:
            dissect_rlc_status(tvb, pinfo, tree, 0);
            break;
        case RLC_RESET:
        case RLC_RESET_ACK:
            col_append_str(pinfo->cinfo, COL_INFO, (type == RLC_RESET) ? " RESET" : " RESET-ACK");
            proto_tree_add_bits_ret_val(tree, hf_rlc_rsn, tvb, 4, 1, &rsn, ENC_BIG_ENDIAN);
            proto_tree_add_bits_ret_val(tree, hf_rlc_r1, tvb, 5, 3, &r1, ENC_BIG_ENDIAN);
            if (r1) {
                expert_add_info(pinfo, ti, &ei_rlc_reserved_bits_not_zero);
                return;
            }
            proto_tree_add_bits_ret_val(tree, hf_rlc_hfni, tvb, 8, 20, &hfn, ENC_BIG_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO, " RSN=%u HFN=%u", (uint16_t)rsn, (uint32_t)hfn);
            break;
        default:
            expert_add_info_format(pinfo, ti, &ei_rlc_ctrl_type, "Invalid RLC AM control type %u", type);
            return; /* invalid */
    }
}

static void
rlc_am_reassemble(tvbuff_t *tvb, uint16_t offs, packet_info *pinfo,
          proto_tree *tree, proto_tree *top_level,
          enum rlc_channel_type channel, uint16_t seq, bool poll_set, struct rlc_li *li,
          uint16_t num_li, bool final, bool li_is_on_2_bytes,
          struct atm_phdr *atm)
{
    uint8_t   i;
    bool      piggyback = false, dissected = false;
    tvbuff_t *next_tvb  = NULL;

    struct rlc_channel  ch_lookup;
    struct rlc_seqlist * endlist = NULL;
    if( 0 == seq ){ /* assuming that a new RRC Connection is established when 0==seq.  */
        if( -1 != rlc_channel_assign(&ch_lookup, RLC_AM, pinfo, atm ) ){
            endlist = get_endlist(pinfo, &ch_lookup, atm);
            endlist->list->data = GINT_TO_POINTER( -1);
        }
    }

    /* perform reassembly now */
    for (i = 0; i < num_li; i++) {
        if ((!li_is_on_2_bytes && (li[i].li == 0x7e)) || (li[i].li == 0x7ffe)) {
            /* piggybacked status */
            piggyback = true;
        } else if ((!li_is_on_2_bytes && (li[i].li == 0x7f)) || (li[i].li == 0x7fff)) {
            /* padding, must be last LI */
            if (tvb_reported_length_remaining(tvb, offs) > 0) {
                if (tree) {
                    proto_tree_add_item(tree, hf_rlc_pad, tvb, offs, -1, ENC_NA);
                }
                if (i == 0) {
                    /* Insert empty RLC frag so RLC doesn't miss this seq number. */
                    add_fragment(RLC_AM, tvb, pinfo, li[i].tree, offs, seq, i, 0, true, atm);
                }
            }
            offs += tvb_captured_length_remaining(tvb, offs);
        } else {
            if (tree) {
                proto_tree_add_item(tree, hf_rlc_data, tvb, offs, li[i].len, ENC_NA);
            }
            if (global_rlc_perform_reassemby) {
                add_fragment(RLC_AM, tvb, pinfo, li[i].tree, offs, seq, i, li[i].len, true, atm);
                next_tvb = get_reassembled_data(RLC_AM, tvb, pinfo, tree, seq, i, atm);
            }
        }
        if (next_tvb) {
            dissected = true;
            rlc_call_subdissector(channel, next_tvb, pinfo, top_level);
            next_tvb = NULL;
        }
        offs += li[i].len;
    }

    if (piggyback) {
        dissect_rlc_status(tvb, pinfo, tree, offs);
    } else {
        if (tvb_reported_length_remaining(tvb, offs) > 0) {
            /* we have remaining data, which we need to mark in the tree */
            if (tree) {
                proto_tree_add_item(tree, hf_rlc_data, tvb, offs, -1, ENC_NA);
            }
            if (global_rlc_perform_reassemby) {
                add_fragment(RLC_AM, tvb, pinfo, tree, offs, seq, i,
                    tvb_captured_length_remaining(tvb,offs), final, atm);
                if (final) {
                    next_tvb = get_reassembled_data(RLC_AM, tvb, pinfo, tree, seq, i, atm);
                }
            }
        }
        if (next_tvb) {
            dissected = true;
            rlc_call_subdissector(channel, next_tvb, pinfo, top_level);
            next_tvb = NULL;
        }
    }
    if (dissected == false)
        col_append_fstr(pinfo->cinfo, COL_INFO, "[RLC AM Fragment]  SN=%u %s",
                     seq, poll_set ? "(P)" : "");
    else
        if (channel == RLC_UNKNOWN_CH)
            col_append_fstr(pinfo->cinfo, COL_INFO, "[RLC AM Data]  SN=%u %s",
                         seq, poll_set ? "(P)" : "");
}

static void
dissect_rlc_am(enum rlc_channel_type channel, tvbuff_t *tvb, packet_info *pinfo,
           proto_tree *top_level, proto_tree *tree, struct atm_phdr *atm)
{
#define MAX_LI 16
    struct rlc_li  li[MAX_LI];
    fp_info       *fpinf;
    rlc_info      *rlcinf;
    uint8_t        ext, dc;
    uint8_t        next_byte;
    uint32_t       orig_num        = 0;
    int16_t        num_li          = 0;
    int16_t        cur_tb;
    uint16_t       seq, offs       = 0;
    bool           is_truncated, li_is_on_2_bytes;
    proto_item    *truncated_ti, *ti;
    uint64_t       polling;
    bool           ciphered_according_to_rrc = false;
    bool           ciphered_flag = false;
    bool           deciphered_flag = false;
    int            ciphered_data_hf;

    fpinf = (fp_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_fp, 0);
    rlcinf = (rlc_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_umts_rlc, 0);

    next_byte = tvb_get_uint8(tvb, offs++);
    dc = next_byte >> 7;
    if (tree) {
        if (fpinf && rlcinf) {
            /* Add "channel" information, very useful for debugging. */
            add_channel_info(pinfo, tree, fpinf, rlcinf);
        }
        proto_tree_add_bits_item(tree, hf_rlc_dc, tvb, 0, 1, ENC_BIG_ENDIAN);
    }
    if (dc == 0) {
        col_set_str(pinfo->cinfo, COL_INFO, "[RLC Control Frame]");
        dissect_rlc_control(tvb, pinfo, tree);
        return;
    }

    seq = next_byte & 0x7f;
    seq <<= 5;
    next_byte = tvb_get_uint8(tvb, offs++);
    seq |= (next_byte >> 3);

    ext = next_byte & 0x03;
    /* show header fields */
    proto_tree_add_bits_item(tree, hf_rlc_seq, tvb, 1, 12, ENC_BIG_ENDIAN);
    proto_tree_add_bits_ret_val(tree, hf_rlc_p, tvb, 13, 1, &polling, ENC_BIG_ENDIAN);
    ti = proto_tree_add_bits_item(tree, hf_rlc_he, tvb, 14, 2, ENC_BIG_ENDIAN);

    /* header extension may only be 00, 01 or 10 */
    if (ext > 2) {
        expert_add_info(pinfo, ti, &ei_rlc_he);
        return;
    }

    if (!fpinf || !rlcinf) {
        proto_tree_add_expert(tree, pinfo, &ei_rlc_no_per_frame_data, tvb, 0, -1);
        return;
    }

    cur_tb = fpinf->cur_tb;
    /**
     * WARNING DECIPHERING IS HIGHLY EXPERIMENTAL!!!
     * */
    ciphered_according_to_rrc = is_ciphered_according_to_rrc(pinfo, fpinf, rlcinf, (uint16_t)seq);
    ciphered_flag = rlcinf->ciphered[cur_tb];
    deciphered_flag = rlcinf->deciphered[cur_tb];
    if (((ciphered_according_to_rrc || ciphered_flag) && !deciphered_flag) || global_rlc_ciphered) {
        if(global_rlc_try_decipher){
            rlc_decipher(tvb, pinfo, tree, fpinf, rlcinf, seq, RLC_AM);
        }else{
            /* Choosing the right field text ("LIs & Data" or just "Data") based on header extension field */
            ciphered_data_hf = (ext == 0x01) ? hf_rlc_ciphered_lis_data : hf_rlc_ciphered_data;
            /* Adding ciphered payload field to tree */
            proto_tree_add_item(tree, ciphered_data_hf, tvb, offs, -1, ENC_NA);
            proto_tree_add_expert(tree, pinfo, &ei_rlc_ciphered_data, tvb, offs, -1);
            col_append_str(pinfo->cinfo, COL_INFO, "[Ciphered Data]");
            return;
        }
    }

    if (global_rlc_li_size == RLC_LI_UPPERLAYER) {
        if (rlcinf->li_size[cur_tb] == RLC_LI_VARIABLE) {
            li_is_on_2_bytes = (tvb_reported_length(tvb) > 126) ? true : false;
        } else {
            li_is_on_2_bytes = (rlcinf->li_size[cur_tb] == RLC_LI_15BITS) ? true : false;
        }
    } else { /* Override rlcinf configuration with preference. */
        li_is_on_2_bytes = (global_rlc_li_size == RLC_LI_15BITS) ? true : false;
    }

    num_li = rlc_decode_li(RLC_AM, tvb, pinfo, tree, li, MAX_LI, li_is_on_2_bytes);
    if (num_li == -1) return; /* something went wrong */
    offs += ((li_is_on_2_bytes) ? 2 : 1) * num_li;
    if (global_rlc_headers_expected) {
        /* There might not be any data, if only header was logged */
        is_truncated = (tvb_captured_length_remaining(tvb, offs) == 0);
        truncated_ti = proto_tree_add_boolean(tree, hf_rlc_header_only, tvb, 0, 0,
                                              is_truncated);
        if (is_truncated) {
            proto_item_set_generated(truncated_ti);
            expert_add_info(pinfo, truncated_ti, &ei_rlc_header_only);
            return;
        } else {
            proto_item_set_hidden(truncated_ti);
        }
    }

    /* do not detect duplicates or reassemble, if prefiltering is done */
    if (pinfo->num == 0) return;
    /* check for duplicates, but not if already visited */
    if (!PINFO_FD_VISITED(pinfo) && rlc_is_duplicate(RLC_AM, pinfo, seq, &orig_num, atm) == true) {
        g_hash_table_insert(duplicate_table, GUINT_TO_POINTER(pinfo->num), GUINT_TO_POINTER(orig_num));
        return;
    } else if (PINFO_FD_VISITED(pinfo) && tree) {
        void *value = g_hash_table_lookup(duplicate_table, GUINT_TO_POINTER(pinfo->num));
        if (value != NULL) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "[RLC AM Fragment] [Duplicate]  SN=%u %s", seq, (polling != 0) ? "(P)" : "");
            proto_tree_add_uint(tree, hf_rlc_duplicate_of, tvb, 0, 0, GPOINTER_TO_UINT(value));
            return;
        }
    }

    rlc_am_reassemble(tvb, offs, pinfo, tree, top_level, channel, seq, polling != 0,
                      li, num_li, ext == 2, li_is_on_2_bytes, atm);
}

/* dissect entry functions */
static int
dissect_rlc_pcch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *subtree = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC");
    col_clear(pinfo->cinfo, COL_INFO);

    /* PCCH is always RLC TM */
    if (tree) {
        proto_item *ti;
        ti = proto_tree_add_item(tree, proto_umts_rlc, tvb, 0, -1, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_rlc);
        proto_item_append_text(ti, " TM (PCCH)");
    }
    dissect_rlc_tm(RLC_PCCH, tvb, pinfo, tree, subtree);
    return tvb_captured_length(tvb);
}

static int
dissect_rlc_bcch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    fp_info    *fpi;
    proto_item *ti      = NULL;
    proto_tree *subtree = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC");
    col_clear(pinfo->cinfo, COL_INFO);

    fpi = (fp_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_fp, 0);
    if (!fpi) return 0; /* dissection failure */

    if (tree) {
        ti = proto_tree_add_item(tree, proto_umts_rlc, tvb, 0, -1, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_rlc);
    }
    proto_item_append_text(ti, " TM (BCCH)");
    dissect_rlc_tm(RLC_BCCH, tvb, pinfo, tree, subtree);
    return tvb_captured_length(tvb);
}

static int
dissect_rlc_ccch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    fp_info    *fpi;
    proto_item *ti      = NULL;
    proto_tree *subtree = NULL;
    struct atm_phdr *atm = (struct atm_phdr *)data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC");
    col_clear(pinfo->cinfo, COL_INFO);

    fpi = (fp_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_fp, 0);
    if (!fpi) return 0; /* dissection failure */

    if (tree) {
        ti = proto_tree_add_item(tree, proto_umts_rlc, tvb, 0, -1, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_rlc);
    }

    if (fpi->is_uplink) {
        /* UL CCCH is always RLC TM */
        proto_item_append_text(ti, " TM (CCCH)");
        dissect_rlc_tm(RLC_UL_CCCH, tvb, pinfo, tree, subtree);
    } else {
        /* DL CCCH is always UM */
        proto_item_append_text(ti, " UM (CCCH)");
        dissect_rlc_um(RLC_DL_CCCH, tvb, pinfo, tree, subtree, atm);
    }
    return tvb_captured_length(tvb);
}

static int
dissect_rlc_ctch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void  *data)
{
    fp_info    *fpi;
    proto_item *ti      = NULL;
    proto_tree *subtree = NULL;
    struct atm_phdr *atm = (struct atm_phdr *)data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC");
    col_clear(pinfo->cinfo, COL_INFO);

    fpi = (fp_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_fp, 0);
    if (!fpi) return 0; /* dissection failure */

    if (tree) {
        ti = proto_tree_add_item(tree, proto_umts_rlc, tvb, 0, -1, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_rlc);
    }

    /* CTCH is always UM */
    proto_item_append_text(ti, " UM (CTCH)");
    dissect_rlc_um(RLC_DL_CTCH, tvb, pinfo, tree, subtree, atm);
    return tvb_captured_length(tvb);
}

static int
dissect_rlc_dcch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item            *ti      = NULL;
    proto_tree            *subtree = NULL;
    fp_info               *fpi;
    rlc_info              *rlci;
    enum rlc_channel_type  channel;
    struct atm_phdr       *atm = (struct atm_phdr *)data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC");
    col_clear(pinfo->cinfo, COL_INFO);

    fpi = (fp_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_fp, 0);
    rlci = (rlc_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_umts_rlc, 0);

    if (!fpi || !rlci){
        proto_tree_add_expert(tree, pinfo, &ei_rlc_no_per_frame_data, tvb, 0, -1);
        return 1;
    }

    if (tree) {
        ti = proto_tree_add_item(tree, proto_umts_rlc, tvb, 0, -1, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_rlc);
    }

    channel = fpi->is_uplink ? RLC_UL_DCCH : RLC_DL_DCCH;

    switch (rlci->mode[fpi->cur_tb]) {
        case RLC_UM:
            proto_item_append_text(ti, " UM (DCCH)");
            dissect_rlc_um(channel, tvb, pinfo, tree, subtree, atm);
            break;
        case RLC_AM:
            proto_item_append_text(ti, " AM (DCCH)");
            dissect_rlc_am(channel, tvb, pinfo, tree, subtree, atm);
            break;
    }
    return tvb_captured_length(tvb);
}

static int
dissect_rlc_ps_dtch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *ti      = NULL;
    proto_tree *subtree = NULL;
    fp_info    *fpi;
    rlc_info   *rlci;
    struct atm_phdr *atm = (struct atm_phdr *)data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC");
    col_clear(pinfo->cinfo, COL_INFO);

    fpi  = (fp_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_fp, 0);
    rlci = (rlc_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_umts_rlc, 0);

    if (!fpi || !rlci) {
        proto_tree_add_expert(tree, pinfo, &ei_rlc_no_per_frame_data, tvb, 0, -1);
        return 1;
    }

    if (tree) {
        ti = proto_tree_add_item(tree, proto_umts_rlc, tvb, 0, -1, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_rlc);
    }

    switch (rlci->mode[fpi->cur_tb]) {
        case RLC_UM:
            proto_item_append_text(ti, " UM (PS DTCH)");
            dissect_rlc_um(RLC_PS_DTCH, tvb, pinfo, tree, subtree, atm);
            break;
        case RLC_AM:
            proto_item_append_text(ti, " AM (PS DTCH)");
            dissect_rlc_am(RLC_PS_DTCH, tvb, pinfo, tree, subtree, atm);
            break;
        case RLC_TM:
            proto_item_append_text(ti, " TM (PS DTCH)");
            dissect_rlc_tm(RLC_PS_DTCH, tvb, pinfo, tree, subtree);
            break;
    }
    return tvb_captured_length(tvb);
}

static int
dissect_rlc_dch_unknown(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *ti      = NULL;
    proto_tree *subtree = NULL;
    fp_info    *fpi;
    rlc_info   *rlci;
    struct atm_phdr *atm = (struct atm_phdr *)data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC");
    col_clear(pinfo->cinfo, COL_INFO);

    fpi = (fp_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_fp, 0);
    rlci = (rlc_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_umts_rlc, 0);

    if (!fpi || !rlci) return 0;

    if (tree) {
        ti = proto_tree_add_item(tree, proto_umts_rlc, tvb, 0, -1, ENC_NA);
        subtree = proto_item_add_subtree(ti, ett_rlc);
    }

    switch (rlci->mode[fpi->cur_tb]) {
        case RLC_UM:
            proto_item_append_text(ti, " UM (Unknown)");
            dissect_rlc_um(RLC_UNKNOWN_CH, tvb, pinfo, tree, subtree, atm);
            break;
        case RLC_AM:
            proto_item_append_text(ti, " AM (Unknown)");
            dissect_rlc_am(RLC_UNKNOWN_CH, tvb, pinfo, tree, subtree, atm);
            break;
        case RLC_TM:
            proto_item_append_text(ti, " TM (Unknown)");
            dissect_rlc_tm(RLC_UNKNOWN_CH, tvb, pinfo, tree, subtree);
            break;
    }
    return tvb_captured_length(tvb);
}

static void
report_heur_error(proto_tree *tree, packet_info *pinfo, expert_field *eiindex,
                  tvbuff_t *tvb, int start, int length)
{
    proto_item *ti;
    proto_tree *subtree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC");
    col_clear(pinfo->cinfo, COL_INFO);
    ti = proto_tree_add_item(tree, proto_umts_rlc, tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_rlc);
    proto_tree_add_expert(subtree, pinfo, eiindex, tvb, start, length);
}

/* Heuristic dissector looks for supported framing protocol (see wiki page)  */
static bool
dissect_rlc_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int         offset             = 0;
    fp_info    *fpi;
    rlc_info   *rlci;
    tvbuff_t   *rlc_tvb;
    uint8_t     tag                = 0;
    unsigned    channelType        = UMTS_CHANNEL_TYPE_UNSPECIFIED;
    bool        fpInfoAlreadySet   = false;
    bool        rlcInfoAlreadySet  = false;
    bool        channelTypePresent = false;
    bool        rlcModePresent     = false;
    proto_item *ti                 = NULL;
    proto_tree *subtree            = NULL;
    struct atm_phdr *atm           = (struct atm_phdr *)data;

    /* Do this again on re-dissection to re-discover offset of actual PDU */

    /* Needs to be at least as long as:
       - the signature string
       - conditional header bytes
       - tag for data
       - at least one byte of RLC PDU payload */
    if (tvb_captured_length_remaining(tvb, offset) < (int)(strlen(RLC_START_STRING)+2+2)) {
        return false;
    }

    /* OK, compare with signature string */
    if (tvb_strneql(tvb, offset, RLC_START_STRING, (int)strlen(RLC_START_STRING)) != 0) {
        return false;
    }
    offset += (int)strlen(RLC_START_STRING);

    /* If redissecting, use previous info struct (if available) */
    fpi = (fp_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_fp, 0);
    if (fpi == NULL) {
        /* Allocate new info struct for this frame */
        fpi = wmem_new0(wmem_file_scope(), fp_info);
    } else {
        fpInfoAlreadySet = true;
    }
    rlci = (rlc_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_umts_rlc, 0);
    if (rlci == NULL) {
        /* Allocate new info struct for this frame */
        rlci = wmem_new0(wmem_file_scope(), rlc_info);
    } else {
        rlcInfoAlreadySet = true;
    }

    /* Setting non-zero UE-ID for RLC reassembly to work, might be
     * overriden if the optional URNTI tag is present */
    rlci->ueid[fpi->cur_tb] = 1;

    /* Read conditional/optional fields */
    while (tag != RLC_PAYLOAD_TAG) {
        /* Process next tag */
        tag = tvb_get_uint8(tvb, offset++);
        switch (tag) {
            case RLC_CHANNEL_TYPE_TAG:
                channelType = tvb_get_uint8(tvb, offset);
                offset++;
                channelTypePresent = true;
                break;
            case RLC_MODE_TAG:
                rlci->mode[fpi->cur_tb] = tvb_get_uint8(tvb, offset);
                offset++;
                rlcModePresent = true;
                break;
            case RLC_DIRECTION_TAG:
                if (tvb_get_uint8(tvb, offset) == DIRECTION_UPLINK) {
                    fpi->is_uplink = true;
                    pinfo->link_dir = P2P_DIR_UL;
                } else {
                    fpi->is_uplink = false;
                    pinfo->link_dir = P2P_DIR_DL;
                }
                offset++;
                break;
            case RLC_URNTI_TAG:
                rlci->ueid[fpi->cur_tb] = tvb_get_ntohl(tvb, offset);
                offset += 4;
                break;
            case RLC_RADIO_BEARER_ID_TAG:
                rlci->rbid[fpi->cur_tb] = tvb_get_uint8(tvb, offset);
                offset++;
                break;
            case RLC_LI_SIZE_TAG:
                rlci->li_size[fpi->cur_tb] = (enum rlc_li_size) tvb_get_uint8(tvb, offset);
                offset++;
                break;
            case RLC_PAYLOAD_TAG:
                /* Have reached data, so get out of loop */
                continue;
            default:
                /* It must be a recognised tag */
                report_heur_error(tree, pinfo, &ei_rlc_unknown_udp_framing_tag, tvb, offset-1, 1);
                return true;
        }
    }

    if ((channelTypePresent == false) && (rlcModePresent == false)) {
        /* Conditional fields are missing */
        report_heur_error(tree, pinfo, &ei_rlc_missing_udp_framing_tag, tvb, 0, offset);
        return true;
    }

    /* Store info in packet if needed */
    if (!fpInfoAlreadySet) {
        p_add_proto_data(wmem_file_scope(), pinfo, proto_fp, 0, fpi);
    }
    if (!rlcInfoAlreadySet) {
        p_add_proto_data(wmem_file_scope(), pinfo, proto_umts_rlc, 0, rlci);
    }

    /**************************************/
    /* OK, now dissect as RLC             */

    /* Create tvb that starts at actual RLC PDU */
    rlc_tvb = tvb_new_subset_remaining(tvb, offset);
    switch (channelType) {
        case UMTS_CHANNEL_TYPE_UNSPECIFIED:
            /* Call relevant dissector according to RLC mode */
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "RLC");
            col_clear(pinfo->cinfo, COL_INFO);

            if (tree) {
                ti = proto_tree_add_item(tree, proto_umts_rlc, rlc_tvb, 0, -1, ENC_NA);
                subtree = proto_item_add_subtree(ti, ett_rlc);
            }

            if (rlci->mode[fpi->cur_tb] == RLC_AM) {
                proto_item_append_text(ti, " AM");
                dissect_rlc_am(RLC_UNKNOWN_CH, rlc_tvb, pinfo, tree, subtree, atm);
            } else if (rlci->mode[fpi->cur_tb] == RLC_UM) {
                proto_item_append_text(ti, " UM");
                dissect_rlc_um(RLC_UNKNOWN_CH, rlc_tvb, pinfo, tree, subtree, atm);
            } else {
                proto_item_append_text(ti, " TM");
                dissect_rlc_tm(RLC_UNKNOWN_CH, rlc_tvb, pinfo, tree, subtree);
            }
            break;
        case UMTS_CHANNEL_TYPE_PCCH:
            dissect_rlc_pcch(rlc_tvb, pinfo, tree, data);
            break;
        case UMTS_CHANNEL_TYPE_CCCH:
            dissect_rlc_ccch(rlc_tvb, pinfo, tree, data);
            break;
        case UMTS_CHANNEL_TYPE_DCCH:
            dissect_rlc_dcch(rlc_tvb, pinfo, tree, data);
            break;
        case UMTS_CHANNEL_TYPE_PS_DTCH:
            dissect_rlc_ps_dtch(rlc_tvb, pinfo, tree, data);
            break;
        case UMTS_CHANNEL_TYPE_CTCH:
            dissect_rlc_ctch(rlc_tvb, pinfo, tree, data);
            break;
        case UMTS_CHANNEL_TYPE_BCCH:
            dissect_rlc_bcch(rlc_tvb, pinfo, tree, data);
            break;
        default:
            /* Unknown channel type */
            return false;
    }

    return true;
}

void
proto_register_rlc(void)
{
    module_t *rlc_module;
    expert_module_t* expert_rlc;
    static hf_register_info hf[] = {
        { &hf_rlc_dc,
          { "D/C Bit", "rlc.dc",
            FT_BOOLEAN, BASE_NONE, TFS(&rlc_dc_val), 0, NULL, HFILL }
        },
        { &hf_rlc_ctrl_type,
          { "Control PDU Type", "rlc.ctrl_pdu_type",
            FT_UINT8, BASE_DEC, VALS(rlc_ctrl_vals), 0, NULL, HFILL }
        },
        { &hf_rlc_r1,
          { "Reserved 1", "rlc.r1",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_rsn,
          { "Reset Sequence Number", "rlc.rsn",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_hfni,
          { "Hyper Frame Number Indicator", "rlc.hfni",
            FT_UINT24, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_seq,
          { "Sequence Number", "rlc.seq",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_ext,
          { "Extension Bit", "rlc.ext",
            FT_BOOLEAN, BASE_NONE, TFS(&rlc_ext_val), 0, NULL, HFILL }
        },
        { &hf_rlc_he,
          { "Header Extension Type", "rlc.he",
            FT_UINT8, BASE_DEC, VALS(rlc_he_vals), 0, NULL, HFILL }
        },
        { &hf_rlc_p,
          { "Polling Bit", "rlc.p",
            FT_BOOLEAN, BASE_NONE, TFS(&rlc_p_val), 0, NULL, HFILL }
        },
        { &hf_rlc_pad,
          { "Padding", "rlc.padding",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_reassembled_data,
          { "Reassembled RLC Data", "rlc.reassembled_data",
            FT_BYTES, BASE_NONE, NULL, 0, "The reassembled payload", HFILL }
        },
        { &hf_rlc_frags,
          { "Reassembled Fragments", "rlc.fragments",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_frag,
          { "RLC Fragment", "rlc.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_duplicate_of,
          { "Duplicate of", "rlc.duplicate_of",
            FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_reassembled_in,
          { "Reassembled Message in frame", "rlc.reassembled_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_data,
          { "Data", "rlc.data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_ciphered_data,
          { "Ciphered Data", "rlc.ciphered_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_ciphered_lis_data,
          { "Ciphered LIs & Data", "rlc.ciphered_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        /* LI information */
        { &hf_rlc_li,
          { "LI", "rlc.li",
            FT_NONE, BASE_NONE, NULL, 0, "Length Indicator", HFILL }
        },
        { &hf_rlc_li_value,
          { "LI value", "rlc.li.value",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_li_ext,
          { "LI extension bit", "rlc.li.ext",
            FT_BOOLEAN, BASE_NONE, TFS(&rlc_ext_val), 0, NULL, HFILL }
        },
        { &hf_rlc_li_data,
          { "LI Data", "rlc.li.data",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        /* SUFI information */
        { &hf_rlc_sufi,
          { "SUFI", "rlc.sufi",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_sufi_type,
          { "SUFI Type", "rlc.sufi.type",
            FT_UINT8, BASE_DEC, VALS(rlc_sufi_vals), 0, NULL, HFILL }
        },
        { &hf_rlc_sufi_lsn,
          { "Last Sequence Number", "rlc.sufi.lsn",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_sufi_wsn,
          { "Window Size Number", "rlc.sufi.wsn",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_sufi_sn,
          { "Sequence Number", "rlc.sufi.sn",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_sufi_l,
          { "Length", "rlc.sufi.l",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_sufi_len,
          { "Length", "rlc.sufi.len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_sufi_fsn,
          { "First Sequence Number", "rlc.sufi.fsn",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_sufi_bitmap,
          { "Bitmap", "rlc.sufi.bitmap",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_sufi_cw,
          { "Codeword", "rlc.sufi.cw",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_sufi_n,
          { "Nlength", "rlc.sufi.n",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_sufi_sn_ack,
          { "SN ACK", "rlc.sufi.sn_ack",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_sufi_sn_mrw,
          { "SN MRW", "rlc.sufi.sn_mrw",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_sufi_poll_sn,
          { "Poll SN", "rlc.sufi.poll_sn",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        /* Other information */
        { &hf_rlc_header_only,
          { "RLC PDU header only", "rlc.header_only",
            FT_BOOLEAN, BASE_NONE, TFS(&rlc_header_only_val), 0 ,NULL, HFILL }
        },
        { &hf_rlc_channel,
          { "Channel", "rlc.channel",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_channel_rbid,
          { "Radio Bearer ID", "rlc.channel.rbid",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_channel_dir,
          { "Direction", "rlc.channel.dir",
            FT_UINT8, BASE_DEC, VALS(rlc_dir_vals), 0, NULL, HFILL }
        },
        { &hf_rlc_channel_ueid,
          { "User Equipment ID", "rlc.channel.ueid",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_sequence_number,
          { "Sequence Number", "rlc.sequence_number",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_length,
          { "Length", "rlc.length",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_rlc_bitmap_string,
          { "Bitmap string", "rlc.bitmap_string",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_rlc,
        &ett_rlc_frag,
        &ett_rlc_fragments,
        &ett_rlc_sdu,
        &ett_rlc_sufi,
        &ett_rlc_bitmap,
        &ett_rlc_rlist,
        &ett_rlc_channel
    };
    static ei_register_info ei[] = {
        { &ei_rlc_reassembly_fail_unfinished_sequence, { "rlc.reassembly.fail.unfinished_sequence", PI_REASSEMBLE, PI_ERROR, "Did not perform reassembly because of previous unfinished sequence.", EXPFILL }},
        { &ei_rlc_reassembly_fail_flag_set, { "rlc.reassembly.fail.flag_set", PI_REASSEMBLE, PI_ERROR, "Did not perform reassembly because fail flag was set previously.", EXPFILL }},
        { &ei_rlc_reassembly_lingering_endpoint, { "rlc.lingering_endpoint", PI_REASSEMBLE, PI_ERROR, "Lingering endpoint.", EXPFILL }},
        { &ei_rlc_reassembly_unknown_error, { "rlc.reassembly.unknown_error", PI_REASSEMBLE, PI_ERROR, "Unknown error.", EXPFILL }},
        { &ei_rlc_kasumi_implementation_missing, { "rlc.kasumi_implementation_missing", PI_UNDECODED, PI_WARN, "Unable to decipher packet since KASUMI implementation is missing.", EXPFILL }},
        { &ei_rlc_li_reserved, { "rlc.li.reserved", PI_PROTOCOL, PI_WARN, "Uses reserved LI", EXPFILL }},
        { &ei_rlc_li_incorrect_warn, { "rlc.li.incorrect", PI_PROTOCOL, PI_WARN, "Incorrect LI value", EXPFILL }},
        { &ei_rlc_li_incorrect_mal, { "rlc.li.incorrect", PI_MALFORMED, PI_ERROR, "Incorrect LI value 0x%x", EXPFILL }},
        { &ei_rlc_li_too_many, { "rlc.li.too_many", PI_MALFORMED, PI_ERROR, "Too many LI entries", EXPFILL }},
        { &ei_rlc_header_only, { "rlc.header_only.expert", PI_SEQUENCE, PI_NOTE, "RLC PDU SDUs have been omitted", EXPFILL }},
        { &ei_rlc_sufi_len, { "rlc.sufi.len.invalid", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
        { &ei_rlc_sufi_cw, { "rlc.sufi.cw.invalid", PI_PROTOCOL, PI_WARN, "Invalid last codeword", EXPFILL }},
        { &ei_rlc_sufi_type, { "rlc.sufi.type.invalid", PI_PROTOCOL, PI_WARN, "Invalid SUFI type", EXPFILL }},
        { &ei_rlc_reserved_bits_not_zero, { "rlc.reserved_bits_not_zero", PI_PROTOCOL, PI_WARN, "reserved bits not zero", EXPFILL }},
        { &ei_rlc_ctrl_type, { "rlc.ctrl_pdu_type.invalid", PI_PROTOCOL, PI_WARN, "Invalid RLC AM control type", EXPFILL }},
        { &ei_rlc_he, { "rlc.he.invalid", PI_PROTOCOL, PI_WARN, "Incorrect HE value", EXPFILL }},
        { &ei_rlc_ciphered_data, { "rlc.ciphered", PI_UNDECODED, PI_WARN, "Cannot dissect RLC frame because it is ciphered", EXPFILL }},
        { &ei_rlc_no_per_frame_data, { "rlc.no_per_frame_data", PI_PROTOCOL, PI_WARN, "Can't dissect RLC frame because no per-frame info was attached!", EXPFILL }},
        { &ei_rlc_incomplete_sequence, { "rlc.incomplete_sequence", PI_MALFORMED, PI_ERROR, "Error: Incomplete sequence", EXPFILL }},
        { &ei_rlc_unknown_udp_framing_tag, { "rlc.unknown_udp_framing_tag", PI_UNDECODED, PI_WARN, "Unknown UDP framing tag, aborting dissection", EXPFILL }},
        { &ei_rlc_missing_udp_framing_tag, { "rlc.missing_udp_framing_tag", PI_UNDECODED, PI_WARN, "Missing UDP framing conditional tag, aborting dissection", EXPFILL }}
    };

    proto_umts_rlc = proto_register_protocol("Radio Link Control", "RLC", "rlc");
    register_dissector("rlc.bcch",        dissect_rlc_bcch,        proto_umts_rlc);
    register_dissector("rlc.pcch",        dissect_rlc_pcch,        proto_umts_rlc);
    register_dissector("rlc.ccch",        dissect_rlc_ccch,        proto_umts_rlc);
    register_dissector("rlc.ctch",        dissect_rlc_ctch,        proto_umts_rlc);
    register_dissector("rlc.dcch",        dissect_rlc_dcch,        proto_umts_rlc);
    register_dissector("rlc.ps_dtch",     dissect_rlc_ps_dtch,     proto_umts_rlc);
    register_dissector("rlc.dch_unknown", dissect_rlc_dch_unknown, proto_umts_rlc);

    proto_register_field_array(proto_umts_rlc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_rlc = expert_register_protocol(proto_umts_rlc);
    expert_register_field_array(expert_rlc, ei, array_length(ei));

    /* Preferences */
    rlc_module = prefs_register_protocol(proto_umts_rlc, NULL);

    prefs_register_obsolete_preference(rlc_module, "heuristic_rlc_over_udp");

    prefs_register_bool_preference(rlc_module, "perform_reassembly",
        "Try to reassemble SDUs",
        "When enabled, try to reassemble SDUs from the various PDUs received",
        &global_rlc_perform_reassemby);

    prefs_register_bool_preference(rlc_module, "header_only_mode",
        "May see RLC headers only",
        "When enabled, if data is not present, don't report as an error, but instead "
        "add expert info to indicate that headers were omitted",
        &global_rlc_headers_expected);

    prefs_register_bool_preference(rlc_module, "ignore_rrc_cipher_indication",
        "Ignore ciphering indication from higher layers",
        "When enabled, RLC will ignore sequence numbers reported in 'Security Mode Command'/'Security Mode Complete' (RRC) messages when checking if frames are ciphered",
        &global_ignore_rrc_ciphering_indication);

    prefs_register_bool_preference(rlc_module, "ciphered_data",
        "All data is ciphered",
        "When enabled, RLC will assume all payloads in RLC frames are ciphered",
        &global_rlc_ciphered);

#ifdef HAVE_UMTS_KASUMI
    prefs_register_bool_preference(rlc_module, "try_decipher",
        "Try to decipher data",
        "When enabled, RLC will try to decipher data. (Experimental)",
        &global_rlc_try_decipher);

    prefs_register_string_preference(rlc_module, "kasumi_key",
        "KASUMI key", "Key for kasumi 32 characters long hex-string", &global_rlc_kasumi_key);
#else
    /* If Wireshark isn't compiled with KASUMI we still want to register the above preferences
     * We are doing so for two reasons:
     * 1. To inform the user about the disabled preferences (using static text preference)
     * 2. To prevent errors when Wireshark reads a preferences file which includes records for these preferences
     */
    prefs_register_static_text_preference(rlc_module, "try_decipher",
        "Data deciphering is disabled", "Wireshark was compiled without the KASUMI decryption algorithm");

    prefs_register_obsolete_preference(rlc_module, "kasumi_key");
#endif /* HAVE_UMTS_KASUMI */

    prefs_register_enum_preference(rlc_module, "li_size",
        "LI size",
        "LI size in bits, either 7 or 15 bit",
        &global_rlc_li_size, li_size_enumvals, false);

    register_init_routine(fragment_table_init);
    register_cleanup_routine(fragment_table_cleanup);
}

void
proto_reg_handoff_rlc(void)
{
    rrc_handle = find_dissector_add_dependency("rrc", proto_umts_rlc);
    ip_handle  = find_dissector_add_dependency("ip", proto_umts_rlc);
    bmc_handle = find_dissector_add_dependency("bmc", proto_umts_rlc);
    /* Add as a heuristic UDP dissector */
    heur_dissector_add("udp", dissect_rlc_heur, "RLC over UDP", "rlc_udp", proto_umts_rlc, HEURISTIC_DISABLE);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

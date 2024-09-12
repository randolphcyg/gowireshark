/* packet-ippusb.c
 * Routines for IPPUSB packet disassembly
 * https://robots.org.uk/IPPOverUSB
 *
 * Jamie Hare <jamienh@umich.edu>
 *
 * PROTONAME: Internet Printing Protocol Over USB
 * PROTOSHORTNAME: IPPUSB
 * PROTOABBREV: ippusb
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include <epan/conversation.h>
#include <epan/wmem_scopes.h>
#include <reassemble.h>
#include "packet-usb.h"

/*
 * IPPUSB transfer_type values
 */
#define HTTP 0

/* As also defined in IPP dissector */
#define PRINT_JOB              0x0002
#define SEND_DOCUMENT          0x0006

#define TAG_END_OF_ATTRIBUTES 0x03
#define NEWLINE 0x0a

#define CHUNK_LENGTH_MIN 5

#define BITS_PER_BYTE 8

static const uint8_t CHUNKED_END[] = { 0x30, 0x0d, 0x0a, 0x0d, 0x0a };
static const uint8_t RETURN_NEWLINE[] = { 0x0d, 0x0a };
static tvbuff_t *return_newline_tvb;

void proto_register_ippusb(void);
void proto_reg_handoff_ippusb(void);
static int is_http_header(unsigned first_linelen, const unsigned char *first_line);

static dissector_handle_t ippusb_handle;

static int proto_ippusb;
static int ett_ippusb;
static int ett_ippusb_as;
static int ett_ippusb_attr;
static int ett_ippusb_member;
static int ett_ippusb_fragment;
static int ett_ippusb_fragments;

/* For reassembly */
static int32_t ippusb_last_pdu = -1;

static int hf_ippusb_fragments;
static int hf_ippusb_fragment;
static int hf_ippusb_fragment_overlap;
static int hf_ippusb_fragment_overlap_conflict;
static int hf_ippusb_fragment_multiple_tails;
static int hf_ippusb_fragment_too_long_fragment;
static int hf_ippusb_fragment_error;
static int hf_ippusb_fragment_count;
static int hf_ippusb_reassembled_in;
static int hf_ippusb_reassembled_length;
static int hf_ippusb_reassembled_data;

/* Reassemble by default */
static bool global_ippusb_reassemble = true;

static const fragment_items ippusb_frag_items = {
    &ett_ippusb_fragment,
    &ett_ippusb_fragments,
    &hf_ippusb_fragments,
    &hf_ippusb_fragment,
    &hf_ippusb_fragment_overlap,
    &hf_ippusb_fragment_overlap_conflict,
    &hf_ippusb_fragment_multiple_tails,
    &hf_ippusb_fragment_too_long_fragment,
    &hf_ippusb_fragment_error,
    &hf_ippusb_fragment_count,
    &hf_ippusb_reassembled_in,
    &hf_ippusb_reassembled_length,
    &hf_ippusb_reassembled_data,
    "IPPUSB fragments"
};

struct ippusb_multisegment_pdu {
    unsigned nxtpdu;
    uint32_t first_frame;
    uint32_t running_size;
    bool finished;
    bool reassembled;
    bool is_ipp;

    uint32_t document;
    #define MSP_HAS_DOCUMENT        0x00000001
    #define MSP_DOCUMENT_TRUNCATED  0x00000002

    uint32_t flags;
    #define MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT	0x00000001
    #define MSP_FLAGS_GOT_ALL_SEGMENTS          0x00000002
    #define MSP_FLAGS_MISSING_FIRST_SEGMENT     0x00000004
};

static struct ippusb_multisegment_pdu *
pdu_store(packet_info *pinfo, wmem_tree_t *multisegment_pdus, uint32_t first_frame, bool is_ipp, unsigned document)
{
    struct ippusb_multisegment_pdu *msp;

    msp = wmem_new(wmem_file_scope(), struct ippusb_multisegment_pdu);
    msp->first_frame = first_frame;
    msp->finished = false;
    msp->reassembled = false;
    msp->is_ipp = is_ipp;
    msp->document = document;
    msp->flags = 0;
    wmem_tree_insert32(multisegment_pdus, pinfo->num, (void *)msp);

    return msp;
}

struct ippusb_analysis {
    wmem_tree_t *multisegment_pdus;
};

static struct ippusb_analysis *
init_ippusb_conversation_data(void)
{
    struct ippusb_analysis *ippusbd;

    ippusbd = wmem_new0(wmem_file_scope(), struct ippusb_analysis);

    ippusbd->multisegment_pdus = wmem_tree_new(wmem_file_scope());

    return ippusbd;
}

static struct ippusb_analysis *
get_ippusb_conversation_data(conversation_t *conv, packet_info *pinfo)
{
    struct ippusb_analysis *ippusbd;

    if(conv == NULL ) {
        conv = find_or_create_conversation(pinfo);
    }

    ippusbd = (struct ippusb_analysis *)conversation_get_proto_data(conv, proto_ippusb);

    if (!ippusbd) {
        ippusbd = init_ippusb_conversation_data();
        conversation_add_proto_data(conv, proto_ippusb, ippusbd);
    }

    return ippusbd;
}


static void *ippusb_temporary_key(const packet_info *pinfo _U_, const uint32_t id _U_, const void *data)
{
    return (void *)data;
}

static void *ippusb_persistent_key(const packet_info *pinfo _U_, const uint32_t id _U_, const void *data)
{
    return (void *)data;
}

static void ippusb_free_temporary_key(void *ptr _U_) { }

static void ippusb_free_persistent_key(void *ptr _U_) { }

static reassembly_table_functions ippusb_reassembly_table_functions =
{
    g_direct_hash,
    g_direct_equal,
    ippusb_temporary_key,
    ippusb_persistent_key,
    ippusb_free_temporary_key,
    ippusb_free_persistent_key
};

static dissector_table_t ippusb_dissector_table;
static reassembly_table ippusb_reassembly_table;

/* Main dissector function */
static int
dissect_ippusb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    int offset = 0;
    int ret = 0;
    unsigned first_linelen;
    const unsigned char *first_line;
    int next_offset;
    uint8_t last;
    uint8_t status_code;
    struct ippusb_analysis *ippusbd = NULL;
    conversation_t *conv = NULL;

    struct ippusb_multisegment_pdu *new_msp = NULL;
    struct ippusb_multisegment_pdu *current_msp = NULL;
    struct ippusb_multisegment_pdu *previous_msp = NULL;

    int reported_length = tvb_reported_length(tvb);
    int captured_length = tvb_captured_length(tvb);

    if((conv = find_conversation_pinfo(pinfo, 0)) != NULL) {
        /* Update how far the conversation reaches */
        if (pinfo->num > conv->last_frame) {
            conv->last_frame = pinfo->num;
        }
    }
    else {
        conv = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, CONVERSATION_TCP,
                     pinfo->srcport, pinfo->destport, 0);
    }

    ippusbd = get_ippusb_conversation_data(conv, pinfo);

    first_linelen = tvb_find_line_end(tvb, offset, tvb_ensure_captured_length_remaining(tvb, offset), &next_offset, true);
    first_line = tvb_get_ptr(tvb, offset, first_linelen);

    /* Get last byte of segment */
    last = tvb_get_uint8(tvb, captured_length - 1);
    status_code = tvb_get_bits8(tvb, 3 * BITS_PER_BYTE, BITS_PER_BYTE);

    /* Is the segment the last chunk from chunk transfer? */
    bool is_last_chunk = false;
    if (captured_length == CHUNK_LENGTH_MIN) {
        is_last_chunk = tvb_memeql(tvb, offset, CHUNKED_END, CHUNK_LENGTH_MIN) == 0;
    }

    if (is_http_header(first_linelen, first_line) && last == TAG_END_OF_ATTRIBUTES && status_code != PRINT_JOB && status_code != SEND_DOCUMENT) {
        /* An individual ippusb packet with http header */

        proto_tree_add_item(tree, proto_ippusb, tvb, offset, -1, ENC_NA);

        if (ippusb_last_pdu >= 0 && !pinfo->fd->visited) {
            ippusb_last_pdu = -1;
        }

        ret = dissector_try_uint_new(ippusb_dissector_table, HTTP, tvb, pinfo, tree, true, data);
    }
    else if (global_ippusb_reassemble) {
        /* If reassembly is wanted */

        if (!pinfo->fd->visited) {
            /* First time this segment is ever seen */

            bool save_fragmented = pinfo->fragmented;
            pinfo->fragmented = true;

            proto_tree_add_item(tree, proto_ippusb, tvb, offset, -1, ENC_NA);

            if (is_http_header(first_linelen, first_line)) {
                /* The start of a new packet that will need to be reassembled */

                new_msp = pdu_store(pinfo, ippusbd->multisegment_pdus, pinfo->num, true, 0);
                new_msp->running_size = captured_length;

                fragment_add_check(&ippusb_reassembly_table, tvb, offset, pinfo, new_msp->first_frame,
                                            GUINT_TO_POINTER(new_msp->first_frame), 0, captured_length, true);

                ippusb_last_pdu = pinfo->num;
            }
            else {

                previous_msp = (struct ippusb_multisegment_pdu *)wmem_tree_lookup32_le(ippusbd->multisegment_pdus, ippusb_last_pdu);

                if (previous_msp) {
                    previous_msp->nxtpdu = pinfo->num;
                    new_msp = pdu_store(pinfo, ippusbd->multisegment_pdus, previous_msp->first_frame, previous_msp->is_ipp, previous_msp->document);
                    new_msp->running_size = previous_msp->running_size + captured_length;

                    /* This packet has an HTTP header but is not an ipp packet */
                    if ((first_linelen >= strlen("Content-Type: ") && strncmp(first_line, "Content-Type: ", strlen("Content-Type: ")) == 0) &&
                        (first_linelen < strlen("Content-Type: application/ipp") || strncmp(first_line, "Content-Type: application/ipp", strlen("Content-Type: application/ipp")) != 0)) {
                        new_msp->is_ipp = false;
                    }

                    /* This packet will have an attached document */
                    if (status_code == PRINT_JOB || status_code == SEND_DOCUMENT) {
                        new_msp->document |= MSP_HAS_DOCUMENT;
                    }

                    if (!is_last_chunk) {
                        /* If this segment is not the last chunk in a chunked transfer */

                        if (captured_length < reported_length && (new_msp->document & MSP_HAS_DOCUMENT)) {
                            /* The attached document segment is smaller than it says it should be and cannot be reassembled properly */

                            tvbuff_t *new_tvb = tvb_new_subset_length(tvb, 0, captured_length);

                            fragment_add_check(&ippusb_reassembly_table, new_tvb, offset, pinfo, new_msp->first_frame,
                                            GUINT_TO_POINTER(new_msp->first_frame), previous_msp->running_size, captured_length, true);

                            new_msp->document |= MSP_DOCUMENT_TRUNCATED;
                        }
                        else {
                            fragment_add_check(&ippusb_reassembly_table, tvb, offset, pinfo, new_msp->first_frame,
                                            GUINT_TO_POINTER(new_msp->first_frame), previous_msp->running_size, captured_length, true);
                        }

                        if (last != NEWLINE) {
                            fragment_add_check(&ippusb_reassembly_table, return_newline_tvb, offset, pinfo, new_msp->first_frame,
                                            GUINT_TO_POINTER(new_msp->first_frame), new_msp->running_size, sizeof(RETURN_NEWLINE), true);

                            new_msp->running_size += sizeof(RETURN_NEWLINE);
                        }

                        ippusb_last_pdu = pinfo->num;
                    }
                    else {
                        /* This segment contains the end of ipp chunked transfer information */

                        new_msp->finished = true;
                        ippusb_last_pdu = -1;

                        fragment_head *head = fragment_add_check(&ippusb_reassembly_table, tvb, offset, pinfo, new_msp->first_frame,
                                                            GUINT_TO_POINTER(new_msp->first_frame), previous_msp->running_size, captured_length, false);
                        tvbuff_t *processed_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled IPPUSB", head, &ippusb_frag_items, NULL, tree);

                        new_msp->reassembled = true;
                        pinfo->can_desegment = 0;

                        if(processed_tvb){
                            ret = dissector_try_uint_new(ippusb_dissector_table, HTTP, processed_tvb, pinfo, tree, true, data);
                            col_append_str(pinfo->cinfo, COL_INFO, " Reassembled Data");
                        }
                    }
                }

                pinfo->fragmented = save_fragmented;
            }
        }
        else {
            /* Not the first time this segment is seen */

            bool save_fragmented = pinfo->fragmented;
            pinfo->fragmented = true;
            current_msp = (struct ippusb_multisegment_pdu *)wmem_tree_lookup32_le(ippusbd->multisegment_pdus, pinfo->num);

            /* This is not an ipp packet */
            if(current_msp && !(current_msp->is_ipp)){
                return captured_length;
            }

            if (current_msp && !current_msp->finished && current_msp->nxtpdu == 0) {
                /* This is a packet that was not completed and assembly will be attempted */

                proto_tree_add_item(tree, proto_ippusb, tvb, offset, -1, ENC_NA);
                fragment_head *head;

                if (!current_msp->reassembled) {
                    /* The first time this segment is passed over after the initial round
                     * it will be added to the pdu and reassembled */

                    pinfo->fd->visited = false;

                    if (captured_length < reported_length && (current_msp->document & MSP_HAS_DOCUMENT)) {
                        /* The attached document segment is smaller than it says it should be and cannot be reassembled properly */

                        tvbuff_t *new_tvb = tvb_new_subset_length(tvb, 0, captured_length);

                        head = fragment_add_check(&ippusb_reassembly_table, new_tvb, offset, pinfo, current_msp->first_frame,
                                            GUINT_TO_POINTER(current_msp->first_frame), current_msp->running_size - captured_length, captured_length, false);

                        current_msp->document |= MSP_DOCUMENT_TRUNCATED;
                    }
                    else {
                         head = fragment_add_check(&ippusb_reassembly_table, tvb, 0, pinfo, current_msp->first_frame,
                                            GUINT_TO_POINTER(current_msp->first_frame), current_msp->running_size - captured_length, captured_length, false);
                    }

                    pinfo->fd->visited = true;

                    current_msp->reassembled = true;
                }
                else {
                    /* Packet has already been reassembled */

                    head = fragment_get_reassembled_id(&ippusb_reassembly_table, pinfo, current_msp->first_frame);
                }

                tvbuff_t *processed_tvb = process_reassembled_data(tvb, offset, pinfo, " Reassembled IPPUSB", head, &ippusb_frag_items, NULL, tree);

                if (processed_tvb) {
                    pinfo->can_desegment = 0;

                    ret = dissector_try_uint_new(ippusb_dissector_table, HTTP, processed_tvb, pinfo, tree, true, data);

                    if (current_msp->document & MSP_DOCUMENT_TRUNCATED) {
                        col_append_str(pinfo->cinfo, COL_INFO, " Document Truncated");
                    }
                }
            }
            else if (current_msp && is_last_chunk) {
                /* This is the last segment of the chunked transfer and reassembled packet */

                proto_tree_add_item(tree, proto_ippusb, tvb, offset, -1, ENC_NA);

                fragment_head *head = fragment_get_reassembled_id(&ippusb_reassembly_table, pinfo, current_msp->first_frame);

                tvbuff_t *processed_tvb = process_reassembled_data(tvb, offset, pinfo, " Reassembled IPPUSB", head, &ippusb_frag_items, NULL, tree);

                if (processed_tvb) {
                    pinfo->can_desegment = 0;

                    ret = dissector_try_uint_new(ippusb_dissector_table, HTTP, processed_tvb, pinfo, tree, true, data);

                    col_append_str(pinfo->cinfo, COL_INFO, " Reassembled Data");

                    /* If the document was truncated mark it as such in the UX */
                    if (current_msp->document & MSP_DOCUMENT_TRUNCATED) {
                        col_append_str(pinfo->cinfo, COL_INFO, " Document Truncated");
                    }
                }
            }

            pinfo->fragmented = save_fragmented;
        }
    }

    if (ret) {
        return tvb_captured_length(tvb);
    }
    else {
        return 0;
    }
}

static int
is_http_header(unsigned first_linelen, const unsigned char *first_line) {
    if ((first_linelen >= strlen("HTTP/") && strncmp(first_line, "HTTP/", strlen("HTTP/")) == 0) ||
        (first_linelen >= strlen("POST /ipp") && strncmp(first_line, "POST /ipp", strlen("POST /ipp")) == 0) ||
        (first_linelen >= strlen("POST / HTTP") && strncmp(first_line, "POST / HTTP", strlen("POST / HTTP")) == 0)) {

        return true;
    }
    else {
        return false;
    }
}

static void
ippusb_shutdown(void) {
    tvb_free(return_newline_tvb);
}

void
proto_register_ippusb(void)
{
    static hf_register_info hf[] = {

        /* Reassembly */
        { &hf_ippusb_fragment,
            { "Fragment", "ippusb.fragment", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_ippusb_fragments,
            { "Fragments", "ippusb.fragments", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_ippusb_fragment_overlap,
            { "Fragment overlap", "ippusb.fragment.overlap", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},
        { &hf_ippusb_fragment_overlap_conflict,
            { "Conflicting data in fragment overlap", "ippusb.fragment.overlap.conflict",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping fragments contained conflicting data", HFILL }},
        { &hf_ippusb_fragment_multiple_tails,
            { "Multiple tail fragments found", "ippusb.fragment.multipletails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when defragmenting the packet", HFILL }},
        { &hf_ippusb_fragment_too_long_fragment,
            { "Fragment too long", "ippusb.fragment.toolongfragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment contained data past end of packet", HFILL }},
        { &hf_ippusb_fragment_error,
            { "Defragmentation error", "ippusb.fragment.error", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, "Defragmentation error due to illegal fragments", HFILL }},
        { &hf_ippusb_fragment_count,
            { "Fragment count", "ippusb.fragment.count", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
        { &hf_ippusb_reassembled_in,
            { "Reassembled payload in frame", "ippusb.reassembled_in", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, "This payload packet is reassembled in this frame", HFILL }},
        { &hf_ippusb_reassembled_length,
            { "Reassembled payload length", "ippusb.reassembled.length", FT_UINT32, BASE_DEC,
            NULL, 0x0, "The total length of the reassembled payload", HFILL }},
        { &hf_ippusb_reassembled_data,
            { "Reassembled data", "ippusb.reassembled.data", FT_BYTES, BASE_NONE,
            NULL, 0x0, "The reassembled payload", HFILL }},
        };

   static int *ett[] = {
        &ett_ippusb,
        &ett_ippusb_as,
        &ett_ippusb_attr,
        &ett_ippusb_member,
        &ett_ippusb_fragments,
        &ett_ippusb_fragment
    };

    proto_ippusb = proto_register_protocol("Internet Printing Protocol Over USB", "IPPUSB", "ippusb");

    ippusb_dissector_table = register_dissector_table("ippusb", "IPP Over USB", proto_ippusb, FT_UINT8, BASE_DEC);

    proto_register_field_array(proto_ippusb, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register reassembly table. */
    reassembly_table_register(&ippusb_reassembly_table, &ippusb_reassembly_table_functions);

    /* Preferences */
     module_t *ippusb_module = prefs_register_protocol(proto_ippusb, NULL);

    /* Reassembly, made an option due to memory costs */
    prefs_register_bool_preference(ippusb_module, "attempt_reassembly", "Reassemble payload", "", &global_ippusb_reassemble);

    return_newline_tvb = tvb_new_real_data(RETURN_NEWLINE, sizeof(RETURN_NEWLINE), sizeof(RETURN_NEWLINE));

    register_shutdown_routine(ippusb_shutdown);

    ippusb_handle = register_dissector("ippusb", dissect_ippusb, proto_ippusb);
}

void
proto_reg_handoff_ippusb(void)
{
    dissector_add_uint("usb.bulk", IF_CLASS_PRINTER, ippusb_handle);
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

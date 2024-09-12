/* packet-user_encap.c
 * Allow users to specify the dissectors for DLTs
 * Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/exported_pdu.h>
#include <epan/tap.h>
#include <wiretap/wtap.h>

#ifdef _MSC_VER
/* disable: warning C4090: 'XY' : different 'const' qualifiers */
#pragma warning(disable:4090)
#endif

void proto_register_user_encap(void);
void proto_reg_handoff_user_encap(void);

typedef struct _user_encap_t {
    unsigned encap;
    char* payload_proto_name;
    dissector_handle_t payload_proto;
    char* header_proto_name;
    dissector_handle_t header_proto;
    char* trailer_proto_name;
    dissector_handle_t trailer_proto;
    unsigned header_size;
    unsigned trailer_size;
} user_encap_t;

#define ENCAP0_STR "User 0 (DLT=147)"
static const value_string user_dlts[] = {
    { WTAP_ENCAP_USER0, ENCAP0_STR},
    { WTAP_ENCAP_USER1, "User 1 (DLT=148)"},
    { WTAP_ENCAP_USER2, "User 2 (DLT=149)"},
    { WTAP_ENCAP_USER3, "User 3 (DLT=150)"},
    { WTAP_ENCAP_USER4, "User 4 (DLT=151)"},
    { WTAP_ENCAP_USER5, "User 5 (DLT=152)"},
    { WTAP_ENCAP_USER6, "User 6 (DLT=153)"},
    { WTAP_ENCAP_USER7, "User 7 (DLT=154)"},
    { WTAP_ENCAP_USER8, "User 8 (DLT=155)"},
    { WTAP_ENCAP_USER9, "User 9 (DLT=156)"},
    { WTAP_ENCAP_USER10, "User 10 (DLT=157)"},
    { WTAP_ENCAP_USER11, "User 11 (DLT=158)"},
    { WTAP_ENCAP_USER12, "User 12 (DLT=159)"},
    { WTAP_ENCAP_USER13, "User 13 (DLT=160)"},
    { WTAP_ENCAP_USER14, "User 14 (DLT=161)"},
    { WTAP_ENCAP_USER15, "User 15 (DLT=162)"},
    { 0, NULL }
};
static int proto_user_encap;

static expert_field ei_user_encap_not_handled;

static user_encap_t* encaps;
static unsigned num_encaps;
static uat_t* encaps_uat;

static int exported_pdu_tap = -1;

static dissector_handle_t user_encap_handle;

/*
 * Use this for DLT_USER2 if we don't have an encapsulation for it.
 */
static user_encap_t user2_encap = {WTAP_ENCAP_USER2, "pktap", NULL, "", NULL, "", NULL, 0, 0};

static void export_pdu(tvbuff_t *tvb, packet_info* pinfo, char *proto_name)
{
    if (have_tap_listener(exported_pdu_tap)) {
        static const exp_pdu_data_item_t *user_encap_exp_pdu_items[] = {
            &exp_pdu_data_orig_frame_num,
            NULL
        };

        exp_pdu_data_t *exp_pdu_data = export_pdu_create_tags(pinfo, proto_name, EXP_PDU_TAG_DISSECTOR_NAME, user_encap_exp_pdu_items);

        exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
        exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
        exp_pdu_data->pdu_tvb = tvb;
        tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
    }
}

static int dissect_user(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_) {
    user_encap_t* encap = NULL;
    tvbuff_t* payload_tvb;
    proto_item* item;
    int len, reported_len;
    unsigned i;

    for (i = 0; i < num_encaps; i++) {
        if (encaps[i].encap == pinfo->match_uint) {
            encap = &(encaps[i]);
            break;
        }
    }

    item = proto_tree_add_item(tree,proto_user_encap,tvb,0,-1,ENC_NA);
    if (!encap && pinfo->match_uint == WTAP_ENCAP_USER2) {
        /*
         * Special-case DLT_USER2 - Apple hijacked it for use as DLT_PKTAP.
         * The user hasn't assigned anything to it, so default it to
         * the PKTAP dissector.
         */
        encap = &user2_encap;
    }
    if (!encap) {
        char* msg = wmem_strdup_printf(pinfo->pool,
                                     "User encapsulation not handled: DLT=%d, "
                                     "check your Preferences->Protocols->DLT_USER",
                         pinfo->match_uint + 147 - WTAP_ENCAP_USER0);
        proto_item_set_text(item,"%s",msg);
        expert_add_info_format(pinfo, item, &ei_user_encap_not_handled, "%s", msg);

        call_data_dissector(tvb, pinfo, tree);
        return tvb_captured_length(tvb);
    }
    if (encap->payload_proto == NULL) {
        char* msg = wmem_strdup_printf(pinfo->pool,
                                     "User encapsulation's protocol %s not found: "
                                     "DLT=%d, check your Preferences->Protocols->DLT_USER",
                                     encap->payload_proto_name,
                                     pinfo->match_uint + 147 - WTAP_ENCAP_USER0);
        proto_item_set_text(item,"%s",msg);
        expert_add_info_format(pinfo, item, &ei_user_encap_not_handled, "%s", msg);

        call_data_dissector(tvb, pinfo, tree);
        return tvb_captured_length(tvb);
    }

    proto_item_set_text(item,"DLT: %d",pinfo->match_uint + 147 - WTAP_ENCAP_USER0);

    if (encap->header_size) {
        tvbuff_t* hdr_tvb = tvb_new_subset_length(tvb, 0, encap->header_size);
        export_pdu(hdr_tvb, pinfo, encap->header_proto_name);
        call_dissector(encap->header_proto, hdr_tvb, pinfo, tree);
        if (encap->header_proto_name) {
            const char *proto_name = dissector_handle_get_protocol_long_name(encap->header_proto);
            if (proto_name) {
                proto_item_append_text(item, ", Header: %s (%s)", encap->header_proto_name, proto_name);
            }
        }
    }

    len = tvb_captured_length(tvb) - (encap->header_size + encap->trailer_size);
    reported_len = tvb_reported_length(tvb) - (encap->header_size + encap->trailer_size);

    payload_tvb = tvb_new_subset_length_caplen(tvb, encap->header_size, len, reported_len);
    export_pdu(payload_tvb, pinfo, encap->payload_proto_name);
    call_dissector(encap->payload_proto, payload_tvb, pinfo, tree);
    if (encap->payload_proto_name) {
        const char *proto_name = dissector_handle_get_protocol_long_name(encap->payload_proto);
        if (proto_name) {
            proto_item_append_text(item, ", Payload: %s (%s)", encap->payload_proto_name, proto_name);
        }
    }

    if (encap->trailer_size) {
        tvbuff_t* trailer_tvb = tvb_new_subset_length(tvb, encap->header_size + len, encap->trailer_size);
        export_pdu(trailer_tvb, pinfo, encap->trailer_proto_name);
        call_dissector(encap->trailer_proto, trailer_tvb, pinfo, tree);
        if (encap->trailer_proto_name) {
            const char *proto_name = dissector_handle_get_protocol_long_name(encap->trailer_proto);
            if (proto_name) {
                proto_item_append_text(item, ", Trailer: %s (%s)", encap->trailer_proto_name, proto_name);
            }
        }
    }
    return tvb_captured_length(tvb);
}

static void* user_copy_cb(void* dest, const void* orig, size_t len _U_)
{
    const user_encap_t *o = (const user_encap_t *)orig;
    user_encap_t *d = (user_encap_t *)dest;

    d->encap = o->encap;
    d->payload_proto_name = g_strdup(o->payload_proto_name);
    d->payload_proto = o->payload_proto;
    d->header_proto_name = g_strdup(o->header_proto_name);
    d->header_proto = o->header_proto;
    d->trailer_proto_name = g_strdup(o->trailer_proto_name);
    d->trailer_proto = o->trailer_proto;
    d->header_size = o->header_size;
    d->trailer_size = o->trailer_size;

    return d;
}

static void user_free_cb(void* record)
{
    user_encap_t *u = (user_encap_t *)record;

    g_free(u->payload_proto_name);
    g_free(u->header_proto_name);
    g_free(u->trailer_proto_name);
}

UAT_VS_DEF(user_encap, encap, user_encap_t, unsigned, WTAP_ENCAP_USER0, ENCAP0_STR)
UAT_DISSECTOR_DEF(user_encap, payload_proto, payload_proto, payload_proto_name, user_encap_t)
UAT_DEC_CB_DEF(user_encap, header_size, user_encap_t)
UAT_DISSECTOR_DEF(user_encap, header_proto, header_proto, header_proto_name, user_encap_t)
UAT_DEC_CB_DEF(user_encap, trailer_size, user_encap_t)
UAT_DISSECTOR_DEF(user_encap, trailer_proto, trailer_proto, trailer_proto_name, user_encap_t)

void proto_reg_handoff_user_encap(void)
{
    unsigned i;

    user2_encap.payload_proto = find_dissector("pktap");

    for (i = WTAP_ENCAP_USER0; i <= WTAP_ENCAP_USER15; i++)
        dissector_add_uint("wtap_encap", i, user_encap_handle);
}


void proto_register_user_encap(void)
{
    module_t *module;
    expert_module_t* expert_user_encap;

    static uat_field_t user_flds[] = {
        UAT_FLD_VS(user_encap,encap,"DLT",user_dlts,"The DLT"),
        UAT_FLD_DISSECTOR(user_encap,payload_proto,"Payload dissector",
                      "Dissector to be used for the payload of this DLT"),
        UAT_FLD_DEC(user_encap,header_size,"Header size",
                    "Size of an eventual header that precedes the actual payload, 0 means none"),
        UAT_FLD_DISSECTOR(user_encap,header_proto,"Header dissector",
                      "Dissector to be used for the header (empty = data)"),
        UAT_FLD_DEC(user_encap,trailer_size,"Trailer size",
                    "Size of an eventual trailer that follows the actual payload, 0 means none"),
        UAT_FLD_DISSECTOR(user_encap,trailer_proto,"Trailer dissector",
                      "Dissector to be used for the trailer (empty = data)"),
        UAT_END_FIELDS
    };

    static ei_register_info ei[] = {
        { &ei_user_encap_not_handled, { "user_dlt.not_handled", PI_UNDECODED, PI_WARN, "Formatted text", EXPFILL }},
    };

    proto_user_encap = proto_register_protocol("DLT User","DLT_USER","user_dlt");
    expert_user_encap = expert_register_protocol(proto_user_encap);
    expert_register_field_array(expert_user_encap, ei, array_length(ei));

    module = prefs_register_protocol(proto_user_encap, NULL);

    encaps_uat = uat_new("User DLTs Table",
                         sizeof(user_encap_t),
                         "user_dlts",
                         true,
                         &encaps,
                         &num_encaps,
                         UAT_AFFECTS_DISSECTION, /* affects dissection of packets, but not set of named fields */
                         "ChUserDLTsSection",
                         user_copy_cb,
                         NULL,
                         user_free_cb,
                         NULL,
                         NULL,
                         user_flds );

    prefs_register_uat_preference(module,
                      "encaps_table",
                      "Encapsulations Table",
                      "A table that enumerates the various protocols to be used against a certain user DLT",
                      encaps_uat);


    user_encap_handle = register_dissector("user_dlt",dissect_user,proto_user_encap);

    /*
    prefs_register_protocol_obsolete(proto_register_protocol("DLT User A","DLT_USER_A","user_dlt_a"));
    prefs_register_protocol_obsolete(proto_register_protocol("DLT User B","DLT_USER_B","user_dlt_b"));
    prefs_register_protocol_obsolete(proto_register_protocol("DLT User C","DLT_USER_C","user_dlt_c"));
    prefs_register_protocol_obsolete(proto_register_protocol("DLT User D","DLT_USER_D","user_dlt_d"));
    */

    exported_pdu_tap = register_export_pdu_tap("DLT User");
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

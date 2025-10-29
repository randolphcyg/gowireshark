/* packet-lin.c
 *
 * LIN dissector.
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 * Copyright 2021-2025 Dr. Lars Völker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/decode_as.h>
#include <epan/prefs.h>
#include <wiretap/wtap.h>
#include <epan/expert.h>
#include <epan/uat.h>

#include "packet-lin.h"

 /*
  * Dissector for the Local Interconnect Network (LIN) bus.
  *
  * see ISO 17987 or search for "LIN Specification 2.2a" online.
  */

#define LIN_NAME                             "LIN"
#define LIN_NAME_LONG                        "LIN Protocol"
#define LIN_NAME_FILTER                      "lin"

static heur_dissector_list_t                 heur_subdissector_list;
static heur_dtbl_entry_t                    *heur_dtbl_entry;

static int proto_lin;

static dissector_handle_t lin_handle;

/* header field */
static int hf_lin_msg_format_rev;
static int hf_lin_reserved1;
static int hf_lin_payload_length;
static int hf_lin_message_type;
static int hf_lin_checksum_type;
static int hf_lin_pid;
static int hf_lin_id;
static int hf_lin_parity;
static int hf_lin_checksum;
static int hf_lin_err_errors;
static int hf_lin_err_no_slave_response;
static int hf_lin_err_framing;
static int hf_lin_err_parity;
static int hf_lin_err_checksum;
static int hf_lin_err_invalidid;
static int hf_lin_err_overflow;
static int hf_lin_event_id;
static int hf_lin_bus_id;

static int ett_lin;
static int ett_lin_pid;
static int ett_errors;

static int * const error_fields[] = {
    &hf_lin_err_overflow,
    &hf_lin_err_invalidid,
    &hf_lin_err_checksum,
    &hf_lin_err_parity,
    &hf_lin_err_framing,
    &hf_lin_err_no_slave_response,
    NULL
};

static dissector_table_t subdissector_table;

static const value_string lin_msg_type_names[] = {
    { LIN_MSG_TYPE_FRAME, "Frame" },
    { LIN_MSG_TYPE_EVENT, "Event" },
    {0, NULL}
};

#define LIN_CHKSUM_TYPE_UNKN_ERR 0
#define LIN_CHKSUM_TYPE_CLASSIC  1
#define LIN_CHKSUM_TYPE_ENHANCED 2
#define LIN_CHKSUM_TYPE_UNDEF    3

static const value_string lin_checksum_type_names[] = {
    { LIN_CHKSUM_TYPE_UNKN_ERR, "Unknown/Error" },
    { LIN_CHKSUM_TYPE_CLASSIC, "Classic" },
    { LIN_CHKSUM_TYPE_ENHANCED, "Enhanced" },
    { LIN_CHKSUM_TYPE_UNDEF, "Undefined" },
    {0, NULL}
};

static const value_string lin_event_type_names[] = {
    { LIN_EVENT_TYPE_GO_TO_SLEEP_EVENT_BY_GO_TO_SLEEP, "Go-to-Sleep event by Go-to-Sleep frame" },
    { LIN_EVENT_TYPE_GO_TO_SLEEP_EVENT_BY_INACTIVITY,  "Go-to-Sleep event by Inactivity for more than 4s" },
    { LIN_EVENT_TYPE_WAKE_UP_BY_WAKE_UP_SIGNAL,        "Wake-up event by Wake-up signal" },
    {0, NULL}
};

void proto_reg_handoff_lin(void);
void proto_register_lin(void);

/********* UATs *********/

/* Interface Config UAT */
typedef struct _interface_config {
    unsigned  interface_id;
    char     *interface_name;
    unsigned  bus_id;
} interface_config_t;

#define DATAFILE_LIN_INTERFACE_MAPPING "LIN_interface_mapping"

static GHashTable *data_lin_interfaces_by_id;
static GHashTable *data_lin_interfaces_by_name;
static interface_config_t* interface_configs;
static unsigned interface_config_num;

UAT_HEX_CB_DEF(interface_configs, interface_id, interface_config_t)
UAT_CSTRING_CB_DEF(interface_configs, interface_name, interface_config_t)
UAT_HEX_CB_DEF(interface_configs, bus_id, interface_config_t)

static void *
copy_interface_config_cb(void *n, const void *o, size_t size _U_) {
    interface_config_t *new_rec = (interface_config_t *)n;
    const interface_config_t *old_rec = (const interface_config_t *)o;

    new_rec->interface_id = old_rec->interface_id;
    new_rec->interface_name = g_strdup(old_rec->interface_name);
    new_rec->bus_id = old_rec->bus_id;
    return new_rec;
}

static bool
update_interface_config(void *r, char **err) {
    interface_config_t *rec = (interface_config_t *)r;

    if (rec->interface_id > 0xffffffff) {
        *err = ws_strdup_printf("We currently only support 32 bit identifiers (ID: 0x%x  Name: %s)",
                               rec->interface_id, rec->interface_name);
        return false;
    }

    if (rec->bus_id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit bus identifiers (ID: 0x%x  Name: %s  Bus-ID: 0x%x)",
                                rec->interface_id, rec->interface_name, rec->bus_id);
        return false;
    }

    return true;
}

static void
free_interface_config_cb(void *r) {
    interface_config_t *rec = (interface_config_t *)r;
    /* freeing result of g_strdup */
    g_free(rec->interface_name);
    rec->interface_name = NULL;
}

static void
post_update_interface_config_cb(void) {
    /* destroy old hash tables, if they exist */
    if (data_lin_interfaces_by_id) {
        g_hash_table_destroy(data_lin_interfaces_by_id);
    }
    if (data_lin_interfaces_by_name) {
        g_hash_table_destroy(data_lin_interfaces_by_name);
    }

    /* create new hash table */
    data_lin_interfaces_by_id = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    data_lin_interfaces_by_name = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);

    for (unsigned i = 0; i < interface_config_num; i++) {
        if (interface_configs[i].interface_id != 0xfffffff) {
            g_hash_table_insert(data_lin_interfaces_by_id, GUINT_TO_POINTER(interface_configs[i].interface_id), &interface_configs[i]);
        }

        if (interface_configs[i].interface_name != NULL && interface_configs[i].interface_name[0] != 0) {
            g_hash_table_insert(data_lin_interfaces_by_name, interface_configs[i].interface_name, &interface_configs[i]);
        }
    }
}

static void
reset_interface_config_cb(void) {
    if (data_lin_interfaces_by_id) {
        g_hash_table_destroy(data_lin_interfaces_by_id);
        data_lin_interfaces_by_id = NULL;
    }

    if (data_lin_interfaces_by_name) {
        g_hash_table_destroy(data_lin_interfaces_by_name);
        data_lin_interfaces_by_name = NULL;
    }
}

/* We match based on the config in the following order:
 * - interface_name matches and interface_id matches
 * - interface_name matches and interface_id = 0xffffffff
 * - interface_name = ""    and interface_id matches
 */

static unsigned
get_bus_id(packet_info *pinfo) {
    if (!(pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID)) {
        return 0;
    }

    uint32_t            interface_id = pinfo->rec->rec_header.packet_header.interface_id;
    unsigned            section_number = pinfo->rec->presence_flags & WTAP_HAS_SECTION_NUMBER ? pinfo->rec->section_number : 0;
    const char         *interface_name = epan_get_interface_name(pinfo->epan, interface_id, section_number);

    if (interface_name != NULL && interface_name[0] != 0) {
        interface_config_t *tmp = NULL;

        if (data_lin_interfaces_by_name != NULL) {
            tmp = g_hash_table_lookup(data_lin_interfaces_by_name, interface_name);

            if (tmp != NULL && (tmp->interface_id == 0xffffffff || tmp->interface_id == interface_id)) {
                /* name + id match or name match and id = any */
                return tmp->bus_id;
            }
        }

        if (data_lin_interfaces_by_id != NULL) {
            tmp = g_hash_table_lookup(data_lin_interfaces_by_id, GUINT_TO_POINTER(interface_id));

            if (tmp != NULL && (tmp->interface_name == NULL || tmp->interface_name[0] == 0)) {
                /* id matches and name is any */
                return tmp->bus_id;
            }
        }
    }

    /* we found nothing */
    return 0;
}

/* Senders and Receivers UAT */
typedef struct _sender_receiver_config {
    unsigned  bus_id;
    unsigned  lin_id;
    char     *sender_name;
    char     *receiver_name;
} sender_receiver_config_t;

#define DATAFILE_LIN_SENDER_RECEIVER "LIN_senders_receivers"

static GHashTable *data_sender_receiver;
static sender_receiver_config_t* sender_receiver_configs;
static unsigned sender_receiver_config_num;

UAT_HEX_CB_DEF(sender_receiver_configs, bus_id, sender_receiver_config_t)
UAT_HEX_CB_DEF(sender_receiver_configs, lin_id, sender_receiver_config_t)
UAT_CSTRING_CB_DEF(sender_receiver_configs, sender_name, sender_receiver_config_t)
UAT_CSTRING_CB_DEF(sender_receiver_configs, receiver_name, sender_receiver_config_t)

static void *
copy_sender_receiver_config_cb(void *n, const void *o, size_t size _U_) {
    sender_receiver_config_t *new_rec = (sender_receiver_config_t *)n;
    const sender_receiver_config_t *old_rec = (const sender_receiver_config_t *)o;

    new_rec->bus_id = old_rec->bus_id;
    new_rec->lin_id = old_rec->lin_id;
    new_rec->sender_name = g_strdup(old_rec->sender_name);
    new_rec->receiver_name = g_strdup(old_rec->receiver_name);
    return new_rec;
}

static bool
update_sender_receiver_config(void *r, char **err) {
    sender_receiver_config_t *rec = (sender_receiver_config_t *)r;

    if (rec->lin_id > 0x3f) {
        *err = ws_strdup_printf("LIN IDs need to be between 0x00 and 0x3f (Bus ID: %i  LIN ID: %i)", rec->bus_id, rec->lin_id);
        return false;
    }

    if (rec->bus_id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit bus identifiers (Bus ID: %i  LIN ID: %i)", rec->bus_id, rec->lin_id);
        return false;
    }

    return true;
}

static void
free_sender_receiver_config_cb(void *r) {
    sender_receiver_config_t *rec = (sender_receiver_config_t *)r;
    /* freeing result of g_strdup */
    g_free(rec->sender_name);
    rec->sender_name = NULL;
    g_free(rec->receiver_name);
    rec->receiver_name = NULL;
}

static uint64_t
sender_receiver_key(uint16_t bus_id, uint32_t lin_id) {
    return ((uint64_t)bus_id << 32) | lin_id;
}

static sender_receiver_config_t *
ht_lookup_sender_receiver_config(uint16_t bus_id, uint32_t lin_id) {
    if (data_sender_receiver == NULL) {
        return NULL;
    }

    uint64_t key = sender_receiver_key(bus_id, lin_id);
    sender_receiver_config_t *tmp = g_hash_table_lookup(data_sender_receiver, &key);

    if (tmp == NULL) {
        key = sender_receiver_key(0, lin_id);
        tmp = g_hash_table_lookup(data_sender_receiver, &key);
    }

    return tmp;
}

static void
post_update_sender_receiver_cb(void) {
    unsigned i;
    uint64_t *key;

    /* destroy old hash table, if it exist */
    if (data_sender_receiver) {
        g_hash_table_destroy(data_sender_receiver);
    }

    /* create new hash table */
    data_sender_receiver = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);

    for (i = 0; i < sender_receiver_config_num; i++) {
        key = g_new(uint64_t, 1);
        *key = sender_receiver_key(sender_receiver_configs[i].bus_id, sender_receiver_configs[i].lin_id);
        g_hash_table_insert(data_sender_receiver, key, &sender_receiver_configs[i]);
    }
}

static void
reset_sender_receiver_cb(void) {
    /* destroy hash table, if it exists */
    if (data_sender_receiver) {
        g_hash_table_destroy(data_sender_receiver);
        data_sender_receiver = NULL;
    }
}

bool
lin_set_source_and_destination_columns(packet_info* pinfo, lin_info_t *lininfo) {
    sender_receiver_config_t *tmp = ht_lookup_sender_receiver_config(lininfo->bus_id, lininfo->id);

    if (tmp != NULL) {
        /* remove all addresses to support LIN as payload (e.g., TECMP) */
        clear_address(&pinfo->net_src);
        clear_address(&pinfo->dl_src);
        clear_address(&pinfo->src);
        clear_address(&pinfo->net_dst);
        clear_address(&pinfo->dl_dst);
        clear_address(&pinfo->dst);

        col_add_str(pinfo->cinfo, COL_DEF_SRC, tmp->sender_name);
        col_add_str(pinfo->cinfo, COL_DEF_DST, tmp->receiver_name);
        return true;
    }
    return false;
}

int
dissect_lin_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, lin_info_t *lininfo) {
    /* LIN encodes a sleep frame by setting ID to LIN_DIAG_MASTER_REQUEST_FRAME and the first byte to 0x00 */
    bool ignore_lin_payload = (lininfo->id == LIN_DIAG_MASTER_REQUEST_FRAME && tvb_get_uint8(tvb, 0) == 0x00);

    int ret = 0;
    if (!ignore_lin_payload) {
        uint32_t bus_frame_id = lininfo->id | (lininfo->bus_id << 16);
        ret = dissector_try_uint_with_data(subdissector_table, bus_frame_id, tvb, pinfo, tree, true, &lininfo);
        if (ret == 0) {
            ret = dissector_try_uint_with_data(subdissector_table, lininfo->id, tvb, pinfo, tree, true, &lininfo);
            if (ret == 0) {
                ret = dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree, &heur_dtbl_entry, &lininfo);
            }
        }
    }

    if (ret == 0) {
        ret = call_data_dissector(tvb, pinfo, tree);
    }

    return ret;
}

static int
dissect_lin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
    proto_item *ti;
    proto_item *ti_root;
    proto_tree *lin_tree;
    proto_tree *lin_id_tree;
    tvbuff_t   *next_tvb;

    unsigned payload_length;
    unsigned msg_type;
    lin_info_t lininfo;
    uint64_t errors;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, LIN_NAME);
    col_clear(pinfo->cinfo, COL_INFO);

    lininfo.bus_id = (uint16_t)get_bus_id(pinfo);
    lininfo.len = 0;

    ti_root = proto_tree_add_item(tree, proto_lin, tvb, 0, -1, ENC_NA);
    lin_tree = proto_item_add_subtree(ti_root, ett_lin);

    if (lininfo.bus_id != 0) {
        ti = proto_tree_add_uint(lin_tree, hf_lin_bus_id, tvb, 0, 0, lininfo.bus_id);
        proto_item_set_hidden(ti);
    }

    proto_tree_add_item(lin_tree, hf_lin_msg_format_rev, tvb, 0, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(lin_tree, hf_lin_reserved1, tvb, 1, 3, ENC_BIG_ENDIAN);
    proto_item_set_hidden(ti);

    proto_tree_add_item_ret_uint(lin_tree, hf_lin_payload_length, tvb, 4, 1, ENC_BIG_ENDIAN, &payload_length);
    proto_tree_add_item_ret_uint(lin_tree, hf_lin_message_type, tvb, 4, 1, ENC_BIG_ENDIAN, &msg_type);
    if (msg_type != LIN_MSG_TYPE_EVENT) {
        proto_tree_add_item(lin_tree, hf_lin_checksum_type, tvb, 4, 1, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(lin_tree, hf_lin_pid, tvb, 5, 1, ENC_BIG_ENDIAN);
        lin_id_tree = proto_item_add_subtree(ti, ett_lin_pid);
        proto_tree_add_item(lin_id_tree, hf_lin_parity, tvb, 5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_uint(lin_id_tree, hf_lin_id, tvb, 5, 1, ENC_BIG_ENDIAN, &(lininfo.id));

        proto_tree_add_item(lin_tree, hf_lin_checksum, tvb, 6, 1, ENC_BIG_ENDIAN);

        lin_set_source_and_destination_columns(pinfo, &lininfo);
    }
    proto_tree_add_bitmask_ret_uint64(lin_tree, tvb, 7, hf_lin_err_errors, ett_errors, error_fields, ENC_BIG_ENDIAN, &errors);

    col_add_fstr(pinfo->cinfo, COL_INFO, "LIN %s", val_to_str(pinfo->pool, msg_type, lin_msg_type_names, "(0x%02x)"));

    if (errors != 0) {
        col_append_str(pinfo->cinfo, COL_INFO, " - ERR");
        proto_item_set_end(ti_root, tvb, 8);
        return 8;
    }

    switch (msg_type) {
    case LIN_MSG_TYPE_EVENT: {
        unsigned event_id;
        proto_tree_add_item_ret_uint(lin_tree, hf_lin_event_id, tvb, 8, 4, ENC_BIG_ENDIAN, &event_id);
        col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str(pinfo->pool, event_id, lin_event_type_names, "0x%08x"));
        proto_item_set_end(ti_root, tvb, 12);
        }
        break;

    case LIN_MSG_TYPE_FRAME:
        if (payload_length > 0) {
            next_tvb = tvb_new_subset_length(tvb, 8, payload_length);
            proto_item_set_end(ti_root, tvb, 8 + payload_length);
            lininfo.len = (uint16_t)payload_length;

            dissect_lin_message(next_tvb, pinfo, tree, &lininfo);
        }

        /* Include padding to a multiple of 4 bytes */
        if (payload_length <= 4)
            proto_item_set_end(ti_root, tvb, 12);
        else if (payload_length <= 8)
            proto_item_set_end(ti_root, tvb, 16);
        break;
    }
    return tvb_captured_length(tvb);
}

void
proto_register_lin(void) {
    module_t   *lin_module;
    uat_t      *lin_interface_uat = NULL;
    uat_t      *sender_receiver_uat = NULL;

    static hf_register_info hf[] = {
        { &hf_lin_msg_format_rev,
            { "Message Format Revision", "lin.message_format",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lin_reserved1,
            { "Reserved", "lin.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lin_payload_length,
            { "Length", "lin.length",
            FT_UINT8, BASE_DEC, NULL, LIN_PAYLOAD_LENGTH_MASK, NULL, HFILL }},
        { &hf_lin_message_type,
            { "Message Type", "lin.message_type",
            FT_UINT8, BASE_DEC, VALS(lin_msg_type_names), LIN_MSG_TYPE_MASK, NULL, HFILL }},
        { &hf_lin_checksum_type,
            { "Checksum Type", "lin.checksum_type",
            FT_UINT8, BASE_DEC, VALS(lin_checksum_type_names), LIN_CHECKSUM_TYPE_MASK, NULL, HFILL }},
        { &hf_lin_pid,
            { "Protected ID", "lin.protected_id",
            FT_UINT8, BASE_HEX_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_lin_id,
            { "Frame ID", "lin.frame_id",
            FT_UINT8, BASE_HEX_DEC, NULL, LIN_FRAME_ID_MASK, NULL, HFILL }},
        { &hf_lin_parity,
            { "Parity", "lin.frame_parity",
            FT_UINT8, BASE_HEX_DEC, NULL, 0xc0, NULL, HFILL }},
        { &hf_lin_checksum,
            { "Checksum", "lin.checksum",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }},
        { &hf_lin_err_errors,
            { "Errors", "lin.errors",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }},
        { &hf_lin_err_no_slave_response,
            { "No Slave Response Error", "lin.errors.no_slave_response",
            FT_BOOLEAN, 8, NULL, LIN_ERROR_NO_SLAVE_RESPONSE, NULL, HFILL }},
        { &hf_lin_err_framing,
            { "Framing Error", "lin.errors.framing_error",
            FT_BOOLEAN, 8, NULL, LIN_ERROR_FRAMING_ERROR, NULL, HFILL }},
        { &hf_lin_err_parity,
            { "Parity Error", "lin.errors.parity_error",
            FT_BOOLEAN, 8, NULL, LIN_ERROR_PARITY_ERROR, NULL, HFILL }},
        { &hf_lin_err_checksum,
            { "Checksum Error", "lin.errors.checksum_error",
            FT_BOOLEAN, 8, NULL, LIN_ERROR_CHECKSUM_ERROR, NULL, HFILL }},
        { &hf_lin_err_invalidid,
            { "Invalid ID Error", "lin.errors.invalid_id_error",
            FT_BOOLEAN, 8, NULL, LIN_ERROR_INVALID_ID_ERROR, NULL, HFILL }},
        { &hf_lin_err_overflow,
            { "Overflow Error", "lin.errors.overflow_error",
            FT_BOOLEAN, 8, NULL, LIN_ERROR_OVERFLOW_ERROR, NULL, HFILL }},
        { &hf_lin_event_id,
            { "Event ID", "lin.event_id",
            FT_UINT32, BASE_HEX_DEC, VALS(lin_event_type_names), 0x00, NULL, HFILL }},
        { &hf_lin_bus_id,
            { "Bus ID", "lin.bus_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_lin,
        &ett_lin_pid,
        &ett_errors,
    };

    proto_lin = proto_register_protocol(LIN_NAME_LONG, LIN_NAME, LIN_NAME_FILTER);
    lin_module = prefs_register_protocol(proto_lin, NULL);

    proto_register_field_array(proto_lin, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    lin_handle = register_dissector(LIN_NAME_FILTER, dissect_lin, proto_lin);

    /* the lin.frame_id subdissector table carries the bus id in the higher 16 bits */
    subdissector_table = register_dissector_table("lin.frame_id", "LIN Frame ID", proto_lin, FT_UINT8, BASE_HEX);
    heur_subdissector_list = register_heur_dissector_list_with_description(LIN_NAME_FILTER, "LIN Message data fallback", proto_lin);

    static uat_field_t lin_interface_mapping_uat_fields[] = {
        UAT_FLD_HEX(interface_configs,      interface_id,   "Interface ID",   "ID of the Interface with 0xffffffff = any (hex uint32 without leading 0x)"),
        UAT_FLD_CSTRING(interface_configs,  interface_name, "Interface Name", "Name of the Interface, empty = any (string)"),
        UAT_FLD_HEX(interface_configs,      bus_id,         "Bus ID",         "Bus ID of the Interface (hex uint16 without leading 0x)"),
        UAT_END_FIELDS
    };

    lin_interface_uat = uat_new("LIN Interface Mapping",
        sizeof(interface_config_t),             /* record size           */
        DATAFILE_LIN_INTERFACE_MAPPING,         /* filename              */
        true,                                   /* from profile          */
        (void**)&interface_configs,             /* data_ptr              */
        &interface_config_num,                  /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                 /* but not fields        */
        NULL,                                   /* help                  */
        copy_interface_config_cb,               /* copy callback         */
        update_interface_config,                /* update callback       */
        free_interface_config_cb,               /* free callback         */
        post_update_interface_config_cb,        /* post update callback  */
        reset_interface_config_cb,              /* reset callback        */
        lin_interface_mapping_uat_fields        /* UAT field definitions */
    );

    prefs_register_uat_preference(lin_module, "_lin_interface_mapping", "Interface Mapping",
        "A table to define the mapping between interface and Bus ID.", lin_interface_uat);

    static uat_field_t sender_receiver_mapping_uat_fields[] = {
            UAT_FLD_HEX(sender_receiver_configs,     bus_id,        "Bus ID",        "Bus ID of the Interface with 0 meaning any (hex uint16 without leading 0x)."),
            UAT_FLD_HEX(sender_receiver_configs,     lin_id,        "LIN ID",        "ID of the LIN Message (hex uint6 without leading 0x)"),
            UAT_FLD_CSTRING(sender_receiver_configs, sender_name,   "Sender Name",   "Name of Sender(s)"),
            UAT_FLD_CSTRING(sender_receiver_configs, receiver_name, "Receiver Name", "Name of Receiver(s)"),
            UAT_END_FIELDS
    };

    sender_receiver_uat = uat_new("Sender Receiver Config",
        sizeof(sender_receiver_config_t),       /* record size           */
        DATAFILE_LIN_SENDER_RECEIVER,           /* filename              */
        true,                                   /* from profile          */
        (void**)&sender_receiver_configs,       /* data_ptr              */
        &sender_receiver_config_num,            /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                 /* but not fields        */
        NULL,                                   /* help                  */
        copy_sender_receiver_config_cb,         /* copy callback         */
        update_sender_receiver_config,          /* update callback       */
        free_sender_receiver_config_cb,         /* free callback         */
        post_update_sender_receiver_cb,         /* post update callback  */
        reset_sender_receiver_cb,               /* reset callback        */
        sender_receiver_mapping_uat_fields      /* UAT field definitions */
    );

    prefs_register_uat_preference(lin_module, "_sender_receiver_config", "Sender Receiver Config",
        "A table to define the mapping between Bus ID and LIN ID to Sender and Receiver.", sender_receiver_uat);
}

void
proto_reg_handoff_lin(void) {
    dissector_add_uint("wtap_encap", WTAP_ENCAP_LIN, lin_handle);
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

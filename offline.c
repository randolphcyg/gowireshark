#include "offline.h"
#include "tcp_follow.h"
#include <epan/expert.h>
#include <stdlib.h>
#include <string.h>
#include <wsutil/value_string.h>

// Global capture file variable
capture_file cf;

// --- Internal Helper Prototypes ---
static void clean();
static bool read_packet(epan_dissect_t **edt_r);
static int apply_decode_as_rules(cJSON *rules);
static void reset_decode_as_rules(void);

typedef struct {
    GSList *src_list;
    gchar **filter;
    pf_flags filter_flags;
    gboolean print_hex;
    gboolean print_text;
    proto_node_children_grouper_func node_children_grouper;
    json_dumper *dumper;
} write_json_data;

typedef struct {
    char *table;
    bool is_string;
    union {
        uint32_t uint_value;
        char *string_value;
    };
} decode_as_entry;

static GArray *g_decode_as_entries = NULL;

static e_addr_resolve saved_gbl_resolv_flags;
static bool gbl_resolv_saved = false;
static char *saved_profile_name = NULL;

static void restore_global_session_options(void) {
    if (gbl_resolv_saved) {
        memcpy(&gbl_resolv_flags, &saved_gbl_resolv_flags, sizeof(e_addr_resolve));
        gbl_resolv_saved = false;
    }
    if (saved_profile_name != NULL) {
        set_profile_name(saved_profile_name);
        g_free(saved_profile_name);
        saved_profile_name = NULL;
    }
}

typedef struct {
    FrameCallback callback;
    int stop;
} expert_callback_data;

typedef struct {
    FrameCallback callback;
    const char *type_name;
    int count;
} conv_tap_callback_data;

typedef void (*proto_node_value_writer)(proto_node *, write_json_data *);
static void write_json_index(json_dumper *dumper, epan_dissect_t *edt);
static void write_json_proto_node_list(GSList *proto_node_list_head, write_json_data *pdata);
static void write_json_proto_node(GSList *node_values_head, const char *suffix,
                                  proto_node_value_writer value_writer, write_json_data *data);
static void write_json_proto_node_value_list(GSList *node_values_head,
                                             proto_node_value_writer value_writer,
                                             write_json_data *data);
static void write_json_proto_node_children(proto_node *node, write_json_data *data);
static void write_json_proto_node_value(proto_node *node, write_json_data *data);
static void write_json_proto_node_no_value(proto_node *node, write_json_data *pdata);
static const char *proto_node_to_json_key(proto_node *node);

// --- Cleanup Functions ---

static int table_is_supported_decode_as(const char *table) {
    if (table == NULL) return 0;

    dissector_table_t dt = find_dissector_table(table);
    if (dt == NULL) return 0;

    ftenum_t ftype = dissector_table_get_type(dt);
    return (ftype == FT_UINT8 || ftype == FT_UINT16 || ftype == FT_UINT24 ||
            ftype == FT_UINT32 || ftype == FT_STRING);
}

static void reset_decode_as_rules(void) {
    if (g_decode_as_entries == NULL) {
        return;
    }
    for (guint i = 0; i < g_decode_as_entries->len; i++) {
        decode_as_entry *entry = &g_array_index(g_decode_as_entries, decode_as_entry, i);
        if (entry->table != NULL) {
            if (entry->is_string && entry->string_value != NULL) {
                dissector_reset_string(entry->table, entry->string_value);
                g_free(entry->string_value);
                entry->string_value = NULL;
            } else {
                dissector_reset_uint(entry->table, entry->uint_value);
            }
            g_free(entry->table);
            entry->table = NULL;
        }
    }
    g_array_free(g_decode_as_entries, TRUE);
    g_decode_as_entries = NULL;
}

static int apply_decode_as_rules(cJSON *rules) {
    if (rules == NULL || !cJSON_IsArray(rules)) {
        return 0;
    }

    cJSON *rule = NULL;
    cJSON_ArrayForEach(rule, rules) {
        const cJSON *table_json = cJSON_GetObjectItemCaseSensitive(rule, "table");
        const cJSON *selector_json = cJSON_GetObjectItemCaseSensitive(rule, "selector");
        const cJSON *protocol_json = cJSON_GetObjectItemCaseSensitive(rule, "protocol");
        if (!cJSON_IsString(table_json) || !cJSON_IsString(selector_json) ||
            !cJSON_IsString(protocol_json) ||
            table_json->valuestring == NULL || selector_json->valuestring == NULL ||
            protocol_json->valuestring == NULL) {
            fprintf(stderr, "decode_as: invalid rule\n");
            return -2;
        }

        const char *table_name = table_json->valuestring;
        const char *selector = selector_json->valuestring;
        const char *protocol = protocol_json->valuestring;

        dissector_table_t table = find_dissector_table(table_name);
        if (table == NULL) {
            fprintf(stderr, "decode_as: table not found %s\n", table_name);
            return -2;
        }

        ftenum_t ftype = dissector_table_get_type(table);
        if (!table_is_supported_decode_as(table_name)) {
            fprintf(stderr, "decode_as: unsupported table %s (type=%d)\n", table_name, ftype);
            return -2;
        }

        dissector_handle_t handle = find_dissector(protocol);
        if (handle == NULL) {
            handle = dissector_table_get_dissector_handle(table, protocol);
        }
        if (handle == NULL) {
            fprintf(stderr, "decode_as: protocol not found %s\n", protocol);
            return -2;
        }

        if (g_decode_as_entries == NULL) {
            g_decode_as_entries = g_array_new(FALSE, TRUE, sizeof(decode_as_entry));
        }

        if (ftype == FT_STRING) {
            dissector_change_string(table_name, selector, handle);

            decode_as_entry entry = {
                .table = g_strdup(table_name),
                .is_string = true,
                .string_value = g_strdup(selector),
            };
            g_array_append_val(g_decode_as_entries, entry);
        } else {
            char *end = NULL;
            unsigned long value = strtoul(selector, &end, 0);
            if (end == selector || *end != '\0') {
                fprintf(stderr, "decode_as: invalid numeric selector %s\n", selector);
                return -2;
            }

            unsigned long max_val = UINT32_MAX;
            switch (ftype) {
                case FT_UINT8:  max_val = 0xFF;        break;
                case FT_UINT16: max_val = 0xFFFF;      break;
                case FT_UINT24: max_val = 0xFFFFFF;    break;
                case FT_UINT32: max_val = 0xFFFFFFFFUL; break;
                default: break;
            }
            if (value > max_val) {
                fprintf(stderr, "decode_as: selector %s out of range (max=%lu, type=%d)\n",
                        selector, max_val, ftype);
                return -2;
            }

            dissector_change_uint(table_name, (uint32_t)value, handle);

            decode_as_entry entry = {
                .table = g_strdup(table_name),
                .is_string = false,
                .uint_value = (uint32_t)value,
            };
            g_array_append_val(g_decode_as_entries, entry);
        }
    }
    return 0;
}

/**
 * Clean the capture file struct and epan mod.
 */
static void clean() {
    reset_decode_as_rules();
    if (cf.provider.frames != NULL) {
        free_frame_data_sequence(cf.provider.frames);
        cf.provider.frames = NULL;
    }
    if (cf.provider.wth != NULL) {
        wtap_close(cf.provider.wth);
        cf.provider.wth = NULL;
    }
    if (cf.epan != NULL) {
        epan_free(cf.epan);
    }
    epan_cleanup();
    restore_global_session_options();
}

/**
 * Clean the capture file struct.
 * Note: epan instance is reused across requests for stability.
 * Only the file handle and frame data are released.
 */
static void close_cf() {
    reset_decode_as_rules();
    cf.stop_flag = FALSE;
    if (cf.provider.wth) {
        wtap_close(cf.provider.wth);
        cf.provider.wth = NULL;
    }

    if (cf.filename != NULL) {
        g_free(cf.filename);
        cf.filename = NULL;
    }

    cf.unsaved_changes = FALSE;
    cf.open_type = WTAP_TYPE_AUTO;

    wtap_rec_cleanup(&cf.rec);

    cf.rfcode = NULL;
    if (cf.provider.frames != NULL) {
        free_frame_data_sequence(cf.provider.frames);
        cf.provider.frames = NULL;
    }
    if (cf.provider.frames_modified_blocks) {
        g_tree_destroy(cf.provider.frames_modified_blocks);
        cf.provider.frames_modified_blocks = NULL;
    }

    cf.count = 0;
    cf.current_frame = NULL;
    cf.finfo_selected = NULL;

    if (cf.linktypes != NULL) {
        g_array_free(cf.linktypes, TRUE);
        cf.linktypes = NULL;
    }

    cf.f_datalen = 0;
    nstime_set_zero(&cf.elapsed_time);

    reset_tap_listeners();

    epan_free(cf.epan);
    cf.epan = NULL;

    restore_global_session_options();

    cf.state = FILE_CLOSED;
}

void close_capture_file(void) {
    close_cf();
}

// --- Session lifecycle ---

int session_reset_read_position(void) {
    int err = 0;
    gchar *err_info = NULL;

    if (cf.provider.wth) {
        wtap_close(cf.provider.wth);
        cf.provider.wth = NULL;
    }

    cf.count = 0;
    cf.current_frame = NULL;

    if (cf.provider.frames) {
        free_frame_data_sequence(cf.provider.frames);
        cf.provider.frames = new_frame_data_sequence();
    }

    cf.provider.ref = NULL;
    cf.provider.prev_dis = NULL;
    cf.provider.prev_cap = NULL;
    nstime_set_unset(&cf.elapsed_time);

    cf.provider.wth = wtap_open_offline(cf.filename, WTAP_TYPE_AUTO, &err, &err_info, TRUE);
    if (cf.provider.wth == NULL) {
        fprintf(stderr, "session_reset_read_position: wtap_open_offline failed, err=%d err_info=%s\n",
                err, err_info ? err_info : "(null)");
        if (err_info) g_free(err_info);
        return err != 0 ? err : -1;
    }
    return 0;
}

// --- Frame offset index ---

static GArray *g_frame_index = NULL;
static int g_frame_index_count = 0;

int build_frame_index(void) {
    if (session_reset_read_position() != 0) {
        return -1;
    }

    if (g_frame_index) {
        g_array_free(g_frame_index, TRUE);
        g_frame_index = NULL;
    }
    g_frame_index_count = 0;
    g_frame_index = g_array_new(FALSE, TRUE, sizeof(int64_t));

    int err = 0;
    gchar *err_info = NULL;
    int64_t prev_offset = 0;
    int64_t data_offset = 0;
    wtap_rec rec;
    wtap_rec_init(&rec, 1514);

    while (wtap_read(cf.provider.wth, &rec, &err, &err_info, &data_offset)) {
        g_array_append_val(g_frame_index, prev_offset);
        g_frame_index_count++;
        prev_offset = data_offset;
        wtap_rec_reset(&rec);
    }

    wtap_rec_cleanup(&rec);
    return g_frame_index_count;
}

int get_frame_index_count(void) {
    return g_frame_index_count;
}

void free_frame_index(void) {
    if (g_frame_index) {
        g_array_free(g_frame_index, TRUE);
        g_frame_index = NULL;
    }
    g_frame_index_count = 0;
}

// --- Initialization ---

/**
 * Init and fill the capture file struct.
 *
 *  @param filepath the pcap file path
 *  @return 0 if init correctly
 */
int init_cf(char *filepath, char *options) {
    char *keysList = NULL;
    char *keylogFile = NULL;
    int desegmentSslRecords = 0;
    int desegmentSslApplicationData = 0;
    int printTcpStreams = 0;
    cJSON *options_json = NULL;
    cJSON *decodeAsJson = NULL;
    const cJSON *nameResolutionJson = NULL;
    const cJSON *preferencesJson = NULL;
    const cJSON *profileJson = NULL;

    if (!gbl_resolv_saved) {
        memcpy(&saved_gbl_resolv_flags, &gbl_resolv_flags, sizeof(e_addr_resolve));
        gbl_resolv_saved = true;
    }
    if (saved_profile_name != NULL) {
        g_free(saved_profile_name);
        saved_profile_name = NULL;
    }
    const char *current_profile = get_profile_name();
    if (current_profile != NULL) {
        saved_profile_name = g_strdup(current_profile);
    }

    // handle conf
    if (!is_empty_json(options)) {
        options_json = cJSON_Parse(options);
        if (options_json == NULL) {
            fprintf(stderr, "Error: Failed to parse options JSON.\n");
            restore_global_session_options();
            return -1;
        }

        // Extract values from JSON
        const cJSON *keysListJson = cJSON_GetObjectItemCaseSensitive(options_json, "tls.keys_list");
        const cJSON *desegmentSslRecordsJson =
            cJSON_GetObjectItemCaseSensitive(options_json, "tls.desegment_ssl_records");
        const cJSON *desegmentSslApplicationDataJson =
            cJSON_GetObjectItemCaseSensitive(options_json, "tls.desegment_ssl_application_data");
        const cJSON *keylogFileJson =
            cJSON_GetObjectItemCaseSensitive(options_json, "tls.keylog_file");

        const cJSON *printTcpStreamsJson =
            cJSON_GetObjectItemCaseSensitive(options_json, "printTcpStreams");
        decodeAsJson = cJSON_GetObjectItemCaseSensitive(options_json, "decode_as");
        nameResolutionJson = cJSON_GetObjectItemCaseSensitive(options_json, "name_resolution");
        preferencesJson = cJSON_GetObjectItemCaseSensitive(options_json, "preferences");
        profileJson = cJSON_GetObjectItemCaseSensitive(options_json, "profile");

        // Copy keys list if present
        if (cJSON_IsString(keysListJson) && (keysListJson->valuestring != NULL)) {
            keysList = strdup(keysListJson->valuestring);
        }

        // Copy keylog file path if present
        if (cJSON_IsString(keylogFileJson) && (keylogFileJson->valuestring != NULL)) {
            keylogFile = strdup(keylogFileJson->valuestring);
        }

        // Set flags for desegment options
        desegmentSslRecords =
            cJSON_IsBool(desegmentSslRecordsJson) && cJSON_IsTrue(desegmentSslRecordsJson);
        desegmentSslApplicationData = cJSON_IsBool(desegmentSslApplicationDataJson) &&
                                      cJSON_IsTrue(desegmentSslApplicationDataJson);
        printTcpStreams = cJSON_IsBool(printTcpStreamsJson) && cJSON_IsTrue(printTcpStreamsJson);

        // Set profile early — must be before epan_load_settings
        if (cJSON_IsString(profileJson) && profileJson->valuestring != NULL) {
            const char *profile_name = profileJson->valuestring;
            if (!profile_exists(profile_name, FALSE) && !profile_exists(profile_name, TRUE)) {
                fprintf(stderr, "profile '%s' does not exist\n", profile_name);
                cJSON_Delete(options_json);
                restore_global_session_options();
                return -3;
            }
            set_profile_name(profile_name);
        }
    }

    int err = 0;
    gchar *err_info = NULL;
    e_prefs *prefs_p;

    /*
     * Release the previous capture before resetting the global struct. Reusing
     * init_cf without this leaves stale epan/tap state alive across operations,
     * which changes protocol classification on later scans.
     */
    if (cf.provider.wth != NULL || cf.provider.frames != NULL || cf.filename != NULL || cf.epan != NULL) {
        close_cf();
    }

    /* Initialize the capture file struct */
    memset(&cf, 0, sizeof(capture_file));
    cf.filename = g_strdup(filepath);
    cf.provider.wth = wtap_open_offline(cf.filename, WTAP_TYPE_AUTO, &err, &err_info, TRUE);
    if (err != 0 || cf.provider.wth == NULL) {
        if (options_json != NULL) {
            cJSON_Delete(options_json);
        }
        clean();
        return err;
    }
    cf.count = 0;
    cf.provider.frames = new_frame_data_sequence();
    static const struct packet_provider_funcs funcs = {
        cap_file_provider_get_frame_ts,
        cap_file_provider_get_interface_name,
        cap_file_provider_get_interface_description,
        NULL,
        NULL,
        NULL,
        NULL,
    };

    // Apply TLS preferences
    tls_prefs_apply(keysList, desegmentSslRecords, desegmentSslApplicationData, keylogFile);
    if (keysList != NULL) {
        free(keysList);
    }
    if (keylogFile != NULL) {
        free(keylogFile);
    }

    // Free previous epan instance if exists, then create new one
    if (cf.epan != NULL) {
        epan_free(cf.epan);
        cf.epan = NULL;
    }
    cf.epan = epan_new(&cf.provider, &funcs);

    // setup tcp follow tap
    if (printTcpStreams) {
        setup_tcp_follow_tap();
    }

    prefs_reset();
    prefs_p = epan_load_settings();

    // Apply preferences overrides (equivalent to -o flags)
    if (preferencesJson != NULL && cJSON_IsArray(preferencesJson)) {
        cJSON *pref;
        cJSON_ArrayForEach(pref, preferencesJson) {
            const cJSON *pn = cJSON_GetObjectItemCaseSensitive(pref, "name");
            const cJSON *pv = cJSON_GetObjectItemCaseSensitive(pref, "value");
            if (cJSON_IsString(pn) && cJSON_IsString(pv) &&
                pn->valuestring != NULL && pv->valuestring != NULL) {
                char *prefarg = g_strdup_printf("%s:%s", pn->valuestring, pv->valuestring);
                char *errmsg = NULL;
                prefs_set_pref_e result = prefs_set_pref(prefarg, &errmsg);
                if (result != PREFS_SET_OK) {
                    fprintf(stderr, "prefs_set_pref(%s): %s\n", prefarg, errmsg ? errmsg : "unknown error");
                    if (errmsg) g_free(errmsg);
                    g_free(prefarg);
                    if (options_json != NULL) {
                        cJSON_Delete(options_json);
                    }
                    close_cf();
                    return -4;
                }
                if (errmsg) g_free(errmsg);
                g_free(prefarg);
            }
        }
    }

    // Apply name resolution flags
    if (nameResolutionJson != NULL) {
        const cJSON *macJ = cJSON_GetObjectItemCaseSensitive(nameResolutionJson, "mac");
        const cJSON *netJ = cJSON_GetObjectItemCaseSensitive(nameResolutionJson, "network");
        const cJSON *trJ = cJSON_GetObjectItemCaseSensitive(nameResolutionJson, "transport");
        const cJSON *extJ = cJSON_GetObjectItemCaseSensitive(nameResolutionJson, "external");
        if (cJSON_IsBool(macJ))
            gbl_resolv_flags.mac_name = cJSON_IsTrue(macJ);
        if (cJSON_IsBool(netJ))
            gbl_resolv_flags.network_name = cJSON_IsTrue(netJ);
        if (cJSON_IsBool(trJ))
            gbl_resolv_flags.transport_name = cJSON_IsTrue(trJ);
        if (cJSON_IsBool(extJ))
            gbl_resolv_flags.use_external_net_name_resolver = cJSON_IsTrue(extJ);
    }

    if (apply_decode_as_rules(decodeAsJson) != 0) {
        if (options_json != NULL) {
            cJSON_Delete(options_json);
        }
        close_cf();
        return -2;
    }
    if (options_json != NULL) {
        cJSON_Delete(options_json);
    }
    build_column_format_array(&cf.cinfo, prefs_p->num_cols, TRUE);
    return 0;
}

static void write_json_index(json_dumper *dumper, epan_dissect_t *edt) {
    char ts[30];
    struct tm *timeinfo;
    char *str;

    timeinfo = localtime(&edt->pi.abs_ts.secs);
    if (timeinfo != NULL) {
        strftime(ts, sizeof(ts), "%Y-%m-%d", timeinfo);
    } else {
        (void)g_strlcpy(ts, "XXXX-XX-XX",
                        sizeof(ts)); /* XXX - better way of saying "Not representable"? */
    }
    json_dumper_set_member_name(dumper, "_index");
    str = ws_strdup_printf("packets-%s", ts);
    json_dumper_value_string(dumper, str);
    g_free(str);
}

/**
 * Returns the json key of a node. Tries to use the node's abbreviated name.
 * If the abbreviated name is not available the representation is used instead.
 *
 * XXX: The representation can have spaces or differ depending on the content,
 * which makes it difficult to match text-only fields with a -j/-J filter in
 * tshark. (Issue #17125).
 */
static const char *proto_node_to_json_key(proto_node *node) {
    const char *json_key;
    // Check if node has abbreviated name.
    if (node->finfo->hfinfo->id != hf_text_only) {
        json_key = node->finfo->hfinfo->abbrev;
    } else if (node->finfo->rep != NULL) {
        json_key = node->finfo->rep->representation;
    } else {
        json_key = "";
    }

    return json_key;
}

/**
 * Returns a boolean telling us whether that node list contains any node which
 * has children
 */
static bool any_has_children(GSList *node_values_list) {
    GSList *current_node = node_values_list;
    while (current_node != NULL) {
        proto_node *current_value = (proto_node *)current_node->data;
        if (current_value->first_child != NULL) {
            return true;
        }
        current_node = current_node->next;
    }
    return false;
}

/**
 * Writes the value of a node to the output.
 */
static void write_json_proto_node_value(proto_node *node, write_json_data *pdata) {
    field_info *fi = node->finfo;
    // Get the actual value of the node as a string.
    char *value_string_repr =
        fvalue_to_string_repr(NULL, fi->value, FTREPR_JSON, fi->hfinfo->display);

    // TODO: Have FTREPR_JSON include quotes where appropriate and use
    // json_dumper_value_anyf() here,
    //  so we can output booleans and numbers and not only strings.
    json_dumper_value_string(pdata->dumper, value_string_repr);

    wmem_free(NULL, value_string_repr);
}

/**
 * Write the value for a node that has no value and no children. This is the
 * empty string for all nodes except those of type FT_PROTOCOL for which the
 * full name is written instead.
 */
static void write_json_proto_node_no_value(proto_node *node, write_json_data *pdata) {
    field_info *fi = node->finfo;

    if (fi->hfinfo->type == FT_PROTOCOL) {
        if (fi->rep) {
            json_dumper_value_string(pdata->dumper, fi->rep->representation);
        } else {
            char label_str[ITEM_LABEL_LENGTH];
            proto_item_fill_label(fi, label_str, NULL);
            json_dumper_value_string(pdata->dumper, label_str);
        }
    } else {
        json_dumper_value_string(pdata->dumper, "");
    }
}

static void write_json_proto_node_dynamic(proto_node *node, write_json_data *data) {
    if (node->first_child == NULL) {
        write_json_proto_node_no_value(node, data);
    } else {
        write_json_proto_node_children(node, data);
    }
}

/**
 * Writes a single node as a key:value pair. The value_writer param can be used
 * to specify how the node's value should be written.
 * @param node_values_head Linked list containing all nodes associated with the
 * same json key in this object.
 * @param suffix Suffix that should be added to the json key.
 * @param value_writer A function which writes the actual values of the node
 * json key.
 * @param pdata json writing metadata
 */
static void write_json_proto_node(GSList *node_values_head, const char *suffix,
                                  proto_node_value_writer value_writer, write_json_data *pdata) {
    // Retrieve json key from first value.
    proto_node *first_value = (proto_node *)node_values_head->data;
    const char *json_key = proto_node_to_json_key(first_value);
    char *json_key_suffix = ws_strdup_printf("%s%s", json_key, suffix);
    json_dumper_set_member_name(pdata->dumper, json_key_suffix);
    g_free(json_key_suffix);
    write_json_proto_node_value_list(node_values_head, value_writer, pdata);
}

/**
 * Writes a list of values of a single json key. If multiple values are passed
 * they are wrapped in a json array.
 * @param node_values_head Linked list containing all values that should be
 * written.
 * @param value_writer Function which writes the separate values.
 * @param pdata json writing metadata
 */
static void write_json_proto_node_value_list(GSList *node_values_head,
                                             proto_node_value_writer value_writer,
                                             write_json_data *pdata) {
    GSList *current_value = node_values_head;

    // Write directly if only a single value is passed. Wrap in json array
    // otherwise.
    if (current_value->next == NULL) {
        value_writer((proto_node *)current_value->data, pdata);
    } else {
        json_dumper_begin_array(pdata->dumper);

        while (current_value != NULL) {
            value_writer((proto_node *)current_value->data, pdata);
            current_value = current_value->next;
        }
        json_dumper_end_array(pdata->dumper);
    }
}

/**
 * Write a json object containing a list of key:value pairs where each key:value
 * pair corresponds to a different json key and its associated nodes in the
 * proto_tree.
 * @param proto_node_list_head A 2-dimensional list containing a list of values
 * for each different node json key. The elements themselves are a linked list
 * of values associated with the same json key.
 * @param pdata json writing metadata
 */
static void write_json_proto_node_list(GSList *proto_node_list_head, write_json_data *pdata) {
    json_dumper_begin_object(pdata->dumper);

    // hash table
    GHashTable *key_nodes = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);

    // First traversal: Group nodes with the same key
    GSList *current_node = proto_node_list_head;
    while (current_node != NULL) {
        GSList *node_values_list = (GSList *)current_node->data;
        proto_node *first_value = (proto_node *)node_values_list->data;
        const char *json_key = proto_node_to_json_key(first_value);

        GSList *existing_list = g_hash_table_lookup(key_nodes, json_key);
        if (existing_list == NULL) {
            g_hash_table_insert(key_nodes, (gpointer)json_key, node_values_list);
        } else {
            // Merge the list of nodes with the same key
            GSList *combined_list =
                g_slist_concat(g_slist_copy(existing_list), g_slist_copy(node_values_list));
            g_hash_table_replace(key_nodes, (gpointer)json_key, combined_list);
        }

        current_node = current_node->next;
    }

    // Second traversal: output merged nodes
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, key_nodes);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        GSList *node_values_list = (GSList *)value;
        proto_node *first_value = (proto_node *)node_values_list->data;

        field_info *fi = first_value->finfo;
        char *value_string_repr =
            fvalue_to_string_repr(NULL, fi->value, FTREPR_JSON, fi->hfinfo->display);
        bool has_children = any_has_children(node_values_list);

        // descriptive values
        gchar label_str[ITEM_LABEL_LENGTH];
        gchar *label_ptr;
        if (!fi->rep) {
            label_ptr = label_str;
            proto_item_fill_label(fi, label_str, NULL);
            char *value_ptr = strstr(label_ptr, ": ");
            if (value_ptr != NULL) {
                value_string_repr = value_ptr + 2;
            }
        }

        gboolean has_value = value_string_repr != NULL;

        if (has_value) {
            write_json_proto_node(node_values_list, "", write_json_proto_node_value, pdata);
        }

        if (has_children) {
            char *suffix = has_value ? "_tree" : "";
            write_json_proto_node(node_values_list, suffix, write_json_proto_node_dynamic, pdata);
        }

        if (!has_value && !has_children) {
            write_json_proto_node(node_values_list, "", write_json_proto_node_no_value, pdata);
        }
    }

    // clean
    g_hash_table_destroy(key_nodes);

    json_dumper_end_object(pdata->dumper);
}

/**
 * Writes the children of a node. Calls get_json_proto_tree internally
 * which recursively writes children of nodes to the output.
 */
static void write_json_proto_node_children(proto_node *node, write_json_data *data) {
    GSList *grouped_children_list = data->node_children_grouper(node);
    write_json_proto_node_list(grouped_children_list, data);
    g_slist_free_full(grouped_children_list, (GDestroyNotify)g_slist_free);
}

/**
 * Get protocol tree dissect result in json format.
 */
void get_json_proto_tree(output_fields_t *fields, print_dissections_e print_dissections,
                         gboolean print_hex, gchar **protocolfilter, pf_flags protocolfilter_flags,
                         epan_dissect_t *edt, column_info *cinfo,
                         proto_node_children_grouper_func node_children_grouper,
                         json_dumper *dumper) {
    write_json_data data;
    data.dumper = dumper;

    json_dumper_begin_object(dumper);
    write_json_index(dumper, edt);

    json_dumper_set_member_name(dumper, "layers");

    data.src_list = edt->pi.data_src;
    data.print_hex = print_hex;
    data.print_text = TRUE;
    data.node_children_grouper = node_children_grouper;
    write_json_proto_node_children(edt->tree, &data);

    json_dumper_end_object(dumper);
}

// --- Internal Processing Helpers ---

/**
 * Read each frame.
 *
 *  @param edt_r the epan_dissect_t struct of each frame
 *  @return true if can dissect frame correctly, false if can not read frame
 */
static bool read_packet(epan_dissect_t **edt_r) {
    if (!edt_r) return false;

    epan_dissect_t *edt = NULL;
    int err;
    gchar *err_info = NULL;
    guint32 cum_bytes = 0;
    int64_t data_offset = 0;
    wtap_rec rec;

    wtap_rec_init(&rec, 1514);

    if (!wtap_read(cf.provider.wth, &rec, &err, &err_info, &data_offset)) {
        wtap_rec_cleanup(&rec);
        return false;
    }

    cf.count++;

    frame_data fd;
    frame_data_init(&fd, cf.count, &rec, data_offset, cum_bytes);

    // data_offset must be correctly set
    data_offset = fd.pkt_len;
    edt = epan_dissect_new(cf.epan, TRUE, TRUE);
    if (!edt) {
        frame_data_destroy(&fd);
        wtap_rec_reset(&rec);
        return false;
    }

    frame_data_set_before_dissect(&fd, &cf.elapsed_time, &cf.provider.ref, cf.provider.prev_dis);

    cf.provider.ref = &fd;

    // core dissect process
    epan_dissect_run_with_taps(edt, cf.cd_t, &rec, &fd, &cf.cinfo);
    frame_data_set_after_dissect(&fd, &cum_bytes);

    cf.provider.prev_cap = cf.provider.prev_dis = frame_data_sequence_add(cf.provider.frames, &fd);

    // free space
    wtap_rec_cleanup(&rec);

    *edt_r = edt;
    return true;
}

/**
 * Dissect and get hex data of specific frame.
 *
 *  @param num the index of frame which you want to dissect
 *  @return char of hex data dissect result, include hex data
 */
char *get_specific_frame_hex_data(int num) {
    epan_dissect_t *edt;
    // start reading packets
    while (read_packet(&edt)) {
        if (num != cf.count) {
            epan_dissect_free(edt);
            edt = NULL;
            continue;
        }

        cJSON *cjson_hex_root = cJSON_CreateObject();

        cJSON *cjson_offset = cJSON_CreateArray();
        cJSON *cjson_hex = cJSON_CreateArray();
        cJSON *cjson_ascii = cJSON_CreateArray();

        get_hex_data(edt, cjson_offset, cjson_hex, cjson_ascii);

        cJSON_AddItemToObject(cjson_hex_root, "offset", cjson_offset);
        cJSON_AddItemToObject(cjson_hex_root, "hex", cjson_hex);
        cJSON_AddItemToObject(cjson_hex_root, "ascii", cjson_ascii);

        epan_dissect_free(edt);
        edt = NULL;

        char *res = cJSON_PrintUnformatted(cjson_hex_root);
        cJSON_Delete(cjson_hex_root);

        return res;
    }

    return strdup("");
}

/**
 * Transfer proto tree to json format.
 *
 *  @param num the index of frame which you want to dissect
 *  @return char of protocol tree dissect result
 */
char *proto_tree_in_json(int num, int printCJson) {
    epan_dissect_t *edt;

    // start reading packets
    while (read_packet(&edt)) {
        if (num != cf.count) {
            epan_dissect_free(edt);
            edt = NULL;
            continue;
        }

        json_dumper dumper = {};
        dumper.output_string = g_string_new(NULL);

        get_json_proto_tree(NULL, print_dissections_expanded, FALSE, NULL, PF_INCLUDE_CHILDREN, edt,
                            &cf.cinfo, proto_node_group_children_by_unique, &dumper);

        // Get JSON string from json_dumper
        char *json_str = NULL;
        if (json_dumper_finish(&dumper)) {
            json_str = g_strdup(dumper.output_string->str);
        }

        // cleanup
        if (dumper.output_string) {
            g_string_free(dumper.output_string, TRUE);
        }
        epan_dissect_free(edt);

        if (printCJson) {
            printf("%s\n", json_str);
        }

        return json_str ? json_str : g_strdup("");
    }

    return g_strdup("");
}

// --- Optimized Callbacks (Single Pass I/O) ---

void get_all_frames_cb(int printCJson, char *filter_str, FrameCallback callback) {
    epan_dissect_t *edt;
    cf.count = 0;
    int err = 0;
    gchar *err_info = NULL;
    int64_t data_offset = 0;
    guint32 cum_bytes = 0;
    wtap_rec rec;
    wtap_rec_init(&rec, 1514);

    dfilter_t *dfcode = NULL;
    if (filter_str != NULL && strlen(filter_str) > 0) {
        if (!dfilter_compile(filter_str, &dfcode, NULL)) {
            fprintf(stderr, "Filter compile failed: %s\n", filter_str);
        }
    }

    while (wtap_read(cf.provider.wth, &rec, &err, &err_info, &data_offset)) {
        cf.count++;
        frame_data fd;
        frame_data_init(&fd, cf.count, &rec, data_offset, 0);

        edt = epan_dissect_new(cf.epan, TRUE, TRUE);

        if (dfcode != NULL) {
            epan_dissect_prime_with_dfilter(edt, dfcode);
        }

        frame_data_set_before_dissect(&fd, &cf.elapsed_time, &cf.provider.ref, cf.provider.prev_dis);
        cf.provider.ref = &fd;

        epan_dissect_run_with_taps(edt, cf.cd_t, &rec, &fd, &cf.cinfo);

        frame_data_set_after_dissect(&fd, &cum_bytes);
        cf.provider.prev_cap = cf.provider.prev_dis = frame_data_sequence_add(cf.provider.frames, &fd);

        if (dfcode != NULL) {
            if (!dfilter_apply_edt(dfcode, edt)) {
                epan_dissect_free(edt);
                wtap_rec_reset(&rec);
                continue;
            }
        }

        json_dumper dumper = {};
        dumper.output_string = g_string_new(NULL);
        get_json_proto_tree(NULL, print_dissections_expanded, FALSE, NULL, PF_INCLUDE_CHILDREN, edt,
                            &cf.cinfo, proto_node_group_children_by_unique, &dumper);

        if (json_dumper_finish(&dumper)) {
            if (printCJson) printf("%s\n", dumper.output_string->str);
            if (callback(dumper.output_string->str, dumper.output_string->len, 0) != 0) {
                if (dumper.output_string) g_string_free(dumper.output_string, TRUE);
                epan_dissect_free(edt);
                wtap_rec_reset(&rec);
                break;
            }
        }

        if (dumper.output_string) g_string_free(dumper.output_string, TRUE);
        epan_dissect_free(edt);
        wtap_rec_reset(&rec);
    }

    if (dfcode != NULL) dfilter_free(dfcode);
    wtap_rec_cleanup(&rec);
}

typedef struct {
    cJSON *arr;
} expert_batch_data;

static tap_packet_status
expert_info_batch_packet_cb(void *tapdata, packet_info *pinfo _U_,
                            epan_dissect_t *edt _U_, const void *pointer,
                            tap_flags_t flags _U_) {
    expert_batch_data *data = (expert_batch_data *)tapdata;
    const expert_info_t *ei = (const expert_info_t *)pointer;
    const header_field_info *hfinfo = NULL;
    const char *severity = NULL;
    const char *group = NULL;

    if (data == NULL || ei == NULL) {
        return TAP_PACKET_DONT_REDRAW;
    }

    if (ei->hf_index >= 0) {
        hfinfo = proto_registrar_get_nth(ei->hf_index);
    }
    severity = try_val_to_str(ei->severity, expert_severity_vals);
    group = try_val_to_str(ei->group, expert_group_vals);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "frameNumber", ei->packet_num);
    cJSON_AddStringToObject(root, "severity", severity ? severity : "");
    cJSON_AddStringToObject(root, "group", group ? group : "");
    cJSON_AddStringToObject(root, "protocol", ei->protocol ? ei->protocol : "");
    cJSON_AddStringToObject(root, "summary", ei->summary ? ei->summary : "");
    cJSON_AddStringToObject(root, "message", ei->summary ? ei->summary : "");
    cJSON_AddStringToObject(root, "field", hfinfo && hfinfo->abbrev ? hfinfo->abbrev : "");
    cJSON_AddStringToObject(root, "name", hfinfo && hfinfo->name ? hfinfo->name : "");

    cJSON_AddItemToArray(data->arr, root);
    return TAP_PACKET_DONT_REDRAW;
}

char *get_expert_infos_json(const char *filter_str) {
    expert_batch_data data;
    data.arr = cJSON_CreateArray();

    GString *tap_error = register_tap_listener("expert", &data, filter_str, 0, NULL,
                                               expert_info_batch_packet_cb, NULL, NULL);
    if (tap_error != NULL) {
        fprintf(stderr, "expert tap registration failed: %s\n", tap_error->str);
        g_string_free(tap_error, TRUE);
        cJSON_Delete(data.arr);
        return strdup("[]");
    }

    cf.count = 0;
    int err = 0;
    gchar *err_info = NULL;
    int64_t data_offset = 0;
    guint32 cum_bytes = 0;
    wtap_rec rec;
    wtap_rec_init(&rec, 1514);

    while (wtap_read(cf.provider.wth, &rec, &err, &err_info, &data_offset)) {
        cf.count++;
        frame_data fd;
        frame_data_init(&fd, cf.count, &rec, data_offset, 0);

        epan_dissect_t *edt = epan_dissect_new(cf.epan, TRUE, TRUE);
        frame_data_set_before_dissect(&fd, &cf.elapsed_time,
                                      &cf.provider.ref, cf.provider.prev_dis);
        cf.provider.ref = &fd;

        epan_dissect_run_with_taps(edt, cf.cd_t, &rec, &fd, &cf.cinfo);

        frame_data_set_after_dissect(&fd, &cum_bytes);
        cf.provider.prev_cap = cf.provider.prev_dis =
            frame_data_sequence_add(cf.provider.frames, &fd);

        epan_dissect_free(edt);
        wtap_rec_reset(&rec);
    }

    remove_tap_listener(&data);
    wtap_rec_cleanup(&rec);
    if (err_info != NULL) {
        g_free(err_info);
    }

    char *result = cJSON_PrintUnformatted(data.arr);
    cJSON_Delete(data.arr);
    return result;
}

char *get_stream_payloads_json(const char *filter_str, const char *proto) {
    cJSON *result_arr = cJSON_CreateArray();

    cf.count = 0;
    int err = 0;
    gchar *err_info = NULL;
    int64_t data_offset = 0;
    guint32 cum_bytes = 0;
    wtap_rec rec;
    wtap_rec_init(&rec, 1514);

    dfilter_t *dfcode = NULL;
    df_error_t *df_err = NULL;
    if (filter_str != NULL && strlen(filter_str) > 0) {
        if (!dfilter_compile(filter_str, &dfcode, &df_err)) {
            fprintf(stderr, "get_stream_payloads_json: invalid filter '%s': %s\n",
                    filter_str, df_err ? df_err->msg : "unknown error");
            if (df_err) df_error_free(&df_err);
            wtap_rec_cleanup(&rec);
            cJSON_Delete(result_arr);
            return strdup("{\"matched_count\":0,\"payloads\":[],\"error\":\"invalid filter\"}");
        }
    }

    int payload_id = proto_registrar_get_id_byname(
        strcmp(proto, "tcp") == 0 ? "tcp.payload" : "udp.payload");
    int matched_packets = 0;

    while (wtap_read(cf.provider.wth, &rec, &err, &err_info, &data_offset)) {
        cf.count++;
        frame_data fd;
        frame_data_init(&fd, cf.count, &rec, data_offset, 0);

        epan_dissect_t *edt = epan_dissect_new(cf.epan, TRUE, TRUE);

        if (dfcode != NULL) epan_dissect_prime_with_dfilter(edt, dfcode);
        if (payload_id != -1) epan_dissect_prime_with_hfid(edt, payload_id);

        frame_data_set_before_dissect(&fd, &cf.elapsed_time,
                                      &cf.provider.ref, cf.provider.prev_dis);
        cf.provider.ref = &fd;

        epan_dissect_run_with_taps(edt, cf.cd_t, &rec, &fd, &cf.cinfo);

        frame_data_set_after_dissect(&fd, &cum_bytes);
        cf.provider.prev_cap = cf.provider.prev_dis =
            frame_data_sequence_add(cf.provider.frames, &fd);

        if (dfcode != NULL) {
            if (!dfilter_apply_edt(dfcode, edt)) {
                epan_dissect_free(edt);
                wtap_rec_reset(&rec);
                continue;
            }
        }

        matched_packets++;

        char src_ip[WS_INET6_ADDRSTRLEN] = {0};
        char dst_ip[WS_INET6_ADDRSTRLEN] = {0};
        address_to_str_buf(&edt->pi.src, src_ip, sizeof(src_ip));
        address_to_str_buf(&edt->pi.dst, dst_ip, sizeof(dst_ip));
        guint32 src_port = edt->pi.srcport;
        guint32 dst_port = edt->pi.destport;

        char *payload_hex = NULL;
        if (payload_id != -1) {
            GPtrArray *finfo_array = proto_get_finfo_ptr_array(edt->tree, payload_id);
            if (finfo_array && finfo_array->len > 0) {
                GString *hex_builder = g_string_new("");

                for (guint i = 0; i < finfo_array->len; i++) {
                    field_info *fi = (field_info *)g_ptr_array_index(finfo_array, i);
                    if (fi && fi->value) {
                        char *raw_repr = fvalue_to_string_repr(NULL, fi->value,
                            FTREPR_JSON, fi->hfinfo->display);
                        if (raw_repr) {
                            char *r = raw_repr;
                            char *w = raw_repr;
                            while (*r) {
                                if (*r != ':') { *w++ = *r; }
                                r++;
                            }
                            *w = '\0';
                            g_string_append(hex_builder, raw_repr);
                            wmem_free(NULL, raw_repr);
                        }
                    }
                }
                payload_hex = g_string_free(hex_builder, FALSE);
            }
        }

        if (payload_hex != NULL && strlen(payload_hex) > 0) {
            cJSON *payload_obj = cJSON_CreateObject();
            cJSON_AddStringToObject(payload_obj, "src", src_ip);
            cJSON_AddStringToObject(payload_obj, "dst", dst_ip);
            cJSON_AddNumberToObject(payload_obj, "srcport", src_port);
            cJSON_AddNumberToObject(payload_obj, "dstport", dst_port);
            cJSON_AddStringToObject(payload_obj, "payload", payload_hex);
            cJSON_AddItemToArray(result_arr, payload_obj);
        }

        if (payload_hex != NULL) {
            g_free(payload_hex);
        }

        epan_dissect_free(edt);
        wtap_rec_reset(&rec);
    }

    if (dfcode != NULL) dfilter_free(dfcode);
    wtap_rec_cleanup(&rec);

    cJSON *wrapper = cJSON_CreateObject();
    cJSON_AddNumberToObject(wrapper, "matched_count", matched_packets);
    cJSON_AddItemToObject(wrapper, "payloads", result_arr);

    char *json_output = cJSON_PrintUnformatted(wrapper);
    cJSON_Delete(wrapper);
    return json_output;
}

static tap_packet_status expert_info_packet_cb(void *tapdata, packet_info *pinfo _U_,
                                               epan_dissect_t *edt _U_, const void *pointer,
                                               tap_flags_t flags _U_) {
    expert_callback_data *data = (expert_callback_data *)tapdata;
    const expert_info_t *ei = (const expert_info_t *)pointer;
    const header_field_info *hfinfo = NULL;
    const char *severity = NULL;
    const char *group = NULL;

    if (data == NULL || data->callback == NULL || ei == NULL) {
        return TAP_PACKET_DONT_REDRAW;
    }

    if (ei->hf_index >= 0) {
        hfinfo = proto_registrar_get_nth(ei->hf_index);
    }
    severity = try_val_to_str(ei->severity, expert_severity_vals);
    group = try_val_to_str(ei->group, expert_group_vals);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "frameNumber", ei->packet_num);
    cJSON_AddStringToObject(root, "severity", severity ? severity : "");
    cJSON_AddStringToObject(root, "group", group ? group : "");
    cJSON_AddStringToObject(root, "protocol", ei->protocol ? ei->protocol : "");
    cJSON_AddStringToObject(root, "summary", ei->summary ? ei->summary : "");
    cJSON_AddStringToObject(root, "message", ei->summary ? ei->summary : "");
    cJSON_AddStringToObject(root, "field", hfinfo && hfinfo->abbrev ? hfinfo->abbrev : "");
    cJSON_AddStringToObject(root, "name", hfinfo && hfinfo->name ? hfinfo->name : "");

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (json != NULL) {
        if (data->callback(json, (int)strlen(json), 0) != 0) {
            data->stop = 1;
        }
        cJSON_free(json);
    }
    return TAP_PACKET_DONT_REDRAW;
}

int get_expert_infos_cb(const char *filter_str, FrameCallback callback) {
    expert_callback_data data = {
        .callback = callback,
        .stop = 0,
    };
    GString *tap_error = register_tap_listener("expert", &data, filter_str, 0, NULL,
                                               expert_info_packet_cb, NULL, NULL);
    if (tap_error != NULL) {
        fprintf(stderr, "expert tap registration failed: %s\n", tap_error->str);
        g_string_free(tap_error, TRUE);
        return -1;
    }

    cf.count = 0;
    int err = 0;
    gchar *err_info = NULL;
    int64_t data_offset = 0;
    guint32 cum_bytes = 0;
    wtap_rec rec;
    wtap_rec_init(&rec, 1514);

    while (!data.stop && wtap_read(cf.provider.wth, &rec, &err, &err_info, &data_offset)) {
        cf.count++;
        frame_data fd;
        frame_data_init(&fd, cf.count, &rec, data_offset, 0);

        epan_dissect_t *edt = epan_dissect_new(cf.epan, TRUE, TRUE);
        frame_data_set_before_dissect(&fd, &cf.elapsed_time, &cf.provider.ref, cf.provider.prev_dis);
        cf.provider.ref = &fd;

        epan_dissect_run_with_taps(edt, cf.cd_t, &rec, &fd, &cf.cinfo);

        frame_data_set_after_dissect(&fd, &cum_bytes);
        cf.provider.prev_cap = cf.provider.prev_dis = frame_data_sequence_add(cf.provider.frames, &fd);

        epan_dissect_free(edt);
        wtap_rec_reset(&rec);
    }

    remove_tap_listener(&data);
    wtap_rec_cleanup(&rec);
    if (err_info != NULL) {
        g_free(err_info);
    }
    return err;
}

static void conv_tap_draw_cb(void *tapdata) {
    conv_hash_t *hash = (conv_hash_t *)tapdata;
    conv_tap_callback_data *cb_data = (conv_tap_callback_data *)hash->user_data;

    if (cb_data == NULL || cb_data->callback == NULL || hash->conv_array == NULL) {
        return;
    }

    for (guint i = 0; i < hash->conv_array->len; i++) {
        conv_item_t *item = &g_array_index(hash->conv_array, conv_item_t, i);

        char src_addr[WS_INET6_ADDRSTRLEN];
        char dst_addr[WS_INET6_ADDRSTRLEN];
        address_to_str_buf(&item->src_address, src_addr, sizeof(src_addr));
        address_to_str_buf(&item->dst_address, dst_addr, sizeof(dst_addr));

        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "type", cb_data->type_name);
        cJSON_AddStringToObject(root, "addr1", src_addr);
        cJSON_AddNumberToObject(root, "port1", item->src_port);
        cJSON_AddStringToObject(root, "addr2", dst_addr);
        cJSON_AddNumberToObject(root, "port2", item->dst_port);
        cJSON_AddNumberToObject(root, "packetsAB", (double)item->tx_frames);
        cJSON_AddNumberToObject(root, "bytesAB", (double)item->tx_bytes);
        cJSON_AddNumberToObject(root, "packetsBA", (double)item->rx_frames);
        cJSON_AddNumberToObject(root, "bytesBA", (double)item->rx_bytes);
        cJSON_AddNumberToObject(root, "totalPackets", (double)(item->tx_frames + item->rx_frames));
        cJSON_AddNumberToObject(root, "totalBytes", (double)(item->tx_bytes + item->rx_bytes));
        cJSON_AddNumberToObject(root, "startTime", nstime_to_sec(&item->start_time));
        cJSON_AddNumberToObject(root, "duration",
            nstime_to_sec(&item->stop_time) - nstime_to_sec(&item->start_time));

        char *json = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        if (json != NULL) {
            int stop = cb_data->callback(json, (int)strlen(json), 0);
            cb_data->count++;
            cJSON_free(json);
            if (stop != 0) break;
        }
    }
}

static void endpoint_tap_draw_cb(void *tapdata) {
    conv_hash_t *hash = (conv_hash_t *)tapdata;
    conv_tap_callback_data *cb_data = (conv_tap_callback_data *)hash->user_data;

    if (cb_data == NULL || cb_data->callback == NULL || hash->conv_array == NULL) {
        return;
    }

    for (guint i = 0; i < hash->conv_array->len; i++) {
        endpoint_item_t *item = &g_array_index(hash->conv_array, endpoint_item_t, i);

        char addr_str[WS_INET6_ADDRSTRLEN];
        address_to_str_buf(&item->myaddress, addr_str, sizeof(addr_str));

        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "type", cb_data->type_name);
        cJSON_AddStringToObject(root, "address", addr_str);
        cJSON_AddNumberToObject(root, "port", item->port);
        cJSON_AddNumberToObject(root, "packets", (double)(item->tx_frames + item->rx_frames));
        cJSON_AddNumberToObject(root, "bytes", (double)(item->tx_bytes + item->rx_bytes));

        char *json = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        if (json != NULL) {
            int stop = cb_data->callback(json, (int)strlen(json), 0);
            cb_data->count++;
            cJSON_free(json);
            if (stop != 0) break;
        }
    }
}

static int run_tap_scan(void) {
    cf.count = 0;
    int err = 0;
    gchar *err_info = NULL;
    int64_t data_offset = 0;
    guint32 cum_bytes = 0;
    wtap_rec rec;
    wtap_rec_init(&rec, 1514);

    while (wtap_read(cf.provider.wth, &rec, &err, &err_info, &data_offset)) {
        cf.count++;
        frame_data fd;
        frame_data_init(&fd, cf.count, &rec, data_offset, 0);

        epan_dissect_t *edt = epan_dissect_new(cf.epan, TRUE, TRUE);
        frame_data_set_before_dissect(&fd, &cf.elapsed_time, &cf.provider.ref, cf.provider.prev_dis);
        cf.provider.ref = &fd;

        epan_dissect_run_with_taps(edt, cf.cd_t, &rec, &fd, &cf.cinfo);

        frame_data_set_after_dissect(&fd, &cum_bytes);
        cf.provider.prev_cap = cf.provider.prev_dis = frame_data_sequence_add(cf.provider.frames, &fd);

        epan_dissect_free(edt);
        wtap_rec_reset(&rec);
    }

    wtap_rec_cleanup(&rec);
    if (err_info != NULL) {
        g_free(err_info);
    }
    return err;
}

int get_tap_conversations_cb(const char *filter_str, const char *conv_type, FrameCallback callback) {
    int proto_id = proto_get_id_by_filter_name(conv_type);
    if (proto_id == -1) {
        fprintf(stderr, "conversation tap: unknown protocol %s\n", conv_type);
        return -1;
    }

    register_ct_t *ct = get_conversation_by_proto_id(proto_id);
    if (ct == NULL) {
        fprintf(stderr, "conversation tap: no conversation table for %s\n", conv_type);
        return -1;
    }

    conv_tap_callback_data cb_data = {
        .callback = callback,
        .type_name = conv_type,
        .count = 0,
    };

    conv_hash_t hash;
    memset(&hash, 0, sizeof(conv_hash_t));
    hash.user_data = &cb_data;

    const char *tap_name = proto_get_protocol_filter_name(proto_id);
    GString *tap_error = register_tap_listener(tap_name, &hash, filter_str, 0, NULL,
                                               get_conversation_packet_func(ct),
                                               conv_tap_draw_cb, NULL);
    if (tap_error != NULL) {
        fprintf(stderr, "conversation tap registration failed: %s\n", tap_error->str);
        g_string_free(tap_error, TRUE);
        return -1;
    }

    int err = run_tap_scan();
    draw_tap_listeners(TRUE);
    remove_tap_listener(&hash);
    reset_conversation_table_data(&hash);

    return err;
}

int get_tap_endpoints_cb(const char *filter_str, const char *endpoint_type, FrameCallback callback) {
    int proto_id = proto_get_id_by_filter_name(endpoint_type);
    if (proto_id == -1) {
        fprintf(stderr, "endpoint tap: unknown protocol %s\n", endpoint_type);
        return -1;
    }

    register_ct_t *ct = get_conversation_by_proto_id(proto_id);
    if (ct == NULL) {
        fprintf(stderr, "endpoint tap: no conversation table for %s\n", endpoint_type);
        return -1;
    }

    conv_tap_callback_data cb_data = {
        .callback = callback,
        .type_name = endpoint_type,
        .count = 0,
    };

    conv_hash_t hash;
    memset(&hash, 0, sizeof(conv_hash_t));
    hash.user_data = &cb_data;

    const char *tap_name = proto_get_protocol_filter_name(proto_id);
    GString *tap_error = register_tap_listener(tap_name, &hash, filter_str, 0, NULL,
                                               get_endpoint_packet_func(ct),
                                               endpoint_tap_draw_cb, NULL);
    if (tap_error != NULL) {
        fprintf(stderr, "endpoint tap registration failed: %s\n", tap_error->str);
        g_string_free(tap_error, TRUE);
        return -1;
    }

    int err = run_tap_scan();
    draw_tap_listeners(TRUE);
    remove_tap_listener(&hash);
    reset_endpoint_table_data(&hash);

    return err;
}

typedef struct {
    FrameCallback callback;
    GSList *entries;
} eo_callback_data;

static void eo_add_entry_with_sha256(void *gui_data, export_object_entry_t *entry) {
    eo_callback_data *data = (eo_callback_data *)gui_data;

    char hostname_buf[256] = {0};
    char content_type_buf[256] = {0};
    char filename_buf[EXPORT_OBJECT_MAXFILELEN + 1] = {0};

    if (entry->hostname) {
        g_strlcpy(hostname_buf, entry->hostname, sizeof(hostname_buf));
    }
    if (entry->content_type) {
        g_strlcpy(content_type_buf, entry->content_type, sizeof(content_type_buf));
    }
    if (entry->filename) {
        g_strlcpy(filename_buf, entry->filename, sizeof(filename_buf));
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "packetNum", entry->pkt_num);
    cJSON_AddStringToObject(root, "hostname", hostname_buf);
    cJSON_AddStringToObject(root, "contentType", content_type_buf);
    cJSON_AddStringToObject(root, "filename", filename_buf);
    cJSON_AddNumberToObject(root, "length", (double)entry->payload_len);

    gchar *sha256_hex = NULL;
    if (entry->payload_data && entry->payload_len > 0) {
        sha256_hex = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
            entry->payload_data, entry->payload_len);
    }
    cJSON_AddStringToObject(root, "sha256", sha256_hex ? sha256_hex : "");
    if (sha256_hex) g_free(sha256_hex);

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (json != NULL) {
        data->callback(json, (int)strlen(json), 0);
        cJSON_free(json);
    }
}

static void eo_add_entry(void *gui_data, export_object_entry_t *entry) {
    eo_callback_data *data = (eo_callback_data *)gui_data;

    char hostname_buf[256] = {0};
    char content_type_buf[256] = {0};
    char filename_buf[EXPORT_OBJECT_MAXFILELEN + 1] = {0};

    if (entry->hostname) {
        g_strlcpy(hostname_buf, entry->hostname, sizeof(hostname_buf));
    }
    if (entry->content_type) {
        g_strlcpy(content_type_buf, entry->content_type, sizeof(content_type_buf));
    }
    if (entry->filename) {
        g_strlcpy(filename_buf, entry->filename, sizeof(filename_buf));
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "packetNum", entry->pkt_num);
    cJSON_AddStringToObject(root, "hostname", hostname_buf);
    cJSON_AddStringToObject(root, "contentType", content_type_buf);
    cJSON_AddStringToObject(root, "filename", filename_buf);
    cJSON_AddNumberToObject(root, "length", (double)entry->payload_len);

    gchar *payload_hex = NULL;
    if (entry->payload_data && entry->payload_len > 0) {
        payload_hex = g_malloc(entry->payload_len * 2 + 1);
        for (size_t i = 0; i < entry->payload_len; i++) {
            g_snprintf(payload_hex + (i * 2), 3, "%02x", entry->payload_data[i]);
        }
        payload_hex[entry->payload_len * 2] = '\0';
    }
    cJSON_AddStringToObject(root, "payloadHex", payload_hex ? payload_hex : "");
    if (payload_hex) g_free(payload_hex);

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (json != NULL) {
        data->callback(json, (int)strlen(json), 0);
        cJSON_free(json);
    }
}

int get_export_objects_cb(const char *filter_str, const char *protocol, FrameCallback callback) {
    register_eo_t *eo = get_eo_by_name(protocol);
    if (eo == NULL) {
        fprintf(stderr, "export objects: unknown protocol %s\n", protocol);
        return -1;
    }

    eo_callback_data cb_data = {
        .callback = callback,
        .entries = NULL,
    };

    export_object_list_t eo_list;
    memset(&eo_list, 0, sizeof(export_object_list_t));
    eo_list.add_entry = eo_add_entry_with_sha256;
    eo_list.gui_data = &cb_data;

    const char *tap_name = get_eo_tap_listener_name(eo);
    tap_packet_cb packet_func = get_eo_packet_func(eo);

    GString *tap_error = register_tap_listener(tap_name, &eo_list, filter_str,
                                               TL_REQUIRES_NOTHING, NULL,
                                               packet_func, NULL, NULL);
    if (tap_error != NULL) {
        fprintf(stderr, "export objects tap registration failed: %s\n", tap_error->str);
        g_string_free(tap_error, TRUE);
        return -1;
    }

    int err = run_tap_scan();
    remove_tap_listener(&eo_list);

    return err;
}

int write_export_object_cb(const char *filter_str, const char *protocol,
                           int packet_num, FrameCallback callback) {
    register_eo_t *eo = get_eo_by_name(protocol);
    if (eo == NULL) {
        fprintf(stderr, "export objects: unknown protocol %s\n", protocol);
        return -1;
    }

    eo_callback_data cb_data = {
        .callback = callback,
        .entries = NULL,
    };

    export_object_list_t eo_list;
    memset(&eo_list, 0, sizeof(export_object_list_t));
    eo_list.add_entry = eo_add_entry;
    eo_list.gui_data = &cb_data;

    const char *tap_name = get_eo_tap_listener_name(eo);
    tap_packet_cb packet_func = get_eo_packet_func(eo);

    char *effective_filter = NULL;
    if (filter_str != NULL && strlen(filter_str) > 0) {
        effective_filter = g_strdup_printf("(%s) && (frame.number == %d)", filter_str, packet_num);
    } else {
        effective_filter = g_strdup_printf("frame.number == %d", packet_num);
    }

    GString *tap_error = register_tap_listener(tap_name, &eo_list, effective_filter,
                                               TL_REQUIRES_NOTHING, NULL,
                                               packet_func, NULL, NULL);
    g_free(effective_filter);

    if (tap_error != NULL) {
        fprintf(stderr, "export objects tap registration failed: %s\n", tap_error->str);
        g_string_free(tap_error, TRUE);
        return -1;
    }

    int err = run_tap_scan();
    remove_tap_listener(&eo_list);

    return err;
}

typedef struct {
    FrameCallback callback;
    const char *protocol;
} srt_callback_data;

static void srt_draw_cb(void *arg) {
    srt_data_t *data = (srt_data_t *)arg;
    srt_callback_data *cb_data = (srt_callback_data *)data->user_data;

    if (cb_data == NULL || cb_data->callback == NULL || data->srt_array == NULL) {
        return;
    }

    for (guint i = 0; i < data->srt_array->len; i++) {
        srt_stat_table *rst = g_array_index(data->srt_array, srt_stat_table *, i);
        if (rst == NULL) continue;

        for (int j = 0; j < rst->num_procs; j++) {
            srt_procedure_t *proc = &rst->procedures[j];
            if (proc->stats.num == 0) continue;

            double min_val = nstime_to_sec(&proc->stats.min);
            double max_val = nstime_to_sec(&proc->stats.max);
            double avg_val = get_average(&proc->stats.tot, proc->stats.num);
            double tot_val = nstime_to_sec(&proc->stats.tot);

            cJSON *root = cJSON_CreateObject();
            cJSON_AddStringToObject(root, "protocol", cb_data->protocol);
            cJSON_AddStringToObject(root, "procedure", proc->procedure ? proc->procedure : "");
            cJSON_AddNumberToObject(root, "calls", proc->stats.num);
            cJSON_AddNumberToObject(root, "min", min_val);
            cJSON_AddNumberToObject(root, "max", max_val);
            cJSON_AddNumberToObject(root, "avg", avg_val);
            cJSON_AddNumberToObject(root, "total", tot_val);

            char *json = cJSON_PrintUnformatted(root);
            cJSON_Delete(root);
            if (json != NULL) {
                cb_data->callback(json, (int)strlen(json), 0);
                cJSON_free(json);
            }
        }
    }
}

int get_service_response_times_cb(const char *filter_str, const char *protocol, FrameCallback callback) {
    register_srt_t *srt = get_srt_table_by_name(protocol);
    if (srt == NULL) {
        fprintf(stderr, "srt: unknown protocol %s\n", protocol);
        return -1;
    }

    srt_callback_data cb_data = {
        .callback = callback,
        .protocol = protocol,
    };

    GArray *srt_array = g_array_new(FALSE, TRUE, sizeof(srt_stat_table *));

    srt_data_t srt_data;
    memset(&srt_data, 0, sizeof(srt_data_t));
    srt_data.srt_array = srt_array;
    srt_data.user_data = &cb_data;

    srt_table_dissector_init(srt, srt_array);

    const char *tap_name = get_srt_tap_listener_name(srt);
    tap_packet_cb packet_func = get_srt_packet_func(srt);

    GString *tap_error = register_tap_listener(tap_name, &srt_data, filter_str,
                                               TL_REQUIRES_NOTHING, NULL,
                                               packet_func, srt_draw_cb, NULL);
    if (tap_error != NULL) {
        fprintf(stderr, "srt tap registration failed: %s\n", tap_error->str);
        g_string_free(tap_error, TRUE);
        free_srt_table(srt, srt_array);
        return -2;
    }

    int err = run_tap_scan();
    draw_tap_listeners(TRUE);
    remove_tap_listener(&srt_data);
    free_srt_table(srt, srt_array);

    return err;
}

void get_frames_by_idxs_cb(int *idxs, int idx_count, int printCJson, FrameCallback callback) {
    if (idx_count <= 0) {
        return;
    }

    epan_dissect_t *edt;
    cf.count = 0;
    int err = 0;
    gchar *err_info = NULL;
    int64_t data_offset = 0;
    guint32 cum_bytes = 0;
    wtap_rec rec;
    wtap_rec_init(&rec, 1514);
    int current_idx_ptr = 0;

    while (wtap_read(cf.provider.wth, &rec, &err, &err_info, &data_offset)) {
        cf.count++;

        // Fast-forward idx pointer if current frame > target (shouldn't happen if
        // sorted, but safe)
        while (current_idx_ptr < idx_count && cf.count > idxs[current_idx_ptr]) {
            current_idx_ptr++;
        }

        // All targets processed
        if (current_idx_ptr >= idx_count) {
            wtap_rec_reset(&rec);
            break;
        }

        // Maintain frame sequence for all frames (required for correct timestamps)
        frame_data fd;
        frame_data_init(&fd, cf.count, &rec, data_offset, 0);
        frame_data_set_before_dissect(&fd, &cf.elapsed_time, &cf.provider.ref, cf.provider.prev_dis);
        cf.provider.ref = &fd;

        // Match found — full dissection
        if (cf.count == idxs[current_idx_ptr]) {
            edt = epan_dissect_new(cf.epan, TRUE, TRUE);
            epan_dissect_run_with_taps(edt, cf.cd_t, &rec, &fd, &cf.cinfo);

            frame_data_set_after_dissect(&fd, &cum_bytes);
            cf.provider.prev_cap = cf.provider.prev_dis = frame_data_sequence_add(cf.provider.frames, &fd);

            json_dumper dumper = {};
            dumper.output_string = g_string_new(NULL);
            get_json_proto_tree(NULL, print_dissections_expanded, FALSE, NULL, PF_INCLUDE_CHILDREN,
                                edt, &cf.cinfo, proto_node_group_children_by_unique, &dumper);

            if (json_dumper_finish(&dumper)) {
                if (printCJson) printf("%s\n", dumper.output_string->str);
                if (callback(dumper.output_string->str, dumper.output_string->len, 0) != 0) {
                    if (dumper.output_string) g_string_free(dumper.output_string, TRUE);
                    epan_dissect_free(edt);
                    wtap_rec_reset(&rec);
                    break;
                }
            }

            if (dumper.output_string) g_string_free(dumper.output_string, TRUE);
            epan_dissect_free(edt);

            // Move to next target
            current_idx_ptr++;
        } else {
            // Non-target frame — still maintain sequence
            frame_data_set_after_dissect(&fd, &cum_bytes);
            cf.provider.prev_cap = cf.provider.prev_dis = frame_data_sequence_add(cf.provider.frames, &fd);
        }

        wtap_rec_reset(&rec);
    }
    wtap_rec_cleanup(&rec);
}

/**
 * Validate Wireshark display filter syntax.
 *
 * @param filter_str the display filter string to check
 * @return NULL if syntax is correct, otherwise returns error message (needs g_free)
 */
char *validate_filter(const char *filter_str) {
    if (filter_str == NULL || strlen(filter_str) == 0) {
        return NULL;
    }

    dfilter_t *dfcode = NULL;
    df_error_t *df_err = NULL;

    // Attempt to compile the filter
    if (!dfilter_compile(filter_str, &dfcode, &df_err)) {
        char *res = NULL;
        if (df_err != NULL) {
            res = g_strdup(df_err->msg);
            df_error_free(&df_err);
        } else {
            res = g_strdup("Unknown filter syntax error");
        }
        return res;
    }

    // Free the compiled filter if it was successful
    if (dfcode != NULL) {
        dfilter_free(dfcode);
    }

    return NULL;
}

/**
 * Count frames in the opened pcap file.
 * If filter_str is empty, this stays on the fast header-only path.
 * If a display filter is present, packets must be dissected so the filter can be evaluated.
 */
int count_frames(const char *filter_str) {
    int count = 0;
    int err = 0;
    gchar *err_info = NULL;
    int64_t data_offset = 0;
    wtap_rec rec;
    wtap_rec_init(&rec, 1514);

    bool has_filter = (filter_str != NULL && strlen(filter_str) > 0);
    dfilter_t *dfcode = NULL;
    if (has_filter && !dfilter_compile(filter_str, &dfcode, NULL)) {
        has_filter = false;
    }

    if (!has_filter) {
        while (wtap_read(cf.provider.wth, &rec, &err, &err_info, &data_offset)) {
            count++;
            wtap_rec_reset(&rec);
        }
        wtap_rec_cleanup(&rec);
        return count;
    }

    cf.count = 0;
    guint32 cum_bytes = 0;
    while (wtap_read(cf.provider.wth, &rec, &err, &err_info, &data_offset)) {
        cf.count++;

        frame_data fd;
        frame_data_init(&fd, cf.count, &rec, data_offset, 0);

        epan_dissect_t *edt = epan_dissect_new(cf.epan, TRUE, FALSE);
        epan_dissect_prime_with_dfilter(edt, dfcode);

        frame_data_set_before_dissect(&fd, &cf.elapsed_time, &cf.provider.ref, cf.provider.prev_dis);
        cf.provider.ref = &fd;
        epan_dissect_run_with_taps(edt, cf.cd_t, &rec, &fd, NULL);
        frame_data_set_after_dissect(&fd, &cum_bytes);
        cf.provider.prev_cap = cf.provider.prev_dis = frame_data_sequence_add(cf.provider.frames, &fd);

        if (dfilter_apply_edt(dfcode, edt)) {
            count++;
        }

        epan_dissect_free(edt);
        wtap_rec_reset(&rec);
    }

    dfilter_free(dfcode);
    wtap_rec_cleanup(&rec);
    return count;
}

void get_frames_by_range(int start, int limit, int printCJson, const char *filter_str, FrameCallback callback) {
    cf.count = 0;
    int err = 0;
    gchar *err_info = NULL;
    int64_t data_offset = 0;
    guint32 cum_bytes = 0;
    wtap_rec rec;
    wtap_rec_init(&rec, 1514);
    epan_dissect_t *edt = NULL;

    dfilter_t *dfcode = NULL;
    bool has_filter = (filter_str != NULL && strlen(filter_str) > 0);
    if (has_filter) {
        if (!dfilter_compile(filter_str, &dfcode, NULL)) {
            fprintf(stderr, "Filter compile failed: %s\n", filter_str);
            has_filter = false;
        }
    }

    int matched_count = 0;
    int end = start + limit;

    while (wtap_read(cf.provider.wth, &rec, &err, &err_info, &data_offset)) {
        cf.count++;

        frame_data fd;
        frame_data_init(&fd, cf.count, &rec, data_offset, 0);

        /*
         * If no display filter is active and we haven't reached the target page,
         * skip full dissection — only read packet headers and maintain frame sequence
         * for timestamp resolution.
         */
        if (!has_filter && matched_count < start - 1) {
            matched_count++;
            frame_data_set_before_dissect(&fd, &cf.elapsed_time, &cf.provider.ref, cf.provider.prev_dis);
            cf.provider.ref = &fd;
            frame_data_set_after_dissect(&fd, &cum_bytes);
            cf.provider.prev_cap = cf.provider.prev_dis = frame_data_sequence_add(cf.provider.frames, &fd);
            wtap_rec_reset(&rec);
            continue;
        }

        /* Full dissection required: either we have a filter, or we're in the target range */
        bool in_target_range = (!has_filter && matched_count >= start - 1) ||
                               (has_filter && matched_count >= start - 1);

        /*
         * When filter is active but we haven't reached the target page,
         * use lightweight dissect (no column info) — just enough to evaluate the filter.
         */
        if (has_filter && matched_count < start - 1) {
            edt = epan_dissect_new(cf.epan, TRUE, FALSE);  // tree=TRUE (for filter), columns=FALSE
            epan_dissect_prime_with_dfilter(edt, dfcode);
        } else {
            edt = epan_dissect_new(cf.epan, TRUE, TRUE);   // full dissect for target frames
            if (dfcode != NULL) {
                epan_dissect_prime_with_dfilter(edt, dfcode);
            }
        }

        frame_data_set_before_dissect(&fd, &cf.elapsed_time, &cf.provider.ref, cf.provider.prev_dis);
        cf.provider.ref = &fd;

        epan_dissect_run_with_taps(edt, cf.cd_t, &rec, &fd, &cf.cinfo);

        frame_data_set_after_dissect(&fd, &cum_bytes);
        cf.provider.prev_cap = cf.provider.prev_dis = frame_data_sequence_add(cf.provider.frames, &fd);

        if (dfcode != NULL) {
            if (!dfilter_apply_edt(dfcode, edt)) {
                epan_dissect_free(edt);
                wtap_rec_reset(&rec);
                continue;
            }
        }

        matched_count++;

        if (matched_count < start) {
            epan_dissect_free(edt);
            wtap_rec_reset(&rec);
            continue;
        }

        if (matched_count >= end) {
            epan_dissect_free(edt);
            wtap_rec_reset(&rec);
            break;
        }

        json_dumper dumper = {};
        dumper.output_string = g_string_new(NULL);
        get_json_proto_tree(NULL, print_dissections_expanded, FALSE, NULL, PF_INCLUDE_CHILDREN, edt,
                            &cf.cinfo, proto_node_group_children_by_unique, &dumper);

        if (json_dumper_finish(&dumper)) {
            if (printCJson) printf("%s\n", dumper.output_string->str);
            if (callback(dumper.output_string->str, dumper.output_string->len, 0) != 0) {
                if (dumper.output_string) g_string_free(dumper.output_string, TRUE);
                epan_dissect_free(edt);
                wtap_rec_reset(&rec);
                break;
            }
        }

        if (dumper.output_string) g_string_free(dumper.output_string, TRUE);
        epan_dissect_free(edt);
        wtap_rec_reset(&rec);
    }

    if (dfcode != NULL) dfilter_free(dfcode);
    wtap_rec_cleanup(&rec);
}

void get_stream_payloads_cb(const char *filter_str, const char *proto, FrameCallback callback) {
    epan_dissect_t *edt;
    cf.count = 0;
    int err = 0;
    gchar *err_info = NULL;
    int64_t data_offset = 0;
    guint32 cum_bytes = 0;
    wtap_rec rec;
    wtap_rec_init(&rec, 1514);

    dfilter_t *dfcode = NULL;
    df_error_t *df_err = NULL;
    if (filter_str != NULL && strlen(filter_str) > 0) {
        if (!dfilter_compile(filter_str, &dfcode, &df_err)) {
            if (df_err) df_error_free(&df_err);
        }
    }

    int payload_id = proto_registrar_get_id_byname(strcmp(proto, "tcp") == 0 ? "tcp.payload" : "udp.payload");
    int matched_packets = 0;

    while (wtap_read(cf.provider.wth, &rec, &err, &err_info, &data_offset)) {
        cf.count++;
        frame_data fd;
        frame_data_init(&fd, cf.count, &rec, data_offset, 0);

        edt = epan_dissect_new(cf.epan, TRUE, TRUE);

        if (dfcode != NULL) epan_dissect_prime_with_dfilter(edt, dfcode);
        if (payload_id != -1) epan_dissect_prime_with_hfid(edt, payload_id);

        frame_data_set_before_dissect(&fd, &cf.elapsed_time, &cf.provider.ref, cf.provider.prev_dis);
        cf.provider.ref = &fd;

        epan_dissect_run_with_taps(edt, cf.cd_t, &rec, &fd, &cf.cinfo);

        frame_data_set_after_dissect(&fd, &cum_bytes);
        cf.provider.prev_cap = cf.provider.prev_dis = frame_data_sequence_add(cf.provider.frames, &fd);

        if (dfcode != NULL) {
            if (!dfilter_apply_edt(dfcode, edt)) {
                epan_dissect_free(edt);
                wtap_rec_reset(&rec);
                continue;
            }
        }

        matched_packets++;

        char src_ip[WS_INET6_ADDRSTRLEN] = {0};
        char dst_ip[WS_INET6_ADDRSTRLEN] = {0};
        address_to_str_buf(&edt->pi.src, src_ip, sizeof(src_ip));
        address_to_str_buf(&edt->pi.dst, dst_ip, sizeof(dst_ip));
        guint32 src_port = edt->pi.srcport;
        guint32 dst_port = edt->pi.destport;

        char *payload_hex = NULL;
        if (payload_id != -1) {
            GPtrArray *finfo_array = proto_get_finfo_ptr_array(edt->tree, payload_id);
            if (finfo_array && finfo_array->len > 0) {
                GString *hex_builder = g_string_new("");

                for (guint i = 0; i < finfo_array->len; i++) {
                    field_info *fi = (field_info *)g_ptr_array_index(finfo_array, i);
                    if (fi && fi->value) {

                        char *raw_repr = fvalue_to_string_repr(NULL, fi->value, FTREPR_JSON, fi->hfinfo->display);
                        if (raw_repr) {
                            char *r = raw_repr;
                            char *w = raw_repr;
                            while (*r) {
                                if (*r != ':') {
                                    *w++ = *r;
                                }
                                r++;
                            }
                            *w = '\0';

                            g_string_append(hex_builder, raw_repr);
                            wmem_free(NULL, raw_repr);
                        }
                    }
                }
                payload_hex = g_string_free(hex_builder, FALSE);
            }
        }

        if (payload_hex != NULL && strlen(payload_hex) > 0) {
            char *tiny_json = g_strdup_printf(
                "{\"src\":\"%s\",\"dst\":\"%s\",\"srcport\":%u,\"dstport\":%u,\"payload\":\"%s\"}",
                src_ip, dst_ip, src_port, dst_port, payload_hex
            );
            if (callback(tiny_json, strlen(tiny_json), 0) != 0) {
                g_free(tiny_json);
                epan_dissect_free(edt);
                wtap_rec_reset(&rec);
                break;
            }
            g_free(tiny_json);
        }

        if (payload_hex != NULL) {
            g_free(payload_hex);
        }

        epan_dissect_free(edt);
        wtap_rec_reset(&rec);
    }

    char *summary_json = g_strdup_printf("{\"_summary\":true,\"matched_count\":%d}", matched_packets);
    (void)callback(summary_json, strlen(summary_json), 0);
    g_free(summary_json);

    if (dfcode != NULL) dfilter_free(dfcode);
    wtap_rec_cleanup(&rec);
}

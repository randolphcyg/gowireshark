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
    uint32_t value;
} decode_as_entry;

static GArray *g_decode_as_entries = NULL;

typedef struct {
    FrameCallback callback;
    int stop;
} expert_callback_data;

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

static int table_is_supported_uint_port(const char *table) {
    return table != NULL &&
           (strcmp(table, "tcp.port") == 0 ||
            strcmp(table, "udp.port") == 0 ||
            strcmp(table, "sctp.port") == 0);
}

static void reset_decode_as_rules(void) {
    if (g_decode_as_entries == NULL) {
        return;
    }
    for (guint i = 0; i < g_decode_as_entries->len; i++) {
        decode_as_entry *entry = &g_array_index(g_decode_as_entries, decode_as_entry, i);
        if (entry->table != NULL) {
            dissector_reset_uint(entry->table, entry->value);
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

        if (!table_is_supported_uint_port(table_name)) {
            fprintf(stderr, "decode_as: unsupported table %s\n", table_name);
            return -2;
        }

        char *end = NULL;
        unsigned long value = strtoul(selector, &end, 10);
        if (end == selector || *end != '\0' || value > 65535) {
            fprintf(stderr, "decode_as: invalid selector %s\n", selector);
            return -2;
        }

        dissector_table_t table = find_dissector_table(table_name);
        if (table == NULL) {
            fprintf(stderr, "decode_as: table not found %s\n", table_name);
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

        dissector_change_uint(table_name, (uint32_t)value, handle);

        if (g_decode_as_entries == NULL) {
            g_decode_as_entries = g_array_new(FALSE, TRUE, sizeof(decode_as_entry));
        }
        decode_as_entry entry = {
            .table = g_strdup(table_name),
            .value = (uint32_t)value,
        };
        g_array_append_val(g_decode_as_entries, entry);
    }
    return 0;
}

/**
 * Clean the capture file struct and epan mod.
 */
static void clean() {
    reset_decode_as_rules();
    if (cf.provider.frames != NULL) {
        /*
         * Free a frame_data_sequence and all the frame_data structures in it.
         */
        free_frame_data_sequence(cf.provider.frames);
        cf.provider.frames = NULL;
    }
    if (cf.provider.wth != NULL) {
        /** Closes any open file handles and frees the memory associated with wth.
         */
        wtap_close(cf.provider.wth);
        cf.provider.wth = NULL;
    }
    if (cf.epan != NULL) {
        epan_free(cf.epan);
    }
    /** cleanup the whole epan module, this is used to be called only once in a
     * program */
    epan_cleanup();
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

    /* We have no file open... */
    if (cf.filename != NULL) {
        g_free(cf.filename);
        cf.filename = NULL;
    }

    /* ...which means we have no changes to that file to save. */
    cf.unsaved_changes = FALSE;

    /* no open_routine type */
    cf.open_type = WTAP_TYPE_AUTO;

    /* Clean up the record metadata. */
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

    /* No frames, no frame selected, no field in that frame selected. */
    cf.count = 0;
    cf.current_frame = NULL;
    cf.finfo_selected = NULL;

    /* No frame link-layer types, either. */
    if (cf.linktypes != NULL) {
        g_array_free(cf.linktypes, TRUE);
        cf.linktypes = NULL;
    }

    cf.f_datalen = 0;
    nstime_set_zero(&cf.elapsed_time);

    reset_tap_listeners();

    epan_free(cf.epan);
    cf.epan = NULL;

    /* We have no file open. */
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

    // handle conf
    if (!is_empty_json(options)) {
        options_json = cJSON_Parse(options);
        if (options_json == NULL) {
            fprintf(stderr, "Error: Failed to parse options JSON.\n");
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

    prefs_p = epan_load_settings();
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

#include "offline.h"
#include <lib.h>
#include <reassembly.h>

// Global capture file variable
capture_file cf;

static guint hexdump_source_option =
    HEXDUMP_SOURCE_MULTI; /* Default - Enable legacy multi-source mode */
static guint hexdump_ascii_option =
    HEXDUMP_ASCII_INCLUDE; /* Default - Enable legacy undelimited ASCII dump */

// --- Internal Helper Prototypes ---
void clean();
bool read_packet(epan_dissect_t **edt_r);

typedef struct {
  GSList *src_list;
  gchar **filter;
  pf_flags filter_flags;
  gboolean print_hex;
  gboolean print_text;
  proto_node_children_grouper_func node_children_grouper;
  json_dumper *dumper;
} write_json_data;

typedef void (*proto_node_value_writer)(proto_node *, write_json_data *);
static void write_json_index(json_dumper *dumper, epan_dissect_t *edt);
static void write_json_proto_node_list(GSList *proto_node_list_head,
                                       write_json_data *pdata);
static void write_json_proto_node(GSList *node_values_head, const char *suffix,
                                  proto_node_value_writer value_writer,
                                  write_json_data *data);
static void
write_json_proto_node_value_list(GSList *node_values_head,
                                 proto_node_value_writer value_writer,
                                 write_json_data *data);
static void write_json_proto_node_children(proto_node *node,
                                           write_json_data *data);
static void write_json_proto_node_value(proto_node *node,
                                        write_json_data *data);
static void write_json_proto_node_no_value(proto_node *node,
                                           write_json_data *pdata);
static const char *proto_node_to_json_key(proto_node *node);

// --- Cleanup Functions ---

/**
 * Clean the capture file struct and epan mod.
 */
void clean() {
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
 */
void close_cf() {
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
    free(cf.provider.frames);
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

// --- Initialization ---

/**
 * Init and fill the capture file struct.
 *
 *  @param filepath the pcap file path
 *  @return 0 if init correctly
 */
int init_cf(char *filepath, char *options) {
  char *keysList = NULL;
  int desegmentSslRecords = 0;
  int desegmentSslApplicationData = 0;
  int printTcpStreams = 0;

  // handle conf
  if (!is_empty_json(options)) {
    cJSON *json = cJSON_Parse(options);
    if (json == NULL) {
      fprintf(stderr, "Error: Failed to parse options JSON.\n");
      return -1;
    }

    // Extract values from JSON
    const cJSON *keysListJson =
        cJSON_GetObjectItemCaseSensitive(json, "tls.keys_list");
    const cJSON *desegmentSslRecordsJson =
        cJSON_GetObjectItemCaseSensitive(json, "tls.desegment_ssl_records");
    const cJSON *desegmentSslApplicationDataJson =
        cJSON_GetObjectItemCaseSensitive(json,
                                         "tls.desegment_ssl_application_data");

    const cJSON *printTcpStreamsJson =
        cJSON_GetObjectItemCaseSensitive(json, "printTcpStreams");

    // Copy keys list if present
    if (cJSON_IsString(keysListJson) && (keysListJson->valuestring != NULL)) {
      keysList = strdup(keysListJson->valuestring);
    }

    // Set flags for desegment options
    desegmentSslRecords = cJSON_IsBool(desegmentSslRecordsJson) &&
                          cJSON_IsTrue(desegmentSslRecordsJson);
    desegmentSslApplicationData =
        cJSON_IsBool(desegmentSslApplicationDataJson) &&
        cJSON_IsTrue(desegmentSslApplicationDataJson);
    printTcpStreams =
        cJSON_IsBool(printTcpStreamsJson) && cJSON_IsTrue(printTcpStreamsJson);

    cJSON_Delete(json);
  }

  int err = 0;
  gchar *err_info = NULL;
  e_prefs *prefs_p;

  /* Initialize the capture file struct */
  memset(&cf, 0, sizeof(capture_file));
  cf.filename = filepath;
  cf.provider.wth =
      wtap_open_offline(cf.filename, WTAP_TYPE_AUTO, &err, &err_info, TRUE);
  if (err != 0 || cf.provider.wth == NULL) {
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
  };

  // Apply TLS preferences
  tls_prefs_apply(keysList, desegmentSslRecords, desegmentSslApplicationData);
  if (keysList != NULL) {
    free(keysList);
  }

  cf.epan = epan_new(&cf.provider, &funcs);

  // setup tcp follow tap
  if (printTcpStreams) {
    setup_tcp_follow_tap();
  }

  prefs_p = epan_load_settings();
  build_column_format_array(&cf.cinfo, prefs_p->num_cols, TRUE);
  return 0;
}

// --- Frame Counting ---

/**
 * Count total frames in pcap file
 */
int count_frames() {
  int err;
  char *err_info = NULL;
  int frame_count = 0;
  int64_t data_offset = 0;

  wtap *count_wth =
      wtap_open_offline(cf.filename, WTAP_TYPE_AUTO, &err, &err_info, TRUE);
  if (count_wth == NULL) {
    if (err_info != NULL) {
      fprintf(stderr, "Error opening file for counting: %s\n", err_info);
      g_free(err_info);
    }
    return -1;
  }

  wtap_rec rec;
  wtap_rec_init(&rec, 1514);

  while (wtap_read(count_wth, &rec, &err, &err_info, &data_offset)) {
    frame_count++;
  }

  wtap_rec_cleanup(&rec);
  wtap_close(count_wth);

  if (err != 0 && err_info != NULL) {
    fprintf(stderr, "Warning during counting: %s\n", err_info);
    g_free(err_info);
  }

  return frame_count;
}

static void write_json_index(json_dumper *dumper, epan_dissect_t *edt) {
  char ts[30];
  struct tm *timeinfo;
  char *str;

  timeinfo = localtime(&edt->pi.abs_ts.secs);
  if (timeinfo != NULL) {
    strftime(ts, sizeof(ts), "%Y-%m-%d", timeinfo);
  } else {
    (void)g_strlcpy(
        ts, "XXXX-XX-XX",
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
static void write_json_proto_node_value(proto_node *node,
                                        write_json_data *pdata) {
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
static void write_json_proto_node_no_value(proto_node *node,
                                           write_json_data *pdata) {
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

static void write_json_proto_node_dynamic(proto_node *node,
                                          write_json_data *data) {
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
                                  proto_node_value_writer value_writer,
                                  write_json_data *pdata) {
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
static void
write_json_proto_node_value_list(GSList *node_values_head,
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
static void write_json_proto_node_list(GSList *proto_node_list_head,
                                       write_json_data *pdata) {
  json_dumper_begin_object(pdata->dumper);

  // hash table
  GHashTable *key_nodes =
      g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);

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
      GSList *combined_list = g_slist_concat(g_slist_copy(existing_list),
                                             g_slist_copy(node_values_list));
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
    char *value_string_repr = fvalue_to_string_repr(
        NULL, fi->value, FTREPR_JSON, fi->hfinfo->display);
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
      write_json_proto_node(node_values_list, "", write_json_proto_node_value,
                            pdata);
    }

    if (has_children) {
      char *suffix = has_value ? "_tree" : "";
      write_json_proto_node(node_values_list, suffix,
                            write_json_proto_node_dynamic, pdata);
    }

    if (!has_value && !has_children) {
      write_json_proto_node(node_values_list, "",
                            write_json_proto_node_no_value, pdata);
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
static void write_json_proto_node_children(proto_node *node,
                                           write_json_data *data) {
  GSList *grouped_children_list = data->node_children_grouper(node);
  write_json_proto_node_list(grouped_children_list, data);
  g_slist_free_full(grouped_children_list, (GDestroyNotify)g_slist_free);
}

/**
 * Get protocol tree dissect result in json format.
 */
void get_json_proto_tree(output_fields_t *fields,
                         print_dissections_e print_dissections,
                         gboolean print_hex, gchar **protocolfilter,
                         pf_flags protocolfilter_flags, epan_dissect_t *edt,
                         column_info *cinfo,
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
bool read_packet(epan_dissect_t **edt_r) {
  if (!edt_r)
    return false;

  epan_dissect_t *edt = NULL;
  int err;
  gchar *err_info = NULL;
  guint32 cum_bytes = 0;
  int64_t data_offset = 0;
  wtap_rec rec;

  wtap_rec_init(&rec, 1514);

  if (!wtap_read(cf.provider.wth, &rec, &err, &err_info, &data_offset)) {
    wtap_rec_reset(&rec);
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

  frame_data_set_before_dissect(&fd, &cf.elapsed_time, &cf.provider.ref,
                                cf.provider.prev_dis);

  cf.provider.ref = &fd;

  // core dissect process
  epan_dissect_run_with_taps(edt, cf.cd_t, &rec, &fd, &cf.cinfo);
  frame_data_set_after_dissect(&fd, &cum_bytes);

  cf.provider.prev_cap = cf.provider.prev_dis =
      frame_data_sequence_add(cf.provider.frames, &fd);

  // free space
  wtap_rec_reset(&rec);
  frame_data_destroy(&fd);

  *edt_r = edt;
  return true;
}

/**
 * Dissect and print all frames.
 *
 *  @return none, just print dissect result
 */
void print_all_frame() {
  epan_dissect_t *edt;
  print_stream_t *print_stream = print_stream_text_stdio_new(stdout);
  // start reading packets
  while (read_packet(&edt)) {
    proto_tree_print(print_dissections_expanded, TRUE, edt, NULL, print_stream);
    // print hex data
    print_hex_data(print_stream, edt,
                   hexdump_source_option | hexdump_ascii_option);
    epan_dissect_free(edt);
    edt = NULL;
  }
  close_cf();
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

    return cJSON_PrintUnformatted(cjson_hex_root);
  }
  close_cf();
  return "";
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

    get_json_proto_tree(NULL, print_dissections_expanded, FALSE, NULL,
                        PF_INCLUDE_CHILDREN, edt, &cf.cinfo,
                        proto_node_group_children_by_unique, &dumper);

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

  close_cf();
  return g_strdup("");
}

// --- Optimized Callbacks (Single Pass I/O) ---

void get_all_frames_cb(int printCJson, FrameCallback callback) {
  epan_dissect_t *edt;
  cf.count = 0;
  int err = 0;
  gchar *err_info = NULL;
  int64_t data_offset = 0;
  wtap_rec rec;
  wtap_rec_init(&rec, 1514);

  while (wtap_read(cf.provider.wth, &rec, &err, &err_info, &data_offset)) {
    cf.count++;
    frame_data fd;
    frame_data_init(&fd, cf.count, &rec, data_offset, 0);

    edt = epan_dissect_new(cf.epan, TRUE, TRUE);
    epan_dissect_run_with_taps(edt, cf.cd_t, &rec, &fd, &cf.cinfo);

    json_dumper dumper = {};
    dumper.output_string = g_string_new(NULL);
    get_json_proto_tree(NULL, print_dissections_expanded, FALSE, NULL,
                        PF_INCLUDE_CHILDREN, edt, &cf.cinfo,
                        proto_node_group_children_by_unique, &dumper);

    if (json_dumper_finish(&dumper)) {
      if (printCJson)
        printf("%s\n", dumper.output_string->str);
      callback(dumper.output_string->str, dumper.output_string->len, 0);
    }

    if (dumper.output_string)
      g_string_free(dumper.output_string, TRUE);
    epan_dissect_free(edt);
    frame_data_destroy(&fd);
    wtap_rec_reset(&rec);
  }
  close_cf();
  wtap_rec_cleanup(&rec);
}

void get_frames_by_idxs_cb(int *idxs, int idx_count, int printCJson,
                           FrameCallback callback) {
  if (idx_count <= 0) {
    close_cf();
    return;
  }

  epan_dissect_t *edt;
  cf.count = 0;
  int err = 0;
  gchar *err_info = NULL;
  int64_t data_offset = 0;
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

    // Match found
    if (cf.count == idxs[current_idx_ptr]) {
      frame_data fd;
      frame_data_init(&fd, cf.count, &rec, data_offset, 0);

      edt = epan_dissect_new(cf.epan, TRUE, TRUE);
      epan_dissect_run_with_taps(edt, cf.cd_t, &rec, &fd, &cf.cinfo);

      json_dumper dumper = {};
      dumper.output_string = g_string_new(NULL);
      get_json_proto_tree(NULL, print_dissections_expanded, FALSE, NULL,
                          PF_INCLUDE_CHILDREN, edt, &cf.cinfo,
                          proto_node_group_children_by_unique, &dumper);

      if (json_dumper_finish(&dumper)) {
        if (printCJson)
          printf("%s\n", dumper.output_string->str);
        callback(dumper.output_string->str, dumper.output_string->len, 0);
      }

      if (dumper.output_string)
        g_string_free(dumper.output_string, TRUE);
      epan_dissect_free(edt);
      frame_data_destroy(&fd);

      // Move to next target. Note: Handles duplicates in idxs implicitly.
      current_idx_ptr++;
    }
    wtap_rec_reset(&rec);
  }
  close_cf();
  wtap_rec_cleanup(&rec);
}

void get_frames_by_range(int start, int limit, int printCJson,
                         FrameCallback callback) {
  cf.count = 0;
  int err = 0;
  gchar *err_info = NULL;
  int64_t data_offset = 0;
  int end = start + limit;
  wtap_rec rec;
  wtap_rec_init(&rec, 1514);
  epan_dissect_t *edt = NULL;

  while (wtap_read(cf.provider.wth, &rec, &err, &err_info, &data_offset)) {
    cf.count++;

    // Case A: Skip IO-only before start
    if (cf.count < start) {
      wtap_rec_reset(&rec);
      continue;
    }

    // Case B: Stop after limit
    if (cf.count >= end) {
      wtap_rec_reset(&rec);
      break;
    }

    // Case C: Dissect
    frame_data fd;
    frame_data_init(&fd, cf.count, &rec, data_offset, 0);
    edt = epan_dissect_new(cf.epan, TRUE, TRUE);
    epan_dissect_run_with_taps(edt, cf.cd_t, &rec, &fd, &cf.cinfo);

    json_dumper dumper = {};
    dumper.output_string = g_string_new(NULL);
    get_json_proto_tree(NULL, print_dissections_expanded, FALSE, NULL,
                        PF_INCLUDE_CHILDREN, edt, &cf.cinfo,
                        proto_node_group_children_by_unique, &dumper);

    if (json_dumper_finish(&dumper)) {
      if (printCJson)
        printf("%s\n", dumper.output_string->str);
      callback(dumper.output_string->str, dumper.output_string->len, 0);
    }

    if (dumper.output_string)
      g_string_free(dumper.output_string, TRUE);
    epan_dissect_free(edt);
    frame_data_destroy(&fd);
    wtap_rec_reset(&rec);
  }
  close_cf();
  wtap_rec_cleanup(&rec);
}
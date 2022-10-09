#include <include/cJSON.h>
#include <include/lib.h>
#include <include/offline.h>

// global capture file variable
capture_file cfile;

/* Init the capture file struct */
void cap_file_init(capture_file *cf) {
  /* Initialize the capture file struct */
  memset(cf, 0, sizeof(capture_file));
}
static const nstime_t *tshark_get_frame_ts(struct packet_provider_data *prov,
                                           guint32 frame_num) {
  if (prov->ref && prov->ref->num == frame_num)
    return &prov->ref->abs_ts;
  if (prov->prev_dis && prov->prev_dis->num == frame_num)
    return &prov->prev_dis->abs_ts;
  if (prov->prev_cap && prov->prev_cap->num == frame_num)
    return &prov->prev_cap->abs_ts;
  if (prov->frames) {
    frame_data *fd = frame_data_sequence_find(prov->frames, frame_num);
    return (fd) ? &fd->abs_ts : NULL;
  }
  return NULL;
}
/* Clean the capture file struct */
void clean() {
  if (cfile.provider.frames != NULL) {
    /*
     * Free a frame_data_sequence and all the frame_data structures in it.
     */
    free_frame_data_sequence(cfile.provider.frames);
    cfile.provider.frames = NULL;
  }
  if (cfile.provider.wth != NULL) {
    /** Closes any open file handles and frees the memory associated with wth.
     */
    wtap_close(cfile.provider.wth);
    cfile.provider.wth = NULL;
  }
  if (cfile.epan != NULL) {
    epan_free(cfile.epan);
  }
  /** cleanup the whole epan module, this is used to be called only once in a
   * program */
  epan_cleanup();
}
/* Fill data to the capture file struct */
int init(char *filepath) {
  int err = 0;
  gchar *err_info = NULL;
  e_prefs *prefs_p;
  /**
   * Called when the program starts, to enable security features and save
   * whatever credential information we'll need later.
   */
  init_process_policies();
  /**
   * Permanently relinquish special privileges. get_credential_info()
   * MUST be called before calling this.
   */
  relinquish_special_privs_perm();
  /**
   * @brief Initialize the Wiretap library.
   *
   * @param load_wiretap_plugins Load Wiretap plugins when initializing library.
   */
  wtap_init(TRUE);
  /**
   * Init the whole epan module.
   *
   * Must be called only once in a program.
   *
   * Returns TRUE on success, FALSE on failure.
   */
  epan_init(NULL, NULL, 0);
  cap_file_init(&cfile);
  cfile.filename = filepath;
  cfile.provider.wth =
      wtap_open_offline(cfile.filename, WTAP_TYPE_AUTO, &err, &err_info, TRUE);
  if (err != 0 || cfile.provider.wth == NULL) {
    clean();
    return err;
  }
  cfile.count = 0;
  cfile.provider.frames = new_frame_data_sequence();
  static const struct packet_provider_funcs funcs = {
      tshark_get_frame_ts,
      NULL,
      NULL,
      NULL,
  };
  cfile.epan = epan_new(&cfile.provider, &funcs);
  prefs_p = epan_load_settings();
  build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);
  return 0;
}
/* Read each frame */
gboolean read_packet(epan_dissect_t **edt_r) {
  epan_dissect_t *edt;
  int err;
  gchar *err_info = NULL;
  static guint32 cum_bytes = 0;
  static gint64 data_offset = 0;
  wtap_rec rec;
  wtap_rec_init(&rec);
  /** Read the next record in the file, filling in *phdr and *buf.
   *
   * @wth a wtap * returned by a call that opened a file for reading.
   * @rec a pointer to a wtap_rec, filled in with information about the
   * record.
   * @buf a pointer to a Buffer, filled in with data from the record.
   * @param err a positive "errno" value, or a negative number indicating
   * the type of error, if the read failed.
   * @param err_info for some errors, a string giving more details of
   * the error
   * @param offset a pointer to a gint64, set to the offset in the file
   * that should be used on calls to wtap_seek_read() to reread that record,
   * if the read succeeded.
   * @return TRUE on success, FALSE on failure.
   */
  if (wtap_read(cfile.provider.wth, &rec, &cfile.buf, &err, &err_info,
                &data_offset)) {
    cfile.count++;
    frame_data fdlocal;
    frame_data_init(&fdlocal, cfile.count, &rec, data_offset, cum_bytes);
    // data_offset must be correctly set
    data_offset = fdlocal.pkt_len;
    edt = epan_dissect_new(cfile.epan, TRUE, TRUE);
    prime_epan_dissect_with_postdissector_wanted_hfids(edt);
    /**
     * Sets the frame data struct values before dissection.
     */
    frame_data_set_before_dissect(&fdlocal, &cfile.elapsed_time,
                                  &cfile.provider.ref, cfile.provider.prev_dis);
    cfile.provider.ref = &fdlocal;
    tvbuff_t *tvb;
    tvb = tvb_new_real_data(cfile.buf.data, data_offset, data_offset);
    // core dissect process
    epan_dissect_run_with_taps(edt, cfile.cd_t, &rec, tvb, &fdlocal,
                               &cfile.cinfo);
    frame_data_set_after_dissect(&fdlocal, &cum_bytes);
    cfile.provider.prev_cap = cfile.provider.prev_dis =
        frame_data_sequence_add(cfile.provider.frames, &fdlocal);
    // free space
    frame_data_destroy(&fdlocal);
    *edt_r = edt;
    return TRUE;
  }
  return FALSE;
}
/* Dissect and print all frames */
void print_all_frame() {
  epan_dissect_t *edt;
  print_stream_t *print_stream;
  print_stream = print_stream_text_stdio_new(stdout);
  // start reading packets
  while (read_packet(&edt)) {
    proto_tree_print(print_dissections_expanded, FALSE, edt, NULL,
                     print_stream);
    epan_dissect_free(edt);
    edt = NULL;
  }
}
/* Dissect and print the first frame */
void print_first_frame() {
  epan_dissect_t *edt;
  print_stream_t *print_stream;
  print_stream = print_stream_text_stdio_new(stdout);
  // start reading packets
  if (read_packet(&edt)) {
    proto_tree_print(print_dissections_expanded, FALSE, edt, NULL,
                     print_stream);
    // print hex data
    print_hex_data(print_stream, edt);
    epan_dissect_free(edt);
    edt = NULL;
  }
}
/* Dissect and print the first several frames */
void print_first_several_frame(int count) {
  epan_dissect_t *edt;
  print_stream_t *print_stream;
  print_stream = print_stream_text_stdio_new(stdout);
  // start reading packets
  while (read_packet(&edt)) {
    // print proto tree
    proto_tree_print(print_dissections_expanded, FALSE, edt, NULL,
                     print_stream);
    // print hex data
    print_hex_data(print_stream, edt);
    epan_dissect_free(edt);
    edt = NULL;
    if (cfile.count == count) {
      break;
    }
  }
}
// Dissect and print specific frame
void print_specific_frame(int num) {
  epan_dissect_t *edt;
  print_stream_t *print_stream;
  print_stream = print_stream_text_stdio_new(stdout);
  // start reading packets
  while (read_packet(&edt)) {
    if (num != cfile.count) {
      epan_dissect_free(edt);
      edt = NULL;
      continue;
    }

    // print proto tree
    proto_tree_print(print_dissections_expanded, FALSE, edt, NULL,
                     print_stream);
    // print hex data
    print_hex_data(print_stream, edt);

    epan_dissect_free(edt);
    edt = NULL;
    break;
  }
}
// Dissect and get hex data of specific frame
char *get_specific_frame_hex_data(int num) {
  epan_dissect_t *edt;
  // start reading packets
  while (read_packet(&edt)) {
    if (num != cfile.count) {
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
    break;
  }
  return "";
}

// proto_tree_in_json transfer proto tree to json format
char *proto_tree_in_json(int num) {
  static output_fields_t *output_fields = NULL;
  static gchar **protocolfilter = NULL;
  static pf_flags protocolfilter_flags = PF_NONE;
  static gboolean no_duplicate_keys = FALSE;
  static proto_node_children_grouper_func node_children_grouper =
      proto_node_group_children_by_unique;
  static json_dumper jdumper;

  epan_dissect_t *edt;
  print_stream_t *print_stream;
  print_stream = print_stream_text_stdio_new(stdout);

  // start reading packets
  while (read_packet(&edt)) {
    if (num != cfile.count) {
      epan_dissect_free(edt);
      edt = NULL;
      continue;
    }

    protocolfilter_flags = PF_INCLUDE_CHILDREN; // PF_NONE
    output_fields = output_fields_new();
    node_children_grouper =
        proto_node_group_children_by_json_key; // proto_node_group_children_by_unique
    protocolfilter = wmem_strsplit(wmem_epan_scope(), NULL, " ", -1);

    char *out;
    out = get_proto_tree_dissect_res_in_json(
        NULL, print_dissections_expanded, TRUE, protocolfilter,
        protocolfilter_flags, edt, &cfile.cinfo, node_children_grouper);

    epan_dissect_free(edt);
    edt = NULL;

    return out;
    break;
  }
  return "";
}

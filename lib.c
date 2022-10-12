#include <include/cJSON.h>
#include <include/lib.h>
#include <include/offline.h>

// global capture file variable
capture_file cf;

/**
 * Init policies、wtap mod、epan mod.
 *
 *  @param filepath the pcap file path
 *  @return 0 if init correctly
 */
int init_env() {
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
  gboolean init_epan_res;
  init_epan_res = epan_init(NULL, NULL, 0);
  if (init_epan_res) {
    return 1;
  } else {
    return 0;
  }

  return 1;
}

/**
 * Copy from tshark, handle time.
 */
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
void clean_cf() {
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
    //    free_frame_data_sequence(cf.provider.frames);
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
  cf.current_row = 0;
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

  //    cf_callback_invoke(cf_cb_file_closed, cf);
}

/**
 * Init and fill the capture file struct.
 *
 *  @param filepath the pcap file path
 *  @return 0 if init correctly
 */
int init_cf(char *filepath) {
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
      tshark_get_frame_ts,
      NULL,
      NULL,
      NULL,
  };
  cf.epan = epan_new(&cf.provider, &funcs);
  prefs_p = epan_load_settings();
  build_column_format_array(&cf.cinfo, prefs_p->num_cols, TRUE);
  return 0;
}

/**
 * Read each frame.
 *
 *  @param edt_r the epan_dissect_t struct of each frame
 *  @return TRUE if can dissect frame correctly, FALSE if can not read frame
 */
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
  if (wtap_read(cf.provider.wth, &rec, &cf.buf, &err, &err_info,
                &data_offset)) {
    cf.count++;
    frame_data fdlocal;
    frame_data_init(&fdlocal, cf.count, &rec, data_offset, cum_bytes);
    // data_offset must be correctly set
    data_offset = fdlocal.pkt_len;
    edt = epan_dissect_new(cf.epan, TRUE, TRUE);
    prime_epan_dissect_with_postdissector_wanted_hfids(edt);
    /**
     * Sets the frame data struct values before dissection.
     */
    frame_data_set_before_dissect(&fdlocal, &cf.elapsed_time, &cf.provider.ref,
                                  cf.provider.prev_dis);
    cf.provider.ref = &fdlocal;
    tvbuff_t *tvb;
    tvb = tvb_new_real_data(cf.buf.data, data_offset, data_offset);
    // core dissect process
    epan_dissect_run_with_taps(edt, cf.cd_t, &rec, tvb, &fdlocal, &cf.cinfo);
    frame_data_set_after_dissect(&fdlocal, &cum_bytes);
    cf.provider.prev_cap = cf.provider.prev_dis =
        frame_data_sequence_add(cf.provider.frames, &fdlocal);
    // free space
    frame_data_destroy(&fdlocal);
    *edt_r = edt;
    return TRUE;
  }
  return FALSE;
}

/**
 * Dissect and print all frames.
 *
 *  @return none, just print dissect result
 */
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
  clean_cf();
}

/**
 * Dissect and print the first frame.
 *
 *  @return none, just print dissect result
 */
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
  clean_cf();
}

/**
 * Dissect and print the first several frames.
 *
 *  @param count the first several frames to dissect and print, count is the num
 *  @return none, just print dissect result
 */
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
    if (cf.count == count) {
      break;
    }
  }
  clean_cf();
}

/**
 * Dissect and print specific frame.
 *
 *  @param num the index of frame which you want to dieesct
 *  @return none, just print dissect result
 */
void print_specific_frame(int num) {
  epan_dissect_t *edt;
  print_stream_t *print_stream;
  print_stream = print_stream_text_stdio_new(stdout);
  // start reading packets
  while (read_packet(&edt)) {
    if (num != cf.count) {
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

  clean_cf();
}

/**
 * Dissect and get hex data of specific frame.
 *
 *  @param num the index of frame which you want to dieesct
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
    break;
  }
  clean_cf();
  return "";
}

/**
 * Transfer proto tree to json format.
 *
 *  @param num the index of frame which you want to dieesct
 *  @return char of protocol tree dissect result, include hex data
 */
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
    if (num != cf.count) {
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
        protocolfilter_flags, edt, &cf.cinfo, node_children_grouper);

    epan_dissect_free(edt);
    edt = NULL;

    return out;
    break;
  }
  clean_cf();
  return "";
}

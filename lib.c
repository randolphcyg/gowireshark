#include <cJSON.h>
#include <lib.h>
#include <offline.h>

// global capture file variable
capture_file cf;

static guint hexdump_source_option =
    HEXDUMP_SOURCE_MULTI; /* Default - Enable legacy multi-source mode */
static guint hexdump_ascii_option =
    HEXDUMP_ASCII_INCLUDE; /* Default - Enable legacy undelimited ASCII dump */

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

  timestamp_set_type(TS_RELATIVE);
  timestamp_set_precision(TS_PREC_AUTO);
  timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

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
  if (!epan_init(NULL, NULL, FALSE)) {
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
  guint32 cum_bytes = 0;
  gint64 data_offset = 0;
  wtap_rec rec;
  wtap_rec_init(&rec);

  if (wtap_read(cf.provider.wth, &rec, &cf.buf, &err, &err_info,
                &data_offset)) {
    cf.count++;
    frame_data fd;
    frame_data_init(&fd, cf.count, &rec, data_offset, cum_bytes);
    // data_offset must be correctly set
    data_offset = fd.pkt_len;
    edt = epan_dissect_new(cf.epan, TRUE, TRUE);
    prime_epan_dissect_with_postdissector_wanted_hfids(edt);
    frame_data_set_before_dissect(&fd, &cf.elapsed_time, &cf.provider.ref,
                                  cf.provider.prev_dis);
    cf.provider.ref = &fd;
    tvbuff_t *tvb;
    tvb = tvb_new_real_data(cf.buf.data, data_offset, data_offset);
    // core dissect process
    epan_dissect_run_with_taps(edt, cf.cd_t, &rec, tvb, &fd, &cf.cinfo);
    frame_data_set_after_dissect(&fd, &cum_bytes);
    cf.provider.prev_cap = cf.provider.prev_dis =
        frame_data_sequence_add(cf.provider.frames, &fd);
    // free space
    frame_data_destroy(&fd);
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
 * Dissect and print the first frame.
 *
 *  @return none, just print dissect result
 */
void print_first_frame() {
  epan_dissect_t *edt;
  print_stream_t *print_stream = print_stream_text_stdio_new(stdout);
  // start reading packets
  if (read_packet(&edt)) {
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
 * Dissect and print the first several frames.
 *
 *  @param count the first several frames to dissect and print, count is the num
 *  @return none, just print dissect result
 */
void print_first_several_frame(int count) {
  epan_dissect_t *edt;
  print_stream_t *print_stream = print_stream_text_stdio_new(stdout);
  // start reading packets
  while (read_packet(&edt)) {
    // print proto tree
    proto_tree_print(print_dissections_expanded, FALSE, edt, NULL,
                     print_stream);
    epan_dissect_free(edt);
    edt = NULL;
    if (cf.count == count) {
      break;
    }
  }
  close_cf();
}

/**
 * Dissect and print specific frame.
 *
 *  @param num the index of frame which you want to dissect
 *  @return int out of bounds:2; correct:0;
 */
int print_specific_frame(int num) {
  epan_dissect_t *edt;
  print_stream_t *print_stream;
  print_stream = print_stream_text_stdio_new(stdout);
  // start reading packets
  while (read_packet(&edt)) {
    if (num == cf.count) {
      // print proto tree
      proto_tree_print(print_dissections_expanded, TRUE, edt, NULL,
                       print_stream);
      // print hex data
      print_hex_data(print_stream, edt,
                     hexdump_source_option | hexdump_ascii_option);

      close_cf();
      return 0;
    }

    epan_dissect_free(edt);
    edt = NULL;
  }

  close_cf();

  return 2;
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
 *  @return char of protocol tree dissect result, include hex data
 */
char *proto_tree_in_json(int num, int descriptive, int debug) {
  epan_dissect_t *edt;

  // start reading packets
  while (read_packet(&edt)) {
    if (num != cf.count) {
      epan_dissect_free(edt);
      edt = NULL;
      continue;
    }

    // json root node
    cJSON *proto_tree_json = cJSON_CreateObject();
    get_proto_tree_json(NULL, print_dissections_expanded, TRUE, NULL,
                        PF_INCLUDE_CHILDREN, edt, &cf.cinfo,
                        proto_node_group_children_by_unique, proto_tree_json,
                        descriptive);

    char *proto_tree_json_str;
    if (debug) {
      proto_tree_json_str = cJSON_Print(proto_tree_json);
      printf("%s\n", proto_tree_json_str);
    } else {
      proto_tree_json_str = cJSON_PrintUnformatted(proto_tree_json);
    }

    cJSON_Delete(proto_tree_json);
    epan_dissect_free(edt);
    edt = NULL;

    return proto_tree_json_str;
  }
  close_cf();
  return "";
}

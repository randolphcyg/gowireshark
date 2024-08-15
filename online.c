#include <lib.h>
#include <offline.h>
#include <online.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uthash.h>

// device_content Contains the information needed for each device
typedef struct device_content {
  char *device;
  char *bpf_expr;
  int num;
  int promisc;
  int to_ms;

  capture_file *cf_live;
  pcap_t *handle;
  frame_data prev_dis_frame;
  frame_data prev_cap_frame;
  wtap_rec rec;
  epan_dissect_t edt;
} device_content;

struct device_map {
  char *device_name;
  device_content content;
  UT_hash_handle hh;
};

// global map to restore device info
struct device_map *devices = NULL;

char *add_device(char *device_name, char *bpf_expr, int num, int promisc,
                 int to_ms);
struct device_map *find_device(char *device_name);

void cap_file_init(capture_file *cf);
char *init_cf_live(capture_file *cf_live);
void close_cf_live(capture_file *cf_live);

static gboolean prepare_data(wtap_rec *rec, const struct pcap_pkthdr *pkthdr);
static gboolean send_data_to_wrap(struct device_map *device);
static gboolean process_packet(struct device_map *device, gint64 offset,
                               const struct pcap_pkthdr *pkthdr,
                               const u_char *packet);
void before_callback_init(struct device_map *device);
void process_packet_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,
                             const u_char *packet);
char *stop_dissect_capture_pkg(char *device_name);
// Set up callback function for send packet to Go
static DataCallback dataCallback;
void setDataCallback(DataCallback callback) { dataCallback = callback; }

/*
PART1. Use uthash to implement the logic related to the map of the device
*/

char *add_device(char *device_name, char *bpf_expr, int num, int promisc,
                 int to_ms) {
  char *err_msg;
  struct device_map *s;
  capture_file *cf_tmp;

  HASH_FIND_STR(devices, device_name, s);
  if (s == NULL) {
    s = (struct device_map *)malloc(sizeof *s);
    memset(s, 0, sizeof(struct device_map));

    cf_tmp = (capture_file *)malloc(sizeof *cf_tmp);
    cap_file_init(cf_tmp);

    s->device_name = device_name;
    s->content.bpf_expr = bpf_expr;
    s->content.num = num;
    s->content.promisc = promisc;
    s->content.to_ms = to_ms;
    s->content.cf_live = cf_tmp;

    // init capture_file
    err_msg = init_cf_live(cf_tmp);
    if (err_msg != NULL) {
      if (strlen(err_msg) != 0) {
        // close cf file
        close_cf_live(cf_tmp);
        return "Add device failed: fail to init cf_live";
      }
    }
    HASH_ADD_KEYPTR(hh, devices, s->device_name, strlen(s->device_name), s);
    return "";
  } else {
    return "The device is in use";
  }
}

struct device_map *find_device(char *device_name) {
  struct device_map *s;

  HASH_FIND_STR(devices, device_name, s);
  return s;
}

/*
PART2. libpcap
*/

#define SNAP_LEN 65535

// interface device list
cJSON *ifaces = NULL;

/**
 * Get interface list.
 *
 *  @return char of map in json format:
 * {
 *  "device name1": {
 *    "name": "device name1",
 *    "description": "xxx device1",
 *    "flags": 1,
 *  },
 *  ...
 * }
 */
char *get_if_list() {
  char err_buf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs;
  pcap_findalldevs(&alldevs, err_buf);

  ifaces = cJSON_CreateObject();
  cJSON *if_item = NULL;
  for (pcap_if_t *pdev = alldevs; pdev != NULL; pdev = pdev->next) {
    if_item = cJSON_CreateObject();
    cJSON_AddStringToObject(if_item, "name", pdev->name);
    cJSON_AddStringToObject(if_item, "description",
                            pdev->description ? pdev->description : "");
    cJSON_AddNumberToObject(if_item, "flags", pdev->flags);
    cJSON_AddItemToObject(ifaces, pdev->name, if_item);
  }
  pcap_freealldevs(alldevs);

  char *result = cJSON_PrintUnformatted(ifaces);
  cJSON_Delete(ifaces);

  return result;
}

/**
 * select the first nic_device available on the machine
 * @return int:
 * -1: failure
 *  0: success
 */
int get_first_device(char *device){
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_if_t *first_if;

    if (pcap_findalldevs(&first_if, err_buf) < 0) {
        fprintf(stderr, "Error: couldn't find any devices %s\n", err_buf);
        return -1;
    }

    strncpy(device, first_if->name, 16 - 1);
    pcap_freealldevs(first_if);

    return 0;
}

/**
 * Get interface nonblock status.
 *
 *  @param device_name: the name of interface device
 *  @return int: current status is nonblock: 1;
 *  current status is not nonblock: 0;
 *  occur error: 2;
 */
int get_if_nonblock_status(char *device_name) {
  char err_buf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  int is_nonblock;

  if (device_name) {
    handle = pcap_open_live(device_name, SNAP_LEN, 1, 20, err_buf);
    if (handle == NULL) {
      return 2;
    }
    is_nonblock = pcap_getnonblock(handle, err_buf);
    pcap_close(handle);

    return is_nonblock;
  }

  return 2;
}

/**
 * Set interface nonblock status.
 *
 *  @param device_name: the name of interface device
 *  @param nonblock: set 1: is nonblock, set 0: is not nonblock
 *  @return int: current status is nonblock: 1;
 *  current status is not nonblock: 0;
 *  occur error: 2;
 */
int set_if_nonblock_status(char *device_name, int nonblock) {
  char err_buf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  int is_nonblock;

  if (device_name) {
    handle = pcap_open_live(device_name, SNAP_LEN, 1, 1000, err_buf);
    if (handle == NULL) {
      return 2;
    }
    // set nonblock status
    pcap_setnonblock(handle, nonblock, err_buf);
    // get nonblock status
    is_nonblock = pcap_getnonblock(handle, err_buf);
    pcap_close(handle);

    return is_nonblock;
  }

  return 2;
}

/*
PART3. wireshark
*/

static const nstime_t *raw_get_frame_ts(struct packet_provider_data *prov,
                                        guint32 frame_num) {
  if (prov->ref && prov->ref->num == frame_num)
    return &prov->ref->abs_ts;

  if (prov->prev_dis && prov->prev_dis->num == frame_num)
    return &prov->prev_dis->abs_ts;

  if (prov->prev_cap && prov->prev_cap->num == frame_num)
    return &prov->prev_cap->abs_ts;

  return NULL;
}

const char *
cap_file_provider_get_interface_name(struct packet_provider_data *prov,
                                     guint32 interface_id) {
  wtapng_iface_descriptions_t *idb_info;
  wtap_block_t wtapng_if_descr = NULL;
  char *interface_name;

  idb_info = wtap_file_get_idb_info(prov->wth);

  if (interface_id < idb_info->interface_data->len)
    wtapng_if_descr =
        g_array_index(idb_info->interface_data, wtap_block_t, interface_id);

  g_free(idb_info);

  if (wtapng_if_descr) {
    if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_NAME,
                                           &interface_name) ==
        WTAP_OPTTYPE_SUCCESS)
      return interface_name;
    if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_DESCRIPTION,
                                           &interface_name) ==
        WTAP_OPTTYPE_SUCCESS)
      return interface_name;
    if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_HARDWARE,
                                           &interface_name) ==
        WTAP_OPTTYPE_SUCCESS)
      return interface_name;
  }
  return "unknown";
}

const char *
cap_file_provider_get_interface_description(struct packet_provider_data *prov,
                                            guint32 interface_id) {
  wtapng_iface_descriptions_t *idb_info;
  wtap_block_t wtapng_if_descr = NULL;
  char *interface_name;

  idb_info = wtap_file_get_idb_info(prov->wth);

  if (interface_id < idb_info->interface_data->len)
    wtapng_if_descr =
        g_array_index(idb_info->interface_data, wtap_block_t, interface_id);

  g_free(idb_info);

  if (wtapng_if_descr) {
    if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_DESCRIPTION,
                                           &interface_name) ==
        WTAP_OPTTYPE_SUCCESS)
      return interface_name;
  }
  return NULL;
}

void cap_file_init(capture_file *cf) {
  /* Initialize the capture file struct */
  memset(cf, 0, sizeof(capture_file));
}

static epan_t *raw_epan_new(capture_file *cf) {
  static const struct packet_provider_funcs funcs = {
      raw_get_frame_ts,
      cap_file_provider_get_interface_name,
      cap_file_provider_get_interface_description,
      NULL,
  };

  return epan_new(&cf->provider, &funcs);
}

// init cf_live
char *init_cf_live(capture_file *cf_live) {
  e_prefs *prefs_p;
  /* Create new epan session for dissection. */
  epan_free(cf_live->epan);

  cf_live->provider.wth = NULL;
  cf_live->f_datalen = 0; /* not used, but set it anyway */
  /* Indicate whether it's a permanent or temporary file. */
  cf_live->is_tempfile = FALSE;

  /* No user changes yet. */
  cf_live->unsaved_changes = FALSE;
  cf_live->cd_t = WTAP_FILE_TYPE_SUBTYPE_UNKNOWN;
  cf_live->open_type = WTAP_TYPE_AUTO;
  cf_live->count = 0;
  cf_live->drops_known = FALSE;
  cf_live->drops = 0;
  cf_live->snap = 0;
  cf_live->provider.frames = new_frame_data_sequence();
  nstime_set_zero(&cf_live->elapsed_time);
  cf_live->provider.ref = NULL;
  cf_live->provider.prev_dis = NULL;
  cf_live->provider.prev_cap = NULL;
  cf_live->epan = raw_epan_new(cf_live);
  prefs_p = epan_load_settings();
  build_column_format_array(&cf_live->cinfo, prefs_p->num_cols, TRUE);

  return "";
}

/**
 * Clean the capture file struct.
 */
void close_cf_live(capture_file *cf_live) {
  cf_live->stop_flag = FALSE;
  if (cf_live->provider.wth) {
    wtap_close(cf_live->provider.wth);
    cf_live->provider.wth = NULL;
  }

  /* We have no file open... */
  if (cf_live->filename != NULL) {
    g_free(cf_live->filename);
    cf_live->filename = NULL;
  }

  /* ...which means we have no changes to that file to save. */
  cf_live->unsaved_changes = FALSE;

  /* no open_routine type */
  cf_live->open_type = WTAP_TYPE_AUTO;

  /* Clean up the record metadata. */
  wtap_rec_cleanup(&cf_live->rec);

  cf_live->rfcode = NULL;
  if (cf_live->provider.frames != NULL) {
    free_frame_data_sequence(cf_live->provider.frames);
  }
  if (cf_live->provider.frames_modified_blocks) {
    g_tree_destroy(cf_live->provider.frames_modified_blocks);
    cf_live->provider.frames_modified_blocks = NULL;
  }

  /* No frames, no frame selected, no field in that frame selected. */
  cf_live->count = 0;
  cf_live->current_frame = NULL;
  cf_live->finfo_selected = NULL;

  /* No frame link-layer types, either. */
  if (cf_live->linktypes != NULL) {
    g_array_free(cf_live->linktypes, TRUE);
    cf_live->linktypes = NULL;
  }

  cf_live->f_datalen = 0;
  nstime_set_zero(&cf_live->elapsed_time);

  reset_tap_listeners();

  epan_free(cf_live->epan);
  cf_live->epan = NULL;

  /* We have no file open. */
  cf_live->state = FILE_CLOSED;
}

/**
 * Prepare wtap_rec data.
 *
 *  @param rec: wtap_rec for each packet
 *  @param pkthdr: package header
 *  @return gboolean: true or false
 */
static gboolean prepare_data(wtap_rec *rec, const struct pcap_pkthdr *pkthdr) {
  rec->rec_type = REC_TYPE_PACKET;
  rec->presence_flags = WTAP_HAS_TS | WTAP_HAS_CAP_LEN;
  rec->ts.nsecs = (gint32)pkthdr->ts.tv_usec * 1000;
  rec->ts.secs = pkthdr->ts.tv_sec;
  rec->rec_header.packet_header.caplen = pkthdr->caplen;
  rec->rec_header.packet_header.len = pkthdr->len;
  rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_ETHERNET;

  if (rec->rec_header.packet_header.len == 0) {
    //    printf("Header is null, frame Num:%lu\n",
    //           (unsigned long int)cf_live->count);
    return FALSE;
  }

  if (pkthdr->caplen > WTAP_MAX_PACKET_SIZE_STANDARD) {
    return FALSE;
  }

  return TRUE;
}

/**
 * Use callback to transfer data to the outside wrap program.
 *
 *  @param device: a device in global device map
 *  @return gboolean: true or false
 */
static gboolean send_data_to_wrap(struct device_map *device) {
  cJSON *proto_tree_json = cJSON_CreateObject();
  get_proto_tree_json(
      NULL, print_dissections_expanded, TRUE, NULL, PF_INCLUDE_CHILDREN,
      &device->content.edt, &device->content.cf_live->cinfo,
      proto_node_group_children_by_json_key, proto_tree_json, 1);

  char *proto_tree_json_str = cJSON_PrintUnformatted(proto_tree_json);
  int len = strlen(proto_tree_json_str);

  // send data to Go
  if (dataCallback != NULL) {
    dataCallback(proto_tree_json_str, len, device->device_name);
  }

  cJSON_free(proto_tree_json_str);
  cJSON_Delete(proto_tree_json);

  return TRUE;
}

/**
 * The core dissective process for each captured packet.
 *
 *  @param device: a device in global device map
 *  @param offset: data offset
 *  @param pkthdr: package header
 *  @param packet: package content
 *  @return gboolean: true or false
 */
static gboolean process_packet(struct device_map *device, gint64 offset,
                               const struct pcap_pkthdr *pkthdr,
                               const u_char *packet) {

  frame_data fd;
  guint32 cum_bytes = 0;

  device->content.cf_live->count++;

  frame_data_init(&fd, device->content.cf_live->count, &device->content.rec,
                  offset, cum_bytes);

  frame_data_set_before_dissect(&fd, &device->content.cf_live->elapsed_time,
                                &device->content.cf_live->provider.ref,
                                device->content.cf_live->provider.prev_dis);

  tvbuff_t *tvb =
      frame_tvbuff_new(&device->content.cf_live->provider, &fd, packet);

  // dissect pkg
  epan_dissect_run_with_taps(
      &device->content.edt, device->content.cf_live->cd_t, &device->content.rec,
      tvb, &fd, &device->content.cf_live->cinfo);

  frame_data_set_after_dissect(&fd, &cum_bytes);

  device->content.prev_dis_frame = fd;
  device->content.cf_live->provider.prev_dis = &device->content.prev_dis_frame;
  device->content.prev_cap_frame = fd;
  device->content.cf_live->provider.prev_cap = &device->content.prev_cap_frame;

  if (!send_data_to_wrap(device)) {
    // free all memory allocated
    epan_dissect_reset(&device->content.edt);
    frame_data_destroy(&fd);
    wtap_rec_cleanup(&device->content.rec);

    return FALSE;
  }

  // free all memory allocated
  epan_dissect_reset(&device->content.edt);
  frame_data_destroy(&fd);
  wtap_rec_cleanup(&device->content.rec);

  return TRUE;
}

void before_callback_init(struct device_map *device) {
  epan_dissect_init(&device->content.edt, device->content.cf_live->epan, TRUE,
                    TRUE);
  wtap_rec_init(&device->content.rec);

  return;
}

/**
 * Dissect each package in real time.
 *
 *  @param arg: user argument
 *  @param pkthdr: package header
 *  @param packet: package content
 */
void process_packet_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,
                             const u_char *packet) {
  char *device_name = (char *)arg;
  struct device_map *device = find_device(device_name);
  if (!device) {
    printf("The device is not in the global map: %s\n", device_name);
    return;
  }

  gchar *err_info = NULL;
  gint64 data_offset = 0;
  if (!prepare_data(&device->content.rec, pkthdr)) {
    wtap_rec_cleanup(&device->content.rec);

    return;
  }

  process_packet(device, data_offset, pkthdr, packet);

  return;
}

/**
 * Add a device to global device map、listen to this device、
 * capture packet from this device.
 *
 *  @param device_name: the name of interface device
 *  @param num: the number of packet you want to capture and dissect
 *  @param promisc: 0 indicates a non-promiscuous mode, and any other value
 * indicates a promiscuous mode
 *  @param to_ms: The timeout period for libpcap to capture packets from the
 * device
 *  @return char: error message
 */
char *handle_packet(char *device_name, char *bpf_expr, int num, int promisc,
                    int to_ms) {
  char *err_msg;
  char err_buf[PCAP_ERRBUF_SIZE];
  // add a device to global device map
  err_msg = add_device(device_name, bpf_expr, num, promisc, to_ms);
  if (err_msg != NULL) {
    if (strlen(err_msg) != 0) {
      return err_msg;
    }
  }

  // fetch target device
  struct device_map *device = find_device(device_name);
  if (!device) {
    return "The device is not in the global map";
  }

  // open device && gen a libpcap handle
  device->content.handle =
      pcap_open_live(device->device_name, SNAP_LEN, device->content.promisc,
                     device->content.to_ms, err_buf);
  if (!device->content.handle) {
    // close cf file for live capture
    close_cf_live(device->content.cf_live);

    return "pcap_open_live() couldn't open device";
  }

  // bpf filter
  struct bpf_program fp;
  bpf_u_int32 mask;
  bpf_u_int32 net;

  if (pcap_lookupnet((const char *)device->device_name, &net, &mask, err_buf) !=
      0) {
    fprintf(stderr, "Could not get netmask for device %s: %s\n",
            device->device_name, err_buf);
    net = 0;
    mask = 0;
  }

  if (pcap_compile(device->content.handle, &fp, device->content.bpf_expr, 0,
                   net) != 0) {
    fprintf(stderr, "Could not parse bpf filter %s: %s\n",
            device->content.bpf_expr, pcap_geterr(device->content.handle));
    return "Could not parse bpf filter";
  }

  if (pcap_setfilter(device->content.handle, &fp) != 0) {
    fprintf(stderr, "Could not set filter %s: %s\n", device->content.bpf_expr,
            pcap_geterr(device->content.handle));
    return "Could not set bpf filter";
  }

  printf("Start capture packet on device:%s bpf: %s \n", device->device_name,
         device->content.bpf_expr);

  // loop and dissect pkg
  before_callback_init(device);
  pcap_loop(device->content.handle, device->content.num,
            process_packet_callback, (u_char *)device->device_name);

  return "";
}

/**
 * Stop capture packet live、 free all memory allocated.
 *
 *  @param device: a device in global device map
 *  @return char: err message
 */
char *stop_dissect_capture_pkg(char *device_name) {
  struct device_map *device = find_device(device_name);
  if (!device) {
    return "The device is not in the global map";
  }

  if (!device || !device->content.handle) {
    return "This device has no pcap_handle, no need to close";
  }

  pcap_breakloop(device->content.handle);
  device->content.handle = NULL;

  // close cf file for live capture
  close_cf_live(device->content.cf_live);

  return "";
}
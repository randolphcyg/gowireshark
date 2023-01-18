#include "file.h"
#include <arpa/inet.h>
#include <frame_tvbuff.h>
#include <include/lib.h>
#include <include/uthash.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <wiretap/libpcap.h>

#define SOCKBUFFSIZE 655350

// device_content Contains the information needed for each device
typedef struct device_content {
  char *sock_server_path;
  int sockfd;
  char sock_buf[SOCKBUFFSIZE];
  struct sockaddr_un serveraddr;
  struct sockaddr_un clientaddr;
  socklen_t addrlen;

  char *device;
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

char *add_device(char *device_name, char *sock_server_path, int num,
                 int promisc, int to_ms);
struct device_map *find_device(char *device_name);

void *init_sock_send(void *arg);
char *init_sock(char *device_name);

void cap_file_init(capture_file *cf);
char *init_cf_live(capture_file *cf_live);
void close_cf_live(capture_file *cf_live);

static frame_data ref_frame;

static gboolean prepare_data(wtap_rec *rec, const struct pcap_pkthdr *pkthdr);
static gboolean send_data_to_go(struct device_map *device);
static gboolean process_packet(struct device_map *device, gint64 offset,
                               const struct pcap_pkthdr *pkthdr,
                               const u_char *packet);
void before_callback_init(struct device_map *device);
void process_packet_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,
                             const u_char *packet);
char *handle_pkt_live(char *device_name, char *sock_server_path, int num,
                      int promisc, int to_ms);
char *stop_dissect_capture_pkg(char *device_name);

/*
PART0. Use uthash to implement the logic related to the map of the device
*/

char *add_device(char *device_name, char *sock_server_path, int num,
                 int promisc, int to_ms) {
  struct device_map *s;
  capture_file *cf_tmp;

  HASH_FIND_STR(devices, device_name, s);
  if (s == NULL) {
    s = (struct device_map *)malloc(sizeof *s);

    memset(s, 0, sizeof(struct device_map));

    cf_tmp = (capture_file *)malloc(sizeof *cf_tmp);
    cap_file_init(cf_tmp);

    s->device_name = device_name;
    s->content.sock_server_path = sock_server_path;
    s->content.num = num;
    s->content.promisc = promisc;
    s->content.to_ms = to_ms;
    s->content.addrlen = sizeof(s->content.clientaddr);
    s->content.cf_live = cf_tmp;

    // init capture_file
    char *errMsg = init_cf_live(cf_tmp);
    if (errMsg != NULL) {
      if (strlen(errMsg) != 0) {
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

  return "";
}

struct device_map *find_device(char *device_name) {
  struct device_map *s;

  HASH_FIND_STR(devices, device_name, s);
  return s;
}

/*
PART1. Unix domain socket(AF_UNIX)
*/

// init Unix domain socket(AF_UNIX) send data func
void *init_sock_send(void *arg) {
  char *device_name = (char *)arg;
  struct device_map *device = find_device(device_name);
  if (!device) {
    //    printf("device unknown\n");
    exit(1);
  }

  if ((device->content.sockfd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
    //    printf("fail to socket\n");
    exit(1);
  }
  device->content.serveraddr.sun_family = AF_UNIX;
  strcpy(device->content.serveraddr.sun_path, device->content.sock_server_path);
}

// init Unix domain socket(AF_UNIX)
char *init_sock(char *device_name) {
  pthread_t send;
  if (pthread_create(&send, NULL, init_sock_send, device_name) == -1) {
    return "fail to create pthread send";
  }

  // wait for end
  void *result;
  if (pthread_join(send, &result) == -1) {
    return "fail to recollect send";
  }
}

// safety memcpy
void *memcpy_safe(void *dest, const void *src, size_t n, size_t left_buf_size) {
  if (n > left_buf_size) {
    n = left_buf_size;
  }
  return memcpy(dest, src, n);
}

/*
PART2. libpcap
*/

#define SNAP_LEN 65535
// error buffer
char errbuf[PCAP_ERRBUF_SIZE];

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
  pcap_if_t *alldevs;
  pcap_findalldevs(&alldevs, errbuf);

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
 * Get interface nonblock status.
 *
 *  @param device_name: the name of interface device
 *  @return int: current status is nonblock: 1;
 *  current status is not nonblock: 0;
 *  occur error: 2;
 */
int get_if_nonblock_status(char *device_name) {
  pcap_t *handle;
  int is_nonblock;

  if (device_name) {
    handle = pcap_open_live(device_name, SNAP_LEN, 1, 20, errbuf);
    if (handle == NULL) {
      return 2;
    }
    is_nonblock = pcap_getnonblock(handle, errbuf);
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
  pcap_t *handle;
  int is_nonblock;

  if (device_name) {
    handle = pcap_open_live(device_name, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
      return 2;
    }
    // set nonblock status
    pcap_setnonblock(handle, nonblock, errbuf);
    // get nonblock status
    is_nonblock = pcap_getnonblock(handle, errbuf);
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
    //    free_frame_data_sequence(cf.provider.frames);
    free(cf_live->provider.frames);
    cf_live->provider.frames = NULL;
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
    //    printf("Size is to big, and size is %d\n", pkthdr->caplen);
    return FALSE;
  }

  return TRUE;
}

/**
 * Use socket to transfer data to the Go program.
 *
 *  @param device: a device in global device map
 *  @return gboolean: true or false
 */
static gboolean send_data_to_go(struct device_map *device) {
  // transfer each pkt dissect result to json format
  cJSON *proto_tree_json = cJSON_CreateObject();
  get_proto_tree_json(NULL, print_dissections_expanded, TRUE, NULL,
                      PF_INCLUDE_CHILDREN, &device->content.edt,
                      &device->content.cf_live->cinfo,
                      proto_node_group_children_by_json_key, proto_tree_json);

  char *proto_tree_json_str = cJSON_PrintUnformatted(proto_tree_json);

  int len = strlen(proto_tree_json_str);
  memset(device->content.sock_buf, 0, len);
  memcpy_safe(device->content.sock_buf, proto_tree_json_str, len, SOCKBUFFSIZE);
  if (sendto(device->content.sockfd, device->content.sock_buf, len, 0,
             (struct sockaddr *)&device->content.serveraddr,
             device->content.addrlen) < 0) {
    cJSON_free(proto_tree_json_str);
    cJSON_Delete(proto_tree_json);
    epan_dissect_cleanup(&device->content.edt);
    wtap_rec_cleanup(&device->content.rec);
    //    printf("socket err, fail to sendto, frame Num:%lu\n",
    //           (unsigned long int)device->content.cf_live->count);
    return FALSE;
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
  static guint32 cum_bytes = 0;

  device->content.cf_live->count++;

  frame_data_init(&fd, device->content.cf_live->count, &device->content.rec,
                  offset, cum_bytes);

  frame_data_set_before_dissect(&fd, &device->content.cf_live->elapsed_time,
                                &device->content.cf_live->provider.ref,
                                device->content.cf_live->provider.prev_dis);

  if (device->content.cf_live->provider.ref == &fd) {
    ref_frame = fd;
    device->content.cf_live->provider.ref = &ref_frame;
  }

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

  if (!send_data_to_go(device)) {
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
    return;
  }

  gchar *err_info = NULL;
  gint64 data_offset = 0;
  if (!prepare_data(&device->content.rec, pkthdr)) {
    //    printf("prepare_data err, frame Num:%lu\n",
    //           (unsigned long int)device->content.cf_live->count);
    wtap_rec_cleanup(&device->content.rec);

    return;
  }

  process_packet(device, data_offset, pkthdr, packet);

  return;
}

/**
 * Listen device and Capture packet.
 *
 *  @param device_name: the name of interface device
 *  @param sock_server_path: device's socket server path
 *  @param num: the number of packet you want to capture and dissect
 *  @param promisc: 0 indicates a non-promiscuous mode, and any other value
 * indicates a promiscuous mode
 *  @param to_ms: The timeout period for libpcap to capture packets from the
 * device
 *  @return char: error message
 */
char *handle_pkt_live(char *device_name, char *sock_server_path, int num,
                      int promisc, int to_ms) {

  char *errMsg;
  char errBuf[PCAP_ERRBUF_SIZE];

  // add device to global map
  errMsg = add_device(device_name, sock_server_path, num, promisc, to_ms);
  if (errMsg != NULL) {
    if (strlen(errMsg) != 0) {
      return errMsg;
    }
  }

  // fetch target device
  struct device_map *device = find_device(device_name);
  if (!device) {
    return "device unknown";
  }

  // open device
  device->content.handle =
      pcap_open_live(device->device_name, SNAP_LEN, device->content.promisc,
                     device->content.to_ms, errBuf);
  if (!device->content.handle) {
    // close cf file for live capture
    close_cf_live(device->content.cf_live);

    return "pcap_open_live() couldn't open device";
  }

  // start Unix domain socket(AF_UNIX) to send data to golang
  errMsg = init_sock(device->device_name);
  if (errMsg != NULL) {
    if (strlen(errMsg) != 0) {
      return errMsg;
    }
  }

  // loop and dissect pkg
  int count = 0;
  before_callback_init(device);
  pcap_loop(device->content.handle, num, process_packet_callback,
            device->device_name);
  // close libpcap device handler
  pcap_close(device->content.handle);
  // close cf file for live capture
  close_cf_live(device->content.cf_live);
  // close socket
  close(device->content.sockfd);

  return "";
}

/**
 * Stop capture packet live、 free all memory allocated、close socket.
 *
 *  @param device: a device in global device map
 *  @return char: err message
 */
char *stop_dissect_capture_pkg(char *device_name) {
  struct device_map *device = find_device(device_name);
  if (!device) {
    return "device unknown";
  }

  if (!device->content.handle) {
    return "This device has no pcap_handle, no need to close";
  }

  pcap_breakloop(device->content.handle);

  // close cf file for live capture
  close_cf_live(device->content.cf_live);

  // shutdown socket's write function and close socket
  int shut_wr_res = shutdown(device->content.sockfd, SHUT_WR);
  if (shut_wr_res != 0) {
    printf("SHUT_WR: %s\n", "close socket write failed!");
  }
  close(device->content.sockfd);

  return "";
}
#include "file.h"
#include <arpa/inet.h>
#include <frame_tvbuff.h>
#include <include/lib.h>
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

/*
PART1. Unix domain socket(AF_UNIX)
*/

#define SOCKSERVERPATH "/tmp/gsocket"
#define SOCKBUFFSIZE 655350
int sockfd;
char sock_buf[SOCKBUFFSIZE] = {};
struct sockaddr_un serveraddr;
struct sockaddr_un clientaddr;
socklen_t addrlen = sizeof(clientaddr);

void *init_sock_send(void *arg);
void init_sock();

// init Unix domain socket(AF_UNIX) send data func
void *init_sock_send(void *arg) {
  if ((sockfd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
    printf("fail to socket\n");
    exit(1);
  }
  serveraddr.sun_family = AF_UNIX;
  strcpy(serveraddr.sun_path, SOCKSERVERPATH);
}

// init Unix domain socket(AF_UNIX)
void init_sock() {
  pthread_t send;
  if (pthread_create(&send, NULL, init_sock_send, NULL) == -1) {
    printf("fail to create pthread send\n");
    exit(1);
  }

  // wait for end
  void *result;
  if (pthread_join(send, &result) == -1) {
    printf("fail to recollect send\n");
    exit(1);
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

/*select the first nic_device available on the machine
 * return :
 * -1: on failture
 *  0: on success*/
int get_first_device(char *device){
    pcap_if_t *first_if;

    if (pcap_findalldevs(&first_if, errbuf) < 0) {
        fprintf(stderr, "Error: couldn't find any devices %s\n", errbuf);
        return -1;
    }

    strncpy(device, first_if->name, IFNAMSIZ - 1);
    pcap_freealldevs(first_if);

    return 0;

}

/**
 * Get interface nonblock status.
 *
 *  @param device: the name of interface device
 *  @return current status is nonblock: 1;
 *  current status is not nonblock: 0;
 *  occur error: 2;
 */
int get_if_nonblock_status(char *device) {
  pcap_t *handle;
  int is_nonblock;

  if (device) {
    handle = pcap_open_live(device, SNAP_LEN, 1, 20, errbuf);
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
 *  @param device: the name of interface device
 *  @param nonblock set 1: is nonblock, set 0: is not nonblock
 *  @return current status is nonblock: 1;
 *  current status is not nonblock: 0;
 *  occur error: 2;
 */
int set_if_nonblock_status(char *device, int nonblock) {
  pcap_t *handle;
  int is_nonblock;

  if (device) {
    handle = pcap_open_live(device, SNAP_LEN, 1, 1000, errbuf);
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

// global capture file variable for online logic
capture_file cf_live;
pcap_t *handle;
static frame_data prev_dis_frame;
static frame_data prev_cap_frame;

int init_cf_live();
void close_cf_live();

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

// init cf_live
int init_cf_live() {
  int err = 0;
  e_prefs *prefs_p;

  /* Create new epan session for dissection. */
  epan_free(cf_live.epan);

  /* Initialize the capture file struct */
  memset(&cf_live, 0, sizeof(capture_file));

  cf_live.provider.wth = NULL;
  cf_live.f_datalen = 0; /* not used, but set it anyway */

  /* Indicate whether it's a permanent or temporary file. */
  cf_live.is_tempfile = FALSE;

  /* No user changes yet. */
  cf_live.unsaved_changes = FALSE;

  cf_live.cd_t = WTAP_FILE_TYPE_SUBTYPE_UNKNOWN;
  cf_live.open_type = WTAP_TYPE_AUTO;
  cf_live.count = 0;
  cf_live.drops_known = FALSE;
  cf_live.drops = 0;
  cf_live.snap = 0;
  cf_live.provider.frames = new_frame_data_sequence();
  nstime_set_zero(&cf_live.elapsed_time);
  cf_live.provider.ref = NULL;
  cf_live.provider.prev_dis = NULL;
  cf_live.provider.prev_cap = NULL;
  static const struct packet_provider_funcs funcs = {
      raw_get_frame_ts,
      cap_file_provider_get_interface_name,
      cap_file_provider_get_interface_description,
      NULL,
  };
  cf_live.epan = epan_new(&cf_live.provider, &funcs);
  prefs_p = epan_load_settings();
  build_column_format_array(&cf_live.cinfo, prefs_p->num_cols, TRUE);
  return 0;
}

/**
 * Clean the capture file struct.
 */
void close_cf_live() {
  cf_live.stop_flag = FALSE;
  if (cf_live.provider.wth) {
    wtap_close(cf_live.provider.wth);
    cf_live.provider.wth = NULL;
  }

  /* We have no file open... */
  if (cf_live.filename != NULL) {
    g_free(cf_live.filename);
    cf_live.filename = NULL;
  }

  /* ...which means we have no changes to that file to save. */
  cf_live.unsaved_changes = FALSE;

  /* no open_routine type */
  cf_live.open_type = WTAP_TYPE_AUTO;

  /* Clean up the record metadata. */
  wtap_rec_cleanup(&cf_live.rec);

  cf_live.rfcode = NULL;
  if (cf_live.provider.frames != NULL) {
    //    free_frame_data_sequence(cf.provider.frames);
    free(cf_live.provider.frames);
    cf_live.provider.frames = NULL;
  }
  if (cf_live.provider.frames_modified_blocks) {
    g_tree_destroy(cf_live.provider.frames_modified_blocks);
    cf_live.provider.frames_modified_blocks = NULL;
  }

  /* No frames, no frame selected, no field in that frame selected. */
  cf_live.count = 0;
  cf_live.current_frame = NULL;
  cf_live.finfo_selected = NULL;

  /* No frame link-layer types, either. */
  if (cf_live.linktypes != NULL) {
    g_array_free(cf_live.linktypes, TRUE);
    cf_live.linktypes = NULL;
  }

  cf_live.f_datalen = 0;
  nstime_set_zero(&cf_live.elapsed_time);

  reset_tap_listeners();

  epan_free(cf_live.epan);
  cf_live.epan = NULL;

  /* We have no file open. */
  cf_live.state = FILE_CLOSED;
}

/**
 * Prepare data: cf_live.buf、rec.
 *
 *  @param
 *  @return gboolean true or false;
 */
static gboolean prepare_data(wtap_rec *rec, Buffer *buf, int *err,
                             gchar **err_info, const struct pcap_pkthdr *pkthdr,
                             const u_char *packet, gint64 *data_offset) {
  *err = 0;

  rec->rec_type = REC_TYPE_PACKET;
  rec->presence_flags = WTAP_HAS_TS | WTAP_HAS_CAP_LEN;
  rec->ts.nsecs = (gint32)pkthdr->ts.tv_usec * 1000;
  rec->ts.secs = pkthdr->ts.tv_sec;
  rec->rec_header.packet_header.caplen = pkthdr->caplen;
  rec->rec_header.packet_header.len = pkthdr->len;
  rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_ETHERNET;

  int length = strlen((char *)packet);
  memcpy(buf->data, packet, length);

  if (rec->rec_header.packet_header.len == 0) {
    printf("Header is null, frame Num:%lu\n", (unsigned long int)cf_live.count);

    return FALSE;
  }

  return TRUE;
}

/**
 * Dissect each package in real time.
 *
 *  @param pkthdr package header;
 *  @param packet package content;
 */
void process_packet_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,
                             const u_char *packet) {
  int err;
  gchar *err_info = NULL;
  gint64 data_offset = 0;
  static guint32 cum_bytes = 0;
  frame_data fd;
  wtap_rec rec;
  Buffer buf;
  epan_dissect_t edt;

  wtap_rec_init(&rec);
  ws_buffer_init(&buf, 1514);
  epan_dissect_init(&edt, cf_live.epan, TRUE, TRUE);

  if (!prepare_data(&rec, &buf, &err, &err_info, pkthdr, packet,
                    &data_offset)) {
    printf("prepare_data err, frame Num:%lu\n",
           (unsigned long int)cf_live.count);

    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);

    return;
  }

  cf_live.count++;
  frame_data_init(&fd, cf_live.count, &rec, data_offset, cum_bytes);
  frame_data_set_before_dissect(&fd, &cf_live.elapsed_time,
                                &cf_live.provider.ref,
                                cf_live.provider.prev_dis);
  cf_live.provider.ref = &fd;

  // dissect pkg
  epan_dissect_run_with_taps(
      &edt, cf_live.cd_t, &rec,
      frame_tvbuff_new_buffer(&cf_live.provider, &fd, &buf), &fd,
      &cf_live.cinfo);

  frame_data_set_after_dissect(&fd, &cum_bytes);
  prev_dis_frame = fd;
  cf_live.provider.prev_dis = &prev_dis_frame;
  prev_cap_frame = fd;
  cf_live.provider.prev_cap = &prev_cap_frame;

  // transfer each pkt dissect result to json format
  cJSON *proto_tree_json = cJSON_CreateObject();
  get_proto_tree_json(NULL, print_dissections_expanded, TRUE, NULL,
                      PF_INCLUDE_CHILDREN, &edt, &cf_live.cinfo,
                      proto_node_group_children_by_json_key, proto_tree_json);

  char *proto_tree_json_str = cJSON_PrintUnformatted(proto_tree_json);

  int len = strlen(proto_tree_json_str);
  memset(sock_buf, 0, len);
  memcpy_safe(sock_buf, proto_tree_json_str, len, SOCKBUFFSIZE);
  if (sendto(sockfd, sock_buf, len, 0, (struct sockaddr *)&serveraddr,
             addrlen) < 0) {
    printf("socket err, fail to sendto, frame Num:%lu\n",
           (unsigned long int)cf_live.count);
  }

  // free all memory allocated
  cJSON_free(proto_tree_json_str);
  cJSON_Delete(proto_tree_json);
  epan_dissect_cleanup(&edt);
  frame_data_destroy(&fd);
  ws_buffer_free(&buf);
  wtap_rec_cleanup(&rec);

  return;
}

/**
 * Listen device and Capture packet.
 *
 *  @param device: the name of interface device
 *  @param num the number of packet you want to capture and dissect
 *  @param promisc 0 indicates a non-promiscuous mode, and any other value
 * indicates a promiscuous mode.
 *  @return correct: 0; error: 2;
 */
int handle_pkt_live(char *device, int num, int promisc, int to_ms) {
  int err = 0;
  char errBuf[PCAP_ERRBUF_SIZE];

  // init capture_file obj for live capture and dissect
  err = init_cf_live();
  if (err != 0) {
    // close cf file for live capture
    close_cf_live();
    return err;
  }

  // open device
  handle = pcap_open_live(device, SNAP_LEN, promisc, to_ms, errBuf);
  if (!handle) {
    printf("pcap_open_live() couldn't open device: %s\n", errBuf);
    // close cf file for live capture
    close_cf_live();
    return 2;
  }

  // start Unix domain socket(AF_UNIX) to send data to golang
  init_sock();

  // loop and dissect pkg
  int count = 0;
  pcap_loop(handle, num, process_packet_callback, NULL);
  // close libpcap device handler
  pcap_close(handle);
  // close cf file for live capture
  close_cf_live();
  // close socket
  close(sockfd);

  return 0;
}

/**
 * Stop capture packet live、 free all memory allocated、close socket.
 */
char *stop_dissect_capture_pkg() {
  if (!handle) {
    return "This device has no pcap_handle, no need to close";
  }
  pcap_breakloop(handle);

  // close cf file for live capture
  close_cf_live();

  // shutdown socket's write function and close socket
  int shut_wr_res = shutdown(sockfd, SHUT_WR);
  if (shut_wr_res != 0) {
    printf("SHUT_WR: %s\n", "close socket write failed！");
  }
  close(sockfd);

  return "";
}

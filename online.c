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
libpcap function
*/

#define BUFSIZE 65535
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
 *  @param device_name the name of interface device
 *  @return current status is nonblock: 1;
 *  current status is not nonblock: 0;
 *  occur error: 2;
 */
int get_if_nonblock_status(char *device_name) {
  pcap_t *handle;
  int is_nonblock;

  if (device_name) {
    handle = pcap_open_live(device_name, BUFSIZE, 1, 20, errbuf);
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
 *  @param device_name the name of interface device
 *  @param nonblock set 1: is nonblock, set 0: is not nonblock
 *  @return current status is nonblock: 1;
 *  current status is not nonblock: 0;
 *  occur error: 2;
 */
int set_if_nonblock_status(char *device_name, int nonblock) {
  pcap_t *handle;
  int is_nonblock;

  if (device_name) {
    handle = pcap_open_live(device_name, BUFSIZE, 1, 1000, errbuf);
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
rawshark function
*/

// global capture file variable for online logic
capture_file cf_live;
static frame_data prev_dis_frame;
static frame_data prev_cap_frame;

/*
 * The way the packet decode is to be written.
 */
typedef enum {
  WRITE_TEXT, /* summary or detail text */
  WRITE_XML   /* PDML or PSML */
              /* Add CSV and the like here */
} output_action_e;

static gboolean line_buffered;
static print_format_e print_format = PR_FMT_TEXT;

static gboolean want_pcap_pkthdr;

int init_cf_live();
static void show_print_file_io_error(int err);

typedef enum {
  SF_NONE,   /* No format (placeholder) */
  SF_NAME,   /* %D Field name / description */
  SF_NUMVAL, /* %N Numeric value */
  SF_STRVAL  /* %S String value */
} string_fmt_e;

typedef struct string_fmt_s {
  gchar *plain;
  string_fmt_e format; /* Valid if plain is NULL */
} string_fmt_t;

int encap;
GPtrArray *string_fmts;

/**
 * Prepare data for print_hex_data func .
 *
 *  @param
 *  @return gboolean true or false;
 */
static gboolean prepare_data(wtap_rec *rec, Buffer *buf, int *err,
                             gchar **err_info, const struct pcap_pkthdr *pkthdr,
                             const u_char *packet, gint64 *data_offset) {
  struct pcaprec_hdr disk_hdr;
  ssize_t bytes_read = 0;
  unsigned int bytes_needed = (unsigned int)sizeof(disk_hdr);

  *err = 0;

  bytes_needed = sizeof(pkthdr);

  rec->rec_type = REC_TYPE_PACKET;
  rec->presence_flags = WTAP_HAS_TS | WTAP_HAS_CAP_LEN;

  rec->ts.nsecs = (gint32)pkthdr->ts.tv_usec * 1000;
  rec->ts.secs = pkthdr->ts.tv_sec;
  rec->rec_header.packet_header.caplen = pkthdr->caplen;
  rec->rec_header.packet_header.len = pkthdr->len;

  bytes_needed = rec->rec_header.packet_header.caplen;

  rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_ETHERNET;

  if (bytes_needed > WTAP_MAX_PACKET_SIZE_STANDARD) {
    *err = WTAP_ERR_BAD_FILE;
    *err_info =
        ws_strdup_printf("Bad packet length: %lu", (unsigned long)bytes_needed);
    return FALSE;
  }

  // assign space for buf
  ws_buffer_assure_space(buf, bytes_needed);
  buf->data = packet;

  return TRUE;
}

static guint hexdump_source_option =
    HEXDUMP_SOURCE_MULTI; /* Default - Enable legacy multi-source mode */
static guint hexdump_ascii_option =
    HEXDUMP_ASCII_INCLUDE; /* Default - Enable legacy undelimited ASCII dump */

static void show_print_file_io_error(int err) {
  switch (err) {

  case ENOSPC:
    printf("Not all the packets could be printed because there is "
           "no space left on the file system.");
    break;

#ifdef EDQUOT
  case EDQUOT:
    printf("Not all the packets could be printed because you are "
           "too close to, or over your disk quota.");
    break;
#endif

  default:
    printf("An error occurred while printing packets: %s.", g_strerror(err));
    break;
  }
}

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

void process_packet_to_file(u_char *arg, const struct pcap_pkthdr *pkthdr,
                            const u_char *packet) {
  pcap_dump(arg, pkthdr, packet);
  printf("Received Packet Size: %d\n", pkthdr->len);
  return;
}

#define N 65535
void *init_psend(void *a);
void init_unix_domain();
char unix_buf[N] = {};
int sockfd;
struct sockaddr_un serveraddr;
struct sockaddr_un clientaddr;
socklen_t addrlen = sizeof(clientaddr);

// unix domain send data
void *init_psend(void *a) {
  if ((sockfd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
    printf("fail to socket\n");
    exit(1);
  }
  serveraddr.sun_family = AF_UNIX;
  strcpy(serveraddr.sun_path, "/tmp/gsocket");
}

// unix domain init
void init_unix_domain() {
  pthread_t send;
  pthread_t recv;
  if (pthread_create(&send, NULL, init_psend, NULL) == -1) {
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

/**
 * Dissect each package in real time.
 *
 *  @param pkthdr package header;
 *  @param packet package content;
 */
void process_packet_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,
                             const u_char *packet) {
  int *count = (int *)arg;
  int err;
  gchar *err_info = NULL;
  gint64 data_offset = 0;
  static guint32 cum_bytes = 0;
   Buffer buf;
   ws_buffer_init(&buf, 1514);

  wtap_rec rec;
  epan_dissect_t edt;

  wtap_rec_init(&rec);

  epan_dissect_init(&edt, cf_live.epan, TRUE, TRUE);

  // prepare data: cf_live.buf、rec
  if (!prepare_data(&rec, &buf, &err, &err_info, pkthdr, packet,
                    &data_offset)) {
    printf("%s \n", "prepare_data err");
    return;
  }

  // dissect pkg
  if (&rec.rec_header.packet_header.len == 0) {
    printf("Header is null, frame No.%lu %" PRIu64 " %ls void -\n",
           (unsigned long int)cf_live.count, (guint64)&rec.ts.secs,
           &rec.ts.nsecs);

    fflush(stdout);

    return;
  }

  cf_live.count++;
  frame_data fd;
  frame_data_init(&fd, cf_live.count, &rec, data_offset, cum_bytes);
  frame_data_set_before_dissect(&fd, &cf_live.elapsed_time,
                                &cf_live.provider.ref,
                                cf_live.provider.prev_dis);
  cf_live.provider.ref = &fd;
  // dissect logic
  epan_dissect_run_with_taps(
      &edt, cf_live.cd_t, &rec,
      frame_tvbuff_new_buffer(&cf_live.provider, &fd, &buf), &fd,
      &cf_live.cinfo);
  frame_data_set_after_dissect(&fd, &cum_bytes);
  prev_dis_frame = fd;
  cf_live.provider.prev_dis = &prev_dis_frame;
  prev_cap_frame = fd;
  cf_live.provider.prev_cap = &prev_cap_frame;

  if (ferror(stdout)) {
    show_print_file_io_error(errno);
    exit(2);
  }

  static pf_flags protocolfilter_flags = PF_NONE;
  static proto_node_children_grouper_func node_children_grouper =
      proto_node_group_children_by_unique;
  protocolfilter_flags = PF_INCLUDE_CHILDREN;
  node_children_grouper = proto_node_group_children_by_json_key;
  // transfer each pkt dissect result to json format
  char *tree_res_json = get_proto_tree_dissect_res_in_json(
      NULL, print_dissections_expanded, TRUE, NULL, protocolfilter_flags, &edt,
      &cf_live.cinfo, node_children_grouper);
  // unix domain send data to go
  memcpy_safe(unix_buf, tree_res_json, strlen(tree_res_json), N);
  if (sendto(sockfd, unix_buf, strlen(tree_res_json), 0,
             (struct sockaddr *)&serveraddr, addrlen) < 0) {
    printf("###### %s #####\n", "fail to sendto");
  }
  memset(unix_buf, 0, N);

  // clean tmp data
  ws_buffer_free(&cf_live.buf);
  cJSON_free(tree_res_json);
  epan_dissect_reset(&edt);
  frame_data_destroy(&fd);
  wtap_rec_cleanup(&rec);

  return;
}

/**
 * Listen device and Capture packet.
 *
 *  @param device_name the name of interface device
 *  @return correct: 0; error: 2;
 */
int handle_pkt_live(char *device_name, int num) {
  int err = 0;
  char errBuf[PCAP_ERRBUF_SIZE], *devStr;
  // Save the starting address of the received packet
  const unsigned char *p_packet_content = NULL;
  struct pcap_pkthdr protocol_header;

  // init capture_file obj for live capture and dissect
  err = init_cf_live();
  if (err != 0) {
    return err;
  }

  // open device
  pcap_t *device = pcap_open_live(device_name, BUFSIZE, 1, 20, errBuf);
  if (!device) {
    printf("pcap_open_live() couldn't open device: %s\n", errBuf);
    return 2;
  }

  // start unix domain to send data to golang
  init_unix_domain();

  // loop and dissect pkg
  int count = 0;
  pcap_loop(device, num, process_packet_callback, (u_char *)&count);

  pcap_close(device);
  close(sockfd);

  return 0;
}
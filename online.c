#include <include/lib.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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

  return cJSON_PrintUnformatted(ifaces);
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
    handle = pcap_open_live(device_name, BUFSIZE, 1, 1000, errbuf);
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

// global capture file variable for online logic
capture_file cf_live;

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

void init_cf_live() {
  int err = 0;
  gchar *err_info = NULL;
  e_prefs *prefs_p;

  /* Initialize the capture file struct */
  memset(&cf_live, 0, sizeof(capture_file));
  // Online analysis does not have the step of wtap_open_offline, how should the
  // data be set correctly?
  //  cf_live.filename = filepath;
  //  cf_live.provider.wth =
  //      wtap_open_offline(cf_live.filename, WTAP_TYPE_AUTO, &err, &err_info,
  //      TRUE);
  //  if (err != 0 || cf_live.provider.wth == NULL) {
  //    clean();
  //    return err;
  //  }
  cf_live.count = 0;
  cf_live.provider.frames = new_frame_data_sequence();
  static const struct packet_provider_funcs funcs = {
      tshark_get_frame_ts,
      NULL,
      NULL,
      NULL,
  };
  cf_live.epan = epan_new(&cf_live.provider, &funcs);
  prefs_p = epan_load_settings();
  build_column_format_array(&cf_live.cinfo, prefs_p->num_cols, TRUE);
}

/**
 * Read each live packet.
 *
 *  @param argument
 *  @param packet_header a pcap_pkthdr type
 *  @param packet_content  pointer to packet
 */
gboolean read_live_packet(epan_dissect_t **edt_r,
                          const struct pcap_pkthdr *packet_header,
                          const unsigned char *packet_content) {
  epan_dissect_t *edt;
  int err;
  gchar *err_info = NULL;
  static guint32 cum_bytes = 0;
  static gint64 data_offset = 0;
  wtap_rec rec;
  wtap_rec_init(&rec);

  cf_live.count++;
  frame_data fd;
  frame_data_init(&fd, cf_live.count, &rec, data_offset, cum_bytes);
  // data_offset must be correctly set
  data_offset = fd.pkt_len;
  edt = epan_dissect_new(cf_live.epan, TRUE, TRUE);
  prime_epan_dissect_with_postdissector_wanted_hfids(edt);
  /**
   * Sets the frame data struct values before dissection.
   */
  frame_data_set_before_dissect(&fd, &cf_live.elapsed_time,
                                &cf_live.provider.ref,
                                cf_live.provider.prev_dis);
  cf_live.provider.ref = &fd;
  tvbuff_t *tvb;
  tvb = tvb_new_real_data(cf_live.buf.data, data_offset, data_offset);
  // core dissect process
  epan_dissect_run_with_taps(edt, cf_live.cd_t, &rec, tvb, &fd, &cf_live.cinfo);
  frame_data_set_after_dissect(&fd, &cum_bytes);
  cf_live.provider.prev_cap = cf_live.provider.prev_dis =
      frame_data_sequence_add(cf_live.provider.frames, &fd);
  // free space
  frame_data_destroy(&fd);
  *edt_r = edt;

  return TRUE;
}

/**
 * Handle each packet in callback function.
 *
 *  @param argument
 *  @param packet_header a pcap_pkthdr type
 *  @param packet_content  pointer to packet
 */
void dissect_protocol_callback(unsigned char *argument,
                               const struct pcap_pkthdr *packet_header,
                               const unsigned char *packet_content) {
  unsigned char *mac_string; // mac str
  struct ether_header *ethernet_protocol;
  unsigned short ethernet_type; // eth type

  printf("----------------------------------------------------\n");
  printf("Packet length : %d\n", packet_header->len);
  printf("Number of bytes : %d\n", packet_header->caplen);
  printf("Received time : %s\n",
         ctime((const time_t *)&packet_header->ts.tv_sec));

  // dissect and print
  epan_dissect_t *edt;
  print_stream_t *print_stream;
  print_stream = print_stream_text_stdio_new(stdout);
  if (read_live_packet(&edt, packet_header, packet_content)) {
    proto_tree_print(print_dissections_expanded, FALSE, edt, NULL,
                     print_stream);
    epan_dissect_free(edt);
    edt = NULL;
  }

  //  ethernet_protocol = (struct ether_header *)packet_content;
  //  // get src mac addr
  //  mac_string = (unsigned char *)&(ethernet_protocol->ether_shost);
  //  printf("Mac Source Address is %02x:%02x:%02x:%02x:%02x:%02x\n",
  //         *(mac_string + 0), *(mac_string + 1), *(mac_string + 2),
  //         *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
  //
  //  // get dest mac
  //  mac_string = (unsigned char *)&(ethernet_protocol->ether_dhost);
  //  printf("Mac Destination Address is %02x:%02x:%02x:%02x:%02x:%02x\n",
  //         *(mac_string + 0), *(mac_string + 1), *(mac_string + 2),
  //         *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
  //
  //  // get eth type
  //  ethernet_type = ntohs(ethernet_protocol->ether_type);
  //  printf("Ethernet type is :%04x\n", ethernet_type);
  //  switch (ethernet_type) {
  //  case 0x0800: // ip
  //    printf("The network layer is IP protocol\n");
  //    break;
  //  case 0x0806: // arp
  //    printf("The network layer is ARP protocol\n");
  //    break;
  //  case 0x0835: // rarp
  //    printf("The network layer is RARP protocol\n");
  //    break;
  //  default:
  //    break;
  //  }
  //
  //  // hex data
  //  int i;
  //  for (i = 0; i < packet_header->caplen; i++) {
  //    printf(" %02x", packet_content[i]);
  //    if ((i + 1) % 16 == 0) {
  //      printf("\n");
  //    }
  //  }
  //  printf("\n\n");

  //  g_usleep(800 * 1000);
}

/**
 * Listen device and Capture packet.
 *
 *  @param device_name the name of interface device
 *  @return normal run: 0;occur error: 2;
 */
int capture_pkt(char *device_name) {
  // init capture file struct to hold live packet
  init_cf_live();

  pcap_if_t *alldevs;
  // Save the starting address of the received packet
  const unsigned char *p_packet_content = NULL;
  pcap_t *pcap_handle = NULL;
  struct pcap_pkthdr protocol_header;

  pcap_findalldevs(&alldevs, errbuf);
  if (alldevs == NULL) {
    fprintf(stderr, "couldn't find device: %s\n", errbuf);
    return 2;
  }

  // gopacket set 1000; too fast if set 1; so set 20 for now
  pcap_handle = pcap_open_live(alldevs->name, BUFSIZE, 1, 20, NULL);
  /* pcap_loop loop read packet
  second para is cnt, if cnt equals -1, will loop util ends;
  else the number of returned packets is cnt;
  third para is callback function, will handle each packet;
  */
  // TODO only 2 packages are analyzed, and it is modified to -1 after the
  // process is completed
  if (pcap_loop(pcap_handle, 2, dissect_protocol_callback, NULL) < 0) {
    perror("pcap_loop");
  }

  pcap_close(pcap_handle);

  return 0;
}

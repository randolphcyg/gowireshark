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

// get_if_list Get interface list
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

// get_if_nonblock_status Get interface nonblock status
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

// set_if_nonblock_status Set interface nonblock status
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

// dissect_protocol_callback handle each packet
void dissect_protocol_callback(unsigned char *argument,
                               const struct pcap_pkthdr *packet_heaher,
                               const unsigned char *packet_content) {
  unsigned char *mac_string; // mac str
  struct ether_header *ethernet_protocol;
  unsigned short ethernet_type; // eth type

  printf("----------------------------------------------------\n");
  printf("%s\n", ctime((time_t *)&(packet_heaher->ts.tv_sec)));

  ethernet_protocol = (struct ether_header *)packet_content;
  // get src mac addr
  mac_string = (unsigned char *)&(ethernet_protocol->ether_shost);
  printf("Mac Source Address is %02x:%02x:%02x:%02x:%02x:%02x\n",
         *(mac_string + 0), *(mac_string + 1), *(mac_string + 2),
         *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

  // get dest mac
  mac_string = (unsigned char *)&(ethernet_protocol->ether_dhost);
  printf("Mac Destination Address is %02x:%02x:%02x:%02x:%02x:%02x\n",
         *(mac_string + 0), *(mac_string + 1), *(mac_string + 2),
         *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

  // get eth type
  ethernet_type = ntohs(ethernet_protocol->ether_type);
  printf("Ethernet type is :%04x\n", ethernet_type);
  switch (ethernet_type) {
  case 0x0800: // ip
    printf("The network layer is IP protocol\n");
    break;
  case 0x0806: // arp
    printf("The network layer is ARP protocol\n");
    break;
  case 0x0835: // rarp
    printf("The network layer is RARP protocol\n");
    break;
  default:
    break;
  }
  //  g_usleep(800 * 1000);
}

// capture_pkt Capture packet
int capture_pkt(char *device_name) {
  pcap_if_t *alldevs;
  // Save the starting address of the received packet
  const unsigned char *p_packet_content = NULL;
  pcap_t *pcap_handle = NULL;
  struct pcap_pkthdr protocol_header;

  pcap_findalldevs(&alldevs, errbuf);
  if (alldevs == NULL) {
    fprintf(stderr, "couldn't find default device: %s\n", errbuf);
    return 2;
  }

  pcap_handle = pcap_open_live(alldevs->name, 1024, 1, 0, NULL);
  if (pcap_loop(pcap_handle, -1, dissect_protocol_callback, NULL) < 0) {
    perror("pcap_loop");
  }

  pcap_close(pcap_handle);

  return 0;
}

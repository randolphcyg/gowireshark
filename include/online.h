#include <pcap/pcap.h>

// interface device list
extern cJSON *ifaces;

// Get interface list
char *get_if_list();
// Get interface nonblock status
int get_if_nonblock_status(char *device_name);
// Set interface nonblock status
int set_if_nonblock_status(char *device_name, int nonblock);
// Capture packet and handle each one
int capture_pkt(char *device_name);
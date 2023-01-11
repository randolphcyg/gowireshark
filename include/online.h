#include <pcap/pcap.h>

// interface device list
extern cJSON *ifaces;

// Get interface list
char *get_if_list();
// Select the first device
int get_first_device(char *device)；
// Get interface nonblock status
int get_if_nonblock_status(char *device);
// Set interface nonblock status
int set_if_nonblock_status(char *device, int nonblock);
// Capture and dissect packet in real time
int handle_pkt_live(char *device, int num, int promisc, int to_ms);
// Stop capture packet live、 free all memory allocated、close socket.
char *stop_dissect_capture_pkg();

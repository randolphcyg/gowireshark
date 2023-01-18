#include <pcap/pcap.h>

// interface device list
extern cJSON *ifaces;

// Get interface list
char *get_if_list();
// Get interface nonblock status
int get_if_nonblock_status(char *device_name);
// Set interface nonblock status
int set_if_nonblock_status(char *device_name, int nonblock);
// Capture and dissect packet in real time
char *handle_packet(char *device_name, char *sock_server_path, int num,
                      int promisc, int to_ms);
// Stop capture packet live、 free all memory allocated、close socket.
char *stop_dissect_capture_pkg(char *device_name);
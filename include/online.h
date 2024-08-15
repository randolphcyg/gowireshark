// interface device list
extern cJSON *ifaces;

// Get interface list
char *get_if_list();
// Select the first device
int get_first_device(char *device);
// Get interface nonblock status
int get_if_nonblock_status(char *device_name);
// Set interface nonblock status
int set_if_nonblock_status(char *device_name, int nonblock);
// Capture and dissect packet in real time
char *handle_packet(char *device_name, char *bpf_expr, int num, int promisc,
                    int to_ms);
// Stop capture packet live、 free all memory allocated
char *stop_dissect_capture_pkg(char *device_name);

// Set up callback function for send packet to wrap layer
typedef void (*DataCallback)(const char *, int, const char *);
void GetDataCallback(char *data, int length, char *device_name);
void setDataCallback(DataCallback callback);
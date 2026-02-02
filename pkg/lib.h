#ifndef LIB_H
#define LIB_H

#include <cJSON.h>
#include <cfile.h>
#include <epan/charsets.h>
#include <epan/column.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/frame_data.h>
#include <epan/frame_data_sequence.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/print.h>
#include <epan/print_stream.h>
#include <epan/tap.h>
#include <epan/timestamp.h>
#include <epan/tvbuff.h>
#include <glib.h>
#include <pcap/bpf.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <wiretap/wtap-int.h>
#include <wiretap/wtap.h>
#include <wsutil/json_dumper.h>
#include <wsutil/nstime.h>
#include <wsutil/privileges.h>
#include <wsutil/wslog.h>

// Callback function type for returning JSON strings to Go
typedef void (*FrameCallback)(char *json, int len, int err);

// Free C string memory (wrapper for g_free)
void free_c_string(char *str);

// Initialize the Wireshark environment (policies, wiretap, epan).
// Must be called once at startup.
bool init_env();

// Helper to check if a JSON string represents an empty object
bool is_empty_json(const char *json_str);

// Apply TLS preferences (keys, desegmentation settings)
void tls_prefs_apply(const char *keysList, int desegmentSslRecords,
                     int desegmentSslApplicationData);

// Extract hex data from a dissection result
bool get_hex_data(epan_dissect_t *edt, cJSON *cjson_offset, cJSON *cjson_hex, cJSON *cjson_ascii);

// Provider callbacks required by Wireshark's epan module
const nstime_t *cap_file_provider_get_frame_ts(struct packet_provider_data *prov,
                                               uint32_t frame_num);
const char *cap_file_provider_get_interface_name(struct packet_provider_data *prov,
                                                 uint32_t interface_id, unsigned section_number);
const char *cap_file_provider_get_interface_description(struct packet_provider_data *prov,
                                                        uint32_t interface_id,
                                                        unsigned section_number);

#endif  // LIB_H
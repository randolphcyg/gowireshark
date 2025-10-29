#include <cJSON.h>
#include <cfile.h>
#include <epan/packet.h>
#include <epan/charsets.h>
#include <epan/column.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/frame_data.h>
#include <epan/frame_data_sequence.h>
#include <epan/prefs.h>
#include <epan/print.h>
#include <epan/print_stream.h>
#include <epan/tap.h>
#include <epan/timestamp.h>
#include <epan/tvbuff.h>
#include <pcap/bpf.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <wiretap/wtap-int.h>
#include <wiretap/wtap.h>
#include <wsutil/json_dumper.h>
#include <wsutil/nstime.h>
#include <wsutil/privileges.h>
#include <wsutil/wslog.h>

// Init policies、wtap mod、epan mod
bool init_env();
// Init capture file
int init_cf(char *filename, char *options);
// get_hex_data get hex part of data
bool get_hex_data(epan_dissect_t *edt, cJSON *cjson_offset, cJSON *cjson_hex,
                  cJSON *cjson_ascii);
// Dissect and print all frames
void print_all_frame();
// Dissect and get hex data of specific frame
char *get_specific_frame_hex_data(int num);
// Get proto tree in json format
char *proto_tree_in_json(int num, int printCJson);
// apply prefs
void tls_prefs_apply(const char *keysList, int desegmentSslRecords,
                     int desegmentSslApplicationData);

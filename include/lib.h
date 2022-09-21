#include <cfile.h>
#include <epan/charsets.h>
#include <epan/column.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/frame_data.h>
#include <epan/frame_data_sequence.h>
#include <epan/print.h>
#include <epan/print_stream.h>
#include <epan/tvbuff.h>
#include <include/cJSON.h>
#include <stdio.h>
#include <wiretap/wtap-int.h>
#include <wiretap/wtap.h>
#include <wsutil/json_dumper.h>
#include <wsutil/nstime.h>
#include <wsutil/privileges.h>
// global variable
extern capture_file cfile;
// init modules & init capture_file
int init(char *filename);
// Read each frame
gboolean read_packet(epan_dissect_t **edt_r);
// Dissect and print all frames
void print_all_frame();
// Dissect and print the first frame
void print_first_frame();
// Dissect and print the first several frames
void print_first_several_frame(int count);
// Dissect and print specific frame
void print_specific_frame(int num);
// transfer proto tree to json format
char *json_tree(int num);
// Dissect and print hex_data of specific frame
char *print_specific_frame_hex_data(int num);
// inner func
gboolean get_hex_data(epan_dissect_t *edt, cJSON *cjson_offset,
                      cJSON *cjson_hex, cJSON *cjson_ascii);
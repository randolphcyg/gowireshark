#include <stdio.h>
#include <cfile.h>
#include <epan/column.h>
#include <epan/epan.h>
#include <epan/tvbuff.h>
#include <epan/frame_data_sequence.h>
#include <epan/frame_data.h>
#include <epan/epan_dissect.h>
#include <epan/print.h>
#include <epan/print_stream.h>
#include <wiretap/wtap.h>
#include <wiretap/wtap-int.h>
#include <wsutil/nstime.h>
#include <wsutil/privileges.h>
// global variable
capture_file cfile;
// init modules & init capture_file
int init(char *filename);
// print the whole frame
void print_all_packet_text();
// print the first frame
void print_first_packet_text();

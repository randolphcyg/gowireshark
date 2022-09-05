#include <stdio.h>

#include <epan/tvbuff.h>
#include <epan/epan.h>
#include <cfile.h>
#include <wiretap/wtap.h>
#include <wsutil/privileges.h>
#include <wiretap/wtap-int.h>
#include <epan/column.h>
#include <wsutil/nstime.h>
#include <epan/frame_data_sequence.h>
#include <epan/frame_data.h>
#include <epan/epan_dissect.h>
#include <epan/print.h>
#include <epan/print_stream.h>

//global variable
capture_file cfile;

int init(char *filename);

void print_all_packet_text();

void print_first_packet_text();
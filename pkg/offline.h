#ifndef OFFLINE_H
#define OFFLINE_H

#include "lib.h"

// Initialize the capture file structure and open the PCAP file.
// Returns 0 on success, error code otherwise.
int init_cf(char *filename, char *options);

// Clean up capture file resources and close the file.
void close_cf();

// Count total frames in the PCAP file (Efficient I/O only scan).
int count_frames();

// Dissect a specific frame and return its JSON representation.
char *proto_tree_in_json(int num, int printCJson);

// Dissect a specific frame and return its Hex Data JSON.
char *get_specific_frame_hex_data(int num);

void get_json_proto_tree(output_fields_t *fields, print_dissections_e print_dissections,
                         gboolean print_hex, gchar **protocolfilter, pf_flags protocolfilter_flags,
                         epan_dissect_t *edt, column_info *cinfo,
                         proto_node_children_grouper_func node_children_grouper,
                         json_dumper *dumper);

// Print all frames to stdout (Mainly for debugging C logic).
void print_all_frame();

// Parse all frames in the file and trigger the callback for each.
void get_all_frames_cb(int printCJson, FrameCallback callback);

// Parse specific frames based on a sorted list of indices.
void get_frames_by_idxs_cb(int *idxs, int idx_count, int printCJson, FrameCallback callback);

// Parse a range of frames
void get_frames_by_range(int start, int limit, int printCJson, FrameCallback callback);

#endif  // OFFLINE_H
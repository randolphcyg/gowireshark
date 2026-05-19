#ifndef OFFLINE_H
#define OFFLINE_H

#include "bridge.h"

// Initialize the capture file structure and open the PCAP file.
// Returns 0 on success, error code otherwise.
int init_cf(char *filename, char *options);

// Close the capture file and release associated resources.
void close_capture_file(void);

// Reset the read position by closing and reopening the wtap handle.
// Does not touch epan, taps, or filename — safe for session reuse.
// Returns 0 on success, otherwise the wiretap error code (or -1).
int session_reset_read_position(void);

// Build a frame offset index by scanning the file once.
// Returns the total number of frames.
int build_frame_index(void);

// Return the total frame count from the index (0 if not built).
int get_frame_index_count(void);

// Free the frame offset index.
void free_frame_index(void);

// Dissect a specific frame and return its JSON representation.
char *proto_tree_in_json(int num, int printCJson);

// Dissect a specific frame and return its Hex Data JSON.
char *get_specific_frame_hex_data(int num);

void get_json_proto_tree(output_fields_t *fields, print_dissections_e print_dissections,
                         gboolean print_hex, gchar **protocolfilter, pf_flags protocolfilter_flags,
                         epan_dissect_t *edt, column_info *cinfo,
                         proto_node_children_grouper_func node_children_grouper,
                         json_dumper *dumper);

// Parse all frames in the file and trigger the callback for each.
void get_all_frames_cb(int printCJson, char *filter, FrameCallback callback);

// Parse specific frames based on a sorted list of indices.
void get_frames_by_idxs_cb(int *idxs, int idx_count, int printCJson, FrameCallback callback);

// Parse a range of frames
void get_frames_by_range(int start, int limit, int printCJson, const char *filter, FrameCallback callback);

// Validate Wireshark display filter syntax.
// Returns NULL if valid, or an error string (must be freed by caller) if invalid.
char *validate_filter(const char *filter_str);

// Count frames in the opened file. If filter_str is empty, this avoids full dissection.
int count_frames(const char *filter_str);

void get_stream_payloads_cb(const char *filter_str, const char *proto, FrameCallback callback);

// Emit Wireshark Expert Info tap records as JSON through callback.
int get_expert_infos_cb(const char *filter_str, FrameCallback callback);

#endif  // OFFLINE_H

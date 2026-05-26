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

// Like proto_tree_in_json but uses frame index for O(1) seek when available.
// Falls back to sequential scan if index is not built or seek fails.
char *proto_tree_in_json_seek(int num, int printCJson);

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

// Emit Wireshark conversation tap records as JSON through callback.
int get_tap_conversations_cb(const char *filter_str, const char *conv_type, FrameCallback callback);

// Emit Wireshark endpoint tap records as JSON through callback.
int get_tap_endpoints_cb(const char *filter_str, const char *endpoint_type, FrameCallback callback);

// Emit Wireshark export object metadata as JSON through callback.
int get_export_objects_cb(const char *filter_str, const char *protocol, FrameCallback callback);

// Emit one Wireshark export object (with payload hex) as JSON through callback.
int write_export_object_cb(const char *filter_str, const char *protocol,
                           int packet_num, FrameCallback callback);

// Emit Wireshark service response time statistics as JSON through callback.
int get_service_response_times_cb(const char *filter_str, const char *protocol, FrameCallback callback);

// Emit only the requested fields for each frame through callback.
// Each callback invocation receives a compact JSON object, e.g.
// {"frame.number":"1","ip.src":"10.0.0.1"}.
// Returns 0 on success, -1 on filter compile error.
int get_fields_rows_cb(const char **fields, int field_count, const char *filter_str, FrameCallback callback);

// Emit only the requested fields with occurrence selection.
// occurrence: 0 = first, 1 = last, 2 = all.
// For all occurrences, JSON is {"_frame": N, "_values": {"field":["val1","val2",...]}}.
// Returns 0 on success, -1 on filter compile error.
int get_fields_rows_occurrence_cb(const char **fields, int field_count, const char *filter_str, int occurrence, FrameCallback callback);

char *get_expert_infos_json(const char *filter_str);

char *get_stream_payloads_json(const char *filter_str, const char *proto);

// Write selected frames to a pcap/pcapng file using native wiretap.
// Preserves all metadata: IDBs, NRBs, packet comments, timestamps.
// output_format: "pcap", "pcapng", or NULL/"" for same-as-input.
// Returns 0 on success, >0 for wiretap error, -1 for other error, -2 for no frames.
int write_pcap_slice_native(const char *input_path, const char *output_path,
                            const int *indices, int idx_count,
                            const char *output_format);

// Collect frame numbers matching a display filter. No JSON is generated.
// Returns count of matching frames, -1 if filter compile fails.
// *numbers_out is allocated with g_malloc; caller must g_free.
int get_frame_numbers_filtered(const char *filter_str, int **numbers_out);

// Extract timeline fields into a compact JSON array string.
// Fields: t=frame.time_epoch, l=frame.len, s=ip.src, d=ip.dst,
//         ts=tcp.stream, us=udp.stream, p=frame.protocols
// Returns g_malloc'd string; caller must g_free. NULL on error.
char *get_timeline_json(const char *filter_str);

int get_proto_hierarchy_cb(const char *filter_str, FrameCallback callback);

int get_io_stats_cb(const char *filter_str, double interval, FrameCallback callback);

#endif  // OFFLINE_H

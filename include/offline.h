// proto tree result
extern cJSON *proto_tree_res;
// json layers member
extern cJSON *layers;

// get_hex_data get hex part of data
gboolean get_hex_data(epan_dissect_t *edt, cJSON *cjson_offset,
                      cJSON *cjson_hex, cJSON *cjson_ascii);

// get_proto_tree_dissect_res_in_json get proto tree dissect result and transfer
// it to json format (include hex data)
cJSON *get_proto_tree_dissect_res_in_json(
    output_fields_t *fields, print_dissections_e print_dissections,
    gboolean print_hex, gchar **protocolfilter, pf_flags protocolfilter_flags,
    epan_dissect_t *edt, column_info *cinfo,
    proto_node_children_grouper_func node_children_grouper);

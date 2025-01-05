
void get_json_proto_tree(output_fields_t *fields,
                         print_dissections_e print_dissections,
                         gboolean print_hex, gchar **protocolfilter,
                         pf_flags protocolfilter_flags, epan_dissect_t *edt,
                         column_info *cinfo,
                         proto_node_children_grouper_func node_children_grouper,
                         json_dumper *dumper);
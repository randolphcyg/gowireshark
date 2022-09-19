#include <include/cJSON.h>

// json result
extern cJSON *root;
extern char *out;
// json对象layers层
extern cJSON* cjson_layers;

gboolean proto_tree_print_hex(print_dissections_e print_dissections,
                              gboolean print_hex, epan_dissect_t *edt,
                              GHashTable *output_only_tables,
                              print_stream_t *stream);

char* proto_tree_to_json(output_fields_t *fields,
                        print_dissections_e print_dissections,
                        gboolean print_hex, gchar **protocolfilter,
                        pf_flags protocolfilter_flags, epan_dissect_t *edt,
                        column_info *cinfo,
                        proto_node_children_grouper_func node_children_grouper);

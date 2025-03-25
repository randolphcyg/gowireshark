#include <lib.h>

typedef struct {
  GSList *src_list;
  gchar **filter;
  pf_flags filter_flags;
  gboolean print_hex;
  gboolean print_text;
  proto_node_children_grouper_func node_children_grouper;
  json_dumper *dumper;
} write_json_data;

typedef void (*proto_node_value_writer)(proto_node *, write_json_data *);
static void write_json_index(json_dumper *dumper, epan_dissect_t *edt);
static void write_json_proto_node_list(GSList *proto_node_list_head,
                                       write_json_data *pdata);
static void write_json_proto_node(GSList *node_values_head, const char *suffix,
                                  proto_node_value_writer value_writer,
                                  write_json_data *data);
static void
write_json_proto_node_value_list(GSList *node_values_head,
                                 proto_node_value_writer value_writer,
                                 write_json_data *data);
static void write_json_proto_node_children(proto_node *node,
                                           write_json_data *data);
static void write_json_proto_node_value(proto_node *node,
                                        write_json_data *data);
static void write_json_proto_node_no_value(proto_node *node,
                                           write_json_data *pdata);
static const char *proto_node_to_json_key(proto_node *node);

static void write_json_index(json_dumper *dumper, epan_dissect_t *edt) {
  char ts[30];
  struct tm *timeinfo;
  char *str;

  timeinfo = localtime(&edt->pi.abs_ts.secs);
  if (timeinfo != NULL) {
    strftime(ts, sizeof(ts), "%Y-%m-%d", timeinfo);
  } else {
    (void)g_strlcpy(
        ts, "XXXX-XX-XX",
        sizeof(ts)); /* XXX - better way of saying "Not representable"? */
  }
  json_dumper_set_member_name(dumper, "_index");
  str = ws_strdup_printf("packets-%s", ts);
  json_dumper_value_string(dumper, str);
  g_free(str);
}

/**
 * Returns the json key of a node. Tries to use the node's abbreviated name.
 * If the abbreviated name is not available the representation is used instead.
 *
 * XXX: The representation can have spaces or differ depending on the content,
 * which makes it difficult to match text-only fields with a -j/-J filter in
 * tshark. (Issue #17125).
 */
static const char *proto_node_to_json_key(proto_node *node) {
  const char *json_key;
  // Check if node has abbreviated name.
  if (node->finfo->hfinfo->id != hf_text_only) {
    json_key = node->finfo->hfinfo->abbrev;
  } else if (node->finfo->rep != NULL) {
    json_key = node->finfo->rep->representation;
  } else {
    json_key = "";
  }

  return json_key;
}

/**
 * Returns a boolean telling us whether that node list contains any node which
 * has children
 */
static bool any_has_children(GSList *node_values_list) {
  GSList *current_node = node_values_list;
  while (current_node != NULL) {
    proto_node *current_value = (proto_node *)current_node->data;
    if (current_value->first_child != NULL) {
      return true;
    }
    current_node = current_node->next;
  }
  return false;
}

/**
 * Writes the value of a node to the output.
 */
static void write_json_proto_node_value(proto_node *node,
                                        write_json_data *pdata) {
  field_info *fi = node->finfo;
  // Get the actual value of the node as a string.
  char *value_string_repr =
      fvalue_to_string_repr(NULL, fi->value, FTREPR_JSON, fi->hfinfo->display);

  // TODO: Have FTREPR_JSON include quotes where appropriate and use
  // json_dumper_value_anyf() here,
  //  so we can output booleans and numbers and not only strings.
  json_dumper_value_string(pdata->dumper, value_string_repr);

  wmem_free(NULL, value_string_repr);
}

/**
 * Write the value for a node that has no value and no children. This is the
 * empty string for all nodes except those of type FT_PROTOCOL for which the
 * full name is written instead.
 */
static void write_json_proto_node_no_value(proto_node *node,
                                           write_json_data *pdata) {
  field_info *fi = node->finfo;

  if (fi->hfinfo->type == FT_PROTOCOL) {
    if (fi->rep) {
      json_dumper_value_string(pdata->dumper, fi->rep->representation);
    } else {
      char label_str[ITEM_LABEL_LENGTH];
      proto_item_fill_label(fi, label_str);
      json_dumper_value_string(pdata->dumper, label_str);
    }
  } else {
    json_dumper_value_string(pdata->dumper, "");
  }
}

static void write_json_proto_node_dynamic(proto_node *node,
                                          write_json_data *data) {
  if (node->first_child == NULL) {
    write_json_proto_node_no_value(node, data);
  } else {
    write_json_proto_node_children(node, data);
  }
}

/**
 * Writes a single node as a key:value pair. The value_writer param can be used
 * to specify how the node's value should be written.
 * @param node_values_head Linked list containing all nodes associated with the
 * same json key in this object.
 * @param suffix Suffix that should be added to the json key.
 * @param value_writer A function which writes the actual values of the node
 * json key.
 * @param pdata json writing metadata
 */
static void write_json_proto_node(GSList *node_values_head, const char *suffix,
                                  proto_node_value_writer value_writer,
                                  write_json_data *pdata) {
  // Retrieve json key from first value.
  proto_node *first_value = (proto_node *)node_values_head->data;
  const char *json_key = proto_node_to_json_key(first_value);
  char *json_key_suffix = ws_strdup_printf("%s%s", json_key, suffix);
  json_dumper_set_member_name(pdata->dumper, json_key_suffix);
  g_free(json_key_suffix);
  write_json_proto_node_value_list(node_values_head, value_writer, pdata);
}

/**
 * Writes a list of values of a single json key. If multiple values are passed
 * they are wrapped in a json array.
 * @param node_values_head Linked list containing all values that should be
 * written.
 * @param value_writer Function which writes the separate values.
 * @param pdata json writing metadata
 */
static void
write_json_proto_node_value_list(GSList *node_values_head,
                                 proto_node_value_writer value_writer,
                                 write_json_data *pdata) {
  GSList *current_value = node_values_head;

  // Write directly if only a single value is passed. Wrap in json array
  // otherwise.
  if (current_value->next == NULL) {
    value_writer((proto_node *)current_value->data, pdata);
  } else {
    json_dumper_begin_array(pdata->dumper);

    while (current_value != NULL) {
      value_writer((proto_node *)current_value->data, pdata);
      current_value = current_value->next;
    }
    json_dumper_end_array(pdata->dumper);
  }
}

/**
 * Write a json object containing a list of key:value pairs where each key:value
 * pair corresponds to a different json key and its associated nodes in the
 * proto_tree.
 * @param proto_node_list_head A 2-dimensional list containing a list of values
 * for each different node json key. The elements themselves are a linked list
 * of values associated with the same json key.
 * @param pdata json writing metadata
 */
static void write_json_proto_node_list(GSList *proto_node_list_head,
                                       write_json_data *pdata) {
  json_dumper_begin_object(pdata->dumper);

  // 创建哈希表
  GHashTable *key_nodes =
      g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);

  // 第一次遍历：将相同key的节点分组
  GSList *current_node = proto_node_list_head;
  while (current_node != NULL) {
    GSList *node_values_list = (GSList *)current_node->data;
    proto_node *first_value = (proto_node *)node_values_list->data;
    const char *json_key = proto_node_to_json_key(first_value);

    GSList *existing_list = g_hash_table_lookup(key_nodes, json_key);
    if (existing_list == NULL) {
      g_hash_table_insert(key_nodes, (gpointer)json_key, node_values_list);
    } else {
      // 合并具有相同key的节点列表
      GSList *combined_list = g_slist_concat(g_slist_copy(existing_list),
                                             g_slist_copy(node_values_list));
      g_hash_table_replace(key_nodes, (gpointer)json_key, combined_list);
    }

    current_node = current_node->next;
  }

  // 第二次遍历：输出合并后的节点
  GHashTableIter iter;
  gpointer key, value;
  g_hash_table_iter_init(&iter, key_nodes);
  while (g_hash_table_iter_next(&iter, &key, &value)) {
    GSList *node_values_list = (GSList *)value;
    proto_node *first_value = (proto_node *)node_values_list->data;

    field_info *fi = first_value->finfo;
    char *value_string_repr = fvalue_to_string_repr(
        NULL, fi->value, FTREPR_JSON, fi->hfinfo->display);
    bool has_children = any_has_children(node_values_list);

    // descriptive values
    gchar label_str[ITEM_LABEL_LENGTH];
    gchar *label_ptr;
    if (!fi->rep) {
      label_ptr = label_str;
      proto_item_fill_label(fi, label_str);
      char *value_ptr = strstr(label_ptr, ": ");
      if (value_ptr != NULL) {
        value_string_repr = value_ptr + 2;
      }
    }

    gboolean has_value = value_string_repr != NULL;

    if (has_value) {
      write_json_proto_node(node_values_list, "", write_json_proto_node_value,
                            pdata);
    }

    if (has_children) {
      char *suffix = has_value ? "_tree" : "";
      write_json_proto_node(node_values_list, suffix,
                            write_json_proto_node_dynamic, pdata);
    }

    if (!has_value && !has_children) {
      write_json_proto_node(node_values_list, "",
                            write_json_proto_node_no_value, pdata);
    }
  }

  // 清理工作移到这里
  g_hash_table_destroy(key_nodes);

  json_dumper_end_object(pdata->dumper);
}

/**
 * Writes the children of a node. Calls get_json_proto_tree internally
 * which recursively writes children of nodes to the output.
 */
static void write_json_proto_node_children(proto_node *node,
                                           write_json_data *data) {
  GSList *grouped_children_list = data->node_children_grouper(node);
  write_json_proto_node_list(grouped_children_list, data);
  g_slist_free_full(grouped_children_list, (GDestroyNotify)g_slist_free);
}

/**
 * Get protocol tree dissect result in json format.
 */
void get_json_proto_tree(output_fields_t *fields,
                         print_dissections_e print_dissections,
                         gboolean print_hex, gchar **protocolfilter,
                         pf_flags protocolfilter_flags, epan_dissect_t *edt,
                         column_info *cinfo,
                         proto_node_children_grouper_func node_children_grouper,
                         json_dumper *dumper) {
  write_json_data data;
  data.dumper = dumper;

  json_dumper_begin_object(dumper);
  write_json_index(dumper, edt);

  json_dumper_set_member_name(dumper, "layers");

  data.src_list = edt->pi.data_src;
  data.print_hex = print_hex;
  data.print_text = TRUE;
  data.node_children_grouper = node_children_grouper;
  write_json_proto_node_children(edt->tree, &data);

  json_dumper_end_object(dumper);
}
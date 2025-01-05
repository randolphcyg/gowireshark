#include <lib.h>
#include <wsutil/json_dumper.h>

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
static void write_json_proto_node_children(proto_node *node,
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
  GSList *current_node = proto_node_list_head;
  GHashTable *key_table = g_hash_table_new(g_str_hash, g_str_equal);

  while (current_node != NULL) {
    GSList *node_values_list = (GSList *)current_node->data;
    proto_node *first_value = (proto_node *)node_values_list->data;
    const char *json_key = proto_node_to_json_key(first_value);

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
        value_string_repr = (char *)value_ptr + 2;
      }
    }

    gboolean has_value = value_string_repr != NULL;

    GSList *existing_values = g_hash_table_lookup(key_table, json_key);
    if (existing_values == NULL) {
      existing_values = g_slist_append(NULL, node_values_list);
      g_hash_table_insert(key_table, g_strdup(json_key), existing_values);
    } else {
      existing_values = g_slist_append(existing_values, node_values_list);
      g_hash_table_replace(key_table, g_strdup(json_key), existing_values);
    }

    // next pointer
    current_node = current_node->next;
  }

  // Iterate over the hash table to write the JSON
  GHashTableIter iter;
  gpointer key, value;
  g_hash_table_iter_init(&iter, key_table);
  while (g_hash_table_iter_next(&iter, &key, &value)) {
    const char *json_key = (const char *)key;
    GSList *node_values_list = (GSList *)value;

    if (g_slist_length(node_values_list) > 1) {
      json_dumper_set_member_name(pdata->dumper, json_key);
      json_dumper_begin_array(pdata->dumper);

      GSList *current_value = node_values_list;
      while (current_value != NULL) {
        GSList *values = (GSList *)current_value->data;
        proto_node *first_value = (proto_node *)values->data;

        field_info *fi = first_value->finfo;
        char *value_string_repr = fvalue_to_string_repr(
            NULL, fi->value, FTREPR_JSON, fi->hfinfo->display);

        gboolean has_children = any_has_children(values);

        if (value_string_repr != NULL) {
          json_dumper_value_string(pdata->dumper, value_string_repr);
        }

        if (has_children) {
          json_dumper_begin_object(pdata->dumper);

          if (first_value->first_child == NULL) {
            write_json_proto_node_no_value(first_value, pdata);
          } else {
            write_json_proto_node_children(first_value, pdata);
          }

          json_dumper_end_object(pdata->dumper);
        }

        current_value = current_value->next;
      }

      json_dumper_end_array(pdata->dumper);
    } else {
      GSList *values = (GSList *)node_values_list->data;
      proto_node *first_value = (proto_node *)values->data;

      field_info *fi = first_value->finfo;
      char *value_string_repr = fvalue_to_string_repr(
          NULL, fi->value, FTREPR_JSON, fi->hfinfo->display);

      gboolean has_children = any_has_children(values);

      if (value_string_repr != NULL) {
        json_dumper_set_member_name(pdata->dumper, json_key);
        json_dumper_value_string(pdata->dumper, value_string_repr);
      }

      if (has_children) {
        char *suffix = value_string_repr != NULL ? "_tree" : "";
        gchar *json_key_s = g_strdup_printf("%s%s", json_key, suffix);

        json_dumper_set_member_name(pdata->dumper, json_key_s);
        json_dumper_begin_object(pdata->dumper);

        if (first_value->first_child == NULL) {
          write_json_proto_node_no_value(first_value, pdata);
        } else {
          write_json_proto_node_children(first_value, pdata);
        }

        json_dumper_end_object(pdata->dumper);
        g_free(json_key_s);
      }
    }
  }

  g_hash_table_destroy(key_table);
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
  json_dumper_begin_object(dumper);

  data.src_list = edt->pi.data_src;
  data.print_hex = print_hex;
  data.print_text = TRUE;
  data.node_children_grouper = node_children_grouper;
  write_json_proto_node_children(edt->tree, &data);

  json_dumper_end_object(dumper);
  json_dumper_end_object(dumper);
}
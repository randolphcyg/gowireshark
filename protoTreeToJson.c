#include <include/cJSON.h>
#include <include/lib.h>
#include <include/protoTreeToJson.h>

typedef struct {
  int level;
  print_stream_t *stream;
  gboolean success;
  GSList *src_list;
  print_dissections_e print_dissections;
  gboolean print_hex_for_data;
  packet_char_enc encoding;
  GHashTable *output_only_tables; /* output only these protocols */
} print_data;

typedef struct {
  int level;
  FILE *fh;
  GSList *src_list;
  gchar **filter;
  pf_flags filter_flags;
} write_pdml_data;

typedef struct {
  GSList *src_list;
  gchar **filter;
  pf_flags filter_flags;
  gboolean print_hex;
  gboolean print_text;
  proto_node_children_grouper_func node_children_grouper;
  json_dumper *dumper;
} write_json_data;

typedef struct {
  output_fields_t *fields;
  epan_dissect_t *edt;
} write_field_data_t;

struct _output_fields {
  gboolean print_bom;
  gboolean print_header;
  gchar separator;
  gchar occurrence;
  gchar aggregator;
  GPtrArray *fields;
  GHashTable *field_indicies;
  GPtrArray **field_values;
  gchar quote;
  gboolean includes_col_fields;
};

/*
 * print hex format data
 */

#define MAX_OFFSET_LEN 8  /* max length of hex offset of bytes */
#define BYTES_PER_LINE 16 /* max byte values printed on a line */
#define HEX_DUMP_LEN (BYTES_PER_LINE * 3)
/* max number of characters hex dump takes -
   2 digits plus trailing blank */
#define DATA_DUMP_LEN (HEX_DUMP_LEN + 2 + BYTES_PER_LINE)
/* number of characters those bytes take;
   3 characters per byte of hex dump,
   2 blanks separating hex from ASCII,
   1 character per byte of ASCII dump */
#define MAX_LINE_LEN (MAX_OFFSET_LEN + 2 + DATA_DUMP_LEN)
/* number of characters per line;
   offset, 2 blanks separating offset
   from data dump, data dump */

static gboolean modify_print_hex_data_buffer(const guchar *cp, guint length,
                                             cJSON *cjson_offset,
                                             cJSON *cjson_hex,
                                             cJSON *cjson_ascii) {

  register unsigned int ad, i, j, k, l;
  guchar c;
  gchar line[MAX_LINE_LEN + 1];
  gchar line_offset[MAX_LINE_LEN + 1];
  unsigned int use_digits;

  static gchar binhex[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                             '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

  /*
   * How many of the leading digits of the offset will we supply?
   * We always supply at least 4 digits, but if the maximum offset
   * won't fit in 4 digits, we use as many digits as will be needed.
   */
  if (((length - 1) & 0xF0000000) != 0)
    use_digits = 8; /* need all 8 digits */
  else if (((length - 1) & 0x0F000000) != 0)
    use_digits = 7; /* need 7 digits */
  else if (((length - 1) & 0x00F00000) != 0)
    use_digits = 6; /* need 6 digits */
  else if (((length - 1) & 0x000F0000) != 0)
    use_digits = 5; /* need 5 digits */
  else
    use_digits = 4; /* we'll supply 4 digits */

  ad = 0;
  i = 0;
  j = 0;
  k = 0;
  while (i < length) {
    if ((i & 15) == 0) {
      /*
       * Start of a new line.
       */
      j = 0;
      l = use_digits;
      do {
        l--;
        c = (ad >> (l * 4)) & 0xF;
        line[j] = binhex[c];
        // offset data
        line_offset[j] = binhex[c];
        line_offset[j + 1] = '\0';
        j++;
      } while (l != 0);
      // add offset to json obj
      cJSON_AddItemToArray(cjson_offset, cJSON_CreateString(line_offset));
      line[j++] = ' ';
      line[j++] = ' ';
      memset(line + j, ' ', DATA_DUMP_LEN);

      /*
       * Offset in line of ASCII dump.
       */
      k = j + HEX_DUMP_LEN + 2;
    }
    c = *cp++;
    line[j++] = binhex[c >> 4];
    line[j++] = binhex[c & 0xf];
    j++;

    line[k++] = ((c >= ' ') && (c < 0x7f)) ? c : '.';
    i++;
    if (((i & 15) == 0) || (i == length)) {
      /*
       * We'll be starting a new line, or
       * we're finished printing this buffer;
       * dump out the line we've constructed,
       * and advance the offset.
       */
      line[k] = '\0';

      // hex data
      char line_hex[48];
      strncpy(line_hex, line + use_digits + 2, 48);
      line_hex[47] = '\0';
      // add hex to json obj
      cJSON_AddItemToArray(cjson_hex, cJSON_CreateString(line_hex));

      // ascii str data
      char line_ascii[17];
      strncpy(line_ascii, line + use_digits + 52, 17);
      line_ascii[16] = '\0';
      // add ascii to json obj
      cJSON_AddItemToArray(cjson_ascii, cJSON_CreateString(line_ascii));

      ad += 16;
    }
  }
  return TRUE;
}

// get_hex_data get hex part of data
gboolean get_hex_data(epan_dissect_t *edt, cJSON *cjson_offset,
                      cJSON *cjson_hex, cJSON *cjson_ascii) {
  gboolean multiple_sources;
  GSList *src_le;
  tvbuff_t *tvb;
  char *line, *name;
  const guchar *cp;
  guint length;
  struct data_source *src;

  /*
   * Set "multiple_sources" iff this frame has more than one
   * data source; if it does, we need to print the name of
   * the data source before printing the data from the
   * data source.
   */
  multiple_sources = (edt->pi.data_src->next != NULL);

  for (src_le = edt->pi.data_src; src_le != NULL; src_le = src_le->next) {
    src = (struct data_source *)src_le->data;
    tvb = get_data_source_tvb(src);
    if (multiple_sources) {
      name = get_data_source_name(src);
      line = g_strdup_printf("%s:", name);
      wmem_free(NULL, name);
      g_free(line);
    }
    length = tvb_captured_length(tvb);
    if (length == 0)
      return TRUE;
    cp = tvb_get_ptr(tvb, 0, length);
    if (!modify_print_hex_data_buffer(cp, length, cjson_offset, cjson_hex,
                                      cjson_ascii))
      return FALSE;
  }
  return TRUE;
}

/* Cache the protocols and field handles that the print functionality needs
   This helps break explicit dependency on the dissectors. */
static int proto_data = -1;
static int proto_frame = -1;

void print_cache_field_handles(void) {
  proto_data = proto_get_id_by_short_name("Data");
  proto_frame = proto_get_id_by_short_name("Frame");
}

/*
 * Find the data source for a specified field, and return a pointer
 * to the data in it. Returns NULL if the data is out of bounds.
 */
/* XXX: What am I missing ?
 *      Why bother searching for fi->ds_tvb for the matching tvb
 *       in the data_source list ?
 *      IOW: Why not just use fi->ds_tvb for the arg to tvb_get_ptr() ?
 */

static const guint8 *get_field_data(GSList *src_list, field_info *fi) {
  GSList *src_le;
  tvbuff_t *src_tvb;
  gint length, tvbuff_length;
  struct data_source *src;

  for (src_le = src_list; src_le != NULL; src_le = src_le->next) {
    src = (struct data_source *)src_le->data;
    src_tvb = get_data_source_tvb(src);
    if (fi->ds_tvb == src_tvb) {
      /*
       * Found it.
       *
       * XXX - a field can have a length that runs past
       * the end of the tvbuff.  Ideally, that should
       * be fixed when adding an item to the protocol
       * tree, but checking the length when doing
       * that could be expensive.  Until we fix that,
       * we'll do the check here.
       */
      tvbuff_length = tvb_captured_length_remaining(src_tvb, fi->start);
      if (tvbuff_length < 0) {
        return NULL;
      }
      length = fi->length;
      if (length > tvbuff_length)
        length = tvbuff_length;
      return tvb_get_ptr(src_tvb, fi->start, length);
    }
  }
  return NULL; /* not found */
}

/*
 *
 * json
 */

// json result
cJSON *root = NULL;
char *out = NULL;
// json obj layers
cJSON *cjson_layers = NULL;

typedef void (*proto_node_value_writer)(proto_node *, write_json_data *);

static void write_json_proto_node_list(GSList *proto_node_list_head,
                                       write_json_data *data,
                                       cJSON *obj_current_node);
static void
write_json_proto_node_value_list(GSList *node_values_head,
                                 proto_node_value_writer value_writer,
                                 write_json_data *data);
static void write_json_proto_node_children(proto_node *node,
                                           write_json_data *data,
                                           cJSON *obj_current_node);
static void write_json_proto_node_no_value(proto_node *node,
                                           write_json_data *data,
                                           cJSON *obj_current_node);

#define COLUMN_FIELD_FILTER "_ws.col."

/**
 * Returns the json key of a node. Tries to use the node's abbreviated name. If
 * the abbreviated name is not available the representation is used instead.
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
static gboolean any_has_children(GSList *node_values_list) {
  GSList *current_node = node_values_list;
  while (current_node != NULL) {
    proto_node *current_value = (proto_node *)current_node->data;
    if (current_value->first_child != NULL) {
      return TRUE;
    }
    current_node = current_node->next;
  }
  return FALSE;
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

typedef void (*FvalueNewFunc)(fvalue_t *);
typedef void (*FvalueFreeFunc)(fvalue_t *);

typedef gboolean (*FvalueFromUnparsed)(fvalue_t *, const char *, gboolean,
                                       gchar **);
typedef gboolean (*FvalueFromString)(fvalue_t *, const char *, gchar **);
typedef void (*FvalueToStringRepr)(fvalue_t *, ftrepr_t, int field_display,
                                   char *volatile, unsigned int);
typedef int (*FvalueStringReprLen)(fvalue_t *, ftrepr_t, int field_display);

typedef void (*FvalueSetByteArrayFunc)(fvalue_t *, GByteArray *);
typedef void (*FvalueSetBytesFunc)(fvalue_t *, const guint8 *);
typedef void (*FvalueSetGuidFunc)(fvalue_t *, const e_guid_t *);
typedef void (*FvalueSetTimeFunc)(fvalue_t *, const nstime_t *);
typedef void (*FvalueSetStringFunc)(fvalue_t *, const gchar *value);
typedef void (*FvalueSetProtocolFunc)(fvalue_t *, tvbuff_t *value,
                                      const gchar *name);
typedef void (*FvalueSetUnsignedIntegerFunc)(fvalue_t *, guint32);
typedef void (*FvalueSetSignedIntegerFunc)(fvalue_t *, gint32);
typedef void (*FvalueSetUnsignedInteger64Func)(fvalue_t *, guint64);
typedef void (*FvalueSetSignedInteger64Func)(fvalue_t *, gint64);
typedef void (*FvalueSetFloatingFunc)(fvalue_t *, gdouble);

typedef gpointer (*FvalueGetFunc)(fvalue_t *);
typedef guint32 (*FvalueGetUnsignedIntegerFunc)(fvalue_t *);
typedef gint32 (*FvalueGetSignedIntegerFunc)(fvalue_t *);
typedef guint64 (*FvalueGetUnsignedInteger64Func)(fvalue_t *);
typedef gint64 (*FvalueGetSignedInteger64Func)(fvalue_t *);
typedef double (*FvalueGetFloatingFunc)(fvalue_t *);

typedef gboolean (*FvalueCmp)(const fvalue_t *, const fvalue_t *);
typedef gboolean (*FvalueMatches)(const fvalue_t *, const GRegex *);

typedef guint (*FvalueLen)(fvalue_t *);
typedef void (*FvalueSlice)(fvalue_t *, GByteArray *, guint offset,
                            guint length);

struct _ftype_t {
  ftenum_t ftype;
  const char *name;
  const char *pretty_name;
  int wire_size;
  FvalueNewFunc new_value;
  FvalueFreeFunc free_value;
  FvalueFromUnparsed val_from_unparsed;
  FvalueFromString val_from_string;
  FvalueToStringRepr val_to_string_repr;
  FvalueStringReprLen len_string_repr;

  union {
    FvalueSetByteArrayFunc set_value_byte_array;
    FvalueSetBytesFunc set_value_bytes;
    FvalueSetGuidFunc set_value_guid;
    FvalueSetTimeFunc set_value_time;
    FvalueSetStringFunc set_value_string;
    FvalueSetProtocolFunc set_value_protocol;
    FvalueSetUnsignedIntegerFunc set_value_uinteger;
    FvalueSetSignedIntegerFunc set_value_sinteger;
    FvalueSetUnsignedInteger64Func set_value_uinteger64;
    FvalueSetSignedInteger64Func set_value_sinteger64;
    FvalueSetFloatingFunc set_value_floating;
  } set_value;

  union {
    FvalueGetFunc get_value_ptr;
    FvalueGetUnsignedIntegerFunc get_value_uinteger;
    FvalueGetSignedIntegerFunc get_value_sinteger;
    FvalueGetUnsignedInteger64Func get_value_uinteger64;
    FvalueGetSignedInteger64Func get_value_sinteger64;
    FvalueGetFloatingFunc get_value_floating;
  } get_value;

  FvalueCmp cmp_eq;
  FvalueCmp cmp_ne;
  FvalueCmp cmp_gt;
  FvalueCmp cmp_ge;
  FvalueCmp cmp_lt;
  FvalueCmp cmp_le;
  FvalueCmp cmp_bitwise_and;
  FvalueCmp cmp_contains;
  FvalueMatches cmp_matches;

  FvalueLen len;
  FvalueSlice slice;
};

typedef struct _ftype_t ftype_t;

/**
 * Write the value for a node that has no value and no children. This is the
 * empty string for all nodes except those of type FT_PROTOCOL for which the
 * full name is written instead.
 */
static void write_json_proto_node_no_value(proto_node *node,
                                           write_json_data *pdata,
                                           cJSON *obj_current_node) {
  field_info *fi = node->finfo;

  const char *json_key = proto_node_to_json_key(node);

  if (fi->hfinfo->type == FT_PROTOCOL) {
    if (fi->rep) {
      cJSON_AddStringToObject(obj_current_node, json_key,
                              fi->rep->representation);
    } else {
      gchar label_str[ITEM_LABEL_LENGTH];
      proto_item_fill_label(fi, label_str);
      cJSON_AddStringToObject(obj_current_node, json_key, label_str);
    }
  } else {
    cJSON_AddStringToObject(obj_current_node, json_key, "");
  }
}

/*
 * A recursive call that keeps parsing the logic of child nodes
 */
static void write_json_proto_node_list(GSList *proto_node_list_head,
                                       write_json_data *pdata,
                                       cJSON *obj_current_node) {
  GSList *current_node = proto_node_list_head;

  while (current_node != NULL) {
    // Get the list of values for the current json key.
    GSList *node_values_list = (GSList *)current_node->data;

    // Retrieve the json key from the first value.
    proto_node *first_value = (proto_node *)node_values_list->data;
    const char *json_key = proto_node_to_json_key(first_value);

    field_info *fi = first_value->finfo;
    char *value_string_repr = fvalue_to_string_repr(
        NULL, &fi->value, FTREPR_DISPLAY, fi->hfinfo->display);

    // has child node ?
    gboolean has_children = any_has_children(node_values_list);

    // has value ?
    gboolean has_value = value_string_repr != NULL;

    // if has value, just insert
    if (pdata->print_text && has_value) {
      cJSON_AddStringToObject(obj_current_node, json_key, value_string_repr);
    }

    // has chil node ?
    if (has_children) {
      // create json obj member
      cJSON *cjson_tmp_child = NULL;
      cjson_tmp_child = cJSON_CreateObject();

      // If a node has both a value and a set of children we print the value and
      // the children in separate key:value pairs. These can't have the same key
      // so whenever a value is already printed with the node json key we print
      // the children with the same key with a "_tree" suffix added.
      char *suffix = has_value ? "_tree" : "";

      gchar *json_key_s = g_strdup_printf("%s%s", json_key, suffix);

      cJSON_AddItemToObject(obj_current_node, json_key_s, cjson_tmp_child);

      // has_children is TRUE if any of the nodes have children. so dynamic
      // judge it.
      if (first_value->first_child == NULL) {
        write_json_proto_node_no_value(first_value, pdata, cjson_tmp_child);
      } else {
        write_json_proto_node_children(first_value, pdata, cjson_tmp_child);
      }
    }

    // next pointer
    current_node = current_node->next;
  }
}

/**
 * Writes the children of a node. Calls write_json_proto_node_list internally
 * which recursively writes children of nodes to the output.
 */
static void write_json_proto_node_children(proto_node *node,
                                           write_json_data *data,
                                           cJSON *obj_current_node) {
  GSList *grouped_children_list = data->node_children_grouper(node);
  write_json_proto_node_list(grouped_children_list, data, obj_current_node);
  g_slist_free_full(grouped_children_list, (GDestroyNotify)g_slist_free);
}

static void write_json_index(epan_dissect_t *edt) {
  char ts[30];
  struct tm *timeinfo;
  gchar *str;

  timeinfo = localtime(&edt->pi.abs_ts.secs);
  if (timeinfo != NULL) {
    strftime(ts, sizeof(ts), "%Y-%m-%d", timeinfo);
  } else {
    (void)g_strlcpy(ts, "XXXX-XX-XX", sizeof(ts));
  }

  str = g_strdup_printf("packets-%s", ts);

  cJSON_AddStringToObject(root, "_index", str);
  g_free(str);
}

char *
proto_tree_to_json(output_fields_t *fields,
                   print_dissections_e print_dissections, gboolean print_hex,
                   gchar **protocolfilter, pf_flags protocolfilter_flags,
                   epan_dissect_t *edt, column_info *cinfo,
                   proto_node_children_grouper_func node_children_grouper) {
  write_json_data data;

  // json root node
  root = cJSON_CreateObject();
  // set json obj common value
  write_json_index(edt);
  cJSON_AddStringToObject(root, "_type", "doc");
  cJSON *cjson_score = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "_score", cjson_score);

  cJSON *cjson_offset = cJSON_CreateArray();
  cJSON *cjson_hex = cJSON_CreateArray();
  cJSON *cjson_ascii = cJSON_CreateArray();
  // process get hex data
  get_hex_data(edt, cjson_offset, cjson_hex, cjson_ascii);

  cJSON_AddItemToObject(root, "offset", cjson_offset);
  cJSON_AddItemToObject(root, "hex", cjson_hex);
  cJSON_AddItemToObject(root, "ascii", cjson_ascii);

  cJSON *cjson_source = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "_source", cjson_source);

  // add layers node
  cjson_layers = cJSON_CreateObject();
  cJSON_AddItemToObject(cjson_source, "layers", cjson_layers);

  if (fields == NULL || fields->fields == NULL) {
    /* Write out all fields */
    data.src_list = edt->pi.data_src;
    data.filter = protocolfilter;
    data.filter_flags = protocolfilter_flags;
    data.print_hex = print_hex;
    data.print_text = TRUE;
    if (print_dissections == print_dissections_none) {
      data.print_text = FALSE;
    }
    data.node_children_grouper = node_children_grouper;
    // core logic
    write_json_proto_node_children(edt->tree, &data, cjson_layers);
  }

  return cJSON_PrintUnformatted(root);
}
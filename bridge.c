#include "bridge.h"
#include <inttypes.h>
#include <string.h>
#include <dirent.h>
#include <epan/expert.h>
#include <epan/decode_as.h>
#include <epan/prefs-int.h>
#include <wsutil/version_info.h>

void free_c_string(char *str) {
    if (str) {
        g_free(str);
    }
}

static void json_add_string(cJSON *obj, const char *key, const char *value) {
    cJSON_AddStringToObject(obj, key, value ? value : "");
}

static cJSON *protocol_info_to_json(int proto_id) {
    protocol_t *protocol = find_protocol_by_id(proto_id);
    cJSON *obj = cJSON_CreateObject();

    cJSON_AddNumberToObject(obj, "id", proto_id);
    json_add_string(obj, "name", proto_get_protocol_name(proto_id));
    json_add_string(obj, "shortName", protocol ? proto_get_protocol_short_name(protocol) : NULL);
    json_add_string(obj, "longName", protocol ? proto_get_protocol_long_name(protocol) : NULL);
    json_add_string(obj, "filterName", proto_get_protocol_filter_name(proto_id));
    cJSON_AddBoolToObject(obj, "enabled", protocol ? proto_is_protocol_enabled(protocol) : FALSE);

    return obj;
}

static cJSON *field_info_to_json(header_field_info *hfinfo) {
    cJSON *obj = cJSON_CreateObject();
    header_field_info *parent_hfinfo = NULL;

    if (hfinfo == NULL) {
        return obj;
    }
    if (hfinfo->parent >= 0) {
        parent_hfinfo = proto_registrar_get_nth(hfinfo->parent);
    }

    cJSON_AddNumberToObject(obj, "id", hfinfo->id);
    json_add_string(obj, "name", hfinfo->name);
    json_add_string(obj, "abbrev", hfinfo->abbrev);
    json_add_string(obj, "type", ftype_name(hfinfo->type));
    json_add_string(obj, "display", proto_field_display_to_string(hfinfo->display));
    json_add_string(obj, "blurb", hfinfo->blurb);
    cJSON_AddNumberToObject(obj, "parentID", hfinfo->parent);
    json_add_string(obj, "parentName", parent_hfinfo ? parent_hfinfo->name : NULL);
    json_add_string(obj, "parentProtocol", parent_hfinfo ? parent_hfinfo->abbrev : NULL);
    char bitmask[32];
    snprintf(bitmask, sizeof(bitmask), "%" PRIu64, hfinfo->bitmask);
    cJSON_AddStringToObject(obj, "bitmask", bitmask);
    cJSON_AddBoolToObject(obj, "isProtocol", proto_registrar_is_protocol(hfinfo->id));

    return obj;
}

char *gowireshark_protocols_json(void) {
    cJSON *arr = cJSON_CreateArray();
    void *proto_cookie = NULL;

    for (int proto_id = proto_get_first_protocol(&proto_cookie); proto_id != -1;
         proto_id = proto_get_next_protocol(&proto_cookie)) {
        cJSON_AddItemToArray(arr, protocol_info_to_json(proto_id));
    }

    char *res = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return res;
}

char *gowireshark_fields_json(void) {
    cJSON *arr = cJSON_CreateArray();
    void *proto_cookie = NULL;

    for (int proto_id = proto_get_first_protocol(&proto_cookie); proto_id != -1;
         proto_id = proto_get_next_protocol(&proto_cookie)) {
        void *field_cookie = NULL;
        for (header_field_info *hfinfo = proto_get_first_protocol_field(proto_id, &field_cookie);
             hfinfo != NULL;
             hfinfo = proto_get_next_protocol_field(proto_id, &field_cookie)) {
            if (hfinfo->same_name_prev_id != -1) {
                continue;
            }
            cJSON_AddItemToArray(arr, field_info_to_json(hfinfo));
        }
    }

    char *res = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return res;
}

char *gowireshark_field_json(const char *name) {
    if (name == NULL || name[0] == '\0') {
        return strdup("");
    }

    header_field_info *hfinfo = proto_registrar_get_byname(name);
    if (hfinfo == NULL) {
        return strdup("");
    }

    cJSON *obj = field_info_to_json(hfinfo);
    char *res = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    return res;
}

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

// Helper to format hex buffer
static gboolean get_hex_data_buffer(const guchar *cp, guint length, cJSON *cjson_offset,
                                    cJSON *cjson_hex, cJSON *cjson_ascii) {
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

/**
 * Get hex part of data.
 *
 *  @param edt epan_dissect_t type
 *  @return cjson_offset、cjson_hex、cjson_ascii;
 */
bool get_hex_data(epan_dissect_t *edt, cJSON *cjson_offset, cJSON *cjson_hex, cJSON *cjson_ascii) {
    gboolean multiple_sources;
    GSList *src_le;
    tvbuff_t *tvb;
    char *line, *description;
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
            description = get_data_source_description(src);
            line = g_strdup_printf("%s:", description);
            wmem_free(NULL, description);
            g_free(line);
        }
        length = tvb_captured_length(tvb);
        if (length == 0) return true;
        cp = tvb_get_ptr(tvb, 0, length);
        if (!get_hex_data_buffer(cp, length, cjson_offset, cjson_hex, cjson_ascii)) return false;
    }
    return true;
}

/**
 * Init policies、wtap mod、epan mod.
 *
 * @return true if initialization is successful, false otherwise.
 */
bool init_env() {
    /**
     * Called when the program starts, to enable security features and save
     * whatever credential information we'll need later.
     */
    init_process_policies();
    /**
     * Permanently relinquish special privileges. get_credential_info()
     * MUST be called before calling this.
     */
    relinquish_special_privs_perm();

    timestamp_set_type(TS_RELATIVE);
    timestamp_set_precision(TS_PREC_AUTO);
    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

    /**
     * @brief Initialize the Wiretap library.
     *
     * @param load_wiretap_plugins Load Wiretap plugins when initializing library.
     */
    wtap_init(TRUE);

    ws_log_set_level(LOG_LEVEL_WARNING);

    /**
     * Init the whole epan module.
     *
     * Must be called only once in a program.
     *
     * Returns TRUE on success, FALSE on failure.
     */
    if (!epan_init(NULL, NULL, FALSE)) {
        return false;
    }

    return true;
}

const nstime_t *cap_file_provider_get_frame_ts(struct packet_provider_data *prov,
                                               uint32_t frame_num) {
    const frame_data *fd = NULL;

    if (prov->ref && prov->ref->num == frame_num) {
        fd = prov->ref;
    } else if (prov->prev_dis && prov->prev_dis->num == frame_num) {
        fd = prov->prev_dis;
    } else if (prov->prev_cap && prov->prev_cap->num == frame_num) {
        fd = prov->prev_cap;
    } else if (prov->frames) {
        fd = frame_data_sequence_find(prov->frames, frame_num);
    }

    return (fd && fd->has_ts) ? &fd->abs_ts : NULL;
}

const char *cap_file_provider_get_interface_name(struct packet_provider_data *prov,
                                                 uint32_t interface_id, unsigned section_number) {
    wtapng_iface_descriptions_t *idb_info;
    wtap_block_t wtapng_if_descr = NULL;
    char *interface_name;

    idb_info = wtap_file_get_idb_info(prov->wth);

    unsigned gbl_iface_id =
        wtap_file_get_shb_global_interface_id(prov->wth, section_number, interface_id);

    if (gbl_iface_id < idb_info->interface_data->len)
        wtapng_if_descr = g_array_index(idb_info->interface_data, wtap_block_t, gbl_iface_id);

    g_free(idb_info);

    if (wtapng_if_descr) {
        if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_NAME, &interface_name) ==
            WTAP_OPTTYPE_SUCCESS)
            return interface_name;
        if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_DESCRIPTION,
                                               &interface_name) == WTAP_OPTTYPE_SUCCESS)
            return interface_name;
        if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_HARDWARE,
                                               &interface_name) == WTAP_OPTTYPE_SUCCESS)
            return interface_name;
    }
    return "unknown";
}

const char *cap_file_provider_get_interface_description(struct packet_provider_data *prov,
                                                        uint32_t interface_id,
                                                        unsigned section_number) {
    wtapng_iface_descriptions_t *idb_info;
    wtap_block_t wtapng_if_descr = NULL;
    char *interface_name;

    idb_info = wtap_file_get_idb_info(prov->wth);

    interface_id = wtap_file_get_shb_global_interface_id(prov->wth, section_number, interface_id);

    if (interface_id < idb_info->interface_data->len)
        wtapng_if_descr = g_array_index(idb_info->interface_data, wtap_block_t, interface_id);

    g_free(idb_info);

    if (wtapng_if_descr) {
        if (wtap_block_get_string_option_value(wtapng_if_descr, OPT_IDB_DESCRIPTION,
                                               &interface_name) == WTAP_OPTTYPE_SUCCESS)
            return interface_name;
    }
    return NULL;
}

static int pref_set(const char *name, const char *value) {
    char pref[4096];
    char *errmsg = NULL;

    prefs_set_pref_e ret;

    snprintf(pref, sizeof(pref), "%s:%s", name, value);

    ret = prefs_set_pref(pref, &errmsg);
    g_free(errmsg);

    return (ret == PREFS_SET_OK);
}

void tls_prefs_apply(const char *keysList, int desegmentSslRecords,
                     int desegmentSslApplicationData, const char *keylogFile) {
    /* Turn off fragmentation for some protocols if enabled */
    if (desegmentSslRecords) {
        pref_set("tls.desegment_ssl_records", "TRUE");
    }
    if (desegmentSslApplicationData) {
        pref_set("tls.desegment_ssl_application_data", "TRUE");
    }

    /* Set the tls.keys_list if it is provided */
    if (keysList != NULL && strlen(keysList) > 0) {
        if (!pref_set("tls.keys_list", keysList)) {
            fprintf(stderr, "Failed to set tls.keys_list\n");
        }
    }

    /* Set the TLS keylog file (SSLKEYLOGFILE) for TLS 1.3 / ECDHE decryption */
    if (keylogFile != NULL && strlen(keylogFile) > 0) {
        if (!pref_set("tls.keylog_file", keylogFile)) {
            fprintf(stderr, "Failed to set tls.keylog_file\n");
        }
    }

    /* Notify all registered modules that have had any of their preferences
     * changed */
    prefs_apply_all();
}

int has_srt_table(const char *protocol) {
    return get_srt_table_by_name(protocol) != NULL;
}

// Helper function to check if JSON is empty
bool is_empty_json(const char *json_str) {
    if (json_str == NULL || strlen(json_str) == 0) {
        return true;  // Empty if NULL or empty string
    }

    cJSON *json = cJSON_Parse(json_str);
    if (json == NULL) {
        return true;  // Invalid JSON treated as empty
    }

    // Check if it's an empty object
    int is_empty = cJSON_IsObject(json) && (cJSON_GetArraySize(json) == 0);

    cJSON_Delete(json);
    return is_empty;
}

char *gowireshark_version_json(void) {
    cJSON *obj = cJSON_CreateObject();

    const char *epan_ver = epan_get_version();
    cJSON_AddStringToObject(obj, "version", epan_ver ? epan_ver : "");

    GString *compiled = get_compiled_version_info(NULL);
    if (compiled) {
        cJSON_AddStringToObject(obj, "compiledVersion", compiled->str);
        g_string_free(compiled, TRUE);
    } else {
        cJSON_AddStringToObject(obj, "compiledVersion", "");
    }

    const char *copyright = get_copyright_info();
    cJSON_AddStringToObject(obj, "copyright", copyright ? copyright : "");

    char *res = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    return res;
}

char *gowireshark_profiles_json(void) {
    cJSON *arr = cJSON_CreateArray();

    char *profiles_dir = get_profiles_dir();
    if (profiles_dir == NULL) {
        cJSON_Delete(arr);
        return cJSON_PrintUnformatted(arr);
    }

    GDir *dir = g_dir_open(profiles_dir, 0, NULL);
    g_free(profiles_dir);

    if (dir == NULL) {
        cJSON_Delete(arr);
        return cJSON_PrintUnformatted(arr);
    }

    const char *name;
    while ((name = g_dir_read_name(dir)) != NULL) {
        cJSON_AddItemToArray(arr, cJSON_CreateString(name));
    }

    g_dir_close(dir);

    char *res = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return res;
}

static void decode_as_choices_collector(const char *table_name _U_, const char *proto_name, void *value _U_, void *user_data) {
    cJSON *arr = (cJSON *)user_data;
    cJSON_AddItemToArray(arr, cJSON_CreateString(proto_name ? proto_name : ""));
}

char *gowireshark_decode_as_tables_json(void) {
    cJSON *arr = cJSON_CreateArray();

    if (decode_as_list == NULL) {
        char *res = cJSON_PrintUnformatted(arr);
        cJSON_Delete(arr);
        return res;
    }

    for (GList *cur = decode_as_list; cur != NULL; cur = cur->next) {
        decode_as_t *entry = (decode_as_t *)cur->data;
        if (entry == NULL) continue;

        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "name", entry->name ? entry->name : "");
        cJSON_AddStringToObject(obj, "tableName", entry->table_name ? entry->table_name : "");
        cJSON_AddNumberToObject(obj, "numItems", entry->num_items);
        cJSON_AddNumberToObject(obj, "defaultIndexValue", entry->default_index_value);

        cJSON *choices = cJSON_CreateArray();
        if (entry->populate_list) {
            entry->populate_list(entry->table_name, decode_as_choices_collector, choices);
        }
        cJSON_AddItemToObject(obj, "choices", choices);

        cJSON_AddItemToArray(arr, obj);
    }

    char *res = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return res;
}

char *gowireshark_decode_as_choices_json(const char *table_name) {
    cJSON *arr = cJSON_CreateArray();
    if (table_name == NULL || table_name[0] == '\0' || decode_as_list == NULL) {
        cJSON_Delete(arr);
        return cJSON_PrintUnformatted(arr);
    }

    for (GList *cur = decode_as_list; cur != NULL; cur = cur->next) {
        decode_as_t *entry = (decode_as_t *)cur->data;
        if (entry == NULL || entry->table_name == NULL) continue;
        if (strcmp(entry->table_name, table_name) != 0) continue;

        if (entry->populate_list) {
            entry->populate_list(table_name, decode_as_choices_collector, arr);
        }
        break;
    }

    char *res = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return res;
}

char *gowireshark_tap_types_json(void) {
    cJSON *arr = cJSON_CreateArray();

    const char *known_taps[] = {
        "frame", "rtp", "expert", "wlan", "eth", "ip", "ipv6",
        "tcp", "udp", "sctp", "arp", "icmp", "icmpv6",
        "diameter", "camel", "credentials", "gsm_a", "rlc_lte", "mac_lte",
        "http", "sip", "smb", "rpc", "wsp",
        "voip", "flow", "hosts", "rtd", "rpcprogs",
        NULL
    };

    for (const char **tap_name = known_taps; *tap_name != NULL; tap_name++) {
        if (find_tap_id(*tap_name) != 0) {
            cJSON_AddItemToArray(arr, cJSON_CreateString(*tap_name));
        }
    }

    char *res = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return res;
}

static unsigned pref_collector_cb(module_t *module, void *user_data) {
    cJSON *arr = (cJSON *)user_data;
    if (module == NULL) return 0;

    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "name", module->name ? module->name : "");
    cJSON_AddStringToObject(obj, "title", module->title ? module->title : "");
    cJSON_AddStringToObject(obj, "description", module->description ? module->description : "");
    cJSON_AddNumberToObject(obj, "numPrefs", module->numprefs);
    cJSON_AddBoolToObject(obj, "obsolete", module->obsolete);

    cJSON_AddItemToArray(arr, obj);

    if (module->submodules) {
        prefs_modules_foreach_submodules(module, pref_collector_cb, arr);
    }

    return 0;
}

char *gowireshark_preferences_json(void) {
    cJSON *arr = cJSON_CreateArray();
    prefs_modules_foreach(pref_collector_cb, arr);
    char *res = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return res;
}

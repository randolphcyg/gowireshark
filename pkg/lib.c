#include "lib.h"

void free_c_string(char *str) {
    if (str) {
        g_free(str);
    }
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
                     int desegmentSslApplicationData) {
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

    /* Notify all registered modules that have had any of their preferences
     * changed */
    prefs_apply_all();
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
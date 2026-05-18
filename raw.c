#include "raw.h"
#include "offline.h"
#include <wiretap/pcap-encap.h>

static epan_t *raw_epan_new(capture_file *cf) {
    static const struct packet_provider_funcs funcs = {
        cap_file_provider_get_frame_ts,
        cap_file_provider_get_interface_name,
        cap_file_provider_get_interface_description,
        NULL,
    };

    return epan_new(&cf->provider, &funcs);
}

static void apply_tls_options(char *options) {
    if (is_empty_json(options)) {
        return;
    }

    cJSON *json = cJSON_Parse(options);
    if (json == NULL) {
        return;
    }

    char *keys_list = NULL;
    const char *keylog_file = NULL;

    const cJSON *keys_list_json = cJSON_GetObjectItemCaseSensitive(json, "tls.keys_list");
    const cJSON *desegment_records_json =
        cJSON_GetObjectItemCaseSensitive(json, "tls.desegment_ssl_records");
    const cJSON *desegment_app_json =
        cJSON_GetObjectItemCaseSensitive(json, "tls.desegment_ssl_application_data");
    const cJSON *keylog_file_json = cJSON_GetObjectItemCaseSensitive(json, "tls.keylog_file");

    if (cJSON_IsString(keys_list_json) && keys_list_json->valuestring != NULL) {
        keys_list = keys_list_json->valuestring;
    }
    if (cJSON_IsString(keylog_file_json) && keylog_file_json->valuestring != NULL) {
        keylog_file = keylog_file_json->valuestring;
    }

    tls_prefs_apply(keys_list, cJSON_IsTrue(desegment_records_json),
                    cJSON_IsTrue(desegment_app_json), keylog_file);

    cJSON_Delete(json);
}

static bool init_raw_capture_file(capture_file *cf, char *options) {
    memset(cf, 0, sizeof(capture_file));
    apply_tls_options(options);

    cf->provider.wth = NULL;
    cf->f_datalen = 0;
    cf->is_tempfile = FALSE;
    cf->unsaved_changes = FALSE;
    cf->cd_t = WTAP_FILE_TYPE_SUBTYPE_UNKNOWN;
    cf->open_type = WTAP_TYPE_AUTO;
    cf->count = 0;
    cf->drops_known = FALSE;
    cf->drops = 0;
    cf->snap = 0;
    cf->provider.frames = new_frame_data_sequence();
    nstime_set_zero(&cf->elapsed_time);
    cf->provider.ref = NULL;
    cf->provider.prev_dis = NULL;
    cf->provider.prev_cap = NULL;
    cf->epan = raw_epan_new(cf);

    e_prefs *prefs = epan_load_settings();
    build_column_format_array(&cf->cinfo, prefs->num_cols, TRUE);

    return cf->epan != NULL;
}

static void close_raw_capture_file(capture_file *cf) {
    wtap_rec_cleanup(&cf->rec);
    if (cf->provider.frames != NULL) {
        free_frame_data_sequence(cf->provider.frames);
        cf->provider.frames = NULL;
    }
    if (cf->provider.frames_modified_blocks) {
        g_tree_destroy(cf->provider.frames_modified_blocks);
        cf->provider.frames_modified_blocks = NULL;
    }
    if (cf->linktypes != NULL) {
        g_array_free(cf->linktypes, TRUE);
        cf->linktypes = NULL;
    }
    reset_tap_listeners();
    if (cf->epan != NULL) {
        epan_free(cf->epan);
        cf->epan = NULL;
    }
}

char *dissect_raw_packet_json(const unsigned char *packet, int caplen, int len,
                              long sec, int nsec, int link_type, char *options) {
    if (packet == NULL || caplen <= 0 || len <= 0 || caplen > WTAP_MAX_PACKET_SIZE_STANDARD) {
        return NULL;
    }

    int encap = wtap_pcap_encap_to_wtap_encap(link_type);
    if (encap < 0) {
        return NULL;
    }

    capture_file cf_raw;
    if (!init_raw_capture_file(&cf_raw, options)) {
        return NULL;
    }

    wtap_rec_init(&cf_raw.rec, caplen);
    wtap_setup_packet_rec(&cf_raw.rec, encap);
    cf_raw.rec.presence_flags = WTAP_HAS_TS | WTAP_HAS_CAP_LEN;
    cf_raw.rec.ts.secs = sec;
    cf_raw.rec.ts.nsecs = nsec;
    cf_raw.rec.rec_header.packet_header.caplen = caplen;
    cf_raw.rec.rec_header.packet_header.len = len;
    ws_buffer_append(&cf_raw.rec.data, packet, caplen);

    cf_raw.count = 1;
    frame_data fd;
    guint32 cum_bytes = 0;
    frame_data_init(&fd, cf_raw.count, &cf_raw.rec, 0, cum_bytes);
    frame_data_set_before_dissect(&fd, &cf_raw.elapsed_time, &cf_raw.provider.ref,
                                  cf_raw.provider.prev_dis);

    epan_dissect_t *edt = epan_dissect_new(cf_raw.epan, TRUE, TRUE);
    if (edt == NULL) {
        frame_data_destroy(&fd);
        close_raw_capture_file(&cf_raw);
        return NULL;
    }

    epan_dissect_run_with_taps(edt, cf_raw.cd_t, &cf_raw.rec, &fd, &cf_raw.cinfo);
    frame_data_set_after_dissect(&fd, &cum_bytes);
    cf_raw.provider.prev_cap = cf_raw.provider.prev_dis =
        frame_data_sequence_add(cf_raw.provider.frames, &fd);

    json_dumper dumper = {};
    dumper.output_string = g_string_new(NULL);
    get_json_proto_tree(NULL, print_dissections_expanded, FALSE, NULL, PF_INCLUDE_CHILDREN,
                        edt, &cf_raw.cinfo, proto_node_group_children_by_unique, &dumper);

    char *result = NULL;
    if (json_dumper_finish(&dumper) && dumper.output_string != NULL) {
        result = g_strdup(dumper.output_string->str);
    }

    if (dumper.output_string != NULL) {
        g_string_free(dumper.output_string, TRUE);
    }
    epan_dissect_free(edt);
    close_raw_capture_file(&cf_raw);

    return result;
}

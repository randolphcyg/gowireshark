#include "reassembly.h"

static TcpTapDataCallback tcpTapDataCallback;
static void *tcpTapCtx = NULL;

// Set up callback function for send packet to Go
void setTcpTapDataCallbackWithCtx(TcpTapDataCallback callback, void *ctx) {
    tcpTapDataCallback = callback;
    tcpTapCtx = ctx;
}

typedef struct tcp_follow_tap_data {
    tvbuff_t *tvb;
    struct tcpheader *tcph;
    struct tcp_analysis *tcpd;
} tcp_follow_tap_data_t;

typedef struct {
    guint32 packet_id;
    guint32 peer;
    guint32 index;
    double timestamp;
    gchar *data;
} tcp_packet;

typedef struct {
    guint32 stream_id;
    guint32 peer_count;
    address src;
    guint16 srcport;
    address dst;
    guint16 destport;
    GList *packets;
} tcp_stream_context;

// helper func：Base64 encode
static gchar *encode_data_to_base64(const guint8 *data, guint32 data_len) {
    if (data == NULL || data_len == 0) {
        return g_strdup("");
    }
    return g_base64_encode(data, data_len);
}

double nstime_to_double(const nstime_t *nstime) {
    if (!nstime) {
        return 0.0;
    }
    return (double)nstime->secs + (double)nstime->nsecs / 1e9;
}

static tap_packet_status follow_tcp_tap_packet(void *tapdata, packet_info *pinfo,
                                               epan_dissect_t *edt _U_, const void *data,
                                               tap_flags_t flags _U_) {
    const tcp_follow_tap_data_t *follow_data = (const tcp_follow_tap_data_t *)data;
    const uint8_t *tcp_data = NULL;
    guint32 tcp_data_len = 0;

    if (follow_data) {
        tcp_data_len = follow_data->tcph->th_seglen;
        if (tcp_data_len > 0) {
            tvbuff_t *tvb = follow_data->tvb;
            tcp_data = tvb_get_ptr(tvb, 0, tcp_data_len);
        }
    } else {
        fprintf(stderr, "Error: No follow_data received.\n");
        return TAP_PACKET_DONT_REDRAW;
    }

    char src_addr[128], dst_addr[128];
    address_to_str_buf(&pinfo->src, src_addr, sizeof(src_addr));
    address_to_str_buf(&pinfo->dst, dst_addr, sizeof(dst_addr));

    gchar *data_base64 = encode_data_to_base64(tcp_data, tcp_data_len);

    GString *json_str = g_string_new(NULL);
    g_string_printf(json_str,
                    "{\"stream_id\":%u,\"packet_id\":%u,\"src\":\"%s:%u\",\"dst\":\"%s:%u\","
                    "\"timestamp\":%.6f,\"data\":\"%s\"}",
                    pinfo->stream_id, pinfo->num, src_addr, pinfo->srcport, dst_addr,
                    pinfo->destport, nstime_to_double(&pinfo->abs_ts), data_base64);

    if (tcpTapDataCallback != NULL) {
        tcpTapDataCallback(json_str->str, json_str->len, tcpTapCtx);
    }

    g_string_free(json_str, TRUE);
    g_free(data_base64);

    return TAP_PACKET_DONT_REDRAW;
}

void setup_tcp_follow_tap() {
    int tap_id = register_tap("tcp_follow");
    if (tap_id == 0) {
        fprintf(stderr, "Error: Failed to register tcp_follow TAP.\n");
        return;
    }

    GString *error = register_tap_listener("tcp_follow", NULL, NULL, TL_REQUIRES_NOTHING, NULL,
                                           follow_tcp_tap_packet, NULL, NULL);

    if (error) {
        fprintf(stderr, "Error registering listener: %s\n", error->str);
        g_string_free(error, TRUE);
    }
}
#include <epan/dissectors/packet-tcp.h>
#include <epan/follow.h>
#include <epan/to_str.h>

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

GHashTable *tcp_streams;

// init hash
void init_tcp_streams() {
  tcp_streams = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, g_free);
}

// cleanup hash
void cleanup_tcp_streams() {
  if (tcp_streams) {
    g_hash_table_destroy(tcp_streams);
    tcp_streams = NULL;
  }
}

// helper func：Base64 encode
static gchar *encode_data_to_base64(const guint8 *data, guint32 data_len) {
  if (data == NULL || data_len == 0) {
    return g_strdup("");
  }
  return g_base64_encode(data, data_len); // 使用 GLib 的 Base64 编码
}

double nstime_to_double(const nstime_t *nstime) {
  if (!nstime) {
    return 0.0;
  }
  return (double)nstime->secs + (double)nstime->nsecs / 1e9;
}

static tap_packet_status follow_tcp_tap_packet(void *tapdata,
                                               packet_info *pinfo,
                                               epan_dissect_t *edt _U_,
                                               const void *data,
                                               tap_flags_t flags _U_) {
  if (!tcp_streams) {
    fprintf(stderr, "Error: tcp_streams is not initialized.\n");
    return FALSE;
  }

  guint32 *key = g_new(guint32, 1);
  *key = pinfo->stream_id;

  tcp_stream_context *ctx = g_hash_table_lookup(tcp_streams, key);
  if (!ctx) {
    ctx = g_new0(tcp_stream_context, 1);
    ctx->stream_id = pinfo->stream_id;
    copy_address(&ctx->src, &pinfo->src);
    ctx->srcport = pinfo->srcport;
    copy_address(&ctx->dst, &pinfo->dst);
    ctx->destport = pinfo->destport;
    ctx->packets = NULL;
    g_hash_table_insert(tcp_streams, key, ctx);
  } else {
    g_free(key);
  }

  const tcp_follow_tap_data_t *follow_data =
      (const tcp_follow_tap_data_t *)data;
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

  tcp_packet *packet = g_new0(tcp_packet, 1);
  packet->packet_id = pinfo->num;
  packet->peer = (addresses_equal(&ctx->src, &pinfo->src) &&
                  ctx->srcport == pinfo->srcport)
                     ? 0
                     : 1;
  packet->index = g_list_length(ctx->packets);
  packet->timestamp = nstime_to_double(&pinfo->abs_ts);

  if (tcp_data && tcp_data_len > 0) {
    packet->data = encode_data_to_base64(tcp_data, tcp_data_len);
  } else {
    packet->data = g_strdup("");
  }

  ctx->packets = g_list_append(ctx->packets, packet);

  return TRUE;
}

void print_tcp_streams() {
  if (!tcp_streams) {
    fprintf(stderr, "No streams to print.\n");
    return;
  }

  GHashTableIter iter;
  gpointer key, value;

  g_hash_table_iter_init(&iter, tcp_streams);
  while (g_hash_table_iter_next(&iter, &key, &value)) {
    tcp_stream_context *ctx = value;

    printf("peers:\n");
    char src_addr[128], dst_addr[128];
    address_to_str_buf(&ctx->src, src_addr, sizeof(src_addr));
    address_to_str_buf(&ctx->dst, dst_addr, sizeof(dst_addr));

    printf("  - peer: 0\n");
    printf("    host: %s\n", src_addr);
    printf("    port: %u\n", ctx->srcport);
    printf("  - peer: 1\n");
    printf("    host: %s\n", dst_addr);
    printf("    port: %u\n", ctx->destport);

    printf("packets:\n");
    if (!ctx->packets) {
      fprintf(stderr, "Warning: Stream %u has no packets.\n", ctx->stream_id);
      continue;
    }

    GList *current = ctx->packets;
    unsigned int index_0 = 0, index_1 = 0;
    while (current) {
      tcp_packet *packet = current->data;

      // ignore invalid data
      if (!packet->data || *packet->data == '\0') {
        current = current->next;
        continue;
      }

      // reindex
      if (packet->peer == 0) {
        packet->index = index_0++;
      } else if (packet->peer == 1) {
        packet->index = index_1++;
      }

      printf("  - packet: %u\n", packet->packet_id);
      printf("    peer: %u\n", packet->peer);
      printf("    index: %u\n", packet->index);
      printf("    timestamp: %.6f\n", packet->timestamp);
      printf("    data: !!binary |\n      %s\n", packet->data);
      current = current->next;
    }
  }
}

void setup_tcp_follow_tap() {
  init_tcp_streams();

  int tap_id = register_tap("tcp_follow");
  if (tap_id == 0) {
    fprintf(stderr, "Error: Failed to register tcp_follow TAP.\n");
    return;
  }

  GString *error =
      register_tap_listener("tcp_follow", NULL, NULL, TL_REQUIRES_NOTHING, NULL,
                            follow_tcp_tap_packet, NULL, NULL);

  if (error) {
    fprintf(stderr, "Error registering listener: %s\n", error->str);
    g_string_free(error, TRUE);
  }
}
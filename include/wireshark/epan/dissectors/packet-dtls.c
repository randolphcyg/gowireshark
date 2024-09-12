/* packet-dtls.c
 * Routines for dtls dissection
 * Copyright (c) 2006, Authesserre Samuel <sauthess@gmail.com>
 * Copyright (c) 2007, Mikael Magnusson <mikma@users.sourceforge.net>
 * Copyright (c) 2013, Hauke Mehrtens <hauke@hauke-m.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 *
 * DTLS dissection and decryption.
 * See RFC 4347 for details about DTLS specs.
 *
 * Notes :
 * This dissector is based on the TLS dissector (packet-tls.c); Because of the similarity
 *   of DTLS and TLS, decryption works like TLS with RSA key exchange.
 * This dissector uses the sames things (file, libraries) as the TLS dissector (gnutls, packet-tls-utils.h)
 *  to make it easily maintainable.
 *
 * It was developed to dissect and decrypt the OpenSSL v 0.9.8f DTLS implementation.
 * It is limited to this implementation; there is no complete implementation.
 *
 * Implemented :
 *  - DTLS dissection
 *  - DTLS decryption (openssl one)
 *
 * Todo :
 *  - activate correct Mac calculation when openssl will be corrected
 *    (or if an other implementation works),
 *    corrected code is ready and commented in packet-tls-utils.h file.
 *  - add missing things (desegmentation, reordering... that aren't present in actual OpenSSL implementation)
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/asn1.h>
#include <epan/tap.h>
#include <epan/reassemble.h>
#include <epan/uat.h>
#include <epan/sctpppids.h>
#include <epan/exported_pdu.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>
#include <epan/secrets.h>   /* for privkey_hash_table_new */
#include <epan/tfs.h>
#include <wsutil/str_util.h>
#include <wsutil/strtoi.h>
#include <wsutil/utf8_entities.h>
#include <wsutil/rsa.h>
#include <wsutil/pint.h>
#include "packet-tls-utils.h"
#include "packet-dtls.h"
#include "packet-rtp.h"
#include "packet-rtcp.h"

void proto_register_dtls(void);

#ifdef HAVE_LIBGNUTLS
/* DTLS User Access Table */
static ssldecrypt_assoc_t *dtlskeylist_uats;
static unsigned ndtlsdecrypt;
#endif

/* we need to remember the top tree so that subdissectors we call are created
 * at the root and not deep down inside the DTLS decode
 */
static proto_tree *top_tree;

/*********************************************************************
 *
 * Protocol Constants, Variables, Data Structures
 *
 *********************************************************************/

/* https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml */

#define SRTP_PROFILE_RESERVED       0x0000
#define SRTP_AES128_CM_HMAC_SHA1_80 0x0001
#define SRTP_AES128_CM_HMAC_SHA1_32 0x0002
#define SRTP_NULL_HMAC_SHA1_80      0x0005
#define SRTP_NULL_HMAC_SHA1_32      0x0006
#define SRTP_AEAD_AES_128_GCM       0x0007
#define SRTP_AEAD_AES_256_GCM       0x0008

#define DTLS13_FIXED_MASK 0xE0
#define DTLS13_C_BIT_MASK 0x10
#define DTLS13_S_BIT_MASK 0x08
#define DTLS13_L_BIT_MASK 0x04
#define DTLS13_HDR_EPOCH_BIT_MASK 0x3

static const value_string srtp_protection_profile_vals[] = {
  { SRTP_AES128_CM_HMAC_SHA1_80, "SRTP_AES128_CM_HMAC_SHA1_80" }, /* RFC 5764 */
  { SRTP_AES128_CM_HMAC_SHA1_32, "SRTP_AES128_CM_HMAC_SHA1_32" },
  { SRTP_NULL_HMAC_SHA1_80, "SRTP_NULL_HMAC_SHA1_80" },
  { SRTP_NULL_HMAC_SHA1_32, "SRTP_NULL_HMAC_SHA1_32" },
  { SRTP_AEAD_AES_128_GCM, "SRTP_AEAD_AES_128_GCM" }, /* RFC 7714 */
  { SRTP_AEAD_AES_256_GCM, "SRTP_AEAD_AES_256_GCM" },
  { 0x00, NULL },
};

static const true_false_string dtls_uni_hdr_seq_tfs = {
  "16 bits",
  "8 bits"
};

/* Initialize the protocol and registered fields */
static int dtls_tap                            = -1;
static int exported_pdu_tap                    = -1;
static int proto_dtls;
static int hf_dtls_record;
static int hf_dtls_record_content_type;
static int hf_dtls_record_special_type;
static int hf_dtls_record_version;
static int hf_dtls_ack_record_numbers;
static int hf_dtls_record_epoch;
static int hf_dtls_record_epoch64;
static int hf_dtls_record_sequence_number;
static int hf_dtls_record_sequence_suffix;
static int hf_dtls_record_sequence_suffix_dec;
static int hf_dtls_record_connection_id;
static int hf_dtls_record_length;
static int hf_dtls_record_appdata;
static int hf_dtls_record_appdata_proto;
static int hf_dtls_record_encrypted_content;
static int hf_dtls_alert_message;
static int hf_dtls_alert_message_level;
static int hf_dtls_alert_message_description;
static int hf_dtls_handshake_protocol;
static int hf_dtls_handshake_type;
static int hf_dtls_handshake_length;
static int hf_dtls_handshake_message_seq;
static int hf_dtls_handshake_fragment_offset;
static int hf_dtls_handshake_fragment_length;

static int hf_dtls_heartbeat_message;
static int hf_dtls_heartbeat_message_type;
static int hf_dtls_heartbeat_message_payload_length;
static int hf_dtls_heartbeat_message_payload;
static int hf_dtls_heartbeat_message_padding;

static int hf_dtls_ack_message;
static int hf_dtls_ack_record_numbers_length;
static int hf_dtls_fragments;
static int hf_dtls_fragment;
static int hf_dtls_fragment_overlap;
static int hf_dtls_fragment_overlap_conflicts;
static int hf_dtls_fragment_multiple_tails;
static int hf_dtls_fragment_too_long_fragment;
static int hf_dtls_fragment_error;
static int hf_dtls_fragment_count;
static int hf_dtls_reassembled_in;
static int hf_dtls_reassembled_length;

static int hf_dtls_hs_ext_use_srtp_protection_profiles_length;
static int hf_dtls_hs_ext_use_srtp_protection_profile;
static int hf_dtls_hs_ext_use_srtp_mki_length;
static int hf_dtls_hs_ext_use_srtp_mki;

static int hf_dtls_uni_hdr;
static int hf_dtls_uni_hdr_fixed;
static int hf_dtls_uni_hdr_cid;
static int hf_dtls_uni_hdr_seq;
static int hf_dtls_uni_hdr_len;
static int hf_dtls_uni_hdr_epoch;

/* header fields used in ssl-utils, but defined here. */
static dtls_hfs_t dtls_hfs;

/* Initialize the subtree pointers */
static int ett_dtls;
static int ett_dtls_record;
static int ett_dtls_alert;
static int ett_dtls_handshake;
static int ett_dtls_heartbeat;
static int ett_dtls_ack;
static int ett_dtls_ack_record_numbers;
static int ett_dtls_ack_record_number;
static int ett_dtls_certs;
static int ett_dtls_uni_hdr;

static int ett_dtls_fragment;
static int ett_dtls_fragments;

static expert_field ei_dtls_handshake_fragment_length_too_long;
static expert_field ei_dtls_handshake_fragment_length_zero;
static expert_field ei_dtls_handshake_fragment_past_end_msg;
static expert_field ei_dtls_msg_len_diff_fragment;
static expert_field ei_dtls_heartbeat_payload_length;
static expert_field ei_dtls_cid_invalid_content_type;
static expert_field ei_dtls_use_srtp_profiles_length;
#if 0
static expert_field ei_dtls_cid_invalid_enc_content;
#endif

#ifdef HAVE_LIBGNUTLS
static GHashTable      *dtls_key_hash;
static wmem_stack_t    *key_list_stack;
static uat_t           *dtlsdecrypt_uat;
static const char      *dtls_keys_list;
#endif
static reassembly_table    dtls_reassembly_table;
static dissector_table_t   dtls_associations;
static dissector_handle_t  dtls_handle;
static StringInfo          dtls_compressed_data;
static StringInfo          dtls_decrypted_data;
static int                 dtls_decrypted_data_avail;

static ssl_common_options_t dtls_options;
static const char *dtls_debug_file_name;

static uint32_t dtls_default_client_cid_length;
static uint32_t dtls_default_server_cid_length;

static heur_dissector_list_t heur_subdissector_list;

static const fragment_items dtls_frag_items = {
  /* Fragment subtrees */
  &ett_dtls_fragment,
  &ett_dtls_fragments,
  /* Fragment fields */
  &hf_dtls_fragments,
  &hf_dtls_fragment,
  &hf_dtls_fragment_overlap,
  &hf_dtls_fragment_overlap_conflicts,
  &hf_dtls_fragment_multiple_tails,
  &hf_dtls_fragment_too_long_fragment,
  &hf_dtls_fragment_error,
  &hf_dtls_fragment_count,
  /* Reassembled in field */
  &hf_dtls_reassembled_in,
  /* Reassembled length field */
  &hf_dtls_reassembled_length,
  /* Reassembled data field */
  NULL,
  /* Tag */
  "Message fragments"
};

static SSL_COMMON_LIST_T(dissect_dtls_hf);

/* initialize/reset per capture state data (dtls sessions cache) */
static void
dtls_init(void)
{
  module_t *dtls_module = prefs_find_module("dtls");
  pref_t   *keys_list_pref;

  ssl_data_alloc(&dtls_decrypted_data, 32);
  ssl_data_alloc(&dtls_compressed_data, 32);

  /* We should have loaded "keys_list" by now. Mark it obsolete */
  if (dtls_module) {
    keys_list_pref = prefs_find_preference(dtls_module, "keys_list");
    if (! prefs_get_preference_obsolete(keys_list_pref)) {
      prefs_set_preference_obsolete(keys_list_pref);
    }
  }

  ssl_init_cid_list();
}

static void
dtls_cleanup(void)
{
  ssl_cleanup_cid_list();

#ifdef HAVE_LIBGNUTLS
  if (key_list_stack != NULL) {
    wmem_destroy_stack(key_list_stack);
    key_list_stack = NULL;
  }
#endif
  g_free(dtls_decrypted_data.data);
  g_free(dtls_compressed_data.data);
}

#ifdef HAVE_LIBGNUTLS
/* parse dtls related preferences (private keys and ports association strings) */
static void
dtls_parse_uat(void)
{
  unsigned         i, port;
  dissector_handle_t handle;

  if (dtls_key_hash)
  {
      g_hash_table_destroy(dtls_key_hash);
  }

  /* remove only associations created from key list */
  if (key_list_stack != NULL) {
    while (wmem_stack_count(key_list_stack) > 0) {
      port = GPOINTER_TO_UINT(wmem_stack_pop(key_list_stack));
      handle = dissector_get_uint_handle(dtls_associations, port);
      if (handle != NULL)
        ssl_association_remove("dtls.port", dtls_handle, handle, port, false);
    }
  }

  /* parse private keys string, load available keys and put them in key hash*/
  dtls_key_hash = privkey_hash_table_new();

  ssl_set_debug(dtls_debug_file_name);

  if (ndtlsdecrypt > 0)
  {
    if (key_list_stack == NULL)
      key_list_stack = wmem_stack_new(NULL);

    for (i = 0; i < ndtlsdecrypt; i++)
    {
      ssldecrypt_assoc_t *d = &(dtlskeylist_uats[i]);
      ssl_parse_key_list(d, dtls_key_hash, "dtls.port", dtls_handle, false);
      if (key_list_stack && ws_strtou32(d->port, NULL, &port))
        wmem_stack_push(key_list_stack, GUINT_TO_POINTER(port));
    }
  }

  dissector_add_for_decode_as("sctp.port", dtls_handle);
  dissector_add_for_decode_as("udp.port", dtls_handle);
}

static void
dtls_reset_uat(void)
{
  g_hash_table_destroy(dtls_key_hash);
  dtls_key_hash = NULL;
}

static void
dtls_parse_old_keys(void)
{
  char           **old_keys, **parts, *err;
  unsigned         i;
  char           *uat_entry;

  /* Import old-style keys */
  if (dtlsdecrypt_uat && dtls_keys_list && dtls_keys_list[0]) {
    old_keys = g_strsplit(dtls_keys_list, ";", 0);
    for (i = 0; old_keys[i] != NULL; i++) {
      parts = g_strsplit(old_keys[i], ",", 4);
      if (parts[0] && parts[1] && parts[2] && parts[3]) {
        char *path = uat_esc(parts[3], (unsigned)strlen(parts[3]));
        uat_entry = wmem_strdup_printf(NULL, "\"%s\",\"%s\",\"%s\",\"%s\",\"\"",
                        parts[0], parts[1], parts[2], path);
        g_free(path);
        if (!uat_load_str(dtlsdecrypt_uat, uat_entry, &err)) {
          ssl_debug_printf("dtls_parse: Can't load UAT string %s: %s\n",
                           uat_entry, err);
          g_free(err);
        }
        wmem_free(NULL, uat_entry);
      }
      g_strfreev(parts);
    }
    g_strfreev(old_keys);
  }
}
#endif  /* HAVE_LIBGNUTLS */

/*
 * DTLS Dissection Routines
 *
 */

/* record layer dissectors */
static int dissect_dtls_record(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree, uint32_t offset,
                                SslSession *session, int is_from_server,
                                SslDecryptSession *conv_data,
                                uint8_t curr_layer_num_ssl);
static int dissect_dtls13_record(tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree, uint32_t offset,
                                SslSession *session, int is_from_server,
                                SslDecryptSession *conv_data,
                                uint8_t curr_layer_num_ssl);

/* alert message dissector */
static void dissect_dtls_alert(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, uint32_t offset,
                               const SslSession *session);

/* handshake protocol dissector */
static void dissect_dtls_handshake(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, uint32_t offset,
                                   uint32_t record_length, bool maybe_encrypted,
                                   SslSession *session, int is_from_server,
                                   SslDecryptSession *conv_data, uint8_t content_type);

/* heartbeat message dissector */
static void dissect_dtls_heartbeat(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, uint32_t offset,
                                   const SslSession *session, uint32_t record_length,
                                   bool decrypted);

/* acknowledgement message dissector */
static void dissect_dtls_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t offset, uint32_t record_length);

static int dissect_dtls_hnd_hello_verify_request(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                                 packet_info *pinfo, proto_tree *tree,
                                                 uint32_t offset, uint32_t offset_end);

/*
 * Support Functions
 *
 */

static int   looks_like_dtls(tvbuff_t *tvb, uint32_t offset);

/*********************************************************************
 *
 * Main dissector
 *
 *********************************************************************/
/*
 * Code to actually dissect the packets
 */
static int
dissect_dtls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

  conversation_t    *conversation;
  proto_item        *ti;
  proto_tree        *dtls_tree;
  uint32_t           offset;
  SslDecryptSession *ssl_session = NULL;
  SslSession        *session = NULL;
  int                is_from_server;
  uint8_t            curr_layer_num_ssl = pinfo->curr_layer_num;

  ti                    = NULL;
  dtls_tree             = NULL;
  offset                = 0;
  ssl_session           = NULL;
  top_tree              = tree;

  /* Track the version using conversations allows
   * us to more frequently set the protocol column properly
   * for continuation data frames.
   *
   * Also: We use the copy in conv_version as our cached copy,
   *       so that we don't have to search the conversation
   *       table every time we want the version; when setting
   *       the conv_version, must set the copy in the conversation
   *       in addition to conv_version
   */
  conversation = find_or_create_conversation(pinfo);

  uint8_t record_type = tvb_get_uint8(tvb, offset);

  /* try to get decrypt session from the connection ID only for the first pass,
   * it should be available from the conversation in the second pass
   */
  if (record_type == SSL_ID_TLS12_CID && !PINFO_FD_VISITED(pinfo)) {
      // CID length is not embedded in the packet
      ssl_session = ssl_get_session_by_cid(tvb, offset+11);

      if (ssl_session) {
          // update conversation
          conversation_add_proto_data(conversation,
                                      dissector_handle_get_protocol_index(dtls_handle),
                                      ssl_session);
      }
  }

  /* if session cannot be retrieved from connection ID, get or create it from conversation */
  if (ssl_session == NULL) {
      ssl_session = ssl_get_session(conversation, dtls_handle);
  }

  session = &ssl_session->session;

  if (session->last_nontls_frame != 0 &&
      session->last_nontls_frame >= pinfo->num) {
    /* This conversation started at a different protocol and STARTTLS was
     * used, but this packet comes too early.
     * XXX - Does anything use STARTTLS with DTLS? Would we get here anyway,
     * since we don't call conversation_set_dissector[_from_frame_number] for
     * DTLS? Regardless, dissect_dtls_heur should check for this 0 and return
     * false.
     */
    return 0;
  }

  ssl_debug_printf("\ndissect_dtls enter frame #%u (%s)\n", pinfo->num, pinfo->fd->visited ? "already visited" : "first time");
  is_from_server = ssl_packet_from_server(session, dtls_associations, pinfo);

  /* try decryption only the first time we see this packet
   * (to keep cipher synchronized) */
  if (pinfo->fd->visited)
    ssl_session = NULL;

  /* Initialize the protocol column; we'll set it later when we
   * figure out what flavor of DTLS it is */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DTLS");

  /* clear the info column */
  col_clear(pinfo->cinfo, COL_INFO);

  /* Create display subtree for SSL as a whole */
  ti = proto_tree_add_item(tree, proto_dtls, tvb, 0, -1, ENC_NA);
  dtls_tree = proto_item_add_subtree(ti, ett_dtls);

  /* iterate through the records in this tvbuff */
  while (tvb_reported_length_remaining(tvb, offset) != 0)
    {
      /* first try to dispatch off the cached version
       * known to be associated with the conversation
       *
       * In fact, all versions of DTLS have the same dissector. Note as
       * we don't set DTLS as the conversation dissector, either
       * looks_like_dtls() passed in dissect_dtls_heur(), or this has
       * been set to DTLS explicitly via the port or some other method,
       * so we already think this is DTLS. We don't expect Continuation
       * Data over UDP datagrams (unlike TCP segments), but we'll check
       * the content type in dissect_dtls_record and mark as Continuation
       * Data if an unknown type, so the only thing calling looks_like_dtls()
       * here would do is additionally verify the legacy_record_version -
       * which MUST be ignored for all purposes per RFC 9147.
       */
      switch(session->version) {
      case DTLSV1DOT0_VERSION:
      case DTLSV1DOT0_OPENSSL_VERSION:
      case DTLSV1DOT2_VERSION:
      case DTLSV1DOT3_VERSION:
      default:
        offset = dissect_dtls_record(tvb, pinfo, dtls_tree,
                                     offset, session, is_from_server,
                                     ssl_session, curr_layer_num_ssl);
        break;
      }
    }

  // XXX there is no Follow DTLS Stream, is this tap needed?
  tap_queue_packet(dtls_tap, pinfo, NULL);
  return tvb_captured_length(tvb);
}

static uint8_t dtls_cid_length(SslSession *session, bool is_from_server)
{
  uint8_t cid_length;

  if (is_from_server) {
    if (session && session->client_cid_len_present) {
      cid_length = session->client_cid_len;
    } else {
      cid_length = (uint8_t)dtls_default_client_cid_length;
    }
  } else {
    if (session && session->server_cid_len_present) {
      cid_length = session->server_cid_len;
    } else {
      cid_length = (uint8_t)dtls_default_server_cid_length;
    }
  }

  return cid_length;
}

static bool
dissect_dtls_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)

{
  /* Stronger confirmation of DTLS packet is provided by verifying the
   * captured payload length against the remainder of the UDP packet size. */
  unsigned length = tvb_captured_length(tvb);
  unsigned offset = 0;
  unsigned record_length = 0;
  SslDecryptSession *ssl_session = NULL;
  SslSession *session = NULL;

  if (tvb_reported_length(tvb) == length) {
    /* The entire payload was captured. */
    while (offset + 13 <= length && looks_like_dtls(tvb, offset)) {
      /* Advance offset to the end of the current DTLS record */
      uint8_t record_type = tvb_get_uint8(tvb, offset);

      if ((record_type & DTLS13_FIXED_MASK) >> 5 == 1) {
        offset += 1;
        /* With the DTLS 1.3 Unified Header, the legacy_record_version
         * field is encrypted, so our heuristics are weaker. Only accept
         * the frame if we already have seen DTLS (with the correct CID,
         * if the CID is included) on the connection.
         * N.B. - We don't call conversation_set_dissector_from_frame_number
         * like in packet-tls.c because DTLS is commonly multiplexed with
         * SRTP/SRTCP/STUN/TURN/ZRTP per RFC 7983. (And now QUIC, RFC 9443.)
         */
        if (record_type & DTLS13_C_BIT_MASK) {
          /* CID length is not embedded in the packet */
          ssl_session = ssl_get_session_by_cid(tvb, offset);
          session = ssl_session ? &ssl_session->session : NULL;
          int is_from_server = ssl_packet_from_server(session, dtls_associations, pinfo);
          offset += dtls_cid_length(session, is_from_server);
        } else {
          /* No CID, just look for a session on this conversation. Don't
           * call ssl_get_session here, as we don't want to allocate a new
           * session. */
          conversation_t *conversation = find_or_create_conversation(pinfo);
          ssl_session = conversation_get_proto_data(conversation, proto_dtls);
          session = ssl_session ? &ssl_session->session : NULL;
        }
        if (session == NULL) {
          return false;
        }
        offset += (record_type & DTLS13_S_BIT_MASK) ? 2 : 1;
        if (record_type & DTLS13_L_BIT_MASK) {
          record_length = tvb_get_ntohs(tvb, offset);
          offset += 2;
        } else {
          /* Length not present, so the heuristic is weaker. */
          record_length = tvb_reported_length_remaining(tvb, offset);
        }
      } else {
        offset += 11;
        if (record_type == SSL_ID_TLS12_CID) {
          /* CID length is not embedded in the packet */
          ssl_session = ssl_get_session_by_cid(tvb, offset);
          session = ssl_session ? &ssl_session->session : NULL;
          int is_from_server = ssl_packet_from_server(session, dtls_associations, pinfo);
          offset += dtls_cid_length(session, is_from_server);
        }
        record_length = tvb_get_ntohs(tvb, offset);
        offset += 2;
      }
      offset += record_length;
      if (offset == length) {
        dissect_dtls(tvb, pinfo, tree, data);
        return true;
      }
    }

    if (pinfo->fragmented && offset >= 13) {
      dissect_dtls(tvb, pinfo, tree, data);
      return true;
    }
    return false;
  }

  /* This packet was truncated by the capture process due to a snapshot
   * length - do our best with what we've got. */
  while (tvb_captured_length_remaining(tvb, offset) >= 3) {
    if (!looks_like_dtls(tvb, offset))
      return false;

    offset += 3;
    if (tvb_captured_length_remaining(tvb, offset) >= 10 ) {
      offset += tvb_get_ntohs(tvb, offset + 8) + 10;
    } else {
      /* Dissect what we've got, which might be as little as 3 bytes. */
      dissect_dtls(tvb, pinfo, tree, data);
      return true;
    }
    if (offset == length) {
      /* Can this ever happen?  Well, just in case ... */
      dissect_dtls(tvb, pinfo, tree, data);
      return true;
    }
  }

  /* One last check to see if the current offset is at least less than the
   * original number of bytes present before truncation or we're dealing with
   * a packet fragment that's also been truncated. */
  if ((length >= 3) && (offset <= tvb_reported_length(tvb) || pinfo->fragmented)) {
    dissect_dtls(tvb, pinfo, tree, data);
    return true;
  }
  return false;
}

static bool
dtls_is_null_cipher(unsigned cipher )
{
  switch(cipher) {
  case 0x0000:
  case 0x0001:
  case 0x0002:
  case 0x002c:
  case 0x002d:
  case 0x002e:
  case 0x003b:
  case 0x00b0:
  case 0x00b1:
  case 0x00b4:
  case 0x00b5:
  case 0x00b8:
  case 0x00b9:
  case 0xc001:
  case 0xc006:
  case 0xc00b:
  case 0xc010:
  case 0xc015:
  case 0xc039:
  case 0xc03a:
  case 0xc03b:
    return true;
  default:
    return false;
  }
}

static void
dtls_save_decrypted_record(packet_info *pinfo, int record_id, uint8_t content_type, uint8_t curr_layer_num_ssl, bool inner_content_type)
{
    const unsigned char *data = dtls_decrypted_data.data;
    unsigned datalen = dtls_decrypted_data_avail;

    if (datalen == 0) {
        return;
    }

    if (content_type == SSL_ID_TLS12_CID || inner_content_type) {
        /*
         * The actual data is followed by the content type and then zero or
         * more padding. Scan backwards for content type, skipping padding.
         */
        while (datalen > 0 && data[datalen - 1] == 0) {
            datalen--;
        }
        ssl_debug_printf("%s found %d padding bytes\n", G_STRFUNC, dtls_decrypted_data_avail - datalen);
        if (datalen == 0) {
            ssl_debug_printf("%s there is no room for content type!\n", G_STRFUNC);
            return;
        }
        content_type = data[--datalen];
        if (datalen == 0) {
            return;
        }
    }

    ssl_add_record_info(proto_dtls, pinfo, data, datalen, record_id, NULL, (ContentType)content_type, curr_layer_num_ssl);
}

static bool
decrypt_dtls_record(tvbuff_t *tvb, packet_info *pinfo, uint32_t offset, SslDecryptSession *ssl,
                    uint8_t content_type, uint16_t record_version, uint16_t record_length, uint8_t curr_layer_num_ssl,
                    const unsigned char *cid, uint8_t cid_length)
{
  bool        success;
  SslDecoder *decoder;

  /* if we can decrypt and decryption have success
   * add decrypted data to this packet info */
  if (!ssl || ((ssl->session.version != DTLSV1DOT3_VERSION) && !(ssl->state & SSL_HAVE_SESSION_KEY))) {
    ssl_debug_printf("decrypt_dtls_record: no session key\n");
    return false;
  }
  ssl_debug_printf("decrypt_dtls_record: app_data len %d, ssl state %X\n",
                   record_length, ssl->state);

  /* retrieve decoder for this packet direction */
  if (ssl_packet_from_server(&ssl->session, dtls_associations, pinfo) != 0) {
    ssl_debug_printf("decrypt_dtls_record: using server decoder\n");
    decoder = ssl->server;
  }
  else {
    ssl_debug_printf("decrypt_dtls_record: using client decoder\n");
    decoder = ssl->client;
  }

  if (!decoder && !dtls_is_null_cipher(ssl->session.cipher)) {
    ssl_debug_printf("decrypt_dtls_record: no decoder available\n");
    return false;
  }

  /* ensure we have enough storage space for decrypted data */
  if (record_length > dtls_decrypted_data.data_len)
    {
      ssl_debug_printf("decrypt_dtls_record: allocating %d bytes"
                       " for decrypt data (old len %d)\n",
                       record_length + 32, dtls_decrypted_data.data_len);
      dtls_decrypted_data.data = (unsigned char *)g_realloc(dtls_decrypted_data.data,
                                           record_length + 32);
      dtls_decrypted_data.data_len = record_length + 32;
    }

  /* run decryption and add decrypted payload to protocol data, if decryption
   * is successful*/
  dtls_decrypted_data_avail = dtls_decrypted_data.data_len;
  if (ssl->state & SSL_HAVE_SESSION_KEY || ssl->session.version == DTLSV1DOT3_VERSION) {
    if (!decoder) {
      ssl_debug_printf("decrypt_dtls_record: no decoder available\n");
      return false;
    }
    success = ssl_decrypt_record(ssl, decoder, content_type, record_version, false,
                           tvb_get_ptr(tvb, offset, record_length), record_length, cid, cid_length,
                           &dtls_compressed_data, &dtls_decrypted_data, &dtls_decrypted_data_avail) == 0;
  }
  else if (dtls_is_null_cipher(ssl->session.cipher)) {
    /* Non-encrypting cipher NULL-XXX */
    tvb_memcpy(tvb, dtls_decrypted_data.data, offset, record_length);
    dtls_decrypted_data_avail = dtls_decrypted_data.data_len = record_length;
    success = true;
  } else {
    success = false;
  }

  if (success) {
    dtls_save_decrypted_record(pinfo, tvb_raw_offset(tvb)+offset, content_type, curr_layer_num_ssl, ssl->session.version == DTLSV1DOT3_VERSION);
  }
  return success;
}

static void
export_pdu_packet(tvbuff_t *tvb, packet_info *pinfo, uint8_t tag, const char *name)
{
  exp_pdu_data_t *exp_pdu_data = export_pdu_create_common_tags(pinfo, name, tag);

  exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
  exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
  exp_pdu_data->pdu_tvb = tvb;

  tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
}


/*********************************************************************
 *
 * DTLS Dissection Routines
 *
 *********************************************************************/

static void
dissect_dtls_appdata(tvbuff_t *tvb, packet_info *pinfo, uint32_t offset,
                     uint32_t record_length, SslSession *session,
                     proto_tree *dtls_record_tree, bool is_from_server,
                     tvbuff_t *decrypted, SslRecordInfo *record)
{
  heur_dtbl_entry_t *hdtbl_entry;
  proto_item *ti;
  /* show on info column what we are decoding */
  col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Application Data");

  /* app_handle discovery is done here instead of dissect_dtls_payload()
   * because the protocol name needs to be displayed below. */
  if (!session->app_handle) {
    /* Unknown protocol handle, ssl_starttls_ack was not called before.
     * Try to find an appropriate dissection handle and cache it. */
    dissector_handle_t handle;
    handle = dissector_get_uint_handle(dtls_associations, pinfo->srcport);
    handle = handle ? handle : dissector_get_uint_handle(dtls_associations, pinfo->destport);
    if (handle) session->app_handle = handle;
  }

  proto_item_set_text(dtls_record_tree,
                      "%s Record Layer: %s Protocol: %s",
                      val_to_str_const(session->version, ssl_version_short_names, "DTLS"),
                      val_to_str_const(SSL_ID_APP_DATA, ssl_31_content_type, "unknown"),
                      session->app_handle
                      ? dissector_handle_get_protocol_long_name(session->app_handle)
                      : "Application Data");

  proto_tree_add_item(dtls_record_tree, hf_dtls_record_appdata, tvb,
                      offset, record_length, ENC_NA);

  if (session->app_handle) {
    ti = proto_tree_add_string(dtls_record_tree, hf_dtls_record_appdata_proto, tvb, 0, 0, dissector_handle_get_protocol_long_name(session->app_handle));
    proto_item_set_generated(ti);
  }

  /* show decrypted data info, if available */
  if (decrypted) {
    bool  dissected;
    uint16_t  saved_match_port;
    /* try to dissect decrypted data*/
    ssl_debug_printf("%s decrypted len %d\n", G_STRFUNC, record->data_len);

    saved_match_port = pinfo->match_uint;
    if (is_from_server) {
      pinfo->match_uint = pinfo->srcport;
    } else {
      pinfo->match_uint = pinfo->destport;
    }

    /* find out a dissector using server port*/
    if (session->app_handle) {
      ssl_debug_printf("%s: found handle %p (%s)\n", G_STRFUNC,
                       (void *)session->app_handle,
                       dissector_handle_get_dissector_name(session->app_handle));
      ssl_print_data("decrypted app data", record->plain_data, record->data_len);

      if (have_tap_listener(exported_pdu_tap)) {
        export_pdu_packet(decrypted, pinfo, EXP_PDU_TAG_DISSECTOR_NAME,
                          dissector_handle_get_dissector_name(session->app_handle));
      }

      dissected = (bool)call_dissector_only(session->app_handle, decrypted, pinfo, top_tree, NULL);
    }
    else {
      /* try heuristic subdissectors */
      dissected = dissector_try_heuristic(heur_subdissector_list, decrypted, pinfo, top_tree, &hdtbl_entry, NULL);
      if (dissected && have_tap_listener(exported_pdu_tap)) {
        export_pdu_packet(decrypted, pinfo, EXP_PDU_TAG_HEUR_DISSECTOR_NAME, hdtbl_entry->short_name);
      }
    }
    pinfo->match_uint = saved_match_port;
    /* fallback to data dissector */
    if (!dissected)
      call_data_dissector(decrypted, pinfo, top_tree);
    }
}
/* Dissect a DTLS record from version 1.2 and below */
static int
dissect_dtls_record(tvbuff_t *tvb, packet_info *pinfo,
                    proto_tree *tree, uint32_t offset,
                    SslSession *session, int is_from_server,
                    SslDecryptSession* ssl,
                    uint8_t curr_layer_num_ssl)
{

  /*
   *    struct {
   *        uint8 major, minor;
   *    } ProtocolVersion;
   *
   *
   *    enum {
   *        change_cipher_spec(20), alert(21), handshake(22),
   *        application_data(23), (255)
   *    } ContentType;
   *
   *    struct {
   *        ContentType type;
   *        ProtocolVersion version;
   *        uint16 epoch;               // New field
   *        uint48 sequence_number;     // New field
   *        uint16 length;
   *        opaque fragment[TLSPlaintext.length];
   *    } DTLSPlaintext;
   *
   *
   * draft-ietf-tls-dtls-connection-id-07:
   *
   *    struct {
   *        ContentType special_type = tls12_cid;
   *        ProtocolVersion version;
   *        uint16 epoch;
   *        uint48 sequence_number;
   *        opaque cid[cid_length];               // New field
   *        uint16 length;
   *        opaque enc_content[DTLSCiphertext.length];
   *    } DTLSCiphertext;
   *
   */

  uint32_t        dtls_record_length;
  uint32_t        record_length;
  uint16_t        version;
  uint16_t        epoch;
  uint64_t        sequence_number;
  uint8_t         content_type;
  unsigned        content_type_offset;
  uint8_t         next_byte;
  proto_tree     *ti;
  proto_tree     *dtls_record_tree;
  proto_item     *length_pi, *ct_pi;
  tvbuff_t       *decrypted;
  SslRecordInfo  *record = NULL;
  uint8_t        *cid = NULL;
  uint8_t         cid_length;

  /* Connection ID length to use if any */
  cid_length = dtls_cid_length(session, is_from_server);

  /*
   * Get the record layer fields of interest
   */
  content_type          = tvb_get_uint8(tvb, offset);
  if ((content_type & DTLS13_FIXED_MASK) >> 5 == 1) {
    /* RFC 9147 s4.1: this is a DTLS 1.3 Unified Header record */
    return dissect_dtls13_record(tvb, pinfo, tree, offset, session,
                               is_from_server, ssl, curr_layer_num_ssl);
  }
  version               = tvb_get_ntohs(tvb, offset + 1);
  epoch                 = tvb_get_ntohs(tvb, offset + 3);
  sequence_number       = tvb_get_ntoh48(tvb, offset + 5);

  if (content_type == SSL_ID_TLS12_CID && cid_length > 0) {
    cid = tvb_memdup(pinfo->pool, tvb, offset + 11, cid_length);
    record_length = tvb_get_ntohs(tvb, offset + cid_length + 11);
    dtls_record_length = 13 + cid_length + record_length;
  } else {
    record_length = tvb_get_ntohs(tvb, offset + 11);
    dtls_record_length = 13 + record_length;
  }

  if (!ssl_is_valid_content_type(content_type)) {

    /* if we don't have a valid content_type, there's no sense
     * continuing any further
     */
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Continuation Data");

    /* If GUI, show unrecognized data in tree */
    ti = proto_tree_add_item(tree, hf_dtls_record, tvb,
                                offset, dtls_record_length, ENC_NA);
    dtls_record_tree = proto_item_add_subtree(ti, ett_dtls_record);
    proto_item_set_text(dtls_record_tree, "%s Record Layer: unrecognized content type 0x%02x",
                        val_to_str_const(session->version, ssl_version_short_names, "DTLS"),
                        content_type);

    return offset + dtls_record_length;
  }

  if (ssl) {
    if (is_from_server) {
      if (ssl->server) {
        ssl->server->seq = sequence_number;
        ssl->server->epoch = epoch;
      }
    } else {
      if (ssl->client) {
        ssl->client->seq = sequence_number;
        ssl->client->epoch = epoch;
      }
    }
  }

  /*
   * If GUI, fill in record layer part of tree
   */

  /* add the record layer subtree header */
  ti = proto_tree_add_item(tree, hf_dtls_record, tvb,
                               offset, dtls_record_length, ENC_NA);
  dtls_record_tree = proto_item_add_subtree(ti, ett_dtls_record);

  /* show the one-byte content type */
  if (content_type == SSL_ID_TLS12_CID) {
      ct_pi = proto_tree_add_item(dtls_record_tree, hf_dtls_record_special_type,
                                  tvb, offset, 1, ENC_BIG_ENDIAN);
  } else {
      ct_pi = proto_tree_add_item(dtls_record_tree, hf_dtls_record_content_type,
                                  tvb, offset, 1, ENC_BIG_ENDIAN);
  }
  content_type_offset = offset;
  offset++;

  /* add the version */
  proto_tree_add_item(dtls_record_tree, hf_dtls_record_version, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /* show epoch */
  proto_tree_add_uint(dtls_record_tree, hf_dtls_record_epoch, tvb, offset, 2, epoch);
  offset += 2;

  /* add sequence_number */
  proto_tree_add_uint64(dtls_record_tree, hf_dtls_record_sequence_number, tvb, offset, 6, sequence_number);
  offset += 6;

  if (content_type == SSL_ID_TLS12_CID) {
    /* add connection ID */
    proto_tree_add_item(dtls_record_tree, hf_dtls_record_connection_id, tvb, offset, cid_length, ENC_NA);
    offset += cid_length;
  }

  /* add the length */
  length_pi = proto_tree_add_uint(dtls_record_tree, hf_dtls_record_length, tvb,
                        offset, 2, record_length);
  offset += 2;    /* move past length field itself */

  /*
   * if we don't already have a version set for this conversation,
   * but this message's version is authoritative (i.e., it's
   * not client_hello), then save the version to the conversation
   * structure and print the column version.
   */
  next_byte = tvb_get_uint8(tvb, offset);
  if (session->version == SSL_VER_UNKNOWN) {
    if (version == DTLSV1DOT2_VERSION && content_type == SSL_ID_HANDSHAKE) {
      /*
       * if the version in the header is DTLS 1.2, this may actually be
       * a DTLS 1.3 handshake; this must be determined from any
       * supported_versions extension in the hello messages. We'll check
       * this later in dissect_dtls_handshake, but try to get the column
       * correct here on the first pass if we can.
       */
      if (next_byte == SSL_HND_SERVER_HELLO && record_length > 12 && tvb_bytes_exist(tvb, offset, 12)) {
        uint32_t fragment_offset = tvb_get_ntoh24(tvb, offset + 6);
        uint32_t fragment_length = tvb_get_ntoh24(tvb, offset + 9);
        if (fragment_offset == 0 && tvb_bytes_exist(tvb, offset + 12, fragment_length)) {
          /* Only look at the first fragment. */
          tls_scan_server_hello(tvb, offset + 12, offset + 12 + fragment_length, &version, NULL);
        }
      }
    }
    ssl_try_set_version(session, ssl, content_type, next_byte, true, version);
  }
  col_set_str(pinfo->cinfo, COL_PROTOCOL,
      val_to_str_const(session->version, ssl_version_short_names, "DTLS"));

  /*
   * now dissect the next layer
   */
  ssl_debug_printf("dissect_dtls_record: content_type %d epoch %d seq %"PRIu64"\n", content_type, epoch, sequence_number);

  /* try to decrypt record on the first pass, if possible. Store decrypted
   * record for later usage (without having to decrypt again).
   * DTLSv1.3 records are decrypted from dissect_dtls13_record */
  if (ssl && (ssl->session.version != DTLSV1DOT3_VERSION)) {
    decrypt_dtls_record(tvb, pinfo, offset, ssl, content_type, version, record_length, curr_layer_num_ssl, cid, cid_length);
  }
  decrypted = ssl_get_record_info(tvb, proto_dtls, pinfo, tvb_raw_offset(tvb)+offset, curr_layer_num_ssl, &record);
  if (decrypted) {
    add_new_data_source(pinfo, decrypted, "Decrypted DTLS");

    if (content_type == SSL_ID_TLS12_CID) {
      content_type = record->type;
      ti = proto_tree_add_uint(dtls_record_tree, hf_dtls_record_content_type,
                               tvb, content_type_offset, 1, record->type);
      proto_item_set_generated(ti);
    }
  }
  ssl_check_record_length(&dissect_dtls_hf, pinfo, (ContentType)content_type, record_length, length_pi, session->version, decrypted);

  /* extract the real record from the connection ID record */
  if (content_type == SSL_ID_TLS12_CID) {
      proto_item_set_text(dtls_record_tree, "%s Record Layer: Connection ID",
                          val_to_str_const(session->version, ssl_version_short_names, "DTLS"));

    /* if content cannot be deciphered or the content is invalid */
    if (decrypted == NULL) {
      col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Connection ID");
      proto_tree_add_item(dtls_record_tree, hf_dtls_record_encrypted_content, tvb,
                          offset, record_length, ENC_NA);
      offset += record_length; /* skip to end of record */
      return offset;
    }
  }

  switch ((ContentType) content_type) {
  case SSL_ID_CHG_CIPHER_SPEC:
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Change Cipher Spec");
    ssl_dissect_change_cipher_spec(&dissect_dtls_hf, tvb, pinfo,
                                   dtls_record_tree, offset, session,
                                   is_from_server, ssl);
    if (ssl) {
        ssl_finalize_decryption(ssl, tls_get_master_key_map(true));
        ssl_change_cipher(ssl, is_from_server);
    }
    /* Heuristic: any later ChangeCipherSpec is not a resumption of this
     * session. Set the flag after ssl_finalize_decryption such that it has
     * a chance to use resume using Session Tickets. */
    if (is_from_server)
      session->is_session_resumed = false;
    break;
  case SSL_ID_ALERT:
    {
      /* try to retrieve and use decrypted alert record, if any. */
      if (decrypted) {
        dissect_dtls_alert(decrypted, pinfo, dtls_record_tree, 0,
                           session);
      } else {
        dissect_dtls_alert(tvb, pinfo, dtls_record_tree, offset,
                           session);
      }
      break;
    }
  case SSL_ID_HANDSHAKE:
    {
      /* try to retrieve and use decrypted handshake record, if any. */
      if (decrypted) {
        dissect_dtls_handshake(decrypted, pinfo, dtls_record_tree, 0,
                               tvb_reported_length(decrypted), false, session, is_from_server,
                               ssl, content_type);
      } else {
        dissect_dtls_handshake(tvb, pinfo, dtls_record_tree, offset,
                               record_length, true, session, is_from_server, ssl,
                               content_type);
      }
      break;
    }
  case SSL_ID_APP_DATA:
    dissect_dtls_appdata(tvb, pinfo, offset, record_length, session,
                         dtls_record_tree, is_from_server, decrypted, record);
    break;
  case SSL_ID_HEARTBEAT:
    /* try to retrieve and use decrypted alert record, if any. */
    if (decrypted) {
      dissect_dtls_heartbeat(decrypted, pinfo, dtls_record_tree, 0,
                             session, tvb_reported_length (decrypted), true);
    } else {
      dissect_dtls_heartbeat(tvb, pinfo, dtls_record_tree, offset,
                             session, record_length, false);
    }
    break;
  case SSL_ID_TLS12_CID:
    expert_add_info_format(pinfo, ct_pi, &ei_dtls_cid_invalid_content_type,
                           "Invalid content type (%d)", content_type);
    break;
  case SSL_ID_DTLS13_ACK:
    if (decrypted) {
      dissect_dtls_ack(decrypted, pinfo, dtls_record_tree, 0, tvb_reported_length(decrypted));
    } else {
      dissect_dtls_ack(tvb, pinfo, dtls_record_tree, offset, record_length);
    }
  }
  offset += record_length; /* skip to end of record */

  return offset;
}


/* setup cryptographic keys based on dtls13_current_epoch */
static int
dtls13_load_keys_from_epoch(SslDecryptSession *session, bool is_from_server, uint64_t epoch)
{
  ssl_master_key_map_t *master_key_map = NULL;
  TLSRecordType secret_type;
  SslDecoder *dec;

  if (!session) {
    ssl_debug_printf("dtls13_load_keys_from_epoch: no session\n");
    return -1;
  }

  dec = NULL;
  if (is_from_server)
    dec = session->server;
  else
    dec = session->client;

  if (dec && dec->dtls13_epoch == epoch)
    return 0;

  /* The DTLS dissector does not support decrypting packets from epoch < N once
   * it decrypted a packet from epoch N.  In order to do that, the dissector
   * needs to maintain the expected next sequence number per epoch. The added
   * complexity makes it not worthwhile. */
  if (dec && dec->dtls13_epoch > epoch) {
    ssl_debug_printf("%s: refuse to load past epoch %" PRIu64"\n", G_STRFUNC, epoch);
    return 0;
  }

  /* double check that we increment the epoch by one after hs */
  if (dec && dec->dtls13_epoch != 0 && epoch != dec->dtls13_epoch + 1)
    return 0;

  master_key_map = tls_get_master_key_map(true);
  if (master_key_map == NULL) {
    ssl_debug_printf("dtls13_load_keys_from_epoch: no master key map\n");
    return -1;
  }

  switch (epoch)
  {
  case 1:
    secret_type = TLS_SECRET_0RTT_APP;
    tls13_change_key(session, master_key_map, is_from_server, secret_type);
    break;
  case 2:
    secret_type = TLS_SECRET_HANDSHAKE;
    tls13_change_key(session, master_key_map, is_from_server, secret_type);
    break;
  case 3:
    secret_type = TLS_SECRET_APP;
    tls13_change_key(session, master_key_map, is_from_server, secret_type);
    break;
  default:
    tls13_key_update(session, is_from_server);
    break;
  }

  if (is_from_server && session->server) {
    session->server->dtls13_epoch = epoch;
  } else if (session->client) {
    session->client->dtls13_epoch = epoch;
  }

  return 0;
}


/**
 * Reconstructs sequence numbers in DTLS 1.3.
 *
 * This function takes the expected sequence number, the low bits of the sequence number,
 * and a mask as input. It finds the closest number to the expected sequence number that
 * has the lower bits equal to @seq_low_bits.
 * @param expected_seq_number The expected sequence number.
 * @param seq_low_bits The low bits of the sequence number (encrypted).
 * @param len The length of @enc_seq_low_bits.
 * @param dec_mask The decryption mask for @enc_seq_low_bits.
 * @return The reconstructed dequeued sequence number.
 */
static uint64_t dtls13_reconstruct_seq_number(uint64_t expected_seq_number, uint16_t seq_low_bits,
                                             int len, uint8_t *dec_mask)
{
  uint16_t expected_low_bits;
  uint64_t c1, c2, d1, d2;
  uint16_t mask;

  /* we just need 1 or 2 bytes of the xor mask */
  if (len == 1) {
    dec_mask[1] = 0;
  }
  seq_low_bits ^= (dec_mask[0] << 8 | dec_mask[1]);

  mask = (len == 2) ? 0xffff : 0xff;
  expected_low_bits = expected_seq_number & mask;
  c1 = (expected_seq_number & ~(mask)) | seq_low_bits;

  if (expected_low_bits == seq_low_bits) {
    return c1;
  }
  if (expected_low_bits < seq_low_bits) {
    d1 = c1 - expected_seq_number;
    c2 = c1 - (mask + 1);
    d2 = expected_seq_number - c2;
  } else {
    d1 = expected_seq_number - c1;
    c2 = c1 + (mask + 1);
    d2 = c2 - expected_seq_number;
  }

  if (d1 < d2)
    return c1;
  return c2;
}

#define DTLS13_RECORD_NUMBER_MASK_SZ 16
static int dtls13_get_record_number_xor_mask(SslDecoder *dec, const uint8_t *ciphertext, uint8_t *mask)
{
  if (!dec->cipher_suite)
    return -1;

  if (dec->cipher_suite->enc == ENC_NULL) {
    memset(mask, 0, DTLS13_RECORD_NUMBER_MASK_SZ);
    return 0;
  }

  if (!dec->sn_evp) {
    return -1;
  }

  if (dec->cipher_suite->enc == ENC_AES || dec->cipher_suite->enc == ENC_AES256) {
    if (gcry_cipher_encrypt(dec->sn_evp, mask, DTLS13_RECORD_NUMBER_MASK_SZ,
                            ciphertext, DTLS13_RECORD_NUMBER_MASK_SZ) != 0) {
      ssl_debug_printf("dtls1.3: record mask generation failed\n");
      return -1;
    }
    return 0;
  }

  if (dec->cipher_suite->enc == ENC_CHACHA20) {
    if (gcry_cipher_setiv(dec->sn_evp, ciphertext, DTLS13_RECORD_NUMBER_MASK_SZ) != 0) {
      ssl_debug_printf("dtls1.3: record mask generation failed: can't set iv\n");
      return -1;
    }
    memset(mask, 0, DTLS13_RECORD_NUMBER_MASK_SZ);
    if (gcry_cipher_encrypt(dec->sn_evp, mask, DTLS13_RECORD_NUMBER_MASK_SZ, mask, DTLS13_RECORD_NUMBER_MASK_SZ) != 0) {
      ssl_debug_printf("dtls1.3: record mask generation failed\n");
      return -1;
    }
     return 0;
  }

  ssl_debug_printf("dtls1.3: unsupported cipher\n");
  return -1;
}

static bool dtls13_create_aad(tvbuff_t *tvb, SslDecryptSession *ssl, bool is_from_server, uint8_t hdr_flags, uint32_t hdr_off, uint32_t hdr_size,
                                  uint64_t sequence_number, uint16_t dtls_record_length)
{
  unsigned int cid_length = 0;
  SslDecoder *dec = NULL;
  int seq_length;

  if (is_from_server && ssl->server) {
    dec = ssl->server;
  } else if (ssl->client) {
    dec = ssl->client;
  }
  if (!dec)
    return false;

  dec->seq = sequence_number;
  dec->dtls13_aad.data = wmem_realloc(wmem_file_scope(), dec->dtls13_aad.data, hdr_size);
  dec->dtls13_aad.data_len = hdr_size;
  dec->dtls13_aad.data[0] = hdr_flags;
  cid_length = 0;

  seq_length = 1;
  if (hdr_flags & DTLS13_S_BIT_MASK)
    seq_length = 2;
  if (hdr_flags & DTLS13_C_BIT_MASK) {
    /* total - 1 byte for hdr flag, 1 or 2 byte for seq suffix, 0 or 2 bytes for len */
    cid_length = hdr_size - 1 - seq_length;
    if (hdr_flags & DTLS13_L_BIT_MASK)
      cid_length -= 2;
    DISSECTOR_ASSERT(cid_length < hdr_size);
    memcpy(&dec->dtls13_aad.data[1], tvb_get_ptr(tvb, hdr_off + 1, cid_length), cid_length);
  }

  if (seq_length == 2) {
    phton16(&dec->dtls13_aad.data[1 + cid_length], sequence_number);
  } else {
    dec->dtls13_aad.data[1 + cid_length] = sequence_number;
  }
  if (hdr_flags & DTLS13_L_BIT_MASK) {
      phton16(&dec->dtls13_aad.data[1 + cid_length + seq_length], dtls_record_length);
  }

  return true;
}

static bool dtls13_decrypt_unified_record(tvbuff_t *tvb, packet_info *pinfo, uint32_t hdr_off, uint32_t hdr_size,
                                              uint8_t hdr_flags, bool is_from_server,
                                              SslDecryptSession *ssl, uint32_t dtls_record_length, uint8_t curr_layer_num_ssl,
                                              uint16_t seq_suffix, uint8_t seq_length)
{
  uint8_t mask[DTLS13_RECORD_NUMBER_MASK_SZ];
  uint64_t sequence_number;
  SslDecoder *dec = NULL;
  bool success;

  if (is_from_server && ssl->server) {
    dec = ssl->server;
  } else if (ssl->client) {
    dec = ssl->client;
  }

  if (dec == NULL) {
    ssl_debug_printf("dissect_dtls13_record: no decoder available\n");
    return false;
  }

  if (dtls13_get_record_number_xor_mask(dec, tvb_get_ptr(tvb, hdr_off + hdr_size, DTLS13_RECORD_NUMBER_MASK_SZ), mask) != 0) {
    ssl_debug_printf("dissect_dtls13_record: can't get record number mask\n");
    return false;
  }

  sequence_number = dtls13_reconstruct_seq_number(ssl->session.dtls13_next_seq_num[is_from_server], seq_suffix, seq_length, mask);

  /* setup parameter for decryption of this packet */
  if (!dtls13_create_aad(tvb, ssl, is_from_server, hdr_flags, hdr_off, hdr_size, sequence_number, dtls_record_length)) {
    ssl_debug_printf("%s: can't create AAD\n", G_STRFUNC);
    return false;
  }

  /* CID is already included in dtls13_add, there is no need to add it here */
  success = decrypt_dtls_record(tvb, pinfo, hdr_off + hdr_size, ssl, 0, ssl->session.version, dtls_record_length, curr_layer_num_ssl, NULL, 0);
  if (sequence_number >= ssl->session.dtls13_next_seq_num[is_from_server]) {
    ssl->session.dtls13_next_seq_num[is_from_server] = sequence_number + 1;
  }

  return success;
}

/**
 * Try to guess the early data cipher using trial decryption. based on decrypt_tls13_early_data.
 * Requires Libgcrypt 1.6 or newer for verifying that decryption is successful.
 */
static bool
dtls13_decrypt_early_data(tvbuff_t *tvb, packet_info *pinfo, uint32_t hdr_off, uint32_t hdr_size, uint8_t hdr_flags,
                          uint16_t record_length, SslDecryptSession *ssl,
                          uint8_t curr_layer_num_ssl, uint16_t seq_suffix, uint8_t seq_length)
{
  StringInfo *secret;

  static const uint16_t tls13_ciphers[] = {
      0x1301, /* TLS_AES_128_GCM_SHA256 */
      0x1302, /* TLS_AES_256_GCM_SHA384 */
      0x1303, /* TLS_CHACHA20_POLY1305_SHA256 */
      0x1304, /* TLS_AES_128_CCM_SHA256 */
      0x1305, /* TLS_AES_128_CCM_8_SHA256 */
  };

  bool success = false;

  ssl_debug_printf("Trying early data encryption, first record / trial decryption: %s\n",
                  !(ssl->state & SSL_SEEN_0RTT_APPDATA) ? "true" : "false");


  secret = tls13_load_secret(ssl, tls_get_master_key_map(true), false, TLS_SECRET_0RTT_APP);
  if (!secret) {
      ssl_debug_printf("Missing secrets, early data decryption not possible!\n");
      return false;
  }

  for (unsigned i = 0; i < G_N_ELEMENTS(tls13_ciphers); i++) {
      uint16_t cipher = tls13_ciphers[i];

      ssl_debug_printf("Performing early data trial decryption, cipher = %#x\n", cipher);
      ssl->session.cipher = cipher;
      ssl->cipher_suite = ssl_find_cipher(cipher);
      if (!tls13_generate_keys(ssl, secret, false)) {
          /* Unable to create cipher (old Libgcrypt) */
          continue;
      }

      success = dtls13_decrypt_unified_record(tvb, pinfo, hdr_off, hdr_size, hdr_flags, false, ssl, record_length, curr_layer_num_ssl, seq_suffix, seq_length);
      if (success) {
          /* update epoch number to decrypt other 0RTT packets */
          ssl->client->dtls13_epoch = 1;
          ssl_debug_printf("Early data decryption succeeded, cipher = %#x\n", cipher);
          break;
      }
  }
  if (!success) {
      ssl_debug_printf("Trial decryption of early data failed!\n");
  }
  return success;
}

static bool dtls13_setup_keys(uint8_t hdr_flags, bool is_from_server, SslDecryptSession *ssl, uint32_t dtls_record_length,
                                  bool *first_early_data)
{
  uint64_t epoch, curr_max_epoch;

  epoch = (hdr_flags & DTLS13_HDR_EPOCH_BIT_MASK);

  if (first_early_data != NULL)
    *first_early_data = false;

  /* DTLSv1.3 minimum payload is 16 bytes */
  if (dtls_record_length < 16) {
      ssl_debug_printf("dtls13: record too short\n");
      return false;
  }

  /* determine the epoch */
  curr_max_epoch = ssl->session.dtls13_current_epoch[is_from_server];

  if ((curr_max_epoch & 0x3) != epoch) {
    /* No KeyUpdate seen, we are still in the handshake (epoch 1 or 2) or using traffic_secret_0 (epoch 3) */
    if (curr_max_epoch < 4) {
      if (epoch > curr_max_epoch) {
        ssl->session.dtls13_current_epoch[is_from_server] = epoch;
      }
    } else {

      /* try to decrypt with the last epoch with the same low bits */
      epoch = (curr_max_epoch & ~(0x3)) | epoch;
      if (epoch > curr_max_epoch)
        epoch -= 4;
    }
  } else {
    epoch = curr_max_epoch;
  }

  if (epoch == 0) {
      ssl_debug_printf("dtls13: unified header with epoch 0 (plaintext)\n");
      return false;
  }

  /* early data */
  if (epoch == 1) {
    if (ssl->session.dtls13_current_epoch[is_from_server] > 1) {
      ssl_debug_printf("%s: early data received after encrypted HS, abort decryption\n", G_STRFUNC);
      return false;
    }
    if (!ssl->has_early_data) {
      ssl_debug_printf("%s: early data received but not advertised in CH extensions, abort decryption\n", G_STRFUNC);
      return false;
    }
    /* first early data packet, need to go into trial decryption */
    if (!(ssl->client && (ssl->client->dtls13_epoch == 1))) {
      if (first_early_data != NULL)
        *first_early_data = true;
      return true;
    }
  }

  if (dtls13_load_keys_from_epoch(ssl, is_from_server, epoch) < 0) {
      ssl_debug_printf("dtls13: can't load keys\n");
      return false;
  }

  return true;
}

/* Dissect a DTLS record from version 1.3 */
static int
dissect_dtls13_record(tvbuff_t *tvb, packet_info *pinfo _U_,
                     proto_tree *tree, uint32_t offset,
                     SslSession *session, int is_from_server,
                     SslDecryptSession* ssl,
                     uint8_t curr_layer_num_ssl _U_)
{
  /*
   * struct {
   *     ContentType type;
   *     ProtocolVersion legacy_record_version;
   *     uint16 epoch = 0
   *     uint48 sequence_number;
   *     uint16 length;
   *     opaque fragment[DTLSPlaintext.length];
   * } DTLSPlaintext;
   *
   * struct {
   *      opaque content[DTLSPlaintext.length];
   *      ContentType type;
   *      uint8 zeros[length_of_padding];
   * } DTLSInnerPlaintext;
   *
   * struct {
   *     opaque unified_hdr[variable];
   *     opaque encrypted_record[length];
   * } DTLSCiphertext;
   *
   * unified_hdr:
   *     0 1 2 3 4 5 6 7
   *    +-+-+-+-+-+-+-+-+
   *    |0|0|1|C|S|L|E E|
   *    +-+-+-+-+-+-+-+-+
   *    | Connection ID |   Legend:
   *    | (if any,      |
   *    /  length as    /   C   - Connection ID (CID) present
   *    |  negotiated)  |   S   - Sequence number length
   *    +-+-+-+-+-+-+-+-+   L   - Length present
   *    |  8 or 16 bit  |   E   - Epoch
   *    |Sequence Number|
   *    +-+-+-+-+-+-+-+-+
   *    | 16 bit Length |
   *    | (if present)  |
   *    +-+-+-+-+-+-+-+-+
   */

  static int * const uni_hdr_flags[] = {
    &hf_dtls_uni_hdr_fixed,
    &hf_dtls_uni_hdr_cid,
    &hf_dtls_uni_hdr_seq,
    &hf_dtls_uni_hdr_len,
    &hf_dtls_uni_hdr_epoch,
    NULL
  };

  proto_tree *dtls_record_tree;
  proto_item *ti;
  proto_item *length_pi;
  uint32_t dtls_record_length = 0;

  uint32_t hdr_offset = offset;
  uint32_t hdr_start = offset;
  uint8_t hdr_flags;
  bool c_bit;     /* 1 = Connection ID field is present */
  bool s_bit;     /* 0 = 8-bit sequence number, 1 = 16-bit */
  bool l_bit;     /* 1 = Length field is present */

  uint8_t seq_length;
  uint8_t cid_length = 0;
  uint16_t seq_suffix;
  tvbuff_t *decrypted = NULL;
  SslRecordInfo *record = NULL;
  bool success;
  bool is_first_early_data;

  hdr_flags = tvb_get_uint8(tvb, hdr_offset);
  c_bit = (hdr_flags & DTLS13_C_BIT_MASK) == DTLS13_C_BIT_MASK;
  s_bit = (hdr_flags & DTLS13_S_BIT_MASK) == DTLS13_S_BIT_MASK;
  l_bit = (hdr_flags & DTLS13_L_BIT_MASK) == DTLS13_L_BIT_MASK;
  hdr_offset += 1;

  if (c_bit) {
    /* Connection ID length to use if any */
    cid_length = dtls_cid_length(session, is_from_server);
    hdr_offset += cid_length;
  }

  if (s_bit) {
    /* Lowest 16 bits of the sequence number */
    seq_length = 2;
    seq_suffix = tvb_get_ntohs(tvb, hdr_offset);
  }
  else {
    /* Lowest 8 bits of the sequence number */
    seq_length = 1;
    seq_suffix = tvb_get_uint8(tvb, hdr_offset);
  }
  /* Note: seq_suffix is encrypted if the payload is encrypted,
   * as per RFC 9147 section 4.2.3. To get the real sequence number,
   * we need to decrypt, and *then* use the result to find the sequence
   * number closest to one plus the last sequence number.
   */
  hdr_offset += seq_length;

  if (l_bit) {
    dtls_record_length = tvb_get_ntohs(tvb, hdr_offset);
    hdr_offset += 2;
  }
  else {
    dtls_record_length = tvb_captured_length_remaining(tvb, hdr_offset);
  }

  /*
   * If GUI, fill in record layer part of tree
   */
  col_set_str(pinfo->cinfo, COL_PROTOCOL,
      val_to_str_const(session->version, ssl_version_short_names, "DTLS"));

  ti = proto_tree_add_item(tree, hf_dtls_record, tvb, offset,
                               (hdr_offset - offset) + dtls_record_length, ENC_NA);
  dtls_record_tree = proto_item_add_subtree(ti, ett_dtls_record);

  proto_tree_add_bitmask_with_flags(dtls_record_tree, tvb, offset,
                                    hf_dtls_uni_hdr, ett_dtls_uni_hdr, uni_hdr_flags,
                                    ENC_BIG_ENDIAN, BMT_NO_INT);

  offset += 1;

  if (c_bit && cid_length > 0) {
    proto_tree_add_item(dtls_record_tree, hf_dtls_record_connection_id, tvb, offset, cid_length, ENC_NA);
    offset += cid_length;
  }

  proto_tree_add_uint(dtls_record_tree, hf_dtls_record_sequence_suffix, tvb, offset, seq_length, seq_suffix);
  offset += seq_length;

  if (l_bit) {
    proto_tree_add_item(dtls_record_tree, hf_dtls_record_length, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
  }
  else {
    length_pi = proto_tree_add_uint(dtls_record_tree, hf_dtls_record_length, tvb,
                          offset, 0, dtls_record_length);
    proto_item_set_generated(length_pi);
  }

  if (ssl) {
    success = dtls13_setup_keys(hdr_flags, is_from_server, ssl, dtls_record_length, &is_first_early_data);
    if (success) {
      if (!is_from_server && is_first_early_data) {
        /* try to decrypt early data */
        dtls13_decrypt_early_data(tvb, pinfo, hdr_start, hdr_offset - hdr_start, hdr_flags, dtls_record_length, ssl, curr_layer_num_ssl, seq_suffix, seq_length);
      } else {
        dtls13_decrypt_unified_record(tvb, pinfo, hdr_start, hdr_offset - hdr_start, hdr_flags, is_from_server, ssl, dtls_record_length, curr_layer_num_ssl, seq_suffix, seq_length);
      }
    }
  }

  decrypted = ssl_get_record_info(tvb, proto_dtls, pinfo, tvb_raw_offset(tvb)+offset, curr_layer_num_ssl, &record);
  if (decrypted)
  {
    /* on first pass add seq suffix decrypted info */
    if (ssl) {
      if (is_from_server && ssl->server) {
        record->dtls13_seq_suffix = ssl->server->seq;
      } else if (ssl->client) {
        record->dtls13_seq_suffix = ssl->client->seq;
      }
    }

    ti = proto_tree_add_uint(dtls_record_tree, hf_dtls_record_sequence_suffix_dec, tvb, hdr_start + 1 + cid_length,
                             seq_length, record->dtls13_seq_suffix);
    proto_item_set_generated(ti);
    add_new_data_source(pinfo, decrypted, "Decrypted DTLS");
    /* real content type*/
    switch ((record->type))
    {
    case SSL_ID_HANDSHAKE:
      dissect_dtls_handshake(decrypted, pinfo, dtls_record_tree, 0,
                             tvb_reported_length(decrypted), false, session, is_from_server,
                             ssl, record->type);
      break;
    case SSL_ID_ALERT:
      dissect_dtls_alert(decrypted, pinfo, dtls_record_tree, 0,
                         session);
      break;
    case SSL_ID_DTLS13_ACK:
      dissect_dtls_ack(decrypted, pinfo, dtls_record_tree, 0, tvb_reported_length(decrypted));
      break;
    case SSL_ID_APP_DATA:
      dissect_dtls_appdata(tvb, pinfo, offset, dtls_record_length, session,
                           dtls_record_tree, is_from_server, decrypted, record);
      break;
    default:
      break;
    }
  } else {
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Encrypted Data");
    proto_tree_add_item(dtls_record_tree, hf_dtls_record_encrypted_content, tvb,
                        offset, dtls_record_length, ENC_NA);
    proto_item_set_text(dtls_record_tree,
                        "%s Record Layer: Encrypted Data",
                        val_to_str_const(session->version, ssl_version_short_names, "DTLS"));
  }

  return offset + dtls_record_length;
}

/* dissects the alert message, filling in the tree */
static void
dissect_dtls_alert(tvbuff_t *tvb, packet_info *pinfo,
                   proto_tree *tree, uint32_t offset,
                   const SslSession *session)
{
  /*     struct {
   *         AlertLevel level;
   *         AlertDescription description;
   *     } Alert;
   */

  proto_tree  *ti;
  proto_tree  *ssl_alert_tree;
  const char *level;
  const char *desc;
  uint8_t      byte;

   ti = proto_tree_add_item(tree, hf_dtls_alert_message, tvb,
                               offset, 2, ENC_NA);
   ssl_alert_tree = proto_item_add_subtree(ti, ett_dtls_alert);

  /*
   * set the record layer label
   */

  /* first lookup the names for the alert level and description */
  byte  = tvb_get_uint8(tvb, offset); /* grab the level byte */
  level = try_val_to_str(byte, ssl_31_alert_level);

  byte  = tvb_get_uint8(tvb, offset+1); /* grab the desc byte */
  desc  = try_val_to_str(byte, ssl_31_alert_description);

  /* now set the text in the record layer line */
  if (level && desc)
    {
       col_append_sep_fstr(pinfo->cinfo, COL_INFO,
             NULL, "Alert (Level: %s, Description: %s)",
             level, desc);
    }
  else
    {
      col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Encrypted Alert");
    }

  if (tree)
    {
      if (level && desc)
        {
          proto_item_set_text(tree, "%s Record Layer: Alert "
                              "(Level: %s, Description: %s)",
                              val_to_str_const(session->version, ssl_version_short_names, "DTLS"),
                              level, desc);
          proto_tree_add_item(ssl_alert_tree, hf_dtls_alert_message_level,
                              tvb, offset++, 1, ENC_BIG_ENDIAN);

          proto_tree_add_item(ssl_alert_tree, hf_dtls_alert_message_description,
                              tvb, offset, 1, ENC_BIG_ENDIAN);
        }
      else
        {
          proto_item_set_text(tree,
                              "%s Record Layer: Encrypted Alert",
                              val_to_str_const(session->version, ssl_version_short_names, "DTLS"));
          proto_item_set_text(ssl_alert_tree,
                              "Alert Message: Encrypted Alert");
        }
    }
}

static void
dtls13_maybe_increase_max_epoch(SslDecryptSession *ssl, bool is_from_server)
{
  SslDecoder *dec;

  if (ssl == NULL)
    return;

  if (is_from_server)
    dec = ssl->server;
  else
    dec = ssl->client;

  if (dec == NULL)
    return;

  /* be sure to increment from the current epoch just once, and to increment
   * again only after the new epoch was seen. This assures that the dissector
   * can always compute the next epoch, and avoid that duplicate packets wrongly
   * increment the max epoch multiple times. */
  if (dec->dtls13_epoch == ssl->session.dtls13_current_epoch[is_from_server])
    ssl->session.dtls13_current_epoch[is_from_server]++;
}

/* dissects the handshake protocol, filling the tree */
static void
dissect_dtls_handshake(tvbuff_t *tvb, packet_info *pinfo,
                       proto_tree *tree, uint32_t offset,
                       uint32_t record_length, bool maybe_encrypted,
                       SslSession *session, int is_from_server,
                       SslDecryptSession* ssl, uint8_t content_type)
{
  /*     struct {
   *         HandshakeType msg_type;
   *         uint24 length;
   *         uint16 message_seq;          //new field
   *         uint24 fragment_offset;      //new field
   *         uint24 fragment_length;      //new field
   *         select (HandshakeType) {
   *             case hello_request:       HelloRequest;
   *             case client_hello:        ClientHello;
   *             case server_hello:        ServerHello;
   *             case hello_verify_request: HelloVerifyRequest;     //new field
   *             case certificate:         Certificate;
   *             case server_key_exchange: ServerKeyExchange;
   *             case certificate_request: CertificateRequest;
   *             case server_hello_done:   ServerHelloDone;
   *             case certificate_verify:  CertificateVerify;
   *             case client_key_exchange: ClientKeyExchange;
   *             case finished:            Finished;
   *         } body;
   *     } Handshake;
   */

  proto_tree  *ti, *length_item = NULL, *fragment_length_item = NULL;
  proto_tree  *ssl_hand_tree;
  const char *msg_type_str;
  uint8_t      msg_type;
  uint32_t     length;
  uint16_t     version;
  uint16_t     message_seq;
  uint32_t     fragment_offset;
  uint32_t     fragment_length;
  bool         first_iteration;
  uint32_t     reassembled_length;
  tvbuff_t     *sub_tvb;

  msg_type_str    = NULL;
  first_iteration = true;

  /* just as there can be multiple records per packet, there
   * can be multiple messages per record as long as they have
   * the same content type
   *
   * we really only care about this for handshake messages
   */

  /* set record_length to the max offset */
  record_length += offset;
  for (; offset < record_length; offset += fragment_length,
         first_iteration = false) /* set up for next pass, if any */
    {
      fragment_head *frag_msg = NULL;
      tvbuff_t      *new_tvb  = NULL;
      const char    *frag_str = NULL;
      bool           fragmented;
      uint32_t       hs_offset = offset;
      bool           is_hrr = 0;

      /* add a subtree for the handshake protocol */
      ti = proto_tree_add_item(tree, hf_dtls_handshake_protocol, tvb, offset, -1, ENC_NA);
      ssl_hand_tree = proto_item_add_subtree(ti, ett_dtls_handshake);

      msg_type = tvb_get_uint8(tvb, offset);
      fragment_length = tvb_get_ntoh24(tvb, offset + 9);

      /* Check the fragment length in the handshake message. Assume it's an
       * encrypted handshake message if the message would pass
       * the record_length boundary. This is a workaround for the
       * situation where the first octet of the encrypted handshake
       * message is actually a known handshake message type.
       */
      if (!maybe_encrypted || offset + fragment_length <= record_length) {
        if (msg_type == SSL_HND_SERVER_HELLO) {
          tls_scan_server_hello(tvb, offset+12, fragment_length, &version, &is_hrr);
        }
        if (is_hrr) {
            msg_type_str = try_val_to_str(SSL_HND_HELLO_RETRY_REQUEST, ssl_31_handshake_type);
        } else {
            msg_type_str = try_val_to_str(msg_type, ssl_31_handshake_type);
        }
      }

      if (!msg_type_str && !first_iteration)
        {
          /* only dissect / report messages if they're
           * either the first message in this record
           * or they're a valid message type
           */
          return;
        }

      /*
       * Update our info string
       */
      if (msg_type_str)
        {
          col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, msg_type_str);
        }
      else
        {
          /* if we don't have a valid handshake type, just quit dissecting */
          col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Encrypted Handshake Message");
          return;
        }

      proto_tree_add_uint(ssl_hand_tree, hf_dtls_handshake_type,
                            tvb, offset, 1, msg_type);
      offset++;

      length = tvb_get_ntoh24(tvb, offset);
      length_item = proto_tree_add_uint(ssl_hand_tree, hf_dtls_handshake_length,
                                          tvb, offset, 3, length);
      offset += 3;

      message_seq = tvb_get_ntohs(tvb,offset);
      proto_tree_add_uint(ssl_hand_tree, hf_dtls_handshake_message_seq,
                            tvb, offset, 2, message_seq);
      offset += 2;

      fragment_offset = tvb_get_ntoh24(tvb, offset);
      proto_tree_add_uint(ssl_hand_tree, hf_dtls_handshake_fragment_offset,
                            tvb, offset, 3, fragment_offset);
      offset += 3;

      fragment_length_item = proto_tree_add_uint(ssl_hand_tree,
                                                   hf_dtls_handshake_fragment_length,
                                                   tvb, offset, 3,
                                                   fragment_length);
      offset += 3;
      proto_item_set_len(ti, fragment_length + 12);

      fragmented = false;
      if (fragment_length + fragment_offset > length)
        {
          if (fragment_offset == 0)
            {
              expert_add_info(pinfo, fragment_length_item, &ei_dtls_handshake_fragment_length_too_long);
            }
          else
            {
              fragmented = true;
              expert_add_info(pinfo, fragment_length_item, &ei_dtls_handshake_fragment_past_end_msg);
            }
        }
      else if (fragment_offset > 0 && fragment_length == 0)
        {
          /* Fragmented message, but no actual fragment... Note that if a
           * fragment was previously completed (reassembled_length == length),
           * it is already dissected. */
          expert_add_info(pinfo, fragment_length_item, &ei_dtls_handshake_fragment_length_zero);
          continue;
        }
      else if (fragment_length < length)
        {
          fragmented = true;

          /* Handle fragments of known message type, ignore others */
          if (ssl_is_valid_handshake_type(msg_type, true))
            {
              /* Fragmented handshake message */
              pinfo->fragmented = true;

              /* Don't pass the reassembly code data that doesn't exist */
              tvb_ensure_bytes_exist(tvb, offset, fragment_length);

              frag_msg = fragment_add(&dtls_reassembly_table,
                                      tvb, offset, pinfo, message_seq, NULL,
                                      fragment_offset, fragment_length, true);
              /*
               * Do we already have a length for this reassembly?
               */
              reassembled_length = fragment_get_tot_len(&dtls_reassembly_table,
                                                        pinfo, message_seq, NULL);
              if (reassembled_length == 0)
                {
                  /* No - set it to the length specified by this packet. */
                  fragment_set_tot_len(&dtls_reassembly_table,
                                       pinfo, message_seq, NULL, length);
                }
              else
                {
                  /* Yes - if this packet specifies a different length,
                     report an error. */
                  if (reassembled_length != length)
                    {
                      expert_add_info(pinfo, length_item, &ei_dtls_msg_len_diff_fragment);
                    }
                }

              if (frag_msg && (fragment_length + fragment_offset) == reassembled_length)
                {
                  /* Reassembled */
                  new_tvb = process_reassembled_data(tvb, offset, pinfo,
                                                     "Reassembled DTLS",
                                                     frag_msg,
                                                     &dtls_frag_items,
                                                     NULL, tree);
                  frag_str = " (Reassembled)";
                }
              else
                {
                  frag_str = " (Fragment)";
                }

              col_append_str(pinfo->cinfo, COL_INFO, frag_str);
            }
        }

      if (tree)
        {
          /* set the label text on the record layer expanding node */
          if (first_iteration)
            {
              proto_item_set_text(tree, "%s Record Layer: %s Protocol: %s%s",
                                  val_to_str_const(session->version, ssl_version_short_names, "DTLS"),
                                  val_to_str_const(content_type, ssl_31_content_type, "unknown"),
                                  msg_type_str, (frag_str!=NULL) ? frag_str : "");
            }
          else
            {
              proto_item_set_text(tree, "%s Record Layer: %s Protocol: %s%s",
                                  val_to_str_const(session->version, ssl_version_short_names, "DTLS"),
                                  val_to_str_const(content_type, ssl_31_content_type, "unknown"),
                                  "Multiple Handshake Messages",
                                  (frag_str!=NULL) ? frag_str : "");
            }

          if (ssl_hand_tree)
            {
              /* set the text label on the subtree node */
              proto_item_set_text(ssl_hand_tree, "Handshake Protocol: %s%s",
                                  msg_type_str, (frag_str!=NULL) ? frag_str : "");
            }
        }

        if (fragmented && !new_tvb)
        {
          /* Skip fragmented messages not reassembled yet */
          continue;
        }

        if (new_tvb)
        {
          sub_tvb = new_tvb;
        }
        else
        {
          sub_tvb = tvb_new_subset_length(tvb, offset, fragment_length);
        }

        if ((msg_type == SSL_HND_CLIENT_HELLO || msg_type == SSL_HND_SERVER_HELLO)) {
            /* Prepare for renegotiation by resetting the state. */
            ssl_reset_session(session, ssl, msg_type == SSL_HND_CLIENT_HELLO);
        }

        /*
         * Add handshake message (including type, length, etc.) to hash (for
         * Extended Master Secret). The computation must however happen as if
         * the message was sent in a single fragment (RFC 6347, section 4.2.6).
         *
         * Skip CertificateVerify since the handshake hash covers just
         * ClientHello up to and including ClientKeyExchange, but the keys are
         * actually retrieved in ChangeCipherSpec (which comes after that).
         */
        if (msg_type != SSL_HND_CERT_VERIFY) {
          if (fragment_offset == 0) {
            /* Unfragmented packet. */
            ssl_calculate_handshake_hash(ssl, tvb, hs_offset, 12 + fragment_length);
          } else {
            /*
             * Handshake message was fragmented over multiple messages, fake a
             * single fragment and add reassembled data.
             */
            /* msg_type (1), length (3), message_seq (2) */
            ssl_calculate_handshake_hash(ssl, tvb, hs_offset, 6);
            /* fragment_offset (3) equals to zero. */
            ssl_calculate_handshake_hash(ssl, NULL, 0, 3);
            /* fragment_length (3) equals to length. */
            ssl_calculate_handshake_hash(ssl, tvb, hs_offset + 1, 3);
            /* actual handshake data */
            ssl_calculate_handshake_hash(ssl, sub_tvb, 0, length);
          }
        }

        /* now dissect the handshake message, if necessary */
        switch ((HandshakeType) msg_type) {
          case SSL_HND_HELLO_REQUEST:
            /* hello_request has no fields, so nothing to do! */
            break;

          case SSL_HND_CLIENT_HELLO:
            if (ssl) {
              /* ClientHello is first packet so set direction */
              ssl_set_server(session, &pinfo->dst, pinfo->ptype, pinfo->destport);
            }
            ssl_dissect_hnd_cli_hello(&dissect_dtls_hf, sub_tvb, pinfo,
                                      ssl_hand_tree, 0, length, session, ssl,
                                      &dtls_hfs);
            if (ssl) {
                tls_save_crandom(ssl, tls_get_master_key_map(false));
                /* force DTLSv1.3 version if early data is seen */
                if (ssl->has_early_data) {
                  session->version = DTLSV1DOT3_VERSION;
                  ssl->state |= SSL_VERSION;
                  ssl_debug_printf("%s forcing version 0x%04X -> state 0x%02X\n", G_STRFUNC, DTLSV1DOT3_VERSION, ssl->state);
                }
            }
            break;

          case SSL_HND_SERVER_HELLO:
            tls_scan_server_hello(sub_tvb, 0, fragment_length, &version, &is_hrr);
            ssl_try_set_version(session, ssl, SSL_ID_HANDSHAKE, SSL_HND_SERVER_HELLO, true, version);

            ssl_dissect_hnd_srv_hello(&dissect_dtls_hf, sub_tvb, pinfo, ssl_hand_tree,
                                      0, length, session, ssl, true, is_hrr);
            break;

          case SSL_HND_HELLO_VERIFY_REQUEST:
            /*
             * The initial ClientHello and HelloVerifyRequest are not included
             * in the calculation of the handshake_messages
             * (https://tools.ietf.org/html/rfc6347#page-18). This is also
             * important for correct calculation of Extended Master Secret.
             */
            if (ssl && ssl->handshake_data.data_len) {
              ssl_debug_printf("%s erasing previous handshake_messages: %d\n", G_STRFUNC, ssl->handshake_data.data_len);
              wmem_free(wmem_file_scope(), ssl->handshake_data.data);
              ssl->handshake_data.data = NULL;
              ssl->handshake_data.data_len = 0;
            }
            dissect_dtls_hnd_hello_verify_request(&dissect_dtls_hf, sub_tvb, pinfo,
                                                  ssl_hand_tree, 0, length);
            break;

          case SSL_HND_NEWSESSION_TICKET:
            /* no need to load keylog file here as it only links a previous
             * master key with this Session Ticket */
            ssl_dissect_hnd_new_ses_ticket(&dissect_dtls_hf, sub_tvb, pinfo,
                                           ssl_hand_tree, 0, length, session, ssl, true,
                                           tls_get_master_key_map(false)->tickets);
            break;

          case SSL_HND_HELLO_RETRY_REQUEST:
            ssl_dissect_hnd_hello_retry_request(&dissect_dtls_hf, sub_tvb, pinfo, ssl_hand_tree,
                                                0, length, session, ssl, true);
            break;

          case SSL_HND_CERTIFICATE:
            ssl_dissect_hnd_cert(&dissect_dtls_hf, sub_tvb, ssl_hand_tree, 0, length,
                pinfo, session, ssl, is_from_server, true);
            break;

          case SSL_HND_SERVER_KEY_EXCHG:
            ssl_dissect_hnd_srv_keyex(&dissect_dtls_hf, sub_tvb, pinfo, ssl_hand_tree, 0, length, session);
            break;

          case SSL_HND_CERT_REQUEST:
            ssl_dissect_hnd_cert_req(&dissect_dtls_hf, sub_tvb, pinfo, ssl_hand_tree, 0, length, session, true);
            break;

          case SSL_HND_SVR_HELLO_DONE:
            /* This is not an abbreviated handshake, it is certainly not resumed. */
            session->is_session_resumed = false;
            break;

          case SSL_HND_CERT_VERIFY:
            ssl_dissect_hnd_cli_cert_verify(&dissect_dtls_hf, sub_tvb, pinfo, ssl_hand_tree, 0, length, session->version);
            break;

          case SSL_HND_CLIENT_KEY_EXCHG:
            ssl_dissect_hnd_cli_keyex(&dissect_dtls_hf, sub_tvb, ssl_hand_tree, 0, length, session);
            if (!ssl)
                break;

            /* try to find master key from pre-master key */
            if (!ssl_generate_pre_master_secret(ssl, length, sub_tvb, 0,
                                                dtls_options.psk, pinfo,
#ifdef HAVE_LIBGNUTLS
                                                dtls_key_hash,
#endif
                                                tls_get_master_key_map(true))) {
                ssl_debug_printf("dissect_dtls_handshake can't generate pre master secret\n");
            }
            break;

          case SSL_HND_FINISHED:
            ssl_dissect_hnd_finished(&dissect_dtls_hf, sub_tvb, ssl_hand_tree,
                                     0, length, session, NULL);
            break;

          case SSL_HND_CERT_STATUS:
            tls_dissect_hnd_certificate_status(&dissect_dtls_hf, sub_tvb, pinfo, ssl_hand_tree, 0, length);
            break;

          case SSL_HND_CERT_URL:
          case SSL_HND_SUPPLEMENTAL_DATA:
          case SSL_HND_KEY_UPDATE:
            tls13_dissect_hnd_key_update(&dissect_dtls_hf, sub_tvb, ssl_hand_tree, 0);
            if (ssl && ssl->session.version == DTLSV1DOT3_VERSION) {
              dtls13_maybe_increase_max_epoch(ssl, is_from_server);
            }
            break;
          case SSL_HND_ENCRYPTED_EXTS:
          case SSL_HND_END_OF_EARLY_DATA: /* TLS 1.3 */
          case SSL_HND_COMPRESSED_CERTIFICATE:
            break;
          case SSL_HND_ENCRYPTED_EXTENSIONS: /* TLS 1.3 */
            ssl_dissect_hnd_encrypted_extensions(&dissect_dtls_hf, sub_tvb, pinfo, ssl_hand_tree, 0, length, session, ssl, 1);
            break;
        }
    }
}

/* dissects the heartbeat message, filling in the tree */
static void
dissect_dtls_heartbeat(tvbuff_t *tvb, packet_info *pinfo,
                       proto_tree *tree, uint32_t offset,
                       const SslSession *session, uint32_t record_length,
                       bool decrypted)
{
  /*     struct {
   *         HeartbeatMessageType type;
   *         uint16 payload_length;
   *         opaque payload;
   *         opaque padding;
   *     } HeartbeatMessage;
   */

  proto_tree  *ti;
  proto_tree  *dtls_heartbeat_tree;
  const char *type;
  uint8_t      byte;
  uint16_t     payload_length;
  uint16_t     padding_length;

  ti = proto_tree_add_item(tree, hf_dtls_heartbeat_message, tvb,
                             offset, record_length - 32, ENC_NA);
  dtls_heartbeat_tree = proto_item_add_subtree(ti, ett_dtls_heartbeat);

  /*
   * set the record layer label
   */

  /* first lookup the names for the message type and the payload length */
  byte = tvb_get_uint8(tvb, offset);
  type = try_val_to_str(byte, tls_heartbeat_type);

  payload_length = tvb_get_ntohs(tvb, offset + 1);
  padding_length = record_length - 3 - payload_length;

  /* now set the text in the record layer line */
  if (type && (payload_length <= record_length - 16 - 3)) {
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Heartbeat %s", type);
  } else {
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Encrypted Heartbeat");
  }

  if (tree) {
    if (type && ((payload_length <= record_length - 16 - 3) || decrypted)) {
      proto_item_set_text(tree, "%s Record Layer: Heartbeat "
                                "%s",
                                val_to_str_const(session->version, ssl_version_short_names, "DTLS"),
                                type);
      proto_tree_add_item(dtls_heartbeat_tree, hf_dtls_heartbeat_message_type,
                          tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      ti = proto_tree_add_uint(dtls_heartbeat_tree, hf_dtls_heartbeat_message_payload_length,
                               tvb, offset, 2, payload_length);
      offset += 2;
      if (payload_length > record_length - 16 - 3) {
        expert_add_info_format(pinfo, ti, &ei_dtls_heartbeat_payload_length,
                               "Invalid heartbeat payload length (%d)", payload_length);
        /* Invalid heartbeat payload length, adjust to try decoding */
        payload_length = record_length - 16 - 3;
        padding_length = 16;
        proto_item_append_text (ti, " (invalid, using %u to decode payload)", payload_length);

      }
      proto_tree_add_bytes_format(dtls_heartbeat_tree, hf_dtls_heartbeat_message_payload,
                                  tvb, offset, payload_length,
                                  NULL, "Payload (%u byte%s)",
                                  payload_length,
                                  plurality(payload_length, "", "s"));
      offset += payload_length;
      proto_tree_add_bytes_format(dtls_heartbeat_tree, hf_dtls_heartbeat_message_padding,
                                  tvb, offset, padding_length,
                                  NULL, "Padding and HMAC (%u byte%s)",
                                  padding_length,
                                  plurality(padding_length, "", "s"));
    } else {
      proto_item_set_text(tree,
                         "%s Record Layer: Encrypted Heartbeat",
                         val_to_str_const(session->version, ssl_version_short_names, "DTLS"));
      proto_item_set_text(dtls_heartbeat_tree,
                          "Encrypted Heartbeat Message");
    }
  }
}

/* dissects the acknowledgement message from RFC 9147 section 7 */
static void
dissect_dtls_ack(tvbuff_t *tvb, packet_info *pinfo,
                       proto_tree *tree, uint32_t offset,
                       uint32_t record_length)
{
  /*
   *    section 4:
   *    struct {
   *        uint64 epoch;
   *        uint64 sequence_number;
   *    } RecordNumber;
   *
   *    section 7:
   *    struct {
   *        RecordNumber record_numbers<0..2^16-1>;
   *    } ACK;
   */

  uint32_t i;
  uint32_t record_number_length;
  proto_tree *ti;
  proto_tree *dtls_ack_tree, *rn_tree;
  uint64_t epoch;
  uint64_t number;

  col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Acknowledgement");
  ti = proto_tree_add_item(tree, hf_dtls_ack_message, tvb,
                             offset, record_length, ENC_NA);
  dtls_ack_tree = proto_item_add_subtree(ti, ett_dtls_ack);

  /* record_numbers<2..2^16-2> */
  if (!ssl_add_vector(&dissect_dtls_hf, tvb, pinfo, dtls_ack_tree, offset, record_length, &record_number_length,
                      hf_dtls_ack_record_numbers_length, 2, UINT16_MAX - 1)) {
        return;
  }

  offset += 2;
  ti = proto_tree_add_none_format(dtls_ack_tree, hf_dtls_ack_record_numbers, tvb, offset, record_number_length,
                                  "RecordNumbers (%u record number%s)",
                                  record_number_length / 16, plurality(record_number_length / 16, "", "s"));
  dtls_ack_tree = proto_item_add_subtree(ti, ett_dtls_ack_record_numbers);

  for (i = 0; i < record_number_length; i += 16) {
      rn_tree = proto_tree_add_subtree(dtls_ack_tree, tvb, offset + i, 16, ett_dtls_ack_record_number, NULL, "");
      proto_tree_add_item_ret_uint64(rn_tree, hf_dtls_record_epoch64, tvb,
                            offset + i + 0, 8, ENC_BIG_ENDIAN, &epoch);
      proto_tree_add_item_ret_uint64(rn_tree, hf_dtls_record_sequence_number, tvb,
                            offset + i + 8, 8, ENC_BIG_ENDIAN, &number);
      proto_item_set_text(rn_tree, "RecordNumber: epoch %" PRIu64 ", sequence number %" PRIu64, epoch, number);
  }
}

static int
dissect_dtls_hnd_hello_verify_request(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                      packet_info *pinfo, proto_tree *tree,
                                      uint32_t offset, uint32_t offset_end)
{
  /*
   * struct {
   *    ProtocolVersion server_version;
   *    opaque cookie<0..32>;
   * } HelloVerifyRequest;
   */

  uint32_t cookie_length;

  /* show the client version */
  proto_tree_add_item(tree, dissect_dtls_hf.hf.hs_server_version, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &cookie_length,
                      dtls_hfs.hf_dtls_handshake_cookie_len, 0, 32)) {
      return offset;
  }
  offset++;

  if (cookie_length > 0)
  {
    proto_tree_add_item(tree, dtls_hfs.hf_dtls_handshake_cookie,
                        tvb, offset, cookie_length, ENC_NA);
    offset += cookie_length;
  }

  return offset;
}

int
dtls_dissect_hnd_hello_ext_use_srtp(packet_info *pinfo, tvbuff_t *tvb,
                                    proto_tree *tree, uint32_t offset,
                                    uint32_t ext_len, bool is_server)
{
  /* From https://tools.ietf.org/html/rfc5764#section-4.1.1
   *
   * uint8 SRTPProtectionProfile[2];
   *
   * struct {
   *    SRTPProtectionProfiles SRTPProtectionProfiles;
   *    opaque srtp_mki<0..255>;
   * } UseSRTPData;
   *
   * SRTPProtectionProfile SRTPProtectionProfiles<2..2^16-1>;
   */

  proto_item *ti;
  uint32_t profiles_length, profiles_end, profile, mki_length;

  if (ext_len < 2) {
    /* XXX expert info, record too small */
    return offset + ext_len;
  }

  /* SRTPProtectionProfiles list length */
  ti = proto_tree_add_item_ret_uint(tree, hf_dtls_hs_ext_use_srtp_protection_profiles_length,
      tvb, offset, 2, ENC_BIG_ENDIAN, &profiles_length);
  if (profiles_length > ext_len - 2) {
    profiles_length = ext_len - 2;
    expert_add_info_format(pinfo, ti, &ei_dtls_use_srtp_profiles_length,
                           "The protection profiles length exceeds the extension data field length");
  }
  if (is_server && profiles_length != 2) {
    /* The server, if sending the use_srtp extension, MUST return a
     * a single chosen profile that the client has offered.
     */
    profile = SRTP_PROFILE_RESERVED;
    expert_add_info_format(pinfo, ti, &ei_dtls_use_srtp_profiles_length,
                           "The server MUST return a single chosen protection profile");
  }
  offset += 2;

  /* SRTPProtectionProfiles list items */
  profiles_end = offset + profiles_length;
  while (offset < profiles_end) {
    proto_tree_add_item_ret_uint(tree,
        hf_dtls_hs_ext_use_srtp_protection_profile, tvb, offset, 2,
        ENC_BIG_ENDIAN, &profile);
    offset += 2;
  }

  /* MKI */
  proto_tree_add_item_ret_uint(tree, hf_dtls_hs_ext_use_srtp_mki_length,
      tvb, offset, 1, ENC_NA, &mki_length);
  offset++;
  if (mki_length > 0) {
    proto_tree_add_item(tree, hf_dtls_hs_ext_use_srtp_mki,
        tvb, offset, mki_length, ENC_NA);
    offset += mki_length;
  }

  /* We don't know which SRTP protection profile is chosen, unless only one
   * was provided.
   */
  if (is_server || profiles_length == 2) {
    struct srtp_info *srtp_info = wmem_new0(wmem_file_scope(), struct srtp_info);
    switch(profile) {
    case SRTP_AES128_CM_HMAC_SHA1_80:
      srtp_info->encryption_algorithm = SRTP_ENC_ALG_AES_CM;
      srtp_info->auth_algorithm = SRTP_AUTH_ALG_HMAC_SHA1;
      srtp_info->auth_tag_len = 10;
      break;
    case SRTP_AES128_CM_HMAC_SHA1_32:
      srtp_info->encryption_algorithm = SRTP_ENC_ALG_AES_CM;
      srtp_info->auth_algorithm = SRTP_AUTH_ALG_HMAC_SHA1;
      srtp_info->auth_tag_len = 4;
      break;
    case SRTP_NULL_HMAC_SHA1_80:
      srtp_info->encryption_algorithm = SRTP_ENC_ALG_NULL;
      srtp_info->auth_algorithm = SRTP_AUTH_ALG_HMAC_SHA1;
      srtp_info->auth_tag_len = 10;
      break;
    case SRTP_NULL_HMAC_SHA1_32:
      srtp_info->encryption_algorithm = SRTP_ENC_ALG_NULL;
      srtp_info->auth_algorithm = SRTP_AUTH_ALG_HMAC_SHA1;
      srtp_info->auth_tag_len = 4;
      break;
    case SRTP_AEAD_AES_128_GCM:
      srtp_info->encryption_algorithm = SRTP_ENC_ALG_AES_CM;
      srtp_info->auth_algorithm = SRTP_AUTH_ALG_GMAC;
      srtp_info->auth_tag_len = 16;
      break;
    case SRTP_AEAD_AES_256_GCM:
      srtp_info->encryption_algorithm = SRTP_ENC_ALG_AES_CM;
      srtp_info->auth_algorithm = SRTP_AUTH_ALG_GMAC;
      srtp_info->auth_tag_len = 16;
      break;
    default:
      srtp_info->encryption_algorithm = SRTP_ENC_ALG_AES_CM;
      srtp_info->auth_algorithm = SRTP_AUTH_ALG_HMAC_SHA1;
      srtp_info->auth_tag_len = 10;
    }
    srtp_info->mki_len = mki_length;
    /* RFC 5764: It is RECOMMENDED that symmetric RTP be used with DTLS-SRTP.
     * RTP and RTCP traffic MAY be multiplexed on a single UDP port. (RFC 5761)
     *
     * XXX: This creates a new RTP conversation. What it _should_ do is update
     * a RTP conversation initiated by SDP in a previous frame with the
     * srtp_info. Assuming we got the SDP and decrypted it if over TLS, etc.
     * However, since we don't actually decrypt SRT[C]P yet, the information
     * carried in the SDP about payload and media types isn't that useful.
     * (Being able to have the stream refer back to both the DTLS-SRTP and
     * SDP setup frame might be useful, though.)
     */
    srtp_add_address(pinfo, PT_UDP, &pinfo->net_src, pinfo->srcport, pinfo->destport, "DTLS-SRTP", pinfo->num, RTP_MEDIA_AUDIO, NULL, srtp_info, NULL);
    srtp_add_address(pinfo, PT_UDP, &pinfo->net_dst, pinfo->destport, pinfo->srcport, "DTLS-SRTP", pinfo->num, RTP_MEDIA_AUDIO, NULL, srtp_info, NULL);
  }
  return offset;
}

/*********************************************************************
 *
 * Support Functions
 *
 *********************************************************************/

/* this applies a heuristic to determine whether
 * or not the data beginning at offset looks like a
 * valid dtls record.
 */
static int
looks_like_dtls(tvbuff_t *tvb, uint32_t offset)
{
  /* have to have a valid content type followed by a valid
   * protocol version
   */
  uint8_t byte;
  uint16_t version;

  /* see if the first byte is a valid content type */
  byte = tvb_get_uint8(tvb, offset);
  if (!ssl_is_valid_content_type(byte))
    {
      if ((byte & DTLS13_FIXED_MASK) >> 5 == 1) {
        return 1;
      }
      return 0;
    }

  /* now check to see if the version byte appears valid */
  version = tvb_get_ntohs(tvb, offset + 1);
  if (version != DTLSV1DOT0_VERSION && version != DTLSV1DOT2_VERSION &&
      version != DTLSV1DOT0_OPENSSL_VERSION)
    {
      return 0;
    }

  return 1;
}

/* UAT */

#if defined(HAVE_LIBGNUTLS)
static void
dtlsdecrypt_free_cb(void* r)
{
  ssldecrypt_assoc_t* h = (ssldecrypt_assoc_t*)r;

  g_free(h->ipaddr);
  g_free(h->port);
  g_free(h->protocol);
  g_free(h->keyfile);
  g_free(h->password);
}
#endif

#if 0
static void
dtlsdecrypt_update_cb(void* r _U_, const char** err _U_)
{
  return;
}
#endif

#if defined(HAVE_LIBGNUTLS)
static void *
dtlsdecrypt_copy_cb(void* dest, const void* orig, size_t len _U_)
{
  const ssldecrypt_assoc_t* o = (const ssldecrypt_assoc_t*)orig;
  ssldecrypt_assoc_t*       d = (ssldecrypt_assoc_t*)dest;

  d->ipaddr    = g_strdup(o->ipaddr);
  d->port      = g_strdup(o->port);
  d->protocol  = g_strdup(o->protocol);
  d->keyfile   = g_strdup(o->keyfile);
  d->password  = g_strdup(o->password);

  return d;
}

UAT_CSTRING_CB_DEF(sslkeylist_uats,ipaddr,ssldecrypt_assoc_t)
UAT_CSTRING_CB_DEF(sslkeylist_uats,port,ssldecrypt_assoc_t)
UAT_CSTRING_CB_DEF(sslkeylist_uats,protocol,ssldecrypt_assoc_t)
UAT_FILENAME_CB_DEF(sslkeylist_uats,keyfile,ssldecrypt_assoc_t)
UAT_CSTRING_CB_DEF(sslkeylist_uats,password,ssldecrypt_assoc_t)

static bool
dtlsdecrypt_uat_fld_protocol_chk_cb(void* r _U_, const char* p, unsigned len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    if (!p || strlen(p) == 0u) {
        // This should be removed in favor of Decode As. Make it optional.
        *err = NULL;
        return true;
    }

    if (!find_dissector(p)) {
        if (proto_get_id_by_filter_name(p) != -1) {
            *err = ws_strdup_printf("While '%s' is a valid dissector filter name, that dissector is not configured"
                                   " to support DTLS decryption.\n\n"
                                   "If you need to decrypt '%s' over DTLS, please contact the Wireshark development team.", p, p);
        } else {
            char* ssl_str = ssl_association_info("dtls.port", "UDP");
            *err = ws_strdup_printf("Could not find dissector for: '%s'\nCommonly used DTLS dissectors include:\n%s", p, ssl_str);
            g_free(ssl_str);
        }
        return false;
    }

    *err = NULL;
    return true;
}
#endif

static void
dtls_src_prompt(packet_info *pinfo, char *result)
{
    SslPacketInfo* pi;
    uint32_t srcport = pinfo->srcport;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto_dtls, pinfo->curr_layer_num);
    if (pi != NULL)
        srcport = pi->srcport;

    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "source (%u%s)", srcport, UTF8_RIGHTWARDS_ARROW);
}

static void *
dtls_src_value(packet_info *pinfo)
{
    SslPacketInfo* pi;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto_dtls, pinfo->curr_layer_num);
    if (pi == NULL)
        return GUINT_TO_POINTER(pinfo->srcport);

    return GUINT_TO_POINTER(pi->srcport);
}

static void
dtls_dst_prompt(packet_info *pinfo, char *result)
{
    SslPacketInfo* pi;
    uint32_t destport = pinfo->destport;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto_dtls, pinfo->curr_layer_num);
    if (pi != NULL)
        destport = pi->destport;

    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "destination (%s%u)", UTF8_RIGHTWARDS_ARROW, destport);
}

static void *
dtls_dst_value(packet_info *pinfo)
{
    SslPacketInfo* pi;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto_dtls, pinfo->curr_layer_num);
    if (pi == NULL)
        return GUINT_TO_POINTER(pinfo->destport);

    return GUINT_TO_POINTER(pi->destport);
}

static void
dtls_both_prompt(packet_info *pinfo, char *result)
{
    SslPacketInfo* pi;
    uint32_t srcport = pinfo->srcport,
            destport = pinfo->destport;

    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto_dtls, pinfo->curr_layer_num);
    if (pi != NULL)
    {
        srcport = pi->srcport;
        destport = pi->destport;
    }

    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "both (%u%s%u)", srcport, UTF8_LEFT_RIGHT_ARROW, destport);
}

void proto_reg_handoff_dtls(void);

/*********************************************************************
 *
 * Standard Wireshark Protocol Registration and housekeeping
 *
 *********************************************************************/
void
proto_register_dtls(void)
{

  /* Setup list of header fields See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    { &hf_dtls_record,
      { "Record Layer", "dtls.record",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_record_content_type,
      { "Content Type", "dtls.record.content_type",
        FT_UINT8, BASE_DEC, VALS(ssl_31_content_type), 0x0,
        NULL, HFILL}
    },
    { &hf_dtls_record_special_type,
      { "Special Type", "dtls.record.special_type",
        FT_UINT8, BASE_DEC, VALS(ssl_31_content_type), 0x0,
        "Always set to value 25, actual content type is known after decryption", HFILL}
    },
    { &hf_dtls_record_version,
      { "Version", "dtls.record.version",
        FT_UINT16, BASE_HEX, VALS(ssl_versions), 0x0,
        "Record layer version", HFILL }
    },
    { &hf_dtls_record_epoch,
      { "Epoch", "dtls.record.epoch",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_record_epoch64,
      { "Epoch", "dtls.record.epoch",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_record_sequence_number,
      { "Sequence Number", "dtls.record.sequence_number",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_record_sequence_suffix,
      { "Sequence Number suffix", "dtls.record.sequence_suffix",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Lowest-order bits of the sequence number", HFILL }
    },
    { &hf_dtls_record_sequence_suffix_dec,
      { "Sequence Number suffix (decrypted)", "dtls.record.sequence_suffix_dec",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Lowest-order bits of the sequence number (decrypted)", HFILL }
    },
    { &hf_dtls_record_connection_id,
      { "Connection ID", "dtls.record.connection_id",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_record_length,
      { "Length", "dtls.record.length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Length of DTLS record data", HFILL }
    },
    { &hf_dtls_record_appdata,
      { "Encrypted Application Data", "dtls.app_data",
        FT_BYTES, BASE_NONE|BASE_NO_DISPLAY_VALUE, NULL, 0x0,
        "Payload is encrypted application data", HFILL }
    },
    { &hf_dtls_record_appdata_proto,
      { "Application Data Protocol", "dtls.app_data_proto",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_record_encrypted_content,
      { "Encrypted Record Content", "dtls.enc_content",
        FT_BYTES, BASE_NONE|BASE_NO_DISPLAY_VALUE, NULL, 0x0,
        "Encrypted record data", HFILL }
    },
    { & hf_dtls_alert_message,
      { "Alert Message", "dtls.alert_message",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { & hf_dtls_alert_message_level,
      { "Level", "dtls.alert_message.level",
        FT_UINT8, BASE_DEC, VALS(ssl_31_alert_level), 0x0,
        "Alert message level", HFILL }
    },
    { &hf_dtls_alert_message_description,
      { "Description", "dtls.alert_message.desc",
        FT_UINT8, BASE_DEC, VALS(ssl_31_alert_description), 0x0,
        "Alert message description", HFILL }
    },
    { &hf_dtls_handshake_protocol,
      { "Handshake Protocol", "dtls.handshake",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Handshake protocol message", HFILL}
    },
    { &hf_dtls_handshake_type,
      { "Handshake Type", "dtls.handshake.type",
        FT_UINT8, BASE_DEC, VALS(ssl_31_handshake_type), 0x0,
        "Type of handshake message", HFILL}
    },
    { &hf_dtls_handshake_length,
      { "Length", "dtls.handshake.length",
        FT_UINT24, BASE_DEC, NULL, 0x0,
        "Length of handshake message", HFILL }
    },
    { &hf_dtls_handshake_message_seq,
      { "Message Sequence", "dtls.handshake.message_seq",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Message sequence of handshake message", HFILL }
    },
    { &hf_dtls_handshake_fragment_offset,
      { "Fragment Offset", "dtls.handshake.fragment_offset",
        FT_UINT24, BASE_DEC, NULL, 0x0,
        "Fragment offset of handshake message", HFILL }
    },
    { &hf_dtls_handshake_fragment_length,
      { "Fragment Length", "dtls.handshake.fragment_length",
        FT_UINT24, BASE_DEC, NULL, 0x0,
        "Fragment length of handshake message", HFILL }
    },
    { &dtls_hfs.hf_dtls_handshake_cookie_len,
      { "Cookie Length", "dtls.handshake.cookie_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length of the cookie field", HFILL }
    },
    { &dtls_hfs.hf_dtls_handshake_cookie,
      { "Cookie", "dtls.handshake.cookie",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_heartbeat_message,
      { "Heartbeat Message", "dtls.heartbeat_message",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_heartbeat_message_type,
      { "Type", "dtls.heartbeat_message.type",
        FT_UINT8, BASE_DEC, VALS(tls_heartbeat_type), 0x0,
        "Heartbeat message type", HFILL }
    },
    { &hf_dtls_heartbeat_message_payload_length,
      { "Payload Length", "dtls.heartbeat_message.payload_length",
        FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_heartbeat_message_payload,
      { "Payload Length", "dtls.heartbeat_message.payload",
        FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_heartbeat_message_padding,
      { "Payload Length", "dtls.heartbeat_message.padding",
        FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_ack_message,
      { "Acknowledgement Message", "dtls.ack_message",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_ack_record_numbers_length,
      { "Record Number Length", "dtls.ack.record_numbers_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_fragments,
      { "Message fragments", "dtls.fragments",
        FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_fragment,
      { "Message fragment", "dtls.fragment",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_ack_record_numbers,
      { "Record Numbers", "dtls.ack.record_numbers",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_dtls_fragment_overlap,
      { "Message fragment overlap", "dtls.fragment.overlap",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dtls_fragment_overlap_conflicts,
      { "Message fragment overlapping with conflicting data",
        "dtls.fragment.overlap.conflicts",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dtls_fragment_multiple_tails,
      { "Message has multiple tail fragments",
        "dtls.fragment.multiple_tails",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dtls_fragment_too_long_fragment,
      { "Message fragment too long", "dtls.fragment.too_long_fragment",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_dtls_fragment_error,
      { "Message defragmentation error", "dtls.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_fragment_count,
      { "Message fragment count", "dtls.fragment.count",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_reassembled_in,
      { "Reassembled in", "dtls.reassembled.in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_reassembled_length,
      { "Reassembled DTLS length", "dtls.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_hs_ext_use_srtp_protection_profiles_length,
      { "SRTP Protection Profiles Length", "dtls.use_srtp.protection_profiles_length",
        FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_hs_ext_use_srtp_protection_profile,
      { "SRTP Protection Profile", "dtls.use_srtp.protection_profile",
        FT_UINT16, BASE_HEX, VALS(srtp_protection_profile_vals), 0x00, NULL, HFILL }
    },
    { &hf_dtls_hs_ext_use_srtp_mki_length,
      { "MKI Length", "dtls.use_srtp.mki_length",
        FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_hs_ext_use_srtp_mki,
      { "MKI", "dtls.use_srtp.mki",
        FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_dtls_uni_hdr,
      { "Unified header bitmask", "dtls.unified_header.bitmask",
        FT_UINT8, BASE_HEX, NULL, 0x00, "DTLS 1.3 unified header bitmask", HFILL }
    },
    { &hf_dtls_uni_hdr_fixed,
      { "Fixed bits", "dtls.unified_header.fixed",
        FT_UINT8, BASE_HEX, NULL, DTLS13_FIXED_MASK, NULL, HFILL }
    },
    { &hf_dtls_uni_hdr_cid,
      { "CID field", "dtls.unified_header.cid_present",
        FT_BOOLEAN, 8, TFS(&tfs_present_not_present), DTLS13_C_BIT_MASK, NULL, HFILL }
    },
    { &hf_dtls_uni_hdr_seq,
      { "Sequence number size", "dtls.unified_header.seq_size",
        FT_BOOLEAN, 8, TFS(&dtls_uni_hdr_seq_tfs), DTLS13_S_BIT_MASK, NULL, HFILL }
    },
    { &hf_dtls_uni_hdr_len,
      { "Length field", "dtls.unified_header.length",
        FT_BOOLEAN, 8, TFS(&tfs_present_not_present), DTLS13_L_BIT_MASK, NULL, HFILL }
    },
    { &hf_dtls_uni_hdr_epoch,
      { "Epoch lowest-order bits", "dtls.unified_header.epoch_bits",
        FT_UINT8, BASE_DEC, NULL, 0x03, NULL, HFILL }
    },

    SSL_COMMON_HF_LIST(dissect_dtls_hf, "dtls")
  };

  /* Setup protocol subtree array */
  static int *ett[] = {
    &ett_dtls,
    &ett_dtls_record,
    &ett_dtls_alert,
    &ett_dtls_handshake,
    &ett_dtls_heartbeat,
    &ett_dtls_ack,
    &ett_dtls_ack_record_number,
    &ett_dtls_ack_record_numbers,
    &ett_dtls_certs,
    &ett_dtls_uni_hdr,
    &ett_dtls_fragment,
    &ett_dtls_fragments,
    SSL_COMMON_ETT_LIST(dissect_dtls_hf)
  };

  static ei_register_info ei[] = {
     { &ei_dtls_handshake_fragment_length_zero, { "dtls.handshake.fragment_length.zero", PI_PROTOCOL, PI_WARN, "Zero-length fragment length for fragmented message", EXPFILL }},
     { &ei_dtls_handshake_fragment_length_too_long, { "dtls.handshake.fragment_length.too_long", PI_PROTOCOL, PI_ERROR, "Fragment length is larger than message length", EXPFILL }},
     { &ei_dtls_handshake_fragment_past_end_msg, { "dtls.handshake.fragment_past_end_msg", PI_PROTOCOL, PI_ERROR, "Fragment runs past the end of the message", EXPFILL }},
     { &ei_dtls_msg_len_diff_fragment, { "dtls.msg_len_diff_fragment", PI_PROTOCOL, PI_ERROR, "Message length differs from value in earlier fragment", EXPFILL }},
     { &ei_dtls_heartbeat_payload_length, { "dtls.heartbeat_message.payload_length.invalid", PI_MALFORMED, PI_ERROR, "Invalid heartbeat payload length", EXPFILL }},
     { &ei_dtls_cid_invalid_content_type, { "dtls.cid.content_type.invalid", PI_MALFORMED, PI_ERROR, "Invalid real content type", EXPFILL }},
     { &ei_dtls_use_srtp_profiles_length, { "dtls.use_srtp.protection_profiles_length.invalid", PI_PROTOCOL, PI_ERROR, "Invalid real content type", EXPFILL }},
#if 0
     { &ei_dtls_cid_invalid_enc_content, { "dtls.cid.enc_content.invalid", PI_MALFORMED, PI_ERROR, "Invalid encrypted content", EXPFILL }},
#endif

     SSL_COMMON_EI_LIST(dissect_dtls_hf, "dtls")
  };

  static build_valid_func dtls_da_src_values[1] = {dtls_src_value};
  static build_valid_func dtls_da_dst_values[1] = {dtls_dst_value};
  static build_valid_func dtls_da_both_values[2] = {dtls_src_value, dtls_dst_value};
  static decode_as_value_t dtls_da_values[3] = {{dtls_src_prompt, 1, dtls_da_src_values}, {dtls_dst_prompt, 1, dtls_da_dst_values}, {dtls_both_prompt, 2, dtls_da_both_values}};
  static decode_as_t dtls_da = {"dtls", "dtls.port", 3, 2, dtls_da_values, "UDP", "port(s) as",
                               decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

  expert_module_t* expert_dtls;

  /* Register the protocol name and description */
  proto_dtls = proto_register_protocol("Datagram Transport Layer Security",
                                       "DTLS", "dtls");

  dtls_associations = register_dissector_table("dtls.port", "DTLS Port", proto_dtls, FT_UINT16, BASE_DEC);

  ssl_common_register_dtls_alpn_dissector_table("dtls.alpn",
        "DTLS Application-Layer Protocol Negotiation (ALPN) Protocol IDs",
        proto_dtls);

  /* Required function calls to register the header fields and
   * subtrees used */
  proto_register_field_array(proto_dtls, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_dtls = expert_register_protocol(proto_dtls);
  expert_register_field_array(expert_dtls, ei, array_length(ei));

  {
    module_t *dtls_module = prefs_register_protocol(proto_dtls, proto_reg_handoff_dtls);

#ifdef HAVE_LIBGNUTLS
    static uat_field_t dtlskeylist_uats_flds[] = {
      UAT_FLD_CSTRING_OTHER(sslkeylist_uats, ipaddr, "IP address", ssldecrypt_uat_fld_ip_chk_cb, "IPv4 or IPv6 address (unused)"),
      UAT_FLD_CSTRING_OTHER(sslkeylist_uats, port, "Port", ssldecrypt_uat_fld_port_chk_cb, "Port Number (optional)"),
      UAT_FLD_CSTRING_OTHER(sslkeylist_uats, protocol, "Protocol", dtlsdecrypt_uat_fld_protocol_chk_cb, "Application Layer Protocol (optional)"),
      UAT_FLD_FILENAME_OTHER(sslkeylist_uats, keyfile, "Key File", ssldecrypt_uat_fld_fileopen_chk_cb, "Path to the keyfile."),
      UAT_FLD_CSTRING_OTHER(sslkeylist_uats, password," Password (p12 file)", ssldecrypt_uat_fld_password_chk_cb, "Password"),
      UAT_END_FIELDS
    };

    dtlsdecrypt_uat = uat_new("DTLS RSA Keylist",
                              sizeof(ssldecrypt_assoc_t),
                              "dtlsdecrypttablefile",         /* filename */
                              true,                           /* from_profile */
                              &dtlskeylist_uats,              /* data_ptr */
                              &ndtlsdecrypt,                  /* numitems_ptr */
                              UAT_AFFECTS_DISSECTION,         /* affects dissection of packets, but not set of named fields */
                              "ChK12ProtocolsSection",        /* TODO, need revision - help */
                              dtlsdecrypt_copy_cb,
                              NULL, /* dtlsdecrypt_update_cb? */
                              dtlsdecrypt_free_cb,
                              dtls_parse_uat,
                              dtls_reset_uat,
                              dtlskeylist_uats_flds);

    prefs_register_uat_preference(dtls_module, "cfg",
                                  "RSA keys list",
                                  "A table of RSA keys for DTLS decryption",
                                  dtlsdecrypt_uat);

    prefs_register_string_preference(dtls_module, "keys_list", "RSA keys list (deprecated)",
                                     "Semicolon-separated list of private RSA keys used for DTLS decryption. "
                                     "Used by versions of Wireshark prior to 1.6",
                                     &dtls_keys_list);
#endif  /* HAVE_LIBGNUTLS */

    prefs_register_filename_preference(dtls_module, "debug_file", "DTLS debug file",
                                       "redirect dtls debug to file name; leave empty to disable debug, "
                                       "use \"" SSL_DEBUG_USE_STDERR "\" to redirect output to stderr\n",
                                       &dtls_debug_file_name, true);

    prefs_register_uint_preference(dtls_module, "client_cid_length", "Client Connection ID length",
                                   "Default client Connection ID length used when the Client Handshake message is missing",
                                   10, &dtls_default_client_cid_length);

    prefs_register_uint_preference(dtls_module, "server_cid_length", "Server Connection ID length",
                                   "Default server Connection ID length used when the Server Handshake message is missing",
                                   10, &dtls_default_server_cid_length);

    ssl_common_register_options(dtls_module, &dtls_options, true);
  }

  dtls_handle = register_dissector("dtls", dissect_dtls, proto_dtls);

  register_init_routine(dtls_init);
  register_cleanup_routine(dtls_cleanup);
  reassembly_table_register (&dtls_reassembly_table, &addresses_ports_reassembly_table_functions);
  register_decode_as(&dtls_da);

  dtls_tap = register_tap("dtls");
  ssl_debug_printf("proto_register_dtls: registered tap %s:%d\n",
                   "dtls", dtls_tap);

  heur_subdissector_list = register_heur_dissector_list_with_description("dtls", "DTLS payload fallback", proto_dtls);
}


/* If this dissector uses sub-dissector registration add a registration
 * routine.  This format is required because a script is used to find
 * these routines and create the code that calls these routines.
 */
void
proto_reg_handoff_dtls(void)
{
  static bool initialized = false;

#ifdef HAVE_LIBGNUTLS
  dtls_parse_uat();
  dtls_parse_old_keys();
#endif

  if (initialized == false) {
    heur_dissector_add("udp", dissect_dtls_heur, "DTLS over UDP", "dtls_udp", proto_dtls, HEURISTIC_ENABLE);
    heur_dissector_add("stun", dissect_dtls_heur, "DTLS over STUN", "dtls_stun", proto_dtls, HEURISTIC_DISABLE);
    heur_dissector_add("classicstun", dissect_dtls_heur, "DTLS over CLASSICSTUN", "dtls_classicstun", proto_dtls, HEURISTIC_DISABLE);
    dissector_add_uint("sctp.ppi", DIAMETER_DTLS_PROTOCOL_ID, dtls_handle);
    dissector_add_uint("sctp.ppi", NGAP_OVER_DTLS_PROTOCOL_ID, dtls_handle);
    dissector_add_uint("sctp.ppi", XNAP_OVER_DTLS_PROTOCOL_ID, dtls_handle);
    dissector_add_uint("sctp.ppi", F1AP_OVER_DTLS_PROTOCOL_ID, dtls_handle);
    dissector_add_uint("sctp.ppi", E1AP_OVER_DTLS_PROTOCOL_ID, dtls_handle);
    exported_pdu_tap = find_tap_id(EXPORT_PDU_TAP_NAME_LAYER_7);
  }

  initialized = true;
}

void
dtls_dissector_add(unsigned port, dissector_handle_t handle)
{
  ssl_association_add("dtls.port", dtls_handle, handle, port, false);
}

void
dtls_dissector_delete(unsigned port, dissector_handle_t handle)
{
  ssl_association_remove("dtls.port", dtls_handle, handle, port, false);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */

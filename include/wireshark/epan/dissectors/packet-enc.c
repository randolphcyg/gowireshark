/* packet-enc.c
 *
 * Copyright (c) 2003 Markus Friedl.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/aftypes.h>
#include <wsutil/pint.h>

void proto_register_enc(void);
void proto_reg_handoff_enc(void);

static dissector_handle_t enc_handle;
static capture_dissector_handle_t enc_cap_handle;


/* The header in OpenBSD Encapsulating Interface files. */

struct enchdr {
  uint32_t af;
  uint32_t spi;
  uint32_t flags;
};
#define BSD_ENC_HDRLEN    12

#define BSD_ENC_M_CONF          0x00000400  /* payload encrypted */
#define BSD_ENC_M_AUTH          0x00000800  /* payload authenticated */
#define BSD_ENC_M_COMP          0x00001000  /* payload compressed */
#define BSD_ENC_M_AUTH_AH       0x00002000  /* header authenticated */

#define BSD_ENC_M_RESERVED      0xFFFFC3FF  /* Reserved/unused flags */

static dissector_table_t enc_dissector_table;

/* header fields */
static int proto_enc;
static int hf_enc_af;
static int hf_enc_spi;
static int hf_enc_flags;
static int hf_enc_flags_payload_enc;
static int hf_enc_flags_payload_auth;
static int hf_enc_flags_payload_compress;
static int hf_enc_flags_header_auth;
static int hf_enc_flags_reserved;

static int ett_enc;
static int ett_enc_flag;

static bool
capture_enc(const unsigned char *pd, int offset _U_, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
  uint32_t af;

  if (!BYTES_ARE_IN_FRAME(0, len, BSD_ENC_HDRLEN))
    return false;

  memcpy((char *)&af, (const char *)&pd[0], sizeof(af));
  if ((af & 0xFFFF0000) != 0) {
    /*
     * BSD AF_ types will always have the upper 16 bits as 0, so if any
     * of them are non-zero, the af field must be byte-swapped, and
     * will, at least in DLT_ENC headers, always have at least one of
     * the lower 16 bits not being 0 (it won't be AF_UNSPEC, which is
     * 0), so if the af field is byte-swapped, at least one of the
     * upper 16 bits will be 0.
     */
    af = GUINT32_SWAP_LE_BE(af);
  }
  return try_capture_dissector("enc", af, pd, BSD_ENC_HDRLEN, len, cpinfo, pseudo_header);
}

static const value_string af_vals[] = {
  { BSD_AF_INET,  "IPv4" },
  { BSD_AF_INET6_BSD, "IPv6" },
  { 0, NULL }
};

static int
dissect_enc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  struct enchdr  ench;
  unsigned       writer_encoding;
  tvbuff_t      *next_tvb;
  proto_tree    *enc_tree;
  proto_item    *ti;

  static int * const flags[] = {
    &hf_enc_flags_payload_enc,
    &hf_enc_flags_payload_auth,
    &hf_enc_flags_payload_compress,
    &hf_enc_flags_header_auth,
    &hf_enc_flags_reserved,
    NULL
  };

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ENC");

  /*
   * Initially assume the file was written by a host with our byte order.
   */
  writer_encoding = ENC_HOST_ENDIAN;
  ench.af = tvb_get_h_uint32(tvb, 0);
  if ((ench.af & 0xFFFF0000) != 0) {
    /*
     * BSD AF_ types will always have the upper 16 bits as 0, so if any
     * of them are non-zero, the af field must be byte-swapped, and
     * will, at least in DLT_ENC headers, always have at least one of
     * the lower 16 bits not being 0 (it won't be AF_UNSPEC, which is
     * 0), so if the af field is byte-swapped, at least one of the
     * upper 16 bits will be 0.
     */
    ench.af = GUINT32_SWAP_LE_BE(ench.af);

    /*
     * It was written by a host with the *opposite* byte order.
     */
    writer_encoding = ENC_ANTI_HOST_ENDIAN;
  }
  ench.spi = tvb_get_ntohl(tvb, 4);

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_enc, tvb, 0,
                                        BSD_ENC_HDRLEN,
                                        "Enc %s, SPI 0x%8.8x",
                                        val_to_str(ench.af, af_vals, "unknown (%u)"),
                                        ench.spi);
    enc_tree = proto_item_add_subtree(ti, ett_enc);

    proto_tree_add_item(enc_tree, hf_enc_af, tvb, 0, 4, writer_encoding);
    proto_tree_add_item(enc_tree, hf_enc_spi, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(enc_tree, tvb, 8, hf_enc_flags, ett_enc_flag, flags, writer_encoding);
  }

  /* Set the tvbuff for the payload after the header */
  next_tvb = tvb_new_subset_remaining(tvb, BSD_ENC_HDRLEN);
  if (!dissector_try_uint(enc_dissector_table, ench.af, next_tvb, pinfo, tree))
    call_data_dissector(next_tvb, pinfo, tree);

  return tvb_captured_length(tvb);
}

void
proto_register_enc(void)
{
  static hf_register_info hf[] = {
    { &hf_enc_af,
      { "Address Family", "enc.af", FT_UINT32, BASE_DEC, VALS(af_vals), 0x0,
        "Protocol (IPv4 vs IPv6)", HFILL }},
    { &hf_enc_spi,
      { "SPI", "enc.spi", FT_UINT32, BASE_HEX, NULL, 0x0,
        "Security Parameter Index", HFILL }},
    { &hf_enc_flags,
      { "Flags", "enc.flags", FT_UINT32, BASE_HEX, NULL, 0x0,
        "ENC flags", HFILL }},
    { &hf_enc_flags_payload_enc,
      { "Payload encrypted", "enc.flags.payload_enc", FT_BOOLEAN, 32, NULL, BSD_ENC_M_CONF,
        NULL, HFILL }},
    { &hf_enc_flags_payload_auth,
      { "Payload authenticated", "enc.flags.payload_auth", FT_BOOLEAN, 32, NULL, BSD_ENC_M_AUTH,
        NULL, HFILL }},
    { &hf_enc_flags_payload_compress,
      { "Payload compressed", "enc.flags.payload_compress", FT_BOOLEAN, 32, NULL, BSD_ENC_M_COMP,
        NULL, HFILL }},
    { &hf_enc_flags_header_auth,
      { "Header authenticated", "enc.flags.header_auth", FT_BOOLEAN, 32, NULL, BSD_ENC_M_AUTH_AH,
        NULL, HFILL }},
    { &hf_enc_flags_reserved,
      { "Reserved", "enc.flags.reserved", FT_UINT32, BASE_HEX, NULL, BSD_ENC_M_RESERVED,
        NULL, HFILL }},
  };
  static int *ett[] =
  {
      &ett_enc,
      &ett_enc_flag
  };

  proto_enc = proto_register_protocol("OpenBSD Encapsulating device",
                                      "ENC", "enc");
  proto_register_field_array(proto_enc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  enc_dissector_table = register_dissector_table("enc", "OpenBSD Encapsulating device", proto_enc, FT_UINT32, BASE_DEC);
  register_capture_dissector_table("enc", "ENC");

  enc_handle  = register_dissector("enc", dissect_enc, proto_enc);
  enc_cap_handle = register_capture_dissector("enc", capture_enc, proto_enc);
}

void
proto_reg_handoff_enc(void)
{
  dissector_add_uint("wtap_encap", WTAP_ENCAP_ENC, enc_handle);
  capture_dissector_add_uint("wtap_encap", WTAP_ENCAP_ENC, enc_cap_handle);
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

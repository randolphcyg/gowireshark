/* packet-ziop.c
 * Routines for CORBA ZIOP packet disassembly
 * Significantly based on packet-giop.c
 * Copyright 2009 Alvaro Vega Garcia <avega at tid dot es>
 *
 * According with GIOP Compression RFP revised submission
 * OMG mars/2008-12-20
 * https://www.omg.org/spec/ZIOP/1.0/Beta1/PDF
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-ziop.h"
#include "packet-giop.h"
#include "packet-tcp.h"

/*
 * Set to 1 for DEBUG output - TODO make this a runtime option
 */

#define DEBUG   0

void proto_reg_handoff_ziop(void);
void proto_register_ziop(void);

/*
 * ------------------------------------------------------------------------------------------+
 *                                 Data/Variables/Structs
 * ------------------------------------------------------------------------------------------+
 */

static int proto_ziop;

/*
 * (sub)Tree declares
 */

static int hf_ziop_magic;
static int hf_ziop_giop_version_major;
static int hf_ziop_giop_version_minor;
static int hf_ziop_flags;
static int hf_ziop_message_type;
static int hf_ziop_message_size;
static int hf_ziop_compressor_id;
static int hf_ziop_original_length;

static int ett_ziop;

static expert_field ei_ziop_version;

static dissector_handle_t ziop_tcp_handle;


static const value_string ziop_compressor_ids[] = {
  { 0, "None" },
  { 1, "GZIP"},
  { 2, "PKZIP"},
  { 3, "BZIP2"},
  { 4, "ZLIB"},
  { 5, "LZMA"},
  { 6, "LZOP"},
  { 7, "RZIP"},
  { 8, "7X"},
  { 9, "XAR"},
  { 0, NULL}
};


static const value_string giop_message_types[] = {
  { 0x0, "Request" },
  { 0x1, "Reply"},
  { 0x2, "CancelRequest"},
  { 0x3, "LocateRequest"},
  { 0x4, "LocateReply"},
  { 0x5, "CloseConnection"},
  { 0x6, "MessageError"},
  { 0x7, "Fragment"},
  { 0, NULL}
};


static bool ziop_desegment = true;


/* Main entry point */
static int
dissect_ziop (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_) {
  unsigned offset = 0;
  uint8_t giop_version_major, giop_version_minor, message_type;

  proto_tree *ziop_tree = NULL;
  proto_item *ti;
  uint8_t flags;
  unsigned byte_order;
  const char *label = "none";

  if (tvb_reported_length(tvb) < 7)
      return 0;

  col_set_str (pinfo->cinfo, COL_PROTOCOL, ZIOP_MAGIC);

  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item (tree, proto_ziop, tvb, 0, -1, ENC_NA);
  ziop_tree = proto_item_add_subtree (ti, ett_ziop);

  proto_tree_add_item(ziop_tree, hf_ziop_magic, tvb, offset, 4, ENC_ASCII);
  offset += 4;
  proto_tree_add_item(ziop_tree, hf_ziop_giop_version_major, tvb, offset, 1, ENC_BIG_ENDIAN);
  giop_version_major = tvb_get_uint8(tvb, offset);
  offset++;
  proto_tree_add_item(ziop_tree, hf_ziop_giop_version_minor, tvb, offset, 1, ENC_BIG_ENDIAN);
  giop_version_minor = tvb_get_uint8(tvb, offset);
  offset++;

  if ( (giop_version_major < 1) ||
       (giop_version_minor < 2) )  /* earlier than GIOP 1.2 */
  {
      col_add_fstr (pinfo->cinfo, COL_INFO, "Version %u.%u",
                    giop_version_major, giop_version_minor);

      expert_add_info_format(pinfo, ti, &ei_ziop_version,
                               "Version %u.%u not supported",
                               giop_version_major,
                               giop_version_minor);

      call_data_dissector(tvb, pinfo, tree);
      return tvb_reported_length(tvb);
  }

  flags = tvb_get_uint8(tvb, offset);
  byte_order = (flags & 0x01) ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN;

  if (flags & 0x01) {
    label = "little-endian";
  }
  proto_tree_add_uint_format_value(ziop_tree, hf_ziop_flags, tvb, offset, 1,
                                        flags, "0x%02x (%s)", flags, label);
  offset++;

  proto_tree_add_item(ziop_tree, hf_ziop_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  message_type = tvb_get_uint8(tvb, offset);
  offset++;

  col_add_fstr (pinfo->cinfo, COL_INFO, "ZIOP %u.%u %s",
                giop_version_major,
                giop_version_minor,
                val_to_str(message_type, giop_message_types,
                           "Unknown message type (0x%02x)")
                );

  proto_tree_add_item(ziop_tree, hf_ziop_message_size, tvb, offset, 4, byte_order);
  offset += 4;
  proto_tree_add_item(ziop_tree, hf_ziop_compressor_id, tvb, offset, 2, byte_order);
  offset += 4;
  proto_tree_add_item(ziop_tree, hf_ziop_original_length, tvb, offset, 4, byte_order);

  return tvb_reported_length(tvb);
}

static unsigned
get_ziop_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  uint8_t flags;
  unsigned message_size;
  bool stream_is_big_endian;

  if ( tvb_memeql(tvb, 0, (const uint8_t *)ZIOP_MAGIC, 4) != 0)
    return 0;

  flags = tvb_get_uint8(tvb, offset + 6);

  stream_is_big_endian =  ((flags & 0x1) == 0);

  if (stream_is_big_endian)
    message_size = tvb_get_ntohl(tvb, offset + 8);
  else
    message_size = tvb_get_letohl(tvb, offset + 8);

  return message_size + ZIOP_HEADER_SIZE;
}

static int
dissect_ziop_tcp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data)
{
  if ( tvb_memeql(tvb, 0, (const uint8_t *)ZIOP_MAGIC, 4) != 0)
    {
      if (tvb_get_ntohl(tvb, 0) == GIOP_MAGIC_NUMBER)
        {
          dissect_giop(tvb, pinfo, tree);
          return tvb_captured_length(tvb);
        }
      return 0;
    }

  tcp_dissect_pdus(tvb, pinfo, tree, ziop_desegment, ZIOP_HEADER_SIZE,
                   get_ziop_pdu_len, dissect_ziop, data);
  return tvb_captured_length(tvb);
}


bool
dissect_ziop_heur (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data)
{
  unsigned tot_len;

  conversation_t *conversation;
  /* check magic number and version */

  tot_len = tvb_captured_length(tvb);

  if (tot_len < ZIOP_HEADER_SIZE) /* tot_len < 12 */
    {
      /* Not enough data captured to hold the ZIOP header; don't try
         to interpret it as GIOP. */
      return false;
    }
  if ( tvb_memeql(tvb, 0, (const uint8_t *)ZIOP_MAGIC, 4) != 0)
    {
      return false;
    }

  if ( pinfo->ptype == PT_TCP )
    {
      /*
       * Make the ZIOP dissector the dissector for this conversation.
       *
       * If this isn't the first time this packet has been processed,
       * we've already done this work, so we don't need to do it
       * again.
       */
      if (!pinfo->fd->visited)
        {
          conversation = find_or_create_conversation(pinfo);

          /* Set dissector */
          conversation_set_dissector(conversation, ziop_tcp_handle);
        }
      dissect_ziop_tcp (tvb, pinfo, tree, data);
    }
  else
    {
      dissect_ziop (tvb, pinfo, tree, data);
    }
  return true;
}

void
proto_register_ziop (void)
{
  /* A header field is something you can search/filter on.
   *
   * We create a structure to register our fields. It consists of an
   * array of hf_register_info structures, each of which are of the format
   * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
   */
  static hf_register_info hf[] = {
    { &hf_ziop_magic,
      { "Header magic", "ziop.magic", FT_STRING, BASE_NONE, NULL, 0x0,
        "ZIOPHeader magic", HFILL }},
    { &hf_ziop_giop_version_major,
      { "Header major version", "ziop.giop_version_major", FT_UINT8, BASE_OCT, NULL, 0x0,
        "ZIOPHeader giop_major_version", HFILL }},
    { &hf_ziop_giop_version_minor,
      { "Header minor version", "ziop.giop_version_minor", FT_UINT8, BASE_OCT, NULL, 0x0,
        "ZIOPHeader giop_minor_version", HFILL }},
    { &hf_ziop_flags,
      { "Header flags", "ziop.flags", FT_UINT8, BASE_OCT, NULL, 0x0,
        "ZIOPHeader flags", HFILL }},
    { &hf_ziop_message_type,
      { "Header type", "ziop.message_type", FT_UINT8, BASE_OCT, VALS(giop_message_types), 0x0,
        "ZIOPHeader message_type", HFILL }},
    { &hf_ziop_message_size,
      { "Header size", "ziop.message_size",  FT_UINT32, BASE_DEC, NULL, 0x0,
        "ZIOPHeader message_size", HFILL }},
    { &hf_ziop_compressor_id,
      { "Header compressor id", "ziop.compressor_id", FT_UINT16, BASE_DEC, VALS(ziop_compressor_ids), 0x0,
        "ZIOPHeader compressor_id", HFILL }},
    { &hf_ziop_original_length,
      { "Header original length", "ziop.original_length", FT_UINT32, BASE_DEC, NULL, 0x0,
        "ZIOP original_length", HFILL }}
  };

  static int *ett[] = {
    &ett_ziop
  };

  static ei_register_info ei[] = {
    { &ei_ziop_version, { "ziop.version_not_supported", PI_PROTOCOL, PI_WARN, "Version not supported", EXPFILL }},
  };

  expert_module_t* expert_ziop;

  proto_ziop = proto_register_protocol("Zipped Inter-ORB Protocol", "ZIOP", "ziop");
  proto_register_field_array (proto_ziop, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  expert_ziop = expert_register_protocol(proto_ziop);
  expert_register_field_array(expert_ziop, ei, array_length(ei));

  register_dissector("ziop", dissect_ziop, proto_ziop);
  ziop_tcp_handle = register_dissector("ziop.tcp", dissect_ziop_tcp, proto_ziop);
}


void
proto_reg_handoff_ziop (void)
{
  dissector_add_for_decode_as_with_preference("udp.port", ziop_tcp_handle);

  heur_dissector_add("tcp", dissect_ziop_heur, "ZIOP over TCP", "ziop_tcp", proto_ziop, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */

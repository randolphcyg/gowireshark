/* packet-eth.c
 * Routines for ethernet packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/etypes.h>
#include <epan/ipproto.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include <epan/conversation_table.h>
#include <epan/conversation_filter.h>
#include <epan/capture_dissectors.h>
#include <epan/exported_pdu.h>
#include <epan/tfs.h>
#include <wsutil/pint.h>
#include "packet-eth.h"
#include "packet-gre.h"
#include "packet-ieee8023.h"
#include "packet-ipx.h"
#include "packet-isl.h"
#include "packet-llc.h"
#include "packet-sll.h"
#include "packet-juniper.h"
#include "packet-sflow.h"
#include "packet-l2tp.h"
#include "packet-vxlan.h"
#include "packet-nsh.h"
#include "packet-acdr.h"
#include "packet-mctp.h"
#include <epan/crc32-tvb.h>
#include <wiretap/erf_record.h>

void proto_register_eth(void);
void proto_reg_handoff_eth(void);

#define PADDING_NONE        0
#define PADDING_ZEROS       1
#define PADDING_ANY         2

static int eth_padding = PADDING_ZEROS;
static unsigned eth_trailer_length;
/* By default, try to autodetect FCS */
static int eth_fcs = -1;
static bool eth_check_fcs;
/* Interpret packets as FW1 monitor file packets if they look as if they are */
static bool eth_interpret_as_fw1_monitor;
/* When capturing on a Cisco FEX some frames start with an extra destination mac */
static bool eth_deduplicate_dmac;
/* Preference settings defining conditions for which the CCSDS dissector is called */
static bool ccsds_heuristic_length;
static bool ccsds_heuristic_version;
static bool ccsds_heuristic_header;
static bool ccsds_heuristic_bit;

/* protocols and header fields */
static int proto_eth;
static int hf_eth_dst;
static int hf_eth_dst_resolved;
static int hf_eth_dst_oui;
static int hf_eth_dst_oui_resolved;
static int hf_eth_src;
static int hf_eth_src_resolved;
static int hf_eth_src_oui;
static int hf_eth_src_oui_resolved;
static int hf_eth_len;
static int hf_eth_type;
static int hf_eth_invalid_lentype;
static int hf_eth_addr;
static int hf_eth_addr_resolved;
static int hf_eth_addr_oui;
static int hf_eth_addr_oui_resolved;
static int hf_eth_dst_lg;
static int hf_eth_dst_ig;
static int hf_eth_src_lg;
static int hf_eth_src_ig;
static int hf_eth_lg;
static int hf_eth_ig;
static int hf_eth_padding;
static int hf_eth_trailer;
static int hf_eth_fcs;
static int hf_eth_fcs_status;
static int hf_eth_stream;

static int ett_ieee8023;
static int ett_ether2;
static int ett_ether;
static int ett_addr;

static expert_field ei_eth_invalid_lentype;
static expert_field ei_eth_src_not_group;
static expert_field ei_eth_fcs_bad;
static expert_field ei_eth_len;
static expert_field ei_eth_padding_bad;

static dissector_handle_t fw1_handle;
static dissector_handle_t ethertype_handle;
static capture_dissector_handle_t isl_cap_handle;
static capture_dissector_handle_t ipx_cap_handle;
static capture_dissector_handle_t llc_cap_handle;
static heur_dissector_list_t heur_subdissector_list;
static heur_dissector_list_t eth_trailer_subdissector_list;
static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t eth_maybefcs_handle;


static int eth_tap;
static uint32_t eth_stream_count;

static int exported_pdu_tap = -1;

#define ETH_HEADER_SIZE    14

static const true_false_string ig_tfs = {
  "Group address (multicast/broadcast)",
  "Individual address (unicast)"
};
static const true_false_string lg_tfs = {
  "Locally administered address (this is NOT the factory default)",
  "Globally unique address (factory default)"
};

static const enum_val_t eth_padding_vals[] = {
  {"never", "Never", PADDING_NONE},
  {"zeros", "Zeros", PADDING_ZEROS},
  {"any",   "Any",   PADDING_ANY},
  {NULL, NULL, 0}
};

static const enum_val_t eth_fcs_vals[] = {
  {"heuristic", "According to heuristic", -1},
  {"never",     "Never",                   0},
  {"always",    "Always",                  4},
  {NULL, NULL, 0}
};

static const char* eth_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
  if ((filter == CONV_FT_SRC_ADDRESS) && (conv->src_address.type == AT_ETHER))
    return "eth.src";

  if ((filter == CONV_FT_DST_ADDRESS) && (conv->dst_address.type == AT_ETHER))
    return "eth.dst";

  if ((filter == CONV_FT_ANY_ADDRESS) && (conv->src_address.type == AT_ETHER))
    return "eth.addr";

  return CONV_FILTER_INVALID;
}

static ct_dissector_info_t eth_ct_dissector_info = {&eth_conv_get_filter_type};

static tap_packet_status
eth_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
  conv_hash_t *hash = (conv_hash_t*) pct;
  hash->flags = flags;
  const eth_hdr *ehdr=(const eth_hdr *)vip;

  add_conversation_table_data_with_conv_id(hash, &ehdr->src, &ehdr->dst, 0, 0, (conv_id_t)ehdr->stream, 1, pinfo->fd->pkt_len,
                                           &pinfo->rel_ts, &pinfo->abs_ts, &eth_ct_dissector_info, CONVERSATION_ETH);

  return TAP_PACKET_REDRAW;
}

static const char* eth_endpoint_get_filter_type(endpoint_item_t* endpoint, conv_filter_type_e filter)
{
  if ((filter == CONV_FT_ANY_ADDRESS) && (endpoint->myaddress.type == AT_ETHER))
    return "eth.addr";

  return CONV_FILTER_INVALID;
}

static et_dissector_info_t eth_endpoint_dissector_info = {&eth_endpoint_get_filter_type};

static tap_packet_status
eth_endpoint_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
  conv_hash_t *hash = (conv_hash_t*) pit;
  hash->flags = flags;
  const eth_hdr *ehdr=(const eth_hdr *)vip;

  /* Take two "add" passes per packet, adding for each direction, ensures that all
     packets are counted properly (even if address is sending to itself)
     XXX - this could probably be done more efficiently inside endpoint_table */
  add_endpoint_table_data(hash, &ehdr->src, 0, true, 1, pinfo->fd->pkt_len, &eth_endpoint_dissector_info, ENDPOINT_NONE);
  add_endpoint_table_data(hash, &ehdr->dst, 0, false, 1, pinfo->fd->pkt_len, &eth_endpoint_dissector_info, ENDPOINT_NONE);

  return TAP_PACKET_REDRAW;
}

static bool
eth_filter_valid(packet_info *pinfo, void *user_data _U_)
{
    return (pinfo->dl_src.type == AT_ETHER);
}

static char*
eth_build_filter(packet_info *pinfo, void *user_data _U_)
{
    return ws_strdup_printf("eth.addr eq %s and eth.addr eq %s",
                address_to_str(pinfo->pool, &pinfo->dl_src),
                address_to_str(pinfo->pool, &pinfo->dl_dst));
}


/* These are the Netware-ish names for the different Ethernet frame types.
    EthernetII: The ethernet with a Type field instead of a length field
    Ethernet802.2: An 802.3 header followed by an 802.2 header
    Ethernet802.3: A raw 802.3 packet. IPX/SPX can be the only payload.
            There's no 802.2 hdr in this.
    EthernetSNAP: Basically 802.2, just with 802.2SNAP. For our purposes,
        there's no difference between 802.2 and 802.2SNAP, since we just
        pass it down to the LLC dissector. -- Gilbert
*/
#define ETHERNET_II     0
#define ETHERNET_802_2  1
#define ETHERNET_802_3  2
#define ETHERNET_SNAP   3

static bool
capture_eth(const unsigned char *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
  uint16_t etype, length;
  int ethhdr_type;          /* the type of ethernet frame */

  if (!BYTES_ARE_IN_FRAME(offset, len, ETH_HEADER_SIZE))
    return false;

  etype = pntoh16(&pd[offset+12]);

  if (etype <= IEEE_802_3_MAX_LEN) {
    /* Oh, yuck.  Cisco ISL frames require special interpretation of the
       destination address field; fortunately, they can be recognized by
       checking the first 5 octets of the destination address, which are
       01-00-0C-00-00 or 0C-00-0C-00-00 for ISL frames. */
    if ((pd[offset] == 0x01 || pd[offset] == 0x0C) && pd[offset+1] == 0x00
        && pd[offset+2] == 0x0C && pd[offset+3] == 0x00
        && pd[offset+4] == 0x00) {
      return call_capture_dissector(isl_cap_handle, pd, offset, len, cpinfo, pseudo_header);
    }
  }

  /*
   * If the type/length field is <= the maximum 802.3 length,
   * and is not zero, this is an 802.3 frame, and it's a length
   * field; it might be an Novell "raw 802.3" frame, with no
   * 802.2 LLC header, or it might be a frame with an 802.2 LLC
   * header.
   *
   * If the type/length field is >= the minimum Ethernet II length,
   * this is an Ethernet II frame, and it's a type field.
   *
   * If the type/length field is > maximum 802.3 length and < minimum
   * Ethernet II length, then this is an invalid packet.
   *
   * If the type/length field is zero (ETHERTYPE_UNK), this is
   * a frame used internally by the Cisco MDS switch to contain
   * Fibre Channel ("Vegas").  We treat that as an Ethernet II
   * frame; the dissector for those frames registers itself with
   * an ethernet type of ETHERTYPE_UNK.
   */
  if (etype > IEEE_802_3_MAX_LEN && etype < ETHERNET_II_MIN_LEN)
    return false;

  if (etype <= IEEE_802_3_MAX_LEN && etype != ETHERTYPE_UNK) {
    length = etype;

    /* Is there an 802.2 layer? I can tell by looking at the first 2
       bytes after the 802.3 header. If they are 0xffff, then what
       follows the 802.3 header is an IPX payload, meaning no 802.2.
       (IPX/SPX is they only thing that can be contained inside a
       straight 802.3 packet). A non-0xffff value means that there's an
       802.2 layer inside the 802.3 layer */
    if (pd[offset+14] == 0xff && pd[offset+15] == 0xff) {
      ethhdr_type = ETHERNET_802_3;
    }
    else {
      ethhdr_type = ETHERNET_802_2;
    }

    /* Convert the LLC length from the 802.3 header to a total
       frame length, by adding in the size of any data that preceded
       the Ethernet header, and adding in the Ethernet header size,
       and set the payload and captured-payload lengths to the minima
       of the total length and the frame lengths. */
    length += offset + ETH_HEADER_SIZE;
    if (len > length)
      len = length;
  } else {
    ethhdr_type = ETHERNET_II;
  }
  offset += ETH_HEADER_SIZE;

  switch (ethhdr_type) {
    case ETHERNET_802_3:
      return call_capture_dissector(ipx_cap_handle, pd, offset, len, cpinfo, pseudo_header);
    case ETHERNET_802_2:
      return call_capture_dissector(llc_cap_handle, pd, offset, len, cpinfo, pseudo_header);
    case ETHERNET_II:
      return try_capture_dissector("ethertype", etype, pd, offset, len, cpinfo, pseudo_header);
  }

  return false;
}

static bool check_is_802_2(tvbuff_t *tvb, int fcs_len);

static void
dissect_address_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bool check_group)
{
  static const mac_hf_list_t eth_dst = {
    &hf_eth_dst,
    &hf_eth_dst_resolved,
    &hf_eth_dst_oui,
    &hf_eth_dst_oui_resolved,
    &hf_eth_dst_lg,
    &hf_eth_dst_ig,
  };
  static const mac_hf_list_t eth_src = {
    &hf_eth_src,
    &hf_eth_src_resolved,
    &hf_eth_src_oui,
    &hf_eth_src_oui_resolved,
    &hf_eth_src_lg,
    &hf_eth_src_ig,
  };
  static const mac_hf_list_t eth_addr = {
    &hf_eth_addr,
    &hf_eth_addr_resolved,
    &hf_eth_addr_oui,
    &hf_eth_addr_oui_resolved,
    &hf_eth_lg,
    &hf_eth_ig,
  };
  proto_item *addr_item;

  proto_tree_add_mac48_detail(&eth_dst, &eth_addr, ett_addr, tvb, tree, 0);

  addr_item = proto_tree_add_mac48_detail(&eth_src, &eth_addr, ett_addr, tvb, tree, 6);
  if (check_group) {
    if (tvb_get_uint8(tvb, 6) & 0x01) {
      expert_add_info(pinfo, addr_item, &ei_eth_src_not_group);
    }
  }
}

static void
export_pdu(tvbuff_t *tvb, packet_info *pinfo)
{
  if (have_tap_listener(exported_pdu_tap)) {
    exp_pdu_data_t *exp_pdu_data = wmem_new0(pinfo->pool, exp_pdu_data_t);

    exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
    exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
    exp_pdu_data->pdu_tvb = tvb;
    tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
  }
}

static struct eth_analysis *
init_eth_conversation_data(packet_info *pinfo)
{
    struct eth_analysis *ethd;

    /* Initialize the eth protocol data structure to add to the ip conversation */
    ethd=wmem_new0(wmem_file_scope(), struct eth_analysis);

    ethd->initial_frame = pinfo->num;
    ethd->stream = 0;
    ethd->stream = eth_stream_count++;

    return ethd;
}

struct eth_analysis *
get_eth_conversation_data(conversation_t *conv, packet_info *pinfo)
{
  struct eth_analysis *ethd;

  /* Did the caller supply the conversation pointer? */
  if( conv==NULL ) {
    return NULL;
  }

  /* Get the data for this conversation */
  ethd=(struct eth_analysis *)conversation_get_proto_data(conv, proto_eth);

  if (!ethd) {
    ethd = init_eth_conversation_data(pinfo);
    conversation_add_proto_data(conv, proto_eth, ethd);
  }

  if (!ethd) {
    return NULL;
  }

  return ethd;
}

static proto_tree *
dissect_eth_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
    int fcs_len)
{
  proto_item        *ti = NULL;
  eth_hdr           *ehdr;
  bool              is_802_2;
  proto_tree        *fh_tree = NULL;
  static eth_hdr    ehdrs[4];
  static int        ehdr_num=0;
  proto_tree        *tree;
  ethertype_data_t  ethertype_data;
  heur_dtbl_entry_t *hdtbl_entry = NULL;
  struct eth_analysis *ethd=NULL;
  /* a facility for not duplicating long code */
  bool              needs_dissector_with_data = false;

  /* Rotating buffer */
  ehdr_num++;
  if(ehdr_num>=4){
     ehdr_num=0;
  }
  ehdr=&ehdrs[ehdr_num];

  tree=parent_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Ethernet");

  set_address_tvb(&pinfo->dl_dst, AT_ETHER, 6, tvb, 0);
  copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);
  copy_address_shallow(&ehdr->dst, &pinfo->dl_dst);

  set_address_tvb(&pinfo->dl_src, AT_ETHER, 6, tvb, 6);
  copy_address_shallow(&pinfo->src, &pinfo->dl_src);
  copy_address_shallow(&ehdr->src, &pinfo->dl_src);

  ehdr->type = tvb_get_ntohs(tvb, 12);

  tap_queue_packet(eth_tap, pinfo, ehdr);
  export_pdu(tvb, pinfo);

  /*
   * In case the packet is a non-Ethernet packet inside
   * Ethernet framing, allow heuristic dissectors to take
   * a first look before we assume that it's actually an
   * Ethernet packet.
   */
  if (dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, parent_tree, &hdtbl_entry, NULL))
    return fh_tree;

  if (ehdr->type <= IEEE_802_3_MAX_LEN) {
    /* Oh, yuck.  Cisco ISL frames require special interpretation of the
       destination address field; fortunately, they can be recognized by
       checking the first 5 octets of the destination address, which are
       01-00-0C-00-00 for ISL frames. */
    if ((tvb_get_uint8(tvb, 0) == 0x01 ||
      tvb_get_uint8(tvb, 0) == 0x0C) &&
      tvb_get_uint8(tvb, 1) == 0x00 &&
      tvb_get_uint8(tvb, 2) == 0x0C &&
      tvb_get_uint8(tvb, 3) == 0x00 &&
      tvb_get_uint8(tvb, 4) == 0x00) {
      dissect_isl(tvb, pinfo, parent_tree, fcs_len);
      return fh_tree;
    }
  }

  /*
   * If the type/length field is <= the maximum 802.3 length,
   * and is not zero, this is an 802.3 frame, and it's a length
   * field; it might be an Novell "raw 802.3" frame, with no
   * 802.2 LLC header, or it might be a frame with an 802.2 LLC
   * header.
   *
   * If the type/length field is >= the minimum Ethernet II length,
   * this is an Ethernet II frame, and it's a type field.
   *
   * If the type/length field is > maximum 802.3 length and < minimum
   * Ethernet II length, then this is an invalid packet.
   *
   * If the type/length field is zero (ETHERTYPE_UNK), this is
   * a frame used internally by the Cisco MDS switch to contain
   * Fibre Channel ("Vegas").  We treat that as an Ethernet II
   * frame; the dissector for those frames registers itself with
   * an ethernet type of ETHERTYPE_UNK.
   */
  if (ehdr->type > IEEE_802_3_MAX_LEN && ehdr->type < ETHERNET_II_MIN_LEN) {
    tvbuff_t *next_tvb;

    col_add_fstr(pinfo->cinfo, COL_INFO,
        "Ethernet Unknown: Invalid length/type: 0x%04x (%d)",
        ehdr->type, ehdr->type);
    ti = proto_tree_add_protocol_format(tree, proto_eth, tvb, 0, ETH_HEADER_SIZE,
        "Ethernet Unknown, Src: %s, Dst: %s",
        address_with_resolution_to_str(pinfo->pool, &pinfo->src),
        address_with_resolution_to_str(pinfo->pool, &pinfo->dst));
    fh_tree = proto_item_add_subtree(ti, ett_ether);

    dissect_address_data(tvb, pinfo, fh_tree, false);

    ti = proto_tree_add_item(fh_tree, hf_eth_invalid_lentype, tvb, 12, 2, ENC_BIG_ENDIAN);
    expert_add_info_format(pinfo, ti, &ei_eth_invalid_lentype,
        "Invalid length/type: 0x%04x (%d)", ehdr->type, ehdr->type);
    next_tvb = tvb_new_subset_remaining(tvb, 14);
    call_data_dissector(next_tvb, pinfo, parent_tree);
    return fh_tree;
  }

  if (ehdr->type <= IEEE_802_3_MAX_LEN && ehdr->type != ETHERTYPE_UNK) {

    is_802_2 = check_is_802_2(tvb, fcs_len);

    col_add_fstr(pinfo->cinfo, COL_INFO, "IEEE 802.3 Ethernet %s",
        (is_802_2 ? "" : "Raw "));
    if (tree) {
      ti = proto_tree_add_protocol_format(tree, proto_eth, tvb, 0, ETH_HEADER_SIZE,
        "IEEE 802.3 Ethernet %s", (is_802_2 ? "" : "Raw "));

      fh_tree = proto_item_add_subtree(ti, ett_ieee8023);
    }

    /* if IP is not referenced from any filters we don't need to worry about
       generating any tree items.  We must do this after we created the actual
       protocol above so that proto hier stat still works though.
    */
    if(!proto_field_is_referenced(parent_tree, proto_eth)){
      tree=NULL;
      fh_tree=NULL;
    }

    dissect_address_data(tvb, pinfo, fh_tree, false);

    dissect_802_3(ehdr->type, is_802_2, tvb, ETH_HEADER_SIZE, pinfo,
        parent_tree, fh_tree, hf_eth_len, hf_eth_trailer, &ei_eth_len, fcs_len);
  } else {
    if (eth_interpret_as_fw1_monitor) {
        const uint8_t *dst_addr = (const uint8_t*)pinfo->dst.data;

        if ((dst_addr[0] == 'i') || (dst_addr[0] == 'I') ||
            (dst_addr[0] == 'o') || (dst_addr[0] == 'O') ||
            (dst_addr[0] == 'e') || (dst_addr[0] == 'E')) {
            call_dissector(fw1_handle, tvb, pinfo, parent_tree);
            return fh_tree;
        }
    }

    col_set_str(pinfo->cinfo, COL_INFO, "Ethernet II");
    if (parent_tree) {
        if (PTREE_DATA(parent_tree)->visible) {
            ti = proto_tree_add_protocol_format(parent_tree, proto_eth, tvb, 0, ETH_HEADER_SIZE,
                "Ethernet II, Src: %s, Dst: %s",
                address_with_resolution_to_str(pinfo->pool, &pinfo->src),
                address_with_resolution_to_str(pinfo->pool, &pinfo->dst));
      }
      else {
            ti = proto_tree_add_item(parent_tree, proto_eth, tvb, 0, ETH_HEADER_SIZE, ENC_NA);
      }
      fh_tree = proto_item_add_subtree(ti, ett_ether2);
    }

    dissect_address_data(tvb, pinfo, fh_tree, true);

    proto_tree_add_uint(fh_tree, hf_eth_type, tvb, 12, 2, ehdr->type);

    ethertype_data.etype = ehdr->type;
    ethertype_data.payload_offset = ETH_HEADER_SIZE;
    ethertype_data.fh_tree = fh_tree;
    ethertype_data.trailer_id = hf_eth_trailer;
    ethertype_data.fcs_len = fcs_len;

    needs_dissector_with_data = true;
  }

  /* if we still did not leave the dissection, try identifying any ETH conversation
   * When deinterlacing was asked and an interface is known, create an _IN conv,
   * otherwise create an ordinary _NN one.
   *
   */

  unsigned conv_type = CONVERSATION_ETH_NN;
  /* deinterlacing is requested */
  if(prefs.conversation_deinterlacing_key>0) {
    uint32_t dtlc_iface = 0;

    if(prefs.conversation_deinterlacing_key&CONV_DEINT_KEY_INTERFACE &&
       pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID) {

      conv_type = CONVERSATION_ETH_IN;
      dtlc_iface = pinfo->rec->rec_header.packet_header.interface_id;
    }
    else {
      conv_type = CONVERSATION_ETH_NN;
    }

    // identify an existing conversation or create a new one
    conversation_t *conv_deint = find_conversation_deinterlacer(pinfo->num, &pinfo->src, &pinfo->dst, conv_type,
                                 dtlc_iface, 0, 0);
    if(!conv_deint) {
      conversation_new_deinterlacer(pinfo->num, &pinfo->src, &pinfo->dst,
                   conv_type, dtlc_iface, 0, 0);
    }
  }

  conversation_t *conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, conv_type, 0, 0, NO_PORT_X);

  if(!conv) {
    conv = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, conv_type, 0, 0, NO_PORTS);
  }
  else {
    /*
     * while not strictly necessary because there is only 1
     * conversation between 2 IPs, we still move the last frame
     * indicator as being a usual practice.
     */
    if (!(pinfo->fd->visited)) {
      if (pinfo->num > conv->last_frame) {
        conv->last_frame = pinfo->num;
      }
    }
  }

  ethd = get_eth_conversation_data(conv, pinfo);
  if(ethd) {
    ehdr->stream = ethd->stream;
    if(tree) {
      ti = proto_tree_add_uint(fh_tree, hf_eth_stream, tvb, 0, 0, ethd->stream);
      proto_item_set_generated(ti);
    }
  }

  if(needs_dissector_with_data) {
    call_dissector_with_data(ethertype_handle, tvb, pinfo, parent_tree, &ethertype_data);
  }

  return fh_tree;
}

static void
eth_init(void)
{
    eth_stream_count = 0;
}

/* -------------- */
static bool check_is_802_2(tvbuff_t *tvb, int fcs_len)
{
  volatile bool is_802_2;
  volatile int length;
  int captured_length, reported_length;

  is_802_2 = true;

    /* Is there an 802.2 layer? I can tell by looking at the first 2
       bytes after the 802.3 header. If they are 0xffff, then what
       follows the 802.3 header is an IPX payload, meaning no 802.2.
       A non-0xffff value means that there's an 802.2 layer or CCSDS
       layer inside the 802.3 layer */

  TRY {
    if (tvb_get_ntohs(tvb, 14) == 0xffff) {
        is_802_2 = false;
    }
    /* Is this a CCSDS payload instead of an 802.2 (LLC)?
       Check the conditions enabled by the user for CCSDS presence */
    else if (ccsds_heuristic_length || ccsds_heuristic_version ||
             ccsds_heuristic_header || ccsds_heuristic_bit) {
      bool CCSDS_len = true;
      bool CCSDS_ver = true;
      bool CCSDS_head = true;
      bool CCSDS_bit = true;
      /* See if the reported payload size matches the
         size contained in the CCSDS header. */
      if (ccsds_heuristic_length) {
        /* The following technique to account for FCS
           is copied from packet-ieee8023.c dissect_802_3() */
        length = tvb_get_ntohs(tvb, 12);
        reported_length = tvb_reported_length_remaining(tvb, ETH_HEADER_SIZE);
        if (fcs_len > 0) {
          if (reported_length >= fcs_len)
            reported_length -= fcs_len;
        }
        /* Make sure the length in the 802.3 header doesn't go past the end of
           the payload. */
        if (length > reported_length) {
          length = reported_length;
        }
        /* Only allow inspection of 'length' number of bytes. */
        captured_length = tvb_captured_length_remaining(tvb, ETH_HEADER_SIZE);
        if (captured_length > length)
          captured_length = length;

        /* Check if payload is large enough to contain a CCSDS header */
        if (captured_length >= 6) {
          /* Compare length to packet length contained in CCSDS header. */
          if (length != 7 + tvb_get_ntohs(tvb, ETH_HEADER_SIZE + 4))
            CCSDS_len = false;
        }
      }
      /* Check if CCSDS Version number (first 3 bits of payload) is zero */
      if ((ccsds_heuristic_version) && (tvb_get_bits8(tvb, 8*ETH_HEADER_SIZE, 3)!=0))
        CCSDS_ver = false;
      /* Check if Secondary Header Flag (4th bit of payload) is set to one. */
      if ((ccsds_heuristic_header) && (tvb_get_bits8(tvb, 8*ETH_HEADER_SIZE + 4, 1)!=1))
        CCSDS_head = false;
      /* Check if spare bit (1st bit of 7th word of payload) is zero. */
      if ((ccsds_heuristic_bit) && (tvb_get_bits8(tvb, 8*ETH_HEADER_SIZE + 16*6, 1)!=0))
        CCSDS_bit = false;
      /* If all the conditions are true, don't interpret payload as an 802.2 (LLC).
       * Additional check in packet-802.3.c will distinguish between
       * IPX and CCSDS packets*/
      if (CCSDS_len && CCSDS_ver && CCSDS_head && CCSDS_bit)
        is_802_2 = false;
    }
  }
  CATCH_BOUNDS_ERRORS {
        ; /* do nothing */

  }
  ENDTRY;
  return is_802_2;
}

/*
 * Add an Ethernet trailer - which, for some captures, might be the FCS
 * rather than a pad-to-60-bytes trailer.
 *
 * If fcs_len is 0, we assume the frame has no FCS; if it's 4, we assume
 * it has an FCS; if it's anything else (such as -1, which means "maybe
 * it does, maybe it doesn't"), we try to infer whether it has an FCS.
 */
void
add_ethernet_trailer(packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
    int trailer_id, tvbuff_t *tvb, tvbuff_t *trailer_tvb, int fcs_len,
    int payload_offset)
{
  /* If there're some bytes left over, it could be a combination of:
     - padding to meet the minimum 64 byte frame length
     - an FCS, if present (if fcs_len is 0, we know it's not present;
       if fcs_len is 4, we know it's present; if fcs_len is -1, we
       need some heuristics to determine whether it's present)
     - information inserted by TAPs or other network monitoring equipment.

     If we don't know whether the FCS is present, then, if we don't have a
     network monitoring trailer, and if the Ethernet frame was claimed to
     have had 64 or more bytes - i.e., it was at least an FCS worth of data
     longer than the minimum payload size - we could assume the last 4 bytes
     of the trailer are an FCS. */
  heur_dtbl_entry_t *hdtbl_entry;

  if (trailer_tvb) {
    unsigned trailer_length, trailer_reported_length;
    unsigned padding_length = 0;
    bool has_fcs = false;
    bool maybe_padded = false;
    tvbuff_t *real_trailer_tvb;

    trailer_length = tvb_captured_length(trailer_tvb);
    trailer_reported_length = tvb_reported_length(trailer_tvb);

    /* Theoretically padding is added if the frame length without the FCS is
     * less than 60 bytes, starting from the addresses. In practice, frames
     * are often padded so that the length is 60 bytes not counting any tags
     * before the final Ethertype. (I.e., padding so that the payload portion
     * is 46.)
     *
     * Padding might be added to a frame at one point in a network, and then a
     * tag or trailer added later without removing the padding. Conversely, a
     * frame might have padding and a tag and trailer, and then the tag removed,
     * dropping the frame below 60 octets, leading to more padding at the end,
     * after the trailer. https://gitlab.com/wireshark/wireshark/-/wikis/PRP
     * has useful illustrations of both situations. The heuristic trailer
     * dissectors can try to deal with both situations (though looping through
     * the trailer bytes increases false positives.)
     *
     * By increasing the minimum frame size (padding payload to 46) the former
     * situation always occurs, and trailers appear at the end. IEEE Std
     * 802.1Q-2014 G.2.1 "Treatment of PAD fields in IEEE 802.3 frames"
     * and G.2.3 "Minimum PDU size" specifically state it is permissible for a
     * Bridge to to adopt a minimum tagged frame length of 68 bytes (64 without
     * FCS) when 802.1Q is used. Other specs don't directly address this, but
     * we often see padding on frames that are more than 60 octets without FCS.
     */
    int frame_len;
    if (eth_padding == PADDING_ANY) {
      /* This is a size at which there definitely should be padding,
       * which we use with PADDING_ANY to be conservative so we don't
       * mark any possible trailer as padding. Fo certain cases (tags,
       * trailers, especially encapsulation like ISL, GSE Bridged Frames)
       * some padding will be classified as trailer.
       */
      frame_len = pinfo->fd->pkt_len;
    } else {
      /* This is the size up to which there might be padding, if padding
       * was added before adding tags after the first ethertype.
       * Use this if we're testing PADDING_ZERO, which is strict.
       * Consecutive zeroes up to this point will be padding,
       * anything starting with the first non-zero will be trailer.
       */
      frame_len = tvb_reported_length(tvb) + (14 - payload_offset);
    }
    maybe_padded = (frame_len >= 60 && (frame_len - trailer_reported_length) < 60);

    if (eth_padding != PADDING_NONE && maybe_padded) {
      /* XXX: There could be another 4 bytes of padding if a Bridge extends
       * the minimum frame size of 68 on untagged fraomes, see discussion
       * above of IEEE 802.1Q Annex G. If we require padding to be zeros,
       * we could possibly use 64 instead of 60. (Too many false positives
       * with PADDING_ANY.)
       */
      padding_length = 60 - (frame_len - trailer_reported_length);
      /* Require padding to be zeros */
      if (eth_padding == PADDING_ZEROS) {
        for (unsigned i = 0; i < padding_length; i++) {
          if (tvb_get_int8(trailer_tvb, i) != 0) {
            padding_length = i;
            break;
          }
        }
      }
      /* If it was determined that we have padding, add it to the tree. */
      if (padding_length > 0) {
          tvb_ensure_bytes_exist(tvb, 0, padding_length);
          proto_tree_add_item(fh_tree, hf_eth_padding, trailer_tvb, 0,
              padding_length, ENC_NA);
          trailer_length -= padding_length;
          trailer_reported_length -= padding_length;
      }
    }

    int payload_length = tvb_reported_length(tvb) - payload_offset;
    bool dissected = false;

    if (fcs_len != 4) {
      /* Try trailer dissection without an FCS */
      real_trailer_tvb = tvb_new_subset_remaining(trailer_tvb, padding_length);
      /* Call all ethernet trailer dissectors to dissect the trailer if
         we actually have a trailer. The PRP trailer dissector wants
         to know about the payload (LSDU) length. */
      if (tvb_reported_length(real_trailer_tvb) != 0) {
        dissected = dissector_try_heuristic(eth_trailer_subdissector_list,
                                            real_trailer_tvb, pinfo, tree,
                                            &hdtbl_entry, &payload_length);
      }
    }

    if (fcs_len != 0) {
      /* If fcs_len is 4, we assume we definitely have an FCS.
         If fcs_len is -1, if the frame is big enough that, if we
         have a trailer, it probably includes an FCS, and we have
         enough space in the trailer for the FCS, and we didn't
         have a heuristic trailer dissector successfully dissect
         without an FCS, we assume we have an FCS.

         "Big enough" means 64 bytes or more; any frame that big
         needs no trailer, as there's no need to pad an Ethernet
         packet past 60 bytes.

         XXX: This is not quite true. See IEEE Std 802.1Q-2014
         G.2.1 "Treatment of PAD fields in IEEE 802.3 frames" and
         G.2.3 "Minimum PDU size" and the discussion above.

         The trailer must be at least 4 bytes long to have enough
         space for an FCS. */

      if (fcs_len == 4 || (fcs_len == -1 && !dissected &&
        frame_len >= 64 && trailer_reported_length >= 4)) {
        /* Either we know we have an FCS, or we believe we have an FCS. */
        if (trailer_length < trailer_reported_length) {
          /* The packet is claimed to have enough data for a 4-byte FCS,
             but we didn't capture all of the packet.
             Slice off the 4-byte FCS from the reported length, and
             trim the captured length so it's no more than the reported
             length; that will slice off what of the FCS, if any, is
             in the captured packet. */
          trailer_reported_length -= 4;
          if (trailer_length > trailer_reported_length) {
            payload_length -= (trailer_length - trailer_reported_length);
            trailer_length = trailer_reported_length;
          }
          has_fcs = true;
        } else {
          /* We captured all of the packet, including what appears to
             be a 4-byte FCS.  Slice it off. */
          trailer_length -= 4;
          trailer_reported_length -= 4;
          payload_length -= 4;
          has_fcs = true;
        }

        real_trailer_tvb = tvb_new_subset_length_caplen(trailer_tvb, padding_length,
                                  trailer_length, trailer_reported_length);

        /* Call all ethernet trailer dissectors to dissect the trailer if
           we actually have a trailer.  */
        if (tvb_reported_length(real_trailer_tvb) != 0) {
          dissected = dissector_try_heuristic(eth_trailer_subdissector_list,
                                              real_trailer_tvb, pinfo, tree,
                                              &hdtbl_entry, &payload_length);
        }
      }
    }

    if (!dissected) {
      /* No luck with the trailer dissectors, so just display the
         extra bytes as general trailer */
      if (trailer_length != 0) {
        tvb_ensure_bytes_exist(real_trailer_tvb, 0, trailer_length);
        proto_item *pi = proto_tree_add_item(fh_tree, trailer_id, real_trailer_tvb, 0,
          trailer_length, ENC_NA);
        if (maybe_padded) {
          if (eth_padding == PADDING_ANY && padding_length > 0) {
            expert_add_info_format(pinfo, pi, &ei_eth_padding_bad,
                "Padding was assumed, and an undecoded trailer exists. Some of the trailer may have been consumed by padding.");
          }
          else if (eth_padding == PADDING_ZEROS && padding_length == 0) {
            expert_add_info_format(pinfo, pi, &ei_eth_padding_bad,
                "Didn't find padding of zeros, and an undecoded trailer exists. There may be padding of non-zeros.");
          }
        }
      }
    }

    if (has_fcs) {
      uint32_t sent_fcs = tvb_get_ntohl(trailer_tvb, padding_length+trailer_length);
      /* If we don't have the entire header, we can't actually check the FCS.
       * Dissectors that don't have the entire header (say, a tag) probably
       * should have set fcs_len to zero in the ethertype_data struct.
       * XXX: Maybe add an expert info saying why we aren't checking the FCS? */
      if (eth_check_fcs && payload_offset == ETH_HEADER_SIZE) {
        uint32_t fcs = crc32_802_tvb(tvb, tvb_captured_length(tvb) - 4);
        proto_tree_add_checksum(fh_tree, trailer_tvb, padding_length+trailer_length, hf_eth_fcs, hf_eth_fcs_status, &ei_eth_fcs_bad, pinfo, fcs, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

        if (fcs != sent_fcs) {
          col_append_str(pinfo->cinfo, COL_INFO, " [ETHERNET FRAME CHECK SEQUENCE INCORRECT]");
        }
      }else{
        proto_tree_add_checksum(fh_tree, trailer_tvb, padding_length+trailer_length, hf_eth_fcs, hf_eth_fcs_status, &ei_eth_fcs_bad, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
      }
      trailer_length += 4;
    }
    proto_tree_set_appendix(fh_tree, tvb, tvb_captured_length(tvb) - padding_length - trailer_length, padding_length + trailer_length);
  }
}

/* Called for the Ethernet Wiretap encapsulation type; pass the FCS length
   reported to us, if known, otherwise falling back to the "fcs" preference. */
static int
dissect_eth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct eth_phdr   *eth = (struct eth_phdr *)data;
  proto_tree        *fh_tree;
  tvbuff_t          *real_tvb;
  int                fcs_len;

  if (eth && eth->fcs_len != -1) {
    /* Use the value reported from Wiretap, if known. */
    fcs_len = eth->fcs_len;
  } else {
    fcs_len = eth_fcs;
  }

  /* When capturing on a Cisco FEX, some frames (most likely all frames
     captured without a vntag) have an extra destination mac prepended. */
  if (eth_deduplicate_dmac && tvb_captured_length(tvb) > 20 &&
      memcmp(tvb_get_ptr(tvb,0,6),tvb_get_ptr(tvb,6,6), 6) == 0) {
    real_tvb = tvb_new_subset_length_caplen(tvb, 6,
      tvb_captured_length(tvb) - 6, tvb_reported_length(tvb) - 6);
  } else {
    real_tvb = tvb;
  }

  /* Some devices slice the packet and add their own trailer before
     putting the frame on the network. Make sure these packets get
     a proper trailer (even though the sliced frame might not
     properly dissect. */
  if ( (eth_trailer_length > 0) && (eth_trailer_length < tvb_captured_length(real_tvb)) ) {
    tvbuff_t *next_tvb;
    unsigned total_trailer_length = eth_trailer_length;

    /* If we have to guess if the trailer includes the FCS, assume not; the
     * user probably set the "eth_trailer_length" preference to the total
     * trailer length. The user has already set the preference, so should
     * have little difficulty changing it or the "fcs" preference if need be.
     */
    total_trailer_length += (fcs_len < 0 ? 0 : (unsigned)fcs_len);

    /* Dissect the tvb up to, but not including the trailer */
    next_tvb = tvb_new_subset_length_caplen(real_tvb, 0,
                              tvb_captured_length(real_tvb) - total_trailer_length,
                              tvb_reported_length(real_tvb) - total_trailer_length);
    fh_tree = dissect_eth_common(next_tvb, pinfo, tree, 0);

    /* Now handle the ethernet trailer and optional FCS */
    next_tvb = tvb_new_subset_remaining(real_tvb, tvb_captured_length(real_tvb) - total_trailer_length);
    add_ethernet_trailer(pinfo, tree, fh_tree, hf_eth_trailer, real_tvb, next_tvb,
                         fcs_len, ETH_HEADER_SIZE);
  } else {
    dissect_eth_common(real_tvb, pinfo, tree, fcs_len);
  }
  return tvb_captured_length(tvb);
}

/* Called by other dissectors  This one's for encapsulated Ethernet
   packets that don't include an FCS. */
static int
dissect_eth_withoutfcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_eth_common(tvb, pinfo, tree, 0);
  return tvb_captured_length(tvb);
}

/* ...and this one's for encapsulated packets that do. */
static int
dissect_eth_withfcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_eth_common(tvb, pinfo, tree, 4);
  return tvb_captured_length(tvb);
}

/* ...and this one's for encapsulated packets that might or might not. */
static int
dissect_eth_maybefcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  dissect_eth_common(tvb, pinfo, tree, eth_fcs);
  return tvb_captured_length(tvb);
}

void
proto_register_eth(void)
{
  register_init_routine(eth_init);

  static hf_register_info hf[] = {

    { &hf_eth_dst,
      { "Destination", "eth.dst", FT_ETHER, BASE_NONE, NULL, 0x0,
        "Destination Hardware Address", HFILL }},

    { &hf_eth_dst_resolved,
      { "Destination (resolved)", "eth.dst_resolved", FT_STRING, BASE_NONE,
        NULL, 0x0, "Destination Hardware Address (resolved)", HFILL }},

    { &hf_eth_dst_oui,
      { "Destination OUI", "eth.dst.oui", FT_UINT24, BASE_OUI,
        NULL, 0x0, "Destination Organizationally Unique Identifier", HFILL } },

    { &hf_eth_dst_oui_resolved,
      { "Destination OUI (resolved)", "eth.dst.oui_resolved", FT_STRING, BASE_NONE,
         NULL, 0x0, "Destination Organizationally Unique Identifier (resolved)", HFILL } },

    { &hf_eth_src,
      { "Source", "eth.src", FT_ETHER, BASE_NONE, NULL, 0x0,
        "Source Hardware Address", HFILL }},

    { &hf_eth_src_resolved,
      { "Source (resolved)", "eth.src_resolved", FT_STRING, BASE_NONE,
        NULL, 0x0, "Source Hardware Address (resolved)", HFILL }},


    { &hf_eth_src_oui,
      { "Source OUI", "eth.src.oui", FT_UINT24, BASE_OUI,
        NULL, 0x0, "Source Organizationally Unique Identifier", HFILL } },

    { &hf_eth_src_oui_resolved,
      { "Source OUI (resolved)", "eth.src.oui_resolved", FT_STRING, BASE_NONE,
        NULL, 0x0, "Source Organizationally Unique Identifier (resolved)", HFILL } },

    { &hf_eth_len,
      { "Length", "eth.len", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    /* registered here but handled in packet-ethertype.c */
    { &hf_eth_type,
      { "Type", "eth.type", FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
        NULL, HFILL }},

    { &hf_eth_invalid_lentype,
      { "Invalid length/type", "eth.invalid_lentype", FT_UINT16, BASE_HEX_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_eth_addr,
      { "Address", "eth.addr", FT_ETHER, BASE_NONE, NULL, 0x0,
        "Source or Destination Hardware Address", HFILL }},

    { &hf_eth_addr_resolved,
      { "Address (resolved)", "eth.addr_resolved", FT_STRING, BASE_NONE,
        NULL, 0x0, "Source or Destination Hardware Address (resolved)",
        HFILL }},

    { &hf_eth_addr_oui,
      { "Address OUI", "eth.addr.oui", FT_UINT24, BASE_OUI,
        NULL, 0x0, "Address Organizationally Unique Identifier", HFILL } },

    { &hf_eth_addr_oui_resolved,
      { "Address OUI (resolved)", "eth.addr.oui_resolved", FT_STRING, BASE_NONE,
        NULL, 0x0, "Address Organizationally Unique Identifier (resolved)", HFILL } },

    { &hf_eth_padding,
      { "Padding", "eth.padding", FT_BYTES, BASE_NONE, NULL, 0x0,
        "Ethernet Padding", HFILL }},

    { &hf_eth_trailer,
      { "Trailer", "eth.trailer", FT_BYTES, BASE_NONE, NULL, 0x0,
        "Ethernet Trailer or Checksum", HFILL }},

    { &hf_eth_fcs,
      { "Frame check sequence", "eth.fcs", FT_UINT32, BASE_HEX, NULL, 0x0,
        "Ethernet checksum", HFILL }},

    { &hf_eth_fcs_status,
      { "FCS Status", "eth.fcs.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
        NULL, HFILL }},

    { &hf_eth_dst_lg,
      { "LG bit", "eth.dst.lg", FT_BOOLEAN, 24,
        TFS(&lg_tfs), 0x020000,
        "Specifies if this is a locally administered or globally unique (IEEE assigned) address", HFILL }},

    { &hf_eth_dst_ig,
      { "IG bit", "eth.dst.ig", FT_BOOLEAN, 24,
        TFS(&ig_tfs), 0x010000,
        "Specifies if this is an individual (unicast) or group (broadcast/multicast) address", HFILL }},

    { &hf_eth_src_lg,
      { "LG bit", "eth.src.lg", FT_BOOLEAN, 24,
        TFS(&lg_tfs), 0x020000,
        "Specifies if this is a locally administered or globally unique (IEEE assigned) address", HFILL }},

    { &hf_eth_src_ig,
      { "IG bit", "eth.src.ig", FT_BOOLEAN, 24,
        TFS(&ig_tfs), 0x010000,
        "Specifies if this is an individual (unicast) or group (broadcast/multicast) address", HFILL }},

    { &hf_eth_lg,
      { "LG bit", "eth.lg", FT_BOOLEAN, 24,
        TFS(&lg_tfs), 0x020000,
        "Specifies if this is a locally administered or globally unique (IEEE assigned) address", HFILL }},

    { &hf_eth_ig,
      { "IG bit", "eth.ig", FT_BOOLEAN, 24,
        TFS(&ig_tfs), 0x010000,
        "Specifies if this is an individual (unicast) or group (broadcast/multicast) address", HFILL }},

    { &hf_eth_stream,
      { "Stream index", "eth.stream", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }}
  };
  static int *ett[] = {
    &ett_ieee8023,
    &ett_ether2,
    &ett_ether,
    &ett_addr,
  };

  static ei_register_info ei[] = {
    { &ei_eth_invalid_lentype, { "eth.invalid_lentype.expert", PI_PROTOCOL, PI_WARN, "Invalid length/type", EXPFILL }},
    { &ei_eth_src_not_group, { "eth.src_not_group", PI_PROTOCOL, PI_WARN, "Source MAC must not be a group address: IEEE 802.3-2002, Section 3.2.3(b)", EXPFILL }},
    { &ei_eth_fcs_bad, { "eth.fcs_bad", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
    { &ei_eth_len, { "eth.len.past_end", PI_MALFORMED, PI_ERROR, "Length field value goes past the end of the payload", EXPFILL }},
    { &ei_eth_padding_bad, {"eth.padding_bad", PI_PROTOCOL, PI_NOTE, "Padding identification may be inaccurate and impact trailer dissector", EXPFILL }},
  };

  module_t *eth_module;
  expert_module_t* expert_eth;

  proto_eth = proto_register_protocol("Ethernet", "Ethernet", "eth");
  proto_register_field_array(proto_eth, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_eth = expert_register_protocol(proto_eth);
  expert_register_field_array(expert_eth, ei, array_length(ei));

  /* subdissector code */
  heur_subdissector_list = register_heur_dissector_list_with_description("eth", "Ethernet framed non-Ethernet data", proto_eth);
  eth_trailer_subdissector_list = register_heur_dissector_list_with_description("eth.trailer", "Ethernet trailer", proto_eth);

  /* Register configuration preferences */
  eth_module = prefs_register_protocol(proto_eth, NULL);

  prefs_register_obsolete_preference(eth_module, "assume_padding");
  prefs_register_enum_preference(eth_module, "padding",
                                 "Assume padding for short frames with trailer",
                                 "Some devices add trailing data to frames.  Depending on where this "
                                 "device exists in the network, padding could be added to short "
                                 "frames before the additional trailer.  This option determines how "
                                 "that padding will be detected.\n\n"
                                 "Never - Don't detect any padding.  Any bytes after the ethernet "
                                 "payload will be considered trailer.\n"
                                 "Zeros (default) - Consecutive bytes of zeros up to the minimum "
                                 "ethernet frame size will be treated as padding.  Additional bytes will "
                                 "be considered trailer.\n"
                                 "Any - Any bytes after the payload up to the minimum ethernet frame "
                                 "size will be treated as padding.  Additional bytes will be considered "
                                 "trailer.",
                                 &eth_padding, eth_padding_vals, false);

  prefs_register_uint_preference(eth_module, "trailer_length",
                                 "Fixed ethernet trailer length",
                                 "Some TAPs add a fixed length ethernet trailer at the end "
                                 "of the frame, but before the (optional) FCS. Make sure it "
                                 "gets interpreted correctly.",
                                 10, &eth_trailer_length);

  prefs_register_obsolete_preference(eth_module, "assume_fcs");
  prefs_register_enum_preference(eth_module, "fcs",
                                 "Assume packets have FCS",
                                 "Some Ethernet adapters and drivers include the FCS at the end of a packet, others do not.  "
                                 "Some capture file formats and protocols do not indicate whether or not the FCS is included. "
                                 "The Ethernet dissector then attempts to guess whether a captured packet has an FCS, "
                                 "but it cannot always guess correctly.  This option can override that heuristic "
                                 "and assume that the FCS is either never or always present in such cases.",
                                 &eth_fcs, eth_fcs_vals, false);

  prefs_register_bool_preference(eth_module, "check_fcs",
                                 "Validate the Ethernet checksum if possible",
                                 "Whether to validate the Frame Check Sequence",
                                 &eth_check_fcs);

  prefs_register_bool_preference(eth_module, "interpret_as_fw1_monitor",
                                 "Attempt to interpret as FireWall-1 monitor file",
                                 "Whether packets should be interpreted as coming from CheckPoint FireWall-1 monitor file if they look as if they do",
                                 &eth_interpret_as_fw1_monitor);

  prefs_register_bool_preference(eth_module, "deduplicate_dmac",
                                 "Skip bytes 1-6 if identical to 7-12",
                                 "When capturing on a Cisco FEX some frames start with an extra destination mac",
                                 &eth_deduplicate_dmac);

  prefs_register_static_text_preference(eth_module, "ccsds_heuristic",
                                        "Dissect as CCSDS if",
                                        "These are the conditions to match a payload against in order to determine if this\n"
                                        "is a CCSDS (Consultative Committee for Space Data Systems) packet within\n"
                                        "an 802.3 packet. A packet is considered as a possible CCSDS packet only if\n"
                                        "one or more of the conditions are checked.");

  prefs_register_bool_preference(eth_module, "ccsds_heuristic_length",
                                 "CCSDS Length in header matches payload size",
                                 "Set the condition that must be true for the CCSDS dissector to be called",
                                 &ccsds_heuristic_length);

  prefs_register_bool_preference(eth_module, "ccsds_heuristic_version",
                                 "CCSDS Version # is zero",
                                 "Set the condition that must be true for the CCSDS dissector to be called",
                                 &ccsds_heuristic_version);

  prefs_register_bool_preference(eth_module, "ccsds_heuristic_header",
                                 "CCSDS Secondary Header Flag is set",
                                 "Set the condition that must be true for the CCSDS dissector to be called",
                                 &ccsds_heuristic_header);

  prefs_register_bool_preference(eth_module, "ccsds_heuristic_bit",
                                 "CCSDS Spare bit is cleared",
                                 "Set the condition that must be true for the CCSDS dissector to be called",
                                 &ccsds_heuristic_bit);

  eth_withoutfcs_handle = register_dissector("eth_withoutfcs", dissect_eth_withoutfcs, proto_eth);
  register_dissector("eth_withfcs", dissect_eth_withfcs, proto_eth);
  eth_maybefcs_handle = register_dissector("eth_maybefcs", dissect_eth_maybefcs, proto_eth);
  eth_tap = register_tap("eth");

  register_conversation_table(proto_eth, true, eth_conversation_packet, eth_endpoint_packet);
  register_conversation_filter("eth", "Ethernet", eth_filter_valid, eth_build_filter, NULL);

  register_capture_dissector("eth", capture_eth, proto_eth);
}

void
proto_reg_handoff_eth(void)
{
  dissector_handle_t eth_handle;
  capture_dissector_handle_t eth_cap_handle;

  /* Get a handle for the Firewall-1 dissector. */
  fw1_handle = find_dissector_add_dependency("fw1", proto_eth);

  /* Get a handle for the ethertype dissector. */
  ethertype_handle = find_dissector_add_dependency("ethertype", proto_eth);

  eth_handle = create_dissector_handle(dissect_eth, proto_eth);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_ETHERNET, eth_handle);
  /* This needs a different (& more user-friendly) name than the other tap */
  exported_pdu_tap = register_export_pdu_tap_with_encap("Ethernet", WTAP_ENCAP_ETHERNET);

  dissector_add_uint("ethertype", ETHERTYPE_ETHBRIDGE, eth_withoutfcs_handle);

  dissector_add_uint("erf.types.type", ERF_TYPE_ETH, eth_maybefcs_handle);
  dissector_add_uint("erf.types.type", ERF_TYPE_COLOR_ETH, eth_maybefcs_handle);
  dissector_add_uint("erf.types.type", ERF_TYPE_DSM_COLOR_ETH, eth_maybefcs_handle);
  dissector_add_uint("erf.types.type", ERF_TYPE_COLOR_HASH_ETH, eth_maybefcs_handle);
  dissector_add_uint("ip.proto", IP_PROTO_ETHERNET, eth_maybefcs_handle);

  dissector_add_uint("chdlc.protocol", ETHERTYPE_ETHBRIDGE, eth_withoutfcs_handle);
  dissector_add_for_decode_as("gre.subproto", eth_withoutfcs_handle);
  dissector_add_uint("gre.proto", ETHERTYPE_ETHBRIDGE, eth_withoutfcs_handle);
  dissector_add_uint("gre.proto", GRE_MIKROTIK_EOIP, eth_withoutfcs_handle);
  dissector_add_uint("juniper.proto", JUNIPER_PROTO_ETHER, eth_withoutfcs_handle);
  dissector_add_uint("sflow_245.header_protocol", SFLOW_245_HEADER_ETHERNET, eth_withoutfcs_handle);
  dissector_add_uint("l2tp.pw_type", L2TPv3_PW_ETH, eth_withoutfcs_handle);
  dissector_add_uint("vxlan.next_proto", VXLAN_ETHERNET, eth_withoutfcs_handle);
  dissector_add_uint("sll.ltype", LINUX_SLL_P_ETHERNET, eth_withoutfcs_handle);
  dissector_add_uint("nsh.next_proto", NSH_ETHERNET, eth_withoutfcs_handle);

  dissector_add_uint("acdr.media_type", ACDR_Control, eth_withoutfcs_handle);
  dissector_add_uint("acdr.media_type", ACDR_DSP_SNIFFER, eth_withoutfcs_handle);
  dissector_add_uint("mctp.encap-type", MCTP_TYPE_ETHERNET, eth_withoutfcs_handle);

  /*
   * This is to handle the output for the Cisco CMTS "cable intercept"
   * command - it encapsulates Ethernet frames in UDP packets, but
   * the UDP port is user-defined.
   */
  dissector_add_for_decode_as_with_preference("udp.port", eth_withoutfcs_handle);

  dissector_add_for_decode_as("pcli.payload", eth_withoutfcs_handle);

  eth_cap_handle = find_capture_dissector("eth");
  capture_dissector_add_uint("wtap_encap", WTAP_ENCAP_ETHERNET, eth_cap_handle);
  capture_dissector_add_uint("atm_lane", TRAF_ST_LANE_802_3, eth_cap_handle);
  capture_dissector_add_uint("atm_lane", TRAF_ST_LANE_802_3_MC, eth_cap_handle);
  capture_dissector_add_uint("ppi", 1 /* DLT_EN10MB */, eth_cap_handle);
  capture_dissector_add_uint("sll.ltype", LINUX_SLL_P_ETHERNET, eth_cap_handle);

  isl_cap_handle = find_capture_dissector("isl");
  ipx_cap_handle = find_capture_dissector("ipx");
  llc_cap_handle = find_capture_dissector("llc");
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

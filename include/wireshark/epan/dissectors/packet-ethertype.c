/* packet-ethertype.c
 * Routines for processing Ethernet payloads and payloads like Ethernet
 * payloads (i.e., payloads when there could be an Ethernet trailer and
 * possibly an FCS).
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
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
#include <epan/etypes.h>
#include <epan/ppptypes.h>
#include <epan/show_exception.h>
#include <epan/decode_as.h>
#include <epan/capture_dissectors.h>
#include <epan/proto_data.h>
#include "packet-eth.h"

void proto_register_ethertype(void);

static dissector_table_t ethertype_dissector_table;

static int proto_ethertype;

const value_string etype_vals[] = {
	{ ETHERTYPE_IP,                   "IPv4" },
	{ ETHERTYPE_IPv6,                 "IPv6" },
	{ ETHERTYPE_VLAN,                 "802.1Q Virtual LAN" },
	{ ETHERTYPE_SLPP,                 "Simple Loop Protection Protocol" },
	{ ETHERTYPE_VLACP,                "Virtual LACP" }, /* Nortel/Avaya/Extremenetworks */
	{ ETHERTYPE_OLDSLPP,              "Simple Loop Protection Protocol (old)" },
	{ ETHERTYPE_ARP,                  "ARP" },
	{ ETHERTYPE_WLCCP,                "Cisco Wireless Lan Context Control Protocol" },
	{ ETHERTYPE_MINT,                 "Motorola Media Independent Network Transport" },
	{ ETHERTYPE_CENTRINO_PROMISC,     "IEEE 802.11 (Centrino promiscuous)" },
	{ ETHERTYPE_XNS_IDP,              "XNS Internet Datagram Protocol" },
	{ ETHERTYPE_X25L3,                "X.25 Layer 3" },
	{ ETHERTYPE_WOL,                  "Wake on LAN" },
	{ ETHERTYPE_WMX_M2M,              "WiMax Mac-to-Mac" },
	{ ETHERTYPE_EPL_V1,               "EPL_V1" },
	{ ETHERTYPE_REVARP,               "RARP" },
	{ ETHERTYPE_DEC_LB,               "DEC LanBridge" },
	{ ETHERTYPE_ATALK,                "AppleTalk LLAP bridging" },
	{ ETHERTYPE_SNA,                  "SNA-over-Ethernet" },
	{ ETHERTYPE_DLR,                  "EtherNet/IP Device Level Ring" },
	{ ETHERTYPE_AARP,                 "AARP" },
	{ ETHERTYPE_IPX,                  "Netware IPX/SPX" },
	{ ETHERTYPE_VINES_IP,             "Vines IP" },
	{ ETHERTYPE_VINES_ECHO,           "Vines Echo" },
	{ ETHERTYPE_TRAIN,                "Netmon Train" },
	/* Ethernet Loopback */
	{ ETHERTYPE_LOOP,                 "Loopback" },
	{ ETHERTYPE_FOUNDRY,              "Foundry proprietary" },
	{ ETHERTYPE_WCP,                  "Wellfleet Compression Protocol" },
	{ ETHERTYPE_STP,                  "Spanning Tree Protocol" },
	/* for ISMP, see RFC 2641, RFC 2642, RFC 2643 */
	{ ETHERTYPE_ISMP,                 "Cabletron Interswitch Message Protocol" },
	{ ETHERTYPE_ISMP_TBFLOOD,         "Cabletron SFVLAN 1.8 Tag-Based Flood" },
	/* In www.iana.org/assignments/ethernet-numbers, 8203-8205 description is
	 * Quantum Software.  Now the company is called QNX Software Systems. */
	{ ETHERTYPE_QNX_QNET6,            "QNX 6 QNET protocol" },
	{ ETHERTYPE_PPPOED,               "PPPoE Discovery" },
	{ ETHERTYPE_PPPOES,               "PPPoE Session" },
	{ ETHERTYPE_LINK_CTL,             "HomePNA, wlan link local tunnel" },
	{ ETHERTYPE_INTEL_ANS,            "Intel ANS probe" },
	{ ETHERTYPE_MS_NLB_HEARTBEAT,     "MS NLB heartbeat" },
	{ ETHERTYPE_JUMBO_LLC,            "Jumbo LLC" },
	{ ETHERTYPE_BRCM_TYPE,            "Broadcom tag" },
	{ ETHERTYPE_HOMEPLUG,             "Homeplug" },
	{ ETHERTYPE_HOMEPLUG_AV,          "Homeplug AV" },
	{ ETHERTYPE_MRP,                  "MRP" },
	{ ETHERTYPE_IEEE_802_1AD,         "802.1ad Provider Bridge (Q-in-Q)" },
	{ ETHERTYPE_MACSEC,               "802.1AE (MACsec)" },
	{ ETHERTYPE_IEEE_1905,            "1905.1a Convergent Digital Home Network for Heterogeneous Technologies" },
	{ ETHERTYPE_IEEE_802_1AH,         "802.1ah Provider Backbone Bridge (mac-in-mac)" },
	{ ETHERTYPE_IEEE_802_1BR,         "802.1br Bridge Port Extension E-Tag" },
	{ ETHERTYPE_EAPOL,                "802.1X Authentication" },
	{ ETHERTYPE_FORTINET_FGCP_HB,     "Fortinet FGCP (FortiGate Cluster Protocol) HB (HeartBeat)" },
	{ ETHERTYPE_RSN_PREAUTH,          "802.11i Pre-Authentication" },
	{ ETHERTYPE_MPLS,                 "MPLS label switched packet" },
	{ ETHERTYPE_MPLS_MULTI,           "MPLS multicast label switched packet" },
	{ ETHERTYPE_3C_NBP_DGRAM,         "3Com NBP Datagram" },
	{ ETHERTYPE_DEC,                  "DEC proto" },
	{ ETHERTYPE_DNA_DL,               "DEC DNA Dump/Load" },
	{ ETHERTYPE_DNA_RC,               "DEC DNA Remote Console" },
	{ ETHERTYPE_DNA_RT,               "DEC DNA Routing" },
	{ ETHERTYPE_LAT,                  "DEC LAT" },
	{ ETHERTYPE_DEC_DIAG,             "DEC Diagnostics" },
	{ ETHERTYPE_DEC_CUST,             "DEC Customer use" },
	{ ETHERTYPE_DEC_SCA,              "DEC LAVC/SCA" },
	{ ETHERTYPE_DEC_LAST,             "DEC LAST" },
	{ ETHERTYPE_ETHBRIDGE,            "Transparent Ethernet bridging" },
	{ ETHERTYPE_CGMP,                 "Cisco Group Management Protocol" },
	{ ETHERTYPE_GIGAMON,              "Gigamon Header" },
	{ ETHERTYPE_MSRP,                 "802.1Qat Multiple Stream Reservation Protocol" },
	{ ETHERTYPE_MMRP,                 "802.1ak Multiple Mac Registration Protocol" },
	{ ETHERTYPE_NSH,                  "Network Service Header" },
	{ ETHERTYPE_PA_HBBACKUP,          "PA HB Backup" },
	{ ETHERTYPE_AVTP,                 "IEEE 1722 Audio Video Transport Protocol" },
	{ ETHERTYPE_ROHC,                 "Robust Header Compression(RoHC)" },
	{ ETHERTYPE_TRILL,                "Transparent Interconnection of Lots of Links" },
	{ ETHERTYPE_L2ISIS,               "Intermediate System to Intermediate System" },
	{ ETHERTYPE_MAC_CONTROL,          "MAC Control" },
	{ ETHERTYPE_SLOW_PROTOCOLS,       "Slow Protocols" },
	{ ETHERTYPE_RTMAC,                "Real-Time Media Access Control" },
	{ ETHERTYPE_RTCFG,                "Real-Time Configuration Protocol" },
	{ ETHERTYPE_CDMA2000_A10_UBS,     "CDMA2000 A10 Unstructured byte stream" },
	{ ETHERTYPE_ATMOE,                "ATM over Ethernet" },
	{ ETHERTYPE_PROFINET,             "PROFINET" },
	{ ETHERTYPE_REALTEK,              "Realtek Layer 2 Protocols" },
	{ ETHERTYPE_AOE,                  "ATA over Ethernet" },
	{ ETHERTYPE_ECATF,                "EtherCAT frame" },
	{ ETHERTYPE_TELKONET,             "Telkonet powerline" },
	{ ETHERTYPE_EPL_V2,               "ETHERNET Powerlink v2" },
	{ ETHERTYPE_XIMETA,               "XiMeta Technology" },
	{ ETHERTYPE_CSM_ENCAPS,           "CSM_ENCAPS Protocol" },
	{ ETHERTYPE_EXPERIMENTAL_ETH1,    "Local Experimental Ethertype 1" },
	{ ETHERTYPE_EXPERIMENTAL_ETH2,    "Local Experimental Ethertype 2" },
	{ ETHERTYPE_IEEE802_OUI_EXTENDED, "IEEE 802a OUI Extended Ethertype" },
	{ ETHERTYPE_IEC61850_GOOSE,       "IEC 61850/GOOSE" },
	{ ETHERTYPE_IEC61850_GSE,         "IEC 61850/GSE management services" },
	{ ETHERTYPE_IEC61850_SV,          "IEC 61850/SV (Sampled Value Transmission" },
	{ ETHERTYPE_TIPC,                 "Transparent Inter Process Communication" },
	{ ETHERTYPE_LLDP,                 "802.1 Link Layer Discovery Protocol (LLDP)" },
	{ ETHERTYPE_3GPP2,                "CDMA2000 A10 3GPP2 Packet" },
	{ ETHERTYPE_TTE_PCF,              "TTEthernet Protocol Control Frame" },
	{ ETHERTYPE_CESOETH,              "Circuit Emulation Services over Ethernet (MEF8)" },
	{ ETHERTYPE_LLTD,                 "Link Layer Topology Discovery (LLTD)" },
	{ ETHERTYPE_WSMP,                 "(WAVE) Short Message Protocol (WSM)" },
	{ ETHERTYPE_VMLAB,                "VMware Lab Manager" },
	{ ETHERTYPE_COBRANET,             "Cirrus Cobranet Packet" },
	{ ETHERTYPE_NSRP,                 "Juniper Netscreen Redundant Protocol" },
	{ ETHERTYPE_EERO,                 "EERO Broadcast Packet" },
	/*
	 * NDISWAN on Windows translates Ethernet frames from higher-level
	 * protocols into PPP frames to hand to the PPP driver, and translates
	 * PPP frames from the PPP driver to hand to the higher-level protocols.
	 *
	 * Apparently the PPP driver, on at least some versions of Windows,
	 * passes frames for internal-to-PPP protocols up through NDISWAN;
	 * the protocol type field appears to be passed through unchanged
	 * (unlike what's done with, for example, the protocol type field
	 * for IP, which is mapped from its PPP value to its Ethernet value).
	 *
	 * This means that we may see, on Ethernet captures, frames for
	 * protocols internal to PPP, so we list as "Ethernet" protocol
	 * types the PPP protocol types we've seen.
	 */
	{ PPP_IPCP,                       "PPP IP Control Protocol" },
	{ PPP_LCP,                        "PPP Link Control Protocol" },
	{ PPP_PAP,                        "PPP Password Authentication Protocol" },
	{ PPP_CCP,                        "PPP Compression Control Protocol" },
	{ ETHERTYPE_LLT,                  "Veritas Low Latency Transport (not officially registered)" },
	{ ETHERTYPE_CFM,                  "IEEE 802.1Q Connectivity Fault Management (CFM) protocol" },
	{ ETHERTYPE_DCE,                  "Data Center Ethernet (DCE) protocol(Cisco)" },
	{ ETHERTYPE_FCOE,                 "Fibre Channel over Ethernet" },
	{ ETHERTYPE_IEEE80211_DATA_ENCAP, "IEEE 802.11 data encapsulation" },
	{ ETHERTYPE_LINX,                 "LINX IPC Protocol" },
	{ ETHERTYPE_FIP,                  "FCoE Initialization Protocol" },
	{ ETHERTYPE_MIH,                  "Media Independent Handover Protocol" },
	{ ETHERTYPE_ELMI,                 "Ethernet Local Management Interface (MEF16)" },
	{ ETHERTYPE_PTP,                  "PTPv2 over Ethernet (IEEE1588)" },
	{ ETHERTYPE_NCSI,                 "Network Controller Sideband Interface" },
	{ ETHERTYPE_PRP,                  "Parallel Redundancy Protocol (PRP) and HSR Supervision (IEC62439 Part 3)" },
	{ ETHERTYPE_FLIP,                 "Flow Layer Internal Protocol" },
	{ ETHERTYPE_ROCE,                 "RDMA over Converged Ethernet" },
	{ ETHERTYPE_TDMOE,                "Digium TDM over Ethernet Protocol" },
	{ ETHERTYPE_WAI,                  "WAI Authentication Protocol" },
	{ ETHERTYPE_VNTAG,                "VN-Tag" },
	{ ETHERTYPE_SEL_L2,               "Schweitzer Engineering Labs Layer 2 Protocol" },
	{ ETHERTYPE_HSR,                  "High-availability Seamless Redundancy (IEC62439 Part 3)" },
	{ ETHERTYPE_BPQ,                  "AX.25" },
	{ ETHERTYPE_CMD,                  "CiscoMetaData" },
	{ ETHERTYPE_GEONETWORKING,        "GeoNetworking" },
	{ ETHERTYPE_XIP,                  "eXpressive Internet Protocol" },
	{ ETHERTYPE_NWP,                  "Neighborhood Watch Protocol" },
	{ ETHERTYPE_BLUECOM,              "bluecom Protocol" },
	{ ETHERTYPE_QINQ_OLD,             "QinQ: old non-standard 802.1ad" },
	{ ETHERTYPE_TECMP,                "Technically Enhanced Capture Module Protocol (TECMP) or ASAM Capture Module Protocol (CMP)" },
	{ ETHERTYPE_6LOWPAN,              "6LoWPAN" },
	{ ETHERTYPE_AVSP,                 "Arista Vendor Specific Protocol" },
	{ ETHERTYPE_ECPRI,                "eCPRI" },
	{ ETHERTYPE_CABLELABS,            "CableLabs Layer-3 Protocol" },
	{ ETHERTYPE_EXEH,                 "EXos internal Extra Header" },
	{ ETHERTYPE_ATRL,                 "Allied Telesis Resiliency Link" },
	{ ETHERTYPE_ACIGLEAN,             "Cisco ACI ARP gleaning" },
	{ ETHERTYPE_IEEE_802_1CB,         "802.1CB Frame Replication and Elimination for Reliability" },
	{ 0, NULL }
};

static void eth_prompt(packet_info *pinfo, char* result)
{
	snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Ethertype 0x%04x as",
		GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_ethertype, pinfo->curr_layer_num)));
}

static void *eth_value(packet_info *pinfo)
{
	return p_get_proto_data(pinfo->pool, pinfo, proto_ethertype, pinfo->curr_layer_num);
}

static void add_dix_trailer(packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
			    int trailer_id, tvbuff_t *tvb, tvbuff_t *next_tvb, int offset_after_etype,
			    unsigned length_before, int fcs_len);

/*
void
ethertype(uint16_t etype, tvbuff_t *tvb, int offset_after_etype,
	  packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
	  int etype_id, int trailer_id, int fcs_len)
*/
static int
dissect_ethertype(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	const char	  *description;
	tvbuff_t	  *volatile next_tvb;
	unsigned		   length_before;
	int		   captured_length, reported_length;
	volatile int	   dissector_found = 0;
	const char	  *volatile saved_proto;
	ethertype_data_t  *ethertype_data;

	/* Reject the packet if data is NULL */
	if (data == NULL)
		return 0;
	ethertype_data = (ethertype_data_t*)data;

	/* Get the captured length and reported length of the data
	   after the Ethernet type. */
	captured_length = tvb_captured_length_remaining(tvb, ethertype_data->payload_offset);
	reported_length = tvb_reported_length_remaining(tvb,
							ethertype_data->payload_offset);

	/* With Cisco ACI gleaning, the rest of the packet is dissected for informational purposes only */
	if (ethertype_data->etype == ETHERTYPE_ACIGLEAN) {

		unsigned gleantype, payload_etype;

		col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "0x%04x", ethertype_data->etype);
		col_set_writable(pinfo->cinfo, COL_PROTOCOL, false);

		description = try_val_to_str(ethertype_data->etype, etype_vals);
		col_add_str(pinfo->cinfo, COL_INFO, description);
		col_set_writable(pinfo->cinfo, COL_INFO, false);
		if (reported_length >= 1) {
			gleantype = (tvb_get_uint8(tvb, ethertype_data->payload_offset) & 0xF0) >> 4;
			switch (gleantype) {
			case 4: /* IPv4 */
				payload_etype = 0x0800;
				break;
			case 6: /* IPv6 */
				payload_etype = 0x86BB;
				break;
			default: /* ARP */
				payload_etype = 0x0806;
			}
			ethertype_data->etype = payload_etype;
		// FIXME: Add glean to protocol-stack in frame-header
		}
	}

	/* Remember how much data there is after the Ethernet type,
	   including any trailer and FCS. */
	length_before = reported_length;

	/* Construct a tvbuff for the payload after the Ethernet type.
	   If the FCS length is positive, remove the FCS.
	   (If it's zero, there's no FCS; if it's negative,
	   we don't know whether there's an FCS, so we'll
	   guess based on the length of the trailer.) */
	if (ethertype_data->fcs_len > 0) {
		if (captured_length >= 0 && reported_length >= 0) {
			if (reported_length >= ethertype_data->fcs_len)
				reported_length -= ethertype_data->fcs_len;
			if (captured_length > reported_length)
				captured_length = reported_length;
		}
	}
	next_tvb = tvb_new_subset_length_caplen(tvb, ethertype_data->payload_offset, captured_length,
				  reported_length);

	p_add_proto_data(pinfo->pool, pinfo, proto_ethertype, pinfo->curr_layer_num, GUINT_TO_POINTER((unsigned)ethertype_data->etype));

	/* Look for sub-dissector, and call it if found.
	   Catch exceptions, so that if the reported length of "next_tvb"
	   was reduced by some dissector before an exception was thrown,
	   we can still put in an item for the trailer. */
	saved_proto = pinfo->current_proto;
	TRY {
		dissector_found = dissector_try_uint(ethertype_dissector_table,
						     ethertype_data->etype, next_tvb, pinfo, tree);
	}
	CATCH_NONFATAL_ERRORS {
		/* Somebody threw an exception that means that there
		   was a problem dissecting the payload; that means
		   that a dissector was found, so we don't need to
		   dissect the payload as data or update the protocol
		   or info columns.

		   Just show the exception and then drive on to show
		   the trailer, after noting that a dissector was found
		   and restoring the protocol value that was in effect
		   before we called the subdissector. */
		show_exception(next_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);

		dissector_found = 1;
		pinfo->current_proto = saved_proto;
	}
	ENDTRY;

	if (!dissector_found) {
		/* No sub-dissector found.
		   Label rest of packet as "Data" */
		call_data_dissector(next_tvb, pinfo, tree);

		/* Label protocol */
		col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "0x%04x", ethertype_data->etype);

		description = try_val_to_str(ethertype_data->etype, etype_vals);
		if (description) {
			col_add_str(pinfo->cinfo, COL_INFO, description);
		}
	}

	add_dix_trailer(pinfo, tree, ethertype_data->fh_tree, ethertype_data->trailer_id, tvb, next_tvb, ethertype_data->payload_offset,
			length_before, ethertype_data->fcs_len);

	return tvb_captured_length(tvb);
}

static void
add_dix_trailer(packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree, int trailer_id,
		tvbuff_t *tvb, tvbuff_t *next_tvb, int offset_after_etype,
		unsigned length_before, int fcs_len)
{
	unsigned		 length;
	tvbuff_t	*trailer_tvb;

	/* OK, how much is there in that tvbuff now? */
	length = tvb_reported_length(next_tvb);

	/* If there's less than there was before, what's left is
	   a trailer. */
	if (length < length_before) {
		/*
		 * Is any of the padding present in the tvbuff?
		 */
		if (tvb_offset_exists(tvb, offset_after_etype + length)) {
			/*
			 * Yes - create a tvbuff for the padding.
			 */
			trailer_tvb = tvb_new_subset_remaining(tvb,
							       offset_after_etype + length);
		} else {
			/*
			 * No - don't bother showing the trailer.
			 * XXX - show a Short Frame indication?
			 */
			trailer_tvb = NULL;
		}
	} else
		trailer_tvb = NULL;	/* no trailer */

	/* XXX: If the length of next_tvb is less than it was before, but this
	 * is not the first time the ethertype dissector has been called, we
	 * would rather not add the trailer here, but instead also reduce the
	 * length of tvb and have the previous ethertype dissector add the
	 * trailer instead. That's the only way we can properly detect and
	 * check the FCS in "maybefcs" mode (we need the full frame.)
	 * It also would be less confusing because we would always just
	 * use eth.trailer instead of sometimes e.g. vlan.trailer (#18252).
	 *
	 * It does require that the second time the ethertype dissector was
	 * called that ethertype_data.payload_offset was set and the original
	 * tvb used instead of creating a new subset tvb - in the latter case
	 * tvb here is not the same as the next_tvb from the previous ethertype
	 * dissector. That's not the case for ethertypes like 802.1AE MACSec
	 * that add a trailer as well, where we likely took a subset to shave
	 * off the trailer.
	 *
	 * We can't just "set the reported length of the backing tvbuff",
	 * because the ultimately backing tvbuff might be something that
	 * encapsulates the Ethernet frame, e.g. ISL or GSE Bridged Frames)
	 *
	 * To see if the ethertype dissector was called earlier from the entire
	 * Ethernet frame, we can't just check if offset_after_etype != 14, as
	 * it could be something that calls ethertype directly without having the
	 * entire Ethernet frame somewhere (e.g. a Linux "cooked mode" capture
	 * (packet-sll), or something set in the USER ENCAP UAT, etc.)
	 * We also can't check pinfo->curr_proto_layer_num or proto_layers if
	 * there are multiple entire Ethernet frames encapsulated in this
	 * frame, e.g. a DVB BaseBand Frame with multiple GSE frames with
	 * Bridge Frame encapsulation.
	 *
	 * We might need to add a new field to ethertype_data, or set
	 * something in pinfo->pool scoped packet data.
	 */
	add_ethernet_trailer(pinfo, tree, fh_tree, trailer_id, tvb, trailer_tvb, fcs_len, offset_after_etype);
}

void
proto_register_ethertype(void)
{
	/* Decode As handling */
	static build_valid_func eth_da_build_value[1] = {eth_value};
	static decode_as_value_t eth_da_values = {eth_prompt, 1, eth_da_build_value};
	static decode_as_t ethertype_da = {"ethertype", "ethertype", 1, 0, &eth_da_values, NULL, NULL,
										decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};


	proto_ethertype = proto_register_protocol("Ethertype", "Ethertype", "ethertype");
	/* This isn't a real protocol, so you can't disable its dissection. */
	proto_set_cant_toggle(proto_ethertype);

	register_dissector("ethertype", dissect_ethertype, proto_ethertype);

	/* subdissector code */
	ethertype_dissector_table = register_dissector_table("ethertype",
								"Ethertype", proto_ethertype, FT_UINT16, BASE_HEX);
	register_capture_dissector_table("ethertype", "Ethertype");

	register_decode_as(&ethertype_da);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */

/* packet-dmx.c
 * DMX packet disassembly.
 *
 * This dissector is written by
 *
 *  Erwin Rol <erwin@erwinrol.com>
 *  Copyright 2012 Erwin Rol
 *
 *  Wireshark - Network traffic analyzer
 *  Gerald Combs <gerald@wireshark.org>
 *  Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This dissector is based on;
 * American National Standard E1.11 - 2004
 * Entertainment Technology USITT DMX512-A
 * Asynchronous Serial Digital Data Transmission Standard
 * for Controlling Lighting Equipment and Accessories
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#define DMX_SC_DMX	0x00
#define DMX_SC_TEXT	0x17
#define DMX_SC_TEST	0x55
#define DMX_SC_RDM	0xCC
#define DMX_SC_SIP	0xCF

#define DMX_TEST_PACKET_SIZE  512
#define DMX_TEST_VALUE       0x55

static const value_string dmx_sc_vals[] = {
	{ DMX_SC_DMX,	"DMX" },
	{ DMX_SC_TEXT,	"Text" },
	{ DMX_SC_TEST,	"Test" },
	{ DMX_SC_RDM,	"RDM" },
	{ DMX_SC_SIP,	"SIP" },
	{ 0, NULL },
};

void proto_register_dmx(void);
void proto_register_dmx_chan(void);
void proto_register_dmx_sip(void);
void proto_register_dmx_test(void);
void proto_register_dmx_text(void);
void proto_reg_handoff_dmx(void);

static int proto_dmx;
static int proto_dmx_chan;
static int proto_dmx_sip;
static int proto_dmx_test;
static int proto_dmx_text;

static int hf_dmx_start_code;

static int hf_dmx_chan_output_dmx_data;
static int hf_dmx_chan_output_data_filter;

static int hf_dmx_sip_byte_count;
static int hf_dmx_sip_control_bit_field;
static int hf_dmx_sip_prev_packet_checksum;
static int hf_dmx_sip_seq_nr;
static int hf_dmx_sip_dmx_universe_nr;
static int hf_dmx_sip_dmx_proc_level;
static int hf_dmx_sip_dmx_software_version;
static int hf_dmx_sip_dmx_packet_len;
static int hf_dmx_sip_dmx_nr_packets;
static int hf_dmx_sip_orig_dev_id;
static int hf_dmx_sip_sec_dev_id;
static int hf_dmx_sip_third_dev_id;
static int hf_dmx_sip_fourth_dev_id;
static int hf_dmx_sip_fifth_dev_id;
static int hf_dmx_sip_reserved;
static int hf_dmx_sip_checksum;
static int hf_dmx_sip_checksum_status;
static int hf_dmx_sip_trailer;

static int hf_dmx_test_data;
static int hf_dmx_test_data_good;
static int hf_dmx_test_data_bad;

static int hf_dmx_text_page_nr;
static int hf_dmx_text_line_len;
static int hf_dmx_text_string;

static int ett_dmx_chan;
static int ett_dmx_sip;
static int ett_dmx_test;
static int ett_dmx_text;

static expert_field ei_dmx_sip_checksum;

static dissector_table_t dmx_dissector_table;

static dissector_handle_t dmx_text_handle;

/*
 * Here are the global variables associated with the preferences for DMX
 */
static int global_disp_chan_val_type;
static int global_disp_col_count     = 16;
static int global_disp_chan_nr_type;

static int
dissect_dmx_chan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DMX Channels");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree != NULL) {
		static const char *chan_format[]   = {
			"%2u%% ",
			"0x%02x ",
			"%3u "
		};
		static const char *string_format[] = {
			"0x%03x: %s",
			"%3u: %s"
		};
		wmem_strbuf_t *chan_str = wmem_strbuf_create(pinfo->pool);
		proto_item    *item;
		uint16_t       length,r,c,row_count;
		uint8_t        v;
		unsigned       offset   = 0;

		proto_tree    *ti = proto_tree_add_item(tree, proto_dmx_chan, tvb, offset, -1, ENC_NA);
		proto_tree    *dmx_chan_tree = proto_item_add_subtree(ti, ett_dmx_chan);

		length = tvb_reported_length_remaining(tvb, offset);

		row_count = (length / global_disp_col_count) + ((length % global_disp_col_count) == 0 ? 0 : 1);
		for (r = 0; r < row_count;r++) {
			wmem_strbuf_truncate(chan_str, 0);
			for (c = 0;(c < global_disp_col_count) && (((r * global_disp_col_count) + c) < length);c++) {
				if ((global_disp_col_count >= 2) && ((c % (global_disp_col_count / 2)) == 0)) {
					wmem_strbuf_append(chan_str, " ");
				}

				v = tvb_get_uint8(tvb, (offset + (r * global_disp_col_count) + c));
				if (global_disp_chan_val_type == 0) {
					v = (v * 100) / 255;
					if (v == 100) {
						wmem_strbuf_append(chan_str, "FL ");
					} else {
						wmem_strbuf_append_printf(chan_str, chan_format[global_disp_chan_val_type], v);
					}
				} else {
					wmem_strbuf_append_printf(chan_str, chan_format[global_disp_chan_val_type], v);
				}
			}

			proto_tree_add_none_format(dmx_chan_tree, hf_dmx_chan_output_dmx_data, tvb,
							offset+(r * global_disp_col_count), c,
							string_format[global_disp_chan_nr_type],
							(r * global_disp_col_count) + 1, wmem_strbuf_get_str(chan_str));
		}

		/* Add the real type hidden */
		item = proto_tree_add_item(dmx_chan_tree, hf_dmx_chan_output_data_filter, tvb,
						offset, length, ENC_NA );
		proto_item_set_hidden(item);
	}
	return tvb_captured_length(tvb);
}

static uint8_t
dmx_sip_checksum(tvbuff_t *tvb, unsigned length)
{
	uint8_t   sum = DMX_SC_SIP;
	unsigned  i;
	for (i = 0; i < length; i++)
		sum += tvb_get_uint8(tvb, i);
	return sum;
}

static int
dissect_dmx_sip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DMX SIP");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree != NULL) {
		unsigned offset = 0;
		unsigned byte_count;

		proto_tree *ti = proto_tree_add_item(tree, proto_dmx_sip, tvb,
							offset, -1, ENC_NA);
		proto_tree *dmx_sip_tree = proto_item_add_subtree(ti, ett_dmx_sip);


		byte_count = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_byte_count, tvb,
							offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_control_bit_field, tvb,
							offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_prev_packet_checksum, tvb,
							offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_seq_nr, tvb,
							offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_dmx_universe_nr, tvb,
							offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_dmx_proc_level, tvb,
							offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_dmx_software_version, tvb,
							offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_dmx_packet_len, tvb,
							offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_dmx_nr_packets, tvb,
							offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_orig_dev_id, tvb,
							offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_sec_dev_id, tvb,
							offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_third_dev_id, tvb,
							offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_fourth_dev_id, tvb,
							offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_fifth_dev_id, tvb,
							offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		if (offset < byte_count) {
			proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_reserved, tvb,
							offset, byte_count - offset, ENC_NA);
			offset += (byte_count - offset);
		}

		proto_tree_add_checksum(dmx_sip_tree, tvb, offset, hf_dmx_sip_checksum, hf_dmx_sip_checksum_status, &ei_dmx_sip_checksum, pinfo, dmx_sip_checksum(tvb, offset), ENC_NA, PROTO_CHECKSUM_VERIFY);
		offset += 1;

		if (offset < tvb_reported_length(tvb))
			proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_trailer, tvb,
					offset, -1, ENC_NA);
	}
	return tvb_captured_length(tvb);
}

static int
dissect_dmx_test(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DMX Test Frame");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree != NULL) {
		unsigned offset = 0;
		unsigned size, i, test_data_is_ok;
		proto_tree *test_data_tree;
		proto_item *item;

		proto_tree *ti = proto_tree_add_item(tree, proto_dmx_test, tvb,
							offset, -1, ENC_NA);
		proto_tree *dmx_test_tree = proto_item_add_subtree(ti, ett_dmx_test);

		size = tvb_reported_length_remaining(tvb, offset);

		item = proto_tree_add_item(dmx_test_tree, hf_dmx_test_data, tvb,
							offset, size, ENC_NA);
		offset += size;

		if (size == DMX_TEST_PACKET_SIZE) {
			test_data_is_ok = true;
			for (i = 0; i < DMX_TEST_PACKET_SIZE; i++) {
				if (tvb_get_uint8(tvb, i) != DMX_TEST_VALUE) {
					test_data_is_ok = false;
					break;
				}
			}
		} else {
			test_data_is_ok = false;
		}

		if (test_data_is_ok) {
			proto_item_append_text(ti, ", Data correct");
			proto_item_append_text(item, " [correct]");

			test_data_tree = proto_item_add_subtree(item, ett_dmx_test);
			item = proto_tree_add_boolean(test_data_tree, hf_dmx_test_data_good, tvb,
							offset, size, true);
			proto_item_set_generated(item);
			item = proto_tree_add_boolean(test_data_tree, hf_dmx_test_data_bad, tvb,
							offset, size, false);
			proto_item_set_generated(item);
		} else {
			proto_item_append_text(ti, ", Data incorrect");
			proto_item_append_text(item, " [incorrect]");

			test_data_tree = proto_item_add_subtree(item, ett_dmx_test);
			item = proto_tree_add_boolean(test_data_tree, hf_dmx_test_data_good, tvb,
							offset, size, false);
			proto_item_set_generated(item);
			item = proto_tree_add_boolean(test_data_tree, hf_dmx_test_data_bad, tvb,
								offset, size, true);
			proto_item_set_generated(item);
		}
	}
	return tvb_captured_length(tvb);
}

static int
dissect_dmx_text(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DMX Text");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree != NULL) {
		unsigned offset = 0;
		unsigned size;

		proto_tree *ti = proto_tree_add_item(tree, proto_dmx_text, tvb,
							offset, -1, ENC_NA);
		proto_tree *dmx_text_tree = proto_item_add_subtree(ti, ett_dmx_text);

		proto_tree_add_item(dmx_text_tree, hf_dmx_text_page_nr, tvb,
							offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(dmx_text_tree, hf_dmx_text_line_len, tvb,
							offset, 1, ENC_BIG_ENDIAN);
		offset++;

		size = tvb_reported_length_remaining(tvb, offset);

		proto_tree_add_item(dmx_text_tree, hf_dmx_text_string, tvb,
							offset, size, ENC_ASCII);
	}
	return tvb_captured_length(tvb);
}

static int
dissect_dmx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	tvbuff_t *next_tvb;
	unsigned  offset = 0;
	uint8_t   start_code;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DMX");
	col_clear(pinfo->cinfo, COL_INFO);

	start_code = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(tree, hf_dmx_start_code, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
	offset++;

	next_tvb = tvb_new_subset_remaining(tvb, offset);

	if (!dissector_try_uint_new(dmx_dissector_table, start_code, tvb, pinfo,
                             tree, true, NULL)) {
		call_data_dissector(next_tvb, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

void
proto_register_dmx(void)
{
	static hf_register_info hf[] = {
		{ &hf_dmx_start_code,
			{ "Start Code", "dmx.start_code",
				FT_UINT8, BASE_HEX, VALS(dmx_sc_vals), 0x0,
				NULL, HFILL }},
	};

	proto_dmx = proto_register_protocol("DMX", "DMX", "dmx");
	proto_register_field_array(proto_dmx, hf, array_length(hf));
	register_dissector("dmx", dissect_dmx, proto_dmx);

	dmx_dissector_table = register_dissector_table("dmx", "DMX Start Code", proto_dmx,
                                                FT_UINT8, BASE_DEC);

}

void
proto_register_dmx_chan(void)
{
	static hf_register_info hf[] = {
		{ &hf_dmx_chan_output_data_filter,
			{ "DMX data filter",
				"dmx_chan.data_filter",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_chan_output_dmx_data,
			{ "DMX data",
				"dmx_chan.dmx_data",
				FT_NONE, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_dmx_chan
	};

	module_t *dmx_chan_module;

	static const enum_val_t disp_chan_val_types[] = {
		{ "pro", "Percent", 0 },
		{ "hex", "Hexadecimal", 1 },
		{ "dec", "Decimal", 2 },
		{ NULL, NULL, 0 }
	};

	static const enum_val_t disp_chan_nr_types[] = {
		{ "hex", "Hexadecimal", 0 },
		{ "dec", "Decimal", 1 },
		{ NULL, NULL, 0 }
	};

	static const enum_val_t col_count[] = {
		{  "6",  "6",  6 },
		{ "10", "10", 10 },
		{ "12", "12", 12 },
		{ "16", "16", 16 },
		{ "24", "24", 24 },
		{ NULL, NULL, 0 }
	};

	proto_dmx_chan = proto_register_protocol("DMX Channels","DMX Channels", "dmx_chan");
	proto_register_field_array(proto_dmx_chan, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("dmx-chan", dissect_dmx_chan, proto_dmx_chan);

	dmx_chan_module = prefs_register_protocol(proto_dmx_chan, NULL);

	prefs_register_enum_preference(dmx_chan_module, "dmx_disp_chan_val_type",
					"DMX Display channel value type",
					"The way DMX values are displayed",
					&global_disp_chan_val_type,
					disp_chan_val_types, false);

	prefs_register_enum_preference(dmx_chan_module, "dmx_disp_chan_nr_type",
					"DMX Display channel nr. type",
					"The way DMX channel numbers are displayed",
					&global_disp_chan_nr_type,
					disp_chan_nr_types, false);

	prefs_register_enum_preference(dmx_chan_module, "dmx_disp_col_count",
					"DMX Display Column Count",
					"The number of columns for the DMX display",
					&global_disp_col_count,
					col_count, false);
}

void
proto_register_dmx_sip(void)
{
	static hf_register_info hf[] = {
		{ &hf_dmx_sip_byte_count,
			{ "Byte Count", "dmx_sip.byte_count",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_control_bit_field,
			{ "Control Bit Field", "dmx_sip.control_bit_field",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_prev_packet_checksum,
			{ "Checksum of prev. packet", "dmx_sip.prev_packet_checksum",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_seq_nr,
			{ "SIP sequence nr.", "dmx_sip.seq_nr",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_dmx_universe_nr,
			{ "DMX512 universe nr.", "dmx_sip.dmx_universe_nr",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_dmx_proc_level,
			{ "DMX512 processing level", "dmx_sip.dmx_proc_level",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_dmx_software_version,
			{ "Software Version", "dmx_sip.dmx_software_version",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_dmx_packet_len,
			{ "Standard Packet Len", "dmx_sip.dmx_packet_len",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_dmx_nr_packets,
			{ "Number of Packets", "dmx_sip.dmx_nr_packets",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_orig_dev_id,
			{ "1st Device's ID", "dmx_sip.orig_dev_id",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_sec_dev_id,
			{ "2nd Device's ID", "dmx_sip.sec_dev_id",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_third_dev_id,
			{ "3rd Device's ID", "dmx_sip.third_dev_id",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_fourth_dev_id,
			{ "4th Device's ID", "dmx_sip.fourth_dev_id",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_fifth_dev_id,
			{ "5th Device's ID", "dmx_sip.fifth_dev_id",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_reserved,
			{ "Reserved", "dmx_sip.reserved",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_checksum,
			{ "Checksum", "dmx_sip.checksum",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_checksum_status,
			{ "Checksum Status", "dmx_sip.checksum.status",
				FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_trailer,
			{ "Trailer", "dmx_sip.trailer",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_dmx_sip
	};

	static ei_register_info ei[] = {
		{ &ei_dmx_sip_checksum, { "dmx_sip.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
	};

	expert_module_t* expert_dmx_sip;

	proto_dmx_sip = proto_register_protocol("DMX SIP", "DMX SIP", "dmx_sip");
	proto_register_field_array(proto_dmx_sip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_dmx_sip = expert_register_protocol(proto_dmx_sip);
	expert_register_field_array(expert_dmx_sip, ei, array_length(ei));
}

void
proto_register_dmx_test(void)
{
	static hf_register_info hf[] = {
		{ &hf_dmx_test_data,
			{ "Test Data", "dmx_test.data",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_test_data_good,
			{ "Data Good", "dmx_test.data_good",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"True: test data is correct; False: test data is incorrect", HFILL }},

		{ &hf_dmx_test_data_bad,
			{ "Data Bad", "dmx_test.data_bad",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"True: test data is incorrect; False: test data is correct", HFILL }},
	};

	static int *ett[] = {
		&ett_dmx_test
	};

	proto_dmx_test = proto_register_protocol("DMX Test Frame", "DMX Test Frame", "dmx_test");
	proto_register_field_array(proto_dmx_test, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_register_dmx_text(void)
{
	static hf_register_info hf[] = {
		{ &hf_dmx_text_page_nr,
			{ "Page Number",
				"dmx_text.page_nr",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},
		{ &hf_dmx_text_line_len,
			{ "Line Length",
				"dmx_text.line_length",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},
		{ &hf_dmx_text_string,
			{ "Text String",
				"dmx_text.string",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_dmx_text
	};

	proto_dmx_text = proto_register_protocol("DMX Text Frame", "DMX Text Frame", "dmx_text");
	proto_register_field_array(proto_dmx_text, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dmx(void)
{
	dmx_text_handle = find_dissector("dmx-text");

	dissector_add_uint("dmx", DMX_SC_DMX, create_dissector_handle(dissect_dmx_chan, proto_dmx_chan));
	dissector_add_uint("dmx", DMX_SC_SIP, create_dissector_handle(dissect_dmx_sip, proto_dmx_sip));
	dissector_add_uint("dmx", DMX_SC_TEST, create_dissector_handle(dissect_dmx_test, proto_dmx_test));
	dissector_add_uint("dmx", DMX_SC_TEXT, create_dissector_handle(dissect_dmx_text, proto_dmx_text));
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

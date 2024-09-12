/* packet-adb_cs.c
 * Routines for Android Debug Bridge Client-Server Protocol
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <wiretap/wtap.h>

#include "packet-adb_service.h"

static int proto_adb_cs;

static int hf_role;
static int hf_hex_ascii_length;
static int hf_length;
static int hf_service;
static int hf_status;
static int hf_data;
static int hf_fail_reason;

static int ett_adb_cs;
static int ett_length;

static expert_field ei_incomplete_message;

static dissector_handle_t  adb_cs_handle;
static dissector_handle_t  adb_service_handle;

static wmem_tree_t *client_requests;

static unsigned server_port = 5037;

typedef struct _client_request_t {
    int64_t   service_length;
    char     *service;
    uint32_t  first_in;
    int64_t   service_in;
    int64_t   response_frame;

    uint8_t   status;
    int64_t   data_length;
} client_request_t;

static const value_string role_vals[] = {
    { 0x00,   "Unknown" },
    { 0x01,   "Server" },
    { 0x02,   "Client" },
    { 0, NULL }
};

#define SERVICE_NONE  NULL

#define STATUS_UNKNOWN  0
#define STATUS_OKAY     1
#define STATUS_FAIL     2

void proto_register_adb_cs(void);
void proto_reg_handoff_adb_cs(void);

static int
dissect_adb_cs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *main_item;
    proto_tree  *main_tree;
    proto_item  *sub_item;
    proto_item  *p_item;
    int          offset = 0;
    int64_t      length = -1;
    int          direction;
    bool         client_request_service = false;
    tvbuff_t           *next_tvb;
    adb_service_data_t  adb_service_data;
    uint32_t            wireshark_interface_id = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ADB CS");
    col_clear(pinfo->cinfo, COL_INFO);

    main_item = proto_tree_add_item(tree, proto_adb_cs, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_adb_cs);

    if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID)
        wireshark_interface_id = pinfo->rec->rec_header.packet_header.interface_id;

    if (pinfo->destport == server_port) { /* Client sent to Server */
        client_request_t  *client_request;
        char              *service = SERVICE_NONE;
        wmem_tree_t       *subtree;
        wmem_tree_key_t    key[5];

        direction = P2P_DIR_SENT;

        p_item = proto_tree_add_uint(main_tree, hf_role, tvb, offset, 0, 0x02);
        proto_item_set_generated(p_item);

        col_set_str(pinfo->cinfo, COL_INFO, "Client");

        if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID)
            wireshark_interface_id = pinfo->rec->rec_header.packet_header.interface_id;

        key[0].length = 1;
        key[0].key = &wireshark_interface_id;
        key[1].length = 1;
        key[1].key = &pinfo->srcport;
        key[2].length = 1;
        key[2].key = &pinfo->destport;
        key[3].length = 0;
        key[3].key = NULL;

        subtree = (wmem_tree_t *) wmem_tree_lookup32_array(client_requests, key);
        client_request = (subtree) ? (client_request_t *) wmem_tree_lookup32_le(subtree, pinfo->num) : NULL;
        if (client_request && client_request->service_in > -1 && client_request->service_in < pinfo->num) {
            p_item = proto_tree_add_string(main_tree, hf_service, tvb, offset, 0, client_request->service);
            proto_item_set_generated(p_item);
            service = client_request->service;
            client_request_service = true;
        } else {
            if (client_request && client_request->service_in > -1 && client_request->service_in <= pinfo->num)
               client_request_service = true;
            client_request = NULL;
        }

        /* heuristic to recognize type of (partial) packet */
        if (tvb_reported_length_remaining(tvb, offset) >= 4) {
            uint8_t hex_ascii_length[5];
            uint32_t ulength;

            hex_ascii_length[4] = 0;

            tvb_memcpy(tvb, hex_ascii_length, offset, 4);
            if (g_ascii_xdigit_value(hex_ascii_length[0]) >= 0 &&
                    g_ascii_xdigit_value(hex_ascii_length[1]) >= 0 &&
                    g_ascii_xdigit_value(hex_ascii_length[2]) >= 0 &&
                    g_ascii_xdigit_value(hex_ascii_length[3]) >= 0) {
                /* probably 4 bytes ascii hex length field */
                offset = dissect_ascii_uint32(main_tree, hf_hex_ascii_length, ett_length, hf_length, tvb, offset, &ulength);
                length = (int64_t) ulength;
                col_append_fstr(pinfo->cinfo, COL_INFO, " Length=%u", ulength);
            }
        }


        if (length == -1 && service) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " Service=<%s>", service);

            /* Decode services */
            adb_service_data.service = service;
            adb_service_data.direction = direction;

            adb_service_data.session_key_length = 3;
            adb_service_data.session_key = (uint32_t *) wmem_alloc(pinfo->pool, adb_service_data.session_key_length * sizeof(uint32_t));
            adb_service_data.session_key[0] = wireshark_interface_id;
            adb_service_data.session_key[1] = pinfo->destport;
            adb_service_data.session_key[2] = pinfo->srcport;

            next_tvb = tvb_new_subset_remaining(tvb, offset);
            call_dissector_with_data(adb_service_handle, next_tvb, pinfo, tree, &adb_service_data);

            return tvb_captured_length(tvb);
        }

        if (!pinfo->fd->visited && length > 0) { /* save Length to client_requests */
            if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID)
                wireshark_interface_id = pinfo->rec->rec_header.packet_header.interface_id;

            key[0].length = 1;
            key[0].key = &wireshark_interface_id;
            key[1].length = 1;
            key[1].key = &pinfo->srcport;
            key[2].length = 1;
            key[2].key = &pinfo->destport;
            key[3].length = 1;
            key[3].key = &pinfo->num;
            key[4].length = 0;
            key[4].key = NULL;

            client_request = wmem_new(wmem_file_scope(), client_request_t);

            client_request->service_length = length;
            client_request->service = SERVICE_NONE;
            client_request->response_frame = -1;
            client_request->first_in = pinfo->num;
            client_request->service_in = -1;
            client_request->data_length = -1;
            wmem_tree_insert32_array(client_requests, key, client_request);
        }

        if (!pinfo->fd->visited && (length == -1 || (client_request && client_request->service_in == -1 && tvb_reported_length_remaining(tvb, offset) > 0))) { /* save Service to client_requests */
            if (!client_request) {
                if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID)
                    wireshark_interface_id = pinfo->rec->rec_header.packet_header.interface_id;

                key[0].length = 1;
                key[0].key = &wireshark_interface_id;
                key[1].length = 1;
                key[1].key = &pinfo->srcport;
                key[2].length = 1;
                key[2].key = &pinfo->destport;
                key[3].length = 0;
                key[3].key = NULL;

                subtree = (wmem_tree_t *) wmem_tree_lookup32_array(client_requests, key);
                client_request = (subtree) ? (client_request_t *) wmem_tree_lookup32_le(subtree, pinfo->num - 1) : NULL;
            }

            if (client_request) {
                /*
                 * I've no idea why the length is 64 bits, but that's
                 * too big to be a field length in Wireshark; if it's
                 * greater than the biggest possible length, clamp it
                 * at the biggest possible length - which is probably
                 * going to be bigger than the available data so that
                 * you'll throw an exception.
                 */
                int service_length;
                if (client_request->service_length <= INT_MAX)
                    service_length = (int)client_request->service_length;
                else
                    service_length = INT_MAX;
                client_request->service = (char *) tvb_get_string_enc(wmem_file_scope(), tvb, offset, service_length, ENC_ASCII);
                client_request->service_in = pinfo->num;
            }
        }

        if (!client_request_service && tvb_reported_length_remaining(tvb, offset) > 0) {
            col_append_str(pinfo->cinfo, COL_INFO, " Unknown service");
            proto_tree_add_item(main_tree, hf_data, tvb, offset, -1, ENC_NA);
        } else if (tvb_reported_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(main_tree, hf_service, tvb, offset, -1, ENC_NA | ENC_ASCII);

            service = (char *) tvb_get_string_enc(pinfo->pool, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_ASCII);
            col_append_fstr(pinfo->cinfo, COL_INFO, " Service=<%s>", service);
        }

        offset = tvb_captured_length(tvb);

    } else if (pinfo->srcport == server_port) { /* Server sent to Client */
        char               *service = SERVICE_NONE;
        wmem_tree_t        *subtree;
        wmem_tree_key_t     key[5];
        client_request_t   *client_request;
        int64_t             response_frame = -1;
        uint8_t             status = STATUS_UNKNOWN;

        direction = P2P_DIR_RECV;

        key[0].length = 1;
        key[0].key = &wireshark_interface_id;
        key[1].length = 1;
        key[1].key = &pinfo->destport;
        key[2].length = 1;
        key[2].key = &pinfo->srcport;
        key[3].length = 0;
        key[3].key = NULL;

        subtree = (wmem_tree_t *) wmem_tree_lookup32_array(client_requests, key);
        client_request = (subtree) ? (client_request_t *) wmem_tree_lookup32_le(subtree, pinfo->num - 1) : NULL;
        if (client_request) {
            service = client_request->service;
            status = client_request->status;
            length = client_request->data_length;
            response_frame = client_request->response_frame;
        }

        p_item = proto_tree_add_uint(main_tree, hf_role, tvb, offset, 0, 0x01);
        proto_item_set_generated(p_item);

        p_item = proto_tree_add_string(main_tree, hf_service, tvb, offset, 0, service);
        proto_item_set_generated(p_item);

        col_set_str(pinfo->cinfo, COL_INFO, "Server");

        if (!service) {
            col_append_str(pinfo->cinfo, COL_INFO, " Unknown service");
            proto_tree_add_item(main_tree, hf_data, tvb, offset, -1, ENC_NA);

            return tvb_captured_length(tvb);
        }

        if (response_frame == -1 || response_frame == (int64_t) pinfo->num) {
            proto_tree_add_item(main_tree, hf_status, tvb, offset, 4, ENC_NA | ENC_ASCII);
            col_append_fstr(pinfo->cinfo, COL_INFO, " Status=%c%c%c%c", tvb_get_uint8(tvb, offset),
            tvb_get_uint8(tvb, offset + 1), tvb_get_uint8(tvb, offset + 2), tvb_get_uint8(tvb, offset + 3));
            offset += 4;

            if (tvb_memeql(tvb, offset - 4, (const uint8_t *) "FAIL", 4) == 0) {
                uint32_t ulength;

                offset = dissect_ascii_uint32(main_tree, hf_hex_ascii_length, ett_length, hf_length, tvb, offset, &ulength);
                length = (int64_t) ulength;

                status = STATUS_FAIL;
            } else if (tvb_memeql(tvb, offset - 4, (const uint8_t *) "OKAY", 4) == 0) {
                status = STATUS_OKAY;
                length = -1;
            }

            if (!pinfo->fd->visited && client_request) {
                client_request->response_frame = pinfo->num;
                client_request->status = status;
                client_request->data_length = length;
            }
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, " Service=<%s>", service);

        if (tvb_reported_length_remaining(tvb, offset) <= 0) return offset;

        if (status == STATUS_FAIL) {
            const uint8_t* str;
            sub_item = proto_tree_add_item_ret_string(main_tree, hf_fail_reason, tvb, offset,
                            tvb_reported_length_remaining(tvb, offset), ENC_NA | ENC_ASCII, pinfo->pool, &str);
            if (length < tvb_reported_length_remaining(tvb, offset)) {
                expert_add_info(pinfo, sub_item, &ei_incomplete_message);
            }

            col_append_fstr(pinfo->cinfo, COL_INFO, " Fail=<%s>", str);
            return tvb_captured_length(tvb);
        }

        /* Decode services */
        adb_service_data.service = service;
        adb_service_data.direction = direction;

        adb_service_data.session_key_length = 3;
        adb_service_data.session_key = (uint32_t *) wmem_alloc(pinfo->pool, adb_service_data.session_key_length * sizeof(uint32_t));
        adb_service_data.session_key[0] = wireshark_interface_id;
        adb_service_data.session_key[1] = pinfo->destport;
        adb_service_data.session_key[2] = pinfo->srcport;

        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector_with_data(adb_service_handle, next_tvb, pinfo, tree, &adb_service_data);
        offset = tvb_captured_length(tvb);
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "Unknown role");

        p_item = proto_tree_add_uint(main_tree, hf_role, tvb, offset, 0, 0x00);
        proto_item_set_generated(p_item);

        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_data_dissector(next_tvb, pinfo, main_tree);
        offset += tvb_captured_length_remaining(tvb, offset);
    }

    return offset;
}

void
proto_register_adb_cs(void)
{
    module_t         *module;
    expert_module_t  *expert_module;

    static hf_register_info hf[] = {
        { &hf_role,
            { "Role",                            "adb_cs.role",
            FT_UINT8, BASE_HEX, VALS(role_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_hex_ascii_length,
            { "Hex ASCII Length",                "adb_cs.hex_ascii_length",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_length,
            { "Length",                          "adb_cs.length",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_service,
            { "Service",                         "adb_cs.service",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_fail_reason,
            { "Fail Reason",                     "adb_cs.fail_reason",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_status,
            { "Status",                          "adb_cs.status",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_data,
            { "Data",                            "adb_cs.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_adb_cs,
        &ett_length
    };

    static ei_register_info ei[] = {
        { &ei_incomplete_message,         { "adb_cs.expert.incomplete_message", PI_PROTOCOL, PI_WARN, "Incomplete message", EXPFILL }},
    };

    client_requests = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_adb_cs = proto_register_protocol("Android Debug Bridge Client-Server", "ADB CS", "adb_cs");
    adb_cs_handle = register_dissector("adb_cs", dissect_adb_cs, proto_adb_cs);

    proto_register_field_array(proto_adb_cs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module = expert_register_protocol(proto_adb_cs);
    expert_register_field_array(expert_module, ei, array_length(ei));

    module = prefs_register_protocol(proto_adb_cs, NULL);
    prefs_register_static_text_preference(module, "version",
            "ADB CS protocol version is compatible prior to: adb 1.0.31",
            "Version of protocol supported by this dissector.");

    prefs_register_uint_preference(module, "server_port",
            "Server Port",
            "Server Port",
            10, &server_port);
}

void
proto_reg_handoff_adb_cs(void)
{
    adb_service_handle = find_dissector_add_dependency("adb_service", proto_adb_cs);

    dissector_add_for_decode_as_with_preference("tcp.port", adb_cs_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

/* packet-finger.c
 * Routines for basic finger dissection (see https://tools.ietf.org/html/rfc742)
 * Copyright 2013, Christopher Maynard <Christopher.Maynard@gtech.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>

#include "packet-tcp.h"

void proto_register_finger(void);
void proto_reg_handoff_finger(void);

static dissector_handle_t finger_handle;

#define FINGER_PORT     79  /* This is the registered IANA port */

static int proto_finger;
static int hf_finger_query;
static int hf_finger_response;
static int hf_finger_response_in;
static int hf_finger_response_to;
static int hf_finger_response_time;

static expert_field ei_finger_nocrlf;

static int ett_finger;

typedef struct _finger_transaction_t {
    uint32_t req_frame;
    uint32_t rep_frame;
    nstime_t req_time;
} finger_transaction_t;

static int
dissect_finger(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data)
{
    proto_item           *ti, *expert_ti;
    proto_tree           *finger_tree;
    conversation_t       *conversation;
    finger_transaction_t *finger_trans;
    bool                  is_query;
    unsigned              len;
    struct tcpinfo       *tcpinfo = (struct tcpinfo*)data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FINGER");

    if (pinfo->destport == FINGER_PORT) {
        is_query = true;
        col_set_str(pinfo->cinfo, COL_INFO, "Query");
    } else {
        is_query = false;
        col_set_str(pinfo->cinfo, COL_INFO, "Response");
    }

    conversation = find_or_create_conversation(pinfo);
    finger_trans = (finger_transaction_t *)conversation_get_proto_data(conversation, proto_finger);
    if (finger_trans == NULL) {
        finger_trans = wmem_new0(wmem_file_scope(), finger_transaction_t);
        conversation_add_proto_data(conversation, proto_finger, finger_trans);
    }

    len = tvb_reported_length(tvb);
    if (!PINFO_FD_VISITED(pinfo)) {
        if (pinfo->can_desegment) {
            if (is_query) {
                if ((len < 2) || (tvb_memeql(tvb, len - 2, (const uint8_t*)"\r\n", 2))) {
                    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                    pinfo->desegment_offset = 0;
                    return -1;
                } else {
                    finger_trans->req_frame = pinfo->num;
                    finger_trans->req_time = pinfo->abs_ts;
                }
            } else if (!(tcpinfo && (IS_TH_FIN(tcpinfo->flags) || tcpinfo->is_reassembled))) {
                /* If this is the FIN (or already desegmented, as with an out
                 * of order segment received after FIN) go ahead and dissect
                 * on the first pass.
                 */
                pinfo->desegment_len = DESEGMENT_UNTIL_FIN;
                pinfo->desegment_offset = 0;
                return -1;
            }
        }
    } else if (is_query && (finger_trans->req_frame == 0)) {
        finger_trans->req_frame = pinfo->num;
        finger_trans->req_time = pinfo->abs_ts;
    }

    if (!is_query && (finger_trans->rep_frame == 0)) {
        /* By comparing finger_trans->rep_frame to 0, if reassembly is turned
         * on, finger_trans->rep_frame will be assigned to the reassembled frame
         * number, and if reassembly is turned off, finger_trans->rep_frame will
         * be assigned to the first frame number of the response.  This seems
         * to match other protocols' behavior.  The alternative is:
         *      if (pinfo->num > finger_trans->rep_frame)
         * which will give us the same frame number either way.
         */
        finger_trans->rep_frame = pinfo->num;
    }

    ti = proto_tree_add_protocol_format(tree, proto_finger, tvb, 0, -1,
        "FINGER: %s", is_query ? "Query" : "Response");
    finger_tree = proto_item_add_subtree(ti, ett_finger);

    if (is_query) {
        expert_ti = proto_tree_add_item(finger_tree, hf_finger_query, tvb, 0, -1, ENC_ASCII);
        if ((len < 2) || (tvb_memeql(tvb, len - 2, (const uint8_t*)"\r\n", 2))) {
            /*
             * From RFC742, Send a single "command line", ending with <CRLF>.
             */
            expert_add_info(pinfo, expert_ti, &ei_finger_nocrlf);
        }
        if (tree && finger_trans->rep_frame) {
            ti = proto_tree_add_uint(finger_tree, hf_finger_response_in,
                tvb, 0, 0, finger_trans->rep_frame);
            proto_item_set_generated(ti);
        }
    } else if (tree && finger_trans->rep_frame) {
        proto_tree_add_item(finger_tree, hf_finger_response, tvb, 0, -1, ENC_ASCII);
        if (finger_trans->req_frame) {
            nstime_t ns;

            ti = proto_tree_add_uint(finger_tree, hf_finger_response_to,
                tvb, 0, 0, finger_trans->req_frame);
            proto_item_set_generated(ti);

            if (pinfo->num == finger_trans->rep_frame) {
                nstime_delta(&ns, &pinfo->abs_ts, &finger_trans->req_time);
                ti = proto_tree_add_time(finger_tree, hf_finger_response_time, tvb, 0, 0, &ns);
                proto_item_set_generated(ti);
            }
        }
    }

    return tvb_captured_length(tvb);
}

void
proto_register_finger(void)
{
    expert_module_t *expert_finger;

    static hf_register_info hf[] = {
        { &hf_finger_query,
            { "Query", "finger.query", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_finger_response,
            { "Response", "finger.response", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_finger_response_in,
            { "Response In", "finger.response_in", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE),
              0x0, "The response to this FINGER query is in this frame",
              HFILL }
        },
        { &hf_finger_response_to,
            { "Request In", "finger.response_to", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST),
              0x0, "This is a response to the FINGER query in this frame",
              HFILL }
        },
        { &hf_finger_response_time,
            { "Response Time", "finger.response_time", FT_RELATIVE_TIME,
              BASE_NONE, NULL, 0x0,
              "The time between the Query and the Response", HFILL }
        }
    };

    static int *ett[] = {
        &ett_finger
    };

    static ei_register_info ei[] = {
        { &ei_finger_nocrlf,
            { "finger.nocrlf", PI_MALFORMED, PI_WARN, "Missing <CR><LF>", EXPFILL}
        }
    };

    proto_finger = proto_register_protocol("finger", "FINGER", "finger");
    finger_handle = register_dissector("finger", dissect_finger, proto_finger);
    proto_register_field_array(proto_finger, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_finger = expert_register_protocol(proto_finger);
    expert_register_field_array(expert_finger, ei, array_length(ei));
}

void
proto_reg_handoff_finger(void)
{
    dissector_add_uint_with_preference("tcp.port", FINGER_PORT, finger_handle);
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


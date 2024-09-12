/* packet-HI2Operations.c
 * Routines for HI2 (ETSI TS 101 671 V3.15.1 (2018-06))
 *  Erwin van Eijk 2010
 *  Joakim Karlsson 2023
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
#include <epan/oids.h>
#include <epan/asn1.h>

#include <wsutil/array.h>

#include "packet-ber.h"
#include "packet-isup.h"
#include "packet-q931.h"

#define PNAME  "HI2Operations"
#define PSNAME "HI2OPERATIONS"
#define PFNAME "HI2operations"

void proto_register_HI2Operations(void);
void proto_reg_handoff_HI2Operations(void);

/* Initialize the protocol and registered fields */
int proto_HI2Operations;
#include "packet-HI2Operations-hf.c"

/* Initialize the subtree pointers */
#include "packet-HI2Operations-ett.c"

#include "packet-HI2Operations-fn.c"

static bool
dissect_UUS1_Content_PDU_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  return dissect_UUS1_Content_PDU(tvb, pinfo, tree, data) > 0;
}

/*--- proto_register_HI2Operations ----------------------------------------------*/
void proto_register_HI2Operations(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-HI2Operations-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-HI2Operations-ettarr.c"
  };

  /* Register protocol */
  proto_HI2Operations = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_HI2Operations, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("HI2Operations", dissect_IRIsContent_PDU, proto_HI2Operations);


}


/*--- proto_reg_handoff_HI2Operations -------------------------------------------*/
void proto_reg_handoff_HI2Operations(void) {

    heur_dissector_add("q931_user", dissect_UUS1_Content_PDU_heur, "HI3CCLinkData", "hi3cclinkdata",
        proto_HI2Operations, HEURISTIC_ENABLE);

}


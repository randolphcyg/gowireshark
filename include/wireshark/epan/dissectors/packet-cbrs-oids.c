/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-cbrs-oids.c                                                         */
/* asn2wrs.py -b -q -L -p cbrs-oids -c ./cbrs-oids.cnf -s ./packet-cbrs-oids-template -D . -O ../.. cbrs-oids.asn */

/* packet-cbrs-oids.c
 *
 * Citizens Broadband Radio Service - Object Identifiers
 *
 * Extracted from
 * - WInnForum CBRS COMSEC TS WINNF-15-S-0065-V2.0.0
 *   https://www.wirelessinnovation.org/assets/work_products/Specifications/winnf-15-s-0065-v2.0.0%20cbrs%20communications%20security%20technical%20specification.pdf
 * - WInnForum CBRS Certificate Policy Document WINNF-17-S-0022
 *   https://www.wirelessinnovation.org/assets/work_products/Specifications/winnf-17-s-0022%20v1.0.0%20cbrs%20pki%20certificate%20policy.pdf
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <wsutil/array.h>

#include "packet-ber.h"

#define PNAME  "Citizen Broadband Radio Service - Object Identifiers"
#define PSNAME "CBRS_OIDS"
#define PFNAME "cbrs_oids"

void proto_register_cbrs_oids(void);
void proto_reg_handoff_cbrs_oids(void);

/* Initialize the protocol and registered fields */
static int proto_cbrs_oids;
static int hf_cbrs_oids_ZONE_PDU;                 /* ZONE */
static int hf_cbrs_oids_FREQUENCY_PDU;            /* FREQUENCY */
static int hf_cbrs_oids_FCCID_PDU;                /* FCCID */
static int hf_cbrs_oids_SERIAL_PDU;               /* SERIAL */
static int hf_cbrs_oids_FRN_PDU;                  /* FRN */
static int hf_cbrs_oids_CPIRID_PDU;               /* CPIRID */
static int hf_cbrs_oids_TEST_PDU;                 /* TEST */
static int hf_cbrs_oids_UTF8String_PDU;

/* Initialize the subtree pointers */


static int
dissect_cbrs_oids_ZONE(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_cbrs_oids_FREQUENCY(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_cbrs_oids_FCCID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_cbrs_oids_SERIAL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_cbrs_oids_FRN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_cbrs_oids_CPIRID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_cbrs_oids_TEST(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_ZONE_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cbrs_oids_ZONE(false, tvb, offset, &asn1_ctx, tree, hf_cbrs_oids_ZONE_PDU);
  return offset;
}
static int dissect_FREQUENCY_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cbrs_oids_FREQUENCY(false, tvb, offset, &asn1_ctx, tree, hf_cbrs_oids_FREQUENCY_PDU);
  return offset;
}
static int dissect_FCCID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cbrs_oids_FCCID(false, tvb, offset, &asn1_ctx, tree, hf_cbrs_oids_FCCID_PDU);
  return offset;
}
static int dissect_SERIAL_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cbrs_oids_SERIAL(false, tvb, offset, &asn1_ctx, tree, hf_cbrs_oids_SERIAL_PDU);
  return offset;
}
static int dissect_FRN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cbrs_oids_FRN(false, tvb, offset, &asn1_ctx, tree, hf_cbrs_oids_FRN_PDU);
  return offset;
}
static int dissect_CPIRID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cbrs_oids_CPIRID(false, tvb, offset, &asn1_ctx, tree, hf_cbrs_oids_CPIRID_PDU);
  return offset;
}
static int dissect_TEST_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cbrs_oids_TEST(false, tvb, offset, &asn1_ctx, tree, hf_cbrs_oids_TEST_PDU);
  return offset;
}


/*--- proto_register_cbrs_oids ----------------------------------------------*/
void proto_register_cbrs_oids(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cbrs_oids_UTF8String_PDU,
      { "UTF8String", "cbrs-oids.UTF8String",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cbrs_oids_ZONE_PDU,
      { "ZONE", "cbrs-oids.ZONE",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cbrs_oids_FREQUENCY_PDU,
      { "FREQUENCY", "cbrs-oids.FREQUENCY",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cbrs_oids_FCCID_PDU,
      { "FCCID", "cbrs-oids.FCCID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cbrs_oids_SERIAL_PDU,
      { "SERIAL", "cbrs-oids.SERIAL",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cbrs_oids_FRN_PDU,
      { "FRN", "cbrs-oids.FRN",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cbrs_oids_CPIRID_PDU,
      { "CPIRID", "cbrs-oids.CPIRID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cbrs_oids_TEST_PDU,
      { "TEST", "cbrs-oids.TEST",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
  };

  /* Register protocol */
  proto_cbrs_oids = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_cbrs_oids, hf, array_length(hf));
/*  proto_register_subtree_array(ett, array_length(ett)); */
}

/*--- proto_reg_handoff_cbrs_oids -------------------------------------------*/
void proto_reg_handoff_cbrs_oids(void) {
  register_ber_oid_dissector("1.3.6.1.4.1.46609.1.2", dissect_ZONE_PDU, proto_cbrs_oids, "CBRS_PAL_ZONE");
  register_ber_oid_dissector("1.3.6.1.4.1.46609.1.3", dissect_FREQUENCY_PDU, proto_cbrs_oids, "CBRS_PAL_FREQUENCY");
  register_ber_oid_dissector("1.3.6.1.4.1.46609.1.4", dissect_FCCID_PDU, proto_cbrs_oids, "CBRS_CBSD_FCCID");
  register_ber_oid_dissector("1.3.6.1.4.1.46609.1.5", dissect_SERIAL_PDU, proto_cbrs_oids, "CBRS_CBSD_SERIAL");
  register_ber_oid_dissector("1.3.6.1.4.1.46609.1.6", dissect_FRN_PDU, proto_cbrs_oids, "CBRS_SAS/OPERATOR_administrator_FRN");
  register_ber_oid_dissector("1.3.6.1.4.1.46609.1.7", dissect_CPIRID_PDU, proto_cbrs_oids, "CBRS_installer_CPIR-ID");
  register_ber_oid_dissector("1.3.6.1.4.1.46609.1.8", dissect_TEST_PDU, proto_cbrs_oids, "CBRS_TEST");

  oid_add_from_string("CBRS Policy Documents","1.3.6.1.4.1.46609.2");
  oid_add_from_string("CBRS Certificates issued pursuant to CPS","1.3.6.1.4.1.46609.2.1");
  oid_add_from_string("CBRS ROLE","1.3.6.1.4.1.46609.1.1");
  oid_add_from_string("CBRS SAS","1.3.6.1.4.1.46609.1.1.1");
  oid_add_from_string("CBRS INSTALLER","1.3.6.1.4.1.46609.1.1.2");
  oid_add_from_string("CBRS CBSD","1.3.6.1.4.1.46609.1.1.3");
  oid_add_from_string("CBRS OPERATOR (Domain Proxy Operator)","1.3.6.1.4.1.46609.1.1.4");
  oid_add_from_string("CBRS CA","1.3.6.1.4.1.46609.1.1.5");
  oid_add_from_string("CBRS PAL","1.3.6.1.4.1.46609.1.1.6");
  oid_add_from_string("CBRS ESC","1.3.6.1.4.1.46609.1.1.7");
}

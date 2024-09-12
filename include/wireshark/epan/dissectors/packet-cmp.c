/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-cmp.c                                                               */
/* asn2wrs.py -b -q -L -p cmp -c ./cmp.cnf -s ./packet-cmp-template -D . -O ../.. CMP.asn */

/* packet-cmp.c
 *
 * Routines for RFC2510 Certificate Management Protocol packet dissection
 *   Ronnie Sahlberg 2004
 * Updated to RFC4210 CMPv2 and associated "Transport Protocols for CMP" draft
 *   Martin Peylo 2008
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
#include <epan/proto_data.h>
#include <wsutil/array.h>
#include "packet-ber.h"
#include "packet-cmp.h"
#include "packet-crmf.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include "packet-pkcs10.h"
#include "packet-tcp.h"
#include "packet-http.h"
#include <epan/prefs.h>

#define PNAME  "Certificate Management Protocol"
#define PSNAME "CMP"
#define PFNAME "cmp"

#define TCP_PORT_CMP 829

void proto_register_cmp(void);

static dissector_handle_t cmp_http_handle;
static dissector_handle_t cmp_tcp_style_http_handle;
static dissector_handle_t cmp_tcp_handle;

/* desegmentation of CMP over TCP */
static bool cmp_desegment = true;

static unsigned cmp_alternate_http_port;
static unsigned cmp_alternate_tcp_style_http_port;

/* Initialize the protocol and registered fields */
static int proto_cmp;
static int hf_cmp_type_oid;
static int hf_cmp_tcptrans_len;
static int hf_cmp_tcptrans_type;
static int hf_cmp_tcptrans_poll_ref;
static int hf_cmp_tcptrans_next_poll_ref;
static int hf_cmp_tcptrans_ttcb;
static int hf_cmp_tcptrans10_version;
static int hf_cmp_tcptrans10_flags;
static int hf_cmp_PBMParameter_PDU;               /* PBMParameter */
static int hf_cmp_DHBMParameter_PDU;              /* DHBMParameter */
static int hf_cmp_CAProtEncCertValue_PDU;         /* CAProtEncCertValue */
static int hf_cmp_SignKeyPairTypesValue_PDU;      /* SignKeyPairTypesValue */
static int hf_cmp_EncKeyPairTypesValue_PDU;       /* EncKeyPairTypesValue */
static int hf_cmp_PreferredSymmAlgValue_PDU;      /* PreferredSymmAlgValue */
static int hf_cmp_CAKeyUpdateInfoValue_PDU;       /* CAKeyUpdateInfoValue */
static int hf_cmp_CurrentCRLValue_PDU;            /* CurrentCRLValue */
static int hf_cmp_UnsupportedOIDsValue_PDU;       /* UnsupportedOIDsValue */
static int hf_cmp_KeyPairParamReqValue_PDU;       /* KeyPairParamReqValue */
static int hf_cmp_KeyPairParamRepValue_PDU;       /* KeyPairParamRepValue */
static int hf_cmp_RevPassphraseValue_PDU;         /* RevPassphraseValue */
static int hf_cmp_ImplicitConfirmValue_PDU;       /* ImplicitConfirmValue */
static int hf_cmp_ConfirmWaitTimeValue_PDU;       /* ConfirmWaitTimeValue */
static int hf_cmp_OrigPKIMessageValue_PDU;        /* OrigPKIMessageValue */
static int hf_cmp_SuppLangTagsValue_PDU;          /* SuppLangTagsValue */
static int hf_cmp_x509v3PKCert;                   /* Certificate */
static int hf_cmp_header;                         /* PKIHeader */
static int hf_cmp_body;                           /* PKIBody */
static int hf_cmp_protection;                     /* PKIProtection */
static int hf_cmp_extraCerts;                     /* SEQUENCE_SIZE_1_MAX_OF_CMPCertificate */
static int hf_cmp_extraCerts_item;                /* CMPCertificate */
static int hf_cmp_PKIMessages_item;               /* PKIMessage */
static int hf_cmp_pvno;                           /* T_pvno */
static int hf_cmp_sender;                         /* GeneralName */
static int hf_cmp_recipient;                      /* GeneralName */
static int hf_cmp_messageTime;                    /* GeneralizedTime */
static int hf_cmp_protectionAlg;                  /* AlgorithmIdentifier */
static int hf_cmp_senderKID;                      /* KeyIdentifier */
static int hf_cmp_recipKID;                       /* KeyIdentifier */
static int hf_cmp_transactionID;                  /* OCTET_STRING */
static int hf_cmp_senderNonce;                    /* OCTET_STRING */
static int hf_cmp_recipNonce;                     /* OCTET_STRING */
static int hf_cmp_freeText;                       /* PKIFreeText */
static int hf_cmp_generalInfo;                    /* SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue */
static int hf_cmp_generalInfo_item;               /* InfoTypeAndValue */
static int hf_cmp_PKIFreeText_item;               /* UTF8String */
static int hf_cmp_ir;                             /* CertReqMessages */
static int hf_cmp_ip;                             /* CertRepMessage */
static int hf_cmp_cr;                             /* CertReqMessages */
static int hf_cmp_cp;                             /* CertRepMessage */
static int hf_cmp_p10cr;                          /* CertificationRequest */
static int hf_cmp_popdecc;                        /* POPODecKeyChallContent */
static int hf_cmp_popdecr;                        /* POPODecKeyRespContent */
static int hf_cmp_kur;                            /* CertReqMessages */
static int hf_cmp_kup;                            /* CertRepMessage */
static int hf_cmp_krr;                            /* CertReqMessages */
static int hf_cmp_krp;                            /* KeyRecRepContent */
static int hf_cmp_rr;                             /* RevReqContent */
static int hf_cmp_rp;                             /* RevRepContent */
static int hf_cmp_ccr;                            /* CertReqMessages */
static int hf_cmp_ccp;                            /* CertRepMessage */
static int hf_cmp_ckuann;                         /* CAKeyUpdAnnContent */
static int hf_cmp_cann;                           /* CertAnnContent */
static int hf_cmp_rann;                           /* RevAnnContent */
static int hf_cmp_crlann;                         /* CRLAnnContent */
static int hf_cmp_pkiconf;                        /* PKIConfirmContent */
static int hf_cmp_nested;                         /* NestedMessageContent */
static int hf_cmp_genm;                           /* GenMsgContent */
static int hf_cmp_genp;                           /* GenRepContent */
static int hf_cmp_error;                          /* ErrorMsgContent */
static int hf_cmp_certConf;                       /* CertConfirmContent */
static int hf_cmp_pollReq;                        /* PollReqContent */
static int hf_cmp_pollRep;                        /* PollRepContent */
static int hf_cmp_salt;                           /* OCTET_STRING */
static int hf_cmp_owf;                            /* AlgorithmIdentifier */
static int hf_cmp_iterationCount;                 /* INTEGER */
static int hf_cmp_mac;                            /* AlgorithmIdentifier */
static int hf_cmp_pkistatus;                      /* PKIStatus */
static int hf_cmp_statusString;                   /* PKIFreeText */
static int hf_cmp_failInfo;                       /* PKIFailureInfo */
static int hf_cmp_hashAlg;                        /* AlgorithmIdentifier */
static int hf_cmp_certId;                         /* CertId */
static int hf_cmp_hashVal;                        /* BIT_STRING */
static int hf_cmp_POPODecKeyChallContent_item;    /* Challenge */
static int hf_cmp_witness;                        /* OCTET_STRING */
static int hf_cmp_challenge;                      /* OCTET_STRING */
static int hf_cmp_POPODecKeyRespContent_item;     /* INTEGER */
static int hf_cmp_caPubs;                         /* SEQUENCE_SIZE_1_MAX_OF_CMPCertificate */
static int hf_cmp_caPubs_item;                    /* CMPCertificate */
static int hf_cmp_response;                       /* SEQUENCE_OF_CertResponse */
static int hf_cmp_response_item;                  /* CertResponse */
static int hf_cmp_certReqId;                      /* INTEGER */
static int hf_cmp_pkistatusinf;                   /* PKIStatusInfo */
static int hf_cmp_certifiedKeyPair;               /* CertifiedKeyPair */
static int hf_cmp_rspInfo;                        /* OCTET_STRING */
static int hf_cmp_certOrEncCert;                  /* CertOrEncCert */
static int hf_cmp_privateKey;                     /* EncryptedValue */
static int hf_cmp_publicationInfo;                /* PKIPublicationInfo */
static int hf_cmp_certificate;                    /* CMPCertificate */
static int hf_cmp_encryptedCert;                  /* EncryptedValue */
static int hf_cmp_newSigCert;                     /* CMPCertificate */
static int hf_cmp_caCerts;                        /* SEQUENCE_SIZE_1_MAX_OF_CMPCertificate */
static int hf_cmp_caCerts_item;                   /* CMPCertificate */
static int hf_cmp_keyPairHist;                    /* SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair */
static int hf_cmp_keyPairHist_item;               /* CertifiedKeyPair */
static int hf_cmp_RevReqContent_item;             /* RevDetails */
static int hf_cmp_certDetails;                    /* CertTemplate */
static int hf_cmp_crlEntryDetails;                /* Extensions */
static int hf_cmp_rvrpcnt_status;                 /* SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo */
static int hf_cmp_rvrpcnt_status_item;            /* PKIStatusInfo */
static int hf_cmp_revCerts;                       /* SEQUENCE_SIZE_1_MAX_OF_CertId */
static int hf_cmp_revCerts_item;                  /* CertId */
static int hf_cmp_crls;                           /* SEQUENCE_SIZE_1_MAX_OF_CertificateList */
static int hf_cmp_crls_item;                      /* CertificateList */
static int hf_cmp_oldWithNew;                     /* CMPCertificate */
static int hf_cmp_newWithOld;                     /* CMPCertificate */
static int hf_cmp_newWithNew;                     /* CMPCertificate */
static int hf_cmp_pkistatus_01;                   /* PKIStatus */
static int hf_cmp_willBeRevokedAt;                /* GeneralizedTime */
static int hf_cmp_badSinceDate;                   /* GeneralizedTime */
static int hf_cmp_crlDetails;                     /* Extensions */
static int hf_cmp_CRLAnnContent_item;             /* CertificateList */
static int hf_cmp_CertConfirmContent_item;        /* CertStatus */
static int hf_cmp_certHash;                       /* OCTET_STRING */
static int hf_cmp_statusInfo;                     /* PKIStatusInfo */
static int hf_cmp_infoType;                       /* T_infoType */
static int hf_cmp_infoValue;                      /* T_infoValue */
static int hf_cmp_SignKeyPairTypesValue_item;     /* AlgorithmIdentifier */
static int hf_cmp_EncKeyPairTypesValue_item;      /* AlgorithmIdentifier */
static int hf_cmp_UnsupportedOIDsValue_item;      /* OBJECT_IDENTIFIER */
static int hf_cmp_SuppLangTagsValue_item;         /* UTF8String */
static int hf_cmp_GenMsgContent_item;             /* InfoTypeAndValue */
static int hf_cmp_GenRepContent_item;             /* InfoTypeAndValue */
static int hf_cmp_pKIStatusInfo;                  /* PKIStatusInfo */
static int hf_cmp_errorCode;                      /* INTEGER */
static int hf_cmp_errorDetails;                   /* PKIFreeText */
static int hf_cmp_PollReqContent_item;            /* PollReqContent_item */
static int hf_cmp_PollRepContent_item;            /* PollRepContent_item */
static int hf_cmp_checkAfter;                     /* INTEGER */
static int hf_cmp_reason;                         /* PKIFreeText */
/* named bits */
static int hf_cmp_PKIFailureInfo_badAlg;
static int hf_cmp_PKIFailureInfo_badMessageCheck;
static int hf_cmp_PKIFailureInfo_badRequest;
static int hf_cmp_PKIFailureInfo_badTime;
static int hf_cmp_PKIFailureInfo_badCertId;
static int hf_cmp_PKIFailureInfo_badDataFormat;
static int hf_cmp_PKIFailureInfo_wrongAuthority;
static int hf_cmp_PKIFailureInfo_incorrectData;
static int hf_cmp_PKIFailureInfo_missingTimeStamp;
static int hf_cmp_PKIFailureInfo_badPOP;
static int hf_cmp_PKIFailureInfo_certRevoked;
static int hf_cmp_PKIFailureInfo_certConfirmed;
static int hf_cmp_PKIFailureInfo_wrongIntegrity;
static int hf_cmp_PKIFailureInfo_badRecipientNonce;
static int hf_cmp_PKIFailureInfo_timeNotAvailable;
static int hf_cmp_PKIFailureInfo_unacceptedPolicy;
static int hf_cmp_PKIFailureInfo_unacceptedExtension;
static int hf_cmp_PKIFailureInfo_addInfoNotAvailable;
static int hf_cmp_PKIFailureInfo_badSenderNonce;
static int hf_cmp_PKIFailureInfo_badCertTemplate;
static int hf_cmp_PKIFailureInfo_signerNotTrusted;
static int hf_cmp_PKIFailureInfo_transactionIdInUse;
static int hf_cmp_PKIFailureInfo_unsupportedVersion;
static int hf_cmp_PKIFailureInfo_notAuthorized;
static int hf_cmp_PKIFailureInfo_systemUnavail;
static int hf_cmp_PKIFailureInfo_systemFailure;
static int hf_cmp_PKIFailureInfo_duplicateCertReq;

/* Initialize the subtree pointers */
static int ett_cmp;
static int ett_cmp_CMPCertificate;
static int ett_cmp_PKIMessage;
static int ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate;
static int ett_cmp_PKIMessages;
static int ett_cmp_PKIHeader;
static int ett_cmp_SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue;
static int ett_cmp_PKIFreeText;
static int ett_cmp_PKIBody;
static int ett_cmp_ProtectedPart;
static int ett_cmp_PBMParameter;
static int ett_cmp_DHBMParameter;
static int ett_cmp_PKIFailureInfo;
static int ett_cmp_PKIStatusInfo;
static int ett_cmp_OOBCertHash;
static int ett_cmp_POPODecKeyChallContent;
static int ett_cmp_Challenge;
static int ett_cmp_POPODecKeyRespContent;
static int ett_cmp_CertRepMessage;
static int ett_cmp_SEQUENCE_OF_CertResponse;
static int ett_cmp_CertResponse;
static int ett_cmp_CertifiedKeyPair;
static int ett_cmp_CertOrEncCert;
static int ett_cmp_KeyRecRepContent;
static int ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair;
static int ett_cmp_RevReqContent;
static int ett_cmp_RevDetails;
static int ett_cmp_RevRepContent;
static int ett_cmp_SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo;
static int ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertId;
static int ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertificateList;
static int ett_cmp_CAKeyUpdAnnContent;
static int ett_cmp_RevAnnContent;
static int ett_cmp_CRLAnnContent;
static int ett_cmp_CertConfirmContent;
static int ett_cmp_CertStatus;
static int ett_cmp_InfoTypeAndValue;
static int ett_cmp_SignKeyPairTypesValue;
static int ett_cmp_EncKeyPairTypesValue;
static int ett_cmp_UnsupportedOIDsValue;
static int ett_cmp_SuppLangTagsValue;
static int ett_cmp_GenMsgContent;
static int ett_cmp_GenRepContent;
static int ett_cmp_ErrorMsgContent;
static int ett_cmp_PollReqContent;
static int ett_cmp_PollReqContent_item;
static int ett_cmp_PollRepContent;
static int ett_cmp_PollRepContent_item;
/*--- Cyclic dependencies ---*/

/* PKIMessage -> PKIBody -> NestedMessageContent -> PKIMessages -> PKIMessage */
/*int dissect_cmp_PKIMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);*/



static const value_string cmp_CMPCertificate_vals[] = {
  {   0, "x509v3PKCert" },
  { 0, NULL }
};

static const ber_choice_t CMPCertificate_choice[] = {
  {   0, &hf_cmp_x509v3PKCert    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Certificate },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_CMPCertificate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CMPCertificate_choice, hf_index, ett_cmp_CMPCertificate,
                                 NULL);

  return offset;
}


static const value_string cmp_T_pvno_vals[] = {
  {   1, "cmp1999" },
  {   2, "cmp2000" },
  { 0, NULL }
};


static int
dissect_cmp_T_pvno(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_cmp_GeneralizedTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_cmp_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_cmp_UTF8String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t PKIFreeText_sequence_of[1] = {
  { &hf_cmp_PKIFreeText_item, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_cmp_UTF8String },
};

static int
dissect_cmp_PKIFreeText(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PKIFreeText_sequence_of, hf_index, ett_cmp_PKIFreeText);

  return offset;
}



static int
dissect_cmp_T_infoType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_cmp_type_oid, &actx->external.direct_reference);

  return offset;
}



static int
dissect_cmp_T_infoValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t InfoTypeAndValue_sequence[] = {
  { &hf_cmp_infoType        , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmp_T_infoType },
  { &hf_cmp_infoValue       , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_T_infoValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_InfoTypeAndValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InfoTypeAndValue_sequence, hf_index, ett_cmp_InfoTypeAndValue);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue_sequence_of[1] = {
  { &hf_cmp_generalInfo_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_InfoTypeAndValue },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue);

  return offset;
}


static const ber_sequence_t PKIHeader_sequence[] = {
  { &hf_cmp_pvno            , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_T_pvno },
  { &hf_cmp_sender          , BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_GeneralName },
  { &hf_cmp_recipient       , BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_GeneralName },
  { &hf_cmp_messageTime     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_cmp_GeneralizedTime },
  { &hf_cmp_protectionAlg   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_cmp_senderKID       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_pkix1implicit_KeyIdentifier },
  { &hf_cmp_recipKID        , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_pkix1implicit_KeyIdentifier },
  { &hf_cmp_transactionID   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_cmp_OCTET_STRING },
  { &hf_cmp_senderNonce     , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_cmp_OCTET_STRING },
  { &hf_cmp_recipNonce      , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_cmp_OCTET_STRING },
  { &hf_cmp_freeText        , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_cmp_PKIFreeText },
  { &hf_cmp_generalInfo     , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_PKIHeader(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PKIHeader_sequence, hf_index, ett_cmp_PKIHeader);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_CMPCertificate_sequence_of[1] = {
  { &hf_cmp_extraCerts_item , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmp_CMPCertificate },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_CMPCertificate_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate);

  return offset;
}



static int
dissect_cmp_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string cmp_PKIStatus_vals[] = {
  {   0, "accepted" },
  {   1, "grantedWithMods" },
  {   2, "rejection" },
  {   3, "waiting" },
  {   4, "revocationWarning" },
  {   5, "revocationNotification" },
  {   6, "keyUpdateWarning" },
  { 0, NULL }
};


static int
dissect_cmp_PKIStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t value;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &value);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " Status=%s", val_to_str_const(value, cmp_PKIStatus_vals, "unknown"));


  return offset;
}


static int * const PKIFailureInfo_bits[] = {
  &hf_cmp_PKIFailureInfo_badAlg,
  &hf_cmp_PKIFailureInfo_badMessageCheck,
  &hf_cmp_PKIFailureInfo_badRequest,
  &hf_cmp_PKIFailureInfo_badTime,
  &hf_cmp_PKIFailureInfo_badCertId,
  &hf_cmp_PKIFailureInfo_badDataFormat,
  &hf_cmp_PKIFailureInfo_wrongAuthority,
  &hf_cmp_PKIFailureInfo_incorrectData,
  &hf_cmp_PKIFailureInfo_missingTimeStamp,
  &hf_cmp_PKIFailureInfo_badPOP,
  &hf_cmp_PKIFailureInfo_certRevoked,
  &hf_cmp_PKIFailureInfo_certConfirmed,
  &hf_cmp_PKIFailureInfo_wrongIntegrity,
  &hf_cmp_PKIFailureInfo_badRecipientNonce,
  &hf_cmp_PKIFailureInfo_timeNotAvailable,
  &hf_cmp_PKIFailureInfo_unacceptedPolicy,
  &hf_cmp_PKIFailureInfo_unacceptedExtension,
  &hf_cmp_PKIFailureInfo_addInfoNotAvailable,
  &hf_cmp_PKIFailureInfo_badSenderNonce,
  &hf_cmp_PKIFailureInfo_badCertTemplate,
  &hf_cmp_PKIFailureInfo_signerNotTrusted,
  &hf_cmp_PKIFailureInfo_transactionIdInUse,
  &hf_cmp_PKIFailureInfo_unsupportedVersion,
  &hf_cmp_PKIFailureInfo_notAuthorized,
  &hf_cmp_PKIFailureInfo_systemUnavail,
  &hf_cmp_PKIFailureInfo_systemFailure,
  &hf_cmp_PKIFailureInfo_duplicateCertReq,
  NULL
};

static int
dissect_cmp_PKIFailureInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    PKIFailureInfo_bits, 27, hf_index, ett_cmp_PKIFailureInfo,
                                    NULL);

  return offset;
}


static const ber_sequence_t PKIStatusInfo_sequence[] = {
  { &hf_cmp_pkistatus       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIStatus },
  { &hf_cmp_statusString    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_PKIFreeText },
  { &hf_cmp_failInfo        , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_PKIFailureInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_PKIStatusInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PKIStatusInfo_sequence, hf_index, ett_cmp_PKIStatusInfo);

  return offset;
}


static const value_string cmp_CertOrEncCert_vals[] = {
  {   0, "certificate" },
  {   1, "encryptedCert" },
  { 0, NULL }
};

static const ber_choice_t CertOrEncCert_choice[] = {
  {   0, &hf_cmp_certificate     , BER_CLASS_CON, 0, 0, dissect_cmp_CMPCertificate },
  {   1, &hf_cmp_encryptedCert   , BER_CLASS_CON, 1, 0, dissect_crmf_EncryptedValue },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_CertOrEncCert(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CertOrEncCert_choice, hf_index, ett_cmp_CertOrEncCert,
                                 NULL);

  return offset;
}


static const ber_sequence_t CertifiedKeyPair_sequence[] = {
  { &hf_cmp_certOrEncCert   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmp_CertOrEncCert },
  { &hf_cmp_privateKey      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_crmf_EncryptedValue },
  { &hf_cmp_publicationInfo , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_crmf_PKIPublicationInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_CertifiedKeyPair(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertifiedKeyPair_sequence, hf_index, ett_cmp_CertifiedKeyPair);

  return offset;
}


static const ber_sequence_t CertResponse_sequence[] = {
  { &hf_cmp_certReqId       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_INTEGER },
  { &hf_cmp_pkistatusinf    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIStatusInfo },
  { &hf_cmp_certifiedKeyPair, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_CertifiedKeyPair },
  { &hf_cmp_rspInfo         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_CertResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertResponse_sequence, hf_index, ett_cmp_CertResponse);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_CertResponse_sequence_of[1] = {
  { &hf_cmp_response_item   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_CertResponse },
};

static int
dissect_cmp_SEQUENCE_OF_CertResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_CertResponse_sequence_of, hf_index, ett_cmp_SEQUENCE_OF_CertResponse);

  return offset;
}


static const ber_sequence_t CertRepMessage_sequence[] = {
  { &hf_cmp_caPubs          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate },
  { &hf_cmp_response        , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_SEQUENCE_OF_CertResponse },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_CertRepMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertRepMessage_sequence, hf_index, ett_cmp_CertRepMessage);

  return offset;
}


static const ber_sequence_t Challenge_sequence[] = {
  { &hf_cmp_owf             , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_cmp_witness         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cmp_OCTET_STRING },
  { &hf_cmp_challenge       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cmp_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_Challenge(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Challenge_sequence, hf_index, ett_cmp_Challenge);

  return offset;
}


static const ber_sequence_t POPODecKeyChallContent_sequence_of[1] = {
  { &hf_cmp_POPODecKeyChallContent_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_Challenge },
};

static int
dissect_cmp_POPODecKeyChallContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      POPODecKeyChallContent_sequence_of, hf_index, ett_cmp_POPODecKeyChallContent);

  return offset;
}


static const ber_sequence_t POPODecKeyRespContent_sequence_of[1] = {
  { &hf_cmp_POPODecKeyRespContent_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_INTEGER },
};

static int
dissect_cmp_POPODecKeyRespContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      POPODecKeyRespContent_sequence_of, hf_index, ett_cmp_POPODecKeyRespContent);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair_sequence_of[1] = {
  { &hf_cmp_keyPairHist_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_CertifiedKeyPair },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair);

  return offset;
}


static const ber_sequence_t KeyRecRepContent_sequence[] = {
  { &hf_cmp_pkistatusinf    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIStatusInfo },
  { &hf_cmp_newSigCert      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_cmp_CMPCertificate },
  { &hf_cmp_caCerts         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate },
  { &hf_cmp_keyPairHist     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_KeyRecRepContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KeyRecRepContent_sequence, hf_index, ett_cmp_KeyRecRepContent);

  return offset;
}


static const ber_sequence_t RevDetails_sequence[] = {
  { &hf_cmp_certDetails     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crmf_CertTemplate },
  { &hf_cmp_crlEntryDetails , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_RevDetails(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RevDetails_sequence, hf_index, ett_cmp_RevDetails);

  return offset;
}


static const ber_sequence_t RevReqContent_sequence_of[1] = {
  { &hf_cmp_RevReqContent_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_RevDetails },
};

static int
dissect_cmp_RevReqContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RevReqContent_sequence_of, hf_index, ett_cmp_RevReqContent);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo_sequence_of[1] = {
  { &hf_cmp_rvrpcnt_status_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIStatusInfo },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_CertId_sequence_of[1] = {
  { &hf_cmp_revCerts_item   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crmf_CertId },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_CertId_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertId);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_CertificateList_sequence_of[1] = {
  { &hf_cmp_crls_item       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_CertificateList },
};

static int
dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertificateList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_CertificateList_sequence_of, hf_index, ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertificateList);

  return offset;
}


static const ber_sequence_t RevRepContent_sequence[] = {
  { &hf_cmp_rvrpcnt_status  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo },
  { &hf_cmp_revCerts        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertId },
  { &hf_cmp_crls            , BER_CLASS_CON, 1, 0, dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CertificateList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_RevRepContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RevRepContent_sequence, hf_index, ett_cmp_RevRepContent);

  return offset;
}


static const ber_sequence_t CAKeyUpdAnnContent_sequence[] = {
  { &hf_cmp_oldWithNew      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmp_CMPCertificate },
  { &hf_cmp_newWithOld      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmp_CMPCertificate },
  { &hf_cmp_newWithNew      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmp_CMPCertificate },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_CAKeyUpdAnnContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CAKeyUpdAnnContent_sequence, hf_index, ett_cmp_CAKeyUpdAnnContent);

  return offset;
}



static int
dissect_cmp_CertAnnContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmp_CMPCertificate(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t RevAnnContent_sequence[] = {
  { &hf_cmp_pkistatus_01    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIStatus },
  { &hf_cmp_certId          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crmf_CertId },
  { &hf_cmp_willBeRevokedAt , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_cmp_GeneralizedTime },
  { &hf_cmp_badSinceDate    , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_cmp_GeneralizedTime },
  { &hf_cmp_crlDetails      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_RevAnnContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RevAnnContent_sequence, hf_index, ett_cmp_RevAnnContent);

  return offset;
}


static const ber_sequence_t CRLAnnContent_sequence_of[1] = {
  { &hf_cmp_CRLAnnContent_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_CertificateList },
};

static int
dissect_cmp_CRLAnnContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      CRLAnnContent_sequence_of, hf_index, ett_cmp_CRLAnnContent);

  return offset;
}



static int
dissect_cmp_PKIConfirmContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t PKIMessages_sequence_of[1] = {
  { &hf_cmp_PKIMessages_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIMessage },
};

static int
dissect_cmp_PKIMessages(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PKIMessages_sequence_of, hf_index, ett_cmp_PKIMessages);

  return offset;
}



static int
dissect_cmp_NestedMessageContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmp_PKIMessages(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t GenMsgContent_sequence_of[1] = {
  { &hf_cmp_GenMsgContent_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_InfoTypeAndValue },
};

static int
dissect_cmp_GenMsgContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      GenMsgContent_sequence_of, hf_index, ett_cmp_GenMsgContent);

  return offset;
}


static const ber_sequence_t GenRepContent_sequence_of[1] = {
  { &hf_cmp_GenRepContent_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_InfoTypeAndValue },
};

static int
dissect_cmp_GenRepContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      GenRepContent_sequence_of, hf_index, ett_cmp_GenRepContent);

  return offset;
}


static const ber_sequence_t ErrorMsgContent_sequence[] = {
  { &hf_cmp_pKIStatusInfo   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIStatusInfo },
  { &hf_cmp_errorCode       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_INTEGER },
  { &hf_cmp_errorDetails    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_PKIFreeText },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_ErrorMsgContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ErrorMsgContent_sequence, hf_index, ett_cmp_ErrorMsgContent);

  return offset;
}


static const ber_sequence_t CertStatus_sequence[] = {
  { &hf_cmp_certHash        , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cmp_OCTET_STRING },
  { &hf_cmp_certReqId       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_INTEGER },
  { &hf_cmp_statusInfo      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_PKIStatusInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_CertStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertStatus_sequence, hf_index, ett_cmp_CertStatus);

  return offset;
}


static const ber_sequence_t CertConfirmContent_sequence_of[1] = {
  { &hf_cmp_CertConfirmContent_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_CertStatus },
};

static int
dissect_cmp_CertConfirmContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      CertConfirmContent_sequence_of, hf_index, ett_cmp_CertConfirmContent);

  return offset;
}


static const ber_sequence_t PollReqContent_item_sequence[] = {
  { &hf_cmp_certReqId       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_PollReqContent_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PollReqContent_item_sequence, hf_index, ett_cmp_PollReqContent_item);

  return offset;
}


static const ber_sequence_t PollReqContent_sequence_of[1] = {
  { &hf_cmp_PollReqContent_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PollReqContent_item },
};

static int
dissect_cmp_PollReqContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PollReqContent_sequence_of, hf_index, ett_cmp_PollReqContent);

  return offset;
}


static const ber_sequence_t PollRepContent_item_sequence[] = {
  { &hf_cmp_certReqId       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_INTEGER },
  { &hf_cmp_checkAfter      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_INTEGER },
  { &hf_cmp_reason          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmp_PKIFreeText },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_PollRepContent_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PollRepContent_item_sequence, hf_index, ett_cmp_PollRepContent_item);

  return offset;
}


static const ber_sequence_t PollRepContent_sequence_of[1] = {
  { &hf_cmp_PollRepContent_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PollRepContent_item },
};

static int
dissect_cmp_PollRepContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PollRepContent_sequence_of, hf_index, ett_cmp_PollRepContent);

  return offset;
}


static const value_string cmp_PKIBody_vals[] = {
  {   0, "ir" },
  {   1, "ip" },
  {   2, "cr" },
  {   3, "cp" },
  {   4, "p10cr" },
  {   5, "popdecc" },
  {   6, "popdecr" },
  {   7, "kur" },
  {   8, "kup" },
  {   9, "krr" },
  {  10, "krp" },
  {  11, "rr" },
  {  12, "rp" },
  {  13, "ccr" },
  {  14, "ccp" },
  {  15, "ckuann" },
  {  16, "cann" },
  {  17, "rann" },
  {  18, "crlann" },
  {  19, "pkiconf" },
  {  20, "nested" },
  {  21, "genm" },
  {  22, "genp" },
  {  23, "error" },
  {  24, "certConf" },
  {  25, "pollReq" },
  {  26, "pollRep" },
  { 0, NULL }
};

static const ber_choice_t PKIBody_choice[] = {
  {   0, &hf_cmp_ir              , BER_CLASS_CON, 0, 0, dissect_crmf_CertReqMessages },
  {   1, &hf_cmp_ip              , BER_CLASS_CON, 1, 0, dissect_cmp_CertRepMessage },
  {   2, &hf_cmp_cr              , BER_CLASS_CON, 2, 0, dissect_crmf_CertReqMessages },
  {   3, &hf_cmp_cp              , BER_CLASS_CON, 3, 0, dissect_cmp_CertRepMessage },
  {   4, &hf_cmp_p10cr           , BER_CLASS_CON, 4, 0, dissect_pkcs10_CertificationRequest },
  {   5, &hf_cmp_popdecc         , BER_CLASS_CON, 5, 0, dissect_cmp_POPODecKeyChallContent },
  {   6, &hf_cmp_popdecr         , BER_CLASS_CON, 6, 0, dissect_cmp_POPODecKeyRespContent },
  {   7, &hf_cmp_kur             , BER_CLASS_CON, 7, 0, dissect_crmf_CertReqMessages },
  {   8, &hf_cmp_kup             , BER_CLASS_CON, 8, 0, dissect_cmp_CertRepMessage },
  {   9, &hf_cmp_krr             , BER_CLASS_CON, 9, 0, dissect_crmf_CertReqMessages },
  {  10, &hf_cmp_krp             , BER_CLASS_CON, 10, 0, dissect_cmp_KeyRecRepContent },
  {  11, &hf_cmp_rr              , BER_CLASS_CON, 11, 0, dissect_cmp_RevReqContent },
  {  12, &hf_cmp_rp              , BER_CLASS_CON, 12, 0, dissect_cmp_RevRepContent },
  {  13, &hf_cmp_ccr             , BER_CLASS_CON, 13, 0, dissect_crmf_CertReqMessages },
  {  14, &hf_cmp_ccp             , BER_CLASS_CON, 14, 0, dissect_cmp_CertRepMessage },
  {  15, &hf_cmp_ckuann          , BER_CLASS_CON, 15, 0, dissect_cmp_CAKeyUpdAnnContent },
  {  16, &hf_cmp_cann            , BER_CLASS_CON, 16, 0, dissect_cmp_CertAnnContent },
  {  17, &hf_cmp_rann            , BER_CLASS_CON, 17, 0, dissect_cmp_RevAnnContent },
  {  18, &hf_cmp_crlann          , BER_CLASS_CON, 18, 0, dissect_cmp_CRLAnnContent },
  {  19, &hf_cmp_pkiconf         , BER_CLASS_CON, 19, 0, dissect_cmp_PKIConfirmContent },
  {  20, &hf_cmp_nested          , BER_CLASS_CON, 20, 0, dissect_cmp_NestedMessageContent },
  {  21, &hf_cmp_genm            , BER_CLASS_CON, 21, 0, dissect_cmp_GenMsgContent },
  {  22, &hf_cmp_genp            , BER_CLASS_CON, 22, 0, dissect_cmp_GenRepContent },
  {  23, &hf_cmp_error           , BER_CLASS_CON, 23, 0, dissect_cmp_ErrorMsgContent },
  {  24, &hf_cmp_certConf        , BER_CLASS_CON, 24, 0, dissect_cmp_CertConfirmContent },
  {  25, &hf_cmp_pollReq         , BER_CLASS_CON, 25, 0, dissect_cmp_PollReqContent },
  {  26, &hf_cmp_pollRep         , BER_CLASS_CON, 26, 0, dissect_cmp_PollRepContent },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_PKIBody(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int branch_taken;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PKIBody_choice, hf_index, ett_cmp_PKIBody,
                                 &branch_taken);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " Body=%s", val_to_str_const(branch_taken, cmp_PKIBody_vals, "unknown"));


  return offset;
}



static int
dissect_cmp_PKIProtection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t PKIMessage_sequence[] = {
  { &hf_cmp_header          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIHeader },
  { &hf_cmp_body            , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmp_PKIBody },
  { &hf_cmp_protection      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_cmp_PKIProtection },
  { &hf_cmp_extraCerts      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_PKIMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // PKIMessage -> PKIBody -> NestedMessageContent -> PKIMessages -> PKIMessage
  actx->pinfo->dissection_depth += 4;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PKIMessage_sequence, hf_index, ett_cmp_PKIMessage);

  actx->pinfo->dissection_depth -= 4;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const ber_sequence_t ProtectedPart_sequence[] = {
  { &hf_cmp_header          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmp_PKIHeader },
  { &hf_cmp_body            , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmp_PKIBody },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_ProtectedPart(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProtectedPart_sequence, hf_index, ett_cmp_ProtectedPart);

  return offset;
}


static const ber_sequence_t PBMParameter_sequence[] = {
  { &hf_cmp_salt            , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cmp_OCTET_STRING },
  { &hf_cmp_owf             , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_cmp_iterationCount  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmp_INTEGER },
  { &hf_cmp_mac             , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_PBMParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PBMParameter_sequence, hf_index, ett_cmp_PBMParameter);

  return offset;
}


static const ber_sequence_t DHBMParameter_sequence[] = {
  { &hf_cmp_owf             , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_cmp_mac             , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmp_DHBMParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DHBMParameter_sequence, hf_index, ett_cmp_DHBMParameter);

  return offset;
}



int
dissect_cmp_OOBCert(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmp_CMPCertificate(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmp_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t OOBCertHash_sequence[] = {
  { &hf_cmp_hashAlg         , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_cmp_certId          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_crmf_CertId },
  { &hf_cmp_hashVal         , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_cmp_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmp_OOBCertHash(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OOBCertHash_sequence, hf_index, ett_cmp_OOBCertHash);

  return offset;
}



static int
dissect_cmp_CAProtEncCertValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmp_CMPCertificate(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SignKeyPairTypesValue_sequence_of[1] = {
  { &hf_cmp_SignKeyPairTypesValue_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
};

static int
dissect_cmp_SignKeyPairTypesValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SignKeyPairTypesValue_sequence_of, hf_index, ett_cmp_SignKeyPairTypesValue);

  return offset;
}


static const ber_sequence_t EncKeyPairTypesValue_sequence_of[1] = {
  { &hf_cmp_EncKeyPairTypesValue_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
};

static int
dissect_cmp_EncKeyPairTypesValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      EncKeyPairTypesValue_sequence_of, hf_index, ett_cmp_EncKeyPairTypesValue);

  return offset;
}



static int
dissect_cmp_PreferredSymmAlgValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pkix1explicit_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmp_CAKeyUpdateInfoValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmp_CAKeyUpdAnnContent(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmp_CurrentCRLValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pkix1explicit_CertificateList(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmp_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t UnsupportedOIDsValue_sequence_of[1] = {
  { &hf_cmp_UnsupportedOIDsValue_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmp_OBJECT_IDENTIFIER },
};

static int
dissect_cmp_UnsupportedOIDsValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      UnsupportedOIDsValue_sequence_of, hf_index, ett_cmp_UnsupportedOIDsValue);

  return offset;
}



static int
dissect_cmp_KeyPairParamReqValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_cmp_KeyPairParamRepValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pkix1explicit_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmp_RevPassphraseValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_crmf_EncryptedValue(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmp_ImplicitConfirmValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_cmp_ConfirmWaitTimeValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_cmp_OrigPKIMessageValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmp_PKIMessages(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SuppLangTagsValue_sequence_of[1] = {
  { &hf_cmp_SuppLangTagsValue_item, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_cmp_UTF8String },
};

static int
dissect_cmp_SuppLangTagsValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SuppLangTagsValue_sequence_of, hf_index, ett_cmp_SuppLangTagsValue);

  return offset;
}

/*--- PDUs ---*/

static int dissect_PBMParameter_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmp_PBMParameter(false, tvb, offset, &asn1_ctx, tree, hf_cmp_PBMParameter_PDU);
  return offset;
}
static int dissect_DHBMParameter_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmp_DHBMParameter(false, tvb, offset, &asn1_ctx, tree, hf_cmp_DHBMParameter_PDU);
  return offset;
}
static int dissect_CAProtEncCertValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmp_CAProtEncCertValue(false, tvb, offset, &asn1_ctx, tree, hf_cmp_CAProtEncCertValue_PDU);
  return offset;
}
static int dissect_SignKeyPairTypesValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmp_SignKeyPairTypesValue(false, tvb, offset, &asn1_ctx, tree, hf_cmp_SignKeyPairTypesValue_PDU);
  return offset;
}
static int dissect_EncKeyPairTypesValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmp_EncKeyPairTypesValue(false, tvb, offset, &asn1_ctx, tree, hf_cmp_EncKeyPairTypesValue_PDU);
  return offset;
}
static int dissect_PreferredSymmAlgValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmp_PreferredSymmAlgValue(false, tvb, offset, &asn1_ctx, tree, hf_cmp_PreferredSymmAlgValue_PDU);
  return offset;
}
static int dissect_CAKeyUpdateInfoValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmp_CAKeyUpdateInfoValue(false, tvb, offset, &asn1_ctx, tree, hf_cmp_CAKeyUpdateInfoValue_PDU);
  return offset;
}
static int dissect_CurrentCRLValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmp_CurrentCRLValue(false, tvb, offset, &asn1_ctx, tree, hf_cmp_CurrentCRLValue_PDU);
  return offset;
}
static int dissect_UnsupportedOIDsValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmp_UnsupportedOIDsValue(false, tvb, offset, &asn1_ctx, tree, hf_cmp_UnsupportedOIDsValue_PDU);
  return offset;
}
static int dissect_KeyPairParamReqValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmp_KeyPairParamReqValue(false, tvb, offset, &asn1_ctx, tree, hf_cmp_KeyPairParamReqValue_PDU);
  return offset;
}
static int dissect_KeyPairParamRepValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmp_KeyPairParamRepValue(false, tvb, offset, &asn1_ctx, tree, hf_cmp_KeyPairParamRepValue_PDU);
  return offset;
}
static int dissect_RevPassphraseValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmp_RevPassphraseValue(false, tvb, offset, &asn1_ctx, tree, hf_cmp_RevPassphraseValue_PDU);
  return offset;
}
static int dissect_ImplicitConfirmValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmp_ImplicitConfirmValue(false, tvb, offset, &asn1_ctx, tree, hf_cmp_ImplicitConfirmValue_PDU);
  return offset;
}
static int dissect_ConfirmWaitTimeValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmp_ConfirmWaitTimeValue(false, tvb, offset, &asn1_ctx, tree, hf_cmp_ConfirmWaitTimeValue_PDU);
  return offset;
}
static int dissect_OrigPKIMessageValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmp_OrigPKIMessageValue(false, tvb, offset, &asn1_ctx, tree, hf_cmp_OrigPKIMessageValue_PDU);
  return offset;
}
static int dissect_SuppLangTagsValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmp_SuppLangTagsValue(false, tvb, offset, &asn1_ctx, tree, hf_cmp_SuppLangTagsValue_PDU);
  return offset;
}


static int
dissect_cmp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	return dissect_cmp_PKIMessage(false, tvb, 0, &asn1_ctx, tree, -1);
}

#define CMP_TYPE_PKIMSG		0
#define CMP_TYPE_POLLREP	1
#define CMP_TYPE_POLLREQ	2
#define CMP_TYPE_NEGPOLLREP	3
#define CMP_TYPE_PARTIALMSGREP	4
#define CMP_TYPE_FINALMSGREP	5
#define CMP_TYPE_ERRORMSGREP	6
static const value_string cmp_pdu_types[] = {
	{ CMP_TYPE_PKIMSG,		"pkiMsg" },
	{ CMP_TYPE_POLLREP,		"pollRep" },
	{ CMP_TYPE_POLLREQ,		"pollReq" },
	{ CMP_TYPE_NEGPOLLREP,		"negPollRep" },
	{ CMP_TYPE_PARTIALMSGREP,	"partialMsgRep" },
	{ CMP_TYPE_FINALMSGREP,		"finalMsgRep" },
	{ CMP_TYPE_ERRORMSGREP,		"errorMsgRep" },
	{ 0, NULL },
};


static int dissect_cmp_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	tvbuff_t   *next_tvb;
	uint32_t   pdu_len;
	uint8_t    pdu_type;
	proto_item *item=NULL;
	proto_item *ti=NULL;
	proto_tree *tree=NULL;
	proto_tree *tcptrans_tree=NULL;
	int offset=0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMP");
	col_set_str(pinfo->cinfo, COL_INFO, "PKIXCMP");

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_cmp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_cmp);
	}

	pdu_len=tvb_get_ntohl(tvb, 0);
	pdu_type=tvb_get_uint8(tvb, 4);

	if (pdu_type < 10) {
		/* RFC2510 TCP transport */
		ti = proto_tree_add_item(tree, proto_cmp, tvb, offset, 5, ENC_NA);
		tcptrans_tree = proto_item_add_subtree(ti, ett_cmp);
		proto_tree_add_item(tree, hf_cmp_tcptrans_len, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_cmp_tcptrans_type, tvb, offset++, 1, ENC_BIG_ENDIAN);
	} else {
		/* post RFC2510 TCP transport - the former "type" field is now "version" */
		tcptrans_tree = proto_tree_add_subtree(tree, tvb, offset, 7, ett_cmp, NULL, "TCP transport");
		pdu_type=tvb_get_uint8(tvb, 6);
		proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_len, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans10_version, tvb, offset++, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans10_flags, tvb, offset++, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_type, tvb, offset++, 1, ENC_BIG_ENDIAN);
	}

	col_add_str (pinfo->cinfo, COL_INFO, val_to_str (pdu_type, cmp_pdu_types, "0x%x"));

	switch(pdu_type){
		case CMP_TYPE_PKIMSG:
			next_tvb = tvb_new_subset_length_caplen(tvb, offset, tvb_reported_length_remaining(tvb, offset), pdu_len);
			dissect_cmp_pdu(next_tvb, pinfo, tree, NULL);
			offset += tvb_reported_length_remaining(tvb, offset);
			break;
		case CMP_TYPE_POLLREP:
			proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_poll_ref, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_ttcb, tvb, offset, 4, ENC_TIME_SECS|ENC_BIG_ENDIAN);
			offset += 4;
			break;
		case CMP_TYPE_POLLREQ:
			proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_poll_ref, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			break;
		case CMP_TYPE_NEGPOLLREP:
			break;
		case CMP_TYPE_PARTIALMSGREP:
			proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_next_poll_ref, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_ttcb, tvb, offset, 4, ENC_TIME_SECS|ENC_BIG_ENDIAN);
			offset += 4;

			next_tvb = tvb_new_subset_length_caplen(tvb, offset, tvb_reported_length_remaining(tvb, offset), pdu_len);
			dissect_cmp_pdu(next_tvb, pinfo, tree, NULL);
			offset += tvb_reported_length_remaining(tvb, offset);
			break;
		case CMP_TYPE_FINALMSGREP:
			next_tvb = tvb_new_subset_length_caplen(tvb, offset, tvb_reported_length_remaining(tvb, offset), pdu_len);
			dissect_cmp_pdu(next_tvb, pinfo, tree, NULL);
			offset += tvb_reported_length_remaining(tvb, offset);
			break;
		case CMP_TYPE_ERRORMSGREP:
			/*XXX to be added*/
			break;
	}

	return offset;
}

static unsigned get_cmp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                             int offset, void *data _U_)
{
	uint32_t plen;

	/*
	 * Get the length of the CMP-over-TCP packet.
	 */
	plen = tvb_get_ntohl(tvb, offset);

	return plen+4;
}


/* CMP over TCP: RFC2510 section 5.2 and "Transport Protocols for CMP" draft */
static int
dissect_cmp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	uint32_t pdu_len;
	uint8_t pdu_type;
	int offset=4; /* RFC2510 TCP transport header length */

	/* only attempt to dissect it as CMP over TCP if we have
	 * at least 5 bytes.
	 */
	if (!tvb_bytes_exist(tvb, 0, 5)) {
		return 0;
	}

	pdu_len=tvb_get_ntohl(tvb, 0);
	pdu_type=tvb_get_uint8(tvb, 4);

	if(pdu_type == 10) {
		/* post RFC2510 TCP transport */
		pdu_type = tvb_get_uint8(tvb, 7);
		offset = 7; /* post RFC2510 TCP transport header length */
		/* arbitrary limit: assume a CMP over TCP pdu is never >10000 bytes
		 * in size.
		 * It is definitely at least 3 byte for post RFC2510 TCP transport
		 */
		if((pdu_len<=2)||(pdu_len>10000)){
			return 0;
		}
	} else {
		/* RFC2510 TCP transport */
		/* type is between 0 and 6 */
		if(pdu_type>6){
			return 0;
		}
		/* arbitrary limit: assume a CMP over TCP pdu is never >10000 bytes
		 * in size.
		 * It is definitely at least 1 byte to accommodate the flags byte
		 */
		if((pdu_len<=0)||(pdu_len>10000)){
			return 0;
		}
	}

	/* type 0 contains a PKI message and must therefore be >= 3 bytes
	 * long (flags + BER TAG + BER LENGTH
	 */
	if((pdu_type==0)&&(pdu_len<3)){
		return 0;
	}

	tcp_dissect_pdus(tvb, pinfo, parent_tree, cmp_desegment, offset, get_cmp_pdu_len,
			dissect_cmp_tcp_pdu, data);

	return tvb_captured_length(tvb);
}


static int
dissect_cmp_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMP");
	col_set_str(pinfo->cinfo, COL_INFO, "PKIXCMP");

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_cmp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_cmp);
	}

	return dissect_cmp_pdu(tvb, pinfo, tree, NULL);
}


/*--- proto_register_cmp ----------------------------------------------*/
void proto_register_cmp(void) {

	/* List of fields */
	static hf_register_info hf[] = {
		{ &hf_cmp_type_oid,
			{ "InfoType", "cmp.type.oid",
				FT_STRING, BASE_NONE, NULL, 0,
				"Type of InfoTypeAndValue", HFILL }},
		{ &hf_cmp_tcptrans_len,
			{ "Length", "cmp.tcptrans.length",
				FT_UINT32, BASE_DEC, NULL, 0,
				"TCP transport Length of PDU in bytes", HFILL }},
		{ &hf_cmp_tcptrans_type,
			{ "Type", "cmp.tcptrans.type",
				FT_UINT8, BASE_DEC, VALS(cmp_pdu_types), 0,
				"TCP transport PDU Type", HFILL }},
		{ &hf_cmp_tcptrans_poll_ref,
			{ "Polling Reference", "cmp.tcptrans.poll_ref",
				FT_UINT32, BASE_HEX, NULL, 0,
				"TCP transport Polling Reference", HFILL }},
		{ &hf_cmp_tcptrans_next_poll_ref,
			{ "Next Polling Reference", "cmp.tcptrans.next_poll_ref",
				FT_UINT32, BASE_HEX, NULL, 0,
				"TCP transport Next Polling Reference", HFILL }},
		{ &hf_cmp_tcptrans_ttcb,
			{ "Time to check Back", "cmp.tcptrans.ttcb",
				FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
				"TCP transport Time to check Back", HFILL }},
		{ &hf_cmp_tcptrans10_version,
			{ "Version", "cmp.tcptrans10.version",
				FT_UINT8, BASE_DEC, NULL, 0,
				"TCP transport version", HFILL }},
		{ &hf_cmp_tcptrans10_flags,
			{ "Flags", "cmp.tcptrans10.flags",
				FT_UINT8, BASE_DEC, NULL, 0,
				"TCP transport flags", HFILL }},
    { &hf_cmp_PBMParameter_PDU,
      { "PBMParameter", "cmp.PBMParameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_DHBMParameter_PDU,
      { "DHBMParameter", "cmp.DHBMParameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_CAProtEncCertValue_PDU,
      { "CAProtEncCertValue", "cmp.CAProtEncCertValue",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        NULL, HFILL }},
    { &hf_cmp_SignKeyPairTypesValue_PDU,
      { "SignKeyPairTypesValue", "cmp.SignKeyPairTypesValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_EncKeyPairTypesValue_PDU,
      { "EncKeyPairTypesValue", "cmp.EncKeyPairTypesValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_PreferredSymmAlgValue_PDU,
      { "PreferredSymmAlgValue", "cmp.PreferredSymmAlgValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_CAKeyUpdateInfoValue_PDU,
      { "CAKeyUpdateInfoValue", "cmp.CAKeyUpdateInfoValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_CurrentCRLValue_PDU,
      { "CurrentCRLValue", "cmp.CurrentCRLValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_UnsupportedOIDsValue_PDU,
      { "UnsupportedOIDsValue", "cmp.UnsupportedOIDsValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_KeyPairParamReqValue_PDU,
      { "KeyPairParamReqValue", "cmp.KeyPairParamReqValue",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_KeyPairParamRepValue_PDU,
      { "KeyPairParamRepValue", "cmp.KeyPairParamRepValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_RevPassphraseValue_PDU,
      { "RevPassphraseValue", "cmp.RevPassphraseValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_ImplicitConfirmValue_PDU,
      { "ImplicitConfirmValue", "cmp.ImplicitConfirmValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_ConfirmWaitTimeValue_PDU,
      { "ConfirmWaitTimeValue", "cmp.ConfirmWaitTimeValue",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_OrigPKIMessageValue_PDU,
      { "OrigPKIMessageValue", "cmp.OrigPKIMessageValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_SuppLangTagsValue_PDU,
      { "SuppLangTagsValue", "cmp.SuppLangTagsValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_x509v3PKCert,
      { "x509v3PKCert", "cmp.x509v3PKCert_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Certificate", HFILL }},
    { &hf_cmp_header,
      { "header", "cmp.header_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIHeader", HFILL }},
    { &hf_cmp_body,
      { "body", "cmp.body",
        FT_UINT32, BASE_DEC, VALS(cmp_PKIBody_vals), 0,
        "PKIBody", HFILL }},
    { &hf_cmp_protection,
      { "protection", "cmp.protection",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PKIProtection", HFILL }},
    { &hf_cmp_extraCerts,
      { "extraCerts", "cmp.extraCerts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_CMPCertificate", HFILL }},
    { &hf_cmp_extraCerts_item,
      { "CMPCertificate", "cmp.CMPCertificate",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        NULL, HFILL }},
    { &hf_cmp_PKIMessages_item,
      { "PKIMessage", "cmp.PKIMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_pvno,
      { "pvno", "cmp.pvno",
        FT_INT32, BASE_DEC, VALS(cmp_T_pvno_vals), 0,
        NULL, HFILL }},
    { &hf_cmp_sender,
      { "sender", "cmp.sender",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralName", HFILL }},
    { &hf_cmp_recipient,
      { "recipient", "cmp.recipient",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralName", HFILL }},
    { &hf_cmp_messageTime,
      { "messageTime", "cmp.messageTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_cmp_protectionAlg,
      { "protectionAlg", "cmp.protectionAlg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_cmp_senderKID,
      { "senderKID", "cmp.senderKID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "KeyIdentifier", HFILL }},
    { &hf_cmp_recipKID,
      { "recipKID", "cmp.recipKID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "KeyIdentifier", HFILL }},
    { &hf_cmp_transactionID,
      { "transactionID", "cmp.transactionID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cmp_senderNonce,
      { "senderNonce", "cmp.senderNonce",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cmp_recipNonce,
      { "recipNonce", "cmp.recipNonce",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cmp_freeText,
      { "freeText", "cmp.freeText",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIFreeText", HFILL }},
    { &hf_cmp_generalInfo,
      { "generalInfo", "cmp.generalInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue", HFILL }},
    { &hf_cmp_generalInfo_item,
      { "InfoTypeAndValue", "cmp.InfoTypeAndValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_PKIFreeText_item,
      { "PKIFreeText item", "cmp.PKIFreeText_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_cmp_ir,
      { "ir", "cmp.ir",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertReqMessages", HFILL }},
    { &hf_cmp_ip,
      { "ip", "cmp.ip_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertRepMessage", HFILL }},
    { &hf_cmp_cr,
      { "cr", "cmp.cr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertReqMessages", HFILL }},
    { &hf_cmp_cp,
      { "cp", "cmp.cp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertRepMessage", HFILL }},
    { &hf_cmp_p10cr,
      { "p10cr", "cmp.p10cr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificationRequest", HFILL }},
    { &hf_cmp_popdecc,
      { "popdecc", "cmp.popdecc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "POPODecKeyChallContent", HFILL }},
    { &hf_cmp_popdecr,
      { "popdecr", "cmp.popdecr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "POPODecKeyRespContent", HFILL }},
    { &hf_cmp_kur,
      { "kur", "cmp.kur",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertReqMessages", HFILL }},
    { &hf_cmp_kup,
      { "kup", "cmp.kup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertRepMessage", HFILL }},
    { &hf_cmp_krr,
      { "krr", "cmp.krr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertReqMessages", HFILL }},
    { &hf_cmp_krp,
      { "krp", "cmp.krp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "KeyRecRepContent", HFILL }},
    { &hf_cmp_rr,
      { "rr", "cmp.rr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RevReqContent", HFILL }},
    { &hf_cmp_rp,
      { "rp", "cmp.rp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RevRepContent", HFILL }},
    { &hf_cmp_ccr,
      { "ccr", "cmp.ccr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertReqMessages", HFILL }},
    { &hf_cmp_ccp,
      { "ccp", "cmp.ccp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertRepMessage", HFILL }},
    { &hf_cmp_ckuann,
      { "ckuann", "cmp.ckuann_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CAKeyUpdAnnContent", HFILL }},
    { &hf_cmp_cann,
      { "cann", "cmp.cann",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "CertAnnContent", HFILL }},
    { &hf_cmp_rann,
      { "rann", "cmp.rann_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RevAnnContent", HFILL }},
    { &hf_cmp_crlann,
      { "crlann", "cmp.crlann",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CRLAnnContent", HFILL }},
    { &hf_cmp_pkiconf,
      { "pkiconf", "cmp.pkiconf_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIConfirmContent", HFILL }},
    { &hf_cmp_nested,
      { "nested", "cmp.nested",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NestedMessageContent", HFILL }},
    { &hf_cmp_genm,
      { "genm", "cmp.genm",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GenMsgContent", HFILL }},
    { &hf_cmp_genp,
      { "genp", "cmp.genp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GenRepContent", HFILL }},
    { &hf_cmp_error,
      { "error", "cmp.error_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ErrorMsgContent", HFILL }},
    { &hf_cmp_certConf,
      { "certConf", "cmp.certConf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertConfirmContent", HFILL }},
    { &hf_cmp_pollReq,
      { "pollReq", "cmp.pollReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PollReqContent", HFILL }},
    { &hf_cmp_pollRep,
      { "pollRep", "cmp.pollRep",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PollRepContent", HFILL }},
    { &hf_cmp_salt,
      { "salt", "cmp.salt",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cmp_owf,
      { "owf", "cmp.owf_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_cmp_iterationCount,
      { "iterationCount", "cmp.iterationCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmp_mac,
      { "mac", "cmp.mac_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_cmp_pkistatus,
      { "status", "cmp.pkistatus",
        FT_INT32, BASE_DEC, VALS(cmp_PKIStatus_vals), 0,
        "PKIStatus", HFILL }},
    { &hf_cmp_statusString,
      { "statusString", "cmp.statusString",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIFreeText", HFILL }},
    { &hf_cmp_failInfo,
      { "failInfo", "cmp.failInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PKIFailureInfo", HFILL }},
    { &hf_cmp_hashAlg,
      { "hashAlg", "cmp.hashAlg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_cmp_certId,
      { "certId", "cmp.certId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_hashVal,
      { "hashVal", "cmp.hashVal",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_cmp_POPODecKeyChallContent_item,
      { "Challenge", "cmp.Challenge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_witness,
      { "witness", "cmp.witness",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cmp_challenge,
      { "challenge", "cmp.challenge",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cmp_POPODecKeyRespContent_item,
      { "POPODecKeyRespContent item", "cmp.POPODecKeyRespContent_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmp_caPubs,
      { "caPubs", "cmp.caPubs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_CMPCertificate", HFILL }},
    { &hf_cmp_caPubs_item,
      { "CMPCertificate", "cmp.CMPCertificate",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        NULL, HFILL }},
    { &hf_cmp_response,
      { "response", "cmp.response",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CertResponse", HFILL }},
    { &hf_cmp_response_item,
      { "CertResponse", "cmp.CertResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_certReqId,
      { "certReqId", "cmp.certReqId",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmp_pkistatusinf,
      { "status", "cmp.status_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIStatusInfo", HFILL }},
    { &hf_cmp_certifiedKeyPair,
      { "certifiedKeyPair", "cmp.certifiedKeyPair_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_rspInfo,
      { "rspInfo", "cmp.rspInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cmp_certOrEncCert,
      { "certOrEncCert", "cmp.certOrEncCert",
        FT_UINT32, BASE_DEC, VALS(cmp_CertOrEncCert_vals), 0,
        NULL, HFILL }},
    { &hf_cmp_privateKey,
      { "privateKey", "cmp.privateKey_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedValue", HFILL }},
    { &hf_cmp_publicationInfo,
      { "publicationInfo", "cmp.publicationInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIPublicationInfo", HFILL }},
    { &hf_cmp_certificate,
      { "certificate", "cmp.certificate",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "CMPCertificate", HFILL }},
    { &hf_cmp_encryptedCert,
      { "encryptedCert", "cmp.encryptedCert_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedValue", HFILL }},
    { &hf_cmp_newSigCert,
      { "newSigCert", "cmp.newSigCert",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "CMPCertificate", HFILL }},
    { &hf_cmp_caCerts,
      { "caCerts", "cmp.caCerts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_CMPCertificate", HFILL }},
    { &hf_cmp_caCerts_item,
      { "CMPCertificate", "cmp.CMPCertificate",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        NULL, HFILL }},
    { &hf_cmp_keyPairHist,
      { "keyPairHist", "cmp.keyPairHist",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair", HFILL }},
    { &hf_cmp_keyPairHist_item,
      { "CertifiedKeyPair", "cmp.CertifiedKeyPair_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_RevReqContent_item,
      { "RevDetails", "cmp.RevDetails_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_certDetails,
      { "certDetails", "cmp.certDetails_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertTemplate", HFILL }},
    { &hf_cmp_crlEntryDetails,
      { "crlEntryDetails", "cmp.crlEntryDetails",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Extensions", HFILL }},
    { &hf_cmp_rvrpcnt_status,
      { "status", "cmp.rvrpcnt_status",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo", HFILL }},
    { &hf_cmp_rvrpcnt_status_item,
      { "PKIStatusInfo", "cmp.PKIStatusInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_revCerts,
      { "revCerts", "cmp.revCerts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_CertId", HFILL }},
    { &hf_cmp_revCerts_item,
      { "CertId", "cmp.CertId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_crls,
      { "crls", "cmp.crls",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_CertificateList", HFILL }},
    { &hf_cmp_crls_item,
      { "CertificateList", "cmp.CertificateList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_oldWithNew,
      { "oldWithNew", "cmp.oldWithNew",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "CMPCertificate", HFILL }},
    { &hf_cmp_newWithOld,
      { "newWithOld", "cmp.newWithOld",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "CMPCertificate", HFILL }},
    { &hf_cmp_newWithNew,
      { "newWithNew", "cmp.newWithNew",
        FT_UINT32, BASE_DEC, VALS(cmp_CMPCertificate_vals), 0,
        "CMPCertificate", HFILL }},
    { &hf_cmp_pkistatus_01,
      { "status", "cmp.status",
        FT_INT32, BASE_DEC, VALS(cmp_PKIStatus_vals), 0,
        "PKIStatus", HFILL }},
    { &hf_cmp_willBeRevokedAt,
      { "willBeRevokedAt", "cmp.willBeRevokedAt",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_cmp_badSinceDate,
      { "badSinceDate", "cmp.badSinceDate",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_cmp_crlDetails,
      { "crlDetails", "cmp.crlDetails",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Extensions", HFILL }},
    { &hf_cmp_CRLAnnContent_item,
      { "CertificateList", "cmp.CertificateList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_CertConfirmContent_item,
      { "CertStatus", "cmp.CertStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_certHash,
      { "certHash", "cmp.certHash",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cmp_statusInfo,
      { "statusInfo", "cmp.statusInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIStatusInfo", HFILL }},
    { &hf_cmp_infoType,
      { "infoType", "cmp.infoType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_infoValue,
      { "infoValue", "cmp.infoValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_SignKeyPairTypesValue_item,
      { "AlgorithmIdentifier", "cmp.AlgorithmIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_EncKeyPairTypesValue_item,
      { "AlgorithmIdentifier", "cmp.AlgorithmIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_UnsupportedOIDsValue_item,
      { "UnsupportedOIDsValue item", "cmp.UnsupportedOIDsValue_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_cmp_SuppLangTagsValue_item,
      { "SuppLangTagsValue item", "cmp.SuppLangTagsValue_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_cmp_GenMsgContent_item,
      { "InfoTypeAndValue", "cmp.InfoTypeAndValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_GenRepContent_item,
      { "InfoTypeAndValue", "cmp.InfoTypeAndValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_pKIStatusInfo,
      { "pKIStatusInfo", "cmp.pKIStatusInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_errorCode,
      { "errorCode", "cmp.errorCode",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmp_errorDetails,
      { "errorDetails", "cmp.errorDetails",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIFreeText", HFILL }},
    { &hf_cmp_PollReqContent_item,
      { "PollReqContent item", "cmp.PollReqContent_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_PollRepContent_item,
      { "PollRepContent item", "cmp.PollRepContent_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmp_checkAfter,
      { "checkAfter", "cmp.checkAfter",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmp_reason,
      { "reason", "cmp.reason",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIFreeText", HFILL }},
    { &hf_cmp_PKIFailureInfo_badAlg,
      { "badAlg", "cmp.PKIFailureInfo.badAlg",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badMessageCheck,
      { "badMessageCheck", "cmp.PKIFailureInfo.badMessageCheck",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badRequest,
      { "badRequest", "cmp.PKIFailureInfo.badRequest",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badTime,
      { "badTime", "cmp.PKIFailureInfo.badTime",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badCertId,
      { "badCertId", "cmp.PKIFailureInfo.badCertId",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badDataFormat,
      { "badDataFormat", "cmp.PKIFailureInfo.badDataFormat",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_wrongAuthority,
      { "wrongAuthority", "cmp.PKIFailureInfo.wrongAuthority",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_incorrectData,
      { "incorrectData", "cmp.PKIFailureInfo.incorrectData",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_missingTimeStamp,
      { "missingTimeStamp", "cmp.PKIFailureInfo.missingTimeStamp",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badPOP,
      { "badPOP", "cmp.PKIFailureInfo.badPOP",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_certRevoked,
      { "certRevoked", "cmp.PKIFailureInfo.certRevoked",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_certConfirmed,
      { "certConfirmed", "cmp.PKIFailureInfo.certConfirmed",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_wrongIntegrity,
      { "wrongIntegrity", "cmp.PKIFailureInfo.wrongIntegrity",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badRecipientNonce,
      { "badRecipientNonce", "cmp.PKIFailureInfo.badRecipientNonce",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_timeNotAvailable,
      { "timeNotAvailable", "cmp.PKIFailureInfo.timeNotAvailable",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_unacceptedPolicy,
      { "unacceptedPolicy", "cmp.PKIFailureInfo.unacceptedPolicy",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_unacceptedExtension,
      { "unacceptedExtension", "cmp.PKIFailureInfo.unacceptedExtension",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_addInfoNotAvailable,
      { "addInfoNotAvailable", "cmp.PKIFailureInfo.addInfoNotAvailable",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badSenderNonce,
      { "badSenderNonce", "cmp.PKIFailureInfo.badSenderNonce",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_badCertTemplate,
      { "badCertTemplate", "cmp.PKIFailureInfo.badCertTemplate",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_signerNotTrusted,
      { "signerNotTrusted", "cmp.PKIFailureInfo.signerNotTrusted",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_transactionIdInUse,
      { "transactionIdInUse", "cmp.PKIFailureInfo.transactionIdInUse",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_unsupportedVersion,
      { "unsupportedVersion", "cmp.PKIFailureInfo.unsupportedVersion",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_notAuthorized,
      { "notAuthorized", "cmp.PKIFailureInfo.notAuthorized",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_systemUnavail,
      { "systemUnavail", "cmp.PKIFailureInfo.systemUnavail",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_systemFailure,
      { "systemFailure", "cmp.PKIFailureInfo.systemFailure",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cmp_PKIFailureInfo_duplicateCertReq,
      { "duplicateCertReq", "cmp.PKIFailureInfo.duplicateCertReq",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
	};

	/* List of subtrees */
	static int *ett[] = {
		&ett_cmp,
    &ett_cmp_CMPCertificate,
    &ett_cmp_PKIMessage,
    &ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CMPCertificate,
    &ett_cmp_PKIMessages,
    &ett_cmp_PKIHeader,
    &ett_cmp_SEQUENCE_SIZE_1_MAX_OF_InfoTypeAndValue,
    &ett_cmp_PKIFreeText,
    &ett_cmp_PKIBody,
    &ett_cmp_ProtectedPart,
    &ett_cmp_PBMParameter,
    &ett_cmp_DHBMParameter,
    &ett_cmp_PKIFailureInfo,
    &ett_cmp_PKIStatusInfo,
    &ett_cmp_OOBCertHash,
    &ett_cmp_POPODecKeyChallContent,
    &ett_cmp_Challenge,
    &ett_cmp_POPODecKeyRespContent,
    &ett_cmp_CertRepMessage,
    &ett_cmp_SEQUENCE_OF_CertResponse,
    &ett_cmp_CertResponse,
    &ett_cmp_CertifiedKeyPair,
    &ett_cmp_CertOrEncCert,
    &ett_cmp_KeyRecRepContent,
    &ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertifiedKeyPair,
    &ett_cmp_RevReqContent,
    &ett_cmp_RevDetails,
    &ett_cmp_RevRepContent,
    &ett_cmp_SEQUENCE_SIZE_1_MAX_OF_PKIStatusInfo,
    &ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertId,
    &ett_cmp_SEQUENCE_SIZE_1_MAX_OF_CertificateList,
    &ett_cmp_CAKeyUpdAnnContent,
    &ett_cmp_RevAnnContent,
    &ett_cmp_CRLAnnContent,
    &ett_cmp_CertConfirmContent,
    &ett_cmp_CertStatus,
    &ett_cmp_InfoTypeAndValue,
    &ett_cmp_SignKeyPairTypesValue,
    &ett_cmp_EncKeyPairTypesValue,
    &ett_cmp_UnsupportedOIDsValue,
    &ett_cmp_SuppLangTagsValue,
    &ett_cmp_GenMsgContent,
    &ett_cmp_GenRepContent,
    &ett_cmp_ErrorMsgContent,
    &ett_cmp_PollReqContent,
    &ett_cmp_PollReqContent_item,
    &ett_cmp_PollRepContent,
    &ett_cmp_PollRepContent_item,
	};
	module_t *cmp_module;

	/* Register protocol */
	proto_cmp = proto_register_protocol(PNAME, PSNAME, PFNAME);

	/* Register fields and subtrees */
	proto_register_field_array(proto_cmp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register preferences */
	cmp_module = prefs_register_protocol(proto_cmp, proto_reg_handoff_cmp);
	prefs_register_bool_preference(cmp_module, "desegment",
			"Reassemble CMP-over-TCP messages spanning multiple TCP segments",
			"Whether the CMP-over-TCP dissector should reassemble messages spanning multiple TCP segments. "
			"To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
			&cmp_desegment);

	prefs_register_uint_preference(cmp_module, "http_alternate_port",
			"Alternate HTTP port",
			"Decode this TCP port\'s traffic as CMP-over-HTTP. Set to \"0\" to disable. "
			"Use this if the Content-Type is not set correctly.",
			10,
			&cmp_alternate_http_port);

	prefs_register_uint_preference(cmp_module, "tcp_style_http_alternate_port",
			"Alternate TCP-style-HTTP port",
			"Decode this TCP port\'s traffic as TCP-transport-style CMP-over-HTTP. Set to \"0\" to disable. "
			"Use this if the Content-Type is not set correctly.",
			10,
			&cmp_alternate_tcp_style_http_port);

	/* Register dissectors */
	cmp_http_handle = register_dissector("cmp.http", dissect_cmp_http, proto_cmp);
	cmp_tcp_style_http_handle = register_dissector("cmp.tcp_pdu", dissect_cmp_tcp_pdu, proto_cmp);
	cmp_tcp_handle = register_dissector("cmp", dissect_cmp_tcp, proto_cmp);
	register_ber_syntax_dissector("PKIMessage", proto_cmp, dissect_cmp_pdu);
}


/*--- proto_reg_handoff_cmp -------------------------------------------*/
void proto_reg_handoff_cmp(void) {
	static bool inited = false;
	static unsigned cmp_alternate_http_port_prev = 0;
	static unsigned cmp_alternate_tcp_style_http_port_prev = 0;

	if (!inited) {
		dissector_add_string("media_type", "application/pkixcmp", cmp_http_handle);
		dissector_add_string("media_type", "application/x-pkixcmp", cmp_http_handle);

		dissector_add_string("media_type", "application/pkixcmp-poll", cmp_tcp_style_http_handle);
		dissector_add_string("media_type", "application/x-pkixcmp-poll", cmp_tcp_style_http_handle);

		dissector_add_uint_with_preference("tcp.port", TCP_PORT_CMP, cmp_tcp_handle);

		oid_add_from_string("Cryptlib-presence-check","1.3.6.1.4.1.3029.3.1.1");
		oid_add_from_string("Cryptlib-PKIBoot","1.3.6.1.4.1.3029.3.1.2");

		oid_add_from_string("HMAC MD5","1.3.6.1.5.5.8.1.1");
		oid_add_from_string("HMAC SHA-1","1.3.6.1.5.5.8.1.2");
		oid_add_from_string("HMAC TIGER","1.3.6.1.5.5.8.1.3");
		oid_add_from_string("HMAC RIPEMD-160","1.3.6.1.5.5.8.1.4");

  register_ber_oid_dissector("1.2.840.113533.7.66.13", dissect_PBMParameter_PDU, proto_cmp, "id-PasswordBasedMac");
  register_ber_oid_dissector("1.2.640.113533.7.66.30", dissect_DHBMParameter_PDU, proto_cmp, "id-DHBasedMac");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.1", dissect_CAProtEncCertValue_PDU, proto_cmp, "id-it-caProtEncCert");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.2", dissect_SignKeyPairTypesValue_PDU, proto_cmp, "id-it-signKeyPairTypes");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.3", dissect_EncKeyPairTypesValue_PDU, proto_cmp, "id-it-encKeyPairTypes");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.4", dissect_PreferredSymmAlgValue_PDU, proto_cmp, "id-it-preferredSymmAlg");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.5", dissect_CAKeyUpdateInfoValue_PDU, proto_cmp, "id-it-caKeyUpdateInfo");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.6", dissect_CurrentCRLValue_PDU, proto_cmp, "id-it-currentCRL");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.7", dissect_UnsupportedOIDsValue_PDU, proto_cmp, "id-it-unsupportedOIDs");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.10", dissect_KeyPairParamReqValue_PDU, proto_cmp, "id-it-keyPairParamReq");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.11", dissect_KeyPairParamRepValue_PDU, proto_cmp, "id-it-keyPairParamRep");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.12", dissect_RevPassphraseValue_PDU, proto_cmp, "id-it-revPassphrase");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.13", dissect_ImplicitConfirmValue_PDU, proto_cmp, "id-it-implicitConfirm");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.14", dissect_ConfirmWaitTimeValue_PDU, proto_cmp, "id-it-confirmWaitTime");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.15", dissect_OrigPKIMessageValue_PDU, proto_cmp, "id-it-origPKIMessage");
  register_ber_oid_dissector("1.3.6.1.5.5.7.4.16", dissect_SuppLangTagsValue_PDU, proto_cmp, "id-it-suppLangTags");

		inited = true;
	}

	/* change alternate HTTP port if changed in the preferences */
	if (cmp_alternate_http_port != cmp_alternate_http_port_prev) {
		if (cmp_alternate_http_port_prev != 0) {
			http_tcp_dissector_delete(cmp_alternate_http_port_prev);
		}
		if (cmp_alternate_http_port != 0)
			http_tcp_dissector_add( cmp_alternate_http_port, cmp_http_handle);
		cmp_alternate_http_port_prev = cmp_alternate_http_port;
	}

	/* change alternate TCP-style-HTTP port if changed in the preferences */
	if (cmp_alternate_tcp_style_http_port != cmp_alternate_tcp_style_http_port_prev) {
		if (cmp_alternate_tcp_style_http_port_prev != 0) {
			http_tcp_dissector_delete(cmp_alternate_tcp_style_http_port_prev);
		}
		if (cmp_alternate_tcp_style_http_port != 0)
			http_tcp_dissector_add( cmp_alternate_tcp_style_http_port, cmp_tcp_style_http_handle);
		cmp_alternate_tcp_style_http_port_prev = cmp_alternate_tcp_style_http_port;
	}

}


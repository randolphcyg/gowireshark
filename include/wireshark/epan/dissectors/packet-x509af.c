/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-x509af.c                                                            */
/* asn2wrs.py -b -q -L -p x509af -c ./x509af.cnf -s ./packet-x509af-template -D . -O ../.. AuthenticationFramework.asn */

/* packet-x509af.c
 * Routines for X.509 Authentication Framework packet dissection
 *  Ronnie Sahlberg 2004
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
#include <epan/strutil.h>
#include <wsutil/array.h>

#include "packet-ber.h"
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"
#include "packet-ldap.h"
#include "packet-pkcs1.h"
#if defined(HAVE_LIBGNUTLS)
#include <gnutls/gnutls.h>
#endif

#define PNAME  "X.509 Authentication Framework"
#define PSNAME "X509AF"
#define PFNAME "x509af"

void proto_register_x509af(void);
void proto_reg_handoff_x509af(void);

static dissector_handle_t pkix_crl_handle;

/* Initialize the protocol and registered fields */
static int proto_x509af;
static int hf_x509af_algorithm_id;
static int hf_x509af_extension_id;
static int hf_x509af_x509af_Certificate_PDU;      /* Certificate */
static int hf_x509af_SubjectPublicKeyInfo_PDU;    /* SubjectPublicKeyInfo */
static int hf_x509af_CertificatePair_PDU;         /* CertificatePair */
static int hf_x509af_CertificateList_PDU;         /* CertificateList */
static int hf_x509af_AttributeCertificate_PDU;    /* AttributeCertificate */
static int hf_x509af_DSS_Params_PDU;              /* DSS_Params */
static int hf_x509af_Userid_PDU;                  /* Userid */
static int hf_x509af_signedCertificate;           /* T_signedCertificate */
static int hf_x509af_version;                     /* Version */
static int hf_x509af_serialNumber;                /* CertificateSerialNumber */
static int hf_x509af_signature;                   /* AlgorithmIdentifier */
static int hf_x509af_issuer;                      /* Name */
static int hf_x509af_validity;                    /* Validity */
static int hf_x509af_subject;                     /* SubjectName */
static int hf_x509af_subjectPublicKeyInfo;        /* SubjectPublicKeyInfo */
static int hf_x509af_issuerUniqueIdentifier;      /* UniqueIdentifier */
static int hf_x509af_subjectUniqueIdentifier;     /* UniqueIdentifier */
static int hf_x509af_extensions;                  /* Extensions */
static int hf_x509af_algorithmIdentifier;         /* AlgorithmIdentifier */
static int hf_x509af_encrypted;                   /* BIT_STRING */
static int hf_x509af_rdnSequence;                 /* RDNSequence */
static int hf_x509af_algorithmId;                 /* T_algorithmId */
static int hf_x509af_parameters;                  /* T_parameters */
static int hf_x509af_notBefore;                   /* Time */
static int hf_x509af_notAfter;                    /* Time */
static int hf_x509af_algorithm;                   /* AlgorithmIdentifier */
static int hf_x509af_subjectPublicKey;            /* T_subjectPublicKey */
static int hf_x509af_utcTime;                     /* T_utcTime */
static int hf_x509af_generalizedTime;             /* GeneralizedTime */
static int hf_x509af_Extensions_item;             /* Extension */
static int hf_x509af_extnId;                      /* T_extnId */
static int hf_x509af_critical;                    /* BOOLEAN */
static int hf_x509af_extnValue;                   /* T_extnValue */
static int hf_x509af_userCertificate;             /* Certificate */
static int hf_x509af_certificationPath;           /* ForwardCertificationPath */
static int hf_x509af_ForwardCertificationPath_item;  /* CrossCertificates */
static int hf_x509af_CrossCertificates_item;      /* Certificate */
static int hf_x509af_theCACertificates;           /* SEQUENCE_OF_CertificatePair */
static int hf_x509af_theCACertificates_item;      /* CertificatePair */
static int hf_x509af_issuedByThisCA;              /* Certificate */
static int hf_x509af_issuedToThisCA;              /* Certificate */
static int hf_x509af_signedCertificateList;       /* T_signedCertificateList */
static int hf_x509af_thisUpdate;                  /* Time */
static int hf_x509af_nextUpdate;                  /* Time */
static int hf_x509af_revokedCertificates;         /* T_revokedCertificates */
static int hf_x509af_revokedCertificates_item;    /* T_revokedCertificates_item */
static int hf_x509af_revokedUserCertificate;      /* CertificateSerialNumber */
static int hf_x509af_revocationDate;              /* Time */
static int hf_x509af_crlEntryExtensions;          /* Extensions */
static int hf_x509af_crlExtensions;               /* Extensions */
static int hf_x509af_attributeCertificate;        /* AttributeCertificate */
static int hf_x509af_acPath;                      /* SEQUENCE_OF_ACPathData */
static int hf_x509af_acPath_item;                 /* ACPathData */
static int hf_x509af_certificate;                 /* Certificate */
static int hf_x509af_signedAttributeCertificateInfo;  /* AttributeCertificateInfo */
static int hf_x509af_info_subject;                /* InfoSubject */
static int hf_x509af_baseCertificateID;           /* IssuerSerial */
static int hf_x509af_infoSubjectName;             /* GeneralNames */
static int hf_x509af_issuerName;                  /* GeneralNames */
static int hf_x509af_attCertValidityPeriod;       /* AttCertValidityPeriod */
static int hf_x509af_attributes;                  /* SEQUENCE_OF_Attribute */
static int hf_x509af_attributes_item;             /* Attribute */
static int hf_x509af_issuerUniqueID;              /* UniqueIdentifier */
static int hf_x509af_serial;                      /* CertificateSerialNumber */
static int hf_x509af_issuerUID;                   /* UniqueIdentifier */
static int hf_x509af_notBeforeTime;               /* GeneralizedTime */
static int hf_x509af_notAfterTime;                /* GeneralizedTime */
static int hf_x509af_assertion_subject;           /* AssertionSubject */
static int hf_x509af_assertionSubjectName;        /* SubjectName */
static int hf_x509af_assertionIssuer;             /* Name */
static int hf_x509af_attCertValidity;             /* GeneralizedTime */
static int hf_x509af_attType;                     /* SET_OF_AttributeType */
static int hf_x509af_attType_item;                /* AttributeType */
static int hf_x509af_p;                           /* INTEGER */
static int hf_x509af_q;                           /* INTEGER */
static int hf_x509af_g;                           /* INTEGER */

/* Initialize the subtree pointers */
static int ett_pkix_crl;
static int ett_x509af_Certificate;
static int ett_x509af_T_signedCertificate;
static int ett_x509af_SubjectName;
static int ett_x509af_AlgorithmIdentifier;
static int ett_x509af_Validity;
static int ett_x509af_SubjectPublicKeyInfo;
static int ett_x509af_Time;
static int ett_x509af_Extensions;
static int ett_x509af_Extension;
static int ett_x509af_Certificates;
static int ett_x509af_ForwardCertificationPath;
static int ett_x509af_CrossCertificates;
static int ett_x509af_CertificationPath;
static int ett_x509af_SEQUENCE_OF_CertificatePair;
static int ett_x509af_CertificatePair;
static int ett_x509af_CertificateList;
static int ett_x509af_T_signedCertificateList;
static int ett_x509af_T_revokedCertificates;
static int ett_x509af_T_revokedCertificates_item;
static int ett_x509af_AttributeCertificationPath;
static int ett_x509af_SEQUENCE_OF_ACPathData;
static int ett_x509af_ACPathData;
static int ett_x509af_AttributeCertificate;
static int ett_x509af_AttributeCertificateInfo;
static int ett_x509af_InfoSubject;
static int ett_x509af_SEQUENCE_OF_Attribute;
static int ett_x509af_IssuerSerial;
static int ett_x509af_AttCertValidityPeriod;
static int ett_x509af_AttributeCertificateAssertion;
static int ett_x509af_AssertionSubject;
static int ett_x509af_SET_OF_AttributeType;
static int ett_x509af_DSS_Params;
static const char *algorithm_id;
static void
x509af_export_publickey(tvbuff_t *tvb, asn1_ctx_t *actx, int offset, int len);

const value_string x509af_Version_vals[] = {
  {   0, "v1" },
  {   1, "v2" },
  {   2, "v3" },
  { 0, NULL }
};


int
dissect_x509af_Version(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



int
dissect_x509af_CertificateSerialNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_x509af_T_algorithmId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  const char *name;

    offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509af_algorithm_id, &actx->external.direct_reference);


  if (algorithm_id) {
    wmem_free(wmem_file_scope(), (void*)algorithm_id);
  }

  if(actx->external.direct_reference) {
    algorithm_id = (const char *)wmem_strdup(wmem_file_scope(), actx->external.direct_reference);

    name = oid_resolved_from_string(actx->pinfo->pool, actx->external.direct_reference);

    proto_item_append_text(tree, " (%s)", name ? name : actx->external.direct_reference);
  } else {
    algorithm_id = NULL;
  }


  return offset;
}



static int
dissect_x509af_T_parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t AlgorithmIdentifier_sequence[] = {
  { &hf_x509af_algorithmId  , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509af_T_algorithmId },
  { &hf_x509af_parameters   , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509af_T_parameters },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509af_AlgorithmIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AlgorithmIdentifier_sequence, hf_index, ett_x509af_AlgorithmIdentifier);

  return offset;
}



static int
dissect_x509af_T_utcTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  char *outstr, *newstr;
  uint32_t tvblen;

  /* the 2-digit year can only be in the range 1950..2049 https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1 */
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index, &outstr, &tvblen);
  if (hf_index > 0 && outstr) {
    newstr = wmem_strconcat(actx->pinfo->pool, outstr[0] < '5' ? "20": "19", outstr, NULL);
    proto_tree_add_string(tree, hf_index, tvb, offset - tvblen, tvblen, newstr);
  }


  return offset;
}



static int
dissect_x509af_GeneralizedTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


const value_string x509af_Time_vals[] = {
  {   0, "utcTime" },
  {   1, "generalizedTime" },
  { 0, NULL }
};

static const ber_choice_t Time_choice[] = {
  {   0, &hf_x509af_utcTime      , BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_x509af_T_utcTime },
  {   1, &hf_x509af_generalizedTime, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_x509af_GeneralizedTime },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_x509af_Time(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Time_choice, hf_index, ett_x509af_Time,
                                 NULL);

  return offset;
}


static const ber_sequence_t Validity_sequence[] = {
  { &hf_x509af_notBefore    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509af_Time },
  { &hf_x509af_notAfter     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509af_Time },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509af_Validity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Validity_sequence, hf_index, ett_x509af_Validity);

  return offset;
}


static const value_string x509af_SubjectName_vals[] = {
  {   0, "rdnSequence" },
  { 0, NULL }
};

static const ber_choice_t SubjectName_choice[] = {
  {   0, &hf_x509af_rdnSequence  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_RDNSequence },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x509af_SubjectName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  const char* str;
    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SubjectName_choice, hf_index, ett_x509af_SubjectName,
                                 NULL);


  str = x509if_get_last_dn();
  proto_item_append_text(proto_item_get_parent(tree), " (%s)", str?str:"");


  return offset;
}



static int
dissect_x509af_T_subjectPublicKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *bs_tvb = NULL;

  dissect_ber_bitstring(false, actx, NULL, tvb, offset,
                        NULL, 0, hf_index, -1, &bs_tvb);

  /* See RFC 3279 for possible subjectPublicKey values given an Algorithm ID.
   * The contents of subjectPublicKey are always explicitly tagged. */
  if (bs_tvb && !g_strcmp0(algorithm_id, "1.2.840.113549.1.1.1")) { /* id-rsa */
    offset += dissect_pkcs1_RSAPublicKey(false, bs_tvb, 0, actx, tree, hf_index);

  } else {
    offset = dissect_ber_bitstring(false, actx, tree, tvb, offset,
                                   NULL, 0, hf_index, -1, NULL);
  }


  return offset;
}


static const ber_sequence_t SubjectPublicKeyInfo_sequence[] = {
  { &hf_x509af_algorithm    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_x509af_subjectPublicKey, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_x509af_T_subjectPublicKey },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509af_SubjectPublicKeyInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int orig_offset = offset;
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SubjectPublicKeyInfo_sequence, hf_index, ett_x509af_SubjectPublicKeyInfo);

  x509af_export_publickey(tvb, actx, orig_offset, offset - orig_offset);
  return offset;
}



static int
dissect_x509af_T_extnId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  const char *name;

    offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509af_extension_id, &actx->external.direct_reference);


  if(actx->external.direct_reference) {
    name = oid_resolved_from_string(actx->pinfo->pool, actx->external.direct_reference);

    proto_item_append_text(tree, " (%s)", name ? name : actx->external.direct_reference);
  }


  return offset;
}



static int
dissect_x509af_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_x509af_T_extnValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int8_t ber_class;
  bool pc, ind;
  int32_t tag;
  uint32_t len;
  /* skip past the T and L  */
  offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &ber_class, &pc, &tag);
  offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, &ind);
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t Extension_sequence[] = {
  { &hf_x509af_extnId       , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509af_T_extnId },
  { &hf_x509af_critical     , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509af_BOOLEAN },
  { &hf_x509af_extnValue    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_x509af_T_extnValue },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509af_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Extension_sequence, hf_index, ett_x509af_Extension);

  return offset;
}


static const ber_sequence_t Extensions_sequence_of[1] = {
  { &hf_x509af_Extensions_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_Extension },
};

int
dissect_x509af_Extensions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Extensions_sequence_of, hf_index, ett_x509af_Extensions);

  return offset;
}


static const ber_sequence_t T_signedCertificate_sequence[] = {
  { &hf_x509af_version      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509af_Version },
  { &hf_x509af_serialNumber , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509af_CertificateSerialNumber },
  { &hf_x509af_signature    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_x509af_issuer       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509if_Name },
  { &hf_x509af_validity     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_Validity },
  { &hf_x509af_subject      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509af_SubjectName },
  { &hf_x509af_subjectPublicKeyInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_SubjectPublicKeyInfo },
  { &hf_x509af_issuerUniqueIdentifier, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509sat_UniqueIdentifier },
  { &hf_x509af_subjectUniqueIdentifier, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509sat_UniqueIdentifier },
  { &hf_x509af_extensions   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_x509af_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509af_T_signedCertificate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedCertificate_sequence, hf_index, ett_x509af_T_signedCertificate);

  return offset;
}



static int
dissect_x509af_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t Certificate_sequence[] = {
  { &hf_x509af_signedCertificate, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_T_signedCertificate },
  { &hf_x509af_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_x509af_encrypted    , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_x509af_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509af_Certificate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Certificate_sequence, hf_index, ett_x509af_Certificate);

  return offset;
}


static const ber_sequence_t CrossCertificates_set_of[1] = {
  { &hf_x509af_CrossCertificates_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_Certificate },
};

int
dissect_x509af_CrossCertificates(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 CrossCertificates_set_of, hf_index, ett_x509af_CrossCertificates);

  return offset;
}


static const ber_sequence_t ForwardCertificationPath_sequence_of[1] = {
  { &hf_x509af_ForwardCertificationPath_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509af_CrossCertificates },
};

int
dissect_x509af_ForwardCertificationPath(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ForwardCertificationPath_sequence_of, hf_index, ett_x509af_ForwardCertificationPath);

  return offset;
}


static const ber_sequence_t Certificates_sequence[] = {
  { &hf_x509af_userCertificate, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_Certificate },
  { &hf_x509af_certificationPath, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509af_ForwardCertificationPath },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509af_Certificates(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Certificates_sequence, hf_index, ett_x509af_Certificates);

  return offset;
}


static const ber_sequence_t CertificatePair_sequence[] = {
  { &hf_x509af_issuedByThisCA, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509af_Certificate },
  { &hf_x509af_issuedToThisCA, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509af_Certificate },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509af_CertificatePair(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertificatePair_sequence, hf_index, ett_x509af_CertificatePair);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_CertificatePair_sequence_of[1] = {
  { &hf_x509af_theCACertificates_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_CertificatePair },
};

static int
dissect_x509af_SEQUENCE_OF_CertificatePair(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_CertificatePair_sequence_of, hf_index, ett_x509af_SEQUENCE_OF_CertificatePair);

  return offset;
}


static const ber_sequence_t CertificationPath_sequence[] = {
  { &hf_x509af_userCertificate, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_Certificate },
  { &hf_x509af_theCACertificates, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509af_SEQUENCE_OF_CertificatePair },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509af_CertificationPath(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertificationPath_sequence, hf_index, ett_x509af_CertificationPath);

  return offset;
}


static const ber_sequence_t T_revokedCertificates_item_sequence[] = {
  { &hf_x509af_revokedUserCertificate, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509af_CertificateSerialNumber },
  { &hf_x509af_revocationDate, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509af_Time },
  { &hf_x509af_crlEntryExtensions, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509af_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509af_T_revokedCertificates_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_revokedCertificates_item_sequence, hf_index, ett_x509af_T_revokedCertificates_item);

  return offset;
}


static const ber_sequence_t T_revokedCertificates_sequence_of[1] = {
  { &hf_x509af_revokedCertificates_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_T_revokedCertificates_item },
};

static int
dissect_x509af_T_revokedCertificates(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_revokedCertificates_sequence_of, hf_index, ett_x509af_T_revokedCertificates);

  return offset;
}


static const ber_sequence_t T_signedCertificateList_sequence[] = {
  { &hf_x509af_version      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509af_Version },
  { &hf_x509af_signature    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_x509af_issuer       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509if_Name },
  { &hf_x509af_thisUpdate   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509af_Time },
  { &hf_x509af_nextUpdate   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509af_Time },
  { &hf_x509af_revokedCertificates, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509af_T_revokedCertificates },
  { &hf_x509af_crlExtensions, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509af_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509af_T_signedCertificateList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signedCertificateList_sequence, hf_index, ett_x509af_T_signedCertificateList);

  return offset;
}


static const ber_sequence_t CertificateList_sequence[] = {
  { &hf_x509af_signedCertificateList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_T_signedCertificateList },
  { &hf_x509af_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_x509af_encrypted    , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_x509af_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509af_CertificateList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertificateList_sequence, hf_index, ett_x509af_CertificateList);

  return offset;
}


static const ber_sequence_t IssuerSerial_sequence[] = {
  { &hf_x509af_issuerName   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralNames },
  { &hf_x509af_serial       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509af_CertificateSerialNumber },
  { &hf_x509af_issuerUID    , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509sat_UniqueIdentifier },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509af_IssuerSerial(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IssuerSerial_sequence, hf_index, ett_x509af_IssuerSerial);

  return offset;
}


static const value_string x509af_InfoSubject_vals[] = {
  {   0, "baseCertificateID" },
  {   1, "subjectName" },
  { 0, NULL }
};

static const ber_choice_t InfoSubject_choice[] = {
  {   0, &hf_x509af_baseCertificateID, BER_CLASS_CON, 0, 0, dissect_x509af_IssuerSerial },
  {   1, &hf_x509af_infoSubjectName, BER_CLASS_CON, 1, 0, dissect_x509ce_GeneralNames },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x509af_InfoSubject(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InfoSubject_choice, hf_index, ett_x509af_InfoSubject,
                                 NULL);

  return offset;
}


static const ber_sequence_t AttCertValidityPeriod_sequence[] = {
  { &hf_x509af_notBeforeTime, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_x509af_GeneralizedTime },
  { &hf_x509af_notAfterTime , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_x509af_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509af_AttCertValidityPeriod(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttCertValidityPeriod_sequence, hf_index, ett_x509af_AttCertValidityPeriod);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Attribute_sequence_of[1] = {
  { &hf_x509af_attributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
};

static int
dissect_x509af_SEQUENCE_OF_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Attribute_sequence_of, hf_index, ett_x509af_SEQUENCE_OF_Attribute);

  return offset;
}


static const ber_sequence_t AttributeCertificateInfo_sequence[] = {
  { &hf_x509af_version      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509af_Version },
  { &hf_x509af_info_subject , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509af_InfoSubject },
  { &hf_x509af_issuerName   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralNames },
  { &hf_x509af_signature    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_x509af_serialNumber , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509af_CertificateSerialNumber },
  { &hf_x509af_attCertValidityPeriod, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AttCertValidityPeriod },
  { &hf_x509af_attributes   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_SEQUENCE_OF_Attribute },
  { &hf_x509af_issuerUniqueID, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509sat_UniqueIdentifier },
  { &hf_x509af_extensions   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509af_Extensions },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509af_AttributeCertificateInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeCertificateInfo_sequence, hf_index, ett_x509af_AttributeCertificateInfo);

  return offset;
}


static const ber_sequence_t AttributeCertificate_sequence[] = {
  { &hf_x509af_signedAttributeCertificateInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AttributeCertificateInfo },
  { &hf_x509af_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_x509af_encrypted    , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_x509af_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509af_AttributeCertificate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeCertificate_sequence, hf_index, ett_x509af_AttributeCertificate);

  return offset;
}


static const ber_sequence_t ACPathData_sequence[] = {
  { &hf_x509af_certificate  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509af_Certificate },
  { &hf_x509af_attributeCertificate, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509af_AttributeCertificate },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509af_ACPathData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ACPathData_sequence, hf_index, ett_x509af_ACPathData);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ACPathData_sequence_of[1] = {
  { &hf_x509af_acPath_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_ACPathData },
};

static int
dissect_x509af_SEQUENCE_OF_ACPathData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ACPathData_sequence_of, hf_index, ett_x509af_SEQUENCE_OF_ACPathData);

  return offset;
}


static const ber_sequence_t AttributeCertificationPath_sequence[] = {
  { &hf_x509af_attributeCertificate, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AttributeCertificate },
  { &hf_x509af_acPath       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509af_SEQUENCE_OF_ACPathData },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509af_AttributeCertificationPath(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeCertificationPath_sequence, hf_index, ett_x509af_AttributeCertificationPath);

  return offset;
}


static const value_string x509af_AssertionSubject_vals[] = {
  {   0, "baseCertificateID" },
  {   1, "subjectName" },
  { 0, NULL }
};

static const ber_choice_t AssertionSubject_choice[] = {
  {   0, &hf_x509af_baseCertificateID, BER_CLASS_CON, 0, 0, dissect_x509af_IssuerSerial },
  {   1, &hf_x509af_assertionSubjectName, BER_CLASS_CON, 1, 0, dissect_x509af_SubjectName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x509af_AssertionSubject(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AssertionSubject_choice, hf_index, ett_x509af_AssertionSubject,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_AttributeType_set_of[1] = {
  { &hf_x509af_attType_item , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
};

static int
dissect_x509af_SET_OF_AttributeType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_AttributeType_set_of, hf_index, ett_x509af_SET_OF_AttributeType);

  return offset;
}


static const ber_sequence_t AttributeCertificateAssertion_sequence[] = {
  { &hf_x509af_assertion_subject, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509af_AssertionSubject },
  { &hf_x509af_assertionIssuer, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509if_Name },
  { &hf_x509af_attCertValidity, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x509af_GeneralizedTime },
  { &hf_x509af_attType      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_x509af_SET_OF_AttributeType },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509af_AttributeCertificateAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeCertificateAssertion_sequence, hf_index, ett_x509af_AttributeCertificateAssertion);

  return offset;
}



static int
dissect_x509af_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t DSS_Params_sequence[] = {
  { &hf_x509af_p            , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509af_INTEGER },
  { &hf_x509af_q            , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509af_INTEGER },
  { &hf_x509af_g            , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509af_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509af_DSS_Params(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DSS_Params_sequence, hf_index, ett_x509af_DSS_Params);

  return offset;
}



static int
dissect_x509af_Userid(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}

/*--- PDUs ---*/

int dissect_x509af_Certificate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509af_Certificate(false, tvb, offset, &asn1_ctx, tree, hf_x509af_x509af_Certificate_PDU);
  return offset;
}
static int dissect_SubjectPublicKeyInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509af_SubjectPublicKeyInfo(false, tvb, offset, &asn1_ctx, tree, hf_x509af_SubjectPublicKeyInfo_PDU);
  return offset;
}
static int dissect_CertificatePair_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509af_CertificatePair(false, tvb, offset, &asn1_ctx, tree, hf_x509af_CertificatePair_PDU);
  return offset;
}
static int dissect_CertificateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509af_CertificateList(false, tvb, offset, &asn1_ctx, tree, hf_x509af_CertificateList_PDU);
  return offset;
}
static int dissect_AttributeCertificate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509af_AttributeCertificate(false, tvb, offset, &asn1_ctx, tree, hf_x509af_AttributeCertificate_PDU);
  return offset;
}
static int dissect_DSS_Params_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509af_DSS_Params(false, tvb, offset, &asn1_ctx, tree, hf_x509af_DSS_Params_PDU);
  return offset;
}
static int dissect_Userid_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509af_Userid(false, tvb, offset, &asn1_ctx, tree, hf_x509af_Userid_PDU);
  return offset;
}


/* Exports the SubjectPublicKeyInfo structure as gnutls_datum_t.
 * actx->private_data is assumed to be a gnutls_datum_t pointer which will be
 * filled in if non-NULL. */
static void
x509af_export_publickey(tvbuff_t *tvb _U_, asn1_ctx_t *actx _U_, int offset _U_, int len _U_)
{
#if defined(HAVE_LIBGNUTLS)
  gnutls_datum_t *subjectPublicKeyInfo = (gnutls_datum_t *)actx->private_data;
  if (subjectPublicKeyInfo) {
    subjectPublicKeyInfo->data = (unsigned char *) tvb_get_ptr(tvb, offset, len);
    subjectPublicKeyInfo->size = len;
    actx->private_data = NULL;
  }
#endif
}

const char *x509af_get_last_algorithm_id(void) {
  return algorithm_id;
}


static int
dissect_pkix_crl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	proto_tree *tree;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "PKIX-CRL");

	col_set_str(pinfo->cinfo, COL_INFO, "Certificate Revocation List");


	tree=proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_pkix_crl, NULL, "Certificate Revocation List");

	return dissect_x509af_CertificateList(false, tvb, 0, &asn1_ctx, tree, -1);
}

static void
x509af_cleanup_protocol(void)
{
  algorithm_id = NULL;
}

/*--- proto_register_x509af ----------------------------------------------*/
void proto_register_x509af(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509af_algorithm_id,
      { "Algorithm Id", "x509af.algorithm.id",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_extension_id,
      { "Extension Id", "x509af.extension.id",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_x509af_Certificate_PDU,
      { "Certificate", "x509af.Certificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_SubjectPublicKeyInfo_PDU,
      { "SubjectPublicKeyInfo", "x509af.SubjectPublicKeyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_CertificatePair_PDU,
      { "CertificatePair", "x509af.CertificatePair_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_CertificateList_PDU,
      { "CertificateList", "x509af.CertificateList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_AttributeCertificate_PDU,
      { "AttributeCertificate", "x509af.AttributeCertificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_DSS_Params_PDU,
      { "DSS-Params", "x509af.DSS_Params_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_Userid_PDU,
      { "Userid", "x509af.Userid",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_signedCertificate,
      { "signedCertificate", "x509af.signedCertificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_version,
      { "version", "x509af.version",
        FT_INT32, BASE_DEC, VALS(x509af_Version_vals), 0,
        NULL, HFILL }},
    { &hf_x509af_serialNumber,
      { "serialNumber", "x509af.serialNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CertificateSerialNumber", HFILL }},
    { &hf_x509af_signature,
      { "signature", "x509af.signature_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_x509af_issuer,
      { "issuer", "x509af.issuer",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_x509af_validity,
      { "validity", "x509af.validity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_subject,
      { "subject", "x509af.subject",
        FT_UINT32, BASE_DEC, VALS(x509af_SubjectName_vals), 0,
        "SubjectName", HFILL }},
    { &hf_x509af_subjectPublicKeyInfo,
      { "subjectPublicKeyInfo", "x509af.subjectPublicKeyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_issuerUniqueIdentifier,
      { "issuerUniqueIdentifier", "x509af.issuerUniqueIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "UniqueIdentifier", HFILL }},
    { &hf_x509af_subjectUniqueIdentifier,
      { "subjectUniqueIdentifier", "x509af.subjectUniqueIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "UniqueIdentifier", HFILL }},
    { &hf_x509af_extensions,
      { "extensions", "x509af.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_algorithmIdentifier,
      { "algorithmIdentifier", "x509af.algorithmIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_encrypted,
      { "encrypted", "x509af.encrypted",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_x509af_rdnSequence,
      { "rdnSequence", "x509af.rdnSequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_algorithmId,
      { "algorithmId", "x509af.algorithmId",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_parameters,
      { "parameters", "x509af.parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_notBefore,
      { "notBefore", "x509af.notBefore",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "Time", HFILL }},
    { &hf_x509af_notAfter,
      { "notAfter", "x509af.notAfter",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "Time", HFILL }},
    { &hf_x509af_algorithm,
      { "algorithm", "x509af.algorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_x509af_subjectPublicKey,
      { "subjectPublicKey", "x509af.subjectPublicKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_utcTime,
      { "utcTime", "x509af.utcTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_generalizedTime,
      { "generalizedTime", "x509af.generalizedTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_Extensions_item,
      { "Extension", "x509af.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_extnId,
      { "extnId", "x509af.extnId",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_critical,
      { "critical", "x509af.critical",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_x509af_extnValue,
      { "extnValue", "x509af.extnValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_userCertificate,
      { "userCertificate", "x509af.userCertificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Certificate", HFILL }},
    { &hf_x509af_certificationPath,
      { "certificationPath", "x509af.certificationPath",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ForwardCertificationPath", HFILL }},
    { &hf_x509af_ForwardCertificationPath_item,
      { "CrossCertificates", "x509af.CrossCertificates",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_CrossCertificates_item,
      { "Certificate", "x509af.Certificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_theCACertificates,
      { "theCACertificates", "x509af.theCACertificates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CertificatePair", HFILL }},
    { &hf_x509af_theCACertificates_item,
      { "CertificatePair", "x509af.CertificatePair_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_issuedByThisCA,
      { "issuedByThisCA", "x509af.issuedByThisCA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Certificate", HFILL }},
    { &hf_x509af_issuedToThisCA,
      { "issuedToThisCA", "x509af.issuedToThisCA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Certificate", HFILL }},
    { &hf_x509af_signedCertificateList,
      { "signedCertificateList", "x509af.signedCertificateList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_thisUpdate,
      { "thisUpdate", "x509af.thisUpdate",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "Time", HFILL }},
    { &hf_x509af_nextUpdate,
      { "nextUpdate", "x509af.nextUpdate",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "Time", HFILL }},
    { &hf_x509af_revokedCertificates,
      { "revokedCertificates", "x509af.revokedCertificates",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_revokedCertificates_item,
      { "revokedCertificates item", "x509af.revokedCertificates_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_revokedUserCertificate,
      { "userCertificate", "x509af.userCertificate",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CertificateSerialNumber", HFILL }},
    { &hf_x509af_revocationDate,
      { "revocationDate", "x509af.revocationDate",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "Time", HFILL }},
    { &hf_x509af_crlEntryExtensions,
      { "crlEntryExtensions", "x509af.crlEntryExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Extensions", HFILL }},
    { &hf_x509af_crlExtensions,
      { "crlExtensions", "x509af.crlExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Extensions", HFILL }},
    { &hf_x509af_attributeCertificate,
      { "attributeCertificate", "x509af.attributeCertificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_acPath,
      { "acPath", "x509af.acPath",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ACPathData", HFILL }},
    { &hf_x509af_acPath_item,
      { "ACPathData", "x509af.ACPathData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_certificate,
      { "certificate", "x509af.certificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_signedAttributeCertificateInfo,
      { "signedAttributeCertificateInfo", "x509af.signedAttributeCertificateInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeCertificateInfo", HFILL }},
    { &hf_x509af_info_subject,
      { "subject", "x509af.subject",
        FT_UINT32, BASE_DEC, VALS(x509af_InfoSubject_vals), 0,
        "InfoSubject", HFILL }},
    { &hf_x509af_baseCertificateID,
      { "baseCertificateID", "x509af.baseCertificateID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IssuerSerial", HFILL }},
    { &hf_x509af_infoSubjectName,
      { "subjectName", "x509af.subjectName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralNames", HFILL }},
    { &hf_x509af_issuerName,
      { "issuer", "x509af.issuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralNames", HFILL }},
    { &hf_x509af_attCertValidityPeriod,
      { "attCertValidityPeriod", "x509af.attCertValidityPeriod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_attributes,
      { "attributes", "x509af.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Attribute", HFILL }},
    { &hf_x509af_attributes_item,
      { "Attribute", "x509af.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_issuerUniqueID,
      { "issuerUniqueID", "x509af.issuerUniqueID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "UniqueIdentifier", HFILL }},
    { &hf_x509af_serial,
      { "serial", "x509af.serial",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CertificateSerialNumber", HFILL }},
    { &hf_x509af_issuerUID,
      { "issuerUID", "x509af.issuerUID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "UniqueIdentifier", HFILL }},
    { &hf_x509af_notBeforeTime,
      { "notBeforeTime", "x509af.notBeforeTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_x509af_notAfterTime,
      { "notAfterTime", "x509af.notAfterTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_x509af_assertion_subject,
      { "subject", "x509af.subject",
        FT_UINT32, BASE_DEC, VALS(x509af_AssertionSubject_vals), 0,
        "AssertionSubject", HFILL }},
    { &hf_x509af_assertionSubjectName,
      { "subjectName", "x509af.subjectName",
        FT_UINT32, BASE_DEC, VALS(x509af_SubjectName_vals), 0,
        NULL, HFILL }},
    { &hf_x509af_assertionIssuer,
      { "issuer", "x509af.issuer",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_x509af_attCertValidity,
      { "attCertValidity", "x509af.attCertValidity",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_x509af_attType,
      { "attType", "x509af.attType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_AttributeType", HFILL }},
    { &hf_x509af_attType_item,
      { "AttributeType", "x509af.AttributeType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509af_p,
      { "p", "x509af.p",
        FT_BYTES, BASE_NONE, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509af_q,
      { "q", "x509af.q",
        FT_BYTES, BASE_NONE, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509af_g,
      { "g", "x509af.g",
        FT_BYTES, BASE_NONE, NULL, 0,
        "INTEGER", HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_pkix_crl,
    &ett_x509af_Certificate,
    &ett_x509af_T_signedCertificate,
    &ett_x509af_SubjectName,
    &ett_x509af_AlgorithmIdentifier,
    &ett_x509af_Validity,
    &ett_x509af_SubjectPublicKeyInfo,
    &ett_x509af_Time,
    &ett_x509af_Extensions,
    &ett_x509af_Extension,
    &ett_x509af_Certificates,
    &ett_x509af_ForwardCertificationPath,
    &ett_x509af_CrossCertificates,
    &ett_x509af_CertificationPath,
    &ett_x509af_SEQUENCE_OF_CertificatePair,
    &ett_x509af_CertificatePair,
    &ett_x509af_CertificateList,
    &ett_x509af_T_signedCertificateList,
    &ett_x509af_T_revokedCertificates,
    &ett_x509af_T_revokedCertificates_item,
    &ett_x509af_AttributeCertificationPath,
    &ett_x509af_SEQUENCE_OF_ACPathData,
    &ett_x509af_ACPathData,
    &ett_x509af_AttributeCertificate,
    &ett_x509af_AttributeCertificateInfo,
    &ett_x509af_InfoSubject,
    &ett_x509af_SEQUENCE_OF_Attribute,
    &ett_x509af_IssuerSerial,
    &ett_x509af_AttCertValidityPeriod,
    &ett_x509af_AttributeCertificateAssertion,
    &ett_x509af_AssertionSubject,
    &ett_x509af_SET_OF_AttributeType,
    &ett_x509af_DSS_Params,
  };

  /* Register protocol */
  proto_x509af = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x509af, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_cleanup_routine(&x509af_cleanup_protocol);

  pkix_crl_handle = register_dissector(PFNAME, dissect_pkix_crl, proto_x509af);

  register_ber_syntax_dissector("Certificate", proto_x509af, dissect_x509af_Certificate_PDU);
  register_ber_syntax_dissector("CertificateList", proto_x509af, dissect_CertificateList_PDU);
  register_ber_syntax_dissector("CrossCertificatePair", proto_x509af, dissect_CertificatePair_PDU);

  register_ber_oid_syntax(".cer", NULL, "Certificate");
  register_ber_oid_syntax(".crt", NULL, "Certificate");
  register_ber_oid_syntax(".crl", NULL, "CertificateList");
}


/*--- proto_reg_handoff_x509af -------------------------------------------*/
void proto_reg_handoff_x509af(void) {

	dissector_add_string("media_type", "application/pkix-crl", pkix_crl_handle);

  register_ber_oid_dissector("2.5.4.36", dissect_x509af_Certificate_PDU, proto_x509af, "id-at-userCertificate");
  register_ber_oid_dissector("2.5.4.37", dissect_x509af_Certificate_PDU, proto_x509af, "id-at-cAcertificate");
  register_ber_oid_dissector("2.5.4.38", dissect_CertificateList_PDU, proto_x509af, "id-at-authorityRevocationList");
  register_ber_oid_dissector("2.5.4.39", dissect_CertificateList_PDU, proto_x509af, "id-at-certificateRevocationList");
  register_ber_oid_dissector("2.5.4.40", dissect_CertificatePair_PDU, proto_x509af, "id-at-crossCertificatePair");
  register_ber_oid_dissector("2.5.4.53", dissect_CertificateList_PDU, proto_x509af, "id-at-deltaRevocationList");
  register_ber_oid_dissector("2.5.4.58", dissect_AttributeCertificate_PDU, proto_x509af, "id-at-attributeCertificate");
  register_ber_oid_dissector("2.5.4.59", dissect_CertificateList_PDU, proto_x509af, "id-at-attributeCertificateRevocationList");
  register_ber_oid_dissector("1.2.840.10040.4.1", dissect_DSS_Params_PDU, proto_x509af, "id-dsa");
  register_ber_oid_dissector("0.9.2342.19200300.100.1.1", dissect_Userid_PDU, proto_x509af, "id-userid");


	/*XXX these should really go to a better place but since
	  I have not that ITU standard, I'll put it here for the time
	  being.
	  Only implemented those algorithms that take no parameters
	  for the time being,   ronnie
	*/
	/* from http://www.alvestrand.no/objectid/1.3.14.3.2.html */
	register_ber_oid_dissector("1.3.14.3.2.2", dissect_ber_oid_NULL_callback, proto_x509af, "md4WithRSA");
	register_ber_oid_dissector("1.3.14.3.2.3", dissect_ber_oid_NULL_callback, proto_x509af, "md5WithRSA");
	register_ber_oid_dissector("1.3.14.3.2.4", dissect_ber_oid_NULL_callback, proto_x509af, "md4WithRSAEncryption");
	register_ber_oid_dissector("1.3.14.3.2.6", dissect_ber_oid_NULL_callback, proto_x509af, "desECB");
	register_ber_oid_dissector("1.3.14.3.2.11", dissect_ber_oid_NULL_callback, proto_x509af, "rsaSignature");
	register_ber_oid_dissector("1.3.14.3.2.14", dissect_ber_oid_NULL_callback, proto_x509af, "mdc2WithRSASignature");
	register_ber_oid_dissector("1.3.14.3.2.15", dissect_ber_oid_NULL_callback, proto_x509af, "shaWithRSASignature");
	register_ber_oid_dissector("1.3.14.3.2.16", dissect_ber_oid_NULL_callback, proto_x509af, "dhWithCommonModulus");
	register_ber_oid_dissector("1.3.14.3.2.17", dissect_ber_oid_NULL_callback, proto_x509af, "desEDE");
	register_ber_oid_dissector("1.3.14.3.2.18", dissect_ber_oid_NULL_callback, proto_x509af, "sha");
	register_ber_oid_dissector("1.3.14.3.2.19", dissect_ber_oid_NULL_callback, proto_x509af, "mdc-2");
	register_ber_oid_dissector("1.3.14.3.2.20", dissect_ber_oid_NULL_callback, proto_x509af, "dsaCommon");
	register_ber_oid_dissector("1.3.14.3.2.21", dissect_ber_oid_NULL_callback, proto_x509af, "dsaCommonWithSHA");
	register_ber_oid_dissector("1.3.14.3.2.22", dissect_ber_oid_NULL_callback, proto_x509af, "rsaKeyTransport");
	register_ber_oid_dissector("1.3.14.3.2.23", dissect_ber_oid_NULL_callback, proto_x509af, "keyed-hash-seal");
	register_ber_oid_dissector("1.3.14.3.2.24", dissect_ber_oid_NULL_callback, proto_x509af, "md2WithRSASignature");
	register_ber_oid_dissector("1.3.14.3.2.25", dissect_ber_oid_NULL_callback, proto_x509af, "md5WithRSASignature");
	register_ber_oid_dissector("1.3.14.3.2.26", dissect_ber_oid_NULL_callback, proto_x509af, "SHA-1");
	register_ber_oid_dissector("1.3.14.3.2.27", dissect_ber_oid_NULL_callback, proto_x509af, "dsaWithSHA1");
	register_ber_oid_dissector("1.3.14.3.2.28", dissect_ber_oid_NULL_callback, proto_x509af, "dsaWithCommonSHA1");
	register_ber_oid_dissector("1.3.14.3.2.29", dissect_ber_oid_NULL_callback, proto_x509af, "sha-1WithRSAEncryption");

	/* these will generally be encoded as ";binary" in LDAP */

	dissector_add_string("ldap.name", "cACertificate", create_dissector_handle(dissect_x509af_Certificate_PDU, proto_x509af));
	dissector_add_string("ldap.name", "userCertificate", create_dissector_handle(dissect_x509af_Certificate_PDU, proto_x509af));

	dissector_add_string("ldap.name", "certificateRevocationList", create_dissector_handle(dissect_CertificateList_PDU, proto_x509af));
	dissector_add_string("ldap.name", "crl", create_dissector_handle(dissect_CertificateList_PDU, proto_x509af));

	dissector_add_string("ldap.name", "authorityRevocationList", create_dissector_handle(dissect_CertificateList_PDU, proto_x509af));
	dissector_add_string("ldap.name", "arl", create_dissector_handle(dissect_CertificateList_PDU, proto_x509af));

	dissector_add_string("ldap.name", "crossCertificatePair", create_dissector_handle(dissect_CertificatePair_PDU, proto_x509af));

	/* RFC 7468 files */
	dissector_add_string("rfc7468.preeb_label", "CERTIFICATE", create_dissector_handle(dissect_x509af_Certificate_PDU, proto_x509af));
	dissector_add_string("rfc7468.preeb_label", "X509 CRL", create_dissector_handle(dissect_CertificateList_PDU, proto_x509af));
	dissector_add_string("rfc7468.preeb_label", "ATTRIBUTE CERTIFICATE", create_dissector_handle(dissect_AttributeCertificate_PDU, proto_x509af));
	dissector_add_string("rfc7468.preeb_label", "PUBLIC KEY", create_dissector_handle(dissect_SubjectPublicKeyInfo_PDU, proto_x509af));
}

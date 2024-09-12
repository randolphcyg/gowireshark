/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-glow.c                                                              */
/* asn2wrs.py -b -q -L -p glow -c ./glow.cnf -s ./packet-glow-template -D . -O ../.. glow.asn */

/* packet-glow.c
 * Routines for GLOW packet dissection
 *
 * Copyright 2018, Gilles Dufour <dufour.gilles@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

# include "config.h"

#include <epan/packet.h>
#include <epan/proto_data.h>
#include <wsutil/array.h>
#include "packet-ber.h"

#define PNAME  "Glow"
#define PSNAME "GLOW"
#define PFNAME "glow"

void proto_register_glow(void);

static dissector_handle_t glow_handle;
static int proto_glow;

static int hf_glow_Root_PDU;                      /* Root */
static int hf_glow_number;                        /* Integer32 */
static int hf_glow_element;                       /* TemplateElement */
static int hf_glow_description;                   /* EmberString */
static int hf_glow_path;                          /* RELATIVE_OID */
static int hf_glow_parameter;                     /* Parameter */
static int hf_glow_node;                          /* Node */
static int hf_glow_matrix;                        /* Matrix */
static int hf_glow_function;                      /* Function */
static int hf_glow_contents;                      /* ParameterContents */
static int hf_glow_children;                      /* ElementCollection */
static int hf_glow_identifier;                    /* EmberString */
static int hf_glow_value;                         /* Value */
static int hf_glow_minimum;                       /* MinMax */
static int hf_glow_maximum;                       /* MinMax */
static int hf_glow_access;                        /* ParameterAccess */
static int hf_glow_format;                        /* EmberString */
static int hf_glow_enumeration;                   /* EmberString */
static int hf_glow_factor;                        /* Integer32 */
static int hf_glow_isOnline;                      /* BOOLEAN */
static int hf_glow_formula;                       /* EmberString */
static int hf_glow_step;                          /* Integer32 */
static int hf_glow_default;                       /* Value */
static int hf_glow_type;                          /* ParameterType */
static int hf_glow_streamIdentifier;              /* Integer32 */
static int hf_glow_enumMap;                       /* StringIntegerCollection */
static int hf_glow_streamDescriptor;              /* StreamDescription */
static int hf_glow_schemaIdentifiers;             /* EmberString */
static int hf_glow_templateReference;             /* RELATIVE_OID */
static int hf_glow_integer;                       /* Integer64 */
static int hf_glow_real;                          /* REAL */
static int hf_glow_string;                        /* EmberString */
static int hf_glow_boolean;                       /* BOOLEAN */
static int hf_glow_octets;                        /* OCTET_STRING */
static int hf_glow_null;                          /* NULL */
static int hf_glow_entryString;                   /* EmberString */
static int hf_glow_entryInteger;                  /* Integer32 */
static int hf_glow__untag_item;                   /* StringIntegerPair */
static int hf_glow_streamFormat;                  /* StreamFormat */
static int hf_glow_offset;                        /* Integer32 */
static int hf_glow_number_01;                     /* CommandType */
static int hf_glow_options;                       /* T_options */
static int hf_glow_dirFieldMask;                  /* FieldFlags */
static int hf_glow_invocation;                    /* Invocation */
static int hf_glow_contents_01;                   /* NodeContents */
static int hf_glow_isRoot;                        /* BOOLEAN */
static int hf_glow_contents_02;                   /* MatrixContents */
static int hf_glow_targetList;                    /* TargetCollection */
static int hf_glow_sourceList;                    /* SourceCollection */
static int hf_glow_connections;                   /* ConnectionCollection */
static int hf_glow_type_01;                       /* MatrixType */
static int hf_glow_addressingMode;                /* MatrixAddressingMode */
static int hf_glow_targetCount;                   /* Integer32 */
static int hf_glow_sourceCount;                   /* Integer32 */
static int hf_glow_maximumTotalConnects;          /* Integer32 */
static int hf_glow_maximumConnectsPerTarget;      /* Integer32 */
static int hf_glow_parametersLocation;            /* ParametersLocation */
static int hf_glow_gainParameterNumber;           /* Integer32 */
static int hf_glow_labels;                        /* LabelCollection */
static int hf_glow_basePath;                      /* RELATIVE_OID */
static int hf_glow_inline;                        /* Integer32 */
static int hf_glow_LabelCollection_item;          /* Label */
static int hf_glow_TargetCollection_item;         /* Target */
static int hf_glow_SourceCollection_item;         /* Source */
static int hf_glow_ConnectionCollection_item;     /* Connection */
static int hf_glow_target;                        /* Integer32 */
static int hf_glow_sources;                       /* PackedNumbers */
static int hf_glow_operation;                     /* ConnectionOperation */
static int hf_glow_disposition;                   /* ConnectionDisposition */
static int hf_glow_contents_03;                   /* FunctionContents */
static int hf_glow_arguments;                     /* TupleDescription */
static int hf_glow_result;                        /* TupleDescription */
static int hf_glow_TupleDescription_item;         /* TupleItemDescription */
static int hf_glow_name;                          /* EmberString */
static int hf_glow_invocationId;                  /* Integer32 */
static int hf_glow_arguments_01;                  /* Tuple */
static int hf_glow_Tuple_item;                    /* Value */
static int hf_glow_success;                       /* BOOLEAN */
static int hf_glow_result_01;                     /* Tuple */
static int hf_glow__untag_item_01;                /* Element */
static int hf_glow_command;                       /* Command */
static int hf_glow_template;                      /* Template */
static int hf_glow_streamValue;                   /* Value */
static int hf_glow__untag_item_02;                /* StreamEntry */
static int hf_glow_elements;                      /* RootElementCollection */
static int hf_glow_streams;                       /* StreamCollection */
static int hf_glow_invocationResult;              /* InvocationResult */
static int hf_glow__untag_item_03;                /* RootElement */
static int hf_glow_element_01;                    /* Element */
static int hf_glow_qualifiedParameter;            /* QualifiedParameter */
static int hf_glow_qualifiedNode;                 /* QualifiedNode */
static int hf_glow_qualifiedMatrix;               /* QualifiedMatrix */
static int hf_glow_qualifiedFunction;             /* QualifiedFunction */
static int hf_glow_qualifiedTemplate;             /* QualifiedTemplate */

/* Initialize the subtree pointers */
static int ett_glow;

static int ett_glow_Template_U;
static int ett_glow_QualifiedTemplate_U;
static int ett_glow_TemplateElement;
static int ett_glow_Parameter_U;
static int ett_glow_QualifiedParameter_U;
static int ett_glow_ParameterContents;
static int ett_glow_Value;
static int ett_glow_MinMax;
static int ett_glow_StringIntegerPair_U;
static int ett_glow_SEQUENCE_OF_StringIntegerPair;
static int ett_glow_StreamDescription_U;
static int ett_glow_Command_U;
static int ett_glow_T_options;
static int ett_glow_Node_U;
static int ett_glow_QualifiedNode_U;
static int ett_glow_NodeContents;
static int ett_glow_Matrix_U;
static int ett_glow_MatrixContents;
static int ett_glow_ParametersLocation;
static int ett_glow_LabelCollection;
static int ett_glow_Label_U;
static int ett_glow_TargetCollection;
static int ett_glow_Signal;
static int ett_glow_SourceCollection;
static int ett_glow_ConnectionCollection;
static int ett_glow_Connection_U;
static int ett_glow_QualifiedMatrix_U;
static int ett_glow_Function_U;
static int ett_glow_QualifiedFunction_U;
static int ett_glow_FunctionContents;
static int ett_glow_TupleDescription;
static int ett_glow_TupleItemDescription_U;
static int ett_glow_Invocation_U;
static int ett_glow_Tuple;
static int ett_glow_InvocationResult_U;
static int ett_glow_SEQUENCE_OF_Element;
static int ett_glow_Element;
static int ett_glow_StreamEntry_U;
static int ett_glow_SEQUENCE_OF_StreamEntry;
static int ett_glow_Root_U;
static int ett_glow_SEQUENCE_OF_RootElement;
static int ett_glow_RootElement;

/*--- Cyclic dependencies ---*/

/* Parameter -> Parameter/_untag -> ElementCollection -> ElementCollection/_untag -> Element -> Parameter */
static int dissect_glow_Parameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* ElementCollection -> ElementCollection/_untag -> Element -> Node -> Node/_untag -> ElementCollection */
/* ElementCollection -> ElementCollection/_untag -> Element -> Matrix -> Matrix/_untag -> ElementCollection */
/* ElementCollection -> ElementCollection/_untag -> Element -> Function -> Function/_untag -> ElementCollection */
static int dissect_glow_ElementCollection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* Template -> Template/_untag -> TemplateElement -> Parameter -> Parameter/_untag -> ElementCollection -> ElementCollection/_untag -> Element -> Template */
static int dissect_glow_Template(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);




static int
dissect_glow_EmberString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_glow_Integer32(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_glow_Integer64(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_glow_REAL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_real(implicit_tag, actx, tree, tvb, offset, hf_index,
                               NULL);

  return offset;
}



static int
dissect_glow_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_glow_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_glow_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string glow_Value_vals[] = {
  {   0, "integer" },
  {   1, "real" },
  {   2, "string" },
  {   3, "boolean" },
  {   4, "octets" },
  {   5, "null" },
  { 0, NULL }
};

static const ber_choice_t Value_choice[] = {
  {   0, &hf_glow_integer        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_glow_Integer64 },
  {   1, &hf_glow_real           , BER_CLASS_UNI, BER_UNI_TAG_REAL, BER_FLAGS_NOOWNTAG, dissect_glow_REAL },
  {   2, &hf_glow_string         , BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_glow_EmberString },
  {   3, &hf_glow_boolean        , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_glow_BOOLEAN },
  {   4, &hf_glow_octets         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_glow_OCTET_STRING },
  {   5, &hf_glow_null           , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_glow_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_Value(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Value_choice, hf_index, ett_glow_Value,
                                 NULL);

  return offset;
}


static const value_string glow_MinMax_vals[] = {
  {   0, "integer" },
  {   1, "real" },
  {   2, "null" },
  { 0, NULL }
};

static const ber_choice_t MinMax_choice[] = {
  {   0, &hf_glow_integer        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_glow_Integer64 },
  {   1, &hf_glow_real           , BER_CLASS_UNI, BER_UNI_TAG_REAL, BER_FLAGS_NOOWNTAG, dissect_glow_REAL },
  {   2, &hf_glow_null           , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_glow_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_MinMax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MinMax_choice, hf_index, ett_glow_MinMax,
                                 NULL);

  return offset;
}


static const value_string glow_ParameterAccess_vals[] = {
  {   0, "none" },
  {   1, "read" },
  {   2, "write" },
  {   3, "readWrite" },
  { 0, NULL }
};


static int
dissect_glow_ParameterAccess(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string glow_ParameterType_vals[] = {
  {   0, "null" },
  {   1, "integer" },
  {   2, "real" },
  {   3, "string" },
  {   4, "boolean" },
  {   5, "trigger" },
  {   6, "enum" },
  {   7, "octets" },
  { 0, NULL }
};


static int
dissect_glow_ParameterType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t StringIntegerPair_U_sequence[] = {
  { &hf_glow_entryString    , BER_CLASS_CON, 0, 0, dissect_glow_EmberString },
  { &hf_glow_entryInteger   , BER_CLASS_CON, 1, 0, dissect_glow_Integer32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_StringIntegerPair_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StringIntegerPair_U_sequence, hf_index, ett_glow_StringIntegerPair_U);

  return offset;
}



static int
dissect_glow_StringIntegerPair(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 7, true, dissect_glow_StringIntegerPair_U);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_StringIntegerPair_sequence_of[1] = {
  { &hf_glow__untag_item    , BER_CLASS_CON, 0, 0, dissect_glow_StringIntegerPair },
};

static int
dissect_glow_SEQUENCE_OF_StringIntegerPair(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_StringIntegerPair_sequence_of, hf_index, ett_glow_SEQUENCE_OF_StringIntegerPair);

  return offset;
}



static int
dissect_glow_StringIntegerCollection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 8, true, dissect_glow_SEQUENCE_OF_StringIntegerPair);

  return offset;
}


static const value_string glow_StreamFormat_vals[] = {
  {   0, "unsignedInt8" },
  {   2, "unsignedInt16BigEndian" },
  {   3, "unsignedInt16LittleEndian" },
  {   4, "unsignedInt32BigEndian" },
  {   5, "unsignedInt32LittleEndian" },
  {   6, "unsignedInt64BigEndian" },
  {   7, "unsignedInt64LittleEndian" },
  {   8, "signedInt8" },
  {  10, "signedInt16BigEndian" },
  {  11, "signedInt16LittleEndian" },
  {  12, "signedInt32BigEndian" },
  {  13, "signedInt32LittleEndian" },
  {  14, "signedInt64BigEndian" },
  {  15, "signedInt64LittleEndian" },
  {  20, "ieeeFloat32BigEndian" },
  {  21, "ieeeFloat32LittleEndian" },
  {  22, "ieeeFloat64BigEndian" },
  {  23, "ieeeFloat64LittleEndian" },
  { 0, NULL }
};


static int
dissect_glow_StreamFormat(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t StreamDescription_U_sequence[] = {
  { &hf_glow_streamFormat   , BER_CLASS_CON, 0, 0, dissect_glow_StreamFormat },
  { &hf_glow_offset         , BER_CLASS_CON, 1, 0, dissect_glow_Integer32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_StreamDescription_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StreamDescription_U_sequence, hf_index, ett_glow_StreamDescription_U);

  return offset;
}



static int
dissect_glow_StreamDescription(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 12, true, dissect_glow_StreamDescription_U);

  return offset;
}



static int
dissect_glow_RELATIVE_OID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_relative_oid(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t ParameterContents_set[] = {
  { &hf_glow_identifier     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_glow_EmberString },
  { &hf_glow_description    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_glow_EmberString },
  { &hf_glow_value          , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_glow_Value },
  { &hf_glow_minimum        , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_glow_MinMax },
  { &hf_glow_maximum        , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_glow_MinMax },
  { &hf_glow_access         , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_glow_ParameterAccess },
  { &hf_glow_format         , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_glow_EmberString },
  { &hf_glow_enumeration    , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_glow_EmberString },
  { &hf_glow_factor         , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_glow_Integer32 },
  { &hf_glow_isOnline       , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_glow_BOOLEAN },
  { &hf_glow_formula        , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_glow_EmberString },
  { &hf_glow_step           , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_glow_Integer32 },
  { &hf_glow_default        , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_glow_Value },
  { &hf_glow_type           , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL, dissect_glow_ParameterType },
  { &hf_glow_streamIdentifier, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL, dissect_glow_Integer32 },
  { &hf_glow_enumMap        , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL, dissect_glow_StringIntegerCollection },
  { &hf_glow_streamDescriptor, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL, dissect_glow_StreamDescription },
  { &hf_glow_schemaIdentifiers, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL, dissect_glow_EmberString },
  { &hf_glow_templateReference, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL, dissect_glow_RELATIVE_OID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_ParameterContents(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ParameterContents_set, hf_index, ett_glow_ParameterContents);

  return offset;
}


static const ber_sequence_t NodeContents_set[] = {
  { &hf_glow_identifier     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_glow_EmberString },
  { &hf_glow_description    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_glow_EmberString },
  { &hf_glow_isRoot         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_glow_BOOLEAN },
  { &hf_glow_isOnline       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_glow_BOOLEAN },
  { &hf_glow_schemaIdentifiers, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_glow_EmberString },
  { &hf_glow_templateReference, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_glow_RELATIVE_OID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_NodeContents(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              NodeContents_set, hf_index, ett_glow_NodeContents);

  return offset;
}


static const ber_sequence_t Node_U_sequence[] = {
  { &hf_glow_number         , BER_CLASS_CON, 0, 0, dissect_glow_Integer32 },
  { &hf_glow_contents_01    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_glow_NodeContents },
  { &hf_glow_children       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_glow_ElementCollection },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_Node_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Node_U_sequence, hf_index, ett_glow_Node_U);

  return offset;
}



static int
dissect_glow_Node(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 3, true, dissect_glow_Node_U);

  return offset;
}


static const value_string glow_CommandType_vals[] = {
  {  30, "subscribe" },
  {  31, "unsubscribe" },
  {  32, "getDirectory" },
  {  33, "invoke" },
  { 0, NULL }
};


static int
dissect_glow_CommandType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string glow_FieldFlags_vals[] = {
  {  -2, "sparse" },
  {  -1, "all" },
  {   0, "default" },
  {   1, "identifier" },
  {   2, "description" },
  {   3, "tree" },
  {   4, "value" },
  {   5, "connections" },
  { 0, NULL }
};


static int
dissect_glow_FieldFlags(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t Tuple_sequence_of[1] = {
  { &hf_glow_Tuple_item     , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_glow_Value },
};

static int
dissect_glow_Tuple(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Tuple_sequence_of, hf_index, ett_glow_Tuple);

  return offset;
}


static const ber_sequence_t Invocation_U_sequence[] = {
  { &hf_glow_invocationId   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_glow_Integer32 },
  { &hf_glow_arguments_01   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_glow_Tuple },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_Invocation_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Invocation_U_sequence, hf_index, ett_glow_Invocation_U);

  return offset;
}



static int
dissect_glow_Invocation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 22, true, dissect_glow_Invocation_U);

  return offset;
}


static const value_string glow_T_options_vals[] = {
  {   1, "dirFieldMask" },
  {   2, "invocation" },
  { 0, NULL }
};

static const ber_choice_t T_options_choice[] = {
  {   1, &hf_glow_dirFieldMask   , BER_CLASS_CON, 1, 0, dissect_glow_FieldFlags },
  {   2, &hf_glow_invocation     , BER_CLASS_CON, 2, 0, dissect_glow_Invocation },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_T_options(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_options_choice, hf_index, ett_glow_T_options,
                                 NULL);

  return offset;
}


static const ber_sequence_t Command_U_sequence[] = {
  { &hf_glow_number_01      , BER_CLASS_CON, 0, 0, dissect_glow_CommandType },
  { &hf_glow_options        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_glow_T_options },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_Command_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Command_U_sequence, hf_index, ett_glow_Command_U);

  return offset;
}



static int
dissect_glow_Command(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 2, true, dissect_glow_Command_U);

  return offset;
}


static const value_string glow_MatrixType_vals[] = {
  {   0, "oneToN" },
  {   1, "oneToOne" },
  {   2, "nToN" },
  { 0, NULL }
};


static int
dissect_glow_MatrixType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string glow_MatrixAddressingMode_vals[] = {
  {   0, "linear" },
  {   1, "nonLinear" },
  { 0, NULL }
};


static int
dissect_glow_MatrixAddressingMode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string glow_ParametersLocation_vals[] = {
  {   0, "basePath" },
  {   1, "inline" },
  { 0, NULL }
};

static const ber_choice_t ParametersLocation_choice[] = {
  {   0, &hf_glow_basePath       , BER_CLASS_UNI, BER_UNI_TAG_RELATIVE_OID, BER_FLAGS_NOOWNTAG, dissect_glow_RELATIVE_OID },
  {   1, &hf_glow_inline         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_glow_Integer32 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_ParametersLocation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ParametersLocation_choice, hf_index, ett_glow_ParametersLocation,
                                 NULL);

  return offset;
}


static const ber_sequence_t Label_U_sequence[] = {
  { &hf_glow_basePath       , BER_CLASS_CON, 0, 0, dissect_glow_RELATIVE_OID },
  { &hf_glow_description    , BER_CLASS_CON, 1, 0, dissect_glow_EmberString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_Label_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Label_U_sequence, hf_index, ett_glow_Label_U);

  return offset;
}



static int
dissect_glow_Label(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 18, true, dissect_glow_Label_U);

  return offset;
}


static const ber_sequence_t LabelCollection_sequence_of[1] = {
  { &hf_glow_LabelCollection_item, BER_CLASS_CON, 0, 0, dissect_glow_Label },
};

static int
dissect_glow_LabelCollection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      LabelCollection_sequence_of, hf_index, ett_glow_LabelCollection);

  return offset;
}


static const ber_sequence_t MatrixContents_set[] = {
  { &hf_glow_identifier     , BER_CLASS_CON, 0, 0, dissect_glow_EmberString },
  { &hf_glow_description    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_glow_EmberString },
  { &hf_glow_type_01        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_glow_MatrixType },
  { &hf_glow_addressingMode , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_glow_MatrixAddressingMode },
  { &hf_glow_targetCount    , BER_CLASS_CON, 4, 0, dissect_glow_Integer32 },
  { &hf_glow_sourceCount    , BER_CLASS_CON, 5, 0, dissect_glow_Integer32 },
  { &hf_glow_maximumTotalConnects, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_glow_Integer32 },
  { &hf_glow_maximumConnectsPerTarget, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_glow_Integer32 },
  { &hf_glow_parametersLocation, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_glow_ParametersLocation },
  { &hf_glow_gainParameterNumber, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_glow_Integer32 },
  { &hf_glow_labels         , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_glow_LabelCollection },
  { &hf_glow_schemaIdentifiers, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_glow_EmberString },
  { &hf_glow_templateReference, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_glow_RELATIVE_OID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_MatrixContents(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MatrixContents_set, hf_index, ett_glow_MatrixContents);

  return offset;
}


static const ber_sequence_t Signal_sequence[] = {
  { &hf_glow_number         , BER_CLASS_CON, 0, 0, dissect_glow_Integer32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_Signal(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Signal_sequence, hf_index, ett_glow_Signal);

  return offset;
}



static int
dissect_glow_Target(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 14, true, dissect_glow_Signal);

  return offset;
}


static const ber_sequence_t TargetCollection_sequence_of[1] = {
  { &hf_glow_TargetCollection_item, BER_CLASS_CON, 0, 0, dissect_glow_Target },
};

static int
dissect_glow_TargetCollection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      TargetCollection_sequence_of, hf_index, ett_glow_TargetCollection);

  return offset;
}



static int
dissect_glow_Source(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 15, true, dissect_glow_Signal);

  return offset;
}


static const ber_sequence_t SourceCollection_sequence_of[1] = {
  { &hf_glow_SourceCollection_item, BER_CLASS_CON, 0, 0, dissect_glow_Source },
};

static int
dissect_glow_SourceCollection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SourceCollection_sequence_of, hf_index, ett_glow_SourceCollection);

  return offset;
}



static int
dissect_glow_PackedNumbers(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_relative_oid(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string glow_ConnectionOperation_vals[] = {
  {   0, "absolute" },
  {   1, "connect" },
  {   2, "disconnect" },
  { 0, NULL }
};


static int
dissect_glow_ConnectionOperation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string glow_ConnectionDisposition_vals[] = {
  {   0, "tally" },
  {   1, "modified" },
  {   2, "pending" },
  {   3, "locked" },
  { 0, NULL }
};


static int
dissect_glow_ConnectionDisposition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t Connection_U_sequence[] = {
  { &hf_glow_target         , BER_CLASS_CON, 0, 0, dissect_glow_Integer32 },
  { &hf_glow_sources        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_glow_PackedNumbers },
  { &hf_glow_operation      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_glow_ConnectionOperation },
  { &hf_glow_disposition    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_glow_ConnectionDisposition },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_Connection_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Connection_U_sequence, hf_index, ett_glow_Connection_U);

  return offset;
}



static int
dissect_glow_Connection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 16, true, dissect_glow_Connection_U);

  return offset;
}


static const ber_sequence_t ConnectionCollection_sequence_of[1] = {
  { &hf_glow_ConnectionCollection_item, BER_CLASS_CON, 0, 0, dissect_glow_Connection },
};

static int
dissect_glow_ConnectionCollection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ConnectionCollection_sequence_of, hf_index, ett_glow_ConnectionCollection);

  return offset;
}


static const ber_sequence_t Matrix_U_sequence[] = {
  { &hf_glow_number         , BER_CLASS_CON, 0, 0, dissect_glow_Integer32 },
  { &hf_glow_contents_02    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_glow_MatrixContents },
  { &hf_glow_children       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_glow_ElementCollection },
  { &hf_glow_targetList     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_glow_TargetCollection },
  { &hf_glow_sourceList     , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_glow_SourceCollection },
  { &hf_glow_connections    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_glow_ConnectionCollection },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_Matrix_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Matrix_U_sequence, hf_index, ett_glow_Matrix_U);

  return offset;
}



static int
dissect_glow_Matrix(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 13, true, dissect_glow_Matrix_U);

  return offset;
}


static const ber_sequence_t TupleItemDescription_U_sequence[] = {
  { &hf_glow_type           , BER_CLASS_CON, 0, 0, dissect_glow_ParameterType },
  { &hf_glow_name           , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_glow_EmberString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_TupleItemDescription_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TupleItemDescription_U_sequence, hf_index, ett_glow_TupleItemDescription_U);

  return offset;
}



static int
dissect_glow_TupleItemDescription(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 21, true, dissect_glow_TupleItemDescription_U);

  return offset;
}


static const ber_sequence_t TupleDescription_sequence_of[1] = {
  { &hf_glow_TupleDescription_item, BER_CLASS_CON, 0, 0, dissect_glow_TupleItemDescription },
};

static int
dissect_glow_TupleDescription(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      TupleDescription_sequence_of, hf_index, ett_glow_TupleDescription);

  return offset;
}


static const ber_sequence_t FunctionContents_set[] = {
  { &hf_glow_identifier     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_glow_EmberString },
  { &hf_glow_description    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_glow_EmberString },
  { &hf_glow_arguments      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_glow_TupleDescription },
  { &hf_glow_result         , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_glow_TupleDescription },
  { &hf_glow_templateReference, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_glow_RELATIVE_OID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_FunctionContents(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              FunctionContents_set, hf_index, ett_glow_FunctionContents);

  return offset;
}


static const ber_sequence_t Function_U_sequence[] = {
  { &hf_glow_number         , BER_CLASS_CON, 0, 0, dissect_glow_Integer32 },
  { &hf_glow_contents_03    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_glow_FunctionContents },
  { &hf_glow_children       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_glow_ElementCollection },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_Function_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Function_U_sequence, hf_index, ett_glow_Function_U);

  return offset;
}



static int
dissect_glow_Function(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 19, true, dissect_glow_Function_U);

  return offset;
}


static const value_string glow_Element_vals[] = {
  {   1, "parameter" },
  {   3, "node" },
  {   2, "command" },
  {  13, "matrix" },
  {  19, "function" },
  {  24, "template" },
  { 0, NULL }
};

static const ber_choice_t Element_choice[] = {
  {   1, &hf_glow_parameter      , BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_glow_Parameter },
  {   3, &hf_glow_node           , BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_glow_Node },
  {   2, &hf_glow_command        , BER_CLASS_APP, 2, BER_FLAGS_NOOWNTAG, dissect_glow_Command },
  {  13, &hf_glow_matrix         , BER_CLASS_APP, 13, BER_FLAGS_NOOWNTAG, dissect_glow_Matrix },
  {  19, &hf_glow_function       , BER_CLASS_APP, 19, BER_FLAGS_NOOWNTAG, dissect_glow_Function },
  {  24, &hf_glow_template       , BER_CLASS_APP, 24, BER_FLAGS_NOOWNTAG, dissect_glow_Template },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_Element(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Element_choice, hf_index, ett_glow_Element,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Element_sequence_of[1] = {
  { &hf_glow__untag_item_01 , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_glow_Element },
};

static int
dissect_glow_SEQUENCE_OF_Element(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Element_sequence_of, hf_index, ett_glow_SEQUENCE_OF_Element);

  return offset;
}



static int
dissect_glow_ElementCollection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // ElementCollection -> ElementCollection/_untag -> Element -> Node -> Node/_untag -> ElementCollection
  actx->pinfo->dissection_depth += 5;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 4, true, dissect_glow_SEQUENCE_OF_Element);

  actx->pinfo->dissection_depth -= 5;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const ber_sequence_t Parameter_U_sequence[] = {
  { &hf_glow_number         , BER_CLASS_CON, 0, 0, dissect_glow_Integer32 },
  { &hf_glow_contents       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_glow_ParameterContents },
  { &hf_glow_children       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_glow_ElementCollection },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_Parameter_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Parameter_U_sequence, hf_index, ett_glow_Parameter_U);

  return offset;
}



static int
dissect_glow_Parameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // Parameter -> Parameter/_untag -> ElementCollection -> ElementCollection/_untag -> Element -> Parameter
  actx->pinfo->dissection_depth += 5;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 1, true, dissect_glow_Parameter_U);

  actx->pinfo->dissection_depth -= 5;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const value_string glow_TemplateElement_vals[] = {
  {   1, "parameter" },
  {   3, "node" },
  {  13, "matrix" },
  {  19, "function" },
  { 0, NULL }
};

static const ber_choice_t TemplateElement_choice[] = {
  {   1, &hf_glow_parameter      , BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_glow_Parameter },
  {   3, &hf_glow_node           , BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_glow_Node },
  {  13, &hf_glow_matrix         , BER_CLASS_APP, 13, BER_FLAGS_NOOWNTAG, dissect_glow_Matrix },
  {  19, &hf_glow_function       , BER_CLASS_APP, 19, BER_FLAGS_NOOWNTAG, dissect_glow_Function },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_TemplateElement(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TemplateElement_choice, hf_index, ett_glow_TemplateElement,
                                 NULL);

  return offset;
}


static const ber_sequence_t Template_U_set[] = {
  { &hf_glow_number         , BER_CLASS_CON, 0, 0, dissect_glow_Integer32 },
  { &hf_glow_element        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_glow_TemplateElement },
  { &hf_glow_description    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_glow_EmberString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_Template_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              Template_U_set, hf_index, ett_glow_Template_U);

  return offset;
}



static int
dissect_glow_Template(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // Template -> Template/_untag -> TemplateElement -> Parameter -> Parameter/_untag -> ElementCollection -> ElementCollection/_untag -> Element -> Template
  actx->pinfo->dissection_depth += 8;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 24, true, dissect_glow_Template_U);

  actx->pinfo->dissection_depth -= 8;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const ber_sequence_t QualifiedTemplate_U_set[] = {
  { &hf_glow_path           , BER_CLASS_CON, 0, 0, dissect_glow_RELATIVE_OID },
  { &hf_glow_element        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_glow_TemplateElement },
  { &hf_glow_description    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_glow_EmberString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_QualifiedTemplate_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              QualifiedTemplate_U_set, hf_index, ett_glow_QualifiedTemplate_U);

  return offset;
}



static int
dissect_glow_QualifiedTemplate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 25, true, dissect_glow_QualifiedTemplate_U);

  return offset;
}


static const ber_sequence_t QualifiedParameter_U_sequence[] = {
  { &hf_glow_path           , BER_CLASS_CON, 0, 0, dissect_glow_RELATIVE_OID },
  { &hf_glow_contents       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_glow_ParameterContents },
  { &hf_glow_children       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_glow_ElementCollection },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_QualifiedParameter_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   QualifiedParameter_U_sequence, hf_index, ett_glow_QualifiedParameter_U);

  return offset;
}



static int
dissect_glow_QualifiedParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 9, true, dissect_glow_QualifiedParameter_U);

  return offset;
}


static const ber_sequence_t QualifiedNode_U_sequence[] = {
  { &hf_glow_path           , BER_CLASS_CON, 0, 0, dissect_glow_RELATIVE_OID },
  { &hf_glow_contents_01    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_glow_NodeContents },
  { &hf_glow_children       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_glow_ElementCollection },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_QualifiedNode_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   QualifiedNode_U_sequence, hf_index, ett_glow_QualifiedNode_U);

  return offset;
}



static int
dissect_glow_QualifiedNode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 10, true, dissect_glow_QualifiedNode_U);

  return offset;
}


static const ber_sequence_t QualifiedMatrix_U_sequence[] = {
  { &hf_glow_path           , BER_CLASS_CON, 0, 0, dissect_glow_RELATIVE_OID },
  { &hf_glow_contents_02    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_glow_MatrixContents },
  { &hf_glow_children       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_glow_ElementCollection },
  { &hf_glow_targetList     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_glow_TargetCollection },
  { &hf_glow_sourceList     , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_glow_SourceCollection },
  { &hf_glow_connections    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_glow_ConnectionCollection },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_QualifiedMatrix_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   QualifiedMatrix_U_sequence, hf_index, ett_glow_QualifiedMatrix_U);

  return offset;
}



static int
dissect_glow_QualifiedMatrix(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 17, true, dissect_glow_QualifiedMatrix_U);

  return offset;
}


static const ber_sequence_t QualifiedFunction_U_sequence[] = {
  { &hf_glow_path           , BER_CLASS_CON, 0, 0, dissect_glow_RELATIVE_OID },
  { &hf_glow_contents_03    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_glow_FunctionContents },
  { &hf_glow_children       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_glow_ElementCollection },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_QualifiedFunction_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   QualifiedFunction_U_sequence, hf_index, ett_glow_QualifiedFunction_U);

  return offset;
}



static int
dissect_glow_QualifiedFunction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 20, true, dissect_glow_QualifiedFunction_U);

  return offset;
}


static const ber_sequence_t InvocationResult_U_sequence[] = {
  { &hf_glow_invocationId   , BER_CLASS_CON, 0, 0, dissect_glow_Integer32 },
  { &hf_glow_success        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_glow_BOOLEAN },
  { &hf_glow_result_01      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_glow_Tuple },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_InvocationResult_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InvocationResult_U_sequence, hf_index, ett_glow_InvocationResult_U);

  return offset;
}



static int
dissect_glow_InvocationResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 23, true, dissect_glow_InvocationResult_U);

  return offset;
}


static const ber_sequence_t StreamEntry_U_sequence[] = {
  { &hf_glow_streamIdentifier, BER_CLASS_CON, 0, 0, dissect_glow_Integer32 },
  { &hf_glow_streamValue    , BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_glow_Value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_StreamEntry_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StreamEntry_U_sequence, hf_index, ett_glow_StreamEntry_U);

  return offset;
}



static int
dissect_glow_StreamEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 5, true, dissect_glow_StreamEntry_U);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_StreamEntry_sequence_of[1] = {
  { &hf_glow__untag_item_02 , BER_CLASS_CON, 0, 0, dissect_glow_StreamEntry },
};

static int
dissect_glow_SEQUENCE_OF_StreamEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_StreamEntry_sequence_of, hf_index, ett_glow_SEQUENCE_OF_StreamEntry);

  return offset;
}



static int
dissect_glow_StreamCollection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 6, true, dissect_glow_SEQUENCE_OF_StreamEntry);

  return offset;
}


static const value_string glow_RootElement_vals[] = {
  {   0, "element" },
  {   1, "qualifiedParameter" },
  {   2, "qualifiedNode" },
  {   3, "qualifiedMatrix" },
  {   4, "qualifiedFunction" },
  {   5, "qualifiedTemplate" },
  { 0, NULL }
};

static const ber_choice_t RootElement_choice[] = {
  {   0, &hf_glow_element_01     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_glow_Element },
  {   1, &hf_glow_qualifiedParameter, BER_CLASS_APP, 9, BER_FLAGS_NOOWNTAG, dissect_glow_QualifiedParameter },
  {   2, &hf_glow_qualifiedNode  , BER_CLASS_APP, 10, BER_FLAGS_NOOWNTAG, dissect_glow_QualifiedNode },
  {   3, &hf_glow_qualifiedMatrix, BER_CLASS_APP, 17, BER_FLAGS_NOOWNTAG, dissect_glow_QualifiedMatrix },
  {   4, &hf_glow_qualifiedFunction, BER_CLASS_APP, 20, BER_FLAGS_NOOWNTAG, dissect_glow_QualifiedFunction },
  {   5, &hf_glow_qualifiedTemplate, BER_CLASS_APP, 25, BER_FLAGS_NOOWNTAG, dissect_glow_QualifiedTemplate },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_RootElement(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RootElement_choice, hf_index, ett_glow_RootElement,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_RootElement_sequence_of[1] = {
  { &hf_glow__untag_item_03 , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_glow_RootElement },
};

static int
dissect_glow_SEQUENCE_OF_RootElement(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_RootElement_sequence_of, hf_index, ett_glow_SEQUENCE_OF_RootElement);

  return offset;
}



static int
dissect_glow_RootElementCollection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 11, true, dissect_glow_SEQUENCE_OF_RootElement);

  return offset;
}


static const value_string glow_Root_U_vals[] = {
  {  11, "elements" },
  {   6, "streams" },
  {  23, "invocationResult" },
  { 0, NULL }
};

static const ber_choice_t Root_U_choice[] = {
  {  11, &hf_glow_elements       , BER_CLASS_APP, 11, BER_FLAGS_NOOWNTAG, dissect_glow_RootElementCollection },
  {   6, &hf_glow_streams        , BER_CLASS_APP, 6, BER_FLAGS_NOOWNTAG, dissect_glow_StreamCollection },
  {  23, &hf_glow_invocationResult, BER_CLASS_APP, 23, BER_FLAGS_NOOWNTAG, dissect_glow_InvocationResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_glow_Root_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Root_U_choice, hf_index, ett_glow_Root_U,
                                 NULL);

  return offset;
}



static int
dissect_glow_Root(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, false, dissect_glow_Root_U);

  return offset;
}

/*--- PDUs ---*/

static int dissect_Root_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_glow_Root(false, tvb, offset, &asn1_ctx, tree, hf_glow_Root_PDU);
  return offset;
}


static int
dissect_glow(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item      *glow_item = NULL;
    proto_tree      *glow_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);

    /* create the glow protocol tree */
    glow_item = proto_tree_add_item(tree, proto_glow, tvb, 0, -1, ENC_NA);
    glow_tree = proto_item_add_subtree(glow_item, ett_glow);

    dissect_Root_PDU(tvb, pinfo, glow_tree, data);

    return tvb_captured_length(tvb);
}

void proto_register_glow(void) {

  /* List of fields */
  static hf_register_info hf[] = {

    { &hf_glow_Root_PDU,
      { "Root", "glow.Root",
        FT_UINT32, BASE_DEC, VALS(glow_Root_U_vals), 0,
        NULL, HFILL }},
    { &hf_glow_number,
      { "number", "glow.number",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_glow_element,
      { "element", "glow.element",
        FT_UINT32, BASE_DEC, VALS(glow_TemplateElement_vals), 0,
        "TemplateElement", HFILL }},
    { &hf_glow_description,
      { "description", "glow.description",
        FT_STRING, BASE_NONE, NULL, 0,
        "EmberString", HFILL }},
    { &hf_glow_path,
      { "path", "glow.path",
        FT_REL_OID, BASE_NONE, NULL, 0,
        "RELATIVE_OID", HFILL }},
    { &hf_glow_parameter,
      { "parameter", "glow.parameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_node,
      { "node", "glow.node_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_matrix,
      { "matrix", "glow.matrix_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_function,
      { "function", "glow.function_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_contents,
      { "contents", "glow.contents_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ParameterContents", HFILL }},
    { &hf_glow_children,
      { "children", "glow.children",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ElementCollection", HFILL }},
    { &hf_glow_identifier,
      { "identifier", "glow.identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "EmberString", HFILL }},
    { &hf_glow_value,
      { "value", "glow.value",
        FT_UINT32, BASE_DEC, VALS(glow_Value_vals), 0,
        NULL, HFILL }},
    { &hf_glow_minimum,
      { "minimum", "glow.minimum",
        FT_UINT32, BASE_DEC, VALS(glow_MinMax_vals), 0,
        "MinMax", HFILL }},
    { &hf_glow_maximum,
      { "maximum", "glow.maximum",
        FT_UINT32, BASE_DEC, VALS(glow_MinMax_vals), 0,
        "MinMax", HFILL }},
    { &hf_glow_access,
      { "access", "glow.access",
        FT_INT32, BASE_DEC, VALS(glow_ParameterAccess_vals), 0,
        "ParameterAccess", HFILL }},
    { &hf_glow_format,
      { "format", "glow.format",
        FT_STRING, BASE_NONE, NULL, 0,
        "EmberString", HFILL }},
    { &hf_glow_enumeration,
      { "enumeration", "glow.enumeration",
        FT_STRING, BASE_NONE, NULL, 0,
        "EmberString", HFILL }},
    { &hf_glow_factor,
      { "factor", "glow.factor",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_glow_isOnline,
      { "isOnline", "glow.isOnline",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_glow_formula,
      { "formula", "glow.formula",
        FT_STRING, BASE_NONE, NULL, 0,
        "EmberString", HFILL }},
    { &hf_glow_step,
      { "step", "glow.step",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_glow_default,
      { "default", "glow.default",
        FT_UINT32, BASE_DEC, VALS(glow_Value_vals), 0,
        "Value", HFILL }},
    { &hf_glow_type,
      { "type", "glow.type",
        FT_INT32, BASE_DEC, VALS(glow_ParameterType_vals), 0,
        "ParameterType", HFILL }},
    { &hf_glow_streamIdentifier,
      { "streamIdentifier", "glow.streamIdentifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_glow_enumMap,
      { "enumMap", "glow.enumMap",
        FT_UINT32, BASE_DEC, NULL, 0,
        "StringIntegerCollection", HFILL }},
    { &hf_glow_streamDescriptor,
      { "streamDescriptor", "glow.streamDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StreamDescription", HFILL }},
    { &hf_glow_schemaIdentifiers,
      { "schemaIdentifiers", "glow.schemaIdentifiers",
        FT_STRING, BASE_NONE, NULL, 0,
        "EmberString", HFILL }},
    { &hf_glow_templateReference,
      { "templateReference", "glow.templateReference",
        FT_REL_OID, BASE_NONE, NULL, 0,
        "RELATIVE_OID", HFILL }},
    { &hf_glow_integer,
      { "integer", "glow.integer",
        FT_INT64, BASE_DEC, NULL, 0,
        "Integer64", HFILL }},
    { &hf_glow_real,
      { "real", "glow.real",
        FT_DOUBLE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_string,
      { "string", "glow.string",
        FT_STRING, BASE_NONE, NULL, 0,
        "EmberString", HFILL }},
    { &hf_glow_boolean,
      { "boolean", "glow.boolean",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_octets,
      { "octets", "glow.octets",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_glow_null,
      { "null", "glow.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_entryString,
      { "entryString", "glow.entryString",
        FT_STRING, BASE_NONE, NULL, 0,
        "EmberString", HFILL }},
    { &hf_glow_entryInteger,
      { "entryInteger", "glow.entryInteger",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_glow__untag_item,
      { "StringIntegerPair", "glow.StringIntegerPair_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_streamFormat,
      { "streamFormat", "glow.streamFormat",
        FT_INT32, BASE_DEC, VALS(glow_StreamFormat_vals), 0,
        NULL, HFILL }},
    { &hf_glow_offset,
      { "offset", "glow.offset",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_glow_number_01,
      { "number", "glow.number",
        FT_INT32, BASE_DEC, VALS(glow_CommandType_vals), 0,
        "CommandType", HFILL }},
    { &hf_glow_options,
      { "options", "glow.options",
        FT_UINT32, BASE_DEC, VALS(glow_T_options_vals), 0,
        NULL, HFILL }},
    { &hf_glow_dirFieldMask,
      { "dirFieldMask", "glow.dirFieldMask",
        FT_INT32, BASE_DEC, VALS(glow_FieldFlags_vals), 0,
        "FieldFlags", HFILL }},
    { &hf_glow_invocation,
      { "invocation", "glow.invocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_contents_01,
      { "contents", "glow.contents_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NodeContents", HFILL }},
    { &hf_glow_isRoot,
      { "isRoot", "glow.isRoot",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_glow_contents_02,
      { "contents", "glow.contents_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MatrixContents", HFILL }},
    { &hf_glow_targetList,
      { "targetList", "glow.targetList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TargetCollection", HFILL }},
    { &hf_glow_sourceList,
      { "sourceList", "glow.sourceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SourceCollection", HFILL }},
    { &hf_glow_connections,
      { "connections", "glow.connections",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ConnectionCollection", HFILL }},
    { &hf_glow_type_01,
      { "type", "glow.type",
        FT_INT32, BASE_DEC, VALS(glow_MatrixType_vals), 0,
        "MatrixType", HFILL }},
    { &hf_glow_addressingMode,
      { "addressingMode", "glow.addressingMode",
        FT_INT32, BASE_DEC, VALS(glow_MatrixAddressingMode_vals), 0,
        "MatrixAddressingMode", HFILL }},
    { &hf_glow_targetCount,
      { "targetCount", "glow.targetCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_glow_sourceCount,
      { "sourceCount", "glow.sourceCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_glow_maximumTotalConnects,
      { "maximumTotalConnects", "glow.maximumTotalConnects",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_glow_maximumConnectsPerTarget,
      { "maximumConnectsPerTarget", "glow.maximumConnectsPerTarget",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_glow_parametersLocation,
      { "parametersLocation", "glow.parametersLocation",
        FT_UINT32, BASE_DEC, VALS(glow_ParametersLocation_vals), 0,
        NULL, HFILL }},
    { &hf_glow_gainParameterNumber,
      { "gainParameterNumber", "glow.gainParameterNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_glow_labels,
      { "labels", "glow.labels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LabelCollection", HFILL }},
    { &hf_glow_basePath,
      { "basePath", "glow.basePath",
        FT_REL_OID, BASE_NONE, NULL, 0,
        "RELATIVE_OID", HFILL }},
    { &hf_glow_inline,
      { "inline", "glow.inline",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_glow_LabelCollection_item,
      { "Label", "glow.Label_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_TargetCollection_item,
      { "Target", "glow.Target_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_SourceCollection_item,
      { "Source", "glow.Source_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_ConnectionCollection_item,
      { "Connection", "glow.Connection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_target,
      { "target", "glow.target",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_glow_sources,
      { "sources", "glow.sources",
        FT_REL_OID, BASE_NONE, NULL, 0,
        "PackedNumbers", HFILL }},
    { &hf_glow_operation,
      { "operation", "glow.operation",
        FT_INT32, BASE_DEC, VALS(glow_ConnectionOperation_vals), 0,
        "ConnectionOperation", HFILL }},
    { &hf_glow_disposition,
      { "disposition", "glow.disposition",
        FT_INT32, BASE_DEC, VALS(glow_ConnectionDisposition_vals), 0,
        "ConnectionDisposition", HFILL }},
    { &hf_glow_contents_03,
      { "contents", "glow.contents_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FunctionContents", HFILL }},
    { &hf_glow_arguments,
      { "arguments", "glow.arguments",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TupleDescription", HFILL }},
    { &hf_glow_result,
      { "result", "glow.result",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TupleDescription", HFILL }},
    { &hf_glow_TupleDescription_item,
      { "TupleItemDescription", "glow.TupleItemDescription_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_name,
      { "name", "glow.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "EmberString", HFILL }},
    { &hf_glow_invocationId,
      { "invocationId", "glow.invocationId",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_glow_arguments_01,
      { "arguments", "glow.arguments",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Tuple", HFILL }},
    { &hf_glow_Tuple_item,
      { "Value", "glow.Value",
        FT_UINT32, BASE_DEC, VALS(glow_Value_vals), 0,
        NULL, HFILL }},
    { &hf_glow_success,
      { "success", "glow.success",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_glow_result_01,
      { "result", "glow.result",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Tuple", HFILL }},
    { &hf_glow__untag_item_01,
      { "Element", "glow.Element",
        FT_UINT32, BASE_DEC, VALS(glow_Element_vals), 0,
        NULL, HFILL }},
    { &hf_glow_command,
      { "command", "glow.command_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_template,
      { "template", "glow.template_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_streamValue,
      { "streamValue", "glow.streamValue",
        FT_UINT32, BASE_DEC, VALS(glow_Value_vals), 0,
        "Value", HFILL }},
    { &hf_glow__untag_item_02,
      { "StreamEntry", "glow.StreamEntry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_elements,
      { "elements", "glow.elements",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RootElementCollection", HFILL }},
    { &hf_glow_streams,
      { "streams", "glow.streams",
        FT_UINT32, BASE_DEC, NULL, 0,
        "StreamCollection", HFILL }},
    { &hf_glow_invocationResult,
      { "invocationResult", "glow.invocationResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow__untag_item_03,
      { "RootElement", "glow.RootElement",
        FT_UINT32, BASE_DEC, VALS(glow_RootElement_vals), 0,
        NULL, HFILL }},
    { &hf_glow_element_01,
      { "element", "glow.element",
        FT_UINT32, BASE_DEC, VALS(glow_Element_vals), 0,
        NULL, HFILL }},
    { &hf_glow_qualifiedParameter,
      { "qualifiedParameter", "glow.qualifiedParameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_qualifiedNode,
      { "qualifiedNode", "glow.qualifiedNode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_qualifiedMatrix,
      { "qualifiedMatrix", "glow.qualifiedMatrix_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_qualifiedFunction,
      { "qualifiedFunction", "glow.qualifiedFunction_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_glow_qualifiedTemplate,
      { "qualifiedTemplate", "glow.qualifiedTemplate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
                  &ett_glow,
    &ett_glow_Template_U,
    &ett_glow_QualifiedTemplate_U,
    &ett_glow_TemplateElement,
    &ett_glow_Parameter_U,
    &ett_glow_QualifiedParameter_U,
    &ett_glow_ParameterContents,
    &ett_glow_Value,
    &ett_glow_MinMax,
    &ett_glow_StringIntegerPair_U,
    &ett_glow_SEQUENCE_OF_StringIntegerPair,
    &ett_glow_StreamDescription_U,
    &ett_glow_Command_U,
    &ett_glow_T_options,
    &ett_glow_Node_U,
    &ett_glow_QualifiedNode_U,
    &ett_glow_NodeContents,
    &ett_glow_Matrix_U,
    &ett_glow_MatrixContents,
    &ett_glow_ParametersLocation,
    &ett_glow_LabelCollection,
    &ett_glow_Label_U,
    &ett_glow_TargetCollection,
    &ett_glow_Signal,
    &ett_glow_SourceCollection,
    &ett_glow_ConnectionCollection,
    &ett_glow_Connection_U,
    &ett_glow_QualifiedMatrix_U,
    &ett_glow_Function_U,
    &ett_glow_QualifiedFunction_U,
    &ett_glow_FunctionContents,
    &ett_glow_TupleDescription,
    &ett_glow_TupleItemDescription_U,
    &ett_glow_Invocation_U,
    &ett_glow_Tuple,
    &ett_glow_InvocationResult_U,
    &ett_glow_SEQUENCE_OF_Element,
    &ett_glow_Element,
    &ett_glow_StreamEntry_U,
    &ett_glow_SEQUENCE_OF_StreamEntry,
    &ett_glow_Root_U,
    &ett_glow_SEQUENCE_OF_RootElement,
    &ett_glow_RootElement,
  };


  /* Register protocol */
  proto_glow = proto_register_protocol(PNAME, PSNAME, PFNAME);
  glow_handle = register_dissector("glow", dissect_glow, proto_glow);

  /* Register fields and subtrees */
  proto_register_field_array(proto_glow, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
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

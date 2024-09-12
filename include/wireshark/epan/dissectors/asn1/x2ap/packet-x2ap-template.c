/* packet-x2ap.c
 * Routines for dissecting Evolved Universal Terrestrial Radio Access Network (EUTRAN);
 * X2 Application Protocol (X2AP);
 * 3GPP TS 36.423 packet dissection
 * Copyright 2007-2014, Anders Broman <anders.broman@ericsson.com>
 * Copyright 2016-2024, Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref:
 * 3GPP TS 36.423 V18.2.0 (2024-06)
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/tfs.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/proto_data.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <wsutil/array.h>

#include "packet-x2ap.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-lte-rrc.h"
#include "packet-nr-rrc.h"
#include "packet-ngap.h"
#include "packet-ranap.h"
#include "packet-ntp.h"
#include "packet-s1ap.h"
#include "packet-f1ap.h"
#include "packet-xnap.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "EUTRAN X2 Application Protocol (X2AP)"
#define PSNAME "X2AP"
#define PFNAME "x2ap"

void proto_register_x2ap(void);

/* Dissector will use SCTP PPID 27 or SCTP port. IANA assigned port = 36422 */
#define SCTP_PORT_X2AP	36422

#include "packet-x2ap-val.h"

/* Initialize the protocol and registered fields */
static int proto_x2ap;
static int hf_x2ap_transportLayerAddressIPv4;
static int hf_x2ap_transportLayerAddressIPv6;
static int hf_x2ap_ReportCharacteristics_PRBPeriodic;
static int hf_x2ap_ReportCharacteristics_TNLLoadIndPeriodic;
static int hf_x2ap_ReportCharacteristics_HWLoadIndPeriodic;
static int hf_x2ap_ReportCharacteristics_CompositeAvailableCapacityPeriodic;
static int hf_x2ap_ReportCharacteristics_ABSStatusPeriodic;
static int hf_x2ap_ReportCharacteristics_RSRPMeasurementReportPeriodic;
static int hf_x2ap_ReportCharacteristics_CSIReportPeriodic;
static int hf_x2ap_ReportCharacteristics_Reserved;
static int hf_x2ap_measurementFailedReportCharacteristics_PRBPeriodic;
static int hf_x2ap_measurementFailedReportCharacteristics_TNLLoadIndPeriodic;
static int hf_x2ap_measurementFailedReportCharacteristics_HWLoadIndPeriodic;
static int hf_x2ap_measurementFailedReportCharacteristics_CompositeAvailableCapacityPeriodic;
static int hf_x2ap_measurementFailedReportCharacteristics_ABSStatusPeriodic;
static int hf_x2ap_measurementFailedReportCharacteristics_RSRPMeasurementReportPeriodic;
static int hf_x2ap_measurementFailedReportCharacteristics_CSIReportPeriodic;
static int hf_x2ap_measurementFailedReportCharacteristics_Reserved;
static int hf_x2ap_eUTRANTraceID_TraceID;
static int hf_x2ap_eUTRANTraceID_TraceRecordingSessionReference;
static int hf_x2ap_interfacesToTrace_S1_MME;
static int hf_x2ap_interfacesToTrace_X2;
static int hf_x2ap_interfacesToTrace_Uu;
static int hf_x2ap_interfacesToTrace_F1_C;
static int hf_x2ap_interfacesToTrace_E1;
static int hf_x2ap_interfacesToTrace_Reserved;
static int hf_x2ap_traceCollectionEntityIPAddress_IPv4;
static int hf_x2ap_traceCollectionEntityIPAddress_IPv6;
static int hf_x2ap_encryptionAlgorithms_EEA1;
static int hf_x2ap_encryptionAlgorithms_EEA2;
static int hf_x2ap_encryptionAlgorithms_EEA3;
static int hf_x2ap_encryptionAlgorithms_Reserved;
static int hf_x2ap_integrityProtectionAlgorithms_EIA1;
static int hf_x2ap_integrityProtectionAlgorithms_EIA2;
static int hf_x2ap_integrityProtectionAlgorithms_EIA3;
static int hf_x2ap_integrityProtectionAlgorithms_EIA7;
static int hf_x2ap_integrityProtectionAlgorithms_Reserved;
static int hf_x2ap_measurementsToActivate_M1;
static int hf_x2ap_measurementsToActivate_M2;
static int hf_x2ap_measurementsToActivate_M3;
static int hf_x2ap_measurementsToActivate_M4;
static int hf_x2ap_measurementsToActivate_M5;
static int hf_x2ap_measurementsToActivate_LoggingM1FromEventTriggered;
static int hf_x2ap_measurementsToActivate_M6;
static int hf_x2ap_measurementsToActivate_M7;
static int hf_x2ap_MDT_Location_Info_GNSS;
static int hf_x2ap_MDT_Location_Info_E_CID;
static int hf_x2ap_MDT_Location_Info_Reserved;
static int hf_x2ap_MDT_transmissionModes_tm1;
static int hf_x2ap_MDT_transmissionModes_tm2;
static int hf_x2ap_MDT_transmissionModes_tm3;
static int hf_x2ap_MDT_transmissionModes_tm4;
static int hf_x2ap_MDT_transmissionModes_tm6;
static int hf_x2ap_MDT_transmissionModes_tm8;
static int hf_x2ap_MDT_transmissionModes_tm9;
static int hf_x2ap_MDT_transmissionModes_tm10;
static int hf_x2ap_NRencryptionAlgorithms_NEA1;
static int hf_x2ap_NRencryptionAlgorithms_NEA2;
static int hf_x2ap_NRencryptionAlgorithms_NEA3;
static int hf_x2ap_NRencryptionAlgorithms_Reserved;
static int hf_x2ap_NRintegrityProtectionAlgorithms_NIA1;
static int hf_x2ap_NRintegrityProtectionAlgorithms_NIA2;
static int hf_x2ap_NRintegrityProtectionAlgorithms_NIA3;
static int hf_x2ap_NRintegrityProtectionAlgorithms_Reserved;
static int hf_x2ap_ReportCharacteristics_ENDC_PRBPeriodic;
static int hf_x2ap_ReportCharacteristics_ENDC_TNLCapacityIndPeriodic;
static int hf_x2ap_ReportCharacteristics_ENDC_CompositeAvailableCapacityPeriodic;
static int hf_x2ap_ReportCharacteristics_ENDC_NumberOfActiveUEs;
static int hf_x2ap_ReportCharacteristics_ENDC_Reserved;
static int hf_x2ap_Registration_Request_ENDC_PDU;
static int hf_x2ap_ReportingPeriodicity_ENDC_PDU;
static int hf_x2ap_ReportCharacteristics_ENDC_PDU;
static int hf_x2ap_rAT_RestrictionInformation_LEO;
static int hf_x2ap_rAT_RestrictionInformation_MEO;
static int hf_x2ap_rAT_RestrictionInformation_GEO;
static int hf_x2ap_rAT_RestrictionInformation_OTHERSAT;
static int hf_x2ap_rAT_RestrictionInformation_NR_LEO;
static int hf_x2ap_rAT_RestrictionInformation_NR_MEO;
static int hf_x2ap_rAT_RestrictionInformation_NR_GEO;
static int hf_x2ap_rAT_RestrictionInformation_NR_OTHERSAT;
#include "packet-x2ap-hf.c"

/* Initialize the subtree pointers */
static int ett_x2ap;
static int ett_x2ap_TransportLayerAddress;
static int ett_x2ap_PLMN_Identity;
static int ett_x2ap_TargeteNBtoSource_eNBTransparentContainer;
static int ett_x2ap_RRC_Context;
static int ett_x2ap_UE_HistoryInformationFromTheUE;
static int ett_x2ap_ReportCharacteristics;
static int ett_x2ap_measurementFailedReportCharacteristics;
static int ett_x2ap_UE_RLF_Report_Container;
static int ett_x2ap_UE_RLF_Report_Container_for_extended_bands;
static int ett_x2ap_MeNBtoSeNBContainer;
static int ett_x2ap_SeNBtoMeNBContainer;
static int ett_x2ap_EUTRANTraceID;
static int ett_x2ap_InterfacesToTrace;
static int ett_x2ap_TraceCollectionEntityIPAddress;
static int ett_x2ap_EncryptionAlgorithms;
static int ett_x2ap_IntegrityProtectionAlgorithms;
static int ett_x2ap_MeasurementsToActivate;
static int ett_x2ap_MDT_Location_Info;
static int ett_x2ap_transmissionModes;
static int ett_x2ap_X2AP_Message;
static int ett_x2ap_MeNBtoSgNBContainer;
static int ett_x2ap_SgNBtoMeNBContainer;
static int ett_x2ap_RRCContainer;
static int ett_x2ap_NRencryptionAlgorithms;
static int ett_x2ap_NRintegrityProtectionAlgorithms;
static int ett_x2ap_measurementTimingConfiguration;
static int ett_x2ap_LastVisitedNGRANCellInformation;
static int ett_x2ap_LastVisitedUTRANCellInformation;
static int ett_x2ap_EndcSONConfigurationTransfer;
static int ett_x2ap_EPCHandoverRestrictionListContainer;
static int ett_x2ap_NBIoT_RLF_Report_Container;
static int ett_x2ap_anchorCarrier_NPRACHConfig;
static int ett_x2ap_anchorCarrier_EDT_NPRACHConfig;
static int ett_x2ap_anchorCarrier_Format2_NPRACHConfig;
static int ett_x2ap_anchorCarrier_Format2_EDT_NPRACHConfig;
static int ett_x2ap_non_anchorCarrier_NPRACHConfig;
static int ett_x2ap_non_anchorCarrier_Format2_NPRACHConfig;
static int ett_x2ap_anchorCarrier_NPRACHConfigTDD;
static int ett_x2ap_non_anchorCarrier_NPRACHConfigTDD;
static int ett_x2ap_Non_anchorCarrierFrequency;
static int ett_x2ap_ReportCharacteristics_ENDC;
static int ett_x2ap_TargetCellInNGRAN;
static int ett_x2ap_TDDULDLConfigurationCommonNR;
static int ett_x2ap_MDT_ConfigurationNR;
static int ett_x2ap_NRCellPRACHConfig;
static int ett_x2ap_IntendedTDD_DL_ULConfiguration_NR;
static int ett_x2ap_UERadioCapability;
static int ett_x2ap_LastVisitedPSCell_Item;
static int ett_x2ap_NRRAReportContainer;
static int ett_x2ap_rAT_RestrictionInformation;
static int ett_x2ap_PSCellListContainer;
#include "packet-x2ap-ett.c"

/* Forward declarations */
static int dissect_x2ap_Registration_Request_ENDC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_x2ap_ReportCharacteristics_ENDC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_x2ap_ReportingPeriodicity_ENDC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

typedef enum {
  RRC_CONTAINER_TYPE_UNKNOWN,
  RRC_CONTAINER_TYPE_PDCP_C_PDU,
  RRC_CONTAINER_TYPE_NR_UE_MEAS_REPORT,
  RRC_CONTAINER_TYPE_FAST_MCG_RECOVERY_SgNB_TO_MeNB,
  RRC_CONTAINER_TYPE_FAST_MCG_RECOVERY_MeNB_TO_SgNB
} rrc_container_type_e;

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

struct x2ap_private_data {
  uint32_t procedure_code;
  uint32_t protocol_ie_id;
  uint32_t message_type;
  rrc_container_type_e rrc_container_type;
  e212_number_type_t number_type;
};

enum {
  X2AP_RRC_CONTEXT_LTE,
  X2AP_RRC_CONTEXT_NBIOT
};

static const enum_val_t x2ap_rrc_context_vals[] = {
  {"lte", "LTE", X2AP_RRC_CONTEXT_LTE},
  {"nb-iot","NB-IoT", X2AP_RRC_CONTEXT_NBIOT},
  {NULL, NULL, -1}
};

/* Global variables */
static int g_x2ap_dissect_rrc_context_as = X2AP_RRC_CONTEXT_LTE;

/* Dissector tables */
static dissector_table_t x2ap_ies_dissector_table;
static dissector_table_t x2ap_extension_dissector_table;
static dissector_table_t x2ap_proc_imsg_dissector_table;
static dissector_table_t x2ap_proc_sout_dissector_table;
static dissector_table_t x2ap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_X2AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
void proto_reg_handoff_x2ap(void);

static dissector_handle_t x2ap_handle;

static const true_false_string x2ap_tfs_failed_succeeded = {
  "Failed",
  "Succeeded"
};

static void
x2ap_Time_UE_StayedInCell_EnhancedGranularity_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fs", ((float)v)/10);
}

static void
x2ap_handoverTriggerChange_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB (%d)", ((float)v)/2, (int32_t)v);
}

static void
x2ap_Threshold_RSRP_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%ddBm (%u)", (int32_t)v-140, v);
}

static void
x2ap_Threshold_RSRQ_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB (%u)", ((float)v/2)-20, v);
}

static void
x2ap_Packet_LossRate_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1f %% (%u)", (float)v/10, v);
}

static void
x2ap_cho_handover_window_duration_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%dms (%u)", v*100, v);
}

static struct x2ap_private_data*
x2ap_get_private_data(packet_info *pinfo)
{
  struct x2ap_private_data *x2ap_data = (struct x2ap_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_x2ap, 0);
  if (!x2ap_data) {
    x2ap_data = wmem_new0(pinfo->pool, struct x2ap_private_data);
    p_add_proto_data(pinfo->pool, pinfo, proto_x2ap, 0, x2ap_data);
  }
  return x2ap_data;
}

#include "packet-x2ap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct x2ap_private_data *x2ap_data = x2ap_get_private_data(pinfo);

  return (dissector_try_uint_new(x2ap_ies_dissector_table, x2ap_data->protocol_ie_id, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct x2ap_private_data *x2ap_data = x2ap_get_private_data(pinfo);

  return (dissector_try_uint_new(x2ap_extension_dissector_table, x2ap_data->protocol_ie_id, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct x2ap_private_data *x2ap_data = x2ap_get_private_data(pinfo);

  x2ap_data->message_type = INITIATING_MESSAGE;
  return (dissector_try_uint_new(x2ap_proc_imsg_dissector_table, x2ap_data->procedure_code, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct x2ap_private_data *x2ap_data = x2ap_get_private_data(pinfo);

  x2ap_data->message_type = SUCCESSFUL_OUTCOME;
  return (dissector_try_uint_new(x2ap_proc_sout_dissector_table, x2ap_data->procedure_code, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct x2ap_private_data *x2ap_data = x2ap_get_private_data(pinfo);

  x2ap_data->message_type = UNSUCCESSFUL_OUTCOME;
  return (dissector_try_uint_new(x2ap_proc_uout_dissector_table, x2ap_data->procedure_code, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_x2ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  proto_item *x2ap_item;
  proto_tree *x2ap_tree;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "X2AP");
  col_clear_fence(pinfo->cinfo, COL_INFO);
  col_clear(pinfo->cinfo, COL_INFO);

  /* create the x2ap protocol tree */
  x2ap_item = proto_tree_add_item(tree, proto_x2ap, tvb, 0, -1, ENC_NA);
  x2ap_tree = proto_item_add_subtree(x2ap_item, ett_x2ap);

  return dissect_X2AP_PDU_PDU(tvb, pinfo, x2ap_tree, data);
}

/*--- proto_register_x2ap -------------------------------------------*/
void proto_register_x2ap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_x2ap_transportLayerAddressIPv4,
      { "transportLayerAddress(IPv4)", "x2ap.transportLayerAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_transportLayerAddressIPv6,
      { "transportLayerAddress(IPv6)", "x2ap.transportLayerAddressIPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_PRBPeriodic,
      { "PRBPeriodic", "x2ap.ReportCharacteristics.PRBPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x80000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_TNLLoadIndPeriodic,
      { "TNLLoadIndPeriodic", "x2ap.ReportCharacteristics.TNLLoadIndPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x40000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_HWLoadIndPeriodic,
      { "HWLoadIndPeriodic", "x2ap.ReportCharacteristics.HWLoadIndPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x20000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_CompositeAvailableCapacityPeriodic,
      { "CompositeAvailableCapacityPeriodic", "x2ap.ReportCharacteristics.CompositeAvailableCapacityPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x10000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_ABSStatusPeriodic,
      { "ABSStatusPeriodic", "x2ap.ReportCharacteristics.ABSStatusPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x08000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_RSRPMeasurementReportPeriodic,
      { "RSRPMeasurementReportPeriodic", "x2ap.ReportCharacteristics.RSRPMeasurementReportPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x04000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_CSIReportPeriodic,
      { "CSIReportPeriodic", "x2ap.ReportCharacteristics.CSIReportPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x02000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_Reserved,
      { "Reserved", "x2ap.ReportCharacteristics.Reserved",
        FT_UINT32, BASE_HEX, NULL, 0x01ffffff,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailedReportCharacteristics_PRBPeriodic,
      { "PRBPeriodic", "x2ap.measurementFailedReportCharacteristics.PRBPeriodic",
        FT_BOOLEAN, 32, TFS(&x2ap_tfs_failed_succeeded), 0x80000000,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailedReportCharacteristics_TNLLoadIndPeriodic,
      { "TNLLoadIndPeriodic", "x2ap.measurementFailedReportCharacteristics.TNLLoadIndPeriodic",
        FT_BOOLEAN, 32, TFS(&x2ap_tfs_failed_succeeded), 0x40000000,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailedReportCharacteristics_HWLoadIndPeriodic,
      { "HWLoadIndPeriodic", "x2ap.measurementFailedReportCharacteristics.HWLoadIndPeriodic",
        FT_BOOLEAN, 32, TFS(&x2ap_tfs_failed_succeeded), 0x20000000,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailedReportCharacteristics_CompositeAvailableCapacityPeriodic,
      { "CompositeAvailableCapacityPeriodic", "x2ap.measurementFailedReportCharacteristics.CompositeAvailableCapacityPeriodic",
        FT_BOOLEAN, 32, TFS(&x2ap_tfs_failed_succeeded), 0x10000000,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailedReportCharacteristics_ABSStatusPeriodic,
      { "ABSStatusPeriodic", "x2ap.measurementFailedReportCharacteristics.ABSStatusPeriodic",
        FT_BOOLEAN, 32, TFS(&x2ap_tfs_failed_succeeded), 0x08000000,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailedReportCharacteristics_RSRPMeasurementReportPeriodic,
      { "RSRPMeasurementReportPeriodic", "x2ap.measurementFailedReportCharacteristics.RSRPMeasurementReportPeriodic",
        FT_BOOLEAN, 32, TFS(&x2ap_tfs_failed_succeeded), 0x04000000,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailedReportCharacteristics_CSIReportPeriodic,
      { "CSIReportPeriodic", "x2ap.measurementFailedReportCharacteristics.CSIReportPeriodic",
        FT_BOOLEAN, 32, TFS(&x2ap_tfs_failed_succeeded), 0x02000000,
        NULL, HFILL }},
    { &hf_x2ap_measurementFailedReportCharacteristics_Reserved,
      { "Reserved", "x2ap.measurementFailedReportCharacteristics.Reserved",
        FT_UINT32, BASE_HEX, NULL, 0x01ffffff,
        NULL, HFILL }},
    { &hf_x2ap_eUTRANTraceID_TraceID,
      { "TraceID", "x2ap.eUTRANTraceID.TraceID",
        FT_UINT24, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_eUTRANTraceID_TraceRecordingSessionReference,
      { "TraceRecordingSessionReference", "x2ap.eUTRANTraceID.TraceRecordingSessionReference",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_interfacesToTrace_S1_MME,
      { "S1-MME", "x2ap.interfacesToTrace.S1_MME",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x80,
        NULL, HFILL }},
    { &hf_x2ap_interfacesToTrace_X2,
      { "X2", "x2ap.interfacesToTrace.X2",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x40,
        NULL, HFILL }},
    { &hf_x2ap_interfacesToTrace_Uu,
      { "Uu", "x2ap.interfacesToTrace.Uu",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x20,
        NULL, HFILL }},
    { &hf_x2ap_interfacesToTrace_F1_C,
      { "F1-C", "x2ap.interfacesToTrace.F1_C",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x10,
        NULL, HFILL }},
    { &hf_x2ap_interfacesToTrace_E1,
      { "E1", "x2ap.interfacesToTrace.E1",
        FT_BOOLEAN, 8, TFS(&tfs_should_be_traced_should_not_be_traced), 0x08,
        NULL, HFILL }},
    { &hf_x2ap_interfacesToTrace_Reserved,
      { "Reserved", "x2ap.interfacesToTrace.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x07,
        NULL, HFILL }},
    { &hf_x2ap_traceCollectionEntityIPAddress_IPv4,
      { "IPv4", "x2ap.traceCollectionEntityIPAddress.IPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_traceCollectionEntityIPAddress_IPv6,
      { "IPv6", "x2ap.traceCollectionEntityIPAddress.IPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_encryptionAlgorithms_EEA1,
      { "128-EEA1", "x2ap.encryptionAlgorithms.EEA1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_x2ap_encryptionAlgorithms_EEA2,
      { "128-EEA2", "x2ap.encryptionAlgorithms.EEA2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_x2ap_encryptionAlgorithms_EEA3,
      { "128-EEA3", "x2ap.encryptionAlgorithms.EEA3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_x2ap_encryptionAlgorithms_Reserved,
      { "Reserved", "x2ap.encryptionAlgorithms.Reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_x2ap_integrityProtectionAlgorithms_EIA1,
      { "128-EIA1", "x2ap.integrityProtectionAlgorithms.EIA1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_x2ap_integrityProtectionAlgorithms_EIA2,
      { "128-EIA2", "x2ap.integrityProtectionAlgorithms.EIA2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_x2ap_integrityProtectionAlgorithms_EIA3,
      { "128-EIA3", "x2ap.integrityProtectionAlgorithms.EIA3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_x2ap_integrityProtectionAlgorithms_EIA7,
      { "EIA7", "x2ap.integrityProtectionAlgorithms.EIA7",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x0200,
        NULL, HFILL }},
    { &hf_x2ap_integrityProtectionAlgorithms_Reserved,
      { "Reserved", "x2ap.integrityProtectionAlgorithms.Reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1dff,
        NULL, HFILL }},
    { &hf_x2ap_measurementsToActivate_M1,
      { "M1", "x2ap.measurementsToActivate.M1",
        FT_BOOLEAN, 8, TFS(&tfs_activate_do_not_activate), 0x80,
        NULL, HFILL }},
    { &hf_x2ap_measurementsToActivate_M2,
      { "M2", "x2ap.measurementsToActivate.M2",
        FT_BOOLEAN, 8, TFS(&tfs_activate_do_not_activate), 0x40,
        NULL, HFILL }},
    { &hf_x2ap_measurementsToActivate_M3,
      { "M3", "x2ap.measurementsToActivate.M3",
        FT_BOOLEAN, 8, TFS(&tfs_activate_do_not_activate), 0x20,
        NULL, HFILL }},
    { &hf_x2ap_measurementsToActivate_M4,
      { "M4", "x2ap.measurementsToActivate.M4",
        FT_BOOLEAN, 8, TFS(&tfs_activate_do_not_activate), 0x10,
        NULL, HFILL }},
    { &hf_x2ap_measurementsToActivate_M5,
      { "M5", "x2ap.measurementsToActivate.M5",
        FT_BOOLEAN, 8, TFS(&tfs_activate_do_not_activate), 0x08,
        NULL, HFILL }},
    { &hf_x2ap_measurementsToActivate_LoggingM1FromEventTriggered,
      { "LoggingOfM1FromEventTriggeredMeasurementReports", "x2ap.measurementsToActivate.LoggingM1FromEventTriggered",
        FT_BOOLEAN, 8, TFS(&tfs_activate_do_not_activate), 0x04,
        NULL, HFILL }},
    { &hf_x2ap_measurementsToActivate_M6,
      { "M6", "x2ap.measurementsToActivate.M6",
        FT_BOOLEAN, 8, TFS(&tfs_activate_do_not_activate), 0x02,
        NULL, HFILL }},
    { &hf_x2ap_measurementsToActivate_M7,
      { "M7", "x2ap.measurementsToActivate.M7",
        FT_BOOLEAN, 8, TFS(&tfs_activate_do_not_activate), 0x01,
        NULL, HFILL }},
    { &hf_x2ap_MDT_Location_Info_GNSS,
      { "GNSS", "x2ap.MDT_Location_Info.GNSS",
        FT_BOOLEAN, 8, TFS(&tfs_activate_do_not_activate), 0x80,
        NULL, HFILL }},
    { &hf_x2ap_MDT_Location_Info_E_CID,
      { "E-CID", "x2ap.MDT_Location_Info.E_CID",
        FT_BOOLEAN, 8, TFS(&tfs_activate_do_not_activate), 0x40,
        NULL, HFILL }},
    { &hf_x2ap_MDT_Location_Info_Reserved,
      { "Reserved", "x2ap.MDT_Location_Info.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x3f,
        NULL, HFILL }},
    { &hf_x2ap_MDT_transmissionModes_tm1,
      { "TM1", "x2ap.MDT_Location_Info.transmissionModes.tm1",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
        NULL, HFILL }},
    { &hf_x2ap_MDT_transmissionModes_tm2,
      { "TM2", "x2ap.MDT_Location_Info.transmissionModes.tm2",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
        NULL, HFILL }},
    { &hf_x2ap_MDT_transmissionModes_tm3,
      { "TM3", "x2ap.MDT_Location_Info.transmissionModes.tm3",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
        NULL, HFILL }},
    { &hf_x2ap_MDT_transmissionModes_tm4,
      { "TM4", "x2ap.MDT_Location_Info.transmissionModes.tm4",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
        NULL, HFILL }},
    { &hf_x2ap_MDT_transmissionModes_tm6,
      { "TM6", "x2ap.MDT_Location_Info.transmissionModes.tm6",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
        NULL, HFILL }},
    { &hf_x2ap_MDT_transmissionModes_tm8,
      { "TM8", "x2ap.MDT_Location_Info.transmissionModes.tm8",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
        NULL, HFILL }},
    { &hf_x2ap_MDT_transmissionModes_tm9,
      { "TM9", "x2ap.MDT_Location_Info.transmissionModes.tm9",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
        NULL, HFILL }},
    { &hf_x2ap_MDT_transmissionModes_tm10,
      { "TM10", "x2ap.MDT_Location_Info.transmissionModes.tm10",
        FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
        NULL, HFILL }},
    { &hf_x2ap_NRencryptionAlgorithms_NEA1,
      { "128-NEA1", "x2ap.NRencryptionAlgorithms.NEA1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_x2ap_NRencryptionAlgorithms_NEA2,
      { "128-NEA2", "x2ap.NRencryptionAlgorithms.NEA2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_x2ap_NRencryptionAlgorithms_NEA3,
      { "128-NEA3", "x2ap.NRencryptionAlgorithms.NEA3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_x2ap_NRencryptionAlgorithms_Reserved,
      { "Reserved", "x2ap.NRencryptionAlgorithms.Reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_x2ap_NRintegrityProtectionAlgorithms_NIA1,
      { "128-NIA1", "x2ap.NRintegrityProtectionAlgorithms.NIA1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_x2ap_NRintegrityProtectionAlgorithms_NIA2,
      { "128-NIA2", "x2ap.NRintegrityProtectionAlgorithms.NIA2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_x2ap_NRintegrityProtectionAlgorithms_NIA3,
      { "128-NIA3", "x2ap.NRintegrityProtectionAlgorithms.NIA3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_x2ap_NRintegrityProtectionAlgorithms_Reserved,
      { "Reserved", "x2ap.NRintegrityProtectionAlgorithms.Reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_ENDC_PRBPeriodic,
      { "PRBPeriodic", "x2ap.ReportCharacteristics_ENDC.PRBPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x80000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_ENDC_TNLCapacityIndPeriodic,
      { "TNLCapacityIndPeriodic", "x2ap.ReportCharacteristics_ENDC.TNLCapacityIndPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x40000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_ENDC_CompositeAvailableCapacityPeriodic,
      { "CompositeAvailableCapacityPeriodic", "x2ap.ReportCharacteristics_ENDC.CompositeAvailableCapacityPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x20000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_ENDC_NumberOfActiveUEs,
      { "NumberOfActiveUEs", "x2ap.ReportCharacteristics_ENDC.NumberOfActiveUEs",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x10000000,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_ENDC_Reserved,
      { "Reserved", "x2ap.ReportCharacteristics_ENDC.Reserved",
        FT_UINT32, BASE_HEX, NULL, 0x0fffffff,
        NULL, HFILL }},
    { &hf_x2ap_Registration_Request_ENDC_PDU,
      { "Registration-Request-ENDC", "x2ap.Registration_Request_ENDC",
        FT_UINT32, BASE_DEC, VALS(x2ap_Registration_Request_ENDC_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_ReportingPeriodicity_ENDC_PDU,
      { "ReportingPeriodicity-ENDC", "x2ap.ReportingPeriodicity_ENDC",
        FT_UINT32, BASE_DEC, VALS(x2ap_ReportingPeriodicity_ENDC_vals), 0,
        NULL, HFILL }},
    { &hf_x2ap_ReportCharacteristics_ENDC_PDU,
      { "ReportCharacteristics-ENDC", "x2ap.ReportCharacteristics_ENDC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_rAT_RestrictionInformation_LEO,
      { "LEO", "x2ap.rAT_RestrictionInformation.LEO",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x80,
        NULL, HFILL }},
    { &hf_x2ap_rAT_RestrictionInformation_MEO,
      { "MEO", "x2ap.rAT_RestrictionInformation.MEO",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x40,
        NULL, HFILL }},
    { &hf_x2ap_rAT_RestrictionInformation_GEO,
      { "GEO", "x2ap.rAT_RestrictionInformation.GEO",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x20,
        NULL, HFILL }},
    { &hf_x2ap_rAT_RestrictionInformation_OTHERSAT,
      { "OTHERSAT", "x2ap.rAT_RestrictionInformation.OTHERSAT",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x10,
        NULL, HFILL }},
    { &hf_x2ap_rAT_RestrictionInformation_NR_LEO,
      { "NR-LEO", "x2ap.rAT_RestrictionInformation.NR_LEO",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x08,
        NULL, HFILL }},
    { &hf_x2ap_rAT_RestrictionInformation_NR_MEO,
      { "NR-MEO", "x2ap.rAT_RestrictionInformation.NR_MEO",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x04,
        NULL, HFILL }},
    { &hf_x2ap_rAT_RestrictionInformation_NR_GEO,
      { "NR-GEO", "x2ap.rAT_RestrictionInformation.NR_GEO",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x02,
        NULL, HFILL }},
    { &hf_x2ap_rAT_RestrictionInformation_NR_OTHERSAT,
      { "NR-OTHERSAT", "x2ap.rAT_RestrictionInformation.NR_OTHERSAT",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x01,
        NULL, HFILL }},
#include "packet-x2ap-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_x2ap,
    &ett_x2ap_TransportLayerAddress,
    &ett_x2ap_PLMN_Identity,
    &ett_x2ap_TargeteNBtoSource_eNBTransparentContainer,
    &ett_x2ap_RRC_Context,
    &ett_x2ap_UE_HistoryInformationFromTheUE,
    &ett_x2ap_ReportCharacteristics,
    &ett_x2ap_measurementFailedReportCharacteristics,
    &ett_x2ap_UE_RLF_Report_Container,
    &ett_x2ap_UE_RLF_Report_Container_for_extended_bands,
    &ett_x2ap_MeNBtoSeNBContainer,
    &ett_x2ap_SeNBtoMeNBContainer,
    &ett_x2ap_EUTRANTraceID,
    &ett_x2ap_InterfacesToTrace,
    &ett_x2ap_TraceCollectionEntityIPAddress,
    &ett_x2ap_EncryptionAlgorithms,
    &ett_x2ap_IntegrityProtectionAlgorithms,
    &ett_x2ap_MeasurementsToActivate,
    &ett_x2ap_MDT_Location_Info,
    &ett_x2ap_transmissionModes,
    &ett_x2ap_X2AP_Message,
    &ett_x2ap_MeNBtoSgNBContainer,
    &ett_x2ap_SgNBtoMeNBContainer,
    &ett_x2ap_RRCContainer,
    &ett_x2ap_NRencryptionAlgorithms,
    &ett_x2ap_NRintegrityProtectionAlgorithms,
    &ett_x2ap_measurementTimingConfiguration,
    &ett_x2ap_LastVisitedNGRANCellInformation,
    &ett_x2ap_LastVisitedUTRANCellInformation,
    &ett_x2ap_EndcSONConfigurationTransfer,
    &ett_x2ap_EPCHandoverRestrictionListContainer,
    &ett_x2ap_NBIoT_RLF_Report_Container,
    &ett_x2ap_anchorCarrier_NPRACHConfig,
    &ett_x2ap_anchorCarrier_EDT_NPRACHConfig,
    &ett_x2ap_anchorCarrier_Format2_NPRACHConfig,
    &ett_x2ap_anchorCarrier_Format2_EDT_NPRACHConfig,
    &ett_x2ap_non_anchorCarrier_NPRACHConfig,
    &ett_x2ap_non_anchorCarrier_Format2_NPRACHConfig,
    &ett_x2ap_anchorCarrier_NPRACHConfigTDD,
    &ett_x2ap_non_anchorCarrier_NPRACHConfigTDD,
    &ett_x2ap_Non_anchorCarrierFrequency,
    &ett_x2ap_ReportCharacteristics_ENDC,
    &ett_x2ap_TargetCellInNGRAN,
    &ett_x2ap_TDDULDLConfigurationCommonNR,
    &ett_x2ap_MDT_ConfigurationNR,
    &ett_x2ap_NRCellPRACHConfig,
    &ett_x2ap_IntendedTDD_DL_ULConfiguration_NR,
    &ett_x2ap_UERadioCapability,
    &ett_x2ap_LastVisitedPSCell_Item,
    &ett_x2ap_NRRAReportContainer,
    &ett_x2ap_rAT_RestrictionInformation,
    &ett_x2ap_PSCellListContainer,
#include "packet-x2ap-ettarr.c"
  };

  module_t *x2ap_module;

  /* Register protocol */
  proto_x2ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_x2ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  x2ap_handle = register_dissector("x2ap", dissect_x2ap, proto_x2ap);

  /* Register dissector tables */
  x2ap_ies_dissector_table = register_dissector_table("x2ap.ies", "X2AP-PROTOCOL-IES", proto_x2ap, FT_UINT32, BASE_DEC);
  x2ap_extension_dissector_table = register_dissector_table("x2ap.extension", "X2AP-PROTOCOL-EXTENSION", proto_x2ap, FT_UINT32, BASE_DEC);
  x2ap_proc_imsg_dissector_table = register_dissector_table("x2ap.proc.imsg", "X2AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_x2ap, FT_UINT32, BASE_DEC);
  x2ap_proc_sout_dissector_table = register_dissector_table("x2ap.proc.sout", "X2AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_x2ap, FT_UINT32, BASE_DEC);
  x2ap_proc_uout_dissector_table = register_dissector_table("x2ap.proc.uout", "X2AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_x2ap, FT_UINT32, BASE_DEC);

  /* Register configuration options */
  x2ap_module = prefs_register_protocol(proto_x2ap, NULL);

  prefs_register_enum_preference(x2ap_module, "dissect_rrc_context_as", "Dissect RRC Context as",
                                 "Select whether RRC Context should be dissected as legacy LTE or NB-IOT",
                                 &g_x2ap_dissect_rrc_context_as, x2ap_rrc_context_vals, false);
}


/*--- proto_reg_handoff_x2ap ---------------------------------------*/
void
proto_reg_handoff_x2ap(void)
{
  dissector_add_uint_with_preference("sctp.port", SCTP_PORT_X2AP, x2ap_handle);
  dissector_add_uint("sctp.ppi", X2AP_PAYLOAD_PROTOCOL_ID, x2ap_handle);
#include "packet-x2ap-dis-tab.c"
}



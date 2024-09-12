/* packet-lpp.c
 * Routines for 3GPP LTE Positioning Protocol (LPP) packet dissection
 * Copyright 2011-2024 Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref 3GPP TS 37.355 version 18.2.0 Release 18
 * http://www.3gpp.org
 */

#include "config.h"

#include "math.h"

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/tfs.h>
#include <epan/proto_data.h>
#include <epan/unit_strings.h>
#include <wsutil/array.h>

#include "packet-per.h"
#include "packet-lpp.h"

#define PNAME  "LTE Positioning Protocol (LPP)"
#define PSNAME "LPP"
#define PFNAME "lpp"

void proto_register_lpp(void);
void proto_reg_handoff_lpp(void);

/* Initialize the protocol and registered fields */
static int proto_lpp;

#include "packet-lpp-hf.c"
static int hf_lpp_svHealthExt_v1240_e5bhs;
static int hf_lpp_svHealthExt_v1240_e1_bhs;
static int hf_lpp_kepSV_StatusINAV_e5bhs;
static int hf_lpp_kepSV_StatusINAV_e1_bhs;
static int hf_lpp_kepSV_StatusFNAV_e5ahs;
static int hf_lpp_bdsSvHealth_r12_sat_clock;
static int hf_lpp_bdsSvHealth_r12_b1i;
static int hf_lpp_bdsSvHealth_r12_b2i;
static int hf_lpp_bdsSvHealth_r12_nav;
static int hf_lpp_AssistanceDataSIBelement_r15_PDU;

static dissector_handle_t lppe_handle;

static uint32_t lpp_epdu_id = -1;

/* Initialize the subtree pointers */
static int ett_lpp;
static int ett_lpp_svHealthExt_v1240;
static int ett_kepSV_StatusINAV;
static int ett_kepSV_StatusFNAV;
static int ett_lpp_bdsSvHealth_r12;
static int ett_lpp_assistanceDataElement_r15;
#include "packet-lpp-ett.c"

/* Include constants */
#include "packet-lpp-val.h"

static const value_string lpp_ePDU_ID_vals[] = {
  { 1, "OMA LPP extensions (LPPe)"},
  { 0, NULL}
};

struct lpp_private_data {
  lpp_pos_sib_type_t pos_sib_type;
  bool is_ciphered;
  bool is_segmented;
};

static struct lpp_private_data*
lpp_get_private_data(packet_info *pinfo)
{
  struct lpp_private_data *lpp_data = (struct lpp_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_lpp, 0);
  if (!lpp_data) {
    lpp_data = wmem_new0(pinfo->pool, struct lpp_private_data);
    p_add_proto_data(pinfo->pool, pinfo, proto_lpp, 0, lpp_data);
  }
  return lpp_data;
}

/* Forward declarations */
static int dissect_GNSS_ReferenceTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_ReferenceLocation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_IonosphericModel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_EarthOrientationParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_RTK_ReferenceStationInfo_r15_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_RTK_CommonObservationInfo_r15_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_RTK_AuxiliaryStationData_r15_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_SSR_CorrectionPoints_r16_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_Integrity_ServiceParameters_r17_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_Integrity_ServiceAlert_r17_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_TimeModelList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_DifferentialCorrections_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_NavigationModel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_RealTimeIntegrity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_DataBitAssistance_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_AcquisitionAssistance_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_Almanac_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_UTC_Model_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_AuxiliaryInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_BDS_DifferentialCorrections_r12_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_BDS_GridModelParameter_r12_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_RTK_Observations_r15_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GLO_RTK_BiasInformation_r15_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_RTK_MAC_CorrectionDifferences_r15_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_RTK_Residuals_r15_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_RTK_FKP_Gradients_r15_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_SSR_OrbitCorrections_r15_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_SSR_ClockCorrections_r15_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_SSR_CodeBias_r15_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_SSR_URA_r16_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_SSR_PhaseBias_r16_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_SSR_STEC_Correction_r16_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_SSR_GriddedCorrection_r16_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_NavIC_DifferentialCorrections_r16_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_NavIC_GridModelParameter_r16_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_OTDOA_UE_Assisted_r15_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_Sensor_AssistanceDataList_r14_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_TBS_AssistanceDataList_r14_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_NR_DL_PRS_AssistanceData_r16_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_NR_UEB_TRP_LocationData_r16_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_NR_UEB_TRP_RTD_Info_r16_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_NR_TRP_BeamAntennaInfo_r17_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_NR_DL_PRS_TRP_TEG_Info_r17_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_NR_On_Demand_DL_PRS_Configurations_r17_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_SSR_OrbitCorrectionsSet2_r17_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_SSR_ClockCorrectionsSet2_r17_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_SSR_URA_Set2_r17_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_LOS_NLOS_GridPoints_r18_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_SSR_IOD_Update_r18_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_LOS_NLOS_GriddedIndications_r18_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_GNSS_SSR_SatellitePCVResiduals_r18_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_NR_PRU_DL_Info_r18_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_NR_IntegrityRiskParameters_r18_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_NR_IntegrityServiceParameters_r18_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_NR_IntegrityServiceAlert_r18_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_NR_IntegrityParameters_r18_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

static void
lpp_degreesLatitude_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%f degrees (%u)",
             ((float)v/8388607.0)*90, v);
}

static void
lpp_degreesLongitude_fmt(char *s, uint32_t v)
{
  int32_t longitude = (int32_t) v;

  snprintf(s, ITEM_LABEL_LENGTH, "%f degrees (%d)",
             ((float)longitude/8388608.0)*180, longitude);
}

static void
lpp_uncertainty_fmt(char *s, uint32_t v)
{
  double uncertainty = 10*(pow(1.1, (double)v)-1);

  if (uncertainty < 1000) {
    snprintf(s, ITEM_LABEL_LENGTH, "%fm (%u)", uncertainty, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%fkm (%u)", uncertainty/1000, v);
  }
}

static void
lpp_angle_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%u degrees (%u)", 2*v, v);
}

static void
lpp_confidence_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "no information (0)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%u%%", v);
  }
}

static void
lpp_1_10_degrees_fmt(char *s, uint32_t v)
{
  double val = (double)v/10;

  snprintf(s, ITEM_LABEL_LENGTH, "%g degrees (%u)", val, v);
}

static void
lpp_1_100_m_fmt(char *s, uint32_t v)
{
  double val = (double)v/100;

  snprintf(s, ITEM_LABEL_LENGTH, "%gm (%u)", val, v);
}

static void
lpp_measurementLimit_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%u octets (%u)", 100*v, v);
}

static void
lpp_altitude_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%um", v);
}

static void
lpp_uncertaintyAltitude_fmt(char *s, uint32_t v)
{
  double uncertainty = 45*(pow(1.025, (double)v)-1);

  snprintf(s, ITEM_LABEL_LENGTH, "%fm (%u)", uncertainty, v);
}

static void
lpp_radius_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%um (%u)", 5*v, v);
}

static void
lpp_nr_LTE_fineTiming_Offset_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%u)", (float)v/2, v);
}

static void
lpp_expectedRSTD_fmt(char *s, uint32_t v)
{
  int32_t rstd = 3*((int32_t)v-8192);

  snprintf(s, ITEM_LABEL_LENGTH, "%dTs (%u)", rstd, v);
}

static void
lpp_expectedRSTD_Uncertainty_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%uTs (%u)", 3*v, v);
}

static void
lpp_rstd_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSTD < -15391Ts (0)");
  } else if (v < 2260) {
    snprintf(s, ITEM_LABEL_LENGTH, "-%uTs <= RSTD < -%uTs (%u)", 15391-5*(v-1), 15391-5*v, v);
  } else if (v < 6355) {
    snprintf(s, ITEM_LABEL_LENGTH, "-%uTs <= RSTD < -%uTs (%u)", 6356-v, 6355-v, v);
  } else if (v == 6355) {
    snprintf(s, ITEM_LABEL_LENGTH, "-1Ts <= RSTD <= 0Ts (6355)");
  } else if (v < 10452) {
    snprintf(s, ITEM_LABEL_LENGTH, "%uTs < RSTD <= %uTs (%u)", v-6356, v-6355, v);
  } else if (v < 12711) {
    snprintf(s, ITEM_LABEL_LENGTH, "%uTs < RSTD <= %uTs (%u)", 5*(v-1)-48159, 5*v-48159, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "15391Ts < RSTD (12711)");
  }
}

static const value_string lpp_error_Resolution_vals[] = {
  { 0, "5 meters"},
  { 1, "10 meters"},
  { 2, "20 meters"},
  { 3, "30 meters"},
  { 0, NULL}
};

static const value_string lpp_error_Value_vals[] = {
  {  0, "0 to (R*1-1) meters"},
  {  1, "R*1 to (R*2-1) meters"},
  {  2, "R*2 to (R*3-1) meters"},
  {  3, "R*3 to (R*4-1) meters"},
  {  4, "R*4 to (R*5-1) meters"},
  {  5, "R*5 to (R*6-1) meters"},
  {  6, "R*6 to (R*7-1) meters"},
  {  7, "R*7 to (R*8-1) meters"},
  {  8, "R*8 to (R*9-1) meters"},
  {  9, "R*9 to (R*10-1) meters"},
  { 10, "R*10 to (R*11-1) meters"},
  { 11, "R*11 to (R*12-1) meters"},
  { 12, "R*12 to (R*13-1) meters"},
  { 13, "R*13 to (R*14-1) meters"},
  { 14, "R*14 to (R*15-1) meters"},
  { 15, "R*15 to (R*16-1) meters"},
  { 16, "R*16 to (R*17-1) meters"},
  { 17, "R*17 to (R*18-1) meters"},
  { 18, "R*18 to (R*19-1) meters"},
  { 19, "R*19 to (R*20-1) meters"},
  { 20, "R*20 to (R*21-1) meters"},
  { 21, "R*21 to (R*22-1) meters"},
  { 22, "R*22 to (R*23-1) meters"},
  { 23, "R*23 to (R*24-1) meters"},
  { 24, "R*24 to (R*25-1) meters"},
  { 25, "R*25 to (R*26-1) meters"},
  { 26, "R*26 to (R*27-1) meters"},
  { 27, "R*27 to (R*28-1) meters"},
  { 28, "R*28 to (R*29-1) meters"},
  { 29, "R*29 to (R*30-1) meters"},
  { 30, "R*30 to (R*31-1) meters"},
  { 31, "R*31 meters or more"},
  { 0, NULL}
};
static value_string_ext lpp_error_Value_vals_ext = VALUE_STRING_EXT_INIT(lpp_error_Value_vals);

static const value_string lpp_error_NumSamples_vals[] = {
  {  0, "Not the baseline metric"},
  {  1, "5-9"},
  {  2, "10-14"},
  {  3, "15-24"},
  {  4, "25-34"},
  {  5, "35-44"},
  {  6, "45-54"},
  {  7, "55 or more"},
  { 0, NULL}
};

static void
lpp_relativeTimeDifference_fmt(char *s, uint32_t v)
{
  double rtd = (double)((int32_t)v)*0.5;

  snprintf(s, ITEM_LABEL_LENGTH, "%.1f Ts (%d)", rtd, (int32_t)v);
}

static void
lpp_referenceTimeUnc_fmt(char *s, uint32_t v)
{
  double referenceTimeUnc = 0.5*(pow(1.14, (double)v)-1);

  snprintf(s, ITEM_LABEL_LENGTH, "%fus (%u)", referenceTimeUnc, v);
}

static const value_string lpp_kp_vals[] = {
  { 0, "No UTC correction at the end of current quarter"},
  { 1, "UTC correction by plus (+1 s) in the end of current quarter"},
  { 3, "UTC correction by minus (-1 s) in the end of current quarter"},
  { 0, NULL}
};

static void
lpp_fractionalSecondsFromFrameStructureStart_fmt(char *s, uint32_t v)
{
  float frac = ((float)v)/4;

  snprintf(s, ITEM_LABEL_LENGTH, "%fus (%u)", frac, v);
}

static void
lpp_frameDrift_fmt(char *s, uint32_t v)
{
  double drift = (double)((int32_t)v)*pow(2, -30);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s (%d)", drift, (int32_t)v);
}

static const value_string lpp_dataID_vals[] = {
  { 0, "Parameters are applicable worldwide"},
  { 1, "Parameters have been generated by BDS"},
  { 3, "Parameters have been generated by QZSS"},
  { 0, NULL}
};

static void
lpp_alpha0_fmt(char *s, uint32_t v)
{
  double alpha = (double)((int32_t)v)*pow(2, -30);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", alpha, (int32_t)v);
}

static void
lpp_alpha1_fmt(char *s, uint32_t v)
{
  double alpha = (double)((int32_t)v)*pow(2, -27);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/semi-circle (%d)", alpha, (int32_t)v);
}

static void
lpp_alpha2_3_fmt(char *s, uint32_t v)
{
  double alpha = (double)((int32_t)v)*pow(2, -24);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/semi-circle (%d)", alpha, (int32_t)v);
}

static void
lpp_beta0_fmt(char *s, uint32_t v)
{
  double beta = (double)((int32_t)v)*pow(2, 11);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", beta, (int32_t)v);
}

static void
lpp_beta1_fmt(char *s, uint32_t v)
{
  double beta = (double)((int32_t)v)*pow(2, 14);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/semi-circle (%d)", beta, (int32_t)v);
}

static void
lpp_beta2_3_fmt(char *s, uint32_t v)
{
  double beta = (double)((int32_t)v)*pow(2, 16);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/semi-circle (%d)", beta, (int32_t)v);
}

static void
lpp_ai0_fmt(char *s, uint32_t v)
{
  double ai = (double)v*pow(2, -2);

  snprintf(s, ITEM_LABEL_LENGTH, "%gsfu (%u)", ai, v);
}

static void
lpp_ai1_fmt(char *s, uint32_t v)
{
  double ai = (double)v*pow(2, -8);

  snprintf(s, ITEM_LABEL_LENGTH, "%gsfu/degree (%u)", ai, v);
}

static void
lpp_ai2_fmt(char *s, uint32_t v)
{
  double ai = (double)v*pow(2, -15);

  snprintf(s, ITEM_LABEL_LENGTH, "%gsfu/degree2 (%u)", ai, v);
}

static void
lpp_teop_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%us (%u)", 16*v, v);
}

static void
lpp_pmX_Y_fmt(char *s, uint32_t v)
{
  double pm = (double)((int32_t)v)*pow(2, -20);

  snprintf(s, ITEM_LABEL_LENGTH, "%g arc-seconds (%d)", pm, (int32_t)v);
}

static void
lpp_pmX_Ydot_fmt(char *s, uint32_t v)
{
  double pmDot = (double)((int32_t)v)*pow(2, -21);

  snprintf(s, ITEM_LABEL_LENGTH, "%g arc-seconds/day (%d)", pmDot, (int32_t)v);
}

static void
lpp_deltaUT1_fmt(char *s, uint32_t v)
{
  double deltaUT1 = (double)((int32_t)v)*pow(2, -24);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", deltaUT1, (int32_t)v);
}

static void
lpp_deltaUT1dot_fmt(char *s, uint32_t v)
{
  double deltaUT1dot = (double)((int32_t)v)*pow(2, -25);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/day (%d)", deltaUT1dot, (int32_t)v);
}

static void
lpp_1_1000m_64_fmt(char *s, uint64_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%gm (%"PRId64")", (double)v/1000, (int64_t)v);
}

static void
lpp_1_1000m_32_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%gm (%d)", (double)v/1000, (int32_t)v);
}

static const value_string lpp_clockSteeringIndicator_vals[] = {
  { 0, "Clock steering is not applied"},
  { 1, "Clock steering has been applied"},
  { 2, "Unknown clock steering status"},
  { 3, "Reserved"},
  { 0, NULL}
};

static const value_string lpp_externalClockIndicator_vals[] = {
  { 0, "Internal clock is used"},
  { 1, "External clock is used, clock status is \"locked\""},
  { 2, "External clock is used, clock status is \"not locked\", which may indicate external clock failure and that the transmitted data may not be reliable"},
  { 3, "Unknown clock is used"},
  { 0, NULL}
};

static const value_string lpp_smoothingIndicator_r15_vals[] = {
  { 0, "Other type of smoothing is used"},
  { 1, "Divergence-free smoothing is used"},
  { 0, NULL}
};

static const value_string lpp_smoothingInterval_r15_vals[] = {
  { 0, "No smoothing"},
  { 1, "< 30 s"},
  { 2, "30-60 s"},
  { 3, "1-2 min"},
  { 4, "2-4 min"},
  { 5, "4-8 min"},
  { 6, "> 8 min"},
  { 7, "Unlimited smoothing interval"},
  { 0, NULL}
};

static void
lpp_aux_master_delta_fmt(char *s, uint32_t v)
{
  double delta = (double)((int32_t)v)*25*pow(10, -6);
  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%u)", delta, (int32_t)v);
}

static void
lpp_gnss_TimeModelRefTime_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%us (%u)", v*16, v);
}

static void
lpp_tA0_fmt(char *s, uint32_t v)
{
  double tA0 = (double)((int32_t)v)*pow(2, -35);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", tA0, (int32_t)v);
}

static void
lpp_tA1_fmt(char *s, uint32_t v)
{
  double tA1 = (double)((int32_t)v)*pow(2, -51);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s (%d)", tA1, (int32_t)v);
}

static void
lpp_tA2_fmt(char *s, uint32_t v)
{
  double tA2 = (double)((int32_t)v)*pow(2, -68);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s2 (%d)", tA2, (int32_t)v);
}

static const value_string lpp_gnss_TO_ID_vals[] = {
  { 1, "GPS"},
  { 2, "Galileo"},
  { 3, "QZSS"},
  { 4, "GLONASS"},
  { 0, NULL}
};

static const value_string lpp_gnss_StatusHealth_vals[] = {
  { 0, "UDRE Scale Factor = 1.0"},
  { 1, "UDRE Scale Factor = 0.75"},
  { 2, "UDRE Scale Factor = 0.5"},
  { 3, "UDRE Scale Factor = 0.3"},
  { 4, "UDRE Scale Factor = 0.2"},
  { 5, "UDRE Scale Factor = 0.1"},
  { 6, "Reference Station Transmission Not Monitored"},
  { 7, "Data is invalid - disregard"},
  { 0, NULL}
};

static const value_string lpp_udre_vals[] = {
  { 0, "UDRE <= 1.0m"},
  { 1, "1.0m < UDRE <= 4.0m"},
  { 2, "4.0m < UDRE <= 8.0m"},
  { 3, "8.0m < UDRE"},
  { 0, NULL}
};

static void
lpp_pseudoRangeCor_fmt(char *s, uint32_t v)
{
  double pseudoRangeCor = ((double)(int32_t)v)*0.32;

  snprintf(s, ITEM_LABEL_LENGTH, "%fm (%d)", pseudoRangeCor, (int32_t)v);
}

static void
lpp_rangeRateCor_fmt(char *s, uint32_t v)
{
  double rangeRateCor = ((double)(int32_t)v)*0.032;

  snprintf(s, ITEM_LABEL_LENGTH, "%fm/s (%d)", rangeRateCor, (int32_t)v);
}

static const value_string lpp_udreGrowthRate_vals[] = {
  { 0, "1.5"},
  { 1, "2"},
  { 2, "4"},
  { 3, "6"},
  { 4, "8"},
  { 5, "10"},
  { 6, "12"},
  { 7, "16"},
  { 0, NULL}
};

static const value_string lpp_udreValidityTime_vals[] = {
  { 0, "20s"},
  { 1, "40s"},
  { 2, "80s"},
  { 3, "160s"},
  { 4, "320s"},
  { 5, "640s"},
  { 6, "1280s"},
  { 7, "2560s"},
  { 0, NULL}
};

static const value_string lpp_signal_health_status_vals[] = {
  { 0, "Signal OK"},
  { 1, "Signal out of service"},
  { 2, "Signal will be out of service"},
  { 3, "Signal Component currently in Test"},
  { 0, NULL}
};
static void
lpp_stanClockToc_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%um/s (%u)", 60*v, v);
}

static void
lpp_stanClockAF2_fmt(char *s, uint32_t v)
{
  double stanClockAF2 = (double)((int32_t)v)*pow(2, -59);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s2 (%d)", stanClockAF2, (int32_t)v);
}

static void
lpp_stanClockAF1_fmt(char *s, uint32_t v)
{
  double stanClockAF1 = (double)((int32_t)v)*pow(2, -46);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s (%d)", stanClockAF1, (int32_t)v);
}

static void
lpp_stanClockAF0_fmt(char *s, uint32_t v)
{
  double stanClockAF0 = (double)((int32_t)v)*pow(2, -34);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", stanClockAF0, (int32_t)v);
}

static void
lpp_stanClockTgd_fmt(char *s, uint32_t v)
{
  double stanClockTgd = (double)((int32_t)v)*pow(2, -32);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", stanClockTgd, (int32_t)v);
}

static void
lpp_sisa_fmt(char *s, uint32_t v)
{
  if (v < 50) {
    snprintf(s, ITEM_LABEL_LENGTH, "%ucm (%u)", v, v);
  } else if (v < 75) {
    snprintf(s, ITEM_LABEL_LENGTH, "%ucm (%u)", 50+((v-50)*2), v);
  } else if (v < 100) {
    snprintf(s, ITEM_LABEL_LENGTH, "%ucm (%u)", 100+((v-75)*4), v);
  } else if (v < 126) {
    snprintf(s, ITEM_LABEL_LENGTH, "%ucm (%u)", 200+((v-100)*16), v);
  } else if (v < 255) {
    snprintf(s, ITEM_LABEL_LENGTH, "Spare (%u)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "No Accuracy Prediction Available (255)");
  }
}

static const value_string lpp_stanModelID_vals[] = {
  { 0, "I/Nav"},
  { 1, "F/Nav"},
  { 0, NULL}
};

static void
lpp_navToc_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%us (%u)", 16*v, v);
}

static void
lpp_navaf2_fmt(char *s, uint32_t v)
{
  double navaf2 = (double)((int32_t)v)*pow(2, -55);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s2 (%d)", navaf2, (int32_t)v);
}

static void
lpp_navaf1_fmt(char *s, uint32_t v)
{
  double navaf1 = (double)((int32_t)v)*pow(2, -43);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s (%d)", navaf1, (int32_t)v);
}

static void
lpp_navaf0_navTgd_fmt(char *s, uint32_t v)
{
  double navaf0_navTgd = (double)((int32_t)v)*pow(2, -31);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s (%d)", navaf0_navTgd, (int32_t)v);
}

static void
lpp_cnavToc_cnavTop_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%us (%u)", 300*v, v);
}

static void
lpp_cnavAf2_fmt(char *s, uint32_t v)
{
  double cnavAf2 = (double)((int32_t)v)*pow(2, -60);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s2 (%d)", cnavAf2, (int32_t)v);
}

static void
lpp_cnavAf1_fmt(char *s, uint32_t v)
{
  double cnavAf1 = (double)((int32_t)v)*pow(2, -48);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s (%d)", cnavAf1, (int32_t)v);
}

static void
lpp_cnavX_fmt(char *s, uint32_t v)
{
  double cnavX = (double)((int32_t)v)*pow(2, -35);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", cnavX, (int32_t)v);
}

static void
lpp_gloTau_gloDeltaTau_fmt(char *s, uint32_t v)
{
  double gloTau_gloDeltaTau = (double)((int32_t)v)*pow(2, -30);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", gloTau_gloDeltaTau, (int32_t)v);
}

static void
lpp_gloGamma_fmt(char *s, uint32_t v)
{
  double gloGamma = (double)((int32_t)v)*pow(2, -40);

  snprintf(s, ITEM_LABEL_LENGTH, "%g (%d)", gloGamma, (int32_t)v);
}

static void
lpp_sbasTo_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%us (%u)", 16*v, v);
}

static void
lpp_sbasAgfo_fmt(char *s, uint32_t v)
{
  double sbasAgfo = (double)((int32_t)v)*pow(2, -31);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", sbasAgfo, (int32_t)v);
}

static void
lpp_sbasAgf1_fmt(char *s, uint32_t v)
{
  double sbasAgf1 = (double)((int32_t)v)*pow(2, -40);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s (%d)", sbasAgf1, (int32_t)v);
}

static void
lpp_bdsAODC_AODE_r12_fmt(char *s, uint32_t v)
{
  if (v < 25) {
    snprintf(s, ITEM_LABEL_LENGTH, "Age of the satellite clock correction parameters is %u hours (%u)", v, v);
  } else if (v < 31) {
    snprintf(s, ITEM_LABEL_LENGTH, "Age of the satellite clock correction parameters is %u days (%u)", v-23, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "Age of the satellite clock correction parameters is over 7 days (%u)", v);
  }
}


static void
lpp_bdsToc_Toe_r12_fmt(char *s, uint32_t v)
{
  double bdsToc = (double)((int32_t)v)*pow(2, 3);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", bdsToc, (int32_t)v);
}

static void
lpp_bdsA0_r12_fmt(char *s, uint32_t v)
{
  double bdsA0 = (double)((int32_t)v)*pow(2, -33);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", bdsA0, (int32_t)v);
}

static void
lpp_bdsA1_r12_fmt(char *s, uint32_t v)
{
  double bdsA1 = (double)((int32_t)v)*pow(2, -50);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s (%d)", bdsA1, (int32_t)v);
}

static void
lpp_bdsA2_r12_fmt(char *s, uint32_t v)
{
  double bdsA2 = (double)((int32_t)v)*pow(2, -66);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s2 (%d)", bdsA2, (int32_t)v);
}

static void
lpp_bdsTgd1_r12_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%gns (%d)", (float)((int32_t)v)*0.1, (int32_t)v);
}

static void
lpp_keplerToe_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%us (%u)", 60*v, v);
}

static void
lpp_keplerW_M0_I0_Omega0_fmt(char *s, uint32_t v)
{
  double keplerW_M0_I0_Omega0 = (double)((int32_t)v)*pow(2, -31);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", keplerW_M0_I0_Omega0, (int32_t)v);
}

static void
lpp_keplerDeltaN_OmegaDot_IDot_fmt(char *s, uint32_t v)
{
  double keplerDeltaN_OmegaDot_IDot = (double)((int32_t)v)*pow(2, -43);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", keplerDeltaN_OmegaDot_IDot, (int32_t)v);
}

static void
lpp_keplerE_fmt(char *s, uint32_t v)
{
  double keplerE = (double)v*pow(2, -33);

  snprintf(s, ITEM_LABEL_LENGTH, "%g (%u)", keplerE, v);
}

static void
lpp_keplerAPowerHalf_fmt(char *s, uint32_t v)
{
  double keplerAPowerHalf = (double)v*pow(2, -19);

  snprintf(s, ITEM_LABEL_LENGTH, "%gm1/2 (%u)", keplerAPowerHalf, v);
}

static void
lpp_keplerCrs_Crc_fmt(char *s, uint32_t v)
{
  double keplerCrs_Crc = (double)((int32_t)v)*pow(2, -5);

  snprintf(s, ITEM_LABEL_LENGTH, "%gm (%d)", keplerCrs_Crc, (int32_t)v);
}

static void
lpp_keplerCx_fmt(char *s, uint32_t v)
{
  double keplerCx = (double)((int32_t)v)*pow(2, -29);

  snprintf(s, ITEM_LABEL_LENGTH, "%grad (%d)", keplerCx, (int32_t)v);
}

static void
lpp_navToe_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%us (%u)", 16*v, v);
}

static void
lpp_navOmega_M0_I0_OmegaA0_fmt(char *s, uint32_t v)
{
  double navOmega_M0_I0_OmegaA0 = (double)((int32_t)v)*pow(2, -31);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", navOmega_M0_I0_OmegaA0, (int32_t)v);
}

static void
lpp_navDeltaN_OmegaADot_IDot_fmt(char *s, uint32_t v)
{
  double navDeltaN_OmegaADot_IDot = (double)((int32_t)v)*pow(2, -43);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", navDeltaN_OmegaADot_IDot, (int32_t)v);
}

static void
lpp_navE_fmt(char *s, uint32_t v)
{
  double navE = (double)v*pow(2, -33);

  snprintf(s, ITEM_LABEL_LENGTH, "%g (%u)", navE, v);
}

static void
lpp_navAPowerHalf_fmt(char *s, uint32_t v)
{
  double navAPowerHalf = (double)v*pow(2, -19);

  snprintf(s, ITEM_LABEL_LENGTH, "%gm1/2 (%u)", navAPowerHalf, v);
}

static void
lpp_navCrs_Crc_fmt(char *s, uint32_t v)
{
  double navCrs_Crc = (double)((int32_t)v)*pow(2, -5);

  snprintf(s, ITEM_LABEL_LENGTH, "%gm (%d)", navCrs_Crc, (int32_t)v);
}

static void
lpp_navCx_fmt(char *s, uint32_t v)
{
  double navCx = (double)((int32_t)v)*pow(2, -29);

  snprintf(s, ITEM_LABEL_LENGTH, "%grad (%d)", navCx, (int32_t)v);
}

static void
lpp_cnavDeltaA_fmt(char *s, uint32_t v)
{
  double cnavDeltaA = (double)((int32_t)v)*pow(2, -9);

  snprintf(s, ITEM_LABEL_LENGTH, "%gm (%d)", cnavDeltaA, (int32_t)v);
}

static void
lpp_cnavAdot_fmt(char *s, uint32_t v)
{
  double cnavAdot = (double)((int32_t)v)*pow(2, -21);

  snprintf(s, ITEM_LABEL_LENGTH, "%gm/s (%d)", cnavAdot, (int32_t)v);
}

static void
lpp_cnavDeltaNo_fmt(char *s, uint32_t v)
{
  double cnavDeltaNo = (double)((int32_t)v)*pow(2, -44);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", cnavDeltaNo, (int32_t)v);
}

static void
lpp_cnavDeltaNoDot_fmt(char *s, uint32_t v)
{
  double cnavDeltaNoDot = (double)((int32_t)v)*pow(2, -57);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s2 (%d)", cnavDeltaNoDot, (int32_t)v);
}

static void
lpp_cnavDeltaOmegaDot_IoDot_fmt(char *s, uint32_t v)
{
  double cnavDeltaOmegaDot_IoDot = (double)((int32_t)v)*pow(2, -44);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", cnavDeltaOmegaDot_IoDot, (int32_t)v);
}

static void
lpp_cnavCx_fmt(char *s, uint32_t v)
{
  double cnavCx = (double)((int32_t)v)*pow(2, -30);

  snprintf(s, ITEM_LABEL_LENGTH, "%grad (%d)", cnavCx, (int32_t)v);
}

static void
lpp_cnavCrs_Crc_fmt(char *s, uint32_t v)
{
  double cnavCrs_Crc = (double)((int32_t)v)*pow(2, -8);

  snprintf(s, ITEM_LABEL_LENGTH, "%gm (%d)", cnavCrs_Crc, (int32_t)v);
}

static void
lpp_gloX_Y_Z_fmt(char *s, uint32_t v)
{
  double gloX_Y_Z = (double)((int32_t)v)*pow(2, -11);

  snprintf(s, ITEM_LABEL_LENGTH, "%gkm (%d)", gloX_Y_Z, (int32_t)v);
}

static void
lpp_gloXdot_Ydot_Zdot_fmt(char *s, uint32_t v)
{
  double gloXdot_Ydot_Zdot = (double)((int32_t)v)*pow(2, -20);

  snprintf(s, ITEM_LABEL_LENGTH, "%gkm/s (%d)", gloXdot_Ydot_Zdot, (int32_t)v);
}

static void
lpp_gloXdotdot_Ydotdot_Zdotdot_fmt(char *s, uint32_t v)
{
  double gloXdotdot_Ydotdot_Zdotdot = (double)((int32_t)v)*pow(2, -30);

  snprintf(s, ITEM_LABEL_LENGTH, "%gkm/s2 (%d)", gloXdotdot_Ydotdot_Zdotdot, (int32_t)v);
}

static void
lpp_sbasXg_Yg_fmt(char *s, uint32_t v)
{
  double sbasXg_Yg = (double)((int32_t)v)*0.08;

  snprintf(s, ITEM_LABEL_LENGTH, "%fm (%d)", sbasXg_Yg, (int32_t)v);
}

static void
lpp_sbasZg_fmt(char *s, uint32_t v)
{
  double sbasZg = (double)((int32_t)v)*0.4;

  snprintf(s, ITEM_LABEL_LENGTH, "%fm (%d)", sbasZg, (int32_t)v);
}

static void
lpp_sbasXgDot_YgDot_fmt(char *s, uint32_t v)
{
  double sbasXgDot_YgDot = (double)((int32_t)v)*0.000625;

  snprintf(s, ITEM_LABEL_LENGTH, "%fm/s (%d)", sbasXgDot_YgDot, (int32_t)v);
}

static void
lpp_sbasZgDot_fmt(char *s, uint32_t v)
{
  double sbasZgDot = (double)((int32_t)v)*0.004;

  snprintf(s, ITEM_LABEL_LENGTH, "%fm/s (%d)", sbasZgDot, (int32_t)v);
}

static void
lpp_sbasXgDotDot_YgDotDot_fmt(char *s, uint32_t v)
{
  double sbasXgDotDot_YgDotDot = (double)((int32_t)v)*0.0000125;

  snprintf(s, ITEM_LABEL_LENGTH, "%gm/s2 (%d)", sbasXgDotDot_YgDotDot, (int32_t)v);
}

static void
lpp_sbasZgDotDot_fmt(char *s, uint32_t v)
{
  double sbasZgDotDot = (double)((int32_t)v)*0.0000625;

  snprintf(s, ITEM_LABEL_LENGTH, "%gm/s2 (%d)", sbasZgDotDot, (int32_t)v);
}

static void
lpp_bdsAPowerHalf_r12_fmt(char *s, uint32_t v)
{
  double bdsAPowerHalf = (double)v*pow(2, -19);

  snprintf(s, ITEM_LABEL_LENGTH, "%gm1/2 (%u)", bdsAPowerHalf, v);
}

static void
lpp_bdsE_r12_fmt(char *s, uint32_t v)
{
  double bdsE = (double)v*pow(2, -33);

  snprintf(s, ITEM_LABEL_LENGTH, "%g (%u)", bdsE, v);
}

static void
lpp_bdsW_M0_Omega0_I0_r12_fmt(char *s, uint32_t v)
{
  double bdsW_M0_Omega0_I0 = (double)((int32_t)v)*pow(2, -31);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", bdsW_M0_Omega0_I0, (int32_t)v);
}

static void
lpp_bdsDeltaN_OmegaDot_IDot_r12_fmt(char *s, uint32_t v)
{
  double bdsDeltaN_OmegaDot_IDot = (double)((int32_t)v)*pow(2, -43);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", bdsDeltaN_OmegaDot_IDot, (int32_t)v);
}

static void
lpp_bdsCuc_Cus_Cic_Cis_r12_fmt(char *s, uint32_t v)
{
  double bdsCuc_Cus_Cic_Cis = (double)((int32_t)v)*pow(2, -31);

  snprintf(s, ITEM_LABEL_LENGTH, "%grad (%d)", bdsCuc_Cus_Cic_Cis, (int32_t)v);
}

static void
lpp_bdsCrc_Crs_r12_fmt(char *s, uint32_t v)
{
  double bdsCrc_Crs = (double)((int32_t)v)*pow(2, -6);

  snprintf(s, ITEM_LABEL_LENGTH, "%grad (%d)", bdsCrc_Crs, (int32_t)v);
}

static void
lpp_doppler0_fmt(char *s, uint32_t v)
{
  double doppler0 = (double)((int32_t)v)*0.5;

  snprintf(s, ITEM_LABEL_LENGTH, "%fm/s (%d)", doppler0, (int32_t)v);
}

static void
lpp_doppler1_fmt(char *s, uint32_t v)
{
  double doppler1 = (double)((int32_t)(v-42))/210;

  snprintf(s, ITEM_LABEL_LENGTH, "%fm/s2 (%u)", doppler1, v);
}

static const value_string lpp_dopplerUncertainty_vals[] = {
  { 0, "40m/s"},
  { 1, "20m/s"},
  { 2, "10m/s"},
  { 3, "5m/s"},
  { 4, "2.5m/s"},
  { 0, NULL}
};

static void
lpp_codePhase_fmt(char *s, uint32_t v)
{
  double codePhase = (double)v*pow(2, -10);

  snprintf(s, ITEM_LABEL_LENGTH, "%gms (%u)", codePhase, v);
}

static const value_string lpp_codePhaseSearchWindow_vals[] = {
  {  0, "No information"},
  {  1, "0.002ms"},
  {  2, "0.004ms"},
  {  3, "0.008ms"},
  {  4, "0.012ms"},
  {  5, "0.016ms"},
  {  6, "0.024ms"},
  {  7, "0.032ms"},
  {  8, "0.048ms"},
  {  9, "0.064ms"},
  { 10, "0.096ms"},
  { 11, "0.128ms"},
  { 12, "0.164ms"},
  { 13, "0.200ms"},
  { 14, "0.250ms"},
  { 15, "0.300ms"},
  { 16, "0.360ms"},
  { 17, "0.420ms"},
  { 18, "0.480ms"},
  { 19, "0.540ms"},
  { 20, "0.600ms"},
  { 21, "0.660ms"},
  { 22, "0.720ms"},
  { 23, "0.780ms"},
  { 24, "0.850ms"},
  { 25, "1.000ms"},
  { 26, "1.150ms"},
  { 27, "1.300ms"},
  { 28, "1.450ms"},
  { 29, "1.600ms"},
  { 30, "1.800ms"},
  { 31, "2.000ms"},
  { 0, NULL}
};
static value_string_ext lpp_codePhaseSearchWindow_vals_ext = VALUE_STRING_EXT_INIT(lpp_codePhaseSearchWindow_vals);

static void
lpp_azimuth_elevation_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%f degrees (%u)", (float)v*0.703125, v);
}

static void
lpp_kepAlmanacE_fmt(char *s, uint32_t v)
{
  double kepAlmanacE = (double)v*pow(2, -16);

  snprintf(s, ITEM_LABEL_LENGTH, "%g (%u)", kepAlmanacE, v);
}

static void
lpp_kepAlmanacDeltaI_fmt(char *s, uint32_t v)
{
  double kepAlmanacDeltaI = (double)((int32_t)v)*pow(2, -14);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", kepAlmanacDeltaI, (int32_t)v);
}

static void
lpp_kepAlmanacOmegaDot_fmt(char *s, uint32_t v)
{
  double kepAlmanacOmegaDot = (double)((int32_t)v)*pow(2, -33);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", kepAlmanacOmegaDot, (int32_t)v);
}

static void
lpp_kepAlmanacAPowerHalf_fmt(char *s, uint32_t v)
{
  double kepAlmanacAPowerHalf = (double)((int32_t)v)*pow(2, -9);

  snprintf(s, ITEM_LABEL_LENGTH, "%gm1/2 (%d)", kepAlmanacAPowerHalf, (int32_t)v);
}

static void
lpp_kepAlmanacOmega0_W_M0_fmt(char *s, uint32_t v)
{
  double kepAlmanacOmega0_W_M0 = (double)((int32_t)v)*pow(2, -15);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", kepAlmanacOmega0_W_M0, (int32_t)v);
}

static void
lpp_kepAlmanacAF0_fmt(char *s, uint32_t v)
{
  double kepAlmanacAF0 = (double)((int32_t)v)*pow(2, -19);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", kepAlmanacAF0, (int32_t)v);
}

static void
lpp_kepAlmanacAF1_fmt(char *s, uint32_t v)
{
  double kepAlmanacAF1 = (double)((int32_t)v)*pow(2, -38);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s (%d)", kepAlmanacAF1, (int32_t)v);
}

static void
lpp_navAlmE_fmt(char *s, uint32_t v)
{
  double navAlmE = (double)v*pow(2, -21);

  snprintf(s, ITEM_LABEL_LENGTH, "%g (%u)", navAlmE, v);
}

static void
lpp_navAlmDeltaI_fmt(char *s, uint32_t v)
{
  double navAlmDeltaI = (double)((int32_t)v)*pow(2, -19);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", navAlmDeltaI, (int32_t)v);
}

static void
lpp_navAlmOMEGADOT_fmt(char *s, uint32_t v)
{
  double navAlmOMEGADOT = (double)((int32_t)v)*pow(2, -38);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", navAlmOMEGADOT, (int32_t)v);
}

static void
lpp_navAlmSqrtA_fmt(char *s, uint32_t v)
{
  double navAlmSqrtA = (double)v*pow(2, -11);

  snprintf(s, ITEM_LABEL_LENGTH, "%gm1/2 (%u)", navAlmSqrtA, v);
}

static void
lpp_navAlmOMEGAo_Omega_Mo_fmt(char *s, uint32_t v)
{
  double navAlmOMEGAo_Omega_Mo = (double)((int32_t)v)*pow(2, -23);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", navAlmOMEGAo_Omega_Mo, (int32_t)v);
}

static void
lpp_navAlmaf0_fmt(char *s, uint32_t v)
{
  double navAlmaf0 = (double)((int32_t)v)*pow(2, -20);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", navAlmaf0, (int32_t)v);
}

static void
lpp_navAlmaf1_fmt(char *s, uint32_t v)
{
  double navAlmaf1 = (double)((int32_t)v)*pow(2, -38);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s (%d)", navAlmaf1, (int32_t)v);
}

static void
lpp_redAlmDeltaA_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%dm (%d)", 512*(int)v, (int)v);
}

static void
lpp_redAlmOmega0_Phi0_fmt(char *s, uint32_t v)
{
  double redAlmOmega0_Phi0 = (double)((int32_t)v)*pow(2, -6);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", redAlmOmega0_Phi0, (int32_t)v);
}

static void
lpp_midiAlmE_fmt(char *s, uint32_t v)
{
  double midiAlmE = (double)v*pow(2, -16);

  snprintf(s, ITEM_LABEL_LENGTH, "%g (%u)", midiAlmE, v);
}

static void
lpp_midiAlmDeltaI_fmt(char *s, uint32_t v)
{
  double midiAlmDeltaI = (double)((int32_t)v)*pow(2, -14);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", midiAlmDeltaI, (int32_t)v);
}

static void
lpp_midiAlmOmegaDot_fmt(char *s, uint32_t v)
{
  double midiAlmOmegaDot = (double)((int32_t)v)*pow(2, -33);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", midiAlmOmegaDot, (int32_t)v);
}

static void
lpp_midiAlmSqrtA_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%fm1/2 (%u)", (float)v*0.0625, v);
}

static void
lpp_midiAlmOmega0_Omega_Mo_fmt(char *s, uint32_t v)
{
  double midiAlmOmega0_Omega_Mo = (double)((int32_t)v)*pow(2, -15);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", midiAlmOmega0_Omega_Mo, (int32_t)v);
}

static void
lpp_midiAlmaf0_fmt(char *s, uint32_t v)
{
  double midiAlmaf0 = (double)((int32_t)v)*pow(2, -20);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", midiAlmaf0, (int32_t)v);
}

static void
lpp_midiAlmaf1_fmt(char *s, uint32_t v)
{
  double midiAlmaf1 = (double)((int32_t)v)*pow(2, -37);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s (%d)", midiAlmaf1, (int32_t)v);
}

static void
lpp_gloAlmLambdaA_DeltaIa_fmt(char *s, uint32_t v)
{
  double gloAlmLambdaA_DeltaIa = (double)((int32_t)v)*pow(2, -20);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", gloAlmLambdaA_DeltaIa, (int32_t)v);
}

static void
lpp_gloAlmtlambdaA_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%fs (%u)", (float)v*0.03125, v);
}

static void
lpp_gloAlmDeltaTA_fmt(char *s, uint32_t v)
{
  double gloAlmDeltaTA = (double)((int32_t)v)*pow(2, -9);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/orbit period (%d)", gloAlmDeltaTA, (int32_t)v);
}

static void
lpp_gloAlmDeltaTdotA_fmt(char *s, uint32_t v)
{
  double gloAlmDeltaTdotA = (double)((int32_t)v)*pow(2, -14);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/orbit period (%d)", gloAlmDeltaTdotA, (int32_t)v);
}

static void
lpp_gloAlmEpsilonA_fmt(char *s, uint32_t v)
{
  double gloAlmEpsilonA = (double)v*pow(2, -20);

  snprintf(s, ITEM_LABEL_LENGTH, "%g (%u)", gloAlmEpsilonA, (int32_t)v);
}

static void
lpp_gloAlmOmegaA_fmt(char *s, uint32_t v)
{
  double gloAlmOmegaA = (double)((int32_t)v)*pow(2, -15);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", gloAlmOmegaA, (int32_t)v);
}

static void
lpp_gloAlmTauA_fmt(char *s, uint32_t v)
{
  double gloAlmTauA = (double)((int32_t)v)*pow(2, -18);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", gloAlmTauA, (int32_t)v);
}

static void
lpp_sbasAlmXg_Yg_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%fkm (%d)", (int32_t)v*2.6, (int32_t)v);
}

static void
lpp_sbasAlmZg_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%dkm (%d)", (int32_t)v*26, (int32_t)v);
}

static void
lpp_sbasAlmXgdot_YgDot_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%dm/s (%d)", (int32_t)v*10, (int32_t)v);
}

static void
lpp_sbasAlmZgDot_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%fm/s (%d)", (int32_t)v*40.96, (int32_t)v);
}

static void
lpp_sbasAlmTo_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%um/s (%u)", v*64, v);
}

static void
lpp_bdsAlmToa_r12_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%us (%u)", v*4096, v);
}

static void
lpp_bdsAlmSqrtA_r12_fmt(char *s, uint32_t v)
{
  double bdsAlmSqrtA = (double)v*pow(2, -11);

  snprintf(s, ITEM_LABEL_LENGTH, "%gm1/2 (%u)", bdsAlmSqrtA, v);
}

static void
lpp_bdsAlmE_r12_fmt(char *s, uint32_t v)
{
  double bdsAlmE = (double)v*pow(2, -21);

  snprintf(s, ITEM_LABEL_LENGTH, "%gm1/2 (%u)", bdsAlmE, v);
}

static void
lpp_bdsAlmW_M0_Omega0_r12_fmt(char *s, uint32_t v)
{
  double bdsAlmW_M0_Omega0 = (double)((int32_t)v)*pow(2, -23);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", bdsAlmW_M0_Omega0, (int32_t)v);
}

static void
lpp_bdsAlmOmegaDot_r12_fmt(char *s, uint32_t v)
{
  double bdsAlmOmegaDot = (double)((int32_t)v)*pow(2, -38);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", bdsAlmOmegaDot, (int32_t)v);
}

static void
lpp_bdsAlmDeltaI_r12_fmt(char *s, uint32_t v)
{
  double bdsAlmDeltaI = (double)((int32_t)v)*pow(2, -19);

  snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", bdsAlmDeltaI, (int32_t)v);
}

static void
lpp_bdsAlmA0_r12_fmt(char *s, uint32_t v)
{
  double bdsAlmA0 = (double)((int32_t)v)*pow(2, -20);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", bdsAlmA0, (int32_t)v);
}

static void
lpp_bdsAlmA1_r12_fmt(char *s, uint32_t v)
{
  double bdsAlmA1 = (double)((int32_t)v)*pow(2, -38);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s (%d)", bdsAlmA1, (int32_t)v);
}

static const true_false_string lpp_bdsSvHealth_r12_b1i_b2i_value = {
  "OK",
  "Weak"
};

static const true_false_string lpp_bdsSvHealth_r12_nav_value = {
  "OK",
  "Bad (IOD over limit)"
};

static void
lpp_gnss_Utc_A1_fmt(char *s, uint32_t v)
{
  double gnss_Utc_A1 = (double)((int32_t)v)*pow(2, -50);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/s (%d)", gnss_Utc_A1, (int32_t)v);
}

static void
lpp_gnss_Utc_A0_fmt(char *s, uint32_t v)
{
  double gnss_Utc_A0 = (double)((int32_t)v)*pow(2, -30);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", gnss_Utc_A0, (int32_t)v);
}

static void
lpp_gnss_Utc_Tot_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%us (%u)", v*4096, v);
}

static const value_string lpp_bds_UDREI_vals[] = {
  {  0, "1 meter"},
  {  1, "1.5 meters"},
  {  2, "2 meters"},
  {  3, "3 meters"},
  {  4, "4 meters"},
  {  5, "5 meters"},
  {  6, "6 meters"},
  {  7, "8 meters"},
  {  8, "10 meters"},
  {  9, "15 meters"},
  { 10, "20 meters"},
  { 11, "50 meters"},
  { 12, "100 meters"},
  { 13, "150 meters"},
  { 14, "Not monitored"},
  { 15, "Not available"},
  { 0, NULL}
};
static value_string_ext lpp_bds_UDREI_vals_ext = VALUE_STRING_EXT_INIT(lpp_bds_UDREI_vals);

static const value_string lpp_bds_RURAI_vals[] = {
  {  0, "0.75 meter"},
  {  1, "1 meter"},
  {  2, "1.25 meters"},
  {  3, "1.75 meters"},
  {  4, "2.25 meters"},
  {  5, "3 meters"},
  {  6, "3.75 meters"},
  {  7, "4.5 meters"},
  {  8, "5.25 meters"},
  {  9, "6 meters"},
  { 10, "7.5 meters"},
  { 11, "15 meters"},
  { 12, "50 meters"},
  { 13, "150 meters"},
  { 14, "300 meters"},
  { 15, "> 300 meters"},
  { 0, NULL}
};
static value_string_ext lpp_bds_RURAI_vals_ext = VALUE_STRING_EXT_INIT(lpp_bds_RURAI_vals);

static void
lpp_bds_ECC_DeltaT_r12_fmt(char *s, uint32_t v)
{
  if ((int32_t)v == -4096) {
    snprintf(s, ITEM_LABEL_LENGTH, "Not available (%d)", (int32_t)v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%gm (%d)", (float)((int32_t)v)*0.1, (int32_t)v);
  }
}

static void
lpp_bds_GridIonElement_dt_r12_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%gm (%d)", (float)((int32_t)v)*0.125, (int32_t)v);
}

static const value_string lpp_bds_givei_vals[] = {
  {  0, "0.3 meter"},
  {  1, "0.6 meter"},
  {  2, "0.9 meter"},
  {  3, "1.2 meters"},
  {  4, "1.5 meters"},
  {  5, "1.8 meters"},
  {  6, "2.1 meters"},
  {  7, "2.4 meters"},
  {  8, "2.7 meters"},
  {  9, "3 meters"},
  { 10, "3.6 meters"},
  { 11, "4.5 meters"},
  { 12, "6 meters"},
  { 13, "9 meters"},
  { 14, "15 meters"},
  { 15, "45 meters"},
  { 0, NULL}
};
static value_string_ext lpp_bds_givei_vals_ext = VALUE_STRING_EXT_INIT(lpp_bds_givei_vals);

static void
lpp_fine_PseudoRange_r15_fmt(char *s, uint32_t v)
{
  double val = (double)((int32_t)v)*pow(2, -29);

  snprintf(s, ITEM_LABEL_LENGTH, "%gms (%d)", val, (int32_t)v);
}

static void
lpp_fine_PhaseRange_r15_fmt(char *s, uint32_t v)
{
  double val = (double)((int32_t)v)*pow(2, -31);

  snprintf(s, ITEM_LABEL_LENGTH, "%gms (%d)", val, (int32_t)v);
}

static void
lpp_carrier_to_noise_ratio_r15_fmt(char *s, uint32_t v)
{
  double val = (double)v*pow(2, -4);

  snprintf(s, ITEM_LABEL_LENGTH, "%gdB-Hz (%d)", val, v);
}

static void
lpp_fine_PhaseRangeRate_r15_fmt(char *s, uint32_t v)
{
  double val = (double)((int32_t)v)/1000;

  snprintf(s, ITEM_LABEL_LENGTH, "%gms (%d)", val, (int32_t)v);
}

static void
lpp_cpBias_r15_fmt(char *s, uint32_t v)
{
  double val = (double)((int32_t)v)/50;

  snprintf(s, ITEM_LABEL_LENGTH, "%gm (%d)", val, (int32_t)v);
}

static const value_string lpp_ambiguityStatusFlag_r15_vals[] = {
  { 0, "Reserved for future use (artificial observations)"},
  { 1, "Correct Integer Ambiguity Level for L1 and L2"},
  { 2, "Correct Integer Ambiguity Level for L1-L2 widelane"},
  { 3, "Uncertain Integer Ambiguity Level. Only a likely guess is used"},
  { 0, NULL}
};

static void
lpp_1_2000m_fmt(char *s, uint32_t v)
{
  double val = (double)((int32_t)v)/2000;

  snprintf(s, ITEM_LABEL_LENGTH, "%gm (%d)", val, (int32_t)v);
}

static void
lpp_1_100ppm_fmt(char *s, uint32_t v)
{
  double val = (double)((int32_t)v)/100;

  snprintf(s, ITEM_LABEL_LENGTH, "%gppm (%d)", val, (int32_t)v);
}

static void
lpp_1_10ppm_fmt(char *s, uint32_t v)
{
  double val = (double)((int32_t)v)/10;

  snprintf(s, ITEM_LABEL_LENGTH, "%gppm (%d)", val, (int32_t)v);
}

static const value_string lpp_ssrUpdateInterval_r15_vals[] = {
  {  0, "1 second"},
  {  1, "2 seconds"},
  {  2, "5 seconds"},
  {  3, "10 seconds"},
  {  4, "15 seconds"},
  {  5, "30 seconds"},
  {  6, "60 seconds"},
  {  7, "120 seconds"},
  {  8, "240 seconds"},
  {  9, "300 seconds"},
  { 10, "600 seconds"},
  { 11, "900 seconds"},
  { 12, "1800 seconds"},
  { 13, "3600 seconds"},
  { 14, "7200 seconds"},
  { 15, "10800 seconds"},
  { 0, NULL}
};

static void
lpp_1_10000m_fmt(char *s, uint32_t v)
{
  double val = (double)((int32_t)v)/10000;

  snprintf(s, ITEM_LABEL_LENGTH, "%gm (%d)", val, (int32_t)v);
}

static void
lpp_4_10000m_fmt(char *s, uint32_t v)
{
  double val = (double)((int32_t)v)/10000*4;

  snprintf(s, ITEM_LABEL_LENGTH, "%gm (%d)", val, (int32_t)v);
}

static void
lpp_1_1000000m_s_fmt(char *s, uint32_t v)
{
  double val = (double)((int32_t)v)/1000000;

  snprintf(s, ITEM_LABEL_LENGTH, "%gm/s (%d)", val, (int32_t)v);
}

static void
lpp_4_1000000m_s_fmt(char *s, uint32_t v)
{
  double val = (double)((int32_t)v)/1000000*4;

  snprintf(s, ITEM_LABEL_LENGTH, "%gm/s (%d)", val, (int32_t)v);
}

static void
lpp_2_100000000m_s2_fmt(char *s, uint32_t v)
{
  double val = (double)((int32_t)v)/100000000*2;

  snprintf(s, ITEM_LABEL_LENGTH, "%gm/s2 (%d)", val, (int32_t)v);
}

static void
lpp_1_100000m_fmt(char *s, uint32_t v)
{
  double val = (double)((int32_t)v)/100000;

  snprintf(s, ITEM_LABEL_LENGTH, "%gm (%d)", val, (int32_t)v);
}

static void
lpp_tauC_fmt(char *s, uint32_t v)
{
  double tauC = (double)((int32_t)v)*pow(2, -31);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", tauC, (int32_t)v);
}

static void
lpp_b1_fmt(char *s, uint32_t v)
{
  double b1 = (double)((int32_t)v)*pow(2, -10);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%d)", b1, (int32_t)v);
}

static void
lpp_b2_fmt(char *s, uint32_t v)
{
  double b2 = (double)((int32_t)v)*pow(2, -16);

  snprintf(s, ITEM_LABEL_LENGTH, "%gs/msd (%d)", b2, (int32_t)v);
}

static const value_string lpp_utcStandardID_vals[] = {
  { 0, "UTC as operated by the Communications Research Laboratory (CRL), Tokyo, Japan"},
  { 1, "UTC as operated by the National Institute of Standards and Technology (NIST)"},
  { 2, "UTC as operated by the U. S. Naval Observatory (USNO)"},
  { 3, "UTC as operated by the International Bureau of Weights and Measures (BIPM)"},
  { 0, NULL}
};

static const value_string lpp_dataBitInterval_vals[] = {
  {  0, "0.1"},
  {  1, "0.2"},
  {  2, "0.4"},
  {  3, "0.8"},
  {  4, "1.6"},
  {  5, "3.2"},
  {  6, "6.4"},
  {  7, "12.8"},
  {  8, "25.6"},
  {  9, "51.2"},
  { 10, "102.4"},
  { 11, "204.8"},
  { 12, "409.6"},
  { 13, "819.2"},
  { 14, "1638.4"},
  { 15, "Not specified"},
  { 0, NULL}
};
static value_string_ext lpp_dataBitInterval_vals_ext = VALUE_STRING_EXT_INIT(lpp_dataBitInterval_vals);

static const value_string lpp_carrierQualityInd_vals[] = {
  { 0, "Data direct, carrier phase not continuous"},
  { 1, "Data inverted, carrier phase not continuous"},
  { 2, "Data direct, carrier phase continuous"},
  { 3, "Data inverted, carrier phase continuous"},
  { 0, NULL}
};

static void
lpp_GNSS_SatMeas_codePhase_fmt(char *s, uint32_t v)
{
  double codePhase = (double)v*pow(2, -21);

  snprintf(s, ITEM_LABEL_LENGTH, "%gms (%u)", codePhase, v);
}

static void
lpp_codePhaseRMSError_fmt(char *s, uint32_t v)
{
  uint8_t mantissa = v & 0x07;
  uint8_t exponent = (v & 0x38) >> 3;
  uint8_t mantissa_1 = (v - 1) & 0x07;
  uint8_t exponent_1 = ((v - 1) & 0x38) >> 3;

  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "P < 0.5 (0)");
  } else if (v < 63) {
    snprintf(s, ITEM_LABEL_LENGTH, "%f <= P < %f (%u)", 0.5*(1+mantissa_1/8)*pow(2, exponent_1),
               0.5*(1+mantissa/8)*pow(2, exponent), v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "112 <= P (63)");
  }
}

static void
lpp_transmitterLatitude_fmt(char *s, uint32_t v)
{
  double lat = ((double)v*4.0/pow(2, 20))-90.0;

  snprintf(s, ITEM_LABEL_LENGTH, "%g degrees (%u)", lat, v);
}

static void
lpp_transmitterLongitude_fmt(char *s, uint32_t v)
{
  double longitude = ((double)v*4.0/pow(2, 20))-180.0;

  snprintf(s, ITEM_LABEL_LENGTH, "%g degrees (%u)", longitude, v);
}

static void
lpp_transmitterAltitude_fmt(char *s, uint32_t v)
{
  double alt = ((double)v*0.29)-500.0;

  snprintf(s, ITEM_LABEL_LENGTH, "%gm (%u)", alt, v);
}

static void
lpp_refPressure_fmt(char *s, uint32_t v)
{
  int32_t pressure = (int32_t)v;

  snprintf(s, ITEM_LABEL_LENGTH, "%dPa (%d)", 101325+pressure, pressure);
}

static void
lpp_refTemperature_fmt(char *s, uint32_t v)
{
  int32_t temp = (int32_t)v;

  snprintf(s, ITEM_LABEL_LENGTH, "%dK (%d)", 273+temp, temp);
}

static void
lpp_referencePressureRate_v1520_fmt(char *s, uint32_t v)
{
  int32_t rate = (int32_t)v;

  snprintf(s, ITEM_LABEL_LENGTH, "%dPa/hour (%d)", 10*rate, rate);
}

static void
lpp_PressureValidityPeriod_v1520_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%umin (%u)", 15*v, v);
}

static void
lpp_doppler_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%gm/s (%d)", (int32_t)v*0.04, (int32_t)v);
}

static void
lpp_adr_fmt(char *s, uint32_t v)
{
  double adr = (double)v*pow(2, -10);

  snprintf(s, ITEM_LABEL_LENGTH, "%gm (%u)", adr, v);
}

static void
lpp_adrMSB_r15_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%um (%u)", v*32768, v);
}

static void
lpp_GNSS_SatMeas_delta_codePhase_r15_fmt(char *s, uint32_t v)
{
  double codePhase = (double)v*pow(2, -24);

  snprintf(s, ITEM_LABEL_LENGTH, "%gms (%u)", codePhase, v);
}

static void
lpp_deliveryAmount_r15_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%g (%u)", pow(2, v), v);
}

static void
lpp_rsrp_Result_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSRP < -140dBm (0)");
  } else if (v < 97) {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= RSRP < %ddBm (%u)", v-141, v-140, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "-44dBm <= RSRP (97)");
  }
}

static void
lpp_rsrq_Result_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSRQ < -19.5dB (0)");
  } else if (v < 34) {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= RSRQ < %.1fdB (%u)", ((float)v/2)-20, (((float)v+1)/2)-20, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "-3dB <= RSRQ (34)");
  }
}

static void
lpp_nrsrp_Result_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "NRSRP < -156dBm (0)");
  } else if (v < 113) {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= NRSRP < %ddBm (%u)", v-157, v-156, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "-44dBm <= NRSRP (97)");
  }
}

static void
lpp_nrsrq_Result_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "NRSRQ < -34dB (0)");
  } else if (v < 74) {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= NRSRQ < %.1fdB (%u)", (((float)v-1)/2)-34, ((float)v/2)-34, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "2.5dB <= NRSRQ (%u)", v);
  }
}

static void
lpp_rsrp_Result_v1470_fmt(char *s, uint32_t v)
{
  int32_t d = (int32_t)v;

  if (d == -17) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSRP < -157dBm (-17)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= RSRP < %ddBm (%d)", d-141, d-140, d);
  }
}

static void
lpp_rsrq_Result_v1470_fmt(char *s, uint32_t v)
{
  int32_t d = (int32_t)v;

  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSRQ < -34.5dB (-30)");
  } else if (v < 46) {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= RSRQ < %.1fdB (%d)", ((float)d/2)-20, (((float)d+1)/2)-20, d);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "3dB <= RSRQ (46)");
  }
}

static void
lpp_ue_RxTxTimeDiff_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "T < 2Ts (0)");
  } else if (v < 2048) {
    snprintf(s, ITEM_LABEL_LENGTH, "%uTs <= T < %uTs (%u)", v*2, (v+1)*2, v);
  } else if (v < 4095) {
    snprintf(s, ITEM_LABEL_LENGTH, "%uTs <= T < %uTs (%u)", (v*8)-12288, ((v+1)*8)-12288, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "20472Ts <= T (4095)");
  }
}

static void
lpp_mbs_beaconMeasElt_codePhase_fmt(char *s, uint32_t v)
{
  double codePhase = (double)v*pow(2, -21);

  snprintf(s, ITEM_LABEL_LENGTH, "%gms (%u)", codePhase, v);
}

static const unit_name_string units_pa = { "Pa", NULL };

#include "packet-lpp-fn.c"

int dissect_lpp_AssistanceDataSIBelement_r15_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, lpp_pos_sib_type_t pos_sib_type) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  struct lpp_private_data *lpp_data = lpp_get_private_data(pinfo);

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, false, pinfo);
  lpp_data->pos_sib_type = pos_sib_type;
  offset = dissect_lpp_AssistanceDataSIBelement_r15(tvb, offset, &asn1_ctx, tree, hf_lpp_AssistanceDataSIBelement_r15_PDU);
  offset += 7; offset >>= 3;
  return offset;
}

static int dissect_lpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
  proto_tree *subtree;
  proto_item *it;

  it = proto_tree_add_item(tree, proto_lpp, tvb, 0, -1, ENC_NA);
  col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "LPP");
  subtree = proto_item_add_subtree(it, ett_lpp);

  return dissect_LPP_Message_PDU(tvb, pinfo, subtree, NULL);
}

/*--- proto_register_lpp -------------------------------------------*/
void proto_register_lpp(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-lpp-hfarr.c"
    { &hf_lpp_svHealthExt_v1240_e5bhs,
      { "E5b Signal Health Status", "lpp.svHealthExt_v1240.e5bhs",
        FT_UINT8, BASE_DEC, VALS(lpp_signal_health_status_vals), 0,
        NULL, HFILL }},
    { &hf_lpp_svHealthExt_v1240_e1_bhs,
      { "E1-B Signal Health Status", "lpp.svHealthExt_v1240.e1_bhs",
        FT_UINT8, BASE_DEC, VALS(lpp_signal_health_status_vals), 0,
        NULL, HFILL }},
    { &hf_lpp_kepSV_StatusINAV_e5bhs,
      { "E5b Signal Health Status", "lpp.kepSV_StatusINAV.e5bhs",
        FT_UINT8, BASE_DEC, VALS(lpp_signal_health_status_vals), 0,
        NULL, HFILL }},
    { &hf_lpp_kepSV_StatusINAV_e1_bhs,
      { "E1-B Signal Health Status", "lpp.kepSV_StatusINAV.e1_bhs",
        FT_UINT8, BASE_DEC, VALS(lpp_signal_health_status_vals), 0,
        NULL, HFILL }},
    { &hf_lpp_kepSV_StatusFNAV_e5ahs,
      { "E5a Signal Health Status", "lpp.kepSV_StatusFNAV.e5ahs",
        FT_UINT8, BASE_DEC, VALS(lpp_signal_health_status_vals), 0,
        NULL, HFILL }},
    { &hf_lpp_bdsSvHealth_r12_sat_clock,
      { "Satellite Clock", "lpp.bdsSvHealth_r12.sat_clock",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_ok_error), 0,
        NULL, HFILL }},
    { &hf_lpp_bdsSvHealth_r12_b1i,
      { "B1I Signal", "lpp.bdsSvHealth_r12.b1i",
        FT_BOOLEAN, BASE_NONE, TFS(&lpp_bdsSvHealth_r12_b1i_b2i_value), 0,
        NULL, HFILL }},
    { &hf_lpp_bdsSvHealth_r12_b2i,
      { "B2I Signal", "lpp.bdsSvHealth_r12.b2i",
        FT_BOOLEAN, BASE_NONE, TFS(&lpp_bdsSvHealth_r12_b1i_b2i_value), 0,
        NULL, HFILL }},
    { &hf_lpp_bdsSvHealth_r12_nav,
      { "NAV Message", "lpp.bdsSvHealth_r12.nav",
        FT_BOOLEAN, BASE_NONE, TFS(&lpp_bdsSvHealth_r12_nav_value), 0,
        NULL, HFILL }},
    { &hf_lpp_AssistanceDataSIBelement_r15_PDU,
      { "AssistanceDataSIBelement-r15", "lpp.AssistanceDataSIBelement_r15_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_lpp,
    &ett_lpp_svHealthExt_v1240,
    &ett_kepSV_StatusINAV,
    &ett_kepSV_StatusFNAV,
    &ett_lpp_bdsSvHealth_r12,
    &ett_lpp_assistanceDataElement_r15,
#include "packet-lpp-ettarr.c"
  };


  /* Register protocol */
  proto_lpp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("lpp", dissect_lpp, proto_lpp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_lpp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


}


/*--- proto_reg_handoff_lpp ---------------------------------------*/
void
proto_reg_handoff_lpp(void)
{
  lppe_handle = find_dissector_add_dependency("lppe", proto_lpp);
}


